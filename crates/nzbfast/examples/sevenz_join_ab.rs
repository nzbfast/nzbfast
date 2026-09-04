//! Price the two ways a split 7-Zip container can be read on the disk
//! post-pass: join every part into one scratch file and open that, or
//! open the ordered parts in place. TODO 212 removed the join and priced
//! only the FAILING ending (no password, nothing decodes); this rig is
//! the succeeding one, where the decoder actually runs. Dev-only; not
//! shipped, and not wired into any test - it writes gigabytes.
//!
//!   sevenz_join_ab gen   <dir> <plain|mhe> <payload_mib> <part_mib>
//!   sevenz_join_ab suite <dir> <reps> [password]
//!
//! `suite` runs the two arms ALTERNATELY (A B A B ...) so a box under
//! load moves both by the same amount, and prints one line per leg plus
//! a median line per arm. Wall, user/sys CPU (getrusage deltas over the
//! whole process, so the LZMA2 worker threads are counted), the peak
//! job-directory footprint sampled at 20 Hz, and the bytes the archive
//! reader actually pulled off disk - counted in the same wrapper on both
//! arms, so the instrumentation cancels.
//!
//! The reader under test is a verbatim copy of `rarfix::sevenz`'s
//! `SplitParts` (that module is `pub(crate)`, and an A/B whose arms
//! differ in anything but the reader is not an A/B). Keep the two in
//! step: if `SplitParts` changes shape, this rig is measuring the old
//! one until it is copied again.

use anyhow::{Context, Result};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

// ---------------------------------------------------------------- rig I/O

/// The ordered parts of one 7z container as a single seekable byte-space.
/// Copied from `crates/nzbfast-unpack/src/rarfix/sevenz.rs` - see the module doc.
struct SplitParts {
    files: Vec<(std::fs::File, u64, u64)>,
    total: u64,
    pos: u64,
    at: Option<(usize, u64)>,
}

impl SplitParts {
    fn open(parts: &[PathBuf]) -> std::io::Result<Self> {
        if parts.is_empty() {
            return Err(std::io::Error::other("7z job has no parts"));
        }
        let mut files = Vec::with_capacity(parts.len());
        let mut total = 0u64;
        for p in parts {
            let f = std::fs::File::open(p)?;
            let len = f.metadata()?.len();
            files.push((f, total, len));
            total = total.checked_add(len).ok_or_else(|| {
                std::io::Error::other("7z split set exceeds the addressable size")
            })?;
        }
        Ok(Self {
            files,
            total,
            pos: 0,
            at: None,
        })
    }

    fn part_at(&self, pos: u64) -> Option<usize> {
        let idx = self.files.partition_point(|&(_, start, _)| start <= pos);
        idx.checked_sub(1)
            .filter(|&i| pos < self.files[i].1 + self.files[i].2)
    }
}

impl Read for SplitParts {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let Some(i) = self.part_at(self.pos) else {
            return Ok(0);
        };
        let (ref mut f, start, len) = self.files[i];
        let local = self.pos - start;
        if self.at != Some((i, local)) {
            f.seek(SeekFrom::Start(local))?;
        }
        let want = usize::try_from(len - local)
            .unwrap_or(usize::MAX)
            .min(buf.len());
        let n = f.read(&mut buf[..want])?;
        self.pos += n as u64;
        self.at = Some((i, local + n as u64));
        Ok(n)
    }
}

impl Seek for SplitParts {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        let next = match to {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(d) => self.total.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        };
        let Some(next) = next else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek before the start of the 7z set",
            ));
        };
        self.pos = next;
        Ok(next)
    }
}

/// Counts the reads and seeks the archive reader issues. Wrapped around
/// BOTH arms' sources, so its own cost cancels in the comparison.
struct Counting<R> {
    inner: R,
    reads: Arc<AtomicU64>,
    bytes: Arc<AtomicU64>,
    seeks: Arc<AtomicU64>,
}

impl<R: Read> Read for Counting<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

impl<R: Seek> Seek for Counting<R> {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        self.seeks.fetch_add(1, Ordering::Relaxed);
        self.inner.seek(to)
    }
}

/// Concatenate `parts` into `dest` - the join TODO 212 removed, kept here
/// as arm A. Same shape as `rarfix::sevenz::concat_files`.
fn concat_files(parts: &[PathBuf], dest: &Path) -> Result<()> {
    let mut out = std::io::BufWriter::new(std::fs::File::create(dest)?);
    for p in parts {
        let mut f = std::fs::File::open(p)?;
        std::io::copy(&mut f, &mut out)?;
    }
    out.flush()?;
    Ok(())
}

// ------------------------------------------------------------- accounting

/// The user and sys CPU seconds this process has spent so far,
/// worker threads included.
///
/// Via `nzbkit::mem` rather than a local `libc::getrusage`, which does
/// not exist on Windows and held `windows-clippy` red under
/// `--all-targets` (an example is a target too). The split is what this
/// rig prints, so it asks for the split.
fn cpu_now() -> (f64, f64) {
    nzbkit::mem::cpu_user_sys_secs().unwrap_or((0.0, 0.0))
}

/// Apparent size of everything under `dir`, the §212 footprint oracle.
fn dir_bytes(dir: &Path) -> u64 {
    let mut total = 0;
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    for e in rd.flatten() {
        let Ok(md) = e.metadata() else { continue };
        if md.is_dir() {
            total += dir_bytes(&e.path());
        } else {
            total += md.len();
        }
    }
    total
}

/// Sample `dir_bytes` at 20 Hz until stopped; returns the peak seen.
struct Footprint {
    stop: Arc<AtomicBool>,
    peak: Arc<AtomicU64>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Footprint {
    fn start(dir: &Path) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let peak = Arc::new(AtomicU64::new(0));
        let (d, s, p) = (dir.to_path_buf(), stop.clone(), peak.clone());
        let handle = std::thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                p.fetch_max(dir_bytes(&d), Ordering::Relaxed);
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            p.fetch_max(dir_bytes(&d), Ordering::Relaxed);
        });
        Self {
            stop,
            peak,
            handle: Some(handle),
        }
    }

    fn finish(mut self) -> u64 {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        self.peak.load(Ordering::Relaxed)
    }
}

// ------------------------------------------------------------- the fixture

/// Incompressible bytes, media-shaped, from a xorshift64 stream.
fn fill_random(buf: &mut [u8], state: &mut u64) {
    for chunk in buf.chunks_mut(8) {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        let b = x.to_le_bytes();
        chunk.copy_from_slice(&b[..chunk.len()]);
    }
}

/// Compressible bytes, so LZMA2 emits real compressed chunks and the
/// multi-threaded decoder has something to do.
fn fill_text(buf: &mut [u8], state: &mut u64) {
    const WORDS: [&str; 8] = [
        "the ", "quick ", "brown ", "fox ", "jumps ", "over ", "lazy ", "dogs\n",
    ];
    let mut at = 0;
    while at < buf.len() {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        let w = WORDS[(x % 8) as usize].as_bytes();
        let n = w.len().min(buf.len() - at);
        buf[at..at + n].copy_from_slice(&w[..n]);
        at += n;
    }
}

fn make_set(dir: &Path, kind: &str, payload_mib: u64, part_mib: u64, password: &str) -> Result<()> {
    use sevenz_rust2::encoder_options::{AesEncoderOptions, Lzma2Options};
    use sevenz_rust2::{ArchiveEntry, ArchiveWriter, Password};
    std::fs::create_dir_all(dir)?;
    let payload = dir.join("payload.bin");
    let mut f = std::io::BufWriter::new(std::fs::File::create(&payload)?);
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let mut buf = vec![0u8; 1 << 20];
    for _ in 0..payload_mib {
        if kind == "text" {
            fill_text(&mut buf, &mut state);
        } else {
            fill_random(&mut buf, &mut state);
        }
        f.write_all(&buf)?;
    }
    f.flush()?;
    drop(f);

    let whole = dir.join("whole.7z");
    {
        let mut w = ArchiveWriter::new(std::fs::File::create(&whole)?)?;
        if kind == "mhe" {
            // The field's shape: `7zz -mx0 -mhe=on`, store plus AES with
            // the header encrypted too, which is what makes the password
            // undiscoverable until the END header is parsed.
            w.set_encrypt_header(true);
            w.set_content_methods(vec![
                AesEncoderOptions::new(Password::from(password)).into(),
            ]);
        } else {
            // LZMA2 the way 7-Zip writes it on a multicore box: several
            // independent chunk streams, which is what lets the decoder
            // spread them over its workers. Level 1 because this rig
            // measures reading, not the encoder.
            w.set_content_methods(vec![Lzma2Options::from_level_mt(1, 8, 64 << 20).into()]);
        }
        w.push_archive_entry(
            ArchiveEntry::new_file("movie.mkv"),
            Some(std::fs::File::open(&payload)?),
        )?;
        w.finish()?;
    }
    std::fs::remove_file(&payload)?;

    let mut src = std::fs::File::open(&whole)?;
    let total = src.metadata()?.len();
    let cut = part_mib << 20;
    let mut buf = vec![0u8; 1 << 20];
    let mut idx = 1u32;
    let mut left = total;
    while left > 0 {
        let this = cut.min(left);
        let part = dir.join(format!("set.7z.{idx:03}"));
        let mut out = std::io::BufWriter::new(std::fs::File::create(&part)?);
        let mut done = 0u64;
        while done < this {
            let want = (this - done).min(buf.len() as u64) as usize;
            src.read_exact(&mut buf[..want])?;
            out.write_all(&buf[..want])?;
            done += want as u64;
        }
        out.flush()?;
        left -= this;
        idx += 1;
    }
    std::fs::remove_file(&whole)?;
    println!(
        "GEN kind={kind} container_bytes={total} parts={} part_mib={part_mib}",
        idx - 1
    );
    Ok(())
}

fn parts_of(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("set.7z."))
        })
        .collect();
    v.sort();
    anyhow::ensure!(!v.is_empty(), "no set.7z.NNN parts in {}", dir.display());
    Ok(v)
}

// ----------------------------------------------------------------- the arms

struct Leg {
    wall: f64,
    join: f64,
    user: f64,
    sys: f64,
    peak: u64,
    reads: u64,
    bytes: u64,
    seeks: u64,
}

/// Extract every entry into `out`, exactly as the disk arm does: one
/// `std::io::copy` per entry into a buffered file.
fn drain<R: Read + Seek>(mut reader: sevenz_rust2::ArchiveReader<R>, out: &Path) -> Result<()> {
    reader
        .for_each_entries(|entry, rd| {
            let target = out.join(entry.name.replace('/', "_"));
            if entry.is_directory {
                return Ok(true);
            }
            let mut w = std::io::BufWriter::new(std::fs::File::create(&target)?);
            std::io::copy(rd, &mut w)?;
            w.flush()?;
            Ok(true)
        })
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

fn run_leg(dir: &Path, arm: &str, password: Option<&str>) -> Result<Leg> {
    use sevenz_rust2::{ArchiveReader, Password};
    let parts = parts_of(dir)?;
    let out = dir.join("out");
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out)?;
    let joined = dir.join("joined.7z");
    if arm == "pre" {
        // Arm C isolates the READER from the join: the joined container
        // is already on disk and its cost is outside the timed region,
        // so C against `parts` is the per-read price of the split
        // byte-space and nothing else.
        if !joined.exists() {
            concat_files(&parts, &joined).context("pre-joining the parts")?;
        }
    } else {
        let _ = std::fs::remove_file(&joined);
    }

    let (reads, bytes, seeks) = (
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicU64::new(0)),
    );
    let pw = match password {
        Some(p) if !p.is_empty() => Password::from(p),
        _ => Password::empty(),
    };

    let fp = Footprint::start(dir);
    let (u0, s0) = cpu_now();
    let t0 = Instant::now();
    let mut join_s = 0.0;

    if arm == "join" || arm == "pre" {
        if arm == "join" {
            concat_files(&parts, &joined).context("joining the parts")?;
            join_s = t0.elapsed().as_secs_f64();
        }
        let mut src = Counting {
            inner: std::fs::File::open(&joined)?,
            reads: reads.clone(),
            bytes: bytes.clone(),
            seeks: seeks.clone(),
        };
        if let Some(reason) = nzbkit::nameprobe::sevenz_disk_declared_bomb(&mut src) {
            anyhow::bail!("{reason}");
        }
        src.seek(SeekFrom::Start(0))?;
        drain(
            ArchiveReader::new(src, pw).map_err(|e| anyhow::anyhow!("opening 7z: {e}"))?,
            &out,
        )?;
    } else {
        let mut src = Counting {
            inner: SplitParts::open(&parts)?,
            reads: reads.clone(),
            bytes: bytes.clone(),
            seeks: seeks.clone(),
        };
        if let Some(reason) = nzbkit::nameprobe::sevenz_disk_declared_bomb(&mut src) {
            anyhow::bail!("{reason}");
        }
        src.seek(SeekFrom::Start(0))?;
        drain(
            ArchiveReader::new(src, pw).map_err(|e| anyhow::anyhow!("opening 7z: {e}"))?,
            &out,
        )?;
    }

    let wall = t0.elapsed().as_secs_f64();
    let (u1, s1) = cpu_now();
    let peak = fp.finish();
    let leg = Leg {
        wall,
        join: join_s,
        user: u1 - u0,
        sys: s1 - s0,
        peak,
        reads: reads.load(Ordering::Relaxed),
        bytes: bytes.load(Ordering::Relaxed),
        seeks: seeks.load(Ordering::Relaxed),
    };
    let _ = std::fs::remove_dir_all(&out);
    if arm != "pre" {
        let _ = std::fs::remove_file(&joined);
    }
    Ok(leg)
}

/// The reader on its own, with no decoder above it: pull the whole byte
/// space through `SplitParts` and through a `File` on the joined copy,
/// in the buffer size the layer above actually asks for (AES reads 512
/// bytes at a time; LZMA2 asks for whole chunks). Both files are warm
/// after the first pass, so what this measures is the per-read cost of
/// the split byte-space against a plain file - the question a decode leg
/// cannot answer on a loaded box because the decode dwarfs it.
fn read_bench(dir: &Path, reps: usize) -> Result<()> {
    let parts = parts_of(dir)?;
    let joined = dir.join("joined.7z");
    if !joined.exists() {
        concat_files(&parts, &joined)?;
    }
    for bufsize in [512usize, 65536] {
        let mut buf = vec![0u8; bufsize];
        for rep in 0..reps {
            for arm in ["file", "parts"] {
                let mut src: Box<dyn Read> = if arm == "file" {
                    Box::new(std::fs::File::open(&joined)?)
                } else {
                    Box::new(SplitParts::open(&parts)?)
                };
                let (u0, s0) = cpu_now();
                let t0 = Instant::now();
                let mut total = 0u64;
                let mut calls = 0u64;
                loop {
                    let n = src.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    total += n as u64;
                    calls += 1;
                }
                let wall = t0.elapsed().as_secs_f64();
                let (u1, s1) = cpu_now();
                println!(
                    "READ arm={arm} buf={bufsize} rep={rep} wall_s={wall:.3} \
cpu_s={:.3} calls={calls} bytes={total} ns_per_call={:.1}",
                    u1 - u0 + s1 - s0,
                    (u1 - u0 + s1 - s0) * 1e9 / calls as f64,
                );
            }
        }
    }
    let _ = std::fs::remove_file(&joined);
    Ok(())
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    if v.is_empty() {
        return 0.0;
    }
    v[v.len() / 2]
}

fn suite(dir: &Path, reps: usize, password: Option<&str>) -> Result<()> {
    let parts = parts_of(dir)?;
    let set_bytes: u64 = parts
        .iter()
        .map(|p| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0))
        .sum();
    println!(
        "SET dir={} parts={} set_bytes={set_bytes}",
        dir.display(),
        parts.len()
    );
    let mut legs: Vec<(String, Leg)> = Vec::new();
    for rep in 0..reps {
        for arm in ["join", "parts", "pre"] {
            let leg = run_leg(dir, arm, password)?;
            println!(
                "LEG arm={arm} rep={rep} wall_s={:.3} join_s={:.3} user_s={:.3} sys_s={:.3} \
cpu_s={:.3} peak_bytes={} peak_x={:.3} reads={} read_bytes={} read_x={:.3} seeks={}",
                leg.wall,
                leg.join,
                leg.user,
                leg.sys,
                leg.user + leg.sys,
                leg.peak,
                leg.peak as f64 / set_bytes as f64,
                leg.reads,
                leg.bytes,
                leg.bytes as f64 / set_bytes as f64,
                leg.seeks,
            );
            legs.push((arm.to_string(), leg));
        }
    }
    for arm in ["join", "parts", "pre"] {
        let sel: Vec<&Leg> = legs
            .iter()
            .filter(|(a, _)| a == arm)
            .map(|(_, l)| l)
            .collect();
        println!(
            "MEDIAN arm={arm} wall_s={:.3} cpu_s={:.3} user_s={:.3} sys_s={:.3} peak_x={:.3} read_x={:.3}",
            median(sel.iter().map(|l| l.wall).collect()),
            median(sel.iter().map(|l| l.user + l.sys).collect()),
            median(sel.iter().map(|l| l.user).collect()),
            median(sel.iter().map(|l| l.sys).collect()),
            median(
                sel.iter()
                    .map(|l| l.peak as f64 / set_bytes as f64)
                    .collect()
            ),
            median(
                sel.iter()
                    .map(|l| l.bytes as f64 / set_bytes as f64)
                    .collect()
            ),
        );
    }
    let _ = std::fs::remove_file(dir.join("joined.7z"));
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    let dir = PathBuf::from(args.get(2).map(String::as_str).unwrap_or("."));
    match cmd {
        "gen" => {
            let kind = args.get(3).map(String::as_str).unwrap_or("plain");
            let payload = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(1024);
            let part = args.get(5).and_then(|s| s.parse().ok()).unwrap_or(100);
            let pw = args
                .get(6)
                .map(String::as_str)
                .unwrap_or("todo-212-mhe-key");
            make_set(&dir, kind, payload, part, pw)?;
        }
        "readbench" => {
            let reps = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(5);
            read_bench(&dir, reps)?;
        }
        "suite" => {
            let reps = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(3);
            let pw = args.get(4).map(String::as_str);
            suite(&dir, reps, pw)?;
        }
        _ => {
            eprintln!(
                "usage: sevenz_join_ab gen <dir> <plain|mhe> <payload_mib> <part_mib> [pw]\n\
                        sevenz_join_ab suite <dir> <reps> [pw]\n\
                        sevenz_join_ab readbench <dir> <reps>"
            );
            std::process::exit(2);
        }
    }
    Ok(())
}
