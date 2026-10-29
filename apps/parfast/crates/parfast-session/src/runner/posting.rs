//! The posting set: files in, a RAR 5 archive or volume set and a PAR2
//! set over it out, as one job (plan B1,
//! `research/PLAN-PARFAST-APP-RARFAST-AND-1.0-2026-10-25.md`).
//!
//! # Two routes, and why only one of them is one pass
//!
//! The design target was ONE pass: the archive's bytes fed into the PAR2
//! create as they are written, so the set is never read back. That is
//! possible for exactly one shape, and the reason is the PAR2 format,
//! not this code.
//!
//! PAR2's recovery data is a sum over GLOBAL input-slice indices, and the
//! index space runs over the files in the order of their file ids, which
//! the Main packet sorts. A file id hashes the file's LENGTH. So no slice
//! of a volume set can be folded until every volume's length is known,
//! which is the moment the last volume is finished - and the fold is the
//! whole cost of creating over volumes (measured: 1.08 s of a 1.23 s
//! create over 41 volumes of 100 MB). Holding the volumes in memory
//! until then is holding the archive. So:
//!
//! - **`one_pass`**: ONE archive (`volumes: none`), STORED. Its PAR2 set
//!   has one member, the index of a slice is its position in the stream,
//!   and [`nzbkit::par2gen::StreamCreate`] folds each slice as it is
//!   written. What this saves is the archive write itself, which runs
//!   under the PAR2 create's whole-file MD5 chain instead of before it.
//! - **`two_pass`**: everything else. The archive or volumes are written
//!   to files that can be patched (so rarkit holds nothing), then the
//!   ordinary create runs over them through [`super::run_create`], the
//!   same code the Create pane runs.
//!
//! STORED, because rarkit can only stream a member to an output that
//! cannot be patched when it knows the member's CRC32 and PACKED size
//! before the member's header: a stored member's packed size is its
//! size, and its CRC32 comes from a parallel pre-read of the sources
//! ([`source_crcs`]). A compressed member's packed size is known only
//! after it is compressed, so rarkit would hold the whole member in
//! memory; that shape takes `two_pass`. Measured 25 Oct 2026 against
//! rarkit 0.9.0: with an output that cannot patch and no CRC given, a
//! stored 1 GiB member is held whole (1.09 GB RSS); with the CRC given,
//! nothing is held.
//!
//! The source files ARE read twice on the one-pass route (the CRC
//! pre-read, then the archive write). That read is of the sources, in
//! parallel, usually from the page cache the user just filled; the
//! archive's own bytes are never read back.
//!
//! # Every filesystem effect is here
//!
//! rarkit does none: it is handed readers and writers. Output names,
//! volume names (decided once the volume count is known, because the
//! number's width depends on it), the overwrite rule, removal of a
//! failed or cancelled job's files, and the archive members' stored
//! times and modes are all this module's.

use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use nzbkit::par2gen::StreamCreate;

use super::*;
use crate::job::{
    CreateSpec, PathMode, PostingResult, PostingSetSpec, RarVolumes, Source, UnicodePolicy,
    VolumeSpec,
};
use crate::planner::PlannedMember;

/// A refusal on its way back to `run`, boxed because an [`Outcome`] is
/// large and travels in an `Err`.
type Refused = Box<Outcome>;

fn refuse(code: &'static str, message: impl Into<String>) -> Refused {
    Box::new(Outcome::failed(code, message))
}

/// The route names a result reports.
const ONE_PASS: &str = "one_pass";
const TWO_PASS: &str = "two_pass";

/// The share of the bar the RAR half takes on the two-pass route; the
/// PAR2 create fills the rest.
const RAR_BAND: f64 = 0.45;

/// Run one posting-set job.
pub(super) fn run(job: &Job, spec: &PostingSetSpec, _started: Instant) -> Outcome {
    if let Err(e) = check_spec(spec) {
        return *e;
    }
    let password = match &spec.rar.password {
        None => None,
        Some(p) => match p.given() {
            Some(pw) if !pw.is_empty() => Some(pw.to_string()),
            Some(_) => return Outcome::failed("bad_spec", "the password is empty"),
            None => {
                return Outcome::failed(
                    "password_required",
                    "this posting set was saved without its password; submit it again \
                     with the password",
                );
            }
        },
    };
    let planner::Expansion { members, left_out } = match planner::expand_sources(
        &spec.sources,
        spec.path_mode,
        spec.base_path.as_deref(),
        planner::SourceRules::Par2,
    ) {
        Ok(m) => m,
        Err(e) => return Outcome::failed(e.code, e.message),
    };
    let coverage = left_out.lines();
    let mut sink = sink_for(job);
    for line in &coverage {
        sink.line(Level::Terse, line);
    }
    if let Err(e) = clear_or_refuse(spec) {
        return *e;
    }
    apply_knobs(
        spec.perf.threads.or(job.settings.performance.threads),
        spec.perf.memory_mb.or(job.settings.performance.memory_mb),
        job.settings.performance.digest_cache,
    );
    let source_bytes: u64 = members.iter().map(|m| m.length).sum();
    let ctx = Ctx {
        job,
        spec,
        members: &members,
        password: password.as_deref(),
        source_bytes,
    };
    let why_not = one_pass_refusal(spec);
    let outcome = match why_not {
        None => one_pass(&ctx, &mut sink),
        Some(reason) => {
            sink.line(Level::Normal, &format!("Two passes: {reason}"));
            two_pass(&ctx, reason)
        }
    };
    // Whatever a failed or cancelled job wrote is removed, both halves:
    // a partial archive beside a PAR2 set that does not describe it is
    // the one thing a posting must never carry.
    if outcome.state != JobState::Done {
        remove_set(spec);
    }
    with_coverage(outcome, coverage)
}

/// Everything both routes read.
struct Ctx<'a> {
    job: &'a Job,
    spec: &'a PostingSetSpec,
    members: &'a [PlannedMember],
    password: Option<&'a str>,
    source_bytes: u64,
}

/// The refusals a spec earns before anything is read.
fn check_spec(spec: &PostingSetSpec) -> Result<(), Refused> {
    let name = spec.name.trim();
    if name.is_empty()
        || name != spec.name
        || name.contains(['/', '\\'])
        || name == "."
        || name == ".."
    {
        return Err(refuse(
            "bad_spec",
            format!(
                "{:?} is not a name a set can take: one file name, no folders",
                spec.name
            ),
        ));
    }
    if !spec.output_dir.is_dir() {
        return Err(refuse(
            "bad_spec",
            format!("{} is not a folder", spec.output_dir.display()),
        ));
    }
    if spec.rar.compression > 5 {
        return Err(refuse(
            "bad_spec",
            format!(
                "compression {} is not a level: 0 is store, 1 to 5 compress",
                spec.rar.compression
            ),
        ));
    }
    match spec.rar.volumes {
        RarVolumes::Size { size } if size < 64 << 10 => Err(refuse(
            "bad_spec",
            format!("a volume of {size} bytes is too small; the least is 64 KiB"),
        )),
        RarVolumes::Count { count } if count < 2 => Err(refuse(
            "bad_spec",
            "a volume count is at least 2; for one archive choose no split",
        )),
        _ => Ok(()),
    }
}

/// Why this spec cannot take the one-pass route, or `None` when it can.
/// The memory check comes later, once the PAR2 geometry is known.
fn one_pass_refusal(spec: &PostingSetSpec) -> Option<String> {
    if spec.rar.volumes != RarVolumes::None {
        return Some(
            "a volume set's PAR2 recovery data can only be computed once every volume \
             is written (PAR2 orders its files by an id that hashes each file's length)"
                .to_string(),
        );
    }
    if spec.rar.compression != 0 {
        return Some(
            "a compressed archive streams only to a file that can be rewritten in place, \
             so it is written first and its PAR2 set made from the file"
                .to_string(),
        );
    }
    if spec.rar.recovery_percent > 0 {
        return Some(
            "a RAR recovery record is computed over the finished archive, which a file \
             that can be read back provides and a stream does not"
                .to_string(),
        );
    }
    if std::env::var("PARFAST_POSTING_TWO_PASS").as_deref() == Ok("1") {
        // The measurement control: the same job, forced the other way.
        return Some("forced by PARFAST_POSTING_TWO_PASS=1".to_string());
    }
    None
}

// ---------------------------------------------------------------------
// Names on disk
// ---------------------------------------------------------------------

/// Whether `file` belongs to the set called `name`: its RAR half
/// (`name.rar`, `name.partN.rar`, and the `.partial` names this module
/// writes volumes under before their final names are known) or its PAR2
/// half (`super::set_member`'s rule).
fn posting_member(name: &str, file: &str) -> bool {
    let Some(rest) = file.strip_prefix(name) else {
        return false;
    };
    let lower = rest.to_ascii_lowercase();
    if lower == ".rar" || super::set_member(name, file) {
        return true;
    }
    let lower = lower.strip_suffix(PARTIAL).unwrap_or(&lower);
    lower
        .strip_prefix(".part")
        .and_then(|r| r.strip_suffix(".rar"))
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
}

/// The suffix a volume is written under until the set's volume count,
/// and so its final name, is known.
const PARTIAL: &str = ".partial";

/// Every file of a set called `spec.name` in the output folder.
fn existing_members(spec: &PostingSetSpec) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(&spec.output_dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| posting_member(&spec.name, &e.file_name().to_string_lossy()))
        .map(|e| e.path())
        .collect();
    found.sort();
    found
}

/// The overwrite rule: refuse if a set is there and the spec did not
/// say replace it; remove all of it if the spec did.
fn clear_or_refuse(spec: &PostingSetSpec) -> Result<(), Refused> {
    let there = existing_members(spec);
    if there.is_empty() {
        return Ok(());
    }
    if !spec.overwrite {
        return Err(refuse(
            "exists",
            format!("{} already exists", there[0].display()),
        ));
    }
    for p in there {
        if let Err(e) = std::fs::remove_file(&p) {
            return Err(refuse(
                "exists",
                format!("{} could not be replaced: {e}", p.display()),
            ));
        }
    }
    Ok(())
}

/// Remove whatever this job wrote, on a failure or a cancel. The set was
/// absent when the job started (`clear_or_refuse`), so every file under
/// the name is this job's.
fn remove_set(spec: &PostingSetSpec) {
    for p in existing_members(spec) {
        let _ = std::fs::remove_file(p);
    }
}

fn with_coverage(mut o: Outcome, coverage: Vec<String>) -> Outcome {
    if coverage.is_empty() {
        return o;
    }
    let result = o.result.get_or_insert_with(JobResult::default);
    let mut w = coverage;
    w.append(&mut result.warnings);
    result.warnings = w;
    o
}

// ---------------------------------------------------------------------
// The RAR half
// ---------------------------------------------------------------------

/// The writer options a spec asks for. `volume_cap` is the resolved
/// volume FILE size, or `None` for one archive.
fn write_options(
    spec: &PostingSetSpec,
    password: Option<&str>,
    volume_cap: Option<u64>,
    threads: Option<usize>,
) -> rarkit::WriteOptions {
    rarkit::WriteOptions {
        format: rarkit::WriteFormat::Rar5,
        method: if spec.rar.compression == 0 {
            rarkit::WriteMethod::Stored
        } else {
            rarkit::WriteMethod::Compressed {
                level: spec.rar.compression,
                dictionary: None,
            }
        },
        solid: spec.rar.solid,
        password: password.map(|p| rarkit::Password::new(p.as_bytes().to_vec())),
        encrypt_headers: password.is_some() && spec.rar.encrypt_headers,
        volume_file_size: volume_cap,
        recovery_percent: (spec.rar.recovery_percent > 0).then_some(spec.rar.recovery_percent),
        workers: threads.filter(|&t| t > 0),
        // Every member is its own file, so its reader shares no source
        // with another: the promise the read-ahead asks a caller to
        // make, and the one rarfast makes for the same reason.
        encrypted_read_ahead: true,
        ..Default::default()
    }
}

/// The volume FILE size a spec resolves to. A count divides an
/// estimate of the archive - the payload, each member's header and each
/// volume's own - rounded up to 4 KiB, so the set comes out at about the
/// count asked; the result lists what was written.
fn volume_cap(spec: &PostingSetSpec, members: &[PlannedMember]) -> Option<u64> {
    match spec.rar.volumes {
        RarVolumes::None => None,
        RarVolumes::Size { size } => Some(size),
        RarVolumes::Count { count } => {
            let count = u64::from(count.max(1));
            let estimate: u64 = members
                .iter()
                .map(|m| m.length + 128 + m.name.len() as u64)
                .sum::<u64>()
                + count * 256;
            Some(estimate.div_ceil(count).div_ceil(4096) * 4096)
        }
    }
}

/// An upper bound on the archive a STORED write of `members` produces:
/// the payload, plus a generous allowance per member for its header and
/// the cipher's padding, plus one for the archive's own headers. The
/// PAR2 block size is chosen from this before the archive exists, so it
/// errs high: a high bound costs a slightly larger block, a low one
/// would cost the one-pass route.
fn archive_bound(members: &[PlannedMember], recovery_percent: u32) -> u64 {
    let payload: u64 = members.iter().map(|m| m.length).sum();
    let headers: u64 = members
        .iter()
        .map(|m| 512 + 2 * m.name.len() as u64)
        .sum::<u64>()
        + (64 << 10);
    let bound = payload + headers;
    bound + bound / 100 * u64::from(recovery_percent) + (1 << 20)
}

/// One opened member, ready to hand to the writer.
struct Opened {
    file: File,
    name: Vec<u8>,
    size: u64,
    mtime: Option<rarkit::Timestamp>,
    attributes: u32,
}

fn open_members(members: &[PlannedMember]) -> Result<Vec<Opened>, Refused> {
    members
        .iter()
        .map(|m| {
            let file = File::open(&m.path).map_err(|e| {
                refuse(
                    "io",
                    format!("{} could not be opened: {e}", m.path.display()),
                )
            })?;
            let meta = file.metadata().map_err(|e| {
                refuse("io", format!("{} could not be read: {e}", m.path.display()))
            })?;
            Ok(Opened {
                name: m.name.as_bytes().to_vec(),
                size: meta.len(),
                mtime: meta.modified().ok().and_then(timestamp),
                attributes: attributes_of(&meta),
                file,
            })
        })
        .collect()
}

fn timestamp(t: std::time::SystemTime) -> Option<rarkit::Timestamp> {
    let d = t.duration_since(std::time::UNIX_EPOCH).ok()?;
    Some(rarkit::Timestamp {
        unix_seconds: i64::try_from(d.as_secs()).ok()?,
        nanos: d.subsec_nanos(),
    })
}

/// The attribute word rarfast stores for a file on this host: the mode
/// on unix, the DOS word on Windows.
#[cfg(unix)]
fn attributes_of(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    meta.mode()
}
#[cfg(windows)]
fn attributes_of(meta: &std::fs::Metadata) -> u32 {
    use std::os::windows::fs::MetadataExt;
    meta.file_attributes()
}
#[cfg(not(any(unix, windows)))]
fn attributes_of(_meta: &std::fs::Metadata) -> u32 {
    0
}

fn host_os() -> rarkit::HostOs {
    if cfg!(windows) {
        rarkit::HostOs::Windows
    } else {
        rarkit::HostOs::Unix
    }
}

/// Add every member to `writer`, with its CRC32 where one is known.
fn add_members<'a>(
    writer: &mut rarkit::Writer<'a>,
    opened: &'a mut [Opened],
    crcs: Option<&[u32]>,
) -> Result<(), rarkit::Error> {
    for (i, o) in opened.iter_mut().enumerate() {
        writer.add(rarkit::MemberSpec {
            name: &o.name,
            payload: rarkit::Payload::Reader {
                reader: &mut o.file,
                size: o.size,
                crc32: crcs.map(|c| c[i]),
            },
            mtime: o.mtime,
            attributes: o.attributes,
            host_os: host_os(),
            is_directory: false,
        })?;
    }
    Ok(())
}

/// The writer's progress and the job's cancel and pause: rarkit calls
/// `output` as member bytes go in, and an error from it ends the write.
struct RarProgress<'a> {
    job: &'a Job,
    total: u64,
    band: (f64, f64),
    label: &'static str,
    last_pct: u64,
}

impl rarkit::Progress for RarProgress<'_> {
    fn output(&mut self, done: u64) -> rarkit::Result<()> {
        // A park site: the writing thread, between two pieces of output,
        // holding nothing another thread waits on (helpers that read
        // ahead fill their buffers and stop).
        if self.job.control.is_paused() && !gated(self.job) {
            return Err(rarkit::Error::caller(Cancelled));
        }
        if self.job.control.is_cancelled() {
            return Err(rarkit::Error::caller(Cancelled));
        }
        let frac = if self.total == 0 {
            1.0
        } else {
            (done as f64 / self.total as f64).min(1.0)
        };
        let pct = (frac * 100.0) as u64;
        if pct != self.last_pct {
            self.last_pct = pct;
            let (base, span) = self.band;
            let label = self.label;
            self.job.publisher.update(|s| {
                s.phase = Phase::Writing;
                s.phase_text = format!("{label} - {pct}%");
                s.progress = s.progress.max(base + span * frac);
            });
        }
        Ok(())
    }
}

/// The error a cancel is raised through rarkit's progress channel as.
#[derive(Debug)]
struct Cancelled;
impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("cancelled")
    }
}
impl std::error::Error for Cancelled {}

fn rar_failure(job: &Job, e: &rarkit::Error) -> Outcome {
    if job.control.is_cancelled() {
        return Outcome::cancelled();
    }
    Outcome::failed(
        "rar_failed",
        format!("the RAR archive could not be written: {e}"),
    )
}

// ---------------------------------------------------------------------
// The CRC pre-read (one-pass route only)
// ---------------------------------------------------------------------

/// Each member's CRC32, read in parallel: big members in 64 MiB pieces
/// on every worker, combined in order. `None` on a cancel; an error
/// names the file.
fn source_crcs(job: &Job, members: &[PlannedMember]) -> Result<Option<Vec<u32>>, Refused> {
    const PIECE: u64 = 64 << 20;
    let pieces: Vec<(usize, u64, u64)> = members
        .iter()
        .enumerate()
        .flat_map(|(i, m)| {
            let n = m.length.div_ceil(PIECE).max(1);
            (0..n).map(move |k| (i, k * PIECE, PIECE.min(m.length - k * PIECE)))
        })
        .collect();
    let total: u64 = members.iter().map(|m| m.length).sum();
    let next = std::sync::atomic::AtomicUsize::new(0);
    let done = std::sync::atomic::AtomicU64::new(0);
    let shown = std::sync::atomic::AtomicU64::new(0);
    let results: Mutex<Vec<Option<u32>>> = Mutex::new(vec![None; pieces.len()]);
    let failed: Mutex<Option<String>> = Mutex::new(None);
    let files: Vec<std::io::Result<File>> = members.iter().map(|m| File::open(&m.path)).collect();
    let workers = nzbkit::mem::cpu_workers()
        .clamp(1, 16)
        .min(pieces.len().max(1));
    std::thread::scope(|sc| {
        for _ in 0..workers {
            sc.spawn(|| {
                let mut buf = vec![0u8; PIECE as usize];
                loop {
                    if job.control.is_cancelled()
                        || failed.lock().map(|f| f.is_some()).unwrap_or(true)
                    {
                        return;
                    }
                    let k = next.fetch_add(1, Ordering::Relaxed);
                    let Some(&(i, at, len)) = pieces.get(k) else {
                        return;
                    };
                    let path = &members[i].path;
                    let read = match &files[i] {
                        Ok(f) => nzbkit::disk::read_exact_at(f, &mut buf[..len as usize], at),
                        Err(e) => Err(std::io::Error::new(e.kind(), e.to_string())),
                    };
                    if let Err(e) = read {
                        *failed.lock().unwrap_or_else(|p| p.into_inner()) =
                            Some(format!("{} could not be read: {e}", path.display()));
                        return;
                    }
                    let crc = nzbkit::yenc_simd::crc32(&buf[..len as usize], 0);
                    results.lock().unwrap_or_else(|p| p.into_inner())[k] = Some(crc);
                    let d = done.fetch_add(len, Ordering::Relaxed) + len;
                    let frac = if total == 0 {
                        1.0
                    } else {
                        d as f64 / total as f64
                    };
                    // The host is rung once per whole percent and no more:
                    // the wake contract is "at most ~20 a second", and a
                    // piece a millisecond is far past that on a warm cache.
                    let pct = (frac * 100.0) as u64;
                    if shown.fetch_max(pct, Ordering::Relaxed) < pct {
                        job.publisher.update(|s| {
                            s.phase = Phase::Scanning;
                            s.phase_text = format!("Reading the source files - {pct}%");
                            s.progress = s.progress.max(0.10 * frac);
                        });
                    }
                }
            });
        }
    });
    if let Some(msg) = failed.into_inner().unwrap_or_else(|p| p.into_inner()) {
        return Err(refuse("io", msg));
    }
    if job.control.is_cancelled() {
        return Ok(None);
    }
    let results = results.into_inner().unwrap_or_else(|p| p.into_inner());
    let mut crcs = vec![0u32; members.len()];
    let mut seen = vec![false; members.len()];
    for (k, &(i, _, len)) in pieces.iter().enumerate() {
        let c = results[k].expect("every piece was read");
        crcs[i] = if seen[i] {
            nzbkit::yenc_simd::crc32_combine(crcs[i], c, len)
        } else {
            c
        };
        seen[i] = true;
    }
    Ok(Some(crcs))
}

// ---------------------------------------------------------------------
// One pass
// ---------------------------------------------------------------------

/// The archive's bytes go to the file AND into the streamed PAR2 create.
/// A failure on either side is held and reported as an I/O error, which
/// is what ends rarkit's write.
struct Tee<'a> {
    file: BufWriter<File>,
    stream: &'a mut StreamCreate,
    stream_error: Option<nzbkit::par2gen::Par2GenError>,
}

impl Write for Tee<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write_all(buf)?;
        if let Err(e) = self.stream.write(buf) {
            self.stream_error = Some(e);
            return Err(std::io::Error::other("the PAR2 half stopped"));
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

/// The PAR2 options a posting set's create runs under, over `members`
/// as the planner sees them. `members` is the finished volumes on the
/// two-pass route, and one estimated archive on the one-pass route.
fn par2_spec(ctx: &Ctx<'_>, sources: Vec<Source>) -> CreateSpec {
    let d = &ctx.job.settings.create;
    let p = &ctx.spec.par2;
    let block = p.block.or(Some(match d.block_allocation {
        crate::settings::BlockAllocation::Count => crate::job::BlockSpec::Count {
            count: d.block_count,
        },
        crate::settings::BlockAllocation::Size => {
            crate::job::BlockSpec::Size { size: d.block_size }
        }
    }));
    let recovery = p.recovery.or(Some(match d.recovery_allocation {
        crate::settings::RecoveryAllocation::Percent => crate::job::RecoverySpec::Percent {
            percent: d.recovery_percent,
        },
        crate::settings::RecoveryAllocation::Count => crate::job::RecoverySpec::Count {
            count: d.recovery_count,
        },
        crate::settings::RecoveryAllocation::Size => crate::job::RecoverySpec::Size {
            size: d.recovery_size,
        },
    }));
    let volumes = p.volumes.clone().unwrap_or_else(|| scheme_from(&d.scheme));
    CreateSpec {
        sources,
        path_mode: PathMode::Basename,
        base_path: None,
        block,
        recovery,
        output: ctx.spec.output_dir.join(format!("{}.par2", ctx.spec.name)),
        volumes,
        first_recovery_block: p.first_recovery_block,
        comment: p.comment.clone(),
        overwrite: ctx.spec.overwrite,
        std_naming: p.std_naming.unwrap_or(d.std_naming),
        unicode: UnicodePolicy::Auto,
        perf: ctx.spec.perf,
    }
}

/// The Settings pane's scheme word as a volume spec. Only the two
/// schemes a word can name without numbers; anything else is the
/// engine's default split.
fn scheme_from(word: &str) -> VolumeSpec {
    match word {
        "none" => VolumeSpec::None,
        _ => VolumeSpec::Pow2,
    }
}

fn one_pass(ctx: &Ctx<'_>, sink: &mut Sink) -> Outcome {
    let job = ctx.job;
    let spec = ctx.spec;
    let dir = &spec.output_dir;
    let archive_name = format!("{}.rar", spec.name);
    let archive_path = dir.join(&archive_name);
    let bound = archive_bound(ctx.members, spec.rar.recovery_percent);

    // The PAR2 geometry, from the bound: the block size and the most
    // recovery slices the stream may be asked for.
    let par = par2_spec(ctx, Vec::new());
    let estimated = PlannedMember {
        path: archive_path.clone(),
        name: archive_name.clone(),
        length: bound,
    };
    let (opts, warnings) = match planner::options_for(&par, std::slice::from_ref(&estimated)) {
        Ok(v) => v,
        Err(e) => return Outcome::failed(e.code, e.message),
    };
    for w in &warnings {
        sink.line(Level::Normal, w);
    }
    let (bs, _) = parfast::create::block_size(&opts, &[bound]);
    let rows =
        parfast::create::recovery_blocks(&opts, parfast::create::slice_total(&[bound], bs), bs)
            as usize;
    if !StreamCreate::fits(bs, rows) {
        let reason = format!(
            "{rows} recovery blocks of {bs} bytes do not fit one pass under the memory limit"
        );
        sink.line(Level::Normal, &format!("Two passes: {reason}"));
        return two_pass(ctx, reason);
    }

    let crcs = match source_crcs(job, ctx.members) {
        Ok(Some(c)) => c,
        Ok(None) => return Outcome::cancelled(),
        Err(o) => return *o,
    };

    let control =
        nzbkit::par2gen::control::CreateControl::new(None, Some(job.control.engine_gate()));
    let mut stream = match StreamCreate::new(
        dir,
        &spec.name,
        &archive_name,
        bs,
        rows,
        opts.first_block as usize,
        bound,
        control,
    ) {
        Ok(s) => s,
        Err(e) => return Outcome::failed("create_failed", e.to_string()),
    };
    let file = match File::options()
        .write(true)
        .create_new(true)
        .open(&archive_path)
    {
        Ok(f) => f,
        Err(e) => {
            return Outcome::failed(
                "exists",
                format!("{} could not be created: {e}", archive_path.display()),
            );
        }
    };
    let mut opened = match open_members(ctx.members) {
        Ok(o) => o,
        Err(o) => return *o,
    };
    let threads = spec.perf.threads.or(job.settings.performance.threads);
    let mut writer = match rarkit::Writer::new(write_options(spec, ctx.password, None, threads)) {
        Ok(w) => w,
        Err(e) => return Outcome::failed("bad_spec", format!("RAR options refused: {e}")),
    };
    if let Err(e) = add_members(&mut writer, &mut opened, Some(&crcs)) {
        return Outcome::failed("rar_failed", e.to_string());
    }
    job.publisher.update(|s| {
        s.command = String::new();
        s.phase = Phase::Writing;
        s.phase_text = "Writing the archive and its recovery set".to_string();
    });
    let mut tee = Tee {
        file: BufWriter::with_capacity(8 << 20, file),
        stream: &mut stream,
        stream_error: None,
    };
    let mut progress = RarProgress {
        job,
        total: ctx.source_bytes,
        band: (0.10, 0.85),
        label: "Writing the archive and its recovery set",
        last_pct: u64::MAX,
    };
    let wrote = writer.finish_into_with(&mut tee, &mut progress);
    let flushed = tee.file.flush();
    let stream_error = tee.stream_error.take();
    drop(tee);
    if let Some(e) = stream_error {
        return match e {
            nzbkit::par2gen::Par2GenError::Cancelled => Outcome::cancelled(),
            e => Outcome::failed("create_failed", e.to_string()),
        };
    }
    let report = match wrote {
        Ok(r) => r,
        Err(e) => return rar_failure(job, &e),
    };
    if let Err(e) = flushed {
        return Outcome::failed("io", format!("{}: {e}", archive_path.display()));
    }
    sink.line(
        Level::Normal,
        &format!(
            "Wrote {} ({} bytes) and hashed it as it went",
            archive_name, report.bytes
        ),
    );

    // The set, from what the stream saw: the real length decides the
    // recovery count the options ask for, which the bound kept within
    // the rows the stream was sized for.
    let length = stream.len();
    let recovery =
        parfast::create::recovery_blocks(&opts, parfast::create::slice_total(&[length], bs), bs);
    let Ok(recovery_n) = usize::try_from(recovery) else {
        return Outcome::failed("create_failed", "recovery count out of range");
    };
    if recovery_n > rows {
        // The bound was wrong. The archive is finished and on disk, so
        // the set is made from it, which is always correct.
        drop(stream);
        return two_pass_par2(ctx, vec![archive_path], "the archive outgrew its estimate");
    }
    let plan = parfast::create::create_plan(&opts, recovery, length, bs);
    job.publisher.update(|s| {
        s.phase = Phase::Writing;
        s.phase_text = "Writing the recovery volumes".to_string();
        s.progress = s.progress.max(0.95);
    });
    let names = match stream.finish(recovery_n, plan, opts.comment.as_deref()) {
        Ok(n) => n,
        Err(nzbkit::par2gen::Par2GenError::Cancelled) => return Outcome::cancelled(),
        Err(e) => return Outcome::failed("create_failed", e.to_string()),
    };
    let unpublished = parfast::create::rename_volumes(
        dir,
        &spec.name,
        &names,
        opts.first_block,
        recovery,
        opts.std_naming,
        opts.no_clobber,
    );
    if !unpublished.is_empty() {
        let (from, to, why) = &unpublished[0];
        return Outcome::failed(
            "create_failed",
            format!("could not name {from} as {to}: {why}"),
        );
    }
    done(ctx, ONE_PASS, String::new(), vec![archive_path])
}

// ---------------------------------------------------------------------
// Two passes
// ---------------------------------------------------------------------

/// Volumes written to files that can be patched and read back, so
/// rarkit holds nothing, under `.partial` names until the count is
/// known.
struct FileVolumes<'a> {
    dir: &'a Path,
    name: &'a str,
    written: Vec<PathBuf>,
}

impl FileVolumes<'_> {
    fn partial(&self, index: u32) -> PathBuf {
        self.dir
            .join(format!("{}.part{}.rar{PARTIAL}", self.name, index + 1))
    }
}

impl rarkit::VolumeOut for FileVolumes<'_> {
    type W = File;

    fn volume(&mut self, index: u32) -> rarkit::Result<File> {
        let path = self.partial(index);
        let f = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(rarkit::Error::caller)?;
        self.written.push(path);
        Ok(f)
    }

    fn can_patch(&self) -> bool {
        true
    }

    fn patch(&mut self, volume: &mut File, at: u64, bytes: &[u8]) -> rarkit::Result<()> {
        let end = volume.stream_position().map_err(rarkit::Error::caller)?;
        volume
            .seek(SeekFrom::Start(at))
            .map_err(rarkit::Error::caller)?;
        volume.write_all(bytes).map_err(rarkit::Error::caller)?;
        volume
            .seek(SeekFrom::Start(end))
            .map_err(rarkit::Error::caller)?;
        Ok(())
    }

    fn can_read_back(&self) -> bool {
        true
    }

    fn read_back(&mut self, volume: &mut File, at: u64, buf: &mut [u8]) -> rarkit::Result<()> {
        let end = volume.stream_position().map_err(rarkit::Error::caller)?;
        volume
            .seek(SeekFrom::Start(at))
            .map_err(rarkit::Error::caller)?;
        volume.read_exact(buf).map_err(rarkit::Error::caller)?;
        volume
            .seek(SeekFrom::Start(end))
            .map_err(rarkit::Error::caller)?;
        Ok(())
    }
}

fn two_pass(ctx: &Ctx<'_>, reason: String) -> Outcome {
    let job = ctx.job;
    let spec = ctx.spec;
    let dir = &spec.output_dir;
    let mut opened = match open_members(ctx.members) {
        Ok(o) => o,
        Err(o) => return *o,
    };
    let threads = spec.perf.threads.or(job.settings.performance.threads);
    let cap = volume_cap(spec, ctx.members);
    let mut writer = match rarkit::Writer::new(write_options(spec, ctx.password, cap, threads)) {
        Ok(w) => w,
        Err(e) => return Outcome::failed("bad_spec", format!("RAR options refused: {e}")),
    };
    if let Err(e) = add_members(&mut writer, &mut opened, None) {
        return Outcome::failed("rar_failed", e.to_string());
    }
    let mut progress = RarProgress {
        job,
        total: ctx.source_bytes,
        band: (0.0, RAR_BAND),
        label: "Writing the archive",
        last_pct: u64::MAX,
    };
    job.publisher.update(|s| {
        s.phase = Phase::Writing;
        s.phase_text = "Writing the archive".to_string();
    });
    let rar_files: Vec<PathBuf> = if cap.is_none() {
        // One archive, to a file that seeks and reads back.
        let path = dir.join(format!("{}.rar", spec.name));
        let file = match File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) => {
                return Outcome::failed(
                    "exists",
                    format!("{} could not be created: {e}", path.display()),
                );
            }
        };
        if let Err(e) = writer.finish_seek_read_with(file, &mut progress) {
            return rar_failure(job, &e);
        }
        vec![path]
    } else {
        let mut out = FileVolumes {
            dir,
            name: &spec.name,
            written: Vec::new(),
        };
        if let Err(e) = writer.finish_volumes_with(&mut out, &mut progress) {
            return rar_failure(job, &e);
        }
        // The count is known now, and with it the width of every
        // volume's number: the names rarkit's own rule gives.
        let total = out.written.len() as u32;
        let mut finals = Vec::with_capacity(out.written.len());
        for (i, from) in out.written.iter().enumerate() {
            let to = dir.join(rarkit::volume_file_name(
                &spec.name,
                i as u32,
                total,
                rarkit::VolumeNaming::Numbered,
            ));
            if to.exists() {
                return Outcome::failed("exists", format!("{} already exists", to.display()));
            }
            if let Err(e) = std::fs::rename(from, &to) {
                return Outcome::failed("io", format!("{}: {e}", to.display()));
            }
            finals.push(to);
        }
        finals
    };
    if job.control.is_cancelled() {
        return Outcome::cancelled();
    }
    two_pass_par2(ctx, rar_files, &reason)
}

/// The PAR2 half over finished RAR files: the Create pane's own create,
/// on the second band of the bar.
fn two_pass_par2(ctx: &Ctx<'_>, rar_files: Vec<PathBuf>, reason: &str) -> Outcome {
    let sources = rar_files
        .iter()
        .map(|p| Source {
            path: p.clone(),
            recursive: false,
        })
        .collect();
    let par = par2_spec(ctx, sources);
    let created = run_create_banded(ctx.job, &par, (RAR_BAND, 1.0 - RAR_BAND));
    if created.state != JobState::Done {
        return created;
    }
    done(ctx, TWO_PASS, reason.to_string(), rar_files)
}

/// The finished job's outcome: every file of both halves, from disk.
fn done(ctx: &Ctx<'_>, route: &str, reason: String, rar_files: Vec<PathBuf>) -> Outcome {
    let spec = ctx.spec;
    let size = |p: &Path| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
    let rar: Vec<WrittenFile> = rar_files
        .iter()
        .map(|p| WrittenFile {
            name: p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            size: size(p),
        })
        .collect();
    let mut par2: Vec<WrittenFile> = std::fs::read_dir(&spec.output_dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            super::set_member(&spec.name, &name).then(|| WrittenFile {
                size: size(&e.path()),
                name,
            })
        })
        .collect();
    // The index first, then the volumes in exponent order - which is
    // name order once the index is set aside.
    par2.sort_by_key(|f| (f.name.to_ascii_lowercase().contains(".vol"), f.name.clone()));
    let written: Vec<WrittenFile> = rar.iter().chain(par2.iter()).cloned().collect();
    Outcome {
        state: JobState::Done,
        result: Some(JobResult {
            written,
            exit_code: Some(parfast::EXIT_SUCCESS),
            posting: Some(PostingResult {
                route: route.to_string(),
                route_reason: reason,
                rar,
                par2,
                source_bytes: ctx.source_bytes,
                source_files: ctx.members.len() as u64,
            }),
            ..Default::default()
        }),
        error: None,
        survey: None,
        // Both halves are on disk and named; a late cancel does not
        // unmake them, for the create's own reason (`run_create`).
        committed: true,
    }
}

#[cfg(test)]
mod tests;
