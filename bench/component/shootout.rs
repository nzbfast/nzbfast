// One race harness, built from one file, run identically on macOS and Windows.
//
// The previous round measured different things on different rigs (an APFS
// clone left the Mac warm while Windows really copied a gigabyte), so this
// binary owns the whole protocol: fresh output dir, explicit pre-warm of every
// input byte, time the child process, then gate the output on a content
// fingerprint. A tool that drops or corrupts a member reports WRONG-OUTPUT
// rather than a fast time, and a tool that cannot do the job at all reports
// why, because a blank cell is not an acceptable answer for any competitor.
//
//   shootout manifest <payload-dir> <out-file>
//   shootout race --shapes D --work D --rounds N --tools a,b,c --manifests D
//                 [--only shape,shape] [--tool-bin name=path ...] [--password P]
//
// No crates: it has to compile with plain `rustc -O` on a box with no cargo.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Instant;

// ---------------------------------------------------------------- sha256

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

struct Sha256 {
    h: [u32; 8],
    buf: [u8; 64],
    n: usize,
    len: u64,
}

impl Sha256 {
    fn new() -> Self {
        Sha256 {
            h: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: [0; 64],
            n: 0,
            len: 0,
        }
    }
    fn block(&mut self, b: &[u8]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b_, mut c, mut d, mut e, mut f, mut g, mut h) = (
            self.h[0], self.h[1], self.h[2], self.h[3], self.h[4], self.h[5], self.h[6], self.h[7],
        );
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b_) ^ (a & c) ^ (b_ & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b_;
            b_ = a;
            a = t1.wrapping_add(t2);
        }
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b_);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }
    fn update(&mut self, mut data: &[u8]) {
        self.len = self.len.wrapping_add(data.len() as u64);
        if self.n > 0 {
            let take = (64 - self.n).min(data.len());
            self.buf[self.n..self.n + take].copy_from_slice(&data[..take]);
            self.n += take;
            data = &data[take..];
            if self.n == 64 {
                let b = self.buf;
                self.block(&b);
                self.n = 0;
            }
        }
        while data.len() >= 64 {
            let (a, b) = data.split_at(64);
            self.block(a);
            data = b;
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.n = data.len();
        }
    }
    fn finish(mut self) -> [u8; 32] {
        let bits = self.len.wrapping_mul(8);
        self.update(&[0x80]);
        while self.n != 56 {
            self.update(&[0]);
        }
        let b = bits.to_be_bytes();
        self.update(&b);
        let mut out = [0u8; 32];
        for i in 0..8 {
            out[4 * i..4 * i + 4].copy_from_slice(&self.h[i].to_be_bytes());
        }
        out
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// A file's fingerprint is sha256 over the concatenated sha256 of its 32 MiB
// chunks, so a gigabyte can be hashed on several cores. It is not a standard
// file digest and does not need to be: both sides of every comparison use this
// same function.
const CHUNK: u64 = 32 * 1024 * 1024;

fn fingerprint(path: &Path, threads: usize) -> std::io::Result<String> {
    let len = fs::metadata(path)?.len();
    let nchunks = if len == 0 { 1 } else { len.div_ceil(CHUNK) } as usize;
    let out = Arc::new(Mutex::new(vec![[0u8; 32]; nchunks]));
    let next = Arc::new(Mutex::new(0usize));
    let nthreads = threads.min(nchunks).max(1);
    std::thread::scope(|s| {
        for _ in 0..nthreads {
            let out = Arc::clone(&out);
            let next = Arc::clone(&next);
            s.spawn(move || {
                let mut f = fs::File::open(path).expect("open for hashing");
                let mut buf = vec![0u8; CHUNK as usize];
                loop {
                    let i = {
                        let mut g = next.lock().unwrap();
                        if *g >= nchunks {
                            return;
                        }
                        let i = *g;
                        *g += 1;
                        i
                    };
                    let off = i as u64 * CHUNK;
                    let want = (len - off.min(len)).min(CHUNK) as usize;
                    read_at(&mut f, off, &mut buf[..want]).expect("read for hashing");
                    let mut h = Sha256::new();
                    h.update(&buf[..want]);
                    out.lock().unwrap()[i] = h.finish();
                }
            });
        }
    });
    let mut top = Sha256::new();
    for c in out.lock().unwrap().iter() {
        top.update(c);
    }
    Ok(hex(&top.finish()))
}

#[cfg(unix)]
fn read_at(f: &mut fs::File, off: u64, buf: &mut [u8]) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    f.read_exact_at(buf, off)
}

#[cfg(windows)]
fn read_at(f: &mut fs::File, off: u64, buf: &mut [u8]) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut done = 0;
    while done < buf.len() {
        let n = f.seek_read(&mut buf[done..], off + done as u64)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "short read",
            ));
        }
        done += n;
    }
    Ok(())
}

fn dir_fingerprint(dir: &Path, threads: usize) -> std::io::Result<Vec<String>> {
    let mut v = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d)? {
            let e = e?;
            let p = e.path();
            let name = e.file_name();
            let name = name.to_string_lossy();
            // AppleDouble sidecars ride along on any Mac-to-Windows copy and
            // are not archive content.
            if name.starts_with("._") || name == ".DS_Store" {
                continue;
            }
            if e.file_type()?.is_dir() {
                stack.push(p);
            } else {
                v.push(fingerprint(&p, threads)?);
            }
        }
    }
    v.sort();
    Ok(v)
}

// ---------------------------------------------------------------- shapes

struct Shape {
    name: &'static str,
    // first volume, relative to <shapes>/<name>/
    entry: &'static str,
    payload: &'static str, // manifest key
    encrypted: bool,
}

const SHAPES: &[Shape] = &[
    Shape { name: "store",  entry: "store.rar",      payload: "rand",  encrypted: false },
    Shape { name: "small",  entry: "small.rar",      payload: "small", encrypted: false },
    Shape { name: "solid",  entry: "solid.rar",      payload: "small", encrypted: false },
    Shape { name: "rep",    entry: "rep.rar",        payload: "rep",   encrypted: false },
    Shape { name: "big",    entry: "big.part01.rar",  payload: "mixed", encrypted: false },
    Shape { name: "enc",    entry: "enc.rar",        payload: "mixed", encrypted: true  },
    Shape { name: "r7dict", entry: "r7dict.rar",     payload: "mixed", encrypted: false },
];

// ---------------------------------------------------------------- tools

fn tool_cmd(
    tool: &str,
    bin: &str,
    voldir: &Path,
    entry: &Path,
    out: &Path,
    password: &str,
    encrypted: bool,
) -> Option<Command> {
    let mut c = Command::new(bin);
    match tool {
        // The product path: same options object the daemon builds. Any name
        // starting `ours` takes this argv, so one interleaved round can race
        // two of OUR OWN builds against each other and against the rivals -
        // `--tools ours,ours-aug14,unrar` with a `--tool-bin` for each. Two
        // separate races cannot answer an old-vs-new question on a shared box:
        // the second one runs under whatever load the first did not.
        t if t.starts_with("ours") => {
            c.arg(voldir).arg(out);
            if encrypted {
                c.arg(password);
            }
        }
        "unrar" => {
            c.arg("x").arg("-y").arg("-idq");
            c.arg(if encrypted {
                format!("-p{password}")
            } else {
                "-p-".to_string()
            });
            c.arg(entry).arg(format!("{}/", out.display()));
        }
        "rarpar" => {
            c.arg("rar").arg("extract").arg("--overwrite");
            if encrypted {
                c.arg("--password-env").arg("RARPAR_PW");
                c.env("RARPAR_PW", password);
            }
            c.arg("-o").arg(out).arg(entry);
        }
        "unar" => {
            c.arg("-q").arg("-f").arg("-o").arg(out);
            if encrypted {
                c.arg("-p").arg(password);
            }
            c.arg(entry);
        }
        // libarchive. No multi-volume RAR5 and no encrypted RAR5; the harness
        // records whatever it says rather than leaving the cell blank.
        "bsdtar" => {
            c.arg("-x").arg("-f").arg(entry).arg("-C").arg(out);
        }
        "7zz" => {
            c.arg("x").arg("-y").arg("-bso0").arg("-bsp0");
            c.arg(format!("-o{}", out.display()));
            c.arg(format!("-p{}", if encrypted { password } else { "-" }));
            c.arg(entry);
        }
        _ => return None,
    }
    Some(c)
}

// ---------------------------------------------------------------- driver

fn prewarm(dir: &Path) -> std::io::Result<u64> {
    let mut total = 0u64;
    let mut buf = vec![0u8; 4 << 20];
    for e in fs::read_dir(dir)? {
        let p = e?.path();
        if !p.is_file() {
            continue;
        }
        let mut f = fs::File::open(&p)?;
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            total += n as u64;
        }
    }
    Ok(total)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("manifest") {
        let payload = PathBuf::from(&args[1]);
        let out = PathBuf::from(&args[2]);
        let t = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(8);
        let mut lines = Vec::new();
        for (key, path) in [
            ("rand", payload.join("rand.bin")),
            ("mixed", payload.join("mixed.bin")),
            ("rep", payload.join("rep.bin")),
        ] {
            lines.push(format!("{key} {}", fingerprint(&path, t).unwrap()));
        }
        for f in dir_fingerprint(&payload.join("small"), t).unwrap() {
            lines.push(format!("small {f}"));
        }
        fs::write(&out, lines.join("\n") + "\n").unwrap();
        eprintln!("wrote {} lines to {}", lines.len(), out.display());
        return;
    }

    let mut shapes_dir = PathBuf::new();
    let mut work = PathBuf::new();
    let mut manifest = PathBuf::new();
    let mut rounds = 3usize;
    let mut tools: Vec<String> = Vec::new();
    let mut only: Vec<String> = Vec::new();
    let mut bins: HashMap<String, String> = HashMap::new();
    let mut password = "benchpw".to_string();
    let mut i = 1;
    while i < args.len() {
        let k = args[i].as_str();
        let mut val = || {
            i += 1;
            args[i].clone()
        };
        match k {
            "--shapes" => shapes_dir = PathBuf::from(val()),
            "--work" => work = PathBuf::from(val()),
            "--manifest" => manifest = PathBuf::from(val()),
            "--rounds" => rounds = val().parse().unwrap(),
            "--tools" => tools = val().split(',').map(str::to_string).collect(),
            "--only" => only = val().split(',').map(str::to_string).collect(),
            "--password" => password = val(),
            "--tool-bin" => {
                let v = val();
                let (n, p) = v.split_once('=').expect("--tool-bin name=path");
                bins.insert(n.to_string(), p.to_string());
            }
            other => panic!("unknown arg {other}"),
        }
        i += 1;
    }

    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(8);
    let mut expected: HashMap<String, Vec<String>> = HashMap::new();
    for line in fs::read_to_string(&manifest).expect("manifest").lines() {
        let (k, v) = line.split_once(' ').unwrap();
        expected.entry(k.to_string()).or_default().push(v.to_string());
    }
    for v in expected.values_mut() {
        v.sort();
    }

    fs::create_dir_all(&work).unwrap();
    println!("# rounds={rounds} tools={} threads={threads}", tools.join(","));

    for round in 1..=rounds {
        for sh in SHAPES {
            if !only.is_empty() && !only.iter().any(|o| o == sh.name) {
                continue;
            }
            let voldir = shapes_dir.join(sh.name);
            if !voldir.is_dir() {
                println!("LEG {} - {round} - MISSING-SHAPE", sh.name);
                continue;
            }
            let entry = voldir.join(sh.entry);
            let want = expected.get(sh.payload).expect("manifest key");
            // Rotate the tool order by round. THE POSITION IN THE ROUND IS
            // WORTH ~1.5% AND A FIXED ORDER HANDS ALL OF IT TO THE SAME ARM.
            // Measured 23 Aug 2026 by racing prodrar against a byte-identical
            // COPY of itself, 15 rounds on the solid shape: the arm that ran
            // first won 6 of 15 and its median leg was 1.0165x the second
            // arm's, on 1.450 against 1.433 at the minimum. Identical
            // binaries. The mechanism is the leg that precedes yours - the
            // first arm starts while the previous leg's 1 GB output is still
            // being torn down by APFS, the second arm does not - and the
            // prewarm cannot undo it because prewarm runs OUTSIDE the timed
            // region. It is far below the 1.2x-5x margins this rig publishes
            // against other extractors, which is why it went unnoticed, and
            // it is the same size as an our-build-versus-our-build delta,
            // which is what it broke: a two-arm A/B read off this harness
            // with a fixed order reported a 2-5% regression on solid that
            // instruction counts then showed did not exist (the newer build
            // retires 0.14% FEWER instructions at level cycles and RSS).
            // Rotation is by round index rather than randomised so a rerun
            // of the same command is still the same experiment.
            let order: Vec<&String> =
                tools.iter().cycle().skip(round % tools.len()).take(tools.len()).collect();
            for tool in order {
                let bin = bins.get(tool).cloned().unwrap_or_else(|| tool.clone());
                let out = work.join(format!("out-{}-{}", sh.name, tool));
                let _ = fs::remove_dir_all(&out);
                fs::create_dir_all(&out).unwrap();
                let warm = prewarm(&voldir).unwrap();
                let Some(mut cmd) =
                    tool_cmd(tool, &bin, &voldir, &entry, &out, &password, sh.encrypted)
                else {
                    println!("LEG {} {tool} {round} - UNKNOWN-TOOL", sh.name);
                    continue;
                };
                cmd.stdout(Stdio::null()).stderr(Stdio::piped()).stdin(Stdio::null());
                let t0 = Instant::now();
                let res = cmd.output();
                let secs = t0.elapsed().as_secs_f64();
                let verdict = match res {
                    Err(e) => format!("NO-BINARY({})", first_line(&e.to_string())),
                    Ok(o) if !o.status.success() => format!(
                        "FAILED(code={} {})",
                        o.status.code().unwrap_or(-1),
                        first_line(&String::from_utf8_lossy(&o.stderr))
                    ),
                    Ok(_) => {
                        let got = dir_fingerprint(&out, threads).unwrap_or_default();
                        if &got == want {
                            "ok".to_string()
                        } else {
                            format!("WRONG-OUTPUT(files {} want {})", got.len(), want.len())
                        }
                    }
                };
                println!(
                    "LEG {} {tool} {round} {secs:.3} {verdict} warm={}MiB",
                    sh.name,
                    warm >> 20
                );
                use std::io::Write as _;
                std::io::stdout().flush().ok();
                let _ = fs::remove_dir_all(&out);
            }
        }
    }
}

fn first_line(s: &str) -> String {
    let l = s
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("")
        .to_string();
    l.chars().take(160).collect()
}
