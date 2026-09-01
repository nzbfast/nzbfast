//! TODO 82: the long-run soak. A multi-hour mixed queue - store RAR5,
//! compressed RAR5, 7z, PAR2 repair, password - driven round and round
//! against the mock NNTP server while the DAEMON's RSS, open-file-descriptor
//! count and thread count are sampled at a quiescent point in every cycle.
//!
//! This exists for the one bug class the other suites structurally cannot
//! see: the slow leak. Every test in `daemon` and `e2e` starts a fresh
//! daemon, runs one job shape, and tears it down - a per-job leak of a few
//! hundred fds or a few MB is invisible in that window and only shows up as
//! a user's week-old daemon sitting on 6 GB. Here one daemon lives for the
//! whole run and the question is whether it comes back to where it started.
//!
//! Two things make the answer specific rather than "looks fine":
//!
//! 1. Samples are taken QUIESCENT and TRIMMED. After each cycle drains, the
//!    harness waits out the daemon's idle memory trim (spawn_memory_trim:
//!    fires once, 60 s after the last download ends, on a 15 s tick) before
//!    reading the counters. Without that wait, RSS drift measures nothing
//!    but how much the allocator happened to be holding, and mimalloc holds
//!    a lot mid-flight by design.
//! 2. The gate is a recorded baseline plus an allowed drift, in
//!    `leak-soak-baseline.json`. Baseline = median of the first third of the
//!    post-warmup samples, final = median of the last third, and the run is
//!    red when the difference exceeds the allowance - naming the resource
//!    and the amount. A per-hour least-squares slope is reported alongside
//!    as context (it is not a second gate: two gates that can disagree just
//!    make a red run ambiguous).
//!
//! `#[ignore]` on purpose - `cargo test` must not turn into a multi-hour
//! run. CI drives it from the nightly workflow:
//!
//! ```sh
//! NZBFAST_NO_ENRICH=1 NZBFAST_SOAK_MINUTES=150 \
//!   cargo test --release -p nzbfast --test leak_soak -- --ignored --nocapture
//! ```
//!
//! Named `leak_soak` to keep three different soaks apart: `nzbfast soak` is
//! the raw provider-throughput CLI subcommand, `tests/queue_soak.rs` is the
//! cross-job CORRECTNESS soak (three overlapping jobs, byte-identical), and
//! this one is the resource-drift soak.
//!
//! Knobs: `NZBFAST_SOAK_MINUTES` (default 20), `NZBFAST_SOAK_SETTLE_SECS`
//! (default 90 - must stay above the daemon's 60 s idle-trim delay plus its
//! 15 s tick), `NZBFAST_SOAK_REPORT` (path for the JSON report, which
//! carries every sample so a baseline can be re-recorded from a green run).

// The forward guard on the repeating-payload trap, and the waiver that
// says a fixture is deliberately in it. A sibling the way `harness` is,
// and reached from `harness::DaemonLog`'s own Drop, so every daemon this
// binary starts is read whether or not the suite looks at its log.
mod adoptguard;
// The shared daemon launcher (free_port / KillOnDrop / DaemonLog /
// serve / wait_ready), one copy for every suite that spawns a daemon.
mod harness;
mod scratch;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use harness::serve;
use nzbkit::mock::{Chaos, MockServer, make_file_articles};
use nzbkit::rar::fixtures;

// ---------------------------------------------------------------------------
// daemon plumbing
//
// Deliberately a copy of the harness in tests/queue_soak.rs rather than a
// shared module: integration-test targets cannot share code without moving
// it into a file every other suite also compiles, and this suite exists to
// be edited on its own schedule. The comments there explain WHY each piece
// is shaped the way it is; they are not repeated in full here.
// ---------------------------------------------------------------------------

/// Response body of a request to the daemon (headers stripped).
///
/// A connection that produced ZERO bytes is retried: tiny_http's honest
/// reply when it cannot start a thread for a new connection is to drop the
/// socket unread, which reaches us as ECONNRESET (memory
/// `nzbfast-daemon-test-harness`). Over a multi-hour run this suite makes
/// tens of thousands of requests, so the retry budget is larger than the
/// short suites'. Once a byte has come back it is an answer and is returned
/// exactly as it arrived - a truncated response must never be retried away.
fn http(port: u16, req: &str, body: Option<(&str, &[u8])>) -> String {
    let mut last = String::new();
    for attempt in 0..8u32 {
        match http_once(port, req, body) {
            Ok(out) => return out,
            Err(e) => {
                last = e.to_string();
                std::thread::sleep(Duration::from_millis(100 * u64::from(attempt) + 50));
            }
        }
    }
    panic!("daemon on :{port} never served {req}: {last}");
}

fn http_once(port: u16, req: &str, body: Option<(&str, &[u8])>) -> std::io::Result<String> {
    let mut request = Vec::new();
    match body {
        None => {
            write!(
                request,
                "GET {req} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        }
        Some((ctype, data)) => {
            write!(
                request,
                "POST {req} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\r\n",
                data.len()
            )
            .unwrap();
            request.extend_from_slice(data);
        }
    }
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    s.write_all(&request)?;
    let mut out = String::new();
    let read = s.read_to_string(&mut out);
    if out.is_empty() {
        return Err(read.err().unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed without answering",
            )
        }));
    }
    Ok(out.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
}

// ---------------------------------------------------------------------------
// resource sampling
// ---------------------------------------------------------------------------

/// One quiescent reading of the daemon's resource footprint.
#[derive(Clone, Copy)]
struct Sample {
    cycle: u32,
    hours: f64,
    rss_kib: f64,
    fds: f64,
    threads: f64,
}

/// Read RSS (KiB), open descriptors and thread count for `pid`.
///
/// Returns Err rather than guessing. A soak that cannot measure is a broken
/// soak, not a green one, so the first failed sample takes the run down -
/// the same reasoning as `NZBFAST_REQUIRE_PAR2` in the other suites.
///
/// Dispatched with `cfg!` (a runtime bool) rather than `#[cfg]`, on purpose.
/// Neither implementation needs platform-specific APIs - one reads files,
/// the other runs two programs - so both COMPILE everywhere, and the Linux
/// arm is therefore type-checked and linted on the macOS dev box. Under
/// `#[cfg]` it would not be, and CI's linux clippy leg discovering a broken
/// arm nobody could see locally is a trap this repo has already been bitten
/// by (memory `nzbfast-ci-linux-clippy-trap`).
fn sample_process(pid: u32) -> Result<(f64, f64, f64), String> {
    if cfg!(target_os = "linux") {
        sample_proc_fs(pid)
    } else if cfg!(target_os = "macos") {
        sample_bsd_tools(pid)
    } else {
        Err(
            "no resource sampler for this platform - the soak runs on linux \
             (CI) and macos (dev)"
                .to_string(),
        )
    }
}

/// Linux: `/proc/<pid>/status` for RSS and thread count, `/proc/<pid>/fd`
/// for the numbered descriptors.
fn sample_proc_fs(pid: u32) -> Result<(f64, f64, f64), String> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|e| format!("/proc/{pid}/status: {e}"))?;
    let field = |name: &str| -> Result<f64, String> {
        status
            .lines()
            .find_map(|l| {
                l.strip_prefix(name)?
                    .split_whitespace()
                    .next()?
                    .parse::<f64>()
                    .ok()
            })
            .ok_or_else(|| format!("no {name} in /proc/{pid}/status"))
    };
    let rss = field("VmRSS:")?;
    let threads = field("Threads:")?;
    let fds = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .map_err(|e| format!("/proc/{pid}/fd: {e}"))?
        .count() as f64;
    Ok((rss, fds, threads))
}

/// macOS: no /proc, so the three readings come from `ps` and `lsof`.
fn sample_bsd_tools(pid: u32) -> Result<(f64, f64, f64), String> {
    let run = |prog: &str, args: &[&str]| -> Result<String, String> {
        let out = Command::new(prog)
            .args(args)
            .output()
            .map_err(|e| format!("{prog}: {e}"))?;
        if !out.status.success() {
            return Err(format!("{prog} {args:?} exited {}", out.status));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    };
    let rss: f64 = run("ps", &["-o", "rss=", "-p", &pid.to_string()])?
        .trim()
        .parse()
        .map_err(|e| format!("ps rss: {e}"))?;
    // -M prints a header, the process line, then ONE LINE PER THREAD -
    // except for a single-threaded process, where it prints no thread
    // lines at all (verified on Darwin 27). Hence the floor of 1 rather
    // than a bare subtraction, which would report zero threads for a
    // process that by definition has at least one.
    let threads = run("ps", &["-M", "-p", &pid.to_string()])?
        .lines()
        .count()
        .saturating_sub(2)
        .max(1) as f64;
    // -F f emits one record per open file. Only the NUMBERED ones are
    // descriptors: lsof also reports cwd/txt/rtd/mem as `fcwd`, `ftxt`
    // and friends, and counting those would put a constant offset
    // between this reading and Linux's /proc/<pid>/fd - which holds
    // numbered descriptors only.
    let fds = run("lsof", &["-nP", "-F", "f", "-p", &pid.to_string()])?
        .lines()
        .filter(|l| {
            l.strip_prefix('f')
                .is_some_and(|r| r.starts_with(|c: char| c.is_ascii_digit()))
        })
        .count() as f64;
    Ok((rss, fds, threads))
}

// ---------------------------------------------------------------------------
// drift analysis
// ---------------------------------------------------------------------------

/// The gate for one resource, read from `leak-soak-baseline.json`.
struct Limit {
    key: &'static str,
    label: &'static str,
    /// How the number is printed. "MiB" divides the KiB reading by 1024.
    unit: &'static str,
    /// Largest tolerated baseline→final difference.
    drift: f64,
    /// Largest tolerated single reading, ever. Catches the run that starts
    /// high and stays flat, which no drift figure can see.
    ceiling: f64,
}

fn fmt(unit: &str, v: f64) -> String {
    match unit {
        "MiB" => format!("{:.1} MiB", v / 1024.0),
        _ => format!("{v:.0}"),
    }
}

fn median(xs: &[f64]) -> f64 {
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

/// Least-squares slope of y over x, in y-units per x-unit. Zero when x has
/// no spread (every sample at the same instant, which cannot happen here
/// but must not divide by zero if it did).
fn slope(x: &[f64], y: &[f64]) -> f64 {
    let n = x.len() as f64;
    let mx = x.iter().sum::<f64>() / n;
    let my = y.iter().sum::<f64>() / n;
    let num: f64 = x.iter().zip(y).map(|(a, b)| (a - mx) * (b - my)).sum();
    let den: f64 = x.iter().map(|a| (a - mx).powi(2)).sum();
    if den == 0.0 { 0.0 } else { num / den }
}

/// What the run concluded about one resource.
struct Verdict {
    label: &'static str,
    unit: &'static str,
    baseline: f64,
    last: f64,
    drift: f64,
    allowed: f64,
    peak: f64,
    ceiling: f64,
    per_hour: f64,
    /// Populated when the resource broke its gate: the sentence the run
    /// fails with, naming the resource and the amount.
    failure: Option<String>,
}

// ---------------------------------------------------------------------------
// the release fixtures
// ---------------------------------------------------------------------------

/// One job shape, built once and re-enqueued every cycle.
struct Release {
    /// Job name stem; the cycle number is appended so no two cycles submit
    /// the same NZB (the daemon's duplicate handling is not what this
    /// suite is measuring).
    tag: &'static str,
    /// `<file>` entries: (subject/name, segments).
    files: Vec<(String, Vec<(String, u64, u32)>)>,
    /// Payload the job must produce: (basename anywhere under the output
    /// root, exact bytes).
    expect: (String, Vec<u8>),
    /// Appended to the submitted filename as `{{pw}}` when set.
    password: Option<&'static str>,
}

fn nzb_xml(files: &[(String, Vec<(String, u64, u32)>)]) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (name, segs) in files {
        xml.push_str(&format!(
            "  <file poster=\"soak@test\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>mock.group</group></groups>\n    <segments>\n",
            segs.len()
        ));
        for (id, bytes, num) in segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n");
    }
    xml.push_str("</nzb>\n");
    xml
}

fn addfile(port: u16, nzb_name: &str, xml: &str) {
    let boundary = "----nzbfastsoak";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{nzb_name}\"\r\nContent-Type: application/x-nzb\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(xml.as_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let r = http(
        port,
        "/api?mode=addfile&output=json",
        Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
    );
    assert!(r.contains("\"status\":true"), "addfile {nzb_name}: {r}");
}

fn payload(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| {
            (i as u8)
                .wrapping_mul(37)
                .wrapping_add(seed)
                .wrapping_add((i >> 9) as u8)
        })
        .collect()
}

/// Incompressible bytes - a store-codec container over these is the shape
/// the census says dominates (already-compressed video).
fn incompressible(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// Compressible bytes - every other byte zero, so the RAR5 writer keeps the
/// compressed method instead of silently storing the entry.
fn half_entropy(n: usize, mut s: u64) -> Vec<u8> {
    (0..n)
        .map(|i| {
            if i % 2 == 0 {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 24) as u8
            } else {
                0
            }
        })
        .collect()
}

/// A store-mode RAR5 volume set over one inner file, in WinRAR-true
/// geometry: volume 0 carries one byte more data than volume 1.
fn store_volumes(inner_name: &str, inner: &[u8]) -> Vec<Vec<u8>> {
    let n = inner.len();
    let a = n / 3 + 1;
    let b = a + n / 3;
    vec![
        fixtures::rar5_volume_n(&[(inner_name, n as u64, &inner[..a], false, true)], 0),
        fixtures::rar5_volume_n(&[(inner_name, n as u64, &inner[a..b], true, true)], 1),
        fixtures::rar5_volume_n(&[(inner_name, n as u64, &inner[b..], true, false)], 2),
    ]
}

/// A single-volume encrypted store RAR5 over one inner file.
fn encrypted_store(pw: &str, inner_name: &str, inner: &[u8], seed: u8) -> Vec<u8> {
    let enc = fixtures::encrypt_file(pw, inner, seed);
    fixtures::rar5_volume_enc(
        &[(inner_name, &enc, 0..enc.cipher.len(), false, false)],
        None,
    )
}

/// An in-memory `.7z` with the COPY codec.
fn sevenz_store(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = sevenz_rust2::ArchiveWriter::new(std::io::Cursor::new(Vec::new())).unwrap();
    w.set_content_methods(vec![sevenz_rust2::EncoderConfiguration::new(
        sevenz_rust2::EncoderMethod::COPY,
    )]);
    for &(n, d) in entries {
        w.push_archive_entry(sevenz_rust2::ArchiveEntry::new_file(n), Some(d))
            .unwrap();
    }
    w.finish().unwrap().into_inner()
}

/// Same contract as the e2e suite's: par2 is a FIXTURE tool here (the
/// runtime repair is native), so a box without it covers one shape fewer -
/// but never silently in CI, where `NZBFAST_REQUIRE_PAR2` makes its absence
/// a red run rather than quietly reduced coverage.
fn have_par2() -> bool {
    let ok = Command::new("par2")
        .arg("-V")
        .output()
        .is_ok_and(|o| o.status.success());
    assert!(
        ok || std::env::var_os("NZBFAST_REQUIRE_PAR2").is_none(),
        "NZBFAST_REQUIRE_PAR2 is set but `par2 -V` does not run - the repair \
         shape would have been dropped and the soak would have looked green"
    );
    ok
}

/// `par2 create` over files already written into `dir`, returning the
/// recovery files as (name, bytes) with the originals left in place.
fn par2_files(dir: &Path, redundancy: u32, names: &[&str]) -> Vec<(String, Vec<u8>)> {
    let st = Command::new("par2")
        .arg("create")
        .arg(format!("-r{redundancy}"))
        .arg("-q")
        .arg("soakset")
        .args(names)
        .current_dir(dir)
        .status()
        .expect("run par2");
    assert!(st.success(), "par2 create failed in {}", dir.display());
    let mut par2s: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            (p.extension().is_some_and(|x| x == "par2")).then_some(p)
        })
        .collect();
    par2s.sort();
    par2s
        .iter()
        .map(|p| {
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            let data = std::fs::read(p).unwrap();
            std::fs::remove_file(p).unwrap();
            (name, data)
        })
        .collect()
}

/// Every file under `root`, keyed by basename. The output root holds only
/// the current cycle's jobs (the previous cycle was deleted with
/// `del_files=1`), so a basename lookup is unambiguous.
fn files_by_name(root: &Path, out: &mut HashMap<String, PathBuf>) {
    let Ok(rd) = std::fs::read_dir(root) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            files_by_name(&p, out);
        } else if let Some(n) = p.file_name().and_then(|n| n.to_str()) {
            out.insert(n.to_string(), p.clone());
        }
    }
}

fn dir_bytes(root: &Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(root) else {
        return 0;
    };
    rd.flatten()
        .map(|e| {
            let p = e.path();
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                dir_bytes(&p)
            } else {
                e.metadata().map(|m| m.len()).unwrap_or(0)
            }
        })
        .sum()
}

fn env_num<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn hms(d: Duration) -> String {
    let s = d.as_secs();
    format!("{}h{:02}m{:02}s", s / 3600, (s % 3600) / 60, s % 60)
}

// ---------------------------------------------------------------------------
// the soak
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "multi-hour; run from the nightly workflow or with --ignored"]
async fn mixed_queue_soak_holds_resources_flat() {
    let minutes: u64 = env_num("NZBFAST_SOAK_MINUTES", 20);
    // Must exceed the daemon's idle trim (60 s after the last download,
    // checked on a 15 s tick) or every RSS reading is "whatever the
    // allocator was holding" rather than the daemon's true footprint.
    let settle: u64 = env_num("NZBFAST_SOAK_SETTLE_SECS", 90);
    assert!(
        settle >= 80,
        "NZBFAST_SOAK_SETTLE_SECS={settle} is below the daemon's 60 s idle \
         trim plus its 15 s tick - RSS drift would measure allocator \
         retention, not a leak"
    );
    // Discarded before any statistics: the first cycles fault in the
    // binary, warm the connection pool, and grow the buffer pool and
    // caches to their working size. That is startup, not drift.
    //
    // Five, not two. The measured curve on the dev box (2 Aug, release,
    // quiescent samples) is 128, 176, 187, 206, 216, 224, 224, 225 MiB -
    // a decelerating climb that is flat by cycle 6 and never moves again.
    // Two warmup cycles leaves three rising samples inside the statistics,
    // which on a short run reported a +284 MiB/h slope for a daemon that
    // was simply still warming up. Cutting at 5 measures the plateau,
    // which is the only part where "did it grow?" is a real question.
    let warmup: usize = env_num("NZBFAST_SOAK_WARMUP_CYCLES", 5);
    // Three post-warmup samples per third is the least that makes a median
    // mean anything.
    let min_cycles = warmup + 6;

    let baseline_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/leak-soak-baseline.json");
    let spec: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&baseline_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", baseline_path.display())),
    )
    .unwrap_or_else(|e| panic!("parse {}: {e}", baseline_path.display()));
    let limit = |key: &'static str, label: &'static str, unit: &'static str| -> Limit {
        let l = &spec["limits"][key];
        let num = |field: &str| -> f64 {
            l[field].as_f64().unwrap_or_else(|| {
                panic!("limits.{key}.{field} missing from leak-soak-baseline.json")
            })
        };
        Limit {
            key,
            label,
            unit,
            drift: num("drift"),
            ceiling: num("ceiling"),
        }
    };
    let limits = [
        limit("rss_kib", "rss", "MiB"),
        limit("fds", "fds", ""),
        limit("threads", "threads", ""),
    ];

    let dir = std::env::temp_dir().join(format!("nzbfast-soak-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let fixtures_dir = dir.join("fixtures");
    std::fs::create_dir_all(&fixtures_dir).unwrap();

    // ---- build the five shapes once ------------------------------------
    let mut articles: HashMap<String, Vec<u8>> = HashMap::new();
    let mut releases: Vec<Release> = Vec::new();
    let art = 700_000usize; // close to the 500-768 KB real posts use

    // 1. store: a plain store-mode RAR5 volume set, direct-extracted.
    {
        let inner = payload(12_000_003, 7);
        let mut files = Vec::new();
        for (i, vol) in store_volumes("store.mkv", &inner).iter().enumerate() {
            let name = format!("st.part{}.rar", i + 1);
            let segs = make_file_articles(&name, vol, art, &format!("st{i}"), &mut articles);
            files.push((name, segs));
        }
        releases.push(Release {
            tag: "store",
            files,
            expect: ("store.mkv".to_string(), inner),
            password: None,
        });
    }

    // 2. rar5: a COMPRESSED multi-volume RAR5, chased in-stream.
    {
        let doc = half_entropy(6_000_000, 0x9e3779b97f4a7c15);
        let vols = rars::rar50::Rar50VolumeWriter::new(rars::rar50::WriterOptions::default())
            .compressed_entries(&[rars::rar50::CompressedEntry {
                name: b"rar5.bin",
                data: &doc,
                mtime: None,
                attributes: 0,
                host_os: 0,
            }])
            .max_payload_per_volume(1_500_000)
            .finish()
            .unwrap();
        assert!(
            vols.len() >= 3,
            "want a real volume set, got {}",
            vols.len()
        );
        let mut files = Vec::new();
        for (i, vol) in vols.iter().enumerate() {
            let name = format!("cz.part{}.rar", i + 1);
            let segs = make_file_articles(&name, vol, art, &format!("cz{i}"), &mut articles);
            files.push((name, segs));
        }
        releases.push(Release {
            tag: "rar5",
            files,
            expect: ("rar5.bin".to_string(), doc),
            password: None,
        });
    }

    // 3. 7z: a store-codec container over incompressible payload.
    {
        let movie = incompressible(12 << 20, 43);
        let arch = sevenz_store(&[("sevenz.mkv", &movie)]);
        let segs = make_file_articles("release.7z", &arch, art, "sz", &mut articles);
        releases.push(Release {
            tag: "sevenz",
            files: vec![("release.7z".to_string(), segs)],
            expect: ("sevenz.mkv".to_string(), movie),
            password: None,
        });
    }

    // 4. repair: a store set with holes in its DATA articles and a PAR2 set
    //    to cure them. The damage is permanent (a fixed `missing` set on the
    //    mock), so repair runs on every single cycle rather than once.
    //
    //    MISSING (430), not corrupt. It is the damage real posts actually
    //    take - propagation holes, not flipped bytes - and it is what the
    //    e2e repair suite drives. It also keeps this suite clear of the
    //    `slot.errors` conflation, where one counter holds both decode and
    //    write errors and gates that read it as "something is wrong with
    //    this file" fire on the very holes repair just filled. The
    //    mapped-repair arm of that (which this harness tripped on its first
    //    run: repair completed, payload correct, job reported Failed) is
    //    fixed in `corrupt_articles_repair_into_output_and_the_job_succeeds`;
    //    the par2-slot sibling is still open. Neither belongs in a drift
    //    measurement - a soak that went red every cycle on a known product
    //    question would just be measuring it.
    //
    //    Smaller articles than the other shapes, on purpose. At 700 KB an
    //    article is ~9% of one volume, so one poisoned article per volume
    //    is a QUARTER of the set gone - past what any realistic recovery
    //    percentage can cure, and the first run of this suite duly failed
    //    "unrepairable: 528 blocks needed, only 300 recovery blocks". Real
    //    posts have thousands of articles per release, so a lost article is
    //    a rounding error; 250 KB here restores that proportion (3 poisoned
    //    articles ≈ 9% of the set, against 20% recovery).
    let mut holes: std::collections::HashSet<String> = Default::default();
    let with_repair = have_par2();
    if with_repair {
        let rp_art = 250_000usize;
        let inner = payload(8_000_003, 19);
        let mut names = Vec::new();
        for (i, vol) in store_volumes("repair.mkv", &inner).iter().enumerate() {
            let name = format!("rp.part{}.rar", i + 1);
            std::fs::write(fixtures_dir.join(&name), vol).unwrap();
            names.push(name);
        }
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let recovery = par2_files(&fixtures_dir, 20, &refs);
        let mut files = Vec::new();
        for (i, name) in names.iter().enumerate() {
            let vol = std::fs::read(fixtures_dir.join(name)).unwrap();
            let segs = make_file_articles(name, &vol, rp_art, &format!("rp{i}"), &mut articles);
            // One mid-file DATA article per volume: the repair leg gets real
            // work on every volume, well inside what 20% recovery covers.
            let victim = segs[segs.len() / 2].0.clone();
            holes.insert(format!("<{victim}>"));
            files.push((name.clone(), segs));
        }
        for (i, (name, data)) in recovery.iter().enumerate() {
            let segs = make_file_articles(name, data, rp_art, &format!("rpp{i}"), &mut articles);
            files.push((name.clone(), segs));
        }
        releases.push(Release {
            tag: "repair",
            files,
            expect: ("repair.mkv".to_string(), inner),
            password: None,
        });
    } else {
        eprintln!("[soak] par2 not installed - running WITHOUT the repair shape");
    }

    // 5. password: an encrypted store RAR whose password rides in on the
    //    `Name{{pw}}` filename convention, so it unlocks in-run.
    {
        let inner = payload(8_000_003, 31);
        let arch = encrypted_store("s0akpw", "pw.mkv", &inner, 5);
        let segs = make_file_articles("locked.rar", &arch, art, "pw", &mut articles);
        releases.push(Release {
            tag: "pw",
            files: vec![("locked.rar".to_string(), segs)],
            expect: ("pw.mkv".to_string(), inner),
            password: Some("s0akpw"),
        });
    }

    let per_cycle_bytes: u64 = releases
        .iter()
        .map(|r| r.expect.1.len() as u64)
        .sum::<u64>();
    println!(
        "[soak] {} shapes, {:.1} MiB of payload per cycle, {} articles on the mock",
        releases.len(),
        per_cycle_bytes as f64 / (1 << 20) as f64,
        articles.len()
    );

    let srv = MockServer::start(
        articles,
        Chaos {
            missing: holes,
            ..Chaos::default()
        },
    )
    .await;

    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false}}]}}",
            srv.addr.ip(),
            srv.addr.port()
        ),
    )
    .unwrap();
    let out_root = dir.join("complete");
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            // Loopback only: a soak binds for hours, and 0.0.0.0 raises the
            // macOS firewall prompt for every freshly built test binary.
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(&out_root)
            .arg("--connections")
            .arg("6");
        c
    })
    .await;
    let (port, pid) = (d.port, d.pid());

    // Fail on the FIRST sample rather than after hours of unmeasured work.
    if let Err(e) = sample_process(pid) {
        panic!("cannot sample the daemon's resources: {e}");
    }

    let deadline = Duration::from_secs(minutes * 60);
    let started = Instant::now();
    let mut samples: Vec<Sample> = Vec::new();
    let mut cycle = 0u32;
    let mut jobs_run = 0u32;

    println!(
        "[soak] daemon pid {pid} on :{port}; target {minutes} min, {settle}s settle, \
         {warmup} warmup cycles, at least {min_cycles} cycles"
    );

    while started.elapsed() < deadline || samples.len() < min_cycles {
        cycle += 1;
        let shapes: Vec<(String, String, String, Vec<u8>)> = releases
            .iter()
            .map(|r| {
                let stem = format!("{}-c{cycle}", r.tag);
                let nzb_name = match r.password {
                    Some(pw) => format!("{stem}{{{{{pw}}}}}.nzb"),
                    None => format!("{stem}.nzb"),
                };
                (
                    nzb_name,
                    nzb_xml(&r.files),
                    r.expect.0.clone(),
                    r.expect.1.clone(),
                )
            })
            .collect();
        let n_jobs = shapes.len();
        let out_for_cycle = out_root.clone();
        let cycle_started = Instant::now();

        let (fetched, disk) = tokio::task::spawn_blocking(move || {
            for (name, xml, _, _) in &shapes {
                addfile(port, name, xml);
            }

            // Drain. Ten minutes is far past any honest cycle here (whole
            // payload is ~46 MiB off a loopback mock); blowing it is a stall,
            // which is itself a finding worth the queue dump.
            let drain = Instant::now();
            let slots = loop {
                let h = http(port, "/api?mode=history&output=json", None);
                let v: serde_json::Value =
                    serde_json::from_str(&h).unwrap_or(serde_json::Value::Null);
                let slots = v["history"]["slots"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                if slots.len() >= n_jobs {
                    break slots;
                }
                assert!(
                    drain.elapsed() < Duration::from_secs(600),
                    "cycle {cycle}: only {}/{n_jobs} jobs reached history in 10 min\n\
                     --- queue ---\n{}\n--- history ---\n{h}",
                    slots.len(),
                    http(port, "/api?mode=queue&output=json", None)
                );
                std::thread::sleep(Duration::from_millis(500));
            };
            for s in &slots {
                assert_eq!(
                    s["status"], "Completed",
                    "cycle {cycle}: job {} ended {}\n{s}",
                    s["name"], s["status"]
                );
            }

            // Byte-exact payloads. A soak that only counts "Completed" would
            // happily measure a daemon that had stopped producing right
            // answers hours ago.
            let mut found = HashMap::new();
            files_by_name(&out_for_cycle, &mut found);
            for (name, _, want_name, want) in &shapes {
                let p = found.get(want_name).unwrap_or_else(|| {
                    panic!(
                        "cycle {cycle}: {name} produced no {want_name}; output root holds {:?}",
                        found.keys().collect::<Vec<_>>()
                    )
                });
                let got = std::fs::read(p).unwrap();
                assert!(
                    got == *want,
                    "cycle {cycle}: {want_name} differs ({} bytes vs {} expected)",
                    got.len(),
                    want.len()
                );
            }

            // Clear history AND the files, so the next cycle measures a
            // daemon at the same starting point rather than one carrying
            // every previous cycle's records.
            let r = http(
                port,
                "/api?mode=history&name=delete&value=all&del_files=1&output=json",
                None,
            );
            assert!(r.contains("\"status\":true"), "history clear: {r}");
            (slots.len(), dir_bytes(&out_for_cycle))
        })
        .await
        .unwrap();
        jobs_run += fetched as u32;
        let download = cycle_started.elapsed();

        // Quiescent point: past the daemon's idle trim, nothing running.
        tokio::time::sleep(Duration::from_secs(settle)).await;
        let (rss_kib, fds, threads) = sample_process(pid)
            .unwrap_or_else(|e| panic!("cycle {cycle}: cannot sample pid {pid}: {e}"));
        let s = Sample {
            cycle,
            hours: started.elapsed().as_secs_f64() / 3600.0,
            rss_kib,
            fds,
            threads,
        };
        samples.push(s);
        println!(
            "[soak] cycle {cycle:>3} t+{:<9} fetch {:>5.1}s  rss {:>9}  fds {:>4}  threads {:>4}  out {:.0} KiB{}",
            hms(started.elapsed()),
            download.as_secs_f64(),
            fmt("MiB", rss_kib),
            fds as u64,
            threads as u64,
            disk as f64 / 1024.0,
            if samples.len() <= warmup {
                "  (warmup)"
            } else {
                ""
            },
        );
    }

    // ---- verdict --------------------------------------------------------
    let post: Vec<Sample> = samples.iter().skip(warmup).copied().collect();
    assert!(
        post.len() >= 6,
        "soak produced only {} post-warmup samples (need 6) - raise \
         NZBFAST_SOAK_MINUTES",
        post.len()
    );
    let third = post.len() / 3;
    let hours: Vec<f64> = post.iter().map(|s| s.hours).collect();
    let pick = |s: &Sample, key: &str| match key {
        "rss_kib" => s.rss_kib,
        "fds" => s.fds,
        _ => s.threads,
    };

    let verdicts: Vec<Verdict> = limits
        .iter()
        .map(|l| {
            let ys: Vec<f64> = post.iter().map(|s| pick(s, l.key)).collect();
            let baseline = median(&ys[..third]);
            let last = median(&ys[ys.len() - third..]);
            let drift = last - baseline;
            let peak = ys.iter().copied().fold(f64::MIN, f64::max);
            let per_hour = slope(&hours, &ys);
            let failure = if drift > l.drift {
                Some(format!(
                    "{} drifted +{} over {} - baseline {} (median of cycles {}-{}), \
                     final {} (median of cycles {}-{}), allowed +{}; slope {}{}/h \
                     across {} samples",
                    l.label,
                    fmt(l.unit, drift),
                    hms(Duration::from_secs_f64(
                        (hours.last().unwrap() - hours[0]) * 3600.0
                    )),
                    fmt(l.unit, baseline),
                    post[0].cycle,
                    post[third - 1].cycle,
                    fmt(l.unit, last),
                    post[post.len() - third].cycle,
                    post[post.len() - 1].cycle,
                    fmt(l.unit, l.drift),
                    if per_hour < 0.0 { "-" } else { "+" },
                    fmt(l.unit, per_hour.abs()),
                    post.len(),
                ))
            } else if peak > l.ceiling {
                Some(format!(
                    "{} peaked at {}, over its {} ceiling - flat, but flat too high \
                     (baseline {})",
                    l.label,
                    fmt(l.unit, peak),
                    fmt(l.unit, l.ceiling),
                    fmt(l.unit, baseline),
                ))
            } else {
                None
            };
            Verdict {
                label: l.label,
                unit: l.unit,
                baseline,
                last,
                drift,
                allowed: l.drift,
                peak,
                ceiling: l.ceiling,
                per_hour,
                failure,
            }
        })
        .collect();

    let elapsed = started.elapsed();
    println!(
        "\n=== nzbfast soak: {cycle} cycles in {}, {jobs_run} jobs, {} shapes{} ===",
        hms(elapsed),
        releases.len(),
        if with_repair {
            ""
        } else {
            " (no repair shape - par2 missing)"
        },
    );
    println!(
        "{:<9} {:>12} {:>12} {:>12} {:>12} {:>12}  verdict",
        "resource", "baseline", "final", "drift", "allowed", "slope/h"
    );
    for v in &verdicts {
        println!(
            "{:<9} {:>12} {:>12} {:>12} {:>12} {:>12}  {}",
            v.label,
            fmt(v.unit, v.baseline),
            fmt(v.unit, v.last),
            format!(
                "{}{}",
                if v.drift < 0.0 { "-" } else { "+" },
                fmt(v.unit, v.drift.abs())
            ),
            format!("+{}", fmt(v.unit, v.allowed)),
            format!(
                "{}{}",
                if v.per_hour < 0.0 { "-" } else { "+" },
                fmt(v.unit, v.per_hour.abs())
            ),
            if v.failure.is_some() { "DRIFT" } else { "ok" },
        );
    }

    let report = serde_json::json!({
        "cycles": cycle,
        "jobs": jobs_run,
        "seconds": elapsed.as_secs(),
        "shapes": releases.iter().map(|r| r.tag).collect::<Vec<_>>(),
        "repair_shape": with_repair,
        "warmup_cycles": warmup,
        "settle_secs": settle,
        "platform": std::env::consts::OS,
        "baseline_spec": spec,
        "resources": verdicts.iter().map(|v| serde_json::json!({
            "resource": v.label,
            "baseline": v.baseline,
            "final": v.last,
            "drift": v.drift,
            "allowed_drift": v.allowed,
            "peak": v.peak,
            "ceiling": v.ceiling,
            "per_hour": v.per_hour,
            "failure": v.failure,
        })).collect::<Vec<_>>(),
        // Every sample, so a green run can be used to re-record the
        // baseline instead of guessing at new numbers.
        "samples": samples.iter().map(|s| serde_json::json!({
            "cycle": s.cycle,
            "hours": s.hours,
            "rss_kib": s.rss_kib,
            "fds": s.fds,
            "threads": s.threads,
        })).collect::<Vec<_>>(),
    });
    let report_path = std::env::var("NZBFAST_SOAK_REPORT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| dir.join("soak-report.json"));
    std::fs::write(&report_path, serde_json::to_string_pretty(&report).unwrap()).unwrap();
    println!("[soak] report written to {}", report_path.display());

    let failures: Vec<&str> = verdicts
        .iter()
        .filter_map(|v| v.failure.as_deref())
        .collect();
    assert!(
        failures.is_empty(),
        "SOAK FAILED - {} of {} resources drifted past their recorded gate:\n  {}\n\
         Samples are in {}. If the new level is legitimate (a deliberate cache \
         or pool change), re-record tests/leak-soak-baseline.json from a green run \
         rather than widening the allowance blind.",
        failures.len(),
        verdicts.len(),
        failures.join("\n  "),
        report_path.display(),
    );

    // The daemon dies with `d` here - by its own pid, never by pattern.
    drop(d);
}
