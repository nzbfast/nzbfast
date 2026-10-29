//! Time one posting set through the desktop session, the measurement
//! behind the one-pass route in `runner::posting`.
//!
//! ```text
//! cargo run --release --manifest-path apps/parfast/Cargo.toml --locked \
//!     -p parfast-session --example posting_set -- <out-dir> <name> <source>...
//! ```
//!
//! `PARFAST_POSTING_TWO_PASS=1` forces the two-pass route over the same
//! spec, which is the control. `VOLUME=<bytes>` splits the archive by
//! size and `COUNT=<n>` by count, `LEVEL=<0-5>` compresses it, `SOLID=1`
//! makes it solid, `PASSWORD=<text>` encrypts it (with its headers, unless
//! `HP=0`), `RR=<percent>` adds a RAR recovery record. The PAR2 half takes
//! the CLI's defaults (2,000 blocks, 5%) unless `PAR2_PCT=<n>`. It prints
//! the route, the wall from submit to Done, and the files written; the
//! phase timeline too under `TIMELINE=1`.
//!
//! `CAPTURE=<file.json>` writes every DISTINCT snapshot the host would
//! have polled (a change of state, phase or sentence), with the
//! output folder's path replaced by `/abs/out` - which is how
//! `apps/parfast/shared/contract/posting-set-snapshots.json` was made:
//! real snapshots of the real core, so a mock that plays them back
//! cannot show more than the contract carries.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use parfast_session::job::{
    JobSpec, PathMode, PostingPar2, PostingSetSpec, RarOptions, RarPassword, RarVolumes,
    RecoverySpec, Source,
};
use parfast_session::{JobState, Session};

fn main() {
    let mut args = std::env::args_os().skip(1);
    let usage = || {
        eprintln!("usage: posting_set <out-dir> <name> <source>...");
        std::process::exit(2);
    };
    let Some(out) = args.next().map(PathBuf::from) else {
        usage()
    };
    let Some(name) = args.next().map(|n| n.to_string_lossy().into_owned()) else {
        usage()
    };
    let sources: Vec<Source> = args
        .map(|p| Source {
            path: PathBuf::from(p),
            recursive: false,
        })
        .collect();
    if sources.is_empty() {
        usage();
    }
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let num = |k: &str| env(k).and_then(|v| v.parse::<u64>().ok());
    let volumes = match (num("VOLUME"), num("COUNT")) {
        (Some(size), _) => RarVolumes::Size { size },
        (None, Some(count)) => RarVolumes::Count {
            count: count as u32,
        },
        (None, None) => RarVolumes::None,
    };
    let rar = RarOptions {
        volumes,
        compression: num("LEVEL").unwrap_or(0) as u8,
        solid: env("SOLID").is_some_and(|v| v == "1"),
        password: env("PASSWORD").map(RarPassword::Given),
        encrypt_headers: env("HP").is_none_or(|v| v != "0"),
        recovery_percent: num("RR").unwrap_or(0) as u32,
    };
    let par2 = PostingPar2 {
        recovery: num("PAR2_PCT").map(|p| RecoverySpec::Percent { percent: p as f64 }),
        ..Default::default()
    };
    let out_text = out.to_string_lossy().into_owned();
    let session = Session::new(None);
    let t0 = Instant::now();
    let id = session.submit(JobSpec::PostingSet {
        posting_set: PostingSetSpec {
            sources,
            path_mode: PathMode::Basename,
            base_path: None,
            output_dir: out,
            name,
            rar,
            par2,
            overwrite: true,
            perf: Default::default(),
        },
    });
    // The phase timeline, for `TIMELINE=1`: each change of the bar's
    // sentence (minus its percentage), and when it first appeared.
    let timeline = env("TIMELINE").is_some();
    let capture = env("CAPTURE");
    let mut frames: Vec<serde_json::Value> = Vec::new();
    let mut last = String::new();
    let mut last_frame = String::new();
    let snap = loop {
        let s = session.job(id).expect("the job exists");
        if capture.is_some() {
            let key = format!("{:?}{:?}{}", s.state, s.phase, s.phase_text);
            if key != last_frame || s.state.finished() {
                last_frame = key;
                let mut v = serde_json::to_value(&s).expect("a snapshot serializes");
                // The wall clock is this run's, not the contract's.
                v["elapsed_ms"] = serde_json::json!(t0.elapsed().as_millis() as u64);
                frames.push(v);
            }
        }
        if timeline {
            let head = s.phase_text.split(" - ").next().unwrap_or("").to_string();
            if head != last {
                eprintln!("  {:>8.3}s {head}", t0.elapsed().as_secs_f64());
                last = head;
            }
        }
        if s.state.finished() {
            break s;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let wall = t0.elapsed();
    if let Some(path) = capture {
        let text = serde_json::to_string_pretty(&frames).expect("frames serialize");
        let text = text.replace(&out_text, "/abs/out");
        std::fs::write(&path, text + "\n").expect("write the capture");
    }
    if snap.state != JobState::Done {
        eprintln!("FAILED {:?}: {:?}", snap.state, snap.error);
        std::process::exit(1);
    }
    let p = snap
        .result
        .as_ref()
        .and_then(|r| r.posting.as_ref())
        .expect("a posting result");
    let rar_bytes: u64 = p.rar.iter().map(|f| f.size).sum();
    let par_bytes: u64 = p.par2.iter().map(|f| f.size).sum();
    println!(
        "POSTING route={} wall={:.3}s rar_files={} rar_bytes={} par2_files={} par2_bytes={}",
        p.route,
        wall.as_secs_f64(),
        p.rar.len(),
        rar_bytes,
        p.par2.len(),
        par_bytes
    );
    if !p.route_reason.is_empty() {
        println!("  reason: {}", p.route_reason);
    }
}
