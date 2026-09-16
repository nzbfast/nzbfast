//! Time the desktop queue over a batch of large single-file creates, with
//! `performance.pair_large_creates` on or off - the measurement behind
//! `parfast_session::pairing`.
//!
//! ```text
//! cargo run --release --manifest-path apps/parfast/Cargo.toml --locked \
//!     -p parfast-session --example pair_queue -- <out-dir> <file>...
//! ```
//!
//! `PAIR=0` is the serial control. Each file gets the CLI's default
//! create (2,000 blocks, 5%) into `<out-dir>/<n>/`, so two arms' sets can
//! be compared byte for byte with `cmp`. It prints each job's wall, the
//! "Started beside" line of a paired job, the "Not started beside" line
//! naming why a job was left queued beside a running one (once per change
//! of reason), how many jobs were ever running at once, and the batch's
//! wall.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use parfast_session::job::{CreateSpec, JobSpec, PathMode, Source, UnicodePolicy, VolumeSpec};
use parfast_session::{JobState, Session, Settings};

fn main() {
    let mut args = std::env::args_os().skip(1);
    let usage = || {
        eprintln!("usage: pair_queue <out-dir> <file>...  (PAIR=0 for the serial control)");
        std::process::exit(2);
    };
    let Some(out) = args.next().map(PathBuf::from) else {
        usage()
    };
    let files: Vec<PathBuf> = args.map(PathBuf::from).collect();
    if files.is_empty() {
        usage();
    }
    let pair = std::env::var_os("PAIR").is_none_or(|v| v != "0");
    let mut settings = Settings::default();
    settings.performance.pair_large_creates = pair;
    let session = Session::new(Some(settings));
    session.set_queue_paused(true);
    for (i, f) in files.iter().enumerate() {
        let dir = out.join(i.to_string());
        std::fs::create_dir_all(&dir).expect("output dir");
        let stem = f
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| format!("source{i}"));
        session.submit(JobSpec::Create {
            create: CreateSpec {
                sources: vec![Source {
                    path: f.clone(),
                    recursive: false,
                }],
                path_mode: PathMode::Basename,
                base_path: None,
                block: None,
                recovery: None,
                output: dir.join(format!("{stem}.par2")),
                volumes: VolumeSpec::Pow2,
                first_recovery_block: 0,
                comment: String::new(),
                overwrite: true,
                std_naming: false,
                unicode: UnicodePolicy::Auto,
                perf: Default::default(),
            },
        });
    }
    let t0 = Instant::now();
    session.set_queue_paused(false);
    let mut most_at_once = 0usize;
    let snap = loop {
        let q = session.snapshot();
        let running = q
            .jobs
            .iter()
            .filter(|j| matches!(j.state, JobState::Running | JobState::Paused))
            .count();
        most_at_once = most_at_once.max(running);
        if q.jobs.iter().all(|j| j.state.finished()) {
            break q;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let wall = t0.elapsed();
    let mut all_done = true;
    for j in &snap.jobs {
        println!(
            "job {} {:?} {:.2} s",
            j.id,
            j.state,
            j.elapsed_ms as f64 / 1000.0
        );
        for line in j
            .log_tail
            .iter()
            .filter(|l| l.starts_with("Started beside") || l.starts_with("Not started beside"))
        {
            println!("  {line}");
        }
        if let Some(e) = &j.error {
            println!("  error {}: {}", e.code, e.message);
        }
        all_done &= j.state == JobState::Done;
    }
    println!(
        "pair={} jobs={} most_at_once={most_at_once} cpu_workers={} wall={:.2} s",
        u8::from(pair),
        snap.jobs.len(),
        nzbkit::mem::cpu_workers(),
        wall.as_secs_f64()
    );
    if !all_done {
        std::process::exit(1);
    }
}
