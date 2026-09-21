//! A queue row's time left is its OWN bytes over its OWN rate.
//!
//! The failure this pins was seen on the live daemon on 21 Sep 2026: job A
//! (66 GB) was draining its last ~0.5 GB at ~1.7 MB/s while job B started
//! and took the line at ~110 MB/s. `current_speed_bps` deliberately SUMS
//! the two counters (the header and the speed chart want the whole line),
//! and every row divided its own bytes-left by that sum, so A read "3
//! seconds left" and then "0s" with 33 MiB to go, for minutes.
//!
//! Payload-side: that the slot's `timeleft` and `job_bps` come off the
//! row's own counter, that the header stays the whole line, and that a row
//! not on the wire has no rate of its own. The window arithmetic is
//! `daemon_speed_tests`.
//!
//! A child of the payload tests, out here for the size gate; the module is
//! named for its file so size-gate.py's CFG_TEST_MOD resolver still reads
//! it as test code.

use nzbfast_daemon::MutexExt;
use nzbfast_daemon::daemon::Daemon;
use nzbfast_daemon::job::{Job, JobState};
use nzbfast_daemon::testutil::{jv, with_daemon};
use serde_json::Value;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const GIB: u64 = 1024 * 1024 * 1024;
const MIB: u64 = 1024 * 1024;

fn queue(d: &Arc<Daemon>) -> Value {
    crate::sabcompat::queue_json(d, &std::collections::HashMap::new())["queue"].clone()
}

fn row(d: &Arc<Daemon>, id: &str) -> Value {
    queue(d)["slots"]
        .as_array()
        .expect("slots array")
        .iter()
        .find(|s| s["nzo_id"] == id)
        .cloned()
        .unwrap_or(Value::Null)
}

/// A 66 GiB job on the wire. The state is set on the job rather than
/// through the wire value: `job_from_json` reads a persisted Downloading
/// back as Queued on purpose (a job caught by a shutdown goes back
/// through the scheduler), so `{"state": "Downloading"}` would not stick.
fn downloading(id: &str, name: &str) -> Arc<std::sync::Mutex<Job>> {
    let j = jv(id, name, serde_json::json!({"total_bytes": 66 * GIB}));
    j.lock_ok().state = JobState::Downloading;
    j
}

/// SAB's `H:MM:SS` (or `D:HH:MM:SS`) as seconds.
fn secs(t: &str) -> u64 {
    let f: Vec<u64> = t.split(':').map(|p| p.parse().expect("a number")).collect();
    match f[..] {
        [h, m, s] => h * 3600 + m * 60 + s,
        [d, h, m, s] => d * 86_400 + h * 3600 + m * 60 + s,
        _ => panic!("not a SAB timeleft: {t}"),
    }
}

#[test]
fn a_draining_row_reads_its_own_rate_while_the_header_stays_the_whole_line() {
    with_daemon("jobrate-drain", |d| {
        {
            let mut q = d.queue.lock_ok();
            for (id, name) in [("nzo-a", "Old.A-GRP"), ("nzo-b", "New.B-GRP")] {
                q.push_back(downloading(id, name));
            }
            q.push_back(jv(
                "nzo-c",
                "Next.C-GRP",
                serde_json::json!({"total_bytes": 10 * GIB}),
            ));
        }
        // A is the drainer with 512 MiB left; B is active on a fresh
        // counter, as the runner leaves them at the hand-over.
        let a_counter = Arc::new(AtomicU64::new(66 * GIB - 512 * MIB));
        *d.drain_dl.lock_ok() = Some(nzbfast_daemon::wire::DrainSlot {
            nzo_id: "nzo-a".to_string(),
            t_start: Instant::now(),
            progress: a_counter.clone(),
            counters: Arc::new(crate::streamhub::FetchCounters::default()),
            total: 66 * GIB,
            resume_seeded: 0,
            pool_live: None,
            abort: None,
            queue_ctl: None,
        });
        *d.active_dl.lock_ok() = Some("nzo-b".to_string());
        d.active_total.store(66 * GIB, Ordering::Relaxed);
        let b_counter = d.progress.reset();
        *d.started_at.lock_ok() = Some(Instant::now());

        // First poll seeds every window.
        queue(d);
        let t = Instant::now();
        std::thread::sleep(Duration::from_millis(300));
        let dt = t.elapsed().as_secs_f64();
        // A crawls at 1.7 MB/s, B takes the line at 110 MB/s.
        a_counter.fetch_add((1.7e6 * dt) as u64, Ordering::Relaxed);
        b_counter.fetch_add((110e6 * dt) as u64, Ordering::Relaxed);

        let q = queue(d);
        let slot = |id: &str| {
            q["slots"]
                .as_array()
                .expect("slots")
                .iter()
                .find(|s| s["nzo_id"] == id)
                .cloned()
                .expect("row")
        };
        let (a, b, c) = (slot("nzo-a"), slot("nzo-b"), slot("nzo-c"));

        let a_bps = a["job_bps"].as_u64().expect("A is on the wire");
        let b_bps = b["job_bps"].as_u64().expect("B is on the wire");
        assert!(
            (100_000..3_000_000).contains(&a_bps),
            "A's own ~1.7 MB/s, not the line's sum: {a_bps}"
        );
        assert!(b_bps > 10_000_000, "B's own ~110 MB/s: {b_bps}");

        // 512 MiB at ~1.7 MB/s is five minutes. Over the LINE's ~112 MB/s
        // it was under five seconds, which is what the row said.
        let a_left = secs(a["timeleft"].as_str().expect("timeleft"));
        assert!(
            a_left >= 60,
            "A has minutes left at its own rate, not seconds: {a_left}s"
        );

        // The header is still the whole line: both counters, summed.
        let line_kib: f64 = q["kbpersec"].as_str().expect("kbpersec").parse().unwrap();
        assert!(
            line_kib * 1024.0 > b_bps as f64 * 0.5,
            "the header speed stays the whole line: {line_kib} KiB/s"
        );

        // A queued row is on neither slot: no rate of its own.
        assert_eq!(c["job_bps"], Value::Null);
        assert_eq!(c["timeleft"], "0:00:00");
    });
}

#[test]
fn a_stalled_drainer_reports_zero_not_the_lines_rate() {
    with_daemon("jobrate-stall", |d| {
        {
            let mut q = d.queue.lock_ok();
            for (id, name) in [("nzo-a", "Old.A-GRP"), ("nzo-b", "New.B-GRP")] {
                q.push_back(downloading(id, name));
            }
        }
        let a_counter = Arc::new(AtomicU64::new(66 * GIB - 33 * MIB));
        *d.drain_dl.lock_ok() = Some(nzbfast_daemon::wire::DrainSlot {
            nzo_id: "nzo-a".to_string(),
            t_start: Instant::now(),
            progress: a_counter,
            counters: Arc::new(crate::streamhub::FetchCounters::default()),
            total: 66 * GIB,
            resume_seeded: 0,
            pool_live: None,
            abort: None,
            queue_ctl: None,
        });
        *d.active_dl.lock_ok() = Some("nzo-b".to_string());
        d.active_total.store(66 * GIB, Ordering::Relaxed);
        let b_counter = d.progress.reset();
        *d.started_at.lock_ok() = Some(Instant::now());

        queue(d);
        let t = Instant::now();
        std::thread::sleep(Duration::from_millis(300));
        // ONLY B moves: A's 33 MiB sit there while the line runs at
        // 110 MB/s.
        b_counter.fetch_add(
            (110e6 * t.elapsed().as_secs_f64()) as u64,
            Ordering::Relaxed,
        );

        let a = row(d, "nzo-a");
        assert_eq!(
            a["job_bps"], 0,
            "a drainer that moved nothing is at 0, whatever B does"
        );
        assert_eq!(
            a["timeleft"], "0:00:00",
            "no countdown without a rate (the dashboard says stalled)"
        );
        assert_eq!(a["mbleft"], "33.00", "and its own bytes are still owed");
    });
}
