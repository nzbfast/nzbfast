//! The idle-server early start on the queue payload: the banked bytes on
//! the row it belongs to, and its own rate in the header for the second
//! series on the dashboard's throughput chart.
//!
//! The failure this pins was measured on the live daemon on 29 Aug 2026.
//! The early start pulled 29.5 GB of the next job in 9.4 minutes at up to
//! 68.8 MB/s, and `mode=queue` reported that row as `Queued, 0%, mbleft
//! unchanged` for the whole of it, with nothing anywhere carrying the
//! rate - so the feature's best night was indistinguishable from a
//! wedged queue, and was reported as one.
//!
//! Payload-side only, deliberately: the pipeline half is
//! `sidecar::spawn_sidecar`'s own tests. What is proved here is that the
//! counter reaches the row, reaches only THAT row, and that a queue with
//! no early start running is byte-for-byte what it always was.
//!
//! A child of daemon_tests, out here for the size gate (TODO 106); the
//! module is named for its file so size-gate.py's CFG_TEST_MOD resolver
//! still reads it as test code, and `use super::*` brings `with_daemon`
//! and `jv`.

// The daemon crate's root vocabulary, which `use super::*` reached while
// this file lived there: `super::` means `serve` here, and serve's globs
// carry the daemon UNITS but not that crate root's own imports.
use crate::sidecar::Sidecar;
use nzbfast_daemon::MutexExt;
use nzbfast_daemon::daemon::Daemon;
use nzbfast_daemon::testutil::{jv, with_daemon};
use serde_json::Value;
use std::collections::VecDeque;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

/// The payload reports mebibytes (`API_MB`), so the fixtures are whole
/// MiB - a round decimal byte count turns every expectation into an
/// unreadable 38146.97.
const GIB: u64 = 1024 * 1024 * 1024;

/// The whole queue answer, as the dashboard polls it.
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

/// Park an early start on `id` with `bytes` already banked, and hand back
/// its counter so the caller can move it.
fn early_start(d: &Arc<Daemon>, id: &str, bytes: u64) -> Arc<AtomicU64> {
    let progress = Arc::new(AtomicU64::new(bytes));
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("rt");
    *d.sidecar.lock_ok() = Some(Sidecar {
        nzo_id: id.to_string(),
        hub: Arc::new(crate::StreamHub::default()),
        progress: progress.clone(),
        rate_win: Mutex::new(VecDeque::new()),
        cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        task: rt.spawn(async {}),
        borrowed: false,
    });
    // The runtime owns the task handle in the Sidecar above; leaking it
    // keeps the handle valid for the life of the test without a second
    // thread. `with_daemon` tears the whole fixture down after.
    std::mem::forget(rt);
    progress
}

#[test]
fn the_early_start_s_banked_bytes_reach_its_own_row_and_no_other() {
    with_daemon("prefetchprog", |d| {
        {
            let mut q = d.queue.lock_ok();
            q.push_back(jv(
                "nzo-a",
                "Set.A-GRP",
                serde_json::json!({"total_bytes": 40 * GIB}),
            ));
            q.push_back(jv(
                "nzo-b",
                "Set.B-GRP",
                serde_json::json!({"total_bytes": 40 * GIB}),
            ));
        }
        // Nothing prefetching: the row is exactly what it has always
        // been, and the flag says so.
        let a = row(d, "nzo-a");
        assert_eq!(a["percentage"], "0");
        assert_eq!(a["prefetching"], false);
        assert_eq!(a["mb"], "40960.00");
        assert_eq!(a["mbleft"], "40960.00");

        // The early start takes job B and banks 10 of its 40 GB.
        early_start(d, "nzo-b", 10 * GIB);

        let b = row(d, "nzo-b");
        assert_eq!(b["prefetching"], true);
        assert_eq!(b["prefetched_mb"], "10240.00");
        assert_eq!(
            b["percentage"], "25",
            "the banked bytes are bytes this queue no longer has to fetch"
        );
        assert_eq!(
            b["mbleft"], "30720.00",
            "and what is left is what is left, not the whole set"
        );

        // ...and job A, which the early start is not holding, is
        // untouched: the whole reason `sc` is matched by nzo_id.
        let a = row(d, "nzo-a");
        assert_eq!(a["percentage"], "0");
        assert_eq!(a["prefetching"], false);
        assert_eq!(a["mbleft"], "40960.00");

        // The queue's own remainder is summed from the rows, so it moves
        // with them - the header and its parts are one arithmetic on one
        // instant, which is the §91 contract the walk exists to keep.
        let q = queue(d);
        assert_eq!(q["mbleft"], "71680.00");
    });
}

/// The header's second rate, which is the whole of what the chart's
/// second series is drawn from. Zero with no early start running, so an
/// ordinary queue draws exactly one trace.
#[test]
fn the_header_carries_the_early_start_s_own_rate() {
    with_daemon("prefetchrate", |d| {
        d.queue.lock_ok().push_back(jv(
            "nzo-b",
            "Set.B-GRP",
            serde_json::json!({"total_bytes": 40 * GIB}),
        ));
        assert_eq!(
            queue(d)["prefetch_bps"],
            serde_json::json!(0.0),
            "no early start, no second series"
        );

        let progress = early_start(d, "nzo-b", 0);
        // First poll opens the window; a single sample is not a rate.
        assert_eq!(queue(d)["prefetch_bps"], serde_json::json!(0.0));

        // Bytes move, and a later poll spans a real interval. The window
        // is sampled where it is READ, so two polls with movement
        // between them is exactly what the dashboard does once a second.
        std::thread::sleep(std::time::Duration::from_millis(400));
        progress.store(50_000_000, Ordering::Relaxed);
        let bps = queue(d)["prefetch_bps"].as_f64().expect("a number");
        assert!(
            bps > 1_000_000.0,
            "50 MB across ~0.4 s is a rate, not a rounding error: {bps}"
        );

        // The active job's own rate is untouched by any of it - two
        // pipelines, two numbers, and `kbpersec` is the one every SAB
        // client reads for the job it asked about. Two decimals and
        // KiB since 31 Aug 2026 (SAB's `"%.2f" % (bps / KIBI)`); the
        // subject here is the ZERO, not the formatting.
        assert_eq!(queue(d)["kbpersec"], "0.00");
    });
}
