//! The per-job rate windows behind `Daemon::job_rates` (child of
//! `daemon_speed`, so the private `step` / `feed` are in scope).

use super::*;
use std::time::Duration;

const MB: u64 = 1_000_000;

/// One-second polls of a slot pair whose counters each move at a steady
/// rate (bytes per second), the way a dashboard polls the queue. Returns
/// the LAST step's rates. `t0` is shared so a test can chain a hand-over.
fn run(
    wins: &mut JobRateWins,
    t0: Instant,
    seconds: std::ops::Range<u64>,
    active: Option<(&str, u64)>,
    drain: Option<(&str, u64)>,
) -> JobRates {
    let mut last = JobRates::default();
    for s in seconds {
        let at = t0 + Duration::from_secs(s);
        last = wins.step(
            at,
            active.map(|(id, per_s)| (id, per_s * s)),
            drain.map(|(id, per_s)| (id, per_s * s)),
        );
    }
    last
}

/// THE DEFECT, in its own arithmetic. Job A is draining its last bytes at
/// 1.7 MB/s while job B takes the line at 110 MB/s. The whole line reads
/// ~112 MB/s, and A's row divided by that read "3 seconds left" for
/// minutes. Each slot's OWN rate must come back, and neither is the sum.
#[test]
fn a_crawling_drainer_and_a_fast_successor_each_read_their_own_rate() {
    let mut w = JobRateWins::default();
    let r = run(
        &mut w,
        Instant::now(),
        0..6,
        Some(("B", 110 * MB)),
        Some(("A", 1_700_000)),
    );
    let b = r.of("B").expect("B is on the wire");
    let a = r.of("A").expect("A is still draining");
    assert!((b - 110e6).abs() < 1e6, "B's own rate, not the line's: {b}");
    assert!((a - 1.7e6).abs() < 1e4, "A's own rate, not the line's: {a}");
    assert!(a * 50.0 < b, "the drainer is nowhere near the successor");
}

/// A queued row is on neither slot and has no rate of its own; the caller
/// must be able to tell that from a measured stall.
#[test]
fn a_job_on_neither_slot_has_no_rate_and_a_stall_is_a_zero() {
    let mut w = JobRateWins::default();
    let r = run(
        &mut w,
        Instant::now(),
        0..6,
        Some(("B", 110 * MB)),
        Some(("A", 0)),
    );
    assert_eq!(r.of("C"), None, "a queued job has no rate to divide by");
    assert_eq!(
        r.of("A"),
        Some(0.0),
        "a drainer whose counter has not moved is a 0 of its own, whatever B is doing"
    );
}

/// The hand-over: A was active a poll ago and is the drainer now. Its
/// window must come with it, or its row reads 0 for the first second of
/// every hand-over - a false stall on exactly the row the user is
/// watching finish. B, new to its slot, starts from nothing.
#[test]
fn a_hand_over_carries_the_predecessors_window_to_the_drain_slot() {
    let mut w = JobRateWins::default();
    let t0 = Instant::now();
    // A alone on the wire at 50 MB/s for four seconds.
    let r = run(&mut w, t0, 0..5, Some(("A", 50 * MB)), None);
    assert!((r.of("A").expect("A") - 50e6).abs() < 1e6);
    // A drains now (its own counter carries on), B is active on a fresh
    // counter.
    let r = w.step(
        t0 + Duration::from_secs(5),
        Some(("B", 0)),
        Some(("A", 50 * MB * 5)),
    );
    let a = r.of("A").expect("A drains");
    assert!(a > 40e6, "A's rate carried across, not reset to 0: {a}");
    assert_eq!(
        r.active.as_ref().map(|(id, _)| id.as_str()),
        Some("B"),
        "and B owns the active slot"
    );
    assert_eq!(r.of("B"), Some(0.0), "B has one sample, which is no rate");
}

/// A new job on the active slot must not inherit the previous job's
/// window even when its counter has already OUT-RUN the old one, which
/// the "counter went backwards" rule alone cannot see.
#[test]
fn a_new_active_job_never_inherits_the_old_ones_window() {
    let mut w = JobRateWins::default();
    let t0 = Instant::now();
    run(&mut w, t0, 0..4, Some(("A", MB)), None);
    let r = w.step(t0 + Duration::from_secs(9), Some(("B", 900 * MB)), None);
    assert_eq!(
        r.of("B"),
        Some(0.0),
        "one sample of a new job, not 900 MB over nine seconds"
    );
}

/// Nothing on the wire forgets both windows.
#[test]
fn an_empty_wire_forgets_both_windows() {
    let mut w = JobRateWins::default();
    let t0 = Instant::now();
    run(&mut w, t0, 0..4, Some(("B", 10 * MB)), Some(("A", MB)));
    let r = w.step(t0 + Duration::from_secs(5), None, None);
    assert_eq!(r, JobRates::default());
    assert!(w.active.is_none() && w.drain.is_none());
}

/// The Daemon-level read: owners and counters come off the real slots,
/// and the drainer's rate is its own. Two counters, as the runner has.
#[test]
fn the_daemon_reports_each_slots_own_rate_and_forgets_when_idle() {
    let dir = std::env::temp_dir().join(format!("nzbfast-jobrates-{}", std::process::id()));
    let dir = crate::testscratch::ScratchDir::attach(&dir);
    let d = crate::testutil::test_daemon(&dir);
    assert_eq!(
        d.job_rates(),
        JobRates::default(),
        "idle: nothing to report"
    );

    *d.started_at.lock_ok() = Some(Instant::now());
    *d.active_dl.lock_ok() = Some("B".to_string());
    let old = Arc::new(AtomicU64::new(0));
    *d.drain_dl.lock_ok() = Some(crate::wire::DrainSlot {
        nzo_id: "A".to_string(),
        t_start: Instant::now(),
        progress: old.clone(),
        counters: Arc::new(crate::streamhub::FetchCounters::default()),
        total: 0,
        resume_seeded: 0,
        pool_live: None,
        abort: None,
        queue_ctl: None,
    });
    let fresh = d.progress.reset();
    // Two polls a real 300 ms apart (over the window's quarter second):
    // the successor moved 33 MB, the drainer 30 kB.
    d.job_rates();
    std::thread::sleep(Duration::from_millis(300));
    fresh.fetch_add(33_000_000, Ordering::Relaxed);
    old.fetch_add(30_000, Ordering::Relaxed);
    let r = d.job_rates();
    let b = r.of("B").expect("B");
    let a = r.of("A").expect("A");
    assert!(b > 10e6, "B ran ~110 MB/s over the poll: {b}");
    assert!(a < 1e6 && a > 0.0, "A crawled: {a}");
    assert!(b > a * 50.0, "the two are not one line figure");

    // Nothing on the wire any more: forgotten.
    *d.started_at.lock_ok() = None;
    assert_eq!(d.job_rates(), JobRates::default());
    assert!(d.job_win.lock_ok().active.is_none());
}
