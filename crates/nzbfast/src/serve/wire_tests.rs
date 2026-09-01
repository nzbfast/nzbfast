//! Owner routing across the two live wire slots (F-04): a job that
//! handed the hub over is still on the wire behind the new one, and its
//! stop handles live in the drain slot rather than on the hub.

use super::*;
use std::sync::atomic::AtomicBool;

/// A fresh temp directory for one test's `test_daemon`.
fn tmp(tag: &str) -> crate::testscratch::ScratchDir {
    let dir = std::env::temp_dir().join(format!("nzbfast-wire-{tag}-{}", std::process::id()));
    crate::testscratch::ScratchDir::attach(&dir)
}

/// A drain slot for `nzo_id` with a fresh abort flag, as `tasks/worker.rs`
/// installs it at the hand-over. The `QueueControl` is the real type,
/// unattached: `abort`/`drain` answer false with no pool to reach, which
/// is exactly the "handles retained, run already gone" case.
fn drain_slot(nzo_id: &str) -> (DrainSlot, Arc<AtomicBool>) {
    let abort = Arc::new(AtomicBool::new(false));
    let slot = DrainSlot {
        nzo_id: nzo_id.to_string(),
        t_start: Instant::now(),
        progress: Arc::new(AtomicU64::new(0)),
        counters: Arc::new(crate::streamhub::FetchCounters::default()),
        total: 0,
        resume_seeded: 0,
        pool_live: None,
        abort: Some(abort.clone()),
        queue_ctl: Some(Arc::new(nzbkit::pool::QueueControl::default())),
    };
    (slot, abort)
}

#[test]
fn a_draining_predecessor_takes_the_stop_signal_after_the_successor_owns_the_hub() {
    let dir = tmp("route");
    let d = crate::serve::testutil::test_daemon(&dir);
    let (slot, abort_a) = drain_slot("A");
    *d.drain_dl.lock_ok() = Some(slot);
    *d.active_stream.lock_ok() = Some("B".to_string());

    // The hub names B, so the old owner test declines for A forever.
    assert!(!d.owns_hub(|id| id == "A"));
    assert!(d.owns_wire(|id| id == "A"), "A is still on the wire");
    assert!(d.owns_wire(|id| id == "B"));
    assert!(!d.owns_wire(|id| id == "C"));

    // Routing by owner reaches A's detached handles.
    d.fire_drain(true, |id| id == "A");
    assert!(
        abort_a.load(Ordering::Relaxed),
        "the draining job's abort flag must be set"
    );
}

#[test]
fn the_successor_is_never_touched_by_a_signal_aimed_at_the_drainer() {
    let dir = tmp("successor");
    let d = crate::serve::testutil::test_daemon(&dir);
    let (slot, abort_a) = drain_slot("A");
    *d.drain_dl.lock_ok() = Some(slot);
    *d.active_stream.lock_ok() = Some("B".to_string());
    let hub_abort = Arc::new(AtomicBool::new(false));
    *d.hub.abort.lock_ok() = Some(hub_abort.clone());

    // A request naming B finds no matching drain slot and signals
    // nothing there; a request naming A never reaches the hub.
    assert!(!d.fire_drain(true, |id| id == "B"));
    assert!(!abort_a.load(Ordering::Relaxed));
    d.fire_drain(true, |id| id == "A");
    assert!(abort_a.load(Ordering::Relaxed));
    assert!(
        !hub_abort.load(Ordering::Relaxed),
        "the active job's abort must be untouched"
    );
}

#[test]
fn a_graceful_pause_of_the_drainer_leaves_its_abort_flag_alone() {
    let dir = tmp("graceful");
    let d = crate::serve::testutil::test_daemon(&dir);
    let (slot, abort_a) = drain_slot("A");
    *d.drain_dl.lock_ok() = Some(slot);
    *d.active_stream.lock_ok() = Some("B".to_string());

    d.fire_drain(false, |id| id == "A");
    assert!(
        !abort_a.load(Ordering::Relaxed),
        "a wind-down must not drop in-flight reads"
    );
}

#[test]
fn an_empty_drain_slot_answers_no_owner() {
    let dir = tmp("empty");
    let d = crate::serve::testutil::test_daemon(&dir);
    assert!(!d.fire_drain(true, |_| true));
    assert!(!d.owns_wire(|_| true));
}

/// F5: a job whose NZB declared no `bytes=` must not report itself
/// FINISHED for the whole of its download.
///
/// `arith`'s old `total.max(1)` clamped `done` to 1 and answered
/// `(1, 1, 0)` - 100%, nothing left - from the first article onward,
/// which is the exact shape `get::plan`'s UX §15 comment records the
/// percentage pair being rebuilt to end ("pinned at 100% / 0 left with
/// articles still in flight"). An unknown total is now reported as
/// unknown, and `done` passes through truthfully because
/// `requeue_cost`'s refetch arm reads it.
///
/// Both wire slots, because they are two copies of the same
/// arithmetic: the owner's, and the draining predecessor's.
#[test]
fn an_undeclared_total_is_reported_unknown_and_never_as_complete() {
    let dir = tmp("unknown-total");
    let d = crate::serve::testutil::test_daemon(&dir);

    // Control first, so the fallback is known to be doing its job: a
    // declared total with no published plan reports ordinary progress.
    *d.active_dl.lock_ok() = Some("U".to_string());
    d.progress.reset().store(5_000_000, Ordering::Relaxed);
    d.active_total.store(20_000_000, Ordering::Relaxed);
    assert_eq!(
        d.wire_counters("U"),
        Some((5_000_000, 20_000_000, 15_000_000)),
        "control: the declared-total fallback is unchanged"
    );

    // The subject. Nothing here is 1, and nothing here is complete.
    d.active_total.store(0, Ordering::Relaxed);
    assert_eq!(
        d.wire_counters("U"),
        Some((5_000_000, 0, 0)),
        "an undeclared total is unknown - the bytes fetched are real, \
         the total and the remainder are the unknowns"
    );

    // ...and the queue row that reads it says 0%, never 100%.
    let (pct, left) = crate::serve::sabcompat::slot_progress(
        JobState::Downloading,
        d.wire_counters("U").map(|(done, total, _)| (done, total)),
        false,
        0,
        0,
        0,
    );
    assert_eq!(
        (pct, left),
        (0, 0),
        "0% is this surface's spelling of an unknown; 100% is a claim \
         that the download has finished"
    );

    // The draining predecessor takes the identical arithmetic.
    *d.active_dl.lock_ok() = Some("SUCC".to_string());
    let (mut slot, _abort) = drain_slot("PRED");
    slot.progress.store(3_000_000, Ordering::Relaxed);
    slot.total = 0;
    *d.drain_dl.lock_ok() = Some(slot);
    assert_eq!(
        d.wire_counters("PRED"),
        Some((3_000_000, 0, 0)),
        "the drain slot must not answer 100% either"
    );
}
