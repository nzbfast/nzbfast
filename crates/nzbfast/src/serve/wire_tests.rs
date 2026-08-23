//! Owner routing across the two live wire slots (F-04): a job that
//! handed the hub over is still on the wire behind the new one, and its
//! stop handles live in the drain slot rather than on the hub.

use super::*;
use std::sync::atomic::AtomicBool;

/// A fresh temp directory for one test's `test_daemon`.
fn tmp(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("nzbfast-wire-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
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
