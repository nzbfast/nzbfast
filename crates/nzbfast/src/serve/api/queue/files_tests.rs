//! TODO 274 (e): which of the three answers `mode=get_files` gives, and
//! when.
//!
//! `listing` has three sources and they are not interchangeable: the
//! ACTIVE run's live table, the frozen table of a run whose TAIL is
//! still going, and - for a job that has not started - a parse of its
//! spooled `.nzb`, which carries names and sizes and no state at all.
//! Picking the third for a job in its tail is the defect this arm was
//! added for: measured on the live daemon 24 Aug 2026, every one of 264
//! polls across a 4.5-minute Repairing tail answered "queued, 0 of
//! 63 MB" for all 88 files of a post that had downloaded every byte,
//! because the next job's start had dropped the table.
//!
//! A sibling file rather than an inline `mod`, per this directory's
//! convention (see `caps_tests.rs`).

use super::*;
use crate::serve::testutil::test_daemon;

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("nzbfast-getfiles-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("temp dir");
    d
}

/// Two files, one payload and one recovery volume the plan never
/// queued, with the payload three articles short - the shape that makes
/// the state words say something a block count cannot.
fn frozen_table() -> crate::streamhub::TailTable {
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    let slot = std::sync::Arc::new(crate::unpack::FileSlot {
        hint: "pack.part01.rar".into(),
        is_par2_main: false,
        sample_skipped: false,
        par2_sniffed: AtomicBool::new(false),
        total_segments: 10,
        remaining: AtomicUsize::new(0),
        missing: AtomicUsize::new(3),
        errors: AtomicUsize::new(0),
        deferred: AtomicUsize::new(0),
        abandoned: AtomicUsize::new(0),
        capture: std::sync::Mutex::new(None),
    });
    let rows = vec![
        crate::streamhub::JobFileRow {
            id: "aaaaaaaaaaaaaaaa".into(),
            name: "pack.part01.rar".into(),
            bytes: 1_000_000,
            segments: 10,
            slot: Some(0),
        },
        crate::streamhub::JobFileRow {
            id: "bbbbbbbbbbbbbbbb".into(),
            name: "pack.vol000+01.par2".into(),
            bytes: 40_000,
            segments: 2,
            slot: None,
        },
    ];
    crate::streamhub::TailTable::settled(std::sync::Arc::new(crate::streamhub::freeze_rows(
        &rows,
        &[slot],
    )))
}

/// A queue row for `id`, pointing its `nzb_path` at a file that does not
/// exist - so the spooled-`.nzb` arm, if it is reached, answers with an
/// empty listing and the test can tell the two apart without asserting
/// on a fixture NZB.
fn queue_row(d: &std::sync::Arc<crate::serve::Daemon>, id: &str) {
    let v = json!({
        "nzo_id": id, "name": id, "nzb_path": "/nonexistent/spool.nzb",
        "out_dir": "/tmp/out", "state": "Downloading", "priority": 0,
    });
    let job = crate::serve::job_from_json(&v).expect("job_from_json");
    d.queue
        .lock_ok()
        .push_back(std::sync::Arc::new(Mutex::new(job)));
}

/// The tail arm: a job past its network phase is answered from the table
/// its run left behind, with the run's own words.
///
/// The two rows are the whole point of the drawer this feeds. "damaged"
/// is articles that never arrived, and it is a different fact from the
/// verify line's block count - a user watching Repairing is asking which
/// FILE is short. The volume with no slot stays in the listing and stays
/// marked as recovery, because a listing that drops the repair set does
/// not describe the post.
#[test]
fn a_job_in_its_tail_is_listed_from_the_table_its_run_left_behind() {
    let dir = tmp("tail");
    let d = test_daemon(&dir);
    queue_row(&d, "nzo_tail");
    crate::streamhub::keep_tail_table(
        &mut d.hub.tail_files.lock_ok(),
        "nzo_tail".into(),
        frozen_table(),
    );
    // The same word the queue payload's status comes from, so the
    // listing and the row it is drawn under cannot disagree.
    d.hub
        .activity
        .lock_ok()
        .insert("nzo_tail".into(), "repairing");

    let rows = listing(&d, "nzo_tail").expect("a queued job answers");
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[0]["filename"], "pack.part01.rar");
    assert_eq!(rows[0]["state"], "damaged", "{rows:?}");
    assert_eq!(rows[0]["segments_missing"], 3, "{rows:?}");
    assert_eq!(rows[0]["bytes_left"], 0, "nothing is still owed: {rows:?}");
    assert_eq!(rows[0]["status"], "finished", "SAB's word for it: {rows:?}");
    assert_eq!(rows[1]["state"], "recovery", "{rows:?}");
    assert_eq!(rows[1]["recovery"], true, "{rows:?}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// ...and ONLY in its tail. A retry re-queues the same nzo_id, and the
/// entry outlives its job by design (it is bounded by a cap, not by a
/// park hook), so a listing keyed on the id alone would report the
/// previous run's damage against a job that has not started.
///
/// Same daemon, same table, the phase word taken away: the answer must
/// fall through to the spooled `.nzb`, which here is missing - an empty
/// listing rather than the frozen rows.
#[test]
fn a_job_that_is_not_in_its_tail_is_never_answered_from_a_retired_table() {
    let dir = tmp("notail");
    let d = test_daemon(&dir);
    queue_row(&d, "nzo_retry");
    crate::streamhub::keep_tail_table(
        &mut d.hub.tail_files.lock_ok(),
        "nzo_retry".into(),
        frozen_table(),
    );
    assert!(
        d.tail_phase("nzo_retry").is_none(),
        "the fixture must not have a phase word for this arm to mean anything"
    );

    let rows = listing(&d, "nzo_retry").expect("the queue row still answers");
    assert!(
        rows.is_empty(),
        "a job with no tail phase must not wear its previous run's rows: {rows:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A phase word for an id with no queue row answers nobody.
///
/// `activity` is keyed by nzo_id and cleared at park, but a retired
/// table is not, so the queue row is what keeps a departed job from
/// being listed out of the residue. `None` here is what the caller
/// turns into "unknown nzo_id".
#[test]
fn a_retired_table_alone_is_not_a_job() {
    let dir = tmp("gone");
    let d = test_daemon(&dir);
    crate::streamhub::keep_tail_table(
        &mut d.hub.tail_files.lock_ok(),
        "nzo_gone".into(),
        frozen_table(),
    );
    d.hub
        .activity
        .lock_ok()
        .insert("nzo_gone".into(), "repairing");

    assert!(listing(&d, "nzo_gone").is_none());

    let _ = std::fs::remove_dir_all(&dir);
}
