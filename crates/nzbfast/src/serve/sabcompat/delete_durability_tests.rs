//! The JSON-RPC delete verbs' queue-to-history handover: a record this
//! facade removes from the queue must never be absent from BOTH stores
//! on disk, however the process dies.
//!
//! Its own file rather than `sabcompat.rs`'s, for the size gate (TODO
//! 106) - `sabcompat.rs` was at 3,039 of its 3,000-line ceiling on
//! 15 Aug 2026. Same module.

use super::*;

/// A second Daemon over the same spool, restored from whatever is on
/// disk RIGHT NOW - the crash harness's restart half. The assertion is
/// made against bytes a stop actually would have left, not a fixture
/// written to match a belief about them.
fn restart(d: &Arc<Daemon>) -> Arc<Daemon> {
    let dir = d.spool.parent().expect("spool has a parent").to_path_buf();
    let d2 = crate::serve::testutil::test_daemon(&dir);
    d2.load_queue();
    d2
}

/// Is `id` named by EITHER store on disk right now - the same question
/// [`restart`] asks, read straight off the bytes.
///
/// A second `Daemon` cannot be the one to ask it INSIDE a delete: since
/// 26 Aug 2026 the durable replacement row goes down before the queue
/// row leaves, so at the seam below the record is in both stores, which
/// is the reconcilable tear §158 exists to produce - and `load_queue`
/// answers a tear by resolving it and calling `save_queue`, which blocks
/// on the process-global hold the handler is still holding. That is a
/// harness artefact and not a product one (a real restart is a new
/// process, with no hold in it), but a test that deadlocks on it teaches
/// nobody anything.
///
/// A substring is enough and is the stronger test of the two here:
/// nothing in this window writes a tombstone, so an id that appears at
/// all is an id some store still names.
fn named_on_disk(d: &Arc<Daemon>, id: &str) -> bool {
    let named = |p: std::path::PathBuf| std::fs::read_to_string(p).unwrap_or_default().contains(id);
    named(d.spool.join("queue.json")) || named(d.spool.join("history.jsonl"))
}

/// §296 (sweep S9): `HistoryDelete` on a record whose move never
/// settled takes back what the job already published at the
/// destination. Before the fix nothing on this arm (or the REST one)
/// called `early_take`, so the record - the ONLY thing naming those
/// copies - went down with the row: after a restart the copies sat
/// orphaned in the completed folder for a job the user deleted, an
/// *arr import of a download that no longer exists.
#[test]
fn a_history_delete_takes_back_the_early_copies() {
    let dir = std::env::temp_dir().join(format!("nzbfast-sabearly-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let d = crate::serve::testutil::test_daemon(&dir);

    let out = d.out_dir().join("Early.Release");
    std::fs::create_dir_all(&out).expect("out dir");
    std::fs::write(out.join("ep1.mkv"), b"payload").expect("source");
    let nas_dest = dir.join("nas").join("Early.Release");
    std::fs::create_dir_all(&nas_dest).expect("dest dir");
    std::fs::write(nas_dest.join("ep1.mkv"), b"payload").expect("early copy");

    let job = Arc::new(Mutex::new(
        job_from_json(&json!({
            "nzo_id": "SABnzbd_nzo_9296", "name": "Early.Release",
            "out_dir": out.to_string_lossy(),
            "nzb_path": dir.join("e.nzb").to_string_lossy(), "state": "Completed",
            "move_pending": true,
            "early_published": [{"name": "ep1.mkv", "len": 7, "mtime_ns": 0,
                                 "nzf_id": "", "dest": nas_dest.to_string_lossy()}],
        }))
        .expect("job"),
    ));
    d.history.lock_ok().push(job.clone());

    let mut rpc_error = None;
    let answer = jr_editqueue(
        &d,
        &[json!("HistoryDelete"), json!(0), json!([9296])],
        &mut rpc_error,
    );
    assert!(rpc_error.is_none(), "the delete was refused: {rpc_error:?}");
    assert_eq!(answer, json!(true));
    assert!(d.history.lock_ok().is_empty(), "the row is gone");
    assert!(
        !nas_dest.join("ep1.mkv").exists(),
        "the early copy at the destination goes with the record"
    );
    assert!(!nas_dest.exists(), "the emptied job folder goes with it");
    assert!(
        out.join("ep1.mkv").exists(),
        "HistoryDelete keeps the download's own files - only FinalDelete's \
         files half would touch out_dir"
    );
    let g = job.lock_ok();
    assert!(g.early_published.is_empty(), "the record is spent");
    // The parked row's Arc may still be in the mover's queue from park.
    // `mover_process` reads this flag first and stands down, instead of
    // re-running a whole-job move for a record that no longer exists.
    assert!(g.tombstone, "the popped mover Arc must find nothing to do");
    drop(g);

    let _ = std::fs::remove_dir_all(&dir);
}

/// `GroupDelete` on an ACTIVE job must never publish the queue without
/// the row while nothing in history names it.
///
/// The placeholder used to be written AFTER the retain, and any OTHER
/// mutation's `save_queue` landing in that gap published a queue.json
/// the record had already left - the coalescing saver runs on a thread
/// of its own, so it needs no user to land there. A stop right there
/// lost the record from both stores: no DELETED/MANUAL row for the dupe
/// check or the retry button, and under `GroupParkDelete` - whose whole
/// contract is "files KEPT" - a full payload on disk that nothing names
/// (read-only sweep 2, M8). The `hold_queue_writes` guard closed that,
/// and P2-1 then moved the placeholder AHEAD of the retain outright, so
/// the seam below is now a tear that reads "in BOTH stores" rather than
/// a window held shut. This asks the same question of both shapes: what
/// would a restart RIGHT NOW find.
///
/// The existing regression for this shape (`histstore.rs`) writes the
/// prewrite FIRST by hand: it models the intended order rather than the
/// handler's, so it could not see this. This one drives the handler.
#[test]
fn an_active_delete_never_publishes_absence_before_its_history_row() {
    let dir = std::env::temp_dir().join(format!("nzbfast-sabdel-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let d = crate::serve::testutil::test_daemon(&dir);

    let job = Arc::new(Mutex::new(
        job_from_json(&json!({
            "nzo_id": "SABnzbd_nzo_9911", "name": "Cancelled.Release",
            "out_dir": d.out_dir().join("Cancelled.Release").to_string_lossy(),
            "nzb_path": dir.join("c.nzb").to_string_lossy(), "state": "Downloading",
        }))
        .expect("job"),
    ));
    // Every nonterminal state restores as Queued through the wire form,
    // so the live state goes on by hand.
    job.lock_ok().state = JobState::Downloading;
    d.queue.lock_ok().push_back(job.clone());
    assert!(d.save_queue(), "the queue snapshot the delete starts from");

    let open = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(2));
    *DELETE_PREWRITE_BARRIER.lock_ok() =
        Some((d.spool.display().to_string(), open.clone(), release.clone()));

    let d2 = d.clone();
    let handler = std::thread::spawn(move || {
        let mut rpc_error = None;
        jr_editqueue(
            &d2,
            &[json!("GroupDelete"), json!(0), json!([9911])],
            &mut rpc_error,
        );
        rpc_error
    });

    // The row has left the queue and its replacement is still ahead.
    open.wait();
    // Something else saves the queue - a settings change, a priority
    // edit, the coalescing saver's own thread.
    let (tx, rx) = std::sync::mpsc::channel();
    let d3 = d.clone();
    let saver = std::thread::spawn(move || {
        let ok = d3.save_queue();
        let _ = tx.send(ok);
        ok
    });
    // It either lands here (and publishes the absence) or it is held
    // off until the replacement row is durable. Both answers are read
    // the same way: by asking what a restart would find RIGHT NOW.
    let landed = rx
        .recv_timeout(std::time::Duration::from_millis(1_500))
        .unwrap_or(false);
    {
        let found = named_on_disk(&d, "SABnzbd_nzo_9911");
        assert!(
            found,
            "a save published the queue without the record before anything in \
             history named it ({}), so a stop here lost it from both stores",
            if landed {
                "the save landed"
            } else {
                "no save landed"
            }
        );
    }
    release.wait();
    assert!(handler.join().expect("delete handler").is_none());
    *DELETE_PREWRITE_BARRIER.lock_ok() = None;
    // The hold must be given back, or the first save after any delete
    // would wedge the daemon for good.
    assert!(
        saver.join().expect("the held save"),
        "the delete never released the queue-write hold"
    );

    // ...and the ordinary outcome is unchanged: the record is filed.
    let d5 = restart(&d);
    let row = d5
        .history
        .lock_ok()
        .iter()
        .find(|j| j.lock_ok().nzo_id == "SABnzbd_nzo_9911")
        .cloned()
        .expect("the deleted record must end up in history");
    let g = row.lock_ok();
    assert_eq!(g.delete_status, "MANUAL", "and must say why it is there");
    assert_eq!(g.state, JobState::Failed);
    drop(g);
    assert!(
        d5.queue.lock_ok().is_empty(),
        "and must not come back as a queued job as well"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A store that cannot take the tombstone must not have destroyed
/// anything by the time it says so - P2-1's whole finding, on the
/// facade the report named.
///
/// `HistoryDelete` unlinked the spooled `.nzb` inside its own `retain`
/// and the §296 destination copies right after it, then appended the
/// tombstone LAST and dropped the answer. `history_replay` drops a row
/// only when it finds a `"deleted": true` line, so a refused append put
/// the record back at the next start naming files this delete had
/// already destroyed - under a `true` the handler had already returned.
///
/// Both stores are cut, which is the state a data folder this daemon
/// cannot write at all is in: the append is refused AND the atomic
/// rewrite that ordinarily rescues it is too. Nothing is left to try,
/// so the answer has to be a refusal rather than a delete that half
/// happened.
#[test]
fn a_refused_tombstone_destroys_nothing_and_says_so() {
    use crate::serve::storecut::{Store, arm_store_cut, disarm};

    let dir = std::env::temp_dir().join(format!("nzbfast-sabtombno-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let d = crate::serve::testutil::test_daemon(&dir);

    let out = d.out_dir().join("Refused.Release");
    std::fs::create_dir_all(&out).expect("out dir");
    let nzb = dir.join("refused.nzb");
    std::fs::write(&nzb, b"<nzb/>").expect("spool copy");
    let nas_dest = dir.join("nas").join("Refused.Release");
    std::fs::create_dir_all(&nas_dest).expect("dest dir");
    std::fs::write(nas_dest.join("ep1.mkv"), b"payload").expect("early copy");

    let job = Arc::new(Mutex::new(
        job_from_json(&json!({
            "nzo_id": "SABnzbd_nzo_9401", "name": "Refused.Release",
            "out_dir": out.to_string_lossy(),
            "nzb_path": nzb.to_string_lossy(), "state": "Completed",
            "move_pending": true,
            "early_published": [{"name": "ep1.mkv", "len": 7, "mtime_ns": 0,
                                 "nzf_id": "", "dest": nas_dest.to_string_lossy()}],
        }))
        .expect("job"),
    ));
    // A second row, so the restore is asked to put the survivor back in
    // its own place rather than at whichever end is convenient.
    let other = Arc::new(Mutex::new(
        job_from_json(&json!({
            "nzo_id": "SABnzbd_nzo_9402", "name": "Kept.Release",
            "out_dir": d.out_dir().join("Kept.Release").to_string_lossy(),
            "nzb_path": dir.join("kept.nzb").to_string_lossy(), "state": "Completed",
        }))
        .expect("job"),
    ));
    {
        let mut h = d.history.lock_ok();
        h.push(job.clone());
        h.push(other.clone());
    }
    // ON DISK, so the closing assertion has a store to find the record
    // in - the whole claim being that the delete never reached it.
    assert!(d.history_upsert(&[job.clone(), other.clone()]));

    arm_store_cut(&[Store::HistoryAppend, Store::HistoryRewrite]);
    let mut rpc_error = None;
    let answer = jr_editqueue(
        &d,
        &[json!("HistoryDelete"), json!(0), json!([9401])],
        &mut rpc_error,
    );
    disarm();

    assert_eq!(
        answer,
        json!(false),
        "a delete that removed nothing must not report success"
    );
    let why = rpc_error.expect("the refusal has to reach the client");
    assert!(
        why.contains("history store"),
        "the client is owed the reason, got {why:?}"
    );
    assert!(
        nzb.exists(),
        "the retry .nzb went before the removal was durable - the record it \
         belongs to is still in the store on disk"
    );
    assert!(
        nas_dest.join("ep1.mkv").exists(),
        "the early-published copies went before the removal was durable"
    );
    {
        let h = d.history.lock_ok();
        let ids: Vec<String> = h.iter().map(|j| j.lock_ok().nzo_id.clone()).collect();
        assert_eq!(
            ids,
            vec![
                "SABnzbd_nzo_9401".to_string(),
                "SABnzbd_nzo_9402".to_string()
            ],
            "a refused delete leaves the list exactly as it found it"
        );
    }
    assert!(
        !job.lock_ok().tombstone,
        "the restored record must not stay fenced against its own mover"
    );

    // ...and the record a restart finds is the one still on disk, so
    // the two agree.
    let d2 = restart(&d);
    assert!(
        d2.history
            .lock_ok()
            .iter()
            .any(|j| j.lock_ok().nzo_id == "SABnzbd_nzo_9401"),
        "the record was never removed from the store, so it is still there"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The report's ACTUAL trigger, and the one a user hits: the append is
/// refused while the folder around it stays writable.
///
/// `history_write_locked` opens the store with `create(true).append(true)`
/// and so needs write permission ON THE FILE, while `history_compact`
/// goes through `persist::write_atomic` - private temp file, rename -
/// and needs only the DIRECTORY. One `sudo nzbfast`, a 0444 store or an
/// immutable flag is enough to separate them, which is why
/// `history_publish` has stood the rewrite in for a refused append since
/// M5 and why the delete paths now do too.
///
/// The delete must therefore SUCCEED, and it is the restart that proves
/// it: a rewrite that does not name a record IS that record's tombstone,
/// because replay reads the file as the whole truth. Before 26 Aug 2026
/// this shape lost the tombstone outright and the record came back with
/// its retry `.nzb` already unlinked.
#[test]
fn a_refused_append_is_rescued_by_the_rewrite_and_the_record_stays_gone() {
    use crate::serve::storecut::{Store, arm_store_cut, disarm};

    let dir = std::env::temp_dir().join(format!("nzbfast-sabtombfix-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let d = crate::serve::testutil::test_daemon(&dir);

    let nzb = dir.join("rescued.nzb");
    std::fs::write(&nzb, b"<nzb/>").expect("spool copy");
    let job = Arc::new(Mutex::new(
        job_from_json(&json!({
            "nzo_id": "SABnzbd_nzo_9403", "name": "Rescued.Release",
            "out_dir": d.out_dir().join("Rescued.Release").to_string_lossy(),
            "nzb_path": nzb.to_string_lossy(), "state": "Completed",
        }))
        .expect("job"),
    ));
    d.history.lock_ok().push(job.clone());
    // The row has to be ON DISK first, or the restart below would find
    // nothing whatever the delete did.
    assert!(d.history_upsert(std::slice::from_ref(&job)));
    assert!(
        restart(&d)
            .history
            .lock_ok()
            .iter()
            .any(|j| j.lock_ok().nzo_id == "SABnzbd_nzo_9403"),
        "the fixture's own premise: the record is in the store"
    );

    arm_store_cut(&[Store::HistoryAppend]);
    let mut rpc_error = None;
    let answer = jr_editqueue(
        &d,
        &[json!("HistoryDelete"), json!(0), json!([9403])],
        &mut rpc_error,
    );
    disarm();

    assert!(rpc_error.is_none(), "the delete was refused: {rpc_error:?}");
    assert_eq!(answer, json!(true));
    assert!(
        !nzb.exists(),
        "the removal is durable, so the spool copy goes with the record"
    );
    let d2 = restart(&d);
    assert!(
        d2.history.lock_ok().is_empty(),
        "the record came back from a store that had been rewritten without it"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `GroupDelete` on an ACTIVE job refuses BEFORE it cancels anything.
///
/// The placeholder row is the only thing that will name the record
/// between this handler's `save_queue` and a `park` that is a pipeline
/// drain away, so a store that cannot take it must stop the verb. It
/// stops it at the very top, ahead of `poke_sidecar` and
/// `cancel_tail_fetches`: a refusal that had already aborted the
/// transfer would be a request the user cannot simply make again.
#[test]
fn a_refused_placeholder_cancels_nothing() {
    use crate::serve::storecut::{Store, arm_store_cut, disarm};

    let dir = std::env::temp_dir().join(format!("nzbfast-sabprewno-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let d = crate::serve::testutil::test_daemon(&dir);

    let job = Arc::new(Mutex::new(
        job_from_json(&json!({
            "nzo_id": "SABnzbd_nzo_9404", "name": "Live.Release",
            "out_dir": d.out_dir().join("Live.Release").to_string_lossy(),
            "nzb_path": dir.join("live.nzb").to_string_lossy(), "state": "Downloading",
        }))
        .expect("job"),
    ));
    job.lock_ok().state = JobState::Downloading;
    d.queue.lock_ok().push_back(job.clone());

    arm_store_cut(&[Store::HistoryAppend, Store::HistoryRewrite]);
    let mut rpc_error = None;
    let answer = jr_editqueue(
        &d,
        &[json!("GroupDelete"), json!(0), json!([9404])],
        &mut rpc_error,
    );
    disarm();

    assert_eq!(answer, json!(false));
    let why = rpc_error.expect("the refusal has to reach the client");
    assert!(
        why.contains("history store"),
        "the client is owed the reason, got {why:?}"
    );
    assert_eq!(
        d.queue.lock_ok().len(),
        1,
        "the row left the queue on a delete that could not file its \
         replacement, so a stop right here loses it from both stores"
    );
    let g = job.lock_ok();
    assert!(
        !g.tombstone,
        "the download was cancelled by a refused delete"
    );
    assert!(g.delete_status.is_empty());
    assert_eq!(g.state, JobState::Downloading);
    drop(g);
    assert!(
        d.history.lock_ok().is_empty(),
        "and nothing was filed for a delete that did not happen"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A queue delete replaces the fail sentence, and the CODE that
/// classified the previous failure must go with it (TODO 307's
/// invariant): a job whose tail already stamped Unrepairable and that
/// the user then deletes is a user deletion, not an unrepairable post -
/// left behind, the stale code steers fail_kind(), the history row's
/// fail_action, and altcand's replacement offer.
#[test]
fn a_queue_delete_clears_the_failure_code_with_the_sentence() {
    let dir = std::env::temp_dir().join(format!("nzbfast-delcode-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let d = crate::serve::testutil::test_daemon(&dir);

    let job = Arc::new(Mutex::new(
        job_from_json(&json!({
            "nzo_id": "SABnzbd_nzo_4471", "name": "Dead.Post",
            "out_dir": dir.join("out").to_string_lossy(),
            "nzb_path": dir.join("d.nzb").to_string_lossy(), "state": "Failed",
        }))
        .expect("job"),
    ));
    {
        // The shape postproc leaves: a classified tail failure.
        let mut g = job.lock_ok();
        g.fail_message = "unrepairable: 12 blocks short".into();
        g.fail_code = Some(FailKind::Unrepairable);
    }
    d.queue.lock_ok().push_back(job.clone());

    let mut rpc_error = None;
    let answer = jr_editqueue(
        &d,
        &[json!("GroupDelete"), json!(0), json!([4471])],
        &mut rpc_error,
    );
    assert!(rpc_error.is_none(), "the delete was refused: {rpc_error:?}");
    assert_eq!(answer, json!(true));

    let g = job.lock_ok();
    assert_eq!(g.fail_message, "deleted from the queue");
    assert_eq!(
        g.fail_code,
        Some(FailKind::Local),
        "the deletion is classified as the user's own act, not by the \
         failure it replaced"
    );
    assert_eq!(g.fail_kind(), FailKind::Local, "and fail_kind agrees");
    drop(g);

    let _ = std::fs::remove_dir_all(&dir);
}
