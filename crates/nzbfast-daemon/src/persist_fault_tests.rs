//! The three persistence findings of the 21 Sep 2026 codex sweep, each
//! as the fault it named, driven through the real stores and restored
//! by a fresh daemon over the same spool - the bytes a crash or a bad
//! chmod leaves, never a fixture hand-written to match a belief.
//!
//!  * P2-1 (the 8 Aug sweep's H4, still open then): `load_queue` ignored
//!    `history_compact`'s answer, so a migration whose history half
//!    failed retired `queue.json` anyway, and a routed terminal row whose
//!    history half failed was tombstoned out of `queue.jsonl` by the
//!    save that followed. Lost from both stores at the next start.
//!  * P2-2: both replays read "cannot read" as "does not exist", loaded
//!    empty, and the next rewrite replaced the unread rows with that
//!    emptiness - orphan recovery could trigger it by itself.
//!  * P2-3: a park whose history write was refused still tombstoned its
//!    queue row; the justification (the rewrite and the queue save need
//!    the same directory) stopped being true when the queue moved to an
//!    append-only store.
//!
//! The three share one remedy: `Daemon::hist_owed`, the terminal records
//! the history store refused, carried in the QUEUE store as terminal
//! rows until history takes them. `restore_records` has routed a
//! terminal queue row into history since before the split, so the next
//! start files them again with no new code path.

use super::*;
// Its only use is inside a #[cfg(unix)] test (the permission-mode arms
// below), so an unconditional import is an unused one on windows and
// -D warnings makes that fatal on the windows-gated clippy leg.
#[cfg(unix)]
use crate::histstore::HistWrite;
use crate::storecut::{Store, arm_store_cut, disarm};
use crate::testutil::{stored_queue, test_daemon};

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("nzbfast-persistfault-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A record in the shape both stores round-trip.
fn row(d: &Arc<Daemon>, id: &str, state: &str) -> Value {
    let mut v = json!({
        "nzo_id": id,
        "name": format!("Release.{id}"),
        "out_dir": crate::naming::out_dir(d).join(format!("Release.{id}")).to_string_lossy(),
        "nzb_path": d.spool.join(format!("{id}.nzb")).to_string_lossy(),
        "state": state,
    });
    if state == "Completed" || state == "Failed" {
        v["finished_unix"] = json!(1_700_000_000);
    }
    v
}

fn job(d: &Arc<Daemon>, id: &str, state: &str) -> Arc<Mutex<Job>> {
    Arc::new(Mutex::new(job_from_json(&row(d, id, state)).expect("job")))
}

fn queue_ids(d: &Arc<Daemon>) -> Vec<String> {
    d.queue
        .lock_ok()
        .iter()
        .map(|j| j.lock_ok().nzo_id.clone())
        .collect()
}

fn history_ids(d: &Arc<Daemon>) -> Vec<String> {
    d.history
        .lock_ok()
        .iter()
        .map(|j| j.lock_ok().nzo_id.clone())
        .collect()
}

fn stored_state(d: &Arc<Daemon>, id: &str) -> Option<String> {
    stored_queue(d)
        .iter()
        .find(|v| v["nzo_id"] == id)
        .map(|v| v["state"].as_str().unwrap_or("").to_string())
}

fn replayed_history_ids(d: &Arc<Daemon>) -> Vec<String> {
    d.history_replay().0.into_iter().map(|j| j.nzo_id).collect()
}

/// P2-1, the migration arm: a legacy `queue.json` whose history array
/// cannot be written into `history.jsonl` must not be retired with that
/// array's records in no store. It IS retired - and the records ride in
/// the queue store it was retired into, as terminal rows, until a start
/// whose history write lands files them.
#[test]
fn a_failed_history_migration_carries_its_records_in_the_queue_store() {
    let dir = tmp("migrate");
    let d = test_daemon(&dir);
    std::fs::write(
        d.spool.join("queue.json"),
        json!({
            "queue": [row(&d, "nzo_q1", "Queued")],
            "history": [row(&d, "nzo_h1", "Completed")],
            "next_id": 7,
        })
        .to_string(),
    )
    .unwrap();

    arm_store_cut(&[Store::HistoryRewrite]);
    d.load_queue();
    disarm();

    assert_eq!(queue_ids(&d), ["nzo_q1"]);
    assert_eq!(history_ids(&d), ["nzo_h1"], "the record is live either way");
    assert!(
        d.queue_store_path().exists() && !d.spool.join("queue.json").exists(),
        "the migration's queue half still runs - what changes is what it carries"
    );
    assert!(
        replayed_history_ids(&d).is_empty(),
        "the fixture's premise: history.jsonl took nothing"
    );
    assert_eq!(
        stored_state(&d, "nzo_h1").as_deref(),
        Some("Completed"),
        "the legacy history record must be in the queue store, as the terminal row \
         restore_records routes into history"
    );

    // The next start: the store is authoritative, the terminal row is
    // routed into history, and this time the compaction lands - after
    // which the queue store stops carrying it.
    let d2 = test_daemon(&dir);
    d2.load_queue();
    assert_eq!(queue_ids(&d2), ["nzo_q1"]);
    assert_eq!(history_ids(&d2), ["nzo_h1"]);
    assert_eq!(
        replayed_history_ids(&d2),
        ["nzo_h1"],
        "history.jsonl holds it now"
    );
    assert_eq!(
        stored_state(&d2, "nzo_h1"),
        None,
        "once history has it, the queue store's copy is tombstoned"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// P2-1, the routed arm: a terminal row that was still in `queue.jsonl`
/// when the daemon died (interrupted post-processing) is routed into
/// history at load, and its history write fails. The queue save that
/// follows used to tombstone it - and so did every later save.
#[test]
fn a_routed_terminal_row_survives_a_refused_history_write_and_every_later_save() {
    let dir = tmp("routed");
    let d = test_daemon(&dir);
    d.queue.lock_ok().push_back(job(&d, "nzo_q1", "Queued"));
    d.queue.lock_ok().push_back(job(&d, "nzo_t1", "Completed"));
    assert!(d.save_queue(), "the fixture's premise");
    assert_eq!(stored_state(&d, "nzo_t1").as_deref(), Some("Completed"));

    let d2 = test_daemon(&dir);
    arm_store_cut(&[Store::HistoryRewrite]);
    d2.load_queue();
    disarm();
    assert_eq!(queue_ids(&d2), ["nzo_q1"]);
    assert_eq!(
        history_ids(&d2),
        ["nzo_t1"],
        "routed into history in memory"
    );
    assert!(
        replayed_history_ids(&d2).is_empty(),
        "...and refused on disk"
    );
    assert_eq!(
        stored_state(&d2, "nzo_t1").as_deref(),
        Some("Completed"),
        "the load's own queue save must keep the row, not tombstone it"
    );

    // A later mutation's save, in the same run, with the history store
    // still refusing: the row is still carried.
    arm_store_cut(&[Store::HistoryRewrite, Store::HistoryAppend]);
    d2.queue.lock_ok().push_back(job(&d2, "nzo_q2", "Queued"));
    assert!(d2.save_queue());
    disarm();
    assert_eq!(stored_state(&d2, "nzo_t1").as_deref(), Some("Completed"));

    // ...and the record can still be deleted from history meanwhile
    // without the carried row resurrecting it: once it has LEFT history,
    // the queue store stops carrying it.
    d2.history.lock_ok().clear();
    assert!(d2.save_queue());
    assert_eq!(
        stored_state(&d2, "nzo_t1"),
        None,
        "a record that left history is not carried into the next start"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// P2-1's happy ending, checked separately from the two above: the
/// carried row is filed at the next start once history takes it, and
/// nothing is filed twice.
#[test]
fn a_carried_row_is_filed_once_history_takes_it() {
    let dir = tmp("carried");
    let d = test_daemon(&dir);
    d.queue.lock_ok().push_back(job(&d, "nzo_t1", "Failed"));
    assert!(d.save_queue());

    let d2 = test_daemon(&dir);
    arm_store_cut(&[Store::HistoryRewrite]);
    d2.load_queue();
    disarm();
    assert_eq!(stored_state(&d2, "nzo_t1").as_deref(), Some("Failed"));

    let d3 = test_daemon(&dir);
    d3.load_queue();
    assert_eq!(history_ids(&d3), ["nzo_t1"]);
    assert!(d3.queue.lock_ok().is_empty());
    assert_eq!(replayed_history_ids(&d3), ["nzo_t1"]);
    assert_eq!(stored_state(&d3, "nzo_t1"), None);
    assert!(
        d3.hist_owed.lock_ok().is_empty(),
        "nothing is owed once it landed"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// P2-3: the park whose history append AND rescue are refused (an
/// unwritable `history.jsonl` in an unwritable directory, beside a
/// `queue.jsonl` that still takes an append). The queue row used to be
/// tombstoned by the save park schedules; the terminal outcome is now
/// kept there and filed at the next start.
#[test]
fn a_park_the_history_store_refuses_keeps_its_terminal_row_in_the_queue_store() {
    let dir = tmp("park");
    let d = test_daemon(&dir);
    let j = job(&d, "nzo_p1", "Finishing");
    d.queue.lock_ok().push_back(j.clone());
    assert!(d.save_queue());
    j.lock_ok().state = JobState::Completed;

    arm_store_cut(&[Store::HistoryAppend, Store::HistoryRewrite]);
    d.park_gen(j, None);
    disarm();

    assert!(
        d.queue.lock_ok().is_empty(),
        "park took it out of the live queue"
    );
    assert_eq!(history_ids(&d), ["nzo_p1"], "...and filed it in memory");
    assert!(
        replayed_history_ids(&d).is_empty(),
        "the fault under test: history took nothing"
    );
    assert_eq!(
        stored_state(&d, "nzo_p1").as_deref(),
        Some("Completed"),
        "the queue store must hold the terminal row, not a tombstone"
    );

    let d2 = test_daemon(&dir);
    d2.load_queue();
    assert!(
        d2.queue.lock_ok().is_empty(),
        "a Completed row does not run again"
    );
    assert_eq!(
        history_ids(&d2),
        ["nzo_p1"],
        "the outcome survived the restart"
    );
    assert_eq!(replayed_history_ids(&d2), ["nzo_p1"]);
    assert_eq!(stored_state(&d2, "nzo_p1"), None);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A retry of a carried record must not be shadowed by its own stale
/// terminal line: once the record is back in the live queue, the queue
/// row wins and the carried copy is dropped.
#[test]
fn a_carried_record_back_in_the_queue_is_published_as_queued() {
    let dir = tmp("retry");
    let d = test_daemon(&dir);
    let j = job(&d, "nzo_r1", "Failed");
    d.history.lock_ok().push(j.clone());
    d.hist_owe(&j);
    assert!(d.save_queue());
    assert_eq!(stored_state(&d, "nzo_r1").as_deref(), Some("Failed"));

    // The retry's shape: the record moves back to the queue as Queued.
    d.history.lock_ok().clear();
    j.lock_ok().state = JobState::Queued;
    d.queue.lock_ok().push_back(j);
    assert!(d.save_queue());
    assert_eq!(stored_state(&d, "nzo_r1").as_deref(), Some("Queued"));
    assert!(d.hist_owed.lock_ok().is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// P2-2: a store that EXISTS and cannot be read is not an empty store.
/// Both are made unreadable in a writable directory (mode 0200, the
/// finding's own trigger: the directory takes a rewrite, the file
/// refuses a read), a daemon is started over them, and everything that
/// would publish its empty view over the unread rows is refused. The
/// append is refused too, and not by the latch: both append paths open
/// the store read+append to mend a torn tail, so a file that cannot be
/// read cannot be appended to either - the store is frozen for the run
/// and `save_failed_at` says so.
#[cfg(unix)]
#[test]
fn an_unreadable_store_is_never_rewritten_from_the_empty_view_it_loaded() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmp("unreadable");
    let d = test_daemon(&dir);
    let q1 = job(&d, "nzo_q1", "Queued");
    q1.lock_ok().paused = true;
    d.queue.lock_ok().push_back(q1);
    assert!(d.save_queue());
    d.history.lock_ok().push(job(&d, "nzo_h1", "Completed"));
    assert!(d.history_compact());
    // A spool copy in the adoptable shape, named by the unread row:
    // orphan recovery must not touch it.
    let spool_copy = d.spool.join("SABnzbd_nzo_nzbfast5.nzb");
    std::fs::write(&spool_copy, b"<nzb/>").unwrap();
    let qpath = d.queue_store_path();
    let hpath = d.history_store_path();
    let qbytes = std::fs::read(&qpath).unwrap();
    let hbytes = std::fs::read(&hpath).unwrap();
    for p in [&qpath, &hpath] {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o200)).unwrap();
    }
    if std::fs::read(&qpath).is_ok() {
        // root reads anything; the fault cannot be staged here.
        for p in [&qpath, &hpath] {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        std::fs::remove_dir_all(&dir).unwrap();
        return;
    }

    let d2 = test_daemon(&dir);
    d2.load_queue();
    assert!(d2.queue_store_unreadable.load(Ordering::Relaxed));
    assert!(d2.history_store_unreadable.load(Ordering::Relaxed));
    assert!(d2.queue.lock_ok().is_empty() && d2.history.lock_ok().is_empty());
    assert!(
        d2.next_id.load(Ordering::Relaxed) >= 1_700_000_000,
        "the allocator is floored as a restore would floor it: the unread rows' ids \
         carry stream tokens"
    );
    assert_eq!(
        d2.recover_orphaned_spool(),
        0,
        "a spool copy an unread store may name is not an orphan"
    );
    assert!(spool_copy.exists());
    assert!(
        !d2.history_compact(),
        "the rewrite is what would erase the unread rows"
    );
    assert!(!d2.queue_compact(), "...and the queue's twin");
    // A mutation's save: the append is refused by the file and the
    // rescue rewrite by the latch, and the failure is on the record.
    d2.queue.lock_ok().push_back(job(&d2, "nzo_q2", "Queued"));
    assert!(!d2.save_queue(), "nothing may land over an unread store");
    assert_ne!(d2.save_failed_at.load(Ordering::Relaxed), 0);
    let h2 = job(&d2, "nzo_h2", "Completed");
    d2.history.lock_ok().push(h2.clone());
    assert_eq!(d2.history_publish_change(&h2, "test"), HistWrite::Refused);

    for p in [&qpath, &hpath] {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert_eq!(
        std::fs::read(&qpath).unwrap(),
        qbytes,
        "the unread queue rows are exactly as they were"
    );
    assert_eq!(std::fs::read(&hpath).unwrap(), hbytes);

    let d3 = test_daemon(&dir);
    d3.load_queue();
    assert_eq!(queue_ids(&d3), ["nzo_q1"]);
    assert!(
        d3.queue.lock_ok()[0].lock_ok().paused,
        "the saved field the empty view would have dropped"
    );
    assert_eq!(history_ids(&d3), ["nzo_h1"]);
    assert!(!d3.queue_store_unreadable.load(Ordering::Relaxed));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// P2-2's other trigger: the store cannot even be OPENED (mode 0000),
/// which is the arm `load_queue` probes before the retired-snapshot
/// sweep so that sweep cannot remove the only other copies.
#[cfg(unix)]
#[test]
fn a_store_that_will_not_open_latches_before_anything_is_swept() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmp("noopen");
    let d = test_daemon(&dir);
    d.queue.lock_ok().push_back(job(&d, "nzo_q1", "Queued"));
    assert!(d.save_queue());
    let qpath = d.queue_store_path();
    std::fs::set_permissions(&qpath, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read(&qpath).is_ok() {
        std::fs::set_permissions(&qpath, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        return;
    }
    let d2 = test_daemon(&dir);
    d2.load_queue();
    assert!(d2.queue_store_unreadable.load(Ordering::Relaxed));
    assert!(d2.queue.lock_ok().is_empty());
    assert!(
        !d2.save_queue(),
        "no append can land on a 0000 file, and no rewrite may"
    );
    std::fs::set_permissions(&qpath, std::fs::Permissions::from_mode(0o600)).unwrap();
    let d3 = test_daemon(&dir);
    d3.load_queue();
    assert_eq!(
        queue_ids(&d3),
        ["nzo_q1"],
        "the unread row was never overwritten"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

// ---------------------------------------------------------------------
// 13 Oct 2026 codex read-only sweep, F2: the fallback above covers a
// record sitting in history, and a record MOVING between the lists sat
// in neither - so a queue save inside the move published a tombstone
// over its only durable row. Each red test runs that save inside the
// real window (the storecut seam), kills every later write, and
// restarts over the spool. `Owed::in_transit` is the remedy.
// ---------------------------------------------------------------------

/// A record with something worth losing beyond its id: the identity and
/// the settings a restart must bring back.
fn marked(d: &Arc<Daemon>, id: &str, state: &str) -> Arc<Mutex<Job>> {
    let j = job(d, id, state);
    {
        let mut g = j.lock_ok();
        g.category = "tv".into();
        g.priority = 1;
    }
    j
}

/// The restarted record, by id, from whichever list it came back in.
fn restored(dir: &Path, id: &str) -> Option<(String, String, String, i32)> {
    let d = test_daemon(dir);
    d.load_queue();
    let q = d.queue.lock_ok().iter().cloned().collect::<Vec<_>>();
    let h = d.history.lock_ok().iter().cloned().collect::<Vec<_>>();
    let all: Vec<_> = q
        .iter()
        .chain(h.iter())
        .filter(|j| j.lock_ok().nzo_id == id)
        .collect();
    assert!(all.len() <= 1, "{id} came back in both lists");
    all.first().map(|j| {
        let g = j.lock_ok();
        (
            g.name.clone(),
            g.category.clone(),
            format!("{:?}", g.state),
            g.priority,
        )
    })
}

/// A Failed record in history that history.jsonl never took, carried in
/// the queue store - the state P2-3's park leaves.
fn owed_in_history(d: &Arc<Daemon>, id: &str) -> Arc<Mutex<Job>> {
    let j = marked(d, id, "Failed");
    d.history.lock_ok().push(j.clone());
    d.hist_owe(&j);
    assert!(d.save_queue());
    assert_eq!(
        stored_state(d, id).as_deref(),
        Some("Failed"),
        "the fixture's premise"
    );
    assert!(replayed_history_ids(d).is_empty(), "the fixture's premise");
    j
}

/// F2, park: the PREWRITE is refused, so from the retain on the queue
/// row is the record's only durable copy - and a queue save landing
/// there used to tombstone it.
#[test]
fn a_park_whose_prewrite_is_refused_survives_a_queue_save_in_its_window() {
    use crate::storecut::{arm_cut, on_park_gap};
    let dir = tmp("f2-park");
    let d = test_daemon(&dir);
    let j = marked(&d, "nzo_f2p", "Finishing");
    d.queue.lock_ok().push_back(j.clone());
    assert!(d.save_queue());
    j.lock_ok().state = JobState::Completed;

    let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = fired.clone();
    arm_store_cut(&[Store::HistoryAppend, Store::HistoryRewrite]);
    on_park_gap(move |d| {
        assert!(d.save_queue(), "the racing save must land");
        // The kill: nothing park writes after this reaches disk.
        arm_cut(0);
        flag.store(true, std::sync::atomic::Ordering::Relaxed);
    });
    d.park_gen(j, None);
    disarm();
    assert!(
        fired.load(std::sync::atomic::Ordering::Relaxed),
        "the gap seam never fired"
    );
    assert!(
        replayed_history_ids(&d).is_empty(),
        "the fault under test: history took nothing"
    );

    assert_eq!(
        restored(&dir, "nzo_f2p"),
        Some(("Release.nzo_f2p".into(), "tv".into(), "Completed".into(), 1)),
        "the save inside park's window tombstoned the record's only durable row"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// F2, retry: a record history refused is moved back to the queue, and a
/// queue save between its history removal and its queue push used to
/// see it in neither list - tombstoning its row AND dropping it from
/// `hist_owed` for good.
#[test]
fn a_retry_of_an_owed_record_survives_a_queue_save_in_its_window() {
    use crate::storecut::{arm_cut, on_retry_gap};
    let dir = tmp("f2-retry");
    let d = test_daemon(&dir);
    owed_in_history(&d, "nzo_f2r");

    arm_store_cut(&[Store::HistoryAppend, Store::HistoryRewrite]);
    on_retry_gap(|d| {
        assert!(d.save_queue(), "the racing save must land");
        arm_cut(0);
    });
    assert!(d.retry("nzo_f2r"));
    disarm();

    let back = restored(&dir, "nzo_f2r")
        .expect("the save inside retry's window tombstoned the record's only durable row");
    assert_eq!(
        (back.0.as_str(), back.1.as_str(), back.3),
        ("Release.nzo_f2r", "tv", 1)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// F2's third door: library play moves a record out of history exactly
/// as retry does, and an owed one had the same window.
#[test]
fn a_play_of_an_owed_record_survives_a_queue_save_in_its_window() {
    use crate::storecut::{arm_cut, on_activate_gap};
    let dir = tmp("f2-play");
    let d = test_daemon(&dir);
    let j = owed_in_history(&d, "nzo_f2a");

    arm_store_cut(&[Store::HistoryAppend, Store::HistoryRewrite]);
    on_activate_gap(|d| {
        assert!(d.save_queue(), "the racing save must land");
        arm_cut(0);
    });
    d.activate_parked(&j);
    disarm();

    let back = restored(&dir, "nzo_f2a")
        .expect("the save inside the play's window tombstoned the record's only durable row");
    assert_eq!(
        (back.0.as_str(), back.1.as_str(), back.3),
        ("Release.nzo_f2a", "tv", 1)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Control: a carry must not outlive a DELETE. A park that history
/// refused end to end leaves the record owed; the user deletes it from
/// history, and the next start must not bring it back.
#[test]
fn a_refused_park_then_deleted_is_not_resurrected() {
    let dir = tmp("f2-delete");
    let d = test_daemon(&dir);
    let j = marked(&d, "nzo_f2d", "Finishing");
    d.queue.lock_ok().push_back(j.clone());
    assert!(d.save_queue());
    j.lock_ok().state = JobState::Completed;

    arm_store_cut(&[Store::HistoryAppend, Store::HistoryRewrite]);
    d.park_gen(j, None);
    assert_eq!(stored_state(&d, "nzo_f2d").as_deref(), Some("Completed"));
    // The delete, as the history verbs do it at this layer.
    d.history
        .lock_ok()
        .retain(|x| x.lock_ok().nzo_id != "nzo_f2d");
    assert!(d.save_queue());
    disarm();

    assert_eq!(stored_state(&d, "nzo_f2d"), None);
    assert!(d.hist_owed.lock_ok().is_empty());
    assert_eq!(
        restored(&dir, "nzo_f2d"),
        None,
        "a deleted record came back"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Control: the prewrite is refused but the FINAL filing lands. The carry
/// stands down, the queue store drops its copy, and the record is in
/// history exactly once.
#[test]
fn a_refused_prewrite_whose_final_filing_lands_is_carried_no_further() {
    use crate::storecut::on_park_gap;
    let dir = tmp("f2-lands");
    let d = test_daemon(&dir);
    let j = marked(&d, "nzo_f2l", "Finishing");
    d.queue.lock_ok().push_back(j.clone());
    assert!(d.save_queue());
    j.lock_ok().state = JobState::Completed;

    arm_store_cut(&[Store::HistoryAppend, Store::HistoryRewrite]);
    on_park_gap(|d| {
        assert!(d.save_queue());
        let raw = std::fs::read(d.queue_store_path()).unwrap_or_default();
        assert!(
            crate::queuestore::replay_bytes(&raw)
                .rows
                .iter()
                .any(|(_, v, _)| v["nzo_id"] == "nzo_f2l" && v["state"] == "Completed"),
            "carried while in transit"
        );
        // History recovers before the final filing.
        disarm();
    });
    d.park_gen(j, None);
    disarm();

    assert!(
        d.hist_owed.lock_ok().is_empty(),
        "a landed filing owes nothing"
    );
    assert_eq!(stored_state(&d, "nzo_f2l"), None);
    assert_eq!(replayed_history_ids(&d), ["nzo_f2l"]);
    assert_eq!(
        restored(&dir, "nzo_f2l"),
        Some(("Release.nzo_f2l".into(), "tv".into(), "Completed".into(), 1))
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Control: an ordinary retry of an owed record with healthy stores. The
/// retry's generation wins - the queue row is Queued, the carry is gone,
/// and the next start runs it rather than showing the old failure.
#[test]
fn a_retry_of_an_owed_record_publishes_the_retry_and_carries_nothing() {
    let dir = tmp("f2-retry-ok");
    let d = test_daemon(&dir);
    owed_in_history(&d, "nzo_f2k");

    assert!(d.retry("nzo_f2k"));

    assert!(d.hist_owed.lock_ok().is_empty());
    assert_eq!(stored_state(&d, "nzo_f2k").as_deref(), Some("Queued"));
    assert_eq!(
        restored(&dir, "nzo_f2k"),
        Some(("Release.nzo_f2k".into(), "tv".into(), "Queued".into(), 1))
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// What a crash leaves: the spool's bytes at this instant, copied into a
/// fresh fixture directory so `restored` can boot over them while the
/// live daemon is still mid-window.
fn snapshot_spool(from: &Path, to: &Path) {
    fn copy(a: &Path, b: &Path) {
        std::fs::create_dir_all(b).unwrap();
        for e in std::fs::read_dir(a).unwrap() {
            let e = e.unwrap();
            let dst = b.join(e.file_name());
            if e.file_type().unwrap().is_dir() {
                copy(&e.path(), &dst);
            } else {
                std::fs::copy(e.path(), &dst).unwrap();
            }
        }
    }
    copy(&from.join("spool"), &to.join("spool"));
}

/// 22 Oct 2026 codex read-only sweep, F2: a successful compaction retired
/// EVERY non-transit `hist_owed` entry, not just the ones its snapshot
/// paid. `HIST_IO` keeps appenders out of the gap between snapshot and
/// rename, but not park's list moves, so a park whose prewrite was
/// refused could file its record into history and land its carry while
/// the compaction held the lock - and the compaction then retired the
/// carry of a record the file it had just written does not hold. A
/// queue save before park's own final append (which is queued behind
/// the same lock) tombstoned the record's only durable row.
///
/// Driven through the real `park_gen` and the real compaction, each on
/// its own thread with its own seam, and restored from the bytes on
/// disk at the instant the queue save lands.
#[test]
fn a_compaction_cannot_retire_the_carry_of_a_park_that_landed_after_its_snapshot() {
    use crate::storecut::{arm_cut, on_park_gap};
    use std::sync::Barrier;
    let dir = tmp("f2-compact");
    let crash = tmp("f2-compact-crash");
    let d = test_daemon(&dir);
    let j = marked(&d, "nzo_f2c", "Finishing");
    d.queue.lock_ok().push_back(j.clone());
    assert!(d.save_queue());
    j.lock_ok().state = JobState::Completed;

    // Park, on its own thread: the prewrite is refused, and the seam
    // holds it at the gap - out of the queue, carried, not yet in
    // history. From there on nothing park writes reaches disk (the kill
    // the window ends in).
    let gap_open = Arc::new(Barrier::new(2));
    let gap_release = Arc::new(Barrier::new(2));
    let parker = {
        let (d, j) = (d.clone(), j.clone());
        let (open, release) = (gap_open.clone(), gap_release.clone());
        std::thread::spawn(move || {
            arm_store_cut(&[Store::HistoryAppend, Store::HistoryRewrite]);
            on_park_gap(move |_| {
                arm_cut(0);
                open.wait();
                release.wait();
            });
            d.park_gen(j, None);
            disarm();
        })
    };
    gap_open.wait();

    // The compaction snapshots NOW, before park files the record.
    let snapped = Arc::new(Barrier::new(2));
    let publish = Arc::new(Barrier::new(2));
    let published = Arc::new(Barrier::new(2));
    let saved = Arc::new(Barrier::new(2));
    crate::histstore::compact_barrier_arm(&d, snapped.clone(), Some(publish.clone()));
    let compactor = {
        let d = d.clone();
        let (published, saved) = (published.clone(), saved.clone());
        std::thread::spawn(move || {
            assert!(d.history_compact_then(|| {
                published.wait();
                saved.wait();
            }));
        })
    };
    snapped.wait();

    // Park files the record into history and lands its carry, then
    // queues behind the compaction for its final append. No seam marks
    // that point, so wait for the state itself.
    gap_release.wait();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let landed = history_ids(&d).iter().any(|i| i == "nzo_f2c")
            && d.hist_owed
                .lock_ok()
                .get("nzo_f2c")
                .is_some_and(|o| !o.in_transit);
        if landed {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "park never landed its carry"
        );
        std::thread::sleep(std::time::Duration::from_millis(2));
    }

    // The compaction publishes its older snapshot, and a queue save
    // lands before park's final append can.
    publish.wait();
    published.wait();
    assert!(d.save_queue(), "the racing save must land");
    snapshot_spool(&dir, &crash);
    saved.wait();
    compactor.join().unwrap();
    parker.join().unwrap();
    crate::histstore::compact_barrier_disarm(&d);

    assert_eq!(
        restored(&crash, "nzo_f2c"),
        Some(("Release.nzo_f2c".into(), "tv".into(), "Completed".into(), 1)),
        "the compaction retired the carry of a record its snapshot did not hold, \
         and the queue save tombstoned the record's only durable row"
    );
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_dir_all(&crash).unwrap();
}

/// F2's second shape: the record WAS in the compaction's snapshot, at an
/// older state, and a later mutation of it was refused by history - so
/// it was owed again while the compaction held the lock. The rewrite
/// paid the old state, not the new one, and must not retire the new
/// debt on the strength of the old line.
#[test]
fn a_compaction_cannot_retire_a_debt_newer_than_its_snapshot() {
    use std::sync::Barrier;
    let dir = tmp("f2-compact-gen");
    let d = test_daemon(&dir);
    let j = owed_in_history(&d, "nzo_f2g");

    let snapped = Arc::new(Barrier::new(2));
    let publish = Arc::new(Barrier::new(2));
    crate::histstore::compact_barrier_arm(&d, snapped.clone(), Some(publish.clone()));
    let compactor = {
        let d = d.clone();
        std::thread::spawn(move || assert!(d.history_compact()))
    };
    snapped.wait();
    // Snapshot taken with the record Failed. It changes, and history
    // refuses the change - the shape `history_publish`'s caller answers
    // with `hist_owe`.
    j.lock_ok().state = JobState::Completed;
    d.hist_owe(&j);
    publish.wait();
    compactor.join().unwrap();
    crate::histstore::compact_barrier_disarm(&d);

    assert_eq!(
        d.hist_owed.lock_ok().len(),
        1,
        "the debt registered after the snapshot was retired by it"
    );
    assert!(d.save_queue());
    assert_eq!(
        stored_state(&d, "nzo_f2g").as_deref(),
        Some("Completed"),
        "the queue store must carry the newer state the history file lacks"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The plain arm, no threads: an owed entry whose record the rewrite did
/// not serialize - not in history, not dropped by the caller - is not
/// paid by that rewrite, whatever `in_transit` says. (`queue_rows`
/// decides separately whether such an entry is still worth carrying.)
#[test]
fn a_compaction_retires_only_what_its_snapshot_serialized() {
    let dir = tmp("f2-compact-unit");
    let d = test_daemon(&dir);
    let paid = job(&d, "nzo_f2u1", "Completed");
    d.history.lock_ok().push(paid.clone());
    d.hist_owe(&paid);
    let unpaid = job(&d, "nzo_f2u2", "Completed");
    d.hist_owe(&unpaid);

    assert!(d.history_compact());

    let owed = d.hist_owed.lock_ok();
    assert!(
        !owed.contains_key("nzo_f2u1"),
        "a record the rewrite wrote is paid"
    );
    assert!(
        owed.get("nzo_f2u2")
            .is_some_and(|o| Arc::ptr_eq(&o.job, &unpaid)),
        "a record absent from the snapshot was retired by it"
    );
    drop(owed);
    std::fs::remove_dir_all(&dir).unwrap();
}
