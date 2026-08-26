//! `park_gen`'s generation fence: the three windows in which a retry
//! can land while a stale lane tail is still walking the record, moved
//! out of daemon_tests.rs under the size gate (TODO 106).
//!
//! One subject, and the reason they belong together: each is a stretch
//! of `park_gen` that runs with the job guard dropped, each is
//! zero-width without a test seam, and each was found only after the
//! one before it had been closed. `use super::*` carries `with_daemon`
//! and everything daemon.rs's test module already has in scope.

use super::*;

/// M4c: the same stale tail must not strip the RETRY's custody entries.
///
/// `park_gen`'s generation re-read protects the terminal branches, and
/// its own comment says it returns "WITHOUT touching the two custody
/// maps, which is the one way it differs from the check at the top ...
/// a remove() would take the live retry's activity row out of the queue
/// - the exact damage this guard exists to prevent". The two removes
/// sat ABOVE that re-read, so the guard could not guard them: by the
/// time it returned, the damage was already done and the early return
/// merely skipped undoing it. `remove_job_files` runs immediately
/// before, unlocked and unbounded on a slow share, which is the window.
#[test]
fn a_stale_lane_tail_leaves_the_retrys_custody_entries_alone() {
    with_daemon("park-generation-custody", |d| {
        let out = d.out_dir().join("Custody.Release");
        std::fs::create_dir_all(&out).expect("payload dir");
        let job = jv(
            "nzo-custody-1",
            "Custody.Release",
            serde_json::json!({ "out_dir": out.to_string_lossy() }),
        );
        let gen0 = Daemon::record_generation(&job.lock_ok());
        d.history.lock_ok().push(job.clone());
        {
            let mut g = job.lock_ok();
            g.state = JobState::Failed;
            g.fail_message = "deleted from the queue".into();
            g.finished_unix = Some(1);
            g.delete_status = "MANUAL".into();
        }

        let open = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        *super::daemon_park::PARK_GEN_BARRIER.lock_ok() =
            Some(("nzo-custody-1".to_string(), open.clone(), release.clone()));

        // Registered BEFORE the tail runs, and deliberately not
        // re-registered at the barrier. The barrier sits AFTER the point
        // the removes used to occupy, so an entry written at the barrier
        // survives either way and proves nothing - the first cut of this
        // test did exactly that and passed against the unfixed code.
        // Both maps are keyed by job id alone and the new generation
        // reuses that key, so an entry standing across the window is
        // precisely what the retry's own registration looks like here.
        d.hub
            .activity
            .lock_ok()
            .insert("nzo-custody-1".to_string(), "preflight");

        let d2 = d.clone();
        let job2 = job.clone();
        let tail = std::thread::spawn(move || d2.park_gen(job2, Some(gen0)));

        // Inside the window: the retry lands, so the tail is now stale.
        open.wait();
        assert!(
            d.retry("nzo-custody-1"),
            "the filed delete row is retryable"
        );
        release.wait();
        tail.join().expect("park tail");
        *super::daemon_park::PARK_GEN_BARRIER.lock_ok() = None;

        assert_eq!(
            d.hub.activity.lock_ok().get("nzo-custody-1").copied(),
            Some("preflight"),
            "the stale tail removed the live retry's activity row"
        );
    });
}

/// The same guard, but for the window rather than the entry.
///
/// `park_gen` checked the generation once, at the top, and then dropped
/// the job guard to run `remove_job_files` - a recursive delete of a
/// whole release, unbounded on a hung NAS. A retry landing in THAT gap
/// bumped the generation after the only test had already passed, so the
/// rest of park_gen ran against a record it no longer owned: it removed
/// the live retry's activity row and went on to file or requeue it.
///
/// The tombstone two lines below was already re-read live for exactly
/// this reason. The generation was not. Driven through PARK_GEN_BARRIER
/// because the window is zero-width without a slow filesystem.
#[test]
fn a_lane_tail_declines_a_retry_that_lands_while_it_is_deleting_files() {
    with_daemon("park-generation-window", |d| {
        let out = d.out_dir().join("Windowed.Release");
        std::fs::create_dir_all(&out).expect("payload dir");
        let job = jv(
            "nzo-parkwin-1",
            "Windowed.Release",
            serde_json::json!({ "out_dir": out.to_string_lossy() }),
        );
        let gen0 = Daemon::record_generation(&job.lock_ok());
        d.history.lock_ok().push(job.clone());
        {
            let mut g = job.lock_ok();
            g.state = JobState::Failed;
            g.fail_message = "deleted from the queue".into();
            g.finished_unix = Some(1);
            g.delete_status = "MANUAL".into();
        }

        let open = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        *super::daemon_park::PARK_GEN_BARRIER.lock_ok() =
            Some(("nzo-parkwin-1".to_string(), open.clone(), release.clone()));

        let d2 = d.clone();
        let job2 = job.clone();
        let tail = std::thread::spawn(move || d2.park_gen(job2, Some(gen0)));

        // The tail is now past its first generation check and past its
        // file removal. This is the window.
        open.wait();
        assert!(
            d.retry("nzo-parkwin-1"),
            "the filed delete row is retryable"
        );
        assert!(
            d.queue
                .lock_ok()
                .iter()
                .any(|j| j.lock_ok().nzo_id == "nzo-parkwin-1"),
            "the retry put it back in the queue"
        );
        release.wait();
        tail.join().expect("park tail");
        *super::daemon_park::PARK_GEN_BARRIER.lock_ok() = None;

        assert!(
            d.queue
                .lock_ok()
                .iter()
                .any(|j| j.lock_ok().nzo_id == "nzo-parkwin-1"),
            "the stale tail pulled the freshly retried row out of the queue"
        );
        assert_eq!(
            d.history
                .lock_ok()
                .iter()
                .filter(|j| j.lock_ok().nzo_id == "nzo-parkwin-1")
                .count(),
            0,
            "and filed it into history, consuming the retry the user pressed"
        );
        assert_eq!(
            job.lock_ok().state,
            JobState::Queued,
            "the retry's own state was overwritten by the stale tail"
        );
    });
}

/// Codex sweep 6, N2: the window BEHIND the second generation check.
///
/// `PARK_GEN_BARRIER` opens before that check, so the test above stages
/// its retry where the guard can see it. Everything after the check -
/// the move stamp, `hist_inflight_begin`, and `park_prewrite`, which is
/// a durable append to history.jsonl - ran with no further check at
/// all, and ended in a `queue.retain` by id. A retry landing there
/// pushes the SAME record back onto the queue and the retain pulls it
/// straight out again, after which the arms below file it into history:
/// the button the user pressed did nothing, and the payload keeps its
/// deleted verdict.
///
/// Driven through a seam on that later stretch, because the disk write
/// is the only thing that makes it wide in production.
#[test]
fn a_lane_tail_declines_a_retry_that_lands_while_it_is_writing_history() {
    with_daemon("park-prewrite-window", |d| {
        let out = d.out_dir().join("Prewrite.Release");
        std::fs::create_dir_all(&out).expect("payload dir");
        let job = jv(
            "nzo-parkpre-1",
            "Prewrite.Release",
            serde_json::json!({ "out_dir": out.to_string_lossy() }),
        );
        let gen0 = Daemon::record_generation(&job.lock_ok());
        d.history.lock_ok().push(job.clone());
        {
            let mut g = job.lock_ok();
            g.state = JobState::Failed;
            g.fail_message = "deleted from the queue".into();
            g.finished_unix = Some(1);
            g.delete_status = "MANUAL".into();
        }

        let open = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        *super::daemon_park::PARK_PREWRITE_BARRIER.lock_ok() =
            Some(("nzo-parkpre-1".to_string(), open.clone(), release.clone()));

        let d2 = d.clone();
        let job2 = job.clone();
        let tail = std::thread::spawn(move || d2.park_gen(job2, Some(gen0)));

        // The tail is past BOTH generation checks it used to have, has
        // stamped its move, and has just written its history row.
        open.wait();
        assert!(
            d.retry("nzo-parkpre-1"),
            "the filed delete row is retryable"
        );
        assert!(
            d.queue
                .lock_ok()
                .iter()
                .any(|j| j.lock_ok().nzo_id == "nzo-parkpre-1"),
            "the retry put it back in the queue"
        );
        release.wait();
        tail.join().expect("park tail");
        *super::daemon_park::PARK_PREWRITE_BARRIER.lock_ok() = None;

        assert!(
            d.queue
                .lock_ok()
                .iter()
                .any(|j| j.lock_ok().nzo_id == "nzo-parkpre-1"),
            "the stale tail pulled the freshly retried row out of the queue"
        );
        assert_eq!(
            d.history
                .lock_ok()
                .iter()
                .filter(|j| j.lock_ok().nzo_id == "nzo-parkpre-1")
                .count(),
            0,
            "and filed it into history, consuming the retry the user pressed"
        );
        assert_eq!(
            job.lock_ok().state,
            JobState::Queued,
            "the retry's own state was overwritten by the stale tail"
        );
        // The counter has to resolve the same way on disk: the queue
        // copy is the later move, so a kill here must not let the
        // prewritten history row win at the next load.
        assert!(job.lock_ok().move_seq > 0, "the retry stamped its own move");
    });
}

// -- §158.7's other half: the park's own filing ------------------------------

/// A job parked as Failed with the auto-retry cooldown armed, which is
/// what makes this a test of the LAST write and not only of the first:
/// `arm_auto_retry` stamps `auto_retry_at` AFTER the row has left the
/// queue, so the prewrite's copy does not carry it and only park's final
/// filing does.
fn failed_with_a_retry_armed(d: &Arc<Daemon>, id: &str, name: &str) -> Arc<Mutex<Job>> {
    d.auto_retry_secs.store(60, Ordering::Relaxed);
    let job = jv(
        id,
        name,
        serde_json::json!({
            "state": "Failed",
            "fail_message": "download incomplete: 3 articles missing",
        }),
    );
    d.queue.lock_ok().push_back(job.clone());
    assert!(d.save_queue(), "the queue snapshot the park starts from");
    assert!(
        d.will_auto_retry(&job),
        "the fixture's own premise: this park arms a retry after the retain"
    );
    job
}

/// P2-1's sibling on the PARK path. `history.jsonl` is opened
/// `create(true).append(true)`, so it needs write permission ON THE FILE,
/// while `queue.json` and the atomic rewrite go through
/// `persist::write_atomic` - private temp file, rename - and need only
/// the DIRECTORY. One `sudo nzbfast`, a store left 0444, or an ownership
/// that no longer matches separates them, and the queue store then keeps
/// working while every history append is refused.
///
/// `park_prewrite` and park's two filings all rode the bare append with
/// their answers dropped, so on that store EVERY finished download was
/// lost from both stores at the next start: gone from the queue, absent
/// from history, its payload on disk named by no record anywhere. That
/// is worse than the delete case P2-1 fixed - it is every finished job
/// rather than every deleted one - and nothing said a word.
///
/// The asymmetry is also the way out, so the park has to SUCCEED here,
/// and the restart is what proves it. The retry stamp is what proves the
/// FINAL filing landed rather than only the prewrite: it is written
/// after the row leaves the queue, so a store holding the prewrite's
/// copy alone restores a failed job with no retry pending.
#[test]
fn a_park_survives_a_store_that_refuses_the_append() {
    use crate::serve::storecut::{Store, arm_store_cut, disarm};

    with_daemon("park-store-refuses-append", |d| {
        let job = failed_with_a_retry_armed(d, "nzo-parkfile-1", "Rescued.Park");

        arm_store_cut(&[Store::HistoryAppend]);
        d.park_gen(job, None);
        disarm();

        let d2 = restart(d);
        let stored = d2
            .history
            .lock_ok()
            .iter()
            .find(|j| j.lock_ok().nzo_id == "nzo-parkfile-1")
            .cloned()
            .expect(
                "the parked record was lost from BOTH stores - the append was \
                 refused and nothing stood the rewrite in for it",
            );
        assert!(
            stored.lock_ok().auto_retry_at.is_some(),
            "only the prewrite's copy reached the store, so the retry this park \
             armed is not coming back"
        );
        assert!(
            d2.queue.lock_ok().is_empty(),
            "and it must not come back as a queued job as well"
        );
    });
}

/// The same store, and a stop the instant the row leaves the live queue -
/// which is the window §158.7 put the prewrite in front of.
///
/// Every write park still owed is refused from the gap onward, the
/// rewrite included, so the ONLY thing that can name this record at the
/// next start is the prewrite. On a store that refuses the append that
/// meant nothing did: the racing save publishes a queue.json without the
/// row and no history line was ever written, so the record was gone from
/// both stores with its payload on disk named by nothing.
#[test]
fn a_park_prewrites_through_a_store_that_refuses_the_append() {
    use crate::serve::storecut::{Store, arm_cut, arm_store_cut, disarm};

    with_daemon("park-prewrite-refuses-append", |d| {
        let job = failed_with_a_retry_armed(d, "nzo-parkfile-3", "Prewritten.Park");

        arm_store_cut(&[Store::HistoryAppend]);
        crate::serve::storecut::on_park_gap(|d| {
            assert!(d.save_queue(), "the racing save must land");
            // ...and the process dies there: nothing park writes after
            // this point reaches disk, the rescue included. `arm_cut`
            // alone would not do it - the rewrite is deliberately
            // outside that budget, so the mask has to name it.
            arm_store_cut(&[Store::HistoryAppend, Store::HistoryRewrite]);
            arm_cut(0);
        });
        d.park_gen(job, None);
        disarm();

        let queued = std::fs::read_to_string(d.spool.join("queue.json")).unwrap_or_default();
        assert!(
            !queued.contains("nzo-parkfile-3"),
            "the racing save was supposed to publish a queue without the row - \
             this harness is not exercising the window"
        );
        assert!(
            restart(d)
                .history
                .lock_ok()
                .iter()
                .any(|j| j.lock_ok().nzo_id == "nzo-parkfile-3"),
            "the record left the queue with nothing durable naming it"
        );
    });
}

/// The M5 arm: a delete verb cancelling an ACTIVE job, whose record park
/// files itself.
///
/// A dropped answer costs more here than one row. `delete_prewrite`
/// overrode the terminal keys in its placeholder, and then this park's
/// own prewrite wrote the LIVE job over the top of it - still
/// nonterminal, still tombstoned - so the store's last word on the id is
/// a row that replays as `Queued` (job_wire.rs). Losing the final filing
/// therefore does not merely forget the delete: it brings the cancelled
/// job back looking like something to download.
#[test]
fn a_deleted_active_jobs_final_record_reaches_a_store_that_refuses_the_append() {
    use crate::serve::storecut::{Store, arm_store_cut, disarm};

    with_daemon("park-store-refuses-m5", |d| {
        let job = jv(
            "nzo-parkfile-4",
            "Cancelled.Park",
            serde_json::json!({ "state": "Downloading" }),
        );
        {
            let mut g = job.lock_ok();
            g.tombstone = true;
            g.delete_status = "MANUAL".into();
        }
        d.queue.lock_ok().push_back(job.clone());
        assert!(d.save_queue());

        arm_store_cut(&[Store::HistoryAppend]);
        d.park_gen(job, None);
        disarm();

        let d2 = restart(d);
        let stored = d2
            .history
            .lock_ok()
            .iter()
            .find(|j| j.lock_ok().nzo_id == "nzo-parkfile-4")
            .cloned()
            .expect("the cancelled job's record was lost from BOTH stores");
        let g = stored.lock_ok();
        assert_eq!(
            g.state,
            JobState::Failed,
            "the store's last word is the row written while it was still \
             downloading, so the cancelled job replays as queued"
        );
        assert_eq!(g.fail_message, "deleted from the queue");
        assert!(
            d2.queue.lock_ok().is_empty(),
            "and the job the user deleted must not be back in the queue"
        );
    });
}

/// The other end: a data folder this daemon cannot write AT ALL, so the
/// rewrite that rescues the append above is refused too.
///
/// Nothing is left to try, and the park still may not stop. A delete verb
/// can refuse because a user is waiting on the answer; this download has
/// already happened and its bytes are on disk, so refusing would leave
/// the daemon holding a finished job it can neither file nor forget. The
/// answer is to carry on and SAY what the next start loses - on the event
/// ring, which is where the dashboard reads it, rather than in a log
/// nobody is reading at 3am.
///
/// One entry, not three. The prewrite's own rescue attempt closes
/// `hist_rescue_open`'s one-a-minute gate, so both filings behind it find
/// it shut and report without an event; that is why the prewrite is the
/// half that carries the sentence.
#[test]
fn a_park_that_cannot_reach_either_store_says_what_the_restart_loses() {
    use crate::serve::storecut::{Store, arm_store_cut, disarm};

    with_daemon("park-store-refuses-both", |d| {
        let job = failed_with_a_retry_armed(d, "nzo-parkfile-2", "Lost.Park");

        arm_store_cut(&[Store::HistoryAppend, Store::HistoryRewrite]);
        d.park_gen(job, None);
        disarm();

        assert!(
            d.history
                .lock_ok()
                .iter()
                .any(|j| j.lock_ok().nzo_id == "nzo-parkfile-2"),
            "a park with nowhere to write must still finish - the record is \
             correct in memory and only its survival across a restart is lost"
        );
        let told: Vec<String> = d
            .recent_events(50)
            .into_iter()
            .filter(|e| e.kind == "disk")
            .map(|e| e.detail)
            .collect();
        assert_eq!(
            told.len(),
            1,
            "exactly one entry for the park, got {told:?}"
        );
        assert!(
            told[0].contains("Lost.Park") && told[0].contains("history"),
            "the entry has to name the job and the store, got {told:?}"
        );
        assert!(
            restart(d)
                .history
                .lock_ok()
                .iter()
                .all(|j| j.lock_ok().nzo_id != "nzo-parkfile-2"),
            "the fixture's own premise: with both stores refused there is \
             nothing on disk for the restart to find"
        );
    });
}
