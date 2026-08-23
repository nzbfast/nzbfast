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
