//! Stopping a Force: what a priority write that WITHDRAWS Force (or
//! sends a released duplicate back to its hold) owes the transfer.
//!
//! The report (21 Sep 2026): the dashboard's Pause was pressed and the
//! download went on at 110 MB/s, because the running job was Force and
//! Force runs through a queue pause by SAB semantics (that stands). The
//! page now lets the user withdraw the Force from the row, and this is
//! the half that has to hold behind it: lowering a Force job that is on
//! the wire while the queue is paused has to make the pause bite on it -
//! before, the priority write changed a number, answered success and left
//! the transfer running under a header that said `paused`. And the other
//! way round, which is the property that keeps the fix honest: with NO
//! pause in force, changing a priority must never touch a transfer.
//!
//! The fixtures are `daemon_suspend`'s: a row shaped like the runner
//! leaves one, and `settle` to retire the 60 s re-fire loop a wind-down
//! starts. The SAB `mode=queue&name=priority` arm needs a live HTTP
//! request, so its body is driven through the two functions it calls
//! under and after its locks (`apply_priority`,
//! `wind_down_after_priority`) - the same pair, in the same order, that
//! the NZBGet `GroupSetPriority` arm and the dashboard's bulk action (the
//! SAB arm, once per selection) run; the wired end-to-end run is
//! `pause_paths::unforcing_*` in the integration target.

use super::{JobState, jr_editqueue};
use crate::api::queue::{apply_priority, reposition_for_priority, wind_down_after_priority};
use nzbfast_daemon::daemon::Daemon;
use nzbfast_daemon::job::Job;
use nzbfast_daemon::testutil::{jv, with_daemon};
use nzbkit::sync::MutexExt;
use serde_json::{Value, json};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

/// A record in `state`, shaped like the runner leaves one.
fn row(id: &str, state: JobState, extra: Value) -> Arc<Mutex<Job>> {
    let j = jv(id, id, extra);
    // Set after the load, which re-queues an interrupted download.
    j.lock_ok().state = state;
    j
}

fn get<T>(d: &Arc<Daemon>, id: &str, f: impl FnOnce(&Job) -> T) -> T {
    let q = d.queue.lock_ok();
    let j = q
        .iter()
        .find(|j| j.lock_ok().nzo_id == id)
        .unwrap_or_else(|| panic!("{id} left the queue"));
    let g = j.lock_ok();
    f(&g)
}

/// Let the re-fire loop a wind-down starts retire (it exits when no
/// matched job is still `suspended` and `Downloading`).
fn settle(d: &Arc<Daemon>) {
    for j in d.queue.lock_ok().iter() {
        j.lock_ok().state = JobState::Queued;
    }
}

/// The SAB arm's body for one selection: write under the queue lock,
/// reposition, then - locks gone - the wind-down.
fn write_priority(d: &Arc<Daemon>, ids: &[&str], prio: i32) -> Vec<String> {
    let moved: Vec<String> = {
        let mut q = d.queue.lock_ok();
        let mut moved = Vec::new();
        for j in q.iter() {
            let mut g = j.lock_ok();
            if ids.contains(&g.nzo_id.as_str()) && apply_priority(d, &mut g, prio) {
                moved.push(g.nzo_id.clone());
            }
        }
        for id in &moved {
            reposition_for_priority(&mut q, id);
        }
        moved
    };
    wind_down_after_priority(d, &moved);
    moved
}

fn slot_of(d: &Arc<Daemon>, id: &str) -> Value {
    let q = super::queue_json(d, &Default::default())["queue"].clone();
    q["slots"]
        .as_array()
        .and_then(|a| a.iter().find(|s| s["nzo_id"] == id))
        .cloned()
        .unwrap_or_else(|| panic!("no slot for {id}: {q}"))
}

/// THE FIX. A Force job on the wire, the queue paused (it kept going by
/// design), then the Force is withdrawn: the pause must now take effect
/// on it, and the job must stay in the queue to resume from the journal.
#[test]
fn unforcing_an_active_job_under_a_queue_pause_winds_it_down() {
    with_daemon("unforce-paused", |d| {
        d.queue
            .lock_ok()
            .push_back(row("forced", JobState::Downloading, json!({"priority": 2})));
        d.paused.store(true, Ordering::Relaxed);
        assert_eq!(d.pause_exempt(), ["forced"], "the setup is not the report");

        write_priority(d, &["forced"], 0);

        assert!(
            get(d, "forced", |g| g.suspended),
            "the priority write left a paused queue's transfer running"
        );
        assert_eq!(get(d, "forced", |g| g.priority), 0);
        assert!(
            !get(d, "forced", |g| g.tombstone),
            "stopping a Force is not a delete: the row stays queued"
        );
        assert_eq!(d.queue.lock_ok().len(), 1);
        // The header agrees: nothing is exempt from the pause any more.
        assert!(d.pause_exempt().is_empty(), "{:?}", d.pause_exempt());
        settle(d);
    });
}

/// The other half of the contract: no pause, no interruption. Lowering
/// Force on an UNPAUSED queue is a re-ranking and nothing else.
#[test]
fn unforcing_an_active_job_on_an_unpaused_queue_leaves_it_transferring() {
    with_daemon("unforce-live", |d| {
        d.queue
            .lock_ok()
            .push_back(row("forced", JobState::Downloading, json!({"priority": 2})));

        let moved = write_priority(d, &["forced"], 0);

        assert_eq!(moved, ["forced"]);
        assert_eq!(get(d, "forced", |g| g.priority), 0);
        assert!(
            !get(d, "forced", |g| g.suspended),
            "a priority write interrupted a transfer no pause was holding"
        );
        assert!(!get(d, "forced", |g| g.paused));
    });
}

/// Force STAYS Force is not an unforce: a write that leaves the row
/// exempt must not wind it down, under a pause or not.
#[test]
fn rewriting_force_over_a_paused_queue_does_not_stop_the_job() {
    with_daemon("reforce", |d| {
        d.queue
            .lock_ok()
            .push_back(row("forced", JobState::Downloading, json!({"priority": 2})));
        d.paused.store(true, Ordering::Relaxed);

        write_priority(d, &["forced"], 2);

        assert!(!get(d, "forced", |g| g.suspended));
        assert_eq!(d.pause_exempt(), ["forced"]);
    });
}

/// The dashboard's bulk action sends ONE priority write over a whole
/// selection. Only the row that was actually on the wire is wound down;
/// the waiting ones just change rank, and a job already winding down is
/// not started on a second time.
#[test]
fn a_bulk_unforce_winds_down_only_what_is_on_the_wire() {
    with_daemon("unforce-bulk", |d| {
        {
            let mut q = d.queue.lock_ok();
            q.push_back(row("run", JobState::Downloading, json!({"priority": 2})));
            q.push_back(row("wait", JobState::Queued, json!({"priority": 2})));
            q.push_back(row("other", JobState::Queued, json!({"priority": 0})));
            let already = row("going", JobState::Downloading, json!({"priority": 2}));
            already.lock_ok().suspended = true;
            q.push_back(already);
        }
        d.paused.store(true, Ordering::Relaxed);

        let moved = write_priority(d, &["run", "wait", "going"], 0);

        assert_eq!(moved.len(), 3);
        assert!(get(d, "run", |g| g.suspended));
        assert!(!get(d, "wait", |g| g.suspended), "a queued row has no wire");
        assert_eq!(get(d, "wait", |g| g.priority), 0);
        assert!(!get(d, "other", |g| g.suspended));
        assert_eq!(d.queue.lock_ok().len(), 4);
        settle(d);
    });
}

/// The NZBGet facade's `GroupSetPriority` is the same door for a client
/// that speaks it (`0` is Normal on its scale).
#[test]
fn the_nzbget_group_set_priority_arm_stops_it_too() {
    with_daemon("unforce-rpc", |d| {
        d.queue.lock_ok().push_back(row(
            "SABnzbd_nzo_nzbfast7",
            JobState::Downloading,
            json!({"priority": 2}),
        ));
        d.paused.store(true, Ordering::Relaxed);

        let mut err = None;
        let r = jr_editqueue(
            d,
            &[json!("GroupSetPriority"), json!("0"), json!([7])],
            &mut err,
        );

        assert_eq!(r, json!(true), "{err:?}");
        assert!(get(d, "SABnzbd_nzo_nzbfast7", |g| g.suspended));
        assert_eq!(get(d, "SABnzbd_nzo_nzbfast7", |g| g.priority), 0);
        settle(d);
    });
}

/// ...and, again, it leaves a live transfer alone when nothing is paused.
#[test]
fn the_nzbget_group_set_priority_arm_leaves_an_unpaused_transfer_alone() {
    with_daemon("unforce-rpc-live", |d| {
        d.queue.lock_ok().push_back(row(
            "SABnzbd_nzo_nzbfast8",
            JobState::Downloading,
            json!({"priority": 2}),
        ));
        let mut err = None;
        jr_editqueue(
            d,
            &[json!("GroupSetPriority"), json!("0"), json!([8])],
            &mut err,
        );
        assert!(!get(d, "SABnzbd_nzo_nzbfast8", |g| g.suspended));
    });
}

/// A copy released with download-anyway is Force and unpaused but still
/// remembers what it is a copy of. Duplicate priority on it is the HOLD
/// again - the exact (paused, -3) pair the hold has always been, so the
/// labels, the promotion when the original fails and `is_held_alternative`
/// all read it back as held.
#[test]
fn a_released_duplicate_can_be_put_back_on_hold() {
    with_daemon("rehold", |d| {
        d.queue.lock_ok().push_back(row(
            "copy",
            JobState::Queued,
            json!({"priority": 2, "held_for": "orig", "dupe_key": "some.key"}),
        ));
        // What the released row looks like on the wire the page reads.
        let before = slot_of(d, "copy");
        assert_eq!(before["priority"], "Force", "{before}");
        assert_eq!(before["held_for"], "orig", "{before}");
        assert_eq!(before["labels"], json!([]), "{before}");

        write_priority(d, &["copy"], nzbfast_daemon::job::DUPE_PRIORITY);

        assert!(get(d, "copy", |g| g.paused && g.priority == -3));
        assert!(get(d, "copy", nzbfast_daemon::job::is_held_alternative));
        assert_eq!(slot_of(d, "copy")["labels"], json!(["ALTERNATIVE"]));
        // The hold is a hold, not a delete.
        assert_eq!(d.queue.lock_ok().len(), 1);
    });
}

/// A copy that is ALREADY running when it is put back on hold stops: its
/// own pause flag is a pause in force even on an unpaused queue, so the
/// wind-down runs for it without any queue pause.
#[test]
fn putting_a_running_released_duplicate_back_on_hold_stops_it() {
    with_daemon("rehold-running", |d| {
        d.queue.lock_ok().push_back(row(
            "copy",
            JobState::Downloading,
            json!({"priority": 2, "held_for": "orig"}),
        ));

        write_priority(d, &["copy"], nzbfast_daemon::job::DUPE_PRIORITY);

        assert!(get(d, "copy", |g| g.suspended), "the hold left it running");
        assert!(get(d, "copy", |g| g.paused));
        settle(d);
    });
}

/// Duplicate priority is only a HOLD on a row that was held for
/// something. On an ordinary row it stays the plain number it always was
/// (an *arr that writes -3 must not find its job paused).
#[test]
fn duplicate_priority_on_an_ordinary_row_does_not_pause_it() {
    with_daemon("rehold-ordinary", |d| {
        d.queue
            .lock_ok()
            .push_back(row("plain", JobState::Queued, json!({"priority": 0})));

        write_priority(d, &["plain"], nzbfast_daemon::job::DUPE_PRIORITY);

        assert!(!get(d, "plain", |g| g.paused));
        assert_eq!(get(d, "plain", |g| g.priority), -3);
    });
}

/// What the page badges a row from. `priority` is the SAB word and is
/// enough for Force on its own; `held_for` is the additive field that
/// says whether "back to hold" is offered.
#[test]
fn the_queue_slot_carries_what_the_page_needs_to_badge_a_forced_row() {
    with_daemon("slot-force", |d| {
        {
            let mut q = d.queue.lock_ok();
            q.push_back(row("f", JobState::Downloading, json!({"priority": 2})));
            q.push_back(row("n", JobState::Queued, json!({"priority": 0})));
        }
        let f = slot_of(d, "f");
        assert_eq!(f["priority"], "Force", "{f}");
        assert_eq!(f["held_for"], "", "{f}");
        let n = slot_of(d, "n");
        assert_eq!(n["priority"], "Normal", "{n}");
    });
}

/// Every priority write through the shared transition leaves a line in
/// daemon.log: the row, both words and what asked - including the two
/// hold transitions, which read as plain rank changes without a word of
/// their own. (The 21 Sep 2026 report could not be explained from the
/// log: the row had been made Force and nothing said so.)
#[test]
fn every_priority_write_leaves_a_trace_in_the_log() {
    with_daemon("unforce-log", |d| {
        d.queue.lock_ok().push_back(row(
            "held",
            JobState::Queued,
            json!({"priority": -3, "paused": true, "held_for": "orig"}),
        ));
        d.queue
            .lock_ok()
            .push_back(row("plain", JobState::Queued, json!({"priority": 0})));

        let (_, lines) = nzbfast_daemon::testutil::capture_log(|| {
            // Download anyway: the hold is released, and the row is Force.
            write_priority(d, &["held"], 2);
            // The same value again changes nothing and says nothing.
            write_priority(d, &["held"], 2);
            // ...and back on hold.
            write_priority(d, &["held"], nzbfast_daemon::job::DUPE_PRIORITY);
            write_priority(d, &["plain"], 1);
        });

        let text = lines.join("\n");
        for want in [
            "[queue] held: duplicate hold released by a priority write",
            "[queue] held: priority Duplicate -> Force (priority write)",
            "[queue] held: priority Force -> Duplicate (priority write put the copy back on hold)",
            "[queue] plain: priority Normal -> High (priority write)",
        ] {
            assert!(
                lines.iter().any(|l| l == want),
                "missing {want:?} in:\n{text}"
            );
        }
        assert_eq!(
            lines
                .iter()
                .filter(|l| l.contains("held: priority"))
                .count(),
            2,
            "a write that changed nothing must say nothing:\n{text}"
        );
    });
}
