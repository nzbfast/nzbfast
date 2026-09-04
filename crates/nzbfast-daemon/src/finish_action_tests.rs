//! The decision half of the queue-finished action, over a real `Daemon`
//! fixture: what a word parses to, what a queue state blocks, and that
//! the drain edge is taken exactly once.
//!
//! The COMMANDS are not exercised here (nothing in this file may sleep
//! the machine running it). Their once-through ladder is pinned by
//! `power_commands` being a pure table, and the end-to-end trigger by
//! tests/daemon_finish/, which arms a real shutdown under
//! NZBFAST_FINISH_DRY_RUN=1.

use super::*;

pub fn with_daemon(name: &str, f: impl FnOnce(&Arc<Daemon>)) {
    let dir = std::env::temp_dir().join(format!("nzbfast-fin-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let d = crate::testutil::test_daemon(&dir);
    f(&d);
    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

fn queued(id: &str, paused: bool, priority: i32) -> Arc<Mutex<Job>> {
    let v = json!({
        "nzo_id": id, "name": id, "nzb_path": "/tmp/x.nzb",
        "out_dir": format!("/tmp/out/{id}"), "state": "Queued",
        "paused": paused, "priority": priority,
    });
    Arc::new(Mutex::new(job_from_json(&v).expect("job_from_json")))
}

/// An unknown word must be an error, never a silent `none`. This is the
/// control that turns the machine off: "sleeep" has to fail loudly at
/// the moment it is typed, or the user believes they armed something and
/// nothing is armed at all.
#[test]
fn only_the_four_words_parse() {
    for (word, want) in [
        ("none", FinishAction::None),
        ("", FinishAction::None),
        ("off", FinishAction::None),
        ("script", FinishAction::Script),
        ("sleep", FinishAction::Sleep),
        ("suspend", FinishAction::Sleep),
        (" shutdown ", FinishAction::Shutdown),
        ("poweroff", FinishAction::Shutdown),
    ] {
        assert_eq!(FinishAction::parse(word), Some(want), "parse {word:?}");
    }
    for word in ["sleeep", "reboot", "yes", "1", "SHUTDOWN"] {
        assert_eq!(FinishAction::parse(word), None, "must refuse {word:?}");
    }
    // The round trip the settings row and settings.json both depend on.
    for a in [
        FinishAction::None,
        FinishAction::Script,
        FinishAction::Sleep,
        FinishAction::Shutdown,
    ] {
        assert_eq!(FinishAction::parse(a.as_str()), Some(a));
    }
}

/// Only the two that end the session disarm themselves and count down. A
/// script is a notifier: it runs every time and warns about nothing.
#[test]
fn one_shot_and_countdown_cover_exactly_sleep_and_shutdown() {
    assert!(!FinishAction::None.one_shot() && !FinishAction::None.counts_down());
    assert!(!FinishAction::Script.one_shot() && !FinishAction::Script.counts_down());
    for a in [FinishAction::Sleep, FinishAction::Shutdown] {
        assert!(a.one_shot(), "{} must disarm on firing", a.as_str());
        assert!(a.counts_down(), "{} must warn first", a.as_str());
    }
}

/// A payload the mover is still relocating must block the machine going
/// to sleep, even though its record has LEFT the queue.
///
/// `park` files the record into history and hands the move over on the
/// mover's own worker, precisely so the runner never waits on a NAS
/// copy - so by the time the queue looks empty, the slowest thing this
/// download will do has not started. Walking `d.queue` alone cannot see
/// it, and shutting down mid-copy is the one outcome a queue-finished
/// action must never produce.
#[test]
fn an_owed_relocation_blocks_the_drain_though_it_left_the_queue() {
    with_daemon("moving", |d| {
        d.queue_idle_latch.store(true, Ordering::Relaxed);
        assert_eq!(drain_blocker(d), None, "empty queue, nothing moving");

        // Queued for the mover but not yet picked up.
        d.mover_q.lock_ok().push_back(queued("owes-move", false, 0));
        assert_eq!(
            drain_blocker(d),
            Some("a finished download is still being moved"),
            "a job waiting on the mover must hold the drain"
        );
        d.mover_q.lock_ok().clear();

        // ...and the copy actually in flight.
        d.moving.lock_ok().insert("owes-move".to_string());
        assert_eq!(
            drain_blocker(d),
            Some("a finished download is still being moved"),
            "a copy in flight must hold the drain"
        );
        d.moving.lock_ok().clear();
        assert_eq!(
            drain_blocker(d),
            None,
            "and it clears when the move is done"
        );
    });
}

/// A refusal must not SPEND the drain edge.
///
/// `note_queue_idle` short-circuits on the set latch, so it can never
/// issue a second edge for an idle period already announced. An edge
/// consumed by a refusal therefore disarmed the action permanently:
/// the user deletes the paused job that was blocking it, the queue is
/// now genuinely empty and idle, and nothing ever fires.
#[test]
fn a_refused_drain_keeps_its_edge_for_the_next_tick() {
    with_daemon("edge", |d| {
        d.queue_idle_latch.store(true, Ordering::Relaxed);
        *d.finish.action.lock_ok() = FinishAction::Sleep;
        d.queue.lock_ok().push_back(queued("paused", true, 0));

        d.finish.note_drained();
        tick(d);
        assert!(
            drain_blocker(d).is_some(),
            "the paused job is still the blocker"
        );
        assert!(
            d.finish.drained.load(Ordering::Relaxed),
            "the refused edge must still be armed"
        );

        // The user deletes the blocker. Nothing re-arms the edge - the
        // latch is still set, so `note_queue_idle` returns early - so
        // the HELD edge is the only thing that can still fire this.
        d.queue.lock_ok().clear();
        assert_eq!(drain_blocker(d), None);
        tick(d);
        assert!(
            d.finish.pending().is_some(),
            "with the blocker gone the held edge must arm the countdown"
        );
    });
}

/// A Completed row whose post-processing tail is still running matches
/// neither state arm - `finalizing` is the marker that says the unpack,
/// rename or pp-script is in flight while the row waits for park. The
/// mover checks cannot cover it either: the mover only receives the job
/// AT park. Without this, a two-wide postproc lane let job A's park
/// drain the queue and power the machine off mid-way through job B's
/// unpack (bug sweep 20 Aug).
#[test]
fn a_finalizing_completed_row_still_blocks_the_drain() {
    with_daemon("finalizing", |d| {
        d.queue_idle_latch.store(true, Ordering::Relaxed);
        let j = queued("tail", false, 0);
        {
            let mut g = j.lock_ok();
            g.state = JobState::Completed;
            g.finalizing = true;
        }
        d.queue.lock_ok().push_back(j.clone());
        assert_eq!(
            drain_blocker(d),
            Some("a download is still finishing"),
            "a finalizing tail is a job in flight"
        );
        j.lock_ok().finalizing = false;
        assert_eq!(drain_blocker(d), None, "and parking it releases the drain");
    });
}

/// A countdown cancelled by a transient blocker must give the edge back,
/// exactly as a refusal before the countdown does. The latch is still
/// set, so `note_queue_idle` will never issue another edge for this idle
/// period - a cancellation that merely SPENDS it silently disarms the
/// action until unrelated new work drains again (bug sweep 20 Aug: a
/// move auto-retry firing mid-countdown was enough).
#[test]
fn a_cancelled_countdown_gives_the_edge_back() {
    with_daemon("cancelledge", |d| {
        d.queue_idle_latch.store(true, Ordering::Relaxed);
        d.finish.set_action(FinishAction::Shutdown);
        d.finish.set_delay_secs(30);
        d.finish.note_drained();
        tick(d);
        assert!(
            d.finish.pending().is_some(),
            "the drain armed the countdown"
        );
        assert!(
            !d.finish.drained.load(Ordering::Relaxed),
            "arming spent the edge"
        );
        // A mover blocker appears mid-countdown (the M32 auto-retry
        // redriving a failed NAS move).
        d.moving.lock_ok().insert("retry".to_string());
        assert_eq!(tick(d), IDLE_TICK);
        assert!(d.finish.pending().is_none(), "the countdown is cancelled");
        assert!(
            d.finish.drained.load(Ordering::Relaxed),
            "and the edge is held for when the blocker clears"
        );
        // The retried move completes to a still-idle queue: the held
        // edge is the only thing that can still fire this, and it must.
        d.moving.lock_ok().clear();
        tick(d);
        assert!(
            d.finish.pending().is_some(),
            "the held edge re-arms the countdown"
        );
    });
}

/// The in-transit windows: a job popped off `mover_q` but not yet in
/// `moving` (the dispatcher's lane-key resolution, a lane's 2 s busy
/// requeue sleep) is invisible to both structure checks. The custody
/// counter is what covers the gap.
#[test]
fn a_move_in_lane_custody_blocks_the_drain_between_the_structures() {
    with_daemon("inflight", |d| {
        d.queue_idle_latch.store(true, Ordering::Relaxed);
        assert_eq!(drain_blocker(d), None);
        d.mover_inflight.fetch_add(1, Ordering::Relaxed);
        assert_eq!(
            drain_blocker(d),
            Some("a finished download is still being moved"),
            "custody without either structure must still hold the drain"
        );
        d.mover_inflight.fetch_sub(1, Ordering::Relaxed);
        assert_eq!(drain_blocker(d), None);
    });
}

/// The whole safety case in one test: every queue state that must refuse
/// to power the machine off, and the one that must not.
#[test]
fn drain_blocker_refuses_anything_the_user_could_still_resume() {
    with_daemon("blocker", |d| {
        // The clean case: latch set, queue empty.
        d.queue_idle_latch.store(true, Ordering::Relaxed);
        assert_eq!(drain_blocker(d), None, "empty queue with the latch set");

        // The latch is the edge's own evidence. Cleared means an add or
        // a pick has happened since, which is exactly the "a download
        // arrived during the countdown" case.
        d.queue_idle_latch.store(false, Ordering::Relaxed);
        assert!(drain_blocker(d).is_some(), "latch cleared = new work");
        d.queue_idle_latch.store(true, Ordering::Relaxed);

        // A job the user paused is work they mean to come back to.
        // `queue.idle` deliberately does not count it; this must.
        d.queue.lock_ok().push_back(queued("paused", true, 0));
        assert_eq!(
            drain_blocker(d),
            Some("a paused download is still in the queue")
        );

        // ...but a held alternative is paused by design and invisible to
        // the user. Counting it would mean an install with duplicate
        // handling on never fires this at all.
        d.queue.lock_ok().clear();
        d.queue
            .lock_ok()
            .push_back(queued("held", true, DUPE_PRIORITY));
        assert_eq!(drain_blocker(d), None, "held alternatives are exempt");

        // An unpaused queued job means the runner simply has not picked
        // it yet.
        d.queue.lock_ok().push_back(queued("waiting", false, 0));
        assert_eq!(
            drain_blocker(d),
            Some("a download is still waiting to start")
        );

        // A post-processing tail is still a job in flight - the whole
        // reason the trigger hangs off `park` rather than off net-drain.
        d.queue.lock_ok().clear();
        let j = queued("finishing", false, 0);
        j.lock_ok().state = JobState::Finishing;
        d.queue.lock_ok().push_back(j);
        assert_eq!(
            drain_blocker(d),
            Some("a download is still finishing"),
            "a post-process tail is not a finished queue"
        );

        // A daemon on its way out must not power the machine off on the
        // drain its own shutdown caused.
        d.queue.lock_ok().clear();
        d.exiting.store(true, Ordering::Relaxed);
        assert_eq!(drain_blocker(d), Some("nzbfast is shutting down"));
        d.exiting.store(false, Ordering::Relaxed);
        assert_eq!(drain_blocker(d), None);
    });
}

/// The edge is TAKEN, not read. Two passes over one drain must produce
/// one action, which is the entire difference between this and a poller.
#[test]
fn the_drain_edge_is_consumed_once() {
    with_daemon("edge", |d| {
        assert!(!d.finish.take_drain_edge(), "nothing has drained yet");
        d.finish.note_drained();
        assert!(d.finish.take_drain_edge(), "the edge is there once");
        assert!(!d.finish.take_drain_edge(), "and only once");
        // Idempotent on the emitting side too: `note_queue_idle` is
        // latched, but a future caller that is not must not queue up two.
        d.finish.note_drained();
        d.finish.note_drained();
        assert!(d.finish.take_drain_edge());
        assert!(!d.finish.take_drain_edge());
    });
}

/// A drain with `none` armed consumes the edge and does nothing - no
/// countdown, no payload change. The default install must be inert.
#[test]
fn a_drain_with_nothing_armed_does_nothing() {
    with_daemon("inert", |d| {
        assert_eq!(d.finish.action(), FinishAction::None, "default is off");
        d.finish.note_drained();
        let nap = tick(d);
        assert_eq!(nap, IDLE_TICK);
        assert!(
            d.finish.pending().is_none(),
            "nothing armed, nothing pending"
        );
        assert_eq!(payload(d)["armed"], json!("none"));
        assert_eq!(payload(d)["in_secs"], Value::Null);
    });
}

/// Arming shutdown: the drain opens a countdown rather than firing, the
/// payload carries the seconds left, and a second pass inside the window
/// does not fire either.
#[test]
fn shutdown_counts_down_before_it_fires() {
    with_daemon("countdown", |d| {
        d.finish.set_action(FinishAction::Shutdown);
        d.finish.set_delay_secs(30);
        d.finish.note_drained();

        assert_eq!(tick(d), COUNTDOWN_TICK, "the drain opens the countdown");
        let p = d.finish.pending().expect("a countdown is pending");
        assert_eq!(p.action, FinishAction::Shutdown);
        let pay = payload(d);
        assert_eq!(pay["armed"], json!("shutdown"));
        let left = pay["in_secs"].as_u64().expect("seconds left");
        assert!((1..=30).contains(&left), "in_secs was {left}");

        // Still armed after another pass: nothing fires early, and the
        // arm is untouched until it does.
        assert_eq!(tick(d), COUNTDOWN_TICK);
        assert!(d.finish.pending().is_some());
        assert_eq!(d.finish.action(), FinishAction::Shutdown);
    });
}

/// Work arriving mid-countdown abandons it. This is the case the whole
/// countdown exists for: the user queues something while the banner is
/// up and the machine must stay on.
#[test]
fn new_work_during_the_countdown_cancels_it() {
    with_daemon("newwork", |d| {
        d.finish.set_action(FinishAction::Shutdown);
        d.finish.set_delay_secs(30);
        d.finish.note_drained();
        assert!(matches!(tick(d), t if t == COUNTDOWN_TICK));
        assert!(d.finish.pending().is_some());

        // What an add does (`daemon_enqueue`) and what a pick does
        // (the runner): re-arm the latch.
        d.queue_idle_latch.store(false, Ordering::Relaxed);
        assert_eq!(tick(d), IDLE_TICK, "the countdown is abandoned");
        assert!(d.finish.pending().is_none());
        assert_eq!(payload(d)["in_secs"], Value::Null);
        // The ARM survives, because the user did not withdraw it: the
        // next real drain warns again.
        assert_eq!(d.finish.action(), FinishAction::Shutdown);
    });
}

/// The Cancel button stops the countdown AND switches the arm off. Two
/// clicks to re-arm is the right price for a control that powers the
/// machine down; leaving it armed after someone pressed stop is not.
#[test]
fn cancel_stops_the_countdown_and_disarms() {
    with_daemon("cancel", |d| {
        let none = cancel(d);
        assert_eq!(none["cancelled"], json!(false), "nothing was counting down");
        assert_eq!(none["disarmed"], json!(false), "and nothing was armed");

        d.finish.set_action(FinishAction::Sleep);
        d.finish.set_delay_secs(30);
        d.finish.note_drained();
        tick(d);
        assert!(d.finish.pending().is_some());

        let stopped = cancel(d);
        assert_eq!(
            stopped["cancelled"],
            json!(true),
            "a live countdown was stopped"
        );
        assert_eq!(stopped["disarmed"], json!(true));
        assert!(d.finish.pending().is_none());
        assert_eq!(d.finish.action(), FinishAction::None, "and disarmed");
        // Persisted, or a restart brings the arm back over a queue the
        // user has already refused to sleep on.
        let saved = crate::load_settings(&d.settings_path);
        assert_eq!(
            saved.get("queue_finished_action").and_then(Value::as_str),
            Some("none")
        );
        // A second click has nothing to stop and says so.
        assert_eq!(cancel(d)["cancelled"], json!(false));
    });
}

/// The header chip's case: an arm that has not fired yet is switched off
/// without any countdown having existed. `cancelled` false, `disarmed`
/// true - the pair the dashboard picks its wording from.
#[test]
fn cancelling_an_armed_action_that_is_not_counting_down_disarms_it() {
    with_daemon("chipoff", |d| {
        d.finish.set_action(FinishAction::Shutdown);
        let out = cancel(d);
        assert_eq!(out["cancelled"], json!(false));
        assert_eq!(out["disarmed"], json!(true));
        assert_eq!(d.finish.action(), FinishAction::None);
    });
}

/// Changing the setting while a countdown is up abandons it. Switching
/// the dropdown to "nothing" IS a cancel, whatever button was pressed.
#[test]
fn re_choosing_the_action_abandons_a_live_countdown() {
    with_daemon("rechoose", |d| {
        d.finish.set_action(FinishAction::Shutdown);
        d.finish.set_delay_secs(30);
        d.finish.note_drained();
        tick(d);
        assert!(d.finish.pending().is_some());
        d.finish.set_action(FinishAction::None);
        assert!(d.finish.pending().is_none());
    });
}

/// A drain that would fire but for a paused job leaves nothing pending
/// and does not spend the arm - so resuming and finishing that job still
/// gets the action the user asked for.
#[test]
fn a_blocked_drain_neither_fires_nor_disarms() {
    with_daemon("blocked", |d| {
        d.finish.set_action(FinishAction::Shutdown);
        d.queue.lock_ok().push_back(queued("paused", true, 0));
        d.finish.note_drained();
        assert_eq!(tick(d), IDLE_TICK);
        assert!(
            d.finish.pending().is_none(),
            "no countdown over a paused job"
        );
        assert_eq!(
            d.finish.action(),
            FinishAction::Shutdown,
            "the arm is not spent by a drain that was refused"
        );
    });
}

/// The countdown is clamped. An unbounded value is not "wait a long
/// time", it is a banner that never resolves.
#[test]
fn the_delay_is_clamped_and_reported_back() {
    with_daemon("clamp", |d| {
        assert_eq!(d.finish.delay_secs(), DEFAULT_DELAY_SECS);
        assert_eq!(d.finish.set_delay_secs(0), 0, "0 = fire at once, allowed");
        assert_eq!(d.finish.set_delay_secs(90), 90);
        assert_eq!(d.finish.set_delay_secs(u64::MAX), MAX_DELAY_SECS);
        assert_eq!(payload(d)["delay_secs"], json!(MAX_DELAY_SECS));
    });
}

/// Every platform offers at least one command for both actions, and none
/// of them is empty - a table that silently had no entry for this build
/// would report "failed" with nothing tried.
#[test]
fn every_platform_has_a_command_for_both_actions() {
    for a in [FinishAction::Sleep, FinishAction::Shutdown] {
        let cmds = power_commands(a);
        assert!(!cmds.is_empty(), "no command for {}", a.as_str());
        for (prog, _) in cmds {
            assert!(!prog.is_empty());
        }
    }
}
