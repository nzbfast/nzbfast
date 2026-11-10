//! The dispatch-stall clock and its idle list, as pure functions: no
//! daemon, no sockets, a synthetic clock. The end-to-end legs (a mute
//! provider, the second stage, a backoff and a pause) are in the daemon
//! suite, `crates/nzbfast/tests/daemon_dispatchstall/`.

use super::{DispatchStall, Facts, Idle, Pulse, idle_reason};
use std::time::{Duration, Instant};

const AFTER: Duration = Duration::from_secs(120);

fn at(t0: Instant, secs: u64) -> Instant {
    t0 + Duration::from_secs(secs)
}

/// A run with work queued and nothing moving.
fn frozen() -> Pulse {
    Pulse {
        bytes: 5_000,
        pending: 40,
        ..Pulse::default()
    }
}

#[test]
fn a_frozen_run_is_reported_once_at_the_threshold() {
    let t0 = Instant::now();
    let mut c = DispatchStall::new(Some(AFTER));
    assert_eq!(c.observe(t0, Some("a"), None, frozen()), None);
    assert_eq!(c.observe(at(t0, 60), Some("a"), None, frozen()), None);
    assert_eq!(c.observe(at(t0, 119), Some("a"), None, frozen()), None);
    assert_eq!(c.observe(at(t0, 121), Some("a"), None, frozen()), Some(121));
    // Latched: one verdict per episode, never one per tick.
    assert_eq!(c.observe(at(t0, 200), Some("a"), None, frozen()), None);
    assert_eq!(c.observe(at(t0, 900), Some("a"), None, frozen()), None);
}

/// Every field of the pulse is liveness on its own - in particular a
/// dead post's refusal ladder, which moves no bytes at all (the 31 Jul
/// trap the engine watchdog fell into), and the bare-430 confirming
/// repeat, which moves neither bytes nor the verdict count.
#[test]
fn any_moving_signal_restarts_the_clock() {
    let moves: [(&str, fn(&mut Pulse)); 6] = [
        ("bytes", |p| p.bytes += 1),
        ("a 430", |p| p.missing += 1),
        ("a verdict", |p| p.pending -= 1),
        ("a confirming repeat", |p| p.deferred += 1),
        ("a held-bytes park", |p| p.parked += 1),
        ("decode backpressure", |p| p.blocked_ms += 1),
    ];
    for (what, bump) in moves {
        let t0 = Instant::now();
        let mut c = DispatchStall::new(Some(AFTER));
        let mut p = frozen();
        assert_eq!(c.observe(t0, Some("a"), None, p), None);
        // Something moves at 100 s; the 121 s sample is then only 21 s
        // into a fresh episode.
        bump(&mut p);
        assert_eq!(c.observe(at(t0, 100), Some("a"), None, p), None, "{what}");
        assert_eq!(c.observe(at(t0, 121), Some("a"), None, p), None, "{what}");
        assert_eq!(
            c.observe(at(t0, 221), Some("a"), None, p),
            Some(121),
            "{what}"
        );
    }
}

/// A legitimate idle restarts the clock rather than pausing it: a stall
/// must be one unbroken stretch, so ninety seconds frozen, a pause, and
/// thirty more frozen is not two minutes of stall.
#[test]
fn an_idle_spell_restarts_the_clock_rather_than_pausing_it() {
    let t0 = Instant::now();
    let mut c = DispatchStall::new(Some(AFTER));
    assert_eq!(c.observe(t0, Some("a"), None, frozen()), None);
    assert_eq!(c.observe(at(t0, 90), Some("a"), None, frozen()), None);
    assert_eq!(
        c.observe(at(t0, 95), Some("a"), Some(Idle::JobPaused), frozen()),
        None
    );
    assert_eq!(c.observe(at(t0, 125), Some("a"), None, frozen()), None);
    assert_eq!(c.observe(at(t0, 214), Some("a"), None, frozen()), None);
    assert_eq!(c.observe(at(t0, 216), Some("a"), None, frozen()), Some(121));
}

/// An idle state held for any length of time never fires, whatever the
/// pulse does. Every arm of the list, one at a time.
#[test]
fn no_idle_state_ever_fires_however_long_it_lasts() {
    for idle in [
        Idle::Offline,
        Idle::QueuePaused,
        Idle::JobPaused,
        Idle::Demoting,
        Idle::PastTheNetwork,
        Idle::HandOver,
        Idle::WindingDown,
        Idle::ProviderBackoff,
        Idle::NothingQueued,
    ] {
        let t0 = Instant::now();
        let mut c = DispatchStall::new(Some(AFTER));
        for s in (0..3_600).step_by(5) {
            assert_eq!(
                c.observe(at(t0, s), Some("a"), Some(idle), frozen()),
                None,
                "{idle:?} fired at {s}s"
            );
        }
    }
}

#[test]
fn a_new_job_starts_a_new_clock() {
    let t0 = Instant::now();
    let mut c = DispatchStall::new(Some(AFTER));
    assert_eq!(c.observe(t0, Some("a"), None, frozen()), None);
    assert_eq!(c.observe(at(t0, 110), Some("b"), None, frozen()), None);
    assert_eq!(c.observe(at(t0, 125), Some("b"), None, frozen()), None);
    assert_eq!(c.observe(at(t0, 231), Some("b"), None, frozen()), Some(121));
    // Nothing on the wire forgets the job, so its return is fresh too.
    assert_eq!(c.observe(at(t0, 300), None, None, Pulse::default()), None);
    assert_eq!(c.observe(at(t0, 301), Some("b"), None, frozen()), None);
    assert_eq!(c.observe(at(t0, 400), Some("b"), None, frozen()), None);
}

#[test]
fn switched_off_never_fires() {
    let t0 = Instant::now();
    let mut c = DispatchStall::new(None);
    for s in (0..3_600).step_by(5) {
        assert_eq!(c.observe(at(t0, s), Some("a"), None, frozen()), None);
    }
}

/// The idle list itself: every fact on its own is an idle, and only a
/// run with none of them and work queued is judged at all.
#[test]
fn each_fact_on_its_own_names_its_idle_state() {
    let busy = Facts {
        pending: 7,
        ..Facts::default()
    };
    assert_eq!(idle_reason(&busy), None, "a plain run is judged");
    let cases: [(fn(&mut Facts), Idle); 9] = [
        (|f| f.offline = true, Idle::Offline),
        (|f| f.queue_paused = true, Idle::QueuePaused),
        (|f| f.job_paused = true, Idle::JobPaused),
        (|f| f.demoting = true, Idle::Demoting),
        (|f| f.past_the_network = true, Idle::PastTheNetwork),
        (|f| f.hand_over = true, Idle::HandOver),
        (|f| f.winding_down = true, Idle::WindingDown),
        (|f| f.provider_backoff = true, Idle::ProviderBackoff),
        (|f| f.pending = 0, Idle::NothingQueued),
    ];
    for (set, want) in cases {
        let mut f = busy;
        set(&mut f);
        assert_eq!(idle_reason(&f), Some(want));
    }
}

/// The shipped window has to sit inside the engine's deadlock window
/// with room for a watchdog tick and the engine's poll, or the abort
/// reaches a stalled run first and the reset never happens.
#[test]
fn the_reset_lands_inside_the_engine_deadlock_window() {
    // The engine's shipped default, unset env (the unit-test process
    // does not set it; if a developer's shell does, the default is what
    // this pins, so read it only when nothing overrides it).
    if std::env::var_os("NZBFAST_STALL_ABORT_SECS").is_some() {
        eprintln!("skipped: NZBFAST_STALL_ABORT_SECS overrides the shipped window");
        return;
    }
    let window = crate::get::deadlock_window_secs();
    let reset = super::RESET_AFTER.as_secs();
    // 5 s watchdog tick + 15 s engine poll at the shipped window.
    assert!(
        reset + 5 + 15 <= window,
        "reset {reset}s does not land inside the {window}s deadlock window"
    );
}

/// `from_env`'s unset default is a literal (env-default-gate reads it);
/// it must stay `RESET_AFTER`.
#[test]
fn the_shipped_default_is_reset_after() {
    if std::env::var_os("NZBFAST_DISPATCH_RESET_SECS").is_some() {
        eprintln!("skipped: NZBFAST_DISPATCH_RESET_SECS is set");
        return;
    }
    assert_eq!(DispatchStall::from_env().after, Some(super::RESET_AFTER));
}
