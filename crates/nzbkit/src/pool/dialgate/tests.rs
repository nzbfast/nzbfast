//! Unit tests for the stated-cap dial gate and the connect-ladder
//! spread (`super`'s module header carries the measurement these are
//! written against).
//!
//! The session-level halves - that `dial_session` really consults the
//! gate, and that `park_or_probe` really staggers a rejoin - live in
//! `pool/session/unit_tests.rs` beside the rest of that machinery.

use super::*;

/// The acceptance bar, first half: while a server is at a stated cap,
/// exactly ONE worker may have a dial in flight.
///
/// The live shape this refuses is eleven `connect failed` lines sharing
/// one timestamp second against a provider that had already said `502
/// connection limit (40) reached`.
#[test]
fn a_capped_server_admits_exactly_one_dial_at_a_time() {
    let gate = DialGate::default();
    gate.arm();
    let held = gate.canary(true).expect("the first worker is the canary");
    for _ in 0..10 {
        assert!(
            gate.canary(true).is_none(),
            "a second dial while the canary is in flight is the burst \
             this gate exists to refuse"
        );
    }
    // The canary's dial completes - however it completed - and the next
    // worker may probe.
    drop(held);
    assert!(
        gate.canary(true).is_some(),
        "the permit is released the instant the dial ends"
    );
}

/// The permit is RAII precisely because the dial is left by four routes
/// and a leak wedges the server for the rest of the run. Pin that the
/// drop is what releases it, not a matching call somebody could omit.
#[test]
fn the_permit_is_released_by_dropping_it() {
    let gate = DialGate::default();
    gate.arm();
    {
        let _c = gate.canary(true).expect("canary");
        assert!(gate.canary(true).is_none(), "held for the scope");
    }
    assert!(gate.canary(true).is_some(), "and released by the scope end");
}

/// An UNARMED gate is a free pass, and that is most of the life of most
/// servers: the whole fleet must dial concurrently on a healthy
/// provider, exactly as it did before this existed.
#[test]
fn an_unarmed_gate_lets_the_whole_fleet_dial() {
    let gate = DialGate::default();
    assert!(!gate.is_armed());
    let all: Vec<_> = (0..32).map(|_| gate.canary(true)).collect();
    assert!(
        all.iter().all(|c| c.is_some()),
        "no server that has not stated a cap may be serialised"
    );
}

/// Only a GRANTED session stands the gate down. The reason this is
/// worth a test of its own is that every other candidate is evidence of
/// the opposite: a refusal naming a smaller number, a connect timing
/// out, or time passing all describe a cap that is still full.
#[test]
fn only_a_granted_session_disarms_the_gate() {
    let gate = DialGate::default();
    gate.arm();
    assert!(gate.is_armed());
    // A second stated cap while already armed changes nothing.
    gate.arm();
    assert!(gate.is_armed());
    gate.reopen();
    assert!(
        !gate.is_armed(),
        "a granted session is the room we waited for"
    );
    let all: Vec<_> = (0..8).map(|_| gate.canary(true)).collect();
    assert!(
        all.iter().all(|c| c.is_some()),
        "and the fleet ramps back in"
    );
}

/// `NZBFAST_DIAL_CANARY=0`'s effect, pinned through the explicit
/// parameter rather than through process env - the pool's own house
/// pattern (`pacing::session_backoff_delay_with`), and the only shape a
/// test may pin without becoming a process-global that its neighbours
/// can move.
#[test]
fn the_off_switch_restores_the_unserialised_dial() {
    let gate = DialGate::default();
    gate.arm();
    let all: Vec<_> = (0..8).map(|_| gate.canary(false)).collect();
    assert!(
        all.iter().all(|c| c.is_some()),
        "off means every worker dials when its own ladder says so"
    );
}

/// The acceptance bar, second half: two workers backing off at the same
/// instant do not wake at the same instant.
///
/// Consecutive tickets, which is what two simultaneous backoffs take.
#[test]
fn consecutive_tickets_never_share_a_delay() {
    let base = Duration::from_secs(2);
    for t in 0..64u64 {
        assert_ne!(
            spread_delay(base, t),
            spread_delay(base, t + 1),
            "ticket {t} and {} landed together",
            t + 1
        );
    }
}

/// ...and the spread is a real one: sixteen distinct positions, not two
/// that happen to differ.
#[test]
fn the_spread_reaches_every_slot() {
    let base = Duration::from_secs(2);
    let seen: std::collections::BTreeSet<_> = (0..SPREAD_SLOTS * 3)
        .map(|t| spread_delay(base, t))
        .collect();
    assert_eq!(
        seen.len() as u64,
        SPREAD_SLOTS,
        "the round robin must reach all {SPREAD_SLOTS} slots and no more"
    );
}

/// The bound that keeps this free of consequences elsewhere: a spread
/// step is never LONGER than the ladder step it replaces, so every
/// horizon quoted as `connect_backoff * 2^n` upstream stays an upper
/// bound. And never shorter than half, so the ladder still paces.
#[test]
fn a_spread_step_stays_inside_half_the_ladder_step() {
    for &ms in &[1u64, 2, 50, 2_000, 32_000] {
        let base = Duration::from_millis(ms);
        for t in 0..SPREAD_SLOTS * 2 {
            let d = spread_delay(base, t);
            assert!(
                d >= base / 2,
                "{d:?} undercuts half of {base:?} - the ladder stops pacing"
            );
            assert!(
                d < base || base.is_zero(),
                "{d:?} exceeds {base:?} - every horizon upstream is quoted \
                 as an upper bound on this"
            );
        }
    }
}

/// The rigs configure `connect_backoff` in single-digit milliseconds,
/// so the slot arithmetic has to resolve below the millisecond or the
/// spread silently collapses to one value exactly where the tests that
/// would notice it run.
#[test]
fn a_millisecond_ladder_still_spreads() {
    let seen: std::collections::BTreeSet<_> = (0..SPREAD_SLOTS)
        .map(|t| spread_delay(Duration::from_millis(1), t))
        .collect();
    assert_eq!(seen.len() as u64, SPREAD_SLOTS, "sub-ms spans must spread");
}

/// A zero base is a configuration the rigs really do use
/// (`ramp_delay: Duration::ZERO` next door), and the arithmetic divides
/// by it in the obvious spelling. Nothing may panic and the answer is
/// zero.
#[test]
fn a_zero_ladder_step_stays_zero() {
    for t in 0..SPREAD_SLOTS {
        assert_eq!(spread_delay(Duration::ZERO, t), Duration::ZERO);
        assert_eq!(rejoin_stagger(Duration::ZERO, t), Duration::ZERO);
    }
}

/// A worker that loses the permit goes straight back round to ask
/// again, so its wait must never be zero however the pool is
/// configured - and `connect_backoff: Duration::ZERO` is a live rig
/// configuration, so this is the difference between a queue and a spin
/// loop. The rest of the spread's properties still have to hold on top
/// of the floor.
#[test]
fn a_gate_wait_is_never_zero_even_at_a_zero_backoff() {
    for t in 0..SPREAD_SLOTS {
        assert!(
            gate_wait(Duration::ZERO, t) >= Duration::from_millis(25),
            "a zero wait turns the queue into a hot loop"
        );
    }
    let seen: std::collections::BTreeSet<_> = (0..SPREAD_SLOTS)
        .map(|t| gate_wait(Duration::ZERO, t))
        .collect();
    assert_eq!(
        seen.len() as u64,
        SPREAD_SLOTS,
        "and the floored wait still spreads, or the queue re-forms a herd"
    );
    // A configured backoff above the floor is used as it stands.
    assert_eq!(
        gate_wait(Duration::from_secs(2), 0),
        spread_delay(Duration::from_secs(2), 0),
        "the floor must only ever lift an absurd configuration"
    );
}

/// The rejoin stagger starts at ZERO, unlike the backoff spread: the
/// fleet has just been told the cap has room, so the first worker back
/// in must not be delayed to fix a burst the others' stagger fixes.
#[test]
fn the_rejoin_stagger_starts_at_zero_and_spreads_the_rest() {
    let spread = Duration::from_secs(2);
    assert_eq!(
        rejoin_stagger(spread, 0),
        Duration::ZERO,
        "the first waker rejoins immediately"
    );
    let all: Vec<_> = (0..SPREAD_SLOTS)
        .map(|t| rejoin_stagger(spread, t))
        .collect();
    let uniq: std::collections::BTreeSet<_> = all.iter().collect();
    assert_eq!(uniq.len() as u64, SPREAD_SLOTS, "and the rest are spread");
    assert!(
        all.iter().all(|d| *d < spread),
        "a stagger never outlasts its own spread"
    );
}

/// The ticket counter is what makes two SIMULTANEOUS backoffs take
/// different values, so it has to be monotonic per server and shared by
/// every worker of it.
#[test]
fn tickets_are_monotonic_and_shared() {
    let gate = DialGate::default();
    let drawn: Vec<u64> = (0..5).map(|_| gate.ticket()).collect();
    assert_eq!(drawn, vec![0, 1, 2, 3, 4]);
}

/// Concurrency, for real rather than by inspection: N threads racing
/// the permit on an armed gate must produce exactly one winner per
/// round, and the ticket counter must lose nothing.
#[test]
fn the_permit_and_the_ticket_hold_under_a_real_race() {
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    let gate = Arc::new(DialGate::default());
    gate.arm();
    let wins = Arc::new(AtomicUsize::new(0));
    let start = Arc::new(std::sync::Barrier::new(8));
    let mut hands = Vec::new();
    for _ in 0..8 {
        let (g, w, b) = (gate.clone(), wins.clone(), start.clone());
        hands.push(std::thread::spawn(move || {
            b.wait();
            // Hold the permit for the whole race, exactly as a dial
            // holds it for the whole connect: without that, a fast
            // winner could release and let a second thread win, which
            // would be correct behaviour and a useless assertion.
            let held = g.canary(true);
            if held.is_some() {
                w.fetch_add(1, Ordering::Relaxed);
            }
            for _ in 0..64 {
                let _ = g.ticket();
            }
            std::thread::sleep(Duration::from_millis(20));
            drop(held);
        }));
    }
    for h in hands {
        h.join().expect("racer");
    }
    assert_eq!(
        wins.load(Ordering::Relaxed),
        1,
        "eight racing workers, one canary"
    );
    assert_eq!(
        gate.tickets.load(Ordering::Relaxed),
        8 * 64,
        "the ticket counter must lose nothing to the race, or two \
         workers can draw one slot and land together"
    );
}
