//! Dial pacing for a server that has STATED a connection cap: the
//! single-canary gate, and the de-synchronising spread the multi-worker
//! connect ladders take their delays through.
//!
//! ## What this is for
//!
//! Measured on a live long-running daemon during the 29 Aug 2026
//! slow-queue investigation (item 3 of its write-up).
//! One provider was pinned at its account's stated cap - `502
//! connection limit (40) reached`, with this box holding only 1-7 of
//! those 40 - and the daemon log then shows connect attempts arriving
//! in bursts of 4, 6, 7 and 11 sharing an IDENTICAL timestamp second,
//! roughly every five minutes, every one of them ending `connect
//! failed: I/O: connect timed out`. An over-cap provider appears to
//! BLACKHOLE the extra SYN rather than refuse it, so each burst parks
//! that many pool workers for the whole connect timeout, and the herd
//! may itself be part of what keeps the provider-side session count
//! pinned.
//!
//! Two separate defects produce that shape and this module answers
//! both.
//!
//! **The workers share a schedule.** Every dial ladder in
//! [`super::session`] is a pure function of a per-worker counter -
//! `connect_backoff * 2^n` - so workers that bounced together at t=0
//! sleep the same number of milliseconds and dial together at t=1, and
//! again at t=2, for as long as the outage lasts. Nothing anywhere in
//! the pool jittered a redial (verified 29 Aug 2026: a `jitter` sweep
//! of the crate reached the mock's fault injector, the livetune rigs
//! and two comments about the LINK's own jitter, and nothing on the
//! dial path). That is what puts a burst inside one second rather than
//! smearing it across the ladder step. [`spread_delay`] is the fix.
//!
//! **Nothing narrows the ramp after a stated cap.** A provider that has
//! told us in words that the account may hold 40 connections has
//! already answered the question the fleet keeps re-asking with eleven
//! sockets at once. [`DialGate`] arms on that sentence and serialises
//! dials to that server - one in flight at a time, the rest waiting a
//! spread delay and re-asking - until a dial SUCCEEDS, which is the
//! only evidence that the cap has room again.
//!
//! ## What the gate costs, stated rather than discovered
//!
//! Serialising dials serialises everything that happens BEHIND a dial,
//! and the one that matters is the stand-down: a capacity refusal is
//! what sends a worker to `park_or_probe`, where `claim_yield` shrinks
//! the fleet to a width the provider will actually accept. Those
//! refusals now arrive one at a time instead of all at once, so a fleet
//! reaches its reduced width more slowly - against a provider that
//! blackholes, by one connect timeout per worker rather than one for
//! all of them.
//!
//! That is the trade being made and not an oversight. Nothing is
//! starved: the permit is released the instant each dial ends, so the
//! queue drains, every worker still meets the refusal, and every wait
//! selects on `finished`/`draining` and sits under the cumulative
//! outage budget the dial path checks before it gets here. What is
//! bought for it is that the provider stops being asked eleven times a
//! second whether it has room - which is the thing that may be keeping
//! it from having any.
//!
//! ## What is deliberately NOT changed
//!
//! The prober's own bounce ladder in [`super::session::park_or_probe`]
//! takes no spread. It is single-worker by construction - `cap_prober`
//! elects exactly one holder and every other claimant stands down - so
//! there is no herd there to break, and its `connect_backoff * 2^n`
//! step is the horizon that
//! `event_ring_tests::the_budget_does_not_undercut_the_consecutive_horizon`
//! prices the shipped outage budget against. Spreading it would move
//! that horizon as a side effect of a fix for a different defect.
//!
//! The log vocabulary is untouched. The bench rig's connection guard
//! anchors on the `[pool]` target and on the existing `at its
//! connection/IP cap` line, and its round readers find `conn_capped` by
//! name; nothing here renames or removes either.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

/// How many evenly spaced delays [`spread_delay`] chooses between.
///
/// A ROUND ROBIN and not a hash, which is the one design decision here
/// worth reading twice. The property that matters is not "the delays
/// look random", it is "two workers backing off at the same instant do
/// not wake at the same instant" - and consecutive tickets differ mod
/// 16 by construction, where a hash only differs with high
/// probability. That makes the guarantee an assertion rather than a
/// statistic, and it leaves the module free of randomness, so a rig
/// replays identically.
///
/// Sixteen because the fleets this bites on are tens of workers, not
/// hundreds: a seventeenth concurrent backoff shares a slot with the
/// first, which still leaves the burst smeared across sixteen
/// positions instead of landing inside one second.
pub(super) const SPREAD_SLOTS: u64 = 16;

/// The de-synchronising spread every MULTI-WORKER connect ladder takes
/// its delay through: sixteen evenly spaced values over `[base/2, base)`.
///
/// NEVER LONGER THAN `base`, which is what keeps this free of
/// consequences elsewhere. Every ladder in the pool is quoted as an
/// upper bound - the shipped outage budget is priced against
/// `connect_backoff * 4 * cap_probe_bounces`, and the `tls_chaos`
/// header reasons about what the session ladder "tops out at" - so a
/// spread that could EXTEND a step would silently move horizons other
/// tests assert against. Shortening one cannot.
///
/// Never shorter than `base/2` either: the ladder's whole job is to
/// stop a refusing server being re-asked at full rate, and a spread
/// that reached zero would hand back the hammering the ladder exists to
/// prevent. Half the step is still a real spread - a full second at the
/// shipped 2 s `connect_backoff`, against bursts that were landing
/// inside ONE second - while still pacing.
///
/// `ticket` comes from [`DialGate::ticket`], a per-server counter, so
/// two workers reaching a backoff together take consecutive values.
pub(super) fn spread_delay(base: Duration, ticket: u64) -> Duration {
    let half = base / 2;
    half + step_of(half, ticket)
}

/// The rejoin stagger: sixteen evenly spaced values over `[0, spread)`.
///
/// A `Reopened` wakes EVERY parked worker of that server at once - one
/// `watch` send, N wakers - and before this each of them returned
/// `DialStep::Retry` and dialled immediately, which is a burst of
/// exactly the shape the log showed. Unlike [`spread_delay`] this one
/// starts at zero: the fleet has just been told the cap has room, and
/// holding the first worker back would cost throughput to fix a problem
/// the spread over the others already fixes.
pub(super) fn rejoin_stagger(spread: Duration, ticket: u64) -> Duration {
    step_of(spread, ticket)
}

/// `span * (ticket % SPREAD_SLOTS) / SPREAD_SLOTS`, computed in
/// nanoseconds so the sub-millisecond spans the rigs configure
/// (`connect_backoff` of a few milliseconds) still resolve into
/// distinct slots.
fn step_of(span: Duration, ticket: u64) -> Duration {
    // u64 nanoseconds covers 584 years; every span here is a backoff.
    let nanos = span.as_nanos().min(u64::MAX as u128) as u64;
    Duration::from_nanos(nanos / SPREAD_SLOTS * (ticket % SPREAD_SLOTS))
}

/// One server's dial gate: the stated-cap latch, the single-canary
/// permit it guards, and the ticket counter the spread draws from.
///
/// Lives on `AuthState`, so it is per-server and shared by every worker
/// of that server, exactly like the capacity latch beside it.
#[derive(Default)]
pub(super) struct DialGate {
    /// This server has told us, in words, how many connections the
    /// account may hold ([`crate::nntp::CapacityLimit::Connections`]).
    ///
    /// Armed by [`DialGate::arm`], disarmed only by a dial that
    /// SUCCEEDS. It is deliberately NOT the `capacity_capped` latch
    /// beside it: that one is set once per run and never cleared, and
    /// gating on it would serialise every dial for the rest of the job
    /// on a fleet whose surplus workers bounce off a capacity refusal as
    /// a matter of course ("we ask 30, the account allows 20" is the
    /// NORMAL case - see `AuthState::mark_down`).
    capped: AtomicBool,
    /// True while one worker holds the canary permit. Only consulted
    /// while `capped`.
    dialing: AtomicBool,
    /// Monotonic per-server counter handed to [`spread_delay`] and
    /// [`rejoin_stagger`]. Wrapping is harmless - the value is only ever
    /// read modulo [`SPREAD_SLOTS`].
    tickets: AtomicU64,
}

/// The canary permit, released on drop.
///
/// RAII rather than a matching `release` call because the dial is left
/// by four routes - a connection, a refusal taxonomy with two arms, a
/// dial error, and the run-ended race that returns from inside the
/// `select!` - and a permit leaked on any one of them would wedge every
/// other worker of that server behind a canary that no longer exists,
/// for the rest of the run.
pub(super) struct Canary<'a>(Option<&'a AtomicBool>);

impl Drop for Canary<'_> {
    fn drop(&mut self) {
        if let Some(flag) = self.0 {
            flag.store(false, Ordering::Release);
        }
    }
}

impl DialGate {
    /// The next spread ticket for this server.
    pub(super) fn ticket(&self) -> u64 {
        self.tickets.fetch_add(1, Ordering::Relaxed)
    }

    /// This server has stated a CONNECTION cap. Arm the gate.
    ///
    /// Connection caps only. A simultaneous-IP refusal is about WHERE
    /// the account is used from, not how many sockets it grants, so
    /// serialising dials would answer a question it never asked - the
    /// same distinction `AuthState::note_cap` already draws, for the
    /// reason recorded there (Codex sweep 5, M9).
    pub(super) fn arm(&self) {
        self.capped.store(true, Ordering::Release);
    }

    /// A session was GRANTED: the cap has room, so the gate stands down
    /// and the rest of the fleet ramps back in.
    ///
    /// Nothing weaker may disarm it. A refusal naming a smaller number,
    /// a connect that times out, time simply passing - none of those is
    /// evidence of room, and a gate that stood down on any of them would
    /// hand back the burst it exists to prevent.
    ///
    /// A WARM-POOL take is not one of them either, and that is a
    /// decision rather than an omission: `acquire_conn`'s warm arm calls
    /// `mark_up` beside a comment arguing that a session taken from the
    /// pool is as granted as a dialled one, which is true of the OUTAGE
    /// clock and false here. A parked connection is a session the
    /// provider granted us earlier and has not yet taken away; it says
    /// nothing about whether it would grant a NEW one, which is the only
    /// question this gate asks. Leaving it armed there costs nothing -
    /// a fleet being served out of the warm pool is not dialling, and
    /// the first worker that does need a dial probes as the canary and
    /// disarms it on success.
    pub(super) fn reopen(&self) {
        self.capped.store(false, Ordering::Release);
    }

    /// Is the gate armed? (Diagnostic and test accessor; the dial path
    /// asks [`DialGate::canary`], which answers both questions at once.)
    pub(super) fn is_armed(&self) -> bool {
        self.capped.load(Ordering::Acquire)
    }

    /// May this worker dial right now?
    ///
    /// `Some(canary)` when the gate is disarmed (a free pass, and the
    /// permit is a no-op) or when it is armed and this worker won the
    /// single permit. `None` when it is armed and another worker's dial
    /// is already in flight: the caller must NOT dial - it waits a
    /// [`spread_delay`] and asks again.
    ///
    /// The permit is scoped to the dial itself and released the instant
    /// that completes, however it completes. Against a provider that
    /// blackholes, that is one connect timeout per attempt for the whole
    /// SERVER instead of one per WORKER, which is the entire point; the
    /// cost is that a worker whose own healthy session died may wait
    /// behind it. That trade is only ever taken against a server which
    /// has just said, in words, that it will not grant another
    /// connection.
    pub(super) fn canary(&self, on: bool) -> Option<Canary<'_>> {
        if !on || !self.is_armed() {
            return Some(Canary(None));
        }
        match self.dialing.swap(true, Ordering::AcqRel) {
            true => None,
            false => Some(Canary(Some(&self.dialing))),
        }
    }
}

/// How long a worker that lost the permit waits before asking again.
///
/// FLOORED, and the floor is not defensive decoration: a worker that
/// loses the permit goes straight back round to ask again, so a zero
/// wait is a hot loop rather than a slow one - and
/// `connect_backoff: Duration::ZERO` is a live rig configuration, not a
/// hypothetical (`pool/inline_tests/serverdown_tests.rs` sets exactly
/// that). Same floor and the same reasoning as
/// `pacing::session_backoff_delay`, which had to reach for it first.
///
/// Split out of [`wait_for_canary`] so the arithmetic can be pinned
/// without standing up a `Shared` and a fleet.
pub(super) fn gate_wait(connect_backoff: Duration, ticket: u64) -> Duration {
    spread_delay(connect_backoff.max(Duration::from_millis(50)), ticket)
}

/// What [`wait_for_canary`] decided: dial holding this permit, go
/// around for another session, or leave the fleet.
pub(super) enum Permit<'a> {
    Go(Canary<'a>),
    Retry,
    Quit,
}

/// Take the canary permit, or wait a [`spread_delay`] and hand the
/// caller back around to ask again.
///
/// No `connect_failures` bump on the wait: not dialling is not a
/// failure, and counting it as one would walk a worker into the prober
/// election for a queue it was politely standing in. The loop that
/// results is bounded exactly as the parked fleet's wait is - by the
/// cumulative outage budget the dial path checks before it gets here,
/// and by `finished`/`draining`, which `backoff_or_finish` selects on.
///
/// Lives here rather than at the call site so the whole of this
/// decision - the gate, the spread, the ticket, and why waiting is not
/// a failure - reads in one place, in the module whose header carries
/// the measurement.
pub(super) async fn wait_for_canary<'a>(
    gate: &'a DialGate,
    cfg: &super::PoolConfig,
    finished: &mut tokio::sync::watch::Receiver<bool>,
    shared: &super::Shared,
) -> Permit<'a> {
    if let Some(c) = gate.canary(canary_on()) {
        return Permit::Go(c);
    }
    let wait = gate_wait(cfg.connect_backoff, gate.ticket());
    match super::backoff_or_finish(wait, finished, shared).await {
        true => Permit::Retry,
        false => Permit::Quit,
    }
}

/// `NZBFAST_DIAL_CANARY=0` reverts to the pre-29-Aug-2026 behaviour -
/// every worker dials whenever its own ladder says so, however many of
/// them that is at once - for an A/B leg. On by default.
///
/// The spread has no knob and wants none: it can only ever SHORTEN a
/// ladder step (see [`spread_delay`]), so there is no behaviour to
/// revert to that is not already inside the ladder's own stated bounds,
/// and a second env read on this path would be a second thing to get
/// wrong.
pub(super) fn canary_on() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| !std::env::var("NZBFAST_DIAL_CANARY").is_ok_and(|v| v == "0"))
}

#[cfg(test)]
mod tests;
