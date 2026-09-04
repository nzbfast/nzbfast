//! TODO 313 item 7: a TEMPORARY SURGE DIAL on a stuck socket.
//!
//! The requirement, 28 Aug 2026: when a connection gets stuck waiting
//! on a response, then after some period one more connection is dialled
//! in addition to all the others - and another is freed when one comes
//! available, so the increase in the number of connections is only
//! temporary.
//!
//! **THE DETECTOR ALREADY EXISTS AND ONLY THE ACTOR IS NEW.** The
//! staleness question - "this article has been on the wire too long" -
//! is [`Shared::hedge_stale_bound`], `3 x` the trained article-time
//! EWMA clamped between the fan-out age floor and the old flat 8 s. It
//! is evaluated on every idle-picker walk and already published live in
//! `RaceLive::hedge_bound_ms`. This module SHARES that bound and grows
//! none of its own, which is the item's own instruction: two spellings
//! of one threshold is this repo's most repeated defect, and the
//! spelling that would drift here is the one nobody can see from the
//! dashboard.
//!
//! What is new is who acts. Today a stale in-flight article is hedged
//! onto an IDLE connection (`Shared::pick_dup`). This is the arm for
//! when there is NO idle connection to hedge onto - which is precisely
//! the case existing hedging cannot reach by construction, because with
//! every socket busy or stuck no idle picker ever walks.
//!
//! # What a surge is worth, and why it is SMALL
//!
//! Measured in `research/SECOND-JOB-OVERLAP-2026-08.md` §9b (120
//! articles, 25% of them behind 2000 ms of silence, 2 MB/s a socket):
//!
//! | fleet | wall | vs 8 | share of the recoverable loss |
//! |---|---|---|---|
//! | 8 (baseline) | 10.78 s | - | - |
//! | **10 (+2)** | **9.02 s** | **-16%** | **23%** |
//! | 12 (+4) | 8.90 s | -17% | 25% |
//! | 16 (+8) | 7.43 s | -31% | 44% |
//! | 24 (+16) | 5.85 s | -46% | 65% |
//! | *healthy 8, for reference* | *3.20 s* | - | *100%* |
//!
//! The first TWO extra sockets recover 23% of the recoverable loss for
//! 25% more sockets; going all the way to 24 recovers 65% for 200%
//! more. **Steeply diminishing, so a small surge is the efficient point
//! and a large one is waste** - which is why [`SURGE_MAX_DEFAULT`] is
//! two and the setting is clamped at [`SURGE_MAX_CLAMP`]. A cold dial
//! (~400 ms of greet delay) costs a healthy 8-socket fleet 13% and does
//! NOT change what the extra socket is worth once it is up: 8 -> 10 is
//! -16% with the dial cost and -16% without (§9c). Item 8's standing
//! warm reserve (`crate::warmreserve`) is the answer to that level
//! shift, not a precondition for the mechanism.
//!
//! # The four constraints, and where each one is met here
//!
//! 1. **The line cap must SEE the surge** (§9d.3). It goes THROUGH
//!    `ConnTarget::set` - [`Shared::surge_apply`] in `pool/linecap.rs`,
//!    which is the SAME per-server apply the §208/§277 governor uses,
//!    with the loan added into its `want`. A raise outside `ConnTarget`
//!    would be invisible to the shed arms, which would then fight it or
//!    mis-read the fleet.
//! 2. **Provider caps** (§9d.1). `ConnTarget::set` above the SPAWNED
//!    fleet wakes nothing, and the spawned count IS
//!    `conntune::line_cap_spawn_slots`'s `min(headroom_share,
//!    uncapped)` with a measured knee already applied. The surge is
//!    clamped to that same per-server ceiling
//!    (`LineCap::targets[si].1`), so both bounds are inherited rather
//!    than restated.
//! 3. **Metered accounts** (§9d.2). A surge is a dup dispatch by
//!    another name, so it asks `Shared::speculative_blocked` - the same
//!    question every other speculative dup picker asks. The 27 Aug 2026
//!    fix (memory `nzbfast-block-account-economics`) is the precedent,
//!    and its defect - a Block account racing for duplicate BODIES - is
//!    exactly what an unguarded surge reintroduces.
//! 4. **Dial cost** (§9c). Priced above; the mechanism pays either way.
//!
//! # Temporary means temporary, on the failure path too
//!
//! Three separate returns, because "the article lands" is only one of
//! the ways a stall ends and it is not the one that matters:
//!
//! * **The stall clears** - no article on that server is stale any
//!   more, whether it landed, requeued or was failed. This is the
//!   ordinary return, and the one the requirement above describes.
//! * **[`SURGE_HOLD_BOUNDS`] x the bound it was taken at**, as an
//!   absolute deadline stamped when the loan is taken. A stuck article
//!   that NEVER arrives - a mute peer inside a long read timeout,
//!   redispatched and stuck again - would otherwise leave the fleet
//!   permanently wide, and a permanently wide fleet is not a surge. The
//!   deadline is stamped once per EPISODE and never extended by a
//!   second loan, so the ceiling holds over the whole episode rather
//!   than per socket.
//!   **And a deadline expiry stands that server down for as long
//!   again** ([`SURGE_COOL_BOUNDS`]), which the failure-case test found
//!   rather than this design: the stall is still on when the deadline
//!   passes, so without a cooldown the very next decision re-took the
//!   loan and the fleet was permanently wide with the ledger churning
//!   an episode a second underneath it.
//! * **[`Drop for Shared`]**, which closes the books whatever happened
//!   inside the run. Under `live_tune` the `ConnTarget` lives on the
//!   daemon hub and OUTLIVES the job (`streamhub::job_targets`), so a
//!   loan left outstanding at the end of a run would be inherited by
//!   the next one with nothing on the record to explain it.
//!
//! # What it deliberately does NOT do
//!
//! **No stand-down on line saturation**, unlike every speculative dup
//! picker. That is not an oversight and the asymmetry is the point: a
//! dup fetches a SECOND copy of bytes already on the wire, so on a full
//! line it displaces payload, while a surge socket takes QUEUED work
//! and displaces nothing. The regime this exists for is dead air, where
//! the line is by construction not full - §9b's own 8-socket baseline
//! moves 2.0x for 4x the sockets where every healthy shape moves
//! ~3.7-4x. A saturation gate here would switch the mechanism off in
//! exactly its own regime, which is the failure the queue-spill lane
//! spent four hours on (`research/NOTE-2026-09-02-QSPILL-E2E-RED-
//! DIAGNOSIS.md`).
//!
//! **No second detector.** Nothing here reads a refusal count, an
//! achieved rate or a per-server carry. `pool/steer.rs`'s header
//! already forbids refusal-derived state, and
//! `nzbfast-linecap-achieved-rate-is-not-a-line` forbids the other.
//! There is one input and it is the shared bound.

use super::*;

/// Extra sockets a surge may hold across the whole fleet when the
/// setting says only "on". TWO, and §9b is the whole argument: the
/// first two recover 23% of the recoverable loss for 25% more sockets,
/// where sixteen recover 65% for 200% more.
pub const SURGE_MAX_DEFAULT: usize = 2;

/// The most a hand-edited `surge_conns` may ask for. Four, one rung
/// past the measured efficient point: §9b's `+4` row buys 2% more of
/// the recoverable loss than `+2` does, so everything above this is
/// paying sockets for nothing, and a number a user could type past it
/// would be a promise the measurement does not support.
pub const SURGE_MAX_CLAMP: usize = 4;

/// At most one surge DECISION this often, fleet-wide.
///
/// The trigger is per-read: with every socket of a wide fleet stuck at
/// once, every one of them fires its timer inside the same instant.
/// Without this they would dial the whole allowance in one breath and
/// the "small surge" the measurement asks for would be whatever the
/// fleet width happened to be. A quarter second reaches
/// [`SURGE_MAX_DEFAULT`] in half a second - fast against the seconds of
/// dead air it answers - and cannot overshoot it.
pub(super) const SURGE_TICK_MS: u64 = 250;

/// How many staleness bounds a loan may be held for before it is given
/// back regardless. Four: a stall that is still a stall after four
/// article-time-derived bounds is not the transient the surge is for,
/// and the article's own read budget has expired inside that window on
/// every shipped configuration.
pub(super) const SURGE_HOLD_BOUNDS: u32 = 4;

/// Floor and ceiling on the derived hold, so a wildly-trained EWMA
/// cannot make the loan either instant or effectively permanent. The
/// ceiling is deliberately below the flat 30 s `read_timeout` default:
/// a loan must not outlive the read that justified it.
pub(super) const SURGE_HOLD_MIN: Duration = Duration::from_secs(2);
pub(super) const SURGE_HOLD_MAX: Duration = Duration::from_secs(20);

/// **A DEADLINE EXPIRY STANDS THAT SERVER DOWN FOR AS LONG AGAIN, AND
/// WITHOUT THIS THE DEADLINE BUYS NOTHING AT ALL.**
///
/// Found by the failure-case test rather than reasoned out, which is
/// why it is written down here at length. A loan returned because its
/// deadline passed leaves an article that is STILL stale on a fleet
/// that still has nothing idle - so the very next decision re-took it,
/// and the ledger churned an episode a second while the fleet sat
/// permanently wide. "Temporary" has to mean the sockets come off, not
/// that the bookkeeping resets.
///
/// One hold, so a server whose stall never ends spends at most half its
/// time surged, and the arithmetic is the same number in both
/// directions rather than a second constant to keep in step.
///
/// Only a DEADLINE expiry cools. A loan given back because the stall
/// cleared is the mechanism working, and making that pay a penalty
/// would punish exactly the case it is for - the next stall on that
/// server is a new question and gets an honest answer.
pub(super) const SURGE_COOL_BOUNDS: u32 = SURGE_HOLD_BOUNDS;

/// The surge's whole state, one per pool run.
///
/// Per-server counts rather than a fleet number, because the loan is
/// applied to a per-server `ConnTarget` and given back to the same one;
/// `out` is their sum so the fleet ceiling is one relaxed load and not
/// a walk on a path that runs per read.
pub(super) struct Surge {
    /// Fleet-wide ceiling on sockets on loan. 0 = OFF, which is every
    /// install today (`PoolConfig::surge_max` defaults to 0 and
    /// `shipped()` does not set it).
    pub(super) max: usize,
    /// Sockets currently on loan to each server.
    lent: Vec<AtomicUsize>,
    /// Run-ms by which this server's whole episode must be back
    /// (0 = nothing out). Stamped when `lent` goes 0 -> 1 and NEVER
    /// extended by a later loan - see the module doc.
    due: Vec<AtomicU64>,
    /// Run-ms before which this server may not surge again, after an
    /// episode was ended by its DEADLINE rather than by the stall
    /// clearing (0 = free). See [`SURGE_COOL_BOUNDS`].
    cool: Vec<AtomicU64>,
    /// Sum of `lent`.
    out: AtomicUsize,
    /// Run-ms of the last decision - the fleet-wide [`SURGE_TICK_MS`]
    /// rate limit, CAS'd so exactly one caller an interval gets past it.
    last: AtomicU64,
    /// Tallies for the `[pool]` line: sockets dialled and episodes
    /// returned over the run.
    dials: AtomicU64,
    episodes: AtomicU64,
}

impl Surge {
    /// MAX-folded across the fleet, like the fleet cap's own seed
    /// (`linecap::seed_cap`): it is a WHOLE-FLEET socket allowance in
    /// the same currency as the cap, so one server asking for it is the
    /// fleet asking for it. Clamped here as well as at the settings
    /// read, so a `PoolConfig` built by hand cannot widen it either.
    pub(super) fn new(servers: &[(ServerConfig, PoolConfig)]) -> Self {
        let n = servers.len();
        Surge {
            max: servers
                .iter()
                .map(|(_, c)| c.surge_max)
                .max()
                .unwrap_or(0)
                .min(SURGE_MAX_CLAMP),
            lent: (0..n).map(|_| AtomicUsize::new(0)).collect(),
            due: (0..n).map(|_| AtomicU64::new(0)).collect(),
            cool: (0..n).map(|_| AtomicU64::new(0)).collect(),
            out: AtomicUsize::new(0),
            last: AtomicU64::new(0),
            dials: AtomicU64::new(0),
            episodes: AtomicU64::new(0),
        }
    }

    /// Sockets on loan to one server. Read by the fleet cap's own apply
    /// loop, which is what keeps the two writers to a `ConnTarget`
    /// agreeing about the number in force.
    pub(super) fn lent_on(&self, si: usize) -> usize {
        self.lent.get(si).map_or(0, |n| n.load(Ordering::Relaxed))
    }
}

impl Shared {
    /// Is the surge dial switched on for this run?
    ///
    /// The one predicate `session::read_one` asks before arming its
    /// timer, so a shipped install - where this is false - never even
    /// creates the sleep. Deliberately a method rather than a field
    /// read at the call site: the answer is `max > 0` today and the
    /// number of places that would have to learn a second term is one.
    pub(super) fn surge_armed(&self) -> bool {
        self.surge.max > 0
    }

    /// One tick of the surge: give back what is due, then consider
    /// taking one more socket.
    ///
    /// Called from two places, and it takes both to cover the regime.
    /// `note_srv_bytes` (where `line_cap_tick` already rides) is the
    /// recovery half - it fires the moment anything delivers again,
    /// which is when a loan is most likely due back. The per-read timer
    /// in `session::read_one` is the other half and it is the one that
    /// matters: in the regime this exists for NOTHING is delivering, so
    /// a tick riding only on arriving bytes would never fire at all.
    ///
    /// One relaxed load when the mechanism is off, which is every
    /// install today.
    pub(super) fn surge_tick(&self, now: u64) {
        if self.surge.max == 0 {
            return;
        }
        self.surge_return_due(now);
        self.surge_consider(now);
    }

    /// Give back every loan whose episode is over: the run is ending,
    /// the deadline passed, or nothing on that server is stale any more.
    ///
    /// The three are one loop deliberately. They are three ways of
    /// saying the same thing - the reason this socket was borrowed has
    /// gone - and splitting them would be three places for the release
    /// to be forgotten.
    fn surge_return_due(&self, now: u64) {
        if self.surge.out.load(Ordering::Relaxed) == 0 {
            return;
        }
        // Run-level: a draining or aborted run has no stall left to
        // answer, and its workers are on their way out.
        let over = self.draining.load(Ordering::Acquire)
            || self.aborted.load(Ordering::Acquire)
            || self.pending.load(Ordering::Acquire) == 0;
        // Taken ONCE for the whole walk: the map lock is what the
        // completion paths contend on, and asking per server would take
        // it once per server on a path that runs per read.
        let stale = match over {
            true => 0u32,
            false => self.surge_stale_mask(),
        };
        for si in 0..self.surge.lent.len() {
            if self.surge.lent[si].load(Ordering::Relaxed) == 0 {
                continue;
            }
            let expired = {
                let due = self.surge.due[si].load(Ordering::Relaxed);
                due != 0 && now >= due
            };
            let still_stale = !over && stale & server_bit(si) != 0;
            if !over && !expired && still_stale {
                continue;
            }
            // Only a deadline that expired with the stall STILL ON
            // cools this server. A loan whose window happens to run out
            // on the same tick the article lands is the mechanism
            // working, and cooling it would both punish the good case
            // and make the log line below say something untrue.
            self.surge_return(si, now, expired && still_stale);
        }
    }

    /// Hand a server's whole loan back and re-apply its target.
    ///
    /// The episode is returned WHOLE rather than a socket at a time.
    /// Loans on one server are fungible - nothing records which socket
    /// answered which article - and the deadline is one number for the
    /// episode, so a partial return would leave a loan outstanding
    /// under a deadline that had already passed.
    fn surge_return(&self, si: usize, now: u64, expired: bool) {
        let had = self.surge.lent[si].swap(0, Ordering::Relaxed);
        if had == 0 {
            return;
        }
        self.surge.out.fetch_sub(had, Ordering::Relaxed);
        self.surge.due[si].store(0, Ordering::Relaxed);
        self.surge.episodes.fetch_add(1, Ordering::Relaxed);
        // An episode the DEADLINE ended leaves the stall in place, so
        // without this the next decision re-takes the loan on the spot
        // and the deadline buys nothing - see [`SURGE_COOL_BOUNDS`].
        if expired {
            let cool = (self.hedge_stale_bound() * SURGE_COOL_BOUNDS)
                .clamp(SURGE_HOLD_MIN, SURGE_HOLD_MAX);
            self.surge.cool[si].store(now + cool.as_millis() as u64, Ordering::Relaxed);
        }
        let applied = self.surge_apply(si);
        info!(
            target: "surge",
            "surge: {} gives back {had} socket{} at {now} ms ({}){}",
            self.surge_host(si),
            match had {
                1 => "",
                _ => "s",
            },
            match expired {
                true => "held its whole window with the stall still on",
                false => "the stall cleared",
            },
            match applied {
                Some(n) => format!(" (target {n})"),
                None => String::new(),
            },
        );
    }

    /// Take one more socket, if every gate says so.
    ///
    /// Ordered cheapest-first, and the run-level gates come before the
    /// map lock on purpose: this runs per stuck read.
    fn surge_consider(&self, now: u64) {
        if self.surge.out.load(Ordering::Relaxed) >= self.surge.max
            || self.draining.load(Ordering::Acquire)
            || self.aborted.load(Ordering::Acquire)
            || self.pending.load(Ordering::Acquire) == 0
        {
            return;
        }
        // THE GATE THIS MECHANISM IS DEFINED BY: an idle connection is
        // one the shipped hedge can already put on the stale article,
        // and doing it there costs no dial at all. This arm exists only
        // for the case that picker cannot reach.
        if self.idle_conns.load(Ordering::Acquire) > 0 {
            return;
        }
        // Fleet-wide rate limit, CAS'd exactly as `line_cap_tick`'s is:
        // one caller an interval gets past, so the two atomics below
        // are read and written by one thread at a time.
        let last = self.surge.last.load(Ordering::Relaxed);
        if now.saturating_sub(last) < SURGE_TICK_MS
            || self
                .surge
                .last
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        let stale = self.surge_stale_mask();
        if stale == 0 {
            return;
        }
        let Some(si) = (0..self.surge.lent.len()).find(|&si| {
            stale & server_bit(si) != 0
                // Standing down after a deadline expiry, so the fleet
                // actually narrows rather than the ledger churning.
                && now >= self.surge.cool[si].load(Ordering::Relaxed)
                // §9d.2: the same question every other speculative dup
                // picker asks. A metered account is excluded whatever
                // its level, and a fill server is excluded whatever its
                // metering - its sockets exist to answer gaps the
                // primaries refused, not to carry the primary's stall.
                && !self.speculative_blocked(server_bit(si), self.levels[si])
        }) else {
            return;
        };
        // Commit, then apply. `surge_apply` answers None when there was
        // nothing to wake - the target is already at its spawn ceiling,
        // or somebody else is driving it - and the loan is rolled back,
        // because a loan that moved no target is a socket we never got
        // and would sit against the fleet allowance for nothing.
        let first = self.surge.lent[si].fetch_add(1, Ordering::Relaxed) == 0;
        self.surge.out.fetch_add(1, Ordering::Relaxed);
        let Some(target) = self.surge_apply(si) else {
            self.surge.lent[si].fetch_sub(1, Ordering::Relaxed);
            self.surge.out.fetch_sub(1, Ordering::Relaxed);
            return;
        };
        if first {
            // Stamped ONCE per episode, from the bound in force now, so
            // a second loan cannot extend the first one's deadline and
            // a bound that grows mid-episode cannot either.
            let hold = (self.hedge_stale_bound() * SURGE_HOLD_BOUNDS)
                .clamp(SURGE_HOLD_MIN, SURGE_HOLD_MAX);
            self.surge.due[si].store(now + hold.as_millis() as u64, Ordering::Relaxed);
        }
        self.surge.dials.fetch_add(1, Ordering::Relaxed);
        info!(
            target: "surge",
            "surge: {} +1 socket (target {target}, {} of {} out) - an article has been on \
             the wire past {} ms with no idle connection to race it",
            self.surge_host(si),
            self.surge.out.load(Ordering::Relaxed),
            self.surge.max,
            self.hedge_stale_bound().as_millis(),
        );
    }

    /// Servers holding an in-flight article that has been on the wire
    /// past [`Shared::hedge_stale_bound`], as a server bitmask.
    ///
    /// The SHARED bound and not one of this module's own, which is the
    /// item's instruction. `RaceLive::hedge_bound_ms` publishes exactly
    /// this number, so a reader diagnosing a surge and a reader
    /// diagnosing a hedge are looking at the same threshold.
    ///
    /// Verdict PROBES are excluded: a probe is one status line asking
    /// whether an already-refused article exists anywhere, so a slow
    /// answer to it is a refusal taking its time and not a stuck
    /// download. Dups are excluded because they carry no entry of their
    /// own - the original's entry is what ages.
    fn surge_stale_mask(&self) -> u32 {
        let bound = self.hedge_stale_bound();
        let mut mask = 0u32;
        for inf in self.inflight.lock_ok().values() {
            if inf.dispatched.elapsed() >= bound {
                mask |= server_bit(inf.server);
            }
        }
        mask
    }

    /// This server's host for a log line, or `sN` where there is no
    /// `LiveStats` to ask (a CLI run, most rigs).
    fn surge_host(&self, si: usize) -> String {
        self.live
            .as_ref()
            .and_then(|l| l.servers.get(si))
            .map_or_else(|| format!("s{si}"), |s| s.host.clone())
    }

    /// The `[pool]` line's fragment. Empty unless a surge actually
    /// happened, so every run that never entered the regime - which is
    /// every run on every install today - keeps its exact log shape.
    pub(super) fn surge_summary(&self) -> String {
        match self.surge.dials.load(Ordering::Relaxed) {
            0 => String::new(),
            n => format!(
                " · surge {n} dial{} in {} episode{}",
                match n {
                    1 => "",
                    _ => "s",
                },
                self.surge.episodes.load(Ordering::Relaxed),
                match self.surge.episodes.load(Ordering::Relaxed) {
                    1 => "",
                    _ => "s",
                },
            ),
        }
    }

    /// Give every outstanding loan back, without a target apply.
    ///
    /// [`Drop for Shared`] only, where the pool is going away and the
    /// `ConnTarget` behind it may not be: under `live_tune` the target
    /// lives on the daemon hub and the next job inherits whatever is on
    /// it. `surge_apply` is what puts the number back, so this exists
    /// to make sure the LEDGER agrees with it on the way out - a
    /// counter left non-zero here would make `surge_summary` lie about
    /// how many episodes closed.
    pub(super) fn surge_close_books(&self) {
        let sg = &self.surge;
        for (si, lent) in sg.lent.iter().enumerate() {
            sg.cool[si].store(0, Ordering::Relaxed);
            if lent.swap(0, Ordering::Relaxed) > 0 {
                sg.due[si].store(0, Ordering::Relaxed);
                sg.episodes.fetch_add(1, Ordering::Relaxed);
            }
        }
        sg.out.store(0, Ordering::Relaxed);
    }
}

/// The idle-connection gauge's RAII half: a worker holding a live
/// session with an EMPTY pipeline, sitting in `session::idle_turn`.
///
/// A guard rather than a pair of bumps because `idle_turn` has three
/// exits and one of them retires the worker outright; a decrement
/// written at the call site would be missed on exactly the path that
/// leaves the gauge permanently over-counted, which reads to the surge
/// as "there is always an idle connection" and switches the mechanism
/// off for the rest of the run.
///
/// Release ordering on the way in and Acquire on the read, so a surge
/// decision taken after a worker went idle sees it.
pub(super) struct IdleConn<'a>(&'a Shared);

impl<'a> IdleConn<'a> {
    pub(super) fn hold(shared: &'a Shared) -> Self {
        shared.idle_conns.fetch_add(1, Ordering::Release);
        IdleConn(shared)
    }
}

impl Drop for IdleConn<'_> {
    fn drop(&mut self) {
        self.0.idle_conns.fetch_sub(1, Ordering::Release);
    }
}

// The surge's own tests - a child of THIS module, so `Surge`'s private
// counters and the ledger arithmetic stay reachable without widening
// anything for a test's benefit.
#[cfg(test)]
mod tests;
