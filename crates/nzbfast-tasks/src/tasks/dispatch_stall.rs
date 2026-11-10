//! TODO 358 item 3 (Weaver parity): the dispatch-stall watchdog.
//!
//! Weaver 0.16.4 resets dispatch after two minutes of queued work with
//! no active connection, and counts the rest missing ten minutes after
//! that. Before this module nzbfast had the second half and not the
//! first: the engine's deadlock watchdog (`get/workers.rs`,
//! `spawn_deadlock_watchdog`) aborts a run that has decoded nothing and
//! resolved nothing for `NZBFAST_STALL_ABORT_SECS` (180 s) and books
//! what is left as missing, so PAR2 repairs it or the job fails with the
//! usual verdict. Nothing ever tried to get a stopped run MOVING again
//! first. [`StallTracker`] only reports the episode, by design.
//!
//! # What "reset dispatch" is here
//!
//! The job's run is wound down and the row goes back into the queue
//! WHERE IT STOOD, through the same door a pause uses
//! (`Daemon::reset_dispatch_matching` - `suspend_matching` without the
//! Force exemption - then the post-processing tail's suspended arm): no
//! history row, no failure, no demotion, no change of
//! position or of `deferred`. The runner picks it up again at once, and
//! the new run is a NEW FLEET - every session dialled fresh, every
//! in-flight article back in the queue - over the article journal, so
//! nothing that landed is fetched twice.
//!
//! Why this and not something inside the pool:
//!
//! * It is the recovery primitive the daemon already has, with five
//!   callers (the pause button, the *arr facade, the scheduler, the
//!   slow-disk hold, the idle release) and the suspend suite behind it.
//!   Custody is the pool's own: `abort()` lets every worker leave
//!   through its normal exit, `pending` is never written from outside,
//!   the steer inbox and the handoff seam die with the `Shared` that
//!   owns them, and the journal keeps every placement. A pool-level
//!   "kick" that tore sessions down under a live run would have to
//!   re-derive every one of those invariants in a 35,000-line module.
//! * A stalled pool is the case where a drain buys nothing: a session in
//!   dead air has no body that will land (see `DEFER_DRAIN_GRACE` in
//!   `stall.rs`, which measured it). So the wind-down is the hard one,
//!   and what is in flight is re-fetched - by the reset's own predicate
//!   nothing in flight has moved a byte in the whole window.
//!
//! # And the ten minutes
//!
//! THE SECOND STAGE IS THE ENGINE'S DEADLOCK WATCHDOG, unchanged. The
//! reset is spent once per record generation (`Job::dispatch_reset_gen`),
//! so if the fresh run stalls the same way, nothing here touches it again
//! and the run's own deadlock watchdog aborts the pool after its window
//! and books the remainder missing through the normal tail: settle,
//! repair, or Failed with the verdict that names the stall. That is
//! 180 s, not Weaver's 600, deliberately: the window is a shipped
//! contract with its own history (the 190 GB run that sat frozen for
//! three hours, and the 31 Jul fix that stopped it firing on a dead
//! post's refusal ladder - both told at `spawn_deadlock_watchdog`), the
//! CLI runs it too, and moving it to ten minutes would add seven minutes
//! to every genuine wedge for no case a longer wait is known to rescue. A second copy of the abort
//! here, at a different number, would be a second rule for one state.
//!
//! The reset therefore has to land INSIDE that window on the first run,
//! which is why [`RESET_AFTER`] is 120 s against the 180. A run with
//! `NZBFAST_STALL_ABORT_SECS` at or under the reset window is aborted by
//! the engine first and is never reset at all, which is exactly the
//! behaviour before this module and is what every existing stall-shaped
//! test that shortens that window relies on.
//!
//! # What counts as stalled
//!
//! NOT "no connections". `ServerLive::connected` counts sockets, and the
//! shape this watchdog exists for - a provider that accepted and then
//! went silent - holds its sockets open in dead air for the whole read
//! bound; a socket count would read that as healthy. Nor "no dispatch":
//! a pool whose read bound keeps cutting dead sessions re-sends the same
//! articles to the same mute frontend, which is dispatch and is not
//! progress. What is measured is everything that moves when a run is
//! ALIVE ([`Pulse`]): bytes, a 430, any verdict at all (`pending`), the
//! bare-430 confirming repeat (`deferred`, the engine watchdog's third
//! signal and for the same reason), a held-bytes park stepping past work
//! on purpose, and the decode channel pushing back. None of them moving,
//! with work still queued, for [`RESET_AFTER`], is the stall - and it is
//! exactly the engine watchdog's own freeze, read one layer up, so the
//! two can never disagree about whether a run is alive.
//!
//! # What never counts ([`Idle`])
//!
//! A legitimate idle restarts the clock rather than pausing it, so a
//! stall has to be one unbroken stretch of the real thing. Each arm names
//! the state it protects; [`idle_reason`] is the whole list:
//!
//! * offline, which outranks Force, and a paused queue - except for a
//!   Force job running through the pause by SAB semantics, whose stall is
//!   a real one (the pause is not what is holding it);
//! * a paused or suspended job - the job pause, the scheduler window,
//!   the slow-disk hold and the idle release all arrive as `suspended`;
//! * a job the slow-job watchdog is already demoting;
//! * a job past the network (`tail_phase`): verify, repair, unpack;
//! * a cross-job hand-over, while the predecessor drains (the
//!   successor's fleet is being handed over one connection at a time);
//! * a run already winding down (a graceful pause in progress);
//! * ANY provider in a named outage (`down_since`): unreachable, refused
//!   or at a connection cap. That is the pool's own bounce ladder and
//!   outage budget at work, a deliberate backoff with a terminal of its
//!   own (`FleetExhausted`), and a reset would only redial into a
//!   provider that is refusing - a capacity ghost lease in particular is
//!   made LONGER by redialling. Conservative on a mixed fleet too: one
//!   server in backoff beside one in dead air leaves the case to the
//!   engine watchdog, as before;
//! * nothing queued (`pending == 0`): the network is done.
//!
//! The line cap and a speed limit never reach here: both throttle a run,
//! neither stops it, so bytes keep moving. The disk-space and quota
//! guards hold a job at PICK time, so a held job is Queued, never
//! Downloading - and a reset job goes back through those same guards.

use super::*;
use std::time::Duration;

/// How long a run may sit with work queued and nothing moving before its
/// dispatch is reset: Weaver's two minutes, and inside the engine's
/// 180 s deadlock window by a full minute, which is the margin that keeps
/// the reset ahead of the abort across a watchdog tick (1-5 s) and the
/// engine's own poll (15 s at the shipped window).
/// `NZBFAST_DISPATCH_RESET_SECS` overrides it; 0 turns the reset off.
pub(crate) const RESET_AFTER: Duration = Duration::from_secs(120);

/// Everything that moves when a run is alive. Compared whole: any field
/// changing is liveness. See the module header for why each is here and
/// why a socket count and a dispatch count are not.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Pulse {
    /// Raw bytes the run has fetched, all servers.
    pub bytes: u64,
    /// "No such article" answers, all servers.
    pub missing: u64,
    /// Articles still owed a verdict (`QueueControl::pending`).
    pub pending: usize,
    /// Responses that advanced an article without resolving it.
    pub deferred: u64,
    /// Candidates a held-bytes park stepped past on purpose.
    pub parked: u64,
    /// Milliseconds workers spent blocked on a full decode channel.
    pub blocked_ms: u64,
}

/// A legitimate reason for a run to move nothing. See the module header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Idle {
    Offline,
    QueuePaused,
    JobPaused,
    Demoting,
    PastTheNetwork,
    HandOver,
    WindingDown,
    ProviderBackoff,
    NothingQueued,
}

/// The facts [`idle_reason`] judges, read off the daemon in one place
/// ([`read`]) so the judgement itself is a pure function a test can
/// drive through every arm.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Facts {
    pub offline: bool,
    pub queue_paused: bool,
    /// `Job::paused || Job::suspended`.
    pub job_paused: bool,
    pub demoting: bool,
    pub past_the_network: bool,
    pub hand_over: bool,
    pub winding_down: bool,
    /// Any server with a live `down_since` stamp.
    pub provider_backoff: bool,
    pub pending: usize,
}

/// The whole list of states that are never a stall, in one expression.
pub(crate) fn idle_reason(f: &Facts) -> Option<Idle> {
    if f.offline {
        Some(Idle::Offline)
    } else if f.queue_paused {
        Some(Idle::QueuePaused)
    } else if f.job_paused {
        Some(Idle::JobPaused)
    } else if f.demoting {
        Some(Idle::Demoting)
    } else if f.past_the_network {
        Some(Idle::PastTheNetwork)
    } else if f.hand_over {
        Some(Idle::HandOver)
    } else if f.winding_down {
        Some(Idle::WindingDown)
    } else if f.provider_backoff {
        Some(Idle::ProviderBackoff)
    } else if f.pending == 0 {
        Some(Idle::NothingQueued)
    } else {
        None
    }
}

/// The pure clock: how long the watched run has gone with no [`Pulse`]
/// movement and no [`Idle`] reason. Synthetic-clock testable, like
/// [`StallTracker`].
pub(crate) struct DispatchStall {
    /// `None` = the reset is switched off.
    after: Option<Duration>,
    job: Option<String>,
    pulse: Option<Pulse>,
    since: Instant,
    /// Latched once an episode has been reported, so a stall is acted on
    /// once and not every tick; cleared by anything that restarts the
    /// clock.
    spoken: bool,
}

impl DispatchStall {
    pub(crate) fn new(after: Option<Duration>) -> Self {
        Self {
            after,
            job: None,
            pulse: None,
            since: Instant::now(),
            spoken: false,
        }
    }

    /// [`RESET_AFTER`], or `NZBFAST_DISPATCH_RESET_SECS` (0 = off).
    pub(crate) fn from_env() -> Self {
        // env-default-gate: the default is RESET_AFTER, 120 s, the const at
        // the top of this file; `the_shipped_default_is_reset_after` pins it.
        let secs = std::env::var("NZBFAST_DISPATCH_RESET_SECS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(RESET_AFTER.as_secs());
        Self::new((secs > 0).then(|| Duration::from_secs(secs)))
    }

    /// One sample. `Some(frozen_secs)` exactly once per unbroken stall
    /// episode that reaches the threshold.
    pub(crate) fn observe(
        &mut self,
        now: Instant,
        job: Option<&str>,
        idle: Option<Idle>,
        pulse: Pulse,
    ) -> Option<u64> {
        let after = self.after?;
        let restart = |s: &mut Self| {
            s.pulse = Some(pulse);
            s.since = now;
            s.spoken = false;
        };
        let Some(id) = job else {
            self.job = None;
            restart(self);
            return None;
        };
        if self.job.as_deref() != Some(id) {
            self.job = Some(id.to_string());
            restart(self);
            return None;
        }
        if idle.is_some() || self.pulse != Some(pulse) {
            restart(self);
            return None;
        }
        let frozen = now.duration_since(self.since);
        if !self.spoken && frozen >= after {
            self.spoken = true;
            return Some(frozen.as_secs());
        }
        None
    }
}

/// One reading of the hub owner's run.
struct Reading {
    id: String,
    idle: Option<Idle>,
    pulse: Pulse,
    generation: (u32, u64),
    spent: bool,
}

/// Read the run that owns the hub. `None` while nothing is on the wire
/// (or its pool is not attached yet): there is nothing to judge.
fn read(d: &Daemon) -> Option<Reading> {
    d.started_at.lock_ok().as_ref()?;
    let id = d.active_stream.lock_ok().clone()?;
    let pool_live = d.hub.pool_live.lock_ok().clone()?;
    let qc = d.hub.queue_ctl.lock_ok().clone()?;
    // Daemon-wide facts first, each lock taken and dropped on its own.
    let hand_over = d.drain_dl.lock_ok().is_some();
    let past_the_network = d.tail_phase(&id).is_some();
    let (job_paused, forced, demoting, generation, spent) = {
        let q = d.queue.lock_ok();
        let j = q.iter().find(|j| {
            let g = j.lock_ok();
            g.nzo_id == id && g.state == JobState::Downloading && !g.tombstone
        })?;
        let g = j.lock_ok();
        let generation = Daemon::record_generation(&g);
        (
            g.paused || g.suspended,
            // `runs_through_queue_pause`'s rule (daemon_suspend.rs), read
            // here because that helper is the daemon crate's own: Force
            // with no pause of its own keeps downloading through a queue
            // pause, so a stall under one is a real stall, not the pause.
            g.priority >= 2 && !g.paused,
            g.demote,
            generation,
            g.dispatch_reset_gen == Some(generation),
        )
    };
    let mut pulse = Pulse {
        pending: qc.pending()?,
        deferred: qc.deferred().unwrap_or(0),
        parked: qc.park_deferrals().unwrap_or(0),
        ..Pulse::default()
    };
    let mut provider_backoff = false;
    for s in &pool_live.servers {
        pulse.bytes += s.bytes.load(Ordering::Relaxed);
        pulse.missing += s.articles_missing.load(Ordering::Relaxed);
        pulse.blocked_ms += s.blocked_ms.load(Ordering::Relaxed);
        provider_backoff |= s.down_since.load(Ordering::Relaxed) != 0;
    }
    let facts = Facts {
        offline: d.offline.load(Ordering::Relaxed),
        queue_paused: d.paused.load(Ordering::Relaxed) && !forced,
        job_paused,
        demoting,
        past_the_network,
        hand_over,
        winding_down: qc.is_draining(),
        provider_backoff,
        pending: pulse.pending,
    };
    Some(Reading {
        id,
        idle: idle_reason(&facts),
        pulse,
        generation,
        spent,
    })
}

/// One watchdog tick. Called from the slow-job watchdog's loop BEFORE its
/// auto-defer gate, so it runs whatever those settings say, like the
/// observation half beside it.
pub(crate) fn dispatch_stall_tick(d: &Arc<Daemon>, clock: &mut DispatchStall) {
    let r = read(d);
    let frozen = clock.observe(
        Instant::now(),
        r.as_ref().map(|r| r.id.as_str()),
        r.as_ref().and_then(|r| r.idle),
        r.as_ref().map(|r| r.pulse).unwrap_or_default(),
    );
    let (Some(frozen), Some(r)) = (frozen, r) else {
        return;
    };
    let window = get::deadlock_window_secs();
    if r.spent {
        info!(
            target: "stall",
            "{}: stalled again for {frozen}s after its dispatch was reset - not resetting \
             twice; the deadlock watchdog books the {} article(s) still owed as missing \
             once the run has been frozen for {window}s",
            r.id, r.pulse.pending
        );
        return;
    }
    // Claim the reset under the job lock, re-reading everything the
    // reading above was taken from: a pause, a delete or a retry landing
    // between the two must win.
    let claimed = d.queue.lock_ok().iter().any(|j| {
        let mut g = j.lock_ok();
        if g.nzo_id != r.id
            || g.state != JobState::Downloading
            || g.tombstone
            || g.paused
            || g.suspended
            || g.demote
            || Daemon::record_generation(&g) != r.generation
            || g.dispatch_reset_gen == Some(r.generation)
        {
            return false;
        }
        g.dispatch_reset_gen = Some(r.generation);
        true
    });
    if !claimed {
        return;
    }
    warn!(
        target: "stall",
        "{}: dispatch stalled - nothing has arrived and no article has been resolved for \
         {frozen}s with {} article(s) still queued, and no provider is in a backoff. \
         Resetting dispatch: the run is wound down and the job goes back in the queue \
         where it stood, so the next pass dials a fresh fleet and resumes from the journal. \
         If that pass stalls too, the deadlock watchdog books the rest missing after {window}s.",
        r.id, r.pulse.pending
    );
    let id = r.id;
    // Not `suspend_matching`: that spares a Force job, and a reset must
    // reach one - see `reset_dispatch_matching`.
    d.reset_dispatch_matching(|g| g.nzo_id == id);
}

#[cfg(test)]
#[path = "dispatch_stall_tests.rs"]
mod dispatch_stall_tests;
