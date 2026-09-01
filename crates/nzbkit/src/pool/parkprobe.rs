//! What a worker does while a server is NOT granting sessions: the
//! two give-up questions and the park-and-probe tail that asks them.
//!
//! Split out of `pool/session.rs` whole - the code is verbatim, only
//! its module moved. That file sat one line under its 3,000-line
//! ceiling and TWO lanes grew it the same evening (the §315 recheck
//! hold in `handle_missing`, and the stated-cap dial gate next door in
//! `dialgate`), which is the shape the size gate's own notes keep
//! recording: neither change is large, the merge of them crosses, and
//! main is red for whoever merges second. This is the seam that buys
//! the file real margin instead of one line.
//!
//! It is a coherent subject rather than a convenient cut. All three
//! items answer one question - this server will not give us a session
//! right now, so is that transient, and who waits how long to find out
//! - and the two predicates exist precisely so the pre-dial gate and
//! the park ladder cannot drift on it.
//!
//! `dialgate` is the same situation from the other side: this module
//! decides WHO waits and for how long once a server has stopped
//! granting, that one paces the dials themselves so the waiting fleet
//! does not arrive back in a herd.
//!
//! A child module of `pool`, so `Shared`, `DialStep`, `CapEpisode` and
//! the rest resolve through `use super::*` exactly as they did when
//! all of this was in `session`.

use super::*;

/// Has this server used up [`PoolConfig::outage_budget`]?
///
/// One place, so the pre-dial gate and the park ladder cannot drift.
/// `None` (never give up) is a supported configuration and answers false
/// forever - the queue row says which provider the job is waiting on for
/// as long as it waits.
pub(super) fn outage_budget_blown(cfg: &PoolConfig, shared: &Arc<Shared>, idx: usize) -> bool {
    let Some(budget) = cfg.outage_budget else {
        return false;
    };
    shared.auth[idx].down_ms() >= budget.as_millis() as u64
}

/// Has the elected prober's CONSECUTIVE bounce ladder run out?
///
/// False forever when `outage_budget` is off: the two give-up paths
/// answer to one control, or the setting lies (a user who chose "wait
/// however long it takes" would still get a failed job at ~10 minutes
/// from a ladder they cannot see).
pub(super) fn ladder_exhausted(cfg: &PoolConfig, bounces: u32) -> bool {
    cfg.outage_budget.is_some() && bounces >= cfg.cap_probe_bounces
}

/// The park-and-probe tail shared by the CAPACITY refusal and the hard
/// connect outage (issue #16 machinery, generalised): the caller has
/// decided this server is not granting sessions right now for a reason
/// that is plausibly transient. Most workers park on the episode watch
/// (claim_yield keeps someone behind); ONE elected prober rides the
/// capped bounce ladder (~8 s cadence) up to `CAP_PROBE_BOUNCES`
/// (~10 min). Any successful connect anywhere sends `Reopened` and the
/// parked fleet rejoins at full width; the horizon sends `Dead` so the
/// parked workers exit and `seal_run` can reach a truthful terminal.
/// Both the park loop and the ladder select on `finished`, so a dead
/// server never holds a FINISHED run open (§34/A15).
pub(super) async fn park_or_probe(
    cfg: &PoolConfig,
    ctx: ServerCtx,
    shared: &Arc<Shared>,
    finished: &mut tokio::sync::watch::Receiver<bool>,
    bounces: &mut u32,
    connect_failures: &mut u32,
) -> DialStep {
    // Subscribe BEFORE claiming the yield: an event published between
    // the claim and the subscription must still wake this parker.
    let mut sub = shared.auth[ctx.idx].episode.subscribe();
    let entry_gen = sub.borrow().1;
    // F-22: under a live target only ADMITTED workers can dial, so the
    // election counts those - a parked ordinal counted as alive once
    // let the sole admitted worker yield to a fleet that could not probe.
    let electorate = if cfg.live_target.is_some() {
        &shared.admitted[ctx.idx]
    } else {
        &shared.alive[ctx.idx]
    };
    if shared.auth[ctx.idx].claim_yield(electorate) {
        // Park, don't die (issue #16): a ghost-session
        // lease clears in minutes, and a fleet that
        // exited leaves the reopened server to one
        // prober crawling the rest of the job alone.
        // Wait for the prober's verdict; Reopened =
        // rejoin the dial loop, Dead (or the run
        // ending) = the old exit.
        loop {
            // Read the episode and DROP the watch guard before anything
            // awaits: a `watch::Ref` is not `Send`, so holding one over
            // the stagger below makes the worker future un-spawnable.
            let rejoin = match *sub.borrow_and_update() {
                // Only a Reopened published AFTER this park counts:
                // the watch never returns to Idle, so the previous
                // episode's Reopened is still sitting in it, and
                // consuming that here would skip the prober election
                // for every later episode - a permanent outage then
                // never reaches Dead and the run never terminates.
                (CapEpisode::Reopened, g) if g > entry_gen => true,
                // A leftover Dead is as final as a fresh one: the
                // prober exhausted its horizon for this server.
                (CapEpisode::Dead, _) => return DialStep::Quit,
                (CapEpisode::Idle | CapEpisode::Probing | CapEpisode::Reopened, _) => false,
            };
            if rejoin {
                shared.auth[ctx.idx].yielded.fetch_sub(1, Ordering::SeqCst);
                // A fresh ladder for the rejoin: the pre-park failures
                // were the episode's, not this worker's, and carrying
                // them over would bounce a rejoining worker straight
                // back into the park on its first unlucky dial.
                *connect_failures = 0;
                // One `watch` send wakes EVERY parker at once, and they
                // all used to dial on the same tick. Stagger them, from
                // zero, so the first back in is not delayed.
                let wait = dialgate::rejoin_stagger(
                    cfg.connect_backoff,
                    shared.auth[ctx.idx].dial.ticket(),
                );
                if !wait.is_zero() && !backoff_or_finish(wait, finished, shared).await {
                    return DialStep::Quit;
                }
                return DialStep::Retry;
            }
            // `drain()` deliberately does not send `finished`, and the
            // prober's own drain exits quit WITHOUT publishing an episode
            // event - so a park that only awaited the watch and `finished`
            // outlived a graceful pause forever: workers_live never reached
            // zero and join_fleet never returned. Poll draining on the same
            // 250 ms slice as run_over/backoff_or_finish.
            if shared.draining.load(Ordering::Acquire) {
                return DialStep::Quit;
            }
            tokio::select! {
                r = sub.changed() => {
                    if r.is_err() {
                        return DialStep::Quit;
                    }
                }
                _ = finished.wait_for(|f| *f) => return DialStep::Quit,
                _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => {}
            }
        }
    }
    // Single-prober election: claim_yield's alive-count
    // race can leave SEVERAL workers thinking they are
    // the last one - only the holder of this flag rides
    // the long ladder, the rest stand down (they missed
    // the yield window, so they exit as every extra
    // claimant did before parking existed).
    if shared.auth[ctx.idx].cap_prober.swap(true, Ordering::AcqRel) && *bounces == 0 {
        return DialStep::Quit;
    }
    shared.auth[ctx.idx].publish_episode(CapEpisode::Probing);
    // Issue #16 (the restart stall): this LAST prober
    // used to walk the ordinary connect ladder to
    // permanent death - five capacity bounces in
    // ~15-30 s and the server was never dialed again,
    // while a provider that still counts a dead
    // process's sessions holds its cap for MINUTES.
    // A capacity refusal is a known-transient (it
    // clears when the ghosts are reaped), so the
    // prober paces on its own bounce ladder instead
    // and gives the lease a realistic horizon to
    // expire; any successful connect resets both
    // counters. A server capped for good costs one
    // paced dial every ~32 s until the horizon.
    *bounces = bounces.saturating_add(1);
    // The prober is the one worker still dialling, so the budget has to
    // be able to end ITS ladder too - otherwise a server that reopens
    // just often enough to keep resetting `bounces` is probed forever.
    if outage_budget_blown(cfg, shared, ctx.idx) {
        shared.auth[ctx.idx].publish_episode(CapEpisode::Dead);
        return DialStep::Quit;
    }
    // Each paced bounce is DELIBERATE progress along the recovery
    // ladder, and it must say so on the liveness counter the stall
    // watchdog reads: during a from-the-start outage nothing decodes
    // and nothing resolves, so without this tick the watchdog's 180 s
    // default aborted the job squarely inside the ladder's promised
    // ~10 min horizon (a provider recovering at 4 min was reported as
    // a local pool wedge). A prober genuinely frozen mid-dial stops
    // bouncing, stops ticking, and still trips the watchdog.
    shared.deferred.fetch_add(1, Ordering::Relaxed);
    // `outage_budget: None` means the user asked to WAIT, however long
    // it takes, rather than have a job come back failed - so it stands
    // this horizon down too. Retiring here at ~10 minutes would give
    // them a failed job on a provider that was going to come back,
    // which is the exact outcome they turned the budget off to avoid.
    //
    // The run then genuinely does not end on its own, which is the
    // point: the queue row names the provider and the duration for the
    // whole wait, the auto-defer watchdog moves other jobs past this one
    // (see the daemon's stall watchdog), and pause/cancel still land -
    // every wait here selects on `finished`.
    if ladder_exhausted(cfg, *bounces) {
        // The lease outlived any realistic horizon:
        // release the parked yielders to exit so the
        // run can reach a truthful terminal instead of
        // idling forever.
        shared.auth[ctx.idx].publish_episode(CapEpisode::Dead);
        return DialStep::Quit;
    }
    if !backoff_or_finish(
        cfg.connect_backoff * 2u32.pow((*bounces).min(3) - 1),
        finished,
        shared,
    )
    .await
    {
        return DialStep::Quit;
    }
    DialStep::Retry
}
