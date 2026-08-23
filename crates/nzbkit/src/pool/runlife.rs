//! What happens to a worker and to the whole run AFTER dispatch: the
//! spare filler, the worker task itself, the read-stall note, and every
//! way a run is sealed or a work item requeued, retried or failed.
//!
//! Sealing is the subject that ties them together. `seal_run` (and its
//! blocking twin, used off the async context) is the last-one-out check -
//! it fails the still-pending work exactly once, and only when no worker
//! anywhere can still finish it, which is why abort and drain are exempt.
//! `backoff_or_finish` and `requeue_or_fail` are the same decision one
//! article at a time.
//!
//! Split out of `pool.rs` whole (TODO 106 size gate) - the code is
//! verbatim, only visibility changed. A child module, so `Shared`,
//! `Work`, `WorkerLife` and `ServerCtx` stay in scope as they were
//! inline; `pub(super)` reads "pub in pool", which is what puts these
//! back in front of pool.rs AND its other children (pool/session.rs
//! calls most of them) exactly as the private ones were.

use super::*;

/// How long the blocking terminal seal waits for the queue lock, in
/// 10 ms tries (sweep 8, L10). Two seconds: every possible holder is a
/// short critical section on a thread that is not a shard, and there is
/// no live run left for the wait to starve.
pub(super) const SEAL_LOCK_TRIES: u32 = 200;

#[cfg(test)]
thread_local! {
    /// Test seam (F-15): bitmask of shard ordinals whose OS thread is
    /// to be refused, answering as the kernel does on resource
    /// exhaustion - the failure `thread::Builder` returns and bare
    /// `thread::spawn` turned into a panic. Thread-local because
    /// `fetch_all_sharded` spawns from its caller's thread, so a test
    /// denying its own shards cannot touch a parallel test's run.
    pub(super) static SHARD_SPAWN_DENY: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

pub(super) fn seal_run_blocking(
    shared: &Arc<Shared>,
    out: &mpsc::Sender<FetchOutcome>,
    reason: &str,
) -> usize {
    let mut seal_waits = 0u32;
    if shared.workers_live.load(Ordering::Acquire) > 0
        || shared.pending.load(Ordering::Acquire) == 0
        || shared.aborted.load(Ordering::Acquire)
        || shared.draining.load(Ordering::Acquire)
    {
        return 0;
    }
    // The shards are joined, but a QueueControl holder is not a shard:
    // the steer consumer can be inside `requeue` right now.
    //
    // Sweep 8, L10: one failed `try_lock` used to be read as an EMPTY
    // queue. The caller drops the outcome channel on the next line, so
    // every id still sitting in there got no terminal outcome at all -
    // silently, and in violation of the one-outcome-per-id contract the
    // run promises. It takes an OS/runtime resource failure plus a
    // narrow lock window to reach, which is why it is a Low and not why
    // it is acceptable. Every holder of this lock is a short critical
    // section on another thread and no shard can take it any more, so
    // waiting is bounded in practice as well as by the loop; the same
    // try-and-sleep discipline `QueueControl::promote` uses, with a
    // much longer bound because there is no live run left to starve.
    let mut orphans: Vec<(Arc<str>, u32)> = loop {
        match shared.queue.try_lock() {
            Ok(mut q) => break q.drain(..).map(|w| (w.id, w.ord)).collect(),
            Err(_) if seal_waits < SEAL_LOCK_TRIES => {
                seal_waits += 1;
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            // Still held after the bound: say so ONCE and keep waiting
            // (F-14). Giving up here used to `break Vec::new()`, which
            // dropped every queued id's terminal outcome on the floor -
            // the very defect L10 above was fixing, reached one bound
            // later. The holder is a short critical section, so this
            // wait is finite in practice; and it cannot be a
            // `blocking_lock`, because a caller that ignored the
            // spawn_blocking contract would then panic inside a runtime
            // worker instead of merely stalling.
            Err(_) => {
                if seal_waits == SEAL_LOCK_TRIES {
                    seal_waits += 1;
                    warn!(
                        target: "pool",
                        "terminal seal still waiting for the queue lock after {}ms - \
                         holding on so every queued article gets its outcome",
                        SEAL_LOCK_TRIES * 10
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    };
    orphans.extend(shared.inflight.lock_ok().drain().map(|(id, e)| (id, e.ord)));
    orphans.extend(
        shared
            .steer_inbox
            .lock_ok()
            .drain(..)
            .map(|w| (w.id, w.ord)),
    );
    let mut sealed = 0;
    for (id, ord) in orphans {
        if !shared.claim_done(&id, ord) {
            continue;
        }
        let _ = out.blocking_send(FetchOutcome::Failed {
            id,
            error: reason.to_string(),
        });
        shared.complete_one();
        sealed += 1;
    }
    sealed
}

/// Hand a DRAINED connection to the warm pool, or close it when there is
/// no warm pool (one-shot CLI runs). Callers must have an empty in-flight
/// deque: a connection with unread pipelined responses on it is not
/// reusable and must go through `quit()` instead.
pub(super) async fn park_or_quit(cfg: &PoolConfig, server: &ServerConfig, conn: Connection) {
    match &cfg.warm {
        Some(w) => w.give(server, conn).await,
        None => conn.quit().await,
    }
}

/// Hot-spare filler: keeps ONE authenticated connection parked for its
/// server until the run ends, re-dialling whenever a worker claims it.
/// Ends with the run (`finished`), on user abort, or on graceful drain -
/// `drain()` deliberately sends no `finished`, so the filler must watch
/// the flag itself or a paused job leaves it looping forever with an
/// authenticated provider session (Codex 5 Aug M4). The 500 ms tick
/// below bounds how late it notices. Quits whatever it still holds on
/// every exit path. Connect failures back off 5 s - a provider at its
/// connection cap refuses the spare and that refusal must not become a
/// dial storm against the very cap the workers depend on.
pub(super) async fn spare_filler(shared: Arc<Shared>, server: ServerConfig, idx: usize) {
    let mut finished = shared.finished.subscribe();
    loop {
        if *finished.borrow()
            || shared.aborted.load(Ordering::Acquire)
            || shared.draining.load(Ordering::Acquire)
        {
            break;
        }
        let empty = shared.spares[idx].lock_ok().is_none();
        if empty {
            match Connection::connect(&server).await {
                Ok((c, _)) => {
                    *shared.spares[idx].lock_ok() = Some(c);
                }
                Err(_) => {
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                        _ = finished.wait_for(|f| *f) => break,
                    }
                }
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(500)) => {}
            _ = finished.wait_for(|f| *f) => break,
        }
    }
    // Guard dropped before the await - the lock must never be held
    // across a suspension point.
    let leftover = shared.spares[idx].lock_ok().take();
    if let Some(c) = leftover {
        c.quit().await;
    }
}

/// One spawned worker: the connect ramp, the session loop, and the run's
/// terminal-state exit protocol. Every worker leaves through here, so the
/// last one out is the one that seals the run (see [`seal_run`]).
#[expect(clippy::too_many_arguments)]
pub(super) async fn worker(
    server: &ServerConfig,
    cfg: &PoolConfig,
    ctx: ServerCtx,
    shared: Arc<Shared>,
    out: mpsc::Sender<FetchOutcome>,
    connects: Arc<AtomicU64>,
    reconnects: Arc<AtomicU64>,
    life: WorkerLife,
    ramp: Duration,
    slot: u32,
) {
    // The ramp paces CONNECT bursts, which is what providers punish (a
    // provider given more sockets than it wants is 3-4x SLOWER, see
    // conntune). A worker that reuses a parked connection performs no
    // connect, so pacing it is pure added latency on exactly the path
    // this mechanism exists to speed up.
    //
    // CLAIM one rather than asking whether one exists. A `has()` probe
    // would let every worker in the fleet see the same single parked
    // connection, all conclude they need no ramp, and all dial at once -
    // reintroducing the burst in the one case the pool is nearly empty.
    // `take` is atomic, so exactly as many workers skip the ramp as
    // there are connections to skip it with.
    //
    // The claim must yield to the run finishing, for the same reason the
    // dial in `session_loop` does (§35): `take` validates its candidate
    // with a DATE round-trip bounded by VALIDATE_TIMEOUT, and that bound
    // is 8 s against EXIT_GRACE's 5 s. A worker validating a peer that
    // has gone mute therefore CANNOT return before `join_fleet` gives up
    // on it, so the run pays the whole grace window - the exact tail §35
    // was about, re-entered through the warm path. Losing the candidate
    // on cancellation is already this code's contract: a validation that
    // runs out of time leaves its DATE unanswered on the socket, so the
    // connection is dropped rather than returned or re-parked.
    let mut fin = shared.finished.subscribe();
    // TODO 112: the live-target park comes BEFORE the warm claim - a
    // slot spawned above the target must hold nothing, and a warm
    // connection it claimed would idle out in its hands rather than
    // serve an admitted worker. A None admission under a live target
    // means the run ended while parked; fall through so `life.retire()`
    // still seals. The guard (F-22) is handed to `session_loop`, which
    // holds it across sessions and drops it on every exit so a parked
    // worker takes this one's place.
    let admit = match &cfg.live_target {
        Some(t) => wait_for_slot(t, ctx.idx, &mut fin, &shared).await,
        None => None,
    };
    let admitted = cfg.live_target.is_none() || admit.is_some();
    // Cross-job hand-over (`handoff`): a connection slot on this host,
    // taken BEFORE the warm claim because a parked connection is a
    // connection. Blocks while the previous job's run still holds the
    // host at its cap; its idle workers release as they drain. Held
    // until this worker leaves, whichever way it leaves. A run without
    // a lease - the CLI, every test that does not opt in - takes the
    // old path verbatim.
    let _permit = match &cfg.lease {
        Some(l) if admitted => tokio::select! {
            p = l.acquire() => Some(p),
            _ = run_over(&mut fin, &shared) => None,
        },
        _ => None,
    };
    let admitted = admitted && (cfg.lease.is_none() || _permit.is_some());
    let warm_conn = match &cfg.warm {
        Some(w) if admitted => tokio::select! {
            c = w.take(server) => c,
            // Nothing left to claim it for. Fall through as if the pool
            // were empty rather than returning: `life.retire()` below is
            // what seals the run, and no path may skip it.
            _ = run_over(&mut fin, &shared) => None,
        },
        _ => None,
    };
    // The ramp sleep must yield to abort/finish: at 100 connections ×
    // 150 ms a still-ramping worker would otherwise outlive an aborted
    // run by up to 15 s.
    let ramped = admitted
        && (warm_conn.is_some() || {
            tokio::select! {
                _ = tokio::time::sleep(ramp) => true,
                _ = fin.wait_for(|f| *f) => false,
            }
        });
    if ramped {
        session_loop(
            server,
            cfg,
            ctx,
            shared.clone(),
            out.clone(),
            connects,
            reconnects,
            slot,
            admit,
            warm_conn,
        )
        .await;
    }
    if life.retire() {
        seal_run(
            &shared,
            &out,
            "no connection worker left to fetch this article",
        )
        .await;
    }
}

/// The read-stall bookkeeping split by WHY the read ended (TODO
/// 121.1/.2). A pre-byte adaptive expiry escalates the charged front
/// article's OWN next-attempt budget (per-server widening alone
/// re-floors between that article's retries) and is NOT a flap death:
/// giving up pre-byte was our budget choice, and a heavy-tailed but
/// healthy provider (cold storage at trained-floor budgets) produces
/// FLAP_DEATHS of them a minute without a session actually dying -
/// clamping it to keepers punished the wrong party. A mid-flow stall
/// on an established session stays a death: bytes were moving and
/// stopped, which is the wedge the flap breaker exists for.
pub(super) fn note_read_stall(
    shared: &Shared,
    idx: usize,
    session_bytes: u64,
    prebyte_expired: bool,
    front: Option<&mut Work>,
) {
    if prebyte_expired {
        if let Some(w) = front {
            w.prebyte_expiries = w.prebyte_expiries.saturating_add(1);
        }
    } else if session_bytes > 0 {
        // Count it where it happens, not at some later redial this
        // worker may never win (a capped provider bounces most
        // re-entries, which hid the churn entirely).
        shared.note_flap(idx);
    }
}

/// Enforce the pool's terminal-state invariant: every article the caller
/// asked for gets exactly one outcome before the outcome channel closes.
///
/// Nothing else guarantees it. A worker bows out for good after
/// `max_connect_attempts` consecutive connect failures, so if every
/// provider is unreachable at startup - or every worker exhausts its
/// reconnects mid-job - the last one returns with articles still queued,
/// or still owned by the `inflight` map of a worker that died holding
/// them. The fleet joins, the senders drop, and the channel closes having
/// said NOTHING about those ids. The engine does eventually notice the
/// unresolved slots, but by then the pool's diagnostics have lied and
/// repair has run against a network ledger that never recorded the
/// failures it is repairing around.
///
/// So whoever turns the lights out - the last worker to retire, or
/// [`join_fleet`] afterwards for workers that panicked or were abandoned
/// mid-flight - drains everything still non-terminal into one `Failed`
/// per id. `claim_done` keeps that "exactly one" even against a straggler
/// emitting its own outcome concurrently.
///
/// Aborted and draining runs are exempt: both are deliberate early stops
/// whose unfinished work belongs to the caller (a resume re-fetches it),
/// and failing it here would journal a user's pause as a download error.
///
/// Returns the number of articles sealed.
pub(super) async fn seal_run(
    shared: &Arc<Shared>,
    out: &mpsc::Sender<FetchOutcome>,
    reason: &str,
) -> usize {
    // Not the last one out: on the sharded path another shard's runtime
    // still has workers that can finish this work.
    if shared.workers_live.load(Ordering::Acquire) > 0
        || shared.pending.load(Ordering::Acquire) == 0
        || shared.aborted.load(Ordering::Acquire)
        || shared.draining.load(Ordering::Acquire)
    {
        return 0;
    }
    // Collected under the locks, emitted after: `out` is bounded, and a
    // send that parks on a slow consumer while the queue is held would
    // stall anything still touching the pool. Queue then inflight is the
    // lock order every other path here uses.
    let mut orphans: Vec<(Arc<str>, u32)> = Vec::new();
    {
        let mut q = shared.queue.lock().await;
        orphans.extend(q.drain(..).map(|w| (w.id, w.ord)));
        let mut inf = shared.inflight.lock_ok();
        orphans.extend(inf.drain().map(|(id, e)| (id, e.ord)));
        orphans.extend(
            shared
                .steer_inbox
                .lock_ok()
                .drain(..)
                .map(|w| (w.id, w.ord)),
        );
    }
    let mut sealed = 0usize;
    for (id, ord) in orphans {
        if !shared.claim_done(&id, ord) {
            continue; // a duplicate dispatch already owns this outcome
        }
        let _ = out
            .send(FetchOutcome::Failed {
                id,
                error: reason.to_string(),
            })
            .await;
        shared.complete_one();
        sealed += 1;
    }
    if sealed > 0 {
        error!(
            target: "pool",
            "fleet exhausted with {sealed} article(s) unresolved - reported \
             Failed ({reason}) so the run's terminal ledger is truthful"
        );
    }
    sealed
}

/// M11 stream-mode shed: requeue a deliberately abandoned pipeline.
/// Nothing failed, so nothing is charged an attempt. Items are inserted
/// directly BEHIND the promoted run at the queue front, preserving their
/// relative order: ahead of the promoted run they would re-create the
/// very backlog the shed exists to clear; at the queue back, the head-of-
/// file bytes a sequential player needs next would land after gigabytes
/// of tail. Tail duplicates are dropped (the original owns the outcome).
pub(super) async fn shed_pipeline(shared: &Shared, inflight: &mut VecDeque<Work>) {
    // B3 wire-cap: the whole pipeline leaves flight in one go.
    shared.release_wire(inflight.len());
    let mut q = shared.queue.lock().await;
    let mut at = q.iter().take_while(|w| w.promoted).count();
    while let Some(w) = inflight.pop_front() {
        if w.dup {
            continue;
        }
        shared.deregister_inflight(&w);
        if shared.done.lock_ok().contains(w.ord) {
            continue; // a dup already emitted this article's outcome
        }
        if w.promoted {
            shared.promoted_pending.fetch_add(1, Ordering::AcqRel);
        }
        let idx = at.min(q.len());
        q.insert(idx, w);
        at += 1;
    }
}

/// On connection death: the front in-flight article (the one that actually
/// errored) is charged an attempt; the rest were casualties of the same
/// connection and requeue free. Articles over budget report Failed. Tail
/// duplicates are dropped silently - the original dispatch owns the
/// outcome (and if the dup had already won, `done` protects the original).
/// Resolves once this worker is no longer needed: every article terminal
/// (`finished`), or a graceful drain under way.
///
/// Used to race blocking work that has no business outliving the run.
/// `drain()` deliberately does not send `finished`, so draining has to be
/// polled rather than awaited - same 250 ms slice as [`backoff_or_finish`],
/// which is the resolution a human notices and far below any dial timeout.
pub(super) async fn run_over(finished: &mut tokio::sync::watch::Receiver<bool>, shared: &Shared) {
    loop {
        if shared.draining.load(Ordering::Acquire) {
            return;
        }
        tokio::select! {
            _ = finished.wait_for(|f| *f) => return,
            _ = tokio::time::sleep(Duration::from_millis(250)) => {}
        }
    }
}

/// Wait out a connect backoff, but give up the moment the RUN is done.
///
/// Returns false if the work finished while we slept, meaning this worker
/// should retire rather than reconnect.
///
/// A bare sleep here held whole jobs open. Measured on the bench farm with
/// one dead server in a six-server config: a job whose bytes had all
/// arrived by 0.79 s did not RETURN until 3.17 s, so about 75% of it was
/// spent after the last byte with nothing outstanding but a server that
/// was never going to answer. Per-job cost of one dead provider was 4.1 s
/// against 2.0 s without it - a dead server doubled every download.
pub(super) async fn backoff_or_finish(
    backoff: Duration,
    finished: &mut tokio::sync::watch::Receiver<bool>,
    shared: &Shared,
) -> bool {
    if *finished.borrow() || shared.draining.load(Ordering::Acquire) {
        return false;
    }
    // Race the wait against a DRAIN as well as a finish. `drain()`
    // deliberately does not send `finished`, and nothing on the connect
    // side checks `draining`, so a worker on an unreachable server slept
    // out its whole ladder before retiring: with the defaults that is
    // 2+4+8+16 s of backoff plus four dial timeouts, and the user's
    // pause - which completes only when the fetch returns - visibly hung
    // for the best part of a minute. The session-backoff path already
    // slices for exactly this reason; the connect path never did.
    let deadline = tokio::time::Instant::now() + backoff;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return true;
        }
        let step = left.min(Duration::from_millis(250));
        tokio::select! {
            _ = tokio::time::sleep(step) => {}
            _ = async { let _ = finished.wait_for(|f| *f).await; } => return false,
        }
        if shared.draining.load(Ordering::Acquire) {
            return false;
        }
    }
}

/// `charge_front`: whether the front-of-pipeline casualty pays for the
/// death (attempts bump + this server's `tried_fail` bit). Pass true
/// when the front article is implicated - its own read stalled past
/// budget, or the session never did any useful work (the RST-after-AUTH
/// livelock the charge exists to break). Pass false for a clean
/// connection death AFTER at least one completed body: that is the flap
/// shape, the next-queued article is innocent, and branding it walked a
/// whole twin-only backlog into the queue - the flapping server then
/// sat idle for the entire drain of a bandwidth-saturated sibling
/// (measured 7.5 s of wasted capacity per 300 MB on the chaos flap
/// leg) because every queued article carried its bit and
/// `other_can_take` barred a retake. A session with a completed body
/// is progress by definition, so the uncharged requeue cannot livelock:
/// the moment such an article is the FIRST casualty of a zero-work
/// session, that session charges it.
pub(super) async fn requeue_or_fail(
    shared: &Shared,
    out: &mpsc::Sender<FetchOutcome>,
    cfg: &PoolConfig,
    ctx: ServerCtx,
    inflight: &mut VecDeque<Work>,
    error: &str,
    charge_front: bool,
) {
    // Failed outcomes are emitted AFTER the queue lock drops: `out` is a
    // bounded channel, and a send that parks on a slow consumer while the
    // queue is locked would stall every worker that needs the queue.
    let mut failed: Vec<Arc<str>> = Vec::new();
    // B3 wire-cap: the dead connection's whole pipeline leaves flight.
    shared.release_wire(inflight.len());
    {
        let mut q = shared.queue.lock().await;
        // Cursors, not a recomputed position. `inflight` is oldest-
        // first, so a fixed insertion point reverses the casualties:
        // `push_front` puts each successive promoted one at index 0,
        // and re-deriving the promoted-prefix length for a NON-promoted
        // insert yields the same index every time, because a
        // non-promoted insert does not extend that prefix. Both give
        // [A,B] back as [B,A], and on a forward-only chase decode that
        // is the head-of-file article landing behind its own tail.
        // `shed_pipeline` above keeps a cursor for exactly this reason
        // ("preserving their relative order"); so does `next_work`'s
        // `left_for_faster` walk. A promoted insert DOES extend the
        // prefix, so `at` tracks it.
        let mut at = q.iter().take_while(|x| x.promoted).count().min(q.len());
        let mut pat = 0usize;
        let mut first = true;
        while let Some(mut w) = inflight.pop_front() {
            let charged = first && charge_front;
            first = false;
            if w.dup {
                continue;
            }
            shared.deregister_inflight(&w);
            if shared.done.lock_ok().contains(w.ord) {
                continue; // a dup already emitted this article's outcome
            }
            if charged {
                w.attempts += 1;
                w.tried_fail |= ctx.bit;
                if w.attempts > cfg.article_retries {
                    // M5: a spent budget is this SERVER's verdict, not
                    // the article's. Every attempt here died in
                    // transport, so nothing ever 430'd and the fill
                    // gate (`required_mask`) never opened - a healthy
                    // server one level down held the article the whole
                    // time and was never asked. `note_spent` opens that
                    // gate and re-arms the budget when some live server
                    // has yet to have a real go at it, once per server,
                    // so the ladder still ends. It costs a deeper tier
                    // (a block account, possibly) one paid article,
                    // which beats losing the article outright.
                    if shared.note_spent(&w, ctx.bit) {
                        w.attempts = 0;
                    } else {
                        if shared.claim_done(&w.id, w.ord) {
                            failed.push(w.id);
                        }
                        continue;
                    }
                }
            }
            // Same books as every other reinsert (shed_pipeline above,
            // the recheck path, the steer adopt): a promoted article
            // going back in the queue is counted back into
            // promoted_pending, or the next pick spends a count that
            // belongs to a DIFFERENT promoted article and read_one's
            // shed gate goes quiet while promoted work still waits.
            // And a non-promoted casualty must not cut ahead of the
            // promoted run at the front.
            if w.promoted {
                shared.promoted_pending.fetch_add(1, Ordering::AcqRel);
                let idx = pat.min(q.len());
                q.insert(idx, w);
                pat += 1;
                at += 1;
            } else {
                let idx = at.min(q.len());
                q.insert(idx, w);
                at += 1;
            }
        }
    }
    for id in failed {
        let _ = out
            .send(FetchOutcome::Failed {
                id,
                error: error.to_string(),
            })
            .await;
        shared.complete_one();
    }
}

/// The fleet shrank: `prev == 1` means the departing worker was its
/// server's LAST, so from this moment the server contributes nothing to
/// the run - `live_mask` no longer counts it. That is the single most
/// throughput-denting thing a pool can do quietly, and until this marker
/// existed it WAS quiet: each worker bowed out alone (session or connect
/// exhaustion, an auth yield) and no one said the server itself was gone.
///
/// Natural wind-downs are not bow-outs: with no work pending, or the run
/// aborted or draining, every worker leaves and none of it belongs on
/// the graph. Fires at most once per server per run by construction -
/// `alive` only ever crosses 1 -> 0 once, since workers are never
/// re-spawned after the ramp. The same test also latches
/// [`PoolStats::left_mid_run`] for the failure summary.
///
/// Moved here from pool.rs whole (TODO 106 size gate): a worker leaving
/// the fleet, and what it means when it was the last one, is this
/// module's subject.
pub(super) fn note_server_dark(shared: &Shared, idx: usize, prev: usize) {
    if prev != 1
        || shared.pending.load(Ordering::Acquire) == 0
        || shared.aborted.load(Ordering::Acquire)
        || shared.draining.load(Ordering::Acquire)
    {
        return;
    }
    // A3: the same moment, for the failure summary rather than the graph
    // - everything above IS the "left while work remained" test. Latched
    // ahead of both stand-downs below, which the summary must still hear
    // about: a spent block is one of the four departures, and a CLI job
    // has no live sink but still fails with a message someone reads.
    if shared.connected[idx].load(Ordering::Relaxed) {
        shared.left_mid_run[idx].store(true, Ordering::Relaxed);
    }
    // §96.5: a budget bow-out already told its own story ("block
    // spent") - the connections-kept-failing copy below would be a
    // lie about a server that was serving fine.
    if shared.budget_noted[idx].load(Ordering::Relaxed) {
        return;
    }
    let Some(live) = &shared.live else {
        return;
    };
    let others = shared
        .alive
        .iter()
        .enumerate()
        .filter(|(i, a)| *i != idx && a.load(Ordering::Relaxed) > 0)
        .count();
    let detail = match others {
        0 => "out of the run - its connections kept failing, and no other server is left",
        1 => "out of the run - its connections kept failing; the remaining server carries on",
        _ => "out of the run - its connections kept failing; the other servers carry on",
    };
    live.note(idx, "retired", detail);
}
