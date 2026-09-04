//! Which article this worker takes next.
//!
//! Split out of `pool.rs` whole under the size gate (TODO 106). One
//! subject: a worker on server `si` asks for a unit of work, and this is
//! the whole of the answer - the per-worker routing identity
//! ([`ServerCtx`], built once per worker by [`ctx_for`]), the bit width
//! that identity is allowed ([`MAX_SERVERS`]), and the selection itself
//! ([`next_work`]): queued articles this server has not 430'd, rotated
//! past the ones it has, then - tail phase - a speculative duplicate of
//! an article already in flight somewhere slower.
//!
//! It consults the gates, the held-bytes park, the saturation and
//! line-cap rules and the hand-over check rather than implementing any
//! of them, which is why it moves as one piece and leaves them where
//! they are.
//!
//! The bodies are verbatim. `pool.rs` globs this back in, so callers in
//! pool/session.rs and the sibling test modules resolve through their
//! own `use super::*` exactly as they did before; only `ServerCtx`, its
//! fields, `ctx_for` and `next_work` widened to `pub(super)`, and
//! `MAX_SERVERS` is declared in `crate::config`, which is what
//! ENFORCES it at load, and re-exported by the parent so
//! `crate::pool::MAX_SERVERS` and `nzbkit::pool::MAX_SERVERS` are
//! both unchanged.

use super::*;

/// Per-worker identity for cross-server routing.
#[derive(Clone, Copy)]
pub(super) struct ServerCtx {
    pub(super) idx: usize,
    pub(super) bit: u32,
    #[expect(dead_code)] // mask of every server bit; kept beside bit/group_bits
    pub(super) all: u32,
    /// Bits of this server's whole mirror group (incl. itself): a 430
    /// here is authoritative for all of them (M14e Group).
    pub(super) group_bits: u32,
    /// Tier (M14e Level): >0 = fill server, gated in next_work.
    pub(super) level: u32,
}

pub(super) fn ctx_for(servers: &[(ServerConfig, PoolConfig)], si: usize) -> ServerCtx {
    let me = &servers[si].0;
    let mut group_bits = server_bit(si);
    if let Some(g) = &me.group {
        for (sj, (s, _)) in servers.iter().enumerate() {
            if s.group.as_deref() == Some(g.as_str()) {
                group_bits |= server_bit(sj);
            }
        }
    }
    ServerCtx {
        idx: si,
        bit: server_bit(si),
        all: servers_mask(servers.len()),
        group_bits,
        level: me.level,
    }
}

/// Next unit of work for this server: queued articles it hasn't 430'd
/// first (rotating skipped items), then - tail phase - a duplicate of an
/// article in flight on a slower/stalled server.
pub(super) async fn next_work(
    shared: &Shared,
    ctx: ServerCtx,
    out: &mpsc::Sender<FetchOutcome>,
    // Caller's current pipeline, split by kind (M2c.4): in the ENDGAME a
    // 430-laddering article must not ride BEHIND queued payload bodies
    // - head-of-line blocking on the slowest provider's last windows
    // was the measured 4-6 s straggler tail. It may ride behind OTHER
    // PROBES, which is the whole difference: a refusal is one line, so
    // a window of probes answers in one round trip where the old
    // empty-pipeline rule spent one round trip per probe. That cap -
    // one verdict per connection per RTT - is what made a damaged post
    // sit at 0.0 MB/s for ~10 s before repair while every payload byte
    // was already on disk.
    pipe: Pipeline,
) -> Option<Work> {
    // TTFB-suspicion hedge (TODO 115): an idle worker checks for suspect
    // articles first - their owners are sitting in pre-byte silence
    // RIGHT NOW, and the whole point is to answer inside the budget they
    // have left. One atomic load when dark, quiet, or busy.
    if let Some(w) = shared.pick_suspect_dup(ctx.bit, ctx.group_bits, ctx.level, pipe.used) {
        return Some(w);
    }
    let endgame = shared.pending.load(Ordering::Acquire) <= ENDGAME_MAX;
    // ONE INSTANT FOR THE WHOLE SCAN. It was read for the throttle
    // alone and is hoisted above the masks since 30 Aug 2026: the fill
    // gate, the terminal test and `recheck::expire_hold` all measure
    // windows in it now (`CONN_DARK`, `RECHECK_430_HOLD`), and a scan
    // that read the clock three times could admit a server to
    // `required_mask` that `live_mask` had just dropped.
    let now_ms = shared.run_ms();
    // Fill-server gate (M14e): a level-N server only takes queued work
    // that every LIVE, SERVING lower-level server has already 430'd.
    let required = if ctx.level > 0 {
        shared.required_mask_at(ctx.level, now_ms)
    } else {
        0
    };
    // Scan throttle: this server's last full scan found nothing takeable
    // and re-shuffled the whole queue for the privilege. Sit out a tick
    // instead of burning the shared queue lock - at scale that burn
    // starves the servers that DO have work (see `scan_futile`).
    let futile_at = shared.scan_futile[ctx.idx].load(Ordering::Relaxed);
    if futile_at != u64::MAX && now_ms.saturating_sub(futile_at) < SCAN_RETRY_MS {
        return shared.pick_dup(ctx.idx, ctx.bit, ctx.group_bits, required, pipe, ctx.level);
    }
    // An article every LIVE server has 430'd is terminal even if servers
    // whose workers bowed out never saw it - a dead server can't answer,
    // and waiting for it deadlocks the whole run (the queue rotates the
    // item forever). Collected under the lock, reported after.
    //
    // Terminal, though, is not the same claim as GONE, and this site used to
    // make both at once (27 Aug sweep finding 8). The refusal mask rides out
    // of the scan with the id so `missing_cause` can tell "every server that
    // could answer refused it" from "the fleet shrank out from under it" -
    // see `Shared::participation_mask`. The test below is deliberately
    // unchanged: a frozen mask there is what the warning above refuses.
    // What DID change on 30 Aug 2026 is the mask and not the test; see
    // `Shared::live_mask`, which can now grow back.
    let live = shared.live_mask_at(now_ms);
    let mut unservable: Vec<(Arc<str>, u32, u32)> = Vec::new();
    let mut picked: Option<Work> = None;
    // Promoted items this (slow) server steps PAST: they must go back to
    // the queue FRONT in order - a fast server picks from the front, and
    // rotating seek-critical work to the back would strand it.
    let mut left_for_faster: Vec<Work> = Vec::new();
    // Held-bytes backpressure: candidates stepped past because their
    // group is at its allowance. Kept in QUEUE ORDER and put back at the
    // front, never rotated: the queue runs file-then-offset, so the
    // first one admitted is the article the engine is blocked on. A
    // rotation scrambled that and the 4G leg of 23 Aug 2026 starved
    // its engine 35 s at 6 MB/s while far-ahead bytes broke the cap.
    // Not a dry queue either - no tail latch, no dup fan-out.
    let mut parked_kept: Vec<Work> = Vec::new();
    // The park's liveness floor in its authoritative form, read ONCE per
    // scan and off every park lock (`FilePark::set` takes its own maps
    // and then this one, so holding this across `defers` would be
    // AB/BA). See `FilePark::defers`.
    let pool_idle = shared.park.is_on() && shared.inflight.lock_ok().is_empty();
    let parked_past = {
        let mut q = shared.queue.lock().await;
        // TODO 114 consumer steer: adopt any steered requeues parked
        // in the inbox (the verdict thread never takes this lock -
        // see the `steer_inbox` field doc). Front, behind the promoted
        // run: the consumer is waiting on exactly this article, and
        // the `PartLatch` needs a refetch to REPORT early, not last.
        {
            let mut inbox = shared.steer_inbox.lock_ok();
            for w in inbox.drain(..) {
                let at = q.iter().take_while(|x| x.promoted).count().min(q.len());
                if w.promoted {
                    shared.promoted_pending.fetch_add(1, Ordering::AcqRel);
                }
                q.insert(at, w);
            }
        }
        for _ in 0..q.len() {
            let Some(mut w) = q.pop_front() else { break };
            // TODO 315: a late re-ask that has outlived its window gives
            // the suppressed evidence back BEFORE the terminal test
            // reads it, and THIS is the site that has to do it - a held
            // item is dispatchable only by the group holding it, so if
            // that group is not taking it, this scan is the only thing
            // that ever looks at the item again. `now_ms` is the scan
            // throttle's, already in hand, so it costs an integer
            // compare per queued item and no clock read. Warned once a
            // run: the failure this bounds was silent for eleven hours,
            // and a count nobody prints is that silence with a counter
            // behind it. See `recheck::RECHECK_430_HOLD`.
            if recheck::expire_hold(&mut w, now_ms, shared.recheck_hold_ms)
                && shared.recheck_expired.fetch_add(1, Ordering::Relaxed) == 0
            {
                warn!(
                    target: "pool",
                    "late re-ask window ({}s) ran out before the backbone answered - \
                     articles are going terminal on the refusals already in hand",
                    shared.recheck_hold_ms / 1000
                );
            }
            if w.tried_430 & live == live {
                // TODO 315: this is the FOURTH place a held article's
                // Work leaves flight for good, and `Shared::take_recheck`
                // named only three - the two verdict arms and the
                // duplicate-resolved early return, all of them in
                // `session`. A held item sits in this queue with its
                // re-asked group's bit CLEARED, so it is not unanimous
                // when it is put back; the fleet shrinking under it is
                // what makes it unanimous later, and the removal here
                // dropped the `Work` whole - budget and all. It does not
                // fail loudly: it silently retires the late re-ask for
                // the rest of the run once `recheck_430_max` slots are
                // gone, and up to that many queued holds can leak
                // together. Released BEFORE `claim_done` is consulted
                // because the slot is owed back whether or not this
                // scan owns the outcome - a duplicate that already
                // terminalized the article did not give it back either.
                shared.release_recheck(&w);
                unservable.push((w.id, w.ord, w.tried_430));
                continue;
            }
            // M5: the fill gate asks for refusals, and a lower-level
            // server that killed this article's connection on every
            // attempt never files one - the deeper tier holding a good
            // copy stayed locked out until the retries ran out and the
            // article was reported lost. A server that spent its whole
            // budget has answered as finally as a 430 does, so it
            // satisfies the gate here (and NOWHERE else: `spent` is not
            // evidence, so unanimous-Missing above still counts 430s
            // alone). The lookup is skipped entirely while the gate is
            // already satisfied, which includes every level-0 pick.
            let gated = w.tried_430 & required != required
                && (w.tried_430 | shared.spent_mask(&w.id)) & required != required;
            if w.tried_430 & ctx.bit != 0
                || gated
                || (w.tried_fail & ctx.bit != 0 && shared.other_can_take(&w, ctx.idx))
                || (endgame && pipe.payload > 0 && w.tried_430 != 0)
            {
                q.push_back(w);
            } else if shared.park.defers(&w, pool_idle) {
                parked_kept.push(w);
            } else if w.promoted
                && w.tried_430 == 0
                && shared.stream_active()
                && shared.faster_can_take(&w, ctx.idx)
            {
                // Untried promoted work waits briefly for a faster server;
                // once ANY backbone has 430'd it, latency beats speed-
                // matching - whoever can serve it, serves it.
                left_for_faster.push(w);
            } else {
                if w.promoted {
                    let _ = shared.promoted_pending.fetch_update(
                        Ordering::AcqRel,
                        Ordering::Acquire,
                        |v| v.checked_sub(1),
                    );
                }
                // Per-dispatch classification (see `Work::ladder`): an
                // article carrying refusal evidence is walking toward a
                // verdict, and this hop is a probe. One that has never
                // been refused is payload, however long it has been
                // queued.
                w.ladder = w.tried_430 != 0 || w.soft_430 != 0;
                // Held-bytes backpressure: counted HERE, under the
                // queue lock, not at registration a socket write later
                // - every idle worker passed the one-in-flight floor
                // in that window at once (60 x 700 KB, the whole
                // margin, on the 22 Aug rig).
                shared.park.note_pick(&w);
                picked = Some(w);
                break;
            }
        }
        let parked_past = !parked_kept.is_empty();
        for w in parked_kept.into_iter().rev() {
            q.push_front(w);
        }
        for w in left_for_faster.into_iter().rev() {
            q.push_front(w);
        }
        parked_past
    };
    if picked.is_none() {
        shared.scan_futile[ctx.idx].store(now_ms, Ordering::Relaxed);
    }
    for (id, ord, tried_430) in unservable {
        if shared.claim_done(&id, ord) {
            let takedown = shared.take_takedown(&id) != 0;
            let cause = shared.missing_cause(tried_430, takedown);
            let _ = out.send(FetchOutcome::Missing { id, cause }).await;
            shared.complete_one();
        }
    }
    if picked.is_some() || parked_past {
        return picked;
    }
    if ctx.level == 0 && shared.pending.load(Ordering::Acquire) > 0 {
        // Only primaries mark the tail - an idle fill server waiting on
        // its gate isn't evidence the queue ran dry.
        let latched_now = {
            let mut ts = shared.tail_started.lock_ok();
            ts.is_none() && {
                *ts = Some(Instant::now());
                true
            }
        };
        if latched_now {
            // The latch opens the early fan-out rules for every server:
            // wake pick_dup scanners gated on an unchanged map (N6).
            shared.bump_inflight_gen();
        }
        // Phase marker, once per run at the latch: from here the line
        // tapers naturally as the last in-flight articles land, and
        // without a marker that taper reads as a fault.
        if latched_now && let Some(l) = &shared.live {
            l.note_run(
                "tail",
                "every article has been handed out - waiting for the last ones in flight",
            );
        }
    }
    // Cross-job hand-over outranks a speculative duplicate (None lets
    // the pipeline drain to empty, where `idle_turn` hands over).
    if shared.want_handoff(ctx.idx) {
        return None;
    }
    shared.pick_dup(ctx.idx, ctx.bit, ctx.group_bits, required, pipe, ctx.level)
}
