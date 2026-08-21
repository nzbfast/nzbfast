// TODO 106: the tail dup race and the in-flight wire budget came out of
// pool.rs whole under the size gate. One subject in two halves that only
// ever read together - hedging is how the pool spends EXTRA wire on an
// article somebody else is already holding, and the B3 wire cap is the
// bound on how much wire may be in flight at once. A child module sees
// the parent's private items (Shared, Work, Inflight, Pipeline and the
// tuning constants), so the bodies are untouched; only the eight methods
// widened to pub(super) for the call sites in pool.rs, session.rs,
// steer.rs and the sibling test modules.

use super::*;

impl Shared {
    /// N6: the inflight map (or a gate a completion moves - `pending`,
    /// `done`) changed in a way that may create a `pick_dup` candidate.
    /// Called AFTER the mutation is visible: the Release here pairs with
    /// `pick_dup`'s Acquire snapshot, taken before it locks the map, so
    /// a snapshot that includes this bump always observes the mutation.
    pub(super) fn bump_inflight_gen(&self) {
        self.inflight_gen.fetch_add(1, Ordering::Release);
    }

    /// Register a dispatched original in the inflight map the dup race
    /// walks. Moved here from pool.rs with its lifecycle siblings under
    /// the size gate - the map's readers and writers are one subject.
    pub(super) fn register_inflight(&self, w: &Work, server: usize) {
        if w.dup {
            return; // dups are tracked via the original's entry
        }
        self.inflight.lock_ok().insert(
            w.id.clone(),
            Inflight {
                server,
                dispatched: Instant::now(),
                dups: 0,
                tried_430: w.tried_430,
                dup_servers: 0,
                tried_fail: w.tried_fail,
                suspect: false,
                found: 0,
                age_days: w.age_days,
                part: w.part,
                ord: w.ord,
            },
        );
        self.bump_inflight_gen();
    }

    /// TODO 96.4: a STAT probe came back 223 - this backbone holds the
    /// article. Recorded on the in-flight entry the probe was racing,
    /// which is what stops the rest of the fan-out (see `Inflight::found`).
    /// The entry can already be gone (the original landed while the probe
    /// was reading); that is a no-op.
    pub(super) fn note_found(&self, id: &str, group_bits: u32) {
        if let Some(inf) = self.inflight.lock_ok().get_mut(id) {
            inf.found |= group_bits;
        }
    }

    pub(super) fn deregister_inflight(&self, w: &Work) {
        if !w.dup {
            self.inflight.lock_ok().remove(&w.id);
            self.bump_inflight_gen();
        }
    }

    /// Done-path deregistration: also feeds the article-time EWMA the
    /// hedge bound trains on. Failure, requeue and shed paths use plain
    /// [`Self::deregister_inflight`] - a requeue's age is not a
    /// completion time.
    pub(super) fn deregister_inflight_done(&self, w: &Work) {
        if w.dup {
            return; // dups are tracked via the original's entry
        }
        if let Some(inf) = self.inflight.lock_ok().remove(&w.id) {
            let ms = (inf.dispatched.elapsed().as_millis() as u64).max(1);
            let old = self.art_ms.load(Ordering::Relaxed);
            let new = if old == 0 { ms } else { old - old / 8 + ms / 8 };
            self.art_ms.store(new.max(1), Ordering::Relaxed);
            // M7b.2: the by-owner twin. Charged to the entry's OWNER,
            // not the completing worker - when a dup wins, the elapsed
            // time still describes how long the owner held the article.
            self.note_srv_art(inf.server, ms);
        }
        self.bump_inflight_gen();
    }

    /// Hedge experiment: the staleness bound for the dup race. 3x the
    /// trained article-time EWMA, clamped between the fan-out age floor
    /// and the old flat 8 s - hedging can only be MORE responsive than
    /// the flat rule, never less, and an untrained EWMA keeps the flat
    /// bound.
    pub(super) fn hedge_stale_bound(&self) -> Duration {
        if !self.hedge {
            return HEDGE_STALE_MAX;
        }
        match self.art_ms.load(Ordering::Relaxed) {
            0 => HEDGE_STALE_MAX,
            ewma => Duration::from_millis((ewma * 3).clamp(
                TAIL_FANOUT_MIN_AGE.as_millis() as u64,
                HEDGE_STALE_MAX.as_millis() as u64,
            )),
        }
    }

    /// B3 wire-cap: charge one dispatched BODY's estimated bytes.
    pub(super) fn charge_wire(&self) {
        self.inflight_body_bytes
            .fetch_add(EST_BODY_BYTES, Ordering::AcqRel);
    }

    /// B3 wire-cap: release `n` pipeline items' charges - every exit
    /// from a worker's in-flight deque (outcome, requeue, shed, abort)
    /// releases exactly what dispatch charged.
    ///
    /// Saturating, not wrapping. The charge/release pairing is symmetric
    /// by construction (one charge per item in a worker's deque), but one
    /// asymmetry is enough to wrap this counter to ~u64::MAX, after which
    /// `wire_over_cap` answers true forever and every worker in the pool
    /// is pinned at pipeline depth one for the rest of the run. A
    /// saturating floor degrades into "throttles slightly early" instead.
    pub(super) fn release_wire(&self, n: usize) {
        let owed = EST_BODY_BYTES.saturating_mul(n as u64);
        let _ = self
            .inflight_body_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                // A worker only ever releases charges it holds, and the
                // global is the sum of all live charges, so this holds for
                // every value we can observe - concurrency included. It
                // fires only when some path has put an UNCHARGED item into
                // a worker's pipeline, which is the whole bug class.
                debug_assert!(
                    v >= owed,
                    "wire-cap over-release: {v} charged, releasing {owed}"
                );
                Some(v.saturating_sub(owed))
            });
    }

    /// B3 wire-cap: true when topping up past the one-in-flight floor
    /// must pause. `cap` 0 = uncapped (default outside budgeted runs).
    pub(super) fn wire_over_cap(&self, cap: u64) -> bool {
        cap > 0 && self.inflight_body_bytes.load(Ordering::Acquire) >= cap
    }

    /// The wire cap just refused a top-up: mark the graph, at most once
    /// per 30 s for the whole run. The check runs on every pipeline
    /// top-up, and an engaged cap answers true on all of them - the gate
    /// is what keeps a slow-disk run from writing nothing but this.
    pub(super) fn note_wire_cap(&self) {
        let Some(live) = &self.live else {
            return;
        };
        let now = now_ms();
        let prev = self.wire_note_at.load(Ordering::Relaxed);
        if now.saturating_sub(prev) >= 30_000
            && self
                .wire_note_at
                .compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            live.note_run(
                "wire",
                "in-flight data reached its memory ceiling - fetching waits \
                 for decode and the disk to catch up",
            );
        }
    }

    /// Tail duplicate-dispatch: pick an article in flight on another
    /// server that is either much slower than `me` or has been sitting on
    /// this article suspiciously long.
    ///
    /// M2c.4 endgame fan-out: when the job's non-terminal remainder is
    /// small and an in-flight article has already 430'd somewhere, the
    /// rate/staleness conditions no longer apply - every backbone that
    /// hasn't tried it races it at once (each at most once, via
    /// `dup_servers`), so the last few poisoned articles reach their
    /// unanimous-430 Missing verdict in one round-trip instead of
    /// walking the server ladder hop by hop (measured ~7 s of 0.0 MB/s
    /// tail on the damaged leg). `required` keeps fill-server economics:
    /// a level-N server only joins once every live lower level 430'd.
    ///
    /// Opt-in tail fan-out (`PoolConfig::tail_fanout`): in the endgame,
    /// an IDLE primary also races HEALTHY in-flight articles - the last
    /// few articles sitting on whichever connection happened to grab
    /// them, while everyone else has gone idle. Gates: endgame only,
    /// level 0 only (block-account bytes are never spent on speed),
    /// empty pipeline only (a busy worker is not the idle capacity this
    /// spends), article on the wire ≥ [`TAIL_FANOUT_MIN_AGE`], and each
    /// server races an article at most once (`dup_servers`) - which also
    /// spreads idle workers across stragglers instead of piling them
    /// all on one. Unlike the two rules above this one may race an
    /// article on ANOTHER CONNECTION OF ITS OWN SERVER: at the tail the
    /// enemy is usually one degraded TCP session, not a slow provider,
    /// and a fresh session to the same host routinely beats it. The
    /// owner connection can never dup itself - the article rides its
    /// pipeline, so its `window_used` is never 0.
    pub(super) fn pick_dup(
        &self,
        me: usize,
        my_bit: u32,
        group_bits: u32,
        required: u32,
        pipe: Pipeline,
        level: u32,
    ) -> Option<Work> {
        // N6 idle-spin gate: this server's last idle walk of the whole
        // map picked nothing and the map has not changed since - skip
        // the walk instead of re-taking the `done` + `inflight` mutexes
        // every 25 ms x idle-workers (at queue-dry that was ~4000 full
        // walks/s on a 100-conn fleet, squarely against the completion
        // paths). Time-capped at [`SCAN_RETRY_MS`] because staleness and
        // fan-out age arm by CLOCK, not by map change; the gen snapshot
        // is taken before the walk so any concurrent mutation
        // invalidates the record it leaves behind. Worst case a
        // speculative dup is delayed one retry window, never lost.
        let now_ms = self.start.elapsed().as_millis() as u64;
        let map_gen = self.inflight_gen.load(Ordering::Acquire);
        let futile_at = self.dup_futile[me].load(Ordering::Relaxed);
        if futile_at != u64::MAX
            && now_ms.saturating_sub(futile_at) < SCAN_RETRY_MS
            && self.dup_futile_gen[me].load(Ordering::Relaxed) == map_gen
        {
            return None;
        }
        // Early fan-out experiment: the tail latch flips at the exact
        // moment idle capacity first exists (a primary found the queue
        // dry with work still in flight), which with a big fleet is
        // long before pending reaches ENDGAME_MAX - 48 connections at
        // window 4 dry the queue with ~190 articles still on the wire.
        // The idle-only and once-per-server gates below keep the spend
        // self-limiting at any pending count.
        let endgame = self.pending.load(Ordering::Acquire) <= ENDGAME_MAX
            || (self.tail_fanout_early && self.tail_started.lock_ok().is_some());
        // PER-WORKER, like `faster_can_take` above. `rate()` is a server's
        // whole-run byte total over wall time, so it measures its share of
        // the job, and that share is set mostly by how many connections it
        // was given. Comparing shares made a big server judge a smaller one
        // "half my speed" when every connection was equally fast, so its
        // idle workers duplicated the smaller server's in-flight articles
        // as a matter of course - fetching those bytes twice. Dividing by
        // live workers asks the question the heuristic means to ask: is
        // this article's owner actually slower. WINDOWED since M7b.2
        // (steer module): the whole-run average judged "slow owner" with
        // evidence as stale as the run is long.
        let my_rate = self.steer_rate_per_worker(me);
        // Hedge experiment: adaptive staleness bound, and a cap on how
        // many dups staleness ALONE may issue - one per 20 completions
        // plus a small burst allowance. The rate rule and the endgame
        // are never capped; the cap exists so EWMA jitter on a link
        // with occasional slow articles cannot become a dup storm.
        let stale_bound = self.hedge_stale_bound();
        // M7b.2 hygiene cap (design 5.2): at the cap every SPECULATIVE
        // picker stops arming; ladder dups stay exempt (verdicts, not speed).
        let capped = self.dup_spend_capped();
        let done = self.done.lock_ok();
        let hedges_ok = !self.hedge
            || self.hedges_issued.load(Ordering::Relaxed) < 4 + done.count() as u64 / 20;
        let mut inflight = self.inflight.lock_ok();
        // (id, owner_rate, ladder-progress, stale-only) - endgame prefers
        // the article CLOSEST to its verdict, normal phase the slowest
        // owner; stale-only marks a hedge for the issue-rate cap.
        let mut best: Option<(&Arc<str>, f64, u32, bool)> = None;
        // Tail fan-out candidates: fewest racers first, then longest on
        // the wire - so the second idle worker picks the second
        // straggler, not the same one.
        let mut fan: Option<(&Arc<str>, u8, Instant)> = None;
        for (id, inf) in inflight.iter() {
            if inf.tried_430 & my_bit != 0
                || inf.dup_servers & my_bit != 0
                || inf.tried_fail & my_bit != 0
                || done.contains(inf.ord)
            {
                continue;
            }
            if endgame && inf.tried_430 != 0 {
                if inf.server == me {
                    continue;
                }
                if pipe.payload > 0 {
                    continue; // ladder probes never ride behind a BODY
                }
                if inf.tried_430 & required != required {
                    continue; // fill gate: lower levels first
                }
                // TODO 96.4: a probe already found a holder, so this
                // article's verdict is settled - it is not Missing, and
                // no further question can change that.
                if inf.found != 0 {
                    continue;
                }
                let progress = inf.tried_430.count_ones();
                if best.is_none_or(|(_, _, p, _)| progress > p) {
                    best = Some((id, 0.0, progress, false));
                }
                continue;
            }
            // Tail fan-out (opt-in): endgame, healthy article, idle
            // primary. Same-server racing allowed - see the doc above.
            // An article younger than the age floor falls through to the
            // normal rules instead, so switching this on never REMOVES a
            // dup the rate rule would have issued.
            //
            // Refetch legs are exempt (`tried_fail != 0`): a CRC-steer
            // (or plain failure) requeue is already a recovery fetch on
            // a deliberately chosen server, and the same-server
            // allowance made the recovering twin race ITS OWN steered
            // refetches - on a damage leg that dup-storms up to one
            // lost race per steered article (measured 33-43 dups, 0
            // won, +15-18% raw transfer on the corrupt/splitbrain/
            // corruptstorm matrix legs). Such an article still falls
            // through to the slow-owner/stale rules, which a third
            // server may legitimately win with.
            if self.tail_fanout
                && endgame
                && !capped
                && !self.speculative_blocked(my_bit, level)
                && pipe.used == 0
                && inf.tried_fail == 0
                && inf.dispatched.elapsed() >= TAIL_FANOUT_MIN_AGE
            {
                if fan.is_none_or(|(_, d, t)| (inf.dups, inf.dispatched) < (d, t)) {
                    fan = Some((id, inf.dups, inf.dispatched));
                }
                continue;
            }
            if inf.server == me {
                continue;
            }
            if inf.dups >= 1 {
                continue;
            }
            // Block-account economy: a FILL server never races on speed.
            // It only ever joins the endgame 430-ladder above, which is
            // gated on every live lower level having already missed. Its
            // bytes are paid for per gigabyte, so spending them to
            // re-fetch an article a primary is already delivering is a
            // straight loss - and it became reachable the moment the
            // comparison went per-worker, because a fill server has FEW
            // connections and so looks fast by that measure exactly when
            // it is least worth using. §5.7 widens the gate to any
            // server flagged block_account, whatever its level.
            if self.speculative_blocked(my_bit, level) {
                continue;
            }
            let owner_rate = self.steer_rate_per_worker(inf.server);
            // With race_envelope armed, the whole-run 2x slow-owner rule
            // retires in favor of the envelope race + per-owner hedge
            // bound - see `steer::speculative_arm` for the full gates.
            let arm =
                self.speculative_arm(inf, pipe.used, my_rate, owner_rate, stale_bound, capped);
            if let Some(stale_only) = arm
                && (!stale_only || hedges_ok)
                && best.is_none_or(|(_, r, _, _)| owner_rate < r)
            {
                best = Some((id, owner_rate, 0, stale_only));
            }
        }
        // Ladder probes and slow-owner races keep priority - they carry
        // verdict or recovery value; the fan-out is pure speculation.
        if let Some((_, _, _, true)) = best {
            self.hedges_issued.fetch_add(1, Ordering::Relaxed);
        }
        // A ladder pick is the only one whose bytes buy a VERDICT rather
        // than a copy of a body someone else may still deliver - which is
        // why it alone rides a pipeline that already holds probes, and why
        // the item it hands back is marked as one.
        let is_ladder = matches!(best, Some((_, _, p, false)) if p > 0);
        let rule = match best {
            _ if is_ladder => "ladder",
            Some((_, _, _, true)) => "stale",
            Some(_) if self.race_envelope => "envelope",
            Some(_) => "slow-owner",
            None => "fanout",
        };
        let Some(id) = best
            .map(|(id, _, _, _)| id.clone())
            .or_else(|| fan.map(|(id, _, _)| id.clone()))
        else {
            // Record the futile walk - but only from a MAXIMALLY
            // permissive one, so its empty answer covers every other
            // shape of call this server can make: a fully idle picker
            // (the fan-out and envelope arms are idle-only) with no
            // fill gate (`required` bits only ever EXCLUDE ladder
            // candidates). Gen first, then the timestamp that arms the
            // record.
            if pipe.used == 0 && required == 0 {
                self.dup_futile_gen[me].store(map_gen, Ordering::Relaxed);
                self.dup_futile[me].store(now_ms, Ordering::Relaxed);
            }
            return None;
        };
        let inf = inflight.get_mut(&id).unwrap();
        if std::env::var_os("NZBFAST_POOL_DEBUG").is_some() {
            eprintln!(
                "[pick-dup] {id}: rule={rule} me={me} owner={} owner_fail={:#b} age={:?}",
                inf.server,
                inf.tried_fail,
                inf.dispatched.elapsed()
            );
        }
        // TODO 96.4: a ladder dup exists to buy a VERDICT, so under
        // `stat_probe` it asks with STAT and can never buy an article
        // twice. Sparing the first racer (letting one of them still
        // deliver in a single round trip) was measured too: it leaves
        // two thirds of the duplicate bodies in place, because the
        // first racer to reach a given article is usually one that has
        // it. All or nothing is the honest pair of arms.
        let probe = is_ladder && self.stat_probe;
        inf.dups += 1;
        inf.dup_servers |= group_bits;
        self.dups_issued.fetch_add(1, Ordering::Relaxed);
        self.mirror_dup_issued();
        self.note_race_burst();
        Some(Work {
            id,
            attempts: 0,
            promoted: false,
            tried_430: 0,
            tried_fail: 0,
            dup: true,
            prebyte_expiries: 0,
            soft_430: 0,
            fenced: false,
            rearms: 0,
            ladder: is_ladder,
            probe,
            age_days: inf.age_days,
            part: inf.part,
            ord: inf.ord,
        })
    }

    /// TTFB-suspicion (TODO 115): the owner's read reported pre-byte
    /// silence past the suspicion bound. Flag the article for
    /// [`Self::pick_suspect_dup`]. The entry may already be gone (the
    /// timer races the read's own completion) - that's a no-op.
    pub(super) fn mark_suspect(&self, id: &str) {
        if let Some(inf) = self.inflight.lock_ok().get_mut(id) {
            inf.suspect = true;
            self.suspect_pending.store(true, Ordering::Release);
            if std::env::var_os("NZBFAST_POOL_DEBUG").is_some() {
                eprintln!("[ttfb-hedge] suspect {id} at {:?}", self.start.elapsed());
            }
        }
    }

    /// TTFB-suspicion dup (TODO 115, gated on [`PoolConfig::ttfb_hedge`]):
    /// race a suspect in-flight article NOW, ahead of queued work,
    /// instead of letting its owner wait out the full adaptive pre-byte
    /// budget and a requeue round-trip. Same machinery as every other
    /// dup - first answer wins, `done` arbitrates, the owner's read is
    /// never killed - and the same economics as the stale rule: primaries
    /// only (fill bytes are never spent on speculation), one dup per
    /// article, each server at most once, and every pick counts against
    /// the hedge issue-rate cap so a jittery link cannot dup-storm.
    /// Unlike the stale rule this MAY race same-server: the owner is a
    /// stalled TCP session, and a sibling session to the same host
    /// routinely answers in one round-trip (the tail fan-out precedent).
    /// And like the tail fan-out, IDLE pickers only (empty pipeline):
    /// a busy worker's dup displaces queued work, which prices real
    /// capacity - measured +6-15% wall on the jitter safety rig when
    /// busy pickers joined, because a dup fetch can eat the same
    /// pre-byte delay that raised the suspicion. Mid-run the pool is
    /// capacity-bound and the hedge cannot win wall time there anyway;
    /// its whole measured payout is at the supply-limited tail, where
    /// idle pickers exist by definition.
    pub(super) fn pick_suspect_dup(
        &self,
        my_bit: u32,
        group_bits: u32,
        level: u32,
        window_used: usize,
    ) -> Option<Work> {
        if !self.ttfb_hedge
            || self.speculative_blocked(my_bit, level)
            || window_used > 0
            || !self.suspect_pending.load(Ordering::Acquire)
            || self.dup_spend_capped()
        {
            return None;
        }
        let done = self.done.lock_ok();
        if self.hedges_issued.load(Ordering::Relaxed) >= 4 + done.count() as u64 / 20 {
            return None; // capped; the budget path still rescues
        }
        let mut inflight = self.inflight.lock_ok();
        // Oldest suspicion first: it has the least budget left.
        let picked: Option<Arc<str>> = inflight
            .iter()
            .filter(|(_, inf)| {
                inf.suspect
                    && inf.dups == 0
                    && inf.tried_430 & my_bit == 0
                    && inf.dup_servers & my_bit == 0
                    && inf.tried_fail & my_bit == 0
                    && !done.contains(inf.ord)
            })
            .min_by_key(|(_, inf)| inf.dispatched)
            .map(|(id, _)| id.clone());
        let Some(id) = picked else {
            // Nothing suspect is still unraced - stop paying the scan
            // until a new suspicion fires.
            self.suspect_pending.store(false, Ordering::Release);
            return None;
        };
        let inf = inflight.get_mut(&id).unwrap();
        inf.dups += 1;
        inf.dup_servers |= group_bits;
        self.hedges_issued.fetch_add(1, Ordering::Relaxed);
        self.dups_issued.fetch_add(1, Ordering::Relaxed);
        self.mirror_dup_issued();
        self.note_race_burst();
        if std::env::var_os("NZBFAST_POOL_DEBUG").is_some() {
            eprintln!("[ttfb-hedge] dup-race {id} at {:?}", self.start.elapsed());
        }
        Some(Work {
            id,
            attempts: 0,
            promoted: false,
            tried_430: 0,
            tried_fail: 0,
            dup: true,
            prebyte_expiries: 0,
            soft_430: 0,
            fenced: false,
            rearms: 0,
            ladder: false,
            probe: false,
            age_days: inf.age_days,
            part: inf.part,
            ord: inf.ord,
        })
    }
}
