// TODO 106: the M11 seek/steer control handle - QueueControl and its
// whole impl - came out of pool.rs whole under the size gate. A child
// module sees the parent's private items (Shared and friends), so the
// body is untouched; only `attach` widened to pub(super) for the
// call sites in pool.rs and the sibling test modules.
//
// The steer's HANDOFF RECORD followed it here (sweep 8, M2/M8 round):
// `Handed` and the `stash_handed` that fills it existed only to be
// read by `note_decoded` below, and pool.rs had three lines of margin
// under its size-gate entry. Moved whole, bodies untouched apart from
// the new `spent` member the M8 fix carries; `stash_handed` widened to
// pub(super) for its one caller in pool/session.rs.

use super::*;

/// Synthesized-numbering latch for the part-identity gate in
/// [`QueueControl::note_decoded`] (22 Aug 2026, tv4-rot1). An NZB whose
/// declared segment numbers are not the yEnc parts (a rotated or
/// synthesized ladder - the obfuscated norm) trips the gate on EVERY
/// article, and each trip is a full extra BODY that no dup or hedge
/// tally shows: 2x the payload on the wire, identically on five
/// releases. The tell that separates it from a split-brain: `first`
/// holds the part a steered id's first copy carried, and a refetch from
/// ANOTHER server repeating it is two backbones agreeing that the NZB's
/// numbers are the lie. One server lying comes back right and the gate
/// stays armed; two agreeing set `off` for the rest of the run. pcrc32
/// and the echoed-id check keep guarding either way.
///
/// `first` records the part AND the deliverer's backbone (`group_bits`),
/// because "another server" has to be checked, not assumed: a tail
/// fan-out dup on the first server's own connection (or a sibling on
/// its backbone) can win the re-claim after the un-claim and repeat
/// the same wrong part. That is one backbone talking twice, and it
/// must not stand the gate down (bug sweep 22 Aug 2026).
#[derive(Default)]
pub(super) struct PartLatch {
    pub(super) first: std::sync::Mutex<HashMap<Arc<str>, (u32, u32)>>,
    /// Files ([`Work::file`]) whose gate has stood down: two backbones
    /// agreed that file's numbering is synthesized. Per FILE, not per
    /// run (F-09): one mislabelled file must not switch off the wrong-
    /// part check for every other file in the job. Reached only through
    /// [`PartLatch::is_off`] and [`PartLatch::stand_down`], which is
    /// what keeps the unscoped sentinel out of it - see
    /// [`PartLatch::scoped`].
    pub(super) off: std::sync::Mutex<HashSet<u32>>,
    /// Part-mismatch steers issued (each one an extra BODY).
    pub(super) steers: AtomicU64,
}

impl PartLatch {
    /// Is this [`Work::file`] a file at all? `u32::MAX` is
    /// [`ArticleReq::file`]'s "unscoped" sentinel - a side fetch, a
    /// probe - and it is not a file index, it is the ABSENCE of one.
    /// Every unscoped request in a run shares that one value, so
    /// admitting it to a set keyed BY file would make one request's
    /// two-backbone agreement stand the gate down for every other
    /// unscoped request beside it: F-09's run-wide latch by another
    /// name, at a one-request bar, on whatever set happened to be
    /// batched together. So an unscoped request can neither EARN a
    /// stand-down nor INHERIT one, and pays its own refetch per
    /// article - which is the honest price of not knowing which file
    /// the evidence belongs to. The per-ID evidence still stands: an
    /// agreed refetch is OWNED either way (see `note_decoded`), so the
    /// cost is bounded at one extra body per id and never a loop.
    ///
    /// `pool::park` opts the same sentinel out of the holds machinery
    /// (`FilePark::defers`, `group_of`) for the same reason and by the
    /// same test.
    ///
    /// UNREACHABLE TODAY, and that is a property of the callers rather
    /// than of this type, so it is guarded here instead of relied on:
    /// the only production caller of `QueueControl::note_decoded` is
    /// `get::workers`, whose requests all carry a real slot index
    /// (`get::plan`), while every unscoped producer - the three
    /// `repair::volume_reqs` side fetches, the post tool, nettools -
    /// runs on a pool whose `crc_steer` is off, so nothing is ever
    /// stashed in `Shared::handed` and this seam never runs. Verified
    /// 31 Aug 2026. What makes it true for the side fetches is
    /// `repair::sidefetch::strip_side_pool_seams` (pinned by
    /// `a_steer_config_side_fetch_still_completes`), and that strip
    /// clears `crc_steer` for an unrelated reason - the 7 Aug 2026
    /// daemon wedge, where the side consumer's missing verdict parked
    /// every delivery forever - so it is a coincidence this file may
    /// not lean on.
    const fn scoped(file: u32) -> bool {
        file != u32::MAX
    }

    /// Has this file's gate stood down? Never for an unscoped request.
    pub(super) fn is_off(&self, file: u32) -> bool {
        Self::scoped(file) && self.off.lock_ok().contains(&file)
    }

    /// Two disjoint backbones proved this file's segment numbering is
    /// synthesized: stand its gate down. True only the FIRST time, so
    /// the caller logs once; false for an unscoped request, which
    /// cannot earn one.
    pub(super) fn stand_down(&self, file: u32) -> bool {
        Self::scoped(file) && self.off.lock_ok().insert(file)
    }

    /// Has ANY file's gate stood down (the ledger summary)?
    pub(super) fn any_off(&self) -> bool {
        !self.off.lock_ok().is_empty()
    }
}

/// TODO 114 consumer steer: one delivered body awaiting the consumer's
/// decode verdict (see `Shared::handed`). `work` is the rebuilt Work a
/// bad verdict requeues - always `dup: false`, whatever copy won the
/// race - and `server`/`group_bits` identify the deliverer so the
/// steer can exclude its whole backbone.
pub(super) struct Handed {
    work: Work,
    server: usize,
    group_bits: u32,
    /// The delivered copy was a DUP dispatch that won the claim. A
    /// dup's bad copy never owns damage and never spends the steer
    /// budget (mirror of the pool-side gate's silent dup discard) -
    /// it is requeued unconditionally, because the copy that should
    /// own the outcome may already have lost the claim race inside
    /// the verdict window.
    dup_copy: bool,
    /// M8 (sweep 8): the article's `spent` mask as it stood the instant
    /// BEFORE the provisional `claim_done` that delivered this body.
    ///
    /// `claim_done` drops the spent entry - correct for a terminal
    /// article, wrong for one whose decode verdict may still send it
    /// back down the ladder. Those bits are the evidence that opens a
    /// fill tier (`gates::other_can_take`, and `next_work`'s pickup
    /// gate), so without this copy a bad-body steer asks "can anyone
    /// else take it?" with the answer already erased and refuses a
    /// retry a healthy peer could have served. Immutable for the
    /// verdict's lifetime; the live map is repaired only if the steer
    /// actually happens.
    spent: u32,
}

impl Shared {
    /// TODO 114 consumer steer: park a claimed, about-to-be-delivered
    /// body's Work in `handed` so [`QueueControl::note_decoded`] can
    /// requeue it after claim (see the field doc). Always `dup: false`
    /// - whichever copy won the race, a steer requeues an original;
    /// `dup_copy` remembers which kind won so a dup's bad copy can be
    /// discarded rather than owned.
    pub(super) fn stash_handed(&self, w: &Work, ctx: ServerCtx, spent: u32) {
        self.handed.lock_ok().insert(
            w.id.clone(),
            Handed {
                work: Work {
                    id: w.id.clone(),
                    attempts: w.attempts,
                    promoted: w.promoted,
                    tried_430: w.tried_430,
                    tried_fail: w.tried_fail,
                    dup: false,
                    prebyte_expiries: w.prebyte_expiries,
                    soft_430: w.soft_430,
                    recheck_430: 0,
                    recheck_at: 0,
                    fenced: false,
                    rearms: w.rearms,
                    ladder: false,
                    probe: false,
                    age_days: w.age_days,
                    part: w.part,
                    file: w.file,
                    ord: w.ord,
                },
                server: ctx.idx,
                group_bits: ctx.group_bits,
                dup_copy: w.dup,
                spent,
            },
        );
    }
}

/// Test-only rendezvous INSIDE the steer's publish/un-claim window
/// (sweep 8, M2). Absent from production builds entirely.
///
/// The invariant the M2 fix installs - a steered refetch is never
/// visible to a draining worker while its old done bit is still set -
/// is a property of a window, and a window cannot be observed from
/// outside it. The regression parks the verdict thread here, plays the
/// worker's adoption against it, and releases; without a barrier the
/// same test is a race that passes for the wrong reason. Keyed by
/// message-id so a threaded test runner cannot cross two legs.
#[cfg(test)]
pub(super) static STEER_WINDOW: std::sync::Mutex<Option<(Arc<str>, Arc<std::sync::Barrier>)>> =
    std::sync::Mutex::new(None);

/// §146 census currency (C4): one refusal-walker, named by message-id
/// AND by its completion ordinal. The pair must travel together from
/// [`QueueControl::verdict_walkers`] to
/// [`QueueControl::give_up_covered`]: an article in transit between a
/// refusal and its requeue is in neither the queue nor the inflight
/// map when the commit runs, so the ordinal the census recorded is the
/// only way the claim can still name its bit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Walker {
    /// R9: the interned id. A census taken over the queue and the
    /// in-flight map hands back handles, not copies - a full-queue
    /// walk at 100k pending used to allocate the whole id set twice
    /// (here, and again in `give_up_covered`'s claim set).
    pub id: Arc<str>,
    pub ord: u32,
}

/// M11 seek re-prioritization: a live handle to a running fetch's pending
/// queue. The streaming layer promotes the articles under a player's seek
/// point to the queue front; workers pick them up on their next pop.
/// Holds the pool by Weak - the handle can outlive the run harmlessly
/// (promote becomes a no-op once the pool is gone). Anything the caller
/// still needs to read AFTER the run returns has to be latched on the
/// handle itself; see `drained`.
#[derive(Default)]
pub struct QueueControl {
    shared: std::sync::Mutex<Option<std::sync::Weak<Shared>>>,
    /// Latched copy of `Shared::draining`. The pool's last strong `Arc` dies
    /// with the fetch call, so by the time the engine asks whether the run
    /// wound down gracefully the Weak above no longer upgrades - the answer
    /// has to live on the handle the caller still holds.
    drained: AtomicBool,
}

impl QueueControl {
    pub(super) fn attach(&self, sh: &Arc<Shared>) {
        *self.shared.lock_ok() = Some(Arc::downgrade(sh));
        // A handle reused for a second run starts that run undrained; the
        // latch below describes the pool currently attached, not a past one.
        self.drained.store(false, Ordering::Release);
    }

    /// Move every PENDING article whose message-id is in `ids` to the
    /// front of the queue, in the ORDER GIVEN - the streaming layer passes
    /// the requested byte range's articles seek-point-first, and that is
    /// the order the player will read them in. (Queue relative order is
    /// deliberately NOT preserved: a tail burst leaves file-end articles
    /// ahead of mid-file ones, and a promoted span crossing that boundary
    /// would otherwise download tail-first while the player starves at
    /// the seek point.) Articles already fetched or in flight are
    /// unaffected. Returns how many were moved.
    pub fn promote(&self, ids: &[Arc<str>]) -> usize {
        self.promote_opts(ids, true)
    }

    /// [`Self::promote`] with the stream-mode side effect explicit.
    /// `engage_stream: false` reorders the queue WITHOUT flipping the
    /// pool into shallow pipelines: the extractor's offset-0 probe wants
    /// its article sooner, but nothing blocks on it, and a scrambled
    /// many-volume set probes once per slot - each 60 s stream-mode
    /// linger would chain into the whole download running shallow.
    pub fn promote_opts(&self, ids: &[Arc<str>], engage_stream: bool) -> usize {
        let Some(sh) = self
            .shared
            .lock_ok()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        else {
            return 0;
        };
        // Streaming-layer promotes (and the 7z chase, whose worker
        // blocks on the footer) engage stream mode (shallow pipelines)
        // even when nothing moves.
        if engage_stream {
            sh.note_stream();
        }
        if ids.is_empty() {
            return 0;
        }
        // The queue is a tokio Mutex popped briefly by workers; we're on a
        // plain OS thread (the /stream handler). Bounded try_lock keeps
        // this best-effort - a missed promotion just retries on the next
        // blocked-read window.
        let mut tries = 0;
        let mut q = loop {
            match sh.queue.try_lock() {
                Ok(g) => break g,
                Err(_) if tries < 20 => {
                    tries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(_) => return 0,
            }
        };
        if q.is_empty() {
            return 0;
        }
        // Rank = position in the caller's range order (first occurrence
        // wins for duplicate ids).
        let mut rank: HashMap<&str, usize> = HashMap::with_capacity(ids.len());
        for (r, id) in ids.iter().enumerate() {
            rank.entry(&**id).or_insert(r);
        }
        let mut front: Vec<(usize, Work)> = Vec::new();
        let mut rest: VecDeque<Work> = VecDeque::with_capacity(q.len());
        for mut w in q.drain(..) {
            if let Some(&r) = rank.get(&*w.id) {
                w.promoted = true;
                front.push((r, w));
            } else {
                rest.push_back(w);
            }
        }
        let n = front.len();
        front.sort_by_key(|(r, _)| *r);
        q.extend(front.into_iter().map(|(_, w)| w));
        q.append(&mut rest);
        if n > 0 {
            // Count EVERY promoted item still queued (front run + shed
            // re-inserts + prior promotes), record the promote's id set
            // for the shed immunity check, then wake blocked readers so
            // non-promoted in-flight transfers yield the line.
            let total = q.iter().filter(|w| w.promoted).count();
            sh.promoted_pending.store(total, Ordering::Release);
            *sh.promoted_ids.lock_ok() = ids.iter().cloned().collect();
            sh.promote_gen.send_modify(|g| *g += 1);
        }
        n
    }

    /// Responses so far that advanced an article without resolving it
    /// (see [`Shared::deferred`]). A caller's stall watchdog must count
    /// a change here as liveness: a refusal-only run can spend a whole
    /// pass in the `soft_430` confirming repeat, moving neither decoded
    /// bytes nor the outstanding count while working perfectly. `None`
    /// once the run's pool is gone - there is nothing left to stall.
    pub fn deferred(&self) -> Option<u64> {
        // lock_ok, like every other accessor of this mutex: this runs
        // inside the stall watchdog, and a poisoned lock panicking here
        // would silently kill the exact protection it feeds.
        Some(
            self.shared
                .lock_ok()
                .as_ref()
                .and_then(std::sync::Weak::upgrade)?
                .deferred
                .load(Ordering::Relaxed),
        )
    }

    /// M11 stream mode: a live /stream reader touched the hub. Workers
    /// cap their pipelines to `stream_window()` while this stays fresh
    /// (see `Shared::stream_until`), so seek promotions preempt instead
    /// of queueing behind hundreds of MB of pipelined responses. Called
    /// on every reader read - cheap (one mutex + one atomic store).
    pub fn note_stream_active(&self) {
        if let Some(sh) = self
            .shared
            .lock_ok()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        {
            sh.note_stream();
        }
    }

    /// Can the ATTACHED fetch run still deliver any of `ids` - is one of
    /// them pending in the queue or on the wire right now? `None` means
    /// no pool is attached at all (between runs, or the run drained -
    /// where settle-side repair may still cover the bytes and the caller
    /// must decide how long repair deserves). The /stream reader uses a
    /// `Some(false)` here to conclude a blocked span is terminally
    /// undeliverable, so every unsure path with a live pool - an empty
    /// id list, a queue lock that could not be taken - answers
    /// `Some(true)`, never `Some(false)`.
    ///
    /// Racy by construction and deliberately so: an article can sit
    /// between the queue pop and the in-flight registration for the
    /// length of a `send_body` await, invisible to both checks. Callers
    /// must therefore require consecutive negative verdicts spaced
    /// longer than that window (the stream reader votes 1 s apart)
    /// before acting.
    pub fn any_live(&self, ids: &[Arc<str>]) -> Option<bool> {
        let sh = self
            .shared
            .lock_ok()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)?;
        if ids.is_empty() {
            return Some(true);
        }
        {
            let inf = sh.inflight.lock_ok();
            if ids.iter().any(|id| inf.contains_key(&**id)) {
                return Some(true);
            }
        }
        // A body that already ARRIVED and is parked on a full outcome
        // channel is the opposite of dead - it is seconds from being
        // real bytes. Without this, disk backpressure long enough to
        // block the handoff send made a successfully fetched article
        // look terminal and the stream served zeros for bytes it
        // already had.
        {
            let ok = sh.done_ok.lock_ok();
            if ids.iter().any(|id| ok.contains(&**id)) {
                return Some(true);
            }
        }
        // A bad-body steer parked in the inbox is a refetch WAITING for
        // a worker's next top-up, not a dead article. That top-up is
        // usually ms away, but with every worker blocked in long
        // pipelined body reads it can be tens of seconds out - long
        // enough for the dead-span verdict to zero-fill the very span
        // the steer is about to rewrite.
        {
            let inbox = sh.steer_inbox.lock_ok();
            if !inbox.is_empty() && ids.iter().any(|id| inbox.iter().any(|w| w.id == *id)) {
                return Some(true);
            }
        }
        // Same bounded try_lock discipline as `promote`: the caller is a
        // plain OS thread, the queue a tokio Mutex popped by workers.
        let mut tries = 0;
        let q = loop {
            match sh.queue.try_lock() {
                Ok(g) => break g,
                Err(_) if tries < 20 => {
                    tries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(_) => return Some(true),
            }
        };
        let set: HashSet<&str> = ids.iter().map(|s| &**s).collect();
        Some(q.iter().any(|w| set.contains(&*w.id)))
    }

    /// In-stream PAR2 deferral (issue #14): permanently remove every
    /// PENDING article whose message-id is in `ids` from the queue, and
    /// mark each one terminal WITHOUT emitting a `FetchOutcome` - the
    /// caller owns the accounting for exactly the ids returned. Articles
    /// already in flight (or already resolved) are untouched and resolve
    /// through their normal outcome; a duplicate call for an id already
    /// cancelled is a no-op. Best-effort like `promote`: a missed lock
    /// returns an empty list and the caller may retry.
    pub fn cancel(&self, ids: &HashSet<Arc<str>>) -> Vec<Arc<str>> {
        let Some(sh) = self
            .shared
            .lock_ok()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        else {
            return Vec::new();
        };
        if ids.is_empty() {
            return Vec::new();
        }
        // Same bounded try_lock discipline as `promote`: callers are the
        // decode OS threads, and the queue is a tokio Mutex popped by
        // workers.
        let mut tries = 0;
        let mut q = loop {
            match sh.queue.try_lock() {
                Ok(g) => break g,
                Err(_) if tries < 20 => {
                    tries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(_) => return Vec::new(),
            }
        };
        let mut removed: Vec<Work> = Vec::new();
        let mut kept: VecDeque<Work> = VecDeque::with_capacity(q.len());
        for w in q.drain(..) {
            if ids.contains(&*w.id) {
                removed.push(w);
            } else {
                kept.push_back(w);
            }
        }
        *q = kept;
        // A cancelled item may have been seek-promoted; keep the promoted
        // count honest so the shed immunity check stays accurate.
        if removed.iter().any(|w| w.promoted) {
            let total = q.iter().filter(|w| w.promoted).count();
            sh.promoted_pending.store(total, Ordering::Release);
        }
        drop(q);
        // Terminal bookkeeping OUTSIDE the queue lock (claim_done takes
        // the done mutex; complete_one may fire the finished watch when
        // the cancelled articles were the last pending work). The Work
        // items are stashed whole so `requeue` can resurrect them.
        let mut out = Vec::with_capacity(removed.len());
        for w in removed {
            if sh.claim_done(&w.id, w.ord) {
                sh.complete_one();
                out.push(w.id.clone());
                sh.cancelled.lock_ok().insert(w.id.clone(), w);
            }
        }
        out
    }

    /// Undo a [`cancel`](Self::cancel): put previously-cancelled articles
    /// back into the queue, un-terminal. All-or-nothing per call for the
    /// ids it finds in the stash: on any obstacle (run already finished,
    /// draining, queue lock unobtainable) everything is rolled back and 0
    /// is returned - the caller keeps its deferred accounting. Only ids
    /// a prior `cancel` returned can ever be requeued; unknown ids are
    /// ignored (and do not count toward the return value).
    pub fn requeue(&self, ids: &[Arc<str>]) -> usize {
        let Some(sh) = self
            .shared
            .lock_ok()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        else {
            return 0;
        };
        if sh.aborted.load(Ordering::Acquire) || sh.draining.load(Ordering::Acquire) {
            return 0;
        }
        let works: Vec<Work> = {
            let mut stash = sh.cancelled.lock_ok();
            ids.iter().filter_map(|id| stash.remove(&**id)).collect()
        };
        if works.is_empty() {
            return 0;
        }
        let put_back = |ws: Vec<Work>| {
            let mut stash = sh.cancelled.lock_ok();
            for w in ws {
                stash.insert(w.id.clone(), w);
            }
        };
        // Pending BEFORE the finished check: with the count raised, a
        // concurrent complete_one cannot reach zero and fire finished
        // under us. If finished already fired, the fleet is winding down
        // and nothing would ever fetch these - roll back.
        // A rollback's fetch_sub can be the one that lands pending on
        // zero (a real completion slipped in between our add and sub, and
        // saw an inflated count) - it must then reach the same drained
        // verdict as complete_one, or the fleet waits forever.
        let sub_pending = |n: usize| {
            if sh.pending.fetch_sub(n, Ordering::AcqRel) == n {
                sh.finish_if_drained();
            }
        };
        {
            // Raise and check under `finish_gate` (see the field's doc):
            // a completion whose fetch_sub already landed pending on
            // zero but whose finished-send is still pending re-reads the
            // count under this same gate, so it either sends before our
            // check (we see it and roll back) or sees our raise and
            // stays silent (the fleet keeps running and fetches these).
            // Without the gate, both sides could lose: raise after the
            // crossing, check before the send - articles queued for a
            // fleet that is already leaving. The scope ends before
            // sub_pending, which takes the gate itself on rollback.
            let _gate = sh.finish_gate.lock_ok();
            sh.pending.fetch_add(works.len(), Ordering::AcqRel);
            // `finished` alone is not the whole "is anyone left"
            // question: a fleet that exhausted with a handed body
            // outstanding never sends it, because the handed id sits in
            // `done` so pending never lands on zero and seal_run skips
            // it - and a revive into that queues work nobody will pop.
            // `workers_live == 0` cannot answer it alone either, since
            // that is also every run before its first worker is born,
            // and refusing THERE drops work racing fleet birth. The two
            // together are the question (Fable sweep 15 Aug, TODO 170).
            let fleet_dead = sh.workers_born.load(Ordering::Acquire) > 0
                && sh.workers_live.load(Ordering::Acquire) == 0;
            if *sh.finished.borrow() || fleet_dead {
                drop(_gate);
                sub_pending(works.len());
                put_back(works);
                return 0;
            }
        }
        // Test seam: the window between dropping `finish_gate` and
        // taking the queue lock. `WorkerLife::retire` decrements
        // `workers_live` under no gate at all, so the LAST worker can
        // cross 1 -> 0 right here and both terminal seals then drain a
        // queue this call has not written to yet. Two-stage shape as
        // `Shared::drain_send_barrier` (first: we are inside the window;
        // second: the test has staged the retirement and releases us).
        #[cfg(test)]
        {
            let pair = sh.requeue_gate_barrier.lock_ok().clone();
            if let Some((entered, released)) = pair {
                entered.wait();
                released.wait();
            }
        }
        // Undo everything this call has done so far, in reverse: drop
        // pending (firing finished if ours is the zeroing sub), re-stash.
        // The caller keeps its accounting. The done bits are NOT touched
        // here: they are only cleared below, under the queue lock, after
        // the last refusal point (F-07) - clearing them earlier and
        // re-claiming on the way out let an in-flight duplicate complete
        // in the window, take the cleared bit as a fresh completion, and
        // sub pending once more than this rollback already did.
        let roll_back = |ws: Vec<Work>| {
            sub_pending(ws.len());
            put_back(ws);
        };
        let mut tries = 0;
        let mut q = loop {
            match sh.queue.try_lock() {
                Ok(g) => break g,
                Err(_) if tries < 20 => {
                    tries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(_) => {
                    roll_back(works);
                    return 0;
                }
            }
        };
        // The fleet-dead question AGAIN, now holding the queue lock.
        // The gate above only closes the case where the fleet was
        // already dead when we looked; it cannot serialise the later
        // 1 -> 0, because retirement never takes `finish_gate`. Left
        // there alone, this call could insert work after BOTH terminal
        // seals had drained an empty queue - no worker to pop it, no
        // outcome sender left to fail it - and still return non-zero,
        // so the caller reversed its deferred/remaining accounting for
        // an outcome that never came. Both seals drain under THIS lock,
        // which is what makes re-asking here sufficient: either the
        // fleet is already gone and we refuse, or a seal starting after
        // us blocks on the lock and fails what we inserted.
        // (Read-only sweep 2, M2.)
        if sh.workers_born.load(Ordering::Acquire) > 0
            && sh.workers_live.load(Ordering::Acquire) == 0
        {
            drop(q);
            roll_back(works);
            return 0;
        }
        // Past every refusal: now un-terminal the articles, still under
        // the queue lock, so a completion can only re-claim a bit whose
        // work is on its way into the queue (F-07).
        {
            let mut done = sh.done.lock_ok();
            for w in &works {
                done.clear(w.ord);
            }
        }
        let n = works.len();
        // Same books as every other reinsert (shed_pipeline, the recheck
        // path, the steer adopt): a promoted article going back in the
        // queue is counted back into `promoted_pending`, and never lands
        // behind the tail it was promoted past. `cancel` already recounts
        // on the way out; without this the counter drifted DOWN by one
        // per requeued promotion and the seek lane read as emptier than
        // it was (Fable sweep 15 Aug).
        let mut at = q.iter().take_while(|w| w.promoted).count().min(q.len());
        for w in works {
            if w.promoted {
                sh.promoted_pending.fetch_add(1, Ordering::AcqRel);
                q.insert(at, w);
                at += 1;
            } else {
                q.push_back(w);
            }
        }
        n
    }

    /// §146 tail give-up, the census half: when EVERY article the run
    /// still owes is walking a 430 refusal ladder - refused by at least
    /// one backbone already, or riding an uncharged bare refusal's
    /// confirming repeat - the ids of those walkers. This is the state
    /// a damaged post spends its whole zero-throughput tail in: every
    /// payload byte on disk, the wire carrying nothing but "no such
    /// article" verdicts at whatever a real provider charges per answer.
    ///
    /// `None` whenever ANY pending article is still payload work: queued
    /// untried, in flight clean, requeued for a transport failure or a
    /// bad-body steer (the CORRUPT damage class - its refetches carry
    /// `tried_fail`, never `tried_430`, so this census keeps the give-up
    /// off that path entirely), parked in a handoff, or invisible
    /// between two locks - the caller is about to trade these articles
    /// for recovery blocks, and an article that would have ARRIVED must
    /// keep that trade off the table. Also `None` while draining or
    /// aborted (a pause must keep the queue intact for resume), and
    /// whenever the snapshot cannot account for every pending article.
    ///
    /// Answers `{id, ordinal}` pairs (see [`Walker`]): the commit half
    /// claims by ordinal, and a walker that is mid-requeue when the
    /// commit runs has no queue or inflight record left to look its
    /// ordinal up in - the census is where the pair is captured.
    pub fn verdict_walkers(&self) -> Option<Vec<Walker>> {
        let sh = self
            .shared
            .lock_ok()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)?;
        if sh.aborted.load(Ordering::Acquire) || sh.draining.load(Ordering::Acquire) {
            return None;
        }
        // NZBFAST_POOL_DEBUG narration, same knob as the idle dump: the
        // census answering None is DESIGNED, and each early return below
        // says why through this - a closed census that should be open is
        // otherwise invisible from outside the pool.
        let closed = |why: &str| {
            if std::env::var_os("NZBFAST_POOL_DEBUG").is_some() {
                info!(target: "census", "closed: {why}");
            }
        };
        let pending = sh.pending.load(Ordering::Acquire);
        if pending == 0 {
            return None;
        }
        // A steered refetch or a delivered-but-unsettled body is payload
        // by definition - both are moments from becoming real bytes.
        if !sh.steer_inbox.lock_ok().is_empty() || !sh.handed.lock_ok().is_empty() {
            closed("steer inbox or handoff holds payload");
            return None;
        }
        // Keyed by id (same article can transiently show in both
        // sweeps); the value is its ordinal, identical wherever seen.
        let mut ids: HashMap<Arc<str>, u32> = HashMap::with_capacity(pending);
        // `done` first, `inflight` second - pick_dup's lock order. Both
        // sweeps filter through it: an article the dup-union already
        // drove terminal keeps its inflight entry (and can even ride
        // back through the queue) until its original's own answer
        // lands, SECONDS on a slow refusal - and it is not pending, so
        // counting it would fail the books against `pending` for the
        // whole tail. That is not a hypothetical: the loopback gone rig
        // measured the census closed on exactly this for every tick of
        // its tail.
        let done = sh.done.lock_ok();
        {
            let inf = sh.inflight.lock_ok();
            for (id, e) in inf.iter() {
                if done.contains(e.ord) {
                    continue; // already terminal - a lingering original
                }
                if e.tried_430 == 0 {
                    drop(inf);
                    closed("a clean article is on the wire");
                    return None; // a clean article is still on the wire
                }
                ids.insert(id.clone(), e.ord);
            }
        }
        // Same bounded try_lock discipline as `promote`/`cancel`.
        let mut tries = 0;
        let q = loop {
            match sh.queue.try_lock() {
                Ok(g) => break g,
                Err(_) if tries < 20 => {
                    tries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(_) => {
                    closed("queue lock contended");
                    return None;
                }
            }
        };
        for w in q.iter() {
            if done.contains(w.ord) {
                continue; // already terminal - a zombie queue entry
            }
            if w.tried_430 == 0 && w.soft_430 == 0 {
                drop(q);
                closed("untried payload still queued");
                return None; // untried payload still queued
            }
            ids.insert(w.id.clone(), w.ord);
        }
        drop(q);
        drop(done);
        // The books must balance: every pending article seen, as a
        // walker, in this one snapshot. An article mid-requeue (between
        // the inflight deregistration and the queue insert) fails the
        // count and the caller simply asks again next tick.
        if ids.len() != pending {
            closed(&format!(
                "snapshot does not account for every pending article \
                 ({} seen, {pending} pending)",
                ids.len()
            ));
            return None;
        }
        Some(
            ids.into_iter()
                .map(|(id, ord)| Walker { id, ord })
                .collect(),
        )
    }

    /// §146 tail give-up, the commit half: mark every article in `ids`
    /// terminal WITHOUT an outcome, wherever it currently is - queued
    /// walkers are removed exactly as [`cancel`](Self::cancel) removes
    /// them, in-flight ones are claimed so their eventual verdict (or
    /// even an unexpected body) lands as a no-op. The caller owns the
    /// accounting for exactly the ids returned, and the caller alone
    /// holds the justification: this is only sound when PAR2 recovery
    /// data on hand covers every one of these articles, because repair
    /// will rebuild their bytes exactly and the ladder's remaining
    /// verdicts stop mattering. The pool does not re-check that - it
    /// cannot, it has never heard of parity.
    ///
    /// When the last pending article is claimed here, `finished` fires
    /// and the fleet winds down mid-read instead of walking the rest of
    /// the refusal ladder - which is the whole point: the measured tail
    /// was 60 articles serially buying "no such article" answers nobody
    /// needed. Unlike `cancel` there is no requeue path back: callers
    /// verify coverage BEFORE committing.
    /// Takes the [`Walker`] pairs the census handed out: the queue
    /// half still cancels by id, but an article in transit between a
    /// refusal and its requeue has no record left to name its ordinal,
    /// so the claim below spends the one the census captured.
    pub fn give_up_covered(&self, walkers: &[Walker]) -> Vec<Arc<str>> {
        let Some(sh) = self
            .shared
            .lock_ok()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        else {
            return Vec::new();
        };
        if sh.aborted.load(Ordering::Acquire) || sh.draining.load(Ordering::Acquire) {
            return Vec::new();
        }
        // Queued walkers first, via the cancel machinery (queue removal,
        // promoted-count upkeep, terminal bookkeeping).
        let ids: HashSet<Arc<str>> = walkers.iter().map(|w| w.id.clone()).collect();
        let mut out = self.cancel(&ids);
        let claimed: HashSet<&str> = out.iter().map(|s| &**s).collect();
        let rest: Vec<&Walker> = walkers
            .iter()
            .filter(|w| !claimed.contains(&*w.id))
            .collect();
        drop(claimed);
        // Everything else - in flight mid-hop, or in transit between a
        // refusal and its requeue - is claimed where it stands. The
        // worker holding it finds `claim_done` already spent when the
        // answer arrives and drops it on the floor, exactly as a lost
        // dup race does. An id that already went terminal on its own
        // claims false and is not returned (the run's outcome for it
        // stands).
        for w in rest {
            if sh.claim_done(&w.id, w.ord) {
                sh.complete_one();
                out.push(w.id.clone());
            }
        }
        out
    }

    /// TODO 114 consumer steer: the decode consumer's per-article
    /// verdict for a `FetchOutcome::Done` body, called once per Done
    /// from the decode OS thread. With `PoolConfig::crc_steer` off (or
    /// no pool attached, or the id unknown) this is a no-op answering
    /// [`DecodeAck::Owned`].
    ///
    /// In steer mode every Done deferred its `complete_one` into
    /// `Shared::handed`; this call settles it. A clean verdict (and a
    /// declared part that matches the requested segment's) finalizes:
    /// the consumer owns the outcome. A bad body - failed pcrc32, or a
    /// valid body for the WRONG article (split-brain; its own CRC
    /// passes, identity is the only tell) - is requeued to a DIFFERENT
    /// server once (requeue-after-claim): the id is un-claimed from
    /// `done` and the stashed Work re-enters the queue with the
    /// deliverer's whole group folded into `tried_fail`, so the
    /// refetch (or a still-racing dup) re-claims through the normal
    /// one-outcome-per-id arbitration. Eligibility is the delivery
    /// rule the shipped gate hardened: `other_can_take` (levels +
    /// aliveness + group + the fill-server 430 pickup gate), checked
    /// AFTER the fold, and one steer per id ever
    /// (`Shared::crc_retried`). Every obstacle - no elsewhere, second
    /// bad copy, aborted/draining/finished run - finalizes as
    /// `Owned`: the consumer processes the body exactly as if this
    /// seam did not exist. The requeue itself goes through
    /// `Shared::steer_inbox`, never the tokio queue lock.
    ///
    /// "No elsewhere" is the ONE obstacle that no longer finalizes,
    /// since 31 Aug 2026: a failed CRC with no eligible peer is re-asked
    /// from the server that just served it, under the run's
    /// [`REASK_WASTE_CAP`] budget, because a corrupt article otherwise
    /// got no second ask of any kind while a genuinely missing one was
    /// requeued and could still complete. A part mismatch is excluded by
    /// name; the block below says why.
    pub fn note_decoded(&self, id: &str, report: DecodeReport) -> DecodeAck {
        let Some(sh) = self
            .shared
            .lock_ok()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        else {
            return DecodeAck::Owned;
        };
        let Some(h) = sh.handed.lock_ok().remove(id) else {
            return DecodeAck::Owned;
        };
        // The consumer owns the outcome from here unless a steer
        // completes below; own = the deferred terminal bookkeeping
        // runs now (mirrors the legacy post-send lines).
        let finalize = |sh: &Shared| {
            // Under arrival_ack the consumer's `note_settled` (after
            // decode AND write) owns the done_ok removal: a clean
            // verdict here precedes the disk write, and dropping the
            // liveness entry now would let a slow pwrite outlast the
            // /stream dead-span verdict and zero-fill bytes that are
            // about to land (TODO 121.4's promise, re-opened by the
            // steer seam). Non-ack pools have no later settle call, so
            // they still clear it here.
            if !sh.arrival_ack {
                sh.done_ok.lock_ok().remove(id);
            }
            sh.complete_one();
            DecodeAck::Owned
        };
        // Same-server re-ask budget: a body whose own CRC passed hands
        // the unit its re-ask spent back, so only the asks that come
        // back bad AGAIN ever deplete it (see `REASK_WASTE_CAP`).
        // Judged on the CRC alone and not on the part gate below: the
        // budget is about whether a second ask fixes DAMAGE, and a
        // re-asked body that decodes clean did.
        sh.settle_reask(id, matches!(report, DecodeReport::Clean { .. }));
        let mut got_part = None;
        let why = match report {
            DecodeReport::Bad { why } => why,
            // The expected part rides the stashed Work (h.work is
            // rebuilt from whatever copy DELIVERED, dups included, so
            // a dup-delivered wrong-part body still trips this); 0
            // means the segment declared no part - no gate.
            DecodeReport::Clean { part } => match (h.work.part, part) {
                (want, Some(got))
                    if want != 0 && got != want && !sh.part_latch.is_off(h.work.file) =>
                {
                    // The refetched copy of an already-steered id
                    // carrying the SAME undeclared part: a second
                    // backbone agrees with the first, so the NZB's
                    // numbering is what is wrong. Stand the gate down
                    // for the rest of that FILE rather than pay one
                    // refetch per article (tv4-rot1: 2x payload).
                    let agreed = matches!(
                        sh.part_latch.first.lock_ok().get(id),
                        Some(&(first_group, first_part))
                            if first_part == got && first_group & h.group_bits == 0
                    );
                    if agreed {
                        if sh.part_latch.stand_down(h.work.file)
                            && let Some(l) = &sh.live
                        {
                            l.note(
                                    h.server,
                                    "crc-retry",
                                    format!(
                                        "{id}: two servers agree on part {got} where the NZB declared {want} - segment numbers are synthesized, part gate off for this file"
                                    ),
                                );
                        }
                        return finalize(&sh);
                    }
                    got_part = Some(got);
                    "valid body for the wrong article (part mismatch)"
                }
                _ => return finalize(&sh),
            },
        };
        let dbg = std::env::var_os("NZBFAST_POOL_DEBUG").is_some();
        if sh.aborted.load(Ordering::Acquire)
            || sh.draining.load(Ordering::Acquire)
            || *sh.finished.borrow()
            // A fleet that fully exhausted while this body sat in the
            // consumer's hands has nobody left to drain the inbox, and
            // seal_run already ran (the handed id was in `done`, so
            // `pending` never reached zero). Steering now would park the
            // Work in a dead pool with no terminal outcome - the
            // dup_copy path skips the other_can_take gate, so this guard
            // is its only stop.
            || sh.workers_live.load(Ordering::Acquire) == 0
        {
            if dbg {
                info!(target: "crc-steer", "{id}: own (run over/draining)");
            }
            return finalize(&sh);
        }
        let mut w = h.work;
        // Captured before the Work moves into the steer inbox: the
        // un-claim below names this bit.
        let ord = w.ord;
        // Group siblings fold FIRST so other_can_take skips the whole
        // backbone serving the same bad copy - and a fill server's
        // pickup gate (the primary's 430 bit) is enforced inside, so a
        // primary+fill pair never buys a wasted refetch.
        w.tried_fail |= h.group_bits;
        // A dup's bad copy skips the eligibility gate and the once-
        // per-id budget (see the `dup_copy` doc): it requeues even
        // with nowhere better to go, because owning it would write
        // damage a non-dup copy may already have resolved cleanly.
        // Bounded structurally: each server group dup-races an id at
        // most once (`dup_servers`), and the fold above stops the
        // pickers re-racing from this group.
        let charged = !h.dup_copy;
        if charged {
            // One decode-seam requeue per id, ever, whether it goes to a
            // peer or back to the deliverer. Asked FIRST, ahead of the
            // routing question below, so a re-ask the budget refuses
            // does not also spend the per-id pass it never used.
            if !sh.crc_retried.lock_ok().insert(w.id.clone()) {
                if dbg {
                    info!(target: "crc-steer", "{id}: own (already steered once)");
                }
                return finalize(&sh);
            }
            // `h.spent` is the pre-claim routing evidence (see the field
            // doc): the provisional claim that delivered this body
            // already dropped the live entry, so asking the live map
            // alone here reads "nobody else can have it" for exactly the
            // fill peers a spent primary opened the tier for.
            //
            // With no eligible peer the article is re-asked from the
            // server that just served it badly, which is what
            // `next_work` does with a `tried_fail` bit nobody else can
            // take (see `Work::tried_fail`: "with none left the failing
            // server may retry it itself"). Until 31 Aug 2026 this arm
            // OWNED the damage instead, so a corrupt body got no second
            // ask of any kind while a genuinely MISSING one was requeued
            // and could still complete - and on a single-server install
            // that was EVERY corrupt article. The two commonest
            // corruptions are not the same fault, which is why asking
            // the same server again is worth a fetch: a damaged article
            // in the spool answers the same bytes forever, and a broken
            // cache node behind a load balancer answers a fraction of
            // requests badly. `REASK_WASTE_CAP` is what separates them,
            // by charging only the asks that come back bad again.
            //
            // NOT for a part mismatch (`got_part`), and that carve-out is
            // the whole reason this is safe to turn on for a peerless
            // fleet: a mismatch is a disagreement about IDENTITY between
            // the NZB's segment numbering and this backbone, so the same
            // backbone re-states it, every time, for every article of
            // that file. The `part_latch` stand-down that ends it needs
            // a DIFFERENT group to agree (see the arm above), which a
            // single server can never provide. So a mismatch still needs
            // a peer or nothing.
            let elsewhere = sh.other_can_take_with(&w, h.server, h.spent);
            if !elsewhere && !(got_part.is_none() && sh.take_reask(&w.id)) {
                if dbg {
                    info!(
                        target: "crc-steer",
                        "{id}: own (no elsewhere, part_mismatch={} reask budget spent)",
                        got_part.is_some()
                    );
                }
                return finalize(&sh);
            }
        }
        // NO tokio queue lock here (see the `steer_inbox` field doc):
        // the Work goes into the inbox, which workers drain into the
        // queue under their own `next_work` lock hold. Inbox FIRST,
        // un-claim after: from the moment the id leaves `done` a
        // future claimant is already guaranteed - the drained refetch,
        // or a dup still racing - and `claim_done` arbitrates exactly
        // one, as ever.
        //
        // M2 (sweep 8): publication and un-claim must also be atomic
        // WITH RESPECT TO ADOPTION, which the two separate lock hops
        // this used to take were not. A worker that drained the inbox
        // while the old done bit was still set could dispatch the
        // refetch AND have it come back - from a cached or local
        // provider, or across any scheduler pause long enough - and
        // `claim_done` would reject the only good copy as a duplicate
        // and deregister it. This thread would then clear the bit over
        // an article that is in no queue, no inbox and no inflight map
        // while `pending` still counts it: every worker waits forever
        // and only an outer watchdog ends the job. So the guard below
        // is HELD across the fleet-live recheck, the spent restore and
        // the done clear. The worker's drain takes this same mutex
        // (pool.rs `next_work`) inside its queue-lock hold, so it parks
        // there until the article is genuinely unowned.
        if let Some(l) = &sh.live {
            l.note(
                h.server,
                "crc-retry",
                format!("{id}: {why} - refetching from another server"),
            );
        }
        if dbg {
            info!(target: "crc-steer", "{id}: steered (from server {})", h.server);
        }
        if let Some(got) = got_part {
            // Keep the FIRST deliverer: a later same-backbone repeat
            // must not launder itself into the record.
            sh.part_latch
                .first
                .lock_ok()
                .entry(w.id.clone())
                .or_insert((h.group_bits, got));
            sh.part_latch.steers.fetch_add(1, Ordering::Relaxed);
        }
        let mut inbox = sh.steer_inbox.lock_ok();
        inbox.push(w);
        #[cfg(test)]
        {
            let hook = STEER_WINDOW
                .lock_ok()
                .as_ref()
                .filter(|(want, _)| &**want == id)
                .map(|(_, b)| b.clone());
            if let Some(b) = hook {
                b.wait();
                b.wait();
            }
        }
        // Re-ask the fleet-dead question the guard above asked. Nothing
        // between the two takes a lock retirement respects - `retire`
        // drops `alive` and `workers_live` bare, taking no gate - and
        // the gap holds `other_can_take`, a `crc_retried` insert and a
        // formatted `live.note`. A fleet that exhausts in there has
        // nobody left to drain the inbox and both seals have already
        // run, so the entry would sit there with no terminal outcome
        // ever emitted for the article.
        //
        // Safe to take back here and nowhere later: the id is STILL in
        // `done`, so no other claimant can have emitted anything for it,
        // and the consumer owning the body is exactly what the guard
        // above would have done.
        if sh.workers_live.load(Ordering::Acquire) == 0 {
            inbox.retain(|x| &*x.id != id);
            drop(inbox);
            if dbg {
                info!(target: "crc-steer", "{id}: own (fleet died during the steer)");
            }
            return finalize(&sh);
        }
        // M8: hand the ladder back the evidence the provisional claim
        // took. Ahead of the done clear and under the inbox guard, so
        // no worker can reach `next_work`'s pickup gate - which reads
        // the same map - between the two.
        sh.restore_spent(id, h.spent);
        sh.done.lock_ok().clear(ord);
        // The body the consumer holds is dead weight now; the article
        // stays in any_live's sight through the inbox entry pushed
        // above until a worker drains it into the queue.
        sh.done_ok.lock_ok().remove(id);
        drop(inbox);
        DecodeAck::Steered
    }

    /// TODO 121.4: the consumer's "this body is decoded and written"
    /// ack for `arrival_ack` pools. Removes the `done_ok` liveness
    /// entry that has covered the article since its claim - through
    /// the outcome channel's buffer and the consumer's in-hand batch -
    /// so the /stream dead-span verdict can never condemn a span whose
    /// bytes are anywhere in the pipe. A no-op for ids already settled
    /// (steer verdicts, non-ack pools) and after the run ends.
    pub fn note_settled(&self, id: &str) {
        if let Some(sh) = self
            .shared
            .lock_ok()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        {
            sh.done_ok.lock_ok().remove(id);
        }
    }

    /// Force a pool-state dump (the stall watchdog, on a suspected
    /// deadlock). Same output as NZBFAST_POOL_DEBUG's idle-branch dump,
    /// but on demand - so a hang in the field self-captures the queue /
    /// inflight state that pins the root cause.
    pub fn dump_state(&self) {
        if let Some(sh) = self
            .shared
            .lock_ok()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        {
            sh.debug_dump_idle();
        }
    }

    /// Hard-stop the run (user cancelled the download). Lock-free by
    /// design: an `aborted` flag every worker loop checks, plus the
    /// finished watch to snap workers out of blocked reads. The old
    /// implementation cleared the queue under a try_lock (starved out
    /// forever on busy pools - 50+ workers contend for that mutex) and
    /// zeroed `pending` (in-flight completions then fetch_sub-wrapped it
    /// to usize::MAX and the pool never returned). The fetch returns
    /// within seconds; the journal keeps what landed.
    pub fn abort(&self) -> bool {
        let Some(sh) = self
            .shared
            .lock_ok()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        else {
            return false;
        };
        sh.aborted.store(true, Ordering::Release);
        let _ = sh.finished.send(true);
        true
    }

    /// Graceful stop (the friendly Pause): stop admitting new articles but
    /// let everything already in flight finish and journal, then return -
    /// so a resume re-fetches only the unstarted queue, wasting nothing.
    /// Contrast [`abort`](Self::abort), which drops in-flight reads (they
    /// re-download on resume) to free the line immediately.
    pub fn drain(&self) -> bool {
        let Some(sh) = self
            .shared
            .lock_ok()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        else {
            return false;
        };
        sh.draining.store(true, Ordering::Release);
        // Same state, latched on the handle: the workers read the flag on
        // `Shared`, but `Shared` is gone by the time the engine asks.
        self.drained.store(true, Ordering::Release);
        // Not a hard finish signal: blocked reads must run to completion,
        // so no finished.send here - the read loop drains naturally.
        true
    }

    /// Was a graceful drain requested? The engine checks this AFTER the
    /// network phase returns - to tell a paused wind-down (park + resume)
    /// from a real completion (settle/repair) - and the pool has dropped its
    /// `Shared` by then, so the answer comes from the latch `drain()` left
    /// here. The live-pool read is kept for callers that ask mid-run.
    pub fn is_draining(&self) -> bool {
        self.drained.load(Ordering::Acquire)
            || self
                .shared
                .lock_ok()
                .as_ref()
                .and_then(std::sync::Weak::upgrade)
                .is_some_and(|sh| sh.draining.load(Ordering::Acquire))
    }

    /// Network-tail visibility (tail-prefetch experiment): Some(pending
    /// article count) once a primary worker has found the queue dry
    /// with articles still in flight - the pool's own tail latch - and
    /// None before that moment or once the run is gone. `Some(0)` means
    /// the tail completed; a live tail is `Some(n)` with `n > 0`.
    /// TODO 208 item 3: the shallowest pipeline depth the endgame taper
    /// handed out, `usize::MAX` if it never bit (or the run is gone).
    /// The `[pool]` line carries the same number; this is the handle a
    /// rig reads it through, and it must be read BEFORE the fetch
    /// returns - the pool's last strong `Arc` dies with it.
    pub fn taper_min(&self) -> usize {
        let sh = {
            let g = self.shared.lock_ok();
            match g.as_ref().and_then(|w| w.upgrade()) {
                Some(sh) => sh,
                None => return usize::MAX,
            }
        };
        sh.taper_min.load(Ordering::Relaxed)
    }

    pub fn tail_pending(&self) -> Option<usize> {
        let sh = {
            let g = self.shared.lock_ok();
            g.as_ref()?.upgrade()?
        };
        let latched = sh.tail_started.lock_ok().is_some();
        latched.then(|| sh.pending.load(Ordering::Acquire))
    }

    /// Held-bytes backpressure (TODO 94 item E): park the pending
    /// articles of these files ([`ArticleReq::file`], the extractor
    /// slots) behind a shared in-flight allowance of `allow` bytes
    /// (`Some`), or release them (`None`). The extractor raises it near
    /// its holds cap for the files of a chased group, refreshes the
    /// allowance as its holds move, and releases it when the group
    /// stops chasing; see `pool::park` for what a parked group still
    /// gets. A no-op with no pool attached, and harmless for a file that
    /// is not queued.
    pub fn park_files(&self, files: &[u32], allow: Option<u64>) {
        let sh = {
            let g = self.shared.lock_ok();
            match g.as_ref().and_then(|w| w.upgrade()) {
                Some(sh) => sh,
                None => return,
            }
        };
        // Seeding a newly parked file's count from the in-flight map is
        // one scan of it per first park of that file - rare, and the
        // only way the allowance can mean what it says.
        sh.park.set(files, allow, |file| {
            sh.inflight
                .lock_ok()
                .iter()
                .filter(|(_, i)| i.file == file)
                .map(|(id, _)| id.clone())
                .collect()
        });
    }

    /// Bytes of BODY responses charged as in flight across the pool
    /// right now (the B3 wire estimate, `Shared::inflight_body_bytes`):
    /// what will land whatever the scheduler decides next. The
    /// extractor's park counts it against its holds cap, since a park
    /// fired at the cap alone breached it by exactly this much. `None`
    /// with no pool attached.
    pub fn wire_inflight_bytes(&self) -> Option<u64> {
        let sh = {
            let g = self.shared.lock_ok();
            g.as_ref()?.upgrade()?
        };
        Some(sh.inflight_body_bytes.load(Ordering::Acquire))
    }

    /// Candidates `next_work` stepped past for a parked file so far
    /// (diagnostics). `None` with no pool attached.
    pub fn park_deferrals(&self) -> Option<u64> {
        let sh = {
            let g = self.shared.lock_ok();
            g.as_ref()?.upgrade()?
        };
        Some(sh.park.deferred())
    }
}
