// TODO 106: the M11 seek/steer control handle - QueueControl and its
// whole impl - came out of pool.rs whole under the size gate. A child
// module sees the parent's private items (Shared and friends), so the
// body is untouched; only `attach` widened to pub(super) for the
// call sites in pool.rs and the sibling test modules.

use super::*;

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
            .lock()
            .unwrap()
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
            .lock()
            .unwrap()
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
            .lock()
            .unwrap()
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
            .lock()
            .unwrap()
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
            .lock()
            .unwrap()
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
        {
            let mut done = sh.done.lock_ok();
            for w in &works {
                done.clear(w.ord);
            }
        }
        // Undo everything this call has done so far, in reverse:
        // re-terminal, drop pending (firing finished if ours is the
        // zeroing sub), re-stash. The caller keeps its accounting.
        let roll_back = |ws: Vec<Work>| {
            let mut done = sh.done.lock_ok();
            for w in &ws {
                done.claim(w.ord);
            }
            drop(done);
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
                eprintln!("[census] closed: {why}");
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
    pub fn note_decoded(&self, id: &str, report: DecodeReport) -> DecodeAck {
        let Some(sh) = self
            .shared
            .lock()
            .unwrap()
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
        let why = match report {
            DecodeReport::Bad { why } => why,
            // The expected part rides the stashed Work (h.work is
            // rebuilt from whatever copy DELIVERED, dups included, so
            // a dup-delivered wrong-part body still trips this); 0
            // means the segment declared no part - no gate.
            DecodeReport::Clean { part } => match (h.work.part, part) {
                (want, Some(got)) if want != 0 && got != want => {
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
                eprintln!("[crc-steer] {id}: own (run over/draining)");
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
        if charged
            && (!sh.other_can_take(&w, h.server) || !sh.crc_retried.lock_ok().insert(w.id.clone()))
        {
            if dbg {
                eprintln!(
                    "[crc-steer] {id}: own (elsewhere={} already={})",
                    sh.other_can_take(&w, h.server),
                    sh.crc_retried.lock_ok().contains(id)
                );
            }
            return finalize(&sh);
        }
        // NO tokio queue lock here (see the `steer_inbox` field doc):
        // the Work goes into the inbox, which workers drain into the
        // queue under their own `next_work` lock hold. Inbox FIRST,
        // un-claim after: from the moment the id leaves `done` a
        // future claimant is already guaranteed - the drained refetch,
        // or a dup still racing - and `claim_done` arbitrates exactly
        // one, as ever.
        if let Some(l) = &sh.live {
            l.note(
                h.server,
                "crc-retry",
                format!("{id}: {why} - refetching from another server"),
            );
        }
        if dbg {
            eprintln!("[crc-steer] {id}: steered (from server {})", h.server);
        }
        sh.steer_inbox.lock_ok().push(w);
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
            sh.steer_inbox.lock_ok().retain(|x| &*x.id != id);
            if dbg {
                eprintln!("[crc-steer] {id}: own (fleet died during the steer)");
            }
            return finalize(&sh);
        }
        sh.done.lock_ok().clear(ord);
        // The body the consumer holds is dead weight now; the article
        // stays in any_live's sight through the inbox entry pushed
        // above until a worker drains it into the queue.
        sh.done_ok.lock_ok().remove(id);
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
            .lock()
            .unwrap()
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
            .lock()
            .unwrap()
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
            .lock()
            .unwrap()
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
            .lock()
            .unwrap()
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
                .lock()
                .unwrap()
                .as_ref()
                .and_then(std::sync::Weak::upgrade)
                .is_some_and(|sh| sh.draining.load(Ordering::Acquire))
    }

    /// Network-tail visibility (tail-prefetch experiment): Some(pending
    /// article count) once a primary worker has found the queue dry
    /// with articles still in flight - the pool's own tail latch - and
    /// None before that moment or once the run is gone. `Some(0)` means
    /// the tail completed; a live tail is `Some(n)` with `n > 0`.
    pub fn tail_pending(&self) -> Option<usize> {
        let sh = {
            let g = self.shared.lock_ok();
            g.as_ref()?.upgrade()?
        };
        let latched = sh.tail_started.lock_ok().is_some();
        latched.then(|| sh.pending.load(Ordering::Acquire))
    }
}
