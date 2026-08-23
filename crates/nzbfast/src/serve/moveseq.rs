//! §158 item 1: the move sequence, and the fault-injection harness that
//! proves it.
//!
//! A job lives in exactly one of two stores - `.spool/queue.json` for the
//! live queue, `.spool/history.jsonl` for the parked record - and moving
//! between them is TWO independent durable writes, never one. There is no
//! transaction across the pair and this module does not invent one. What
//! it does is make the tear RECOVERABLE.
//!
//! ## Why precedence alone was not enough
//!
//! Both directions tear into the same shape. A park (queue -> history)
//! writes the terminal history row and dies before the queue.json rewrite
//! drops it; a retry (history -> queue) writes queue.json and dies before
//! the history tombstone lands. Either way the next boot finds ONE
//! nzo_id with a nonterminal queue row (`job_wire` restores `Finishing`
//! and `Downloading` alike as `Queued`) and a terminal history row.
//!
//! §158 resolved that by precedence - history wins - which is exactly
//! right for the park and silently wrong for the retry: the record is
//! still there and still retryable, so nothing is lost, but the button
//! the user pressed is undone by a crash in a sub-millisecond window.
//! Precedence cannot do better, because the two cases are indist-
//! inguishable by state.
//!
//! ## The rule
//!
//! [`stamp_move`] bumps [`Job::move_seq`] on the way OUT of a store,
//! BEFORE the destination store's durable write. Both move paths already
//! write the destination first (§158 reordered them so a tear reads "in
//! both stores" rather than "in neither"), so the destination's copy is
//! always the one carrying the higher number:
//!
//! | cut | queue.json | history.jsonl | winner |
//! |-----|-----------|---------------|--------|
//! | park, before the queue rewrite | stale row, seq N | fresh row, seq N+1 | history |
//! | retry, before the tombstone | fresh row, seq N+1 | stale row, seq N | queue |
//!
//! [`move_winner`] is that comparison and nothing more. The direction of
//! the last INTENDED move is recovered from the counter instead of being
//! inferred from state, which is the whole of the fix.
//!
//! Ties keep the §158 answer. A tie means neither copy was stamped -
//! every record written by 1.0.23 and earlier reads `move_seq: 0` on
//! both sides - so an existing install's split-brain resolves exactly as
//! it does today, and only moves performed by this version and later get
//! the sharper answer.
//!
//! ## Cleaning up after the resolution
//!
//! [`reconcile_moves`] also reports which rows it dropped, and
//! `load_queue` makes that durable: a losing history row is tombstoned, a
//! losing queue row is rewritten out of queue.json. Without it the loser
//! sits in its store forever waiting to resurrect the job the moment its
//! winner is deleted - a retry resolved in the queue's favour, then
//! deleted from the queue, would have come back as a Failed history row
//! from the stale line nothing ever removed.
//!
//! ## The harness
//!
//! The window is a few hundred microseconds between two `fsync`s, so it
//! is not reachable by racing threads. The cut comes from §158 item 7's
//! [`storecut`](super::storecut), which is already installed at both
//! durable-write seams (`Daemon::save_queue`,
//! `Daemon::history_write_locked`): `arm_cut(1)` lets a path's FIRST
//! write land and drops the second, which is what a kill between them
//! leaves on disk. That harness is positional rather than keyed by
//! store, and positional is the right axis here - every move below is
//! two writes in a fixed order, so "the second one" names the window
//! exactly, and one seam serves both §158 items instead of two
//! competing ones. The tests then restore from those real bytes twice -
//! once with `LEGACY_RULE` forcing the §158 answer, once with this
//! module's - so the differential is measured over one set of files
//! rather than two hand-written fixtures. See `mod harness` at the
//! bottom.

use super::*;

/// Which store keeps the record when one nzo_id is found in both.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(in crate::serve) enum MoveWinner {
    /// The move was heading INTO the queue (a retry, a library-stream
    /// activation) and got there durably. Keep the queued copy.
    Queue,
    /// The move was heading INTO history (a park), or nothing is stamped
    /// and the §158 rule applies. Keep the parked copy.
    History,
}

#[cfg(test)]
thread_local! {
    /// Harness control arm: force the pre-§158-item-1 rule, "history
    /// always wins", so the same torn bytes can be restored under both
    /// rules and the difference measured rather than described.
    static LEGACY_RULE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Test seam: a two-stage barrier `commit_to_queue` trips between its
/// queue save and its tombstone. The Q1 window is exactly that gap - a
/// slow `save_queue` on a large queue lets the resumed job run and park
/// again before the tombstone lands - and holding the commit open there
/// is what makes the interleaving a schedule instead of a sleep. First
/// barrier: the commit has saved the queue and is about to tombstone;
/// second: the test has run its interleaved work and releases it.
///
/// Keyed by nzo_id, like `postproc::TAIL_GEN_BARRIER`. `retry` commits
/// through here and dozens of bin tests call `retry`, in parallel with
/// this one - unkeyed, any of them becomes a third waiter on a
/// two-party barrier and the whole run hangs rather than fails (the
/// 15 Aug `PARK_GEN_BARRIER` wedge, same shape).
#[cfg(test)]
pub(in crate::serve) static COMMIT_TOMB_BARRIER: Mutex<
    Option<(String, Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
> = Mutex::new(None);

/// Run `f` with the §158 rule in force on this thread.
#[cfg(test)]
pub(in crate::serve) fn with_legacy_rule<T>(f: impl FnOnce() -> T) -> T {
    LEGACY_RULE.with(|c| c.set(true));
    let out = f();
    LEGACY_RULE.with(|c| c.set(false));
    out
}

/// Whichever store holds the higher `move_seq` was the destination of the
/// last move that got as far as its own durable write.
///
/// A tie - which is every pre-§158 record, both copies reading 0 - keeps
/// the §158 answer, so nothing about an existing install's stores changes
/// meaning.
pub(in crate::serve) fn move_winner(queue_seq: u64, hist_seq: u64) -> MoveWinner {
    #[cfg(test)]
    if LEGACY_RULE.with(std::cell::Cell::get) {
        return MoveWinner::History;
    }
    if queue_seq > hist_seq {
        MoveWinner::Queue
    } else {
        MoveWinner::History
    }
}

/// Claim the NEXT move for this record: bump the counter that the
/// destination store is about to write.
///
/// Call it with no store lock held, after the in-memory move and before
/// the destination's durable write. Per-record and monotonic by
/// construction - the counter travels on the Job itself, so it cannot
/// collide with another job's and cannot go backwards across a restart
/// (the winning copy carries it, and the loser is removed).
pub(in crate::serve) fn stamp_move(job: &Arc<Mutex<Job>>) {
    stamp_move_locked(&mut job.lock_ok());
}

/// The same, for a caller that already holds the record - and has to,
/// because the check that says the stamp is still theirs to make must
/// happen under the same hold (Codex sweep 6, N2).
pub(in crate::serve) fn stamp_move_locked(job: &mut Job) {
    job.move_seq += 1;
}

/// What [`reconcile_moves`] dropped, so the caller can make the
/// resolution durable instead of re-deriving it every boot.
#[derive(Default)]
pub(in crate::serve) struct MoveResolution {
    /// Ids whose HISTORY row lost: a retry (or a library-stream
    /// activation) that reached queue.json and not its tombstone. The
    /// stale history line must be tombstoned.
    pub(in crate::serve) reverted: Vec<String>,
    /// Ids whose QUEUE row lost: a park that reached history.jsonl and
    /// not the queue rewrite. queue.json must be rewritten without them.
    pub(in crate::serve) parked: Vec<String>,
}

/// Resolve every nzo_id that came back in BOTH stores, and report what
/// was dropped from each.
///
/// Split out of `load_queue` as a pure function over the two restored
/// Vecs: the whole point of the counter is a decision that can be
/// asserted directly, without a daemon or a filesystem.
pub(in crate::serve) fn reconcile_moves(
    queued: Vec<Job>,
    history: Vec<Job>,
) -> (Vec<Job>, Vec<Job>, MoveResolution) {
    let mut split = MoveResolution::default();
    if queued.is_empty() || history.is_empty() {
        return (queued, history, split);
    }
    // The history side keyed by id. First line wins on a duplicate, the
    // same way the rest of `load_queue` reads the Vec.
    let hist_seq: std::collections::HashMap<&str, u64> = history
        .iter()
        .rev()
        .map(|j| (j.nzo_id.as_str(), j.move_seq))
        .collect();
    let mut keep_queued: Vec<Job> = Vec::with_capacity(queued.len());
    for job in queued {
        let Some(&hseq) = hist_seq.get(job.nzo_id.as_str()) else {
            keep_queued.push(job);
            continue;
        };
        match move_winner(job.move_seq, hseq) {
            MoveWinner::Queue => {
                warn!(
                    target: "queue",
                    "{}: a restart caught a history -> queue move half-written \
                     (queue seq {} > history seq {hseq}) - keeping the queued \
                     copy, which is the move the user asked for",
                    job.nzo_id,
                    job.move_seq
                );
                split.reverted.push(job.nzo_id.clone());
                keep_queued.push(job);
            }
            MoveWinner::History => {
                warn!(
                    target: "queue",
                    "{}: a restart caught a queue -> history move half-written \
                     (queue seq {} <= history seq {hseq}) - keeping the history \
                     copy, so the release is not downloaded a second time",
                    job.nzo_id,
                    job.move_seq
                );
                split.parked.push(job.nzo_id.clone());
            }
        }
    }
    let history: Vec<Job> = history
        .into_iter()
        .filter(|j| !split.reverted.contains(&j.nzo_id))
        .collect();
    (keep_queued, history, split)
}

impl Daemon {
    /// The durable half of a history -> queue move: save the queue, and
    /// only then stop the record replaying out of the history store.
    ///
    /// ORDER MATTERS, and it used to be the other way round. The
    /// tombstone was appended and fsync'd first, then queue.json was
    /// rewritten independently - so a kill, an ENOSPC or an EIO between
    /// the two left the record deleted from replayed history and absent
    /// from the old queue snapshot: it existed in NEITHER store, and no
    /// amount of startup reconciliation can recover a record nothing
    /// wrote down (Codex sweep 12 Aug F1).
    ///
    /// Queue first. The torn state is "in both stores", which
    /// `load_queue` now resolves in the QUEUE's favour on this path -
    /// [`stamp_move`] has already put the higher `move_seq` on the copy
    /// this call is about to persist, so the move survives the crash
    /// instead of being reverted by precedence.
    ///
    /// And a queue write that FAILED must not be followed by the
    /// tombstone at all, or the same loss happens with no crash needed.
    /// The move itself stands: the job is live in memory and will run,
    /// exactly as `enqueue` runs a job whose persist failed. What is
    /// given up is only its survival across a restart, and the record it
    /// reverts to is the parked one it came from.
    ///
    /// Returns whether the queue write landed. Call with no store locks
    /// held, after [`stamp_move`]; `seq` is the stamp this move put on
    /// the record, and bounds the tombstone below.
    pub(in crate::serve) fn commit_to_queue(&self, nzo_id: &str, seq: u64, why: &str) -> bool {
        if self.save_queue() {
            #[cfg(test)]
            {
                let pair = COMMIT_TOMB_BARRIER
                    .lock_ok()
                    .clone()
                    .filter(|(k, _, _)| k == nzo_id);
                if let Some((_, entered, released)) = pair {
                    entered.wait();
                    released.wait();
                }
            }
            // The record has LEFT history: stop it replaying there. Bound
            // by THIS move's generation - `save_queue` can be slow on a
            // large queue, and the resumed job can run and park again
            // (seq+1) before this thread gets here. An id-only tombstone
            // landing after that park's history row deleted it, and the
            // next queue save omitted the parked job too: lost from both
            // stores with no crash needed (Codex sweep 13 Aug Q1). The
            // bounded tombstone still buries the seq-N row this move
            // pulled out of history, and can never touch a later one.
            self.history_tombstone_upto(nzo_id, seq);
            true
        } else {
            error!(
                target: "queue",
                "{nzo_id}: {why} now, but the queue could not be written - its \
                 history record was left in place rather than deleted, so a \
                 restart before the next successful save shows it parked again"
            );
            false
        }
    }

    /// M14i: a parked library entry becomes a running download. The
    /// history -> queue move in one place, so it and `Daemon::retry`
    /// cannot drift apart on the ordering their durability depends on.
    ///
    /// Front of the queue - the caller has already set the force
    /// priority - because this play IS the download trigger.
    pub(in crate::serve) fn activate_parked(&self, job: &Arc<Mutex<Job>>) {
        let nzo = job.lock_ok().nzo_id.clone();
        // Same claim transaction as `retry`: from the history retain
        // below until the queue push, the record is in NEITHER store in
        // memory, and a concurrent add picking a directory under
        // `add_lock` would read this job's folder as free - its first
        // decoded span then truncates the payload this play is about to
        // serve. Held across the in-memory move only, dropped before the
        // durable commit exactly as `retry` drops it before
        // `commit_to_queue`.
        let publish = self.add_lock.lock_ok();
        // Same Q2 fence as retry: between this removal and commit_to_queue's
        // save, a concurrent history compaction must carry the disk row or a
        // crash in the window loses the record from both stores.
        let _inflight = self.hist_inflight_begin(&nzo);
        self.history.lock_ok().retain(|x| !Arc::ptr_eq(x, job));
        // The harness's window: the record has left history and not yet
        // reached the queue.
        #[cfg(test)]
        super::storecut::activate_gap(self);
        stamp_move(job);
        let seq = job.lock_ok().move_seq;
        self.queue.lock_ok().push_front(job.clone());
        drop(publish);
        self.commit_to_queue(&nzo, seq, "fetching");
    }
}

#[cfg(test)]
mod harness {
    //! The fault-injection harness for §158 item 1.
    //!
    //! Every test here follows the same three beats:
    //!
    //! 1. drive the REAL move path (`Daemon::retry`,
    //!    `Daemon::activate_parked`, `Daemon::park`) with a cut armed at
    //!    its second durable write;
    //! 2. read the two stores back off disk and assert the tear is the
    //!    F1 shape - one nzo_id, a nonterminal queue row and a terminal
    //!    history row - and which side carries the higher `move_seq`;
    //! 3. restore those same bytes into a fresh daemon twice, under the
    //!    §158 rule and under this module's, and assert the difference.
    //!
    //! Beat 3 is the point. A test that only asserted the new behaviour
    //! would not show that the old one was wrong, and the park half - the
    //! half that is currently CORRECT and that this change could break -
    //! has to come out the same under both.

    use super::*;
    use crate::serve::testutil::test_daemon;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("nzbfast-moveseq-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A job in the shape the stores round-trip, owned by `d`'s out root
    /// so `retry` reuses the folder instead of refiling it.
    fn job(d: &Arc<Daemon>, id: &str, state: JobState) -> Arc<Mutex<Job>> {
        let out = d.out_dir().join(format!("Release.{id}"));
        let v = json!({
            "nzo_id": id,
            "name": format!("Release.{id}"),
            "out_dir": out.to_string_lossy(),
            "nzb_path": d.spool.join(format!("{id}.nzb")).to_string_lossy(),
            "state": format!("{state:?}"),
        });
        Arc::new(Mutex::new(job_from_json(&v).expect("job")))
    }

    /// What the two stores hold for `id`, read back off disk: the queue
    /// row's `(state, move_seq)` and the history row's.
    fn on_disk(dir: &Path, id: &str) -> (Option<(JobState, u64)>, Option<(JobState, u64)>) {
        let d = test_daemon(dir);
        let queue = crate::persist::load_json_with_backup(&d.spool.join("queue.json"))
            .and_then(|v| v.get("queue").and_then(Value::as_array).cloned())
            .unwrap_or_default()
            .iter()
            .filter_map(job_from_json)
            .find(|j| j.nzo_id == id)
            .map(|j| (j.state, j.move_seq));
        let hist = d
            .history_replay()
            .0
            .into_iter()
            .find(|j| j.nzo_id == id)
            .map(|j| (j.state, j.move_seq));
        (queue, hist)
    }

    /// Restore `dir`'s stores into a fresh daemon and report where `id`
    /// ended up: `(queued state, history state)`.
    fn restore(dir: &Path, id: &str) -> (Option<JobState>, Option<JobState>) {
        let d = test_daemon(dir);
        d.load_queue();
        let q = d
            .queue
            .lock_ok()
            .iter()
            .find(|j| j.lock_ok().nzo_id == id)
            .map(|j| j.lock_ok().state);
        let h = d
            .history
            .lock_ok()
            .iter()
            .find(|j| j.lock_ok().nzo_id == id)
            .map(|j| j.lock_ok().state);
        (q, h)
    }

    /// Both stores, byte-for-byte, so one torn state can be restored more
    /// than once.
    fn snapshot(d: &Arc<Daemon>) -> (Vec<u8>, Vec<u8>) {
        (
            std::fs::read(d.spool.join("queue.json")).unwrap_or_default(),
            std::fs::read(d.history_store_path()).unwrap_or_default(),
        )
    }

    fn rewind(d: &Arc<Daemon>, snap: &(Vec<u8>, Vec<u8>)) {
        std::fs::write(d.spool.join("queue.json"), &snap.0).unwrap();
        std::fs::write(d.history_store_path(), &snap.1).unwrap();
        // The backup `load_json_with_backup` keeps is part of the state a
        // restore reads; a stale one would answer for a rewound file.
        let _ = std::fs::remove_file(d.spool.join("queue.json.bak"));
    }

    /// A retry killed between its queue write and its tombstone.
    ///
    /// The user pressed retry, the queue write landed, the process died
    /// before the history record could be tombstoned. Under the §158 rule
    /// the terminal history row wins and the retry is silently undone -
    /// nothing is lost, but the button did nothing. The move sequence
    /// says the queue copy is the newer intent, and it survives.
    #[test]
    fn a_half_written_retry_is_no_longer_reverted() {
        let dir = tmp("retry-cut");
        let d = test_daemon(&dir);
        let j = job(&d, "nzo_r1", JobState::Failed);
        j.lock_ok().fail_message = "articles missing".to_string();
        d.history.lock_ok().push(j.clone());
        assert!(d.history_upsert(std::slice::from_ref(&j)));
        assert!(d.save_queue(), "the empty queue has to exist on disk");

        // The kill: the queue write lands, the tombstone never happens.
        super::super::storecut::arm_cut(1);
        assert!(d.retry("nzo_r1"), "retry refused the record");
        super::super::storecut::disarm();

        let (q, h) = on_disk(&dir, "nzo_r1");
        assert_eq!(
            q,
            Some((JobState::Queued, 1)),
            "the queue write must have landed, stamped, before the cut"
        );
        assert_eq!(
            h,
            Some((JobState::Failed, 0)),
            "the tombstone must NOT have landed - this is the torn state"
        );

        let snap = snapshot(&d);
        drop(d);

        // The control arm: what shipped in 1.0.23 does with these bytes.
        assert_eq!(
            with_legacy_rule(|| restore(&dir, "nzo_r1")),
            (None, Some(JobState::Failed)),
            "the §158 rule is supposed to revert the retry - if it does \
             not, this harness is not exercising the window"
        );

        // ...and what this change does with the same bytes.
        let d = test_daemon(&dir);
        rewind(&d, &snap);
        drop(d);
        assert_eq!(
            restore(&dir, "nzo_r1"),
            (Some(JobState::Queued), None),
            "the retry must survive the crash"
        );

        // The resolution is durable, not re-derived: the stale history
        // line is tombstoned, so deleting the queue row later cannot
        // resurrect the record as a Failed one.
        let (_, h) = on_disk(&dir, "nzo_r1");
        assert_eq!(h, None, "the losing history row was left to resurrect");
        assert_eq!(
            restore(&dir, "nzo_r1"),
            (Some(JobState::Queued), None),
            "a second boot must reach the same answer"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The same cut on the OTHER history -> queue path: a library entry
    /// activated by /stream, killed before its tombstone.
    #[test]
    fn a_half_written_library_activation_is_no_longer_reverted() {
        let dir = tmp("stream-cut");
        let d = test_daemon(&dir);
        let j = job(&d, "nzo_s1", JobState::Completed);
        {
            let mut g = j.lock_ok();
            g.library = true;
            g.fetched = false;
        }
        d.history.lock_ok().push(j.clone());
        assert!(d.history_upsert(std::slice::from_ref(&j)));
        assert!(d.save_queue());

        // Exactly what `stream_request` does to the record before it
        // hands the move over.
        {
            let mut g = j.lock_ok();
            g.state = JobState::Queued;
            g.priority = 2;
            g.paused = false;
        }
        super::super::storecut::arm_cut(1);
        d.activate_parked(&j);
        super::super::storecut::disarm();

        let (q, h) = on_disk(&dir, "nzo_s1");
        assert_eq!(q, Some((JobState::Queued, 1)));
        assert_eq!(h, Some((JobState::Completed, 0)));

        let snap = snapshot(&d);
        drop(d);
        assert_eq!(
            with_legacy_rule(|| restore(&dir, "nzo_s1")),
            (None, Some(JobState::Completed)),
            "the §158 rule sends the play back to the library"
        );
        let d = test_daemon(&dir);
        rewind(&d, &snap);
        drop(d);
        assert_eq!(
            restore(&dir, "nzo_s1"),
            (Some(JobState::Queued), None),
            "the download the play triggered must survive the crash"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The half the change must NOT break: a FAILURE park killed between
    /// its history row and the queue rewrite still resolves in history's
    /// favour, under either rule.
    ///
    /// This is the F1 duplicate-and-rerun cut. The stale queue row is
    /// `Finishing` - post-processing persisted it, the failure changed it
    /// in memory only - and `job_wire` restores it as `Queued`, so
    /// getting this wrong downloads the whole release a second time.
    #[test]
    fn a_half_written_failure_park_still_resolves_to_history() {
        let dir = tmp("park-fail");
        assert_eq!(
            park_torn(&dir, "nzo_p1", JobState::Failed),
            ((JobState::Queued, 0), (JobState::Failed, 1)),
        );
        let d = test_daemon(&dir);
        let snap = snapshot(&d);
        drop(d);
        assert_eq!(
            with_legacy_rule(|| restore(&dir, "nzo_p1")),
            (None, Some(JobState::Failed)),
        );
        let d = test_daemon(&dir);
        rewind(&d, &snap);
        drop(d);
        assert_eq!(
            restore(&dir, "nzo_p1"),
            (None, Some(JobState::Failed)),
            "the park half was already right and must stay right"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// ...and the success park, which tears identically and whose queued
    /// copy would re-download a release that is already on disk.
    #[test]
    fn a_half_written_success_park_still_resolves_to_history() {
        let dir = tmp("park-ok");
        assert_eq!(
            park_torn(&dir, "nzo_p2", JobState::Completed),
            ((JobState::Queued, 0), (JobState::Completed, 1)),
        );
        let d = test_daemon(&dir);
        let snap = snapshot(&d);
        drop(d);
        assert_eq!(
            with_legacy_rule(|| restore(&dir, "nzo_p2")),
            (None, Some(JobState::Completed)),
        );
        let d = test_daemon(&dir);
        rewind(&d, &snap);
        drop(d);
        assert_eq!(
            restore(&dir, "nzo_p2"),
            (None, Some(JobState::Completed)),
            "a finished release must not be queued for a second download"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Drive a park to its torn state: the job is persisted into
    /// queue.json as `Finishing`, reaches `outcome` in memory only, and
    /// the process dies after the history append and before the queue
    /// rewrite. Returns what each store holds afterwards.
    fn park_torn(dir: &Path, id: &str, outcome: JobState) -> ((JobState, u64), (JobState, u64)) {
        let d = test_daemon(dir);
        let j = job(&d, id, JobState::Finishing);
        d.queue.lock_ok().push_back(j.clone());
        assert!(
            d.save_queue(),
            "the Finishing row is the durable write park tears from"
        );
        j.lock_ok().state = outcome;

        // The kill: the history append lands, the queue rewrite that
        // would drop the row never runs.
        super::super::storecut::arm_cut(1);
        d.park_gen(j, None);
        super::super::storecut::disarm();

        let (q, h) = on_disk(dir, id);
        (
            q.expect("the stale queue row is the whole tear"),
            h.expect("park's history append must have landed"),
        )
    }

    /// The dir-claim fence: from the instant `park` drops the row from
    /// the live queue until it files the record into `self.history`,
    /// the job is in neither store in memory - so `dir_claim` reads its
    /// canonical directory as free, and an add landing in the window is
    /// handed the folder of a finished payload, whose first decoded
    /// span truncates it. Directory decisions run under `add_lock`, so
    /// the fence is that park holds it across the window.
    #[test]
    fn a_park_holds_the_add_lock_across_its_neither_store_window() {
        let dir = tmp("park-claim");
        let d = test_daemon(&dir);
        let j = job(&d, "nzo_a1", JobState::Finishing);
        let out = j.lock_ok().out_dir.clone();
        d.queue.lock_ok().push_back(j.clone());
        assert!(d.save_queue());
        j.lock_ok().state = JobState::Completed;
        let probed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = probed.clone();
        let out2 = out.clone();
        super::super::storecut::on_park_gap(move |d| {
            // The window is real: the record is in neither store, so the
            // claim scan itself answers Free here...
            assert!(
                matches!(d.dir_claim(&out2), DirClaim::Free),
                "the record is in neither store, so the scan answers Free"
            );
            // ...which is exactly why no add may be ALLOWED to scan: the
            // deciders all take `add_lock` first, and park must be
            // holding it.
            assert!(
                d.add_lock.try_lock().is_err(),
                "the add lock is free inside park's neither-store window - \
                 a concurrent add could claim this job's directory"
            );
            flag.store(true, Ordering::Relaxed);
        });
        d.park_gen(j, None);
        super::super::storecut::disarm();
        assert!(probed.load(Ordering::Relaxed), "the gap seam never fired");
        // Released once the record is filed, and the record answers for
        // its directory again.
        assert!(d.add_lock.try_lock().is_ok());
        assert!(
            d.history
                .lock_ok()
                .iter()
                .any(|x| x.lock_ok().nzo_id == "nzo_a1"),
            "the parked record must be in history"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The same fence on the other move: `activate_parked` takes the
    /// record out of history before it reaches the queue, and used to
    /// take no `add_lock` at all.
    #[test]
    fn an_activation_holds_the_add_lock_across_its_neither_store_window() {
        let dir = tmp("activate-claim");
        let d = test_daemon(&dir);
        let j = job(&d, "nzo_a2", JobState::Completed);
        {
            let mut g = j.lock_ok();
            g.library = true;
            g.fetched = false;
        }
        d.history.lock_ok().push(j.clone());
        assert!(d.history_upsert(std::slice::from_ref(&j)));
        assert!(d.save_queue());
        {
            let mut g = j.lock_ok();
            g.state = JobState::Queued;
            g.priority = 2;
            g.paused = false;
        }
        let probed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = probed.clone();
        super::super::storecut::on_activate_gap(move |d| {
            assert!(
                d.add_lock.try_lock().is_err(),
                "the add lock is free inside the activation's neither-store \
                 window - a concurrent add could claim this job's directory"
            );
            flag.store(true, Ordering::Relaxed);
        });
        d.activate_parked(&j);
        super::super::storecut::disarm();
        assert!(probed.load(Ordering::Relaxed), "the gap seam never fired");
        assert!(d.add_lock.try_lock().is_ok());
        assert!(
            d.queue
                .lock_ok()
                .iter()
                .any(|x| x.lock_ok().nzo_id == "nzo_a2"),
            "the activated record must be in the queue"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The rule itself, without a filesystem: a tie keeps the §158
    /// answer, which is what every record written before this field
    /// existed produces.
    #[test]
    fn an_unstamped_pair_resolves_the_way_it_always_did() {
        assert_eq!(move_winner(0, 0), MoveWinner::History);
        assert_eq!(move_winner(3, 3), MoveWinner::History);
        assert_eq!(move_winner(1, 2), MoveWinner::History);
        assert_eq!(move_winner(2, 1), MoveWinner::Queue);
    }

    /// Reconciliation touches only the ids that are genuinely in both
    /// stores. Without this the rules above would be indistinguishable
    /// from "drop one of the two lists".
    #[test]
    fn reconciliation_leaves_unrelated_records_alone() {
        let v = |id: &str, state: &str, seq: u64| {
            job_from_json(&json!({
                "nzo_id": id, "name": "R", "out_dir": "/tmp/o",
                "nzb_path": "/tmp/n.nzb", "state": state, "move_seq": seq,
            }))
            .expect("job")
        };
        let (queued, history, split) = reconcile_moves(
            vec![v("only_queued", "Queued", 0), v("both", "Queued", 4)],
            vec![v("only_parked", "Completed", 0), v("both", "Failed", 3)],
        );
        assert_eq!(
            queued.iter().map(|j| j.nzo_id.as_str()).collect::<Vec<_>>(),
            ["only_queued", "both"]
        );
        assert_eq!(
            history
                .iter()
                .map(|j| j.nzo_id.as_str())
                .collect::<Vec<_>>(),
            ["only_parked"]
        );
        assert_eq!(split.reverted, ["both"]);
        assert!(split.parked.is_empty());
    }

    /// Q1 (Codex sweep 13 Aug): a retry's tombstone, delayed behind its
    /// own slow queue save, must not erase the NEWER park generation
    /// that landed meanwhile.
    ///
    /// Schedule, held open by the commit barrier rather than a sleep:
    /// the retry stamps seq 1 and saves the queue; before its tombstone
    /// lands, the resumed job runs, fails and parks again at seq 2,
    /// appending its terminal history row and dropping itself from the
    /// queue; the retry's tombstone then lands LAST. Id-only, it deleted
    /// the seq-2 row - and the queue save had already omitted the parked
    /// job, so the record was in neither store after a restart, no crash
    /// needed. Generation-bound, it buries only seq <= 1.
    #[test]
    fn a_delayed_retry_tombstone_cannot_erase_a_newer_park() {
        let dir = tmp("tomb-race");
        let d = test_daemon(&dir);
        let j = job(&d, "nzo_t1", JobState::Failed);
        d.history.lock_ok().push(j.clone());
        assert!(d.history_upsert(std::slice::from_ref(&j)));
        assert!(d.save_queue());

        let entered = Arc::new(std::sync::Barrier::new(2));
        let released = Arc::new(std::sync::Barrier::new(2));
        *COMMIT_TOMB_BARRIER.lock_ok() =
            Some(("nzo_t1".to_string(), entered.clone(), released.clone()));
        let retry = {
            let d = d.clone();
            std::thread::spawn(move || assert!(d.retry("nzo_t1")))
        };
        // The retry has saved the queue (seq 1) and is held before its
        // tombstone. Disarm the seam for THIS thread's park commit paths.
        entered.wait();
        *COMMIT_TOMB_BARRIER.lock_ok() = None;

        // The resumed job runs and fails again: the real park, seq 2.
        let jq = d
            .queue
            .lock_ok()
            .iter()
            .find(|x| x.lock_ok().nzo_id == "nzo_t1")
            .cloned()
            .expect("the retried job is in the queue");
        jq.lock_ok().state = JobState::Failed;
        d.park_gen(jq, None);

        // ...and only now does the retry's tombstone land.
        released.wait();
        retry.join().unwrap();

        let (q, h) = on_disk(&dir, "nzo_t1");
        assert_eq!(
            h,
            Some((JobState::Failed, 2)),
            "the retry's stale tombstone erased the newer parked record"
        );
        assert_eq!(q, None, "the parked job must not also be queued");
        assert_eq!(
            restore(&dir, "nzo_t1"),
            (None, Some(JobState::Failed)),
            "a restart must find the park, in history, exactly once"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Q2 (Codex sweep 13 Aug): "Save queue" compacting history inside a
    /// park's window must not erase the park's durable prewrite.
    ///
    /// The window is real code: park prewrites the history row to DISK,
    /// drops the job from the live queue, and only files it into
    /// `self.history` after the give-up bookkeeping. `history_compact`
    /// snapshots memory, so a compaction run in that window published a
    /// history.jsonl without the row - and the queue save beside it had
    /// already omitted the job. If the park's later writes then never
    /// land (a kill), the record was in neither store. The in-flight
    /// carry-over keeps the disk row in the snapshot.
    #[test]
    fn a_compaction_inside_a_park_keeps_the_prewrite() {
        let dir = tmp("park-compact");
        let d = test_daemon(&dir);
        let j = job(&d, "nzo_c1", JobState::Finishing);
        d.queue.lock_ok().push_back(j.clone());
        assert!(d.save_queue());
        j.lock_ok().state = JobState::Failed;

        super::super::storecut::on_park_gap(|d| {
            // The exact interval: prewrite on disk, row out of the live
            // queue, record not yet in self.history.
            assert!(
                !d.history
                    .lock_ok()
                    .iter()
                    .any(|x| x.lock_ok().nzo_id == "nzo_c1"),
                "the gap fires before the record is filed"
            );
            // The API's "Save queue": queue save + compaction, live.
            assert!(d.save_queue());
            assert!(d.history_compact());
            // ...and the kill: every later durable write of this park -
            // the final upsert - is dropped.
            super::super::storecut::arm_cut(0);
        });
        d.park_gen(j, None);
        super::super::storecut::disarm();

        let (q, h) = on_disk(&dir, "nzo_c1");
        assert_eq!(q, None, "the queue save inside the gap dropped the row");
        assert_eq!(
            h.map(|(s, _)| s),
            Some(JobState::Failed),
            "the compaction erased the park's prewrite - the record \
             survives in NEITHER store"
        );
        assert_eq!(
            restore(&dir, "nzo_c1"),
            (None, Some(JobState::Failed)),
            "a restart must recover the parked record from the prewrite"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A compaction must not flatten `move_seq`, or the next torn park
    /// resolves the wrong way and re-downloads a finished release.
    ///
    /// `history_compact` re-serializes every in-memory record from
    /// scratch, and "Save queue" runs one on a live daemon, so it is the
    /// one durable write in this story whose counter nothing above
    /// asserts: every cut test reads a row that `park_gen` or `retry`
    /// wrote directly. The field survives today only because there is a
    /// single serializer (`job_wire::job_json`) and compaction goes
    /// through it - a property, not a decision anybody wrote down.
    ///
    /// Trimming the record here is the obvious future edit, history.jsonl
    /// being the file that grows without bound. It would leave a parked
    /// row reading 0 beside the stale queue row at seq N that a torn park
    /// left behind, and `move_winner` reads that as the QUEUE being the
    /// newer intent - which is the F1 duplicate-and-rerun cut coming back
    /// through the back door, on a store that had merely been compacted.
    ///
    /// MEASURED, not assumed (23 Aug 2026): with `history_compact` forced
    /// to write `move_seq: 0`, this test fails on its own message and
    /// `a_newer_terminal_queue_snapshot_beats_stale_history` fails too -
    /// so the shape was not a blind spot, but the only test that caught
    /// it caught it INCIDENTALLY, through the compaction `load_queue`
    /// runs to make a resolution durable, and reported it as a seq 2 that
    /// read 0 with no mention of compaction. The other ten stay green, so
    /// what this one adds is naming the cause rather than finding the
    /// defect.
    ///
    /// Asserted twice over: the field off disk, and then the RESOLUTION
    /// it exists to decide, so the pin survives a rename of the field.
    #[test]
    fn a_compaction_preserves_the_move_counter() {
        let dir = tmp("compact-seq");
        let d = test_daemon(&dir);
        let j = job(&d, "nzo_k1", JobState::Finishing);
        d.queue.lock_ok().push_back(j.clone());
        assert!(d.save_queue());
        j.lock_ok().state = JobState::Completed;
        // A whole park, uncut: both durable writes land.
        d.park_gen(j, None);
        assert_eq!(
            on_disk(&dir, "nzo_k1").1,
            Some((JobState::Completed, 1)),
            "precondition: the park stamped its move"
        );

        // "Save queue" on a live daemon: the whole store rewritten from
        // the in-memory records.
        assert!(d.history_compact());
        assert_eq!(
            on_disk(&dir, "nzo_k1").1,
            Some((JobState::Completed, 1)),
            "the compaction flattened the move counter"
        );

        // ...and the consequence, stated as a resolution rather than as a
        // field: the stale seq-0 queue row a torn park leaves behind must
        // still lose to the compacted history row.
        let stale = job_from_json(&json!({
            "nzo_id": "nzo_k1", "name": "Release.nzo_k1", "out_dir": "/tmp/o",
            "nzb_path": "/tmp/n.nzb", "state": "Queued", "move_seq": 0,
        }))
        .expect("job");
        let (_, _, split) = reconcile_moves(vec![stale], d.history_replay().0);
        assert_eq!(
            split.parked,
            ["nzo_k1"],
            "a compacted park lost to the stale queue row it tore from - \
             the release would be downloaded a second time"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Q3 (Codex sweep 13 Aug): a TERMINAL queue snapshot carrying a
    /// higher `move_seq` than the stored history row is the newer
    /// outcome and must win - it used to be discarded on id alone,
    /// which reverted a finished retry to its previous failure.
    #[test]
    fn a_newer_terminal_queue_snapshot_beats_stale_history() {
        let dir = tmp("routed-seq");
        let d = test_daemon(&dir);
        let row = |state: &str, seq: u64, msg: &str| {
            json!({
                "nzo_id": "nzo_q3", "name": "Release.q3",
                "out_dir": "/tmp/o", "nzb_path": "/tmp/n.nzb",
                "state": state, "move_seq": seq, "fail_message": msg,
            })
            .to_string()
        };
        // The stale seq-1 failure the retry was retrying...
        std::fs::write(
            d.history_store_path(),
            format!("{}\n", row("Failed", 1, "articles missing")),
        )
        .unwrap();
        // ...and the retry's terminal seq-2 snapshot, persisted into
        // queue.json by a save during post-processing, crash before the
        // history cleanup.
        std::fs::write(
            d.spool.join("queue.json"),
            format!(r#"{{"next_id":9,"queue":[{}]}}"#, row("Completed", 2, "")),
        )
        .unwrap();
        drop(d);

        assert_eq!(
            restore(&dir, "nzo_q3"),
            (None, Some(JobState::Completed)),
            "the newer terminal outcome must be the one restored"
        );
        // Durably: the resolution ran a compaction, so the store now
        // holds the winner and a second boot - where the still-routed
        // queue row ties against it - reads the same answer.
        let (_q, h) = on_disk(&dir, "nzo_q3");
        assert_eq!(h, Some((JobState::Completed, 2)));
        assert_eq!(
            restore(&dir, "nzo_q3"),
            (None, Some(JobState::Completed)),
            "a second boot must reach the same answer"
        );

        // The other direction is unchanged: history newer (a park that
        // landed after the queue snapshot) keeps the history copy.
        let d = test_daemon(&dir);
        std::fs::write(
            d.history_store_path(),
            format!("{}\n", row("Failed", 3, "wrong password")),
        )
        .unwrap();
        std::fs::write(
            d.spool.join("queue.json"),
            format!(r#"{{"next_id":9,"queue":[{}]}}"#, row("Completed", 2, "")),
        )
        .unwrap();
        let _ = std::fs::remove_file(d.spool.join("queue.json.bak"));
        drop(d);
        assert_eq!(
            restore(&dir, "nzo_q3"),
            (None, Some(JobState::Failed)),
            "a newer history row still wins over a stale queue snapshot"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
