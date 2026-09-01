//! §129 phase 1a: history's own store.
//!
//! History used to ride inside `queue.json`, which `save_queue` rewrote
//! wholesale - queue AND every history record, pretty-printed, fsync'd,
//! under one process-wide mutex - on every mutation anywhere in the
//! daemon. With history now UNLIMITED by default (a product ruling),
//! that made every pause/add/delete an O(all-time) disk write. The store
//! here splits history into `.spool/history.jsonl`, one compact
//! `job_json` line per record, append-only:
//!
//!  * a job PARKING appends its record;
//!  * the rare history MUTATIONS (recategorize, unlock, mover
//!    bookkeeping...) append a fresh line for the same nzo_id - the
//!    LAST line for an id wins on replay;
//!  * a delete (or a retry/stream pulling the record back into the
//!    queue) appends a tombstone line `{"nzo_id": ..., "deleted": true}`.
//!
//! Replay tolerates a torn tail (a crash mid-append costs at most that
//! one line) and compacts the file - one line per live record - when
//! more than half the lines are dead. `queue.json` keeps `next_id` +
//! the live queue only; a legacy file still carrying a "history" array
//! is read once and split (see `Daemon::load_queue`).
//!
//! Revision discipline: every write here bumps `history_rev`, which is
//! what `mode=dashboard` hands to clients so an unchanged history costs
//! an atomic load instead of a payload. Bumping at the persistence seam
//! is deliberate - a history change that should survive a restart MUST
//! come through here, so the seam sees every change by construction.

use super::*;
use std::io::Write as _;

/// ONE publication lock for `history.jsonl`: every append, tombstone and
/// the compacting rewrite take it.
///
/// Same discipline as save_queue's IO lock (two workers appending must
/// not interleave bytes), and a separate lock so history appends do not
/// queue behind full queue.json rewrites - but it covers the REWRITE
/// too, which it did not until the 10 Aug sweep (H3). Compaction
/// snapshots the live rows and renames a replacement over the file; an
/// append that landed after that snapshot was published into the file
/// the rename then replaced, and the transition - a park, an upsert, a
/// delete's tombstone - was simply gone at the next boot. The lock makes
/// snapshot-and-publish indivisible against the appenders, so a
/// concurrent transition is either inside the snapshot or appended after
/// the rename, never lost between them.
static HIST_IO: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Test seam: a barrier `history_compact` trips between snapshotting the
/// live rows and publishing the replacement.
///
/// The H3 regression is a two-thread ordering, and a sleep-based test
/// either misses the window or goes flaky. Parking the compaction
/// exactly in the gap lets the test hold it open and prove what an
/// appender does there - which, with the lock in place, is wait.
///
/// Keyed by the owning daemon's spool path: the bin tests run in
/// parallel and `history_compact` is on the save-queue path, so an
/// unkeyed seam pairs this test's compactor with a stranger's and the
/// test's own `wait()` then never returns (the 15 Aug
/// `daemon_park::PARK_GEN_BARRIER` wedge, same shape).
#[cfg(test)]
pub(super) static COMPACT_BARRIER: std::sync::Mutex<Option<(String, Arc<std::sync::Barrier>)>> =
    std::sync::Mutex::new(None);

/// What a `_if_present` upsert actually did.
///
/// The helper answered a bare bool, and its false conflates two
/// opposite things: "the record left history while you were working, so
/// nothing was owed" - the ordinary mover/unlock/prober race, and the
/// reason the guard exists - and "the record is right here and the
/// store refused the line". Only the second is a fault, and a caller
/// that logs or reports on a bool logs the daemon's healthy races too
/// (Codex sweep 7, M5 follow-up).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum HistWrite {
    /// The record's current state is on disk.
    Wrote,
    /// Nothing was written because nothing was owed: the record is not
    /// in history (the `_if_present` race this enum was minted for), or
    /// it is not bound for history at all (`park_prewrite`'s demote arm,
    /// which returns the job to the queue).
    Absent,
    /// The record IS in history and could not be written. Its current
    /// state is live in memory and nowhere else.
    Refused,
}

impl Daemon {
    pub(super) fn history_store_path(&self) -> PathBuf {
        self.spool.join("history.jsonl")
    }

    /// Append pre-serialized lines and bump the revision. One fsync per
    /// call, not per line; callers batch. Best-effort like save_queue -
    /// a failed write must never take down a live daemon - but logged,
    /// because a silent miss here is a history row lost across restart.
    ///
    /// A CALLER WHOSE MISS COSTS MORE THAN A ROW does not stop at that
    /// trade: [`Daemon::history_publish`] on the mutation side, and
    /// `delete_prewrite` / `history_tombstone` on the removal side, take
    /// [`HIST_IO`] themselves and stand the atomic rewrite in for a
    /// refused append rather than logging and carrying on. The rewrite
    /// needs only the DIRECTORY, which is the whole way out of the
    /// commonest refusal there is - see
    /// [`Daemon::history_rescue_locked`]. What is left on this bare path
    /// is the caller whose refusal really does cost one row.
    fn history_append(&self, lines: &[String]) -> bool {
        if lines.is_empty() {
            return true;
        }
        let _g = HIST_IO.lock_ok();
        self.history_write_locked(lines)
    }

    /// The append itself, with [`HIST_IO`] ALREADY held. Split out so a
    /// caller that must decide something under the same lock (the
    /// present-check in `history_upsert_if_present`) can do so without
    /// dropping it between the decision and the write.
    fn history_write_locked(&self, lines: &[String]) -> bool {
        // §158 item 7: the harness's kill-here seam, matching save_queue's.
        #[cfg(test)]
        if super::storecut::cut_here(super::storecut::Store::HistoryAppend) {
            return false;
        }
        let path = self.history_store_path();
        // 0600 on unix, for the same reason `persist::write_atomic`
        // does it: these rows are daemon-private and carry credentials.
        // A history record serializes the job's archive `password`
        // (job_wire.rs), its local paths and its identity metadata, and
        // this file is created by plain append - so under the ordinary
        // 022 umask it landed 0644 and stayed world-readable for the
        // life of the store, since compaction (which does go through
        // the private path) may not run for weeks. `mode` applies only
        // to creation, so an existing file keeps whatever it has.
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).append(true).read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let r = opts.open(&path).and_then(|mut f| {
            let mut buf = String::with_capacity(lines.iter().map(|l| l.len() + 1).sum());
            // A crash mid-append leaves the file without its final
            // newline, and replay's per-line tolerance budgets that at
            // ONE lost line. Appending straight after the torn bytes
            // welded the first post-recovery record onto them into one
            // unreadable line, so the NEXT replay dropped this record
            // with the tear - a park or tombstone written after a crash
            // was silently gone two restarts later (Codex sweep 24 Aug,
            // F-03). One leading newline turns the weld back into "torn
            // line, then this record", the shape replay already
            // handles. Read through the same handle: `append` binds
            // WRITES to the end, reads seek freely.
            {
                use std::io::{Read, Seek, SeekFrom};
                if f.metadata()?.len() > 0 {
                    f.seek(SeekFrom::End(-1))?;
                    let mut last = [0u8; 1];
                    f.read_exact(&mut last)?;
                    if last[0] != b'\n' {
                        buf.push('\n');
                    }
                }
            }
            for l in lines {
                buf.push_str(l);
                buf.push('\n');
            }
            f.write_all(buf.as_bytes())?;
            f.sync_all()
        });
        let ok = match r {
            Ok(()) => true,
            Err(e) => {
                error!(target: "queue", "history store {}: {e}", path.display());
                false
            }
        };
        self.history_rev.fetch_add(1, Ordering::Relaxed);
        ok
    }

    /// Persist the CURRENT state of history records that changed: one
    /// fresh line each, last-wins on replay. Callers pass the records
    /// AFTER mutating them, with no history/job locks held. Returns
    /// whether the write landed (recategorize reports durability).
    pub(super) fn history_upsert(&self, jobs: &[Arc<Mutex<Job>>]) -> bool {
        let lines: Vec<String> = jobs
            .iter()
            .map(|j| job_json(&j.lock_ok()).to_string())
            .collect();
        self.history_append(&lines)
    }

    /// Upsert ONLY when the record is currently in history. The mover
    /// and unlock tasks mutate a job they hold an Arc to, and by the
    /// time they persist, a delete may have pulled it out - appending
    /// then would resurrect the record at the next boot. (A queue job
    /// must never reach the store either; replay would mint a phantom
    /// history row for it.)
    ///
    /// The check and the append happen under ONE hold of [`HIST_IO`],
    /// which is what makes the guard true rather than likely: the check
    /// used to drop the history lock before serializing, and a delete
    /// that removed the row and appended its tombstone in that window
    /// left the stale upsert as the LAST line for the id - replay then
    /// resurrected exactly the record this guard exists to bury (H6,
    /// 10 Aug sweep). A delete either finishes first (the check sees the
    /// record gone and writes nothing) or waits here for the lock and
    /// tombstones after (the tombstone stays last).
    ///
    /// Returns what happened. The outcome used to be dropped by a
    /// semicolon, and `history_write_locked` is the only append path
    /// there is: a store that cannot be appended to logs an error and
    /// carries on, which is right for a live daemon but left every
    /// caller believing its mutation had persisted (Codex sweep 7, M5).
    /// [`HistWrite`] rather than a bool because the not-present arm
    /// writes nothing either, and that one is not a fault - see the
    /// enum's own note.
    ///
    /// Most callers want [`Daemon::history_publish`], which stands the
    /// atomic rewrite in for a refused append and says what the refusal
    /// cost. This is the raw one, for the bulk migration pass whose
    /// answer to a refusal is to leave its version stamp alone.
    pub(super) fn history_upsert_if_present(&self, job: &Arc<Mutex<Job>>) -> HistWrite {
        let _g = HIST_IO.lock_ok();
        if !self.history.lock_ok().iter().any(|j| Arc::ptr_eq(j, job)) {
            return HistWrite::Absent;
        }
        let line = job_json(&job.lock_ok()).to_string();
        match self.history_write_locked(&[line]) {
            true => HistWrite::Wrote,
            false => HistWrite::Refused,
        }
    }

    /// Persist a history record the caller has just mutated, and say
    /// what a refusal costs when it cannot be persisted at all.
    ///
    /// Three outcomes, and the middle one is why this exists:
    ///
    ///  * the append lands, which is every ordinary call;
    ///  * the append is REFUSED and the atomic rewrite publishes the
    ///    record instead. The asymmetry that hid M5 is also the way out
    ///    of it: `history_write_locked` appends to the file, so it needs
    ///    write permission ON THE FILE, while `history_compact` goes
    ///    through `persist::write_atomic` - private temp file, rename -
    ///    and needs only the DIRECTORY. A store left 0444, owned by a
    ///    uid this daemon no longer runs as (one `sudo nzbfast` is
    ///    enough) or holding an immutable flag is REPLACED by a file
    ///    this daemon owns, so the append after it works too. The record
    ///    is in `self.history` by construction here - the append just
    ///    checked - so the rewrite's memory snapshot carries it;
    ///  * both refuse, which is a data folder this daemon cannot write
    ///    at all. Nothing is left to try, so `cost` names what the
    ///    record loses at the next start. It is logged, and raised on
    ///    the event ring so it reaches the dashboard rather than only a
    ///    log file nobody is reading at 3am.
    ///
    /// `cost` is a closure because the ordinary path must not pay to
    /// format a sentence nobody will read. Callers carry on either way:
    /// a live daemon whose disk went read-only still has a queue to run,
    /// and the in-memory record is correct - what was lost is its
    /// survival across a restart.
    pub(super) fn history_publish(
        &self,
        job: &Arc<Mutex<Job>>,
        cost: impl FnOnce() -> String,
    ) -> HistWrite {
        match self.history_upsert_if_present(job) {
            HistWrite::Refused => {}
            settled => return settled,
        }
        let Some(now) = self.hist_rescue_open() else {
            self.hist_report_refusal(cost, false);
            return HistWrite::Refused;
        };
        if self.history_compact() {
            return HistWrite::Wrote;
        }
        self.hist_rescue_failed(now);
        self.hist_report_refusal(cost, true);
        HistWrite::Refused
    }

    /// The sentence a store refusal owes, in ONE place - both the
    /// mutation side ([`Daemon::history_publish`]) and the park's
    /// prewrite say it, and a rule written twice drifts.
    ///
    /// `on_ring` is the whole of the difference between the two exits,
    /// and it is a RATE LIMIT rather than a judgement about severity.
    /// Both callers reach this from two places: the rescue was GATED
    /// (some other caller tried and failed inside the last minute, so
    /// this one did not even attempt it) and the rescue was ATTEMPTED
    /// and failed. Only the second raises the event, so a data folder
    /// that is not coming back costs the ring one entry a minute instead
    /// of one per job event - the same argument
    /// [`Daemon::hist_rescue_open`] makes about the write itself.
    ///
    /// `cost` stays a closure all the way in: the ordinary path must not
    /// pay to format a sentence nobody will read.
    fn hist_report_refusal(&self, cost: impl FnOnce() -> String, on_ring: bool) {
        let cost = cost();
        error!(target: "queue", "history store refused the write - {cost}");
        if on_ring {
            self.note_event("disk", format!("history not saved - {cost}"));
        }
    }

    /// [`Daemon::history_publish`] with the ordinary cost sentence, for
    /// the callers whose whole loss is "this change goes back to the
    /// line already in the store at the next start" - a media chip, a
    /// verdict a later pass will reach again, a password.
    ///
    /// `what` names the change from the user's side, so the log line
    /// reads as a consequence rather than as a stack of field names.
    /// The callers that owe a SHARPER sentence - the movers, whose
    /// refused line leaves the record pointing at a folder the payload
    /// has left - call `history_publish` directly and name both paths.
    pub(super) fn history_publish_change(&self, job: &Arc<Mutex<Job>>, what: &str) -> HistWrite {
        self.history_publish(job, || {
            format!(
                "{}: {what} did not reach the store - a restart undoes the change",
                job.lock_ok().name
            )
        })
    }

    /// `history_publish` for the three callers that publish a MOVED
    /// payload's new folder: the mover step, its redrive, and the
    /// unlock re-run whose `finalize_names` relocated the files.
    ///
    /// Their loss is the sharp one, which is why they get a sentence of
    /// their own. The other refusals here cost a field the next pass
    /// re-derives; this one leaves the record naming a folder the
    /// payload has left, and the row - and the delete, retry, play and
    /// *arr import that read it - points at nothing from the next start
    /// on. `from` is where the record said the files were, `to` where
    /// they went (None when nothing moved after all).
    ///
    /// Moving the bytes back was considered and rejected: a second bulk
    /// copy that can itself fail part way turns a record with the wrong
    /// path into a payload split across two folders, which is the worse
    /// state - it is the one `move_split` exists to warn about.
    pub(super) fn history_publish_move(
        &self,
        job: &Arc<Mutex<Job>>,
        from: &std::path::Path,
        to: Option<&std::path::Path>,
    ) -> HistWrite {
        self.history_publish(job, || {
            let name = job.lock_ok().name.clone();
            match to {
                Some(dest) => format!(
                    "{name}: the payload moved to {} but its history row still says \
                     {} - after a restart the row points at a folder the files have \
                     left",
                    dest.display(),
                    from.display()
                ),
                None => format!(
                    "{name}: the move outcome did not reach the store - a restart \
                     undoes the change"
                ),
            }
        })
    }

    /// The one-a-minute gate every rewrite RESCUE takes before standing
    /// the atomic rewrite in for a refused append.
    ///
    /// The rewrite writes every live record, so a folder that is not
    /// coming back must not turn each job event into a full-store write.
    /// `None` means the last attempt failed less than a minute ago and
    /// this one must not be made; `Some(now)` is the clock to hand
    /// [`Daemon::hist_rescue_failed`] if it fails. A rewrite that LANDS
    /// clears nothing, because it heals the store and the next caller is
    /// back to appending.
    fn hist_rescue_open(&self) -> Option<u64> {
        let now = nzbkit::pool::now_ms();
        let last = self.hist_rewrite_fail_ms.load(Ordering::Relaxed);
        (last == 0 || now.saturating_sub(last) >= 60_000).then_some(now)
    }

    /// The other half of [`Daemon::hist_rescue_open`]: stamp a rewrite
    /// that was attempted and failed, so the next minute's callers skip
    /// straight past it.
    fn hist_rescue_failed(&self, now: u64) {
        self.hist_rewrite_fail_ms
            .store(now.max(1), Ordering::Relaxed);
    }

    /// Stand the atomic rewrite in for an append this store refused, with
    /// [`HIST_IO`] ALREADY held. Returns whether the store now says what
    /// the refused line said.
    ///
    /// [`Daemon::history_publish`] is the same move on the mutation side
    /// and carries the argument at length: the append needs write
    /// permission ON THE FILE while the rewrite goes through
    /// `persist::write_atomic` and needs only the DIRECTORY, so a
    /// `history.jsonl` left 0444, owned by a uid this daemon no longer
    /// runs as (one `sudo nzbfast` is enough) or holding an immutable
    /// flag is REPLACED by a file this daemon owns. That asymmetry is the
    /// whole of P2-1's trigger, so it is also the whole of its way out -
    /// a delete's tombstone and a delete's placeholder get the same
    /// second chance a recategorize has had since M5.
    ///
    /// Its own function rather than `history_publish`'s, because THIS one
    /// must run under the lock. A removal that dropped [`HIST_IO`]
    /// between "the append was refused" and "rewrite the store without
    /// the record" would let an `history_upsert_if_present` land in
    /// between and write back the very record the rewrite is about to
    /// omit - the H6 shape, one store-write further out.
    fn history_rescue_locked(&self, extra: &[String], drop_ids: &[String]) -> bool {
        let Some(now) = self.hist_rescue_open() else {
            return false;
        };
        if self.history_rewrite_locked(extra, drop_ids) {
            return true;
        }
        self.hist_rescue_failed(now);
        false
    }

    /// §158 item 7: a park's history row, written BEFORE the row leaves
    /// the live queue. Returns whether it landed.
    ///
    /// Dropping the queue row publishes a queue.json without it the moment
    /// any other thread saves - every queue mutation in the daemon calls
    /// `save_queue` - and until `park` reached its `history_upsert`, past
    /// the give-up bookkeeping and that bookkeeping's own file write, the
    /// record was in NEITHER store. A kill or an ENOSPC in that window
    /// lost it outright: gone from the queue, absent from history, its
    /// payload on disk named by no record anywhere. Written first, the
    /// torn state is "in both", which `load_queue` already reconciles in
    /// history's favour.
    ///
    /// `dropping` is not a convenience: a record that is NOT bound for
    /// history must not be written here. `park`'s demote arm returns the
    /// job to the queue, and a history line for it would make that same
    /// reconciliation drop the requeued row. It is narrower than
    /// "tombstoned" - an M5 delete verb's tombstone IS filed into
    /// history, so the caller passes false for that one and this row is
    /// what covers the interval before it lands.
    ///
    /// Not the final word on the record either. The auto-retry stamps and
    /// the demote scrub settle it afterwards and the upsert beside the
    /// history push writes it again; last line wins on replay, so this one
    /// only has to EXIST.
    ///
    /// [`HistWrite`] AND NOT A BOOL, for the reason that enum was minted:
    /// a `false` here conflated "this park is dropping the record, so no
    /// row was owed" with "the row was owed and the store would not take
    /// it", and the caller bound the pair to one `filed_early` flag. The
    /// demote is the daemon working; the refusal is §158.7's window
    /// reopening under a park that carried straight on to drop the queue
    /// row. Only the second is a fault, and until 26 Aug 2026 neither the
    /// caller nor the log could tell them apart. `Absent` is the demote -
    /// nothing owed, nothing written - and `Refused` means the row was
    /// owed and no store holds it.
    ///
    /// A refused append is retried as the atomic rewrite, exactly as
    /// `delete_prewrite`'s placeholder is and for the reason
    /// [`Daemon::history_rescue_locked`] gives: the append needs write
    /// permission ON THE FILE and the rewrite needs only the DIRECTORY,
    /// so the commonest refusal there is - a `history.jsonl` left 0444 or
    /// owned by a uid this daemon no longer runs as - now files the park
    /// rather than losing it. The line is carried into the rewrite as
    /// `extra`, because the record is in neither `self.history` (park
    /// pushes it a hundred lines below) nor, once the append was refused,
    /// the file. `Refused` therefore means the whole spool folder is
    /// unwritable, not merely the file.
    ///
    /// `cost` is the sentence a `Refused` owes, on
    /// [`Daemon::history_publish`]'s model: logged always, and raised on
    /// the event ring when the rescue was actually attempted, so it
    /// reaches the dashboard rather than a log nobody reads at 3am. It
    /// matters most on the two arms that have no later filing to report
    /// for them - a tombstoned park files into no store at all, and the
    /// M5 delete arm's `already` path writes nothing either.
    ///
    /// WHAT A `Refused` MEANS ON A REAL BOX, and why park does not stop
    /// on it: the rewrite and `save_queue` both go through
    /// `persist::write_atomic` on the same directory, so a directory that
    /// refuses one refuses the other. A refusal here is therefore a
    /// daemon whose queue store has stopped landing too - which
    /// `save_failed_at` already surfaces through `sab_warnings`. The
    /// download has happened and the bytes are on disk; there is no
    /// caller waiting on an answer the way a delete verb's is, so the
    /// park carries on and says what the next start loses.
    ///
    /// Serialized BEFORE [`HIST_IO`] is taken, the way `delete_prewrite`
    /// does it: the rescue path underneath takes the history lock and
    /// then job locks, so this must not be holding a job guard on its way
    /// in.
    pub(super) fn park_prewrite(
        &self,
        job: &Arc<Mutex<Job>>,
        dropping: bool,
        cost: impl FnOnce() -> String,
    ) -> HistWrite {
        if dropping {
            return HistWrite::Absent;
        }
        let line = job_json(&job.lock_ok()).to_string();
        let lines = std::slice::from_ref(&line);
        let _g = HIST_IO.lock_ok();
        if self.history_write_locked(lines) {
            return HistWrite::Wrote;
        }
        // Spelled out rather than delegated to
        // [`Daemon::history_rescue_locked`], because the gate and the
        // report are ONE decision: a rescue that was never attempted
        // must not raise a ring event, and a caller outside this
        // function cannot tell "gated" from "tried and failed". Exactly
        // the shape [`Daemon::history_publish`] has on the mutation
        // side, and it reports through the same helper so the two say
        // the same thing.
        let Some(now) = self.hist_rescue_open() else {
            self.hist_report_refusal(cost, false);
            return HistWrite::Refused;
        };
        if self.history_rewrite_locked(lines, &[]) {
            return HistWrite::Wrote;
        }
        self.hist_rescue_failed(now);
        self.hist_report_refusal(cost, true);
        HistWrite::Refused
    }

    /// The same idea one caller further back: the DELETE's history row,
    /// written while the job it names is still downloading.
    ///
    /// A delete verb that owes a history row files it from `park` when
    /// the job is active - which is a long way off. The handler drops
    /// the queue row and calls `save_queue`, so from that save until
    /// park's own prewrite (after the fetch drains, after the deferred
    /// file removal, which on a hung NAS is unbounded) nothing durable
    /// names the record at all. A kill in there and the row is gone from
    /// both stores: no DELETED/MANUAL record for the dupe check or the
    /// retry button, and for `GroupParkDelete` - whose whole contract is
    /// "files KEPT" - a full payload on disk that nothing names (Codex
    /// sweep 14 Aug M1).
    ///
    /// The terminal keys are overridden in the JSON rather than written
    /// to the live `Job`: the pipeline is still running, and stamping
    /// `state = Failed` on it would confuse the runner. An un-overridden
    /// row is worse than none - a nonterminal state restores as `Queued`
    /// (job_wire.rs), so replay would mint a queued-looking record
    /// sitting in history.
    ///
    /// The id is registered in `hist_inflight` and deliberately NOT
    /// deregistered here: the Q2 hazard runs from this write until park
    /// files the record into `self.history`, and a compaction anywhere
    /// in that span ("Save queue" runs one on a live daemon) snapshots
    /// MEMORY and would erase the disk-only row. park re-registers the
    /// same id and its guard is what takes it back out - the set is
    /// id-keyed, so the two never fight, and a tombstoned delete always
    /// reaches that guard (park's demote arm, the one early return
    /// ahead of it, cannot claim a tombstoned job).
    ///
    /// In-memory `self.history` is deliberately NOT touched: park's M5
    /// arm handles both "already present" and "not present", and a
    /// still-Downloading job surfacing as a history row would race that
    /// check and `dir_claim`'s two-store scan. Last line wins on replay,
    /// so park's later rows simply overwrite this one.
    ///
    /// RETURNS WHETHER THE PLACEHOLDER IS DURABLE, and the caller has to
    /// read it BEFORE it removes anything: this row is the ONLY thing
    /// that will name the record between the queue row going and a park
    /// that is a pipeline drain away, so a caller that goes on to drop
    /// the row anyway has lost it from both stores - which is what the
    /// answer being a `()` cost until 26 Aug 2026 (P2-1). A refused
    /// append is retried as the atomic rewrite WITH this line carried
    /// into it, for the reason [`Daemon::history_rescue_locked`] gives;
    /// `false` therefore means the whole spool folder is unwritable, not
    /// merely the file.
    ///
    /// An empty `status` is `true` and not a lie: FinalDelete's contract
    /// is that no record survives at all, so nothing was owed and
    /// nothing can be missing.
    ///
    /// A SLICE, and one append for the batch. The verb takes a list of
    /// ids, and since the answer became load-bearing the call moved
    /// ahead of the queue retain - so a bulk cancel of a hundred rows
    /// would otherwise be a hundred `fsync`s in front of the user's
    /// request instead of one.
    #[must_use]
    pub(super) fn delete_prewrite(&self, jobs: &[Arc<Mutex<Job>>], status: &str) -> bool {
        if status.is_empty() || jobs.is_empty() {
            return true;
        }
        let mut lines: Vec<String> = Vec::with_capacity(jobs.len());
        {
            let mut inflight = self.hist_inflight.lock_ok();
            for job in jobs {
                let g = job.lock_ok();
                let mut v = job_json(&g);
                v["state"] = json!("Failed");
                v["fail_message"] = json!(if status == "DUPE" {
                    "deleted from the queue as a duplicate"
                } else {
                    "deleted from the queue"
                });
                v["finished_unix"] = json!(unix_now());
                v["delete_status"] = json!(status);
                inflight.insert(g.nzo_id.clone());
                lines.push(v.to_string());
            }
        }
        let _g = HIST_IO.lock_ok();
        if self.history_write_locked(&lines) || self.history_rescue_locked(&lines, &[]) {
            return true;
        }
        // No line reached disk, so there is nothing for the Q2
        // carry-forward to protect and the ids would sit in the set for
        // the life of the daemon - the caller is about to refuse, and a
        // refused verb leaves nothing of itself behind. HIST_IO then
        // `hist_inflight` is the order `history_rewrite_locked` already
        // takes them in.
        let mut inflight = self.hist_inflight.lock_ok();
        for job in jobs {
            inflight.remove(&job.lock_ok().nzo_id);
        }
        false
    }

    /// The far end of a [`Daemon::delete_prewrite`] whose record was
    /// filed into `self.history` right here rather than by a `park` an
    /// unbounded wait away.
    ///
    /// The Q2 hazard that registration covers runs from the placeholder
    /// to the record reaching memory, and for a row the delete verb
    /// files itself that is a few lines, not a pipeline drain - so the
    /// id comes back out here. `park`'s own guard does it for the active
    /// arm; without this the set would grow for the life of the daemon
    /// on the arm that has no park to reach.
    pub(super) fn delete_prewrite_filed(&self, ids: &[String]) {
        let mut inflight = self.hist_inflight.lock_ok();
        for id in ids {
            inflight.remove(id);
        }
    }

    /// Register a park's nzo_id as in flight between its prewrite and its
    /// final filing, so `history_compact` carries the disk-only prewrite
    /// row into any snapshot it publishes meanwhile (Q2). Returns a guard;
    /// dropping it - however the park exits - deregisters the id.
    pub(super) fn hist_inflight_begin(&self, id: &str) -> HistInflightGuard<'_> {
        self.hist_inflight.lock_ok().insert(id.to_string());
        HistInflightGuard {
            d: self,
            id: id.to_string(),
        }
    }

    /// Persist removals: tombstone lines. For a record leaving history
    /// for good (delete) AND for one moving back into the queue (retry,
    /// stream) - in both cases the id must stop replaying into history;
    /// the queue arm of `save_queue` carries the latter onward.
    ///
    /// RETURNS WHETHER THE REMOVAL IS DURABLE, and every caller has to
    /// read it. `history_replay` drops a row only when it finds a
    /// `"deleted": true` line, so a refused tombstone is not a cosmetic
    /// miss: the record comes back at the next start, and it comes back
    /// after its retry `.nzb` and its early-published copies have been
    /// destroyed on the strength of a delete that reported success.
    /// A `()` here is what let all four delete paths do exactly that
    /// (P2-1) - so the answer is `#[must_use]`, and a caller must not
    /// destroy anything the returning record will need until it is
    /// `true`.
    ///
    /// A refused append is retried as the atomic rewrite, which OMITS
    /// these ids: a rewrite that does not name a record is that record's
    /// tombstone, because replay reads the file as the whole truth. See
    /// [`Daemon::history_rescue_locked`] for why that second chance
    /// exists at all and for why it takes the lock rather than dropping
    /// it. `false` therefore means the whole spool folder is unwritable,
    /// not merely the file.
    #[must_use]
    pub(super) fn history_tombstone(&self, ids: &[String]) -> bool {
        if ids.is_empty() {
            return true;
        }
        let lines: Vec<String> = ids
            .iter()
            .map(|id| json!({"nzo_id": id, "deleted": true}).to_string())
            .collect();
        let _g = HIST_IO.lock_ok();
        self.history_write_locked(&lines) || self.history_rescue_locked(&[], ids)
    }

    /// Put records back into `self.history` where they were, after a
    /// removal whose tombstone the store REFUSED.
    ///
    /// Every delete path takes the row out of memory before asking the
    /// store to forget it, and that order is deliberate: an
    /// `history_upsert_if_present` landing in the gap finds the record
    /// absent and writes nothing, where the other order would let it
    /// write back the row the tombstone had just buried (the H6 shape).
    /// The price is that a refused tombstone leaves a record on disk and
    /// not in memory - live at the next start, invisible until then -
    /// so it goes back.
    ///
    /// `at` is each record's position in the list AS IT STOOD once the
    /// removal was done, so re-inserting in REVERSE order of removal
    /// reconstructs it. Clamped rather than asserted: the list is not
    /// held across the store write, so a park can file a row meanwhile,
    /// and a stale index must land at the end instead of panicking a
    /// live daemon. Order is best-effort for that reason and correctness
    /// does not rest on it - `history_replay` keys on the id.
    ///
    /// The caller owns the record's own FIELDS: a delete stamps
    /// `tombstone` (and the queue arm stamps a terminal state) before it
    /// gets here, and only the caller knows what it stamped.
    pub(super) fn history_restore(&self, removed: Vec<(usize, Arc<Mutex<Job>>)>) {
        if removed.is_empty() {
            return;
        }
        let mut h = self.history.lock_ok();
        for (at, job) in removed.into_iter().rev() {
            let at = at.min(h.len());
            h.insert(at, job);
        }
        self.history_rev.fetch_add(1, Ordering::Relaxed);
    }

    /// A GENERATION-BOUND tombstone: deletes only history rows whose
    /// `move_seq` is at or below `seq`. For the move paths (retry,
    /// stream activation), never for a user delete.
    ///
    /// The plain tombstone above is id-only, and the move paths used it
    /// too - which let an OLD move erase a NEWER generation of the same
    /// job. A retry stamps seq N+1, saves the queue, and only then
    /// tombstones; `save_queue` can be slow on a large queue, and in
    /// that window the resumed job can run, fail and PARK again at seq
    /// N+2, appending its terminal history row. The retry's id-only
    /// tombstone then landed after that row and, last-line-wins, deleted
    /// it - while the next queue save omits the parked job too. Lost
    /// from both stores, no crash required (Codex sweep 13 Aug Q1).
    ///
    /// Bounded by the mover's OWN stamp, the tombstone still buries the
    /// row it is meant to bury (the seq-N record the move pulled out of
    /// history) and can never touch a generation stamped after it.
    ///
    /// Returns whether the removal is durable, for the reason the plain
    /// tombstone above gives. The rescue passes NO `drop_ids`, and that
    /// is the generation bound rather than a hole in it: the rewrite
    /// publishes the LIVE records, so a job that has left history is
    /// omitted (which is what this move asked for) while one that has
    /// already parked again at a later seq is present (which is what the
    /// bound exists to protect). The seq is a property of the LINE, and
    /// a rewrite has no earlier lines to be bounded against.
    #[must_use]
    pub(super) fn history_tombstone_upto(&self, id: &str, seq: u64) -> bool {
        let line = json!({"nzo_id": id, "deleted": true, "move_seq": seq}).to_string();
        let _g = HIST_IO.lock_ok();
        self.history_write_locked(std::slice::from_ref(&line))
            || self.history_rescue_locked(&[], &[])
    }

    /// Rewrite the store as exactly the live records, atomically. Called
    /// at load when replay found more garbage than live rows, after the
    /// one-time migration out of queue.json - and by "Save queue", the
    /// remedy the durability errors name, which is a LIVE daemon with
    /// appenders running. Returns whether the rewrite landed: the remedy
    /// has to be able to report that it did not.
    ///
    /// Snapshot and publish both happen under [`HIST_IO`]; see the lock's
    /// own note for what an unsynchronised rewrite cost.
    pub(super) fn history_compact(&self) -> bool {
        let _g = HIST_IO.lock_ok();
        self.history_rewrite_locked(&[], &[])
    }

    /// The rewrite itself, with [`HIST_IO`] ALREADY held, and with two
    /// knobs the plain compaction above does not need.
    ///
    /// Both exist because this is also the RESCUE for a refused append
    /// (see [`Daemon::history_rescue_locked`]), and a rescue has to be
    /// able to publish the same thing the refused line said:
    ///
    ///  * `drop_ids` are records the caller is REMOVING and has not taken
    ///    out of `self.history` yet, so the snapshot would otherwise put
    ///    them straight back. A rewrite that omits a record IS its
    ///    tombstone - the replay reads the file as the whole truth - so
    ///    this is what makes a refused tombstone survivable.
    ///  * `extra` are pre-serialized lines with no live record behind
    ///    them: `delete_prewrite`'s placeholder for a job that is still
    ///    downloading and is in neither `self.history` nor, once the
    ///    append was refused, the file. Written LAST so last-wins replay
    ///    treats them exactly as an append would have.
    ///
    /// The two never overlap in practice and are not asserted not to:
    /// `extra` is a bare line, `drop_ids` are ids, and a caller passing
    /// both would be saying "remove the record and then write this row",
    /// which is what an append pair would have done anyway.
    fn history_rewrite_locked(&self, extra: &[String], drop_ids: &[String]) -> bool {
        // The rewrite's own kill-here seam. Separate from the append's
        // because the two writes need DIFFERENT permissions - append
        // needs the file, this needs the directory - and P2-1's trigger
        // is exactly a store where one works and the other does not.
        #[cfg(test)]
        if super::storecut::cut_here(super::storecut::Store::HistoryRewrite) {
            return false;
        }
        let path = self.history_store_path();
        let doomed = |id: &str| drop_ids.iter().any(|d| d == id);
        let mut snap_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
        let lines: Vec<String> = self
            .history
            .lock_ok()
            .iter()
            .filter_map(|j| {
                let g = j.lock_ok();
                if doomed(&g.nzo_id) {
                    return None;
                }
                snap_ids.insert(g.nzo_id.clone());
                Some(job_json(&g).to_string())
            })
            .collect();
        let mut buf = String::with_capacity(lines.iter().map(|l| l.len() + 1).sum());
        for l in &lines {
            buf.push_str(l);
            buf.push('\n');
        }
        // A park in flight has its prewrite on DISK and its record not yet
        // in `self.history` - park removes the row from the live queue
        // right after the prewrite and only files it into history at the
        // end. A snapshot built from memory alone drops exactly that row,
        // and "Save queue" runs this compaction on a live daemon: a crash
        // before park's final upsert then left the job in neither store -
        // the very hole `park_prewrite` exists to close (Codex sweep
        // 13 Aug Q2). Parks register in `hist_inflight` around that
        // interval; carry their latest disk line into the snapshot.
        // ...and a record the caller is REMOVING is not carried forward
        // either, however in-flight it is: the whole point of the call is
        // that its row must not survive this rewrite.
        let inflight: Vec<String> = {
            let set = self.hist_inflight.lock_ok();
            set.iter()
                .filter(|id| !snap_ids.contains(*id) && !doomed(id))
                .cloned()
                .collect()
        };
        if !inflight.is_empty()
            && let Ok(raw) = std::fs::read(&path)
        {
            let mut last: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
            for chunk in raw.split(|b| *b == b'\n') {
                let Ok(line) = std::str::from_utf8(chunk) else {
                    continue;
                };
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let Ok(v) = serde_json::from_str::<Value>(line) else {
                    continue;
                };
                if let Some(id) = v.get("nzo_id").and_then(Value::as_str)
                    && let Some(want) = inflight.iter().find(|w| *w == id)
                {
                    last.insert(want.as_str(), line);
                }
            }
            for id in &inflight {
                if let Some(line) = last.get(id.as_str()) {
                    buf.push_str(line);
                    buf.push('\n');
                }
            }
        }
        // LAST, so last-wins replay reads them exactly as the append
        // that was refused would have left them.
        for l in extra {
            buf.push_str(l);
            buf.push('\n');
        }
        #[cfg(test)]
        {
            let spool = self.spool.display().to_string();
            let barrier = COMPACT_BARRIER
                .lock_ok()
                .clone()
                .filter(|(k, _)| *k == spool);
            if let Some((_, b)) = barrier {
                b.wait();
            }
        }
        let ok = match crate::persist::write_atomic(&path, buf.as_bytes()) {
            Ok(()) => true,
            Err(e) => {
                error!(target: "queue", "history compact {}: {e}", path.display());
                false
            }
        };
        self.history_rev.fetch_add(1, Ordering::Relaxed);
        ok
    }

    /// Replay `.spool/history.jsonl` into Job records, oldest first.
    /// Returns `(records, wants_compaction)`.
    ///
    /// Last line wins per nzo_id; tombstones remove; a torn or garbled
    /// line is skipped (the crash window is the file's own tail, and one
    /// lost append is the worst case the format permits). Order is
    /// first-APPEND order per id - an upsert refreshes a record's
    /// contents, not its age - matching the Vec the daemon serves
    /// newest-last.
    pub(super) fn history_replay(&self) -> (Vec<Job>, bool) {
        let path = self.history_store_path();
        // Read BYTES and decode per line. `read_to_string` rejects the
        // whole file on one invalid UTF-8 byte, and a crash mid-append
        // can tear the tail through the middle of a multi-byte
        // character - a foreign-language release name is all it takes.
        // That turned a recoverable one-line loss into "the history is
        // empty", permanently: nothing rewrites the bad byte, so every
        // later start read empty too, and the per-line tolerance below -
        // which exists for exactly this - never got to run.
        let Ok(raw) = std::fs::read(&path) else {
            return (Vec::new(), false);
        };
        // Append order as SLOTS, and every live record carrying the index
        // of its own slot. A tombstone used to `retain` the id out of a
        // Vec - O(n) per delete, so replay was quadratic in a
        // delete-heavy store (tens of seconds at 50k rows with a few
        // thousand tombstones, every start). Punching a hole through the
        // stored index is O(1) and the holes cost one `Option<String>`
        // each; the drain below skips them, so first-APPEND order and
        // last-line-wins are exactly what they were.
        let mut order: Vec<Option<String>> = Vec::new();
        let mut live: std::collections::HashMap<String, (usize, Job)> =
            std::collections::HashMap::new();
        let mut lines = 0usize;
        for chunk in raw.split(|b| *b == b'\n') {
            let Ok(line) = std::str::from_utf8(chunk) else {
                warn!(
                    target: "queue",
                    "history store: skipping a line with invalid UTF-8"
                );
                continue;
            };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            lines += 1;
            let Ok(v) = serde_json::from_str::<Value>(line) else {
                // A torn tail parses as garbage exactly once; anything
                // mid-file was already fsync'd whole, so noise here is
                // worth a line in the log.
                warn!(target: "queue", "history store: skipping an unreadable line");
                continue;
            };
            let Some(id) = v.get("nzo_id").and_then(Value::as_str).map(str::to_string) else {
                continue;
            };
            if v.get("deleted").and_then(Value::as_bool).unwrap_or(false) {
                // A tombstone carrying a `move_seq` is generation-bound:
                // it buries rows stamped at or below it and must never
                // touch a LATER generation (a park that raced ahead of a
                // slow retry commit - Q1). An id-only tombstone (user
                // delete, retention) stays unconditional.
                let applies = match v.get("move_seq").and_then(Value::as_u64) {
                    None => true,
                    Some(ts) => live.get(&id).is_none_or(|(_, j)| j.move_seq <= ts),
                };
                if applies && let Some((slot, _)) = live.remove(&id) {
                    order[slot] = None;
                }
                continue;
            }
            let Some(mut job) = job_from_json(&v) else {
                continue;
            };
            // `finalizing` is a LIVE flag: it says a post-processing tail
            // is running right now, and nothing is running after a
            // restart. A record appended while it was raised - the
            // password-unlock path upserts twice inside its
            // ClearFinalizing scope, and the guard only clears the
            // in-memory copy - comes back permanently marked busy, and
            // every consumer refuses it forever: history delete (the
            // WHOLE request, so "Clear completed" stops working),
            // change_cat, retry, the owed move, retention. A wrong
            // password is worse - `password_required && finalizing`
            // refuses every further unlock attempt, so the job can never
            // be opened again. The legacy `restore_records` this replaced
            // cleared it on load and said so; §129's store lost that, so
            // clear it here, whichever write path persisted the stale
            // true.
            job.finalizing = false;
            // An upsert refreshes the record in place - a resurrected id
            // (tombstoned, then appended again) takes a fresh slot at the
            // end, which is where the retain-based order put it too.
            match live.get_mut(&id) {
                Some((_, held)) => *held = job,
                None => {
                    order.push(Some(id.clone()));
                    live.insert(id, (order.len() - 1, job));
                }
            }
        }
        let records: Vec<Job> = order
            .into_iter()
            .flatten()
            .filter_map(|id| live.remove(&id).map(|(_, j)| j))
            .collect();
        // More dead lines than live rows: worth a rewrite once loaded.
        let wants_compaction = lines > records.len().saturating_mul(2).max(64);
        (records, wants_compaction)
    }
}

/// The Q2 fence's other half: holds a parked id in `hist_inflight` for
/// exactly as long as the park is between its prewrite and its final
/// filing. Drop-based so an early return or a panic cannot leave the id
/// registered forever (which would only cost compaction a lookup, but
/// stale entries would accrete for the life of the daemon).
pub(super) struct HistInflightGuard<'a> {
    d: &'a Daemon,
    id: String,
}

impl Drop for HistInflightGuard<'_> {
    fn drop(&mut self) {
        self.d.hist_inflight.lock_ok().remove(&self.id);
    }
}

/// §129 1b: one discrete lifecycle event, sequence-numbered so a client
/// can ask "everything since N" instead of diffing snapshots. Ring
/// bounded at [`LIFE_RING`]; a client whose cursor has fallen off the
/// tail is told to reseed (`events_reset`), never replayed stale toasts.
pub(super) const LIFE_RING: usize = 512;

/// §129 4a: the event schema's version, stamped on every event.
/// Additive payload keys never bump it; renaming or removing a key, or
/// changing what one means, does. Consumers must ignore unknown keys
/// and unknown kinds - the dashboard's if/else-if chain and the webhook
/// filter both already do.
pub(super) const LIFE_SCHEMA_VERSION: u32 = 1;

impl Daemon {
    /// Emit one lifecycle event. `payload` carries the kind-specific
    /// keys; `seq`/`kind`/`at`/`schema_version` are stamped here.
    /// Sequence allocation and ring insertion happen under ONE hold of
    /// the ring lock, and `life_seq` is only ever advanced there. They
    /// used to be separate: the counter went up first, then hooks were
    /// offered, then the ring lock was taken - so a poll landing in that
    /// window read a ring WITHOUT the event and a cursor that already
    /// counted it, and the client, which adopts the returned cursor,
    /// filtered that event out forever (M1, 10 Aug sweep). Two emitters
    /// racing could also push [2, 1] and break `front()` being the
    /// numerically oldest, which is what `life_since` reads to decide
    /// whether a client has fallen off the tail.
    pub(super) fn life_emit(&self, kind: &str, mut payload: Value) {
        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let published = {
            let mut ring = self.life_events.lock_ok();
            let seq = self.life_seq.fetch_add(1, Ordering::Relaxed) + 1;
            if let Some(o) = payload.as_object_mut() {
                o.insert("seq".into(), json!(seq));
                o.insert("kind".into(), json!(kind));
                o.insert("at".into(), json!(at));
                o.insert("schema_version".into(), json!(LIFE_SCHEMA_VERSION));
            }
            if ring.len() >= LIFE_RING {
                ring.pop_front();
            }
            ring.push_back(payload.clone());
            payload
        };
        // §129 4a: offer the event to the webhook dispatcher - a
        // try-send that can neither block nor fail the emitter. AFTER
        // publication now, and outside the ring lock: a dispatcher that
        // is behind must not hold the emitter's lock, and the event is
        // already visible to pollers by the time it is offered.
        self.hooks_offer(&published);
    }

    /// Everything after `since`, plus whether that cursor already fell
    /// off the ring's tail (reseed signal). "No cursor at all" (a fresh
    /// page's first poll) is the CALLER's case - it omits the param and
    /// never reaches here - so a numeric cursor, zero included, means
    /// "I have seen everything up to here": a daemon whose first-ever
    /// event lands after the page opened must deliver it to a client
    /// holding cursor 0, not swallow it as a replay guard.
    /// The cursor a client with no cursor at all should adopt: the last
    /// PUBLISHED sequence, read under the ring lock like `life_since`
    /// reads it, so a fresh page cannot start out already past an event
    /// that is mid-publication (M1's shape, from the other end).
    pub(super) fn life_cursor(&self) -> u64 {
        let _ring = self.life_events.lock_ok();
        self.life_seq.load(Ordering::Relaxed)
    }

    /// Returns `(events, reset, cursor)`. The cursor is read under the
    /// SAME ring lock the events are read under, and is what the client
    /// must adopt: answering with the atomic's current value instead
    /// reintroduced M1's gap from the reader's side, since an event
    /// published between this call and that load would be counted by the
    /// cursor and absent from the batch.
    pub(super) fn life_since(&self, since: u64) -> (Vec<Value>, bool, u64) {
        let ring = self.life_events.lock_ok();
        let cursor = self.life_seq.load(Ordering::Relaxed);
        let oldest = ring
            .front()
            .and_then(|e| e["seq"].as_u64())
            .unwrap_or(cursor + 1);
        // A gap between the cursor and the oldest retained event means
        // events were lost to the ring bound: say so instead of quietly
        // skipping them.
        //
        // A cursor AHEAD of this daemon's sequence is the other reseed
        // case: a tab that was open across a restart still holds the old
        // boot's numbering, and every event of the new boot reads as
        // already-seen (M2, 10 Aug sweep). Numbering is per-boot, so
        // "impossible cursor" means "different boot" - reseed.
        let reset = since + 1 < oldest || since > cursor;
        let events: Vec<Value> = ring
            .iter()
            .filter(|e| e["seq"].as_u64().unwrap_or(0) > since)
            .cloned()
            .collect();
        (if reset { Vec::new() } else { events }, reset, cursor)
    }

    /// The park-side emitter: the one place a job becomes history, so
    /// the one place "it finished" becomes an event. Locked; call with
    /// no locks held.
    pub(super) fn life_emit_parked(&self, job: &Arc<Mutex<Job>>) {
        let g = job.lock_ok();
        match g.state {
            JobState::Failed => self.life_emit(
                "job.failed",
                json!({
                    "nzo_id": g.nzo_id,
                    "name": g.name,
                    "category": g.category,
                    "fail_message": g.fail_message,
                    "auto_retry_at": g.auto_retry_at,
                    // A Failed row can be asking for a password too (the
                    // in-stream probe saw an encrypted set); the client's
                    // password chime keys off this.
                    "locked": g.password_required,
                }),
            ),
            _ => {
                // §129 4a: a completed job that needed repair announces
                // the repair as its own kind first - the schema's
                // job.repaired - then completes. Same derivation the
                // notify router uses for its "repaired" token.
                let repaired = g.bad_blocks.unwrap_or(0) > 0;
                if repaired {
                    // event-arm-gate: a STATE, not a moment - the
                    // history row carries it (`s.bad_blocks` renders
                    // "repaired"), and the `job.completed` emitted right
                    // after this one in the same park carries `repaired`
                    // for anything that wants the pair in one event.
                    // §129 1b finding (b) is the rule.
                    self.life_emit(
                        "job.repaired",
                        json!({
                            "nzo_id": g.nzo_id,
                            "name": g.name,
                            "category": g.category,
                            "bad_blocks": g.bad_blocks.unwrap_or(0),
                        }),
                    );
                }
                self.life_emit(
                    "job.completed",
                    json!({
                        "nzo_id": g.nzo_id,
                        "name": g.name,
                        "category": g.category,
                        // The completed-but-locked split the toast rules need.
                        "locked": g.password_required,
                        "moved_to": if g.out_dir.starts_with(self.out_dir()) {
                            String::new()
                        } else {
                            g.out_dir.to_string_lossy().into_owned()
                        },
                        // §129 4a additive keys (schema v1): what the job
                        // was, whether it repaired, and the archive shape
                        // the one-pass engine unpacked ("" = plain files)
                        // - job.extracted's answer lives here, extraction
                        // being integral to the download rather than a
                        // stage of its own.
                        "bytes": g.total_bytes,
                        "repaired": repaired,
                        "archive_shape": g.archive_shape,
                    }),
                );
            }
        }
    }

    /// §129 D5: the optional retention knobs, both 0 = unlimited (the
    /// default; unlimited SHIPS by ruling). Applied at park, at load, at
    /// a client history clear, and - since the age knob gained sub-day
    /// granularity (issue #45) - on a one-minute sweep, because an
    /// "after 10 minutes" rule that only fires when the NEXT job parks
    /// is not the rule the user set.
    ///
    /// Count cap drops oldest-first regardless of state; the age cap
    /// only ever drops Completed rows (a Failed row is a pending
    /// decision, not a memory). Rows mid-move/unlock are never touched.
    /// Only the RECORD and its spooled .nzb go: the downloaded files are
    /// the user's, and nothing here reaches them.
    pub(super) fn history_enforce_retention(&self) {
        let keep_count = self.history_keep_count.load(Ordering::Relaxed) as usize;
        let keep_secs = self.history_keep_secs.load(Ordering::Relaxed);
        if keep_count == 0 && keep_secs == 0 {
            return;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let mut doomed: Vec<String> = Vec::new();
        let mut spooled: Vec<PathBuf> = Vec::new();
        // Where each retired row sat, so a store that refuses the
        // tombstone can have them all back (P2-1); see
        // `Daemon::history_restore`.
        let mut removed: Vec<(usize, Arc<Mutex<Job>>)> = Vec::new();
        {
            let mut h = self.history.lock_ok();
            let moving = self.moving.lock_ok();
            let untouchable = |g: &Job| g.finalizing || moving.contains(&g.nzo_id);
            if keep_secs > 0 {
                // Saturating: the knob is a u64 the API clamps, but a
                // hand-written settings.json can hold anything, and a
                // plain subtraction would panic in a debug build rather
                // than mean "keep everything".
                let cutoff = now.saturating_sub(keep_secs.min(i64::MAX as u64) as i64);
                let mut at = 0usize;
                h.retain(|j| {
                    let g = j.lock_ok();
                    let old = g.state == JobState::Completed
                        && g.finished_unix.is_some_and(|t| t < cutoff);
                    if old && !untouchable(&g) {
                        doomed.push(g.nzo_id.clone());
                        spooled.push(g.nzb_path.clone());
                        removed.push((at, j.clone()));
                        false
                    } else {
                        at += 1;
                        true
                    }
                });
            }
            if keep_count > 0 && h.len() > keep_count {
                let mut excess = h.len() - keep_count;
                let mut at = 0usize;
                // Oldest first = front of the Vec.
                h.retain(|j| {
                    if excess == 0 {
                        at += 1;
                        return true;
                    }
                    let g = j.lock_ok();
                    if untouchable(&g) {
                        at += 1;
                        return true;
                    }
                    doomed.push(g.nzo_id.clone());
                    spooled.push(g.nzb_path.clone());
                    removed.push((at, j.clone()));
                    excess -= 1;
                    false
                });
            }
        }
        if doomed.is_empty() {
            return;
        }
        // THE TOMBSTONE FIRST. The comment that used to stand here
        // asserted exactly that - "through `drop_spool`, because the
        // tombstone is durable by now" - above code that ran the unlinks
        // and then tombstoned, so the claim was false against the lines
        // under it from the day it was written (P2-1, 26 Aug 2026). A
        // refused tombstone with the spool copies already gone is the
        // worst state this sweep can reach: the aged-out record replays
        // at the next start with nothing left to retry it from.
        if !self.history_tombstone(&doomed) {
            // Nothing has been destroyed, so put the rows back rather
            // than leave them live on disk and invisible in memory. They
            // age out again on the next tick, by which time the store
            // may be writable.
            self.history_restore(std::mem::take(&mut removed));
            error!(
                target: "queue",
                "history retention: the store refused the removal of {} old \
                 record(s), so they were kept - the spool copies they retry \
                 from are untouched",
                doomed.len()
            );
            return;
        }
        info!(
            target: "queue",
            "history retention: dropped {} old record(s) (keep_count {}, keep_secs {})",
            doomed.len(),
            keep_count,
            keep_secs
        );
        // The RECORD has retired; the payload on disk is the user's. Only
        // the spooled .nzb (kept for retry, and retry needs a record)
        // goes with it - through `drop_spool`, because the tombstone IS
        // durable by now and a copy whose unlink is refused would be
        // re-adopted at the next start as a fresh download of a release
        // retention just aged out (Codex sweep 24 Aug, F-04).
        for p in spooled {
            drop_spool(&p);
        }
    }
}

/// The retention sweep's own clock.
///
/// Retention used to be enforced only at three edges - daemon start, a
/// job parking, and a client clearing history - which is enough for a
/// rule measured in days, because a daemon that has not finished a
/// download in a day has nothing new to expire either. Issue #45
/// let the rule be measured in minutes, and at that scale the edges are
/// no longer close enough together: "remove them 20 minutes after they
/// finish" on a queue that has gone quiet would hold the last few
/// records until the next download parked, which could be days.
///
/// A minute is the resolution the dashboard offers, so a minute is the
/// tick. It costs two relaxed atomic loads while the feature is off -
/// `history_enforce_retention` returns before it takes a single lock -
/// which is why this is unconditional rather than started and stopped
/// with the setting.
///
/// **IT CARRIES A SECOND SWEEP** since §282 item 5's residue was closed
/// (24 Aug 2026): `Daemon::drop_stranded_spares`, which drops a held
/// spare whose owner has left both stores. The two ride one clock
/// because the reap above is the commonest way that state is REACHED -
/// a Failed row retired by the keep_count arm takes its spare's only
/// remaining reason with it - and because a spare parked at
/// `DUPE_PRIORITY` costs nothing while it waits, so a minute of latency
/// is the whole price of not needing a hook on every delete path. It is
/// NOT folded into `history_enforce_retention` itself, and must not be:
/// that function returns on the first two atomic loads when retention is
/// off, and a user deleting a history row by hand strands a spare
/// whether retention is on or not. Its own cost with nothing held is one
/// queue walk.
pub(super) fn spawn_retention_sweep(daemon: &Arc<Daemon>) {
    let d = daemon.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            d.history_enforce_retention();
            // After the reap, not before: a record this tick retires is
            // one this tick can then collect the spares of.
            d.drop_stranded_spares();
        }
    });
}

#[cfg(test)]
mod store_tests {
    use super::*;
    use crate::serve::testutil::test_daemon;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("nzbfast-hist-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A torn multi-byte tail costs ONE row, not the whole history.
    ///
    /// Replay used to `read_to_string` the file before its per-line
    /// recovery, so a crash that tore an append through the middle of a
    /// character - a foreign-language release name is enough - made the
    /// entire history read as empty. Nothing ever rewrote the bad byte,
    /// so it stayed empty across every later restart, and the documented
    /// per-line tolerance never got to run.
    #[test]
    fn a_torn_utf8_tail_costs_one_row_not_the_history() {
        let dir = tmp("torn");
        let d = test_daemon(&dir);
        let path = d.history_store_path();

        // The fields `job_from_json` insists on, and nothing else.
        let row = |id: &str, name: &str| {
            format!(
                r#"{{"nzo_id":"{id}","name":"{name}","out_dir":"/tmp/o","nzb_path":"/tmp/n.nzb","state":"Completed"}}"#
            )
        };
        let mut bytes = Vec::new();
        bytes.extend_from_slice(row("a1", "Ordinary.Release").as_bytes());
        bytes.push(b'\n');
        // A name with real multi-byte characters, written whole.
        bytes.extend_from_slice(row("a2", "Æon.Flux.Æ").as_bytes());
        bytes.push(b'\n');
        // ...and a third append that died mid-character: the leading
        // byte of a 2-byte sequence with its continuation byte missing.
        bytes.extend_from_slice(
            br#"{"nzo_id":"a3","out_dir":"/tmp/o","nzb_path":"/tmp/n.nzb","state":"Completed","name":"Tor"#,
        );
        bytes.push(0xC3);

        std::fs::write(&path, &bytes).unwrap();
        let (jobs, _) = d.history_replay();
        let ids: Vec<String> = jobs.iter().map(|j| j.nzo_id.clone()).collect();
        assert_eq!(
            ids,
            ["a1", "a2"],
            "a torn tail took the whole history with it"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The first append AFTER a torn tail survives the restart after
    /// that.
    ///
    /// Replay tolerates the tear itself, but the store used to append
    /// straight onto the torn bytes, welding the first post-recovery
    /// record into the same unreadable line - so the SECOND replay
    /// dropped both, and a park or tombstone written right after a
    /// crash was silently gone (Codex sweep 24 Aug, F-03). The append
    /// path now starts a fresh line when the tail lacks its newline.
    /// Both tear shapes: invalid UTF-8, and syntactically torn JSON.
    #[test]
    fn an_append_after_a_torn_tail_survives_the_next_replay() {
        let row = |id: &str| {
            format!(
                r#"{{"nzo_id":"{id}","name":"{id}.Release","out_dir":"/tmp/o","nzb_path":"/tmp/n.nzb","state":"Completed"}}"#
            )
        };
        for (tag, tear) in [
            ("tornutf8", &b"{\"nzo_id\":\"a2\",\"name\":\"Tor\xC3"[..]),
            ("tornjson", &br#"{"nzo_id":"a2","name":"Torn"#[..]),
        ] {
            let dir = tmp(tag);
            let d = test_daemon(&dir);
            let path = d.history_store_path();

            let mut bytes = Vec::new();
            bytes.extend_from_slice(row("a1").as_bytes());
            bytes.push(b'\n');
            bytes.extend_from_slice(tear);
            std::fs::write(&path, &bytes).unwrap();

            // Restart 1: the tear costs its own line and nothing else.
            let (jobs, _) = d.history_replay();
            assert_eq!(jobs.len(), 1, "{tag}: replay after the tear");

            // The first post-recovery mutation...
            assert!(d.history_append(&[row("a3")]), "{tag}: append refused");

            // ...is still there on restart 2.
            let (jobs, _) = d.history_replay();
            let ids: Vec<String> = jobs.iter().map(|j| j.nzo_id.clone()).collect();
            assert_eq!(
                ids,
                ["a1", "a3"],
                "{tag}: the torn tail swallowed the append after it"
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// Tombstones punch holes in the append order instead of compacting
    /// it, and everything the old `Vec::retain` guaranteed still holds:
    /// a buried id is gone, the survivors keep first-APPEND order, a
    /// re-appended id comes back at the END, and a generation-bound
    /// tombstone leaves a LATER generation alone.
    #[test]
    fn tombstones_keep_append_order_and_let_an_id_come_back() {
        let dir = tmp("order");
        let d = test_daemon(&dir);
        let path = d.history_store_path();

        let row = |id: &str, seq: u64| {
            format!(
                r#"{{"nzo_id":"{id}","name":"{id}.Release","out_dir":"/tmp/o","nzb_path":"/tmp/n.nzb","state":"Completed","move_seq":{seq}}}"#
            )
        };
        let mut lines: Vec<String> = Vec::new();
        for id in ["a1", "a2", "a3", "a4"] {
            lines.push(row(id, 0));
        }
        // a2 is buried by an id-only tombstone, then posted again: it
        // belongs at the end, not back in its original slot.
        lines.push(r#"{"nzo_id":"a2","deleted":true}"#.into());
        lines.push(row("a2", 0));
        // a3's record is stamped at generation 5; a tombstone from
        // generation 4 is stale and must not touch it.
        lines.push(row("a3", 5));
        lines.push(r#"{"nzo_id":"a3","deleted":true,"move_seq":4}"#.into());
        // a4 goes for good.
        lines.push(r#"{"nzo_id":"a4","deleted":true}"#.into());
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let (rows, _) = d.history_replay();
        let ids: Vec<String> = rows.iter().map(|j| j.nzo_id.clone()).collect();
        assert_eq!(ids, ["a1", "a3", "a2"], "replay order changed");
        assert_eq!(
            rows.iter().find(|j| j.nzo_id == "a3").map(|j| j.move_seq),
            Some(5),
            "a stale generation's tombstone buried a newer record"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A queue -> history move is two independent durable writes: park
    /// appends and fsyncs the terminal history row, then `save_queue`
    /// rewrites queue.json without it. A kill in between leaves the same
    /// nzo_id in BOTH files - and until this fix nothing deduplicated
    /// them, so the job came back as Queued (job_wire restores a
    /// nonterminal `Finishing` row that way) AND as Failed, and the
    /// queued copy downloaded the whole release again (Codex sweep 12 Aug
    /// F1).
    ///
    /// This writes the exact split-brain state a kill produces, restores
    /// from it, and asserts exactly one copy - in history.
    #[test]
    fn a_half_written_park_restores_as_one_history_row() {
        let dir = tmp("splitbrain");
        let d = test_daemon(&dir);
        let row = |id: &str, state: &str| {
            format!(
                r#"{{"nzo_id":"{id}","name":"Some.Release","out_dir":"/tmp/o",
                    "nzb_path":"/tmp/n.nzb","state":"{state}"}}"#
            )
            .replace('\n', "")
        };
        // The durable write that DID land: the terminal history row.
        std::fs::write(
            d.history_store_path(),
            format!("{}\n", row("nzo_7", "Failed")),
        )
        .unwrap();
        // ...and the stale queue.json the rewrite never got to replace.
        // `Finishing` is nonterminal, so job_wire brings it back as Queued.
        std::fs::write(
            d.spool.join("queue.json"),
            format!(r#"{{"next_id":9,"queue":[{}]}}"#, row("nzo_7", "Finishing")),
        )
        .unwrap();

        d.load_queue();

        let queued: Vec<String> = d
            .queue
            .lock_ok()
            .iter()
            .map(|j| j.lock_ok().nzo_id.clone())
            .collect();
        let hist: Vec<(String, JobState)> = d
            .history
            .lock_ok()
            .iter()
            .map(|j| {
                let g = j.lock_ok();
                (g.nzo_id.clone(), g.state)
            })
            .collect();
        assert!(
            queued.is_empty(),
            "the stale queue copy must not come back runnable: {queued:?}"
        );
        assert_eq!(
            hist,
            vec![("nzo_7".to_string(), JobState::Failed)],
            "exactly one copy, holding the terminal verdict"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The other half of the contract: an ORDINARY queued job, with an
    /// unrelated history, is restored untouched. Without this the fix
    /// above would be indistinguishable from "drop the queue".
    #[test]
    fn an_ordinary_queue_survives_reconciliation() {
        let dir = tmp("nosplit");
        let d = test_daemon(&dir);
        let row = |id: &str, state: &str| {
            format!(
                r#"{{"nzo_id":"{id}","name":"Some.Release","out_dir":"/tmp/o","nzb_path":"/tmp/n.nzb","state":"{state}"}}"#
            )
        };
        std::fs::write(
            d.history_store_path(),
            format!("{}\n", row("nzo_old", "Completed")),
        )
        .unwrap();
        std::fs::write(
            d.spool.join("queue.json"),
            format!(r#"{{"next_id":9,"queue":[{}]}}"#, row("nzo_new", "Queued")),
        )
        .unwrap();

        d.load_queue();

        assert_eq!(d.queue.lock_ok().len(), 1, "the queued job must survive");
        assert_eq!(d.history.lock_ok().len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The append-only store is created private. It carries the job's
    /// archive password, its local paths and its identity metadata, and
    /// plain `OpenOptions` under the usual 022 umask left it 0644 -
    /// readable by every local account until a compaction (which does go
    /// through the private path) happened to run.
    #[cfg(unix)]
    #[test]
    fn a_fresh_history_store_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("mode");
        let d = test_daemon(&dir);
        assert!(d.history_append(&[r#"{"nzo_id":"a1","name":"x"}"#.to_string()]));
        let mode = std::fs::metadata(d.history_store_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "history store is group/world readable");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// One record, filed in history, for the concurrency tests below.
    fn filed(d: &Arc<Daemon>, id: &str) -> Arc<Mutex<Job>> {
        let v = json!({
            "nzo_id": id, "name": format!("Release.{id}"),
            "out_dir": "/tmp/o", "nzb_path": "/tmp/n.nzb", "state": "Completed",
        });
        let job = Arc::new(Mutex::new(job_from_json(&v).expect("job")));
        d.history.lock_ok().push(job.clone());
        job
    }

    /// A compaction running beside live appends must not lose one.
    ///
    /// `history_compact` used to snapshot the rows and rename its
    /// replacement over `history.jsonl` with no lock at all, while
    /// appends went to the file it was about to replace. Every
    /// transition that landed in that window - a park, a recategorize, a
    /// delete's tombstone - was simply absent at the next boot, and
    /// "Save queue", the remedy the durability errors name, calls the
    /// compaction on a LIVE daemon (H3, 10 Aug sweep).
    #[test]
    fn a_compaction_cannot_erase_a_concurrent_append() {
        let dir = tmp("compact-race");
        let d = test_daemon(&dir);
        filed(&d, "seed");
        assert!(d.history_compact());

        // Hold the compaction open in the exact gap: snapshot taken,
        // replacement not yet renamed into place.
        let gate = Arc::new(std::sync::Barrier::new(2));
        *super::COMPACT_BARRIER.lock_ok() = Some((d.spool.display().to_string(), gate.clone()));
        let compactor = {
            let d = d.clone();
            std::thread::spawn(move || assert!(d.history_compact()))
        };
        gate.wait();

        // A park lands here: the record joins history and is appended to
        // the store. The snapshot the compaction is holding predates it.
        let appender = {
            let d = d.clone();
            std::thread::spawn(move || {
                let job = filed(&d, "parked-in-the-gap");
                assert!(d.history_upsert(std::slice::from_ref(&job)));
            })
        };
        // Long enough that an UNSERIALIZED append would have reached the
        // file the rename is about to replace. With the lock it simply
        // waits for the rename, which is the whole point.
        std::thread::sleep(std::time::Duration::from_millis(50));
        compactor.join().unwrap();
        appender.join().unwrap();
        *super::COMPACT_BARRIER.lock_ok() = None;

        let (rows, _) = d.history_replay();
        assert!(
            rows.iter().any(|j| j.nzo_id == "parked-in-the-gap"),
            "the compaction published its stale snapshot over a live \
             append: {:?}",
            rows.iter().map(|j| &j.nzo_id).collect::<Vec<_>>()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A deleted record stays deleted, whatever a concurrent upsert is
    /// doing.
    ///
    /// `history_upsert_if_present` checked membership, dropped the lock,
    /// and only then serialized and appended. A delete landing in that
    /// window removed the row and wrote its tombstone FIRST, so the
    /// stale upsert became the last line for the id and replay brought
    /// the record back - exactly the resurrection the helper exists to
    /// prevent (H6, 10 Aug sweep).
    #[test]
    fn an_upsert_cannot_resurrect_a_deleted_record() {
        let dir = tmp("resurrect");
        for round in 0..40 {
            let d = test_daemon(&dir);
            let _ = std::fs::remove_file(d.history_store_path());
            let job = filed(&d, "victim");
            assert!(d.history_upsert(std::slice::from_ref(&job)));

            let deleter = {
                let d = d.clone();
                std::thread::spawn(move || {
                    d.history
                        .lock_ok()
                        .retain(|j| j.lock_ok().nzo_id != "victim");
                    assert!(d.history_tombstone(&["victim".to_string()]));
                })
            };
            // The mover's shape: mutate the record it holds an Arc to,
            // then persist it.
            job.lock_ok().name = format!("Renamed.{round}");
            d.history_upsert_if_present(&job);
            deleter.join().unwrap();

            let (rows, _) = d.history_replay();
            assert!(
                !rows.iter().any(|j| j.nzo_id == "victim"),
                "round {round}: the deleted record came back"
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A store that refuses the append is REWRITTEN instead, and the
    /// record survives the restart.
    ///
    /// The asymmetry M5 turned up is physical: the append needs write
    /// permission on `history.jsonl` itself, while the rewrite renames
    /// a fresh private file over it and needs only the directory. So a
    /// store left 0444 - or owned by a uid this daemon no longer runs
    /// as, one `sudo nzbfast` being enough to arrange that - loses every
    /// mutation until someone notices, and the way out is a path the
    /// daemon already has. It heals, too: the file that ends up there
    /// is one this daemon owns, so the next append is ordinary.
    #[cfg(unix)]
    #[test]
    fn a_refused_append_is_published_by_the_rewrite_instead() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("refused");
        let d = test_daemon(&dir);
        let job = filed(&d, "movedjob");
        assert!(d.history_upsert(std::slice::from_ref(&job)));

        let store = d.history_store_path();
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o444)).unwrap();
        job.lock_ok().out_dir = "/nas/Some.Release".into();
        let out = d.history_publish_move(
            &job,
            std::path::Path::new("/tmp/o"),
            Some(std::path::Path::new("/nas/Some.Release")),
        );
        // Restored first, so a failing assertion cannot leave an
        // unwritable file behind for the next run.
        let mode = std::fs::metadata(&store).unwrap().permissions().mode() & 0o777;
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert_eq!(out, HistWrite::Wrote, "the rewrite had to stand in");
        let (rows, _) = d.history_replay();
        assert_eq!(
            rows.iter()
                .find(|j| j.nzo_id == "movedjob")
                .map(|j| j.out_dir.clone()),
            Some("/nas/Some.Release".into()),
            "the moved payload's new folder never reached the store"
        );
        assert_eq!(mode, 0o600, "the replacement must be the private one");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// ...and when the DIRECTORY is unwritable too there is nothing left
    /// to try, so the caller is told rather than reassured.
    ///
    /// The rewrite is a fallback, not a guarantee: it fails exactly
    /// where a full volume, a read-only mount or a data folder this uid
    /// cannot write fails. `Refused` is what the movers' log line and
    /// the event ring hang off.
    #[cfg(unix)]
    #[test]
    fn a_store_no_rewrite_can_reach_answers_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("norewrite");
        let d = test_daemon(&dir);
        let job = filed(&d, "stuck");
        assert!(d.history_upsert(std::slice::from_ref(&job)));

        let store = d.history_store_path();
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o444)).unwrap();
        std::fs::set_permissions(&d.spool, std::fs::Permissions::from_mode(0o555)).unwrap();
        let out = d.history_publish_change(&job, "the media chip");
        std::fs::set_permissions(&d.spool, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert_eq!(out, HistWrite::Refused);
        // ...and the next refusal inside the minute does not pay for a
        // second whole-store rewrite. The record is unchanged either
        // way; what this pins is that the guard, not the disk, is what
        // answers.
        assert!(
            d.hist_rewrite_fail_ms.load(Ordering::Relaxed) > 0,
            "a failed rewrite has to arm the guard"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A record that left history while its caller was working is not a
    /// refusal, and must not be reported as one.
    ///
    /// This is the ordinary mover/unlock/prober race - a delete pulling
    /// the row - and the whole reason the guard exists. A bool could not
    /// tell it from a store that refused the line, so every caller that
    /// logged on false logged the daemon's healthy races too.
    #[test]
    fn a_deleted_record_answers_absent_not_refused() {
        let dir = tmp("absent");
        let d = test_daemon(&dir);
        let job = filed(&d, "gone");
        assert!(d.history_upsert(std::slice::from_ref(&job)));
        d.history.lock_ok().retain(|j| !Arc::ptr_eq(j, &job));

        assert_eq!(
            d.history_publish_change(&job, "the media chip"),
            HistWrite::Absent
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Retention must not throw the spool copies away before the store
    /// has agreed to forget the records they belong to.
    ///
    /// The sweep ran `drop_spool` over every retired row and THEN
    /// tombstoned, discarding the answer - while the comment three lines
    /// above the unlinks asserted the opposite ("because the tombstone is
    /// durable by now"), which was false against the code under it from
    /// the day it was written (P2-1). A refused tombstone left the
    /// aged-out record replaying at the next start with the `.nzb` its
    /// retry needs already gone - the one state this sweep must never
    /// reach, because the record is the user's only handle on it.
    ///
    /// Both stores are cut: the atomic rewrite rescues the ordinary
    /// refusal (a 0444 store in a writable folder), so the refusal that
    /// has to be survivable is the one with nothing left to try.
    #[test]
    fn retention_keeps_the_spool_copies_when_the_store_refuses() {
        use crate::serve::storecut::{Store, arm_store_cut, disarm};

        let dir = tmp("retainrefuse");
        let d = test_daemon(&dir);
        let mut nzbs = Vec::new();
        for id in ["r1", "r2", "r3"] {
            let nzb = dir.join(format!("{id}.nzb"));
            std::fs::write(&nzb, b"<nzb/>").unwrap();
            let job = Arc::new(Mutex::new(
                job_from_json(&json!({
                    "nzo_id": id, "name": format!("Release.{id}"),
                    "out_dir": "/tmp/o", "nzb_path": nzb.to_string_lossy(),
                    "state": "Completed", "finished_unix": 1,
                }))
                .expect("job"),
            ));
            d.history.lock_ok().push(job);
            nzbs.push(nzb);
        }
        assert!(d.history_compact(), "the fixture's own premise");
        // Keep one: the other two are the oldest and go.
        d.history_keep_count.store(1, Ordering::Relaxed);

        arm_store_cut(&[Store::HistoryAppend, Store::HistoryRewrite]);
        d.history_enforce_retention();
        disarm();

        for nzb in &nzbs {
            assert!(
                nzb.exists(),
                "{} was unlinked before the removal was durable - the record \
                 it retries from is still in the store on disk",
                nzb.display()
            );
        }
        let ids: Vec<String> = d
            .history
            .lock_ok()
            .iter()
            .map(|j| j.lock_ok().nzo_id.clone())
            .collect();
        assert_eq!(
            ids,
            ["r1", "r2", "r3"],
            "a refused reap leaves the list exactly as it found it, in order"
        );

        // ...and the ordinary outcome is unchanged: with a store that
        // takes the tombstone, the copies go with the records.
        d.history_enforce_retention();
        assert!(!nzbs[0].exists() && !nzbs[1].exists());
        assert!(nzbs[2].exists(), "the kept record keeps its own copy");
        let (rows, _) = d.history_replay();
        let ids: Vec<String> = rows.iter().map(|j| j.nzo_id.clone()).collect();
        assert_eq!(ids, ["r3"], "the store forgot the two it reaped");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Every emitted event reaches a client that keeps polling with the
    /// cursor it was handed.
    ///
    /// Allocation, ring insertion and the published cursor used to be
    /// three separate steps: a poll could see the counter already
    /// advanced and the ring not yet pushed, hand back that cursor, and
    /// the client - which adopts whatever it is given - filtered the
    /// event out forever (M1, 10 Aug sweep).
    #[test]
    fn no_event_can_slip_between_the_ring_and_the_cursor() {
        let dir = tmp("life-race");
        let d = test_daemon(&dir);
        const N: u64 = 300;
        let emitters: Vec<_> = (0..3)
            .map(|w| {
                let d = d.clone();
                std::thread::spawn(move || {
                    for i in 0..N / 3 {
                        d.life_emit("job.completed", json!({"w": w, "i": i}));
                    }
                })
            })
            .collect();
        // The dashboard's loop: ask for everything since the cursor the
        // last answer gave, and adopt the new one unconditionally.
        let mut cursor = 0u64;
        let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
        while cursor < N {
            let (events, reset, next) = d.life_since(cursor);
            assert!(!reset, "the ring is far larger than this test's traffic");
            for e in events {
                seen.insert(e["seq"].as_u64().unwrap());
            }
            cursor = next;
        }
        for h in emitters {
            h.join().unwrap();
        }
        let (events, _, _) = d.life_since(cursor);
        for e in events {
            seen.insert(e["seq"].as_u64().unwrap());
        }
        let missed: Vec<u64> = (1..=N).filter(|s| !seen.contains(s)).collect();
        assert!(missed.is_empty(), "a poller never saw events {missed:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A cursor from the PREVIOUS boot asks for a reseed.
    ///
    /// Sequence numbers restart at zero with the daemon, so a tab that
    /// slept through a restart came back holding a number no event of
    /// this boot will ever exceed: every new event read as already-seen,
    /// and the client adopted the lower cursor without ever being told
    /// it had missed anything (M2, 10 Aug sweep).
    #[test]
    fn a_cursor_from_a_previous_boot_forces_a_reseed() {
        let dir = tmp("life-boot");
        let d = test_daemon(&dir);
        d.life_emit("job.completed", json!({}));
        let (events, reset, cursor) = d.life_since(50);
        assert!(reset, "an impossible cursor must ask for a reseed");
        assert!(events.is_empty(), "a reseed replays nothing");
        assert_eq!(cursor, 1);
        // ...and a cursor this boot could have issued is served normally.
        let (events, reset, _) = d.life_since(0);
        assert!(!reset);
        assert_eq!(events.len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An NZBGet delete verb that owes a history row must not depend on
    /// `park` to make that row durable.
    ///
    /// For a job caught DOWNLOADING, park is a long way off: the fetch
    /// has to drain and the deferred file removal has to run (unbounded
    /// on a hung NAS) before it writes anything. The handler meanwhile
    /// drops the queue row and calls `save_queue`, publishing a
    /// queue.json the record has already left - so a kill in between
    /// lost it from BOTH stores: no DELETED/MANUAL row for the dupe
    /// check or the retry button, and under `GroupParkDelete` (files
    /// KEPT by contract) a whole payload on disk that nothing named
    /// (Codex sweep 14 Aug M1).
    #[test]
    fn a_deleted_active_job_is_durable_before_park_can_file_it() {
        let dir = tmp("del-prewrite");
        let d = test_daemon(&dir);
        let v = json!({
            "nzo_id": "nzo-actdel-1", "name": "Cancelled.Release",
            "out_dir": "/tmp/o", "nzb_path": "/tmp/n.nzb", "state": "Downloading",
        });
        let job = Arc::new(Mutex::new(job_from_json(&v).expect("job")));
        // `job_from_json` restores every nonterminal state as Queued -
        // that is the point of the override below, so set the live state
        // by hand rather than through the wire form.
        job.lock_ok().state = JobState::Downloading;
        d.queue.lock_ok().push_back(job.clone());
        assert!(d.save_queue(), "the queue snapshot the delete starts from");

        // The delete verb's active arm, in order: the durable
        // placeholder, then the tombstone, then the row leaving the
        // queue and the save that publishes its absence.
        assert!(d.delete_prewrite(std::slice::from_ref(&job), "MANUAL"));
        {
            let mut g = job.lock_ok();
            g.tombstone = true;
            g.delete_status = "MANUAL".into();
        }
        d.queue.lock_ok().retain(|j| !Arc::ptr_eq(j, &job));
        assert!(d.save_queue());
        // The live record is untouched by the prewrite: the pipeline is
        // still running, and stamping it terminal here would be a lie
        // the runner reads.
        assert_eq!(job.lock_ok().state, JobState::Downloading);

        // ...and the process dies right there, before the fetch drains.
        let d2 = test_daemon(&dir);
        d2.load_queue();
        let h = d2.history.lock_ok();
        let row = h
            .iter()
            .find(|j| j.lock_ok().nzo_id == "nzo-actdel-1")
            .cloned()
            .expect("the deleted record was lost from BOTH stores");
        drop(h);
        let g = row.lock_ok();
        assert_eq!(g.delete_status, "MANUAL", "the row must say why it is here");
        // A nonterminal state restores as Queued, so an un-overridden
        // row would sit in history looking like a job waiting to run.
        assert_eq!(g.state, JobState::Failed);
        assert!(g.finished_unix.is_some(), "and it must have an age");
        drop(g);
        assert!(
            d2.queue.lock_ok().is_empty(),
            "and it must not come back as a queued job as well"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The queue going idle without a park still says so.
    ///
    /// `queue.idle` was evaluated only from `Daemon::park`, so deleting
    /// the last queued job or pausing the last runnable one made the
    /// queue idle in silence (M3, 10 Aug sweep). The latch keeps it a
    /// transition: said once, and not again until something re-arms it.
    #[test]
    fn an_idle_queue_is_announced_once_per_transition() {
        let dir = tmp("idle");
        let d = test_daemon(&dir);
        // Armed the way an add arms it, with nothing runnable left.
        d.queue_idle_latch
            .store(false, std::sync::atomic::Ordering::Relaxed);
        d.note_queue_idle();
        d.note_queue_idle();
        let (events, _, _) = d.life_since(0);
        let idle: Vec<&Value> = events
            .iter()
            .filter(|e| e["kind"] == "queue.idle")
            .collect();
        assert_eq!(idle.len(), 1, "{events:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// ...and RESUMING a job is one of the things that re-arms it.
    ///
    /// Only the add and the runner's pick used to clear the latch, and
    /// neither can happen while a global pause (or an offline/disk/quota
    /// hold) keeps `pick_job` away. So pause -> resume -> pause on the
    /// last job announced the first idle edge and swallowed the second,
    /// even though the queue had genuinely gone runnable and quiet again
    /// in between (Codex sweep 14 Aug L2).
    #[test]
    fn resuming_a_job_re_arms_the_idle_latch() {
        let dir = tmp("idle-resume");
        let d = test_daemon(&dir);
        let v = json!({
            "nzo_id": "nzo-idle-1", "name": "Runnable.Release",
            "out_dir": "/tmp/o", "nzb_path": "/tmp/n.nzb", "state": "Queued",
        });
        let job = Arc::new(Mutex::new(job_from_json(&v).expect("job")));
        d.queue.lock_ok().push_back(job.clone());

        let idles = |d: &Arc<Daemon>| {
            d.life_since(0)
                .0
                .iter()
                .filter(|e| e["kind"] == "queue.idle")
                .count()
        };
        // A runnable job means the queue is not idle, whatever the latch
        // says - so this emits nothing and leaves the latch as it found it.
        d.queue_idle_latch
            .store(false, std::sync::atomic::Ordering::Relaxed);
        d.note_queue_idle();
        assert_eq!(idles(&d), 0, "a runnable queue is not idle");

        let pause = |d: &Arc<Daemon>, job: &Arc<Mutex<Job>>, on: bool| {
            let _q = d.queue.lock_ok();
            let mut g = job.lock_ok();
            assert!(crate::serve::api::queue::apply_pause(d, &mut g, on));
        };
        pause(&d, &job, true);
        d.note_queue_idle();
        assert_eq!(
            idles(&d),
            1,
            "pausing the last runnable job idles the queue"
        );

        // The queue is runnable again, and nothing can pick it up.
        pause(&d, &job, false);
        d.note_queue_idle();
        assert_eq!(idles(&d), 1, "a runnable queue is still not idle");

        pause(&d, &job, true);
        d.note_queue_idle();
        assert_eq!(
            idles(&d),
            2,
            "the second idle transition was swallowed - the resume never re-armed the latch"
        );

        // And the latch still keeps repeats silent, which is what stops
        // an over-broad re-arm from turning every poll into an event.
        d.note_queue_idle();
        assert_eq!(idles(&d), 2, "the latch must keep repeats silent");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The C8 measuring stick: replay a REAL `history.jsonl` and report
    /// what it cost.
    ///
    /// Codex audit C8 proposes an indexed on-disk history store, and the
    /// handoff holds it "conditional on real long-lived history scale".
    /// That condition needs a number, and a number needs a rig that runs
    /// against a real file rather than a synthetic one - the per-row cost
    /// here is dominated by fields a fixture would not bother to fill in
    /// (`cleaned_files`, identity metadata, failure detail), so a made-up
    /// row prices the wrong thing by an order of magnitude.
    ///
    /// Ignored by default because it takes a path:
    ///
    /// ```sh
    /// NZBFAST_NO_ENRICH=1 NZBFAST_HIST_REPLAY_FILE=/path/to/history.jsonl \
    ///   NZBFAST_HIST_REPLAY_SCALE=10 \
    ///   cargo test -p nzbfast --bin nzbfast -- --ignored --nocapture \
    ///   measure_history_replay
    /// ```
    ///
    /// `SCALE` replicates the file's LINES that many times, re-stamping
    /// every `nzo_id` with a per-copy suffix so the copies are distinct
    /// records rather than upserts of each other. Tombstones replicate
    /// with their ids, so the live:dead ratio - which is what the
    /// quadratic-replay fix (1d1460f7c) turns on - is preserved at every
    /// scale. That is the whole point: a 10x file is what years of use
    /// look like, and it is the only honest way to extrapolate from a
    /// store that is five days old.
    #[test]
    #[ignore = "measuring stick: set NZBFAST_HIST_REPLAY_FILE"]
    fn measure_history_replay() {
        let Ok(src) = std::env::var("NZBFAST_HIST_REPLAY_FILE") else {
            eprintln!("set NZBFAST_HIST_REPLAY_FILE=/path/to/history.jsonl");
            return;
        };
        let scale: usize = std::env::var("NZBFAST_HIST_REPLAY_SCALE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1)
            .max(1);

        let raw = std::fs::read(&src).expect("read the source history file");
        let dir = tmp("measure");
        let d = test_daemon(&dir);
        let path = d.history_store_path();

        // Build the file to replay. At scale 1 this is a byte copy; above
        // it, every line is re-stamped through serde so the copies are
        // separate records. Lines that do not parse (a torn tail) are
        // carried through verbatim on the first copy and dropped from the
        // rest - replay's per-line tolerance is being measured, not the
        // tear itself.
        let mut out: Vec<u8> = Vec::with_capacity(raw.len() * scale);
        for copy in 0..scale {
            for chunk in raw.split(|b| *b == b'\n') {
                let Ok(line) = std::str::from_utf8(chunk) else {
                    if copy == 0 {
                        out.extend_from_slice(chunk);
                        out.push(b'\n');
                    }
                    continue;
                };
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if copy == 0 && scale == 1 {
                    out.extend_from_slice(line.as_bytes());
                    out.push(b'\n');
                    continue;
                }
                match serde_json::from_str::<Value>(line) {
                    Ok(mut v) => {
                        if let Some(id) = v.get("nzo_id").and_then(Value::as_str) {
                            let fresh = format!("{id}-c{copy}");
                            v["nzo_id"] = Value::String(fresh);
                        }
                        out.extend_from_slice(v.to_string().as_bytes());
                        out.push(b'\n');
                    }
                    Err(_) if copy == 0 => {
                        out.extend_from_slice(line.as_bytes());
                        out.push(b'\n');
                    }
                    Err(_) => {}
                }
            }
        }
        std::fs::write(&path, &out).expect("write the replay fixture");
        let file_bytes = out.len();
        let file_lines = out.iter().filter(|b| **b == b'\n').count();

        // Three runs: the first pays the page-cache fault, and the spread
        // says whether the number is stable enough to extrapolate from.
        let mut times = Vec::new();
        let mut rows = 0usize;
        let mut wants_compaction = false;
        let rss_before = rss_kb();
        let peak_start = peak_rss_kb();
        let mut held: Vec<Arc<Mutex<Job>>> = Vec::new();
        for run in 0..3 {
            let t0 = std::time::Instant::now();
            let (jobs, wants) = d.history_replay();
            let dt = t0.elapsed();
            times.push(dt);
            rows = jobs.len();
            wants_compaction = wants;
            if run == 2 {
                // Hold them the way `load_queue` does - one Arc<Mutex>
                // per row - so the RSS reading below prices what the daemon
                // actually keeps resident, not the transient Vec<Job>.
                held = jobs.into_iter().map(|j| Arc::new(Mutex::new(j))).collect();
            }
        }
        let rss_after = rss_kb();
        let peak_replay = peak_rss_kb();

        let best = times.iter().min().copied().unwrap_or_default();
        let worst = times.iter().max().copied().unwrap_or_default();
        println!("--- history replay measurement ---");
        println!("source          {src}");
        println!("scale           {scale}x");
        println!("file            {file_bytes} bytes, {file_lines} lines");
        println!("live rows       {rows} (wants_compaction {wants_compaction})");
        println!("replay          best {best:?}, worst {worst:?}, runs {times:?}");
        println!(
            "per row         {:.1} us, {} file bytes",
            best.as_secs_f64() * 1e6 / rows.max(1) as f64,
            file_bytes / rows.max(1)
        );
        println!("size_of::<Job>  {}", std::mem::size_of::<Job>());
        match (rss_before, rss_after) {
            (Some(a), Some(b)) => println!(
                "rss             {a} -> {b} kB (delta {} kB, {:.1} kB/row)",
                b.saturating_sub(a),
                b.saturating_sub(a) as f64 / rows.max(1) as f64
            ),
            _ => println!("rss             unavailable"),
        }
        assert!(!held.is_empty(), "the rows must outlive the RSS reading");

        // ...and the OTHER full scan C8 names: `history_page`, which
        // clones the whole Arc vector and walks every row. Install the
        // replayed rows the way the daemon does and time both shapes.
        // The dashboard poll takes this path only when `history_rev`
        // moved (api/queue.rs gates it on `client_h != hrev`); the SAB
        // facade's `mode=history` - what every *arr polls - is UNGATED
        // and pays it on every request, which is the one that scales
        // with client count rather than with download rate.
        *d.history.lock_ok() = held;
        let page = |summary: bool, limit: usize| {
            let q = super::super::history::HistQuery {
                failed_only: false,
                status: None,
                category: None,
                ids: None,
                search: None,
                bucket: None,
                start: 0,
                limit,
            };
            let mut best = std::time::Duration::MAX;
            let mut n = 0usize;
            for _ in 0..3 {
                let t0 = std::time::Instant::now();
                let (slots, matched, _) =
                    super::super::history::history_page(d.as_ref(), &q, summary);
                best = best.min(t0.elapsed());
                n = matched;
                std::hint::black_box(slots);
            }
            (best, n)
        };
        let (dash, n) = page(true, 50);
        let peak_dash = peak_rss_kb();
        // What a bare `mode=history` costs NOW: `from_params` defaults
        // an absent (or zero) `limit` to `HISTORY_DEFAULT_LIMIT`.
        let (capped, _) = page(false, super::super::history::HISTORY_DEFAULT_LIMIT);
        let peak_capped = peak_rss_kb();
        // ...and what it cost before that default existed, which is
        // still what an explicit `limit` big enough to cover the store
        // buys whoever asks for it.
        let (sab, _) = page(false, 0);
        let peak_sab = peak_rss_kb();
        println!("history_page    dashboard window (summary, 50 of {n}): {dash:?}");
        println!(
            "history_page    SAB facade, default cap ({} of {n} full rows): {capped:?}",
            super::super::history::HISTORY_DEFAULT_LIMIT
        );
        println!("history_page    SAB facade (full rows, unbounded): {sab:?}");
        if let (Some(a), Some(b), Some(c), Some(dd), Some(e)) =
            (peak_start, peak_replay, peak_dash, peak_capped, peak_sab)
        {
            println!(
                "peak rss        start {a} kB -> replay+install {b} kB (+{}) -> \
                 dashboard page {c} kB (+{}) -> capped SAB page {dd} kB (+{}) -> \
                 unbounded SAB page {e} kB (+{})",
                b.saturating_sub(a),
                c.saturating_sub(b),
                dd.saturating_sub(c),
                e.saturating_sub(dd)
            );
        }

        // Compaction is the other thing startup can owe: `load_queue`
        // runs it inline when replay reports more dead lines than live
        // rows, so on a delete-heavy store it lands on the critical path
        // beside the replay. Time it whenever the fixture asked for it.
        if wants_compaction {
            let t0 = std::time::Instant::now();
            let ok = d.history_compact();
            let dt = t0.elapsed();
            let after = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            println!("history_compact {dt:?} (ok {ok}), file {file_bytes} -> {after} bytes");
        }

        d.history.lock_ok().clear();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// This process's resident set in kB, or None where `ps` cannot say.
    ///
    /// Deliberately a shell-out rather than a crate: `ps -o rss=` is
    /// spelled the same on macOS and Linux, and the measuring stick is
    /// not worth a dependency.
    fn rss_kb() -> Option<u64> {
        let out = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p"])
            .arg(std::process::id().to_string())
            .output()
            .ok()?;
        String::from_utf8_lossy(&out.stdout).trim().parse().ok()
    }

    /// The process's PEAK resident set in kB - the high-water mark, which
    /// is what a memory verdict actually turns on.
    ///
    /// Current RSS answers the wrong question here. Replay's transients
    /// (the whole-file byte vector C8 names, and the per-line `Value`)
    /// are freed before it returns, and a large one goes back to the OS
    /// through munmap, so a reading taken afterwards can be LOWER than
    /// the moment that decides whether a small box survives the start.
    /// `ru_maxrss` is monotone, so the deltas between checkpoints
    /// attribute the peak to the phase that caused it.
    ///
    /// Unit trap: macOS reports `ru_maxrss` in BYTES and Linux in
    /// KILOBYTES, for the same field of the same struct.
    #[cfg(unix)]
    fn peak_rss_kb() -> Option<u64> {
        // SAFETY: `libc::rusage` is a C struct of integers and timevals,
        // so all-zero is a valid bit pattern, and getrusage fills it
        // before `ru_maxrss` is read.
        let mut u: libc::rusage = unsafe { std::mem::zeroed() };
        // SAFETY: `&mut u` is a live, exclusively borrowed struct of
        // exactly the type getrusage(2) writes, and the field is only
        // read on the success path.
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut u) } != 0 {
            return None;
        }
        let raw = u.ru_maxrss as u64;
        Some(if cfg!(target_os = "macos") {
            raw / 1024
        } else {
            raw
        })
    }

    #[cfg(not(unix))]
    fn peak_rss_kb() -> Option<u64> {
        None
    }
}
