//! §7a / round 39: the QUEUE's own append-only store, the same shape
//! `histstore.rs` gave history in §129 phase 1a and for the same reason.
//!
//! `save_queue` used to serialize the WHOLE live queue to pretty-printed
//! JSON and write it atomically to `.spool/queue.json` on every mutation,
//! from 42 call sites. At 5,000 jobs that is 12.3 MB re-serialized,
//! re-written and fsynced TWICE (file, then directory) per add, so
//! building a queue was O(N^2) by construction - round 37 measured it at
//! 113.2 s of a 188.1 s 1,500-job build, 60% of what was left and the
//! whole of the remaining rise.
//!
//! The store here is `.spool/queue.jsonl`, one compact `job_json` line
//! per record, append-only:
//!
//!  * a mutation appends a fresh line for the same nzo_id - the LAST
//!    line for an id wins on replay;
//!  * a removal appends a tombstone line `{"nzo_id": ..., "deleted": true}`;
//!  * the id allocator rides a control line `{"next_id": N}`, appended
//!    only when it moved, and replay takes the MAX it sees (which is what
//!    `load_queue` already did with the snapshot's value);
//!  * replay tolerates a torn tail, so a crash mid-append costs at most
//!    the one line being written;
//!  * compaction rewrites one line per live record when more than half
//!    the lines are dead.
//!
//! ### What `save_queue` still promises, and how it keeps it cheaply
//!
//! **Durable-before-return.** `save_queue` returns whether the record
//! LANDED and the watch poller deletes the user's original `.nzb` on that
//! return (`Enqueued::durable`, the 27 Aug C09 fix). Nothing here is
//! asynchronous: the durable path is one appended line plus its fsync,
//! O(1) in queue size instead of O(queue), which is the whole point. The
//! debounce (`save_queue_soon`) is untouched and no caller moves onto it.
//!
//! **Make disk match memory, whatever the caller changed.** The 42 call
//! sites do not say WHAT they mutated, and they were not asked to: a
//! publish serializes the live rows and appends only the lines that
//! DIFFER from what this process last published (a 64-bit hash per id,
//! [`QueuePub::published`]). So a site that mutates two jobs and calls
//! `save_queue` once still publishes both, exactly as the whole-file
//! rewrite did, and a mutation whose own save was somehow missed is
//! picked up by the next publish rather than lost. What the store removes
//! is the WRITE, not the check.
//!
//! **Queue ORDER is part of the record.** History is a set; the queue is
//! a sequence, and `pick_job` reads it in order. Append order carries
//! that for free while rows only arrive at the back and leave from
//! anywhere - which is every add and every delete. When the live order is
//! anything else (a `push_front` restore, a move-to-top), the publish
//! falls back to the atomic REWRITE, which is what the whole file used to
//! do on every mutation and now does only on a reorder.
//!
//! **A store this daemon cannot append to.** The old write went through
//! `persist::write_atomic` - private temp file, rename - and so needed
//! only the DIRECTORY; an append needs write permission ON THE FILE.
//! That asymmetry is P2-1's trigger on the history side, so the queue
//! takes history's answer too: a refused append falls back to the
//! rewrite, one attempt a minute, and only both refusing returns false.
//!
//! ### Going back to an older build
//!
//! The migration is one way, and what an older nzbfast does on a spool
//! it has run over was MEASURED on 3 Sep 2026 rather than assumed - two
//! real binaries, one built at the commit before this store landed. The
//! queue comes back either way, through the `queue.json.bak` the
//! migration's own read leaves behind or, once that is swept, through
//! `recover_orphaned_spool`. See [`Daemon::sweep_retired_snapshots`] for
//! the two retirement copies and their lifetime, and
//! [`Daemon::legacy_snapshot_outlives_store`] for the way forward; both
//! carry the measurement and what each path costs.
//!
//! `queue_rev`, the dashboard's change handle, is still bumped AT this
//! seam and for the same reason: a queue change that must survive a
//! restart comes through here, so the revision sees it by construction.

use super::*;
use std::collections::{HashMap, HashSet};
use std::io::Write as _;

/// What this process has published to `queue.jsonl`, so a publish can
/// append only what changed.
///
/// Guarded by [`Daemon::hold_queue_writes`] - the same lock every queue
/// write already serialized on - so the cache and the file move together
/// and two workers can neither interleave bytes nor disagree about what
/// is in them.
#[derive(Default)]
pub struct QueuePub {
    /// nzo_id -> hash of the last line published for it. A hash rather
    /// than the line: 8 bytes against ~2.4 KB a row, which is 12 MB of
    /// resident cache at 5,000 jobs for a check that only ever asks
    /// "same or not".
    published: HashMap<String, u64>,
    /// The id order the store implies, oldest first. Compared against
    /// the live order to decide append-or-rewrite; see the module header.
    order: Vec<String>,
    /// Lines on disk, live and dead, for the compaction rule.
    lines: usize,
    /// The last `next_id` published, so an unchanged allocator costs no
    /// line. 0 means "nothing published yet", which no real allocator is.
    next_id: u64,
    /// When a rewrite that stood in for a REFUSED append last failed, in
    /// `now_ms` (0 = never) - history's `hist_rewrite_fail_ms` rule, for
    /// the same reason: a data folder that is not coming back must not
    /// turn every add into a full-store write.
    rewrite_fail_ms: u64,
}

/// One line's worth of hash. `DefaultHasher` is in-process only - the
/// cache never outlives the run that built it - so its lack of a stability
/// guarantee across releases costs nothing here.
fn line_hash(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

/// A record's `nzo_id` and its serialized line, in queue order.
pub(crate) type Row = (String, String);

impl Daemon {
    pub fn queue_store_path(&self) -> PathBuf {
        self.spool.join("queue.jsonl")
    }

    /// Was the `queue.json` sitting beside the store written AFTER it?
    ///
    /// `load_queue` treats `queue.jsonl` as the whole truth whenever it
    /// exists, and its reason is sound as far as it goes: the store is
    /// only ever created by the migration, which consumes `queue.json` in
    /// the same breath, so a snapshot still beside it is a crash between
    /// that atomic write and the rename that retires it - a snapshot the
    /// store has already superseded, which it would be wrong to re-merge.
    ///
    /// There is a second producer, and it is the more likely one: an
    /// OLDER nzbfast. A build from before §7a does not read `queue.jsonl`
    /// at all, so a user who rolls a release back runs a whole session
    /// writing `queue.json` beside a store nothing is updating. Measured
    /// 3 Sep 2026 against a binary built at `d2d57c079`: rolling forward
    /// again then reverted the queue to the instant of the migration -
    /// the release the user had deleted came back, and the one they had
    /// added was gone, with no message anywhere saying so.
    ///
    /// The two cases are told apart by the one thing that differs. The
    /// torn migration wrote the store LAST, so its snapshot is the older
    /// file; the older binary wrote its snapshot last, after the store
    /// had been sitting untouched for the length of that session. So a
    /// snapshot strictly newer than the store is a build that could not
    /// see the store, and `load_queue` migrates it again - which adopts
    /// that session's queue and retires its snapshot exactly as the first
    /// migration did. Anything else keeps the store, which is the
    /// unchanged rule and the answer for every torn write.
    ///
    /// Equal timestamps keep the store: a filesystem whose granularity
    /// cannot separate the two writes is describing the torn migration,
    /// not a session.
    pub(crate) fn legacy_snapshot_outlives_store(&self) -> bool {
        let mtime = |p: PathBuf| std::fs::metadata(p).and_then(|m| m.modified()).ok();
        let (Some(snap), Some(store)) = (
            mtime(self.spool.join("queue.json")),
            mtime(self.queue_store_path()),
        ) else {
            return false;
        };
        snap > store
    }

    /// How long the pre-migration snapshots are kept beside the store,
    /// in days. See [`Daemon::sweep_retired_snapshots`].
    const RETIRED_SNAPSHOT_KEEP_DAYS: u64 = 14;

    /// Remove the pre-migration `queue.json` copies once they are old
    /// enough that keeping them costs more than they can buy back.
    ///
    /// The migration retires `queue.json` by RENAMING it to
    /// `queue.json.premigrate` (see `load_queue`), and the read that fed
    /// that migration leaves a second, byte-identical copy at
    /// `queue.json.bak` - `persist::load_json_with_backup` refreshes the
    /// backup from the bytes it just parsed. So a migrated spool carries
    /// two full copies of the old snapshot forever: 12.4 MB apiece at
    /// 5,000 jobs, for the life of the install.
    ///
    /// The `.bak` is not inert, and that is the reason this sweep exists
    /// rather than a note saying the copies are harmless. An older
    /// nzbfast booting on a migrated spool finds no `queue.json`, and
    /// `load_json_with_backup` then RECOVERS from the `.bak` - measured
    /// 3 Sep 2026 against a 1.3.1 binary built at `d2d57c079`, the commit
    /// before the store landed. That path restores the queue exactly as
    /// it stood AT THE MIGRATION, ids, order, categories, priorities and
    /// paused state all intact, which is the best possible answer the day
    /// after an upgrade. Weeks later it is the worst one: it is a
    /// snapshot of a queue the user has moved on from, and a job they
    /// deleted in the meantime comes back from it pointing at an `.nzb`
    /// the delete unlinked. With both copies gone the same rollback falls
    /// through to `recover_orphaned_spool`, which adopts the CURRENT
    /// spool - ids, order and category survive, priority and paused state
    /// do not - and that is the better trade once the snapshot is stale.
    ///
    /// So: keep both for [`Self::RETIRED_SNAPSHOT_KEEP_DAYS`] days, which
    /// covers the window a rollback actually happens in, and then take
    /// both. Both, together: sweeping only the copy this daemon named
    /// would leave the `.bak` doing the whole job invisibly, which is
    /// the worst of the two behaviours and the hardest to explain.
    ///
    /// Called from `load_queue` and only when the store exists, so a
    /// spool still waiting for its migration is never touched. Each file
    /// is judged on its own mtime: a user who removed one by hand does
    /// not thereby pin the other.
    pub(crate) fn sweep_retired_snapshots(&self) {
        let cutoff = std::time::Duration::from_secs(Self::RETIRED_SNAPSHOT_KEEP_DAYS * 86_400);
        for name in ["queue.json.premigrate", "queue.json.bak"] {
            let p = self.spool.join(name);
            let Ok(age) = std::fs::metadata(&p).and_then(|m| m.modified()) else {
                continue;
            };
            let Ok(age) = age.elapsed() else {
                // A future mtime (a clock that went backwards, a restored
                // backup) is not evidence of age. Leave it and ask again
                // next start.
                continue;
            };
            if age < cutoff {
                continue;
            }
            match std::fs::remove_file(&p) {
                Ok(()) => info!(
                    target: "queue",
                    "removed {} - it is {} days old and queue.jsonl has been the \
                     record throughout",
                    p.display(),
                    age.as_secs() / 86_400
                ),
                Err(e) => warn!(target: "queue", "could not remove {}: {e}", p.display()),
            }
        }
    }

    /// The queue as it stands, serialized, ready to publish. Membership
    /// is snapshotted under the queue lock (Arc clones, O(N) pointer
    /// bumps) and each job is serialized AFTER it is released - the
    /// #38 rule `save_queue` has held since issue #38: serializing under
    /// the queue lock held it across every job lock and JSON build, and
    /// every API request queues behind it.
    pub(crate) fn queue_rows(&self) -> Vec<Row> {
        let snapshot: Vec<Arc<Mutex<Job>>> = self.queue.lock_ok().iter().cloned().collect();
        snapshot
            .iter()
            .map(|j| {
                let g = j.lock_ok();
                (g.nzo_id.clone(), job_json(&g).to_string())
            })
            .collect()
    }

    /// Publish `rows` as the whole live queue, with
    /// [`Daemon::hold_queue_writes`] ALREADY held. Returns whether the
    /// queue on disk now says what memory says.
    pub(crate) fn queue_publish_locked(&self, rows: &[Row]) -> bool {
        let mut st = self.queue_pub.lock_ok();
        let next_id = self.next_id.load(Ordering::Relaxed);
        let mut batch: Vec<String> = Vec::new();
        let mut live: HashSet<&str> = HashSet::with_capacity(rows.len());
        // Hashed ONCE per row: this loop is the whole of what a publish
        // still costs O(queue), so it does not get to do the work twice.
        let hashes: Vec<u64> = rows.iter().map(|(_, line)| line_hash(line)).collect();
        for ((id, line), h) in rows.iter().zip(&hashes) {
            live.insert(id.as_str());
            if st.published.get(id) != Some(h) {
                batch.push(line.clone());
            }
        }
        // A row that left the queue is a tombstone, exactly as a deleted
        // history record is. Order within the batch does not matter: an
        // id is either live (and re-appended above) or gone.
        let gone: Vec<String> = st
            .published
            .keys()
            .filter(|id| !live.contains(id.as_str()))
            .cloned()
            .collect();
        for id in &gone {
            batch.push(json!({ "nzo_id": id, "deleted": true }).to_string());
        }
        if next_id != st.next_id {
            batch.push(json!({ "next_id": next_id }).to_string());
        }
        // Does append order still describe the live order? Everything
        // that survives keeps its place, everything new lands at the
        // back. Anything else - a `push_front` restore, a move-to-top -
        // cannot be said with an append and takes the rewrite.
        let implied: Vec<&str> = st
            .order
            .iter()
            .map(String::as_str)
            .filter(|id| live.contains(id))
            .chain(
                rows.iter()
                    .map(|(id, _)| id.as_str())
                    .filter(|id| !st.published.contains_key(*id)),
            )
            .collect();
        let want: Vec<&str> = rows.iter().map(|(id, _)| id.as_str()).collect();
        let reordered = implied != want;
        // The dashboard's change handle, bumped WITH the write and
        // whatever it costs - a queue change that should survive restart
        // comes through here, so the revision sees it by construction.
        self.queue_rev.fetch_add(1, Ordering::Relaxed);
        if batch.is_empty() && !reordered {
            // Nothing changed. The old whole-file rewrite wrote anyway;
            // not writing is the same statement about disk and saves the
            // fsync, and `save_failed_at` still clears because the queue
            // on disk is not stale.
            self.save_failed_at.store(0, Ordering::Relaxed);
            return true;
        }
        // More dead lines than live rows: worth a rewrite. Histstore's
        // rule, and its 64-line floor - a store this small is not worth
        // rewriting whatever fraction of it is dead.
        let overgrown = st.lines + batch.len() > rows.len().saturating_mul(2).max(64);
        let record = |st: &mut QueuePub| {
            for ((id, _), h) in rows.iter().zip(&hashes) {
                st.published.insert(id.clone(), *h);
            }
            for id in &gone {
                st.published.remove(id);
            }
            st.order = want.iter().map(|s| (*s).to_string()).collect();
            st.lines += batch.len();
            st.next_id = next_id;
        };
        let landed = if reordered {
            // The one change an append cannot say. A refused rewrite is a
            // refused save: appending the batch would publish the rows
            // under an order the store no longer means, which is worse
            // than saying the write did not happen.
            self.queue_rewrite_locked(&mut st, rows, next_id)
        } else if overgrown {
            // Housekeeping rather than a rescue, so it is NOT rate-gated
            // and a rewrite that refuses falls back to the APPEND - still
            // a correct publish, with the store merely staying long.
            if self.queue_rewrite_locked(&mut st, rows, next_id) {
                true
            } else if self.queue_write_locked(&batch) {
                record(&mut st);
                true
            } else {
                false
            }
        } else if self.queue_write_locked(&batch) {
            record(&mut st);
            true
        } else {
            // The append was refused. It needs write permission ON THE
            // FILE while the rewrite needs only the DIRECTORY, which is
            // the whole way out of the commonest refusal there is.
            self.queue_rescue_locked(&mut st, rows, next_id)
        };
        self.save_failed_at
            .store(if landed { 0 } else { epoch_secs() }, Ordering::Relaxed);
        landed
    }

    /// Publish ONE row and the id allocator, without scanning the queue.
    ///
    /// [`Daemon::save_queue`]'s remaining O(queue) half is the DIFF SCAN
    /// - serializing every live row to find the ones that changed - and
    /// on the ADD path there is nothing to find. `enqueue` mutates the
    /// job it is adding and no other record (its one edit to another
    /// row's world is the `post_ids` memo, which is not persisted), and
    /// it pushes at the BACK, which is exactly what an append means. So
    /// the add says which row it wrote and the publish costs one line
    /// plus its fsync at any queue size. Round 39 measured what the scan
    /// was worth without this: ~7 us per queued row per add, which is
    /// half the cost of an add at 5,000 jobs and all of the curve.
    ///
    /// The full scan stays the default for the other 41 call sites. They
    /// do not say what they changed and were not asked to, and a site
    /// that mutates two records must keep publishing both.
    ///
    /// Safe against a future edit to `enqueue` in three separate ways,
    /// which is why it is worth having at all:
    ///
    ///  * the publish cache is a statement about DISK, not about this
    ///    call, so a row this path leaves stale is picked up by the next
    ///    full `save_queue` rather than lost;
    ///  * a row published here that is NOT at the back leaves
    ///    `QueuePub::order` disagreeing with the live queue, and the next
    ///    full publish reads that as a reorder and rewrites the store;
    ///  * a refused append falls back to the full publish, which is what
    ///    carries the rewrite rescue.
    ///
    /// AND IT NEVER RUNS WHILE A SAVE IS KNOWN FAILED. The first bullet
    /// says a stale row is picked up by "the next full `save_queue`" -
    /// but nothing schedules one: the saver task
    /// (`nzbfast-tasks::tasks`) is wake-driven, not a timer, so the next
    /// mutation is the next save, and if that mutation is an add it
    /// comes back here. An append would then land ONE row, clear
    /// `save_failed_at`, and take the dashboard's "The queue could not
    /// be saved at ..." warning down while the rows the failed save was
    /// carrying are still only in memory - a pause, say, that a crash
    /// then replays as unpaused with nothing ever having said so. So
    /// when the flag is set on entry this hands the whole publish over
    /// to `queue_publish_locked`, which diffs against `published` and
    /// therefore re-emits exactly those stale rows, and which clears the
    /// flag only when the whole store landed. The O(1) append is for the
    /// healthy case, which is all of them but this one.
    ///
    /// Durable-before-return holds exactly as it does on the full path:
    /// the line is fsync'd before this returns, which is what the watch
    /// poller reads before it deletes the user's original `.nzb`.
    pub fn save_queue_row(&self, job: &Arc<Mutex<Job>>) -> bool {
        // §158 item 7: the harness's kill-here seam, the same one
        // `save_queue` takes and before the lock for the same reason.
        #[cfg(any(test, feature = "test-support"))]
        if super::storecut::cut_here(super::storecut::Store::Queue) {
            return false;
        }
        let _g = Self::hold_queue_writes();
        // A save is already known failed, so the store is stale in rows
        // this append cannot carry. Take the full publish - see the last
        // paragraph of the doc comment. Read under the IO lock, which is
        // what orders it against the store that set it.
        if self.save_failed_at.load(Ordering::Relaxed) != 0 {
            let rows = self.queue_rows();
            return self.queue_publish_locked(&rows);
        }
        let (id, line) = {
            let g = job.lock_ok();
            (g.nzo_id.clone(), job_json(&g).to_string())
        };
        let next_id = self.next_id.load(Ordering::Relaxed);
        let h = line_hash(&line);
        let mut st = self.queue_pub.lock_ok();
        let mut batch: Vec<String> = Vec::new();
        if st.published.get(&id) != Some(&h) {
            batch.push(line);
        }
        if next_id != st.next_id {
            batch.push(json!({ "next_id": next_id }).to_string());
        }
        self.queue_rev.fetch_add(1, Ordering::Relaxed);
        if batch.is_empty() {
            self.save_failed_at.store(0, Ordering::Relaxed);
            return true;
        }
        // Compaction is the full path's to run - it needs every live row
        // - so an overgrown store hands the whole publish over rather
        // than appending onto it for ever.
        let overgrown = st.lines + batch.len() > st.order.len().saturating_mul(2).max(64);
        if !overgrown && self.queue_write_locked(&batch) {
            if !st.published.contains_key(&id) {
                st.order.push(id.clone());
            }
            st.published.insert(id, h);
            st.lines += batch.len();
            st.next_id = next_id;
            self.save_failed_at.store(0, Ordering::Relaxed);
            return true;
        }
        // Overgrown, or the store refused the append: the full publish
        // is what carries the compaction and the rewrite rescue, and it
        // is the same statement about disk either way.
        drop(st);
        let rows = self.queue_rows();
        self.queue_publish_locked(&rows)
    }

    /// Append pre-serialized lines and fsync once. Best-effort like the
    /// whole-file write it replaces - a failed write must never take down
    /// a live daemon - but the caller stands the rewrite in for it.
    fn queue_write_locked(&self, lines: &[String]) -> bool {
        if lines.is_empty() {
            return true;
        }
        let path = self.queue_store_path();
        // 0600 on unix, for the same reason `persist::write_atomic` does
        // it and `history_write_locked` repeats it: a queue row
        // serializes the job's archive password, its local paths and its
        // identity metadata. An append CREATES the file under the
        // ordinary 022 umask, which would leave it world-readable for the
        // life of the store. `mode` applies only to creation.
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
            // welds the first post-recovery record onto them into one
            // unreadable line, so the NEXT replay drops this record with
            // the tear - history's F-03, and the queue would lose a JOB
            // to it rather than a row. One leading newline turns the weld
            // back into "torn line, then this record", the shape replay
            // already handles.
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
        match r {
            Ok(()) => true,
            Err(e) => {
                error!(target: "queue", "queue store {}: {e}", path.display());
                false
            }
        }
    }

    /// One line per live record, published atomically - the compaction,
    /// and the RESCUE a refused append falls back to.
    ///
    /// The asymmetry is the whole reason it can rescue anything: the
    /// append needs write permission ON THE FILE, this goes through
    /// `persist::write_atomic` and needs only the DIRECTORY, so a
    /// `queue.jsonl` left 0444, owned by a uid this daemon no longer runs
    /// as (one `sudo nzbfast` is enough) or holding an immutable flag is
    /// REPLACED by a file this daemon owns - and the append after it
    /// works too. The rescue path takes that at most once a minute -
    /// see [`Daemon::queue_rescue_locked`], which holds the gate; a
    /// compaction is not gated, because it only runs when the store has
    /// earned it.
    fn queue_rewrite_locked(&self, st: &mut QueuePub, rows: &[Row], next_id: u64) -> bool {
        // Outside the `arm_cut` budget and reachable only through
        // `arm_store_cut`, for `Store::HistoryRewrite`'s reason: the
        // budget models a KILL, and the rewrite is not a step on any
        // ordinary path.
        #[cfg(any(test, feature = "test-support"))]
        if super::storecut::cut_here(super::storecut::Store::QueueRewrite) {
            return false;
        }
        let now = nzbkit::pool::now_ms();
        let mut buf =
            String::with_capacity(rows.iter().map(|(_, l)| l.len() + 1).sum::<usize>() + 32);
        for (_, line) in rows {
            buf.push_str(line);
            buf.push('\n');
        }
        // LAST, so last-wins replay reads the allocator the publish
        // meant even if a stale control line sits above it.
        buf.push_str(&json!({ "next_id": next_id }).to_string());
        buf.push('\n');
        let path = self.queue_store_path();
        match crate::persist::write_atomic(&path, buf.as_bytes()) {
            Ok(()) => {
                st.published = rows
                    .iter()
                    .map(|(id, line)| (id.clone(), line_hash(line)))
                    .collect();
                st.order = rows.iter().map(|(id, _)| id.clone()).collect();
                st.lines = rows.len() + 1;
                st.next_id = next_id;
                st.rewrite_fail_ms = 0;
                true
            }
            Err(e) => {
                error!(target: "queue", "queue store rewrite {}: {e}", path.display());
                st.rewrite_fail_ms = now.max(1);
                false
            }
        }
    }

    /// The rewrite as a RESCUE for a refused append, at most one attempt
    /// a minute.
    ///
    /// The rewrite writes every live row, so a data folder that is not
    /// coming back must not turn each queue mutation into a full-store
    /// write - history's `hist_rescue_open` rule. The gate lives HERE
    /// rather than inside the rewrite because a COMPACTION is
    /// housekeeping the store has earned, and must not be held back by an
    /// unrelated permission failure a moment ago.
    fn queue_rescue_locked(&self, st: &mut QueuePub, rows: &[Row], next_id: u64) -> bool {
        let now = nzbkit::pool::now_ms();
        if st.rewrite_fail_ms != 0 && now.saturating_sub(st.rewrite_fail_ms) < 60_000 {
            return false;
        }
        self.queue_rewrite_locked(st, rows, next_id)
    }

    /// Rewrite the store from the live queue, unconditionally. The
    /// migration's one-way write, and what "Save queue" means for the
    /// queue half.
    pub fn queue_compact(&self) -> bool {
        let _g = Self::hold_queue_writes();
        let rows = self.queue_rows();
        let next_id = self.next_id.load(Ordering::Relaxed);
        let mut st = self.queue_pub.lock_ok();
        st.rewrite_fail_ms = 0;
        self.queue_rewrite_locked(&mut st, &rows, next_id)
    }

    /// Replay `.spool/queue.jsonl` into the raw records `restore_records`
    /// takes, oldest first, and prime the publish cache from what the
    /// file already says.
    ///
    /// Last line wins per nzo_id; tombstones remove; `{"next_id": N}`
    /// control lines contribute their MAX; a torn or garbled line is
    /// skipped (the crash window is the file's own tail, and one lost
    /// append is the worst case the format permits). Order is
    /// first-APPEND order per id - an upsert refreshes a record's
    /// contents, not its place in the queue - which is exactly the order
    /// the publish maintains.
    pub fn queue_replay(&self) -> (Vec<Value>, Option<u64>) {
        let path = self.queue_store_path();
        let Ok(raw) = std::fs::read(&path) else {
            return (Vec::new(), None);
        };
        let replayed = replay_bytes(&raw);
        let mut records: Vec<Value> = Vec::with_capacity(replayed.rows.len());
        let mut st = self.queue_pub.lock_ok();
        st.published.clear();
        st.order.clear();
        for (id, v, h) in replayed.rows {
            // Primed from the STORED line, not from what `job_json` would
            // make of the RESTORED record: the two differ wherever a
            // restore normalises (a Downloading row comes back Queued),
            // and the first publish after start is then the one line that
            // says so. Priming from the restored form instead would cost
            // an O(N) re-serialize on the startup critical path to assert
            // a disk state that is not what is on disk.
            st.published.insert(id.clone(), h);
            st.order.push(id);
            records.push(v);
        }
        st.lines = replayed.lines;
        st.next_id = replayed.next_id.unwrap_or(0);
        (records, replayed.next_id)
    }
}

/// What one pass over a `queue.jsonl` found.
pub struct Replayed {
    /// Live records in first-APPEND order, each with the hash of the
    /// line that published it.
    pub rows: Vec<(String, Value, u64)>,
    /// The highest `next_id` any control line carried.
    pub next_id: Option<u64>,
    /// Lines read, live and dead, for the compaction rule.
    pub lines: usize,
}

/// Replay a `queue.jsonl`'s BYTES. A free function so a test can read a
/// store without disturbing a live daemon's publish cache, and so the
/// tolerance rules below have one home.
///
/// Bytes rather than a `&str`: `read_to_string` rejects the whole file on
/// one invalid UTF-8 byte, and a crash mid-append can tear the tail
/// through the middle of a multi-byte character - a foreign-language
/// release name is all it takes. On the history side that turned a
/// recoverable one-line loss into a permanently empty store; here it
/// would be the whole QUEUE.
pub fn replay_bytes(raw: &[u8]) -> Replayed {
    let mut order: Vec<Option<String>> = Vec::new();
    let mut live: HashMap<String, (usize, Value, u64)> = HashMap::new();
    let mut next_id: Option<u64> = None;
    let mut lines = 0usize;
    for chunk in raw.split(|b| *b == b'\n') {
        let Ok(line) = std::str::from_utf8(chunk) else {
            warn!(target: "queue", "queue store: skipping a line with invalid UTF-8");
            continue;
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        lines += 1;
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            // A torn tail parses as garbage exactly once; anything
            // mid-file was fsync'd whole, so noise here is worth a line
            // in the log.
            warn!(target: "queue", "queue store: skipping an unreadable line");
            continue;
        };
        if let Some(n) = v.get("next_id").and_then(Value::as_u64) {
            next_id = Some(next_id.map_or(n, |cur: u64| cur.max(n)));
            continue;
        }
        let Some(id) = v.get("nzo_id").and_then(Value::as_str).map(str::to_string) else {
            continue;
        };
        if v.get("deleted").and_then(Value::as_bool).unwrap_or(false) {
            // Punching a hole through the stored index rather than
            // `retain`ing the id out of a Vec: O(1) per delete, so a
            // delete-heavy store does not make replay quadratic
            // (histstore's own lesson, at tens of seconds per start).
            if let Some((slot, _, _)) = live.remove(&id) {
                order[slot] = None;
            }
            continue;
        }
        let h = line_hash(line);
        match live.get_mut(&id) {
            Some((_, held, hh)) => {
                *held = v;
                *hh = h;
            }
            None => {
                order.push(Some(id.clone()));
                live.insert(id, (order.len() - 1, v, h));
            }
        }
    }
    let rows: Vec<(String, Value, u64)> = order
        .into_iter()
        .flatten()
        .filter_map(|id| live.remove(&id).map(|(_, v, h)| (id, v, h)))
        .collect();
    Replayed {
        rows,
        next_id,
        lines,
    }
}

#[cfg(test)]
mod queue_store_tests {
    use super::*;
    use crate::testutil::{stored_queue, test_daemon};

    /// One real, parseable NZB, for the tests that go through
    /// `enqueue` rather than building a `Job` by hand.
    const ROLLBACK_NZB: &str = r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb"><file poster="x" date="0" subject="&quot;a.bin&quot; yEnc (1/1)"><groups><group>g</group></groups><segments><segment bytes="1000" number="1">one@x</segment></segments></file></nzb>"#;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("nzbfast-qstore-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A queued row with the fields `job_from_json` insists on.
    fn row(d: &Arc<Daemon>, id: &str) -> Arc<Mutex<Job>> {
        let v = json!({
            "nzo_id": id,
            "name": format!("{id}.Release"),
            "nzb_path": d.spool.join(format!("{id}.nzb")).to_string_lossy(),
            "out_dir": format!("/tmp/out/{id}"),
            "state": "Queued",
        });
        Arc::new(Mutex::new(job_from_json(&v).expect("job")))
    }

    fn ids(v: &[Value]) -> Vec<String> {
        v.iter()
            .filter_map(|j| j.get("nzo_id").and_then(Value::as_str).map(str::to_string))
            .collect()
    }

    /// THE acceptance case: a kill mid-append costs the line being
    /// written and nothing behind it - so the job the watch poller was
    /// told was accepted, and whose original `.nzb` it deleted on the
    /// strength of that, is still there.
    ///
    /// The guarantee `save_queue` carries is durable-BEFORE-return
    /// (`Enqueued::durable`, the 27 Aug C09 fix), and the append-only
    /// store keeps it by making the durable path one line plus its fsync
    /// rather than a whole-file rewrite. What a crash may take is only
    /// the append that had not returned yet.
    #[test]
    fn a_kill_mid_append_costs_the_torn_line_and_keeps_the_accepted_job() {
        let dir = tmp("torn");
        let d = test_daemon(&dir);
        d.queue.lock_ok().push_back(row(&d, "accepted"));
        assert!(d.save_queue(), "the accepted job must be durable on return");

        // The crash: a second add's line, fsync'd only part way - and
        // torn through the middle of a multi-byte character, which is
        // what a foreign-language release name makes of any tear.
        let path = d.queue_store_path();
        let mut raw = std::fs::read(&path).unwrap();
        raw.extend_from_slice(br#"{"nzo_id":"halfway","state":"Queued","name":"Tor"#);
        raw.push(0xC3);
        std::fs::write(&path, &raw).unwrap();

        let d2 = test_daemon(&dir);
        d2.load_queue();
        let back: Vec<String> = d2
            .queue
            .lock_ok()
            .iter()
            .map(|j| j.lock_ok().nzo_id.clone())
            .collect();
        assert_eq!(
            back,
            ["accepted"],
            "the torn tail took the accepted job with it"
        );

        // ...and the first append after the tear is still there at the
        // restart after that: it must start a fresh line rather than
        // weld itself onto the torn bytes (history's F-03, which would
        // cost the QUEUE a job rather than a history row).
        d2.queue.lock_ok().push_back(row(&d2, "after-crash"));
        assert!(d2.save_queue());
        let d3 = test_daemon(&dir);
        d3.load_queue();
        let back: Vec<String> = d3
            .queue
            .lock_ok()
            .iter()
            .map(|j| j.lock_ok().nzo_id.clone())
            .collect();
        assert_eq!(back, ["accepted", "after-crash"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The point of the whole item: a mutation on a wide queue costs ONE
    /// appended line, not a rewrite of every row.
    ///
    /// Asserted on the FILE rather than on a clock, so it is a statement
    /// about the format that holds on any box under any load. Round 37
    /// measured what the rewrite cost in seconds; this is what stops it
    /// coming back.
    #[test]
    fn a_mutation_on_a_wide_queue_appends_one_line() {
        let dir = tmp("onel");
        let d = test_daemon(&dir);
        for i in 0..200 {
            d.queue.lock_ok().push_back(row(&d, &format!("j{i:03}")));
        }
        assert!(d.save_queue());
        let path = d.queue_store_path();
        let before = std::fs::metadata(&path).unwrap().len();
        let lines_before = std::fs::read_to_string(&path).unwrap().lines().count();

        // One row pauses. Every one of the 42 call sites says exactly
        // this much - "something changed, persist the queue" - and the
        // store works out that it was one row.
        d.queue.lock_ok()[7].lock_ok().paused = true;
        assert!(d.save_queue());

        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            after.lines().count(),
            lines_before + 1,
            "a one-row change rewrote the queue instead of appending to it"
        );
        let grew = std::fs::metadata(&path).unwrap().len() - before;
        assert!(
            grew < before / 10,
            "one mutation cost {grew} bytes against a {before}-byte store"
        );
        // ...and last-line-wins means the pause is what comes back.
        let back = stored_queue(&d);
        assert_eq!(ids(&back).len(), 200, "a row went missing");
        assert_eq!(back[7]["paused"], json!(true));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A removed row is tombstoned and stays gone across a restart, and
    /// the rows that stay keep their order.
    #[test]
    fn a_removed_row_is_tombstoned_and_stays_gone() {
        let dir = tmp("tomb");
        let d = test_daemon(&dir);
        for id in ["a", "b", "c"] {
            d.queue.lock_ok().push_back(row(&d, id));
        }
        assert!(d.save_queue());
        d.queue.lock_ok().retain(|j| j.lock_ok().nzo_id != "b");
        assert!(d.save_queue());
        assert_eq!(ids(&stored_queue(&d)), ["a", "c"]);

        let d2 = test_daemon(&dir);
        d2.load_queue();
        let back: Vec<String> = d2
            .queue
            .lock_ok()
            .iter()
            .map(|j| j.lock_ok().nzo_id.clone())
            .collect();
        assert_eq!(back, ["a", "c"], "a tombstoned row came back");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Queue ORDER is part of the record, and the one change an append
    /// cannot say. A row moved to the front is published by the REWRITE,
    /// and the order survives the restart.
    ///
    /// History is a set and could ignore this; the queue is a sequence -
    /// `pick_job` reads it in order - so a store that only ever appended
    /// would quietly serve the old order back after every restart.
    #[test]
    fn a_reorder_the_append_cannot_say_is_published_whole() {
        let dir = tmp("order");
        let d = test_daemon(&dir);
        for id in ["a", "b", "c"] {
            d.queue.lock_ok().push_back(row(&d, id));
        }
        assert!(d.save_queue());
        {
            let mut q = d.queue.lock_ok();
            let last = q.pop_back().expect("c");
            q.push_front(last);
        }
        assert!(d.save_queue());
        assert_eq!(ids(&stored_queue(&d)), ["c", "a", "b"]);

        let d2 = test_daemon(&dir);
        d2.load_queue();
        let back: Vec<String> = d2
            .queue
            .lock_ok()
            .iter()
            .map(|j| j.lock_ok().nzo_id.clone())
            .collect();
        assert_eq!(back, ["c", "a", "b"], "the restart served the old order");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A legacy `queue.json` - including one still carrying a `history`
    /// array, the shape §129 1a's own migration reads - moves into the
    /// store once, one way, losing nothing: the queue rows, their order,
    /// the history records and the id allocator all come across, and the
    /// snapshot is retired so the next start does not read it again.
    #[test]
    fn a_legacy_queue_json_migrates_once_and_loses_nothing() {
        let dir = tmp("migrate");
        let d = test_daemon(&dir);
        let legacy = json!({
            "next_id": 77,
            "queue": [
                { "nzo_id": "q1", "name": "One", "nzb_path": "/tmp/1.nzb",
                  "out_dir": "/tmp/o1", "state": "Queued" },
                { "nzo_id": "q2", "name": "Two", "nzb_path": "/tmp/2.nzb",
                  "out_dir": "/tmp/o2", "state": "Queued" },
            ],
            "history": [
                { "nzo_id": "h1", "name": "Done", "nzb_path": "/tmp/3.nzb",
                  "out_dir": "/tmp/o3", "state": "Completed" },
            ],
        });
        let legacy_path = d.spool.join("queue.json");
        std::fs::write(&legacy_path, serde_json::to_string_pretty(&legacy).unwrap()).unwrap();
        d.load_queue();

        let queued: Vec<String> = d
            .queue
            .lock_ok()
            .iter()
            .map(|j| j.lock_ok().nzo_id.clone())
            .collect();
        assert_eq!(queued, ["q1", "q2"], "the queue did not survive the move");
        let hist: Vec<String> = d
            .history
            .lock_ok()
            .iter()
            .map(|j| j.lock_ok().nzo_id.clone())
            .collect();
        assert_eq!(hist, ["h1"], "the legacy history array was dropped");
        assert!(
            d.next_id.load(Ordering::Relaxed) >= 77,
            "the id allocator fell back behind the snapshot"
        );
        assert!(
            !legacy_path.exists(),
            "the legacy snapshot is still there for the next start to re-read"
        );
        assert!(
            d.spool.join("queue.json.premigrate").exists(),
            "the legacy snapshot was deleted rather than retired"
        );
        assert_eq!(ids(&stored_queue(&d)), ["q1", "q2"]);

        // ...and the SECOND start reads the store, not the snapshot.
        let d2 = test_daemon(&dir);
        d2.load_queue();
        let queued: Vec<String> = d2
            .queue
            .lock_ok()
            .iter()
            .map(|j| j.lock_ok().nzo_id.clone())
            .collect();
        assert_eq!(queued, ["q1", "q2"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// THE ROLLBACK CASE, measured 3 Sep 2026 and held here: an older
    /// nzbfast booting on a spool this build wrote does NOT come up with
    /// an empty queue.
    ///
    /// A binary from before the store (built at `d2d57c079`, the commit
    /// before §7a) reads `queue.json` and knows nothing about
    /// `queue.jsonl`, so on a store-only spool its `load_queue` takes the
    /// early return and restores history alone. What puts the queue back
    /// is `recover_orphaned_spool`, which adopts every spooled `.nzb` no
    /// live row names - and that is the shape asserted here, because a
    /// test cannot run an old binary but it can put a daemon in exactly
    /// the position one is in: no `queue.json`, and the store out of
    /// reach.
    ///
    /// Against the real old binary this recovered all three queued jobs
    /// under their own ids, in order, with their categories, and left
    /// history untouched with nothing downloaded twice. What it did NOT
    /// keep is a job's PRIORITY and its PAUSED flag - `recover_orphaned_spool`
    /// re-adds at the default priority, unpaused - and those two losses
    /// are asserted as well, so this reads as the record of what a
    /// rollback costs rather than as a claim that it costs nothing.
    #[test]
    fn an_older_binary_that_cannot_see_the_store_recovers_the_queue_from_the_spool() {
        let dir = tmp("rollback");
        let d = test_daemon(&dir);
        let mut added = Vec::new();
        for (i, cat) in ["tv", "movies", "tv"].iter().enumerate() {
            // Distinct message-ids per release, or the second add is
            // held as an ALTERNATIVE of the first rather than queued.
            let bytes = ROLLBACK_NZB.replace("one@x", &format!("m{i}@x"));
            let e = d
                .enqueue(
                    bytes.as_bytes(),
                    &format!("Rollback.Release.S01E0{}", i + 1),
                    cat,
                    SAB_DEFAULT_PRIORITY,
                    None,
                    None,
                    "test",
                    false,
                )
                .expect("enqueue");
            added.push(e.nzo_id);
        }
        // The two fields the recovery cannot carry, set here so their
        // loss is measured rather than assumed.
        {
            let q = d.queue.lock_ok();
            let mut g = q[1].lock_ok();
            g.paused = true;
            g.priority = 1;
        }
        assert!(d.save_queue());
        assert_eq!(ids(&stored_queue(&d)), added, "the store did not take them");

        // The older binary's view: `queue.jsonl` is a file it never
        // opens, and there is no `queue.json` for it to read.
        let store = d.queue_store_path();
        std::fs::rename(&store, dir.join("queue.jsonl.hidden")).expect("hide the store");
        assert!(
            !d.spool.join("queue.json").exists(),
            "the fixture must not leave a snapshot the old binary could read"
        );

        let old = test_daemon(&dir);
        old.load_queue();
        assert!(
            old.queue.lock_ok().is_empty(),
            "the store must be invisible to a build that does not know it"
        );
        assert_eq!(
            old.recover_orphaned_spool(),
            3,
            "the queue did not come back"
        );

        let back: Vec<String> = old
            .queue
            .lock_ok()
            .iter()
            .map(|j| j.lock_ok().nzo_id.clone())
            .collect();
        assert_eq!(
            back, added,
            "ids or queue order did not survive the rollback"
        );
        let cats: Vec<String> = old
            .queue
            .lock_ok()
            .iter()
            .map(|j| j.lock_ok().category.clone())
            .collect();
        assert_eq!(
            cats,
            ["tv", "movies", "tv"],
            "the category sidecar did not come back with the job"
        );
        // ...and what it costs, stated.
        let (paused, prio) = {
            let q = old.queue.lock_ok();
            let g = q[1].lock_ok();
            (g.paused, g.priority)
        };
        assert!(!paused, "recovery is documented as losing the paused flag");
        // 0 is Normal, the priority `SAB_DEFAULT_PRIORITY` resolves to
        // for an add that expresses no preference - not the High this row
        // carried into the store.
        assert_eq!(prio, 0, "recovery is documented as losing the priority");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A ROLLED-BACK session's `queue.json` is adopted on the way
    /// forward, rather than thrown away for the store's stale copy.
    ///
    /// An older build writes `queue.json` beside a `queue.jsonl` it
    /// cannot see, so rolling forward used to revert the queue to the
    /// instant of the migration: measured 3 Sep 2026, a release deleted
    /// while rolled back came back, and one added while rolled back was
    /// gone. The snapshot is NEWER than the store here, which is the one
    /// thing that separates that session from the torn migration the
    /// store-wins rule exists for.
    #[test]
    fn a_snapshot_written_after_the_store_is_an_older_build_and_is_adopted() {
        let dir = tmp("rollfwd");
        let d = test_daemon(&dir);
        for id in ["stale-a", "stale-b"] {
            d.queue.lock_ok().push_back(row(&d, id));
        }
        assert!(d.save_queue());

        // What the rolled-back session left: a snapshot naming a
        // different queue, written after the store stopped moving.
        let snapshot = d.spool.join("queue.json");
        std::fs::write(
            &snapshot,
            serde_json::to_string_pretty(&json!({
                "next_id": 4242,
                "queue": [
                    { "nzo_id": "kept", "name": "Kept", "nzb_path": "/tmp/k.nzb",
                      "out_dir": "/tmp/ok", "state": "Queued" },
                    { "nzo_id": "added-while-back", "name": "Added",
                      "nzb_path": "/tmp/a.nzb", "out_dir": "/tmp/oa", "state": "Queued" },
                ],
            }))
            .unwrap(),
        )
        .unwrap();
        let later = std::fs::metadata(d.queue_store_path())
            .and_then(|m| m.modified())
            .unwrap()
            + std::time::Duration::from_secs(60);
        std::fs::File::options()
            .write(true)
            .open(&snapshot)
            .unwrap()
            .set_modified(later)
            .unwrap();

        let fwd = test_daemon(&dir);
        fwd.load_queue();
        let back: Vec<String> = fwd
            .queue
            .lock_ok()
            .iter()
            .map(|j| j.lock_ok().nzo_id.clone())
            .collect();
        assert_eq!(
            back,
            ["kept", "added-while-back"],
            "the rolled-back session's queue was discarded for the stale store"
        );
        assert!(
            fwd.next_id.load(Ordering::Relaxed) >= 4242,
            "the allocator fell back behind the session that just ran"
        );
        // ...and it is a migration like any other: the store now says the
        // same thing, and the snapshot is retired rather than left to be
        // read a second time.
        assert_eq!(ids(&stored_queue(&fwd)), ["kept", "added-while-back"]);
        assert!(
            !snapshot.exists(),
            "the snapshot was left for the next start"
        );
        assert!(d.spool.join("queue.json.premigrate").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// ...and the case the store-wins rule was written for is UNCHANGED:
    /// a snapshot the migration's own crash left behind is older than the
    /// store that superseded it, and is still ignored.
    #[test]
    fn a_snapshot_older_than_the_store_is_still_ignored() {
        let dir = tmp("tornmig");
        let d = test_daemon(&dir);
        d.queue.lock_ok().push_back(row(&d, "live"));
        assert!(d.save_queue());
        let snapshot = d.spool.join("queue.json");
        std::fs::write(
            &snapshot,
            serde_json::to_string_pretty(&json!({
                "next_id": 9,
                "queue": [
                    { "nzo_id": "superseded", "name": "Old", "nzb_path": "/tmp/s.nzb",
                      "out_dir": "/tmp/os", "state": "Queued" },
                ],
            }))
            .unwrap(),
        )
        .unwrap();
        let earlier = std::fs::metadata(d.queue_store_path())
            .and_then(|m| m.modified())
            .unwrap()
            - std::time::Duration::from_secs(60);
        std::fs::File::options()
            .write(true)
            .open(&snapshot)
            .unwrap()
            .set_modified(earlier)
            .unwrap();

        let d2 = test_daemon(&dir);
        d2.load_queue();
        let back: Vec<String> = d2
            .queue
            .lock_ok()
            .iter()
            .map(|j| j.lock_ok().nzo_id.clone())
            .collect();
        assert_eq!(back, ["live"], "a superseded snapshot was re-merged");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The migration's two leftovers: `recover_orphaned_spool` must never
    /// mistake either for an adoptable NZB, and both are swept once they
    /// are older than the keep window.
    ///
    /// The `.bak` is in this test because it is not incidental - it is a
    /// byte-identical second copy of the retired snapshot that
    /// `load_json_with_backup` leaves behind, and it is what an older
    /// binary actually recovers from. Sweeping one without the other is
    /// the outcome `sweep_retired_snapshots` exists to prevent.
    #[test]
    fn the_retired_snapshots_are_never_adopted_and_are_swept_when_old() {
        let dir = tmp("retired");
        let d = test_daemon(&dir);
        d.queue.lock_ok().push_back(row(&d, "a"));
        assert!(d.save_queue());
        let pre = d.spool.join("queue.json.premigrate");
        let bak = d.spool.join("queue.json.bak");
        std::fs::write(&pre, r#"{"queue":[],"next_id":1}"#).unwrap();
        std::fs::write(&bak, r#"{"queue":[],"next_id":1}"#).unwrap();

        // Neither is an NZB, whatever else happens to them.
        assert_eq!(d.recover_orphaned_spool(), 0, "a snapshot was adopted");
        assert!(pre.exists() && bak.exists(), "recovery removed a snapshot");

        // Fresh, so the sweep leaves them: a rollback the day after the
        // upgrade is the case they exist for.
        d.load_queue();
        assert!(
            pre.exists() && bak.exists(),
            "the copies were swept while they were still the rollback path"
        );

        // Older than the window, on both, and they go.
        let old = std::time::SystemTime::now()
            - std::time::Duration::from_secs((Daemon::RETIRED_SNAPSHOT_KEEP_DAYS + 1) * 86_400);
        for p in [&pre, &bak] {
            let f = std::fs::File::options().write(true).open(p).unwrap();
            f.set_modified(old).unwrap();
        }
        let d2 = test_daemon(&dir);
        d2.load_queue();
        assert!(!pre.exists(), "the retired snapshot was kept forever");
        assert!(!bak.exists(), "the .bak half of the pair was left behind");
        // ...and the store itself is untouched by the sweep.
        assert_eq!(ids(&stored_queue(&d2)), ["a"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A store the APPEND cannot reach is rescued by the rewrite, and
    /// the save still lands.
    ///
    /// The asymmetry is real and is why the queue kept a rewrite path:
    /// an append needs write permission ON THE FILE, `write_atomic`
    /// needs only the DIRECTORY. A `queue.jsonl` left 0444 - one `sudo
    /// nzbfast` is enough to arrive at that - would otherwise refuse
    /// every queue write for the life of the process, which is P2-1 on
    /// the history side. A real permission fault rather than a seam,
    /// because the fault the rescue exists for is a permission one.
    #[cfg(unix)]
    #[test]
    fn a_store_the_append_cannot_reach_is_rescued_by_the_rewrite() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("rescue");
        let d = test_daemon(&dir);
        d.queue.lock_ok().push_back(row(&d, "a"));
        assert!(d.save_queue());
        let path = d.queue_store_path();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();

        d.queue.lock_ok().push_back(row(&d, "b"));
        assert!(
            d.save_queue(),
            "an unappendable store must be replaced by one this daemon owns"
        );
        assert_eq!(ids(&stored_queue(&d)), ["a", "b"]);
        // The replacement is a file the daemon owns, so the next append
        // works too - which is the whole point of the rescue.
        d.queue.lock_ok().push_back(row(&d, "c"));
        assert!(d.save_queue());
        assert_eq!(ids(&stored_queue(&d)), ["a", "b", "c"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The O(1) add path publishes durably, keeps append order, and is
    /// still a correct statement about disk when the row it names is not
    /// the only thing that changed.
    ///
    /// The last clause is the one worth a test: `save_queue_row` is safe
    /// TODAY because `enqueue` mutates only the job it adds, and the
    /// three guards in its doc comment are what keep it safe if that ever
    /// stops being true. Here, a row is mutated behind the store's back
    /// and the add path publishes a different one - the next full save
    /// must still catch it.
    #[test]
    fn a_row_publish_is_o1_and_the_next_full_save_catches_what_it_missed() {
        let dir = tmp("rowpub");
        let d = test_daemon(&dir);
        for i in 0..120 {
            d.queue.lock_ok().push_back(row(&d, &format!("j{i:03}")));
        }
        assert!(d.save_queue());
        let path = d.queue_store_path();
        let lines_before = std::fs::read_to_string(&path).unwrap().lines().count();

        // A row changes with NO save of its own...
        d.queue.lock_ok()[3].lock_ok().paused = true;
        // ...and the add path publishes only the row it added.
        let fresh = row(&d, "added-last");
        d.queue.lock_ok().push_back(fresh.clone());
        assert!(
            d.save_queue_row(&fresh),
            "the add must be durable on return"
        );
        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            after.lines().count(),
            lines_before + 1,
            "the row publish wrote more than the row"
        );
        let stored = stored_queue(&d);
        assert_eq!(stored.len(), 121);
        assert_eq!(stored[120]["nzo_id"], json!("added-last"), "append order");
        assert_eq!(
            stored[3]["paused"],
            json!(false),
            "the row publish is not supposed to have found this yet"
        );

        // The next FULL save is what finds it - the cache is a statement
        // about disk, not about the call that wrote last.
        assert!(d.save_queue());
        assert_eq!(stored_queue(&d)[3]["paused"], json!(true));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An ADD after a FAILED save re-publishes the whole queue instead
    /// of appending its one row and calling the store durable.
    ///
    /// This is the fourth of `save_queue_row`'s guards and the only one
    /// that is not about `enqueue`. The first three all end "the next
    /// full `save_queue` catches it" - but nothing schedules one, the
    /// saver task is wake-driven, so the next mutation IS the next save
    /// and an add comes back through this path. Appending there would
    /// land the added row, clear `save_failed_at`, and take the
    /// dashboard's "The queue could not be saved at ..." warning down
    /// while the pause the failed save was carrying is still only in
    /// memory. A crash then replays the row UNPAUSED with nothing having
    /// said so - queue state silently rolled back behind a clean UI.
    ///
    /// Both write paths are refused the way a permission fault refuses
    /// them - the append by file mode (the P2-1 shape), the rescue by
    /// the rewrite seam - and then BOTH are healed, so an append would
    /// succeed if the flag were not read.
    #[cfg(unix)]
    #[test]
    fn an_add_after_a_failed_save_republishes_instead_of_clearing_the_failure() {
        use crate::storecut::{Store, arm_store_cut, disarm};
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("failthenadd");
        let d = test_daemon(&dir);
        d.queue.lock_ok().push_back(row(&d, "paused-one"));
        assert!(d.save_queue());
        let path = d.queue_store_path();

        // The pause the store never gets to hear about.
        d.queue.lock_ok()[0].lock_ok().paused = true;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        arm_store_cut(&[Store::QueueRewrite]);
        assert!(!d.save_queue(), "both write paths were refused");
        assert_ne!(
            d.save_failed_at.load(Ordering::Relaxed),
            0,
            "a refused save must be on the record"
        );
        disarm();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        // The add. An append alone would succeed now, and that is
        // exactly what must NOT happen.
        let fresh = row(&d, "added-after");
        d.queue.lock_ok().push_back(fresh.clone());
        assert!(
            d.save_queue_row(&fresh),
            "the add must be durable on return"
        );
        assert_eq!(
            d.save_failed_at.load(Ordering::Relaxed),
            0,
            "the whole queue landed, so the warning is over"
        );

        // ...and it landed the STALE row too, which is the point.
        let stored = stored_queue(&d);
        assert_eq!(ids(&stored), ["paused-one", "added-after"]);
        assert_eq!(
            stored[0]["paused"],
            json!(true),
            "the pause the failed save was carrying is still only in memory"
        );

        // The end state a crash would read.
        let d2 = test_daemon(&dir);
        d2.load_queue();
        let back: Vec<(String, bool)> = d2
            .queue
            .lock_ok()
            .iter()
            .map(|j| {
                let g = j.lock_ok();
                (g.nzo_id.clone(), g.paused)
            })
            .collect();
        assert_eq!(
            back,
            [
                ("paused-one".to_string(), true),
                ("added-after".to_string(), false)
            ],
            "a restart must not silently unpause the row"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// ...and when the re-publish ALSO fails, the flag stays set and the
    /// add says it is not durable - the half that stops the fix from
    /// being "clear it later instead of now".
    #[cfg(unix)]
    #[test]
    fn an_add_that_cannot_republish_keeps_the_failure_and_is_not_durable() {
        use crate::storecut::{Store, arm_store_cut, disarm};
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("failthenaddfail");
        let d = test_daemon(&dir);
        d.queue.lock_ok().push_back(row(&d, "paused-one"));
        assert!(d.save_queue());
        let path = d.queue_store_path();

        d.queue.lock_ok()[0].lock_ok().paused = true;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        arm_store_cut(&[Store::QueueRewrite]);
        assert!(!d.save_queue());

        // The store is still refusing when the add arrives.
        let fresh = row(&d, "added-after");
        d.queue.lock_ok().push_back(fresh.clone());
        assert!(
            !d.save_queue_row(&fresh),
            "an add onto an unwritable store is not durable and must say so"
        );
        assert_ne!(
            d.save_failed_at.load(Ordering::Relaxed),
            0,
            "the warning must still be up"
        );
        disarm();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A row published somewhere other than the back leaves the store's
    /// implied order disagreeing with the live queue, and the next full
    /// publish reads that as a reorder and rewrites - the second of
    /// `save_queue_row`'s three guards.
    #[test]
    fn a_row_published_out_of_place_is_repaired_by_the_next_full_save() {
        let dir = tmp("roword");
        let d = test_daemon(&dir);
        for id in ["a", "b"] {
            d.queue.lock_ok().push_back(row(&d, id));
        }
        assert!(d.save_queue());
        let fresh = row(&d, "c");
        d.queue.lock_ok().push_front(fresh.clone());
        assert!(d.save_queue_row(&fresh));
        // The append could only say "at the back", and did.
        assert_eq!(ids(&stored_queue(&d)), ["a", "b", "c"]);
        assert!(d.save_queue());
        assert_eq!(ids(&stored_queue(&d)), ["c", "a", "b"]);
        let d2 = test_daemon(&dir);
        d2.load_queue();
        let back: Vec<String> = d2
            .queue
            .lock_ok()
            .iter()
            .map(|j| j.lock_ok().nzo_id.clone())
            .collect();
        assert_eq!(back, ["c", "a", "b"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The store is daemon-private from the moment it is created.
    ///
    /// An append CREATES the file, and creation under the ordinary 022
    /// umask lands 0644 - world-readable for the life of the store,
    /// since compaction (which goes through `write_atomic`'s private
    /// path) may not run for weeks. A queue row serializes the job's
    /// archive password and its local paths. Histstore's own lesson,
    /// asserted here before it can be relearned.
    #[cfg(unix)]
    #[test]
    fn a_fresh_queue_store_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("mode");
        let d = test_daemon(&dir);
        d.queue.lock_ok().push_back(row(&d, "a"));
        assert!(d.save_queue());
        let mode = std::fs::metadata(d.queue_store_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the queue store is readable by other users");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Dead lines do not accumulate for ever: once more than half the
    /// store is superseded, the next publish compacts it to one line per
    /// live record.
    #[test]
    fn a_store_that_is_mostly_dead_lines_compacts() {
        let dir = tmp("compact");
        let d = test_daemon(&dir);
        for id in ["a", "b", "c"] {
            d.queue.lock_ok().push_back(row(&d, id));
        }
        assert!(d.save_queue());
        for i in 0..100 {
            d.queue.lock_ok()[0].lock_ok().retries = i;
            assert!(d.save_queue());
        }
        let lines = std::fs::read_to_string(d.queue_store_path())
            .unwrap()
            .lines()
            .count();
        // The rule has histstore's floor - a store under 64 lines is
        // not worth rewriting, whatever fraction of it is dead - so the
        // ceiling here is that floor rather than the 4 live lines.
        assert!(
            lines <= 64,
            "100 mutations of one row left {lines} lines on disk"
        );
        assert_eq!(ids(&stored_queue(&d)), ["a", "b", "c"]);
        assert_eq!(stored_queue(&d)[0]["retries"], json!(99));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
