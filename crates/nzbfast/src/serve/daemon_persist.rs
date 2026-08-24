//! The queue on disk: `.spool/queue.json` out and back again (TODO 106
//! code motion out of daemon.rs).
//!
//! One subject in two halves - `save_queue` serializes queue + history
//! under its own IO lock, `load_queue` restores them at startup and
//! re-floors the id counter so a restored record can never have its id
//! handed out twice.
//!
//! A second `impl Daemon` in a child module of `daemon`, on the
//! daemon_index shape, for the same reasons as daemon_retry.rs -
//! including `pub(super)` becoming `pub(in crate::serve)`.

use super::*;

impl Daemon {
    /// The lock every `queue.json` write serializes on, held from outside
    /// [`Daemon::save_queue`] by a caller that must not let ANY save land
    /// in the middle of what it is doing.
    ///
    /// The one such caller is a delete verb removing an ACTIVE job. The row
    /// leaves the queue under the queue lock, and the durable history
    /// placeholder that replaces it (`delete_prewrite`, and the immediate
    /// filing for the non-active arm) is a file write, which has no
    /// business under that mutex - so it happens after the lock drops. A
    /// save landing in that gap publishes a queue.json the record has
    /// already left while nothing in history names it yet, and a stop right
    /// there loses it from BOTH stores: no DELETED row for the dupe check
    /// or the retry button, and under `GroupParkDelete` - whose whole
    /// contract is "files KEPT" - a full payload on disk that nothing names
    /// (read-only sweep 2, M8).
    ///
    /// Holding this across the two is what orders them durably without
    /// putting a file write under the queue lock. Order is IO then queue,
    /// the same order `save_queue` itself takes them in.
    pub(in crate::serve) fn hold_queue_writes() -> std::sync::MutexGuard<'static, ()> {
        static IO: std::sync::Mutex<()> = std::sync::Mutex::new(());
        IO.lock_ok()
    }

    /// Persist queue + history to `.spool/queue.json` so a daemon restart
    /// doesn't forget the job list. Only the record is at stake: the NZB
    /// itself already lives in the spool, and each out_dir's article
    /// journal makes a resumed download fetch only what's still missing.
    /// Called after every mutation, once the queue/history locks are
    /// released. Best-effort like save_setting: a failed write must never
    /// take down a live daemon.
    ///
    /// Returns whether the record actually landed. Almost every caller is
    /// right to ignore that - the job is live in memory either way. The watch
    /// poller is not: it deletes the user's original .nzb once the job is
    /// accepted, so it needs to know the acceptance survived a restart.
    pub(in crate::serve) fn save_queue(&self) -> bool {
        // §158 item 7: the harness's kill-here seam. Before the lock, so a
        // dropped write holds nothing up.
        #[cfg(test)]
        if super::storecut::cut_here() {
            return false;
        }
        // API requests run on a worker pool - serialize the writes so two
        // mutations can't interleave bytes in the file. Take the IO lock
        // BEFORE snapshotting: if the snapshot were built first, a slow
        // encoder (T1) could grab the lock after a later mutation (T2)
        // already wrote its fresher snapshot, then overwrite it with stale
        // state and lose T2's change across restart. Snapshotting under the
        // lock makes the last writer also the one holding the newest state.
        let _g = Self::hold_queue_writes();
        // Snapshot the queue's MEMBERSHIP under the queue lock (Arc
        // clones, O(N) pointer bumps), then serialize each job after it
        // is released. Serializing under the queue lock held it across
        // 14,500 job locks and JSON builds - seconds at issue #38's
        // queue size, and every API request queues behind it. The
        // ordering argument above still holds: both steps happen under
        // the IO lock, so the last writer snapshots the newest state. A
        // job that leaves the queue between the two steps is written one
        // extra time; its own mutation site calls save_queue after the
        // change and rewrites the file behind us.
        let snapshot: Vec<Arc<Mutex<Job>>> = self.queue.lock_ok().iter().cloned().collect();
        let jobs: Vec<Value> = snapshot.iter().map(|j| job_json(&j.lock_ok())).collect();
        // §129 1a: history is NOT here any more. It lives in its own
        // append-only store (`histstore.rs`), written by the sites that
        // actually change it - park, delete, retry, recategorize, the
        // unlock/mover bookkeeping - so an unlimited history stops
        // costing every queue mutation an O(all-time) rewrite.
        let v = json!({
            "next_id": self.next_id.load(Ordering::Relaxed),
            "queue": jobs,
        });
        // The dashboard's change handle, bumped WITH the write: a queue
        // change that should survive restart comes through here, so the
        // revision sees it by construction.
        self.queue_rev.fetch_add(1, Ordering::Relaxed);
        let path = self.spool.join("queue.json");
        match serde_json::to_string_pretty(&v) {
            Ok(text) => match crate::persist::write_atomic(&path, text.as_bytes()) {
                Ok(()) => true,
                Err(e) => {
                    error!(target: "queue", "persist {}: {e}", path.display());
                    false
                }
            },
            Err(e) => {
                error!(target: "queue", "serialize: {e}");
                false
            }
        }
    }

    /// Coalesced [`save_queue`](Self::save_queue) for the per-completion
    /// hot path (issue #38 follow-up). Marks the queue dirty and wakes
    /// the saver task, which debounces the burst into one write - a
    /// completion used to rewrite a 14,500-job file four times over.
    ///
    /// Only for callers that never needed the write's verdict and whose
    /// crash window was already covered: the queue restores Downloading
    /// as Queued and replays the journal, and park's history move is
    /// durable in history.jsonl first with load_queue deduplicating in
    /// history's favour. Anything that needs durable-before-return (the
    /// finalize marker, the watch poller's delete) stays on the
    /// synchronous call.
    ///
    /// The revision bump is immediate so the dashboard's change handle
    /// does not inherit the debounce delay; save_queue bumps it again
    /// with the write, which is harmless (clients just refetch).
    pub(in crate::serve) fn save_queue_soon(&self) {
        if !self.saver_armed.load(Ordering::Relaxed) {
            self.save_queue();
            return;
        }
        self.queue_rev.fetch_add(1, Ordering::Relaxed);
        self.save_soon.store(true, Ordering::Release);
        self.save_wake.notify_one();
    }

    /// Reload `.spool/queue.json` at startup, re-creating the Job records.
    /// Wall-clock floor (seconds since the Unix epoch) for the RESTORED
    /// id allocator. The snapshot's `next_id` can be stale when the run
    /// that allocated past it could not persist (disk full at enqueue),
    /// and those already-issued ids carry permanent stream tokens - so
    /// a restore must never let allocation fall back behind real time.
    /// Only applied on restore: a fresh daemon with no state keeps its
    /// small ids (and has no earlier run to collide with unless
    /// persistence never worked at all, which startup now warns about).
    fn id_floor() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// A job that was Downloading when the daemon stopped comes back
    /// Queued, so the scheduler restarts it and its journal resumes the
    /// transfer.
    pub(in crate::serve) fn load_queue(&self) {
        // Before anything reads a job's out_dir: put back a download that
        // an interrupted replace left in limbo.
        recover_interrupted_publishes(&self.out_dir());
        let path = self.spool.join("queue.json");
        // A torn/corrupt file falls back to the .bak of the last good
        // parse - never "start empty" and let the next save_queue make
        // the loss permanent.
        // §129 1a: history has its own store now. Replay it FIRST so the
        // legacy-migration merge below can prefer the newer layout when
        // both name an id (a crash between the split's two writes).
        let (stored_hist, wants_compaction) = self.history_replay();
        let (v, mut legacy_hist) = match crate::persist::load_json_with_backup(&path) {
            Some(v) => {
                let legacy = v
                    .get("history")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                (Some(v), legacy)
            }
            None => (None, Vec::new()),
        };
        // Records already living in history.jsonl win over their legacy
        // queue.json copies - the split happened, then something wrote
        // history.jsonl, then the queue.json rewrite was lost.
        legacy_hist.retain(|r| {
            r.get("nzo_id")
                .and_then(Value::as_str)
                .is_none_or(|id| !stored_hist.iter().any(|j| j.nzo_id == id))
        });
        let migrating = !legacy_hist.is_empty();
        let queue_arr = v
            .as_ref()
            .and_then(|v| v.get("queue"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let (queued, from_file) = restore_records(&queue_arr, &legacy_hist);
        // `from_file` is the legacy history records plus any terminal
        // records restore_records routed OUT of the queue array
        // (interrupted post-processing). Order for the final Vec, oldest
        // first: legacy array, then the store's records, then the routed
        // ones (they finished last, mid-shutdown). A routed record whose
        // park already reached history.jsonl before the crash keeps the
        // store's copy.
        let legacy_ids: std::collections::HashSet<String> = legacy_hist
            .iter()
            .filter_map(|r| r.get("nzo_id").and_then(Value::as_str))
            .map(str::to_string)
            .collect();
        let (legacy_part, routed): (Vec<Job>, Vec<Job>) = from_file
            .into_iter()
            .partition(|j| legacy_ids.contains(&j.nzo_id));
        // A routed TERMINAL queue row vs a stored history row for the same
        // id is a torn move like any other, so the same `move_seq` rule
        // decides it - the filter here used to be id-only, which threw the
        // routed copy away whenever the store had the id. But the routed
        // copy can be the NEWER one: a retry stamps N+1, the job runs to a
        // terminal state, a save persists that terminal seq-N+1 snapshot
        // into queue.json, and the crash lands before the stale seq-N
        // history row was cleaned up. Discarding the routed copy then
        // silently reverted the whole retry - the completed run reappeared
        // as its previous failure (Codex sweep 13 Aug Q3). Ties keep the
        // store's copy, which is the pre-stamp behaviour.
        let mut superseded: std::collections::HashSet<String> = std::collections::HashSet::new();
        let routed: Vec<Job> = routed
            .into_iter()
            .filter(|j| {
                let Some(s) = stored_hist.iter().find(|s| s.nzo_id == j.nzo_id) else {
                    return true;
                };
                if moveseq::move_winner(j.move_seq, s.move_seq) == moveseq::MoveWinner::Queue {
                    warn!(
                        target: "queue",
                        "{}: a restart caught a finished retry before its history \
                         cleanup (queue seq {} > history seq {}) - keeping the \
                         newer outcome",
                        j.nzo_id,
                        j.move_seq,
                        s.move_seq
                    );
                    superseded.insert(j.nzo_id.clone());
                    true
                } else {
                    false
                }
            })
            .collect();
        let routed_any = !routed.is_empty();
        let mut history = legacy_part;
        history.extend(
            stored_hist
                .into_iter()
                .filter(|s| !superseded.contains(&s.nzo_id)),
        );
        history.extend(routed);
        // Cross-store reconciliation. A queue -> history move is two
        // independent durable writes - park appends and fsyncs the terminal
        // history row, then `save_queue` rewrites queue.json without it -
        // and a kill between them leaves the SAME nzo_id in both files. The
        // queue copy is nonterminal (Finishing), `job_wire` restores a
        // nonterminal row as Queued, and nothing deduplicated the two: the
        // job then showed as Queued AND Failed, and the queued copy
        // downloaded the whole release again (Codex sweep 12 Aug F1).
        //
        // §158 resolved every such pair in history's favour, which is
        // right for the park and quietly reverts a retry - both directions
        // tear into the same shape, so precedence cannot tell them apart.
        // `moveseq` can: each move stamps the copy it is moving TO with a
        // higher `move_seq` before writing it, so the counter names the
        // direction the last intended move was heading. See
        // `serve/moveseq.rs`; a pair that is unstamped on both sides -
        // every record written by 1.1.0 and earlier - ties, and a tie
        // keeps the §158 answer.
        //
        // `routed` above is the same rule applied to records restore_records
        // moved out of the queue array; this covers the ones it leaves in
        // it, which is the case that could still run.
        let (queued, history, split) = moveseq::reconcile_moves(queued, history);
        let (nq, nh) = (queued.len(), history.len());
        for job in queued {
            self.register_cat(&job.category);
            self.queue.lock_ok().push_back(Arc::new(Mutex::new(job)));
        }
        for job in history {
            self.register_cat(&job.category);
            self.history.lock_ok().push(Arc::new(Mutex::new(job)));
        }
        // Make the resolution DURABLE rather than re-deriving it every
        // boot. The loser is still sitting in its own store, waiting to
        // resurrect the job the moment its winner is removed: a retry
        // resolved in the queue's favour and then deleted from the queue
        // would come back as a parked failure from the stale history line
        // nothing ever tombstoned. Each store's winner is already durable
        // in it - that is why it won - so removing the loser cannot lose
        // anything, whichever of the two writes below is interrupted.
        //
        // The queue half rides on the `save_queue` further down, AFTER the
        // id allocator has been restored: writing queue.json here would
        // publish a fresh daemon's `next_id` of 1 over the snapshot's and
        // hand a later job an id that already carries a stream token. The
        // `v == None` early return below cannot have a queue half at all -
        // no queue.json means no queue array and no legacy history array,
        // so `queued` is empty and nothing could have lost to history.
        if !split.reverted.is_empty() {
            self.history_tombstone(&split.reverted);
        }
        let v = match v {
            Some(v) => v,
            None => {
                // No queue.json at all, but maybe a history store.
                if wants_compaction {
                    self.history_compact();
                }
                self.history_enforce_retention();
                if nh > 0 {
                    // A history-only restore is still a restore: those
                    // rows' ids carry permanent stream tokens, and a
                    // fresh allocator starting at 1 would re-mint them
                    // (old bearer URL authorizes the new job, and the
                    // next boot's move-sequence reconciliation can drop
                    // the new queue row as a half-written move). Same
                    // wall-clock floor as the snapshot path below.
                    let cur = self.next_id.load(Ordering::Relaxed);
                    self.next_id
                        .store(cur.max(Self::id_floor()), Ordering::Relaxed);
                    info!(target: "queue", "restored {nh} history jobs");
                }
                return;
            }
        };
        if let Some(n) = v.get("next_id").and_then(Value::as_u64) {
            // Never reuse an id - SABnzbd clients key on nzo_id uniqueness,
            // and stream tokens are H(secret, nzo_id): a reused id would
            // hand a previous job's permanent capability URL to a NEW job.
            // The persisted allocator alone cannot guarantee that (the
            // snapshot write is best-effort and an enqueue whose snapshot
            // failed already returned its id and token), so the wall-clock
            // floor below keeps allocations ahead of any earlier run's
            // even when its snapshots never landed.
            let cur = self.next_id.load(Ordering::Relaxed);
            self.next_id
                .store(n.max(cur).max(Self::id_floor()), Ordering::Relaxed);
        }
        // The one-time split, and the store's own housekeeping. Compact
        // FIRST (it writes every live record, so migrated and routed
        // rows land in history.jsonl), then rewrite queue.json without
        // its history array - in that order, so a crash between the two
        // duplicates records into both files (deduped above on the next
        // boot) rather than losing them from both.
        if migrating || routed_any || wants_compaction {
            self.history_compact();
        }
        // ...and the queue half of the resolution above, here because the
        // id allocator is restored by now. `routed_any` belongs in this
        // gate too: a routed terminal row that won under Q3 went to
        // history above, and without a queue rewrite its stale copy
        // stays in queue.json - where, after the user deletes the record
        // from history and the daemon dies uncleanly, the next boot
        // re-routes it and resurrects the deleted record (14 Aug sweep).
        if migrating || routed_any || !split.parked.is_empty() {
            self.save_queue();
        }
        if migrating {
            info!(
                target: "queue",
                "history moved out of queue.json into its own store ({} records)",
                nh
            );
        }
        self.history_enforce_retention();
        if nq + nh > 0 {
            info!(target: "queue", "restored {nq} queued + {nh} history jobs");
        }
    }

    /// Does a live queue or history row name this exact spool path?
    ///
    /// The one ownership question `recover_orphaned_spool` must ask
    /// before it unlinks anything, and it must ask it against the rows
    /// as they stand NOW: a row adopted earlier in the same pass counts.
    fn path_is_recorded(&self, p: &Path) -> bool {
        self.queue
            .lock_ok()
            .iter()
            .chain(self.history.lock_ok().iter())
            .any(|j| j.lock_ok().nzb_path == p)
    }

    /// TODO 16g / A12: adopt back into the queue every spooled .nzb that
    /// no record names. `enqueue` writes the NZB to the spool BEFORE it
    /// saves queue.json, and the save is best-effort (ENOSPC, EIO, a
    /// read-only volume), so a job accepted in a run whose saves never
    /// landed again leaves exactly one trace behind: its spool file. The
    /// watch poller keeps the user's copy in that case (since 16g's first
    /// half), but every other add path - the *arrs, the dashboard, RSS,
    /// the kept-files retry button - has no copy to keep, and their job
    /// simply vanished at the next start.
    ///
    /// Idempotent by construction, which is what makes it safe to run on
    /// every start rather than behind some "the last run was unclean"
    /// guess:
    ///
    ///  * a file named by a queue row, a history row or a kept-files
    ///    notice is not an orphan, whatever state its job is in;
    ///  * an orphan is re-adopted under the id in its OWN file name, so a
    ///    second start finds that id in the queue and skips it - and the
    ///    *arr that was handed the id still holds a valid handle;
    ///  * a file whose id IS known but whose path is not (a spool sibling
    ///    left by an older layout) is left alone rather than adopted as a
    ///    second copy;
    ///  * an orphan byte-identical to a record already held (same
    ///    `nzb_sha`) is a duplicate copy, not a lost job, and is removed
    ///    - unless a row names that very path, which is what an
    ///    adoption earlier in this same pass can have made of it.
    ///
    /// Runs after `load_queue` and after the settings restore: the
    /// categories must be loaded for §218 to infer one, because the
    /// category the job was originally added under is not recoverable -
    /// it lived only in the record that was lost. The duplicate hold
    /// applies as it would to any add: a release the user re-added under
    /// another NZB while this one was unrecorded comes back as an
    /// ALTERNATIVE behind it, not as a second download. Returns how many
    /// were adopted.
    pub(in crate::serve) fn recover_orphaned_spool(&self) -> usize {
        use std::collections::HashSet;
        let Ok(rd) = std::fs::read_dir(&self.spool) else {
            return 0;
        };
        let mut named: HashSet<std::ffi::OsString> = HashSet::new();
        let mut ids: HashSet<String> = HashSet::new();
        let mut shas: HashSet<String> = HashSet::new();
        let mut note = |g: &Job| {
            if let Some(f) = g.nzb_path.file_name() {
                named.insert(f.to_os_string());
            }
            ids.insert(g.nzo_id.clone());
            shas.insert(g.nzb_sha.clone());
        };
        for j in self.queue.lock_ok().iter() {
            note(&j.lock_ok());
        }
        for j in self.history.lock_ok().iter() {
            note(&j.lock_ok());
        }
        for k in self.delete_kept.lock_ok().iter() {
            if let Some(f) = Path::new(&k.nzb).file_name() {
                named.insert(f.to_os_string());
            }
        }
        // (allocator number, display stem, path), oldest id first so the
        // queue comes back in the order the jobs were accepted.
        let mut orphans: Vec<(u64, String, PathBuf)> = Vec::new();
        for entry in rd.flatten() {
            let fname = entry.file_name();
            if named.contains(&fname) {
                continue;
            }
            let Some(fname) = fname.to_str() else {
                continue;
            };
            let Some(rest) = fname
                .strip_suffix(".nzb")
                .and_then(|f| f.strip_prefix("SABnzbd_nzo_nzbfast"))
            else {
                continue;
            };
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            let Ok(n) = digits.parse::<u64>() else {
                continue;
            };
            if ids.contains(&format!("SABnzbd_nzo_nzbfast{n}")) {
                continue;
            }
            let stem = rest[digits.len()..].trim_start_matches('-').to_string();
            orphans.push((n, stem, entry.path()));
        }
        orphans.sort();
        let mut adopted = 0;
        for (n, stem, path) in orphans {
            let id = format!("SABnzbd_nzo_nzbfast{n}");
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            if bytes.is_empty() {
                // A delete whose unlink was refused empties the spool
                // copy as its last resort (`drop_spool`). It names no
                // record and holds no articles: adopting it would
                // resurrect the release the user cancelled, as a job
                // that can only fail.
                continue;
            }
            let sha = nzb_sha(&bytes);
            if !shas.insert(sha) {
                if self.path_is_recorded(&path) {
                    // Not a spare copy: a row adopted EARLIER IN THIS
                    // PASS names this very path. `enqueue_as` reruns the
                    // pre-queue hook, which can rename the release and
                    // so write its copy under a name this scan had
                    // already snapshotted as a separate orphan. Removing
                    // it here left the durable row pointing at nothing -
                    // an unrecoverable loss, since that row then keeps
                    // the next start from seeing an orphan at all.
                    continue;
                }
                info!(
                    target: "queue",
                    "{}: a spare copy of an NZB the queue already holds - removed",
                    path.display()
                );
                let _ = std::fs::remove_file(&path);
                continue;
            }
            // Never hand this number out again, whatever the allocator
            // was restored to.
            self.next_id.fetch_max(n + 1, Ordering::Relaxed);
            match self.enqueue_as(
                Some(&id),
                &bytes,
                &stem,
                "",
                SAB_DEFAULT_PRIORITY,
                None,
                None,
                "recovered",
                false,
                None,
            ) {
                Ok(e) if e.durable => {
                    adopted += 1;
                    ids.insert(id.clone());
                    info!(
                        target: "queue",
                        "recovered {id} ({stem}) from {} - it was accepted by the last \
                         run but its record never reached disk",
                        path.display()
                    );
                    // `enqueue_as` wrote its own spool copy (usually over
                    // this very path); an original left under another
                    // name would read as a fresh orphan next start.
                    if !self.path_is_recorded(&path) {
                        let _ = std::fs::remove_file(&path);
                    }
                }
                // Not durable: the file stays, and the next start asks
                // again under the same id - which is the idempotence.
                Ok(_) => {}
                Err(e) => warn!(
                    target: "queue",
                    "{}: left in the spool, could not be re-adopted: {e}",
                    path.display()
                ),
            }
        }
        if adopted > 0 {
            info!(target: "queue", "recovered {adopted} job(s) from orphaned spool files");
        }
        adopted
    }
}
