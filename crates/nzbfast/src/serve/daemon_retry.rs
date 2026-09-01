//! `Daemon`'s retry paths - every way a job is sent round again (TODO 106
//! code motion out of daemon.rs).
//!
//! Three ladders that only ever get read together: the M32 auto-retry
//! cooldown that re-queues a Failed history job on its own, the manual
//! `retry` a client asks for, and the move-retry ladder underneath them
//! (`settle_move_attempt` records an attempt and prices the next one,
//! `redrive_move` and `retry_move_now` fire it).
//!
//! A second `impl Daemon` in a child module of `daemon`, on the
//! daemon_index shape, so `Daemon`'s private fields and daemon.rs's
//! private types stay in scope exactly as they were inline. `pub(super)`
//! became `pub(in crate::serve)` for exactly that reason: `super` is
//! `daemon` here, and every call site is one level up.

use super::*;

impl Daemon {
    /// M32: re-queue any Failed history job whose auto-retry cooldown has
    /// elapsed. Called from the scheduler loop; one lock + linear scan.
    pub(in crate::serve) fn run_due_auto_retries(self: &Arc<Self>) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let due: Vec<(String, String)> = self
            .history
            .lock_ok()
            .iter()
            .filter_map(|j| {
                let g = j.lock_ok();
                // `alt_to_name` is the belt: item 14 stamps it on a row
                // something has replaced, and a replaced record must not
                // come back through the queue and download the same
                // release beside its replacement. The doors that stamp it
                // disarm the row themselves; this is what keeps a future
                // one from having to remember.
                (g.state == JobState::Failed
                    && g.alt_to_name.is_empty()
                    && g.auto_retry_at.is_some_and(|t| t <= now))
                .then(|| (g.nzo_id.clone(), g.name.clone()))
            })
            .collect();
        for (id, name) in due {
            if self.retry(&id) {
                info!(
                    target: "retry",
                    "{id}: automatic retry (cooldown elapsed - refetching only what's missing)"
                );
                // The row the user was shown as FAILED has just left
                // History and joined the queue. Announce the move: without
                // it the record appears to have been lost and a download
                // nobody asked for appears to have started.
                //
                // §129 1b(b): on the sequence-cursored lifecycle ring,
                // where it replaces a bounded `auto_retried` array on the
                // queue payload that the dashboard diffed against a
                // seen-set of its own. Emitted AFTER `retry` has moved
                // the record, so anything acting on the event finds the
                // job in the queue and not in history.
                self.life_emit("job.retried", json!({"nzo_id": id, "name": name}));
            }
        }
        // The other half of the cooldown: a COMPLETED job whose move to
        // the completed folder failed retries the MOVE, never the
        // download. Separate arm on purpose - `retry` above would pull
        // the record out of history and re-fetch a payload that is
        // already whole on disk.
        let due_moves: Vec<String> = self
            .history
            .lock_ok()
            .iter()
            .filter_map(|j| {
                let g = j.lock_ok();
                (g.state == JobState::Completed
                    && !g.move_failed.is_empty()
                    && g.auto_retry_at.is_some_and(|t| t <= now))
                .then(|| g.nzo_id.clone())
            })
            .collect();
        for id in due_moves {
            self.redrive_move(&id);
        }
    }

    /// Record what one move attempt did to the job and arm - or refuse
    /// to arm - the next automatic try. Call with the job lock held,
    /// once `move_failed` carries the attempt's outcome.
    ///
    /// The one place the ladder lives. Both movers (the finalize-side
    /// worker and the scheduler's redrive) used to carry their own copy
    /// of "re-arm the flat cooldown", which is how the retry stayed
    /// unbounded in two places at once: nothing counted the attempts,
    /// so nothing could grow the delay or ever stop. An unreachable
    /// destination is not a transient the way a missing article is -
    /// an unmounted destination volume logged 45 identical EACCES
    /// failures over 15 hours on 8 Aug 2026, and the 45th was as
    /// uninformative as the first.
    ///
    /// Giving up is not giving up on the payload: every byte is whole
    /// at `out_dir`, the row stays amber, the drawer still names the
    /// destination and the error, and `Try the move now` restarts the
    /// ladder the moment the user has fixed what was wrong.
    pub(in crate::serve) fn settle_move_attempt(&self, j: &mut Job) {
        if j.move_failed.is_empty() {
            j.move_attempts = 0;
            // Only ever disarm OUR reason: a stamp left by anything
            // else is not this function's to clear.
            if j.auto_retry_why.as_deref() == Some("move") {
                j.auto_retry_at = None;
                j.auto_retry_why = None;
            }
            return;
        }
        j.move_attempts = j.move_attempts.saturating_add(1);
        let base = self.auto_retry_secs.load(Ordering::Relaxed);
        // Zero is the user turning automatic retries off outright, and
        // it is not a give-up worth logging - they asked for this.
        if base == 0 {
            return;
        }
        if j.move_attempts >= MOVE_RETRY_GIVE_UP {
            // Disarm rather than merely declining to re-arm. The
            // redrive clears the stamp before it tries, so this is
            // usually already None - but the finalize-side mover does
            // not, and a stamp left behind here is the scheduler's cue
            // to run the whole ladder again, which is the unbounded
            // loop this function exists to end.
            j.auto_retry_at = None;
            j.auto_retry_why = None;
            warn!(
                target: "move",
                "{}: giving up on the move after {} failed attempts - {}. \
                 The download is safe at {}; \"Try the move now\" in its \
                 history drawer starts a fresh ladder.",
                j.nzo_id,
                j.move_attempts,
                j.move_failed,
                j.out_dir.display()
            );
            return;
        }
        let secs = move_retry_delay(base, j.move_attempts);
        j.auto_retry_at = Some(unix_now() as u64 + secs);
        j.auto_retry_why = Some("move".to_string());
    }

    /// Re-attempt the move-completed relocation for a parked Completed
    /// job whose first attempt failed (Job::move_failed). Files only -
    /// the download is done and stays done. Returns false when the job
    /// is missing, unfenced state forbids it, or no failure is recorded.
    ///
    /// The observed failure mode this exists for is transient: macOS
    /// denied a network volume to the daemon for a moment and allowed
    /// it minutes later (7 Aug 2026), so "try again on the M32
    /// cooldown" converts hours of silently-stranded payloads into one
    /// delayed move. On another failure the cooldown re-arms - each
    /// attempt is one create_dir plus one copy that stops at the first
    /// error, so a persistently absent NAS costs a probe per cycle, not
    /// a re-download.
    pub(in crate::serve) fn redrive_move(self: &Arc<Self>, nzo_id: &str) -> bool {
        let Some(job) = self.history_job(nzo_id) else {
            return false;
        };
        // Same fence pair the recategorize path takes, for the same
        // reasons: `moving` keeps deletes/retries off the payload while
        // files are in flight, and `finalizing` means the tail already
        // owns the directory. The fence is dropped by the guard inside
        // the blocking task, so it holds exactly as long as files can
        // be moving; the early-out paths below release it by hand.
        if !self.moving.lock_ok().insert(nzo_id.to_string()) {
            return false;
        }
        struct MoveClaim(Arc<Daemon>, String);
        impl Drop for MoveClaim {
            fn drop(&mut self) {
                self.0.moving.lock_ok().remove(&self.1);
            }
        }
        let claim = MoveClaim(self.clone(), nzo_id.to_string());
        let (out_dir, cat) = {
            let mut g = job.lock_ok();
            if g.state != JobState::Completed || g.finalizing || g.move_failed.is_empty() {
                return false; // claim drops here, releasing the fence
            }
            // Disarm before the attempt so a success does not leave a
            // stale cooldown ticking; a failure re-arms below.
            g.auto_retry_at = None;
            g.auto_retry_why = None;
            (g.out_dir.clone(), g.category.clone())
        };
        let d = self.clone();
        let job2 = job.clone();
        let id2 = nzo_id.to_string();
        // The copy is bulk I/O - blocking pool, with the fence riding
        // along in `claim` so it cannot be released before the move
        // settles.
        tokio::task::spawn_blocking(move || {
            let _claim = claim;
            info!(target: "move", "{id2}: retrying the move to the completed folder");
            let (moved, split, failed) = d.relocate_completed(&out_dir, &cat, None);
            let mut j = job2.lock_ok();
            j.move_failed = failed.unwrap_or_default();
            j.move_split = match &split {
                Some(src) => src.to_string_lossy().to_string(),
                None => String::new(),
            };
            if let Some(dest) = &moved {
                j.filed = j.tv_sort && is_season_dir(dest);
                j.out_dir = dest.clone();
            }
            // Arms the NEXT rung, or stops the ladder. The disarm above
            // ran before the attempt, so this is the only thing that
            // can leave a stamp behind.
            d.settle_move_attempt(&mut j);
            drop(j);
            // The mover's hazard exactly (see `mover_process`), plus
            // the ladder's own stamps: without them a restart retries a
            // move that already landed.
            d.history_publish_move(&job2, &out_dir, moved.as_deref());
            d.save_queue();
        });
        true
    }

    /// The drawer button's redrive: forget the failed-attempt count
    /// first, then try.
    ///
    /// A user pressing "Try the move now" has almost always just fixed
    /// the thing that was wrong - mounted the volume, granted the
    /// share, freed the disk - so the ladder starts again from its
    /// first rung, and a job the daemon had given up on becomes
    /// automatic again. Without the reset, one manual press on a job at
    /// the give-up count would try exactly once and go quiet forever.
    pub(in crate::serve) fn retry_move_now(self: &Arc<Self>, nzo_id: &str) -> bool {
        if let Some(job) = self.history_job(nzo_id) {
            job.lock_ok().move_attempts = 0;
        }
        self.redrive_move(nzo_id)
    }

    pub(in crate::serve) fn retry(&self, nzo_id: &str) -> bool {
        // Same transaction as `enqueue`: this picks an output directory
        // by the same claim rule and republishes the job into the queue,
        // so it must not interleave with an add (or another retry)
        // making the same decision about the same folder.
        let publish = self.add_lock.lock_ok();
        let mut h = self.history.lock_ok();
        // A recategorize is moving this job's payload right now. Taking
        // it out of history and re-queueing it would start writers at
        // the path the move is emptying, and the move would then point
        // the record at the destination while the download continued at
        // the source. The auto-retry timer fires from the scheduler, so
        // this is not a race the user has to lose deliberately.
        //
        // UNDER the history lock, which is the half that makes it work
        // (Codex H7). `history_change_cat` raises its `moving` marker and
        // THEN re-verifies the record is still in history; a check taken
        // outside this lock could pass just before the marker went up
        // while the move still proceeded. Both REST and JSON-RPC history
        // delete already sample it here; retry read it one lock too
        // early, so a recategorize could re-verify the record present,
        // block on `add_lock`, and then move the payload of a job this
        // call had already pulled out of history and re-queued - leaving
        // a full payload at the destination named by no record, while
        // the re-queued job downloaded the release again into the
        // directory the move was emptying.
        if self.moving.lock_ok().contains(nzo_id) {
            info!(target: "retry", "{nzo_id}: refused - its files are being moved right now");
            return false;
        }
        let Some(pos) = h.iter().position(|j| j.lock_ok().nzo_id == nzo_id) else {
            return false;
        };
        // A password unlock is finalizing this record right now - it is
        // extracting/renaming/moving under `out_dir` and will write the
        // committed state back when it settles. Removing and re-queueing
        // the record here would reassign that directory under the
        // running task (Codex sweep 3 Aug H1). Checked under the history
        // lock: set_password raises the flag and then re-verifies the
        // record is still present under this same lock, so whichever
        // committed second sees the other.
        if h[pos].lock_ok().finalizing {
            info!(target: "retry", "{nzo_id}: refused - an unlock is finalizing it right now");
            return false;
        }
        // Q2's other direction: from this removal until `commit_to_queue`'s
        // save lands, the record's only durable copy is its history.jsonl
        // row - and a concurrent "Save queue" compaction snapshots
        // `self.history`, which no longer holds it. Register the id so the
        // compaction carries the disk row, exactly as park does around its
        // prewrite window. Guard drops on every exit below.
        let _inflight = self.hist_inflight_begin(nzo_id);
        let job = h.remove(pos);
        drop(h);
        // A TV-filed job's out_dir is the SHARED `Show/Season NN` library
        // folder. Re-queueing it as-is would point the whole re-download
        // (journal, volume writers, and every later "delete this job's
        // files") at a directory that belongs to the season, not the job.
        // Give it a fresh private directory instead.
        //
        // So does a job whose old folder someone else has taken since it
        // failed: a Failed record reads as Free, so a re-add of the same
        // name is handed exactly that directory, and re-queueing this one
        // as-is would put two live jobs in it - or, once the re-add has
        // finished, aim this download straight at its verified payload,
        // which is the collision `DirClaim::Payload` exists to prevent.
        // Checked AFTER the history removal above, so an ordinary failed
        // retry still finds its own folder unclaimed and reuses it in
        // place: re-adds must not climb .2/.3/.4.
        let (filed, category, name, cur) = {
            let j = job.lock_ok();
            (
                j.filed,
                j.category.clone(),
                j.name.clone(),
                j.out_dir.clone(),
            )
        };
        // With NO job lock held: dir_claim locks every job in the queue
        // and history.
        let taken = matches!(self.dir_claim(&cur), DirClaim::Active | DirClaim::Payload);
        // A job's out_dir is the absolute path baked in from the
        // download-folder setting IN FORCE WHEN IT WAS ADDED. If that
        // setting has since changed - the user picked a new download folder,
        // or a settings.json was carried between two machines where the old
        // path (a since-unplugged drive, a differently mounted volume) does
        // not even exist - the captured path no longer sits under the
        // current root. Re-running the job as-is would keep writing to, or
        // fail EACCES/ENOENT against, a folder the user has deliberately
        // moved away from (field repro 9 Aug: out_dir was changed to a
        // mounted path, yet retry still targeted the old /Volumes/... one).
        // Re-derive it from the CURRENT root + this job's category, exactly
        // as a fresh add resolves it. A path still under the current root is
        // left untouched, so an ordinary failed retry keeps its own folder,
        // its journal and its progress. (refile_out_dir honours the category
        // as a subfolder; a cat_meta `dir` rename is not re-applied here, the
        // same as the filed/taken paths above - a pre-existing gap, not this
        // fix's concern.)
        // TODO 317: a write-through job's out_dir is DELIBERATELY
        // outside the download root - it is under its category's
        // destination - so the root test alone calls every one of them
        // stale and refiles it back into the download folder, throwing
        // away its journal and its progress on an ordinary retry. A
        // path under the destination this category currently resolves
        // to is not stale. Asked of `move_dest_root` rather than of the
        // write-through setting, so turning the setting off does not
        // strand a job that is already down there: what makes the path
        // valid is that a destination for the category still exists.
        let wt_root = self.write_through_root(&category);
        let stale = !cur.starts_with(self.out_dir())
            && !self
                .move_dest_root(&category)
                .is_some_and(|(root, _)| cur.starts_with(&root));
        if filed || taken || stale {
            let (dir, replaces) = match &wt_root {
                // The destination root already IS this category's
                // folder, so `refile_out_dir`'s category component must
                // not be repeated under it. Same stem spelling either
                // way - `refile_out_dir`'s own note about the two sites
                // having to agree applies to this arm too.
                Some(root) => {
                    let stem =
                        nzbkit::disk::sanitize_filename_capped(name.trim_end_matches(".nzb"));
                    crate::serve::job::choose_out_dir(&root.join(&stem), &stem, &|p| {
                        self.dir_claim(p)
                    })
                }
                None => refile_out_dir(&self.out_dir(), &category, &name, &|p| self.dir_claim(p)),
            };
            let mut j = job.lock_ok();
            info!(
                target: "retry",
                "{}: {} {} - re-downloading into {} instead",
                j.nzo_id,
                if filed {
                    "was filed into"
                } else if taken {
                    "another job now owns"
                } else {
                    "targeted a download folder that is no longer configured:"
                },
                j.out_dir.display(),
                dir.display()
            );
            j.out_dir = dir;
            j.replaces = replaces;
            // TODO 317: the refile just decided which root this job
            // downloads under, so the record that says whether it owes
            // a move at completion has to follow it. A job refiled OUT
            // of a destination (write-through since turned off) now
            // owes the mover a visit; one refiled INTO one does not.
            j.write_through = wt_root.is_some();
            j.filed = false;
            // The journal that backed those bytes is in the OLD folder,
            // so nothing is on disk at the new one: this retry really
            // does start from zero, and the queue row must say so rather
            // than inherit a percentage from a directory it has just
            // been moved out of. (An ordinary failed retry keeps its
            // folder, its journal and its figure.)
            j.downloaded_bytes = 0;
            // The two travel together: the job is no longer in the season
            // folder, so the suffix its old files carried there is not an
            // answer about anything this record now owns.
            j.filed_suffix = None;
        }
        let had_del_on_drop;
        {
            let mut j = job.lock_ok();
            j.state = JobState::Queued;
            // A retry is an instruction to RUN the job, so it cannot
            // arrive back in the queue holding a pause `pick_job` will
            // skip it for (Codex sweep 2, 3 Aug M4). The flag reaches
            // here from a pause taken while the job was in its
            // post-network tail, which the tail correctly ignored and
            // then left set; the shared transition now refuses to set
            // it there at all, and this is the belt to that brace - a
            // failed record's pause flag describes nothing either way.
            j.paused = false;
            j.clear_failure();
            // §207: the verdict goes with the run it explained. `stamp`
            // only overwrites on Some, so a re-run too short (or too
            // unclassifiable) to earn one would otherwise keep the first
            // attempt's verdict on its record (bug sweep 22 Aug 2026).
            // Also drops fail_detail, the finished stamps and
            // postproc_secs - a retry parked by preflight or give-up
            // never reaches the tail that rewrites the last one.
            j.clear_attempt_verdicts();
            // M5: a row an NZBGet delete verb filed here carries the
            // delete's mark, and the queued-prefetch shape keeps its
            // tombstone too (the sidecar tail may still land an Ok).
            // A retry is an instruction to RUN the job: left set, the
            // mark would refile the next park as "deleted", and the
            // tombstone would make pick_job skip the row forever.
            j.delete_status.clear();
            j.tombstone = false;
            // Same reasoning one field further: a retry is an
            // instruction to RUN the job and KEEP what it produces. The
            // delete that filed this row set `del_on_drop` on the same
            // Arc, and for the `finalizing` shape the HANDLER files the
            // row while the tail is still on its way to park - so the
            // record can reach here with the flag still set, and the
            // first park after a successful re-run would delete the
            // payload it just produced (Codex sweep 14 Aug H1). park
            // now spends the flag as it reads it; this is the belt to
            // that brace and the only cover for the row filed by hand.
            had_del_on_drop = std::mem::replace(&mut j.del_on_drop, false);
            j.retries += 1;
            // A due-or-pending auto-retry is consumed by ANY retry (manual
            // included) - never leave a stale past-due stamp that would
            // re-trigger endlessly from history.
            j.auto_retry_at = None;
            // Travels with the stamp: a cleared retry has no reason left
            // to explain, and a stale token would caption the NEXT
            // failure's row with the last one's cause.
            j.auto_retry_why = None;
            // TODO §77: the pre-flight verdict is about a moment that has
            // passed. A retry exists BECAUSE the answer may have changed -
            // the automatic one runs on exactly the theory that propagation
            // has filled the gaps since - so the row must not go on showing
            // what the servers said before the last attempt. Cleared rather
            // than aged out: the prober re-samples a job with no verdict on
            // its next idle tick, which is the answer worth having here.
            j.health = None;
        }
        // The reservation that flag owned dies with it. A delete of an
        // active/lane/finalizing job sets `del_on_drop` AND reserves the
        // out_dir so `dir_claim` cannot hand it out in the gap, and
        // `park_gen` is the only release - but a retry bumps `retries`,
        // which is half of `record_generation`, so the old tail's
        // `park_gen` takes its stale-generation early return and never
        // reaches that release. Nothing else removes it: that arm does
        // not push the directory onto `doomed`, so the post-batch
        // `reserved_dirs` loops never see it either, and the release
        // could not use its own directory again for the life of the
        // process. Released here, beside the flag it belongs to, because
        // a retry is exactly what makes the deferred delete moot.
        if had_del_on_drop {
            self.reserved.lock_ok().remove(&cur);
        }
        // §158 item 1: claim the history -> queue move BEFORE the queue
        // write below, so the copy that write makes durable carries the
        // higher `move_seq` and a kill before the tombstone resolves in
        // the QUEUE's favour. Until this existed the reconciliation had
        // only precedence to go on, and precedence quietly undid the
        // retry - the record was still there and still retryable, but the
        // button the user pressed had done nothing.
        moveseq::stamp_move(&job);
        let seq = job.lock_ok().move_seq;
        self.queue.lock_ok().push_back(job);
        drop(publish);
        // Queue first, tombstone second, and never the tombstone on its
        // own - `commit_to_queue` holds the ordering and the reasons for
        // it, shared with the library-stream activation that moves a
        // record the same way.
        self.commit_to_queue(nzo_id, seq, moveseq::Requeue::Retry);
        true
    }
}
