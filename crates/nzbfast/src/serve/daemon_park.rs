//! How a job stops running (TODO 106 code motion out of daemon.rs).
//!
//! One subject end to end: whether a failure will re-arm itself
//! (`will_auto_retry`), the failure report the queue row and the *arr
//! see (`report_failure`), aborting a prefetch sidecar that was serving
//! it (`poke_sidecar`), quarantining payload a delete must not silently
//! destroy (`note_delete_kept`/`save_delete_kept`), parking the job into
//! history (`park`, the big one), noticing the queue has gone quiet
//! (`note_queue_idle`) and persisting the give-up ledger
//! (`save_giveup`).
//!
//! A second `impl Daemon` in a child module of `daemon`, on the
//! daemon_index shape, for the same reasons as daemon_persist.rs -
//! including `pub(super)` becoming `pub(in crate::serve)`, which is what
//! the ORIGINAL visibility meant here and what every existing call site
//! across serve/ still needs.

use super::*;

/// Test seam: `note_queue_idle` trips between its empty scan and its
/// latch CAS, inside the queue critical section - the exact window the
/// M3 interleaving needed open. First barrier: the scan has run and the
/// CAS has not; second: the test has staged its interleaved work and
/// releases it. Same two-stage shape as `moveseq::COMMIT_TOMB_BARRIER`.
///
/// Keyed by the owning daemon's spool path, which is what one test
/// fixture has and another does not. The bin tests run in parallel and
/// `note_queue_idle` is on every queue-emptying path there is, so an
/// unkeyed seam is a two-party barrier that any of them can walk into
/// as a third waiter - which does not fail the run, it HANGS it (seen
/// twice, 15 Aug). Same reason `postproc::TAIL_GEN_BARRIER` carries an
/// nzo_id.
#[cfg(test)]
pub(in crate::serve) static IDLE_CAS_BARRIER: Mutex<
    Option<(String, Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
> = Mutex::new(None);

/// Test seam: `park_gen` trips it after its first generation check has
/// passed and its file removal is done, which is the window a retry
/// lands in. The guard is dropped across `remove_job_files` - a whole
/// recursive delete, unbounded on a hung NAS - so this is a wide window
/// in practice and a zero-width one in a test without a seam. Same
/// two-stage shape as `IDLE_CAS_BARRIER`: first barrier says the window
/// is open, second says the test has staged its retry and releases it.
///
/// Keyed by nzo_id, like `postproc::TAIL_GEN_BARRIER`, so a park
/// belonging to some other test can never wander into a two-party
/// barrier that is not its own. Unkeyed it hung the whole `--bin
/// nzbfast` run twice on 15 Aug: every park reaches this seam, the bin
/// tests run in parallel, and a third waiter on a `Barrier::new(2)`
/// blocks forever instead of failing.
#[cfg(test)]
pub(in crate::serve) static PARK_GEN_BARRIER: Mutex<
    Option<(String, Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
> = Mutex::new(None);

/// Test seam: `park_gen` trips it AFTER its second generation check,
/// its move stamp and its durable history prewrite, and before the
/// queue retain. `PARK_GEN_BARRIER` sits before that second check, so a
/// retry staged there is seen and declined - which is exactly why the
/// stretch behind it went unexercised while the suite stayed green. The
/// prewrite is disk I/O, so this is a real window and a zero-width one
/// without a seam. Same keyed two-stage shape, for the same reason.
#[cfg(test)]
pub(in crate::serve) static PARK_PREWRITE_BARRIER: Mutex<
    Option<(String, Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
> = Mutex::new(None);

/// Keeps a finished prefetch's detached completion tail registered as
/// an owner of its directory for as long as that tail runs. See
/// [`Daemon::sidecar_tail_begin`].
pub(in crate::serve) struct SidecarTailGuard {
    d: Arc<Daemon>,
    target: Arc<AtomicBool>,
}

impl Drop for SidecarTailGuard {
    fn drop(&mut self) {
        self.d
            .sidecar_tails
            .lock_ok()
            .retain(|t| !Arc::ptr_eq(t, &self.target));
    }
}

impl Daemon {
    /// Will [`park`](Daemon::park) arm an M32 automatic retry for this
    /// job? See [`auto_retry_eligible`], which both this and the hook
    /// planner share so they cannot drift (they already did once - see
    /// [`fail_kind`]).
    pub(in crate::serve) fn will_auto_retry(&self, job: &Arc<Mutex<Job>>) -> bool {
        let secs = self.auto_retry_secs.load(Ordering::Relaxed);
        auto_retry_eligible(&job.lock_ok(), secs)
    }

    /// Tell the indexer this download failed, and queue the replacement
    /// it offers - NZBGet's FailureLink, natively.
    ///
    /// An indexer that sends `X-DNZB-Failure` is offering two things at
    /// one URL: a failure report (which is how it learns a post is dead,
    /// and how the next person is spared it) and, in the response body,
    /// another NZB for the same title. `failure_link` chooses how far to
    /// go: "report" sends the report and stops, "regrab" also queues what
    /// comes back. Off by default - it tells a third party what failed
    /// for you, which is a reasonable thing to want and not a reasonable
    /// default.
    ///
    /// A 404, an empty body, or anything that isn't XML means the
    /// indexer has nothing else, which is the ordinary outcome and not an
    /// error. Blocking: call from the blocking pool.
    pub(in crate::serve) fn report_failure(&self, job: &Arc<Mutex<Job>>) {
        let mode = self.failure_link.lock_ok().clone();
        if mode == "off" {
            return;
        }
        let (link, depth, name, cat, priority, pp, password) = {
            let j = job.lock_ok();
            // A job the user DELETED owes the outside world nothing, and
            // least of all a dead-post report for a post that is not dead.
            if j.state != JobState::Failed || j.tombstone || j.failure_link.is_empty() {
                return;
            }
            // Only a post-unavailability failure is news the indexer can
            // act on. A full disk, a permission error or an unpack that
            // fell over says nothing about the post - reporting it marks
            // a healthy release dead for every other user of that indexer
            // and, under `regrab`, spends bandwidth replacing it.
            if !fail_kind(&j.fail_message).post_unavailable() {
                info!(
                    target: "failurelink",
                    "{}: not reported - {} is a local fault, not a dead post",
                    j.name, j.fail_message
                );
                return;
            }
            if !failure_link_allowed(&j.failure_link, &j.failure_host, j.failure_https) {
                warn!(
                    target: "failurelink",
                    "{}: refusing {} - it does not point back at {} (the indexer that supplied it)",
                    j.name,
                    // The X-DNZB-Failure endpoint is the indexer's own URL and
                    // carries its key - and this line fires exactly on a host
                    // mismatch, which in practice is an indexer serving the
                    // link from a CDN alias with ?apikey= attached. stdout is
                    // not private (logtee mirrors it into mode=log, the
                    // JSON-RPC log methods and `docker logs`), so redact here
                    // like the accept path below already does.
                    redact_url_creds(&j.failure_link),
                    if j.failure_host.is_empty() {
                        "the origin"
                    } else {
                        &j.failure_host
                    }
                );
                return;
            }
            let (cat, priority, password) = replacement_inherits(&j);
            (
                j.failure_link.clone(),
                j.failure_depth,
                j.name.clone(),
                cat,
                priority,
                // The pp the failed job's add asked for: the replacement
                // is the same request re-made, so the pre-queue hook
                // sees the same mode.
                j.sab_pp,
                password,
            )
        };
        let regrab = may_regrab(&mode, depth);
        if mode == "regrab" && !regrab {
            info!(target: "failurelink", "{name}: {depth} replacements already tried - reporting only");
        }
        // In `report` mode the report IS the GET: nothing reads the
        // response, a 404 counts as success, and there is no reason to
        // pull a body down (let alone a large one) only to drop it.
        let fetched = match if regrab {
            fetch_url(&link).map(Some)
        } else {
            ping_url(&link)
        } {
            Ok(f) => f,
            // 404 is the indexer saying "nothing else for that title".
            Err(e) => {
                let s = e.to_string();
                if s.contains("404") {
                    info!(target: "failurelink", "{name}: reported, no other release available");
                } else {
                    // Same reason as the watch leg above: the X-DNZB-Failure
                    // endpoint is the indexer's own URL and carries the key.
                    warn!(target: "failurelink", "{name}: {}", redact_url_creds(&s));
                }
                return;
            }
        };
        let Some(fetched) = fetched else {
            info!(target: "failurelink", "{name}: failure reported to the indexer");
            return;
        };
        if !is_nzb_body(&fetched.bytes) {
            info!(target: "failurelink", "{name}: reported, no other release available");
            return;
        }
        // Our category, always: it selects the output subfolder, the
        // library flag and the move-completed destination, so taking the
        // one out of the (untrusted) response would let the indexer pick
        // which of the user's destinations the payload lands in.
        match self.enqueue_fetched(
            &fetched,
            &format!("{name}.nzb"),
            &cat,
            priority,
            pp,
            password.as_deref(),
            depth + 1,
            // A failure-link replacement inherits nothing useful from the
            // failed job, but "we picked this for you" is worth saying.
            "failure-link",
            false,
        ) {
            Ok(id) => info!(target: "failurelink", "{name}: queued a replacement ({id})"),
            Err(e) => warn!(target: "failurelink", "{name}: replacement was not usable: {e}"),
        }
    }

    /// Abort of the prefetch sidecar when a user op removes or pauses the
    /// job it holds (sync handler contexts - the task winds down on its
    /// own; the runner's stop_sidecar await covers pipeline handover).
    ///
    /// Fires inline and then RE-FIRES until the sidecar is actually gone,
    /// for the same reason suspend_matching does: `get_with_progress`
    /// installs the hub's abort and queue-ctl handles asynchronously after
    /// launch, so a single signal that lands in the gap finds both slots
    /// empty and no-ops. `cancelled` is not a safety net there either - the
    /// task reads it once, before the transfer starts, and is then parked
    /// inside the pipeline with nothing left to re-check it.
    ///
    /// That gap was reachable and it lost data-plane work: deleting a job
    /// mid-prefetch removed it from the queue and kept it out of history
    /// (both correct) while the transfer ran to completion, spending
    /// provider quota on a job the user had explicitly deleted and leaving
    /// the finished files in the output directory. Caught by
    /// `jsonrpc_delete_stops_a_prefetching_job`, which failed on
    /// "the delete did not stop the prefetch" roughly 1 run in 40 in
    /// release - the whole reason that assertion exists.
    ///
    /// Returns whether it found a sidecar to fire at. Most callers only
    /// want the signal sent and ignore it; `requeue_category` needs the
    /// answer, because the sidecar's exit path is what moves a
    /// re-pointed job's part-downloaded files - and with no sidecar
    /// live, nobody else does (Codex sweep 3, M12).
    pub(in crate::serve) fn poke_sidecar(self: &Arc<Self>, hit: impl Fn(&str) -> bool) -> bool {
        // Inline first, so the transfer is already stopping by the time the
        // delete/pause API call returns.
        let Some(target) = self.fire_sidecar_abort(&hit) else {
            return false;
        };
        let d = self.clone();
        std::thread::spawn(move || {
            // Bounded like the pause re-fire: 60 s is far longer than the
            // handles take to attach, and the loop exits the moment the
            // sidecar slot is empty or holds a different sidecar.
            for _ in 0..240 {
                std::thread::sleep(std::time::Duration::from_millis(250));
                if !d.refire_sidecar_abort(&target) {
                    return;
                }
            }
        });
        true
    }

    /// One abort signal at the current sidecar, if `hit` accepts it.
    /// Returns the sidecar it fired at (see [`Self::refire_sidecar_abort`]
    /// for why that is the cancel flag rather than the id), or None when
    /// there is nothing to fire at.
    fn fire_sidecar_abort(&self, hit: &impl Fn(&str) -> bool) -> Option<Arc<AtomicBool>> {
        let sc = self.sidecar.lock_ok();
        let sc = sc.as_ref().filter(|s| hit(&s.nzo_id))?;
        Self::signal_sidecar(sc);
        Some(sc.cancelled.clone())
    }

    /// Re-fire at the SAME sidecar `fire_sidecar_abort` picked. False =
    /// it is gone (or something else holds the slot) and the loop stops.
    ///
    /// Identity is the cancel flag's allocation, not the nzo_id: a retry
    /// keeps its id, so a job re-queued inside the 60 s window started a
    /// fresh prefetch that the previous delete's loop then aborted. The
    /// Arc is held for the whole loop, so the address cannot be recycled
    /// under it.
    fn refire_sidecar_abort(&self, target: &Arc<AtomicBool>) -> bool {
        let sc = self.sidecar.lock_ok();
        let Some(sc) = sc.as_ref().filter(|s| Arc::ptr_eq(&s.cancelled, target)) else {
            return false;
        };
        Self::signal_sidecar(sc);
        true
    }

    /// Who the prefetch sidecar is serving right now, as `(nzo_id,
    /// cancel flag)`. Snapshot this BEFORE taking the queue lock: the
    /// sidecar mutex under queue+job would be a new lock edge, and this
    /// is the only thing either delete arm needs from it.
    pub(in crate::serve) fn sidecar_owner(&self) -> Option<(String, Arc<AtomicBool>)> {
        self.sidecar
            .lock_ok()
            .as_ref()
            .map(|s| (s.nzo_id.clone(), s.cancelled.clone()))
    }

    /// Delete-with-files for a job the prefetch sidecar is RUNNING:
    /// wait for the sidecar to wind down, then remove.
    ///
    /// A prefetching job reads `Queued` and not `finalizing`, so both
    /// delete arms took it for a record with no live writer and removed
    /// its directory on the request thread, microseconds after a
    /// fire-and-forget `poke_sidecar`. The pipeline was still draining,
    /// and `ensure_plain_writer` opens a slot's writer LAZILY - on that
    /// file's first article - so the next file of any multi-file release
    /// ran `create_dir_all` and laid a fresh payload in the directory
    /// the user had just deleted, named by no record at all (Codex sweep
    /// 14 Aug M2).
    ///
    /// NOT deferred to `park` instead: the abort's ordinary outcome is
    /// the sidecar's Err arm, which never parks, so park-deferral would
    /// leave the payload on disk forever AND leave the directory
    /// reserved forever with it.
    ///
    /// Off the request thread, because the wind-down is the sidecar's
    /// to finish and an HTTP handler must not hold for it - the same
    /// reason the plain removal moved out from under the queue lock.
    pub(in crate::serve) fn remove_after_sidecar_drain(
        self: &Arc<Self>,
        target: Arc<AtomicBool>,
        name: String,
        dir: std::path::PathBuf,
        filed: bool,
        tail: crate::smart::FiledTail,
    ) {
        let d = self.clone();
        std::thread::spawn(move || {
            // Until the last owner lets go, and no sooner. This was
            // bounded at 60 s "exactly like `poke_sidecar`'s re-fire
            // loop", and the two are not the same wait at all: the
            // re-fire is waiting for handles to ATTACH, which takes
            // milliseconds, while this is waiting for a whole pipeline
            // to let go of a directory. The abort does not even reach
            // the disk tail - the cancel flag is read once, right after
            // the network phase - so verify, repair and unpack run to
            // their end afterwards, and on a big damaged set that is
            // routinely longer than a minute. Past the bound, this
            // removed the directory under those writers and handed the
            // reservation back while the old owner was still in there:
            // the next positioned write then recreated a payload
            // nothing named, which is the very orphan the drain exists
            // to prevent (read-only sweep 2, M6).
            //
            // The unbounded wait it was written to avoid is a sidecar
            // that never clears its slot, and that is not a directory
            // to strand quietly - it is a bug to say out loud. So the
            // wait says so, once a minute, and keeps waiting.
            let started = std::time::Instant::now();
            let mut said = 0u64;
            while d.sidecar_still_holds(&target) {
                let mins = started.elapsed().as_secs() / 60;
                if mins > said {
                    said = mins;
                    info!(
                        target: "prefetch",
                        "{name}: still waiting for the early start to let go of {} \
                         before removing it ({mins} min)",
                        dir.display()
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
            // The request answered long ago, so a refusal here has no
            // response left to ride back on - same as park's deferred
            // removal, and the notice is how it reaches the user.
            if let FilesGone::Kept(why) = remove_job_files(&dir, &name, filed, &tail) {
                // No NZB to offer: the delete handler removed this job's
                // spool copy when it took the row out of the queue, long
                // before the sidecar had finished with the directory.
                d.note_delete_kept(&name, &dir, &why, None);
            }
            d.reserved.lock_ok().remove(&dir);
        });
    }

    /// Is anything from the run this delete aborted still holding its
    /// directory - the download, or the tail the download handed off to?
    ///
    /// By the cancel flag's allocation, not the nzo_id, for the reason
    /// [`Self::refire_sidecar_abort`] spells out: a retry keeps its id,
    /// so a re-queued job's FRESH prefetch would answer yes and this
    /// wait would sit through a download it has nothing to do with.
    ///
    /// BOTH registers, because the slot answers for the download only.
    /// A prefetch that finishes hands its completion tail to a task of
    /// its own and then clears the slot on its way out, so between
    /// those two the slot says "nobody is here" while the tail is about
    /// to unlock, sweep, rename and move inside that very directory -
    /// and `finalizing`, which the delete arms test instead, is not
    /// raised until part-way through it (read-only sweep 2, M6).
    fn sidecar_still_holds(&self, target: &Arc<AtomicBool>) -> bool {
        self.sidecar
            .lock_ok()
            .as_ref()
            .is_some_and(|s| Arc::ptr_eq(&s.cancelled, target))
            || self
                .sidecar_tails
                .lock_ok()
                .iter()
                .any(|t| Arc::ptr_eq(t, target))
    }

    /// Register a finished prefetch's detached completion tail as an
    /// owner of its directory, and hand a guard back that deregisters
    /// it however that tail ends - normally, by panic, or by being
    /// dropped at shutdown.
    pub(in crate::serve) fn sidecar_tail_begin(
        self: &Arc<Self>,
        target: Arc<AtomicBool>,
    ) -> SidecarTailGuard {
        self.sidecar_tails.lock_ok().push(target.clone());
        SidecarTailGuard {
            d: self.clone(),
            target,
        }
    }

    /// The signal itself: the pre-armed flag, plus whichever pipeline
    /// handles have attached by now.
    fn signal_sidecar(sc: &crate::serve::sidecar::Sidecar) {
        sc.cancelled.store(true, Ordering::Relaxed);
        if let Some(f) = sc.hub.abort.lock_ok().as_ref() {
            f.store(true, Ordering::Relaxed);
        }
        if let Some(c) = sc.hub.queue_ctl.lock_ok().as_ref() {
            c.abort();
        }
    }

    /// Record a delete that removed the RECORD but not the FILES, for the
    /// dashboard's kept-files notice.
    ///
    /// Every delete-with-files path ends here on a [`FilesGone::Kept`],
    /// and the reason is the same one each time: the user asked for
    /// recoverable deletes, no Trash would take the path, and we now
    /// leave the download alone rather than destroying it (70990f19).
    /// That was the right call and it opened this hole - the queue row or
    /// history row goes regardless, so the only handle the user had on a
    /// folder that is still sitting there is the thing the delete removed,
    /// and a `warn!` in a log they will never open is not telling them.
    ///
    /// The path is the replacement handle, which is why it is stored
    /// rather than the id: they cannot open a record that no longer
    /// exists, but they can go and look at the folder.
    /// `nzb` is the spooled NZB this delete did NOT throw away, so the
    /// notice can offer the download again in place. None where there is
    /// nothing to offer - a job with no spool copy left, or a caller
    /// (the watchlist's upgrade sweep) whose refusal is not a download
    /// the user was asking to repeat.
    ///
    /// Never a copy some OTHER record still names. The M5 arm of
    /// `park_gen` files a deleted-but-retryable history row that keeps
    /// `nzb_path` and reads it back on retry, and the refusal in that
    /// same park used to hand the notice that very path: one file, two
    /// owners, neither aware of the other. Dismissing the strip - or
    /// pressing "download it again", or letting the notice age off the
    /// 12-entry ring - then removed the NZB the history row's retry
    /// button needs, and the retry failed with a raw ENOENT out of the
    /// NZB read (Codex sweep 3, M11; reachable from JSON-RPC
    /// GroupDelete / GroupDupeDelete on an ACTIVE job). A notice with
    /// no NZB is an ordinary one - it keeps the folder handle and loses
    /// only the button, which the surviving history row provides.
    ///
    /// Returns whether a notice was actually filed, which is the only
    /// answer to "does anything name that NZB now?". The dedupe below
    /// drops the whole entry, `nzb` included, so a caller that handed
    /// its spool copy over on faith kept a file nothing can reach - the
    /// exact litter this notice exists to complain about.
    pub(in crate::serve) fn note_delete_kept(
        &self,
        name: &str,
        path: &std::path::Path,
        why: &str,
        nzb: Option<&std::path::Path>,
    ) -> bool {
        {
            let mut k = self.delete_kept.lock_ok();
            let path = path.display().to_string();
            // One entry per path. A bulk history sweep over a shared season
            // folder refuses once per record, and a dozen identical rows
            // would bury the one thing the notice has to say.
            if k.iter().any(|n| n.path == path) {
                return false;
            }
            // The dropped entry's kept NZB goes with it: nothing can
            // reach it once the notice naming it is off the ring, and
            // spool files nobody names are what the delete was trying
            // to avoid leaving behind in the first place.
            k.push_back(KeptNote {
                name: name.to_string(),
                path,
                why: why.to_string(),
                at: unix_now(),
                nzb: nzb.map(|p| p.display().to_string()).unwrap_or_default(),
            });
            while k.len() > 12 {
                if let Some(gone) = k.pop_front() {
                    drop_kept_nzb(&gone);
                }
            }
        }
        // The strip rides the revisioned queue payload, so raising a
        // notice has to move the revision too - on an idle daemon
        // nothing else will, and the strip would not appear until
        // something unrelated did. `spend_kept_notice` is the other
        // door and carries the same bump; neither bumps on its no-op
        // arm (the dedupe above, an absent path there), or every
        // refusal would re-send the payload to every idle tab.
        self.queue_rev.fetch_add(1, Ordering::Relaxed);
        self.save_delete_kept();
        true
    }

    /// Persist the kept-files notices to `.spool/delete-kept.json`.
    ///
    /// This ring is not a moment that scrolls past like the ones beside
    /// it - it is the REPLACEMENT handle on a folder whose history row
    /// was just deleted, and it stays on screen until dismissed. Held
    /// only in memory it did not survive a restart, which includes the
    /// auto-updater's own restart and `restart_daemon` from the settings
    /// UI: the row was already gone, so the user was left with the exact
    /// state the notice exists to prevent - a folder still eating disk,
    /// named by nothing anywhere. The deferred `park()` refusal has no
    /// response to ride back on at all, so for that path this is the
    /// only channel there is.
    pub(in crate::serve) fn save_delete_kept(&self) {
        let path = self.spool.join("delete-kept.json");
        // The lock is held ACROSS the write, not just around a snapshot.
        // Snapshotting and then writing lets two writers land in the
        // opposite order to the states they carry: a refusal snapshots
        // [X, Y] and is preempted, the user dismisses X and its write of
        // [Y] completes, then the first write lands [X, Y] - and the next
        // restart resurrects the notice the user just cleared, which is
        // the one thing persisting the dismissal exists to prevent.
        // Safe to hold: `write_atomic` takes no other lock of ours, and
        // this mutex is a leaf (never acquired while queue/history are
        // held - both delete arms record after dropping them).
        let kept = self.delete_kept.lock_ok();
        if let Ok(text) = serde_json::to_string_pretty(&*kept) {
            let _ = crate::persist::write_atomic(&path, text.as_bytes());
        }
    }

    /// Which round of a record's life a long-running caller started on:
    /// `(retries, move_seq)`, bumped by [`Daemon::retry`] and
    /// `moveseq::stamp_move` respectively.
    pub(in crate::serve) fn record_generation(g: &Job) -> (u32, u64) {
        (g.retries, g.move_seq)
    }

    /// Is a record still on the round `gen0` names? `None` is a caller
    /// that asked for no fence at all, and everything is theirs.
    ///
    /// Ask it under the SAME hold as the write it guards wherever the
    /// two can be brought together - the whole reason `park_gen` grew a
    /// second check is that a test separated from its write by an
    /// unlocked interval is not a guard, and every caller of this one
    /// is a long-running tail with exactly such intervals in it.
    pub(in crate::serve) fn same_generation(g: &Job, gen0: Option<(u32, u64)>) -> bool {
        gen0.is_none_or(|g0| Self::record_generation(g) == g0)
    }

    /// Drop the per-job custody maps, but only for an id nobody is
    /// still using.
    ///
    /// `activity` and `tail_cancel` are keyed by id ALONE. `park_gen`'s
    /// stale-at-entry branch used to clear them unconditionally, on the
    /// assumption that a retry seen there has only just landed and will
    /// re-register afterwards. A tail delayed in a long post-processing
    /// script gives no such ordering: the retry had already registered,
    /// and clearing took its activity token and its recovery-tail cancel
    /// handle - after which a delete could no longer stop that work. The
    /// non-stale path avoids this by re-reading the generation and
    /// returning before it removes (sweep 4, M4c); the stale branch is
    /// where that condition is true by definition, so it asks a
    /// different question instead (Codex sweep 5, M5).
    fn release_custody_if_unclaimed(&self, id: &str) {
        if find_job(self.queue.lock_ok().iter(), id).is_some() {
            return;
        }
        self.hub.activity.lock_ok().remove(id);
        self.hub.tail_cancel.lock_ok().remove(id);
    }

    /// Spend a delete that was deferred until the download drained,
    /// removing the payload and the spooled .nzb the request could not
    /// touch while the job was live.
    ///
    /// Lifted out of `park_gen` whole under the size gate (TODO 106).
    /// It takes no decision of its own: everything it needs is on the
    /// record, and it returns nothing, which is why it lifts cleanly.
    // The active-download delete deferred its file removal to here: by
    // now the fetch has drained and no writer can recreate the dir. A
    // tombstoned job is dropped (not filed to history), so its spooled
    // .nzb is dead weight too - remove it (history retry keeps its own).
    fn spend_deferred_delete(&self, job: &Arc<Mutex<Job>>) {
        // Set when a refused removal handed this job's spooled NZB
        // to a kept-files notice: the drop below must then leave it
        // where it is - see `note_delete_kept`.
        let mut kept_nzb: Option<std::path::PathBuf> = None;
        // Snapshot what the removal needs, then RELEASE the guard
        // before touching the filesystem. Recursive deletion of a
        // whole release is slow (and on a hung NAS, unbounded), and
        // the queue -> job lock order means anyone walking the queue
        // - save_queue, pick_job, the API - would park behind this
        // one job's mutex for the duration. The job is terminal and
        // its fetch has drained, so nothing rewrites these fields
        // between the snapshot and the removal.
        let (del, gone_nzb) = {
            let mut g = job.lock_ok();
            let del = g.del_on_drop.then(|| {
                (
                    delete_tail(&g, || self.job_suffix(filed_stem(&g))),
                    g.out_dir.clone(),
                    filed_stem(&g).to_string(),
                    g.filed,
                )
            });
            // One request, one deletion: the flag is spent here.
            // M5 lets a deleted record LIVE ON as a retryable
            // history row, and this is the same Arc that gets filed
            // and later re-queued - so a flag left set carried the
            // user's old delete forward into the RETRY's own park,
            // which removed a freshly completed release just before
            // filing its Completed row (Codex sweep 14 Aug H1).
            // Cleared unconditionally, not only when the removal
            // reported the files gone: a Trash refusal already
            // reaches the user through `note_delete_kept` below, and
            // re-arming a later park would be this same bug with an
            // extra step.
            g.del_on_drop = false;
            // M5: a delete verb that files a history row keeps the
            // spooled .nzb - the row is retryable and retry reads
            // the spool. Only the history-less delete drops it.
            (
                del,
                (g.tombstone && g.delete_status.is_empty()).then(|| g.nzb_path.clone()),
            )
        };
        if let Some((tail, out_dir, stem, filed)) = del {
            // The user pressed delete-with-files on a LIVE download
            // and this is where it finally happens, long after the
            // request answered - so a refusal here has no response
            // left to ride back on, and the notice is the only way it
            // reaches them at all.
            if let FilesGone::Kept(why) = remove_job_files(&out_dir, &stem, filed, &tail) {
                // ...and the spool copy becomes the notice's offer to
                // run it again - but ONLY where `gone_nzb` already
                // says this park is the last thing naming that file.
                // The M5 arm below files a RETRYABLE history row that
                // reads the same copy, so sharing it let a dismiss
                // break the retry: see `note_delete_kept` (M11).
                if self.note_delete_kept(&stem, &out_dir, &why, gone_nzb.as_deref()) {
                    kept_nzb = gone_nzb.clone();
                }
            }
            // The other end of the reservation the delete took when
            // it set this flag: the directory is only safe to hand
            // out once its files are actually gone.
            self.reserved.lock_ok().remove(&out_dir);
        }
        if let Some(nzb) = gone_nzb
            && kept_nzb.as_ref() != Some(&nzb)
        {
            let _ = std::fs::remove_file(&nzb);
        }
    }

    /// Park a finished job in history (NZBGet-style: failures are parked,
    /// not lost - mode=retry sends them back through the queue and the
    /// journal resumes from what already landed), on the generation the
    /// caller started on.
    ///
    /// There is no unfenced `park` any more: sweep 3 H1 fenced the last
    /// two callers that had one (the lane's crashed-tail arm and the
    /// hooks-only submit), and a spelling that silently accepts ANY
    /// round is the footgun that finding was about. `None` still means
    /// "no fence" for the callers that genuinely have no round to name.
    ///
    /// `park` itself needs no guard: its fifteen callers park a job they
    /// are holding across a short window. The post-processing lane tail
    /// is the exception - it can run for minutes, and one of the NZBGet
    /// delete verbs will file a Finishing job into history from under it,
    /// after which a RETRY (retryable by design) clears the tombstone and
    /// re-queues the same Arc. The tail then parked the freshly queued
    /// row straight back into history, consuming the button the user had
    /// just pressed: the same shape the sidecar's late Ok had, and the
    /// same answer (Fable sweep 15 Aug). `None` keeps the old behaviour
    /// exactly.
    pub(in crate::serve) fn park_gen(&self, job: Arc<Mutex<Job>>, gen0: Option<(u32, u64)>) {
        /// Was this held row held against the job that just failed?
        ///
        /// The `dupe_key` filter alone asks "same title", which is what
        /// `smart` admission judges on and is therefore the same
        /// question there. Under `dupe_scope = "exact"` it is NOT: a
        /// different release of the same episode is admitted and runs,
        /// so its failure promoted rows held against a still-completed
        /// original (Codex sweep K). An empty `held_for` is a row from
        /// before the field existed and keeps the old behaviour: for
        /// those rows only, the caller's `dupe_key` filter is the whole
        /// gate. A row that NAMES the failed job outranks the key
        /// comparison - the alias arm of the duplicate check holds a
        /// job whose key spells the show differently, and requiring
        /// the keys to also match would park that row forever.
        fn held_against(g: &Job, failed_id: &str, failed_key: &str) -> bool {
            if g.held_for.is_empty() {
                return g.dupe_key.as_deref() == Some(failed_key);
            }
            g.held_for == failed_id
        }
        let (id, failed, key, demote, stale) = {
            let g = job.lock_ok();
            (
                g.nzo_id.clone(),
                g.state == JobState::Failed,
                g.dupe_key.clone(),
                g.demote,
                // Read under the SAME hold as the rest: a test separated
                // from the first write it guards is not a guard.
                gen0.is_some_and(|g0| Self::record_generation(&g) != g0),
            )
        };
        if stale {
            // Not ours any more. Do NOT retain the queue, prewrite,
            // file history or stamp a move - the record belongs to
            // whoever re-queued it.
            self.release_custody_if_unclaimed(&id);
            return;
        }
        self.spend_deferred_delete(&job);
        // Read LIVE, not from the snapshot above: everything between the two
        // is unlocked, and file removal is slow. A queue or JSON-RPC delete
        // landing in that window used to be decided against a stale
        // `tombstone == false`, so the deleted job was requeued (demote arm),
        // filed into history, or had an alternative promoted for a cancel the
        // user had just made. Every terminal branch below re-reads it.
        //
        // The GENERATION needs the same treatment and did not have it. The
        // check at the top of this function is the only one there was, and
        // between it and here the guard is dropped for `remove_job_files`,
        // which walks a whole release and is unbounded on a hung NAS. A
        // retry landing in THAT window bumps the generation after the test
        // has already passed, so the rest of this function then ran against
        // a record it no longer owns: it removed the live retry's activity
        // and tail-cancel entries, and went on to requeue or file it. Same
        // stale-read class as the tombstone above, same fix - re-read it.
        //
        // It returns WITHOUT touching the two custody maps, which is the one
        // way it differs from the check at the top. Both maps are keyed by
        // job id, not by generation, and the new run registers its own
        // entries under that same key. At the top of this function the retry
        // has only just landed and has not registered yet, so removing is
        // handing custody back. Here it is the opposite: we have been away
        // for the length of a recursive delete, the new generation is
        // running and its entries are in those maps, and a remove() would
        // take the live retry's activity row out of the queue - the exact
        // damage this guard exists to prevent.
        #[cfg(test)]
        {
            // The id is read BEFORE the seam lock is taken: a job lock
            // under the seam guard would order the two the other way
            // round from every other reader of this record.
            let id = job.lock_ok().nzo_id.clone();
            let seam = PARK_GEN_BARRIER
                .lock_ok()
                .clone()
                .filter(|(k, _, _)| *k == id);
            if let Some((_, open, release)) = seam {
                open.wait();
                release.wait();
            }
        }
        if gen0.is_some_and(|g0| Self::record_generation(&job.lock_ok()) != g0) {
            return;
        }
        // Activity and §129's tail-cancel die with the row - BELOW the
        // re-read, not above it, or the guard cannot guard the one thing
        // the comment above says it exists for (sweep 4, M4c).
        self.hub.activity.lock_ok().remove(&id);
        self.hub.tail_cancel.lock_ok().remove(&id);
        let tombstone = job.lock_ok().tombstone;
        // Watchdog demotion: back into the queue (deferred, at the end)
        // instead of history - the abort was ours, not a failure. The
        // journal keeps everything already landed, so the eventual rerun
        // fetches only what's still missing.
        // `!tombstone`: a deleted job stays deleted. Both flags together is
        // an ordinary race - the slow-job watchdog demotes at T, the user (or
        // an *arr) deletes at T+ε - and the demote arm used to win, pushing
        // the just-deleted job back onto the queue with its payload removed
        // and its spooled .nzb already unlinked above. It then reappeared in
        // the *arr, ran, and failed.
        // `failed`: the demotion only counts if its abort actually took the
        // download down. The watchdog's abort can lose the race with the
        // finish line - it once fired at a job whose network had already
        // drained (see the runner's stand-down at net-drain) - and a stale
        // flag on a job that went on to COMPLETE must not send it back
        // through the queue: post-processing has renamed its directory by
        // now, so the "rerun" was a full second download of a finished
        // release into the renamed folder (the 31 Jul queue soak).
        if demote_requeues(demote, tombstone, failed) {
            {
                let mut g = job.lock_ok();
                g.state = JobState::Queued;
                g.fail_message.clear();
                // The evidence goes with the verdict it explained - a
                // re-queued job that fails again captures its own.
                g.fail_detail.clear();
                g.finished_at = None;
                g.finished_unix = None;
                g.demote = false;
                g.deferred = true;
                g.defer_count += 1;
            }
            // §158.7: the row leaves and rejoins the queue under ONE hold
            // of the lock. It used to be dropped near the top of `park` and
            // pushed back here, and a demoted job has no history copy to
            // fall back on, so any other thread's save inside that gap
            // published a queue.json while NO store held the record. The
            // coalescing saver widened that: the write now happens on the
            // saver thread, off a live queue this park had already emptied.
            {
                let mut q = self.queue.lock_ok();
                q.retain(|j| j.lock_ok().nzo_id != id);
                q.push_back(job);
            }
            self.save_queue_soon();
            return;
        }
        // §158 item 1: claim the queue -> history move before ANY of it is
        // durable, so every copy this park writes carries the higher
        // `move_seq` and the queue.json rewrite at the end is the only
        // write left holding the lower one. A kill between them leaves a
        // stale nonterminal queue row beside the terminal history one, and
        // the counter is what tells `load_queue` that the history copy is
        // where the job was heading rather than where it happened to be.
        //
        // Ahead of `park_prewrite`, not beside the `history_upsert` lower
        // down: §158.7 made the prewrite the FIRST durable history write,
        // so stamping after it filed an unstamped row and left the tear
        // reading as a tie. The demote arm has already returned by here,
        // so a requeued job is never stamped; a tombstoned one is stamped
        // and dropped, which is inert because it reaches neither store.
        //
        // Read and stamped under ONE hold of the job lock. A retry
        // slipping between the two would have bumped `retries` (and
        // stamped its own `move_seq`) FIRST, and this stamp would then
        // land a HIGHER counter on a history row the retry has already
        // superseded - which resolves the wrong way at the next
        // `load_queue` and quietly undoes the retry. Combining them
        // makes that ordering unrepresentable (Codex sweep 6, N2).
        {
            let mut g = job.lock_ok();
            if gen0.is_some_and(|g0| Self::record_generation(&g) != g0) {
                return;
            }
            moveseq::stamp_move_locked(&mut g);
        }
        // Q2: from the prewrite until the record is filed into
        // `self.history` below, its only durable copy is the disk row the
        // prewrite is about to append - and `history_compact` snapshots
        // MEMORY. The guard keeps the id registered for the whole
        // interval so a concurrent compaction ("Save queue" runs one on
        // a live daemon) carries the disk row into its snapshot instead
        // of erasing it.
        let _inflight = self.hist_inflight_begin(&id);
        // §158.7: the DESTINATION store FIRST, before the row leaves the
        // live queue - `park_prewrite` carries the why, and the demote arm
        // above is why it has to know about the tombstone.
        // A tombstone that OWES a history row (M5: an NZBGet delete verb
        // on an active job, filed a hundred lines below) is bound for
        // history like any other park, so it gets the same prewrite -
        // without it the record sits in NEITHER store from the queue
        // removal on the next line until that arm files it, which is the
        // window §158.7 closed for every other park.
        let dropping = tombstone && job.lock_ok().delete_status.is_empty();
        let filed_early = self.park_prewrite(&job, dropping);
        // From the retain below until an arm files the record into
        // `self.history`, the job is in NEITHER store in memory - and
        // `dir_claim` scans exactly those two stores, so a concurrent
        // add (or retry) picking a directory inside the window reads
        // this job's canonical folder as free and hands it out; the new
        // job's first decoded span then truncates the finished payload.
        // Every directory decision runs under `add_lock` (enqueue,
        // retry, recategorize), so holding it across the window locks
        // the deciders out until the record is visible again. Taken
        // AFTER the prewrite - the row is still in the queue until the
        // retain, and a durable write has no business under this lock -
        // and released by each arm the moment it files the record.
        // The harness's window for the LAST unguarded stretch: from the
        // stamp above to the retain below, this park does history.jsonl
        // I/O with no generation check at all.
        #[cfg(test)]
        {
            let seam = PARK_PREWRITE_BARRIER
                .lock_ok()
                .clone()
                .filter(|(k, _, _)| *k == id);
            if let Some((_, open, release)) = seam {
                open.wait();
                release.wait();
            }
        }
        let mut publish = Some(self.add_lock.lock_ok());
        // The generation once more, and this time under the hold that
        // makes it a guard rather than a guess: `retry` takes
        // `add_lock` for its whole critical section, so a retry is
        // either fully visible here or cannot land until the retain is
        // done. Without this the durable prewrite above - unbounded on
        // a slow disk - was a window in which a retry could push the
        // SAME record back onto the queue, only for the retain to pull
        // it straight out again by id and the arms below to file it
        // into history. The user's retry vanished (Codex sweep 6, N2).
        //
        // `retries` alone, not the whole generation: this park has just
        // stamped its own `move_seq`, so the tuple no longer matches by
        // construction. `retries` is the half a retry moves and park
        // never does.
        if gen0.is_some_and(|(r0, _)| job.lock_ok().retries != r0) {
            return;
        }
        self.queue.lock_ok().retain(|j| j.lock_ok().nzo_id != id);
        // The harness's window: the row has just left the queue and every
        // store write park still owes is ahead of it.
        #[cfg(test)]
        super::storecut::park_gap(self);
        if demote {
            // The flag outlived a download that finished anyway (or a
            // tombstone). Scrub it before the record reaches history, or a
            // later retry of this job carries it back here and the arm
            // above requeues that retry's park unconditionally.
            job.lock_ok().demote = false;
        }
        // M32: a FIRST failure with missing articles gets ONE
        // automatic retry after a cooldown - propagation lag is a real
        // cause of missing articles that clears on its own, and the
        // journal makes the rerun fetch only what's still missing. Only
        // transient shapes qualify: password and takedown verdicts don't,
        // and nor does a post too old for propagation to explain it.
        //
        // The predicate itself is `will_auto_retry`, shared with
        // `run_post_job_hooks` so the report/re-grab side and the
        // duplicate promotion below agree with what actually happens here.
        let armed_auto_retry = self.will_auto_retry(&job);
        if armed_auto_retry {
            let secs = self.auto_retry_secs.load(Ordering::Relaxed);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            // What we are waiting FOR decides both the delay and what
            // to call it. Propagation filling in missing articles takes
            // real time; a pool that stalled on this machine has nothing
            // to wait for at all, and the old copy told the user to sit
            // out 20 minutes for a propagation that was never the
            // problem.
            let kind = fail_kind(&job.lock_ok().fail_message);
            let (secs, why, token) = match kind {
                FailKind::Transport => (
                    secs.min(SHORT_RETRY_SECS),
                    "connection trouble, not missing articles - retrying shortly",
                    RETRY_WHY_TRANSPORT,
                ),
                // Everything left is missing articles on a post young
                // enough for propagation to be a live explanation -
                // `retry_may_still_help` refused the rest.
                _ => (
                    secs,
                    "articles missing - propagation may fill them",
                    RETRY_WHY_PROPAGATION,
                ),
            };
            {
                let mut g = job.lock_ok();
                g.auto_retry_at = Some(now + secs);
                // Beside the stamp, because the delay above was chosen
                // from it: the drawer says "2 minutes, because this was
                // the link and not the post" in the user's own language,
                // which needs the reason as a token and not as this
                // English log line.
                g.auto_retry_why = Some(token.to_string());
            }
            info!(
                target: "retry",
                "{id}: {why}; automatic retry in {} min \
                 (resumes from the journal; only the gaps will be refetched)",
                secs.div_ceil(60)
            );
        }
        // Re-read once more: the demote arm above returns, so this is the
        // first point the history/promotion decisions are actually taken.
        let tombstone = job.lock_ok().tombstone;
        // §96.3: feed the per-target give-up breaker. Here because this
        // is where a failure becomes FINAL - a tombstone owes nobody
        // anything and an armed auto-retry means the story continues.
        if !tombstone {
            self.giveup_note_outcome(&job, armed_auto_retry);
        }
        if !tombstone {
            // C: hand the owed move over only once the record is IN
            // history - the mover looks the job up there, and it runs
            // on its own worker so this park (and the runner tail
            // behind it) never waits on a NAS copy.
            let owes_move = job.lock_ok().move_pending;
            self.history.lock_ok().push(job.clone());
            // In history: `dir_claim` sees the record again, so the
            // directory deciders waiting on the lock may look now -
            // ahead of the durable upsert, which they need not wait for.
            publish.take();
            // §129 1a/1b: the record reaches its own store the moment it
            // reaches history, and the lifecycle event replaces the
            // dashboard's snapshot-diff toast inference. Then retention,
            // which is a no-op unless the optional knobs are set.
            let _ = self.history_upsert(std::slice::from_ref(&job));
            self.life_emit_parked(&job);
            self.history_enforce_retention();
            if owes_move {
                self.mover_enqueue(&job);
            }
        } else if !job.lock_ok().delete_status.is_empty() {
            // M5: the tombstone came from an NZBGet delete verb that
            // owes a history row (GroupDelete / GroupDupeDelete /
            // GroupParkDelete on an ACTIVE job - the queued case files
            // directly from the handler). The abort's own fail verdict
            // is not the story; stamp the delete's, then file. None of
            // the failure duties above ran (give-up, failure-link,
            // duplicate promotion are all tombstone-gated), which is
            // right: this is a cancellation, not a failure.
            {
                let mut g = job.lock_ok();
                g.state = JobState::Failed;
                g.fail_message = if g.delete_status == "DUPE" {
                    "deleted from the queue as a duplicate".into()
                } else {
                    "deleted from the queue".into()
                };
                g.fail_detail.clear();
                // The auto-retry stamp too: `will_auto_retry` read the
                // tombstone BEFORE this arm's delete verb landed, so a
                // transient failure parking concurrently with the delete
                // can arrive here armed - and run_due_auto_retries checks
                // nothing but Failed + due, which would re-download a
                // title the user explicitly deleted.
                g.auto_retry_at = None;
                g.auto_retry_why = None;
                // The record is done with its abort; clearing the
                // tombstone here makes it an ordinary history row, so a
                // later retry re-queues something pick_job will run.
                g.tombstone = false;
                if g.finished_unix.is_none() {
                    g.finished_at = Some(Instant::now());
                    g.finished_unix = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .ok()
                        .map(|t| t.as_secs() as i64);
                }
            }
            // Not pushed twice: the handler files QUEUED deletes into
            // history itself, and a late prefetch Ok can still walk that
            // same record through this park.
            let already = {
                let mut h = self.history.lock_ok();
                let already = h.iter().any(|j| Arc::ptr_eq(j, &job));
                if !already {
                    h.push(job.clone());
                }
                already
            };
            // Filed (or already present): the record is visible to
            // `dir_claim` again.
            publish.take();
            if !already {
                let _ = self.history_upsert(std::slice::from_ref(&job));
                self.history_enforce_retention();
            }
        } else if filed_early {
            // A tombstoned job files into no store at all: its payload
            // was removed above, so the directory really is free and the
            // deciders need not wait for the burial below.
            publish.take();
            // §158.7: a delete landed INSIDE this park, after
            // `park_prewrite`. The job is dropped rather than filed, so
            // bury the row it already wrote or the next boot replays a
            // history record for the job the user cancelled.
            self.history_tombstone(std::slice::from_ref(&id));
        }
        // The remaining arm (a tombstone with nothing prewritten) files
        // nothing either; make the release explicit before the promotion
        // scan below.
        drop(publish);
        // The original failed → promote its best held ALTERNATIVE (M14f).
        // Not while an automatic retry is armed: the original is coming
        // back through the queue in minutes, and starting the alternative
        // now downloads the same title twice. And not for a tombstone: the
        // "failure" there is the abort the user's own delete fired, so
        // promoting would start downloading the very title they cancelled.
        if failed
            && !tombstone
            && !armed_auto_retry
            && let Some(key) = key
        {
            // BEST, not first. Breaking at the first match promoted
            // whichever alternative happened to be added earliest, so
            // a 720p held before a 2160p won and the 2160p stayed
            // parked for good - the user ended up with the worst copy
            // of the three while two better ones sat in the queue.
            // Rank them the way the watchlist ranks candidates, so
            // "best" means the same thing in both places.
            // Collect the held candidates under the queue lock (a few
            // Arc + name clones), then rank them AFTER it is released:
            // parse_release is real parsing work, and running it under
            // the lock scaled with the number of held duplicates while
            // every API request waited (issue #38 follow-up).
            let candidates: Vec<(Arc<Mutex<Job>>, String)> = self
                .queue
                .lock_ok()
                .iter()
                .filter_map(|j| {
                    let g = j.lock_ok();
                    (g.priority == -3 && g.paused && held_against(&g, &id, &key))
                        .then(|| (j.clone(), g.name.clone()))
                })
                .collect();
            let mut best: Option<(u32, &Arc<Mutex<Job>>)> = None;
            for (j, name) in &candidates {
                let rank = crate::watchlist::quality_rank(&crate::wall::parse_release(name));
                // Ties keep the earlier-added one, which is the
                // old behaviour and is as good a tiebreak as any.
                if best.is_none_or(|(r, _)| rank > r) {
                    best = Some((rank, j));
                }
            }
            if let Some((rank, j)) = best {
                let mut g = j.lock_ok();
                // Re-check now that the queue lock has been dropped and
                // retaken a world away: a delete landing in the gap sets
                // tombstone, and promoting a just-deleted alternative
                // would start downloading the very title the user
                // cancelled.
                if g.priority == -3 && g.paused && !g.tombstone && held_against(&g, &id, &key) {
                    g.paused = false;
                    g.priority = 0;
                    info!(
                        target: "queue",
                        "{} promoted (best held duplicate of failed {id}, rank {rank})",
                        g.nzo_id
                    );
                }
            }
        }
        // Coalesced: the record is already durable in history.jsonl (the
        // upsert above), and load_queue resolves a torn queue/history
        // pair in history's favour - the debounced rewrite only drops
        // the queue row.
        self.save_queue_soon();
        self.note_queue_idle();
    }

    /// §129 4a: `queue.idle`, if the queue has just become idle. Idle =
    /// nothing downloading or finishing and nothing unpaused waiting; a
    /// held ALTERNATIVE (paused by design) does not keep the queue
    /// "busy". The latch makes it a transition, said once until the next
    /// add or pick re-arms it.
    ///
    /// Every way the last runnable job can leave calls this, not just
    /// `park`. Deleting the last queued job and pausing the last
    /// runnable one both make the queue idle without a park, and until
    /// the 10 Aug sweep (M3) neither said so - the subscriber that
    /// starts a media scan or spins a disk down when the queue empties
    /// simply never heard about those two.
    pub(in crate::serve) fn note_queue_idle(&self) {
        // Latch already set = idle is already announced and nothing has
        // re-armed it, so the CAS below cannot succeed and the answer to
        // the walk is moot - return rather than take 15,000 job locks
        // under the queue lock to learn that (issue #38 residue). This
        // can only suppress an emit the CAS would have refused anyway:
        // "said once until re-armed" is decided by the latch, and the
        // walk was only ever evidence for the arming edge.
        if self.queue_idle_latch.load(Ordering::Relaxed) {
            return;
        }
        // The scan, the CAS and the emit share ONE hold of the queue
        // lock (Codex sweep 14 Aug M3). Dropped between scan and CAS,
        // an enqueue could slip into the gap - re-arm the latch, push
        // its job, publish job.added - and this thread's CAS then
        // succeeded on the stale scan, announcing queue.idle over a
        // runnable job with the latch left set. Enqueue publishes
        // under this same lock, so holding it makes the pair a
        // serialization: whichever side wins the lock, the emitted
        // order is one the queue really passed through. Emitting under
        // the queue lock follows enqueue's established order (ring and
        // webhook channel are leaves under it).
        let _q = self.queue.lock_ok();
        let idle = !_q.iter().any(|j| {
            let g = j.lock_ok();
            matches!(g.state, JobState::Downloading | JobState::Finishing)
                || (g.state == JobState::Queued && !g.paused)
        });
        #[cfg(test)]
        {
            let spool = self.spool.display().to_string();
            let pair = IDLE_CAS_BARRIER
                .lock_ok()
                .clone()
                .filter(|(k, _, _)| *k == spool);
            if let Some((_, entered, released)) = pair {
                entered.wait();
                released.wait();
            }
        }
        if idle
            && self
                .queue_idle_latch
                .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.life_emit("queue.idle", json!({}));
            // The queue-finished action hangs off this exact CAS, so
            // "once per drain" is the latch's property and not a second
            // copy of the same reasoning. Store-and-return only: we are
            // under the queue lock, and the lane does the rest.
            self.finish.note_drained();
        }
    }

    /// Persist the give-up counters (small, changes rarely - every
    /// terminal outcome of an automated grab at most).
    /// Persist the give-up counters (small, changes rarely - every
    /// terminal outcome of an automated grab at most).
    ///
    /// Snapshot AND write under one hold of the state lock. `write_atomic`
    /// publishes through a uniquely named temp file, so two savers that
    /// snapshot in one order can rename in the other: a tripped snapshot
    /// that stalled behind a "Try again" reset could land last and
    /// restore the trip at the next restart, with the UI still saying
    /// reset (M14, 10 Aug sweep). Holding the lock across the write
    /// costs nothing here - this file is a few hundred bytes and is
    /// written at most once per terminal grab.
    pub(in crate::serve) fn save_giveup(&self) {
        let path = self.spool.join("giveup-state.json");
        let st = self.giveup.lock_ok();
        if let Ok(text) = serde_json::to_string_pretty(&*st) {
            let _ = crate::persist::write_atomic(&path, text.as_bytes());
        }
    }
}

#[cfg(test)]
mod park_custody_tests {
    use super::*;
    use crate::serve::testutil::test_daemon;

    /// The smallest NZB that parses and enqueues, so "the retry can
    /// still use it" is a claim about real bytes rather than a stat().
    const NZB: &[u8] = br#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb"><file poster="x" date="0" subject="&quot;a.bin&quot; yEnc (1/1)"><groups><group>g</group></groups><segments><segment bytes="1000" number="1">one@x</segment></segments></file></nzb>"#;

    /// A delete verb that owes a HISTORY row keeps the spooled NZB - the
    /// row is retryable and the retry reads that copy - so the
    /// kept-files notice raised by the same refusal must NOT also claim
    /// it.
    ///
    /// Both records named one file and neither knew about the other, so
    /// whichever was spent first silently broke the other. Dismissing
    /// the strip (or letting it age off the 12-entry ring, or pressing
    /// "download it again") ran `drop_kept_nzb` and removed the spool
    /// copy while the history row still pointed at it, and the
    /// advertised retry then failed with a raw ENOENT out of the NZB
    /// read (Codex sweep 3, M11).
    #[test]
    fn a_history_owed_delete_keeps_its_nzb_out_of_the_kept_notice() {
        let dir = std::env::temp_dir().join(format!("nzbfast-parkcust-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let d = test_daemon(&dir);

        let spool_nzb = d.spool.join("Kept.Release.nzb");
        std::fs::write(&spool_nzb, NZB).expect("spool copy");
        // The removal has to be REFUSED, and the cheapest honest refusal
        // is a path that is not a directory: `remove_user_dir` passes
        // the error straight through as `FilesGone::Kept`, exactly as a
        // Trash that will not take the folder does.
        let out = dir.join("Kept.Release");
        std::fs::write(&out, b"not a directory").expect("blocker");

        let job = Arc::new(Mutex::new(
            job_from_json(&serde_json::json!({
                "nzo_id": "nzo-parkcust-1",
                "name": "Kept.Release",
                "nzb_path": spool_nzb.to_string_lossy(),
                "out_dir": out.to_string_lossy(),
                "state": "Failed",
            }))
            .expect("job"),
        ));
        // Exactly what JSON-RPC `GroupDelete` leaves behind for a job it
        // caught DOWNLOADING: tombstoned, stamped for a history row, its
        // file removal deferred to park.
        {
            let mut g = job.lock_ok();
            g.fail_message = "deleted from the queue".into();
            g.finished_unix = Some(1);
            g.tombstone = true;
            g.delete_status = "MANUAL".into();
            g.del_on_drop = true;
        }
        d.queue.lock_ok().push_back(job.clone());
        d.park_gen(job.clone(), None);

        let note = d
            .delete_kept
            .lock_ok()
            .front()
            .cloned()
            .expect("the refused removal must raise a kept-files notice");
        assert!(
            note.nzb.is_empty(),
            "the notice claimed the spool copy the history row still owns"
        );
        assert!(
            d.history
                .lock_ok()
                .iter()
                .any(|j| j.lock_ok().nzo_id == "nzo-parkcust-1"),
            "M5: a delete verb with a status files a retryable row"
        );

        // The user dismisses the strip. That spends the notice - and
        // with it, before the fix, the NZB the row's retry needs.
        assert!(
            crate::serve::api::queue::spend_kept_notice(&d, &note.path),
            "the notice is the one being dismissed"
        );
        assert!(
            spool_nzb.exists(),
            "dismissing the notice deleted the spooled NZB the history retry reads"
        );
        assert!(
            d.retry("nzo-parkcust-1"),
            "the filed delete row is retryable"
        );
        let named = job.lock_ok().nzb_path.clone();
        assert_eq!(
            named, spool_nzb,
            "the re-queued row still names its spool copy"
        );
        let bytes = std::fs::read(&named).expect("the retry's NZB read");
        d.enqueue(&bytes, "Kept.Release", "", -100, None, None, "test", true)
            .expect("the kept spool copy must still parse and enqueue");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
