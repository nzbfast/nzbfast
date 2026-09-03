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

use super::histstore::HistWrite;
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

/// What a `Refused` [`Daemon::park_prewrite`] costs, and the sentence
/// the user is shown for it.
///
/// The report is owed HERE and not by the filings further down
/// `park_gen`, which is the one thing about the ordering worth reading
/// twice. The prewrite's own rescue attempt is what CLOSES
/// `hist_rescue_open`'s one-a-minute gate, so a `history_publish` a
/// hundred lines on finds it shut and reports without an event; and the
/// two arms that file nothing at all - a tombstoned park, and the M5
/// delete arm's `already` path - have no later write to report for them
/// either. So the prewrite carries the sentence, and a park costs the
/// event ring exactly one entry however many of its writes the store
/// refuses.
fn prewrite_cost(job: &Arc<Mutex<Job>>) -> String {
    let g = job.lock_ok();
    format!(
        "{}: its history row did not reach the store before it left the queue - after \
         a restart nothing names it or the files in {}",
        g.name,
        g.out_dir.display()
    )
}

/// What a `Refused` filing costs on the ordinary park road: the record
/// is correct in memory and the payload is on disk, and nothing names
/// either of them from the next start on.
fn filed_cost(job: &Arc<Mutex<Job>>) -> String {
    let g = job.lock_ok();
    format!(
        "{}: the finished job's history row did not reach the store - after a restart \
         nothing names it or the files in {}",
        g.name,
        g.out_dir.display()
    )
}

/// What a `Refused` filing costs on the M5 arm, which is more than one
/// row.
///
/// `delete_prewrite` overrode the terminal keys in its placeholder;
/// `park_prewrite` then wrote the LIVE job over the top of it, still
/// nonterminal and still tombstoned, and a nonterminal state replays as
/// `Queued` (job_wire.rs). So losing this write does not merely forget
/// the delete - it leaves a queued-looking history row for a job the
/// user cancelled.
fn deleted_cost(job: &Arc<Mutex<Job>>) -> String {
    format!(
        "{}: the deleted job's final record did not reach the store - after a restart \
         its history row is the one written while it was still downloading",
        job.lock_ok().name
    )
}

/// What `park_gen` has settled about a job by the time it files it: the
/// three flags its two closing steps read between them.
///
/// One value rather than three loose `bool` parameters, for two reasons.
/// [`Daemon::park_file_terminal`] and [`Daemon::park_settle_spares`] want
/// overlapping subsets of them, so passing them loose puts the second at
/// the `clippy::too_many_arguments` line; and the two steps must never be
/// handed disagreeing answers, which one value makes unrepresentable.
#[derive(Clone, Copy)]
struct ParkVerdict {
    /// The job's state was `Failed` when the park took its snapshot.
    failed: bool,
    /// Re-read LIVE just before filing, never from that snapshot: a
    /// delete verb landing inside the park moves it, which is the whole
    /// reason `park_gen` reads it a second time.
    tombstone: bool,
    /// An automatic retry is armed, so this is not a terminal verdict -
    /// the original comes back through the queue in minutes.
    armed_auto_retry: bool,
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
            if !j.fail_kind().post_unavailable() {
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
            DupeExempt::Nobody,
        ) {
            Ok(Enqueued { nzo_id: id, .. }) => {
                info!(target: "failurelink", "{name}: queued a replacement ({id})")
            }
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
            d.hub.release_handles_for_dir(&dir);
            if let FilesGone::Kept(why) = remove_job_files(&dir, &name, filed, &tail) {
                // No NZB to offer: the delete handler removed this job's
                // spool copy when it took the row out of the queue, long
                // before the sidecar had finished with the directory.
                d.note_delete_kept(&name, &dir, &why, None);
            }
            d.reserved.lock_ok().remove(&dir);
        });
    }

    /// Remove ONE record's payload under the same custody the delete
    /// arms take, for a caller that settles a single record rather than
    /// a batch.
    ///
    /// Both facades' delete arms - `api::queue::payload`'s `delete` and
    /// `sabcompat::editqueue_delete::group_delete` - take this exact
    /// transaction, in batch form: reserve every doomed directory while
    /// the queue lock is still held, remove after it drops, and hand the
    /// one directory the prefetch sidecar is still writing into to
    /// [`Self::remove_after_sidecar_drain`] instead of removing it here.
    /// The batch shape is what the queue lock forces on them; the
    /// transaction is this, and it is the reservation that does the
    /// work. `dir_claim` consults `reserved` before it consults either
    /// store, precisely so a directory that no record names any more
    /// cannot be handed to a NEW job in the window between the record
    /// going and the files - a window that is a Trash call wide (bounded
    /// at 30 s per route, and macOS runs two).
    ///
    /// A single-record caller takes it here rather than growing a third
    /// choreography beside those two. Watchlist upgrade settlement WAS
    /// that third choreography, and it removed a superseded release's
    /// directory with no reservation at all (Codex sweep 24 Aug, F-05).
    ///
    /// `sidecar` is the [`Self::sidecar_owner`] snapshot, taken BEFORE
    /// the queue lock for the reason that function gives. `None` comes
    /// back when the sidecar owns this directory and the drain has taken
    /// the removal: there is no outcome to report yet, and a refusal
    /// that lands out there reaches the user through the kept-files
    /// notice rather than through this return.
    pub(in crate::serve) fn remove_files_in_custody(
        self: &Arc<Self>,
        sidecar: Option<&(String, Arc<AtomicBool>)>,
        nzo_id: &str,
        name: String,
        dir: std::path::PathBuf,
        filed: bool,
        tail: crate::smart::FiledTail,
    ) -> Option<FilesGone> {
        self.reserved.lock_ok().insert(dir.clone());
        if let Some((_, target)) = sidecar.filter(|(id, _)| id == nzo_id) {
            // Live writers. The removal is the drain's, and so is the
            // reservation it gives back - see the note on that function
            // for why the wait is unbounded rather than the minute it
            // used to be.
            self.remove_after_sidecar_drain(target.clone(), name, dir, filed, tail);
            return None;
        }
        let outcome = remove_job_files(&dir, &name, filed, &tail);
        self.reserved.lock_ok().remove(&dir);
        Some(outcome)
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
        // §129 1b(b): the STRIP still rides the queue payload above -
        // it is not a moment that scrolls past, it is a folder still on
        // disk and the page keeps it until the user dismisses it. What
        // moves here is the one-toast-each NUDGE towards that strip,
        // which is a moment, and which the page used to recover by
        // diffing the array against a seen-set of its own.
        //
        // Emitted only on the arm that actually raised a notice: the
        // dedupe above returns early, and re-announcing a path the ring
        // already holds is exactly what that dedupe exists to stop.
        self.life_emit(
            "job.delete_kept",
            json!({
                "name": name,
                "path": path.display().to_string(),
                "why": why,
                // What the page needs is whether the Retry button can
                // be offered at all, which is the same question the
                // strip row answers - not the spool path itself.
                "retry": nzb.is_some(),
            }),
        );
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
        self.hub.unpack.lock_ok().remove(id);
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
            self.hub.release_handles_for_dir(&out_dir);
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
            // `drop_spool` and not a raw unlink (sweep 9, finding 3):
            // a refusal here is the last thing standing between a
            // cancelled release and `recover_orphaned_spool` adopting
            // it at the next start. The helper renames out of the
            // adoptable `SABnzbd_nzo_nzbfast*.nzb` shape and, failing
            // that, empties the file so recovery skips it. The
            // Downloading arm has usually masked the name already, so
            // this is the leftover road where the request-time rename
            // was refused too - but that is a fault path, not a reason
            // to keep the one spelling that re-adopts.
            drop_spool(&nzb);
        }
    }

    /// M32: a FIRST failure with missing articles gets ONE
    /// automatic retry after a cooldown - propagation lag is a real
    /// cause of missing articles that clears on its own, and the
    /// journal makes the rerun fetch only what's still missing. Only
    /// transient shapes qualify: password and takedown verdicts don't,
    /// and nor does a post too old for propagation to explain it.
    ///
    /// The predicate itself is `will_auto_retry`, shared with
    /// `run_post_job_hooks_gen` so the report/re-grab side and the
    /// duplicate promotion below agree with what actually happens here.
    ///
    /// Stamps `auto_retry_at` and the reason token the drawer renders, and
    /// says so once in the log. The PREDICATE stays at the call site - the
    /// duplicate promotion below reads the same answer. Split out of
    /// `park_gen` (TODO 106), body verbatim.
    fn arm_auto_retry(&self, job: &Arc<Mutex<Job>>, id: &str) {
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
        let kind = job.lock_ok().fail_kind();
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
    ///
    /// **The demote arm's requeue is not free, and nothing here decides
    /// that** (TODO 309(d)). A job sent back deferred reruns from its
    /// journal through `get::plan::resume_map_admitted`, which stops
    /// mapping the replay in-stream once the journal's placed bytes
    /// exceed the held-span budget and extracts from volumes on disk
    /// instead - 2.53x payload of device I/O against 1.02x (TODO 94 A).
    /// The WATCHDOG weighs that before it ever sets `demote`
    /// (`serve/tasks/stall.rs`: `requeue_cost`, `slow_keeps_its_slot`),
    /// so by the time a job reaches here the cost is already spelled out
    /// in its `defer_reason`.
    pub(in crate::serve) fn park_gen(&self, job: Arc<Mutex<Job>>, gen0: Option<(u32, u64)>) {
        let (id, failed, key, nzb_path, demote, stale) = {
            let g = job.lock_ok();
            (
                g.nzo_id.clone(),
                g.state == JobState::Failed,
                g.dupe_key.clone(),
                // TODO 282 item 6: the promote scan compares posts, and
                // this is where the failed one's articles are read from.
                g.nzb_path.clone(),
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
        // §296: a job that ends FAILED never reaches the mover, so
        // nothing would ever reconcile what it published early - and two
        // episodes of a three-episode pack sitting in the completed
        // folder is precisely the partial an *arr imports as though the
        // job had worked. Take them back. A watchdog DEMOTE lands here
        // too and wants the same answer for a different reason: the
        // retry re-publishes whatever it re-verifies, so leaving the old
        // copies would have the move merge over them.
        //
        // The take is path arithmetic under the job lock; the unlinks
        // are outside it, like every other file removal on this path.
        if failed {
            let taken = {
                let mut g = job.lock_ok();
                self.early_take(&mut g)
            };
            crate::serve::earlyfile::early_unlink(&taken);
        }
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
        // Activity, §205's unpack counters and §129's tail-cancel die
        // with the row - BELOW the re-read, not above it, or the guard
        // cannot guard the one thing the comment above says it exists
        // for (sweep 4, M4c).
        self.hub.activity.lock_ok().remove(&id);
        self.hub.unpack.lock_ok().remove(&id);
        self.hub.tail_cancel.lock_ok().remove(&id);
        let tombstone = job.lock_ok().tombstone;
        // Watchdog demotion: back into the queue (deferred, at the end)
        // instead of history - the abort was ours, not a failure. The
        // journal keeps everything already landed, so the eventual rerun
        // fetches only what's still missing (and what THAT costs is
        // TODO 309(d), weighed before the flag is set - see the doc
        // comment above).
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
                g.clear_failure();
                // The evidence goes with the verdict it explained - a
                // re-queued job that fails again captures its own.
                g.clear_attempt_verdicts();
                g.demote = false;
                g.deferred = true;
                // The stamp goes on with the flag, never apart from it:
                // `deferred` survives the next run by design, so a row
                // that says nothing about WHEN is a verdict with no age
                // on it. The queue row prints this as "tried <t> ago".
                g.defer_at = unix_now().max(0) as u64;
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
        // Three answers, not two, and `park_prewrite` carries why: only
        // `Wrote` means a row is on disk to bury, and `Refused` is the
        // §158.7 window reopening rather than the demote it used to be
        // indistinguishable from.
        let prewrite = self.park_prewrite(&job, dropping, || prewrite_cost(&job));
        let filed_early = prewrite == HistWrite::Wrote;
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
        let publish = Some(self.add_lock.lock_ok());
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
        let armed_auto_retry = self.will_auto_retry(&job);
        if armed_auto_retry {
            self.arm_auto_retry(&job, &id);
        }
        // Re-read once more: the demote arm above returns, so this is the
        // first point the history/promotion decisions are actually taken.
        let verdict = ParkVerdict {
            failed,
            tombstone: job.lock_ok().tombstone,
            armed_auto_retry,
        };
        self.park_file_terminal(&job, &id, filed_early, verdict, publish);
        self.park_settle_spares(&job, &id, key, &nzb_path, verdict);
        // Coalesced: the record is already durable in history.jsonl (the
        // upsert above), and load_queue resolves a torn queue/history
        // pair in history's favour - the debounced rewrite only drops
        // the queue row.
        self.save_queue_soon();
        self.note_queue_idle();
    }

    /// File a parked job into whatever store its verdict sends it to, and
    /// let the directory deciders look again the moment it lands there.
    ///
    /// Split out of [`Self::park_gen`] under the size gate's 500-line
    /// function ceiling (31 Aug 2026), body verbatim - the same code
    /// motion [`Self::promote_held_alternative`] came out of, and for the
    /// same reason. Nothing else calls it: every gate it runs behind (the
    /// generation re-reads, the retain, the demote arm's early return)
    /// stays in `park_gen`, where the facts they read live.
    ///
    /// `publish` is the `add_lock` guard `park_gen` took before that
    /// retain, moved IN rather than re-taken here: the window it closes
    /// runs from the retain to the moment the record is visible in a
    /// store again, so the guard has to cross this seam. Each arm
    /// releases it the instant it has filed, which taking it here would
    /// make impossible to express.
    fn park_file_terminal(
        &self,
        job: &Arc<Mutex<Job>>,
        id: &str,
        filed_early: bool,
        verdict: ParkVerdict,
        mut publish: Option<std::sync::MutexGuard<'_, ()>>,
    ) {
        // §96.3: feed the per-target give-up breaker. Here because this
        // is where a failure becomes FINAL - a tombstone owes nobody
        // anything and an armed auto-retry means the story continues.
        if !verdict.tombstone {
            self.giveup_note_outcome(job, verdict.armed_auto_retry);
        }
        if !verdict.tombstone {
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
            //
            // `history_publish` and not a `let _ = history_upsert`: the
            // answer was dropped, and this brings the rescue AND the
            // `_if_present` guard this site never had - `publish` was
            // released above, so a delete can land right here and a raw
            // append would write the record back after its tombstone
            // (H6). `filed_cost` has the rest.
            self.history_publish(job, || filed_cost(job));
            // §76: the record is in history, so the media prober's final
            // on-disk pass has something to read. Owed HERE, as an event,
            // rather than inferred by that task noticing the job stop
            // downloading between two of its ticks: a job whose whole
            // download fits inside one tick is never seen running at all,
            // and used to reach history with no chip and no log line to
            // say why. A small post on a fast line is exactly that job.
            // Bound before the mailbox lock is taken, never inline: the
            // other producer (post-processing's re-judge) pushes while
            // holding the job guard, so a `mailbox.lock().push(job.lock())`
            // here would be that pair in the opposite order.
            let owed = job.lock_ok().nzo_id.clone();
            self.media_final_owed.lock_ok().push(owed);
            self.life_emit_parked(job);
            self.history_enforce_retention();
            if owes_move {
                self.mover_enqueue(job);
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
                // The code that classified the ABORT goes with the
                // sentence it explained (TODO 307's invariant): left
                // behind, fail_kind() reports this deletion as the
                // tail's verdict and altcand can offer a replacement
                // for a title the user just removed.
                g.fail_code = Some(FailKind::Local);
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
                let already = h.iter().any(|j| Arc::ptr_eq(j, job));
                if !already {
                    h.push(job.clone());
                }
                already
            };
            // Filed (or already present): the record is visible to
            // `dir_claim` again.
            publish.take();
            if !already {
                // The delete's OWN row - `deleted_cost` carries what a
                // dropped answer costs, which is more than one row.
                self.history_publish(job, || deleted_cost(job));
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
            //
            // Nothing here can be held back on a refusal - the payload
            // was removed above, on the strength of the user's delete -
            // so the answer is reported rather than acted on: what
            // survives is a record naming files that have gone, which is
            // exactly what the log line has to say.
            // `&[id.to_owned()]` rather than the `from_ref` this was
            // before the split: `id` is a `&str` parameter now, and one
            // String on a path that is already rewriting history.jsonl
            // costs nothing worth a `&String` parameter (`ptr_arg`).
            if !self.history_tombstone(&[id.to_owned()]) {
                error!(
                    target: "queue",
                    "{id}: the deleted job's history row could not be buried, so a \
                     restart brings it back - its files were already removed"
                );
            }
        }
        // The remaining arm (a tombstone with nothing prewritten) files
        // nothing either; make the release explicit before the promotion
        // scan below.
        drop(publish);
    }

    /// Settle what the finished job's held spares are for, and ask the
    /// hunt worker for a replacement when nothing was held.
    ///
    /// Split out of [`Self::park_gen`] under the size gate's 500-line
    /// function ceiling (31 Aug 2026), body verbatim. It runs AFTER
    /// [`Self::park_file_terminal`] has released `add_lock`, and the
    /// ordering is the point: `still_filed` asks whether the failure
    /// these two decisions are ABOUT is still in history, which is only a
    /// meaningful question once the record has been filed and the
    /// lifecycle event has gone out.
    fn park_settle_spares(
        &self,
        job: &Arc<Mutex<Job>>,
        id: &str,
        key: Option<String>,
        nzb_path: &Path,
        verdict: ParkVerdict,
    ) {
        // The original failed → promote its best held ALTERNATIVE (M14f).
        // Not while an automatic retry is armed: the original is coming
        // back through the queue in minutes, and starting the alternative
        // now downloads the same title twice. And not for a tombstone: the
        // "failure" there is the abort the user's own delete fired, so
        // promoting would start downloading the very title they cancelled.
        //
        // §282 item 8 needs to know whether anything WAS held, and it
        // has to ask BEFORE the promotion: the winner leaves priority
        // -3 and the runners-up are repointed at it, so the same
        // question answered afterwards answers about a different queue.
        // The harness's window: the record is in history, `job.failed`
        // has gone out, and nothing has been unpaused yet.
        #[cfg(test)]
        super::storecut::promote_gap(self);
        // Sweep 9, finding 5: is the failure the two decisions below
        // are ABOUT still in history? `tombstone` cannot answer that -
        // it is a statement about the QUEUE row, and the history row is
        // deleted through a different door entirely. Park has already
        // emitted `job.failed` by now, deliberately (the page pairs
        // that emit with the replacement one), so a subscriber acting
        // on it - an *arr script, a dashboard history delete - can
        // remove the record in the gap. The user then dismissed a
        // failure and watched the same title start downloading anyway:
        // as the promoted spare here, or as the hunt below.
        //
        // By pointer, the idiom `histstore`, `history` and the unlock
        // path already use: this is the same Arc park pushed, and a
        // delete removes it from the vector under the history lock, so
        // whichever committed second sees the other. Only ever
        // consulted under `failed && !tombstone`, which is the one road
        // that put the record there.
        let still_filed = self.history.lock_ok().iter().any(|j| Arc::ptr_eq(j, job));
        let mut spare_held = false;
        if verdict.failed
            && !verdict.tombstone
            && !verdict.armed_auto_retry
            && let Some(key) = key
        {
            if still_filed {
                spare_held = self.spare_held_for(id, &key);
                self.promote_held_alternative(job, id, &key, nzb_path);
            } else {
                // Dropped rather than merely skipped, because "the
                // owner is in neither store" is precisely the state
                // `drop_stranded_spares` exists to clear - reaching it
                // here just means the spares go now rather than at the
                // next sweep, and a PROMOTED row would be past that
                // sweep's reach anyway (it drops HELD rows only).
                // Retention cannot take this row: it ages from the
                // front and the push above is at the back, so a record
                // that has gone is somebody's delete.
                info!(
                    target: "queue",
                    "{id}: the failure was deleted from history while it \
                     was being parked, so its held alternative is \
                     dropped rather than started"
                );
                self.drop_spares_for(id);
            }
        }
        // TODO 282 item 5's other half: a job that COMPLETED (or that
        // the user deleted) has nothing left for a spare to be a spare
        // for, and a row this daemon added that outlives its reason is
        // §4b's junk queue arriving by a new road. An armed auto-retry
        // is neither - the job is coming back through the queue in
        // minutes and its spares must be waiting when it does.
        if (!verdict.failed || verdict.tombstone) && !verdict.armed_auto_retry {
            self.drop_spares_for(id);
        }
        // §282 item 8: the job is dead and NOTHING was held for it, so
        // ask the hunt worker whether a replacement can be found. It
        // refuses an *arr-origin job outright (item 9), and it costs one
        // relaxed load on an install that has not opted in.
        //
        // HELD, not PROMOTED, and the difference is item 19's doing. A
        // spare that exists but was not promoted because
        // `alt_auto_switch` is off is still the answer to this job: item
        // 12's notice offers it on a click, and hunting alongside it
        // would put a THIRD copy of one release in front of the user.
        //
        // `!armed_auto_retry` is the same guard the promotion takes, and
        // for the same reason: the original is coming back through the
        // queue in minutes, so this is not yet a terminal verdict. A
        // tombstone is the user's own delete, not a failure.
        //
        // `still_filed` for the reason given at the promotion above:
        // hunting a replacement for a failure the user has just deleted
        // from history puts a download in front of them for a job they
        // dismissed, which is the promotion's own bug reached by the
        // other road.
        if verdict.failed
            && !verdict.tombstone
            && !verdict.armed_auto_retry
            && !spare_held
            && still_filed
        {
            self.hunt_request(job);
        }
    }

    /// Is ANY spare still held against this job? §282 item 8's whole
    /// trigger: the hunt is what happens when nothing is.
    ///
    /// Separate from [`Self::promote_held_alternative`] rather than a
    /// value it returns, because the two questions differ the moment
    /// `alt_auto_switch` is off (item 19): nothing is promoted, and a
    /// spare is still held for item 12's notice to offer on a click.
    /// Hunting then would put a THIRD copy of one release in front of
    /// the user.
    ///
    /// **THAT CLAIM WAS UNTRUE FROM THE DAY IT WAS WRITTEN, AND §284
    /// MADE IT TRUE.** The notice it names was drawn on the QUEUE row,
    /// and this function runs inside the park that takes the queue row
    /// away - so from the moment `alt_auto_switch` existed to be
    /// switched off, the spare this preserved sat paused at priority -3
    /// pointing at a history record that offered nothing, with
    /// `drop_spares_for` not running on a failure either. §284 put the
    /// offer on the history row (`altcand::parked_offer_json`, and
    /// `alt_switch`'s parked road), so the sentence above now describes
    /// something that happens.
    ///
    /// It also has to be asked BEFORE the promotion runs -
    /// the winner leaves priority -3 and the runners-up are repointed
    /// at it, so afterwards this answers about a different queue.
    ///
    /// A tombstoned row does not count: it is a spare the user has
    /// deleted, and the promotion's own re-check refuses it too.
    fn spare_held_for(&self, id: &str, key: &str) -> bool {
        self.queue.lock_ok().iter().any(|j| {
            let g = j.lock_ok();
            g.priority == -3 && g.paused && !g.tombstone && held_against(&g, id, key)
        })
    }

    /// §282 item 18 / M14f: the original finally failed, so promote the
    /// best spare held against it and SAY SO on the lifecycle ring.
    ///
    /// Split out of [`Self::park_gen`], which was 428 lines and within
    /// sight of the size gate's 500-line function ceiling; nothing else
    /// calls it and the gates it runs behind stay in `park_gen` where
    /// the tombstone and auto-retry facts live.
    ///
    /// Gated on the `alt_auto_switch` setting (§282 item 19), which
    /// ships ON: promoting a spare we already hold spends no bytes
    /// beyond the payload the user already asked for, so the away case
    /// gets a working download rather than a failed one. Switched OFF,
    /// the spare is not lost - it stays held at priority -3 for §282
    /// item 12's dashboard notice to offer on a click, **on the
    /// abandoned job's HISTORY row** (§284). The queue row that notice
    /// was originally drawn on is gone by the time anyone could read it:
    /// this function runs from `park_gen`, after the retain that takes
    /// it out of the queue. Until §284 that made this sentence a
    /// description of nothing - the spare was held, and no surface could
    /// offer it, promote it or drop it.
    ///
    /// **THE GATE REACHES FURTHER THAN §282, AND THAT IS THE ONE THING
    /// TO KNOW ABOUT IT.** M14f is older than every part of this
    /// section: a user who deliberately queued two NZBs of one release
    /// has always had the second run when the first failed, with no
    /// setting involved. Turning `alt_auto_switch` off now switches
    /// that off too, and it does so silently - the second row simply
    /// stays parked, which looks like nothing happening rather than
    /// like a setting taking effect. Deliberate, and the alternative
    /// was worse: gating only the §282 promotions would leave one of
    /// the two ways a held copy gets promoted without asking outside
    /// the switch that says it governs exactly that, and the shipped
    /// copy for the key ("when a download turns out to be one that
    /// cannot finish, start the best copy already being held for it")
    /// describes a failed job as squarely as it describes a terminal
    /// verdict. If this is ever reconsidered, reconsider it as a
    /// behaviour change to a shipped path and not as a default.
    ///
    /// **The event.** `job.switched` is a plain dotted `job.*` kind, so
    /// every wildcard webhook subscriber picks it up with no
    /// configuration (`hooks::wants_lifecycle`), and it carries what
    /// §282 item 18 asked for: what was abandoned (`replaces`,
    /// `replaces_name`), what replaced it (`nzo_id`, `name`), and why
    /// (`reason`, the failed job's own `fail_message`). The hunt half of
    /// that item is not emitted HERE because it is not this path's to
    /// emit: §282 section C landed the same day and `serve/hunt.rs`
    /// emits its own `job.replaced` when a search finds a replacement
    /// nobody held.
    ///
    /// **THAT CALL IS NOW MADE, and the answer is one payload shape
    /// across two kinds** (item 18, 24 Aug 2026). `job.replaced` keeps
    /// its own kind - a hunt spends NEW bytes and an indexer grab on a
    /// release the user never queued, where both doors here promote a
    /// copy already held, and `hooks::wants_lifecycle` matches a kind or
    /// a `prefix.*` and nothing in the body, so the kind is the only
    /// axis a target's `events` field can express that difference on.
    /// Its KEYS are now these keys exactly: `nzo_id`, `name`,
    /// `category`, `replaces`, `replaces_name`, `reason`, `by`. Change
    /// one of them here and change it there in the same commit; the
    /// argument, and the door-specific keys, are written up at the emit
    /// in `serve/hunt.rs`.
    ///
    /// **THIS IS NOT THE ONLY DOOR, and `by` is how a subscriber tells
    /// them apart.** `altcand::alt_switch` - item 12's "Switch to this
    /// copy" button - reaches the same outcome by hand and emits the
    /// same kind, so both carry `"by"`: `"auto"` here, `"user"` there.
    /// Until 24 Aug 2026 only this one emitted at all, and a target
    /// subscribed to `job.*` heard a bare `job.failed` when a person
    /// clicked - the same user-visible switch in a quieter vocabulary,
    /// and the one case where a switch is known for certain rather than
    /// inferred.
    ///
    /// `rank` IS THIS DOOR'S ONLY, and is omitted rather than nulled on
    /// the other. It reports which held spare `watchlist::quality_rank`
    /// picked; a clicked switch is the user overriding that choice, so
    /// there is no winning rank to report - and `by` already answers
    /// why the key is absent, which an explicit null would not (a
    /// subscriber that coerces cannot tell `null` from rank 0). Read
    /// `rank` only under `by == "auto"`.
    ///
    /// **THE DASHBOARD IS A THIRD CONSUMER, and has been since 24 Aug
    /// 2026.** `handleLifeEvents` in web/dashboard.html has one arm for
    /// `job.switched` and `job.replaced` together: it reads `by` (to
    /// stay silent on the clicked door, which `altSwitch()` already
    /// confirms), `replaces_name` and `name` for the sentence, and
    /// `replaces` for the click-through into the abandoned row's
    /// history drawer. It also uses the presence of a switch in the
    /// same event batch to suppress the `job.failed` alarm for the row
    /// this one replaces, which is why the two emits being back to back
    /// - `life_emit_parked` in `park_gen` and then this one - is a
    /// property the page relies on rather than an accident. That arm
    /// REPLACED a queue-snapshot diff (a page-side "this row stopped
    /// being a Duplicate" cue) which could name neither the abandoned
    /// release nor the reason and could not see a hunt at all; the
    /// retirement note is in `sndQueueEvents`. So the keys below have
    /// three readers, not two, and the third one ships user-visible
    /// copy in 27 catalogues.
    ///
    /// `by` is TOTAL across both kinds since item 18 closed, and it was
    /// scoped to this kind's two doors before that. Three values, one
    /// per door: `"auto"` here, `"user"` on the click, `"hunt"` on
    /// `job.replaced`. A subscriber that unions the two kinds therefore
    /// always has a "which door" answer, which was the whole complaint -
    /// under the old scoping, reading `by` over a `job.*` feed returned
    /// nothing for the one door the user did least to ask for. `"hunt"`
    /// is redundant with the kind, deliberately: a total key a consumer
    /// can read unconditionally is worth more than the byte it costs.
    fn promote_held_alternative(
        &self,
        failed: &Arc<Mutex<Job>>,
        id: &str,
        key: &str,
        nzb_path: &Path,
    ) {
        if !self.alt.auto_switch.load(Ordering::Relaxed) {
            return;
        }
        // §290 (Codex F-11). Held the whole way down, so the winner is
        // weighed and unpaused without a hunt or a click slipping a
        // second copy in between. Taken BEFORE any store lock, which is
        // the order every door takes (see `altspend`).
        let _gate = self.alt_gate();
        // §282 item 14's half, read off the FAILED record before
        // anything is promoted: the clause names it, and by the time the
        // winner is chosen the queue lock has been dropped and retaken a
        // world away. Read ONCE here rather than again at the emit, so
        // no job lock is held across `life_emit` (below). The event
        // carries the raw `fail_message` because it is what an operator
        // pastes into a bug report; the CLAUSE carries `why_from_fail`'s
        // stripped form, because a build stamp in the middle of
        // "replaced X because Y" is noise about the wrong build.
        let (failed_name, fail_message) = {
            let g = failed.lock_ok();
            (g.name.clone(), g.fail_message.clone())
        };
        let failed_why = crate::serve::altcand::why_from_fail(&fail_message);
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
        //
        // The spool path rides along for TODO 282 item 6: `spare`
        // reads both NZBs to refuse a candidate that is the SAME
        // POST as the job that just failed - a byte-different NZB
        // of identical articles, which fails identically and shows
        // the user the same failure twice. It also breaks a rank tie
        // toward a candidate on a different group and poster (item
        // 7). Both degrade to the pre-282 pure-rank pick when a
        // spool file cannot be read; see `spare::best_alternative`.
        let candidates: Vec<(Arc<Mutex<Job>>, String, PathBuf, u32)> = self
            .queue
            .lock_ok()
            .iter()
            .filter_map(|j| {
                let g = j.lock_ok();
                (g.priority == -3 && g.paused && held_against(&g, id, key)).then(|| {
                    (
                        j.clone(),
                        g.name.clone(),
                        g.nzb_path.clone(),
                        // §295: the prober now visits held rows, so a
                        // spare can carry a real verdict by the time it
                        // matters - here. The band outranks the quality
                        // rank inside `best_alternative`.
                        crate::health::promote_band(g.health.as_ref()),
                    )
                })
            })
            .collect();
        let named: Vec<(String, PathBuf, u32)> = candidates
            .iter()
            .map(|(_, n, p, b)| (n.clone(), p.clone(), *b))
            .collect();
        // §290 (F-11): the ceilings, at the one moment payload spend
        // begins. Built here rather than at the top because it reads the
        // failed row out of whichever store now has it, and `park_gen`
        // has only just finished deciding which that is.
        let ctx = self.alt_ctx(
            id,
            &failed_name,
            crate::serve::giveup::target_keys(&crate::wall::parse_release(&failed_name)),
        );
        let promoted = spare::best_alternative(nzb_path, &named).and_then(|(i, rank)| {
            let j = &candidates[i].0;
            // §290: the mechanism-wide ceilings, which this door
            // consulted NOWHERE until then - not the copy cap, not the
            // byte cap, not the metered rule - while being the only one
            // of the three that ships ON. With the shipped defaults
            // (hold 2, max_copies 2) the original failed, spare A was
            // promoted, A failed, and the repointed spare B started as a
            // THIRD copy of one release. `altcand::AltSettings` has
            // always documented both limits as governing "this whole
            // mechanism"; this is where that becomes true.
            //
            // The spare is left HELD on a refusal rather than dropped:
            // §284's parked offer draws it on the abandoned row's
            // history entry, so the answer degrades to the click, which
            // is §282's documented safe posture on any account type.
            // The job lock is taken and released on its own line - it
            // must NOT be held across `alt_admit`, which walks the
            // stores and takes job locks of its own.
            let want = j.lock_ok().total_bytes;
            if let Err(no) = self.alt_admit(&ctx, want, super::hunt::Trigger::Auto) {
                info!(
                    target: "queue",
                    "{id}: a copy is held for this download but was not started - {}",
                    no.why()
                );
                return None;
            }
            let mut g = j.lock_ok();
            // Re-check now that the queue lock has been dropped and
            // retaken a world away: a delete landing in the gap sets
            // tombstone, and promoting a just-deleted alternative
            // would start downloading the very title the user
            // cancelled.
            (g.priority == -3 && g.paused && !g.tombstone && held_against(&g, id, key)).then(|| {
                g.paused = false;
                g.priority = 0;
                // §282 item 14: the promotion is a SWITCH, and until now
                // it said so nowhere the user could read. What they saw
                // was a file arriving under a release name they never
                // clicked, with the row they did click sitting in
                // history saying only that it failed - which is a bug
                // report, not a feature. Stamp both halves: this row
                // records what it replaced and why, the failed row
                // records what replaced it (below), and
                // `altcand::switch_lines` is the one place every surface
                // reads them from.
                g.alt_from = id.to_string();
                g.alt_from_name = failed_name.clone();
                g.alt_why = failed_why.clone();
                info!(
                    target: "queue",
                    "{} promoted (best held duplicate of failed {id}, rank {rank})",
                    g.nzo_id
                );
                (g.nzo_id.clone(), g.name.clone(), g.category.clone(), rank)
            })
        });
        let Some((nzo_id, name, category, rank)) = promoted else {
            return;
        };
        // The spares that did NOT win are still held against a job
        // that has just left the queue, so nothing will ever park it
        // again and `held_against` can never match them. Point them
        // at the row that took its place, or a grab that held two
        // spares only ever tries one.
        self.repoint_spares(id, &nzo_id);
        // ...and the failed row learns what replaced it HERE, which is
        // after its own history upsert - the one fact about it that is
        // not known in time for that write. So it takes one more append,
        // and only when a promotion actually happened.
        // `_if_present` rather than `history_upsert`: a delete landing in
        // between must not resurrect the record. Through
        // `history_publish_change`, which is that call plus the rewrite
        // rescue and a sentence for the refusal that cannot be rescued -
        // the loss here is the ordinary one that helper is for, a field
        // the store's existing line simply does not carry.
        failed.lock_ok().alt_to_name = name.clone();
        self.history_publish_change(failed, "the alternative that replaced this job");
        // Last, and with no job lock held: `life_emit` takes the ring
        // lock and then offers the event to the webhook dispatcher, and
        // no job mutex may be held across either (the rule
        // `life_emit_parked` states for the same reason). The
        // announcement also follows the durable record rather than
        // racing it - a subscriber that reads history on the event finds
        // the switch already written.
        self.life_emit(
            "job.switched",
            json!({
                "nzo_id": nzo_id,
                "name": name,
                "category": category,
                "rank": rank,
                "replaces": id,
                "replaces_name": failed_name,
                "reason": fail_message,
                "by": "auto",
            }),
        );
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
    ///
    /// Idle is not answered by the queue alone: a post-processing tail
    /// leaves the walk's sight well before its `job.completed` is
    /// emitted, so the lane counter is half the question. The whole of
    /// that argument is at `Daemon::postproc_backlog`, and the retry
    /// that gets the suppressed edge said is `BacklogTicket`'s Drop.
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
        let quiet = !_q.iter().any(|j| {
            let g = j.lock_ok();
            matches!(g.state, JobState::Downloading | JobState::Finishing)
                || (g.state == JobState::Queued && !g.paused)
        });
        // The other half of the question, because the walk above cannot
        // see a tail for most of the time one owes its `job.completed`:
        // `run_tail` stamps the row `Completed` early, which matches no
        // arm up there, and `park_gen` then retains the row out of the
        // queue a hundred lines before it files the record into history
        // - a window in which the job is in NEITHER list.
        //
        // Under this hold, and AFTER the walk rather than before it,
        // which is what makes a Relaxed load enough. Every increment is
        // published to this thread by a lock it has just taken: for a
        // tail still in the queue, by the job mutex the walk took to
        // read its state (the lane's increments both sit on the far
        // side of a write that walk observes); for one already retained
        // out, by the queue mutex held here, which its park released.
        // Read FIRST, neither edge is in place yet and a stale zero
        // beside a fresh queue is representable.
        let idle = quiet && self.postproc_backlog.load(Ordering::Relaxed) == 0;
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

/// One directory a delete is about to remove, as the slow half needs to
/// see it: the stem its files on disk were built from, the directory,
/// whether the job was FILED into a shared library folder, and the tail
/// that tells a filed delete which episode in there is this record's.
type DoomedDir = (String, std::path::PathBuf, bool, crate::smart::FiledTail);

/// The BATCH form of [`Daemon::remove_files_in_custody`], for a caller
/// that settles a whole delete REQUEST rather than one record.
///
/// Same transaction, in two halves, and the halves are what the queue
/// lock forces rather than a taste for phases: a Trash call is bounded
/// at 30 s per route and macOS runs TWO of them (Finder, then
/// NSFileManager), so removing inside `q.retain` held the GLOBAL queue
/// lock for up to a minute on a headless mac or a share with no
/// .Trashes - pick_job, queue_json, save_queue and every *arr status
/// poll stalling behind it, and the *arr marking the client unhealthy.
/// [`Self::plan`] runs under the lock and does only what has to be
/// atomic with the row leaving the queue - the arm choice, the
/// RESERVATION, and the §296 path arithmetic - and [`Self::settle`]
/// does the slow half once the lock has dropped.
///
/// It is the reservation that carries the transaction. `dir_claim`
/// consults `reserved` before it consults either store, precisely so a
/// directory that no record names any more cannot be handed to a NEW job
/// in the window between the record going and the files - a window a
/// Trash call wide.
///
/// Both facade delete arms take it here - `api::queue::payload`'s
/// `m_queue` delete and `sabcompat::editqueue_delete::group_delete` -
/// rather than hand-copying the choreography a third time. That
/// hand-copy is the shape this repo keeps being bitten by, and
/// `group_delete` says so about ITSELF at its `owns_hub` block: the REST
/// path was fixed for that hazard, the JSON-RPC facade was a copy that
/// never got it, and which client type the user had configured in Sonarr
/// decided whether the bug was reachable.
///
/// It had happened AGAIN by the time this was extracted, in the very
/// commit that added the §296 arm (0e225e890, 25 Aug 2026). That commit
/// set out to reconcile early-published copies at three places - the
/// mover, the delete tombstone and `park_gen` - and wrote the take into
/// BOTH of `group_delete`'s arms but only the non-active arm of the REST
/// delete's. So a REST delete of a DOWNLOADING job left whatever it had
/// already published sitting in the completed folder until `park_gen`
/// reached its `if failed` arm, which is the DEFERRED removal (unbounded
/// on a hung NAS) and never fires at all for a job that does not end
/// `Failed` - while the identical delete through JSON-RPC took the
/// copies back at once. An *arr polling in that window imports a partial
/// as though the job had worked, which is the one outcome an early
/// publish must not be able to produce. Structural now: the take is the
/// first thing [`Self::plan`] does, before the `del_files` gate, so
/// neither facade can have it and the other not.
#[derive(Default)]
pub(in crate::serve) struct CustodyBatch {
    /// Directories to remove as soon as the queue lock is down.
    doomed: Vec<DoomedDir>,
    /// The one directory whose live writers are the prefetch sidecar's:
    /// removed only once that has wound down, by the drain, which also
    /// hands back its reservation.
    pending_sidecar: Vec<DoomedDir>,
    /// §296 destination copies of jobs that will never reach the mover.
    /// Path arithmetic under the queue lock, the unlinks in the slow
    /// half - a destination that has gone offline must not turn a delete
    /// into a stalled queue.
    early_gone: Vec<std::path::PathBuf>,
}

impl CustodyBatch {
    /// Phase one, UNDER the queue lock, once per record this request is
    /// taking out of the queue. Call it for EVERY hit row, files half or
    /// not: the §296 take is not gated on `del_files`, because with the
    /// files kept the whole payload is still in `out_dir` and the
    /// destination copies are a partial duplicate either way.
    ///
    /// Three arms past that gate, and the divider is who is still
    /// WRITING into the directory:
    ///
    /// * Live pipeline writers - `Downloading`, `Finishing`, or
    ///   `finalizing`. Removing now just lets the next positioned write
    ///   recreate the files and orphan them, so the removal is deferred
    ///   to `park()`, which runs after the fetch drains and releases the
    ///   reservation itself. `finalizing` is NOT covered by the state
    ///   test and is why it is asked separately: a Completed job whose
    ///   post-processing (unlock, rename, TV filing, NAS move) is still
    ///   running has left `Downloading`, so it used to take the plain arm
    ///   and `remove_dir_all` the very directory the mover was reading
    ///   from. The deferral is on those three ONLY, never on every
    ///   non-active state: a never-run `Queued` job has no tail, so
    ///   `park` would never fire and its files would never go at all.
    /// * The prefetch sidecar's own job - which is the exception that
    ///   rule leaves open, and it bit: a PREFETCHING job is `Queued` and
    ///   not `finalizing`, so it fell to the plain arm and had its
    ///   directory removed while the sidecar was still writing into it,
    ///   after which the next file's first article recreated it and laid
    ///   a fresh payload nothing named (M2). `park` is the wrong
    ///   destination too - the abort's ordinary outcome is the sidecar's
    ///   `Err` arm, which never parks - so this waits on the wind-down.
    /// * Everything else: removed by [`Self::settle`] below.
    ///
    /// The reservation is taken for all three, which is why it is one
    /// unconditional line at the top rather than a line inside each arm:
    /// the deferred arm needs it LONGEST (a tombstoned job is dropped
    /// rather than filed, so between the row going and `park()` running,
    /// `dir_claim` finds the directory in neither store and calls it
    /// free - and a re-add of the same release can be writing there when
    /// `park()` finally removes the whole tree).
    ///
    /// `sidecar` is the [`Daemon::sidecar_owner`] snapshot, taken BEFORE
    /// the queue lock for the reason that function gives: reading the
    /// sidecar mutex inside `q.retain` would take it under queue+job, a
    /// lock edge nothing else in the daemon has.
    pub(in crate::serve) fn plan(
        &mut self,
        d: &Daemon,
        g: &mut Job,
        sidecar: Option<&(String, Arc<AtomicBool>)>,
        del_files: bool,
    ) {
        self.early_gone.extend(d.early_take(g));
        if !del_files {
            return;
        }
        d.reserved.lock_ok().insert(g.out_dir.clone());
        if matches!(g.state, JobState::Downloading | JobState::Finishing) || g.finalizing {
            g.del_on_drop = true;
            return;
        }
        let stem = filed_stem(g).to_string();
        let tail = delete_tail(g, || d.job_suffix(&stem));
        let entry = (stem, g.out_dir.clone(), g.filed, tail);
        if sidecar.is_some_and(|(id, _)| *id == g.nzo_id) {
            self.pending_sidecar.push(entry);
        } else {
            self.doomed.push(entry);
        }
    }

    /// Phase two, once the queue lock has DROPPED: the slow half.
    ///
    /// Every reservation is released AFTER the whole batch, never per
    /// entry. `reserved` is a set, so two entries naming one directory
    /// are one member: releasing after the first would unreserve a
    /// directory a later entry has not reached yet, and the gap is a
    /// whole Trash call wide.
    ///
    /// `held` is the spool copies `park_or_drop_spool` set aside for the
    /// records whose removal may be refused - a notice's "download it
    /// again" needs that NZB, and everything still held afterwards
    /// belongs to a directory that went cleanly and so goes.
    pub(in crate::serve) fn settle(
        self,
        d: &Arc<Daemon>,
        sidecar: Option<&(String, Arc<AtomicBool>)>,
        held: &mut std::collections::HashMap<std::path::PathBuf, Vec<std::path::PathBuf>>,
    ) {
        let reserved_dirs: Vec<std::path::PathBuf> = self
            .doomed
            .iter()
            .map(|(_, dir, _, _)| dir.clone())
            .collect();
        crate::serve::earlyfile::early_unlink(&self.early_gone);
        let mut kept: Vec<(String, std::path::PathBuf, String)> = Vec::new();
        for (name, dir, filed, tail) in self.doomed {
            d.hub.release_handles_for_dir(&dir);
            if let FilesGone::Kept(why) = remove_job_files(&dir, &name, filed, &tail) {
                kept.push((name, dir, why));
            }
        }
        {
            let mut r = d.reserved.lock_ok();
            for dir in &reserved_dirs {
                r.remove(dir);
            }
        }
        // The row is gone from the queue either way - that is what was
        // asked for and it worked. What did NOT work was the files half,
        // and with the row went the only place the user could see this
        // download named.
        note_kept_files(d, kept, held);
        // The sidecar's job waits for the sidecar. Its own reservation is
        // released by the drain, not by the batch above - the removal is
        // still ahead of it.
        if let Some((_, target)) = sidecar {
            for (name, dir, filed, tail) in self.pending_sidecar {
                d.remove_after_sidecar_drain(target.clone(), name, dir, filed, tail);
            }
        }
    }
}

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

// §290 (Codex F-11): the ceilings the automatic promotion now consults.
// A separate file under the size gate, and a CHILD of this module so it
// can reach `promote_held_alternative`, which nothing outside calls.
#[cfg(test)]
#[path = "daemon_park_spend_tests.rs"]
mod daemon_park_spend_tests;

#[cfg(test)]
mod park_custody_tests {
    use super::*;
    use crate::serve::testutil::test_daemon;

    /// A queue row as `CustodyBatch::plan` needs to see it, with one
    /// file already published to the completed folder.
    ///
    /// The state is stamped after the parse rather than through it:
    /// `job_from_json` restores a record caught mid-download as `Queued`
    /// on purpose (it goes back through the scheduler), and the live
    /// state is exactly what the deferral asks about.
    fn early_job(dir: &std::path::Path, state: JobState) -> Arc<Mutex<Job>> {
        let out = dir.join("out").join("Pack.S01");
        let job = Arc::new(Mutex::new(
            job_from_json(&serde_json::json!({
                "nzo_id": "nzo-custody-1",
                "name": "Pack.S01",
                "nzb_path": dir.join("spool").join("Pack.S01.nzb").to_string_lossy(),
                "out_dir": out.to_string_lossy(),
                "state": "Queued",
            }))
            .expect("job"),
        ));
        {
            let mut g = job.lock_ok();
            g.state = state;
            g.early_published = vec![crate::serve::earlyfile::EarlyFile {
                name: "ep1.mkv".into(),
                len: 1 << 20,
                mtime_ns: 0,
                nzf_id: String::new(),
                // Pre-dest record: the take derives the destination,
                // which is the configuration this rig sets up.
                dest: None,
            }];
        }
        job
    }

    /// A delete of a job that is still DOWNLOADING takes back whatever
    /// it had already published at the destination, right here, rather
    /// than leaving it to `park_gen`.
    ///
    /// The divergence this pins is the one that motivated the shared
    /// batch. 0e225e890 wrote the §296 take into BOTH arms of the
    /// JSON-RPC `group_delete` and only the non-active arm of the REST
    /// delete, so the identical cancel left episodes sitting in the
    /// completed folder or did not, according to which client type the
    /// user had configured. `park_gen`'s own take is NOT the same
    /// promise: it is the deferred removal, and it never fires at all
    /// for a job that does not end `Failed`.
    #[test]
    fn an_active_delete_takes_its_early_copies_back_at_once() {
        let dir = std::env::temp_dir().join(format!("nzbfast-custody-a-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let d = test_daemon(&dir);
        let dest = dir.join("completed");
        *d.move_completed.write_ok() = Some(dest.clone());

        let job = early_job(&dir, JobState::Downloading);
        let mut batch = CustodyBatch::default();
        batch.plan(&d, &mut job.lock_ok(), None, true);

        assert_eq!(
            batch.early_gone,
            vec![dest.join("Pack.S01").join("ep1.mkv")],
            "the destination copy of a job being cancelled mid-download was left behind"
        );
        assert!(
            job.lock_ok().early_published.is_empty(),
            "the record must stop naming copies this delete has taken back"
        );
        assert!(
            job.lock_ok().del_on_drop,
            "a job with live pipeline writers defers its removal to park()"
        );
        assert!(
            batch.doomed.is_empty() && batch.pending_sidecar.is_empty(),
            "nothing may remove a directory a running pipeline is still writing into"
        );
        assert!(
            d.reserved.lock_ok().contains(&job.lock_ok().out_dir),
            "the deferred arm needs the reservation LONGEST - park() releases it"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ...and the take is not gated on the files half. With the files
    /// KEPT the whole payload is still in `out_dir`, so a copy left at
    /// the destination is a partial duplicate either way, and an *arr
    /// that imports it has imported a download the user stopped.
    ///
    /// `GroupParkDelete` is the verb that reaches this, and the REST
    /// delete without `del_files=1` is the other.
    #[test]
    fn the_early_take_is_not_gated_on_the_files_half() {
        let dir = std::env::temp_dir().join(format!("nzbfast-custody-k-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let d = test_daemon(&dir);
        let dest = dir.join("completed");
        *d.move_completed.write_ok() = Some(dest.clone());

        let job = early_job(&dir, JobState::Queued);
        let mut batch = CustodyBatch::default();
        batch.plan(&d, &mut job.lock_ok(), None, false);

        assert_eq!(
            batch.early_gone,
            vec![dest.join("Pack.S01").join("ep1.mkv")],
            "a files-KEPT delete still owes the destination copy back"
        );
        assert!(
            d.reserved.lock_ok().is_empty(),
            "a delete that removes no files must reserve no directory"
        );
        assert!(
            !job.lock_ok().del_on_drop,
            "a files-KEPT delete must not arm park's removal"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The slow half removes the directory and hands the reservation
    /// back, and it hands it back only once the WHOLE batch is through.
    #[test]
    fn settle_removes_the_directory_and_releases_its_reservation() {
        let dir = std::env::temp_dir().join(format!("nzbfast-custody-s-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let d = test_daemon(&dir);

        let job = early_job(&dir, JobState::Queued);
        let out = job.lock_ok().out_dir.clone();
        std::fs::create_dir_all(&out).expect("payload dir");
        std::fs::write(out.join("ep1.mkv"), b"payload").expect("payload");

        let mut batch = CustodyBatch::default();
        batch.plan(&d, &mut job.lock_ok(), None, true);
        assert!(
            d.reserved.lock_ok().contains(&out),
            "the reservation goes up while the row is still leaving the queue"
        );

        let mut held = std::collections::HashMap::new();
        batch.settle(&d, None, &mut held);

        assert!(!out.exists(), "the payload was not removed");
        assert!(
            d.reserved.lock_ok().is_empty(),
            "a directory that is gone must not stay reserved - `dir_claim` would \
             refuse a re-add of the same release forever"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

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

    /// Sweep 9, finding 2: a HISTORY-LESS delete of a FINISHING job
    /// defers its files to park, so the spool copy has to reach park
    /// too - a refusal there is the only thing the user ever sees, and
    /// "download it again" is the only way back to the release.
    ///
    /// The Downloading arm masks the copy and leaves it for park. A
    /// Finishing (or `finalizing`) job is not `active`, so it took the
    /// non-active arm, which HELD the NZB for a kept-files notice this
    /// request will never raise - the files have not been attempted
    /// yet - and `note_kept_files` then unlinked it as leftover from a
    /// removal that went cleanly. Park's own refusal, minutes later,
    /// handed `note_delete_kept` a path that was already gone.
    ///
    /// The test above cannot see this: it is a `delete_status`
    /// history-KEEPING delete, whose spool copy is kept for the retry
    /// and never goes near `hold_or_drop_spool`.
    #[test]
    fn a_finishing_jobs_deferred_delete_still_has_an_nzb_to_offer() {
        let dir = std::env::temp_dir().join(format!("nzbfast-parkfin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let d = test_daemon(&dir);

        // The ADOPTABLE name, because that is what `enqueue_as` writes
        // and what the masking is about: a copy left under this shape
        // with no record naming it is re-downloaded at the next start.
        let spool_nzb = d
            .spool
            .join("SABnzbd_nzo_nzbfast4242-Finishing.Release.nzb");
        std::fs::write(&spool_nzb, NZB).expect("spool copy");
        // The same cheap honest refusal the test above uses.
        let out = dir.join("Finishing.Release");
        std::fs::write(&out, b"not a directory").expect("blocker");

        let job = Arc::new(Mutex::new(
            job_from_json(&serde_json::json!({
                "nzo_id": "SABnzbd_nzo_nzbfast4242",
                "name": "Finishing.Release",
                "nzb_path": spool_nzb.to_string_lossy(),
                "out_dir": out.to_string_lossy(),
                "state": "Finishing",
            }))
            .expect("job"),
        ));
        // The request half, in the order `m_queue`'s delete arm runs it
        // for a Finishing row with `del_files=1` and no history status:
        // tombstone, settle the spool, defer the files to park, then
        // drain the holds with no refusal to pair them against.
        let mut held = std::collections::HashMap::new();
        {
            let mut g = job.lock_ok();
            g.tombstone = true;
            g.del_on_drop = true;
            park_or_drop_spool(&mut g, true, true, &mut held);
        }
        note_kept_files(&d, Vec::new(), &mut held);
        let carried = job.lock_ok().nzb_path.clone();
        assert!(
            carried.exists(),
            "the request destroyed the copy park is about to need: {}",
            carried.display()
        );
        assert!(
            !spool_nzb.exists(),
            "it must not sit under the adoptable name - a kill before park would re-download it"
        );

        d.queue.lock_ok().push_back(job.clone());
        d.park_gen(job.clone(), None);

        let note = d
            .delete_kept
            .lock_ok()
            .front()
            .cloned()
            .expect("the refused removal must raise a kept-files notice");
        assert!(
            !note.nzb.is_empty(),
            "the refusal had no NZB to offer - the user cannot get the release back"
        );
        assert!(
            std::path::Path::new(&note.nzb).exists(),
            "the notice names a file that is gone: {}",
            note.nzb
        );
        let bytes = std::fs::read(&note.nzb).expect("the offer's NZB read");
        d.enqueue(
            &bytes,
            "Finishing.Release",
            "",
            -100,
            None,
            None,
            "test",
            true,
        )
        .expect("\"download it again\" must parse and enqueue");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Sweep 9, finding 3: park's own last unlink is a `drop_spool`,
    /// not a raw `remove_file`.
    ///
    /// The record is gone durably by the time this runs, so a survivor
    /// under the adoptable `SABnzbd_nzo_nzbfast*.nzb` name is
    /// re-enqueued at the next start - the release the user cancelled
    /// downloads again. `drop_spool` renames it out of that shape and,
    /// failing that (a read-only spool DIRECTORY refuses the rename for
    /// the same reason it refused the unlink), empties the file, which
    /// recovery skips. The raw call here had neither resort.
    ///
    /// The fault path this closes is narrow, and named rather than
    /// hidden: the Downloading arm has usually masked the name at
    /// request time already, so reaching an adoptable copy here means
    /// that rename was refused too. Narrow is not the same as unwritten.
    #[cfg(unix)]
    #[test]
    fn park_does_not_leave_a_refused_unlink_under_the_adoptable_name() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("nzbfast-parkrefuse-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let d = test_daemon(&dir);

        let spool_nzb = d
            .spool
            .join("SABnzbd_nzo_nzbfast7373-Cancelled.Release.nzb");
        std::fs::write(&spool_nzb, NZB).expect("spool copy");
        // A control of the same shape under an unknown id, written
        // before the directory goes read-only: without it this would
        // pass against a recovery that adopts nothing at all.
        let control = d.spool.join("SABnzbd_nzo_nzbfast7374-Other.Release.nzb");
        let other = String::from_utf8_lossy(NZB).replace("one@x", "two@x");
        std::fs::write(&control, other).expect("control copy");

        let job = Arc::new(Mutex::new(
            job_from_json(&serde_json::json!({
                "nzo_id": "SABnzbd_nzo_nzbfast7373",
                "name": "Cancelled.Release",
                "nzb_path": spool_nzb.to_string_lossy(),
                "out_dir": dir.join("Cancelled.Release").to_string_lossy(),
                "state": "Failed",
            }))
            .expect("job"),
        ));
        // History-less and tombstoned is what makes park the last thing
        // naming this file. No `del_on_drop`: the spool half runs
        // either way, and a deferred file removal would only add noise.
        job.lock_ok().tombstone = true;

        let was = std::fs::metadata(&d.spool)
            .expect("spool")
            .permissions()
            .mode();
        std::fs::set_permissions(&d.spool, std::fs::Permissions::from_mode(0o555)).expect("chmod");
        d.spend_deferred_delete(&job);
        std::fs::set_permissions(&d.spool, std::fs::Permissions::from_mode(was))
            .expect("chmod back");
        assert!(
            spool_nzb.exists(),
            "the fault under test is an unlink that was REFUSED"
        );

        assert_eq!(
            d.recover_orphaned_spool(),
            1,
            "only the control is an orphan - the cancelled release came back"
        );
        let back: Vec<String> = d
            .queue
            .lock_ok()
            .iter()
            .map(|j| j.lock_ok().nzo_id.clone())
            .collect();
        assert!(
            !back.contains(&"SABnzbd_nzo_nzbfast7373".to_string()),
            "the cancelled release was re-adopted: {back:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
