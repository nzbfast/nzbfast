//! §129 perf lane: the post-processing lane.
//!
//! The download worker used to hold the slot hostage to the PREVIOUS
//! job's tail: `prev_tail.await` meant job N+1's drain could not hand
//! the line to job N+2 until job N's repair/unpack/move finished, so
//! consecutive damaged or compressed jobs serialized completely (the
//! 8 Aug 2026 queue-continuity and profiling rounds are the
//! evidence). This module generalizes "at most one outstanding tail the
//! worker eventually blocks on" into a bounded lane the worker never
//! blocks on, except for honest backpressure.
//!
//! Contract, in one sentence: a job's ticket is in the lane if and only
//! if the job sits in the queue list as `Finishing` - tickets enter at
//! net-drain (where `net_done` fires today, AFTER the worker's
//! singleton accounting) and leave only via `park`.
//!
//! What the lane does NOT do: touch anything inside `get_with_progress`.
//! The engine's own tail (settle, repair, unpack, the §100 journal
//! handshake, §101's gates) keeps its exact ordering because it lives
//! inside the fetch task, which [`run_tail`] merely awaits from a
//! different place than the old inline closure did.
//!
//! Kill-switch: `NZBFAST_POSTPROC_INLINE=1` forces width 1 AND
//! worker-blocking submission - byte-for-byte the old scheduling
//! envelope, kept as a bisection tool.

use super::*;
use std::sync::atomic::AtomicUsize;

/// Post-processing longer than this gets a line in the log naming what
/// it cost. Two minutes: past any plausible unlock probe, identity
/// lookup or sweep, and comfortably inside what a real repair or a
/// large disk unpack is allowed to spend without comment.
const TAIL_SLOW_SECS: f64 = 120.0;

/// Test seam: [`run_tail`] trips it once the download task has resolved
/// and before the tail's FIRST mutation of the record - the window a
/// delete-then-retry lands in. Keyed by nzo_id so a lane tail belonging
/// to some other test can never wander into a two-party barrier that is
/// not its own. Same two-stage shape as `daemon_park::PARK_GEN_BARRIER`:
/// first barrier says the window is open, second says the test has
/// staged its retry and releases it.
#[cfg(test)]
pub(in crate::serve) static TAIL_GEN_BARRIER: Mutex<
    Option<(String, Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
> = Mutex::new(None);

/// Test seam: the lane supervisor trips it after `submit` has marked the
/// job `Finishing` and sampled the generation, and BEFORE it waits for a
/// lane slot - the interval `TAIL_GEN_BARRIER` cannot reach, because
/// that one opens inside `run_tail`, long after the two unbounded waits
/// this seam covers (the run permit at width 2, and the oracle fold on
/// the index write mutex). Same two-stage shape and the same nzo_id key
/// as `TAIL_GEN_BARRIER`: an unkeyed global barrier does not fail the
/// parallel bin run, it HANGS it (15 Aug, twice).
#[cfg(test)]
pub(in crate::serve) static SUBMIT_GEN_BARRIER: Mutex<
    Option<(String, Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
> = Mutex::new(None);

/// Everything the old inline tail closure captured, as a named ticket.
/// The worker builds it between `net_rx` and lane submission, after the
/// per-job accounting that must read the hub singletons before the next
/// job resets them (quota, usage, reliability, oracle drain, the
/// verifier/extractor snapshots).
pub(super) struct PostprocTicket {
    pub(super) job: Arc<Mutex<Job>>,
    /// The running engine task - settle, repair, unpack, nested pass
    /// all happen inside it. The lane awaits it; nothing reorders it.
    pub(super) fetch: tokio::task::JoinHandle<Result<()>>,
    /// Snapshotted pre-handoff: still THIS job's, even after the next
    /// job swaps the hub's slot.
    pub(super) verifier: Option<Arc<nzbkit::live::LiveVerifier>>,
    pub(super) shaper: Option<Arc<nzbkit::extract::Extractor>>,
    pub(super) log_mark: u64,
    pub(super) dl_bytes: u64,
    pub(super) dl_secs: f64,
    pub(super) on_disk_bytes: u64,
    pub(super) index_job_guard: IndexJobGuard,
    /// M29 oracle samples the runner drained off the hub for this job.
    /// Ingested here rather than there: the fold takes the index write
    /// mutex, and the runner must never wait on it.
    #[cfg(feature = "indexer")]
    pub(super) oracle_samples: Vec<nzbkit::oracle::Sample>,
}

/// The bounded lane. Width says how many tails may RUN at once; the
/// backpressure threshold (`saturated`, at 2x width of running plus
/// waiting tickets) is what keeps a fast line over a slow disk honest -
/// the worker stops picking new jobs with a stated reason instead of
/// filling the disk with undone unpacks.
pub(super) struct PostprocLane {
    d: Arc<Daemon>,
    width: usize,
    inline: bool,
    /// RUN permits (fair FIFO): a submitted ticket waits here until a
    /// lane slot frees. Admission order is submission order.
    slots: Arc<tokio::sync::Semaphore>,
    /// Tickets submitted and not yet parked (running + waiting).
    /// Shared with the daemon (`Daemon::postproc_backlog`), which is
    /// where `note_queue_idle` reads it: the lane belongs to the runner,
    /// so a counter owned here would be unreachable from the emit.
    backlog: Arc<AtomicUsize>,
}

impl PostprocLane {
    pub(super) fn new(d: Arc<Daemon>) -> Self {
        let inline = std::env::var("NZBFAST_POSTPROC_INLINE").is_ok_and(|v| v == "1");
        let width = if inline {
            1
        } else {
            (d.postproc_jobs.load(Ordering::Relaxed) as usize).clamp(1, 4)
        };
        if inline {
            info!(
                target: "lane",
                "NZBFAST_POSTPROC_INLINE=1 - post-processing runs inline \
                 (width 1, the worker blocks on each tail)"
            );
        }
        PostprocLane {
            backlog: d.postproc_backlog.clone(),
            d,
            width,
            inline,
            slots: Arc::new(tokio::sync::Semaphore::new(width)),
        }
    }

    pub(super) fn backlog(&self) -> usize {
        self.backlog.load(Ordering::Relaxed)
    }

    /// Take the lane's custody of a job BEFORE its terminal state is
    /// stamped, for the three runner arms that end a job without ever
    /// starting the pipeline.
    ///
    /// [`Self::submit`] needs no such thing: the row it takes is
    /// `Downloading` right up to the hold that marks it `Finishing`, so
    /// the queue walk in `note_queue_idle` covers the hand-over with no
    /// gap. Those arms stamp `Failed` (or `Completed`) on a row that is
    /// then neither busy in that walk nor yet counted here, and a
    /// concurrent park landing in between would announce the drain over
    /// a job whose `job.failed` is still owed. Small window, same defect
    /// as the two the counter exists for; reserving first removes it
    /// rather than narrowing it.
    pub(in crate::serve) fn reserve(&self) -> BacklogTicket {
        self.backlog.fetch_add(1, Ordering::Relaxed);
        BacklogTicket {
            backlog: self.backlog.clone(),
            cap: self.cap(),
            d: self.d.clone(),
        }
    }

    /// The backpressure bound: running + waiting at twice the width.
    pub(super) fn cap(&self) -> usize {
        self.width * 2
    }

    pub(super) fn saturated(&self) -> bool {
        self.backlog() >= self.cap()
    }

    /// Hand one finished download's tail to the lane. Marks the job
    /// `Finishing` (the moment it stops being a download) and returns
    /// immediately - unless the inline kill-switch is set, in which
    /// case this awaits the whole tail like the old scheduler did.
    pub(super) async fn submit(&self, t: PostprocTicket) {
        // The round of this record's life the whole tail belongs to,
        // sampled under the SAME hold that marks it Finishing - i.e. at
        // the instant the lane takes custody.
        //
        // It used to be sampled inside `run_tail`, after two unbounded
        // waits: the run permit (width 2 by default, so a third finished
        // job parks here behind two unpacks) and the M29 oracle fold,
        // which takes the index write mutex - the same mutex a retention
        // reap has held for hours. A delete verb files a `Finishing` job
        // into history and a retry of that row re-queues the SAME Arc one
        // generation on; landing in either wait made gen0 the RETRY's
        // generation, so every fence below it - the verdict, the stats,
        // finalize, the hooks, park - passed happily and did to the live
        // retry exactly what read-only sweep 2's H1 fence exists to stop
        // (Codex sweep 3, H1). The fence was at the wrong end of the wait.
        let gen0 = {
            let mut j = t.job.lock_ok();
            j.state = JobState::Finishing;
            // §129 4a: the per-stage transition the schema promises -
            // the download is done, the tail (verify remainder, unlock,
            // rename, move, scripts) begins.
            self.d.life_emit(
                "job.finishing",
                json!({
                    "nzo_id": j.nzo_id,
                    "name": j.name,
                    "category": j.category,
                }),
            );
            Daemon::record_generation(&j)
        };
        // Coalesced: a crash before the debounced write lands restores
        // the job from an OLDER snapshot, which the wildcard state arm
        // reads as Queued either way, and the journal replays the
        // network phase for free. What the deferral buys is not writing
        // a 14,500-job file four times per completion (issue #38).
        self.d.save_queue_soon();
        self.backlog.fetch_add(1, Ordering::Relaxed);
        let d = self.d.clone();
        let slots = self.slots.clone();
        let ticket = BacklogTicket {
            backlog: self.backlog.clone(),
            cap: self.cap(),
            d: self.d.clone(),
        };
        let job = t.job.clone();
        // The outer task is the per-job supervisor: it owns the lane
        // slot, catches a panicked tail (the inner JoinHandle surfaces
        // it) and guarantees the job record cannot vanish - only `park`
        // removes it from the queue list, and every arm below ends in
        // `park`.
        let supervisor = tokio::spawn(async move {
            // The count comes down when the ticket drops, wherever that
            // happens - end of this body, a panic in the crashed-tail
            // arm, the semaphore expect, or the task being dropped at
            // shutdown. The slot permit is already RAII; a decrement
            // that ran only on the happy path leaked once per panicked
            // park, and cap() leaks left saturated() true over an idle
            // daemon until restart.
            let _ticket = ticket;
            #[cfg(test)]
            {
                // The id is read BEFORE the seam lock, like
                // `daemon_park`'s: a job lock taken under the seam guard
                // orders the two the other way round from every other
                // reader of this record.
                let id = job.lock_ok().nzo_id.clone();
                let seam = SUBMIT_GEN_BARRIER
                    .lock_ok()
                    .clone()
                    .filter(|(k, _, _)| *k == id);
                if let Some((_, open, release)) = seam {
                    open.wait();
                    release.wait();
                }
            }
            let _slot = slots
                .acquire_owned()
                .await
                .expect("the lane semaphore is never closed");
            let tail = tokio::spawn(run_tail(d.clone(), t, gen0));
            if let Err(e) = tail.await {
                // Fenced like every other write this tail owns: the
                // crash arm files Failed onto the record, and if the
                // record was deleted and retried while the tail ran that
                // record now belongs to a live download.
                if file_crashed_tail(&job, &e, Some(gen0)) {
                    d.run_post_job_hooks_gen(&job, Some(gen0));
                }
                d.park_gen(job, Some(gen0));
            }
        });
        if self.inline {
            let _ = supervisor.await;
        }
    }

    /// Hand the lane a job that finished WITHOUT a download: the
    /// post-job hooks in the order `park` needs them, then `park`,
    /// off the caller's thread. Returns as soon as the tail is
    /// queued.
    ///
    /// The queue runner has three arms that end a job before the
    /// pipeline ever starts - the metadata-only library pick, the
    /// §138 give-up on a post no server carries, and the opt-in
    /// pre-flight Impossible verdict - and they owe history the same
    /// ordering every other completion owes: the post-processing
    /// script has to be FINISHED before the row appears, because the
    /// word in that row (`Completed`, and `Failed` just as much) is
    /// what a SAB client acts on. See
    /// [`Daemon::run_post_job_hooks_before_park`] for why that word is
    /// a contract rather than a status line.
    ///
    /// What the runner cannot do is await it in place: those arms run
    /// on the picker's own loop, so a user script would stall every
    /// other job in the queue for its whole run - up to
    /// `script_timeout_secs`, an hour by default. This is where the
    /// difference is paid instead. A tail here costs exactly what a
    /// download's tail costs: one lane slot, one unit of backlog, and
    /// therefore the lane's own backpressure once the tails outnumber
    /// the width - so a slow script spends POST-PROCESSING capacity,
    /// with the runner stating the reason, rather than queue capacity
    /// with no reason stated at all. That is the whole point of the
    /// lane existing.
    ///
    /// Two things it deliberately does NOT do that [`Self::submit`]
    /// does. It does not mark the job `Finishing`: the terminal state
    /// is already decided and set, `resolve_scripts` and the SAB_*
    /// environment are read FROM it, and a job that reads Finishing
    /// while its script runs would hand that script the wrong answer.
    /// And it emits no `job.finishing` lifecycle event, because no
    /// download stage ended here - there was none.
    ///
    /// A crash inside this window is already answered: the queue row
    /// is terminal, and `restore_records` routes a terminal queue row
    /// into history on the next start (losing the hooks, which it
    /// says).
    ///
    /// The unit of backlog is the caller's to take, through
    /// [`Self::reserve`], and it must be taken BEFORE the terminal
    /// state is stamped - see there.
    pub(super) async fn submit_hooks_only(&self, job: Arc<Mutex<Job>>, ticket: BacklogTicket) {
        // The fence, taken at the handoff. These arms used to park on
        // the very next statement, where nothing could get between
        // them and no fence was needed; a tail that can now run for an
        // hour is exactly the long-running caller `park_gen` grew its
        // generation check for - a delete verb files the row from
        // under it, a retry re-queues the same Arc, and an unfenced
        // park would consume the button the user just pressed.
        let gen0 = Some(Daemon::record_generation(&job.lock_ok()));
        let d = self.d.clone();
        let slots = self.slots.clone();
        let supervisor = tokio::spawn(async move {
            let _ticket = ticket;
            let _slot = slots
                .acquire_owned()
                .await
                .expect("the lane semaphore is never closed");
            // Same supervisor shape as a download's tail, for the same
            // reason: only `park` takes the record off the queue list,
            // so a panicked hook run must not be allowed to leave it
            // there. The inner task is what makes the park below
            // unconditional.
            let hooks = tokio::spawn({
                let (d, job) = (d.clone(), job.clone());
                async move { d.run_post_job_hooks_before_park(&job, gen0).await }
            });
            if let Err(e) = hooks.await {
                file_crashed_tail(&job, &e, gen0);
            }
            // Close the bracket `tasks.rs` opened at pick, exactly as the
            // full lane does at the end of its tail. Without it these
            // three arms park with `log_end` still 0, and `mode=report`
            // reads "no closing mark" as "still running" and runs the
            // span to the present - so a job that finished an hour ago
            // is handed every line every OTHER job has printed since.
            // Same generation fence as the full lane, and for the same
            // reason: a record that left this lane's custody belongs to
            // a live download now.
            {
                let mut j = job.lock_ok();
                if Daemon::same_generation(&j, gen0) {
                    j.log_end = nzbkit::logtee::mark();
                }
            }
            d.park_gen(job, gen0);
        });
        if self.inline {
            let _ = supervisor.await;
        }
    }
}

/// One unit of lane backlog, paid back on Drop.
///
/// The withdraw-the-hold half lives here too: the guard loop re-reads
/// `saturated()` only once a second, so clearing where the lane drains
/// takes the stale "waiting for post-processing to catch up" sentence
/// off the screen sooner. Re-read rather than reason from fetch_sub's
/// return: a submit may have raced in behind us, and the fresher number
/// is the honest one. `clear_postproc_hold` checks the KIND, so a disk
/// or quota hold raised in between survives.
///
/// §129 4a: and the `queue.idle` edge, for the same reason and off the
/// same re-read. `note_queue_idle` refuses to announce a drain while
/// this counter is up (see `Daemon::postproc_backlog`), so the call
/// `park_gen` makes at the end of the LAST tail is always suppressed -
/// by that tail's own ticket, which is still held. This is the retry
/// that gets it said. Drop-based, so a supervisor that panicked or was
/// dropped at shutdown gives the edge back too; a hand-placed call
/// after `park_gen` would not, and a lost edge is a queue-finished
/// action that never fires.
pub(in crate::serve) struct BacklogTicket {
    backlog: Arc<AtomicUsize>,
    cap: usize,
    d: Arc<Daemon>,
}

impl Drop for BacklogTicket {
    fn drop(&mut self) {
        self.backlog.fetch_sub(1, Ordering::Relaxed);
        let left = self.backlog.load(Ordering::Relaxed);
        if left < self.cap {
            self.d.clear_postproc_hold();
        }
        // Only the ticket that leaves the lane empty can unblock the
        // scan, so the others would take the queue lock to learn
        // nothing. Two tickets dropping together may both read 0 and
        // both call, which the latch answers; what cannot happen is
        // nobody calling, because the LAST decrement of a lane that
        // stays empty reads 0 by construction, and a submit racing in
        // to spoil the read brings its own ticket - and its own drop -
        // with it.
        if left == 0 {
            self.d.note_queue_idle();
        }
    }
}

impl Daemon {
    /// Stop the recovery-volume side-fetches of every named job.
    ///
    /// The delete arms already tombstone a `Finishing` job and rely on
    /// the tombstone making its tail a no-op at `park` - correct for the
    /// filing, silent about the network. A damaged set's repair pulls
    /// parity over its own small pool, and that fetch has no share of
    /// `hub.abort`: those handles belong to whatever is DOWNLOADING now
    /// (see `owns_hub`), which since the lane is routinely a different
    /// job. So a deleted job went on asking a provider for volumes
    /// nobody would read, for as long as the retry ladder took.
    ///
    /// Only the network is stopped. A repair already patching bytes runs
    /// to its end and parks - cutting it mid-write would leave a
    /// half-patched file behind, and the tombstone makes the outcome a
    /// no-op either way.
    ///
    /// Unknown ids are silently skipped: a queued job that never ran, a
    /// CLI run, a job already parked.
    pub(super) fn cancel_tail_fetches(&self, hit: impl Fn(&str) -> bool) {
        for (id, c) in self.hub.tail_cancel.lock_ok().iter() {
            if hit(id) {
                info!(target: "lane", "{id}: stopping recovery fetches - the job was deleted");
                c.cancel();
            }
        }
    }

    /// Drop the lane's backpressure hold, and only that one.
    ///
    /// `queue_hold` is one slot shared by every reason the runner can
    /// stop picking (disk, postproc, quota), so a blind `= None` here
    /// would erase a min-free hold raised while a tail was finishing and
    /// leave the header claiming downloads are running. Kind-checked
    /// under the same lock the write takes, so there is no window
    /// between the test and the clear.
    pub(super) fn clear_postproc_hold(&self) {
        let mut h = self.queue_hold.lock_ok();
        if h.as_ref().is_some_and(|(kind, _, _)| kind == "postproc") {
            *h = None;
        }
    }
}

/// The lane task panicked (or was cancelled by a dying runtime): file
/// the job Failed with the journal untouched, so a user retry re-runs
/// the tail from what is on disk. Same contract `finalize_completed`
/// already keeps for its inner `spawn_blocking`.
///
/// Fenced to the round the lane took custody of, and the check shares
/// the write's hold: a delete verb plus a retry can hand this record to
/// a new generation while the tail runs, and stamping Failed then does
/// not file a dead job - it fails a download that is at that moment
/// queued to run. Returns whether the filing happened, which is what
/// decides if the hooks are owed.
fn file_crashed_tail(
    job: &Arc<Mutex<Job>>,
    e: &tokio::task::JoinError,
    gen0: Option<(u32, u64)>,
) -> bool {
    warn!(target: "lane", "post-processing task died: {e}");
    let mut j = job.lock_ok();
    if !Daemon::same_generation(&j, gen0) {
        return false;
    }
    j.state = JobState::Failed;
    j.fail_message = crate::with_build(
        "post-processing crashed (internal error) - retry the job to re-run it".to_string(),
    );
    j.finished_at = Some(Instant::now());
    j.finished_unix = Some(unix_now());
    true
}

/// The tail itself: a verbatim move of the worker's old inline closure
/// (tasks.rs `run_worker`), with the captured state read off the ticket.
/// Runs settle-result filing, the suspended/park-on-full-disk arms,
/// verdict + stats onto the record, `finalize_completed`, hooks, `park`.
///
/// `gen0` is the round of the record's life the LANE took custody of,
/// sampled by `submit` under the same hold that wrote `Finishing`. It is
/// a parameter and not a local sample on purpose - see the note there.
pub(super) async fn run_tail(d2: Arc<Daemon>, t: PostprocTicket, gen0: (u32, u64)) {
    let PostprocTicket {
        job: job2,
        fetch,
        verifier,
        shaper,
        log_mark,
        dl_bytes,
        dl_secs,
        on_disk_bytes,
        index_job_guard,
        #[cfg(feature = "indexer")]
        oracle_samples,
    } = t;
    let _index_job_guard = index_job_guard;
    // When this tail started, for `Job::postproc_secs`. Taken before
    // the oracle fold below rather than after `fetch.await`, because the
    // fold takes the index write mutex and a wait there is time the user
    // spends looking at a `Finishing` row like any other.
    let tail_began = Instant::now();
    // M29: fold this job's per-article outcomes into the availability
    // ledger. On the lane, not on the runner - `with_index` waits on
    // the index write mutex, and a wait there stops the queue picking
    // at all (see `settle_job_tail`). Here the wait costs one lane
    // slot, which the lane's own backpressure already accounts for and
    // reports as a hold.
    #[cfg(feature = "indexer")]
    if !oracle_samples.is_empty() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.as_secs() as i64)
            .unwrap_or(0);
        let d3 = d2.clone();
        let n = oracle_samples.len();
        // Read into a local so the job lock is not held across the
        // activity lock inside `with_index_for_tail` (see `tail_id`
        // below for the ordering rule).
        let fold_id = job2.lock_ok().nzo_id.clone();
        // A blocking SQLite fold does not belong on an async worker,
        // and this one has a whole tail waiting behind it either way.
        //
        // BOUNDED, and that bound is load-bearing. On 20 Aug 2026 an
        // index scan lane wedged mid-I/O against a provider that had
        // stopped answering and held the index write mutex while it
        // sat there; this fold waited 8m46s for it, and because the
        // fold runs before `fetch.await` the whole tail waited with it,
        // showing the user a finishing row that did nothing for nine
        // minutes. The runner is already protected from that exact
        // shape (`index_gate_rendezvous`, issue #38's second wedge);
        // the tail was not.
        //
        // Giving up loses availability samples for one job, which is
        // sampled telemetry and the cheapest thing in this function.
        // The job's own completion is not negotiable against it.
        let folded = tokio::task::spawn_blocking(move || {
            d3.with_index_for_tail(&fold_id, |ix| ix.oracle_ingest(&oracle_samples, now).ok())
                .is_some()
        })
        .await
        .unwrap_or(false);
        if !folded {
            info!(
                target: "oracle",
                "index busy for {}s - dropping {n} availability sample(s) rather than \
                 holding this job's post-processing behind it",
                Daemon::TAIL_INDEX_WAIT.as_secs()
            );
        }
    }
    let res = match fetch.await {
        Ok(r) => r,
        Err(e) => Err(anyhow::anyhow!("download task panicked: {e}")),
    };
    // The download is over: hand the operating system back
    // every output file descriptor before anything else runs.
    //
    // `Extractor::finish` deliberately KEEPS its writers open
    // (see `park_outputs`), and the hub leaves the extractor
    // installed until the NEXT job starts - so on an idle
    // daemon a finished job's handles are held indefinitely.
    // On unix an unlinked file with a live descriptor keeps
    // its blocks, and unlinking those files is exactly what
    // happens after a download: cleanup deletes the volumes,
    // then an *arr imports the release and removes the
    // folder. The space never came back, the folder would not
    // delete over a share that cannot remove an open file,
    // and restarting the daemon was the only cure (reported
    // on Unraid, 2 Aug). A FAILED or paused job holds its
    // partial volumes open just as long, so this sits above
    // every exit path below rather than in the completed arm.
    //
    // Parking, not clearing: the extractor stays installed,
    // so the shape/CRC latch below and `writers_snapshot`
    // keep working. Nothing that serves bytes needs these
    // handles - `serve_range` opens the path itself, and a
    // finished job streams from disk through
    // `find_completed_media` - and the sweeps and renames in
    // `finalize_completed` are happier with them closed.
    if let Some(ex) = &shaper
        && let Err(e) = ex.park_outputs()
    {
        warn!(target: "cleanup", "could not release the output handles: {e}");
    }
    // The engine's own pipeline is over, so its last activity token -
    // "extracting", written when the disk-unpack ladder began - has
    // stopped being true. Everything below is the daemon's tail, and it
    // says so from here on: see `Daemon::note_tail_stage`.
    // The id is read into a local FIRST, so the job lock is released
    // before the activity lock is taken. Same discipline as
    // `daemon_park`'s seam: a job lock held across another of the
    // daemon's mutexes orders the two the opposite way from every other
    // reader of this record, and that is how lock-order bugs are grown.
    let tail_id = job2.lock_ok().nzo_id.clone();
    d2.note_tail_stage(&tail_id, "finalizing");
    // The record may have left this lane's custody while the download
    // ran, and everything below here writes to it: terminal state,
    // statistics, timestamps, the finalize marker, the payload
    // directory, the pp-script and the notification targets.
    //
    // The fence used to start at the very last statement - `park_gen` -
    // so the guard covered the filing and nothing that had already
    // happened to the record by the time it was reached. One of the
    // NZBGet delete verbs files a `Finishing` job into history from
    // under the lane, and a RETRY of that row (retryable by design)
    // clears the tombstone and re-queues the SAME Arc one generation
    // on. The old tail then stamped `Completed` plus the old run's
    // statistics onto the freshly queued record, ran the whole
    // finalization over the retry's output directory - unlock, rename,
    // TV filing, the move to the destination folder - and fired the
    // pp-script and every notification target for it, before park
    // finally declined to file it (read-only sweep 2, H1).
    //
    // Checked here and again inside each write's own lock hold below:
    // this one is what stops the tail dead, those are what make the
    // guard and the write one operation.
    #[cfg(test)]
    {
        let seam = TAIL_GEN_BARRIER
            .lock_ok()
            .clone()
            .filter(|(id, _, _)| *id == job2.lock_ok().nzo_id);
        if let Some((_, open, release)) = seam {
            open.wait();
            release.wait();
        }
    }
    if !Daemon::same_generation(&job2.lock_ok(), Some(gen0)) {
        info!(
            target: "lane",
            "{}: the record left this post-processing tail's custody while it ran \
             (deleted, or deleted and sent round again) - leaving the round that owns it alone",
            job2.lock_ok().nzo_id
        );
        d2.park_gen(job2, Some(gen0));
        return;
    }
    // M23e: a pause aborted this job - put it back in the
    // queue (not history) so resume continues it from the
    // journal. If it somehow completed despite the abort,
    // fall through and file it normally.
    let was_suspended = {
        let g = job2.lock_ok();
        g.suspended && !g.tombstone
    };
    if was_suspended && res.is_err() {
        {
            let mut j = job2.lock_ok();
            j.state = JobState::Queued;
            j.suspended = false;
            // The abort still ran whyslow::stamp at network-drain; that
            // verdict describes the stint that was cut short, not the
            // job, and the resumed run captures its own.
            j.clear_attempt_verdicts();
            // What is on disk, not what this run fetched:
            // the queue row reports its percentage from this
            // while paused, and a job paused twice would
            // otherwise report only the second stint. It was
            // not recorded here at all - a paused row read
            // 0% with the full size still to go, which is
            // the exact reading that has users deleting a
            // job whose journal is intact.
            j.downloaded_bytes = on_disk_bytes;
            info!(
                target: "pause",
                "{} parked back in the queue ({:.2} GB already on disk)",
                j.nzo_id,
                on_disk_bytes as f64 / 1e9
            );
        }
        d2.save_queue();
        return;
    }
    job2.lock_ok().suspended = false;
    // Mid-download disk full: park under the min-free hold
    // instead of failing - see `park_on_full_disk`.
    if park_on_full_disk(&d2, &job2, res.as_ref().err(), on_disk_bytes).await {
        return;
    }
    let demoted = {
        let mut j = job2.lock_ok();
        // The check and the first write it guards, under ONE hold. The
        // disk-full arm above awaits, so the entry check is stale by
        // the time this runs.
        if !Daemon::same_generation(&j, Some(gen0)) {
            None
        } else {
            match &res {
                Ok(_) => {
                    j.state = JobState::Completed;
                    j.fetched = true;
                }
                Err(e) => {
                    j.state = JobState::Failed;
                    j.fail_message = e.to_string();
                    // TODO §77: fold the pre-flight sample into
                    // the failure evidence. "It was already
                    // short when you added it" and "it rotted
                    // out from under the download" call for
                    // different things - a replacement from the
                    // indexer versus a retry - and after the
                    // fact nothing else can tell them apart.
                    //
                    // APPENDED, never prefixed: `fail_kind`, the
                    // *arr health mapping and the diag tests all
                    // key on the opening clause, exactly as the
                    // segment census does in `incomplete_reason`.
                    if let Some(h) = j.health.as_ref()
                        && crate::serve::fail_kind(&j.fail_message).post_unavailable()
                        && let Some(clause) = crate::health::failure_clause(h)
                    {
                        j.fail_message.push_str(&clause);
                    }
                    // A disk that filled up during the unpack is
                    // the one failure where the fix is entirely
                    // in the user's hands and the cost of the
                    // retry is near zero: the spent-volume sweep
                    // only removes volumes after a SUCCESSFUL
                    // extraction, so the downloaded parts are
                    // still on disk and mode=retry resumes from
                    // the article journal without re-fetching a
                    // byte. Say so, with the amount to free -
                    // the extracted payload is roughly the size
                    // of the set. APPENDED, same rule as the
                    // health clause above.
                    // Not for the mid-download halt: its verdict
                    // already says the fetch resumes from the
                    // journal, and "only the unpack re-runs"
                    // would be flatly wrong for it.
                    if crate::serve::disk_full_failure(&j.fail_message)
                        && !crate::serve::disk_full_mid_download(&j.fail_message)
                    {
                        let clause = format!(
                            "; free about {:.1} GB on that disk and hit Retry - the downloaded archive parts are kept, so nothing is re-downloaded and only the unpack re-runs",
                            j.total_bytes as f64 / 1e9
                        );
                        j.fail_message.push_str(&clause);
                    }
                    // Keep the console block that explains the
                    // one-liner. Failures are where a user
                    // needs the log MOST and where it is least
                    // likely to still be there when they look.
                    j.fail_detail = crate::fail_detail_snapshot(log_mark);
                }
            }
            j.downloaded_bytes = dl_bytes;
            j.elapsed_secs = dl_secs;
            // A verdict only where something actually verified.
            // `live_counts()` is (ok + bad, bad): no verifier at
            // all (par2-less post) and a verifier that mapped
            // nothing (the resume case) both check zero blocks,
            // and neither is evidence the payload is clean. Keep
            // an earlier run's verdict rather than overwriting it
            // with "unknown" - a retry that maps nothing in
            // stream must not erase what the first pass proved.
            let (checked, bad) = verifier.as_ref().map_or((0, 0), |v| v.live_counts());
            if checked > 0 {
                j.bad_blocks = Some(bad);
                j.verify_blocks = checked;
            }
            // Latch the shape for history. Keep whatever a
            // previous run learned if this one recognized
            // nothing (a resume maps nothing in-stream, and
            // reporting "no archive" for a retried RAR5 set
            // would be a downgrade, not an update).
            if let Some(tag) = shaper.as_ref().and_then(|e| e.archive_shape()) {
                j.archive_shape = tag.tag();
            }
            // Same latch-don't-downgrade rule, same reason:
            // a resumed run maps nothing in-stream, and the
            // headers this key came from are not on disk to
            // read again.
            if let Some((_, crc)) = shaper.as_ref().and_then(|e| e.inner_crc()) {
                j.inner_crc = crc;
            }
            j.finished_at = Some(Instant::now());
            j.finished_unix = Some(unix_now());
            // A demotion only HAPPENED if the watchdog's abort
            // actually took the download down. When the flag
            // loses the race with the finish line the job is a
            // plain completion: it gets its hooks below, and
            // park files it to history (clearing the flag)
            // instead of re-queueing a finished release.
            Some(res.is_err() && j.demote)
        }
    };
    let Some(demoted) = demoted else {
        info!(
            target: "lane",
            "{}: the record was sent round again while this tail was settling - \
             leaving its verdict, its files and its hooks to the round that owns it",
            job2.lock_ok().nzo_id
        );
        d2.park_gen(job2, Some(gen0));
        return;
    };
    // Feed the watchdog's reference: every job's average
    // network rate is an observed "the line can do this"
    // sample (short bursts are too noisy to count).
    if dl_secs >= 0.5 && dl_bytes > 0 {
        let avg = (dl_bytes as f64 / dl_secs) as u64;
        d2.best_rate_bps.fetch_max(avg, Ordering::Relaxed);
    }
    finalize_completed_gen(&d2, &job2, Some(gen0)).await;
    // A watchdog demotion is not a completion - no
    // script and no notification; park() requeues it
    // deferred.
    //
    // Awaited, and awaited HERE: the next statement files this job into
    // history, and history saying "Completed" is what a SAB client
    // imports on. The post-processing script is the step most likely to
    // still be moving the payload, so it has to be finished before the
    // *arr is told where to find it. Only the script is waited for -
    // see `run_post_job_hooks_before_park`.
    //
    // What it costs, so nobody has to rediscover it: a slow script now
    // holds this lane slot for its whole run (bounded by
    // `script_timeout_secs`, an hour by default) instead of being cut
    // loose onto the blocking pool, so a script that takes minutes is
    // post-processing capacity spent - which is what a post-processing
    // step IS, and what the lane's width and its backpressure hold
    // exist to express.
    if !demoted {
        d2.run_post_job_hooks_before_park(&job2, Some(gen0)).await;
    }
    // The tail is over: record what it cost. Written under the same
    // generation fence as every other stat this tail owns - a record
    // that left this lane's custody belongs to a live download now, and
    // stamping it with THIS run's timing would be describing the wrong
    // job (read-only sweep 2, H1).
    let tail_secs = tail_began.elapsed().as_secs_f64();
    {
        let mut j = job2.lock_ok();
        if Daemon::same_generation(&j, Some(gen0)) {
            j.postproc_secs = tail_secs;
            // Closes the bracket `tasks.rs` opened at pick: everything
            // this job printed lies between the two, and `mode=report`
            // slices exactly that. Taken here rather than after `park`
            // because park is where the record leaves the queue.
            j.log_end = nzbkit::logtee::mark();
        }
    }
    // Said out loud only when it is worth saying. Post-processing that
    // outlasts the download it followed is the shape a user reports as
    // "stuck at 100%", and until now the log recorded no trace of it at
    // all - so the one line that names the cost is worth more than the
    // silence it replaces. The threshold is deliberately generous: a
    // repair or a big unpack legitimately takes minutes, and a warning
    // that fires on healthy work is a warning people learn to skip.
    if tail_secs >= TAIL_SLOW_SECS {
        warn!(
            target: "lane",
            "{}: post-processing took {tail_secs:.0}s after a {dl_secs:.0}s download - \
             the queue row showed this as a finishing job the whole time",
            tail_id
        );
    }
    // With the generation this lane started on: a delete verb can file
    // this job into history mid-tail, and a retry of that row re-queues
    // the same Arc. Parking it then would consume the retry.
    d2.park_gen(job2, Some(gen0));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_daemon(name: &str, f: impl FnOnce(&Arc<Daemon>)) {
        let dir = std::env::temp_dir().join(format!("nzbfast-lane-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let d = crate::serve::testutil::test_daemon(&dir);
        f(&d);
        drop(d);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The delete arms reach the right job's recovery fetches and only
    /// that job's. The registry is keyed by owning nzo_id precisely
    /// because the hub's own abort handles are not - aiming a cancel at
    /// the wrong job is the hazard `owns_hub` exists for, and this
    /// registry must not reintroduce it under a new name.
    #[test]
    fn cancel_tail_fetches_hits_the_named_owner_only() {
        with_daemon("cancel", |d| {
            let mine = Arc::new(crate::repair::SideCancel::new());
            let other = Arc::new(crate::repair::SideCancel::new());
            {
                let mut m = d.hub.tail_cancel.lock_ok();
                m.insert("SABnzbd_nzo_mine".to_string(), mine.clone());
                m.insert("SABnzbd_nzo_other".to_string(), other.clone());
            }
            d.cancel_tail_fetches(|id| id == "SABnzbd_nzo_mine");
            assert!(mine.is_cancelled(), "the deleted job's fetches stop");
            assert!(
                !other.is_cancelled(),
                "a job nobody deleted keeps fetching - this is the owns_hub hazard"
            );

            // An id with no registration (a queued job that never ran, a
            // job already parked) is skipped, never a panic.
            d.cancel_tail_fetches(|id| id == "SABnzbd_nzo_ghost");

            // "all" reaches everything, which is what a delete-all asks
            // for.
            d.cancel_tail_fetches(|_| true);
            assert!(other.is_cancelled());
        });
    }

    /// The drain-side clear is kind-scoped. `queue_hold` is one slot for
    /// every guard, so the interesting case is not "does it clear its
    /// own" but "does it leave the others alone" - a tail parking while
    /// the disk guard holds the queue must not report the queue running.
    #[test]
    fn clear_postproc_hold_takes_only_its_own_kind() {
        with_daemon("hold", |d| {
            *d.queue_hold.lock_ok() = Some(("postproc".into(), 4.0, 4.0));
            d.clear_postproc_hold();
            assert!(d.queue_hold.lock_ok().is_none(), "its own hold clears");

            *d.queue_hold.lock_ok() = Some(("disk".into(), 1.5, 20.0));
            d.clear_postproc_hold();
            assert_eq!(
                d.queue_hold.lock_ok().as_ref().map(|(k, ..)| k.clone()),
                Some("disk".to_string()),
                "a min-free hold raised while a tail finished must survive"
            );

            *d.queue_hold.lock_ok() = Some(("quota".into(), 50.0, 50.0));
            d.clear_postproc_hold();
            assert_eq!(
                d.queue_hold.lock_ok().as_ref().map(|(k, ..)| k.clone()),
                Some("quota".to_string()),
                "so must a quota hold"
            );

            // Nothing held: still a no-op, never a panic.
            *d.queue_hold.lock_ok() = None;
            d.clear_postproc_hold();
            assert!(d.queue_hold.lock_ok().is_none());
        });
    }

    /// A ticket for a job that is already whole on disk: the download
    /// task hands back Ok immediately, so the tail is all that runs.
    fn done_ticket(d: &Arc<Daemon>, job: &Arc<Mutex<Job>>) -> PostprocTicket {
        PostprocTicket {
            job: job.clone(),
            fetch: tokio::spawn(async { Ok(()) }),
            verifier: None,
            shaper: None,
            log_mark: 0,
            dl_bytes: 1_000,
            dl_secs: 1.0,
            on_disk_bytes: 1_000,
            index_job_guard: d.begin_index_job(),
            // No articles were fetched, so there is nothing for the
            // availability ledger to learn.
            #[cfg(feature = "indexer")]
            oracle_samples: Vec::new(),
        }
    }

    /// The lane tail belongs to ONE round of a record's life, and the
    /// fence used to start at its very last statement.
    ///
    /// `park_gen` carries the generation, so the FILING declined a
    /// record that had been retried out from under the tail - but
    /// everything ahead of it did not. A delete verb files a `Finishing`
    /// job into history, the user retries that row (retryable by
    /// design), and the same Arc comes back to the queue one generation
    /// on. The old tail then stamped `Completed` and the old run's
    /// statistics onto the freshly queued record, ran the whole
    /// finalization over the retry's output directory, and fired the
    /// pp-script and every notification target for a release that was at
    /// that moment waiting to download again (read-only sweep 2, H1).
    ///
    /// Driven through `TAIL_GEN_BARRIER` because the window between the
    /// download resolving and the first write is zero-width without one.
    /// Both directions in one test on purpose: the seam is a global, and
    /// a guard that declines everything would pass the stale half alone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_lane_tail_never_writes_over_a_record_that_was_retried_out_from_under_it() {
        let dir = std::env::temp_dir().join(format!("nzbfast-lane-tailgen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let d = crate::serve::testutil::test_daemon(&dir);

        // --- the stale direction ---------------------------------------
        let out = d.out_dir().join("Laned.Release");
        std::fs::create_dir_all(&out).expect("payload dir");
        let job = Arc::new(Mutex::new(
            job_from_json(&json!({
                "nzo_id": "nzo-tailgen-1",
                "name": "Laned.Release",
                "nzb_path": dir.join("laned.nzb").to_string_lossy(),
                "out_dir": out.to_string_lossy(),
                "state": "Queued",
            }))
            .expect("job"),
        ));
        // What the lane submission does before it hands the ticket over,
        // including the generation sample that goes with the ticket.
        let gen0 = {
            let mut j = job.lock_ok();
            j.state = JobState::Finishing;
            Daemon::record_generation(&j)
        };
        d.queue.lock_ok().push_back(job.clone());

        let open = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        *TAIL_GEN_BARRIER.lock_ok() =
            Some(("nzo-tailgen-1".to_string(), open.clone(), release.clone()));

        let ticket = done_ticket(&d, &job);
        let tail = tokio::spawn(run_tail(d.clone(), ticket, gen0));

        // The download has resolved and the tail has written nothing
        // yet. This is the window.
        let o2 = open.clone();
        tokio::task::spawn_blocking(move || o2.wait())
            .await
            .unwrap();
        // The delete verb: the Finishing row leaves the queue and is
        // filed into history, tombstoned.
        d.queue.lock_ok().retain(|j| !Arc::ptr_eq(j, &job));
        {
            let mut g = job.lock_ok();
            g.state = JobState::Failed;
            g.tombstone = true;
            g.delete_status = "MANUAL".into();
            g.fail_message = "deleted from the queue".into();
            g.finished_unix = Some(1);
        }
        d.history.lock_ok().push(job.clone());
        // ...and the user presses Retry on it, which is an instruction
        // to RUN: the tombstone goes and the same Arc is queued again,
        // one generation on.
        assert!(
            d.retry("nzo-tailgen-1"),
            "the filed delete row is retryable"
        );
        let r2 = release.clone();
        tokio::task::spawn_blocking(move || r2.wait())
            .await
            .unwrap();
        tail.await.expect("lane tail");
        *TAIL_GEN_BARRIER.lock_ok() = None;

        {
            let g = job.lock_ok();
            assert_eq!(
                g.state,
                JobState::Queued,
                "the stale tail stamped its own verdict onto the record the retry queued"
            );
            assert!(!g.fetched, "and reported the retry as already downloaded");
            assert!(
                !g.finalizing,
                "and left the retry carrying a finalize marker"
            );
        }
        assert!(
            d.queue
                .lock_ok()
                .iter()
                .any(|j| j.lock_ok().nzo_id == "nzo-tailgen-1"),
            "the stale tail pulled the freshly retried row out of the queue"
        );
        assert_eq!(
            d.history
                .lock_ok()
                .iter()
                .filter(|j| j.lock_ok().nzo_id == "nzo-tailgen-1")
                .count(),
            0,
            "and filed it into history, consuming the retry the user pressed"
        );

        // --- the live direction ----------------------------------------
        // Same tail, nothing taken away from it: it must still complete
        // the job and file it. A fence that declines everything would
        // look green above and break every download.
        let out2 = d.out_dir().join("Ordinary.Release");
        std::fs::create_dir_all(&out2).expect("payload dir");
        let job2 = Arc::new(Mutex::new(
            job_from_json(&json!({
                "nzo_id": "nzo-tailgen-2",
                "name": "Ordinary.Release",
                "nzb_path": dir.join("ordinary.nzb").to_string_lossy(),
                "out_dir": out2.to_string_lossy(),
                "state": "Queued",
            }))
            .expect("job"),
        ));
        let gen2 = {
            let mut j = job2.lock_ok();
            j.state = JobState::Finishing;
            Daemon::record_generation(&j)
        };
        d.queue.lock_ok().push_back(job2.clone());
        run_tail(d.clone(), done_ticket(&d, &job2), gen2).await;
        {
            let g = job2.lock_ok();
            assert_eq!(
                g.state,
                JobState::Completed,
                "an untouched job still completes"
            );
            assert!(g.fetched);
        }
        assert_eq!(
            d.history
                .lock_ok()
                .iter()
                .filter(|j| j.lock_ok().nzo_id == "nzo-tailgen-2")
                .count(),
            1,
            "and the tail still files it into history"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A width-1 lane whose `submit` waits for its own supervisor, so a
    /// test can drive one ticket end to end. Byte-for-byte what
    /// `NZBFAST_POSTPROC_INLINE=1` builds, without touching the process
    /// environment (which every other test in this binary shares).
    fn inline_lane(d: &Arc<Daemon>) -> PostprocLane {
        PostprocLane {
            d: d.clone(),
            width: 1,
            inline: true,
            slots: Arc::new(tokio::sync::Semaphore::new(1)),
            // The DAEMON's counter, exactly as `new` takes it. A private
            // one here would compile and would quietly take the
            // `queue.idle` suppression out of every lane test - the
            // counter is only worth anything because `note_queue_idle`
            // reads the same cell the tickets move.
            backlog: d.postproc_backlog.clone(),
        }
    }

    /// The generation the tail is fenced to must be the one the LANE
    /// took custody of, not one sampled after its waits.
    ///
    /// `submit` marks the job `Finishing` and returns; the supervisor
    /// then waits for a run permit (width 2 by default, so a third
    /// finished job really does park there behind two unpacks) and
    /// `run_tail` then waits on the M29 oracle fold, which takes the
    /// index write mutex - a wait a retention reap has held for hours.
    /// gen0 was sampled after BOTH. A delete verb files the `Finishing`
    /// row into history and a retry of it re-queues the same Arc one
    /// generation on, so a delete+retry landing in either wait made gen0
    /// the RETRY's own generation and every fence downstream waved the
    /// stale tail through: Completed and the old run's statistics onto
    /// the queued record, finalization over the retry's directory, the
    /// pp-script and every notification target fired, and park consuming
    /// the retry (Codex sweep 3, H1).
    ///
    /// Driven through `SUBMIT_GEN_BARRIER`, which opens in exactly that
    /// interval - `TAIL_GEN_BARRIER` cannot reach it, because it sits on
    /// the far side of both waits.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_lane_fences_on_the_generation_it_took_custody_of() {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-lane-submitgen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let d = crate::serve::testutil::test_daemon(&dir);

        let out = d.out_dir().join("Waiting.Release");
        std::fs::create_dir_all(&out).expect("payload dir");
        let job = Arc::new(Mutex::new(
            job_from_json(&json!({
                "nzo_id": "nzo-submitgen-1",
                "name": "Waiting.Release",
                "nzb_path": dir.join("waiting.nzb").to_string_lossy(),
                "out_dir": out.to_string_lossy(),
                "state": "Downloading",
            }))
            .expect("job"),
        ));
        d.queue.lock_ok().push_back(job.clone());

        let open = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        *SUBMIT_GEN_BARRIER.lock_ok() =
            Some(("nzo-submitgen-1".to_string(), open.clone(), release.clone()));

        let lane = inline_lane(&d);
        let ticket = done_ticket(&d, &job);
        let submitted = tokio::spawn(async move { lane.submit(ticket).await });

        // The job is Finishing, the ticket is in the lane, and the tail
        // has not started: this is the window the semaphore and the
        // oracle fold hold open in production.
        let o2 = open.clone();
        tokio::task::spawn_blocking(move || o2.wait())
            .await
            .unwrap();
        // The delete verb: a Finishing row leaves the queue tombstoned
        // and is filed into history.
        d.queue.lock_ok().retain(|j| !Arc::ptr_eq(j, &job));
        {
            let mut g = job.lock_ok();
            g.state = JobState::Failed;
            g.tombstone = true;
            g.delete_status = "MANUAL".into();
            g.fail_message = "deleted from the queue".into();
            g.finished_unix = Some(1);
        }
        d.history.lock_ok().push(job.clone());
        assert!(
            d.retry("nzo-submitgen-1"),
            "the filed delete row is retryable"
        );
        let r2 = release.clone();
        tokio::task::spawn_blocking(move || r2.wait())
            .await
            .unwrap();
        submitted.await.expect("lane submission");
        *SUBMIT_GEN_BARRIER.lock_ok() = None;

        {
            let g = job.lock_ok();
            assert_eq!(
                g.state,
                JobState::Queued,
                "the stale tail stamped its verdict onto the record the retry queued"
            );
            assert!(!g.fetched, "and reported the retry as already downloaded");
            assert!(
                !g.finalizing,
                "and left the retry carrying a finalize marker"
            );
        }
        assert!(
            d.queue
                .lock_ok()
                .iter()
                .any(|j| j.lock_ok().nzo_id == "nzo-submitgen-1"),
            "the stale tail pulled the freshly retried row out of the queue"
        );
        assert_eq!(
            d.history
                .lock_ok()
                .iter()
                .filter(|j| j.lock_ok().nzo_id == "nzo-submitgen-1")
                .count(),
            0,
            "and filed it into history, consuming the retry the user pressed"
        );

        // The live direction, through the same seam-less path: a lane
        // submission nobody touched still completes and files its job. A
        // fence that declined everything would pass the half above and
        // break every download.
        let out2 = d.out_dir().join("Untouched.Release");
        std::fs::create_dir_all(&out2).expect("payload dir");
        let job2 = Arc::new(Mutex::new(
            job_from_json(&json!({
                "nzo_id": "nzo-submitgen-2",
                "name": "Untouched.Release",
                "nzb_path": dir.join("untouched.nzb").to_string_lossy(),
                "out_dir": out2.to_string_lossy(),
                "state": "Downloading",
            }))
            .expect("job"),
        ));
        d.queue.lock_ok().push_back(job2.clone());
        inline_lane(&d).submit(done_ticket(&d, &job2)).await;
        assert_eq!(
            job2.lock_ok().state,
            JobState::Completed,
            "an untouched submission still completes"
        );
        assert_eq!(
            d.history
                .lock_ok()
                .iter()
                .filter(|j| j.lock_ok().nzo_id == "nzo-submitgen-2")
                .count(),
            1,
            "and the lane still files it into history"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `queue.idle` must never be said while a tail still owes its
    /// `job.completed` - including a tail that is, at that instant, in
    /// neither the queue nor history.
    ///
    /// The lane runs tails concurrently (`postproc_jobs`, default 2), so
    /// two jobs' parks overlap. `park_gen` retains the row out of the
    /// queue a hundred lines before it pushes the record into history,
    /// and it ends with `note_queue_idle`, whose scan asks only the
    /// QUEUE. Job A's park landing inside job B's window therefore saw
    /// an empty queue, won the latch CAS and announced the drain between
    /// the two `job.completed`s - with B in neither list for a
    /// subscriber that reacted by reading history for what had just
    /// finished (23 Aug 2026, off the `queue_handoff` ring dump).
    ///
    /// Driven by moving the tickets by hand rather than by racing two
    /// real tails: the ordering under test is an INVARIANT of the
    /// counter, and the two tails on the fixture that found this park
    /// about 16 ms apart, either way round on a loaded box. The events
    /// this asserts on are the real ones - `park_gen` emits them.
    #[test]
    fn an_overlapping_tail_holds_the_idle_edge_until_it_has_completed() {
        let dir = std::env::temp_dir().join(format!("nzbfast-lane-idle-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let d = crate::serve::testutil::test_daemon(&dir);
        let lane = inline_lane(&d);

        let park_me = |id: &str, name: &str| {
            let out = d.out_dir().join(name);
            let job = Arc::new(Mutex::new(
                job_from_json(&json!({
                    "nzo_id": id,
                    "name": name,
                    "nzb_path": dir.join("x.nzb").to_string_lossy(),
                    "out_dir": out.to_string_lossy(),
                    "state": "Completed",
                    "finished_unix": 1,
                }))
                .expect("job"),
            ));
            d.queue.lock_ok().push_back(job.clone());
            job
        };
        let a = park_me("nzo-laneidle-a", "Overlap.A");
        let b = park_me("nzo-laneidle-b", "Overlap.B");
        // Armed the way an add arms it: both tails are in the lane's
        // custody, which is the state two overlapping parks start from.
        d.queue_idle_latch.store(false, Ordering::Relaxed);
        let seat_a = lane.reserve();
        let seat_b = lane.reserve();

        // A parks first and finds an empty queue - B's row is still in
        // it here, but B's own park will take it out long before B's
        // record reaches history, and this is the emit that used to run
        // in that window.
        d.park_gen(a, None);
        d.queue.lock_ok().clear();
        d.park_gen(b, None);
        let kinds = |d: &Arc<Daemon>| -> Vec<String> {
            d.life_since(0)
                .0
                .iter()
                .filter_map(|e| e["kind"].as_str())
                .filter(|k| k.starts_with("job.completed") || *k == "queue.idle")
                .map(str::to_string)
                .collect()
        };
        assert_eq!(
            kinds(&d),
            vec!["job.completed", "job.completed"],
            "the drain was announced while a tail was still in the lane"
        );

        // The tails leave. Only the LAST ticket may say it, and it must:
        // every `note_queue_idle` the parks made was suppressed, so a
        // ticket that stayed silent would lose the edge altogether and
        // with it the queue-finished action.
        drop(seat_a);
        assert_eq!(
            kinds(&d),
            vec!["job.completed", "job.completed"],
            "a lane that is still busy has not drained"
        );
        drop(seat_b);
        assert_eq!(
            kinds(&d),
            vec!["job.completed", "job.completed", "queue.idle"],
            "the last ticket out owes the edge its parks could not say"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
