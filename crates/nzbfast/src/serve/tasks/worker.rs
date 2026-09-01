//! The download runner: which job runs, when the next one starts, and
//! the order their tails reach the post-processing lane.
//!
//! Moved out of tasks.rs whole (it sat at the file ceiling) and
//! restructured around the cross-job hand-over
//! (`nzbkit::pool::handoff`). Two overlaps exist now:
//!
//! - Job N's TAIL (settle/repair/extract, on the lane) overlaps job
//!   N+1's download. This is the old one, and it is what `net_rx`
//!   resolving at network-drain buys.
//! - Job N's network DRAIN overlaps job N+1's download. New. Once N's
//!   fleet starts going idle after queue-dry (`HandoffSignal`), the
//!   runner picks and starts N+1 on the real daemon hub while N's last
//!   in-flight articles are still landing. N+1's workers take N's idle
//!   connections one at a time through the per-host lease, so the line
//!   stays full and the two runs never hold more than one job's cap
//!   between them.
//!
//! What keeps that honest is the `Running` / `detach` split below. The
//! daemon's hub and counters belong to the NEWEST job from the moment
//! it claims them, exactly as before; everything the runner will still
//! need from job N after that moment is taken off the hub first
//! ([`detach_job_tail`]) and carried until N drains. The lane sees N's
//! ticket before N+1's by construction: after a hand-over the runner
//! awaits N's drain and submits N before it looks at N+1's signals, so
//! at most two pipelines are ever alive.
//!
//! That is an ordering of the LANE'S INBOX, and this doc said "history
//! order is queue order" until 23 Aug 2026, which is a different and
//! false claim. Filing happens at `park`, at the END of a tail, and the
//! lane runs tails concurrently (`postproc_jobs`, default 2): two jobs
//! whose tails overlap file in whichever order they finish. That is
//! deliberate and predates the hand-over - a fast job behind one that
//! is still repairing has always reached history first, which is the
//! whole point of §129's lane - and the hand-over only makes the two
//! tails start together, so the margin on a small pair is milliseconds.
//! `tests/integration/queue_handoff.rs` asserted the false version and
//! duly failed on a loaded CI runner; it pins the `job.finishing`
//! sequence now, which is this inbox order and has no timing window.
//!
//! With no successor there is nothing to hand over to: the signal fires
//! and `start_next` finds nothing, the run drains exactly as it always
//! did.

use super::*;

/// A job whose pipeline is running: everything the runner needs once
/// its network phase ends.
pub(super) struct Running {
    job: Arc<Mutex<Job>>,
    nzo_id: String,
    fetch: tokio::task::JoinHandle<Result<()>>,
    net_rx: tokio::sync::oneshot::Receiver<Instant>,
    /// When the network phase ended, as the PIPELINE stamped it - set
    /// once `net_rx` has resolved (or dropped, which is the same
    /// meaning: no more network work for this job), so a receiver is
    /// never awaited twice. A dropped sender stamps the read instead.
    net_at: Option<Instant>,
    handoff: Arc<nzbkit::pool::handoff::HandoffSignal>,
    t_start: Instant,
    log_mark: u64,
    index_job_guard: IndexJobGuard,
    /// This job's own decoded-byte counter - the handle its pipeline
    /// holds, whichever job owns the daemon's cell by now.
    progress: Arc<AtomicU64>,
    /// Taken off the hub at the hand-over, while the hub was still this
    /// job's; None until then, and None for a job that was never handed
    /// over (its settle detaches at drain, as before).
    detached: Option<DetachedTail>,
    /// Retention insurance: this run banks a deferred row's payload
    /// (`no_extract`) and its tail re-queues the row instead of filing
    /// it. Threaded as run state rather than read off the record at
    /// tail time, so a promotion landing mid-fetch cannot change what
    /// kind of run this WAS.
    insurance: bool,
}

/// What `start_next` did.
enum Start {
    /// A pipeline is running for the picked job.
    Started(Running),
    /// A job was picked and ended before any pipeline started (the
    /// metadata-only, give-up and pre-flight arms) - pick again.
    Ended,
    /// Nothing to start right now: a guard holds, or the queue has no
    /// runnable job.
    Nothing,
}

/// The runner's loop-carried state, named so `start_next` and `finish`
/// can take it whole.
struct Runner {
    d: Arc<Daemon>,
    config: std::path::PathBuf,
    index_pass_gate: Arc<tokio::sync::Mutex<()>>,
    mem_budget: nzbkit::mem::MemBudget,
    /// §129: the post-processing lane the tails hand off to. The worker
    /// never blocks on a tail again - it blocks only on the lane's
    /// honest backpressure bound (in the guards).
    lane: PostprocLane,
    guard_reason: Option<String>,
    /// Opened lazily on the first pass with a quota set - the quota
    /// (and its period) are live settings now.
    ledger: Option<QuotaLedger>,
    /// In-flight statfs probe for the min-free guard (≤1 outstanding).
    disk_probe: Option<tokio::task::JoinHandle<Option<u64>>>,
    /// §156 item 7: the no-servers guard's config read, on the blocking
    /// pool under the same one-outstanding rule.
    server_probe: ServerProbe,
}

/// Download worker: one download at a time at full pipeline speed, but
/// job N's tail AND its network drain overlap job N+1's download - the
/// network never idles across queue boundaries. See the module doc.
pub(in crate::serve) fn spawn_download_worker(
    daemon: &Arc<Daemon>,
    config: &std::path::Path,
    index_pass_gate: &Arc<tokio::sync::Mutex<()>>,
    mem_budget: nzbkit::mem::MemBudget,
) {
    // The per-host connection budget every primary run on this hub
    // draws its sockets from (`nzbkit::pool::handoff`). Installed here,
    // once, because this runner is the only thing that ever starts two
    // runs on one hub. `NZBFAST_QUEUE_HANDOFF=0` leaves it uninstalled,
    // which is the strictly serial queue of before: no lease, no
    // waiters, no hand-over.
    if std::env::var("NZBFAST_QUEUE_HANDOFF")
        .ok()
        .is_none_or(|v| v != "0")
    {
        let _ = daemon
            .hub
            .conn_budget
            .set(nzbkit::pool::handoff::ConnBudget::new());
    }
    let mut st = Runner {
        d: daemon.clone(),
        config: config.to_path_buf(),
        index_pass_gate: index_pass_gate.clone(),
        mem_budget,
        lane: PostprocLane::new(daemon.clone()),
        guard_reason: None,
        ledger: None,
        disk_probe: None,
        server_probe: ServerProbe::default(),
    };
    tokio::spawn(async move {
        let mut cur: Option<Running> = None;
        loop {
            let Some(mut run) = cur.take() else {
                // Nothing running: the ordinary pick, with the guards
                // sleeping on holds as they always have.
                if let Start::Started(r) = start_next(&mut st, false, None).await {
                    cur = Some(r);
                }
                continue;
            };
            // A run is live. Its network ending comes first (`biased`):
            // a run that is already drained never takes the hand-over
            // path.
            let signal = run.handoff.clone();
            let drained = tokio::select! {
                biased;
                at = &mut run.net_rx => Some(at.unwrap_or_else(|_| Instant::now())),
                _ = signal.wait() => None,
            };
            if let Some(at) = drained {
                run.net_at = Some(at);
                finish(&mut st, run).await;
                continue;
            }
            // N's fleet is going idle: start N+1 on the connections it
            // sheds. The sidecar is wound down first for the same reason
            // the drain path always did it before the next pick - the
            // next primary may be the very job it holds, and two
            // pipelines must never share an out_dir.
            stop_sidecar(&st.d).await;
            let next = loop {
                match start_next(&mut st, true, Some(&mut run)).await {
                    Start::Started(r) => break Some(r),
                    Start::Ended => continue,
                    Start::Nothing => {
                        // Nothing startable this instant. A job added
                        // during the drain still deserves the overlap,
                        // so look again shortly - unless the drain ends
                        // first.
                        let done = tokio::select! {
                            at = &mut run.net_rx => Some(at.unwrap_or_else(|_| Instant::now())),
                            _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => None,
                        };
                        if let Some(at) = done {
                            run.net_at = Some(at);
                            break None;
                        }
                    }
                }
            };
            // Whether or not a successor started, N drains now and is
            // settled and submitted BEFORE the runner looks at anything
            // of N+1's: that is the history-order guarantee.
            if run.net_at.is_none() {
                let at = (&mut run.net_rx).await.unwrap_or_else(|_| Instant::now());
                run.net_at = Some(at);
            }
            finish(&mut st, run).await;
            cur = next;
        }
    });
}

/// The runner's pick, plus the test seam that holds the gap behind it
/// open.
///
/// `pick_job` drops the job lock before it returns, so everything
/// between that call and the critical section in [`start_next`] that
/// flips the state to Downloading is a window a whole recategorize
/// fits inside - which is why that section re-reads
/// [`Job::relocating`] rather than trusting what the pick saw. The
/// window is microseconds wide on a live daemon, so nothing can land
/// in it on purpose and that re-read was pinned by no test at all
/// (measured 25 Aug 2026: comment the arm out, leave `pick_job`'s in,
/// and the whole repo stays green - `daemon_relocate`'s existing case
/// is satisfied by either arm alone and says so). This hook holds the
/// window open so `daemon_relocate::a_recategorize_inside_the_pick_to_
/// start_gap_cannot_start_the_job` can publish inside it, and
/// announces itself on the way in so that case can rendezvous on the
/// log instead of on a sleep. No effect unless the suite sets it.
///
/// A tokio sleep rather than the blocking one the two hooks in
/// `requeue_category` use: those fire on tiny_http's own thread, this
/// one is on the runner task and must not pin a runtime worker for the
/// length of the stall.
/// The bool is retention insurance: `true` means no ordinary job was
/// runnable and a deferred row's payload gets banked instead - the
/// ordinary pipeline with `no_extract`, ending in the queue rather than
/// in history (see `serve::insurance` for the picker and the cap, and
/// the insurance arm in `postproc::run_tail`). Behind every ordinary
/// pick by construction, and never while the queue is paused - a global
/// pause means stop, background errands included.
async fn pick_for_start(d: &Arc<Daemon>, only_force: bool) -> Option<(Arc<Mutex<Job>>, bool)> {
    let (job, insurance) = match d.pick_job(only_force) {
        Some(j) => (j, false),
        None => (
            (!only_force).then(|| d.pick_insurance_job()).flatten()?,
            true,
        ),
    };
    if let Some(ms) = std::env::var("NZBFAST_TEST_STALL_PICK_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        let id = job.lock_ok().nzo_id.clone();
        info!(target: "queue", "{id}: test stall in the pick-to-start gap");
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }
    Some((job, insurance))
}

/// What an ORDINARY pick does at the flip to `Downloading`, and a
/// retention-insurance pick deliberately does not: re-arm the
/// queue-finished latch, emit `job.started` (a webhook acting on it
/// would act on a job the user deferred), and take the late-pick stamp.
///
/// The late-pick marker: the runner was free when this job arrived, yet
/// took over 2 s to start it - the signature of the fixed
/// runner-starvation bug, named so any recurrence attributes itself.
/// Taken, not read, so a job that requeues can never replay a stale
/// stamp - and NOT taken by an insurance pick, which runs last by
/// design (its lateness is not the signature) and must not spend the
/// real run's stamp.
fn note_ordinary_start(d: &Daemon, j: &mut Job) {
    d.queue_idle_latch.store(false, Ordering::Relaxed);
    emit_started(d, j);
    if let Some(waited) = j
        .queued_at
        .take()
        .filter(|_| j.idle_at_add)
        .map(|t| t.elapsed())
        .filter(|w| *w > std::time::Duration::from_secs(2))
    {
        d.note_event(
            "late",
            format!(
                "{} started {:.1} s after it was added with nothing \
                 ahead of it - the runner was slow to pick it up",
                j.name,
                waited.as_secs_f64()
            ),
        );
    }
}

/// §129 4a: the pick is the "started" moment, as its own kind.
///
/// A job that re-enters the runner after a demotion, disk hold or retry
/// starts again - `resumed` carries the difference. Its own function
/// only because `start_next` sits one line under the size ceiling; it is
/// called with the job lock held, exactly where the flip to
/// `Downloading` happens, so the event cannot describe a state the queue
/// payload has not reached.
fn emit_started(d: &Daemon, j: &Job) {
    // event-arm-gate: a STATE, not a moment - the queue row renders it.
    // `s.status` reads Downloading from the very next poll, so a toast
    // would narrate a row the user is already looking at. The rule is
    // finding (b) of §129 1b: a moment goes on the ring, a state stays
    // on the queue payload.
    d.life_emit(
        "job.started",
        json!({
            "nzo_id": j.nzo_id,
            "name": j.name,
            "category": j.category,
            "total_bytes": j.total_bytes,
            "resumed": j.downloaded_bytes > 0,
        }),
    );
}

/// The pick-to-start re-checks, run inside the one lock hold that is
/// atomic with the flip to Downloading - `pick_job` and
/// `pick_insurance_job` both drop the job lock before returning, so
/// everything they checked can move in the gap.
///
/// `relocating` is Codex F-06: a recategorize fits entirely inside the
/// gap, and starting into the destination races `move_tree`. `tombstone`
/// is the same gap class - a delete landing there has already begun
/// unlinking the payload and the spooled .nzb, so starting spends
/// bandwidth on a row the user just dismissed. An insurance pick is
/// re-judged in full: the insure toggle can turn off in the gap (nothing
/// could ever wind the fetch down afterwards, since
/// `insurance_yields_to_arrivals` finds the active fetch by
/// `g.insurance`), the row can be promoted or unpaused (it is
/// `pick_job`'s business now), or already banked. The caller answers
/// Ended, not Nothing, so another row can run.
fn start_gap_refusal(j: &Job, insurance: bool) -> bool {
    j.relocating > 0
        || j.tombstone
        || (insurance
            && (!j.insurance
                || j.fetched
                || j.state != JobState::Queued
                || crate::serve::insurance::insure_refusal(j).is_some()))
}

/// Run the guards, pick a job, run the three pre-pipeline arms
/// (`worker/prestart.rs`), then claim the hub and spawn the pipeline.
///
/// `quick`: the hand-over path, where a guard that holds must return
/// rather than sleep (the caller has a draining run to watch).
/// `carried`: the run whose drain this start overlaps; its pool-facing
/// figures are detached off the hub right before the new job claims
/// it, and not a moment earlier - a start that finds nothing leaves
/// the carried run owning the hub for its whole drain.
async fn start_next(st: &mut Runner, quick: bool, carried: Option<&mut Running>) -> Start {
    let d = st.d.clone();
    let config = st.config.clone();
    let Some(only_force) = download_guards(
        &d,
        &config,
        &st.lane,
        &mut st.guard_reason,
        &mut st.ledger,
        &mut st.disk_probe,
        &mut st.server_probe,
        quick,
    )
    .await
    else {
        return Start::Nothing;
    };
    d.run_due_auto_retries();
    let Some((job, insurance)) = pick_for_start(&d, only_force).await else {
        if !quick {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        return Start::Nothing;
    };
    // Never start a primary while this job's prefetch sidecar
    // still runs (possible when a library pick bypassed the
    // job-end stop below).
    {
        let picked = job.lock_ok().nzo_id.clone();
        let holds = d
            .sidecar
            .lock_ok()
            .as_ref()
            .is_some_and(|s| s.nzo_id == picked);
        if holds {
            stop_sidecar(&d).await;
            // The sidecar may have FINISHED this job while we
            // waited. Its success arm marks the job Completed
            // and hands the post-processing tail to a task of
            // its own, so that tail can be unlocking, renaming
            // or moving `out_dir` right now. Starting the
            // pipeline would point a fresh download at the
            // directory being moved out from under it, so
            // re-read what we picked on and let the job go if it
            // is no longer waiting to run (an insurance pick is
            // paused by design - its stand-down signal is the state).
            let j = job.lock_ok();
            if (j.paused && !insurance) || j.state != JobState::Queued {
                return Start::Ended;
            }
        }
    }
    let (nzb_path, out_dir, total, library, nzo_id, name, prio, job_password, eat_ok, failure_host) = {
        let mut j = job.lock_ok();
        // Re-read the pick's own preconditions here because this is the
        // only critical section that can be atomic with a publish that
        // invalidates them - see `start_gap_refusal` for the list.
        if start_gap_refusal(&j, insurance) {
            return Start::Ended;
        }
        j.state = JobState::Downloading;
        // An insurance pick is a background errand, not the user's
        // download starting - see the helper for what it skips.
        if !insurance {
            note_ordinary_start(&d, &mut j);
        }
        (
            j.nzb_path.clone(),
            j.out_dir.clone(),
            j.total_bytes,
            j.library,
            j.nzo_id.clone(),
            j.name.clone(),
            j.priority,
            j.password.clone(),
            j.eat_volumes_ok,
            // §99 try-order key for the in-stream password
            // probe: which site supplied the NZB.
            j.failure_host.clone(),
        )
    };
    let index_job_guard = d.begin_index_job();
    // Raise the guard first so an active scan observes it and
    // cancels, then rendezvous on the shared gate. Once this
    // lock is acquired no scan, tip ingest, eviction or
    // VACUUM can still be running beside the foreground job.
    //
    // Bounded (issue #38's second wedge shape): a lane wedged
    // mid-I/O against a mute peer would otherwise park this
    // runner forever with the job stuck in Downloading and
    // nothing logged. Past the bound, say so and start - every
    // lane also stands down on its own once the guard above is
    // visible, so the gate is confirmation, not permission.
    if d.index_pause_on_download.load(Ordering::Relaxed)
        && !index_gate_rendezvous(&st.index_pass_gate, index_gate_bound()).await
    {
        let detail = format!(
            "{name} started without the index-pass rendezvous - an index \
             lane held the gate past {} s (stuck mid-I/O against an \
             unresponsive server); it stands down on its own",
            index_gate_bound().as_secs()
        );
        warn!(target: "queue", "{detail}");
        d.note_event("indexer", detail);
    }

    // What the three arms that can end this job before any pipeline
    // starts need from the pick, gathered once. See
    // `worker/prestart.rs` for what belongs on that side of the seam
    // and what may not.
    let pre = prestart::PreStart {
        job: &job,
        nzb_path: &nzb_path,
        out_dir: &out_dir,
        name: &name,
        nzo_id: &nzo_id,
        insurance,
        overlapping: carried.is_some(),
    };

    // A /stream trigger re-queues a library entry at Force
    // priority - that's the "actually download now" signal.
    if library && prio < 2 {
        return prestart::metadata_only(st, &pre).await;
    }

    // Bracket this job's console output. Everything the
    // failure diagnosis needs - the per-file segment tally,
    // the per-server table, the first transport error - is
    // PRINTED and then lost: the log ring is memory-only and
    // 2000 lines deep, so a daemon restart (or a busy hour)
    // takes it with it, and the one-line fail_message is all
    // that reaches history. Marked before any of this job's
    // work so the snapshots below are its lines, nobody else's.
    let log_mark = nzbkit::logtee::mark();
    // Onto the RECORD as well, so `mode=report` can slice this
    // job's lines later. The ticket's copy dies with the tail;
    // a user asks for a report minutes or hours afterwards.
    if let Some(j) = d
        .queue
        .lock_ok()
        .iter()
        .find(|j| j.lock_ok().nzo_id == nzo_id)
    {
        j.lock_ok().log_mark = log_mark;
    }

    // TODO §138 (issue #29), opt-in `post_health_fail`: end a post the
    // §77 sample already proved gone, instead of spending a doomed
    // download to reach the same verdict. `prestart::post_health_giveup`
    // carries why the decision is the runner's and not the prober's.
    if let Some(ended) = prestart::post_health_giveup(st, &pre).await {
        return ended;
    }

    // Opt-in pre-flight (settings.json `preflight`): sample this post's
    // articles before spending the bandwidth on it - see
    // `prestart::preflight_verdict` for what may and may not stop a job
    // here.
    if let Some(ended) = prestart::preflight_verdict(st, &pre, log_mark).await {
        return ended;
    }

    // The hand-over proper. Everything the runner still needs from the
    // draining job comes off the hub NOW, while the hub is still that
    // job's; the next statement makes it this job's.
    let drain = carried.map(|c| {
        info!(
            target: "queue",
            "{nzo_id} starting while {} drains - its idle connections are handed over as they free up",
            c.nzo_id
        );
        let detached = detach_job_tail(&d, &c.nzo_id);
        let slot = DrainSlot {
            nzo_id: c.nzo_id.clone(),
            t_start: c.t_start,
            progress: c.progress.clone(),
            counters: d.hub.fetch_counters(),
            total: d.active_total.load(Ordering::Relaxed),
            resume_seeded: detached.resume_seeded,
            pool_live: detached.pool_live.clone(),
            abort: detached.abort.clone(),
            queue_ctl: detached.queue_ctl.clone(),
        };
        c.detached = Some(detached);
        slot
    });
    // Claim the shared progress counters for THIS job, in one
    // lock section with the re-pointing they describe. A queue
    // payload that reads the owner can then never pair it with
    // the next job's zeroes: it either gets the lock first and
    // sees the previous owner with the previous counters, or
    // gets it after and sees this job with this job's.
    let progress = {
        let mut owner = d.active_dl.lock_ok();
        // A fresh counter rather than a zeroed one: the previous
        // job's pipeline may still be counting its last in-flight
        // articles into the old one (see `ProgressCell`).
        let progress = d.progress.reset();
        *d.drain_dl.lock_ok() = drain;
        d.active_total.store(total, Ordering::Relaxed);
        // The UX §15 fetch-plan pair goes with them, and the plan
        // is zeroed FIRST: a reader that catches the gap sees "no
        // plan" and falls back to the counters above, never a
        // fresh plan paired with the previous job's finished
        // count. Fresh, not zeroed, for the same reason as the
        // byte counter.
        d.hub.fresh_fetch_counters();
        // §129 4b's post date goes with them, and for the same
        // reason: a whyslow tick between the transition and the
        // plan publish must not read the PREVIOUS job's post age
        // against this job's article misses. 0 is "unknown",
        // which asserts nothing.
        d.hub.post_unix.store(0, Ordering::Relaxed);
        *owner = Some(nzo_id.clone());
        // TODO 309(b): and where this job's journal lives, for the
        // queue payload's pause-cost answer. In here with the owner
        // publish because it IS the same fact - which job is on the
        // wire - and the payload path may not reach into the queue for
        // the out_dir (see `PauseCostState::owners`). It pushes the
        // predecessor into the second slot rather than over it: the
        // drain installed three lines up is still fetching, and until
        // 28 Aug 2026 this call is what silenced its row.
        d.note_wire_owner(&nzo_id, &out_dir);
        progress
    };
    let t_start = Instant::now();
    *d.started_at.lock_ok() = Some(t_start);

    reset_hub_for_job(&d, st.server_probe.config(), &nzo_id, failure_host);
    // This run's hand-over signal, read by the fleet builder into every
    // server's pool config. Installed after the reset so nothing the
    // reset clears can take it with it - and ONLY alongside a budget:
    // a signal without a lease would start the successor on a second
    // full fleet, which is exactly the cap overshoot the lease exists
    // to prevent. With `NZBFAST_QUEUE_HANDOFF=0` the signal is never
    // installed, so it never latches and the runner below waits for the
    // drain as it always did.
    let handoff = nzbkit::pool::handoff::HandoffSignal::new();
    *d.hub.handoff.lock_ok() = d.hub.conn_budget.get().map(|_| handoff.clone());
    let (net_tx, net_rx) = tokio::sync::oneshot::channel::<Instant>();
    // §293: a switch job (spare promotion, hunt replacement, §284
    // parked switch - every road stamps `alt_from`) donates from its
    // failed predecessor's output: the disk repair's adoption scan
    // reads that directory, so blocks the wire will not serve again
    // can still be found on disk. Resolved here because only the
    // daemon knows the predecessor. The row lookup runs under the
    // history lock; the existence check runs OUTSIDE it (out_dir can
    // be a network share, and a stat under the history lock stalls
    // the API behind it). A predecessor that is gone, or whose
    // directory was cleaned, degrades to an ordinary run - the
    // adoption walk itself tolerates the directory vanishing later.
    let donor_dirs: Vec<std::path::PathBuf> = {
        let alt_from = job.lock_ok().alt_from.clone();
        (!alt_from.is_empty())
            .then(|| {
                d.history.lock_ok().iter().find_map(|j| {
                    let g = j.lock_ok();
                    (g.nzo_id == alt_from).then(|| g.out_dir.clone())
                })
            })
            .flatten()
            .filter(|p| p.is_dir())
            .into_iter()
            .collect()
    };
    if let Some(p) = donor_dirs.first() {
        info!(
            target: "repair",
            "{nzo_id}: replacement job - the failed predecessor's files at \
             {} are available to the repair as donors",
            p.display()
        );
    }
    // PLAN M31: the same question one medium over - see
    // `predecessor_posting` below and `get::dupefill`.
    let donor_nzbs = predecessor_posting(&d, &job, &nzo_id);
    let fetch = {
        let config = config.clone();
        let nzb_path = nzb_path.clone();
        let out_dir = out_dir.clone();
        let progress = progress.clone();
        let hub = d.hub.clone();
        let stream_owner = nzo_id.clone();
        // Live settings, sampled once per job: a dashboard
        // change applies from the NEXT download.
        let connections = d.connections.load(Ordering::Relaxed).max(1);
        let window = d.window.load(Ordering::Relaxed).max(1);
        let decoders = d.decoders.load(Ordering::Relaxed).max(1);
        let fast_verify = d.fast_verify.load(Ordering::Relaxed);
        let verify_lean = d.verify_lean.load(Ordering::Relaxed);
        let par_cleanup = d.par_cleanup.load(Ordering::Relaxed);
        let skip_samples = d.skip_samples.load(Ordering::Relaxed);
        let mem_budget = st.mem_budget;
        tokio::spawn(async move {
            crate::get_with_progress(crate::JobSpec {
                config: &config,
                nzb_path: &nzb_path,
                out_dir: &out_dir,
                connections,
                window,
                decoders,
                fast_verify,
                verify_lean,
                // insurance banks volumes + journal, the resumable form
                // the promotion run extracts from.
                no_extract: insurance,
                // X5-03: the queue row is the durable terminal record
                // and `postproc::run_tail` commits it after this future
                // resolves, so the journal is not this run's to unlink -
                // see `JournalOwner`. Orthogonal to `no_extract` above:
                // that keeps the journal for a LATER run of this job,
                // this keeps it for THIS job's own post-processing tail,
                // and an insurance fetch wants both (its `insurance` arm
                // in `run_tail` re-queues the row and never finalizes,
                // so nothing retires it - which is the banked form).
                journal_owner: crate::JournalOwner::Caller,
                par_cleanup,
                skip_samples,
                password: job_password,
                eat_consent: eat_ok,
                donor_dirs,
                donor_nzbs,
                progress: Some(progress),
                hub: Some(hub),
                stream_owner: &stream_owner,
                net_done: Some(net_tx),
                budget: mem_budget,
            })
            .await
        })
    };
    Start::Started(Running {
        job,
        nzo_id,
        fetch,
        net_rx,
        net_at: None,
        handoff,
        t_start,
        log_mark,
        index_job_guard,
        progress,
        detached: None,
        insurance,
    })
}

// ---- the three pre-pipeline arms ------------------------------------
//
// The metadata-only .strm verdict, the §138 post-health give-up and the
// opt-in pre-flight sample live in worker/prestart.rs (TODO 106):
// `start_next` sat at 500 of the size gate's 500-line ceiling, the three
// are one subject sharing one exit, and none of them touches the
// hand-over, the hub claim or the pipeline spawn that are the rest of
// this file's job. The module doc states what may cross that seam.
mod prestart;

/// PLAN M31: the NZBs of duplicate POSTINGS of this job's release whose
/// live articles may fill a bad block - `get::dupefill`.
///
/// The sibling of `donor_dirs` in [`start_next`] and deliberately not
/// the same thing. That one is a failed predecessor's BYTES ON DISK,
/// which §293's block adoption already reads; this is a duplicate
/// posting's ARTICLES, so a block the wire refused US can be asked for
/// from a posting whose copy of it is still alive.
///
/// **STAGE 1 IS THE FAILED PREDECESSOR AND NOTHING ELSE, and that is a
/// deliberate narrowing rather than the obvious first cut.** The
/// spares §282 parks against a RUNNING row are equally reachable here
/// and were wired first; what that measured is written up in
/// `research/M31-DUPE-DONOR-LADDER-2026-08-28.md` and it is a product
/// question rather than a bug. In short: a job with a byte-identical
/// spare held against it now COMPLETES by borrowing a few of that
/// spare's articles, so §282's promotion rung never fires - which is
/// cheaper and better, and is also a decision to retire a shipped
/// escalation path on this lane's own authority. Two `daemon_ladder`
/// tests pin the old behaviour and both go red on it. So the source
/// that needs that decision is held back, and the one that needs no
/// decision at all ships. The write-up names the exact lines that turn
/// the other source back on, including the `held_against` re-widening
/// this narrowing reverted so the tree carries no reach nothing uses.
///
/// A promoted successor already IS the switch §282 chose, so borrowing
/// from the post it replaced spends nothing anyone was holding: that
/// job has failed, its NZB is in history, and its articles may well
/// still serve the segments THIS post lost - a job fails for many
/// reasons that are not "every article is gone".
///
/// Says so on the log itself rather than leaving that to the caller:
/// `start_next` sits under the size gate's function ceiling and this
/// sentence is about what THIS function found.
fn predecessor_posting(
    d: &Arc<Daemon>,
    job: &Arc<Mutex<Job>>,
    nzo_id: &str,
) -> Vec<std::path::PathBuf> {
    let alt_from = job.lock_ok().alt_from.clone();
    if alt_from.is_empty() {
        return Vec::new();
    }
    let pred = d.history.lock_ok().iter().find_map(|j| {
        let g = j.lock_ok();
        (g.nzo_id == alt_from).then(|| g.nzb_path.clone())
    });
    // A spool file that has been swept is not a donor. The existence
    // check runs OUTSIDE the history lock, for the reason
    // `start_next`'s donor_dirs stat does: the spool can be a network
    // share, and a stat under that lock stalls the API behind it.
    let out: Vec<std::path::PathBuf> = pred.into_iter().filter(|p| p.is_file()).collect();
    if !out.is_empty() {
        info!(
            target: "repair",
            "{nzo_id}: the post this replaces is available as an article donor - a block \
             no server serves for us may still be alive in its copy",
        );
    }
    out
}

/// The three arms that end a job before a pipeline starts share this
/// exit. The idle clock starts at every job exit, not only the
/// completion path - the idle memory trim arms on this stamp, and a
/// give-up as the last pick of the day otherwise left it unarmed for
/// good (§156 item 8a). `started_at` is untouched: these arms never
/// claimed it, and on the hand-over path it is the draining job's.
fn job_ended_before_pipeline(d: &Arc<Daemon>, overlapping: bool) {
    if !overlapping {
        *d.last_download_end.lock_ok() = Instant::now();
    }
}

/// The run's network phase is over: stand the per-job singletons down
/// (unless a successor already owns them), settle the figures and hand
/// the tail to the lane.
async fn finish(st: &mut Runner, run: Running) {
    let d = &st.d;
    let Running {
        job,
        nzo_id,
        fetch,
        t_start,
        net_at,
        log_mark,
        index_job_guard,
        progress,
        detached,
        insurance,
        ..
    } = run;
    // This run was handed over if its figures were detached: the hub,
    // the counters and `started_at` are the successor's, and only the
    // drain-side counter is this job's to clear.
    let handed_over = detached.is_some();
    // TODO 274 (e): this run's per-file counters have stopped moving, so
    // read them one final time for the tail that is about to start. Only
    // the hand-over path has anything to do here - it retired this table
    // at the successor's start, which is DURING this drain, and the rows
    // still in flight at that instant would otherwise read "downloading"
    // for the whole tail, directly under the drawer's own sentence
    // saying nothing more is being downloaded. On the plain path the
    // table is still on the hub and is frozen exactly when the next job
    // starts, so this is a no-op there.
    d.hub.settle_tail_files(&nzo_id);
    // Network wall time stops where the PIPELINE said it did, never
    // here: bytes÷seconds is the history's average speed, a stalled
    // tail once inflated a 72 s download to a recorded 121 s, and
    // since the hand-over this call can itself run long after the
    // network ended (the runner was holding the predecessor's drain).
    let dl_secs = net_at
        .unwrap_or_else(Instant::now)
        .saturating_duration_since(t_start)
        .as_secs_f64();
    if handed_over {
        *d.drain_dl.lock_ok() = None;
    } else {
        // Stand the watchdog down BEFORE waiting on the previous
        // tail, not after: `started_at` means "this job's network
        // phase is live", and the wait below can be long (job N-1's
        // tail once sat minutes in a Finder-trash stall). This job
        // is still Downloading in the queue for all of it, and the
        // watchdog reading a drained pool as "one host at ~0 MB/s
        // while others wait" demoted a job that had already
        // finished - park then re-queued it after post-processing
        // had renamed its directory, and the whole release
        // downloaded a second time (31 Jul queue soak).
        *d.started_at.lock_ok() = None;
        // Phase marker: the pipeline (download AND checks) is over.
        // This is what closes the chart's "checking files" shading -
        // without it the tint would run on into the idle time after
        // the job, dressing ordinary quiet as an endless check.
        d.note_event(
            "finished",
            "job finished - the line is idle until the next download",
        );
        // Release the progress counters at the same instant and for
        // the same reason: from here this job reads 100% and its
        // phase word, and the next job is free to zero them without
        // its bar appearing on this one's row.
        *d.active_dl.lock_ok() = None;
        // The network phase is what occupies the account, so the
        // idle clock starts here rather than after the tail: the
        // post-processing that follows touches no provider.
        *d.last_download_end.lock_ok() = Instant::now();
        // §129: the previous tail is the LANE's business now; only
        // the backpressure gate at the loop top can hold the line.
        // Wind down any idle-server prefetch before the next pick:
        // the next primary may be the very job the sidecar holds,
        // and two pipelines must never share an out_dir or a
        // server's connection budget. Its journal keeps the bytes.
        stop_sidecar(d).await;
    }
    let JobTail {
        dl_bytes,
        on_disk_bytes,
        verifier,
        shaper,
        resume_route,
        #[cfg(feature = "indexer")]
        oracle_samples,
        prov_facts,
        prov_post_unix,
    } = settle_job_tail(d, &nzo_id, &mut st.ledger, &progress, detached);
    st.lane
        .submit(PostprocTicket {
            job,
            fetch,
            verifier,
            shaper,
            resume_route,
            log_mark,
            dl_bytes,
            dl_secs,
            on_disk_bytes,
            index_job_guard,
            insurance,
            #[cfg(feature = "indexer")]
            oracle_samples,
            prov_facts,
            prov_post_unix,
        })
        .await;
}
