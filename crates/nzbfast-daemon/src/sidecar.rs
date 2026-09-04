//! The idle-server prefetch sidecar: a secondary download that runs on
//! ONLY the servers the active job leaves idle, so the next job is already
//! partly on disk when the runner gets to it.
//!
//! Moved out of job.rs bodily (TODO 106) as a SIBLING of `job` rather than
//! a child, so `pub(super)` still means "pub in serve" and no call site
//! moved - the runner (`tasks.rs`), the slow-job watchdog
//! (`tasks/stall.rs`) and `Daemon::sidecar` all reach these by the names
//! they always used.

use super::*;

/// A secondary download running on ONLY the servers the active job
/// leaves idle (their copies of its articles keep 430ing). Its own hub
/// gives it independent abort control and pool stats; its writes land in
/// the job's normal out_dir + journal, so however it ends - completion,
/// abort at active-job end, or "these servers don't have it either" -
/// nothing is lost: the eventual primary run resumes from the journal.
pub struct Sidecar {
    pub nzo_id: String,
    /// `pub(crate)`: [`crate::StreamHub`] is crate-private, and the
    /// field follows it (Q5, as with [`Job::health`]).
    pub hub: Arc<crate::StreamHub>,
    /// Decoded bytes so far (dashboard shows prefetch progress).
    pub progress: Arc<AtomicU64>,
    /// Pre-armed cancel: the pipeline installs its own abort flag into
    /// the hub only once it starts - this one is checked by the task
    /// BEFORE that, so a stop can never miss the install window.
    pub cancelled: Arc<std::sync::atomic::AtomicBool>,
    pub task: tokio::task::JoinHandle<()>,
    /// Rolling ~5 s window of `progress` samples, for the early start's
    /// OWN throughput series on the dashboard chart (`Sidecar::rate_bps`).
    /// Per-sidecar rather than on the daemon, so a fresh early start can
    /// never read a rate across the previous one's bytes.
    pub rate_win: Mutex<VecDeque<(Instant, u64)>>,
    /// True when this sidecar runs on connections BORROWED from servers
    /// busy on the active job (no healthy idle server existed). An idle
    /// sidecar suppresses the defer verdict - the idle capacity is
    /// already on the next job, so demoting the slow one buys nothing.
    /// A borrowed sidecar claims no idle capacity, so that reasoning
    /// does not apply and the watchdog stays armed.
    pub borrowed: bool,
}

impl Sidecar {
    /// What the early start is pulling right now, bytes/sec, over the
    /// same ~5 s window and the same rules as the primary job's rate -
    /// `window_rate` is shared with `Daemon::current_speed_bps` for
    /// exactly that reason, since the dashboard draws the two against
    /// one axis.
    ///
    /// Sampled where it is READ (once per queue poll, before the queue
    /// lock, beside the `progress` snapshot the rows are matched
    /// against), not on a timer of its own: the counter is a plain
    /// atomic the pipeline bumps, so there is nothing to schedule.
    /// A poll that stops therefore stops the window too, and the first
    /// figure after it resumes is an honest average over that whole gap
    /// - `window_rate` never evicts its last two samples, precisely so
    /// that a client polling more slowly than the window is long reads a
    /// rate rather than a zero.
    ///
    /// Which is also why the counter is handed over as a CLOSURE rather
    /// than loaded here: several clients can be polling at once, and a
    /// reading taken before the window's lock can arrive after a later
    /// one, which reads as a counter going backwards and drops the
    /// window. See `window_rate`, where the measurement is written up.
    pub fn rate_bps(&self) -> f64 {
        window_rate(&self.rate_win, || self.progress.load(Ordering::Relaxed))
    }
}

/// Which round of a record's life this is, and where it is pointed:
/// `(retries, move_seq, out_dir)`.
///
/// `retries` is bumped only by [`Daemon::retry`] and `move_seq` only by
/// `moveseq::stamp_move`, which is retry, park and `activate_parked` -
/// NOT a recategorize, whatever an earlier version of this comment
/// claimed. `requeue_category` re-points a queued job's `out_dir` and
/// stamps nothing, so a prefetch that ran across it kept passing this
/// test and filed a Completed row against a directory holding none of
/// the bytes it had just downloaded (Fable sweep 15 Aug).
///
/// So the directory is part of the stamp rather than a fact this test
/// hopes every re-pointer remembers to announce: the sidecar's result
/// is only about the directory it wrote into.
fn job_generation(g: &Job) -> (u32, u64, std::path::PathBuf) {
    (g.retries, g.move_seq, g.out_dir.clone())
}

/// May the prefetch that sampled `gen0` still claim this record?
///
/// A queued job can be RUNNING in the sidecar, and the NZBGet delete
/// verbs file exactly such a job into history while the task is alive -
/// tombstoned, because the tombstone is the only thing that makes the
/// late Ok a no-op. Then the user presses Retry, which clears the
/// tombstone by design (a retry is an instruction to RUN), and the
/// sidecar's Ok arrived afterwards to flip the freshly re-queued record
/// to Completed, run the whole completion tail on payload the delete had
/// already removed, and park the retry into history - consuming the
/// button the user had just pressed (Codex sweep 14 Aug M3).
///
/// The window is not a race: the sidecar's cancel flag is read once,
/// right after the network phase, so a delete landing during the disk
/// tail (verify, repair, unpack) cannot stop the pipeline at all and the
/// user has that whole span to delete and retry.
///
/// So the tombstone alone cannot be the test - retry legitimately clears
/// it. The generation is what a retry cannot hide.
///
/// The tombstone half stays in front of it, and does more here than the
/// downstream gates it duplicates: the delete verbs file that SAME Arc
/// into history as Failed/DELETED, so the old unconditional
/// `state = Completed` was rewriting a filed delete row into a
/// completion. Refusing the write leaves the record saying what actually
/// happened to it, and skipping the tail costs nothing the delete
/// handler has not already done (the queue row is gone, the history row
/// is filed, the spooled .nzb is settled).
fn sidecar_result_is_ours(g: &Job, gen0: &(u32, u64, std::path::PathBuf)) -> bool {
    !g.tombstone && job_generation(g) == *gen0
}

/// Abort the sidecar (if any) and wait for it to wind down. Called by
/// the runner at every primary-job end - the next pick may be the very
/// job the sidecar holds open, and two pipelines must never share an
/// out_dir or a server's connection budget. The abort is re-fired on a
/// short interval because the pipeline installs its hub abort/queue-ctl
/// handles asynchronously after launch.
///
/// This waits for the DOWNLOAD only. A sidecar that completed its job
/// hands the post-processing tail to a task of its own (see
/// `spawn_sidecar`), so the queue never waits on a move to a NAS.
pub async fn stop_sidecar(d: &Arc<Daemon>) {
    // Take the TASK, not the slot. `remove_after_sidecar_drain` reads the
    // slot to decide when a deleted job's writers are done, and the
    // pipeline keeps writing well past the abort - the consumer join and
    // the two pending flushes all run before it bails, and
    // `ensure_plain_writer` opens a slot's file lazily, recreating the
    // directory. Emptying the slot here answered "writers are done" while
    // they demonstrably were not, which is the very orphan-payload shape
    // the drain exists to prevent (Fable sweep 15 Aug). The slot stays
    // occupied for the whole wind-down and is cleared below.
    let taken = {
        let mut g = d.sidecar.lock_ok();
        g.as_mut().map(|s| {
            let task = std::mem::replace(&mut s.task, tokio::spawn(async {}));
            (task, s.hub.clone(), s.cancelled.clone())
        })
    };
    if let Some((mut task, hub, cancelled)) = taken {
        d.note_event(
            "sidecar",
            "early start wound down - the main queue takes over",
        );
        cancelled.store(true, Ordering::Relaxed);
        loop {
            if let Some(f) = hub.abort.lock_ok().as_ref() {
                f.store(true, Ordering::Relaxed);
            }
            if let Some(c) = hub.queue_ctl.lock_ok().as_ref() {
                c.abort();
            }
            // A timeout means the handles are not installed yet - re-fire.
            if tokio::time::timeout(std::time::Duration::from_millis(250), &mut task)
                .await
                .is_ok()
            {
                break;
            }
        }
        // Writers are genuinely done now, so the slot may go. Only clear
        // the run we just stopped: the task's own exit path may already
        // have cleared it and a fresh prefetch may have taken the slot.
        let mut g = d.sidecar.lock_ok();
        if g.as_ref()
            .is_some_and(|s| Arc::ptr_eq(&s.cancelled, &cancelled))
        {
            *g = None;
        }
    }
}

/// The completion tail a finished prefetch owes its job: the same
/// hand-over, unlock, junk sweep, rename and move the runner's lane
/// gives one, then the hooks, then history.
///
/// Named rather than inline in the spawn so the fence has something to
/// be tested against: the whole hazard is that this runs on a task of
/// its own, an unbounded interval after the ownership test that
/// authorised it, and an interval nothing in a test can otherwise open.
///
/// `fence` is the round of the record's life the prefetch was serving.
/// Every step re-reads it, so a delete-and-retry that lands while this
/// is queued or part-way through leaves the new generation alone.
///
/// `owner` is the prefetch's cancel flag, which is how every sidecar
/// identity test here names a run. Registering it keeps
/// `sidecar_still_holds` true for the length of this tail.
///
/// `verifier` and `shaper` are the prefetch run's own snapshots, taken
/// off its PRIVATE hub at the spawn site and moved in here - see the
/// settle call below for why they have to travel by hand rather than be
/// read from `d.hub`. Both are `Option` because both are absent on the
/// paths the unit tests drive, which call this function with no run
/// behind it at all; `None` is a normal caller of the settle step, not
/// a degenerate one.
pub(super) async fn completion_tail(
    d: Arc<Daemon>,
    job: Arc<Mutex<Job>>,
    fence: Option<(u32, u64)>,
    owner: Option<SidecarTailGuard>,
    verifier: Option<Arc<nzbkit::live::LiveVerifier>>,
    shaper: Option<Arc<nzbkit::extract::Extractor>>,
) {
    // Held for the whole tail, so a delete-with-files that landed on
    // this record waits for THIS - not just for the download task,
    // which cleared the sidecar slot on its way to spawning us. Taken
    // by the SPAWNER (see the spawn site) so there is no gap between
    // the slot going and this ownership being on the books; the guard
    // deregisters however this ends, panic included.
    let _owner = owner;
    finalize_completed_gen(&d, &job, fence).await;
    // ISSUE #18's deferral is a HOLD, and whoever arms it owes the
    // release. With `write_manifest` on - the shipped default since
    // §310 - `finalize_cleanup_exts` drops `par2` from the sweep the
    // call above runs, and this is the only function that puts it back.
    // Without this line a prefetch that finished a whole job left its
    // recovery files in the folder for ever: invisible while the flag
    // was opt-in, the default the day it was flipped on.
    //
    // The verifier and the extractor travel as ARGUMENTS, and that is
    // the whole shape of this road. The prefetch runs against its OWN
    // hub (`StreamHub::default()`, below), while the ticket the runner
    // hands `postproc::run_tail` snapshots `d.hub.verifier`
    // (`tasks/runner.rs`) - so reading `d.hub` here would hand this
    // job's tail whatever the ACTIVE job happens to have on the daemon
    // hub, which is a different job by construction (the prefetch only
    // runs while another job downloads). The private hub is populated:
    // `get/vrig.rs`'s `install_seek` publishes the verifier, the
    // extractor and the seek ladder onto whatever hub the run was given,
    // and the sidecar gives it one. It is unreachable from here only in
    // the sense that nothing on this task can see it - so the spawn site
    // clones both Arcs off that hub before the prefetch task ends and
    // passes them in. This was two `None`s and a stated limit until
    // §310 turned `write_manifest` on by default (2 Sep 2026); the cost
    // was that a job a prefetch finished outright left a folder with no
    // `.nzbfast.manifest` in it, silently, beside folders that had one.
    //
    // **PASSING THEM CHANGES WHAT THE SWEEP BELOW MEANS, and that is
    // handled inside the one function rather than here.**
    // `par2_sweep_deferred` reads the GLOBAL `write_manifest` flag, so
    // it answers "a manifest is owed" for this road too; what used to
    // make the unconditional sweep correct was that no verifier came
    // with it. `settle_manifest_and_deferred_par2_sweep` writes the
    // manifest FIRST and sweeps second, and declines the sweep when the
    // write fails - so the recovery files outlive a failed write rather
    // than leaving the directory uncheckable by anything. Do not add a
    // second sweep here to "make sure": one function, one place, and a
    // run whose verifier carries no PAR2 set (a post with no recovery
    // data) falls through it to exactly the unconditional sweep this
    // line has always performed.
    super::postproc::settle_manifest_and_deferred_par2_sweep(
        &d,
        &job,
        verifier.as_ref(),
        shaper.as_ref(),
        fence,
    )
    .await;
    // "then the hooks, then history" above is an ordering, not a
    // sequence of statements: `park_gen` is what a SAB client reads
    // Completed from, and the post-processing script is what may still
    // be moving the payload it is about to import. Same await, same
    // reason, as the runner's own lane tail.
    crate::hooks::run_post_job_hooks_before_park(&d, &job, fence).await;
    d.park_gen(job, fence);
}

/// A recategorize re-pointed this record while the prefetch was
/// downloading into the OLD directory: take the bytes and the journal
/// with it.
///
/// `requeue_category` rewrites `category` and `out_dir` on a still-
/// `Queued` job and stamps neither counter, so it is invisible to
/// everything except the directory half of [`job_generation`] - which
/// only ever made the prefetch DISCARD its result. The bytes stayed
/// where they were: a part-downloaded release and its journal sitting
/// in a folder no record named, while the primary run started at the
/// new directory and fetched the whole release again over the same
/// provider quota (read-only sweep 2, M7).
///
/// Runs at the END of the prefetch task and nowhere else, which is
/// what makes it safe to move a whole directory with no lock held: the
/// runner awaits that task (`stop_sidecar`) before it may start this
/// job, so nothing can be writing at either path while this runs.
///
/// Only the recategorize shape is adopted. A retry re-points too, but
/// it re-points BECAUSE the old folder was filed, taken by someone
/// else, or outside the configured root - it zeroes the record's
/// progress and means to start clean - and it stamps both counters, so
/// the test below tells the two apart.
fn adopt_reparented_directory(job: &Mutex<Job>, gen0: &(u32, u64, std::path::PathBuf)) {
    let to = {
        let g = job.lock_ok();
        if g.retries != gen0.0 || g.move_seq != gen0.1 || g.state != JobState::Queued {
            return;
        }
        g.out_dir.clone()
    };
    let from = &gen0.2;
    if &to == from || !from.exists() {
        return;
    }
    match crate::smart::move_tree(from, &to) {
        Ok(()) => info!(
            target: "prefetch",
            "moved the early start's progress from {} to {} - the release was \
             re-filed while it was downloading, so nothing has to be fetched twice",
            from.display(),
            to.display()
        ),
        // Not fatal to anything: the record is correct, the new
        // directory is empty, and the job simply downloads again. Say
        // where the abandoned bytes are, because nothing else will.
        Err(e) => warn!(
            target: "prefetch",
            "could not move the early start's progress from {} to {}: {e} - \
             the release will be downloaded again, and those files are not \
             named by any record",
            from.display(),
            to.display()
        ),
    }
}

/// Launch the idle-server prefetch pipeline for `job` (see Sidecar).
///
/// `fleet` is the host set the sidecar may download on:
/// - `borrow == false`: the idle hosts. The exclusion list is every host
///   that IS serving the active job, plus every host on which each
///   enabled account is an exhausted prepaid block, plus the
///   auth-refused hosts - the sidecar may only touch idle capacity.
/// - `borrow == true`: healthy BUSY hosts, used when no healthy idle
///   server exists (the 31 Jul soak state: the only idle server
///   auth-refused, and cross-job tail-overlap simply never engaged -
///   49 s line-idle of a 144 s queue vs ~2% healthy). Each host stays in
///   the sidecar's fleet but its pool is capped (hub.host_conn_caps) to
///   a 1-2 connection slice sized into the headroom between the active
///   job's fleet and the provider cap, so the next job's tail-overlap
///   engages without starving the active job. When there is no headroom
///   (the active fleet already fills the account limit) the single
///   borrowed connection may be capacity-refused; the sidecar's own pool
///   answers 481s by yielding, never hammering (see AuthState in
///   nzbkit::pool), and picks the slot up as the active job's tail
///   releases it - which is exactly when tail-overlap wants it.
pub fn spawn_sidecar(
    d: &Arc<Daemon>,
    config: &Path,
    job: &Arc<Mutex<Job>>,
    fleet: &[String],
    deltas: &[(String, u64)],
    budget: nzbkit::mem::MemBudget,
    borrow: bool,
) {
    let (nzo_id, nzb_path, out_dir, password) = {
        let g = job.lock_ok();
        (
            g.nzo_id.clone(),
            g.nzb_path.clone(),
            g.out_dir.clone(),
            g.password.clone(),
        )
    };
    let total: u64 = deltas.iter().map(|(_, b)| b).sum();
    let cfg_loaded = nzbkit::config::Config::load(config).ok();
    // §96.5: the same block-account arithmetic the main job's start
    // does, from the SAME place - `Daemon::block_pool_rules`, which owns
    // the rule and every reason behind it. This was written out a second
    // time here until 28 Aug 2026 and carried all three of that helper's
    // defects: it read DISABLED rows, one exhausted row excluded the
    // whole host (funded or flat-rate siblings with it), and the budget
    // map was last-write-wins so the config's order decided the cap.
    // Keep the two on one helper; a third copy is how they drift.
    let (block_excluded, block_budgets) = d.block_pool_rules(
        cfg_loaded
            .as_ref()
            .map(|c| c.servers.as_slice())
            .unwrap_or(&[]),
    );
    let block: std::collections::HashSet<String> = block_excluded.into_iter().collect();
    // Servers the active job's pool has recorded a refusal for (bad
    // credential or connection/IP cap) moved no bytes, so the busy-host
    // test below never catches them - but they are dead weight, not idle
    // capacity, and the sidecar must not build its fleet on them. The
    // pool clears the note on the next successful connect, so a cap that
    // lifts re-qualifies the host for the NEXT spawn.
    let refused: std::collections::HashSet<String> = d
        .hub
        .pool_live
        .lock_ok()
        .as_ref()
        .map(|l| {
            l.servers
                .iter()
                .filter(|s| s.refusal.lock_ok().is_some())
                .map(|s| s.host.clone())
                .collect()
        })
        .unwrap_or_default();
    // The caller filters too, but enforcement must not depend on it.
    let fleet: Vec<String> = fleet
        .iter()
        .filter(|h| !refused.contains(*h) && !block.contains(*h))
        .cloned()
        .collect();
    if fleet.is_empty() {
        return;
    }
    // The borrowed slice per host: the provider cap (config `connections`
    // - "we typically use far fewer") minus the active job's fleet is
    // free headroom; take up to 2 connections of it so active + sidecar
    // never overcount the account limit. With zero headroom, take 1 and
    // let the pool's capacity-refusal handling wait it out (doc above).
    let caps: std::collections::HashMap<String, usize> = if borrow {
        let global = d.connections.load(Ordering::Relaxed).max(1);
        fleet
            .iter()
            .filter_map(|h| {
                let acct = cfg_loaded
                    .as_ref()?
                    .servers
                    .iter()
                    .find(|s| &s.host == h)?
                    .connections
                    .max(1) as usize;
                let headroom = acct.saturating_sub(global.min(acct));
                Some((h.clone(), headroom.clamp(1, 2)))
            })
            .collect()
    } else {
        Default::default()
    };
    // A borrowed host without a computed cap (config unreadable, or the
    // host vanished from it) must not join the fleet at all - an
    // uncapped "borrow" would be a full second fleet on a busy server.
    // Narrowed BEFORE the exclusion list is built, so a dropped host
    // falls back into it (it is busy) instead of slipping through both.
    let fleet: Vec<String> = if borrow {
        let kept: Vec<String> = fleet.into_iter().filter(|h| caps.contains_key(h)).collect();
        if kept.is_empty() {
            return;
        }
        kept
    } else {
        fleet
    };
    let mut excl: Vec<String> = deltas
        .iter()
        .filter(|(_, b)| (*b as f64) >= total as f64 * 0.01)
        // Borrow mode deliberately keeps its (busy) fleet hosts in.
        .filter(|(h, _)| !(borrow && fleet.contains(h)))
        .map(|(h, _)| h.clone())
        .collect();
    excl.extend(block);
    excl.extend(refused);
    let hub = Arc::new(crate::StreamHub::default());
    *hub.excluded_hosts.lock_ok() = excl;
    *hub.host_conn_caps.lock_ok() = caps.clone();
    // §96.5: a block host with bytes left may serve the sidecar, but
    // its remaining budget rides along, so a block that runs out
    // mid-prefetch releases the server there and then, same as on the
    // main job. Computed above with the exclusion, in one pass, so the
    // two cannot disagree about the same host. (The ledger is read at
    // spawn: a main job spending the same host concurrently is not
    // re-subtracted mid-run, so the bound is per-fleet, not global -
    // the exclusion lists above keep that overlap to the borrow path.)
    *hub.host_byte_budgets.lock_ok() = block_budgets;
    // M29 3d: the idle-server prefetch is real availability signal too.
    // The primary job's OracleSink lives on the daemon hub; this sidecar
    // runs on a FRESH hub, so without its own sink every 222/430 it sees
    // was silently dropped. Give it one and drain it when it winds down.
    *hub.oracle.lock_ok() = Some(Arc::new(nzbkit::oracle::OracleSink::default()));
    let progress = Arc::new(AtomicU64::new(0));
    let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut sc_guard = d.sidecar.lock_ok();
    if sc_guard.is_some() {
        return; // raced another spawn - keep the first
    }
    if borrow {
        let slice: Vec<String> = fleet
            .iter()
            .map(|h| format!("{h} x{}", caps.get(h).copied().unwrap_or(1)))
            .collect();
        info!(
            target: "prefetch",
            "{nzo_id} borrowing connection(s) from busy server(s) {} while the active job downloads (no healthy idle server)",
            slice.join(", ")
        );
        d.note_event(
            "sidecar",
            "next job started early on connections borrowed from busy servers",
        );
    } else {
        info!(
            target: "prefetch",
            "{nzo_id} starting on idle server(s) {} while the active job downloads",
            fleet.join(", ")
        );
        d.note_event("sidecar", "next job started early on idle servers");
    }
    let eat_ok = job.lock_ok().eat_volumes_ok;
    // Which round of this record's life the prefetch is serving. See
    // [`sidecar_result_is_ours`] - the Ok arm below compares against it
    // before it claims the record.
    let gen0 = job_generation(&job.lock_ok());
    let task = {
        let d = d.clone();
        let config = config.to_path_buf();
        let job = job.clone();
        // Kept back from the completion tail's spawn, which consumes
        // the handle above: the exit path below still needs the record.
        let job2 = job.clone();
        let hub = hub.clone();
        let progress = progress.clone();
        let cancelled = cancelled.clone();
        let nzo_id = nzo_id.clone();
        let connections = d.connections.load(Ordering::Relaxed).max(1);
        let window = d.window.load(Ordering::Relaxed).max(1);
        let decoders = d.decoders.load(Ordering::Relaxed).max(1);
        let fast_verify = d.fast_verify.load(Ordering::Relaxed);
        let verify_lean = d.verify_lean.load(Ordering::Relaxed);
        let par_cleanup = d.par_cleanup.load(Ordering::Relaxed);
        let skip_samples = d.skip_samples.load(Ordering::Relaxed);
        tokio::spawn(async move {
            let t0 = Instant::now();
            let res = if cancelled.load(Ordering::Relaxed) {
                Err(anyhow::anyhow!("cancelled before start"))
            } else {
                crate::get_with_progress(crate::JobSpec {
                    config: &config,
                    nzb_path: &nzb_path,
                    out_dir: &out_dir,
                    connections,
                    window,
                    decoders,
                    fast_verify,
                    verify_lean,
                    no_extract: false,
                    // X5-03. A prefetch that finishes the WHOLE job runs
                    // the same tail the runner gives one - `sidecar::
                    // completion_tail` is `finalize_completed_gen`, the
                    // hooks, then `park_gen` - so the terminal record
                    // lands there and not here, and this run's finish is
                    // only half of it. Same window, same answer as the
                    // runner beside it.
                    journal_owner: crate::JournalOwner::Caller,
                    par_cleanup,
                    skip_samples,
                    password,
                    // The sidecar prefetches ANOTHER job; its consent
                    // travels with that job's record, not this one's.
                    eat_consent: eat_ok,
                    // §293: and its donor question travels the same way -
                    // the primary runner resolves donors when the job
                    // actually runs; the prefetch never repairs.
                    donor_dirs: Vec::new(),
                    // PLAN M31, same reason one line up: the prefetch
                    // never settles, so it never has a bad block to fill.
                    donor_nzbs: Vec::new(),
                    progress: Some(progress.clone()),
                    hub: Some(hub.clone()),
                    stream_owner: &nzo_id,
                    net_done: None,
                    budget,
                })
                .await
            };
            // Bill what moved to the per-server usage history either way
            // (block accounts must see every byte).
            let per: Vec<(String, u64)> = hub
                .pool_live
                .lock_ok()
                .as_ref()
                .map(|l| {
                    l.servers
                        .iter()
                        .map(|s| (s.host.clone(), s.bytes.load(Ordering::Relaxed)))
                        .collect()
                })
                .unwrap_or_default();
            d.add_usage(&per);
            // M29 3d: fold the sidecar's per-article hit/430 outcomes into
            // the availability ledger, exactly as the primary job does at
            // net-drain. Partial/cancelled runs still carry real signal.
            #[cfg(feature = "indexer")]
            if let Some(sink) = hub.oracle.lock_ok().take() {
                let samples = sink.drain();
                if !samples.is_empty() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|t| t.as_secs() as i64)
                        .unwrap_or(0);
                    // Bounded like the primary tail's fold: the queue
                    // runner awaits this task through `stop_sidecar`
                    // before starting its next pick, so an unbounded
                    // wait here parks the whole picker behind a wedged
                    // scan lane (the 20 Aug 8m46s hold).
                    d.with_index_for_tail(&nzo_id, |ix| ix.oracle_ingest(&samples, now).ok());
                }
            }
            match res {
                Ok(()) => {
                    // The whole job fit on the idle servers - it's done.
                    // Unless the record stopped being ours while we ran:
                    // the ownership test and the state write are ONE hold
                    // of the job lock, or the interleaving this guards
                    // against simply moves inside the gap between them.
                    let ours = {
                        let mut g = job.lock_ok();
                        let ours = sidecar_result_is_ours(&g, &gen0);
                        if ours {
                            g.state = JobState::Completed;
                            g.fetched = true;
                            g.downloaded_bytes = progress.load(Ordering::Relaxed);
                            g.elapsed_secs = t0.elapsed().as_secs_f64();
                            g.finished_at = Some(Instant::now());
                            g.finished_unix = Some(unix_now());
                        }
                        ours
                    };
                    if !ours {
                        // Nothing is lost by walking away: every byte is
                        // on disk and in the journal, so whichever run
                        // owns the record now resumes from them.
                        info!(
                            target: "prefetch",
                            "{nzo_id} finished, but the record left this early start's \
                             custody while it ran (deleted, or deleted and sent round \
                             again) - keeping the bytes, dropping the result"
                        );
                    } else {
                        info!(
                            target: "prefetch",
                            "{nzo_id} completed entirely on {}",
                            if borrow {
                                "borrowed connections"
                            } else {
                                "idle servers"
                            }
                        );
                        d.note_event(
                            "sidecar",
                            if borrow {
                                "early start finished the whole job on borrowed connections"
                            } else {
                                "early start finished the whole job on idle servers"
                            },
                        );
                        // A sidecar completion is a completion: it owes
                        // the job the same tail the runner gives one
                        // (hand-over, unlock, junk sweep, rename, move),
                        // and it must run before the pp-script and
                        // history see the job.
                        //
                        // On its OWN task, because the runner awaits this
                        // one (stop_sidecar) at every primary-job end
                        // before it may pick the next: a tail that copies
                        // the payload to a NAS would hold the whole queue
                        // for the length of that copy. Nothing here needs
                        // the sidecar's abort handles - the download is
                        // over and its connections are gone.
                        //
                        // ...and on that task the ownership answer above
                        // is a CACHED BOOLEAN, taken before an unlocked
                        // interval of unbounded length: the tail can sit
                        // behind the runtime's queue, and once it starts
                        // it unlocks, sweeps, renames, files into the TV
                        // library and copies to a NAS. Delete the record
                        // in there and retry it - the shape this whole
                        // ownership test exists for - and the old
                        // prefetch's tail did all of that to the retry,
                        // fired its hooks, and parked it straight back
                        // into history (read-only sweep 2, M5). So the
                        // generation travels with the work rather than
                        // being spent on the state write: the same fence
                        // the post-processing lane carries, for the same
                        // reason and by the same route.
                        //
                        // `park_gen`, not `park`: it declines a record
                        // that has moved on, and hands the two custody
                        // maps back on its way out.
                        //
                        // `(retries, move_seq)` and not the directory
                        // that [`job_generation`] adds: the one
                        // re-pointer that stamps neither counter is
                        // `requeue_category`, and it refuses anything
                        // that is not still `Queued`. The write above
                        // has already made this record `Completed`, so
                        // from here the directory cannot move without
                        // one of those two counters moving with it.
                        let d2 = d.clone();
                        // Registered HERE, synchronously, not on the
                        // spawned task. `tokio::spawn` only queues it,
                        // and the slot is cleared a few lines below on
                        // this thread - so a tail that registered itself
                        // would leave a window in which the slot says
                        // "gone" and the tail has not yet said "mine".
                        // A `remove_after_sidecar_drain` poll landing in
                        // there reads `sidecar_still_holds` false and
                        // removes the directory, hands the reservation
                        // back, and the tail then unlocks, sweeps,
                        // renames and moves inside it - the exact orphan
                        // shape M6 closed for the download half. The
                        // guard moves into the tail and deregisters
                        // however it ends, panic included.
                        let owner = d.sidecar_tail_begin(cancelled.clone());
                        // §310. Taken HERE, off the prefetch's private
                        // hub, because this is the last moment either
                        // exists: `hub` is fresh per prefetch and its
                        // final Arc drops a few lines below when the
                        // slot is cleared, so a tail that went looking
                        // for them would find the ACTIVE job's instead.
                        // `install_seek` put them there (`get/vrig.rs`);
                        // the settle step inside the tail turns the
                        // verifier's parsed PAR2 sets into the
                        // `.nzbfast.manifest` that lets this folder be
                        // re-checked years after the recovery files are
                        // swept, and reads the extractor only for
                        // whether the payload arrived as an archive.
                        //
                        // Owner-checked like the runner's own snapshot
                        // (`d.hub.extractor_for(Some(nzo_id))`) even
                        // though this hub has exactly one run on it: the
                        // rule costs nothing and is the same rule.
                        let verifier = hub.verifier.lock_ok().clone();
                        let shaper = hub.extractor_for(Some(&nzo_id));
                        tokio::spawn(completion_tail(
                            d2,
                            job,
                            Some((gen0.0, gen0.1)),
                            Some(owner),
                            verifier,
                            shaper,
                        ));
                    }
                }
                Err(e) => {
                    // A restricted attempt, not a verdict - the job stays
                    // queued and its journal keeps everything landed.
                    //
                    // Our own wind-down surfaces from the pipeline as the
                    // user-cancel bail ("stopped by user"), and printing
                    // that verbatim reads as a cancel nobody made (issue
                    // #38). The runner set `cancelled` before firing the
                    // abort, so the flag says which story is true.
                    if cancelled.load(Ordering::Relaxed) {
                        info!(
                            target: "prefetch",
                            "{nzo_id} wound down - the main queue takes over (progress kept in the journal)"
                        );
                    } else {
                        info!(target: "prefetch", "{nzo_id} stopped: {e} (progress kept in the journal)");
                    }
                }
            }
            // Before the slot goes, because the slot is what keeps the
            // runner off this job: everything this touches must be
            // settled while `stop_sidecar` is still awaiting us.
            adopt_reparented_directory(&job2, &gen0);
            // And the parked sessions go with the hub they are parked
            // in. This hub is FRESH per prefetch (see above) and has no
            // second owner, so once the slot is cleared the last Arc
            // drops - and `WarmPool` has no Drop impl, its keepalive
            // holding only a Weak. A successful prefetch on a
            // warm-pool server therefore dropped every session it had
            // parked without a QUIT, and the provider went on counting
            // them against the account's connection cap until its own
            // idle timeout - the same occupancy the wind-down clears
            // for the main hub (read-only sweep 2 M9, re-found by
            // Codex sweep 3 M13). `.get()`, NOT `warm()`: the accessor
            // CONSTRUCTS the pool and spawns a keepalive tick, so
            // asking for it here would create the very thing we are
            // emptying. Bounded - each `quit()` carries its own
            // timeout - so `stop_sidecar` cannot park on a mute peer.
            if let Some(warm) = hub.warm.get() {
                warm.clear().await;
            }
            let mut g = d.sidecar.lock_ok();
            if g.as_ref().is_some_and(|s| s.nzo_id == nzo_id) {
                *g = None;
            }
        })
    };
    *sc_guard = Some(Sidecar {
        nzo_id,
        hub,
        progress,
        rate_win: Mutex::new(VecDeque::new()),
        cancelled,
        task,
        borrowed: borrow,
    });
}

#[cfg(test)]
mod sidecar_tests {
    use super::*;
    use crate::testutil::test_daemon;

    pub fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("nzbfast-sc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A prefetch whose record was deleted and then RETRIED must not
    /// claim the retry with its own late Ok.
    ///
    /// The NZBGet delete verbs file a still-running queued job into
    /// history and rely on the tombstone to make the late Ok a no-op.
    /// Retry clears that tombstone by design - it is an instruction to
    /// RUN - so the guard has to be something a retry cannot hide, or
    /// the old prefetch's Ok flips the freshly re-queued record to
    /// Completed, runs the whole completion tail over payload the delete
    /// already removed, and parks the retry straight back into history:
    /// the button the user pressed does nothing at all (Codex sweep 14
    /// Aug M3).
    #[test]
    fn a_late_prefetch_ok_never_claims_the_record_it_was_retried_out_of() {
        let dir = tmp("gen");
        let d = test_daemon(&dir);
        let v = serde_json::json!({
            "nzo_id": "nzo-sc-1", "name": "Prefetched.Release",
            "out_dir": crate::naming::out_dir(&d).join("Prefetched.Release").to_string_lossy(),
            "nzb_path": "/tmp/n.nzb", "state": "Queued",
        });
        let job = Arc::new(Mutex::new(job_from_json(&v).expect("job")));
        // What spawn_sidecar samples before the task starts.
        let gen0 = job_generation(&job.lock_ok());
        assert!(
            sidecar_result_is_ours(&job.lock_ok(), &gen0),
            "an untouched record is the one the prefetch started on"
        );

        // The queued-delete arm: tombstoned and filed into history while
        // the sidecar task is still alive.
        {
            let mut g = job.lock_ok();
            g.tombstone = true;
            g.delete_status = "MANUAL".into();
            g.state = JobState::Failed;
            g.fail_message = "deleted from the queue".into();
            g.finished_unix = Some(1);
        }
        d.history.lock_ok().push(job.clone());
        assert!(
            !sidecar_result_is_ours(&job.lock_ok(), &gen0),
            "the tombstone alone already stopped this half"
        );

        // The user presses Retry, which clears the tombstone.
        assert!(d.retry("nzo-sc-1"), "the filed delete row is retryable");
        assert!(
            !job.lock_ok().tombstone,
            "a retry clears the tombstone by design - that is the point"
        );
        assert!(
            !sidecar_result_is_ours(&job.lock_ok(), &gen0),
            "the old prefetch tail claimed the record its own delete was retried out of"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Delete-with-files on a PREFETCHING job waits for the sidecar.
    ///
    /// The row reads Queued and not finalizing, so both delete arms used
    /// to remove its directory on the request thread, microseconds after
    /// a fire-and-forget poke. The pipeline was still draining, and a
    /// slot writer is created lazily on its file's first article - so
    /// the next file of any multi-file release recreated the directory
    /// and laid a fresh payload in it that no record named (Codex sweep
    /// 14 Aug M2).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_delete_waits_for_the_sidecar_before_removing_its_files() {
        let dir = tmp("drain");
        let d = test_daemon(&dir);
        let out = crate::naming::out_dir(&d).join("Prefetching.Release");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("part01.rar"), b"bytes").unwrap();

        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        *d.sidecar.lock_ok() = Some(Sidecar {
            nzo_id: "nzo-drain-1".into(),
            hub: Arc::new(crate::StreamHub::default()),
            progress: Arc::new(AtomicU64::new(0)),
            rate_win: Mutex::new(VecDeque::new()),
            cancelled: cancelled.clone(),
            task: tokio::spawn(async {}),
            borrowed: false,
        });
        // What the delete arm reserves on this job's behalf.
        d.reserved.lock_ok().insert(out.clone());

        d.remove_after_sidecar_drain(
            cancelled.clone(),
            "Prefetching.Release".to_string(),
            out.clone(),
            false,
            crate::smart::FiledTail::default(),
        );

        std::thread::sleep(std::time::Duration::from_millis(600));
        assert!(
            out.join("part01.rar").exists(),
            "the files went while the sidecar was still writing into the directory"
        );
        assert!(
            d.reserved.lock_ok().contains(&out),
            "and the directory must stay reserved until they actually go"
        );

        // The sidecar winds down and clears its own slot.
        *d.sidecar.lock_ok() = None;
        // Wait on the LAST thing the drain does, not the first. It removes
        // the files and only THEN gives the reservation back
        // (`remove_after_sidecar_drain`: remove_job_files, then
        // `reserved.remove`), so a loop that breaks the instant the
        // directory vanishes can reach the reservation assert while the
        // drain thread is still between those two statements - a gap that
        // is microseconds when it is scheduled and milliseconds when it is
        // not, which is how this failed roughly one run in nine under a
        // loaded `cargo test`. Polling the reservation covers both
        // assertions, because the files are already gone by the time it
        // clears.
        for _ in 0..200 {
            if !d.reserved.lock_ok().contains(&out) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert!(
            !out.exists(),
            "the delete's files half never ran once the sidecar was gone"
        );
        assert!(
            !d.reserved.lock_ok().contains(&out),
            "the drain owes the reservation back"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A recategorize re-points a QUEUED job's out_dir and stamps no
    /// move, so the prefetch that is at that moment downloading into the
    /// old directory used to come back, pass the ownership test on
    /// `(retries, move_seq)` alone, and file a Completed row against a
    /// directory holding none of its bytes (Fable sweep 15 Aug).
    #[test]
    fn a_recategorize_takes_the_record_out_of_the_prefetch_custody() {
        let dir = tmp("recat");
        let d = test_daemon(&dir);
        let v = serde_json::json!({
            "nzo_id": "nzo-recat-1", "name": "Some.Release",
            "out_dir": crate::naming::out_dir(&d).join("movies/Some.Release").to_string_lossy(),
            "nzb_path": "/tmp/n.nzb", "state": "Queued",
        });
        let job = Arc::new(Mutex::new(job_from_json(&v).expect("job")));
        let gen0 = job_generation(&job.lock_ok());
        assert!(
            sidecar_result_is_ours(&job.lock_ok(), &gen0),
            "the prefetch owns its own untouched record"
        );

        // What requeue_category does: a new directory under the new
        // category, no retry, no move stamp.
        job.lock_ok().out_dir = crate::naming::out_dir(&d).join("tv/Some.Release");
        assert!(
            !sidecar_result_is_ours(&job.lock_ok(), &gen0),
            "a re-pointed record is no longer the one the prefetch downloaded"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The drain's oracle is the SLOT, so whoever empties the slot
    /// decides when the files may go - and `stop_sidecar` runs at the end
    /// of every primary job, on whatever prefetch happens to be in there,
    /// including one a delete already aborted. Taking the slot before
    /// awaiting the task answered "writers are done" during the wind-down
    /// the drain was written to wait out (Fable sweep 15 Aug). The test
    /// above cannot see this: it clears the slot by hand.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stop_sidecar_holds_the_slot_until_the_run_has_wound_down() {
        let dir = tmp("stopdrain");
        let d = test_daemon(&dir);
        let out = crate::naming::out_dir(&d).join("Prefetching.Release");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("part01.rar"), b"bytes").unwrap();

        // A pipeline that keeps running well past the abort, as the real
        // one does: consumer join plus two pending flushes.
        let winding = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let w2 = winding.clone();
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        *d.sidecar.lock_ok() = Some(Sidecar {
            nzo_id: "nzo-drain-2".into(),
            hub: Arc::new(crate::StreamHub::default()),
            progress: Arc::new(AtomicU64::new(0)),
            rate_win: Mutex::new(VecDeque::new()),
            cancelled: cancelled.clone(),
            task: tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(900)).await;
                w2.store(false, std::sync::atomic::Ordering::Relaxed);
            }),
            borrowed: false,
        });
        d.reserved.lock_ok().insert(out.clone());
        d.remove_after_sidecar_drain(
            cancelled.clone(),
            "Prefetching.Release".to_string(),
            out.clone(),
            false,
            crate::smart::FiledTail::default(),
        );

        // The primary job ends and winds the prefetch down. Run it
        // CONCURRENTLY: the defect is not in what stop_sidecar returns,
        // it is that emptying the slot lets the drain fire while the task
        // is still going, so the assertion has to land inside that window.
        let d2 = d.clone();
        let stopper = tokio::spawn(async move { stop_sidecar(&d2).await });
        tokio::time::sleep(std::time::Duration::from_millis(450)).await;
        assert!(
            winding.load(std::sync::atomic::Ordering::Relaxed),
            "test is mis-timed: the run finished before the window was checked"
        );
        assert!(
            out.join("part01.rar").exists(),
            "the drain removed the files while the sidecar run was still winding down"
        );

        stopper.await.unwrap();
        assert!(
            !winding.load(std::sync::atomic::Ordering::Relaxed),
            "stop_sidecar returned before the run it stopped had finished"
        );
        assert!(
            d.sidecar.lock_ok().is_none(),
            "and it must leave the slot empty once it has"
        );

        for _ in 0..200 {
            if !out.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert!(!out.exists(), "the delete's files half never ran");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A prefetch that finished a whole job still sweeps its recovery
    /// files, WHATEVER the settle manifest is set to.
    ///
    /// ISSUE #18's deferral takes `par2` off `finalize_completed_gen`'s
    /// sweep list while a manifest is owed, and puts it back in
    /// `postproc::settle_manifest_and_deferred_par2_sweep`. This tail is
    /// the one road that awaits the first without the second, so it had
    /// to be joined up by hand: while `write_manifest` was opt-in the
    /// gap was invisible, and the day §310 turned that flag on it became
    /// "every prefetch-completed folder keeps its recovery files for
    /// ever" on the default configuration. It was found by the arm below
    /// going red on the flip, which is why this states it directly.
    ///
    /// BOTH arms, and each STORES the flag it means rather than
    /// inheriting a default, so neither reading moves when the default
    /// does. What the off arm adds is narrow and worth stating rather
    /// than overclaiming: it is the before-picture, pinning that this
    /// road ends the same way it did before §310 existed. It does NOT
    /// catch a fix that swept unconditionally - that would pass here -
    /// and it is not meant to: whether the deferral is SCOPED to a
    /// manifest actually being owed is
    /// `postproc::tests::the_par2_sweep_is_deferred_only_while_the_settle_manifest_is_owed`,
    /// which asks the predicate directly.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_prefetch_completion_sweeps_the_recovery_files_either_way() {
        let dir = tmp("scpar2");
        let d = test_daemon(&dir);
        assert!(
            d.par_cleanup.load(Ordering::Relaxed),
            "the deferral only arms while the .par2 sweep is on at all"
        );
        for (manifest, arm) in [(true, "manifest on"), (false, "manifest off")] {
            d.write_manifest.store(manifest, Ordering::Relaxed);
            let name = format!("Prefetched.{}", u8::from(manifest));
            let out = crate::naming::out_dir(&d).join(&name);
            std::fs::create_dir_all(&out).unwrap();
            let par2 = out.join("prefetched.par2");
            std::fs::write(&par2, b"par2").unwrap();
            let job = Arc::new(Mutex::new(
                job_from_json(&serde_json::json!({
                    "nzo_id": format!("nzo-scpar2-{}", u8::from(manifest)),
                    "name": name,
                    "out_dir": out.to_string_lossy(),
                    "nzb_path": dir.join("p.nzb").to_string_lossy(), "state": "Queued",
                }))
                .expect("job"),
            ));
            let gen0 = job_generation(&job.lock_ok());
            {
                let mut g = job.lock_ok();
                g.state = JobState::Completed;
                g.fetched = true;
            }
            d.queue.lock_ok().push_back(job.clone());
            completion_tail(
                d.clone(),
                job.clone(),
                Some((gen0.0, gen0.1)),
                None,
                None,
                None,
            )
            .await;
            assert!(
                !par2.exists(),
                "{arm}: a prefetch completion left the recovery files behind"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A prefetch whose record was deleted and RETRIED after its
    /// completion tail was already on its way must not touch the retry.
    ///
    /// The ownership test and the state write share one hold of the job
    /// lock, and that was taken to settle the question - but the answer
    /// was then carried, as a cached boolean, across a spawn onto
    /// another task. That task unlocks, sweeps, renames, files into the
    /// TV library and copies to a NAS before it parks, and the whole
    /// span is unlocked. Delete the record in there and press Retry -
    /// the very shape the ownership test exists for - and the old
    /// prefetch's tail finalized the retry's directory, fired its hooks
    /// and parked the freshly queued row straight back into history
    /// (read-only sweep 2, M5).
    ///
    /// No barrier needed: the hazard IS the tail being a separate task,
    /// so running it after the retry has landed is the interleaving,
    /// not an approximation of it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_late_prefetch_tail_never_finalizes_or_parks_the_retry() {
        let dir = tmp("tailgen");
        let d = test_daemon(&dir);

        // --- the stale direction ---------------------------------------
        let out = crate::naming::out_dir(&d).join("Prefetched.Release");
        std::fs::create_dir_all(&out).unwrap();
        // A sidecar the default par2 sweep deletes: if the stale tail
        // finalizes anyway, this file is gone and the assert names it.
        std::fs::write(out.join("prefetched.release.par2"), b"par2").unwrap();
        let job = Arc::new(Mutex::new(
            job_from_json(&serde_json::json!({
                "nzo_id": "nzo-sctail-1", "name": "Prefetched.Release",
                "out_dir": out.to_string_lossy(),
                "nzb_path": dir.join("p.nzb").to_string_lossy(), "state": "Queued",
            }))
            .expect("job"),
        ));
        let gen0 = job_generation(&job.lock_ok());
        // What the Ok arm writes under the ownership test's own hold.
        {
            let mut g = job.lock_ok();
            assert!(sidecar_result_is_ours(&g, &gen0));
            g.state = JobState::Completed;
            g.fetched = true;
        }
        // ...and before the detached tail is polled, the record is
        // deleted, filed, and sent round again.
        {
            let mut g = job.lock_ok();
            g.state = JobState::Failed;
            g.tombstone = true;
            g.delete_status = "MANUAL".into();
            g.fail_message = "deleted from the queue".into();
            g.finished_unix = Some(1);
        }
        d.history.lock_ok().push(job.clone());
        assert!(d.retry("nzo-sctail-1"), "the filed delete row is retryable");

        completion_tail(
            d.clone(),
            job.clone(),
            Some((gen0.0, gen0.1)),
            None,
            None,
            None,
        )
        .await;

        {
            let g = job.lock_ok();
            assert_eq!(
                g.state,
                JobState::Queued,
                "the stale tail filed the record the retry had just queued"
            );
            assert!(
                !g.finalizing,
                "and left the retry carrying a finalize marker"
            );
        }
        assert!(
            out.join("prefetched.release.par2").exists(),
            "the stale tail ran post-processing over the retry's directory"
        );
        assert!(
            d.queue
                .lock_ok()
                .iter()
                .any(|j| j.lock_ok().nzo_id == "nzo-sctail-1"),
            "the stale tail pulled the freshly retried row out of the queue"
        );
        assert_eq!(
            d.history
                .lock_ok()
                .iter()
                .filter(|j| j.lock_ok().nzo_id == "nzo-sctail-1")
                .count(),
            0,
            "and parked it into history, consuming the retry the user pressed"
        );

        // --- the live direction ----------------------------------------
        // Nothing taken away from it: the tail must still finish and
        // file the job. A fence that declines everything would look
        // green above and lose every prefetched completion.
        let out2 = crate::naming::out_dir(&d).join("Untouched.Release");
        std::fs::create_dir_all(&out2).unwrap();
        std::fs::write(out2.join("untouched.release.par2"), b"par2").unwrap();
        let job2 = Arc::new(Mutex::new(
            job_from_json(&serde_json::json!({
                "nzo_id": "nzo-sctail-2", "name": "Untouched.Release",
                "out_dir": out2.to_string_lossy(),
                "nzb_path": dir.join("u.nzb").to_string_lossy(), "state": "Queued",
            }))
            .expect("job"),
        ));
        let gen2 = job_generation(&job2.lock_ok());
        {
            let mut g = job2.lock_ok();
            g.state = JobState::Completed;
            g.fetched = true;
        }
        d.queue.lock_ok().push_back(job2.clone());
        completion_tail(
            d.clone(),
            job2.clone(),
            Some((gen2.0, gen2.1)),
            None,
            None,
            None,
        )
        .await;
        assert_eq!(
            job2.lock_ok().state,
            JobState::Completed,
            "an untouched prefetch completion is still a completion"
        );
        assert!(
            !out2.join("untouched.release.par2").exists(),
            "and its post-processing must still have run"
        );
        assert_eq!(
            d.history
                .lock_ok()
                .iter()
                .filter(|j| j.lock_ok().nzo_id == "nzo-sctail-2")
                .count(),
            1,
            "and the tail must still file it into history"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The drain's wait is for the LAST owner, not for a clock.
    ///
    /// It polled for 60 s and then removed the directory and handed the
    /// reservation back whether or not the prefetch had let go -
    /// "bounded exactly like `poke_sidecar`'s re-fire loop", which is a
    /// different wait entirely: that one waits for handles to attach and
    /// takes milliseconds, this one waits for a whole pipeline to let go
    /// of a directory. The abort never reaches the disk tail (the cancel
    /// flag is read once, right after the network phase), so verify,
    /// repair and unpack run to their end afterwards, and on a big
    /// damaged set that is routinely longer than a minute. Past the
    /// bound the removal raced live writers and the next positioned
    /// write laid a fresh payload nothing named (read-only sweep 2, M6).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_drain_never_removes_while_the_prefetch_still_holds() {
        let dir = tmp("drainhold");
        let d = test_daemon(&dir);
        let out = crate::naming::out_dir(&d).join("Slow.Release");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("part01.rar"), b"bytes").unwrap();

        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        *d.sidecar.lock_ok() = Some(Sidecar {
            nzo_id: "nzo-drainhold-1".into(),
            hub: Arc::new(crate::StreamHub::default()),
            progress: Arc::new(AtomicU64::new(0)),
            rate_win: Mutex::new(VecDeque::new()),
            cancelled: cancelled.clone(),
            task: tokio::spawn(async {}),
            borrowed: false,
        });
        d.reserved.lock_ok().insert(out.clone());
        d.remove_after_sidecar_drain(
            cancelled.clone(),
            "Slow.Release".to_string(),
            out.clone(),
            false,
            crate::smart::FiledTail::default(),
        );

        // Past the point the old wait gave up at. (The shipped bound was
        // 240 polls of 250 ms; the red run shortens it to 4 so this test
        // costs a second and a half rather than a minute.)
        tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;
        assert!(
            out.join("part01.rar").exists(),
            "the drain gave up and removed the files while the prefetch was still in there"
        );
        assert!(
            d.reserved.lock_ok().contains(&out),
            "and handed the directory back while its old owner was still writing to it"
        );

        // The owner lets go, and only now may the files go. Polling the
        // reservation, not the directory: the drain removes the files
        // and gives the reservation back afterwards.
        *d.sidecar.lock_ok() = None;
        for _ in 0..200 {
            if !d.reserved.lock_ok().contains(&out) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert!(
            !out.exists(),
            "the delete's files half never ran once the owner was gone"
        );
        assert!(
            !d.reserved.lock_ok().contains(&out),
            "the drain owes the reservation back"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ...and the last owner is not always the download.
    ///
    /// A prefetch that finishes hands its completion tail to a task of
    /// its own and then clears the sidecar slot on its way out. That
    /// tail is what unlocks, sweeps, renames and moves inside the
    /// directory, and between the slot clearing and `finalizing` going
    /// up part-way through `finalize_completed` the slot answered
    /// "nobody is here" - so a delete-with-files landing in there
    /// removed the directory out from under the finalizer (read-only
    /// sweep 2, M6). The tail registers itself, so the drain sees it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_drain_waits_for_the_detached_completion_tail_too() {
        let dir = tmp("draintail");
        let d = test_daemon(&dir);
        let out = crate::naming::out_dir(&d).join("Finalizing.Release");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("part01.rar"), b"bytes").unwrap();

        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        // The state the defect lives in: the download task has spawned
        // the completion tail and emptied the slot behind it.
        let owner = d.sidecar_tail_begin(cancelled.clone());
        assert!(
            d.sidecar.lock_ok().is_none(),
            "the slot is empty - that is the whole point of this shape"
        );
        d.reserved.lock_ok().insert(out.clone());
        d.remove_after_sidecar_drain(
            cancelled.clone(),
            "Finalizing.Release".to_string(),
            out.clone(),
            false,
            crate::smart::FiledTail::default(),
        );

        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        assert!(
            out.join("part01.rar").exists(),
            "the drain removed the files while the completion tail still owned the directory"
        );
        assert!(
            d.reserved.lock_ok().contains(&out),
            "and released the reservation with the old owner still in there"
        );

        drop(owner);
        for _ in 0..200 {
            if !d.reserved.lock_ok().contains(&out) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert!(
            !out.exists(),
            "the delete's files half never ran once the tail was done"
        );
        assert!(
            !d.reserved.lock_ok().contains(&out),
            "the drain owes the reservation back"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A recategorize re-points a still-QUEUED job's out_dir and stamps
    /// neither counter, so it was invisible to everything except the
    /// directory half of the ownership stamp - which only ever made the
    /// prefetch DISCARD its result. The bytes and the journal stayed
    /// where they were: a part-downloaded release in a folder no record
    /// named, while the primary run started at the new directory and
    /// fetched the whole thing again over the same provider quota
    /// (read-only sweep 2, M7). They travel with the record now.
    #[test]
    fn a_recategorize_takes_the_prefetched_progress_with_it() {
        let dir = tmp("recatmove");
        let d = test_daemon(&dir);
        let mk = |id: &str, sub: &str| {
            let out = crate::naming::out_dir(&d).join(sub);
            std::fs::create_dir_all(&out).unwrap();
            std::fs::write(out.join("part01.rar"), b"bytes").unwrap();
            std::fs::write(out.join(".nzbfast.journal"), b"journal").unwrap();
            let job = Arc::new(Mutex::new(
                job_from_json(&serde_json::json!({
                    "nzo_id": id, "name": "Some.Release",
                    "out_dir": out.to_string_lossy(),
                    "nzb_path": "/tmp/n.nzb", "state": "Queued",
                }))
                .expect("job"),
            ));
            (job, out)
        };

        // The recategorize shape: same round, new directory.
        let (job, from) = mk("nzo-recatmove-1", "movies/Some.Release");
        let gen0 = job_generation(&job.lock_ok());
        let to = crate::naming::out_dir(&d).join("tv/Some.Release");
        job.lock_ok().out_dir = to.clone();
        adopt_reparented_directory(&job, &gen0);
        assert!(
            to.join("part01.rar").exists() && to.join(".nzbfast.journal").exists(),
            "the early start's bytes and journal were abandoned at the old directory"
        );
        assert!(
            !from.exists(),
            "and the old directory is left named by no record"
        );

        // A RETRY re-points too, and must NOT be adopted: it re-points
        // because the old folder was filed, taken by another job, or
        // outside the configured root, and it zeroes the record's
        // progress on purpose. The counters are what tell them apart.
        let (job2, from2) = mk("nzo-recatmove-2", "movies/Other.Release");
        let gen2 = job_generation(&job2.lock_ok());
        let to2 = crate::naming::out_dir(&d).join("tv/Other.Release");
        {
            let mut g = job2.lock_ok();
            g.out_dir = to2.clone();
            g.retries += 1;
        }
        adopt_reparented_directory(&job2, &gen2);
        assert!(
            from2.join("part01.rar").exists(),
            "a retry's fresh start took the old directory's files with it"
        );
        assert!(
            !to2.exists(),
            "and laid them where the retry means to start clean"
        );

        // And a record nobody touched is left entirely alone.
        let (job3, from3) = mk("nzo-recatmove-3", "movies/Still.Release");
        let gen3 = job_generation(&job3.lock_ok());
        adopt_reparented_directory(&job3, &gen3);
        assert!(
            from3.join("part01.rar").exists(),
            "an untouched record must not move"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
