//! The three arms that can end a job before its pipeline ever starts:
//! the metadata-only `.strm` verdict, the §138 post-health give-up and
//! the opt-in pre-flight sample.
//!
//! Moved out of `worker::start_next` whole (TODO 106) - that function
//! sat at 500 of the size gate's 500-line ceiling, so the next line
//! anybody added to it reddened main for whoever pushed next. Split
//! along the seam the runner's own doc already named: the three arms
//! are one subject, they share one exit
//! ([`job_ended_before_pipeline`] plus the lane's hooks-only submit),
//! and none of them touches the hand-over, the hub claim or the
//! pipeline spawn that make up the rest of `start_next`.
//!
//! **What belongs on this side.** An arm that reaches a TERMINAL state
//! for the picked job without spending the wire on it, ending in
//! [`PostprocLane::submit_hooks_only`] and `Start::Ended` so the runner
//! picks again. It runs AFTER the critical section that flipped the job
//! to `Downloading` (so the job is already the runner's) and BEFORE
//! anything claims the hub - which is exactly why the exit is
//! `job_ended_before_pipeline` and not `finish`: there is no pipeline,
//! no progress cell and no `started_at` of this job's to unwind.
//!
//! **What does not.** Anything that touches `Daemon::active_dl`,
//! `hub.handoff`, the drain slot or the fetch spawn: those are one
//! critical section in `start_next` and must stay there. Nor a guard
//! that decides whether to START at all - that is `download_guards`
//! and the pick, which run before any of this.
//!
//! A child of `worker`, so `use super::*` reaches [`Runner`], [`Start`]
//! and the runner's private neighbours unchanged. The arms are
//! `pub(super)`, which is exactly `worker` and so exactly the reach
//! they had as statements inside `start_next`: nothing outside this
//! file's parent can call one, and nothing outside it should.

use super::*;

/// What the three arms in this module need from the pick, gathered once
/// so each arm takes one borrow rather than six.
///
/// Every field is what the critical section in [`start_next`] read off
/// the record under the one lock hold that is atomic with the flip to
/// `Downloading`, so an arm can never disagree with that flip about
/// what it is ending. Borrowed rather than cloned: the arms outlive
/// nothing, and `start_next` still owns these bindings for the pipeline
/// spawn on the path where no arm fires.
pub(super) struct PreStart<'a> {
    pub(super) job: &'a Arc<Mutex<Job>>,
    pub(super) nzb_path: &'a std::path::Path,
    pub(super) out_dir: &'a std::path::Path,
    pub(super) name: &'a str,
    pub(super) nzo_id: &'a str,
    /// A retention-insurance pick: a background errand that may only
    /// ever put its row back in the queue, so both verdict arms below
    /// stand down for it (each says why at its own condition).
    pub(super) insurance: bool,
    /// `carried.is_some()` - this start overlaps a draining run, which
    /// is what [`job_ended_before_pipeline`] reads.
    pub(super) overlapping: bool,
}

/// M14i metadata-only: the `/stream` library arm.
///
/// A /stream trigger re-queues a library entry at Force priority -
/// that's the "actually download now" signal - so the caller reaches
/// here on `library && prio < 2`, and the condition stays at the call
/// site because it is the runner's dispatch rather than this arm's
/// business. STAT-sample availability instead of downloading: pass →
/// Completed + .strm pointer, and the real fetch happens on first
/// /stream/<id> playback.
pub(super) async fn metadata_only(st: &Runner, p: &PreStart<'_>) -> Start {
    let d = &st.d;
    let config = st.config.as_path();
    let PreStart {
        job,
        nzb_path,
        out_dir,
        name,
        nzo_id,
        overlapping,
        ..
    } = *p;
    // M14i metadata-only: STAT-sample availability instead of
    // downloading. Pass → Completed + .strm pointer; the real
    // fetch happens on first /stream/<id> playback.
    d.hub
        .activity
        .lock_ok()
        .insert(nzo_id.to_string(), "preflight");
    let verdict = crate::check(config, nzb_path, 10, 4, 50, true).await;
    // The lane's unit of backlog, taken BEFORE the terminal
    // state is stamped: from the stamp to the submit the row is
    // terminal in the queue, which `note_queue_idle`'s walk reads
    // as not busy, and a park landing there would announce the
    // drain over a job that still owes its lifecycle event. See
    // `PostprocLane::reserve`.
    let seat = st.lane.reserve();
    {
        let mut j = job.lock_ok();
        match verdict {
            Ok(crate::Verdict::Impossible {
                est_missing,
                recovery,
                measured,
                ..
            }) => {
                j.state = JobState::Failed;
                // The counts make the verdict checkable;
                // append-only, the prefix is classified on. TODO 307
                // item 1: the kind is stated beside the sentence, so
                // the prefix is no longer the only thing carrying it.
                j.fail_message = crate::with_build(format!(
                    "pre-flight: articles missing beyond repair - {}",
                    crate::check::impossible_reason(est_missing, recovery, &measured)
                ));
                j.fail_code = Some(FailKind::PreflightImpossible);
            }
            Ok(_) => {
                j.state = JobState::Completed;
                let authority = pointer_authority(&d.bind, d.port);
                warn_docker_pointer_once(&authority);
                if let Err(e) = write_strm(
                    out_dir,
                    name,
                    d.scheme(),
                    &authority,
                    nzo_id,
                    &d.stream_token(nzo_id),
                ) {
                    warn!(target: "strm", "write for {nzo_id}: {e}");
                }
            }
            Err(e) => {
                j.state = JobState::Failed;
                j.fail_message = e.to_string();
                // A sweep that errored, not a verdict: the sampler
                // says nothing about the post, so nothing is stated
                // and the sentence is all the evidence there is.
                j.fail_code = crate::failkind::code_of_error(&e);
            }
        }
        j.finished_at = Some(Instant::now());
        j.finished_unix = Some(unix_now());
    }
    job_ended_before_pipeline(d, overlapping);
    // The hooks and the park go to the post-processing
    // lane, not to the next two statements. This arm
    // reaches `Completed` without downloading a byte, and
    // Completed is the word Sonarr imports on - so the
    // pp-script, which may be moving or renaming the .strm
    // this arm just wrote, has to be finished before the
    // history row exists. Awaiting that here would stall
    // the picker for the script's whole run; the lane is
    // where the wait is affordable. See
    // `PostprocLane::submit_hooks_only`.
    st.lane.submit_hooks_only(job.clone(), seat).await;
    Start::Ended
}

/// TODO §138 (issue #29), opt-in `post_health_fail`: the §77
/// sample already asked every configured server about this
/// post while the queue was idle. If every one of them said
/// every sampled article was missing, and the post is old
/// enough that propagation is no longer an explanation, end
/// it here - the *arr gets a FAILURE/HEALTH it can blocklist
/// and re-search on within seconds of the job coming up,
/// instead of after however long it takes a doomed download
/// to prove the same thing at full retry ladder.
///
/// Free: no probe runs here, the evidence is the verdict on
/// the record. The bar is `no_server_can_supply`, which is
/// deliberately much narrower than the red bucket the
/// reorder acts on - see its doc for each clause.
///
/// WHY HERE and not in the prober that gathered the evidence:
/// the runner picks a job and only then marks it Downloading,
/// so a prober failing a queued job races that window and can
/// park a job the runner has already started - one record in
/// history and a live download with no queue row. The runner
/// is single and owns the transition, so deciding here cannot
/// race anything, and it is the same seam the opt-in
/// `preflight` sweep below already fails jobs on.
///
/// Sentence, class and consequences arrive together:
/// `giveup_reason` opens with `post is gone`, so `fail_kind`
/// reads Gone - no automatic retry, FAILURE/HEALTH to the
/// *arr, "find another release" as the suggested move.
/// Neither pre-pipeline verdict arm runs for an insurance pick: both
/// END the job into history as Failed, and an insurance errand may
/// only ever put its row back in the queue.
pub(super) async fn post_health_giveup(st: &Runner, p: &PreStart<'_>) -> Option<Start> {
    let d = &st.d;
    let PreStart {
        job,
        nzo_id,
        insurance,
        overlapping,
        ..
    } = *p;
    let giveup: Option<String> = if !insurance && d.post_health_fail.load(Ordering::Relaxed) {
        let j = job.lock_ok();
        j.health
            .as_ref()
            .filter(|h| h.no_server_can_supply())
            .map(crate::health::giveup_reason)
    } else {
        None
    };
    if let Some(reason) = giveup {
        // The lane's seat, taken before the stamp - see
        // `PostprocLane::reserve`.
        let seat = st.lane.reserve();
        {
            let mut j = job.lock_ok();
            j.state = JobState::Failed;
            j.fail_message = crate::with_build(reason);
            // `giveup_reason` opens `post is gone` and the block comment
            // above says why; TODO 307 item 1 states it as well, so the
            // opening is a courtesy to the reader rather than the only
            // carrier of the verdict.
            j.fail_code = Some(FailKind::Gone);
            j.finished_at = Some(Instant::now());
            j.finished_unix = Some(unix_now());
            info!(target: "health", "{nzo_id}: {}", j.fail_message);
        }
        job_ended_before_pipeline(d, overlapping);
        // Off the picker's loop and into the lane, same as the
        // metadata-only arm above. `Failed` is a word an *arr
        // acts on too - it blocklists this release and
        // re-searches - and a user's failure script runs on
        // this path exactly as it does on a download that
        // failed the long way round, where the lane already
        // finishes it before the row is filed. One ordering
        // for every ending, not one per arm.
        //
        // The give-up's own selling point survives it: what
        // this feature buys is not having to spend a doomed
        // download to reach the verdict, and none of that is
        // given back by the script taking the time the user
        // configured it to take. The failure REPORT still
        // lands after the park by construction - only the
        // script is awaited - so a re-grab can never enter the
        // queue while the row it replaces is still in it.
        st.lane.submit_hooks_only(job.clone(), seat).await;
        return Some(Start::Ended);
    }

    None
}

/// Opt-in pre-flight (settings.json `preflight`): sample
/// this post's articles before spending the bandwidth. A
/// post nothing carries any more is otherwise discovered
/// the slow way - every article asked of every server, at
/// full retry ladder, for a verdict a 10% STAT sample
/// reaches in seconds. Only `Impossible` stops the job:
/// "repairable" is what PAR2 is for, and an errored sweep
/// (a provider hiccup mid-probe) must never fail a job the
/// download itself might well complete.
///
/// `log_mark` is the console bracket [`start_next`] takes for this job
/// just above the call: this arm is the only one of the three that
/// snapshots `fail_detail`, and the mark is taken after the
/// metadata-only arm above, so it is a parameter rather than a
/// [`PreStart`] field.
pub(super) async fn preflight_verdict(
    st: &Runner,
    p: &PreStart<'_>,
    log_mark: u64,
) -> Option<Start> {
    let d = &st.d;
    let config = st.config.as_path();
    let PreStart {
        job,
        nzb_path,
        nzo_id,
        insurance,
        overlapping,
        ..
    } = *p;
    if !insurance && d.preflight.load(Ordering::Relaxed) {
        d.hub
            .activity
            .lock_ok()
            .insert(nzo_id.to_string(), "preflight");
        match crate::check(config, nzb_path, 10, 4, 50, true).await {
            Ok(crate::Verdict::Impossible {
                est_missing,
                recovery,
                measured,
                ..
            }) => {
                // The lane's seat, taken before the stamp - see
                // `PostprocLane::reserve`.
                let seat = st.lane.reserve();
                {
                    let mut j = job.lock_ok();
                    j.state = JobState::Failed;
                    j.fail_message = crate::with_build(format!(
                        "pre-flight: articles missing beyond repair - {}",
                        crate::check::impossible_reason(est_missing, recovery, &measured)
                    ));
                    j.fail_code = Some(FailKind::PreflightImpossible);
                    j.fail_detail = crate::fail_detail_snapshot(log_mark);
                    j.finished_at = Some(Instant::now());
                    j.finished_unix = Some(unix_now());
                }
                job_ended_before_pipeline(d, overlapping);
                // Third of the three runner arms that end a job
                // before the pipeline starts, and the lane
                // takes its tail for the same reason as the
                // other two.
                st.lane.submit_hooks_only(job.clone(), seat).await;
                return Some(Start::Ended);
            }
            Ok(_) => {}
            Err(e) => info!(target: "preflight", "sweep failed, downloading anyway: {e}"),
        }
    }

    None
}
