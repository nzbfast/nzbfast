//! One worker thread per job, and the three controls a host has over it.
//!
//! # The snapshot is the only channel
//!
//! A job publishes into an `Arc<Mutex<JobSnapshot>>` and rings a wake
//! function; the host polls. There is no event stream, no queue of
//! deltas and no callback carrying data, because every one of those is
//! a cross-thread hazard in a UI toolkit and both hosts would have to
//! solve it separately. A snapshot is a value: whoever reads it owns
//! it, whenever they like, from wherever they like.
//!
//! # The process-global knobs
//!
//! `nzbkit::mem::set_cpu_workers`, `set_process_budget`,
//! `par2repair::set_joint_arm` and `digest_cache::publish` are
//! PROCESS-wide (`set_file_workers` is the CLI's `-T`, which has no
//! GUI counterpart, so this crate never calls it). A CLI sets them
//! once in `run_with` and exits; a long-lived app has to set them per
//! job - and to UNSET them per job, because a knob nobody writes is
//! the last job's and not the engine's (see [`apply_knobs`]) - and
//! with two jobs running at once the last writer wins. That is not a
//! bug this crate can fix - it
//! is what the engine's interface is - so the queue takes a lock around
//! the setting and the START of the job, the Settings pane says
//! plainly that the performance knobs are shared above concurrency 1,
//! and [`KnobLock`] is the one place any of those FOUR is written.
//!
//! A FIFTH process-global engine knob is written in this crate and is
//! deliberately not one of them: `nzbkit::par2::set_fast_check`, the
//! verify tier, which `Session::new` chooses once for the whole
//! session and never revisits (the reasoning is at that call). It sits
//! outside [`KnobLock`] because it is not per-job - no job carries a
//! value for it, so there is no last writer to lose to. If the CLI's
//! `--slow` ever gets a Settings field it becomes per-job, and then it
//! moves into [`apply_knobs`] with the other four.
//!
//! # What cancel and pause can actually reach today
//!
//! Honestly, and this is what `pf_capabilities` reports:
//!
//! * a VERIFY is cancellable and pausable between members, through
//!   `parfast::verify::SurveyWatch` - so a 200-member set stops within
//!   one member's hashing;
//! * a REPAIR is cancellable at the engine's survey handshake
//!   (`parfast::repair::RepairWatch::before_fold`, where nothing is
//!   written yet) AND from inside the repair itself, since 12 Sep 2026
//!   (`RepairWatch::control`, plan section 4.2 item 1): the engine's
//!   hashing loop, feed, solve and patch all poll this job's cancel and
//!   report a fraction back into the snapshot. Pause parks in all of
//!   them except the SOLVE, whose work grid is a shared queue - see
//!   `nzbkit::par2repair::control::PauseGate`. The job's [`Control`] IS
//!   the engine's gate rather than a copy of it, so one press means one
//!   thing;
//! * a CREATE is cancellable and reports its phases from INSIDE the
//!   engine, since 12 Sep 2026 (`parfast::create::CreateWatch` ->
//!   `nzbkit::par2gen::control`): the member hashing, the fold or the
//!   transform, and the volume writes all poll this job's cancel and
//!   report a fraction back into the snapshot, and a cancelled create
//!   leaves NOTHING on disk - the engine unlinks the index and every
//!   volume it wrote, because a volume's critical packets are patched
//!   in last and a half-written set names no member. Pause parks at a
//!   fold window, a batch boundary and a member's block range, and NOT
//!   inside a transform, whose stripes come off a shared queue - the
//!   same exception the repair's solve has;
//! * a CHECKSUM job is cancellable and pausable between files.
//!
//! A control that cannot be honoured is still RECORDED - the job goes
//! to `cancelled` when it finishes - so a host never shows a button
//! that does nothing, and `pf_capabilities.pause` is what a host reads
//! to decide whether to show one at all.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use nzbkit::par2repair;
use parfast::out::{Level, Sink};

use crate::job::{
    ChecksumFormat, ChecksumResult, CreateSpec, JobError, JobKind, JobResult, JobSnapshot, JobSpec,
    JobState, Phase, RepairSpec, VerifySpec, WrittenFile,
};
use crate::planner;
use crate::settings::Settings;
use crate::survey::{SurveyModel, Verdict};

/// The three controls, as one shared value.
///
/// # It is the ENGINE's gate, not a second copy of it
///
/// Since 12 Sep 2026 the two bits live in
/// `nzbkit::par2repair::PauseGate` and this type is a thin face over
/// it. That is deliberate and it is the whole point: a repair's fold,
/// solve and write loops poll the ENGINE's cancel, and a `Control` that
/// kept its own pair beside it would be two sources of truth for one
/// button - the host presses Cancel, one of them is set, and whether
/// the repair stops depends on which loop happened to be running.
/// [`engine_gate`](Self::engine_gate) hands the very same value to
/// `par2repair::RepairControl`.
///
/// The gate's own doc carries the argument for the shape: why the state
/// is under a mutex rather than in atomics beside it (the wait loop
/// must open on a terminating check that reads the guard - the shape
/// `tools/wait-recheck-gate.py` refuses to classify otherwise), why
/// pause is a condvar and not a spin, and the rule about where a
/// PauseGate may park. Every caller of [`gate`](Self::gate) in this
/// crate is between units of work - between two members of a verify,
/// between two files of a checksum - which is that rule.
#[derive(Debug, Default)]
pub struct Control {
    gate: Arc<par2repair::PauseGate>,
}

impl Control {
    pub fn new() -> Arc<Control> {
        Arc::new(Control::default())
    }

    /// The gate to hand `par2repair::RepairControl`, so the engine's
    /// loops poll THIS job's cancel and park on THIS job's pause.
    pub fn engine_gate(&self) -> Arc<par2repair::PauseGate> {
        self.gate.clone()
    }

    pub fn cancel(&self) {
        self.gate.cancel();
    }

    pub fn set_paused(&self, paused: bool) {
        self.gate.set_paused(paused);
    }

    pub fn is_cancelled(&self) -> bool {
        self.gate.is_cancelled()
    }

    pub fn is_paused(&self) -> bool {
        self.gate.is_paused()
    }

    /// Block while paused; answer `false` once cancelled.
    pub fn gate(&self) -> bool {
        self.gate.gate()
    }
}

/// The shared snapshot plus the host's wake function.
///
/// The wake carries NO data and may fire on any thread; that rule is
/// the whole of the threading contract both apps are written against,
/// and it is why this type hands out nothing but a `&JobSnapshot`
/// under a lock.
pub struct Publisher {
    pub snapshot: Mutex<JobSnapshot>,
    /// An `Arc` rather than a `Box` so [`Publisher::ring`] can take a
    /// handle to it and let go of this mutex BEFORE calling - see there.
    wake: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl Publisher {
    pub fn new(snapshot: JobSnapshot) -> Arc<Publisher> {
        Arc::new(Publisher {
            snapshot: Mutex::new(snapshot),
            wake: Mutex::new(None),
        })
    }

    pub fn set_wake(&self, f: Option<Box<dyn Fn() + Send + Sync>>) {
        *self.wake.lock().unwrap_or_else(|p| p.into_inner()) = f.map(Arc::from);
    }

    /// Change the snapshot and ring the host. The lock is NEVER held
    /// across the wake: a host that calls back into the session from
    /// its wake handler would deadlock on it, and that is exactly what
    /// a UI thread does when it marshals and polls.
    pub fn update(&self, f: impl FnOnce(&mut JobSnapshot)) {
        self.update_quiet(f);
        self.ring();
    }

    /// [`Publisher::update`] with NO wake, for a caller that is holding
    /// a session lock. It rings once the lock is gone; the wake carries
    /// no data, so ringing a moment later is the same wake.
    ///
    /// Not an optimisation - it is the other half of the API.md promise
    /// that "the session never holds a lock across the callback". Every
    /// `update` under `Inner::jobs` used to ring from inside it, so a
    /// host whose wake handler polls (which API.md explicitly permits,
    /// and which is what a host that polls from its wake DOES) re-entered
    /// `snapshot()` on the ringing thread and wedged on a `std` mutex
    /// that is not reentrant. Cancelling a queued job was the shortest
    /// route to it.
    pub fn update_quiet(&self, f: impl FnOnce(&mut JobSnapshot)) {
        let mut s = self.snapshot.lock().unwrap_or_else(|p| p.into_inner());
        f(&mut s);
    }

    pub fn ring(&self) {
        // TAKEN, not borrowed: the callback is allowed to call back in,
        // and `set_wake` is one of the doors it may come through. Holding
        // this mutex across `w()` made replacing the wake from inside a
        // wake a deadlock of its own, beside the jobs-lock one above.
        let held = self
            .wake
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map(Arc::clone);
        if let Some(w) = held {
            w();
        }
    }

    pub fn get(&self) -> JobSnapshot {
        self.snapshot
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

/// The one place any process-global engine knob is written.
///
/// Held for the whole job and not merely for the write: two jobs that
/// each set their own thread count and then both ran would be running
/// under whichever set it last, which is worse than running under one
/// of them on purpose.
///
/// A READ-WRITE lock since 15 Sep 2026, and a job takes the write side
/// unless the queue started it [`Job::shared`]. Before that it was a
/// mutex held for the whole job, which also meant a concurrency above 1
/// started a second job only for it to wait here. The read side is for
/// exactly one case, [`crate::pairing`]'s: two large single-file creates
/// the queue has checked set the SAME knobs, so both writing them is one
/// value written twice.
///
/// # This lock is per SESSION; the knobs are per PROCESS
///
/// A real gap, and an unreachable one - checked 17 Sep 2026 and recorded
/// here so the next host does not have to re-derive it. Two `Session`s
/// in one process would serialise against two different locks over one
/// set of globals, and the FFI permits that: `pf_session_new` may be
/// called as often as a host likes. Neither shipped wrapper does. The
/// mac app builds exactly one `FfiCore` (`App.swift`) and the Windows
/// app exactly one (`App.xaml.cs`), each once at launch, and both apps
/// are single-instance. A host that wants a second Session needs this
/// lock moved to a process-wide static FIRST - the type is deliberately
/// the only thing that would have to change.
pub struct KnobLock(pub RwLock<()>);

impl KnobLock {
    pub fn new() -> Arc<KnobLock> {
        Arc::new(KnobLock(RwLock::new(())))
    }
}

impl Default for KnobLock {
    fn default() -> KnobLock {
        KnobLock(RwLock::new(()))
    }
}

/// Apply a job's performance knobs. EVERY knob is written on EVERY job,
/// including the ones this job does not name.
///
/// Returns nothing, deliberately: the engine has no way to hand the
/// previous values back, so there is nothing to save and restore and a
/// caller that believed otherwise would be wrong. That is why the reset
/// is a door of the engine's own - `mem::clear_cpu_workers` and
/// `mem::clear_process_budget`, which put a knob back to the state it is
/// in when no entry point has ever spoken - rather than a value stashed
/// here.
///
/// # "Auto" means the ENGINE'S default, not the last job's number
///
/// SETTLED 17 Sep 2026, lead 2 of
/// `research/CODEX-SWEEP-2026-09-17-VERDICTS.md`. Until then each knob
/// was written only for a positive `Some`, so a job carrying `None` ran
/// under whatever the PREVIOUS job had published: one job at 4 threads
/// and the next left on Auto ran at 4 threads, with the pane saying
/// Auto. The other coherent answer was to keep the stickiness and stop
/// both apps calling it Auto. Three things decided it this way:
///
/// * [`crate::settings::Performance::threads`] already PROMISED it -
///   "`None` is `nzbkit::mem::cpu_workers()`". A promise the code did
///   not keep is not a policy.
/// * `digest_cache` below has published in BOTH directions since it
///   landed, for the identical reason, stated there: a job must never
///   inherit the last one's store. Two knobs in one function answering
///   that question opposite ways is an oversight, not a design.
/// * The sticky reading has no surface to read it off. The number in
///   force came from a job that has FINISHED, and may have come from a
///   per-job override ([`crate::job::Perf`],
///   [`crate::job::VerifyOptions::threads`]) that was never in the
///   Settings pane at all - so nothing on screen would ever name it.
///   "Leave it alone" is defensible for a knob a user can SEE; it is not
///   one for a knob whose value is invisible.
///
/// `Some(0)` is Auto here and not a zero-width pool. Both panes map
/// their Auto row to `null`, so the only source of a 0 is a host writing
/// the JSON by hand, and the engine reads a published 0 as a SERIAL run
/// - the one answer nobody asked for.
///
/// Pinned by `parfast-ffi`'s `tests/knobs.rs`, which reads the live
/// `mem::cpu_workers()` from INSIDE a second job rather than reading
/// this function's spec back to itself. It sits in that crate and not
/// in this one's unit tests because it needs a process to itself - the
/// header of that file says why, and the reason is this function.
fn apply_knobs(
    threads: Option<usize>,
    memory_mb: Option<u64>,
    fast_solver: bool,
    digest_cache: bool,
) {
    match threads.filter(|&t| t > 0) {
        Some(t) => nzbkit::mem::set_cpu_workers(t),
        None => nzbkit::mem::clear_cpu_workers(),
    }
    match memory_mb.filter(|&m| m > 0) {
        // `from_user_limit`, not a struct literal: this is a figure a
        // person typed into the Settings pane's Memory limit picker (or
        // sent as `Perf::memory_mb` over the FFI), and that funnel is
        // what lets `par2repair::fastpar::clamp_to_published` RAISE the
        // repair's solve window to meet it, not just lower it - the same
        // reason `-m` and the daemon's `mem_limit` setting both go
        // through it. It also clamps and warns on its own, so the
        // hand-rolled `.max(MemBudget::MIN)` this replaced was a second
        // copy of a floor `with_total` already owns.
        Some(mb) => nzbkit::mem::set_process_budget(nzbkit::mem::MemBudget::from_user_limit(
            mb.saturating_mul(1024 * 1024),
            "the Memory limit setting",
        )),
        None => nzbkit::mem::clear_process_budget(),
    }
    // A plain `bool` and not an `Option`: every caller already resolved
    // the job's answer against the Settings field, which is itself a
    // `bool`, so the absent case this used to carry could not arise -
    // and an `Option` that is always `Some` is the shape the two knobs
    // above went wrong in.
    nzbkit::par2repair::set_joint_arm(fast_solver);
    nzbkit::par2repair::reset_joint_reach();
    // The Settings pane's "Remember checksums of large files", published
    // in BOTH directions for the CLI's reason (`parfast::run_with`): a job
    // must never inherit the last one's store. Always the per-user store;
    // an account with no cache folder simply runs without one.
    nzbkit::digest_cache::publish(if digest_cache {
        nzbkit::digest_cache::DigestCache::at_default_location()
    } else {
        None
    });
}

/// [`Control::gate`], with the job's STATE kept in step.
///
/// A host presses Pause and then looks at the snapshot; if the state
/// still said `running` while the worker was parked, the button would
/// appear not to have worked. The two halves are here rather than
/// inside `Control` because `Control` is shared with the queue, which
/// pauses a job that has not started yet and has no worker to park.
pub fn gated(job: &Job) -> bool {
    if job.control.is_paused() {
        job.publisher.update(|s| {
            if s.state == JobState::Running {
                s.state = JobState::Paused;
            }
        });
    }
    let go = job.control.gate();
    if go {
        job.publisher.update(|s| {
            if s.state == JobState::Paused {
                s.state = JobState::Running;
            }
        });
    }
    go
}

/// Everything one job needs to run.
pub struct Job {
    pub spec: JobSpec,
    pub control: Arc<Control>,
    pub publisher: Arc<Publisher>,
    pub knobs: Arc<KnobLock>,
    pub settings: Settings,
    /// Take the [`KnobLock`]'s READ side rather than its write side. Set by
    /// the queue for a create [`crate::pairing`] may start a second create
    /// beside, and for nothing else.
    pub shared: bool,
}

/// Run one job to completion on the calling thread.
pub fn run(job: &Job) {
    let started = Instant::now();
    job.publisher.update(|s| {
        s.state = JobState::Running;
        s.phase = Phase::Scanning;
        s.progress = 0.0;
    });
    let outcome = if !gated(job) {
        Outcome::cancelled()
    } else {
        let _held = if job.shared {
            (
                Some(job.knobs.0.read().unwrap_or_else(|p| p.into_inner())),
                None,
            )
        } else {
            (
                None,
                Some(job.knobs.0.write().unwrap_or_else(|p| p.into_inner())),
            )
        };
        match &job.spec {
            JobSpec::Create { create } => run_create(job, create, started),
            JobSpec::Verify { verify } => run_verify(job, verify, started),
            JobSpec::Repair { repair } => run_repair(job, repair, started),
            JobSpec::ChecksumCreate { checksum_create } => {
                crate::runner::checksums::create(job, checksum_create, started)
            }
            JobSpec::ChecksumVerify { checksum_verify } => {
                crate::runner::checksums::verify(job, checksum_verify, started)
            }
        }
    };
    let elapsed = started.elapsed().as_millis() as u64;
    // A cancel that arrived while the work was already past its last
    // honouring point still decides the STATE: a host that pressed
    // Cancel must not be told the job simply finished. That is right
    // for work which can stop part-way, which is nearly all of it - a
    // half-repaired file, a verify abandoned between members.
    //
    // It is NOT right for work the engine COMMITTED, and until 12 Sep
    // 2026 there was no way to say so. A PAR2 create is all-or-nothing:
    // it either sealed the whole set or removed every file it wrote,
    // and it says which in its exit code. Labelling a sealed set
    // "Cancelled" left a complete, valid recovery set on disk that the
    // job named none of and that API.md forbids the host to offer to
    // clean up. So an outcome may now declare itself the engine's, and
    // exactly one does - see `Outcome::committed` and the create.
    let state = final_state(job.control.is_cancelled(), &outcome);
    job.publisher.update(|s| {
        s.state = state;
        s.phase = Phase::Finishing;
        s.elapsed_ms = elapsed;
        s.eta_ms = None;
        s.progress = if state == JobState::Done {
            1.0
        } else {
            s.progress
        };
        s.result = outcome.result;
        s.error = outcome.error;
        if let Some(m) = outcome.survey {
            s.survey = Some(m);
        }
        if state == JobState::Cancelled {
            s.phase_text = "Cancelled".to_string();
        }
    });
}

/// The state a finished job REPORTS, which is its own outcome unless a
/// late cancel overrides it. Named rather than inlined because it is a
/// rule with two halves and a test that pins only one of them would
/// look complete - see the comment at its one call site.
fn final_state(cancelled: bool, outcome: &Outcome) -> JobState {
    if cancelled && !outcome.committed {
        JobState::Cancelled
    } else {
        outcome.state
    }
}

/// What one job's own work came to, before the cancel flag is applied.
struct Outcome {
    state: JobState,
    result: Option<JobResult>,
    error: Option<JobError>,
    survey: Option<SurveyModel>,
    /// Whether the ENGINE committed this outcome, so a late cancel must
    /// not rewrite it. False for everything that can be stopped
    /// part-way, which is nearly everything - see the cancel rule at
    /// the one site that reads this.
    committed: bool,
}

impl Outcome {
    fn cancelled() -> Outcome {
        Outcome {
            state: JobState::Cancelled,
            result: None,
            error: None,
            survey: None,
            committed: false,
        }
    }
    fn failed(code: &str, message: impl Into<String>) -> Outcome {
        Outcome {
            state: JobState::Failed,
            result: None,
            error: Some(JobError::new(code, message)),
            survey: None,
            committed: false,
        }
    }
}

/// A sink that appends to the job's log tail and rings the host.
fn sink_for(job: &Job) -> Sink {
    let pub_ = Arc::clone(&job.publisher);
    let cap = job.settings.log_tail_lines.max(1);
    let mut sink = Sink::tapped(Box::new(move |line, is_err| {
        pub_.update(|s| {
            let line = if is_err {
                format!("! {line}")
            } else {
                line.to_string()
            };
            if s.log_tail.len() >= cap {
                s.log_tail.remove(0);
            }
            s.log_tail.push(line);
        });
    }));
    sink.set_level(job.settings.advanced.log_level);
    sink
}

/// The `parfast` options a verify or a repair runs under.
fn verify_options(
    par2: &std::path::Path,
    extra: &[std::path::PathBuf],
    o: &crate::job::VerifyOptions,
    purge: bool,
    level: i32,
) -> parfast::cli::Options {
    parfast::cli::Options {
        level,
        threads: o.threads,
        purge,
        rename_only: o.rename_only,
        data_skip: o.data_skipping,
        // `-S` without `-N` is the reference's own refusal, so a leaway
        // with no skipping is dropped rather than sent to a parser that
        // would refuse the whole line.
        skip_leaway: o.skip_leaway.filter(|_| o.data_skipping),
        // `fast` went with parfast's `--fast` (d89e1027da): the joint
        // solve it armed is the engine's default on every class that
        // can run it, so `o.fast_solver` now selects nothing and the
        // setting stays in the model only until the two apps drop the
        // toggle. `slow` is the CLI's whole-file verdict; the app has no
        // counterpart yet and takes the default, which `Session::new`
        // sets process-wide.
        par2: Some(par2.to_path_buf()),
        files: extra.to_vec(),
        ..Default::default()
    }
}

/// The verify half, orchestrated here rather than through
/// `parfast::verify::run` because the SURVEY is the product: `run`
/// answers an exit code and prints, and a block map cannot be drawn
/// from either.
fn run_verify(job: &Job, spec: &VerifySpec, started: Instant) -> Outcome {
    let opts = verify_options(
        &spec.par2,
        &spec.extra_dirs,
        &spec.options,
        false,
        job.settings.advanced.log_level,
    );
    apply_knobs(
        spec.options.threads.or(job.settings.performance.threads),
        job.settings.performance.memory_mb,
        spec.options
            .fast_solver
            .unwrap_or(job.settings.performance.fast_solver),
        job.settings.performance.digest_cache,
    );
    let mut sink = sink_for(job);
    job.publisher.update(|s| {
        s.phase = Phase::Scanning;
        s.phase_text = "Reading the recovery set".to_string();
        s.survey = Some(SurveyModel::pending(
            spec.par2
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            spec.par2
                .parent()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
        ));
    });
    let mut loaded = match parfast::verify::load(&opts, &mut sink) {
        Ok(l) => l,
        Err(code) => {
            return Outcome {
                state: JobState::Failed,
                result: Some(JobResult {
                    exit_code: Some(code),
                    ..Default::default()
                }),
                error: Some(JobError::new(
                    "load_failed",
                    format!("could not load {}", spec.par2.display()),
                )),
                survey: None,
                committed: false,
            };
        }
    };
    parfast::verify::print_set_summary(&loaded, &mut sink);
    job.publisher.update(|s| {
        s.phase = Phase::Hashing;
    });
    let watch = HashWatch {
        job,
        started,
        bytes: loaded.set.files.iter().map(|f| f.length).sum(),
    };
    let Some((mut survey, bits)) =
        parfast::verify::survey_watched(&loaded, &opts, &mut sink, &watch)
    else {
        return Outcome::cancelled();
    };
    if survey.damaged() {
        survey.recovery_blocks = parfast::verify::ensure_recovery(&mut loaded);
    }
    parfast::verify::print_targets(&survey, &mut sink);
    let code = parfast::verify::print_verdict(&loaded, &survey, &mut sink);
    let candidates = parfast::verify::extra_candidates(&loaded, &survey);
    let model = SurveyModel::from_parfast(&loaded, &survey, &bits, &candidates);
    Outcome {
        state: JobState::Done,
        result: Some(JobResult {
            exit_code: Some(code),
            ..Default::default()
        }),
        error: None,
        survey: Some(model),
        committed: false,
    }
}

/// The repair, through `parfast::repair::run_watched` so every safety
/// rail - the `<name>.1` backup aside, the `-p` purge's provenance
/// rule, the `-B` refusal - is the CLI's own and not a second copy.
fn run_repair(job: &Job, spec: &RepairSpec, started: Instant) -> Outcome {
    let opts = verify_options(
        &spec.par2,
        &spec.extra_dirs,
        &spec.options,
        spec.purge,
        job.settings.advanced.log_level,
    );
    apply_knobs(
        spec.options.threads.or(job.settings.performance.threads),
        job.settings.performance.memory_mb,
        spec.options
            .fast_solver
            .unwrap_or(job.settings.performance.fast_solver),
        job.settings.performance.digest_cache,
    );
    let mut sink = sink_for(job);
    job.publisher.update(|s| {
        s.phase = Phase::Hashing;
        s.phase_text = "Verifying before repair".to_string();
    });
    // ONE cancel bit and ONE pause bit for the whole job: the engine's
    // gate IS the job's `Control`, adapted rather than mirrored. A
    // second copy of either would be the two-sources-of-truth bug this
    // crate exists to avoid - a host pressing Pause and watching the
    // state stay `running` is exactly the shape `gated` was written for.
    let watch = FoldWatch {
        job,
        started,
        control: par2repair::RepairControl::new(
            Some(Arc::new(RepairProgress::new(job.publisher.clone()))),
            Some(job.control.engine_gate()),
        ),
    };
    let code = parfast::repair::run_watched(&opts, &mut sink, &watch);
    if job.control.is_cancelled() {
        return Outcome::cancelled();
    }
    // The map the watch captured before the fold, brought forward. A
    // repair that completed made every member whole, so the strip is
    // redrawn from the verdict rather than from a THIRD pass over the
    // payload - `repair::run` has already read it twice.
    let repaired = code == parfast::EXIT_SUCCESS;
    let mut model = watch.take_survey();
    let repaired_files = model
        .as_ref()
        .map(|m| {
            m.files
                .iter()
                .filter(|f| f.status != crate::survey::FileStatus::Complete)
                .count()
        })
        .unwrap_or(0);
    if let Some(m) = model.as_mut() {
        m.verdict = if repaired {
            Verdict::Repaired
        } else {
            Verdict::Failed
        };
        if repaired {
            for f in &mut m.files {
                f.status = crate::survey::FileStatus::Complete;
                f.blocks_ok = f.blocks_total;
                f.found_as = None;
            }
            m.recovery_needed = 0;
            m.block_runs = if m.source_blocks == 0 {
                Vec::new()
            } else {
                vec![[
                    u64::from(crate::survey::block_state::PRESENT),
                    m.source_blocks as u64,
                ]]
            };
        }
    }
    let state = if repaired {
        JobState::Done
    } else {
        JobState::Failed
    };
    Outcome {
        state,
        result: Some(JobResult {
            repaired_files: if repaired { repaired_files } else { 0 },
            purged: spec.purge && repaired,
            exit_code: Some(code),
            ..Default::default()
        }),
        error: (!repaired).then(|| {
            JobError::new(
                if code == parfast::EXIT_REPAIR_NOT_POSSIBLE {
                    "unrepairable"
                } else {
                    "repair_failed"
                },
                format!("parfast exited {code}"),
            )
        }),
        survey: model,
        committed: false,
    }
}

/// Is `name` a file of the recovery set based on `base`? The index
/// itself, or one of its volumes under EITHER spelling - the engine's
/// fixed `vol000+01` or the renamed `vol0+1` / `vol0-0` the CLI leaves
/// behind, which is why this matches the `vol` prefix and not a width.
///
/// ONE predicate, read by the no-overwrite guard before a create and by
/// the written-file report after it: a file the guard would not protect
/// but the report would claim is a file destroyed without warning and
/// then listed as this job's own output.
fn set_member(base: &str, name: &str) -> bool {
    name == format!("{base}.par2")
        || (name.starts_with(&format!("{base}.vol")) && name.ends_with(".par2"))
}

/// The first file of `output`'s recovery set already on disk, if any.
/// See [`set_member`], and the guard in [`run_create`] that reads this.
fn existing_set_member(output: &std::path::Path) -> Option<std::path::PathBuf> {
    let dir = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let base = planner::base_name(output);
    let mut found: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| set_member(&base, &e.file_name().to_string_lossy()))
        .map(|e| e.path())
        .collect();
    // Sorted so the message names the same file every time rather than
    // whatever the directory happened to hand back first.
    found.sort();
    found.into_iter().next()
}

/// The create, through `parfast::create::run` for the same reason.
fn run_create(job: &Job, spec: &CreateSpec, _started: Instant) -> Outcome {
    let planner::Expansion { members, left_out } = match planner::expand_sources(
        &spec.sources,
        spec.path_mode,
        spec.base_path.as_deref(),
        planner::SourceRules::Par2,
    ) {
        Ok(m) => m,
        Err(e) => return Outcome::failed(e.code, e.message),
    };
    // WHAT THE WALK COULD NOT TAKE IN, said twice: once into the log
    // tail the moment it is known, and once into the result the pane
    // shows beside Done. The preview says it too, but the preview is a
    // different moment - the walk happens AGAIN here, over a tree that
    // may have changed, and a folder that became unreadable since the
    // pane was drawn would otherwise reach nobody. See
    // `planner::LeftOut`.
    let coverage = left_out.lines();
    if !coverage.is_empty() {
        let mut early = sink_for(job);
        for line in &coverage {
            early.line(Level::Terse, line);
        }
    }
    let preview = match planner::preview(spec) {
        Ok(p) => p,
        Err(e) => return Outcome::failed(e.code, e.message),
    };
    let (mut opts, _warnings) = match planner::options_for(spec, &members) {
        Ok(v) => v,
        Err(e) => return Outcome::failed(e.code, e.message),
    };
    // The run must use the SAME switches as the preview or it would
    // write a set the pane never described, so both sides read ONE
    // translation - `planner::options_for`, which resolves the volume
    // scheme as well as everything else. It did not always: the scheme
    // was resolved inside `preview` alone, and this argv was built from
    // an `Options` that had never seen it, so every scheme a user
    // picked was written as the exponential default. The line below is
    // unchanged; what changed is that `options_for` now returns the
    // whole answer. See its doc comment and
    // `queue::tests::a_create_writes_exactly_the_files_its_preview_drew`.
    let args: Vec<String> = std::iter::once("c".to_string())
        .chain(planner::command_args(
            &opts,
            &members,
            spec,
            preview.recovery_blocks,
        ))
        .collect();
    match parfast::cli::parse("parfast", &args) {
        Ok(parsed) => opts = parsed.opts,
        Err(e) => return Outcome::failed("bad_plan", e.message),
    }
    opts.level = job.settings.advanced.log_level;
    apply_knobs(
        spec.perf.threads.or(job.settings.performance.threads),
        spec.perf.memory_mb.or(job.settings.performance.memory_mb),
        job.settings.performance.fast_solver,
        job.settings.performance.digest_cache,
    );
    // THE WHOLE SET, not just the index. A create writes one `.par2`
    // and N `.vol...par2` beside it, the engine writes those volumes
    // under its own fixed-width spelling and the CLI renames them to
    // par2cmdline's widths afterwards - and this guard asked only
    // whether `spec.output` existed. A set whose index had been deleted
    // (or which was written under a different `-f`) left its volumes
    // sitting there, and a create submitted with `overwrite = false`
    // replaced every one of them and reported Done. The pane's own
    // protection, on the only files it protects.
    //
    // The predicate is `set_member` - the SAME one the run reads the
    // written set back with below - so what the guard protects and what
    // the create claims cannot drift apart. It is deliberately wider
    // than the exact planned names: a volume of some earlier, differently
    // sliced run of this base is still a file this create is about to
    // destroy.
    //
    // A PREFLIGHT, and it is now the FIRST of two. It is what gives the
    // good message - the path of the file that is in the way, under an
    // `exists` code a host can act on - and it is the only one of the
    // pair that can say anything at all, because the engine answers a
    // refused open with an exit code and nothing else.
    //
    // It cannot be the only one: a set that appears between this check
    // and the engine's first open is not caught here, and two creates
    // started together on one base walk straight through it. The engine
    // has an `O_EXCL` door of its own since 17 Sep 2026 (claim
    // `par2gen-no-clobber-create`), reached by `--no-clobber` on the
    // argv above - `planner::options_for` sets it from this same
    // `spec.overwrite` and `planner::command_args` spells it, so the
    // line the pane SHOWS carries it too. Belt and brace: this check
    // for the message, the open for the guarantee.
    if !spec.overwrite
        && let Some(clash) = existing_set_member(&spec.output)
    {
        return Outcome::failed("exists", format!("{} already exists", clash.display()));
    }
    job.publisher.update(|s| {
        s.phase = Phase::Solving;
        s.phase_text = format!(
            "Creating {} recovery blocks over {} source blocks",
            preview.recovery_blocks, preview.block_count
        );
    });
    let mut sink = sink_for(job);
    // ONE cancel bit and ONE pause bit, as for the repair above: the
    // engine's gate IS this job's `Control`.
    let watch = CreateProgress::watch(job);
    let code = parfast::create::run_watched(&opts, &mut sink, &watch);
    // THE ENGINE'S VERDICT DECIDES, and the order of these two checks
    // is the whole of it.
    //
    // A create is ATOMIC: `EXIT_SUCCESS` means the complete, sealed set
    // is on disk, and a create that really honoured a cancel returns a
    // failure code having removed every file it wrote (`par2gen`'s
    // `CreateTrail`, and `create::run`'s `Err(Cancelled)` arm). So the
    // two cases are already perfectly separated by the code, and until
    // 12 Sep 2026 this read the cancel FLAG first and threw that
    // separation away: a Cancel that lost the race by milliseconds -
    // the engine takes its last poll immediately before sealing the
    // volumes - reported `Cancelled` with `result: None`, so a complete
    // valid recovery set sat on disk with the job claiming none and
    // API.md telling the host not to offer to clean up after it. That
    // is the one outcome nobody wants: files the user paid for that the
    // app refuses to name.
    //
    // Now a job reports cancelled only when the engine actually
    // unwound, which is what makes API.md's "a cancelled create leaves
    // NOTHING" true rather than aspirational, and what lets a host act
    // on it. The cost is showing Done to somebody who pressed Cancel,
    // which is accurate - that is what happened - and was weighed
    // against the alternative of a contract no host can rely on.
    if code != parfast::EXIT_SUCCESS {
        if job.control.is_cancelled() {
            return Outcome::cancelled();
        }
        return Outcome {
            state: JobState::Failed,
            result: Some(JobResult {
                exit_code: Some(code),
                warnings: coverage,
                ..Default::default()
            }),
            error: Some(JobError::new(
                "create_failed",
                format!("parfast exited {code}"),
            )),
            survey: None,
            committed: false,
        };
    }
    // What is ON DISK, not what was planned: the reference renames its
    // volumes to par2cmdline's field widths after the writer has
    // finished, so the planned names are the engine's and these are the
    // user's.
    let dir = spec
        .output
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let base = planner::base_name(&spec.output);
    let mut written: Vec<WrittenFile> = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            set_member(&base, &name).then(|| {
                let size = e.metadata().map(|m| m.len()).unwrap_or(0);
                WrittenFile { name, size }
            })
        })
        .collect();
    written.sort_by(|a, b| a.name.cmp(&b.name));
    Outcome {
        state: JobState::Done,
        result: Some(JobResult {
            written,
            exit_code: Some(code),
            warnings: coverage,
            ..Default::default()
        }),
        error: None,
        survey: None,
        // The engine sealed this set. See the exit-code comment above:
        // this is the ONE outcome in this file a late cancel may not
        // rewrite, because it is the one whose work is all-or-nothing
        // and already finished.
        committed: true,
    }
}

/// The verify pass's progress and cancel, as `parfast` sees them.
struct HashWatch<'a> {
    job: &'a Job,
    started: Instant,
    bytes: u64,
}

impl parfast::verify::SurveyWatch for HashWatch<'_> {
    fn should_continue(&self) -> bool {
        gated(self.job)
    }

    fn member_done(&self, done: usize, total: usize) {
        let frac = if total == 0 {
            1.0
        } else {
            done as f64 / total as f64
        };
        let ms = self.started.elapsed().as_millis() as u64;
        let rate = (frac > 0.0 && ms > 0)
            .then(|| ((self.bytes as f64 * frac) / (ms as f64 / 1000.0)) as u64);
        let eta = (frac > 0.0 && frac < 1.0).then(|| ((ms as f64) * (1.0 - frac) / frac) as u64);
        self.job.publisher.update(|s| {
            s.phase = Phase::Hashing;
            s.phase_text = format!("Hashing {done} of {total} files");
            s.progress = frac;
            s.elapsed_ms = ms;
            s.eta_ms = eta;
            s.rate_bytes_per_s = rate;
        });
    }
}

/// The repair's pre-fold moment - the survey is captured for the block
/// map - and, since 12 Sep 2026, the control the engine reports through
/// for the rest of it.
///
/// The two are one type because they answer one job: `before_fold` is
/// the last moment nothing is written, and [`RepairProgress`] is
/// everything after it.
struct FoldWatch<'a> {
    job: &'a Job,
    started: Instant,
    /// Handed to the engine once, at the top of the repair. Holds the
    /// job's own [`Control`] as the pause gate, so one Pause press
    /// parks the engine and one Cancel press is seen by its loops -
    /// there is no second copy of either bit.
    control: par2repair::RepairControl,
}

/// The engine's progress, as the one bar and the one sentence a host
/// draws.
///
/// WHY THE WEIGHTS ARE HERE AND NOT IN THE ENGINE. The engine reports
/// four phases in four different units and refuses to weigh them,
/// because only a caller knows what its user is waiting on
/// (`par2repair::RepairPhase`). This is that decision, taken once for
/// both apps so they cannot disagree: the verify half is the first
/// 45% of a repair's bar, the fold the next 40%, the solve 10% and the
/// write the last 5%. Those are the shape of an ordinary damaged repair
/// on the measured corpus - the fold and the hashing dominate, the
/// structured solve is seconds - and they are a LABELLING choice, not a
/// prediction: a bar that is honest about which phase is running and
/// monotone within it beats one that lies smoothly.
///
/// # And the SWEEP those weights sit inside
///
/// A memory-capped repair sweeps the payload once per SLAB, re-entering
/// `Fold` and `Solve` at every one (`par2repair`'s two drivers), so
/// their `(done, total)` says where this SWEEP is and nothing about
/// where the repair is. Weighing them without the sweep count froze
/// this bar at the literal figure 0.95 for slabs 2..N - measured here
/// 17 Sep 2026 over the engine's own recorded four-sweep sequence, and
/// three quarters of the slabbed work read `0.9500` while the sentence
/// under it went on counting. That is the daemon's defect of 16 Sep
/// 2026 (`research/REPAIR-SLABBED-BAR-2026-09-16.md`), in the second
/// copy of it, and this is that fix.
///
/// **The split is by SWEEP, not by phase**, and the obvious version is
/// wrong in exactly the way that would leave the defect in place:
/// giving `Fold` the `i`th slice of `[0.45, 0.85)` and `Solve` the
/// `i`th slice of `[0.85, 0.95)` puts sweep 1's solve ABOVE sweep 2's
/// fold, so a monotone bar swallows every later fold just as it does
/// today. So `[0.45, 0.95)` is cut into `of` equal sweep segments and
/// the 40/10 weighting lives INSIDE each one. `Verify` runs once before
/// any of it and `Write` once after, so neither is swept.
///
/// At `of == 1` the arithmetic is the pre-sweep split - to within a
/// float ULP rather than to the bit, which
/// `a_repair_that_does_not_slab_keeps_the_bar_it_always_had` states as
/// the tolerance it checks.
struct RepairProgress {
    publisher: Arc<Publisher>,
    /// The sweep frame: which slab, and how many. `(0, 1)` until the
    /// engine says otherwise - a repair that does not slab announces
    /// `(0, 1)` once and one with no blocks to rebuild announces
    /// nothing, and `(0, 1)` is the right reading of both.
    ///
    /// Relaxed: `slab` is the driver thread, at the top of its sweep,
    /// before that sweep's `begin(Fold, ..)` and never concurrent with
    /// a `progress`.
    slab: AtomicU32,
    slabs: AtomicU32,
}

impl RepairProgress {
    /// A sink publishing into `publisher`, framed as one sweep of one
    /// until the engine says otherwise.
    fn new(publisher: Arc<Publisher>) -> RepairProgress {
        RepairProgress {
            publisher,
            slab: AtomicU32::new(0),
            slabs: AtomicU32::new(1),
        }
    }

    /// `(bar offset, bar span)` for a phase in sweep `slab` of `of`.
    fn band(phase: par2repair::RepairPhase, slab: u32, of: u32) -> (f64, f64) {
        use par2repair::RepairPhase as P;
        let of = f64::from(of.max(1));
        let i = f64::from(slab).min(of - 1.0);
        match phase {
            P::Verify => (0.0, 0.45),
            // The two swept phases, inside sweep `i`'s own segment of
            // the half-open `[0.45, 0.95)` the sweeps share.
            P::Fold => (0.45 + 0.50 * i / of, 0.40 / of),
            P::Solve => (0.45 + (0.50 * i + 0.40) / of, 0.10 / of),
            P::Write => (0.95, 0.05),
        }
    }
}

impl par2repair::ProgressSink for RepairProgress {
    fn slab(&self, index: usize, of: usize) {
        self.slabs
            .store(u32::try_from(of.max(1)).unwrap_or(1), Ordering::Relaxed);
        self.slab
            .store(u32::try_from(index).unwrap_or(0), Ordering::Relaxed);
    }

    fn progress(&self, phase: par2repair::RepairPhase, done: u64, total: u64) {
        use par2repair::RepairPhase as P;
        let (base, span) = RepairProgress::band(
            phase,
            self.slab.load(Ordering::Relaxed),
            self.slabs.load(Ordering::Relaxed),
        );
        let frac = if total == 0 {
            0.0
        } else {
            (done as f64 / total as f64).clamp(0.0, 1.0)
        };
        let pct = (frac * 100.0).round() as u64;
        self.publisher.update(|s| {
            s.phase = match phase {
                P::Verify => Phase::Hashing,
                P::Fold | P::Solve => Phase::Solving,
                P::Write => Phase::Writing,
            };
            s.phase_text = match phase {
                P::Verify => format!("Verifying before repair - {pct}%"),
                // "Folding", not "Reading": since 17 Sep 2026 this
                // phase's figure counts bytes XORed into the syndrome
                // rows rather than bytes handed to the worker that
                // does it, and on a set whose corpus the verify pass
                // kept there is no read in it at all.
                P::Fold => format!("Combining the good blocks - {pct}%"),
                P::Solve => format!("Rebuilding the missing blocks - {pct}%"),
                P::Write => format!("Writing the repaired files - {pct}%"),
            };
            // MONOTONE ACROSS PHASES as well as within one: the bands
            // above run in the order the engine enters them, and a bar
            // that went backwards at a hand-over would read as a
            // restart.
            s.progress = s.progress.max(base + span * frac);
        });
    }
}

/// The create's progress and cancel, as `parfast` sees them.
///
/// # Why the create's bar is not banded like the repair's
///
/// [`RepairProgress`] gives each of the repair's four phases a slice of
/// the bar, because they run one after another. A create's do NOT: it
/// hashes the members on one thread while the fold reads the same
/// payload on another - that overlap is what the creator's whole
/// pipeline is built around - and on the fused arm the fold's own
/// reader does the hashing, so the hash phase never reports at all.
/// Banding them would make the bar jump backwards on one shape and
/// stall at 45% on the other.
///
/// So HASHING and the FOLD share one span, 0 to 90%, and the bar is
/// whichever of the two is further along - honest on every arm, and
/// monotone because the snapshot only ever takes the larger value. The
/// volume WRITES are the last 10%.
///
/// # The batch frame, and the three ways this bar pegged without it
///
/// A memory-capped create folds the set a BATCH of volumes at a time.
/// `Verify` is sized once for the whole create and `Write` is sized
/// once over every recovery slice of the set, but `Fold` is re-sized at
/// every batch (`par2gen::recovery_slices`), so its `(done, total)`
/// says where THIS batch is and nothing about where the create is.
/// Merging the three with `max` and no frame pegged the bar three
/// separate ways on an 18-batch create, all of them during batch 1:
///
/// 1. the scan reads the payload ONCE, beside batch 1, so `Verify`
///    reached 100% of the shared span there and `max` held the bar at
///    90% for the seventeen batches after it;
/// 2. `Fold` itself ran 0 to 100% of that span within batch 1 and was
///    then discarded at every later batch, for the same reason;
/// 3. and `Write`, which `par2gen::volwrite` steps after EVERY batch,
///    put the bar over 90% as soon as batch 1's volumes were flushed -
///    so even with 1 and 2 fixed, seventeen eighteenths of the create
///    would have shared the last tenth of the bar. This one is the
///    dominant peg and it is not in the report that found the other
///    two: `Write` overlaps the fold on the stripe-first arm as well
///    (the volumes are laid out up front and filled by chunk), where it
///    took the bar to 90% within the first chunk of a ONE-batch create.
///
/// That is the shape the daemon's slabbed repair bar had until 16 Sep
/// 2026 (`research/REPAIR-SLABBED-BAR-2026-09-16.md`), and the fix is
/// that one: the engine announces the frame through
/// [`par2repair::ProgressSink::slab`]
/// (`nzbkit::par2gen::control::CreateControl::batch`), `Fold` is placed
/// INSIDE it, `Verify` may not push the bar past the end of the batch
/// it runs beside, and the writes wait for their turn.
///
/// `parfast c`'s own meter does exactly this (`parfast::control`'s
/// `CreateMeter`) and the two must not disagree: one job showing two
/// percentages is a defect whichever side moved.
///
/// ON A ONE-BATCH CREATE - every create that fits the accumulator
/// budget, so nearly all of them - the first two rules are arithmetic
/// identities over the old ones and the figures are unchanged to the
/// bit. `a_one_batch_create_draws_exactly_the_bar_it_always_did` is
/// that claim.
///
/// # Why the writes wait, which is a real change on every arm
///
/// Rule 3 has no one-batch identity: holding the write band back until
/// the hash-and-fold band is full changes what a one-batch stripe-first
/// create draws, deliberately. Drawing the writes as they arrive is not
/// a bar - it is 90% reached in the first seconds and then a tenth of a
/// bar for the rest of the create - and it flickers `phase_text`
/// between "Building the recovery blocks" and "Writing the recovery
/// volumes" for the whole of the overlap, because the two phases really
/// are running at once. Held, the bar is the hashing and the folding
/// until they are done and the volume writes after, which is the order
/// the user is told about, the order `parfast c` prints
/// (`Processing:` runs to 100 before `Writing:` takes the line) and the
/// order par2cmdline prints. The cost, stated: the writes that already
/// happened during the fold are not owed a second showing, so on the
/// arms where the overlap is total the last tenth crosses quickly.
struct CreateProgress {
    publisher: Arc<Publisher>,
    /// The fold batch frame: which batch, and how many there are.
    /// `(0, 1)` until the engine says otherwise, which is the right
    /// reading of a create that folds in one pass and of the
    /// stripe-first transform, which announces nothing.
    ///
    /// Relaxed: `slab` is the driver thread, once per batch, before
    /// that batch's `begin(Fold, ..)` and never concurrent with a
    /// `progress` of its own - and the only other reader is a scan
    /// thread whose `Verify` fraction is a cap on a bar, not a
    /// correctness bit.
    batch: AtomicU32,
    batches: AtomicU32,
    /// Set once the hash-and-fold band is FULL, which is the gate on
    /// the write band - see the type doc. A separate flag rather than a
    /// read of `s.progress`, so a held write frame never takes the
    /// snapshot lock or rings the host's wake.
    ///
    /// EITHER phase can set it, which is deliberate and is why it is
    /// not named for the fold. The band holds whichever of the two is
    /// further along, so a hash that reaches the end of it has left
    /// nothing for the fold to move: the bar would sit at 0.90 with the
    /// writes still held, which is the freeze this whole type is about.
    /// On a multi-batch create the hash cannot reach the end anyway,
    /// because it is capped at the batch it runs beside.
    band_full: AtomicBool,
}

impl CreateProgress {
    /// The watch to hand `parfast::create::run_watched`: this job's own
    /// gate, and a sink that publishes into its snapshot.
    fn watch(job: &Job) -> CreateWatch {
        CreateWatch {
            control: nzbkit::par2gen::control::CreateControl::new(
                Some(Arc::new(CreateProgress::new(job.publisher.clone()))),
                Some(job.control.engine_gate()),
            ),
        }
    }

    /// A sink publishing into `publisher`, framed as one batch of one
    /// until the engine says otherwise.
    fn new(publisher: Arc<Publisher>) -> CreateProgress {
        CreateProgress {
            publisher,
            batch: AtomicU32::new(0),
            batches: AtomicU32::new(1),
            band_full: AtomicBool::new(false),
        }
    }
}

/// The create's half of [`FoldWatch`]: one control, fetched once.
struct CreateWatch {
    control: nzbkit::par2gen::control::CreateControl,
}

impl parfast::create::CreateWatch for CreateWatch {
    fn control(&self) -> nzbkit::par2gen::control::CreateControl {
        self.control.clone()
    }
}

impl par2repair::ProgressSink for CreateProgress {
    fn slab(&self, index: usize, of: usize) {
        self.batches
            .store(u32::try_from(of.max(1)).unwrap_or(1), Ordering::Relaxed);
        self.batch
            .store(u32::try_from(index).unwrap_or(0), Ordering::Relaxed);
    }

    fn progress(&self, phase: par2repair::RepairPhase, done: u64, total: u64) {
        use par2repair::RepairPhase as P;
        let frac = if total == 0 {
            0.0
        } else {
            (done as f64 / total as f64).clamp(0.0, 1.0)
        };
        let pct = (frac * 100.0).round() as u64;
        let of = f64::from(self.batches.load(Ordering::Relaxed).max(1));
        let i = f64::from(self.batch.load(Ordering::Relaxed)).min(of - 1.0);
        // The bar this frame asks for, in the 0..0.90 hash-and-fold
        // span, or `None` for a frame that is not allowed to draw.
        let band = match phase {
            // This batch's own fraction, placed inside the batch frame.
            P::Fold => Some((i + frac) / of),
            // The hash, which cannot speak for a batch it never ran
            // beside - see the type doc.
            P::Verify => Some(frac.min((i + 1.0) / of)),
            // A create has nothing to solve; `par2gen` never sends it.
            P::Solve => return,
            // The writes, held until the fold has finished with the bar.
            P::Write => None,
        };
        if band.is_some_and(|b| b >= 1.0) {
            self.band_full.store(true, Ordering::Relaxed);
        }
        if band.is_none() && !self.band_full.load(Ordering::Relaxed) {
            return;
        }
        self.publisher.update(|s| {
            s.phase = match phase {
                P::Verify => Phase::Hashing,
                P::Write => Phase::Writing,
                _ => Phase::Solving,
            };
            s.phase_text = match phase {
                P::Verify => format!("Hashing the source files - {pct}%"),
                P::Write => format!("Writing the recovery volumes - {pct}%"),
                _ => format!("Building the recovery blocks - {pct}%"),
            };
            // MONOTONE, as it always was: every hand-over this bar has -
            // the hashing and the folding trading places as the further
            // on of the two, one batch to the next - can present a
            // smaller figure than the one already on screen, and a bar
            // that falls back reads as a restart.
            s.progress = s.progress.max(match band {
                Some(b) => 0.90 * b,
                None => 0.90 + 0.10 * frac,
            });
        });
    }
}

impl FoldWatch<'_> {
    /// The model the watch built, if it reached the handshake at all.
    fn take_survey(&self) -> Option<SurveyModel> {
        self.job
            .publisher
            .snapshot
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .survey
            .clone()
    }
}

impl parfast::repair::RepairWatch for FoldWatch<'_> {
    fn control(&self) -> par2repair::RepairControl {
        self.control.clone()
    }
    fn before_fold(&self, survey: &parfast::verify::Survey) -> bool {
        let ms = self.started.elapsed().as_millis() as u64;
        let model = model_from_counts(survey);
        self.job.publisher.update(|s| {
            s.phase = Phase::Solving;
            s.phase_text = format!(
                "Rebuilding {} of {} blocks",
                survey.owed(),
                survey.total_blocks
            );
            s.elapsed_ms = ms;
            s.survey = Some(model);
        });
        gated(self.job)
    }
}

/// A survey model from per-member COUNTS alone - what the repair path
/// has before the fold.
///
/// The positions in this strip are not measured: the engine's survey
/// reports how many of a member's blocks are present, not which, so
/// the present ones are drawn first. A verify job draws the real
/// positions (it has the bitmap); this is the transient picture during
/// a repair and `crates/parfast-ffi/API.md` says so.
fn model_from_counts(survey: &parfast::verify::Survey) -> SurveyModel {
    use crate::survey::{FileRow, FileStatus};
    use parfast::verify::Target;

    let mut files = Vec::with_capacity(survey.targets.len());
    let mut runs: Vec<[u64; 2]> = Vec::new();
    for (name, t) in &survey.targets {
        let (status, ok, total) = match t {
            Target::Found => (FileStatus::Complete, 0usize, 0usize),
            Target::Damaged { have, total } => (FileStatus::Damaged, *have, *total),
            Target::Missing => (FileStatus::Missing, 0, 0),
        };
        let bits: Vec<bool> = (0..total).map(|i| i < ok).collect();
        crate::survey::push_blocks(&mut runs, status, &bits, total);
        files.push(FileRow {
            name: name.clone(),
            size: 0,
            status,
            blocks_ok: ok,
            blocks_total: total,
            found_as: None,
            progress: 1.0,
        });
    }
    SurveyModel {
        set_name: String::new(),
        folder: String::new(),
        block_size: 0,
        source_blocks: survey.total_blocks,
        recovery_available: survey.recovery_blocks,
        recovery_needed: survey.owed(),
        verdict: if survey.repairable() {
            Verdict::Repairable
        } else {
            Verdict::Unrepairable
        },
        files,
        block_runs: runs,
    }
}

/// A key equal for two paths naming the SAME file on disk - through a
/// symlink, a hard link, or two spellings of one path - and `None` for a
/// path that is not there at all.
///
/// The identity, not the spelling: a checksum create asked to write its
/// manifest over one of its own inputs is the same destruction whether
/// the user typed the path twice, pointed at a symlink to it, or hard
/// linked it beside itself.
fn same_file_key(path: &std::path::Path) -> Option<String> {
    // Follows links deliberately: a symlink and its target are one file
    // for the purpose of "am I about to overwrite my input".
    let md = std::fs::metadata(path).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(format!("{}:{}", md.dev(), md.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = md;
        Some(
            std::fs::canonicalize(path)
                .ok()?
                .to_string_lossy()
                .to_lowercase(),
        )
    }
}

/// Do these two paths name the same file on disk? [`same_file_key`] on
/// both, with a missing file never equal to anything.
fn same_file(a: &std::path::Path, b: &std::path::Path) -> bool {
    match (same_file_key(a), same_file_key(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

/// The two checksum jobs, which are wholly this crate's - see
/// [`crate::checksum`] for why they are not `nzbfast-engine`'s parser.
mod checksums {
    use super::*;
    use crate::checksum;
    use crate::job::{ChecksumCreateSpec, ChecksumVerifySpec};

    pub(super) fn create(job: &Job, spec: &ChecksumCreateSpec, started: Instant) -> Outcome {
        let members = match crate::planner::expand_sources(
            &spec.sources,
            if spec.relative {
                crate::job::PathMode::Relative
            } else {
                crate::job::PathMode::Basename
            },
            spec.output.parent(),
            // NOT the PAR2 rule. A checksum manifest is not a recovery
            // set: `sha256sum` hashes what it is given, and both of
            // par2cmdline's source exclusions are silently wrong here -
            // a folder holding a PAR2 set produced a manifest with every
            // `.par2` missing from it, and a dot-file named explicitly
            // as a source was dropped with nothing said. The manifest
            // then verified CLEAN, because what is not in it is not
            // checked. See `planner::SourceRules`.
            crate::planner::SourceRules::All,
        ) {
            Ok(m) => m,
            Err(e) => return Outcome::failed(e.code, e.message),
        };
        // As `run_create`: a manifest that covers less than the folder
        // the user chose says so, on the log and on the result. It
        // matters MORE here than it does for a create, because what is
        // not in a manifest is not checked - the verify that reads this
        // file back reports CLEAN over the gap.
        let coverage = members.left_out.lines();
        if !coverage.is_empty() {
            let mut early = sink_for(job);
            for line in &coverage {
                early.line(Level::Terse, line);
            }
        }
        let members = members.members;
        // THE MANIFEST IS NOT ONE OF ITS OWN INPUTS. A recursive source
        // over the folder the manifest sits in picks the manifest up on
        // the SECOND run, so the file recorded its own previous contents
        // and then mismatched itself the moment it was rewritten - and
        // the aliasing case below is worse still. Dropped silently and
        // not refused: a whole folder is the ordinary way to ask for
        // this, and "hash everything here except the answer" is what the
        // user meant by it.
        let out_id = same_file_key(&spec.output);
        let members: Vec<_> = members
            .into_iter()
            .filter(|m| {
                m.path != spec.output && !(out_id.is_some() && same_file_key(&m.path) == out_id)
            })
            .collect();
        // AN INPUT NAMED AS THE OUTPUT IS REFUSED, and this is the whole
        // of P1: the write below is an unconditional `fs::write`, so
        // `parfast` asked to checksum `payload.bin` INTO `payload.bin`
        // replaced the file it was protecting with a one-line manifest
        // of what it used to be, and reported Done. The filter above
        // removes the alias from a folder expansion; an explicitly named
        // one is a refusal, because dropping it silently would leave a
        // manifest that does not cover the file the user pointed at.
        if let Some(clash) = spec.sources.iter().find(|s| {
            s.path == spec.output || (out_id.is_some() && same_file_key(&s.path) == out_id)
        }) {
            return Outcome::failed(
                "output_is_a_source",
                format!(
                    "{} is both a source and the checksum file to write; \
                     choose a different output",
                    clash.path.display()
                ),
            );
        }
        if members.is_empty() {
            return Outcome::failed(
                "no_sources",
                "no files to check: add at least one file, or a folder that holds one \
                 besides the checksum file itself",
            );
        }
        // NEVER WRITE A MANIFEST THIS SAME CODE CANNOT READ BACK. A
        // checksum file's names are resolved relative to its OWN
        // directory (`checksum::resolve`), so a source that does not sit
        // under that directory has no name this format can carry:
        // `expand_sources` falls back to the source's own - usually
        // ABSOLUTE - path, and the checker then finds nothing at all.
        // The file the user just hashed verifies as Missing while
        // sitting untouched where it always was.
        //
        // Asked as a ROUND TRIP rather than as a list of bad shapes:
        // each name is put back through the reader's own resolver and
        // must come out pointing at the file it was made from. That is
        // the property that matters, it needs no second reading of the
        // traversal rules, and it catches whatever a future name rule
        // would catch too.
        let out_dir = spec
            .output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        if let Some(stray) = members.iter().find(|m| {
            !checksum::resolve(&out_dir, &m.name)
                .is_some_and(|back| back == m.path || same_file(&back, &m.path))
        }) {
            return Outcome::failed(
                "outside_checksum_folder",
                format!(
                    "{} is not inside {}, so no name in the checksum file can point at it; \
                     write the checksum file beside the files it covers",
                    stray.path.display(),
                    out_dir.display()
                ),
            );
        }
        let total = members.len();
        let entries: Vec<(String, std::path::PathBuf)> = members
            .iter()
            .map(|m| (m.name.clone(), m.path.clone()))
            .collect();
        // THE GATE IS ROUND THE HASHING, which is where the work is.
        // This loop used to run first and only build the list above -
        // so the progress bar reached 100% before a single byte was
        // read, and the whole hashing pass then happened inside one
        // uninterruptible call. A Cancel pressed during a large folder
        // was noticed when the LAST file finished, against an API.md
        // that promises cancellation between files.
        let text = match checksum::write_text_watched(&entries, spec.format, |i| {
            if !gated(job) {
                return false;
            }
            publish_file_progress(job, i, total, started, "Hashing");
            true
        }) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => return Outcome::cancelled(),
            Err(e) => return Outcome::failed("io", e.to_string()),
        };
        // STAGED and renamed over, the same shape the queue store uses:
        // a failed or interrupted write must not leave a truncated
        // manifest where a complete one was.
        let tmp = spec.output.with_extension(format!(
            "{}.parfast-tmp",
            spec.output
                .extension()
                .map(|e| e.to_string_lossy().into_owned())
                .unwrap_or_default()
        ));
        if let Err(e) = std::fs::write(&tmp, text.as_bytes()) {
            let _ = std::fs::remove_file(&tmp);
            return Outcome::failed("io", format!("{}: {e}", tmp.display()));
        }
        if let Err(e) = std::fs::rename(&tmp, &spec.output) {
            let _ = std::fs::remove_file(&tmp);
            return Outcome::failed("io", format!("{}: {e}", spec.output.display()));
        }
        let size = std::fs::metadata(&spec.output)
            .map(|m| m.len())
            .unwrap_or(0);
        Outcome {
            state: JobState::Done,
            result: Some(JobResult {
                written: vec![WrittenFile {
                    name: spec
                        .output
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    size,
                }],
                checksum: Some(ChecksumResult {
                    ok: total,
                    ..Default::default()
                }),
                warnings: coverage,
                ..Default::default()
            }),
            error: None,
            survey: None,
            committed: false,
        }
    }

    pub(super) fn verify(job: &Job, spec: &ChecksumVerifySpec, started: Instant) -> Outcome {
        let text = match std::fs::read_to_string(&spec.file) {
            Ok(t) => t,
            Err(e) => return Outcome::failed("io", format!("{}: {e}", spec.file.display())),
        };
        let hint = spec
            .file
            .extension()
            .and_then(|e| e.to_str())
            .and_then(ChecksumFormat::from_extension);
        let parsed = match checksum::parse(&text, hint) {
            Ok(p) => p,
            Err(e) => return Outcome::failed(e.code, e.message),
        };
        let base = spec
            .file
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let total = parsed.entries.len();
        let mut tally = ChecksumResult::default();
        let mut rows = Vec::with_capacity(total);
        for (i, e) in parsed.entries.iter().enumerate() {
            if !gated(job) {
                return Outcome::cancelled();
            }
            publish_file_progress(job, i, total, started, "Checking");
            let one = checksum::ChecksumFile {
                format: parsed.format,
                entries: vec![e.clone()],
            };
            let row = match checksum::check(&one, &base) {
                Ok(mut r) => r.remove(0),
                Err(err) => return Outcome::failed("io", err.to_string()),
            };
            match row.status {
                checksum::RowStatus::Ok => tally.ok += 1,
                checksum::RowStatus::Mismatch => tally.mismatch += 1,
                checksum::RowStatus::Missing => tally.missing += 1,
            }
            rows.push(row);
        }
        let clean = tally.mismatch == 0 && tally.missing == 0;
        // Read off before the tally is moved into the result below.
        let (mismatch, missing) = (tally.mismatch, tally.missing);
        job.publisher.update(|s| {
            s.log_tail.extend(rows.iter().map(|r| {
                format!(
                    "{}: {}",
                    r.name,
                    match r.status {
                        checksum::RowStatus::Ok => "OK",
                        checksum::RowStatus::Mismatch => "MISMATCH",
                        checksum::RowStatus::Missing => "MISSING",
                    }
                )
            }));
        });
        Outcome {
            state: if clean {
                JobState::Done
            } else {
                JobState::Failed
            },
            result: Some(JobResult {
                checksum: Some(ChecksumResult {
                    entries: rows,
                    ..tally
                }),
                ..Default::default()
            }),
            error: (!clean).then(|| {
                JobError::new(
                    "checksum_mismatch",
                    format!("{mismatch} mismatched, {missing} missing of {total}"),
                )
            }),
            survey: None,
            committed: false,
        }
    }

    fn publish_file_progress(job: &Job, i: usize, total: usize, started: Instant, verb: &str) {
        let frac = if total == 0 {
            1.0
        } else {
            i as f64 / total as f64
        };
        let ms = started.elapsed().as_millis() as u64;
        job.publisher.update(|s| {
            s.phase = Phase::Hashing;
            s.phase_text = format!("{verb} {} of {total} files", i + 1);
            s.progress = frac;
            s.elapsed_ms = ms;
        });
    }
}

/// A job kind's own name, for the queue's table.
pub fn kind_label(kind: JobKind) -> &'static str {
    match kind {
        JobKind::Create => "Create",
        JobKind::Verify => "Verify",
        JobKind::Repair => "Repair",
        JobKind::ChecksumCreate => "Checksum",
        JobKind::ChecksumVerify => "Check",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// The gate blocks while paused and comes back the moment the
    /// pause is lifted - the property a Pause button is.
    #[test]
    fn the_gate_parks_while_paused_and_returns_on_resume() {
        let c = Control::new();
        c.set_paused(true);
        let c2 = Arc::clone(&c);
        let done = Arc::new(AtomicBool::new(false));
        let d2 = Arc::clone(&done);
        let h = std::thread::spawn(move || {
            let ok = c2.gate();
            d2.store(true, Ordering::SeqCst);
            ok
        });
        // Not a sleep-and-hope: the flag must still be false while the
        // worker is parked, and the only way past is the resume below.
        for _ in 0..20 {
            if done.load(Ordering::SeqCst) {
                panic!("the gate let a paused job through");
            }
            std::thread::yield_now();
        }
        c.set_paused(false);
        assert!(h.join().expect("gate thread"), "resume lets it through");
    }

    /// A cancel WHILE PAUSED takes effect at once. Without this a
    /// cancelled job would sit parked until somebody pressed Resume,
    /// which is the one thing they are not going to do.
    #[test]
    fn a_cancel_while_paused_releases_the_gate_and_answers_false() {
        let c = Control::new();
        c.set_paused(true);
        let c2 = Arc::clone(&c);
        let h = std::thread::spawn(move || c2.gate());
        c.cancel();
        assert!(!h.join().expect("gate thread"));
    }

    #[test]
    fn a_cancelled_control_never_parks_again() {
        let c = Control::new();
        c.cancel();
        c.set_paused(true);
        assert!(!c.gate(), "a cancelled control answers immediately");
        assert!(!c.is_paused(), "cancel outranks pause");
    }

    /// The wiring, end to end and with no clock in it: a create job
    /// whose Control is ALREADY cancelled reaches the engine, unwinds
    /// at its first poll, and leaves nothing on disk.
    ///
    /// What it would catch: a `run_create` that built a watch and did
    /// not pass it, or passed a control holding a SECOND gate. Either
    /// writes the whole set and returns `Done`, and both are the
    /// two-sources-of-truth shape `Control`'s doc exists for. Nothing
    /// here races - `run_create` is called directly, so the cancel is
    /// in place before the first member is opened.
    #[test]
    fn a_create_whose_job_is_cancelled_writes_nothing_and_reports_cancelled() {
        use crate::job::{
            BlockSpec, CreateSpec, PathMode, RecoverySpec, Source, UnicodePolicy, VolumeSpec,
        };
        let d = std::env::temp_dir().join(format!(
            "parfast-session-createcancel-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("temp dir");
        std::fs::write(d.join("a.bin"), vec![5u8; 200_000]).expect("member");
        let spec = CreateSpec {
            sources: vec![Source {
                path: d.join("a.bin"),
                recursive: false,
            }],
            path_mode: PathMode::Basename,
            base_path: None,
            block: Some(BlockSpec::Size { size: 2_048 }),
            recovery: Some(RecoverySpec::Count { count: 20 }),
            output: d.join("set.par2"),
            volumes: VolumeSpec::Pow2,
            first_recovery_block: 0,
            comment: String::new(),
            overwrite: false,
            std_naming: false,
            unicode: UnicodePolicy::Auto,
            perf: Default::default(),
        };
        let job = Job {
            spec: JobSpec::Create {
                create: spec.clone(),
            },
            control: Control::new(),
            publisher: Publisher::new(JobSnapshot::queued(
                1,
                JobKind::Create,
                "2026-09-12T00:00:00Z".into(),
                false,
            )),
            knobs: KnobLock::new(),
            shared: false,
            settings: Settings::default(),
        };
        job.control.cancel();
        let outcome = run_create(&job, &spec, Instant::now());
        assert_eq!(
            outcome.state,
            JobState::Cancelled,
            "error: {:?}",
            outcome.error
        );
        let left: Vec<String> = std::fs::read_dir(&d)
            .expect("read dir")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".par2"))
            .collect();
        assert!(
            left.is_empty(),
            "a cancelled create job left files: {left:?}"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A Cancel that lost the race to a SEALED set reports Done and
    /// names the files, rather than reporting Cancelled and naming
    /// none.
    ///
    /// # Why the race is not raced here
    ///
    /// The window is between the engine's last poll - which it takes
    /// immediately before sealing the volumes - and the runner reading
    /// the flag, so it is sub-millisecond and cannot be hit on purpose
    /// from outside. Nothing here tries. The create is run to
    /// completion for real, which establishes the two facts that matter
    /// (the engine returns a COMMITTED outcome, and the set is on
    /// disk), and the cancel is then applied to `final_state`, which is
    /// the rule the runner applies at exactly that seam.
    ///
    /// Both halves of that rule are pinned. A test that checked only
    /// the create would pass just as well against a runner that ignored
    /// every late cancel for every job kind, which is the opposite
    /// defect and a worse one.
    #[test]
    fn a_cancel_that_lost_the_race_to_a_sealed_set_reports_done_and_names_the_files() {
        use crate::job::{
            BlockSpec, CreateSpec, PathMode, RecoverySpec, Source, UnicodePolicy, VolumeSpec,
        };
        let d = std::env::temp_dir().join(format!(
            "parfast-session-latecancel-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("temp dir");
        std::fs::write(d.join("a.bin"), vec![5u8; 200_000]).expect("member");
        let spec = CreateSpec {
            sources: vec![Source {
                path: d.join("a.bin"),
                recursive: false,
            }],
            path_mode: PathMode::Basename,
            base_path: None,
            block: Some(BlockSpec::Size { size: 2_048 }),
            recovery: Some(RecoverySpec::Count { count: 20 }),
            output: d.join("set.par2"),
            volumes: VolumeSpec::Pow2,
            first_recovery_block: 0,
            comment: String::new(),
            overwrite: false,
            std_naming: false,
            unicode: UnicodePolicy::Auto,
            perf: Default::default(),
        };
        let job = Job {
            spec: JobSpec::Create {
                create: spec.clone(),
            },
            control: Control::new(),
            publisher: Publisher::new(JobSnapshot::queued(
                1,
                JobKind::Create,
                "2026-09-12T00:00:00Z".into(),
                false,
            )),
            knobs: KnobLock::new(),
            shared: false,
            settings: Settings::default(),
        };
        // Uncancelled: the engine runs to the end and seals the set.
        let outcome = run_create(&job, &spec, Instant::now());
        assert_eq!(outcome.state, JobState::Done, "error: {:?}", outcome.error);
        assert!(
            outcome.committed,
            "a sealed set must declare itself the engine's, or the rule below has nothing to act on"
        );
        let written = outcome
            .result
            .as_ref()
            .expect("a finished create names what it wrote")
            .written
            .clone();
        assert!(!written.is_empty(), "a finished create wrote no files");
        let on_disk: Vec<String> = std::fs::read_dir(&d)
            .expect("read dir")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".par2"))
            .collect();
        assert_eq!(
            written.len(),
            on_disk.len(),
            "the outcome names {} files and the disk holds {}: {on_disk:?}",
            written.len(),
            on_disk.len()
        );

        // The press lands NOW - after the engine committed.
        job.control.cancel();
        assert_eq!(
            final_state(job.control.is_cancelled(), &outcome),
            JobState::Done,
            "a set that is sealed on disk must not be reported as cancelled"
        );

        // The other half: an outcome the engine did NOT commit still
        // takes the cancel, which is every other job kind.
        let interruptible = Outcome {
            state: JobState::Done,
            result: None,
            error: None,
            survey: None,
            committed: false,
        };
        assert_eq!(
            final_state(true, &interruptible),
            JobState::Cancelled,
            "a late cancel must still decide the state for work that can stop part-way"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A repair that does NOT slab keeps the bar it always had: the
    /// 45/40/10/5 split, phase by phase.
    ///
    /// This is the safety argument for the sweep frame, and both ways a
    /// repair can be one sweep are run - the engine announcing `(0, 1)`
    /// and the engine announcing NOTHING, which is what a repair with
    /// no blocks to rebuild does.
    ///
    /// Checked to within a float ULP and not to the bit, which is the
    /// honest claim: the segment arithmetic reassociates the same
    /// weights, so `0.45 + 0.40/1.0` is one ULP above the literal
    /// `0.85` the table used to carry. Nothing draws a bar to
    /// seventeen digits; a host draws a percentage.
    #[test]
    fn a_repair_that_does_not_slab_keeps_the_bar_it_always_had() {
        use par2repair::ProgressSink;
        use par2repair::RepairPhase as P;
        for announce in [false, true] {
            let p = Publisher::new(JobSnapshot::queued(
                1,
                JobKind::Repair,
                "2026-09-12T00:00:00Z".into(),
                false,
            ));
            let sink = RepairProgress::new(Arc::clone(&p));
            if announce {
                sink.slab(0, 1);
            }
            for (phase, base, span) in [
                (P::Verify, 0.0, 0.45),
                (P::Fold, 0.45, 0.40),
                (P::Solve, 0.85, 0.10),
                (P::Write, 0.95, 0.05),
            ] {
                for done in 0..=4u64 {
                    sink.progress(phase, done, 4);
                    // The pre-sweep table, verbatim.
                    let want: f64 = base + span * (done as f64 / 4.0);
                    assert!(
                        (p.get().progress - want).abs() < 1e-12,
                        "{phase:?} {done}/4 (announce={announce}) drew {} and the pre-sweep \
                         table says {want}",
                        p.get().progress
                    );
                }
            }
        }
    }

    /// THE DEFECT, pinned, and measured off the engine before it was
    /// fixed: a four-sweep repair read the literal figure 0.95 for
    /// sweeps 1, 2 and 3 while the sentence under it went on counting.
    ///
    /// The sequence is the engine's own order - `Verify` once, then per
    /// sweep an announcement, a `Fold` and a `Solve`, then one `Write`
    /// (`research/REPAIR-SLABBED-BAR-2026-09-16.md` section 2 records
    /// it from a real four-sweep repair). Asserted per sweep that BOTH
    /// of its phases moved the bar, which is the discriminating pair: a
    /// bar that merely rose somewhere and landed on full passes against
    /// the unswept bands too.
    #[test]
    fn every_sweep_of_a_slabbed_repair_moves_the_bar() {
        use par2repair::ProgressSink;
        use par2repair::RepairPhase as P;
        const OF: usize = 4;
        let p = Publisher::new(JobSnapshot::queued(
            1,
            JobKind::Repair,
            "2026-09-12T00:00:00Z".into(),
            false,
        ));
        let sink = RepairProgress::new(Arc::clone(&p));
        for step in 1..=4u64 {
            sink.progress(P::Verify, step, 4);
        }
        assert!((p.get().progress - 0.45).abs() < 1e-12, "{:?}", p.get());
        for sweep in 0..OF {
            sink.slab(sweep, OF);
            let opened = p.get().progress;
            for step in 1..=4u64 {
                sink.progress(P::Fold, step, 4);
            }
            let folded = p.get().progress;
            assert!(
                folded > opened,
                "sweep {sweep} of {OF}: its fold did not move the bar ({opened} -> {folded})"
            );
            for step in 1..=4u64 {
                sink.progress(P::Solve, step, 4);
            }
            let solved = p.get().progress;
            assert!(
                solved > folded,
                "sweep {sweep} of {OF}: its solve did not move the bar ({folded} -> {solved})"
            );
            // And no sweep may spend the room the later ones need.
            assert!(
                solved <= 0.95 + 1e-12,
                "sweep {sweep} of {OF} took the bar to {solved}, into the write's band"
            );
        }
        // The last sweep hands the bar to the write exactly where the
        // unswept table handed it over.
        assert!((p.get().progress - 0.95).abs() < 1e-12, "{:?}", p.get());
        for step in 1..=4u64 {
            sink.progress(P::Write, step, 4);
        }
        assert!((p.get().progress - 1.0).abs() < 1e-12, "{:?}", p.get());
    }

    /// A create's bar on a ONE-BATCH create: the two OVERLAPPING
    /// phases share one span and the writes are the last tenth,
    /// monotone throughout.
    ///
    /// This is the mapping `CreateProgress`'s doc argues for, pinned -
    /// because the failure it avoids (a bar that stalls at 45% on one
    /// engine arm and jumps backwards on another) is invisible in any
    /// test that only runs one arm.
    ///
    /// The figures here are the ones this bar drew before the batch
    /// frame landed, to the bit, which is half of the safety argument
    /// for that change - see
    /// `a_one_batch_create_draws_exactly_the_bar_it_always_did` for the
    /// other half. What did change is WHEN the writes may draw: they
    /// now wait for the fold, so the fold is run to full below before
    /// the write is asked for.
    #[test]
    fn a_creates_hash_and_fold_share_one_span_and_the_writes_are_the_last_tenth() {
        use par2repair::ProgressSink;
        let p = Publisher::new(JobSnapshot::queued(
            1,
            JobKind::Create,
            "2026-09-12T00:00:00Z".into(),
            false,
        ));
        let sink = CreateProgress::new(Arc::clone(&p));
        sink.progress(par2repair::RepairPhase::Verify, 1, 2);
        assert!((p.get().progress - 0.45).abs() < 1e-9, "{:?}", p.get());
        assert_eq!(p.get().phase, Phase::Hashing);
        // The fold, further along than the hashing, moves the bar; the
        // hashing reporting again behind it does NOT move it back.
        sink.progress(par2repair::RepairPhase::Fold, 3, 4);
        assert!((p.get().progress - 0.675).abs() < 1e-9, "{:?}", p.get());
        sink.progress(par2repair::RepairPhase::Verify, 1, 4);
        assert!(
            (p.get().progress - 0.675).abs() < 1e-9,
            "a create bar went backwards"
        );
        // A create has nothing to solve and the engine never sends it;
        // if one ever arrived it must not move a create's bar to 85%.
        let before = p.get().progress;
        sink.progress(par2repair::RepairPhase::Solve, 1, 2);
        assert!((p.get().progress - before).abs() < f64::EPSILON);
        // The fold finishes, which is what hands the bar to the writes.
        sink.progress(par2repair::RepairPhase::Fold, 4, 4);
        assert!((p.get().progress - 0.90).abs() < 1e-9, "{:?}", p.get());
        // The writes are the last tenth, and they land on full.
        sink.progress(par2repair::RepairPhase::Write, 1, 2);
        assert!((p.get().progress - 0.95).abs() < 1e-9, "{:?}", p.get());
        assert_eq!(p.get().phase, Phase::Writing);
        sink.progress(par2repair::RepairPhase::Write, 2, 2);
        assert!((p.get().progress - 1.0).abs() < 1e-9, "{:?}", p.get());
    }

    /// THE SAFETY ARGUMENT FOR THE BATCH FRAME, as a test rather than a
    /// claim: on a create that folds in one batch - every create that
    /// fits the accumulator budget, so nearly all of them - the framed
    /// rules are arithmetic identities over the unframed ones.
    ///
    /// Both ways a create can be one batch are run: the engine
    /// announcing `(0, 1)` (the batched driver with one group) and the
    /// engine announcing NOTHING (the stripe-first transform, which
    /// never calls `batch`). They must give the same bar, because the
    /// frame's default is what makes the silent arm safe.
    ///
    /// Compared against the expression this sink used before the frame,
    /// evaluated here, so the two cannot drift apart silently.
    #[test]
    fn a_one_batch_create_draws_exactly_the_bar_it_always_did() {
        use par2repair::ProgressSink;
        use par2repair::RepairPhase as P;
        for announce in [false, true] {
            let p = Publisher::new(JobSnapshot::queued(
                1,
                JobKind::Create,
                "2026-09-12T00:00:00Z".into(),
                false,
            ));
            let sink = CreateProgress::new(Arc::clone(&p));
            if announce {
                sink.slab(0, 1);
            }
            let mut want: f64 = 0.0;
            for (phase, done) in [
                (P::Verify, 1u64),
                (P::Fold, 1),
                (P::Verify, 4),
                (P::Fold, 2),
                (P::Verify, 7),
                (P::Fold, 9),
                (P::Verify, 10),
                (P::Fold, 10),
            ] {
                sink.progress(phase, done, 10);
                // The pre-frame rule, verbatim: one 0.0..0.90 span for
                // both phases, the larger of the two wins, monotone.
                want = want.max(0.0 + 0.90 * (done as f64 / 10.0));
                assert_eq!(
                    p.get().progress,
                    want,
                    "{phase:?} {done}/10 (announce={announce}) moved a one-batch bar off the \
                     figure it drew before the batch frame"
                );
            }
        }
    }

    /// THE DEFECT, pinned: an 18-batch create must not spend
    /// seventeen of its eighteen passes at the top of the bar.
    ///
    /// The sequence is the engine's own, in the engine's order
    /// (`par2gen`'s batch loop): the frame is announced before each
    /// batch's fold, the scan runs ONCE beside batch 1 and reaches
    /// 100% there, each batch's fold runs 0 to 100% of its own
    /// re-sized phase, and the volume writes step after every batch
    /// against a total sized over the whole set.
    ///
    /// Three assertions, one per peg the unframed bar had: the hash
    /// cannot take the bar past the end of batch 1, the writes cannot
    /// take it into the last tenth while folding is still to come, and
    /// every batch after the first moves it. Against the unframed
    /// rule all three fail; the two tests above pass against it, which
    /// is why they are not enough on their own.
    #[test]
    fn every_batch_of_a_multi_batch_create_moves_the_bar() {
        use par2repair::ProgressSink;
        use par2repair::RepairPhase as P;
        const OF: usize = 18;
        // The whole set's recovery payload, which is what `Write` is
        // sized over: one volume's worth per batch here.
        const SET: u64 = OF as u64;
        let p = Publisher::new(JobSnapshot::queued(
            1,
            JobKind::Create,
            "2026-09-12T00:00:00Z".into(),
            false,
        ));
        let sink = CreateProgress::new(Arc::clone(&p));
        let mut last = 0.0f64;
        for b in 0..OF {
            sink.slab(b, OF);
            let opened = p.get().progress;
            for step in 1..=4u64 {
                sink.progress(P::Fold, step, 4);
                if b == 0 {
                    // The scan reads the payload once, beside batch 1.
                    sink.progress(P::Verify, step, 4);
                }
            }
            let folded = p.get().progress;
            assert!(
                folded > opened,
                "batch {b} of {OF} did not move the bar: {opened} -> {folded}"
            );
            assert!(
                folded > last,
                "batch {b} of {OF} did not move the bar past batch {}: {last} -> {folded}",
                b.saturating_sub(1)
            );
            if b == 0 {
                // THE FIRST PEG: the hash finished here and may not
                // speak for the seventeen batches it never ran beside.
                assert!(
                    folded <= 0.90 / OF as f64 + 1e-9,
                    "a finished hash took the bar to {folded} during batch 1 of {OF}"
                );
            }
            // The batch's volumes are flushed. `Write` is sized over
            // the whole set, so this is the create's own write
            // fraction and not the batch's.
            sink.progress(P::Write, b as u64 + 1, SET);
            let written = p.get().progress;
            if b + 1 < OF {
                // THE SECOND PEG, and the dominant one: a write frame
                // may not put the bar into the last tenth while there
                // are batches left to fold.
                assert!(
                    written < 0.90,
                    "batch {b} of {OF}'s volume write took the bar to {written}, into the band \
                     reserved for the writes that outlive the fold"
                );
            }
            last = p.get().progress;
        }
        // The last batch has folded, so the writes own the bar now and
        // the create lands on full.
        sink.progress(P::Write, SET, SET);
        assert!(
            (p.get().progress - 1.0).abs() < 1e-9,
            "a finished create left the bar at {}",
            p.get().progress
        );
    }

    /// A held write frame publishes NOTHING - not the bar, not the
    /// phase word, and no wake to the host.
    ///
    /// The phase word is the half a bar-only test cannot see: `Write`
    /// overlaps `Fold` on the stripe-first arm for the whole of the
    /// create, so a sink that suppressed only the FIGURE would leave
    /// the pane saying "Writing the recovery volumes" while the fold
    /// ran, which is the flicker this rule exists to stop.
    #[test]
    fn a_write_that_arrives_during_the_fold_says_nothing_at_all() {
        use par2repair::ProgressSink;
        use par2repair::RepairPhase as P;
        let p = Publisher::new(JobSnapshot::queued(
            1,
            JobKind::Create,
            "2026-09-12T00:00:00Z".into(),
            false,
        ));
        let woke = Arc::new(AtomicU32::new(0));
        let w2 = Arc::clone(&woke);
        p.set_wake(Some(Box::new(move || {
            w2.fetch_add(1, Ordering::Relaxed);
        })));
        let sink = CreateProgress::new(Arc::clone(&p));
        sink.progress(P::Fold, 1, 4);
        let after_fold = p.get();
        let wakes = woke.load(Ordering::Relaxed);
        sink.progress(P::Write, 3, 4);
        let after_write = p.get();
        assert_eq!(
            after_write.progress, after_fold.progress,
            "a write drew during the fold"
        );
        assert_eq!(
            after_write.phase_text, after_fold.phase_text,
            "a held write took the phase text"
        );
        assert_eq!(after_write.phase, Phase::Solving);
        assert_eq!(
            woke.load(Ordering::Relaxed),
            wakes,
            "a held write rang the host's wake"
        );
        // And once the fold is done with the bar, the same frame draws.
        sink.progress(P::Fold, 4, 4);
        sink.progress(P::Write, 3, 4);
        assert!((p.get().progress - 0.975).abs() < 1e-9, "{:?}", p.get());
        assert_eq!(p.get().phase, Phase::Writing);
    }

    /// A hash that reaches the end of the shared span opens the write
    /// band too, and on a ONE-BATCH create that is the case that
    /// matters: the two phases run at once and either can be the one
    /// that finishes it.
    ///
    /// Not an oversight in the write's hold, and the alternative is
    /// worse. The span holds whichever of the two is further along, so
    /// a finished hash has left nothing for the fold to move it with -
    /// waiting for the fold as well would leave the bar sitting at 0.90
    /// with the writes still held, which is the freeze the hold exists
    /// to avoid. On a MULTI-batch create the hash cannot reach the end
    /// of the span at all, which
    /// `every_batch_of_a_multi_batch_create_moves_the_bar` pins.
    #[test]
    fn a_finished_hash_hands_a_one_batch_create_to_its_writes() {
        use par2repair::ProgressSink;
        use par2repair::RepairPhase as P;
        let p = Publisher::new(JobSnapshot::queued(
            1,
            JobKind::Create,
            "2026-09-12T00:00:00Z".into(),
            false,
        ));
        let sink = CreateProgress::new(Arc::clone(&p));
        sink.progress(P::Fold, 1, 4);
        sink.progress(P::Write, 1, 4);
        assert!(
            (p.get().progress - 0.225).abs() < 1e-9,
            "a write drew while the span still had room: {:?}",
            p.get()
        );
        // The hash finishes first, which is all the span has left.
        sink.progress(P::Verify, 4, 4);
        assert!((p.get().progress - 0.90).abs() < 1e-9, "{:?}", p.get());
        sink.progress(P::Write, 1, 4);
        assert!((p.get().progress - 0.925).abs() < 1e-9, "{:?}", p.get());
        assert_eq!(p.get().phase, Phase::Writing);
    }

    /// The publisher must not hold its lock across the wake: a host
    /// marshals the wake to its UI thread and polls, and a wake handler
    /// that polls synchronously would deadlock on a held lock.
    #[test]
    fn the_wake_fires_with_no_lock_held() {
        let p = Publisher::new(JobSnapshot::queued(
            1,
            JobKind::Verify,
            "2026-09-12T00:00:00Z".into(),
            false,
        ));
        let seen = Arc::new(Mutex::new(0usize));
        let p2 = Arc::clone(&p);
        let s2 = Arc::clone(&seen);
        p.set_wake(Some(Box::new(move || {
            // Exactly what a host does: poll from the wake.
            let _ = p2.get();
            *s2.lock().expect("counter") += 1;
        })));
        p.update(|s| s.progress = 0.5);
        assert_eq!(*seen.lock().expect("counter"), 1);
        assert!((p.get().progress - 0.5).abs() < f64::EPSILON);
    }
}
