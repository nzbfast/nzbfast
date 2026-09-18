//! "Auto" means the ENGINE'S default, and this asks the engine rather
//! than the spec.
//!
//! The policy is stated where the code is, in `parfast-session`'s
//! `runner::apply_knobs`. What is asserted here is the FACT: a job
//! carrying an explicit thread and memory limit reaches the engine, and
//! the Auto job submitted after it in the SAME PROCESS runs at the
//! engine's own width, not at the number the job before it published.
//! Until 17 Sep 2026 it ran at the number before it - lead 2 of
//! `research/CODEX-SWEEP-2026-09-17-VERDICTS.md`.
//!
//! # Why it lives in this crate and not beside the code
//!
//! `parfast-session` is unit-tested in ONE process on purpose (its
//! `lib.rs` says why: the engine knobs it sets are process-global and a
//! per-test process would hide every interaction between them). That is
//! the right default and it is exactly wrong for THIS test, which reads
//! one of those globals back: every job any neighbouring test runs
//! writes the same knob, and since the fix an Auto job CLEARS it, so a
//! neighbour clears the width this test is asserting on. Measured, not
//! feared - the first draft lived in `runner.rs` and failed under the
//! default parallel `cargo test --lib` with `saw [1, 1, ..., 32, 32,
//! ...]`, a neighbour's Auto create wiping the limit mid-assertion.
//!
//! An integration target is a process of its own, which is the clean
//! room a global needs. This crate is also its proper subject: the
//! defect is a LONG-LIVED HOST one, and `pf_session_new` is the door
//! that host comes through. It rides the `cargo test -p parfast-ffi`
//! line that CLAUDE.md and `parfast-gui.yml`'s `one-process` job
//! already carry, so it needs no new plumbing of its own.
//!
//! ONE TEST IN THIS FILE, and a second one must either take the same
//! care or belong somewhere else: two tests here would share this
//! process and be back where the first draft was.

use parfast_session::job::{
    BlockSpec, CreateSpec, JobKind, PathMode, Perf, Phase, RecoverySpec, Source, UnicodePolicy,
    VolumeSpec,
};
use parfast_session::runner::{Control, Job, KnobLock, Publisher, run};
use parfast_session::{JobSnapshot, JobSpec, JobState, Settings};
use std::sync::{Arc, Mutex};

/// One small create, run through the real [`run`] entry point, sampling
/// `nzbkit::mem::cpu_workers()` from the publisher's wake.
///
/// Answers the samples taken AFTER `apply_knobs`: every update past
/// `Phase::Scanning`, which is the only phase `run` publishes before
/// `run_create` reaches the knobs. Reading the snapshot from inside the
/// wake is what a polling host does and what `Publisher::update` is
/// written to allow - the snapshot lock is released before the ring.
fn create_sampling_workers(tag: &str, perf: Perf) -> (JobSnapshot, Vec<usize>) {
    let d = std::env::temp_dir().join(format!("parfast-ffi-knobs-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("temp dir");
    std::fs::write(d.join("a.bin"), vec![7u8; 200_000]).expect("member");
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
        overwrite: true,
        std_naming: false,
        unicode: UnicodePolicy::Auto,
        perf,
    };
    let job = Job {
        spec: JobSpec::Create {
            create: spec.clone(),
        },
        control: Control::new(),
        publisher: Publisher::new(JobSnapshot::queued(
            1,
            JobKind::Create,
            "2026-09-17T00:00:00Z".into(),
            false,
        )),
        knobs: KnobLock::new(),
        shared: false,
        settings: Settings::default(),
    };
    let samples: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&samples);
    let publisher = Arc::clone(&job.publisher);
    job.publisher.set_wake(Some(Box::new(move || {
        if publisher.get().phase != Phase::Scanning {
            seen.lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(nzbkit::mem::cpu_workers());
        }
    })));
    run(&job);
    job.publisher.set_wake(None);
    let _ = std::fs::remove_dir_all(&d);
    let taken = samples.lock().unwrap_or_else(|p| p.into_inner()).clone();
    (job.publisher.get(), taken)
}

/// Both halves are asserted, because a test that checked only the second
/// job would pass just as well against an `apply_knobs` that had stopped
/// publishing anything at all - which is the opposite defect and a worse
/// one. The explicit job must REACH the engine; the Auto job after it
/// must not inherit what it left.
#[test]
fn an_auto_job_runs_under_the_engine_default_and_not_the_last_jobs_limit() {
    nzbkit::mem::clear_cpu_workers();
    nzbkit::mem::clear_process_budget();
    let engine_default = nzbkit::mem::cpu_workers();
    // A width this machine will not choose for itself, so "the Auto job
    // read the default" cannot come out true by coincidence.
    let limit = if engine_default == 1 { 2 } else { 1 };

    let (explicit, during_explicit) = create_sampling_workers(
        "explicit",
        Perf {
            threads: Some(limit),
            memory_mb: Some(512),
            low_priority: false,
        },
    );
    assert_eq!(
        explicit.state,
        JobState::Done,
        "explicit create: {:?}",
        explicit.error
    );
    assert!(
        !during_explicit.is_empty() && during_explicit.iter().all(|&n| n == limit),
        "an explicit {limit}-thread job must REACH the engine, saw {during_explicit:?}"
    );
    assert_eq!(
        nzbkit::mem::process_budget().total,
        512 * 1024 * 1024,
        "an explicit memory limit must reach the engine"
    );

    let (auto, during_auto) = create_sampling_workers("auto", Perf::default());
    assert_eq!(auto.state, JobState::Done, "auto create: {:?}", auto.error);
    assert!(
        !during_auto.is_empty() && during_auto.iter().all(|&n| n == engine_default),
        "an Auto job must run at the engine default {engine_default}, saw \
         {during_auto:?} - it inherited the last job's limit"
    );
    assert!(
        nzbkit::mem::published_budget().is_none(),
        "an Auto job must leave NOTHING published, so the engine picks"
    );
}
