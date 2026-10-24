//! A job run under the DEFAULT Settings leaves the engine's joint Forney
//! solve where the engine put it.
//!
//! The joint solve is the engine's default on every class that can run
//! it (`par2repair::forney::joint::joint_default_on`), and the CLI stopped
//! touching the arm when `--fast` was dropped (d89e1027da, 13 Sep 2026).
//! The session did not: `runner::apply_knobs` published
//! `Settings::performance.fast_solver` - default `false` - through
//! `set_joint_arm` before every job, so every repair the desktop apps ran
//! was forced onto the slower solve the CLI no longer uses (Gemini sweep
//! H11, 14 Oct 2026).
//!
//! Its own integration target, and so its own process, for the reason
//! `knobs.rs` gives at length: the arm is process-global, and a
//! neighbouring test's job writing it would make this assertion read
//! whatever that job left. ONE TEST IN THIS FILE for the same reason.
//!
//! The comparison is against the arm as this fresh process found it, not
//! against `true`: the default is per host class (and
//! `NZBFAST_FORNEY_JOINT` can move it), so on a box whose default is off
//! this passes trivially, and on the dev Macs (aarch64, default on) it is
//! the assertion that failed before the fix.

use parfast_session::job::{
    BlockSpec, CreateSpec, JobKind, PathMode, RecoverySpec, Source, UnicodePolicy, VolumeSpec,
};
use parfast_session::runner::{Control, Job, KnobLock, Publisher, run};
use parfast_session::{JobSnapshot, JobSpec, JobState, Settings};

#[test]
fn a_default_settings_job_leaves_the_joint_solve_at_the_engine_default() {
    let engine_default = nzbkit::par2repair::joint_armed();

    let d = std::env::temp_dir().join(format!("parfast-ffi-joint-arm-{}", std::process::id()));
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
        perf: Default::default(),
    };
    let job = Job {
        spec: JobSpec::Create { create: spec },
        control: Control::new(),
        publisher: Publisher::new(JobSnapshot::queued(
            1,
            JobKind::Create,
            "2026-10-14T00:00:00Z".into(),
            false,
        )),
        knobs: KnobLock::new(),
        shared: false,
        settings: Settings::default(),
    };
    run(&job);
    let _ = std::fs::remove_dir_all(&d);
    let snap = job.publisher.get();
    assert_eq!(snap.state, JobState::Done, "create: {:?}", snap.error);
    assert_eq!(
        nzbkit::par2repair::joint_armed(),
        engine_default,
        "a job under the default Settings moved the engine's joint-solve arm"
    );
}
