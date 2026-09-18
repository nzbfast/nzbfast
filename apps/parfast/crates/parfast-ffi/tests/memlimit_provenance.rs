//! The GUI's Memory limit picker must be a PERSON'S figure, not merely a
//! total.
//!
//! `runner::apply_knobs` used to publish an explicit `memory_mb` with a
//! bare `MemBudget { total }` struct literal rather than
//! `MemBudget::from_user_limit`, so `mem::published_user_limit()` never
//! saw it. That provenance is what
//! `par2repair::fastpar::clamp_to_published` branches on: a figure that
//! reaches `published_user_limit` may RAISE the repair's solve window to
//! meet it, and anything else published only LOWERS. Asserting
//! `process_budget().total` alone would pass against the unfixed code -
//! the total was always right - so this reads the provenance flag
//! instead.
//!
//! # Its own file, not a second test in `knobs.rs`
//!
//! `knobs.rs`'s header explains why a test reading a process-global knob
//! back needs a process to itself: `parfast-session`'s own unit tests run
//! in one shared process on purpose, so a neighbour's job can clear or
//! overwrite the knob mid-assertion. Cargo gives every file under
//! `tests/` its own binary and its own process by default, so a second
//! file here is that clean room without touching the "one test in this
//! file" rule `knobs.rs` states for itself.

use parfast_session::job::{
    BlockSpec, CreateSpec, JobKind, PathMode, Perf, RecoverySpec, Source, UnicodePolicy, VolumeSpec,
};
use parfast_session::runner::{Control, Job, KnobLock, Publisher, run};
use parfast_session::{JobSnapshot, JobSpec, JobState, Settings};

#[test]
fn an_explicit_create_memory_limit_is_published_as_the_users_figure() {
    nzbkit::mem::clear_cpu_workers();
    nzbkit::mem::clear_process_budget();

    let d = std::env::temp_dir().join(format!(
        "parfast-ffi-memlimit-provenance-{}",
        std::process::id()
    ));
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
        perf: Perf {
            threads: None,
            memory_mb: Some(512),
            low_priority: false,
        },
    };
    let job = Job {
        spec: JobSpec::Create { create: spec },
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

    run(&job);
    let snapshot = job.publisher.get();
    let _ = std::fs::remove_dir_all(&d);

    assert_eq!(
        snapshot.state,
        JobState::Done,
        "create: {:?}",
        snapshot.error
    );

    let published = nzbkit::mem::published_user_limit();
    assert_eq!(
        published.map(|b| b.total),
        Some(512 * 1024 * 1024),
        "a GUI create's explicit Memory limit must be published as a \
         PERSON'S figure (mem::published_user_limit), not merely reach \
         process_budget().total - otherwise a repair reading it back \
         can only ever lower its solve window, never raise it to meet \
         what was typed"
    );
}
