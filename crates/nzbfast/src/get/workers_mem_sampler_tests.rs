//! Bug sweep 22 Aug 2026, F-19: the memory-floor sampler's stop token.

use super::*;

/// Bug sweep 22 Aug 2026, F-19: the old job's stop must not retire
/// the new job's sampler.
#[test]
fn stopping_an_old_sampler_leaves_the_new_one_running() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let _g = rt.enter();
    let first = spawn_mem_sampler("nzo_first", std::path::Path::new("first.nzb"));
    let second = spawn_mem_sampler("nzo_second", std::path::Path::new("second.nzb"));
    assert_eq!(MEM_SAMPLER_RUN.load(Ordering::Relaxed), second.run);
    stop_mem_sampler(first.run);
    assert_eq!(
        MEM_SAMPLER_RUN.load(Ordering::Relaxed),
        second.run,
        "the first job's stop is a no-op once the second has spawned"
    );
    stop_mem_sampler(second.run);
    assert_eq!(MEM_SAMPLER_RUN.load(Ordering::Relaxed), second.run + 1);
    first.handle.abort();
    second.handle.abort();
}

/// Bug sweep 22 Aug 2026, F-19 (the other half): each sampler writes
/// its OWN peak record, so a later job's spawn leaves an overlapping
/// earlier job's attribution in place, while the process-wide reader
/// names the newest job.
#[test]
fn each_sampler_owns_its_peak_record() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let _g = rt.enter();
    let first = spawn_mem_sampler("nzo_first", std::path::Path::new("first.nzb"));
    first.record.note_rss_sample();
    assert!(first.record.peak_attribution().is_some());
    let second = spawn_mem_sampler("nzo_second", std::path::Path::new("second.nzb"));
    assert!(!Arc::ptr_eq(&first.record, &second.record));
    assert!(
        first.record.peak_attribution().is_some(),
        "the second job's spawn must not wipe the first job's record"
    );
    assert!(second.record.peak_attribution().is_none());
    stop_mem_sampler(first.run);
    stop_mem_sampler(second.run);
    first.handle.abort();
    second.handle.abort();
}

/// The per-job API view (`mem_floor.jobs`): both overlapping samplers
/// are registered under their labels while both are alive, and a
/// sampler guard's drop retires its row.
#[test]
fn live_samplers_are_registered_under_their_labels() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let _g = rt.enter();
    let first = spawn_mem_sampler("nzo_reg_a", std::path::Path::new("a.nzb"));
    let second = spawn_mem_sampler("", std::path::Path::new("/tmp/Some.Release.nzb"));
    let labels: Vec<String> = nzbkit::memgauge::live_peak_attributions()
        .into_iter()
        .map(|j| j.label)
        .collect();
    assert!(
        labels.contains(&"nzo_reg_a".to_string()),
        "the daemon job is named by its nzo_id: {labels:?}"
    );
    assert!(
        labels.contains(&"Some.Release".to_string()),
        "a CLI run falls back to the NZB stem: {labels:?}"
    );
    stop_mem_sampler(first.run);
    stop_mem_sampler(second.run);
    first.handle.abort();
    second.handle.abort();
    let run_a = first.run;
    drop(first);
    let labels: Vec<String> = nzbkit::memgauge::live_peak_attributions()
        .into_iter()
        .map(|j| j.label)
        .collect();
    assert!(
        !labels.contains(&"nzo_reg_a".to_string()),
        "sampler {run_a}'s row goes with its guard: {labels:?}"
    );
    drop(second);
}
