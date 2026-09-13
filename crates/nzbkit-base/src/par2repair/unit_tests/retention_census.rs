//! The eight validation cases the retention admission census owes
//! (`research/PAR2-RETENTION-CALLER-CENSUS-2026-09-08.md`, "Required
//! validation cases"). Each one exists because a tempting counter gets
//! it wrong; the test names say which.
//!
//! A child module of `unit_tests` for the same two reasons its
//! neighbours are: the parent stays inside its size-gate entry, and
//! `use super::*` keeps the real PAR2 fixtures reachable. Every test
//! holds `census::testing::record()`, which is a process-wide lock -
//! the census sink AND the retention budget are both process-global,
//! so these cannot run beside each other or beside a forced policy.

use super::*;
use crate::par2repair::census::testing;

/// A clean single-member set on disk, with two recovery exponents.
/// Returns the directory, the set id and the index bytes.
fn clean_set(tag: &str) -> (PathBuf, [u8; 16], Vec<u8>) {
    let dir = tmpdir(tag);
    let data = payload(600, 7);
    let files: &[(&str, &[u8])] = &[("clean.bin", &data)];
    let index = par2_index(SET, BS, files);
    std::fs::write(dir.join("clean.bin"), &data).unwrap();
    std::fs::write(dir.join("s.par2"), &index).unwrap();
    std::fs::write(
        dir.join("s.vol0+2.par2"),
        par2_volume(SET, BS, files, &[0, 1]),
    )
    .unwrap();
    (dir, SET, index)
}

/// One member with `holes` blocks flipped, and `exps` recovery
/// exponents on disk - fewer exponents than holes is a shortfall.
fn damaged_set(tag: &str, holes: usize, exps: &[u32]) -> (PathBuf, [u8; 16]) {
    let dir = tmpdir(tag);
    let data = payload(600, 11);
    let files: &[(&str, &[u8])] = &[("dmg.bin", &data)];
    let mut bad = data.clone();
    for h in 0..holes {
        bad[h * BS + 3] ^= 0x5a;
    }
    std::fs::write(dir.join("dmg.bin"), &bad).unwrap();
    std::fs::write(dir.join("s.par2"), par2_index(SET, BS, files)).unwrap();
    std::fs::write(dir.join("s.vol.par2"), par2_volume(SET, BS, files, exps)).unwrap();
    (dir, SET)
}

fn one(events: &[serde_json::Value]) -> &serde_json::Value {
    assert_eq!(events.len(), 1, "exactly one record: {events:?}");
    &events[0]
}

/// CASE 1. The route ordinary download settlement actually takes over a
/// clean outer set - `par2::verify_file_path_tiered`, the verifier with
/// no retention sink - takes NO admission, while the retaining entry
/// over the very same directory takes one.
///
/// This is the denominator's whole problem in one test: the measured
/// clean tax is real, and the population it was priced against does not
/// enter the code (`get::settle` calls `run_set_repair` only once
/// `damage > 0`).
#[test]
fn an_ordinary_settlement_verify_takes_no_retention_admission() {
    let (dir, set_id, index) = clean_set("census-outer");
    let rec = testing::record();

    let set = par2::Par2Set::parse(&[&index[..]]).expect("the fixture parses");
    for f in &set.files {
        let v = par2::verify_file_path_tiered(&dir.join(&f.name), f, set.block_size, 2, false)
            .expect("the fixture file reads");
        assert!(v.md5_ok, "the fixture is clean");
    }
    assert!(
        rec.of_kind("admission").is_empty(),
        "the settlement verifier has no retention sink to admit"
    );

    let status = repair_dir_set_with_donors_as(
        &dir,
        &set_id,
        &[],
        RetentionCaller::new(CallerSite::OfflineExtraction),
    )
    .expect("repair runs");
    assert!(matches!(status, RepairStatus::NoDamage));
    let adm = rec.of_kind("admission");
    assert_eq!(one(&adm)["admitted"], true, "the retaining entry admits");
}

/// CASE 2. A clean NESTED set does take an admission, and it carries
/// its depth - an outer archive can be clean while the set inside it is
/// not, so the two are different populations.
#[test]
fn a_clean_nested_set_takes_an_admission_at_its_depth() {
    let (dir, _, _) = clean_set("census-nested");
    let rec = testing::record();

    let out = repair_present_sets_as(
        &dir,
        RetentionCaller::new(CallerSite::NestedExtraction).at_depth(2),
    )
    .expect("sets walk");
    assert_eq!(out.len(), 1);
    assert!(matches!(out[0].status, Ok(RepairStatus::NoDamage)));

    let start = rec.of_kind("invocation_start");
    assert_eq!(one(&start)["caller"]["site"], "nested_extraction");
    assert_eq!(one(&start)["caller"]["depth"], 2);
    let adm = rec.of_kind("admission");
    assert_eq!(one(&adm)["admitted"], true);
    let disp = rec.of_kind("disposition");
    assert_eq!(one(&disp)["consumed"], false, "a clean set reads nothing");
    assert_eq!(one(&disp)["reason"], "no_damage");
}

/// CASE 3. A clean LATE set is counted, though its `NoDamage` return
/// prints nothing at all - failure 1 of the caller census, and the one
/// caller a log parser can never see.
#[test]
fn a_clean_late_set_is_counted_despite_its_quiet_log() {
    let (dir, set_id, _) = clean_set("census-late");
    let rec = testing::record();

    let status = repair_dir_set_with_donors_scoped_as(
        &dir,
        &set_id,
        &[],
        PacketScope::Flat,
        false,
        None,
        RetentionCaller::new(CallerSite::LateSet),
    )
    .expect("repair runs");
    assert!(matches!(status, RepairStatus::NoDamage));

    assert_eq!(
        one(&rec.of_kind("invocation_start"))["caller"]["site"],
        "late_set"
    );
    let survey = rec.of_kind("survey");
    assert_eq!(one(&survey)["blocks_remaining"], 0);
    assert_eq!(one(&survey)["observer"], "none");
    let fin = rec.of_kind("invocation_finish");
    assert_eq!(one(&fin)["outcome"], "no_damage");
    assert_eq!(one(&fin)["attempts"], 1);
}

/// CASE 4. An observer-stopped DAMAGED survey is not called clean. The
/// engine spells the stop `NoDamage` (failure 3), so the census records
/// the observer's answer beside the verdict and the disposition names
/// the stop rather than the clean return it borrowed.
#[test]
fn an_observer_stopped_damaged_survey_is_not_called_clean() {
    let (dir, set_id) = damaged_set("census-stopped", 1, &[0, 1]);
    let rec = testing::record();

    let mut observe = |_: &[MemberSurvey]| AfterSurvey::Stop;
    let status = repair_dir_set_surveyed_as(
        &dir,
        &set_id,
        &[],
        &mut observe,
        RetentionCaller::new(CallerSite::ParfastRepair),
    )
    .expect("survey runs");
    assert!(status.is_none(), "a stop is the caller's refusal");

    let survey = rec.of_kind("survey");
    assert_eq!(one(&survey)["observer"], "stop");
    assert!(
        one(&survey)["blocks_remaining"].as_u64().unwrap() > 0,
        "the set really was damaged: {survey:?}"
    );
    let disp = rec.of_kind("disposition");
    assert_eq!(one(&disp)["reason"], "observer_stop");
    assert_ne!(one(&disp)["reason"], "no_damage");
    assert_eq!(one(&disp)["consumed"], false);
}

/// CASE 5. An UNREPAIRABLE attempt pays for retention and reads none of
/// it. The existing retention log sits inside `blocks_rebuilt > 0 &&
/// shortfall.is_none()` (failure 2), so this attempt is invisible to it
/// while having bought the whole corpus.
#[test]
fn an_unrepairable_attempt_records_unused_retention() {
    let (dir, set_id) = damaged_set("census-short", 3, &[0]);
    let rec = testing::record();

    let status = repair_dir_set_with_donors_as(
        &dir,
        &set_id,
        &[],
        RetentionCaller::new(CallerSite::DownloadDiskRepair).at_stage(CallerStage::Final),
    )
    .expect("repair runs");
    assert!(
        matches!(status, RepairStatus::Unrepairable { .. }),
        "{status:?}"
    );

    let adm = rec.of_kind("admission");
    assert_eq!(one(&adm)["admitted"], true, "it was paid for");
    let disp = rec.of_kind("disposition");
    assert_eq!(one(&disp)["consumed"], false, "and never read");
    assert_eq!(one(&disp)["reason"], "shortfall");
    assert!(
        one(&disp)["retained_bytes"].as_u64().unwrap() > 0,
        "bytes were copied into it: {disp:?}"
    );
    assert_eq!(one(&disp)["consumed_bytes"], 0);
}

/// CASE 6. A fallback retry is TWO attempts of ONE invocation. An NTT
/// verify failure re-runs the whole verify pass and buys a second
/// corpus under one final verdict (failure 4); a counter keyed on the
/// call would see one.
#[test]
fn a_fallback_retry_has_two_attempt_ids() {
    let (dir, set_id, _) = clean_set("census-retry");
    let rec = testing::record();

    crate::par2repair::fastpar::force_one_retry();
    let status = repair_dir_set_with_donors_as(
        &dir,
        &set_id,
        &[],
        RetentionCaller::new(CallerSite::ParfastResurvey),
    )
    .expect("repair runs");
    assert!(matches!(status, RepairStatus::NoDamage));

    assert_eq!(rec.of_kind("invocation_start").len(), 1, "one invocation");
    let adm = rec.of_kind("admission");
    assert_eq!(adm.len(), 2, "two paid corpora: {adm:?}");
    assert_eq!(adm[0]["attempt"], 1);
    assert_eq!(adm[1]["attempt"], 2);
    assert_eq!(adm[0]["inv"], adm[1]["inv"], "under one invocation id");
    assert_eq!(rec.of_kind("attempt_finish").len(), 2);
    let fin = rec.of_kind("invocation_finish");
    assert_eq!(one(&fin)["attempts"], 2);
}

/// CASE 7. Forced on, forced off, and the default above and below the
/// ceiling all report the admission ACTUALLY taken, with the arm that
/// took it. Set size alone does not decide (failure 5): the budget and
/// the explicit override decide too, and the override beats the
/// ceiling in both directions.
///
/// The four decisions are driven through `retain::admit` directly. A
/// 4 GiB corpus is 32,768 blocks of 128 KiB, which decides in a few
/// microseconds and allocates nothing near that size - the corpus is
/// filled by the verify pass, never by the decision.
#[test]
fn forced_on_forced_off_and_the_default_reflect_actual_admission() {
    use crate::par2repair::retain;
    let _rec = testing::record();
    let (small, big) = ((16usize, 64usize), (32768usize, 128 << 10));

    {
        let _f = retain::force_policy(1 << 30, false);
        let a = retain::admit(small.0, small.1);
        assert!(a.corpus.is_some(), "default, under the ceiling");
        assert_eq!(a.refusal, None);
        assert!(!a.explicit_override);

        let a = retain::admit(big.0, big.1);
        assert!(a.corpus.is_none(), "default, over the ceiling");
        assert_eq!(a.refusal, Some("over_corpus_ceiling"));
        assert_eq!(a.corpus_bytes, 4 << 30);
    }
    {
        // Forced ON is exactly what makes the 4 and 10 GiB columns of
        // the 8 Sep round reachable at all: the knob overrides the
        // ceiling, so the corpus size stops deciding.
        //
        // The budget is a `usize`, so it is spelled at a size the
        // NARROWEST target can hold: `8 << 30` is 2^33 and reads as ZERO
        // at 32-bit pointer width - a shift that loses its top bits is
        // not an overflow Rust checks - and a zero budget takes the
        // `forced_off` arm below instead of this one. That took the
        // armv7 nightly red on 10 Sep 2026. What this arm needs of the
        // number is only that it clear one block; 1 GiB is also what
        // `ntt_default_budget` caps a 32-bit host to, so it is the
        // largest figure that means the same thing on both.
        let _f = retain::force_policy(1 << 30, true);
        let a = retain::admit(big.0, big.1);
        assert!(a.corpus.is_some(), "forced on, over the ceiling");
        assert_eq!(a.refusal, None);
        assert!(a.explicit_override);
    }
    {
        let _f = retain::force_policy(0, true);
        let a = retain::admit(small.0, small.1);
        assert!(a.corpus.is_none(), "forced off");
        assert_eq!(
            a.refusal,
            Some("forced_off"),
            "the A/B off arm names itself"
        );
    }
}

/// CASE 7b. The same three arms end to end, so the wiring between the
/// decision and the census cannot drift from the decision itself.
#[test]
fn a_forced_off_repair_records_the_refusal_it_took() {
    let (dir, set_id, _) = clean_set("census-forced-off");
    let rec = testing::record();
    let _f = crate::par2repair::retain::force_policy(0, true);

    let status = repair_dir_set_with_donors_as(
        &dir,
        &set_id,
        &[],
        RetentionCaller::new(CallerSite::OfflineExtraction),
    )
    .expect("repair runs");
    assert!(matches!(status, RepairStatus::NoDamage));

    let adm = rec.of_kind("admission");
    assert_eq!(one(&adm)["admitted"], false);
    assert_eq!(one(&adm)["refusal"], "forced_off");
    assert_eq!(one(&adm)["explicit_override"], true);
    let disp = rec.of_kind("disposition");
    assert_eq!(one(&disp)["admitted"], false);
    assert_eq!(one(&disp)["retained_bytes"], 0);
}

/// CASE 8. An interrupted attempt stays EXPLICITLY unfinished. Silence
/// would be read as a clean attempt, and a start with no finish is the
/// one thing a collector must be able to see.
#[test]
fn an_interrupted_attempt_remains_explicitly_unfinished() {
    let (dir, set_id) = damaged_set("census-interrupted", 1, &[0, 1]);
    let rec = testing::record();

    struct Unwind;
    impl SurveyObserver for Unwind {
        fn after_survey(&mut self, _: &[MemberSurvey]) -> AfterSurvey {
            panic!("the caller went away mid-survey");
        }
    }
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = std::panic::catch_unwind(|| {
        let mut o = Unwind;
        repair_dir_set_surveyed_as(
            &dir,
            &set_id,
            &[],
            &mut o,
            RetentionCaller::new(CallerSite::ParfastRepair),
        )
    });
    std::panic::set_hook(prev);
    assert!(r.is_err(), "the panic propagates");

    let adm = rec.of_kind("admission");
    assert_eq!(one(&adm)["admitted"], true, "the corpus was paid for");
    let fin = rec.of_kind("attempt_finish");
    assert_eq!(one(&fin)["state"], "unfinished");
    assert_eq!(one(&fin)["outcome"], "unfinished");
    assert_eq!(one(&fin)["panicking"], true);
    assert_eq!(
        one(&rec.of_kind("disposition"))["reason"],
        "attempt_unfinished"
    );
    let inv = rec.of_kind("invocation_finish");
    assert_eq!(one(&inv)["outcome"], "unfinished");
    assert!(
        rec.of_kind("survey").is_empty(),
        "nothing surveyed: the observer never answered"
    );
}

/// The collector's own boundaries: a run opens with its schema, build,
/// host class and traffic class, every record carries the run id and
/// the dropped-event count so far, and the window closes explicitly.
/// Without these the census "merely moves the missing-denominator
/// problem into JSON" - failure 6.
#[test]
fn every_record_carries_the_run_boundary_and_the_dropped_count() {
    let (dir, set_id, _) = clean_set("census-boundaries");
    let rec = testing::record();
    let _ = repair_dir_set_with_donors_as(
        &dir,
        &set_id,
        &[],
        RetentionCaller::new(CallerSite::OfflineExtraction),
    );

    let all = rec.events();
    let open = &all[0];
    assert_eq!(open["kind"], "run_open");
    assert_eq!(open["schema"], 1);
    assert_eq!(
        open["traffic"], "synthetic",
        "a fixture is never production"
    );
    assert!(open["host"]["cpus"].as_u64().unwrap() >= 1);
    assert!(open["build"].as_str().is_some());
    let run = open["run"].as_str().expect("a run id").to_string();
    for e in &all {
        assert_eq!(e["run"], run.as_str(), "one join key: {e:?}");
        assert_eq!(e["schema"], 1);
        assert_eq!(e["dropped_before"], 0, "nothing dropped: {e:?}");
        assert!(e["mono_ms"].as_u64().is_some());
    }
    // Every attempt that started also finished.
    assert_eq!(
        rec.of_kind("admission").len(),
        rec.of_kind("attempt_finish").len()
    );
}

/// The census is OFF unless it is armed, and an unlabelled library
/// caller lands in an explicit `unknown` bucket rather than borrowing
/// whichever label ran last on this thread.
#[test]
fn unlabelled_callers_are_an_explicit_unknown_bucket() {
    let (dir, _, _) = clean_set("census-unknown");
    let rec = testing::record();
    let _ = repair_dir(&dir).expect("repair runs");
    let start = rec.of_kind("invocation_start");
    assert_eq!(one(&start)["caller"]["site"], "unknown");
    assert_eq!(one(&start)["caller"]["stage"], "unspecified");
}

/// The FILE sink - what a collector actually reads - writes one valid
/// JSON object per line and closes its window with the run's total
/// dropped count. `record()` above shares everything but the write, so
/// without this the arm that ships is the arm nothing runs.
#[test]
fn the_file_sink_writes_one_json_object_per_line_and_closes_its_window() {
    let (dir, set_id, _) = clean_set("census-file");
    let out = dir.join("census.jsonl");
    {
        let _rec = testing::record_to_file(&out);
        let _ = repair_dir_set_with_donors_as(
            &dir,
            &set_id,
            &[],
            RetentionCaller::new(CallerSite::LateSet),
        );
        crate::par2repair::close_retention_census();
    }
    let text = std::fs::read_to_string(&out).expect("the census file exists");
    let lines: Vec<serde_json::Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).expect("one JSON object per line"))
        .collect();
    assert_eq!(lines.first().unwrap()["kind"], "run_open");
    assert_eq!(lines.last().unwrap()["kind"], "run_close");
    assert_eq!(lines.last().unwrap()["dropped_before"], 0);
    let kinds: Vec<&str> = lines.iter().filter_map(|l| l["kind"].as_str()).collect();
    for want in [
        "invocation_start",
        "admission",
        "survey",
        "disposition",
        "attempt_finish",
        "invocation_finish",
    ] {
        assert!(kinds.contains(&want), "missing {want} in {kinds:?}");
    }
}
