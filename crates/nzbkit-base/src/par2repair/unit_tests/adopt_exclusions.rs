//! [`SurveyObserver::adoption_exclusions`] - the gate that keeps an
//! observer's OWN fresh copies out of the adoption scan - had no test
//! anywhere in the tree until 16 Sep 2026.
//!
//! WHY THAT MATTERED, and why the cost is invisible without one. The
//! only caller is `parfast`, which copies each damaged original aside
//! as `<name>.1` beside the fold (`back_up_damaged`) and declares those
//! copies here. A backup is a copy of a damaged file and can carry no
//! block the original lacks, so scanning it is pure cost - and because
//! it is PURE cost, a regression in this gate changes no verdict, no
//! report and no file on disk. It shows up only as the sliding scan
//! reading the whole member a second time.
//!
//! That is not hypothetical: a repair-timing round in Sep 2026 read a
//! bimodal `adoption` phase (one mode at twice the other, on about a
//! fifth of legs) as exactly this - a double read of the damaged
//! member. It was not one. Counting the scan as STATE rather than off
//! the clock showed one candidate visited once on every leg, fast and
//! slow alike, the slow legs being the same single pass retired more
//! slowly by one unpinned thread. The gate was sound the whole time.
//! But nothing in the tree could SAY so, which is how a phase with no
//! coverage came to be suspected for a fortnight, and nothing would say
//! so tomorrow either.
//!
//! So the two tests below are a MATCHED PAIR over one fixture, and the
//! pair is the point: the excluded arm alone would pass against a gate
//! that excluded everything, and the admitted arm alone would pass
//! against a gate that excluded nothing.
//!
//! The fixture is `donor_dir`'s obfuscated-post shape - the payload on
//! disk only under a hash name, no recovery slices anywhere - because
//! it is the one shape where the gate's effect is OBSERVABLE rather
//! than merely cheaper: with the copy admitted the set repairs entirely
//! out of it, and with the copy excluded there is nothing else to
//! repair from, so the verdict flips. A real backup is never a set's
//! only source of a block; this fixture is how the gate is made to
//! speak, not a shape the gate was written for.
//!
//! A CHILD of `unit_tests` for its neighbours' two reasons: it reaches
//! the parent's PAR2 fixture helpers through `use super::*` while the
//! parent stays inside its size-gate ceiling.

use super::*;

/// Answers `Repair` and declares whatever it was built with. The
/// exclusion list is the ONLY thing that differs between the two tests.
struct Excluding {
    exclude: Vec<PathBuf>,
    surveys: usize,
}

impl SurveyObserver for Excluding {
    fn after_survey(&mut self, _members: &[MemberSurvey]) -> AfterSurvey {
        self.surveys += 1;
        AfterSurvey::Repair
    }
    fn adoption_exclusions(&self) -> &[PathBuf] {
        &self.exclude
    }
}

/// The payload under a hash name, its declared name absent, and NO
/// recovery volume - so every block the set can rebuild has to come
/// out of the copy or not at all.
fn copy_only_set(tag: &str) -> (PathBuf, Vec<u8>, PathBuf) {
    let dir = tmpdir(tag);
    let a = payload(200, 7);
    let files: &[(&str, &[u8])] = &[("a.bin", &a)];
    let copy = dir.join("0f9a7c");
    std::fs::write(&copy, &a).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    (dir, a, copy)
}

/// THE ADMITTED ARM, and the control for the one below: with nothing
/// excluded the copy is an ordinary candidate and the set repairs
/// wholly out of it. Same assertion as `donor_dir`'s
/// `a_wholly_renamed_copy_is_adopted_and_reported_consumed`, taken
/// through the SURVEYED entry point - which is the only entry point
/// that has an observer, and so the only one the gate exists on.
#[test]
fn a_copy_the_observer_does_not_exclude_is_adopted() {
    let (dir, a, _copy) = copy_only_set("adopt-excl-admitted");
    let mut observe = Excluding {
        exclude: Vec::new(),
        surveys: 0,
    };
    let status = repair_dir_set_surveyed(&dir, &SET, &[], &mut observe)
        .expect("survey runs")
        .expect("the observer said Repair");
    assert_eq!(observe.surveys, 1, "the observer was asked exactly once");
    let report = match status {
        RepairStatus::Repaired(r) => r,
        other => panic!("the copy holds every block, so this repairs: {other:?}"),
    };
    assert_eq!(report.blocks_adopted, 4, "every slice found in the copy");
    assert_eq!(report.files_created, ["a.bin"]);
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a);
    let _ = std::fs::remove_dir_all(&dir);
}

/// THE EXCLUDED ARM. The same directory, the same copy, the same
/// entry point - and the observer naming the copy is enough to take it
/// out of the candidate set entirely. Nothing is adopted, and with no
/// recovery slice on disk the set is short by its whole four blocks.
///
/// `blocks_adopted == 0` is the assertion that pins the SCAN rather
/// than the verdict: a gate that admitted the copy and merely declined
/// to USE it would still report the blocks it found.
#[test]
fn a_copy_the_observer_excludes_is_never_offered_to_the_scan() {
    let (dir, _a, copy) = copy_only_set("adopt-excl-refused");
    let mut observe = Excluding {
        exclude: vec![copy.clone()],
        surveys: 0,
    };
    let status = repair_dir_set_surveyed(&dir, &SET, &[], &mut observe)
        .expect("survey runs")
        .expect("the observer said Repair");
    assert_eq!(observe.surveys, 1, "the observer was asked exactly once");
    match status {
        RepairStatus::Unrepairable {
            needed,
            have,
            adopted,
            ..
        } => {
            assert_eq!(adopted, 0, "the excluded copy was never scanned");
            assert_eq!(
                (needed, have),
                (4, 0),
                "no recovery volume, so the whole member is short"
            );
        }
        other => panic!("the only source was excluded, so nothing repairs: {other:?}"),
    }
    assert!(
        !dir.join("a.bin").exists(),
        "nothing was published from an excluded source"
    );
    assert!(copy.exists(), "and the excluded file itself is untouched");
    let _ = std::fs::remove_dir_all(&dir);
}
