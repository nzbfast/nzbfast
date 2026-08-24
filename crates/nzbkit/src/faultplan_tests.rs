//! Unit tests for the role-aware fault planner (TODO 283).
//!
//! These are cheap and run on the per-push path on purpose: the heavy
//! matrix in `nzbfast/tests/e2e_faults` is only as good as the selector
//! underneath it, and a selector that quietly resolves to the empty set
//! turns every shape above it green.

use super::*;

fn file(name: &str, arts: usize, bytes: u64) -> PostFile {
    PostFile {
        name: name.to_string(),
        ids: (1..=arts).map(|i| format!("{name}-{i}@mock")).collect(),
        bytes,
    }
}

/// A conventional par2cmdline post: payload, index, five volumes whose
/// declared first blocks are 0, 1, 2, 4, 8.
fn conventional() -> FaultPlan {
    FaultPlan::new(vec![
        file("movie.mkv", 10, 1_000_000),
        file("testset.par2", 1, 40_000),
        file("testset.vol000+001.par2", 1, 60_000),
        file("testset.vol001+001.par2", 1, 60_000),
        file("testset.vol002+002.par2", 2, 110_000),
        file("testset.vol004+004.par2", 3, 210_000),
        file("testset.vol008+008.par2", 5, 410_000),
    ])
}

#[test]
fn roles_come_from_the_products_own_classifier() {
    assert_eq!(role_of("movie.mkv"), FileKind::Data);
    assert_eq!(role_of("testset.par2"), FileKind::Par2Main);
    assert_eq!(role_of("testset.vol000+002.par2"), FileKind::Par2Volume);
    // The bare-ordinal shape `NzbFile::kind` accepts and the naming-gap
    // memory (nzbfast-par2-vol-dash-naming-gap) is about.
    assert_eq!(role_of("release.vol-01.par2"), FileKind::Par2Volume);
    // And the two traps that rule carries: a name that CONTINUES past
    // .par2 is payload, and a subject's quoted filename wins over the
    // subject text around it.
    assert_eq!(
        role_of("extras.vol-10.par2-sample.mkv"),
        FileKind::Data,
        "a name continuing past .par2 is payload, not a volume"
    );
    assert_eq!(
        role_of("\"testset.vol000+002.par2\" yEnc (1/2)"),
        FileKind::Par2Volume
    );
    assert_eq!(role_of("\"movie.mkv\" yEnc (1/9)"), FileKind::Data);
}

#[test]
fn payload_and_recovery_partition_the_post() {
    let plan = conventional();
    let payload = plan.role(Role::Payload);
    let recovery = plan.role(Role::Recovery);
    assert_eq!(payload.len(), 10);
    assert_eq!(recovery.len(), 1 + 1 + 1 + 2 + 3 + 5);
    assert_eq!(
        payload.len() + recovery.len(),
        plan.total_articles(),
        "every article holds exactly one of the two roles"
    );
    assert_eq!(plan.role(Role::Par2Main).files(), 1);
    assert_eq!(plan.role(Role::Par2Volumes).files(), 5);
}

/// Volume order is the DECLARED first-block ordinal, not the name's text
/// order - which is the difference the moment a set runs past `vol099`.
#[test]
fn volume_order_is_numeric_not_lexical() {
    let plan = FaultPlan::new(vec![
        file("s.vol100+050.par2", 1, 10),
        file("s.vol012+008.par2", 1, 10),
        file("s.vol000+004.par2", 1, 10),
    ]);
    let names: Vec<&str> = plan
        .files_in(Role::Par2Volumes)
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    assert_eq!(
        names,
        [
            "s.vol000+004.par2",
            "s.vol012+008.par2",
            "s.vol100+050.par2"
        ]
    );
    assert_eq!(
        plan.files_in(Role::Par2Volume(0))[0].name,
        "s.vol000+004.par2"
    );
    assert_eq!(
        plan.files_in(Role::Par2Volume(2))[0].name,
        "s.vol100+050.par2"
    );
    // Out of range resolves EMPTY rather than panicking, which is why
    // every damage-shaped selection has to be checked - see
    // `an_empty_selection_is_refused_loudly`.
    assert!(plan.files_in(Role::Par2Volume(9)).is_empty());
}

/// The bare-ordinal shape numbers its volume AFTER the dash, so it must
/// not order as "no ordinal".
#[test]
fn the_bare_ordinal_shape_orders_by_its_own_number() {
    let plan = FaultPlan::new(vec![
        file("r.vol-09.par2", 1, 10),
        file("r.vol-02.par2", 1, 10),
    ]);
    let names: Vec<&str> = plan
        .files_in(Role::Par2Volumes)
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    assert_eq!(names, ["r.vol-02.par2", "r.vol-09.par2"]);
}

#[test]
fn largest_and_smallest_volume_are_by_encoded_bytes() {
    let plan = conventional();
    assert_eq!(
        plan.files_in(Role::LargestVolume)[0].name,
        "testset.vol008+008.par2"
    );
    // The smallest volume is the one the bootstrap election picks, so
    // this role is how a shape denies the set its cheap activation.
    assert_eq!(
        plan.files_in(Role::SmallestVolume)[0].name,
        "testset.vol000+001.par2"
    );
}

#[test]
fn last_posted_counts_from_the_end_of_the_nzb() {
    let plan = conventional();
    let tail: Vec<&str> = plan
        .files_in(Role::LastPosted(2))
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    assert_eq!(tail, ["testset.vol004+004.par2", "testset.vol008+008.par2"]);
    // Asking for more than the post has is the whole post, not a panic.
    assert_eq!(plan.files_in(Role::LastPosted(99)).len(), 7);
}

#[test]
fn ids_reach_chaos_in_the_wire_form_the_mock_keys_on() {
    let plan = conventional();
    let mut chaos = Chaos::default();
    plan.role(Role::Par2Main).missing(&mut chaos);
    assert_eq!(chaos.missing.len(), 1);
    assert!(
        chaos.missing.contains("<testset.par2-1@mock>"),
        "ids must be bracketed: {:?}",
        chaos.missing
    );
    // Already-bracketed input is left alone rather than double-wrapped.
    let bracketed = FaultPlan::new(vec![PostFile {
        name: "x.par2".into(),
        ids: vec!["<abc@mock>".into()],
        bytes: 1,
    }]);
    let mut c2 = Chaos::default();
    bracketed.role(Role::Par2Main).missing(&mut c2);
    assert!(c2.missing.contains("<abc@mock>"));
}

/// A rate too fine for the fixture damages ONE article rather than none:
/// the live incident's 0.21% over 22,920 segments is 48 articles, and
/// the same figure over a 40-article fixture rounds to zero.
#[test]
fn a_fraction_too_fine_for_the_fixture_still_damages_something() {
    let plan = conventional();
    let sel = plan.role(Role::Payload).fraction(0.0021);
    assert_eq!(sel.len(), 1, "a live-scale rate must not select nothing");
    assert_eq!(plan.role(Role::Payload).fraction(1.0).len(), 10);
    assert_eq!(plan.role(Role::Payload).fraction(0.5).len(), 5);
    // Zero is the one way to ask for nothing, and it is explicit.
    assert_eq!(plan.role(Role::Payload).fraction(0.0).len(), 0);
}

#[test]
fn narrowing_is_deterministic_and_spread() {
    let plan = conventional();
    let a: Vec<String> = plan.role(Role::Payload).evenly(3).ids().to_vec();
    let b: Vec<String> = plan.role(Role::Payload).evenly(3).ids().to_vec();
    assert_eq!(a, b, "the same shape must reproduce exactly");
    assert_eq!(
        a,
        [
            "<movie.mkv-1@mock>",
            "<movie.mkv-4@mock>",
            "<movie.mkv-7@mock>"
        ],
        "spread across the file, not clustered at its head"
    );
    // Asking for more than there is yields everything, not a panic.
    assert_eq!(plan.role(Role::Payload).evenly(999).len(), 10);
}

#[test]
fn without_heads_spares_the_first_article_of_each_file() {
    let plan = conventional();
    let sel = plan
        .role(Role::Par2Volumes)
        .without_heads(&plan, Role::Par2Volumes);
    assert_eq!(sel.len(), 12 - 5, "one head spared per volume");
    assert!(
        !sel.ids()
            .contains(&"<testset.vol008+008.par2-1@mock>".to_string())
    );
    assert!(
        sel.ids()
            .contains(&"<testset.vol008+008.par2-2@mock>".to_string())
    );
}

#[test]
#[should_panic(expected = "selected NO articles")]
fn an_empty_selection_is_refused_loudly() {
    // A post with no recovery set at all: every PAR2 role resolves
    // empty, and applying it to a Chaos would be a silent no-op - the
    // exact trap the substring censuses this module replaces carried.
    let plan = FaultPlan::new(vec![file("movie.mkv", 4, 100)]);
    plan.role(Role::Recovery).expect_nonempty(&plan);
}

#[test]
fn from_segments_reads_the_fixture_rows_the_e2e_suite_already_carries() {
    let rows = vec![
        (
            "movie.mkv".to_string(),
            vec![("a-1@mock".to_string(), 700u64, 1u32); 3],
        ),
        (
            "testset.vol000+002.par2".to_string(),
            vec![("p-1@mock".to_string(), 500, 1)],
        ),
    ];
    let plan = FaultPlan::from_segments(&rows);
    assert_eq!(plan.files()[0].bytes, 2100, "encoded bytes, summed");
    assert_eq!(plan.role(Role::Payload).files(), 1);
    assert_eq!(plan.role(Role::Par2Volumes).len(), 1);
    assert!(plan.describe_post().contains("Par2Volume"));
}

/// The split-brain applier is symmetric and leaves an odd tail alone -
/// an id pointed at itself would serve correctly and quietly halve the
/// damage a shape thinks it asked for.
#[test]
fn swap_pairwise_is_symmetric_and_spares_an_odd_tail() {
    let plan = FaultPlan::new(vec![file("m.mkv", 5, 100)]);
    let mut chaos = Chaos::default();
    plan.role(Role::Payload).swap_pairwise(&mut chaos);
    assert_eq!(chaos.swap.len(), 4, "two pairs, four entries");
    assert_eq!(chaos.swap["<m.mkv-1@mock>"], "<m.mkv-2@mock>");
    assert_eq!(chaos.swap["<m.mkv-2@mock>"], "<m.mkv-1@mock>");
    assert!(
        !chaos.swap.contains_key("<m.mkv-5@mock>"),
        "the odd tail must be left alone, never pointed at itself"
    );
}

/// The cross-file applier pairs by position and stops at the shorter
/// selection - the shape a mismatched backend actually produces, and
/// the one a within-file swap cannot express because a yEnc body is
/// self-locating.
#[test]
fn swap_with_pairs_across_two_files_by_position() {
    let plan = FaultPlan::new(vec![file("a.bin", 3, 100), file("b.bin", 2, 100)]);
    let mut chaos = Chaos::default();
    let a = plan.role(Role::Named("a.bin".into()));
    let b = plan.role(Role::Named("b.bin".into()));
    a.swap_with(&b, &mut chaos);
    assert_eq!(
        chaos.swap.len(),
        4,
        "two pairs; a.bin's third has no partner"
    );
    assert_eq!(chaos.swap["<a.bin-2@mock>"], "<b.bin-2@mock>");
    assert_eq!(chaos.swap["<b.bin-1@mock>"], "<a.bin-1@mock>");
    assert!(!chaos.swap.contains_key("<a.bin-3@mock>"));
}
