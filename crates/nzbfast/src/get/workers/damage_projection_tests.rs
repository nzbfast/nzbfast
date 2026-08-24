//! §282 item 3: the running damage projection's calibration.
//!
//! A child of `workers`, out here for the size gate alongside
//! `par_race_tests` and `spec_ladder_tests`, and for the same reasons:
//! named for its file so size-gate.py keeps scoring it as test code,
//! and `use super::*` reaches exactly what the inline module reached
//! because `super` is still `workers`.
//!
//! Every case below is arithmetic on [`project_damage`]. What it is
//! FOR - firing early on a genuinely shredded post - is pinned by the
//! doomed cases; what it must NEVER do is pinned by the two incident
//! jobs, which are the whole reason §282 warns that this projection
//! must not become the primary trigger.

use super::*;

/// The §282 incident, both jobs, converted to this function's terms.
///
/// S02E08: 22,920 segments, 48 terminally missing, ~868 kB articles
/// against a 5,505,024-byte block, so each miss is
/// `ceil(868k/5.5M) + 1` = 2 blocks. S02E04: 17,130 segments, 135
/// missing, same geometry. The NZB declares 255 recovery blocks in
/// both. Sampled halfway through the run, which is where the
/// projection is at its most confident and still must not fire.
///
/// This is the test of the calibration and not a smoke case. Both jobs
/// FAILED, so a projection that fired on them would look prescient in
/// a log and be wrong about the reason: the payload was 99.2% and
/// 99.8% intact and would have repaired comfortably. What was fiction
/// was the recovery set, which is item 4's yield gate, not this.
#[test]
fn the_incident_jobs_must_not_project_doomed() {
    // Halfway: half the segments resolved, half the misses seen.
    for (label, segments, misses) in [("s02e08", 22_920usize, 48usize), ("s02e04", 17_130, 135)] {
        let resolved = segments / 2;
        let now = (misses / 2) * 2; // 2 blocks per lost article
        let p = project_damage(resolved, segments, now, 0, 255);
        assert!(
            p.is_none(),
            "{label}: the payload projection fired on a job whose payload was fine: {p:?}"
        );
    }
}

/// A genuinely shredded post: 30% of the articles gone, against the
/// same 10%-of-payload recovery the incident carried. This is the case
/// the item exists for, and it must be answerable from a small sample.
#[test]
fn a_shredded_post_projects_doomed_early() {
    let segments = 20_000usize;
    // 5% of the plan resolved, 30% of that lost, 2 blocks a miss.
    let resolved = segments / 20;
    let now = (resolved * 30 / 100) * 2;
    let p = project_damage(resolved, segments, now, 0, 255)
        .expect("30% loss against 255 recovery blocks is not survivable");
    assert_eq!(p.resolved, resolved);
    assert_eq!(p.planned, segments);
    assert!(
        p.projected >= 255 * 2,
        "the verdict must clear the margin it claims: {p:?}"
    );
}

/// The floors. A rate needs a sample: two misses in the first hundred
/// articles of a large post is not one, and neither is a 1% slice of
/// the plan however bad it looks.
#[test]
fn a_thin_sample_never_projects() {
    // Under PROJECT_MIN_FRACTION: 1% of the plan, everything lost.
    assert!(project_damage(200, 20_000, 400, 0, 10).is_none());
    // Over the fraction, under PROJECT_MIN_MISSES: 4 damaged blocks.
    assert!(project_damage(2_000, 20_000, 4, 0, 1).is_none());
    // Nothing resolved, nothing planned, no damage: no opinion.
    assert!(project_damage(0, 20_000, 400, 0, 1).is_none());
    assert!(project_damage(200, 0, 400, 0, 1).is_none());
    assert!(project_damage(20_000, 20_000, 0, 0, 1).is_none());
}

/// The margin is a MARGIN: a projection that merely exceeds the
/// declared recovery says nothing, because `now` is a worst-case
/// ceiling and the rate is a sample. S02E04 is exactly that shape at
/// full run - 270 projected blocks against 255 declared - and it must
/// stay quiet.
#[test]
fn merely_exceeding_the_declared_recovery_is_not_a_verdict() {
    assert!(project_damage(17_130, 17_130, 270, 0, 255).is_none());
    // Double it and the verdict lands.
    assert!(project_damage(17_130, 17_130, 540, 0, 255).is_some());
}

/// Blocks in-stream verification has already found bad are damage too,
/// and they are counted at face value rather than extrapolated: they
/// are a census of what arrived, not a sample of what will.
#[test]
fn live_bad_blocks_count_toward_the_projection() {
    // 8 blocks of miss damage over a full run, so nothing to scale.
    assert!(project_damage(1_000, 1_000, 8, 0, 100).is_none());
    assert!(project_damage(1_000, 1_000, 8, 192, 100).is_some());
}
