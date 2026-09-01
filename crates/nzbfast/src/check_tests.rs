//! Unit and end-to-end tests for the pre-flight check command.
//!
//! Split out of `check.rs` verbatim when the placement floor and the
//! encoded-to-raw conversion together took that file past the 3,000-line
//! ceiling (TODO 106, the `splitjoin_tests.rs` pattern). Behaviour
//! unchanged: this is still `check`'s own child module, so `use super::*`
//! reaches its private items exactly as it did in place.

use super::*;

fn names(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// Stand-in for "this post has recovery volumes on Usenet". Any non-zero
/// figure does the same job: the only thing `verdict_of` asks about them
/// is whether there are any.
const VOLUMES: usize = 7;

/// Issue #23 in one assertion: the reporter's post, one absent
/// article in a single-segment `.nfo`, 51 spare recovery blocks.
///
/// The old verdict weighed 1 against 51 and said REPAIRABLE. It is
/// not repairable at any block count - a `.nfo` the recovery set
/// does not cover has no parity behind it - and the downloader now
/// completes the job and drops the file. Pre-flight has to predict
/// THAT, so the only wrong answer here is any verdict carrying a
/// repair promise.
#[test]
fn a_missing_nfo_is_not_a_repair_promise() {
    let v = verdict_of(0, 51, false, VOLUMES, names(&["release.nfo"]));
    assert_eq!(
        v,
        Verdict::Complete {
            dropped: names(&["release.nfo"])
        }
    );
    // And the reverse framing: nothing missing anywhere is still the
    // plain COMPLETE, with nothing to say about metadata.
    assert_eq!(
        verdict_of(0, 51, false, VOLUMES, vec![]),
        Verdict::Complete { dropped: vec![] }
    );
}

/// Furniture set aside must not spend the block budget either. A
/// payload deficit that fits is REPAIRABLE even when the same post
/// also lost a `.sfv`, and the dropped file rides along rather than
/// being folded into the count.
#[test]
fn furniture_does_not_spend_the_recovery_budget() {
    assert_eq!(
        verdict_of(4, 51, false, VOLUMES, names(&["release.sfv"])),
        Verdict::Repairable {
            est_missing: 4,
            recovery: 51,
            recovery_unknown: false,
            dropped: names(&["release.sfv"]),
        }
    );
    // 52 articles against 51 blocks was an IMPOSSIBLE here until 16 Aug,
    // and it was never a comparison: see
    // `a_counted_budget_alone_cannot_condemn_a_post`. The furniture still
    // rides along either way, which is what this test is for.
    assert_eq!(
        verdict_of(52, 51, false, VOLUMES, names(&["release.sfv"])),
        Verdict::Repairable {
            est_missing: 52,
            recovery: 51,
            recovery_unknown: false,
            dropped: names(&["release.sfv"]),
        }
    );
    // The boundary the old code drew, undisturbed: exactly enough
    // blocks still repairs.
    assert_eq!(
        verdict_of(51, 51, false, VOLUMES, vec![]),
        Verdict::Repairable {
            est_missing: 51,
            recovery: 51,
            recovery_unknown: false,
            dropped: vec![],
        }
    );
}

/// 14 Aug sweep: recovery volumes whose names carry an ordinal but
/// no slice count (`.vol-01.par2` … `.vol-09.par2`, the playWEB
/// shape) summed to a ZERO budget, so one missing payload article
/// beside nine real recovery volumes reported IMPOSSIBLE and aborted
/// a job the downloader repairs. Unknown must not be spent as zero.
#[test]
fn unknown_recovery_counts_never_reach_impossible() {
    // The old arithmetic: 5 missing against a budget counted as 0.
    assert_eq!(
        verdict_of(5, 0, true, VOLUMES, vec![]),
        Verdict::Repairable {
            est_missing: 5,
            recovery: 0,
            recovery_unknown: true,
            dropped: vec![],
        },
        "an uncountable recovery set cannot prove a job impossible"
    );
    // A PARTLY known budget is still a floor, not a ceiling: the
    // known 2 blocks do not bound what the ordinal volumes hold.
    assert_eq!(
        verdict_of(40, 2, true, VOLUMES, vec![]),
        Verdict::Repairable {
            est_missing: 40,
            recovery: 2,
            recovery_unknown: true,
            dropped: vec![],
        }
    );
    // Nothing missing stays COMPLETE either way.
    assert_eq!(
        verdict_of(0, 0, true, VOLUMES, vec![]),
        Verdict::Complete { dropped: vec![] }
    );
}

/// The 15 Aug report, in one assertion.
///
/// `SABnzbd_nzo_nzbfast1786807567-Johnny.Vegas…nzb`: one 3.23 GB data
/// file in 4,506 articles, seven recovery volumes all named
/// `.vol-NN.par2` so not one declared a slice count, and 1,965
/// payload articles missing on every server. Pre-flight estimated
/// 2,068 - within 5% of the truth - and printed PROBABLY REPAIRABLE,
/// because a budget summed from those names is zero and
/// `recovery_unknown` forbids IMPOSSIBLE on a budget it cannot size.
/// The download then spent 1.9 GB and 153 s to reach the verdict the
/// sweep already had the evidence for.
///
/// The missing fact is the set's block size, 1,614,720 bytes, which
/// the Main packet in the smallest volume states in its first 92
/// bytes. With it both halves become bounds: 1.45 GB of missing
/// payload (encoded; 1.38 GB of it raw at worst) cannot hide in
/// fewer than 854 slices - 427 even after the sample is halved -
/// and the volumes cannot hold more than 40 between them. The real
/// repair needed 1,669 blocks against 40, so the floor here is
/// barely a quarter of the true damage and still clears the ceiling
/// tenfold. That is the margin working.
#[test]
fn the_johnny_vegas_post_is_provably_dead_once_the_block_size_is_known() {
    const BLOCK: u64 = 1_614_720;
    // Encoded bytes of the six recovery volumes that carry slices.
    // The seventh (41,901 bytes) is the index in disguise - it holds
    // no slices, and its size floors to zero blocks either way.
    let volumes: [(u64, Option<usize>); 7] = [
        (41_901, None),
        (1_708_175, None),
        (3_415_979, None),
        (6_790_307, None),
        (13_497_147, None),
        (15_163_522, None),
        (26_869_479, None),
    ];
    // 1,965 of 4,506 articles of a 3,332,350,599-byte (encoded) file.
    let missing_bytes = 3_332_350_599u64 * 1_965 / 4_506;

    // What the report actually printed, and still prints from names
    // alone: seven volumes declaring no count sum to a zero budget,
    // `recovery_unknown` is set, and no deficit however large may
    // reach IMPOSSIBLE through this door. Nothing here weakens that.
    assert_eq!(
        verdict_of(2_068, 0, true, volumes.len(), vec![]),
        Verdict::Repairable {
            est_missing: 2_068,
            recovery: 0,
            recovery_unknown: true,
            dropped: vec![],
        },
        "the names-only route must still decline to claim impossibility"
    );

    let v = measured_verdict(missing_bytes, 10, BLOCK, &volumes, 0, &[], vec![])
        .expect("an 11x deficit must reach IMPOSSIBLE");
    let Verdict::Impossible {
        est_missing,
        recovery,
        measured: Some(m),
        ..
    } = v
    else {
        panic!("measured route must carry its evidence");
    };
    assert_eq!(m.block_size, BLOCK);
    // The ceiling reproduces the budget the real repair found.
    assert_eq!(recovery, 40, "at most 40 recovery blocks");
    assert_eq!(est_missing, 427, "blocks the missing bytes must damage");
    assert!(
        est_missing > recovery * 10,
        "the post this exists to catch misses by an order of magnitude"
    );
}

/// A floor may not exceed the truth, and whole-file damage is where
/// that is checkable: a file has the blocks it has.
///
/// The 15 Aug post again, with every one of its 4,506 articles gone
/// at a 100% sweep. Its payload is 3,229,432,857 raw bytes over a
/// 1,614,720-byte block size - 2,000 slices, and no arrangement of
/// missing bytes can damage a 2,001st. But the deficit arrives in
/// the NZB's yEnc-ENCODED units, 3,332,350,599 bytes, and dividing
/// THOSE by a raw block size claimed 2,063: a "floor" 63 blocks
/// above everything there is to damage.
///
/// The flat 0.5 margin hid this for as long as it lasted - half of
/// 2,063 is under 2,000 - so the census margin dd99ca06 released is
/// what made it reachable, not what caused it. The direction is the
/// serious part: this number only ever appears on the damage side of
/// an IMPOSSIBLE, which stops a download.
#[test]
fn whole_file_damage_can_never_claim_more_blocks_than_the_file_has() {
    const BLOCK: u64 = 1_614_720;
    // The one payload file of the 15 Aug post, both ways round.
    const ENCODED: u64 = 3_332_350_599;
    const RAW: u64 = 3_229_432_857;
    let blocks_in_file = RAW.div_ceil(BLOCK) as usize;
    assert_eq!(blocks_in_file, 2_000);

    // A single live volume too small to hold a block, so the ceiling
    // is zero and the verdict is the floor itself.
    let v = measured_verdict(ENCODED, 100, BLOCK, &[(41_901, None)], 0, &[], vec![])
        .expect("a whole payload gone must condemn");
    let Verdict::Impossible { est_missing, .. } = v else {
        panic!("expected IMPOSSIBLE");
    };
    assert!(
        est_missing <= blocks_in_file,
        "a census claimed {est_missing} damaged blocks of a {blocks_in_file}-block file"
    );

    // And with the placement floor beside it, since the verdict
    // takes whichever proves more: the same post described, every
    // one of its 4,506 articles gone. Neither bound may break the
    // property on its own and their max may not break it either.
    let whole = FileDamage {
        seg_bytes: vec![ENCODED / 4_506; 4_506],
        missing: (0..4_506).collect(),
        length: Some(RAW),
    };
    let v = measured_verdict(
        ENCODED,
        100,
        BLOCK,
        &[(41_901, None)],
        0,
        std::slice::from_ref(&whole),
        vec![],
    )
    .expect("a whole payload gone must condemn");
    let Verdict::Impossible { est_missing, .. } = v else {
        panic!("expected IMPOSSIBLE");
    };
    assert!(
        est_missing <= blocks_in_file,
        "weight and placement together claimed {est_missing} damaged blocks of a \
         {blocks_in_file}-block file"
    );

    // Not vacuous: the census must still claim most of the truth.
    // Losing the whole file is 2,000 blocks of damage and the floor
    // gives up only the yEnc overhead plus its headroom.
    assert!(
        est_missing > blocks_in_file * 9 / 10,
        "the conversion may cost the overhead, not the verdict: {est_missing}"
    );

    // The pre-gate reads the same converted figure, so it cannot
    // send a fetch after a condemnation the verdict would not make.
    assert!(block_size_could_condemn(ENCODED, 100, &[41_901], &[]));
}

/// The safety half, which matters more than the reach half: a
/// deficit that the budget can plausibly cover must stay REPAIRABLE
/// no matter how confidently the block size was read. IMPOSSIBLE
/// stops a download that might have worked; PROBABLY REPAIRABLE only
/// lets the real verify decide.
#[test]
fn a_deficit_the_budget_could_cover_never_reaches_impossible() {
    const BLOCK: u64 = 1_000_000;
    // A volume of 60 MB ceilings at 60 blocks.
    let volumes = [(60_000_000u64, None)];
    // 100 blocks' worth of encoded bytes - but halved by the margin
    // a 10% sample carries and shrunk again into raw bytes, so 47
    // blocks against a ceiling of 60.
    assert_eq!(
        measured_verdict(100_000_000, 10, BLOCK, &volumes, 0, &[], vec![]),
        None
    );
    // Exactly at the ceiling is still not beyond it.
    assert_eq!(
        measured_verdict(126_400_000, 10, BLOCK, &volumes, 0, &[], vec![]),
        None
    );
    // One block past it is.
    assert!(measured_verdict(128_500_000, 10, BLOCK, &volumes, 0, &[], vec![]).is_some());
    // And a block size we could not read decides nothing at all -
    // the honest fallback the whole design keeps.
    assert_eq!(
        measured_verdict(3_000_000_000, 10, 0, &volumes, 0, &[], vec![]),
        None
    );
    // Nothing missing is never this function's verdict to give.
    assert_eq!(
        measured_verdict(0, 10, BLOCK, &volumes, 0, &[], vec![]),
        None
    );
}

/// A volume the NZB promises but no server carries is not a budget.
/// Striking it off is what lets a post whose parity was taken down
/// with its payload be called dead; leaving a PARTIALLY available
/// volume in the ceiling is what keeps that from misfiring.
#[test]
fn volumes_no_server_has_hold_no_blocks_for_us() {
    const BLOCK: u64 = 1_000_000;
    // 190 blocks of provable damage: 400 MB encoded, halved by the
    // margin a 10% sample carries and converted to raw bytes.
    let missing = 400_000_000u64;
    // Two 150-block volumes: the ceiling covers the deficit.
    assert_eq!(
        measured_verdict(
            missing,
            10,
            BLOCK,
            &[(150_000_000, None), (150_000_000, None)],
            0,
            &[],
            vec![]
        ),
        None
    );
    // One of them absent everywhere - the caller passes only the
    // live one, and 190 now outruns 150.
    let v = measured_verdict(missing, 10, BLOCK, &[(150_000_000, None)], 1, &[], vec![]);
    assert!(matches!(
        v,
        Some(Verdict::Impossible {
            est_missing: 190,
            recovery: 150,
            measured: Some(Measured {
                absent_volumes: 1,
                ..
            }),
            ..
        })
    ));
}

/// Furniture rides the measured route exactly as it rides the named
/// one: set aside, named, and never folded into either number.
#[test]
fn the_measured_route_still_carries_the_dropped_furniture() {
    let v = measured_verdict(
        3_000_000_000,
        10,
        1_000_000,
        &[(1_000_000, None)],
        0,
        &[],
        names(&["release.nfo"]),
    );
    assert!(matches!(
        v,
        Some(Verdict::Impossible { ref dropped, .. }) if dropped == &names(&["release.nfo"])
    ));
}

/// The two bounds must never meet in the middle. Whatever the block
/// size, the damage floor is discounted by the sample margin while
/// the budget ceiling takes the volumes' FULL encoded size - so the
/// same byte figure fed to both sides can never fire. At the census
/// end the margin is 1.0 and the two sides are computed alike; there
/// the strict `>` is what keeps a tie from condemning.
#[test]
fn the_two_bounds_lean_in_opposite_directions() {
    for block in [4_096u64, 768_000, 1_614_720, 5_376_000] {
        for bytes in [block, block * 37, block * 1_000] {
            for pct in [10u8, 55, 100] {
                assert_eq!(
                    measured_verdict(bytes, pct, block, &[(bytes, None)], 0, &[], vec![]),
                    None,
                    "block {block}, {bytes} bytes at {pct}%: equal evidence must not condemn"
                );
            }
        }
    }
}

/// A file of `n` equal articles, `missing` of them gone, sized so
/// the encoded total carries `overhead_per_mille` of yEnc on top of
/// the exact length the FileDesc packet would state.
fn damaged(n: usize, enc: u64, overhead_per_mille: u64, missing: Vec<usize>) -> FileDamage {
    let encoded_total = enc * n as u64;
    FileDamage {
        seg_bytes: vec![enc; n],
        missing,
        length: Some(encoded_total * 1_000 / (1_000 + overhead_per_mille)),
    }
}

/// The payoff: where the missing articles SIT proves twice what
/// their weight alone can.
///
/// The 15 Aug post's own shape - 4,506 articles of 739,536 encoded
/// bytes over a 3,229,432,857-byte file, 1,614,720-byte slices - with
/// one article in ten gone, weighed at a full census so the sample
/// margin is not doing any of the work. Each article is 0.44 of a
/// slice, so weight can prove 196 slices damaged however far apart
/// they land; placing them proves 451, because 451 absent bytes each
/// more than a slice from the next cannot share one.
///
/// Weight proves 196 rather than the 206 its encoded bytes would
/// suggest because it converts them to raw first
/// ([`margined_deficit_raw_bytes`]) - it has no per-file length to
/// work from, so it pays a flat constant where placement, which
/// does have one, pays the file's real overhead. That widens the
/// gap this test is about rather than narrowing it.
#[test]
fn placing_the_damage_proves_more_than_weighing_it_does() {
    const BLOCK: u64 = 1_614_720;
    const SEGS: usize = 4_506;
    const ENC: u64 = 739_536;
    let scattered: Vec<usize> = (0..SEGS).step_by(10).collect();
    let d = FileDamage {
        seg_bytes: vec![ENC; SEGS],
        missing: scattered.clone(),
        length: Some(3_229_432_857),
    };
    let placed = placed_damage_floor(&d, BLOCK);
    assert_eq!(placed, scattered.len(), "every one of them is placeable");

    let missing_bytes = ENC * scattered.len() as u64;
    let by_bytes =
        nzbkit::par2::min_damaged_blocks(margined_deficit_raw_bytes(missing_bytes, 100), BLOCK);
    assert_eq!(by_bytes, 196, "weight alone proves this much");
    assert!(
        placed as u64 > by_bytes * 2,
        "placement proves {placed} against {by_bytes}"
    );

    // And it is the placed figure the verdict then rests on: a
    // 300-block budget covers what weight can prove and not what
    // placement can.
    let volumes = [(BLOCK * 300, None)];
    assert_eq!(
        measured_verdict(missing_bytes, 100, BLOCK, &volumes, 0, &[], vec![]),
        None,
        "weight alone could not condemn this post"
    );
    let v = measured_verdict(
        missing_bytes,
        100,
        BLOCK,
        &volumes,
        0,
        std::slice::from_ref(&d),
        vec![],
    );
    assert!(
        matches!(v, Some(Verdict::Impossible { est_missing, recovery, .. })
            if est_missing == placed && recovery == 300),
        "placement is what condemns it: {v:?}"
    );
}

/// The other end of the range, where placement has nothing to add.
///
/// The mapping can never credit a missing segment with more than
/// ONE slice - it counts a single byte of each and throws the rest
/// of the article away - so a post whose articles are comfortably
/// over a slice is one where weighing the damage already proves at
/// least as much as placing it. The deficit then comes out of the
/// byte figure unchanged, which is the point of taking whichever
/// proves more: adding the mapping cannot make any verdict weaker
/// than it was.
///
/// "Comfortably" is doing work there, and the first case below is
/// why. At EXACTLY one slice of payload per article neither floor
/// reaches ten. Weight converts encoded bytes to raw through a flat
/// constant that gives up 5% where this file's real overhead is 3%,
/// so it proves nine. Placement proves five, because crediting a
/// segment needs a PROVABLE block of distance from the last credit
/// and one article of 1.03 slices cannot supply it - it takes two.
/// Weight still dominates, which is the claim this test is making;
/// what the case pins is that it dominates by arithmetic rather
/// than by luck.
#[test]
fn a_segment_that_is_already_a_whole_block_gains_nothing_from_placement() {
    const BLOCK: u64 = 1_000_000;
    // Articles of exactly one slice of raw payload, 3% of yEnc on
    // top, every one of the ten gone.
    let d = damaged(10, 1_030_000, 30, (0..10).collect());
    assert_eq!(d.length, Some(10_000_000), "ten slices of payload");
    let placed = placed_damage_floor(&d, BLOCK);
    assert!(
        placed <= d.missing.len(),
        "one slice per segment is the ceiling on what placement can prove"
    );
    let missing_bytes: u64 = d.seg_bytes.iter().sum();
    let by_bytes =
        nzbkit::par2::min_damaged_blocks(margined_deficit_raw_bytes(missing_bytes, 100), BLOCK);
    assert_eq!(
        by_bytes, 9,
        "weight proves a slice per segment bar the conversion's headroom"
    );
    assert_eq!(
        placed, 5,
        "two articles of 1.03 slices each are what a provable block of distance costs"
    );
    assert!(
        by_bytes >= placed as u64,
        "weight must still dominate here: {by_bytes} against {placed}"
    );

    // Articles of two slices each, so weight proves twice what
    // placement can and the deficit is weight's.
    let wide = damaged(10, 2_060_000, 30, (0..10).collect());
    let wide_bytes: u64 = wide.seg_bytes.iter().sum();
    assert_eq!(placed_damage_floor(&wide, BLOCK), 10);
    let v = measured_verdict(
        wide_bytes,
        100,
        BLOCK,
        &[(BLOCK * 5, None)],
        0,
        std::slice::from_ref(&wide),
        vec![],
    );
    assert!(
        matches!(
            v,
            Some(Verdict::Impossible {
                est_missing: 19,
                ..
            })
        ),
        "19 is weight's answer - twenty slices of payload less the raw \
         conversion's headroom - not placement's 10: {v:?}"
    );
}

/// The safety half again, now that the deficit has a second way to
/// grow: a placed count the budget covers must still hand back the
/// "probably repairable" that lets the real verify decide.
#[test]
fn a_placed_deficit_the_budget_could_cover_never_reaches_impossible() {
    const BLOCK: u64 = 1_000_000;
    // 40 scattered articles of a third of a slice each: placement
    // proves 40 slices, weight proves 13.
    let d = damaged(400, 340_000, 30, (0..400).step_by(10).collect());
    assert_eq!(placed_damage_floor(&d, BLOCK), 40);
    let missing_bytes = 340_000 * 40;
    let damage = std::slice::from_ref(&d);
    assert_eq!(
        measured_verdict(
            missing_bytes,
            100,
            BLOCK,
            &[(BLOCK * 40, None)],
            0,
            damage,
            vec![]
        ),
        None,
        "exactly at the ceiling is not beyond it"
    );
    assert!(
        measured_verdict(
            missing_bytes,
            100,
            BLOCK,
            &[(BLOCK * 39, None)],
            0,
            damage,
            vec![]
        )
        .is_some(),
        "one block short of it, and only then"
    );
    // A block size we could not read still decides nothing, placed
    // damage or not.
    assert_eq!(
        measured_verdict(
            missing_bytes,
            100,
            0,
            &[(BLOCK * 39, None)],
            0,
            damage,
            vec![]
        ),
        None
    );
}

/// Everything the mapping declines to place, and why each one is a
/// refusal rather than a zero.
///
/// The whole grid rests on the FileDesc packet's exact length. A
/// probe reads whatever packets landed in one or two articles, so
/// most of these are ordinary, and every one of them must fall back
/// to the byte figure rather than quietly count nothing as nothing.
#[test]
fn nothing_the_mapping_cannot_place_is_counted() {
    const BLOCK: u64 = 1_000_000;
    let all = (0..100).collect::<Vec<_>>();
    // No FileDesc packet for this file: the probe learnt nothing
    // about it, which is NOT the same as it not being in the set.
    let undescribed = FileDamage {
        seg_bytes: vec![340_000; 100],
        missing: all.clone(),
        length: None,
    };
    assert_eq!(placed_damage_floor(&undescribed, BLOCK), 0);
    // A set member LONGER than the sum of its own encoded articles
    // is not this NZB file - yEnc never shrinks a byte - so the two
    // records describe different things and no grid may be laid.
    let mismatched = FileDamage {
        seg_bytes: vec![340_000; 100],
        missing: all.clone(),
        length: Some(34_000_001),
    };
    assert_eq!(placed_damage_floor(&mismatched, BLOCK), 0);
    // A zero-length member, a block size we never read, and a file
    // with nothing missing.
    let empty_member = FileDamage {
        seg_bytes: vec![340_000; 100],
        missing: all.clone(),
        length: Some(0),
    };
    assert_eq!(placed_damage_floor(&empty_member, BLOCK), 0);
    assert_eq!(placed_damage_floor(&damaged(100, 340_000, 30, all), 0), 0);
    assert_eq!(
        placed_damage_floor(&damaged(100, 340_000, 30, vec![]), BLOCK),
        0
    );
    // A segment index the file does not have is skipped, not counted
    // and not panicked on: the two come from different passes.
    assert_eq!(
        placed_damage_floor(&damaged(4, 2_000_000, 30, vec![0, 99]), BLOCK),
        1
    );
}

/// The contract the verdict rests on, checked against the truth it
/// is a floor UNDER.
///
/// `placed_damage_floor` may never name more slices than the damage
/// really touched, because that count licenses an IMPOSSIBLE that
/// stops a download. Here the file is modelled exactly - equal raw
/// articles, a fixed yEnc ratio - so the truly damaged slices can be
/// counted outright and compared. Sizes, densities, overheads and
/// block sizes are swept, including articles far smaller and far
/// larger than a slice, since it is the sub-slice article that the
/// floor gains on and therefore the one it could overreach on.
#[test]
fn the_placed_count_never_outruns_the_damage_it_stands_for() {
    // Deterministic, so a failure replays. (A real sweep's misses
    // are not random, but the floor may not depend on that.)
    let mut seed = 0x2545_F491_4F6C_DD1Du64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for &block in &[4_096u64, 768_000, 1_614_720] {
        for &raw in &[1_024u64, 716_697, 1_614_720, 4_000_000] {
            for &n in &[7usize, 64, 501] {
                for &per_mille in &[0u64, 16, 31, 200] {
                    let length = raw * n as u64;
                    let enc = raw + raw * per_mille / 1_000;
                    for &pct in &[3u64, 25, 60, 100] {
                        let missing: Vec<usize> = (0..n).filter(|_| next() % 100 < pct).collect();
                        if missing.is_empty() {
                            continue;
                        }
                        let d = FileDamage {
                            seg_bytes: vec![enc; n],
                            missing: missing.clone(),
                            length: Some(length),
                        };
                        // The truth: every slice holding a byte of a
                        // missing article, counted once.
                        let mut hit: std::collections::BTreeSet<u64> = Default::default();
                        for &k in &missing {
                            let start = raw * k as u64;
                            hit.extend(start / block..=(start + raw - 1) / block);
                        }
                        let placed = placed_damage_floor(&d, block);
                        assert!(
                            placed <= hit.len(),
                            "block {block}, raw {raw}, n {n}, +{per_mille}/1000, \
                             {pct}% missing: placed {placed} over a true {}",
                            hit.len()
                        );
                    }
                }
            }
        }
    }
}

/// The pre-gate has to let through what PLACEMENT could condemn, not
/// only what weight could.
///
/// Its byte comparison is [`measured_verdict`]'s weight rule with
/// the block size divided out, so on its own it skips the fetch on
/// exactly the scattered damage the placed count exists to catch -
/// silently, since a fetch never made is a verdict never reached.
/// Same property as the single-volume one above and the same shape:
/// every input the measured route would condemn is one the gate lets
/// through. Held to volumes at least a block wide, which is the
/// assumption the gate already documents and every real recovery set
/// meets - below it the ceiling floors to zero and no block-size-free
/// gate can be sound.
#[test]
fn the_pre_gate_hides_no_condemnation_placement_could_make() {
    for block in [4_096u64, 384_000, 1_614_720, 5_376_000] {
        for vol_blocks in [1u64, 4, 40, 400] {
            for step in [1usize, 3, 11] {
                for segs in [16usize, 200] {
                    for enc in [block / 8, block / 2, block * 2] {
                        let d = damaged(segs, enc.max(1), 31, (0..segs).step_by(step).collect());
                        let bytes = enc.max(1) * d.missing.len() as u64;
                        let vol = block * vol_blocks;
                        let damage = std::slice::from_ref(&d);
                        if measured_verdict(bytes, 100, block, &[(vol, None)], 0, damage, vec![])
                            .is_some()
                        {
                            assert!(
                                block_size_could_condemn(bytes, 100, &[vol], damage),
                                "block {block}, volume {vol}, {segs} segments of {enc} \
                                 every {step}: the gate skipped a fetch that would have \
                                 condemned the post"
                            );
                        }
                    }
                }
            }
        }
    }
    // Not vacuous: damage that reaches nowhere near across the
    // budget is still skipped, placed or not.
    let slight = damaged(4_000, 700_000, 31, vec![0, 1, 2]);
    assert!(!block_size_could_condemn(
        2_100_000,
        100,
        &[900_000_000],
        std::slice::from_ref(&slight)
    ));
}

/// The whole path, wired end to end against a mock: NZB in, an
/// IMPOSSIBLE resting on a fetched block size out.
///
/// The pure `measured_verdict` tests above prove the arithmetic; this
/// one proves the arithmetic is REACHED - that recovery volumes now
/// ride the sweep, that the escalation fires on exactly the verdict
/// names could not settle, and that the block size comes off the
/// wire. Built to the 15 Aug shape and scaled down so a test can post
/// it: one data file, recovery volumes named `.vol-NN.par2` so not
/// one declares a slice count, and a payload gone from the server.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preflight_condemns_the_post_only_once_it_has_read_the_block_size() {
    use nzbkit::mock::{Chaos, MockServer, make_file_articles};

    const BLOCK: u64 = 4_096;
    const INDEX: &[u8] = include_bytes!("../../nzbkit/tests/fixtures/par2/testset.par2");

    let mut articles = std::collections::HashMap::new();
    // The par2 index, posted under a `.vol-01.par2` name - the shape
    // that made the 15 Aug post unsizable, and the file whose Main
    // packet sizes it.
    let idx = make_file_articles("i.par2", INDEX, 64_000, "idx", &mut articles);
    // A recovery volume that IS on the server: 40 KB of it, so its
    // ceiling is 9 blocks at this block size.
    let vol = make_file_articles("v.par2", &vec![7u8; 40_000], 64_000, "vol", &mut articles);
    // The payload: 40 articles of 8 KB. NONE of them are posted, so
    // the sweep finds 327,680 bytes gone - 80 blocks at this block
    // size, against a 9-block ceiling. Swept at 100%, so nothing is
    // discounted: a census has nothing to be wrong about.
    let payload: Vec<(String, u64, u32)> = (1..=40)
        .map(|n| (format!("gone-{n}@mock"), 8_192u64, n))
        .collect();

    let srv = MockServer::start(articles, Chaos::default()).await;
    let dir = std::env::temp_dir().join(format!("nzbfast-preflight-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("config.json");
    std::fs::write(
        &config_path,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}",
            srv.addr.port()
        ),
    )
    .unwrap();

    let seglist = |segs: &[(String, u64, u32)]| {
        segs.iter()
            .map(|(id, bytes, part)| {
                format!("<segment bytes=\"{bytes}\" number=\"{part}\">{id}</segment>")
            })
            .collect::<Vec<_>>()
            .join("")
    };
    let file = |name: &str, segs: &[(String, u64, u32)]| {
        format!(
            "<file subject=\"Rel - &quot;{name}&quot; yEnc (1/1)\"><groups><group>a.b.test\
             </group></groups><segments>{}</segments></file>",
            seglist(segs)
        )
    };
    let nzb_path = dir.join("dead.nzb");
    std::fs::write(
        &nzb_path,
        format!(
            "<?xml version=\"1.0\"?><nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">{}{}{}\
             </nzb>",
            file("rel.mkv", &payload),
            file("rel.vol-01.par2", &idx),
            file("rel.vol-02.par2", &vol),
        ),
    )
    .unwrap();

    let verdict = check(&config_path, &nzb_path, 100, 4, 16, false)
        .await
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    let Verdict::Impossible {
        est_missing,
        recovery,
        measured: Some(m),
        ..
    } = verdict
    else {
        panic!("expected a measured IMPOSSIBLE, got {verdict:?}");
    };
    // Read off the wire, not guessed at from a filename.
    assert_eq!(m.block_size, BLOCK);
    // Neither `.vol-NN` name declares a count, so the old route saw
    // a zero budget and had to say "probably repairable". The
    // measured route sizes the live volume instead.
    assert_eq!(recovery, 9, "40,000 bytes of volume ceilings at 9 blocks");
    assert_eq!(
        est_missing, 76,
        "327,680 encoded bytes gone, converted to raw and taken over 4 KB blocks, \
         undiscounted at a 100% sweep"
    );
    assert_eq!(m.absent_volumes, 0, "both par2 files are on the server");
}

/// The mapping wired end to end: an NZB whose damage neither the
/// byte figure nor the pre-gate would have condemned, and placement
/// does.
///
/// Everything comes off the wire - the block size and the payload
/// file's exact length out of the same probed packets, the budget
/// off a volume the sweep found present. The numbers are picked so
/// the two floors straddle the ceiling. Seven of `beta.bin`'s 33
/// articles are gone, five apart, so weight proves 7,392 bytes over
/// 4 KB slices = 1 block against a live volume holding 4, and even
/// the fetch is skipped: 7,392 bytes of damage against 21 KB of
/// volumes is the pre-gate's whole reason to exist. Placing the same
/// seven inside the 33,792-byte file the FileDesc packet describes
/// proves 7 distinct slices, the damage SPANS 32 KB of the file, and
/// both halves of the answer change.
///
/// `beta.bin` is not a name chosen for flavour: it is a member of
/// the `testset.par2` recovery set, so the packets the probe reads
/// really do describe the file the NZB posts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_measured_route_places_damage_the_byte_figure_could_not_condemn() {
    use nzbkit::mock::{Chaos, MockServer, make_file_articles};

    const INDEX: &[u8] = include_bytes!("../../nzbkit/tests/fixtures/par2/testset.par2");
    // Every fifth article of the payload, and only those, are absent.
    const GONE: [u32; 7] = [1, 6, 11, 16, 21, 26, 31];

    let mut articles = std::collections::HashMap::new();
    let idx = make_file_articles("i.par2", INDEX, 64_000, "pidx", &mut articles);
    let vol = make_file_articles("v.par2", &vec![7u8; 20_000], 64_000, "pvol", &mut articles);
    // 33 articles of `beta.bin` declared at 1,056 encoded bytes each:
    // 34,848 against the 33,792 bytes the recovery set says the file
    // is, i.e. 3% of yEnc, the live figure. The sweep only STATs
    // these, so what the present ones contain is beside the point.
    let payload: Vec<(String, u64, u32)> = (1..=33)
        .map(|n| (format!("pgone-{n}@mock"), 1_056u64, n))
        .collect();
    for (id, _, part) in &payload {
        if !GONE.contains(part) {
            articles.insert(format!("<{id}>"), b"present".to_vec());
        }
    }

    let srv = MockServer::start(articles, Chaos::default()).await;
    let dir = std::env::temp_dir().join(format!("nzbfast-placed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("config.json");
    std::fs::write(
        &config_path,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}",
            srv.addr.port()
        ),
    )
    .unwrap();

    let file = |name: &str, segs: &[(String, u64, u32)]| {
        let inner = segs
            .iter()
            .map(|(id, bytes, part)| {
                format!("<segment bytes=\"{bytes}\" number=\"{part}\">{id}</segment>")
            })
            .collect::<Vec<_>>()
            .join("");
        format!(
            "<file subject=\"Rel - &quot;{name}&quot; yEnc (1/1)\"><groups><group>a.b.test\
             </group></groups><segments>{inner}</segments></file>"
        )
    };
    let nzb_path = dir.join("placed.nzb");
    std::fs::write(
        &nzb_path,
        format!(
            "<?xml version=\"1.0\"?><nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">{}{}{}\
             </nzb>",
            file("beta.bin", &payload),
            file("rel.vol-01.par2", &idx),
            file("rel.vol-02.par2", &vol),
        ),
    )
    .unwrap();

    let verdict = check(&config_path, &nzb_path, 100, 4, 16, false)
        .await
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    let Verdict::Impossible {
        est_missing,
        recovery,
        measured: Some(m),
        ..
    } = verdict
    else {
        panic!("expected a measured IMPOSSIBLE, got {verdict:?}");
    };
    assert_eq!(m.block_size, 4_096);
    assert_eq!(
        recovery, 4,
        "20,000 bytes of live volume, and the index holds no slices"
    );
    assert_eq!(
        est_missing, 7,
        "seven absent articles inside 33,792 bytes place into seven slices"
    );

    // What makes this worth its wire time, stated against the same
    // numbers: weight alone proves one block, which the four-block
    // budget covers, and on weight alone the pre-gate would not have
    // spent the fetch that found any of it.
    let live: u64 = idx.iter().chain(&vol).map(|(_, b, _)| b).sum();
    let missing_bytes = 7 * 1_056u64;
    assert_eq!(
        nzbkit::par2::min_damaged_blocks(margined_deficit_raw_bytes(missing_bytes, 100), 4_096),
        1,
        "weight alone cannot condemn a 4-block budget"
    );
    assert!(
        !block_size_could_condemn(missing_bytes, 100, &[live], &[]),
        "and without the damage's placement the fetch is skipped outright"
    );
}

/// The daemon's profile must reach the SAME verdict as the report's.
///
/// That is the standing risk in having two: the fast one skips
/// questions, and the block-size escalation runs off the answers. A
/// par2 file whose column the second server skipped is Unknown,
/// which `union_missing` reads as "not evidence of absence" - if a
/// skip were ever read as an absence instead it would strike the
/// only sizable par2 off, leave the budget unsizable, and hand back
/// the "probably repairable" the escalation exists to replace. That
/// is what `absent_volumes` is asserted on, and it is asserted on
/// the fast profile because only the fast profile skips.
///
/// Two servers, and the second one slow, because that is what makes
/// the skip actually happen: on two localhost mocks of equal speed
/// there is no race to lose, and the test would prove nothing. The
/// STAT counter is asserted for the same reason.
///
/// What the two profiles are NOT required to agree on, now that the
/// fast one can abort this shape, is how far past the ceiling the
/// deficit went. An abort stops the sweep the moment more STATs
/// cannot change the answer, so the fast profile condemns the post
/// on the evidence it had at that moment - 13 blocks against 9 where
/// the exhaustive sweep goes on to prove 40. Both numbers are
/// floors, the verdict reads "at least", and the direction is the
/// only one that is safe: less evidence can only soften an answer,
/// never manufacture one. So the deficits are asserted as an
/// ORDERING that still clears the ceiling, and everything the
/// verdict actually rests on is asserted as equality.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_fast_profile_still_reads_the_block_size_off_a_skipped_file() {
    use nzbkit::mock::{Chaos, MockServer, make_file_articles};

    const INDEX: &[u8] = include_bytes!("../../nzbkit/tests/fixtures/par2/testset.par2");
    let mut articles = std::collections::HashMap::new();
    let idx = make_file_articles("i.par2", INDEX, 64_000, "fidx", &mut articles);
    let vol = make_file_articles("v.par2", &vec![7u8; 40_000], 64_000, "fvol", &mut articles);
    let payload: Vec<(String, u64, u32)> = (1..=40)
        .map(|n| (format!("fgone-{n}@mock"), 8_192u64, n))
        .collect();

    let carries = MockServer::start(articles, Chaos::default()).await;
    // Carries nothing at all, and is slow to say so - the live
    // shape, where a miss costs 9-31x a hit. Every id it is asked
    // about is a miss; every id it is NOT asked about is one
    // `settle_on_have` spared it.
    let empty = MockServer::start(
        std::collections::HashMap::new(),
        Chaos {
            missing_delay_ms: 30,
            ..Chaos::default()
        },
    )
    .await;

    let dir = std::env::temp_dir().join(format!("nzbfast-preflight-fast-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("config.json");
    std::fs::write(
        &config_path,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}},\
             {{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}",
            carries.addr.port(),
            empty.addr.port()
        ),
    )
    .unwrap();

    let seglist = |segs: &[(String, u64, u32)]| {
        segs.iter()
            .map(|(id, bytes, part)| {
                format!("<segment bytes=\"{bytes}\" number=\"{part}\">{id}</segment>")
            })
            .collect::<Vec<_>>()
            .join("")
    };
    let file = |name: &str, segs: &[(String, u64, u32)]| {
        format!(
            "<file subject=\"Rel - &quot;{name}&quot; yEnc (1/1)\"><groups><group>a.b.test\
             </group></groups><segments>{}</segments></file>",
            seglist(segs)
        )
    };
    let nzb_path = dir.join("dead.nzb");
    std::fs::write(
        &nzb_path,
        format!(
            "<?xml version=\"1.0\"?><nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">{}{}{}\
             </nzb>",
            file("rel.mkv", &payload),
            file("rel.vol-01.par2", &idx),
            file("rel.vol-02.par2", &vol),
        ),
    )
    .unwrap();

    let fast = check(&config_path, &nzb_path, 100, 4, 16, true)
        .await
        .unwrap();
    let asked_fast = empty.stats.load(std::sync::atomic::Ordering::Relaxed);
    let full = check(&config_path, &nzb_path, 100, 4, 16, false)
        .await
        .unwrap();
    let asked_full = empty.stats.load(std::sync::atomic::Ordering::Relaxed) - asked_fast;
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        asked_fast < asked_full,
        "nothing was skipped ({asked_fast} vs {asked_full} STATs), so this proves nothing \
         about skipping"
    );
    // And the abort fired, separately from the skipping. No server
    // has the payload here, so `settle_on_have` can spare only the
    // two par2 ids the first server answers Have for; every STAT
    // beyond that which the fast profile did not spend is the sweep
    // standing down on a verdict already reached. Before the probe
    // moved in front of the sweep this post could not arm an abort
    // at all, and the daemon paid a full sweep AND a probe for it.
    assert!(
        asked_fast + 2 < asked_full,
        "the fast profile asked {asked_fast} of {asked_full} STATs, which settle-on-have \
         alone explains - the abort never fired on the shape it exists for"
    );
    let (
        Verdict::Impossible {
            est_missing: fast_missing,
            recovery: fast_recovery,
            measured: Some(fast_m),
            dropped: fast_dropped,
        },
        Verdict::Impossible {
            est_missing: full_missing,
            recovery: full_recovery,
            measured: Some(full_m),
            dropped: full_dropped,
        },
    ) = (&fast, &full)
    else {
        panic!("the two profiles disagreed about the post: {fast:?} vs {full:?}");
    };
    assert_eq!(
        fast_m, full_m,
        "the two profiles sized the recovery set differently"
    );
    assert_eq!(fast_m.block_size, 4_096, "the set's own block size");
    assert_eq!(fast_m.absent_volumes, 0, "a skipped cell is not an absence");
    assert_eq!(
        fast_recovery, full_recovery,
        "the budget is the same budget"
    );
    assert_eq!(fast_dropped, full_dropped);
    assert_eq!(*full_recovery, 9);
    assert_eq!(
        *full_missing, 76,
        "the exhaustive sweep proves every one, and a 100% sweep is a census"
    );
    assert!(
        fast_missing <= full_missing,
        "the fast profile claimed {fast_missing} blocks of damage the exhaustive sweep \
         ({full_missing}) never found"
    );
    assert!(
        fast_missing > fast_recovery,
        "{fast_missing} blocks does not clear a ceiling of {fast_recovery}, so this \
         IMPOSSIBLE rests on nothing"
    );
}

/// What the reordering costs, stated exactly, on the post that pays
/// it for nothing.
///
/// The abort has to be armed before the sweep starts, and a healthy
/// post is indistinguishable from a dead one until the sweep runs -
/// so the daemon's profile buys the block size for every post whose
/// volume names leave the budget unsizable, healthy ones included.
/// That is one BODY: 872 bytes here, 41,901 on the 15 Aug post,
/// against the 160 s the same shape spends when it IS dead.
///
/// The price is bounded by the gate, and the gate is what this
/// asserts: `.vol-NN.par2` declares an ordinal and no slice count,
/// so it pays; `vol000+02.par2` declares two blocks, arms the
/// counted abort with no network at all, and pays nothing. The
/// second half is the overwhelming majority of real posts, and it is
/// what keeps pre-flight cheap enough to leave on.
///
/// It does NOT contradict
/// `damage_the_budget_could_cover_never_reaches_for_the_block_size`,
/// which asserts the opposite for the same shape: that one runs the
/// report's profile, where the probe is still late and
/// `block_size_could_condemn` can weigh a deficit that by then
/// exists. Neither number exists before a sweep, so the daemon's
/// profile cannot ask it and buys the article instead. Two profiles,
/// two cost decisions, one verdict.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_an_unsizable_budget_pays_for_the_early_probe() {
    use nzbkit::mock::{Chaos, MockServer, make_file_articles};

    const INDEX: &[u8] = include_bytes!("../../nzbkit/tests/fixtures/par2/testset.par2");
    let mut articles = std::collections::HashMap::new();
    let data: Vec<u8> = (0..40_000u32).map(|i| i as u8).collect();
    let payload = make_file_articles("rel.mkv", &data, 8_192, "pay", &mut articles);
    let idx = make_file_articles("i.par2", INDEX, 64_000, "fidx", &mut articles);

    let srv = MockServer::start(articles, Chaos::default()).await;
    let dir = std::env::temp_dir().join(format!("nzbfast-preflight-cost-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("config.json");
    std::fs::write(
        &config_path,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}",
            srv.addr.port()
        ),
    )
    .unwrap();
    let seg = |segs: &[(String, u64, u32)]| {
        segs.iter()
            .map(|(id, bytes, part)| {
                format!("<segment bytes=\"{bytes}\" number=\"{part}\">{id}</segment>")
            })
            .collect::<Vec<_>>()
            .join("")
    };
    let write_nzb = |name: &str, vol: &str| {
        let path = dir.join(name);
        std::fs::write(
            &path,
            format!(
                "<?xml version=\"1.0\"?><nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
                 <file subject=\"Rel - &quot;rel.mkv&quot; yEnc (1/1)\"><groups><group>\
                 a.b.test</group></groups><segments>{}</segments></file>\
                 <file subject=\"Rel - &quot;{vol}&quot; yEnc (1/1)\"><groups><group>\
                 a.b.test</group></groups><segments>{}</segments></file></nzb>",
                seg(&payload),
                seg(&idx),
            ),
        )
        .unwrap();
        path
    };

    let unsizable = write_nzb("unsizable.nzb", "rel.vol-01.par2");
    let verdict = check(&config_path, &unsizable, 100, 2, 8, true)
        .await
        .unwrap();
    let paid = srv.serve_counts();
    assert_eq!(verdict, Verdict::Complete { dropped: vec![] });
    assert_eq!(
        paid.len(),
        1,
        "the unsizable shape should buy exactly one article, but bought {paid:?}"
    );

    let counted = write_nzb("counted.nzb", "rel.vol000+02.par2");
    let verdict = check(&config_path, &counted, 100, 2, 8, true)
        .await
        .unwrap();
    let after = srv.serve_counts();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(verdict, Verdict::Complete { dropped: vec![] });
    assert_eq!(
        after, paid,
        "a budget the names already size must reach its verdict on STAT alone, but \
         served {after:?} against {paid:?}"
    );
}

/// The other half of the same wiring: a payload the server HAS must
/// come back COMPLETE, and must not spend a byte finding out. The
/// escalation exists only behind the one verdict names cannot settle,
/// which is what lets pre-flight be left on permanently.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_healthy_post_never_reaches_for_the_block_size() {
    use nzbkit::mock::{Chaos, MockServer, make_file_articles};

    let mut articles = std::collections::HashMap::new();
    let data: Vec<u8> = (0..40_000u32).map(|i| i as u8).collect();
    let payload = make_file_articles("rel.mkv", &data, 8_192, "pay", &mut articles);
    let vol = make_file_articles("v.par2", &vec![7u8; 40_000], 64_000, "vol", &mut articles);

    let srv = MockServer::start(articles, Chaos::default()).await;
    let dir = std::env::temp_dir().join(format!("nzbfast-preflight-ok-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("config.json");
    std::fs::write(
        &config_path,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}",
            srv.addr.port()
        ),
    )
    .unwrap();
    let seg = |segs: &[(String, u64, u32)]| {
        segs.iter()
            .map(|(id, bytes, part)| {
                format!("<segment bytes=\"{bytes}\" number=\"{part}\">{id}</segment>")
            })
            .collect::<Vec<_>>()
            .join("")
    };
    let nzb_path = dir.join("live.nzb");
    std::fs::write(
        &nzb_path,
        format!(
            "<?xml version=\"1.0\"?><nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
             <file subject=\"Rel - &quot;rel.mkv&quot; yEnc (1/1)\"><groups><group>a.b.test\
             </group></groups><segments>{}</segments></file>\
             <file subject=\"Rel - &quot;rel.vol-01.par2&quot; yEnc (1/1)\"><groups>\
             <group>a.b.test</group></groups><segments>{}</segments></file></nzb>",
            seg(&payload),
            seg(&vol),
        ),
    )
    .unwrap();

    let verdict = check(&config_path, &nzb_path, 100, 4, 16, false)
        .await
        .unwrap();
    let served = srv.serve_counts();
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(verdict, Verdict::Complete { dropped: vec![] });
    assert!(
        served.is_empty(),
        "a healthy post must reach its verdict on STAT alone, but served {served:?}"
    );
}

/// Shared rig for the two cap tests: one mock server, a config
/// pointing at it, and an NZB of the given files written to a
/// private temp dir. Returns the dir so the caller can clean up.
fn write_rig(
    tag: &str,
    port: u16,
    files: &[(&str, Vec<(String, u64, u32)>)],
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("nzbfast-preflight-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("config.json");
    std::fs::write(
        &config_path,
        format!("{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{port},\"tls\":false}}]}}"),
    )
    .unwrap();
    let body: String = files
        .iter()
        .map(|(name, segs)| {
            let seglist: String = segs
                .iter()
                .map(|(id, bytes, part)| {
                    format!("<segment bytes=\"{bytes}\" number=\"{part}\">{id}</segment>")
                })
                .collect();
            format!(
                "<file subject=\"Rel - &quot;{name}&quot; yEnc (1/1)\"><groups><group>\
                 a.b.test</group></groups><segments>{seglist}</segments></file>"
            )
        })
        .collect();
    let nzb_path = dir.join("rig.nzb");
    std::fs::write(
        &nzb_path,
        format!(
            "<?xml version=\"1.0\"?><nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
             {body}</nzb>"
        ),
    )
    .unwrap();
    (dir, config_path, nzb_path)
}

/// A recovery set bigger than the payload sample leaves the sweep,
/// and takes the right to call a volume absent with it.
///
/// This is the cap, and it is a RATIO because the cost it bounds is
/// one: the volumes ride the payload's sweep, so "whole volumes"
/// is affordable exactly while there are fewer of them than there
/// are sampled payload articles. Over that line they drop out
/// entirely, and the budget goes back to the full NZB ceiling -
/// which is the SAFE direction, since a ceiling that counts a
/// volume Usenet does not carry can only make the verdict kinder.
///
/// Six volume segments against three sampled payload ones, so the
/// old flat 4,000 would have swept them, found `rel.vol-02.par2`
/// missing everywhere, and struck its 48 blocks off the ceiling.
/// The assertions below are what fails on that behaviour:
/// `absent_volumes` must be empty and the absent volume's bytes
/// must still be in `recovery`. The VERDICT is the same either way,
/// which is the point of the trade - the deficit outruns both
/// ceilings by thirty times.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recovery_set_larger_than_the_payload_sample_leaves_the_sweep() {
    use nzbkit::mock::{Chaos, MockServer, make_file_articles};

    const INDEX: &[u8] = include_bytes!("../../nzbkit/tests/fixtures/par2/testset.par2");
    let mut articles = std::collections::HashMap::new();
    // The only thing on the server: the file whose Main packet
    // sizes the set. Its own encoded bytes are under one block, so
    // it contributes nothing to either ceiling and cannot muddy the
    // comparison below.
    let idx = make_file_articles("i.par2", INDEX, 64_000, "capidx", &mut articles);
    assert_eq!(idx.len(), 1, "the index must stay a one-segment file");
    // Three payload articles, none of them posted, each declaring 4
    // MB - a deficit of 2,929 blocks, undiscounted because a 100%
    // sweep is a census.
    let payload: Vec<(String, u64, u32)> = (1..=3)
        .map(|n| (format!("capgone-{n}@mock"), 4_000_000u64, n))
        .collect();
    // Five volume segments, none of them posted either. 200,000
    // bytes = 48 blocks of ceiling that the old cap would have
    // struck off.
    let vol: Vec<(String, u64, u32)> = (1..=5)
        .map(|n| (format!("capvol-{n}@mock"), 40_000u64, n))
        .collect();

    let srv = MockServer::start(articles, Chaos::default()).await;
    let (dir, config_path, nzb_path) = write_rig(
        "cap",
        srv.addr.port(),
        &[
            ("rel.mkv", payload),
            ("rel.vol-01.par2", idx),
            ("rel.vol-02.par2", vol),
        ],
    );

    let verdict = check(&config_path, &nzb_path, 100, 4, 16, false)
        .await
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    let Verdict::Impossible {
        est_missing,
        recovery,
        measured: Some(m),
        ..
    } = verdict
    else {
        panic!("expected a measured IMPOSSIBLE, got {verdict:?}");
    };
    assert_eq!(m.block_size, 4_096);
    assert_eq!(
        m.absent_volumes, 0,
        "the volumes were over the cap, so the sweep never asked about them and \
         nothing may be called absent"
    );
    assert_eq!(
        recovery, 48,
        "over the cap the ceiling covers EVERY volume in the NZB - 200,000 bytes \
         of rel.vol-02.par2 included"
    );
    assert_eq!(
        est_missing, 2_783,
        "12 MB gone over 4 KB blocks, undiscounted at a 100% sweep bar the \
         encoded-to-raw conversion"
    );
}

/// Under the cap, the sweep does its job: a volume no server carries
/// is struck off the ceiling.
///
/// The other half of the trade, and the reason the cap is a ratio
/// rather than zero. Same shape as the test above with the numbers
/// the other way round - eight sampled payload articles against two
/// volume segments - so the volumes ride the sweep, `rel.vol-02.par2`
/// comes back missing on every server, and its 48 blocks stop
/// counting as a budget. `recovery` of 0 against a volume the NZB
/// says is worth 48 is the assertion that the strike-off happened.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_volume_absent_everywhere_is_struck_off_while_it_is_under_the_cap() {
    use nzbkit::mock::{Chaos, MockServer, make_file_articles};

    const INDEX: &[u8] = include_bytes!("../../nzbkit/tests/fixtures/par2/testset.par2");
    let mut articles = std::collections::HashMap::new();
    let idx = make_file_articles("i.par2", INDEX, 64_000, "undidx", &mut articles);
    let payload: Vec<(String, u64, u32)> = (1..=8)
        .map(|n| (format!("undgone-{n}@mock"), 4_000_000u64, n))
        .collect();
    // One segment, 200,000 bytes, on no server at all.
    let vol = vec![("undvol-1@mock".to_string(), 200_000u64, 1u32)];

    let srv = MockServer::start(articles, Chaos::default()).await;
    let (dir, config_path, nzb_path) = write_rig(
        "under",
        srv.addr.port(),
        &[
            ("rel.mkv", payload),
            ("rel.vol-01.par2", idx),
            ("rel.vol-02.par2", vol),
        ],
    );

    let verdict = check(&config_path, &nzb_path, 100, 4, 16, false)
        .await
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    let Verdict::Impossible {
        est_missing,
        recovery,
        measured: Some(m),
        ..
    } = verdict
    else {
        panic!("expected a measured IMPOSSIBLE, got {verdict:?}");
    };
    assert_eq!(m.block_size, 4_096);
    assert_eq!(
        m.absent_volumes, 1,
        "every segment of rel.vol-02.par2 was swept and missing everywhere"
    );
    assert_eq!(
        recovery, 0,
        "the struck-off volume's 48 blocks must not survive in the ceiling"
    );
    assert_eq!(
        est_missing, 7_421,
        "32 MB gone over 4 KB blocks, undiscounted at a 100% sweep bar the \
         encoded-to-raw conversion"
    );
}

/// A 100% sweep is a census, and a census is entitled to the whole
/// deficit rather than half of it.
///
/// The margin exists to absorb extrapolation error. At 100% there is
/// no extrapolation: every article was asked about. Halving there
/// threw away half the reach for nothing - the live 16 Aug run
/// claimed a floor of 104 blocks where 208 were provable. The floor
/// at the other end does NOT move, because the stratified sample
/// over-weights the head and tail on purpose and that bias does not
/// shrink with the sample.
#[test]
fn a_census_is_entitled_to_the_whole_deficit_and_a_sample_is_not() {
    const BLOCK: u64 = 1_614_720;
    let volumes: [(u64, Option<usize>); 7] = [
        (41_901, None),
        (1_708_175, None),
        (3_415_979, None),
        (6_790_307, None),
        (13_497_147, None),
        (15_163_522, None),
        (26_869_479, None),
    ];
    let missing_bytes = 3_332_350_599u64 * 1_965 / 4_506;
    let deficit =
        |pct: u8| match measured_verdict(missing_bytes, pct, BLOCK, &volumes, 0, &[], vec![]) {
            Some(Verdict::Impossible { est_missing, .. }) => est_missing,
            other => panic!("an 11x deficit must condemn at {pct}%, got {other:?}"),
        };
    // The sampled figure the 15 Aug report was built on.
    assert_eq!(deficit(10), 427, "a 10% sample still claims half");
    // The same post swept whole: nothing was estimated, so nothing
    // is discounted for sampling. The yEnc conversion still applies
    // - it is a units fix, not a discount, and it is the only thing
    // separating 854 from the 899 that dividing ENCODED bytes by a
    // raw block size would claim.
    assert_eq!(deficit(100), 854, "a census claims the whole figure");
    // And a curve between them, not two cases - the daemon's default
    // sample is expected to move as the sweep gets cheaper.
    assert!(
        deficit(10) < deficit(55) && deficit(55) < deficit(100),
        "the margin must rise with the sample, not step"
    );
    // Below the daemon's sample the margin holds its floor: the
    // head/tail over-weighting is a BIAS, and a smaller sample does
    // not make it worse in a way a smaller margin would answer.
    assert_eq!(deficit(1), deficit(10), "the 0.5 floor must hold");
    assert_eq!(deficit(0), deficit(10), "including at the bottom");
}

/// The pre-gate may skip the fetch only when the fetch could not
/// have changed the answer.
///
/// With one live volume the byte comparison and the block one agree
/// exactly - `floor` is monotone - so this is the property in its
/// pure form: every input the measured route would condemn is an
/// input the gate lets through. (With several volumes the real rule
/// floors each one separately and can reach a band up to one block
/// per volume beyond this; that residue is documented on
/// [`block_size_could_condemn`] and runs in the safe direction.)
#[test]
fn the_pre_gate_hides_no_condemnation_a_single_volume_could_make() {
    for block in [4_096u64, 384_000, 768_000, 1_614_720, 3_840_000, 5_376_000] {
        for vol in [block / 2, block, block * 7, block * 137 + 11] {
            for mult in [1u64, 2, 3, 5, 8, 13] {
                for pct in [0u8, 1, 10, 25, 50, 75, 100] {
                    let bytes = vol * mult + block / 3;
                    if measured_verdict(bytes, pct, block, &[(vol, None)], 0, &[], vec![]).is_some()
                    {
                        assert!(
                            block_size_could_condemn(bytes, pct, &[vol], &[]),
                            "block {block}, volume {vol}, {bytes} bytes at {pct}%: the gate \
                             skipped a fetch that would have condemned the post"
                        );
                    }
                }
            }
        }
    }
    // And it is not vacuously true: ordinary damage against a budget
    // that dwarfs it is skipped, and the margin feeds this side too,
    // so the same post can be worth a look at 100% and not at 10%.
    assert!(!block_size_could_condemn(1_000, 100, &[40_000], &[]));
    assert!(!block_size_could_condemn(60_000, 10, &[40_000], &[]));
    assert!(block_size_could_condemn(60_000, 100, &[40_000], &[]));
}

/// Damage the budget could plainly cover must not spend a BODY
/// fetch finding out - and the verdict gate alone does not stop it.
///
/// This is the whole cost argument. `Repairable { recovery_unknown }`
/// with `est_missing > recovery` sounds narrow, but on a
/// `.vol-NN.par2` set `recovery` is ZERO, so ONE missing article out
/// of thousands satisfies it. Before the pre-gate this post fetched
/// a par2 body, read the block size, worked out that one block of
/// damage does not outrun a nine-block ceiling, and returned exactly
/// the verdict it already had. `serve_counts` is the assertion
/// because it is the cost: STAT is the sweep, BODY is the round trip
/// this saves.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn damage_the_budget_could_cover_never_reaches_for_the_block_size() {
    use nzbkit::mock::{Chaos, MockServer, make_file_articles};

    const INDEX: &[u8] = include_bytes!("../../nzbkit/tests/fixtures/par2/testset.par2");
    let mut articles = std::collections::HashMap::new();
    // Five payload articles that ARE on the server, and a sixth on
    // none - a post with real but modest damage.
    let data: Vec<u8> = (0..40_000u32).map(|i| i as u8).collect();
    let mut payload = make_file_articles("rel.mkv", &data, 8_192, "cov", &mut articles);
    payload.push(("cov-gone@mock".to_string(), 8_192, payload.len() as u32 + 1));
    // Recovery named the unsizable way, so the names route sums a
    // ZERO budget and the escalation gate opens - but the volumes
    // dwarf the missing payload, so no block size could turn that
    // into an IMPOSSIBLE.
    let idx = make_file_articles("i.par2", INDEX, 64_000, "covidx", &mut articles);
    let vol = make_file_articles(
        "v.par2",
        &vec![7u8; 40_000],
        64_000,
        "covvol",
        &mut articles,
    );

    let srv = MockServer::start(articles, Chaos::default()).await;
    let (dir, config_path, nzb_path) = write_rig(
        "cov",
        srv.addr.port(),
        &[
            ("rel.mkv", payload),
            ("rel.vol-01.par2", idx),
            ("rel.vol-02.par2", vol),
        ],
    );

    let verdict = check(&config_path, &nzb_path, 100, 4, 16, false)
        .await
        .unwrap();
    let served = srv.serve_counts();
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(
        verdict,
        Verdict::Repairable {
            est_missing: 1,
            recovery: 0,
            recovery_unknown: true,
            dropped: vec![],
        },
        "the answer is the one the names route already had"
    );
    assert!(
        served.is_empty(),
        "the block size could not have changed this verdict, but it was fetched anyway: \
         {served:?}"
    );
}

/// The false IMPOSSIBLE this route carried until 16 Aug, in the
/// numbers that make it fire.
///
/// `est_missing` counts payload ARTICLES; `recovery` counts recovery
/// BLOCKS summed off volume filenames. The ratio between them is the
/// poster's to choose and it is routinely not 1 - the call site said
/// so itself ("block ~= article for typical posts") and compared
/// them anyway.
///
/// Take a post at 4 MB blocks and 739,536-byte articles - 5.4
/// articles to the block, a shape the 15 Aug report was already
/// halfway to at 1,614,720-byte blocks. Lose 500 payload articles
/// and they can damage at most a few hundred blocks and provably
/// damage only 43, against 300 declared recovery blocks that repair
/// it with room to spare. The old comparison read `500 > 300`,
/// returned IMPOSSIBLE, and refused the job outright in all three
/// callers: the CLI's `--preflight`, the daemon's sweep, and the
/// library metadata-only path.
///
/// Both halves are asserted because only the pair is the fix: names
/// no longer condemn, and the measured route - the one that CAN
/// compare blocks with blocks - agrees the post is fine.
#[test]
fn a_counted_budget_alone_cannot_condemn_a_post() {
    const BLOCK: u64 = 4_000_000;
    // 300 blocks of parity, encoded onto Usenet at the usual yEnc
    // inflation, and the name says how many it holds.
    const VOLUME: (u64, Option<usize>) = (1_644_000_000, Some(300));
    // 500 articles of 739,536 bytes.
    const MISSING: u64 = 739_536 * 500;

    assert_eq!(
        verdict_of(500, 300, false, 1, vec![]),
        Verdict::Repairable {
            est_missing: 500,
            recovery: 300,
            recovery_unknown: false,
            dropped: vec![],
        },
        "500 articles is not 500 blocks, and a name cannot say which"
    );
    assert_eq!(
        measured_verdict(MISSING, 10, BLOCK, &[VOLUME], 0, &[], vec![]),
        None,
        "43 damaged blocks against a 300-block budget is a repair, not a refusal"
    );

    // And the reach is not what was given up. Same post, same
    // budget, ten times the loss: the measured route condemns it on
    // blocks, which is the comparison that was always meant.
    let v = measured_verdict(MISSING * 10, 10, BLOCK, &[VOLUME], 0, &[], vec![])
        .expect("4.6 GB of loss cannot hide in 300 blocks");
    assert!(matches!(
        v,
        Verdict::Impossible {
            est_missing: 439,
            recovery: 300,
            measured: Some(_),
            ..
        }
    ));
}

/// The one impossibility a sweep can state without reading a Main
/// packet: there is no recovery data. No block size can make zero
/// volumes repair a missing article, so this needs no probe and no
/// measurement - and it is the reach that would otherwise have been
/// lost with the article-against-block comparison, since a post with
/// no PAR2 at all summed to a budget of zero and got its IMPOSSIBLE
/// through that door.
#[test]
fn a_post_with_no_recovery_data_is_impossible_at_any_block_size() {
    assert_eq!(
        verdict_of(1, 0, false, 0, vec![]),
        Verdict::Impossible {
            est_missing: 1,
            recovery: 0,
            measured: None,
            dropped: vec![],
        },
        "one missing article and nothing to rebuild it from"
    );
    // Every volume the NZB promised proved absent from every server:
    // the same nothing, reached the other way.
    assert_eq!(
        verdict_of(900, 51, false, 0, names(&["release.nfo"])),
        Verdict::Impossible {
            est_missing: 900,
            recovery: 0,
            measured: None,
            dropped: names(&["release.nfo"]),
        },
        "a budget on no server is not a budget"
    );
    // A whole payload beside no recovery at all is still COMPLETE -
    // there is nothing to repair.
    assert_eq!(
        verdict_of(0, 0, false, 0, vec![]),
        Verdict::Complete { dropped: vec![] }
    );
    // And the sentence three callers refuse the job with says what
    // was actually found, in one unit.
    let msg = impossible_reason(1, 0, &None);
    assert!(
        msg.contains("no recovery data") && !msg.contains("recovery block(s)"),
        "a zero budget must not be reported as a block comparison: {msg}"
    );
}

/// An NZB that omits `bytes=` must not be read as a post with empty
/// recovery volumes.
///
/// The parser reports an absent `bytes=` as zero, and both halves of
/// this file would happily spend that zero as a fact: as "no
/// recovery at all" in `verdict_of`, and as a ceiling of nought in
/// `measured_verdict`. Both readings condemn every post in such an
/// NZB, and both are a floor put where a ceiling belongs - the same
/// error `recovery_unknown` exists to refuse.
#[test]
fn an_unsized_volume_declines_the_verdict_rather_than_deciding_it() {
    // The volume exists; only its size is unrecorded. That is a
    // budget we cannot bound, not a budget of nothing.
    assert_eq!(
        verdict_of(900, 0, false, 1, vec![]),
        Verdict::Repairable {
            est_missing: 900,
            recovery: 0,
            recovery_unknown: false,
            dropped: vec![],
        }
    );
    assert_eq!(
        measured_verdict(3_000_000_000, 10, 1_000_000, &[(0, None)], 0, &[], vec![]),
        None,
        "a volume of unrecorded size cannot ceiling anything"
    );
    // Not even with a count off its name: the min of a real count
    // and an unsized zero is the zero, which is the trap.
    assert_eq!(
        measured_verdict(
            3_000_000_000,
            10,
            1_000_000,
            &[(0, Some(51))],
            0,
            &[],
            vec![]
        ),
        None
    );
    // One unsized volume is enough to decline - the ceiling is a
    // sum, so a hole anywhere in it is a hole in the answer.
    assert_eq!(
        measured_verdict(
            3_000_000_000,
            10,
            1_000_000,
            &[(500_000_000, Some(400)), (0, None)],
            0,
            &[],
            vec![]
        ),
        None
    );
}

/// The declared count caps the ceiling the bytes would have given.
///
/// Sizing a volume by its encoded bytes over the bare block size is
/// loose on purpose - it credits the volume with every byte it spent
/// on yEnc inflation, packet headers and its repeated critical
/// packets. At the usual ~1.37x that is a third of the budget
/// invented, and the name is right there saying how many blocks the
/// volume really holds. Neither bound may be exceeded, so the
/// smaller is the ceiling.
#[test]
fn a_declared_count_bounds_a_volume_the_bytes_would_over_credit() {
    const BLOCK: u64 = 1_000_000;
    // 51 blocks of parity, 140 MB encoded: the bytes alone would
    // credit it with 140.
    const ENCODED: u64 = 140_000_000;
    // 114 blocks of provable damage after the margin and the
    // encoded-to-raw conversion.
    const MISSING: u64 = 240_000_000;

    assert_eq!(
        measured_verdict(MISSING, 10, BLOCK, &[(ENCODED, None)], 0, &[], vec![]),
        None,
        "unnamed, the bytes credit 140 blocks and 114 fits"
    );
    let v = measured_verdict(MISSING, 10, BLOCK, &[(ENCODED, Some(51))], 0, &[], vec![])
        .expect("51 declared blocks cannot repair 114 damaged ones");
    assert!(matches!(
        v,
        Verdict::Impossible {
            est_missing: 114,
            recovery: 51,
            ..
        }
    ));
    // The cap is a MIN, not a replacement: a name claiming more
    // blocks than the volume has bytes for buys nothing.
    assert_eq!(
        measured_verdict(
            MISSING,
            10,
            BLOCK,
            &[(80_000_000, Some(4_000))],
            0,
            &[],
            vec![]
        ),
        Some(Verdict::Impossible {
            est_missing: 114,
            recovery: 80,
            measured: Some(Measured {
                block_size: BLOCK,
                absent_volumes: 0
            }),
            dropped: vec![],
        }),
        "a name cannot conjure blocks that will not fit in the bytes"
    );
}

/// The named route, wired end to end, in both directions.
///
/// This is the route that actually fires on live posts - every
/// volume declaring a slice count, so `recovery_unknown` is false -
/// and until 16 Aug it was the one with no rigour behind it: a count
/// of missing ARTICLES against a count of declared BLOCKS, refusing
/// the job when the first outran the second. Both halves are here
/// because the fix is the pair. A post whose articles outnumber its
/// declared blocks but whose BLOCKS survive must download; the same
/// post ten times as damaged must still be refused, on blocks
/// compared with blocks.
///
/// 4,096-byte blocks against 1,024-byte payload articles - four
/// articles to the block, the ratio inverted from the 15 Aug post
/// and every bit as much the poster's choice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_named_budget_refuses_only_what_the_blocks_refuse() {
    use nzbkit::mock::{Chaos, MockServer, make_file_articles};

    const INDEX: &[u8] = include_bytes!("../../nzbkit/tests/fixtures/par2/testset.par2");
    let mut articles = std::collections::HashMap::new();
    // A real `.par2` index, named as one: this is what makes the
    // block size readable, and it is not a volume so it is not
    // budget either.
    let idx = make_file_articles("i.par2", INDEX, 64_000, "nidx", &mut articles);
    // One recovery volume that says how many blocks it holds. 100 KB
    // of encoded bytes would credit it with 24 blocks at this block
    // size; its own name says 20, and the smaller bound wins.
    let vol = make_file_articles("v.par2", &vec![7u8; 100_000], 64_000, "nvol", &mut articles);

    let srv = MockServer::start(articles, Chaos::default()).await;
    // The same post twice over, differing only in how much of the
    // payload is gone. `gone` articles of `each` bytes, none of them
    // posted.
    let post = |tag: &str, gone: u32, each: u64| {
        let payload: Vec<(String, u64, u32)> = (1..=gone)
            .map(|n| (format!("{tag}-{n}@mock"), each, n))
            .collect();
        write_rig(
            tag,
            srv.addr.port(),
            &[
                ("rel.mkv", payload),
                ("rel.par2", idx.clone()),
                ("rel.vol000+20.par2", vol.clone()),
            ],
        )
    };

    // 40 articles of 1 KB gone: 40 > 20 was an IMPOSSIBLE, and the job
    // was refused outright. 40,960 encoded bytes can damage at most 11
    // blocks and provably damage 9, against a 20-block budget.
    let (alive_dir, cfg, nzb) = post("named-alive", 40, 1_024);
    let alive = check(&cfg, &nzb, 100, 4, 16, false).await.unwrap();
    let after_alive = srv.serve_counts();
    // 400 articles of 8 KB gone: 760 blocks of provable damage - a 100%
    // sweep is a census and claims the whole figure - and 20 blocks
    // cannot mend them.
    let (dead_dir, cfg, nzb) = post("named-dead", 400, 8_192);
    let dead = check(&cfg, &nzb, 100, 4, 16, false).await.unwrap();
    let after_dead = srv.serve_counts();
    let _ = std::fs::remove_dir_all(&alive_dir);
    let _ = std::fs::remove_dir_all(&dead_dir);

    assert_eq!(
        alive,
        Verdict::Repairable {
            est_missing: 40,
            recovery: 20,
            recovery_unknown: false,
            dropped: vec![],
        },
        "40 missing articles is not 40 damaged blocks, and only blocks repair"
    );
    // And it reached that answer without a fetch. 40 articles
    // against 20 declared blocks is exactly the shape that used to
    // condemn, and the pre-gate can see it is not worth a look
    // without knowing the block size at all.
    assert!(
        after_alive.is_empty(),
        "a post the blocks can cover must not pay for a block size: served {after_alive:?}"
    );
    assert!(
        !after_dead.is_empty(),
        "the block size was never fetched, so this proves nothing about the \
         measured route being reached from the named one"
    );
    let Verdict::Impossible {
        est_missing,
        recovery,
        measured: Some(m),
        ..
    } = dead
    else {
        panic!("expected a measured IMPOSSIBLE, got {dead:?}");
    };
    assert_eq!(m.block_size, 4_096, "read off the wire, not off a name");
    assert_eq!(
        recovery, 20,
        "the declared count caps the 24 blocks the bytes would have credited"
    );
    assert_eq!(
        est_missing, 760,
        "3,276,800 encoded bytes gone, converted to raw, over 4 KB blocks - a 100% \
         sweep discounts nothing further"
    );
}

/// The rule is only correct while it is NARROW - a version that
/// spared everything would pass the tests above just as well. Both
/// halves in one function so neither can be deleted alone.
#[test]
fn only_usenet_furniture_is_droppable() {
    for n in [
        "release.nfo",
        "release.NFO",
        "release.sfv",
        "release.txt",
        "release.srr",
        "Some.Release-GRP.md5",
    ] {
        assert!(is_droppable_metadata(n), "{n} should be furniture");
    }
    for n in [
        // Payload, in every shape: the whole point of the check.
        "release.mkv",
        "release.rar",
        "release.r00",
        "release.part01.rar",
        "release.7z",
        "setup.exe",
        "release.zip",
        // The main packet is how repair happens at all, so it is not
        // furniture here even though cleanup deletes it.
        "release.par2",
        "release.vol000+51.par2",
        // Obfuscated: a hash with no extension could be anything,
        // and guessing wrong drops a video.
        "8upt36kdv2iwfhb1ev81aj",
        "",
    ] {
        assert!(!is_droppable_metadata(n), "{n} should NOT be furniture");
    }
}

/// M2: a two-set NZB must not let one set's block size cap the OTHER
/// set's volumes by their declared counts.
///
/// The cap (`min(by_bytes, declared)`) is right on a single-set NZB and
/// unsound across two, because `block_size_probe` picks the cheapest
/// par2 anywhere in the NZB and hands back a block size with no set
/// identity, while `live_volumes` takes every volume there is. A
/// previous review refuted this exact case on the grounds that the
/// verdict is scale-invariant in `block_size` - and it WAS, before the
/// cap: `floor(margined/bs) > sum(floor(V_i/bs))` cancels. `declared`
/// comes off a filename and does not scale, so the cap broke the
/// cancellation. Pinned at the seam that decides it.
#[test]
fn a_two_set_nzb_does_not_cap_one_sets_volumes_by_anothers_name() {
    let seg =
        |id: &str, bytes: u64| format!("<segment bytes=\"{bytes}\" number=\"1\">{id}</segment>");
    let file = |name: &str, bytes: u64, id: &str| {
        format!(
            "<file subject=\"Rel - &quot;{name}&quot; yEnc (1/1)\"><groups><group>a.b.test\
             </group></groups><segments>{}</segments></file>",
            seg(id, bytes)
        )
    };
    let parse = |xml: String| {
        nzbkit::nzb::Nzb::parse(
            format!(
                "<?xml version=\"1.0\"?><nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">{xml}</nzb>"
            )
            .as_bytes(),
        )
        .expect("nzb parses")
    };

    // One set: the cap is live and load-bearing, exactly as before.
    let one = parse(format!(
        "{}{}",
        file("seta.mkv", 5_000_000, "p1@x"),
        file("seta.vol000+02.par2", 50_000_000, "v1@x"),
    ));
    assert!(!multiple_par2_sets(&one), "one stem is one set");
    assert_eq!(
        live_volumes(&one, &[]),
        vec![(50_000_000u64, Some(2usize))],
        "a single-set NZB keeps the declared cap"
    );

    // Two sets: same volume, cap withdrawn.
    let two = parse(format!(
        "{}{}{}{}",
        file("seta.mkv", 5_000_000, "p1@x"),
        file("seta.par2", 100_000, "m1@x"),
        file("setb.mkv", 5_000_000, "p2@x"),
        file("setb.vol000+02.par2", 50_000_000, "v2@x"),
    ));
    assert!(multiple_par2_sets(&two), "two stems are two sets");
    assert_eq!(
        live_volumes(&two, &[]),
        vec![(50_000_000u64, None)],
        "across sets the name cannot cap a volume the probe did not size"
    );

    // A Main and its own volumes are ONE set, not two - the Main has no
    // `.vol` suffix, so the stem has to come off the bare `.par2`.
    let main_plus_vols = parse(format!(
        "{}{}{}",
        file("rel.par2", 100_000, "m@x"),
        file("rel.vol000+01.par2", 10_000_000, "v0@x"),
        file("rel.vol001+02.par2", 20_000_000, "v1@x"),
    ));
    assert!(
        !multiple_par2_sets(&main_plus_vols),
        "a Main and its volumes share a stem"
    );

    // A second set represented ONLY by a Main with an UNQUOTED subject.
    // kind() calls that a Par2Main - `.par2` followed by whitespace -
    // but this function used `strip_suffix(".par2")`, which the " yEnc
    // (1/1)" tail defeats, so the set was invisible here and the cap
    // stayed alive on set A's volume. That cap can refuse a genuinely
    // repairable post, which is the whole thing M2 exists to stop
    // (18 Aug sweep).
    let raw_main = format!(
        "<file subject=\"setb.par2 yEnc (1/1)\"><groups><group>a.b.test</group></groups>\
         <segments>{}</segments></file>",
        seg("m2@x", 100_000)
    );
    let unquoted_second_set = parse(format!(
        "{}{}{}",
        file("seta.mkv", 5_000_000, "p1@x"),
        file("seta.vol000+02.par2", 50_000_000, "v1@x"),
        raw_main,
    ));
    assert_eq!(
        unquoted_second_set.files[2].kind(),
        nzbkit::nzb::FileKind::Par2Main,
        "precondition: kind() reads the unquoted subject as a Main"
    );
    assert!(
        multiple_par2_sets(&unquoted_second_set),
        "an unquoted Main is still a second set"
    );
    assert_eq!(
        live_volumes(&unquoted_second_set, &[]),
        vec![(50_000_000u64, None)],
        "with the second set seen, the declared cap is withdrawn"
    );

    // ONE set whose raw subjects carry a per-file counter. The stems
    // differ only by that counter, and comparing the whole prefix
    // declared two sets and threw away a trustworthy 51-slice cap -
    // preflight then credits the looser byte-derived number, and damage
    // between the two downloads the whole release before failing
    // (Codex sweep 5, L8).
    let raw = |subject: &str, bytes: u64, id: &str| {
        format!(
            "<file subject=\"{subject}\"><groups><group>a.b.test</group></groups>\
             <segments>{}</segments></file>",
            seg(id, bytes)
        )
    };
    let one_set_raw_counters = parse(format!(
        "{}{}",
        raw("[01/02] - set.par2 yEnc (1/1)", 100_000, "rm@x"),
        raw(
            "[02/02] - set.vol000+51.par2 yEnc (1/1)",
            50_000_000,
            "rv@x"
        ),
    ));
    assert!(
        !multiple_par2_sets(&one_set_raw_counters),
        "a counter prefix is not a second recovery set"
    );
    assert_eq!(
        live_volumes(&one_set_raw_counters, &[]),
        vec![(50_000_000u64, Some(51usize))],
        "one set keeps its declared cap"
    );

    // An ANONYMOUS set - ".vol-01.par2", no prefix at all - reduces to
    // an empty stem, so it was skipped entirely. It cannot be
    // name-capped itself, but it can still supply the global block-size
    // probe and cap a DIFFERENT set with a foreign block size, which is
    // the false-Impossible the cross-set rule exists to prevent
    // (Codex sweep 5, L2).
    let anon_plus_named = parse(format!(
        "{}{}",
        file(".vol-01.par2", 100_000, "a1@x"),
        file("setb.vol000+02.par2", 50_000_000, "b1@x"),
    ));
    assert!(
        multiple_par2_sets(&anon_plus_named),
        "an anonymous set beside a named one is still two sets"
    );
    assert_eq!(
        live_volumes(&anon_plus_named, &[]),
        vec![(100_000u64, None), (50_000_000u64, None)],
        "so neither volume is capped by the other's declared count"
    );

    // TWO sets in one NZB whose unquoted subjects happen to end on the
    // same token - here the release group, which every set in a post
    // shares. Taking the last whitespace token folded both to "group",
    // so a genuine second set stopped registering, the declared cap
    // stayed alive, and a foreign block size could cap the wrong
    // volumes back into a false Impossible - a worse direction than the
    // split L8 was fixing (Codex sweep 6, N9).
    let two_sets_one_group = parse(format!(
        "{}{}{}{}",
        raw("[01/03] - Feature - GROUP.par2 yEnc (1/1)", 100_000, "fm@x"),
        raw(
            "[02/03] - Feature - GROUP.vol000+51.par2 yEnc (1/1)",
            50_000_000,
            "fv@x"
        ),
        raw("[01/02] - Extras - GROUP.par2 yEnc (1/1)", 100_000, "em@x"),
        raw(
            "[02/02] - Extras - GROUP.vol000+02.par2 yEnc (1/1)",
            30_000_000,
            "ev@x"
        ),
    ));
    assert!(
        multiple_par2_sets(&two_sets_one_group),
        "Feature and Extras are two sets, whatever group posted them"
    );
    assert_eq!(
        live_volumes(&two_sets_one_group, &[]),
        vec![(50_000_000u64, None), (30_000_000u64, None)],
        "so neither set's declared count caps the other's volumes"
    );

    // And the counter is dropped wherever it sits, not only at the
    // front - one set stays one set.
    let counter_mid = parse(format!(
        "{}{}",
        raw(
            "Cool Movie 2024 (1/2) - Cool.par2 yEnc (1/1)",
            100_000,
            "cm@x"
        ),
        raw(
            "Cool Movie 2024 (2/2) - Cool.vol000+51.par2 yEnc (1/1)",
            50_000_000,
            "cv@x"
        ),
    ));
    assert!(
        !multiple_par2_sets(&counter_mid),
        "a counter inside the subject is still not a second set"
    );
    assert_eq!(
        live_volumes(&counter_mid, &[]),
        vec![(50_000_000u64, Some(51usize))],
        "one set keeps its declared cap"
    );
}

/// T2: the stem comes off the CLASSIFICATION, never off a second,
/// looser reading of the same name.
///
/// `multiple_par2_sets` gated on `kind()` and then called the public
/// `nzbkit::nzb::par2_vol_suffix` - the RAW-subject rule, whatever rule
/// produced that kind. The two answer differently about a quoted name
/// carrying `.par2` twice with whitespace between: `kind()` applies the
/// isolated rule (N6-05), finds the tail after the ordinal is
/// `.par2 x.par2` and answers `Par2Main`, so the file's set stem is
/// `a.vol-10.par2 x` - while `par2_vol_suffix` answers `Some(1)` and
/// hands back the stem `a`, which is the name of a DIFFERENT set that
/// is also in this NZB.
///
/// MEASURED on origin/main at ed6857955: `multiple_par2_sets` answered
/// FALSE on this NZB, so the two sets read as one and the declared
/// count of `a.par2`'s own volume stayed live as a cap over a set the
/// block-size probe never sized - which is exactly the false-Impossible
/// this detector exists to prevent, arriving through the detector.
/// `nzb_tests::a_subject_class_carries_the_rule_that_produced_the_kind`
/// pins the rule itself one crate down.
///
/// Pathological rather than hostile-only, and cheap to hold: the two
/// rules agree on every name a real post carries, which is why this
/// went unreported.
#[test]
fn a_quoted_par2_with_a_trailing_par2_is_its_own_set() {
    let seg =
        |id: &str, bytes: u64| format!("<segment bytes=\"{bytes}\" number=\"1\">{id}</segment>");
    let file = |name: &str, bytes: u64, id: &str| {
        format!(
            "<file subject=\"Rel - &quot;{name}&quot; yEnc (1/1)\"><groups><group>a.b.test\
             </group></groups><segments>{}</segments></file>",
            seg(id, bytes)
        )
    };
    let nzb = nzbkit::nzb::Nzb::parse(
        format!(
            "<?xml version=\"1.0\"?><nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">{}{}{}</nzb>",
            file("a.mkv", 5_000_000, "p1@x"),
            file("a.par2", 100_000, "m1@x"),
            // A Main whose name merely CONTAINS `.vol-10.par2 `.
            file("a.vol-10.par2 x.par2", 100_000, "m2@x"),
        )
        .as_bytes(),
    )
    .expect("nzb parses");

    let par2: Vec<_> = nzb
        .files
        .iter()
        .filter(|f| f.kind() != nzbkit::nzb::FileKind::Data)
        .map(|f| (f.kind(), f.classify().par2_stem()))
        .collect();
    assert_eq!(
        par2,
        vec![
            (nzbkit::nzb::FileKind::Par2Main, Some("a")),
            (nzbkit::nzb::FileKind::Par2Main, Some("a.vol-10.par2 x")),
        ],
        "the second Main's stem is its own, not the raw rule's `a`"
    );
    assert!(
        multiple_par2_sets(&nzb),
        "two stems are two sets; the raw-rule re-derivation read one"
    );
}

/// U2: the declared count comes off the CLASSIFICATION's name, never
/// off `filename_hint().unwrap_or(&f.subject)`'s second, looser read of
/// the same subject.
///
/// `filename_hint` applies the OUTPUT-NAME policy (N6-10, 255 bytes a
/// component) and the classifier's `quoted_runs` does not, so a subject
/// whose only quoted run is over-length answers `None` at
/// `filename_hint()` - and the six `vol_count_from_name` callers this
/// pins used to fall back to the RAW SUBJECT for a name the classifier
/// had already judged isolated and Par2Volume.
///
/// MEASURED before landing: on the pre-fix read, that fallback is not
/// merely a wider name, it is a WORSE one. The raw subject wraps the
/// quoted run in `"..."` and a trailing ` yEnc (1/1)`, so the `.par2`
/// this name ends on is immediately followed by a closing quote - and
/// `vol_suffix`'s tail rule accepts a whitespace tail after `.par2` but
/// not a quote character, so parsing the raw subject answers `None`
/// where the isolated name answers `Some(2)`. That is `recovery_unknown
/// = true` over a real declared count, never a wrong number - which is
/// why this is a P3 and not a live divergence like T2's.
#[test]
fn an_overlong_quoted_par2_volume_name_reads_its_count_off_the_classification() {
    let long_stem = "a".repeat(250);
    let quoted = format!("{long_stem}.vol01+02.par2");
    assert!(
        quoted.len() > 255,
        "the fixture must actually exceed the per-component limit"
    );
    let nzb = nzbkit::nzb::Nzb::parse(
        format!(
            "<?xml version=\"1.0\"?><nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
             <file subject=\"Rel - &quot;{quoted}&quot; yEnc (1/1)\"><groups><group>a.b.test\
             </group></groups><segments><segment bytes=\"50000\" number=\"1\">v1@x</segment>\
             </segments></file></nzb>"
        )
        .as_bytes(),
    )
    .expect("nzb parses");
    let f = &nzb.files[0];

    // The seam this closes: the output-name policy rejects the only
    // quoted candidate, so the pre-classification hint is gone...
    assert_eq!(
        f.filename_hint(),
        None,
        "an over-255-byte single component fails name_within_limits"
    );
    // ...while the classifier, which never applies that policy, still
    // reads the name straight off the quoted run and calls it a volume.
    let class = f.classify();
    assert_eq!(class.kind(), nzbkit::nzb::FileKind::Par2Volume);
    assert_eq!(class.name(), quoted);

    // The pre-fix formula: what the OLD `filename_hint().unwrap_or(&f.subject)`
    // caller handed to `vol_count_from_name`. Kept inline, not by
    // reverting the six call sites, so the divergence stays pinned
    // even after nobody reads that expression from a call site again.
    let pre_fix_name = f.filename_hint().unwrap_or(&f.subject);
    assert_eq!(
        vol_count_from_name(pre_fix_name),
        None,
        "the raw subject's closing quote right after .par2 breaks the \
         whitespace-tail allowance; this is the failure this test would \
         have shown before the fix"
    );

    // The fix: `live_volumes` (and the five siblings) now read the count
    // off `f.classify().name()`, which has no such quote in the way.
    assert_eq!(
        live_volumes(&nzb, &[]),
        vec![(50_000u64, Some(2usize))],
        "the declared count is read off the classification, not a raw-\
         subject re-derivation that a quoted name can defeat"
    );
}

/// M2 again, one layer down: the cap is withdrawn at BOTH ceilings or
/// the abort can stand down on a budget the verdict then reads larger.
/// `measured_verdict` is deliberately untouched by the fix - it takes
/// the `(bytes, declared)` pairs it is given - so this pins that an
/// uncapped pair is what reaches it, and that the verdict it then
/// reaches is the scale-invariant one.
#[test]
fn withdrawing_the_cap_restores_the_pre_cap_verdict() {
    const BLOCK: u64 = 1_000_000;
    // Set B's volume: 50 MB encoded, name declares 2 slices. Sized with
    // set A's 1 MB block it credits 50 blocks by bytes.
    const ENCODED: u64 = 50_000_000;
    // ~9 blocks of provable damage after margin and conversion.
    const MISSING: u64 = 20_000_000;

    // Capped by the foreign name: 2 blocks of budget, 9 of damage.
    let capped = measured_verdict(MISSING, 10, BLOCK, &[(ENCODED, Some(2))], 0, &[], vec![]);
    assert!(
        matches!(capped, Some(Verdict::Impossible { .. })),
        "this is the false condemnation the cap made possible: {capped:?}"
    );
    // Uncapped, which is what a two-set NZB now hands it.
    assert_eq!(
        measured_verdict(MISSING, 10, BLOCK, &[(ENCODED, None)], 0, &[], vec![]),
        None,
        "with the cap withdrawn the bytes credit 50 blocks and 9 fits"
    );
}

/// Row M4-33's payload arm, from the pre-flight side: a TEXT RELEASE has
/// nothing droppable in it, because the `.txt` IS the deliverable.
///
/// `is_droppable_metadata` answers a question about one NAME, and the
/// census's spare rule asks a second, per-POST one that no such
/// predicate can carry: furniture is only furniture where the post
/// carries payload beside it. Its counterpart lives at the `furniture`
/// vector in `check`, and this is what holds the two in step.
///
/// The mispredict without it is precise and is the one thing this whole
/// function exists to prevent - a book post short an article reads
/// "one droppable `.txt`, deficit 0, Complete", and then the download
/// fails, because `census::SpareRule` correctly refuses to empty the
/// release. Pre-flight must predict what the downloader will do.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preflight_does_not_drop_a_text_release_as_furniture() {
    use nzbkit::mock::{Chaos, MockServer};

    // Nothing is posted, so the sweep proves every article absent. No
    // PAR2 anywhere: with a real deficit and no budget the verdict can
    // only be Impossible - unless the deliverable was shrugged off as
    // furniture first, which turns the same post Complete.
    let srv = MockServer::start(std::collections::HashMap::new(), Chaos::default()).await;
    let dir = std::env::temp_dir().join(format!("nzbfast-preflight-txt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("config.json");
    std::fs::write(
        &config_path,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}",
            srv.addr.port()
        ),
    )
    .unwrap();
    let file = |name: &str, n: u32| {
        let segs: String = (1..=n)
            .map(|p| format!("<segment bytes=\"8192\" number=\"{p}\">{name}-{p}@mock</segment>"))
            .collect();
        format!(
            "<file subject=\"Rel - &quot;{name}&quot; yEnc (1/1)\"><groups><group>a.b.test\
             </group></groups><segments>{segs}</segments></file>"
        )
    };
    let nzb_path = dir.join("book.nzb");
    std::fs::write(
        &nzb_path,
        format!(
            "<?xml version=\"1.0\"?><nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">{}{}\
             </nzb>",
            // The deliverable, wearing a furniture extension...
            file("Novel.Chapter.txt", 8),
            // ...and real furniture beside it, so the post is ALL
            // furniture by name. Both must be judged payload here.
            file("release.nfo", 1),
        ),
    )
    .unwrap();

    let verdict = check(&config_path, &nzb_path, 100, 4, 16, false)
        .await
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    match verdict {
        Verdict::Impossible { dropped, .. } => assert!(
            dropped.is_empty(),
            "a post that is nothing BUT furniture had files shrugged off as \
             droppable - there is no payload here for them to be furniture \
             TO, so dropping them empties the release: {dropped:?}"
        ),
        other => panic!(
            "a text release with every article absent and no PAR2 must be \
             Impossible; the `.txt` was dropped as furniture, so the deficit \
             came out zero: {other:?}"
        ),
    }
}
