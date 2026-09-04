//! Y4 (31 Aug 2026): the recovery-slice length rule, from nzbkit's side.
//!
//! A child of `unit_tests` rather than more lines in it - that file
//! reached the 3,000-line ceiling the day this landed, with another
//! lane's M4-83 test arriving in the same merge. `use super::*` reaches
//! the parent's fixtures (`par2_volume_sized`, `payload`, `SET`, `BS`)
//! exactly as an inline test did, and the module is named for its file
//! so size-gate.py's CFG_TEST_MOD resolver keeps scoring it as test
//! code.

use super::*;

/// Y4 (31 Aug 2026), the follow-up M4-56 owed. That row moved the two
/// SELECTION sites onto [`slice_fits_block`] and left the two COUNTING
/// sites - `nzbfast get::settle` and the tail give-up's census - spelling
/// `== bs`, so for a day a padded volume repaired perfectly while both
/// counters read it as holding no parity. Their half is pinned in
/// `nzbfast get::workers::slice_len_tests`, which is the only scope that
/// can see both; this is the nzbkit half of the same agreement.
///
/// What is asserted is that the FINDERS report the raw length and the
/// PREDICATE alone judges it. Anyone tempted to close a future drift by
/// filtering inside `recovery_slice_locators` or `recovery_slice_census`
/// has to break this first, and that move would be wrong for a reason no
/// counter can see: a buffer holds several sets with several block sizes
/// and neither finder is handed one (TODO 311 / GH #63's eighteen).
#[test]
fn the_slice_finders_report_raw_lengths_and_the_predicate_alone_judges_them() {
    let a = payload(200, 3);
    let files: &[(&str, &[u8])] = &[("a.bin", &a)];
    for delta in [-4isize, 0, 4, 64] {
        let vol = par2_volume_sized(SET, BS, files, &[0, 1, 2, 3], delta);
        let want_len = (BS as isize + delta) as usize;
        let locs = recovery_slice_locators(&vol, &SET);
        assert_eq!(locs.len(), 4, "every packet must reach the locator");
        for (_, _, len) in &locs {
            assert_eq!(*len, want_len, "the locator judged a length it must report");
        }
        assert_eq!(
            recovery_slice_census(&vol),
            vec![(SET, want_len, 4)],
            "the census judged a length it must group by"
        );
        // The one judgement, and both roads must reach the same count
        // through it - which is exactly what the two nzbfast counters
        // stopped doing when they kept their own `== bs`.
        let want = if delta < 0 { 0 } else { 4 };
        assert_eq!(
            locs.iter()
                .filter(|(_, _, len)| slice_fits_block(*len, BS))
                .count(),
            want,
            "locator road at {want_len} bytes against a {BS}-byte block"
        );
        assert_eq!(
            recovery_slice_census(&vol)
                .iter()
                .filter(|(id, len, _)| *id == SET && slice_fits_block(*len, BS))
                .map(|(_, _, n)| *n)
                .sum::<usize>(),
            want,
            "census road at {want_len} bytes against a {BS}-byte block"
        );
    }
}

/// Y4b (31 Aug 2026), the THIRD site M4-56 and Y4 between them left.
/// Y4 moved the two per-tick COUNTERS onto the predicate; this one is
/// upstream of both - `Par2Set::parse` builds its own count and the only
/// length test on that path was `body.len() >= 4`, "carries an
/// exponent". So a volume of short slices reported full repair power
/// from the parse itself, and `get::settle` seeds every set's `on_hand`
/// straight off `recovery_blocks_seen`.
///
/// MEASURED RED on origin/main at 3337439bb: at BS=64, four exponents at
/// delta 0, -4 and -64 (a payload of nothing at all) each reported
/// `recovery_blocks_seen = 4`, while the SELECTION sites correctly find
/// zero usable slices in the same bytes - M4-56's own
/// `a_recovery_slice_shorter_than_the_block_is_refused_not_zero_extended`
/// pins `Unrepairable { needed: 1, have: 0 }` on the delta=-4 corpus.
///
/// This is the UNSAFE direction. An under-count over-fetches and the
/// repair covers for it (Y4 proper, where nobody ever got a wrong
/// answer); an over-count makes `needed = damage - on_hand` too SMALL,
/// so the exact-fit fetch buys too few volumes. The job still repairs -
/// `fetch_and_repair`'s last-resort escalation buys every REMAINING
/// volume and retries - so the cost is the whole ladder where one rung
/// would have done, which is the §282 shape and is real money on a
/// metered line. ONE arm the escalation cannot reach, stated because it
/// is not pinned here and no unit test can pin it: `recovery_candidates`
/// excludes what is already fetched, so a set whose only parity is the
/// bootstrap volume already on disk has nothing remaining to buy and the
/// verdict is a shortfall - correct about the bytes, reached after two
/// under-sized rounds that bought nothing.
///
/// Driven through `Par2Set::parse` and NOT through the locators, on
/// purpose: `slice_len_tests` above already pins that the finders report
/// raw lengths and the predicate alone judges them, and the whole point
/// of this row is that a THIRD road to a count existed which neither
/// finder is on.
#[test]
fn the_parse_counts_only_slices_that_can_serve_a_block() {
    let a = payload(200, 3);
    let files: &[(&str, &[u8])] = &[("a.bin", &a)];
    let idx = par2_index(SET, BS, files);
    let seen = |delta: isize| {
        let vol = par2_volume_sized(SET, BS, files, &[0, 1, 2, 3], delta);
        let set = par2::Par2Set::parse(&[&idx, &vol]).expect("index plus volume is one set");
        assert_eq!(set.block_size as usize, BS, "the fixture declares the grid");
        set.recovery_blocks_seen
    };
    // The two directions are not symmetric, and this count must read
    // them exactly as the selection sites do (`slice_fits_block`).
    assert_eq!(seen(0), 4, "a slice of exactly one block serves it");
    assert_eq!(
        seen(4),
        4,
        "a padded slice is cut to the block and serves it"
    );
    assert_eq!(seen(-4), 0, "four bytes short of a block serves nothing");
    assert_eq!(
        seen(-(BS as isize)),
        0,
        "an empty payload is not four blocks of parity"
    );
    // The agreement itself, which is the thing that broke: whatever the
    // parse counts, the locator road through the predicate must find the
    // same number of usable slices in the very same bytes.
    for delta in [-(BS as isize), -4, 0, 4] {
        let vol = par2_volume_sized(SET, BS, files, &[0, 1, 2, 3], delta);
        let usable = recovery_slice_locators(&vol, &SET)
            .into_iter()
            .filter(|(_, _, len)| slice_fits_block(*len, BS))
            .count();
        assert_eq!(
            par2::Par2Set::parse(&[&idx, &vol])
                .expect("parses")
                .recovery_blocks_seen,
            usable,
            "the parse and the selection road disagree at delta {delta}"
        );
    }
}
