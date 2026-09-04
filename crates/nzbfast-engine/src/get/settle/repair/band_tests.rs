//! The pre-settle alias band's own rule, claim
//! `reconcile-band-and-cross-set-pairing`, 31 Aug 2026.
//!
//! A CHILD of `repair.rs` rather than an inline module, for that file's
//! own reason: it is a size-gate neighbour of the two 500-line functions
//! the `repair-rs-fn-ceilings` claim had just finished shrinking, and a
//! test module inline would give the next lane its margin back.
//!
//! What is pinned here is the RULE - [`alias_size_band`] and the
//! best-fit score beside it. What the rule is FOR is pinned by the e2e
//! probes in `crates/nzbfast/tests/e2e_lateset/chainset.rs`, over real
//! `par2 create` output and a real yEnc encoder; the 648/788 pair the
//! band defect was measured on is a property of those and not a number
//! this file could choose. Both halves are wanted: a unit test cannot
//! produce that post, and an e2e cannot say which side of the boundary
//! a figure sits on.

use super::*;

/// Defect 1, the boundary: yEnc's per-article framing is a FIXED cost
/// and the old band was a pure ratio, so a small member fell out of it.
///
/// The numbers are the measured ones. A PAR2 index over ONE member is
/// 648 bytes and posts in a single article at 788 - 1.216x, which the
/// 1.2 ceiling refused, failing a job whose output was complete and
/// MD5-proved. Three members put the index at 1,244 bytes, which posts
/// at about 1.13x and always fitted; that is the whole difference
/// between the two, and it is why the e2e fixture next door is kept at
/// three members and the band probe at one.
#[test]
fn the_band_admits_the_framing_a_small_member_cannot_amortize() {
    // The measurement. One article, 648 bytes of payload, 788 declared.
    assert!(alias_size_band(788, 648, 1));
    // ...and the same file under the RATIO alone is outside it, which
    // is the defect stated as an assertion rather than as prose.
    assert!(788 * 100 > 648 * 120);
    // The three-member index, which fitted before and must still fit.
    assert!(alias_size_band(1_404, 1_244, 1));

    // THE ALLOWANCE IS PER ARTICLE, so a slot posted in more of them
    // carries more of it - that is the whole shape of the cost.
    assert!(alias_size_band(648 + 3 * 250, 648, 3));
    assert!(!alias_size_band(648 + 3 * 250, 648, 1));
}

/// ...and what the band still REFUSES, which is the half that matters:
/// the allowance is additive and bounded, so it cannot be spent to
/// excuse a slot of a quite different size.
#[test]
fn the_band_still_refuses_a_file_of_a_quite_different_size() {
    // The e2e's own collision, at the sizes it uses: a 120,000-byte
    // payload slot declaring ~124,600 against the largest rebuilt
    // sidecar (85,208). No number of articles buys this - three
    // articles is 768 bytes of allowance against a 39,000-byte gap.
    assert!(!alias_size_band(124_600, 85_208, 3));
    // Half the size, and twice it.
    assert!(!alias_size_band(10_000, 20_000, 1));
    assert!(!alias_size_band(40_000, 20_000, 1));
    // The floor is untouched slack for the NZB's own approximation.
    assert!(alias_size_band(18_500, 20_000, 1));
    assert!(!alias_size_band(17_000, 20_000, 1));
    // A SIZELESS NZB PAIRS NOTHING, and a zero-length member is not a
    // thing to pair against either. Both are deliberate and neither is
    // relaxed by the allowance - a slot declaring nothing has nothing
    // to sanity-check, so 256 bytes of framing must not become a licence
    // to excuse it.
    assert!(!alias_size_band(0, 648, 1));
    assert!(!alias_size_band(788, 0, 1));
    assert!(!alias_size_band(200, 0, 1));
}

/// Defect 2: the score that makes the pairing best-fit, at the exact
/// collision the first-fit rule got wrong.
///
/// Measured 31 Aug 2026 on the two-level chain. The spare is
/// `setb.vol03+4.par2` at 43,796 bytes. Two slots are in band for it:
/// the sidecar slot it really belongs to, declaring ~45,595 over two
/// articles, and the payload slot `pay1` (48,000 bytes) declaring
/// ~49,945 over two. First-fit walked the slots in order and gave it to
/// `pay1`, and the sidecar was left uncovered - an excuse claiming a
/// slot's bytes were on disk PROVEN, made about a file that was not on
/// disk at all at that moment.
#[test]
fn the_score_prefers_the_slot_the_spare_really_belongs_to() {
    let sidecar = alias_size_gap_ppm(45_595, 43_796, 2);
    let payload = alias_size_gap_ppm(49_945, 43_796, 2);
    assert!(
        sidecar < payload,
        "the sidecar slot must fit its own rebuilt member better than an \
         unrelated payload slot does: {sidecar} vs {payload}"
    );
    // The other half of the same collision, one article apiece:
    // `setb.vol01+2.par2` at 22,520 against its own slot (~23,440) and
    // the `pay2` payload slot (20,000 bytes, ~20,830).
    assert!(alias_size_gap_ppm(23_440, 22_520, 1) < alias_size_gap_ppm(20_830, 22_520, 1));
}

/// The score is RELATIVE, and this is the case that decides it.
///
/// [`predicted_posted_bytes`] is a model, so its error grows with the
/// file: an expansion rate wrong by 0.4% is 3 MB on a 750 MB member. An
/// ABSOLUTE gap would then rank a true pairing of two large files below
/// a false pairing of two small ones, and the global best-first sort
/// would hand the small pair's spare out first. In parts per million a
/// true pairing scores small whatever its size.
#[test]
fn a_large_true_pairing_outranks_a_small_false_one() {
    // 750 MB in 1,000 articles, declared with the true ~3.2% expansion
    // and ~120 bytes of real framing - so the MODEL is wrong by both its
    // 3.6% rate and its generous 256-byte framing, which is the point.
    let big_len: u64 = 750 * 1024 * 1024;
    let big_posted = big_len + big_len * 32 / 1_000 + 1_000 * 120;
    let true_big = alias_size_gap_ppm(big_posted, big_len, 1_000);
    // A small pair 8% apart in size - well inside the band, and a
    // pairing the score should rank BELOW the true one above.
    let false_small = alias_size_gap_ppm(21_600, 20_000, 1);
    assert!(
        true_big < false_small,
        "a true pairing of two large files must outrank a false pairing \
         of two small ones: {true_big} vs {false_small}"
    );
    // An absolute gap gets this backwards by five orders of magnitude,
    // which is why the ppm divide is not decoration.
    let abs_big = big_posted.abs_diff(predicted_posted_bytes(big_len, 1_000));
    let abs_small = 21_600u64.abs_diff(predicted_posted_bytes(20_000, 1));
    assert!(abs_big > abs_small);
}

/// The model itself, and its stated over-prediction.
///
/// [`YENC_ARTICLE_FRAMING`] is a generous UPPER bound (256 against a
/// measured ~118), so the prediction runs high by roughly 140 bytes per
/// article. That is deliberate - the band wants a bound and the score
/// only wants a ranking - and it is pinned here so a lane that tightens
/// the constant sees which of the two it is moving.
#[test]
fn the_prediction_is_the_bands_own_model_and_runs_high() {
    // 648 bytes in one article: 648 + 23 expansion + 256 framing.
    assert_eq!(predicted_posted_bytes(648, 1), 648 + 23 + 256);
    // A real post of that file declares 788, so the model is 139 high
    // and the gap is nonzero even for an exact pairing.
    assert!(alias_size_gap_ppm(788, 648, 1) > 0);
    // Zero length is zero payload plus the framing of whatever articles
    // were claimed.
    assert_eq!(predicted_posted_bytes(0, 0), 0);
    // The `.max(1)` in the score is a divide-by-zero guard over an input
    // [`alias_size_band`] has ALREADY refused - a sizeless slot and a
    // zero-length member both pair nothing - so what it answers there is
    // not a specification, only that it answers rather than panicking.
    // Asserting a figure for it would pin a number no caller can reach.
    let _ = alias_size_gap_ppm(0, 0, 0);
    // Saturating throughout: a nonsense length must not wrap into a
    // band that admits everything.
    assert_eq!(predicted_posted_bytes(u64::MAX, u64::MAX), u64::MAX);
    assert!(!alias_size_band(1, u64::MAX, 1));
}
