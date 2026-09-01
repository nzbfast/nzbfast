//! How many recovery blocks a volume may be CREDITED with before a byte
//! of it has been fetched.
//!
//! Its own file rather than a block in repair.rs, which SAT at 2,809 of
//! the size gate's 3,000-line ceiling when this was carved out and takes
//! edits from several lanes a day - the same reason `volbase`,
//! `sidefetch` and `mappedplan` are each out here. Past tense on purpose:
//! that file crossed 2,990 the same afternoon, so the number is the
//! reason this split happened rather than a claim about today. One function, one caller
//! ([`super::recovery_candidates`]), and nothing about the split for
//! anyone else to know.
//!
//! WHAT THIS IS FOR. `recovery_candidates` ended every candidate row
//! with `vol_count_from_name(name).unwrap_or(est.max(1))`, so a volume
//! was credited with the block count its FILENAME claimed and nothing
//! ever checked that the bytes behind that name could hold them. Two
//! things read that number and both of them decide before any recovery
//! data is on the wire:
//!
//! * `have` in `fetch_and_repair` is the saturating fold of it, and
//!   `have < needed` is the ONLY gate in front of
//!   [`super::shortfall_is_final`]. An inflated `have` that reaches
//!   `needed` skips that whole chain - donor dirs,
//!   `adoption_candidates_present`, `in_set_harvest_possible`,
//!   `repeated_block_donor_possible` - which are exactly the arms that
//!   rescue a job with no parity left.
//! * [`super::pick_volumes`] is a byte-minimizing subset cover over
//!   `(blocks, bytes)`, so a name declaring a large count over a small
//!   body satisfies ANY block target on its own and is bought alone,
//!   ahead of every honest volume in the post. The engine then reads a
//!   file carrying no recovery slices at all and the escalation has to
//!   buy the real parity a second time. `par2_vol_count` already caps a
//!   declared count at 1 << 20, which stops the arithmetic OVERFLOWING -
//!   that is its own fix for its own question; 1,048,576 slices is still
//!   32x PAR2's GF(16) maximum and still covers any target a real post
//!   can ask for.
//!
//! WHAT THIS DOES NOT DO, stated rather than left to be found, because
//! the knapsack half is the half it is easy to overclaim. The ceiling is
//! `bytes / block_size`, i.e. `block_size` bytes per credited block,
//! while an honest volume spends `block_size + SLICE_PACKET_OVERHEAD`
//! plus the critical packets it repeats - so a CLAMPED impostor is still
//! marginally the cheapest row per slice and can still be selected. What
//! it can no longer do is stand in for parity it has no room for, so a
//! target past its own byte budget forces the honest volumes into the
//! buy. Telling a movie chunk from recovery data needs the bytes, and
//! the bytes are what every decision here runs BEFORE.
//! `volcount_tests::a_lying_name_can_no_longer_cover_a_target_its_bytes_have_no_room_for`
//! pins both halves of that.
//!
//! THE NAME IS NOT DELETED, and that is the judgement rather than the
//! default. On a healthy post the name is right, and reading it is what
//! lets `pick_volumes` plan a batch BEFORE anything is fetched - the
//! whole point of having a count you can know without spending wire.
//! What is added is the second half of a rule this repo already applies
//! one layer up, at pre-flight: `check::measured_verdict` sizes each
//! live volume as `max_recovery_blocks(bytes, block_size).min(declared)`
//! and says why in its own words - "a name cannot conjure blocks that
//! will not fit in the volume's bytes, and bytes cannot conjure blocks
//! the name denies". Repair had the other half of that sentence and not
//! this one, so the two answered "how much parity is there" differently
//! about the same NZB.
//!
//! IT IS ONE-SIDED, which is what makes it safe to apply unconditionally
//! rather than behind pre-flight's `multiple_par2_sets` guard. A volume
//! of THIS set holding `k` slices spends `k * (block_size +
//! SLICE_PACKET_OVERHEAD)` raw bytes before its critical packets, and the
//! NZB's `bytes=` is the larger yEnc-ENCODED figure, so
//! `floor(bytes / block_size) >= k + floor(k * 68 / block_size) >= k` and
//! the ceiling can never fall below an honest volume's true count. So a
//! healthy post is bit-identical to what it was and no post can be pushed
//! INTO a premature give-up by this.
//! `volcount_tests::the_ceiling_can_never_fall_below_an_honest_volumes_own_count`
//! drives that at the tightest end - the RAW slice bytes, with the yEnc
//! inflation and the critical packets left out - over seven block sizes
//! and seven slice counts.
//!
//! HOW TIGHT IT IS DEPENDS ON THE BLOCK SIZE, measured 31 Aug 2026 on
//! real par2cmdline output, because the critical packets every volume
//! repeats are exactly what the ceiling cannot see. At a real release's
//! geometry (`-s384000 -c40 -n8 -u` over 20 MB) it is EXACT - it credits
//! 5 against a true 5, so a name overstating by ONE block is caught, and
//! the encoded `bytes=` would have to run 19.7% above raw to over-credit
//! against yEnc's 2-3%. At a tiny block size it is 32x to 526x loose
//! (`-r20` over 150 KB lands on a 76-byte block, where a ONE-slice volume
//! is 40 KB of repeated critical packets) and only a gross lie is caught.
//! THE TRAP IN THAT IS FOR TESTS, not for posts: `Fixture::add_par2` uses
//! `-r<pct>` over par2cmdline's default layout, so a fixture on a small
//! payload sits in the loose regime and will show this doing almost
//! nothing - it is measuring the layout, not the clamp. The e2e row
//! spells its geometry out for that reason. A tighter divisor
//! (`bytes / (block_size + SLICE_PACKET_OVERHEAD)`, also one-sided) was
//! measured and is NOT worth having: identical where the ceiling is
//! already exact, 526x to 278x where nothing helps, and it would put a
//! second recovery ceiling in the tree beside `max_recovery_blocks`.
//!
//! Pre-flight needs that guard because `block_size_probe` hands it a
//! block size with no recovery-set identity on it; here the size comes
//! off THIS set's own parsed packets. A volume belonging to some OTHER
//! set can still be sized with the wrong block size when the affinity
//! filter found nothing to filter on - and understating one is the
//! honest direction, because its slices carry another set id and cannot
//! repair anything here whatever its name says.

use super::*;

/// The block count `name` declares, held down to what `bytes` could
/// possibly carry at `block_size`.
///
/// `None` means the name declares no count at all - not a volume, the
/// bare-ordinal `.vol-NN` shape, or a figure past `par2_vol_count`'s cap
/// - and the caller falls back to its size estimate exactly as it did
/// before this existed.
///
/// TWO CASES DECLINE THE CEILING rather than applying a zero one, and
/// both are the same mistake in different costumes: a floor put where a
/// ceiling belongs.
///
/// * `bytes == 0` is an NZB record carrying no `bytes=`, which is
///   UNSIZED and not empty. `check::measured_verdict` declines its whole
///   verdict on one such volume for this reason; here declining the
///   ceiling for that row is enough, because nothing else in the fold
///   depends on it.
/// * `block_size == 0` is an unreadable set. `max_recovery_blocks`
///   answers 0 there by contract, and 0 credited blocks for every volume
///   in the post would drive `have` to nothing and hand a repairable job
///   to `shortfall_is_final` with no parity to its name.
pub(super) fn credited_blocks(name: &str, bytes: u64, block_size: u64) -> Option<usize> {
    let declared = vol_count_from_name(name)?;
    if bytes == 0 || block_size == 0 {
        return Some(declared);
    }
    // Compared in u64 and narrowed by `try_from`, never by `as`: `usize`
    // is 32 bits on the shipped armv7 build and both terms here are
    // poster-controlled, so a cast is a silent wrap on the side that
    // would credit a lying name with MORE than its bytes allow. A
    // ceiling past `usize::MAX` cannot bind a `usize` count anyway, so
    // saturating there is exact rather than merely safe.
    let ceiling = nzbkit::par2::max_recovery_blocks(bytes, block_size);
    Some(declared.min(usize::try_from(ceiling).unwrap_or(usize::MAX)))
}

// The arithmetic above and its wiring into `recovery_candidates`. Out
// here for the reason the module is: `repair_tests` is 2,905 of the size
// gate's 3,000 lines and this subject is its own.
#[cfg(test)]
#[path = "volcount_tests.rs"]
mod tests;
