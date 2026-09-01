//! X5-16: `pick_volumes` must survive an NZB's advertised byte costs.
//!
//! In-crate rather than beside the sibling e2e pins in
//! `crates/nzbfast/tests/e2e_wave5_cost/` for one reason: `pick_volumes`
//! is `pub(crate)`, so nothing in `tests/` can reach it.
//!
//! What that placement buys, and why it is worth knowing before moving
//! these: living in the bin root puts them in `cargo test -p nzbfast
//! --bin nzbfast` and in CI's `unit-one-process` job, which is the one
//! shape that runs the whole bin crate's tests in ONE process. Both
//! cases here are pure arithmetic over a local vector and touch no
//! process-global state, so that is free.
//!
//! BOTH arms were measured as an actual PANIC against the tree before
//! the fix - `attempt to add with overflow` in the exact-DP arm and
//! `attempt to multiply with overflow` in the greedy one - so these are
//! pins on a defect that happened, not on one that was reasoned about.
//! The release-build behavior is worse than the panic and is what the
//! assertions are really written against: unchecked arithmetic WRAPS
//! there, and a wrapped comparator is not a consistent ordering, so
//! `sort_by` may hand back an arbitrary subset with nothing to say so.

use super::pick_volumes;

/// X5-16 (exact-DP arm): `dp` accumulated `cost + bytes` with no
/// checked or saturating guard, and its `cost == INF` skip caught only
/// exactly `u64::MAX`. Two volumes whose advertised byte costs are near
/// `u64::MAX` therefore overflowed on the second accumulation.
///
/// The cost is attacker-supplied: an NZB segment's `bytes=` parses as
/// `u64` and `NzbFile::bytes()` saturates only the per-file SUM, so a
/// tiny real article can advertise the triggering figure.
///
/// The assertion is about COVER and not about the panic, deliberately.
/// Saturating the addition alone would stop the panic and leave the
/// planner answering an empty selection for a deficit it can in fact
/// cover, because a saturated cost lands on the very sentinel the old
/// code spelled "unreachable". Asserting the deficit is covered is what
/// separates the two fixes.
#[test]
fn x5_16_exact_dp_volume_costs_must_not_overflow() {
    let vols = vec![
        (0usize, 1usize, u64::MAX - 1),
        (1usize, 1usize, u64::MAX - 1),
    ];
    let chosen = pick_volumes(&vols, 2);
    let got: usize = chosen.iter().map(|&i| vols[i].1).sum();
    assert!(
        got >= 2,
        "planner did not cover the deficit from near-u64::MAX costs: {chosen:?}"
    );
}

/// X5-16 (greedy arm): beyond 64 volumes the ordering comparator
/// cross-multiplied `vols[a].2 * vols[b].1 as u64` - an untrusted byte
/// count against a slice count - with no widening. It overflowed on the
/// same advertised figures, and a wrapped comparison is not even a
/// consistent ordering, so `sort_by` could pick an arbitrary subset.
///
/// This arm asserts the CHOICE and not the absence of a panic: what a
/// release build does here is return the expensive volumes silently,
/// which no panic-shaped assertion could ever see.
#[test]
fn x5_16_greedy_cost_per_slice_ordering_must_not_overflow() {
    // 65 volumes forces the greedy arm. Two carry the huge advertised
    // cost; the rest are ordinary and are what a sane planner picks.
    let mut vols: Vec<(usize, usize, u64)> = (0..63).map(|i| (i, 4usize, 1_000_000u64)).collect();
    vols.push((63, 4, u64::MAX / 2));
    vols.push((64, 4, u64::MAX / 2));
    let chosen = pick_volumes(&vols, 8);
    assert!(
        chosen.iter().all(|&i| vols[i].2 == 1_000_000),
        "greedy ordering picked a near-u64::MAX volume over the cheap \
         ones: {chosen:?}"
    );
}

/// X5-16 (deficit-index arm): the DP's own `d + slices` is a third
/// unguarded add in the same function, and it is reachable from the same
/// place - `slices` is a per-volume recovery-block COUNT derived from
/// parsed packet data, and `d` is already the covered deficit. Two
/// volumes advertising a huge count therefore panic on the second one,
/// before either of the two costs above is ever consulted.
///
/// Weaker provenance than its two siblings and worth saying so: nobody
/// has produced a real post whose block count is near `usize::MAX`, so
/// this arm is defence-in-depth rather than a measured wire path. It is
/// pinned anyway because the guard is one `saturating_add` and because
/// the row's demand is that the planner survive whatever the wire says,
/// not whatever the wire has said so far.
#[test]
fn x5_16_deficit_index_must_not_overflow_on_a_huge_block_count() {
    let vols = vec![(0usize, usize::MAX, 10u64), (1usize, usize::MAX, 10u64)];
    let chosen = pick_volumes(&vols, 2);
    assert!(
        !chosen.is_empty(),
        "planner covered nothing from two volumes that each cover the \
         whole deficit: {chosen:?}"
    );
}
