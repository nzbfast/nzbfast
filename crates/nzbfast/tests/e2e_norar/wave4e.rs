//! Wave-4 matrix-read rows M4-96 and M4-97, both split-tail grammar
//! predictions from the 30 Aug 2026 read, and both PASS PINS - the
//! today-behavior each row predicted is exactly what MEASURING against
//! this baseline gets, after the M4-55 (`.partNN` spelling) and M4-74
//! (mixed `.001`/`.part02` spelling) prerequisites both landed.
//!
//! A CHILD module, for the same reason as `wave4d.rs` beside it:
//! `mod.rs` was within touching distance of its 3,000-line size-gate
//! ceiling with several other wave-4 lanes appending to it, and a child
//! reaches the builders above through one `use super::*` where a
//! sibling directory of `e2e.rs` would need each of them made
//! `pub(crate)` on lines those lanes are also editing.

use super::*;

/// M4-96 - a mixed split-tail WIDTH in one set: `Movie.mkv.01` (2 digits)
/// beside `Movie.mkv.002` (3 digits). PASS PIN.
///
/// `numeric_tail` (`splitjoin.rs`) records each tail's digit width as
/// part of [`crate::splitjoin::Tail`]; `collect_split_sets` rule 3
/// requires the run to be either UNIFORM (every tail the same width) or
/// MINIMAL (the unpadded rollover `.1 … .9 .10`). `.01` + `.002` is
/// neither: the widths disagree (2 vs 3), and `.002`'s own width does
/// not match its minimal spelling for index 2 (`"2".len() == 1`) either.
/// So the set is silently refused and both parts are left exactly where
/// they landed - this is the WIDTH twin of the SPELLING refusal M4-55 /
/// M4-74 already pin in `splitjoin_tests.rs`
/// (`one_base_spelled_two_ways_refuses_the_whole_set`), measured here
/// end to end instead of at the unit level.
///
/// MEASURED on the 30 Aug 2026 baseline (with M4-55 and M4-74 landed):
/// no `Mixedwidth.mkv` is ever written, and both parts land byte-exact
/// under their original split-tail names. Matches the row's prediction
/// ("parts left, join FileDesc missing / reconstruct") exactly, since
/// nothing here identifies the parts through a FileDesc at all - there
/// is no PAR2 set, so there is nothing to reconstruct from either.
#[tokio::test(flavor = "multi_thread")]
async fn a_mixed_split_tail_width_refuses_the_whole_set() {
    let mut fx = Fixture::new("norarmixedwidth");
    let full = payload(240_000, 96);
    fx.add_file("Mixedwidth.mkv.01", &full[..120_000], 40_000);
    fx.add_file("Mixedwidth.mkv.002", &full[120_000..], 40_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "the mixed-width split post failed:\n{log}");
    assert!(
        !out.join("Mixedwidth.mkv").exists(),
        "M4-96: a mixed-width split must not join\n{log}"
    );
    let p1 = std::fs::read(out.join("Mixedwidth.mkv.01"))
        .unwrap_or_else(|e| panic!("M4-96: part .01 is missing: {e}\n{log}"));
    let p2 = std::fs::read(out.join("Mixedwidth.mkv.002"))
        .unwrap_or_else(|e| panic!("M4-96: part .002 is missing: {e}\n{log}"));
    assert!(
        p1 == full[..120_000] && p2 == full[120_000..],
        "M4-96: the refused parts must still be byte-exact\n{log}"
    );
}

/// M4-97 - 5-digit split tails, `Fivedigit.mkv.00001` / `.00002`. PASS
/// PIN.
///
/// `numeric_tail` accepts a tail of **1..=4** digits only; HJSplit and
/// Total Commander both write 5-digit tails for very large splits. A
/// name with 5 digits after the dot fails that width check and
/// `numeric_tail` returns `None`, so the file never enters
/// `collect_sets`'s grouping map at all - it is not merely refused as a
/// SET, it is never seen as a split PART in the first place. Same
/// FileDesc-names-the-join outcome as M4-96 (nothing joins), a
/// different door: grouped-then-refused there, never-grouped here.
///
/// MEASURED on the 30 Aug 2026 baseline: both halves land byte-exact
/// under their original 5-digit-tail names and no `Fivedigit.mkv` is
/// ever written.
#[tokio::test(flavor = "multi_thread")]
async fn five_digit_split_tails_are_not_a_set() {
    let mut fx = Fixture::new("norarfivedigit");
    let full = payload(240_000, 97);
    fx.add_file("Fivedigit.mkv.00001", &full[..120_000], 40_000);
    fx.add_file("Fivedigit.mkv.00002", &full[120_000..], 40_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "the 5-digit split post failed:\n{log}");
    assert!(
        !out.join("Fivedigit.mkv").exists(),
        "M4-97: a 5-digit tail must not be recognised as a split set\n{log}"
    );
    let p1 = std::fs::read(out.join("Fivedigit.mkv.00001"))
        .unwrap_or_else(|e| panic!("M4-97: part .00001 is missing: {e}\n{log}"));
    let p2 = std::fs::read(out.join("Fivedigit.mkv.00002"))
        .unwrap_or_else(|e| panic!("M4-97: part .00002 is missing: {e}\n{log}"));
    assert!(
        p1 == full[..120_000] && p2 == full[120_000..],
        "M4-97: the ungrouped parts must still be byte-exact\n{log}"
    );
}
