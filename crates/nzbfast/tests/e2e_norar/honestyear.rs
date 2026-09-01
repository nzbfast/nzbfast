//! Row M4-48 - an honest subject with the YEAR or SEQUEL NUMBER run onto
//! the title, against a recovery set that names the hashes back.
//!
//! `nzbkit::release::looks_obfuscated` called a single 10+ character
//! alphanumeric token carrying a digit a hash, which is every subject a
//! poster writes as "Inception2010", "Godzilla1998" or "Terminator2".
//! That verdict is `stem_is_a_name`, which `get::plan` turns into
//! `hint_is_posted_name`, which is the whole of what arms GH #63's
//! keep-the-honest-subject rule in `get::settle::filedesc_name_is_better`
//! - so on a post whose set was generated AFTER the obfuscating rename
//! (#63's own shape, and what `add_file_renamed_by_par2` builds) the
//! GOOD file was renamed TO the FileDesc hash. Not a cosmetic misread: a
//! wrong name on a real file, sitting in the finished directory where
//! the person who downloaded it cannot find it.
//!
//! MEASURED on the 30 Aug 2026 baseline (origin/main 10cb0ad77) before
//! the fix was written: the pin below landed the payload as
//! `KpZ7mQx4TvB9nR2sLdFq.mkv` and `Terminator2.mkv` did not exist, while
//! BOTH controls in the same run passed - which is what makes the red
//! attributable to the rule rather than to the fixture.
//!
//! A CHILD of `e2e_norar` for the reason `pins.rs` gives at length:
//! `mod.rs` was 2,906 lines against a 3,000 ceiling with several M4
//! lanes still appending to it, and a child module reaches the builders
//! through `use super::*` where a sibling directory would need each one
//! made `pub(crate)` on lines those lanes are also editing.

use super::*;

/// Row M4-48. Three files, ONE run, because the two controls are only
/// worth having if they are graded against the same wiring as the pin.
///
/// * the PIN - subject `Terminator2.mkv`, FileDesc a hash. Eleven
///   characters, ONE digit, no separator: a "fix" that merely raises the
///   ten-character threshold to twelve passes `Godzilla1998` and still
///   fails this, which is why this is the name on the pin.
/// * CONTROL A - the same shape with the year separated
///   (`Terminator.Two.mkv`), which the rule accepted before the fix too.
///   Its job is to fail the same way the pin does if the fixture, the
///   recovery set or the settle path is what is broken.
/// * CONTROL B - the OPPOSITE polarity, #43's: the subject is a real
///   hash and the FileDesc carries the name. The FileDesc must still
///   win, or the fix has bought the honest subject by throwing away the
///   deobfuscation the whole no-RAR family exists for.
#[tokio::test(flavor = "multi_thread")]
async fn a_year_or_sequel_run_onto_the_subject_is_not_renamed_to_the_filedesc_hash() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarm448");
    let pinned = payload(83_000, 141);
    let control = payload(71_000, 142);
    let inverse = payload(64_000, 143);
    // Set built AFTER the rename: the descriptors carry the hashes and
    // the NZB subject is the truthful record (#63).
    fx.add_file_renamed_by_par2(
        "KpZ7mQx4TvB9nR2sLdFq.mkv",
        "Terminator2.mkv",
        &pinned,
        40_000,
    );
    fx.add_file_renamed_by_par2(
        "Wm3bHt8yPcJ5vN6xQzRk.mkv",
        "Terminator.Two.mkv",
        &control,
        40_000,
    );
    // Set built BEFORE the rename: the descriptor carries the name.
    fx.add_file_renamed_by_par2(
        "Real.Feature.2021.1080p-GRP.mkv",
        "Zq4hVn82BdT7mKxLpWcE",
        &inverse,
        40_000,
    );
    assert!(fx.add_par2(
        20,
        &[
            "KpZ7mQx4TvB9nR2sLdFq.mkv",
            "Wm3bHt8yPcJ5vN6xQzRk.mkv",
            "Real.Feature.2021.1080p-GRP.mkv",
        ],
        40_000,
    ));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "honest-subject post failed outright:\n{log}");

    // CONTROL A first: a red here means the fixture, not the rule.
    let got_control = std::fs::read(out.join("Terminator.Two.mkv")).unwrap_or_else(|e| {
        panic!("CONTROL A: the separated subject lost its name too: {e}\n{log}")
    });
    assert!(
        got_control == control,
        "control payload not byte-exact\n{log}"
    );

    // The pin.
    let got = std::fs::read(out.join("Terminator2.mkv")).unwrap_or_else(|e| {
        panic!("the honest subject was renamed to the FileDesc hash: {e}\n{log}")
    });
    assert!(got == pinned, "pinned payload not byte-exact\n{log}");
    assert!(
        !out.join("KpZ7mQx4TvB9nR2sLdFq.mkv").exists(),
        "the FileDesc hash name survived beside the honest subject:\n{log}"
    );

    // CONTROL B: the deobfuscation direction is untouched.
    let got_inverse = std::fs::read(out.join("Real.Feature.2021.1080p-GRP.mkv"))
        .unwrap_or_else(|e| panic!("CONTROL B: the FileDesc name stopped winning: {e}\n{log}"));
    assert!(
        got_inverse == inverse,
        "inverse payload not byte-exact\n{log}"
    );
    assert!(
        !out.join("Zq4hVn82BdT7mKxLpWcE").exists(),
        "CONTROL B: the posted hash survived beside the FileDesc name:\n{log}"
    );
}
