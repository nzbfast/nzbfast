//! The boundary of `get::settle::set_name_loses_to_held` - claim
//! `filedesc-refusal-under-damage`, 31 Aug 2026.
//!
//! A CHILD of the inline `spare_contract_tests` module in `settle.rs`,
//! which is what makes `slot` and both predicates reachable through
//! `use super::*` with nothing made more visible than it already is.

use super::*;

/// Claim `filedesc-refusal-under-damage` (31 Aug 2026): the two arms
/// of [`set_name_loses_to_held`] and the boundary between them.
///
/// The three `e2e_norar::sixtythreedamage` fixtures drive the #63 arm
/// through real posts, which is where the duplicate it exists to stop
/// is actually visible; what this adds is the boundary, including the
/// case the e2e cannot build - a slot the guard refuses for whose file
/// there is no readable name to give back, where #63's refusal must
/// still stand rather than spending the honest name on a deferral
/// nothing can honour.
#[test]
fn the_set_name_gives_way_to_a_held_name_by_either_rule() {
    // #63: an honest subject, a hash in the set. The guard refuses
    // the rename, so the held name is the one to give back.
    let named = slot("Terminator2.mkv", false, 0);
    assert!(set_name_loses_to_held(
        &named,
        "KpZ7mQx4TvB9nR2sLdFq.mkv",
        "Terminator2.mkv"
    ));
    // ...and the held leaf has to BE a name. `filedesc_name_is_better`
    // answers about the slot's HINT, and a yEnc header can have landed
    // the file under something else entirely - deferring to that would
    // hand the file a hash the guard never spoke for, and worse, would
    // rename it away from the honest name first.
    assert!(!set_name_loses_to_held(
        &named,
        "KpZ7mQx4TvB9nR2sLdFq.mkv",
        "Wm3bHt8yPcJ5vN6xQzRk"
    ));
    // #43/#47, the deobfuscation direction: the guard ACCEPTS, so
    // there is nothing to take back and the FileDesc name lands.
    let obf = slot("2137d880a074c9f1e0b3a5d6c7e8f901", false, 0);
    assert!(!set_name_loses_to_held(
        &obf,
        "Some.Film.2026-GRP.mkv",
        "2137d880a074c9f1e0b3a5d6c7e8f901"
    ));
    // M4-86's arm is unchanged and still reachable through this door,
    // including on a slot whose hint the #63 arm says nothing about.
    assert!(set_name_loses_to_held(
        &obf,
        "caf\u{fffd}.mkv",
        "caf\u{e9}.mkv"
    ));
    assert!(!set_name_loses_to_held(
        &obf,
        "caf\u{fffd}.mkv",
        "Kj8sWm3xPd"
    ));
}
