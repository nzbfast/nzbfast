//! GH #63's arm of `get::settle::filedesc_name_is_better`, on a DAMAGED
//! post - claim `filedesc-refusal-under-damage`, 31 Aug 2026.
//!
//! #63's rule refuses the FileDesc rename when the subject already named
//! the file and the set names a hash back. It has shipped since v1.2.4
//! and every e2e that builds its shape - `honestyear` (M4-48),
//! `pins.rs`, `wave4d.rs` - is UNDAMAGED, so nothing had ever run it
//! through the case that decided M4-86 one guard over: the set's
//! spelling is what the disk-side repair looks a member up by, so ANY
//! refusal to rename leaves a member the set cannot find, and it adopts
//! the bytes by content and writes its own copy beside them.
//!
//! MEASURED on `honestyear`'s own fixture with ONE corrupt article,
//! against origin/main before the fix:
//!
//! ```text
//! [repair] repair complete ✔ (native, in place: 52 block(s) rebuilt
//!   across 1 file(s), 1 recreated, 1913 block(s) adopted from
//!   Terminator2.mkv)
//! tree: KpZ7mQx4TvB9nR2sLdFq.mkv (220000 bytes)
//!       Terminator2.mkv          (220000 bytes)
//! ```
//!
//! Two 220,000-byte files and `ok=true`. And the POLARITY is worse than
//! M4-86's was: `KpZ7mQx4TvB9nR2sLdFq.mkv` was byte-exact and
//! `Terminator2.mkv` differed from the payload at byte 80,000 - the
//! corrupt article's own span - so the honest name the whole #63 rule
//! exists to keep is the one the user opens and the one that is corrupt.
//! The fix defers instead of refusing, through the channel M4-86 already
//! built (`deferred_renames` in `tail::report_extraction`).
//!
//! A CHILD module of `e2e_norar` for the same reason as `honestyear` and
//! `encoding` beside it: `mod.rs` is at 2,920 lines against a 3,000
//! ceiling with about a dozen M4 lanes still appending to it, and a child
//! reaches the builders through `use super::*` where a sibling directory
//! would need each one made `pub(crate)`.

use super::*;

/// `honestyear`'s pin, with one article corrupted: subject
/// `Terminator2.mkv`, FileDesc `KpZ7mQx4TvB9nR2sLdFq.mkv`, which is
/// `add_file_renamed_by_par2`'s shape and #63's own post.
///
/// The article damaged is the FOURTH (`-0-3@mock`), whose span begins at
/// byte 80,000 - far enough into the file that a copy carrying the
/// damage and a copy without it are separable by a byte compare rather
/// than by their length, which is what the pre-fix measurement above
/// leaned on. Its presence is asserted before the run: an id that has
/// moved damages nothing and would make this pass for no reason.
/// 25%, not the 10% both rows posted until 4 Sep 2026, and CONTROL B
/// below moved with it. One corrupt 40,000-byte article of a
/// 220,000-byte payload is 358 bad blocks of 1,965 (18.2%), which 10%
/// (197 blocks) cannot close - so both damaged rows completed on the
/// `payload` generator's 131,072-byte self-period rather than on the
/// set, at `52 block(s) rebuilt, 306 adopted`, while asserting "a
/// repairable post failed"
/// (research/PAYLOAD-TRAP-PATH-DEPENDENT-CENSUS-2026-09-04.md). 25% is
/// 491 blocks. The payloads moved to `payloads::unique_payload` in the
/// same commit; the two changes are one fix and neither works alone.
fn sixtythree_fixture(tag: &str, data: &[u8]) -> Fixture {
    let mut fx = Fixture::new(tag);
    fx.add_file_renamed_by_par2("KpZ7mQx4TvB9nR2sLdFq.mkv", "Terminator2.mkv", data, 40_000);
    assert!(
        fx.add_par2(25, &["KpZ7mQx4TvB9nR2sLdFq.mkv"], 40_000),
        "par2 create failed"
    );
    fx
}

/// The article whose loss this row's damaged runs are built on.
const DAMAGED: &str = "<Terminator2_mkv-0-3@mock>";

/// THE ROW. One corrupt article against #63's shape.
///
/// What must hold: the job succeeds, there is exactly ONE copy of the
/// payload, it is byte-exact, and it is under the honest name. Before the
/// fix all four of those were true of the wrong file - two copies landed,
/// the byte-exact one wore the set's hash, and the honest name held the
/// damage.
///
/// The `Fixture` binding is held to the end of the body: `out` lives
/// inside it and its `ScratchDir` guard deletes the tree on drop, so an
/// assertion made after it has gone grades an emptied directory.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_filedesc_rename_does_not_leave_the_set_rebuilding_its_own_member() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    // `unique_payload`: on the repeating generator the damage healed out
    // of this same file - see `sixtythree_fixture`'s note.
    let data = crate::payloads::unique_payload(220_000, 97);
    let fx = sixtythree_fixture("norar63dmg", &data);
    assert!(
        fx.articles.contains_key(DAMAGED),
        "the fixture's article ids moved, so nothing is being damaged: {:?}",
        fx.articles.keys().take(6).collect::<Vec<_>>()
    );
    let chaos = Chaos {
        corrupt: std::iter::once(DAMAGED.to_string()).collect(),
        ..Chaos::default()
    };
    let (log, ok, out) = run_norar_chaos(&fx, chaos).await;
    assert!(ok, "a repairable post failed:\n{log}");

    let got = std::fs::read(out.join("Terminator2.mkv"))
        .unwrap_or_else(|e| panic!("the honest subject did not survive the repair: {e}\n{log}"));
    assert!(
        got == data,
        "the honest name carries the DAMAGE and the repaired bytes went \
         somewhere else - first differing byte {:?}, tree {:?}\n{log}",
        got.iter().zip(data.iter()).position(|(x, y)| x != y),
        tree_names(&out)
    );
    assert!(
        !out.join("KpZ7mQx4TvB9nR2sLdFq.mkv").exists(),
        "the set rebuilt its member under the name it knows, beside the one \
         it adopted the bytes from - issue #9's shape, and what refusing \
         the rename instead of deferring it measured at:\n{:?}\n{log}",
        tree_names(&out)
    );
}

/// CONTROL A - the SAME fixture with the damage removed.
///
/// A probe red for the predicted reason and a probe red for an unrelated
/// one are not distinguishable from outside, so this is what makes the
/// row's red attributable to the damage. It is #63's shipped behaviour
/// and passes under both designs; a red here means the fixture, the set,
/// or the settle path, not the rule.
#[tokio::test(flavor = "multi_thread")]
async fn the_same_post_undamaged_keeps_the_honest_subject() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let data = payload(220_000, 97);
    let fx = sixtythree_fixture("norar63clean", &data);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "a fully fetchable post failed:\n{log}");
    let got = std::fs::read(out.join("Terminator2.mkv"))
        .unwrap_or_else(|e| panic!("CONTROL A: the honest subject lost its name: {e}\n{log}"));
    assert!(got == data, "CONTROL A: payload not byte-exact\n{log}");
    assert!(
        !out.join("KpZ7mQx4TvB9nR2sLdFq.mkv").exists(),
        "CONTROL A: the FileDesc hash survived beside the honest subject:\n{log}"
    );
}

/// CONTROL B - the OPPOSITE polarity under the SAME damage, which is
/// #43/#47's and the whole reason the deobfuscation line exists: the
/// subject is a hash and the FileDesc carries the real name.
///
/// The guard ACCEPTS this rename, so nothing about it is deferred and it
/// must land exactly as it always has - one copy, under the FileDesc
/// name, byte-exact after repair. It is the control that tells "the fix
/// broke the deobfuscation direction" apart from "the fix worked", and
/// it also grades the damaged wiring a second time.
#[tokio::test(flavor = "multi_thread")]
async fn the_deobfuscation_direction_still_repairs_in_place_under_the_same_damage() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    // `unique_payload`, for the reason at `sixtythree_fixture`.
    let data = crate::payloads::unique_payload(220_000, 99);
    let mut fx = Fixture::new("norar63inv");
    fx.add_file_renamed_by_par2(
        "Real.Feature.2021.1080p-GRP.mkv",
        "Zq4hVn82BdT7mKxLpWcE",
        &data,
        40_000,
    );
    assert!(
        fx.add_par2(25, &["Real.Feature.2021.1080p-GRP.mkv"], 40_000),
        "par2 create failed"
    );
    let id = "<Zq4hVn82BdT7mKxLpWcE-0-3@mock>";
    assert!(
        fx.articles.contains_key(id),
        "CONTROL B: the fixture's article ids moved: {:?}",
        fx.articles.keys().take(6).collect::<Vec<_>>()
    );
    let chaos = Chaos {
        corrupt: std::iter::once(id.to_string()).collect(),
        ..Chaos::default()
    };
    let (log, ok, out) = run_norar_chaos(&fx, chaos).await;
    assert!(ok, "CONTROL B: a repairable post failed:\n{log}");
    let got = std::fs::read(out.join("Real.Feature.2021.1080p-GRP.mkv"))
        .unwrap_or_else(|e| panic!("CONTROL B: the FileDesc name stopped winning: {e}\n{log}"));
    assert!(
        got == data,
        "CONTROL B: payload not byte-exact after repair, tree {:?}\n{log}",
        tree_names(&out)
    );
    assert!(
        !out.join("Zq4hVn82BdT7mKxLpWcE").exists(),
        "CONTROL B: the posted hash survived beside the FileDesc name:\n{log}"
    );
}
