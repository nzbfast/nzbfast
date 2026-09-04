//! No-RAR matrix: Cursor's THIRD extreme pass (30 Aug 2026).
//!
//! M4-41 lives in `nzbkit`'s own `live::tests` (it needs a `ReadAt`
//! source, not a posted job); M4-42, M4-43 and M4-46 are here. A
//! SIBLING of `e2e_norar` rather than more lines in it, because
//! `e2e_norar/mod.rs` was at 2,912 of its size-gate 3,000-line ceiling
//! on 30 Aug 2026 and its own header already names this as the answer - the `e2e_sniffedpar2` pattern. The rows
//! these borrow helpers from stay where they are; only the four tests
//! moved.
//!
//! M4-66 and M4-67 joined them on 30 Aug 2026 - the dot-trim and
//! format-character rows of the same matrix - for the same reason one
//! level on: `e2e.rs` was AT its size-gate ceiling on 30 Aug 2026 (the
//! 31 Aug recalibration gave test files their own), so a module of their
//! own could not be registered there at all. See the section header
//! above those two.

use super::e2e_norar::{add_par2_patched, out_tree, rename_filedesc, run_norar, run_norar_chaos};
use super::{Fixture, have_par2, payload};
use nzbkit::mock::Chaos;
use std::collections::HashSet;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Third extreme pass (30 Aug 2026): M4-42, M4-43, M4-46.
// ---------------------------------------------------------------------------

/// Post `data` with the yEnc `=ybegin` keys written AFTER `name=`.
///
/// Our own encoder puts `name=` last, so every other fixture in this
/// tree is blind to the shape M4-42 names: a poster whose tooling emits
/// `... name=foo.bin size=1000 pcrc32=DEADBEEF`. `parse_header` lets
/// `name=` consume the rest of the line, so the stored filename is the
/// whole tail. The article is built by [`nzbkit::yenc::encode`] and its
/// header line is then re-written, so the payload, the `=ypart` range
/// and the `=yend` trailer are all a real encoder's - only the key
/// ORDER on the first line is the poster's.
fn add_file_trailing_header_keys(
    fx: &mut Fixture,
    real_name: &str,
    subject: &str,
    yenc_name: &str,
    data: &[u8],
    art_size: usize,
    trailer: &str,
) {
    std::fs::write(fx.dir.join(real_name), data).unwrap();
    let total = data.len().div_ceil(art_size).max(1) as u32;
    let tag = format!("{}-{}", subject.replace('.', "_"), fx.nzb_files.len());
    let mut segs = Vec::new();
    for (i, chunk) in data.chunks(art_size).enumerate() {
        let part = i as u32 + 1;
        let begin = (i * art_size) as u64 + 1;
        let article = nzbkit::yenc::encode(
            yenc_name,
            data.len() as u64,
            Some((part, total)),
            begin,
            chunk,
        );
        // Splice the extra keys in after `name=<yenc_name>` on the
        // FIRST line only (the `=ypart`/`=yend` lines carry no name).
        let nl = article
            .windows(2)
            .position(|w| w == b"\r\n")
            .expect("encoded header line");
        let mut patched = Vec::with_capacity(article.len() + trailer.len());
        patched.extend_from_slice(&article[..nl]);
        patched.extend_from_slice(trailer.as_bytes());
        patched.extend_from_slice(&article[nl..]);
        let id = format!("{tag}-{part}@mock");
        segs.push((id.clone(), patched.len() as u64, part));
        fx.articles.insert(format!("<{id}>"), patched);
    }
    fx.nzb_files.push((subject.to_string(), segs));
}

/// M4-42: `=ybegin` keys AFTER `name=`, with NO recovery set anywhere,
/// so the yEnc name is the ONLY name the job has.
///
/// This is the row at its most visible: the file the user asked for
/// lands called `Trail.Keys.bin size=1000 pcrc32=DEADBEEF`. With a
/// PAR2 set the md5-16k tier still rescues a unique head, which is why
/// the row has to be measured on the no-set path to be measured at all.
#[tokio::test(flavor = "multi_thread")]
async fn yenc_keys_after_name_do_not_ride_into_the_published_name() {
    let mut fx = Fixture::new("norartrailkeys");
    let data = payload(60_000, 91);
    add_file_trailing_header_keys(
        &mut fx,
        "Trail.Keys.bin",
        "Nv6tQm38HcL",
        "Trail.Keys.bin",
        &data,
        40_000,
        " size=1000 pcrc32=DEADBEEF",
    );
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "trailing-key post failed outright:\n{log}");
    let tree = out_tree(&out);
    let names: Vec<&str> = tree.iter().map(|(n, _)| n.as_str()).collect();
    let got = std::fs::read(out.join("Trail.Keys.bin")).unwrap_or_else(|e| {
        panic!(
            "the yEnc name ate the keys that followed it - published as {names:?} \
             instead of Trail.Keys.bin: {e}\n{log}"
        )
    });
    assert!(got == data, "payload not byte-exact\n{log}");
}

/// M4-42, the PAR2 half: the same trailing-key header, this time with a
/// recovery set whose FileDesc names the file. The exact-name tier
/// cannot hit a name carrying the keys, so this row measures whether
/// the set still lands the right name - and, with a matching head, it
/// is the md5-16k tier that must do it.
#[tokio::test(flavor = "multi_thread")]
async fn yenc_keys_after_name_still_land_the_filedesc_name() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norartrailkeyspar2");
    let data = payload(60_000, 92);
    add_file_trailing_header_keys(
        &mut fx,
        "Trail.Set.bin",
        "Zp4hRc72NbK",
        "Trail.Set.bin",
        &data,
        40_000,
        " size=1000 pcrc32=DEADBEEF",
    );
    assert!(fx.add_par2(20, &["Trail.Set.bin"], 40_000));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "trailing-key post under a set failed:\n{log}");
    let tree = out_tree(&out);
    let names: Vec<&str> = tree.iter().map(|(n, _)| n.as_str()).collect();
    let got = std::fs::read(out.join("Trail.Set.bin"))
        .unwrap_or_else(|e| panic!("published as {names:?}, not Trail.Set.bin: {e}\n{log}"));
    assert!(got == data, "payload not byte-exact\n{log}");
}

/// M4-43: two FileDescs sharing one name with DIFFERENT content and
/// BOTH bodies on the wire, posted under obfuscated names so nothing on
/// the wire carries the shared name at all.
///
/// [`duplicate_filedesc_names_keep_both_files`] is the same descriptor
/// shape and asserts only that two distinct byte-strings survive
/// somewhere in the output. This row asks the sharper question the
/// matrix names: WHAT are they called. One of them must be the
/// FileDesc name itself, the other a disambiguated sibling of it -
/// never a hash, never one file, never an overwrite.
#[tokio::test(flavor = "multi_thread")]
async fn two_filedescs_one_name_both_posted_publish_under_disambiguated_names() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norardupboth");
    let one = payload(90_000, 93);
    let two = payload(110_000, 94);
    fx.add_file_renamed_by_par2("dupBa.bin", "Ke2sVt84WqR", &one, 40_000);
    fx.add_file_renamed_by_par2("dupBb.bin", "Ph7mDx19GnZ", &two, 40_000);
    assert!(add_par2_patched(
        &mut fx,
        20,
        &["dupBa.bin", "dupBb.bin"],
        40_000,
        |blob| {
            rename_filedesc(blob, "dupBa.bin", "twin.bin");
            rename_filedesc(blob, "dupBb.bin", "twin.bin");
        }
    ));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "two-FileDescs-one-name post failed:\n{log}");
    let tree = out_tree(&out);
    let shown: Vec<(String, usize)> = tree.iter().map(|(n, b)| (n.clone(), b.len())).collect();
    let name_of = |want: &[u8]| -> Option<String> {
        tree.iter().find(|(_, b)| b == want).map(|(n, _)| n.clone())
    };
    let (Some(n1), Some(n2)) = (name_of(&one), name_of(&two)) else {
        panic!("a duplicate-named body was lost; tree: {shown:?}\n{log}");
    };
    assert_ne!(n1, n2, "both bodies read back from one path\n{log}");
    assert!(
        n1 == "twin.bin" || n2 == "twin.bin",
        "neither body landed under the FileDesc name itself; tree: {shown:?}\n{log}"
    );
    for n in [&n1, &n2] {
        assert!(
            n.contains("twin"),
            "a duplicate-named body kept a hash instead of a disambiguated \
             FileDesc name ({n}); tree: {shown:?}\n{log}"
        );
    }
}

/// M4-46: FIVE files sharing an identical 16 KiB zero head (the ISO
/// 9660 system area), same length, ONE of them damaged past the head.
///
/// [`a_damaged_identical_head_twin_is_repaired_in_place_in_either_settle_order`]
/// is N=2 and is fixed. This is the N-way case the matrix predicts is
/// worse: `try_match_whole` enters on any head shared by two or more
/// unclaimed descriptors, so with five candidates the damaged slot
/// declines against FOUR live rivals rather than one, and the member is
/// priced WHOLLY MISSING while the other four claim themselves by
/// whole-file MD5. What must hold is the same verdict as N=2 - every
/// file byte-exact under its own name, no crossed pairing, and no
/// superseded hash-named partial shipped beside the rebuilt member.
///
/// The recovery is sized so a wholly-missing member is repairable: this
/// row pins the OUTCOME, and the cost of pricing one damaged block as a
/// whole missing file is the open `damaged-twin-ifsc-claim` lane's
/// (per-block IFSC assignment among the N). Claiming by elimination is
/// forbidden here for exactly the reason `try_match_whole`'s comment
/// gives, and five candidates make the arbitrary pairing five times
/// likelier to be wrong.
#[tokio::test(flavor = "multi_thread")]
async fn five_identical_head_files_with_one_damaged_all_land_under_their_own_names() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norariso5");
    // 20 KB of zeros covers the whole 16 KiB head, so all five share one
    // (length, md5_16k) key; the tails are distinct.
    let bodies: Vec<Vec<u8>> = (0..5u8)
        .map(|i| {
            let mut v = vec![0u8; 100_000];
            v[20_000..].copy_from_slice(&payload(80_000, 101 + i));
            v
        })
        .collect();
    let names = [
        "Iso.One.iso",
        "Iso.Two.iso",
        "Iso.Three.iso",
        "Iso.Four.iso",
        "Iso.Five.iso",
    ];
    let posted = [
        "Aa1bCc2dEe3",
        "Ff4gHh5iJj6",
        "Kk7lMm8nPp9",
        "Qq1rSs2tUu3",
        "Vv4wXx5yZz6",
    ];
    for (i, name) in names.iter().enumerate() {
        fx.add_file_renamed_by_par2(name, posted[i], &bodies[i], 25_000);
    }
    assert!(fx.add_par2(40, &names, 40_000));
    // Article 3 of the damaged file covers bytes 50k..75k - past the
    // 16 KiB head, so no head key moves and the whole-file MD5 is the
    // only thing that can tell it from its four rivals.
    let dmg = 2usize;
    let chaos = Chaos {
        corrupt: HashSet::from([format!("<{}-{dmg}-3@mock>", posted[dmg])]),
        ..Chaos::default()
    };
    let (log, ok, out) = run_norar_chaos(&fx, chaos).await;
    assert!(
        ok,
        "one damaged block among five identical-head files failed the job:\n{log}"
    );
    for (i, name) in names.iter().enumerate() {
        let got =
            std::fs::read(out.join(name)).unwrap_or_else(|e| panic!("{name} missing: {e}\n{log}"));
        assert!(
            got == bodies[i],
            "{name} carries another identical-head file's bytes\n{log}"
        );
    }
    for p in posted {
        assert!(
            !out.join(p).exists(),
            "a superseded hash-named partial shipped beside the rebuilt file \
             - an *arr would import {p}\n{log}"
        );
    }
}

// ---------------------------------------------------------------------------
// M4-66 / M4-67 (30 Aug 2026), the matrix's dot-trim and format-character
// rows. They live here rather than in a module of their own for a
// mechanical reason: `crates/nzbfast/tests/e2e.rs` was AT its size-gate
// ceiling on 30 Aug 2026, so a new `mod` line did not fit - and these are
// no-RAR matrix rows from the same document as the four above.
//
// The mechanism has its own unit tests in
// `crates/nzbkit-base/src/disk/tests.rs`
// (`a_leading_dot_no_longer_collides_with_the_undotted_name`,
// `format_characters_are_neutralised_like_control_characters`, and the
// Unicode table pin) and in `crates/nzbkit-base/src/disk/relpath.rs` for the
// out-name key. Both premises are visible at the function, so these
// three are not there to re-confirm them - they are here for the parts
// only a real post shows: that M4-66 costs a declared name when a
// DAMAGED twin sends the decision through repair rather than through the
// publish guard, and that M4-67 spoofs the engine's own log line as well
// as the directory listing.
// ---------------------------------------------------------------------------

/// Post two FileDescs whose names differ ONLY by a leading dot, over
/// bodies of the same length, with the payload posted under hashes so
/// nothing but the recovery set can name it. `damage` corrupts one
/// article of the second file, which is what makes repair - rather than
/// the publish pass - decide where the name goes.
/// The `Fixture` is RETURNED rather than dropped here: its `ScratchDir`
/// guard deletes the whole tree, so a helper that keeps it would grade
/// every assertion against an empty directory - a spectacular false red
/// (measured while writing this: `out_tree` came back `[]` while the log
/// showed both files landing correctly).
///
/// **THE PAYLOAD IS `unique_payload` AND MUST STAY THAT WAY.** On
/// `super::payload(120_000, 71)` / `(120_000, 72)` the damaged leg
/// completed `73 block(s) rebuilt ... 927 block(s) adopted`, because
/// every `payload` file is drawn from ONE shared 256-element alphabet
/// of 256-byte blocks (`payload`'s own doc comment has the algebra), so
/// the blocks the corrupt article destroyed were sitting in the sibling
/// and the adoption scan harvested them instead of the solver rebuilding
/// them. De-correlated the same leg reads `334 block(s) rebuilt ... 666
/// block(s) adopted` - 261 blocks that this row is meant to be pricing
/// against parity. The verdict did not flip either way, which is exactly
/// why nothing reported it: measured 31 Aug 2026, census in
/// `research/E2E-IDENTITY-CLASS-CENSUS-2026-08-31.md`. This fixture
/// landed at 21:35 on 30 Aug, two and a half hours AFTER the adoption
/// census that swept the rest of the tree - it is the "sixth fixture"
/// that census's own follow-up 13c.1 predicted would arrive with nothing
/// to say so.
async fn dot_twin_run(
    tag: &str,
    damage: bool,
) -> (Fixture, String, bool, PathBuf, Vec<u8>, Vec<u8>) {
    let mut fx = Fixture::new(tag);
    let a = crate::payloads::unique_payload(120_000, 0x4d07_0071);
    let b = crate::payloads::unique_payload(120_000, 0x4d07_0072);
    fx.add_file_renamed_by_par2("zzzzzzdotA.bin", "Rz5jTn93GcW", &a, 40_000);
    fx.add_file_renamed_by_par2("zzzzzzdotB.bin", "Hd8pYw41SkV", &b, 40_000);
    assert!(
        add_par2_patched(
            &mut fx,
            40,
            &["zzzzzzdotA.bin", "zzzzzzdotB.bin"],
            40_000,
            |blob| {
                assert!(rename_filedesc(blob, "zzzzzzdotA.bin", ".dotcol.bin") > 0);
                assert!(rename_filedesc(blob, "zzzzzzdotB.bin", "dotcol.bin") > 0);
            }
        ),
        "par2 create failed"
    );
    let chaos = if damage {
        // Sorted, not `find`: `articles` is a HashMap, so taking "an"
        // id makes WHICH article is damaged depend on hash order, and
        // the pre-fix outcome differs by that choice (measured 30 Aug
        // 2026: `001-dotcol.bin` on one draw, `dotcol.bin.dup-<hex>` on
        // another). Both are "not the declared name", so the assertion
        // held either way - but a fixture that draws a different case
        // each run is one nobody can reproduce a failure from.
        let mut ids: Vec<&String> = fx
            .articles
            .keys()
            .filter(|k| k.contains("Hd8pYw41SkV"))
            .collect();
        ids.sort();
        let id = ids
            .first()
            .copied()
            .expect("no article of the second file to damage")
            .clone();
        Chaos {
            corrupt: std::iter::once(id).collect(),
            ..Chaos::default()
        }
    } else {
        Chaos::default()
    };
    let (log, ok, out) = run_norar_chaos(&fx, chaos).await;
    (fx, log, ok, out, a, b)
}

/// M4-66: two FileDesc names differing only by a leading dot are two
/// files, and each lands under the name its own descriptor gives it.
///
/// `sanitize_filename_for` used to DELETE leading dots, so `.dotcol.bin`
/// and `dotcol.bin` were one on-disk name - a genuine many-to-one
/// collapse of two names that are legal and distinct everywhere, since
/// Windows folds TRAILING dots and never leading ones.
///
/// What this measured on the 30 Aug baseline, and why the clean run is
/// not the interesting half: on a clean run `PublishedNames` DID catch
/// the collision, so nothing was lost and the second payload landed as
/// `001-dotcol.bin` - which is one of the two outcomes the row itself
/// called acceptable. The damaged sibling below is where it cost
/// something.
#[tokio::test(flavor = "multi_thread")]
async fn a_leading_dot_filedesc_is_its_own_file() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (_fx, log, ok, out, a, b) = dot_twin_run("dotcol", false).await;
    assert!(ok, "leading-dot twin post failed:\n{log}");
    let tree = out_tree(&out);
    let named = |want: &str, bytes: &[u8]| tree.iter().any(|(n, got)| n == want && got == bytes);
    assert!(
        named("_dotcol.bin", &a),
        "the `.dotcol.bin` FileDesc did not land under its own name: {:?}\n{log}",
        tree.iter().map(|(n, _)| n).collect::<Vec<_>>()
    );
    assert!(
        named("dotcol.bin", &b),
        "the `dotcol.bin` FileDesc did not land under its own name: {:?}\n{log}",
        tree.iter().map(|(n, _)| n).collect::<Vec<_>>()
    );
    // Neither was pushed onto the collision convention, because there is
    // no collision left to resolve.
    assert!(
        !tree.iter().any(|(n, _)| n.contains("001-")),
        "a slot was still disambiguated, so the names still collide: {:?}\n{log}",
        tree.iter().map(|(n, _)| n).collect::<Vec<_>>()
    );
    // And neither landed hidden - the reason the dot is MAPPED to `_`
    // rather than preserved. A dotfile is furniture to this product
    // (`smart::nzbname::is_furniture` will not call one the main
    // payload), so honouring the dot would trade this defect for an
    // invisibility bug.
    for (n, _) in &tree {
        assert!(
            !n.split('/').any(|c| c.starts_with('.')),
            "a payload landed hidden: {n:?}\n{log}"
        );
    }
}

/// The damaged arm, and the one that made M4-66 worth fixing rather than
/// pinning as a pass.
///
/// Measured on the 30 Aug baseline, one corrupt article in the second
/// file: the first file published onto the collapsed name `dotcol.bin`,
/// the damaged one never published so the collision guard never fired,
/// and repair then addressed its set member by that same canonical name,
/// found the OTHER file's bytes there and rebuilt over them. Both
/// payloads survived - but one of them only as
/// `dotcol.bin.dup-1881545fbde1`, a machine name, at rc=0, with nothing
/// in the log saying a declared name had been lost. That is the W4-18
/// mechanism `get::publishplan` already writes up, reached here purely
/// by the sanitizer collapsing two distinct names.
#[tokio::test(flavor = "multi_thread")]
async fn a_damaged_leading_dot_twin_still_lands_under_both_declared_names() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (_fx, log, ok, out, a, b) = dot_twin_run("dotcoldmg", true).await;
    assert!(ok, "damaged leading-dot twin post failed:\n{log}");
    let tree = out_tree(&out);
    let shown = || tree.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>();
    assert!(
        tree.iter().any(|(n, got)| n == "_dotcol.bin" && got == &a),
        "the `.dotcol.bin` payload is not under its declared name: {:?}\n{log}",
        shown()
    );
    assert!(
        tree.iter().any(|(n, got)| n == "dotcol.bin" && got == &b),
        "the repaired `dotcol.bin` is not under its declared name: {:?}\n{log}",
        shown()
    );
    // The dup-rescue name is the fingerprint of the old behaviour: a
    // payload kept, but under a name nobody declared and no *arr will
    // import.
    assert!(
        !tree.iter().any(|(n, _)| n.contains(".dup-")),
        "a payload was displaced onto a machine name: {:?}\n{log}",
        shown()
    );
}

/// M4-67: a Unicode FORMAT character in a FileDesc name never reaches
/// disk. `char::is_control()` is general category Cc only, so U+202E
/// RIGHT-TO-LEFT OVERRIDE sailed through - and it REORDERS the display,
/// so `readme<RLO>gpj.exe` is sixteen bytes ending `.exe` that every
/// file manager and terminal renders as `readmeexe.jpg`.
///
/// Measured on the 30 Aug baseline: it landed verbatim, and the engine's
/// own `[extract] renamed ... → readme<RLO>gpj.exe` line was spoofed
/// too - so the log a user reads to check what happened told the same
/// lie the directory listing did. The log is asserted here for that
/// reason and not as decoration.
#[tokio::test(flavor = "multi_thread")]
async fn a_format_character_in_a_filedesc_name_never_reaches_disk() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("rlofd");
    let data = payload(80_000, 73);
    fx.add_file_renamed_by_par2("zzzzzzzzzzzzzzzzz.bin", "Qw8jTn93GcW", &data, 40_000);
    assert!(add_par2_patched(
        &mut fx,
        20,
        &["zzzzzzzzzzzzzzzzz.bin"],
        40_000,
        |blob| {
            assert!(
                rename_filedesc(blob, "zzzzzzzzzzzzzzzzz.bin", "readme\u{202e}gpj.exe") > 0,
                "the RLO patch matched no FileDesc"
            );
        }
    ));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "RLO-named post failed:\n{log}");
    let tree = out_tree(&out);
    assert!(
        tree.iter()
            .any(|(n, got)| n == "readme_gpj.exe" && got == &data),
        "the payload is not under the neutralised name: {:?}\n{log}",
        tree.iter().map(|(n, _)| n).collect::<Vec<_>>()
    );
    // Nothing on disk, at any depth, carries a bidi or zero-width
    // character - the name a person sees is the name in the bytes.
    for (n, _) in &tree {
        assert!(
            !n.chars().any(|c| matches!(
                c,
                '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}'
            )),
            "a format character reached disk: {n:?} ({:?})\n{log}",
            n.as_bytes()
        );
    }
    // And the log cannot be made to lie either.
    assert!(
        !log.contains('\u{202e}'),
        "the engine's own log carried the override character\n{log}"
    );
}

// ---------------------------------------------------------------------------
// M4-99 / M4-80 (31 Aug 2026), the TRAILING half of the same trim M4-66
// fixed at the leading end. They live beside those two because they are
// the same collision class in the same function, and because `e2e.rs` is
// still at its size-gate ceiling.
//
// The asymmetry is deliberate and is pinned by
// `disk::tests::the_trailing_trim_is_untouched_by_the_leading_dot_mapping`:
// Windows really does fold `evil. ` onto `evil`, so a portable name has
// to strip there, and mapping the trailing run to `_` the way M4-66 maps
// the leading one would break the extension (`movie.mkv.` ->
// `movie.mkv_`), which is a worse outcome than a disambiguated name that
// keeps `.mkv`. So the sanitizer cannot be made injective here, and
// these rows are about what the PUBLISH does with a collapse it cannot
// avoid.
// ---------------------------------------------------------------------------

/// Post two FileDescs whose names differ ONLY at the trailing end, over
/// bodies of the same length, with the payload posted under hashes so
/// nothing but the recovery set can name it.
///
/// The shape and every trap in it are `dot_twin_run`'s - read that
/// function's doc comment first, including why the payload must stay
/// `unique_payload` (a shared-alphabet `payload` lets the adoption scan
/// harvest the corrupt article's blocks out of the SIBLING, which moves
/// the block accounting this row prices against parity without moving
/// the verdict).
///
/// `suffix` is what the first twin carries and the second does not: `.`
/// is M4-99, `\u{a0}` and ` ` are M4-80.
async fn trailing_twin_run(
    tag: &str,
    stem: &str,
    suffix: &str,
    damage: bool,
) -> (Fixture, String, bool, PathBuf, Vec<u8>, Vec<u8>) {
    let mut fx = Fixture::new(tag);
    let a = crate::payloads::unique_payload(120_000, 0x4d07_0099);
    let b = crate::payloads::unique_payload(120_000, 0x4d07_0080);
    fx.add_file_renamed_by_par2("zzzzzzzzzztrailA.bin", "Tr5jTn93GcW", &a, 40_000);
    fx.add_file_renamed_by_par2("zzzzzzzzzztrailB.bin", "Sp8pYw41SkV", &b, 40_000);
    let decorated = format!("{stem}{suffix}");
    let bare = stem.to_string();
    assert!(
        add_par2_patched(
            &mut fx,
            40,
            &["zzzzzzzzzztrailA.bin", "zzzzzzzzzztrailB.bin"],
            40_000,
            |blob| {
                assert!(rename_filedesc(blob, "zzzzzzzzzztrailA.bin", &decorated) > 0);
                assert!(rename_filedesc(blob, "zzzzzzzzzztrailB.bin", &bare) > 0);
            }
        ),
        "par2 create failed"
    );
    let chaos = if damage {
        // Sorted, not `find` - `articles` is a HashMap, so an unsorted
        // draw makes WHICH article is damaged depend on hash order and
        // the fixture stops being reproducible. `dot_twin_run` measured
        // two different pre-fix outcomes off that one choice.
        let mut ids: Vec<&String> = fx
            .articles
            .keys()
            .filter(|k| k.contains("Sp8pYw41SkV"))
            .collect();
        ids.sort();
        let id = ids
            .first()
            .copied()
            .expect("no article of the second file to damage")
            .clone();
        Chaos {
            corrupt: std::iter::once(id).collect(),
            ..Chaos::default()
        }
    } else {
        Chaos::default()
    };
    let (log, ok, out) = run_norar_chaos(&fx, chaos).await;
    (fx, log, ok, out, a, b)
}

/// M4-99, the CLEAN arm: both members arrive, so the publish guard sees
/// the collision and resolves it under the house `{slot:03}-`
/// convention. `None` because that path already named the landing -
/// see [`assert_twin_survived`] for the asymmetry.
#[tokio::test(flavor = "multi_thread")]
async fn a_trailing_dot_filedesc_twin_keeps_both_payloads() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (_fx, log, ok, out, a, b) = trailing_twin_run("traildot", "trailcol.bin", ".", false).await;
    assert_twin_survived(&log, ok, &out, &a, &b, "trailcol.bin", None);
}

/// M4-99, the DAMAGED arm - the one that made M4-66 worth fixing rather
/// than pinning as a pass, reached here through the trailing end of the
/// same trim. The damaged member never publishes, so the collision
/// falls to `par2repair`'s claim loop, which resolved it in silence
/// until 31 Aug 2026.
#[tokio::test(flavor = "multi_thread")]
async fn a_damaged_trailing_dot_twin_keeps_both_payloads() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (_fx, log, ok, out, a, b) =
        trailing_twin_run("traildotdmg", "trailcol.bin", ".", true).await;
    assert_twin_survived(
        &log,
        ok,
        &out,
        &a,
        &b,
        "trailcol.bin",
        Some("\"trailcol.bin.\""),
    );
}

/// M4-80's ASCII-space half, clean.
#[tokio::test(flavor = "multi_thread")]
async fn a_trailing_space_filedesc_twin_keeps_both_payloads() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (_fx, log, ok, out, a, b) =
        trailing_twin_run("trailspace", "spacecol.bin", " ", false).await;
    assert_twin_survived(&log, ok, &out, &a, &b, "spacecol.bin", None);
}

/// M4-80's NBSP half, damaged - the sharpest shape either row has.
///
/// U+00A0 is `White_Space`, so `str::trim` peels it exactly as it peels
/// an ASCII space; unlike a trailing dot it is legitimate in a release
/// name and INVISIBLE, so the two names a poster typed are
/// indistinguishable in a listing, in a raw log line and on disk. The
/// declared-name assertion is spelled `"spacecol.bin\u{a0}"` because
/// the log renders it with `{:?}` - that escape is the only place a
/// user can see the character that cost the name.
#[tokio::test(flavor = "multi_thread")]
async fn a_damaged_trailing_nbsp_twin_keeps_both_payloads() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (_fx, log, ok, out, a, b) =
        trailing_twin_run("trailnbspdmg", "spacecol.bin", "\u{a0}", true).await;
    assert_twin_survived(
        &log,
        ok,
        &out,
        &a,
        &b,
        "spacecol.bin",
        Some("\"spacecol.bin\\u{a0}\""),
    );
}

/// What both rows ask for, in the words the matrix uses: **two inodes**
/// - plus the account of it that neither row thought to ask for and
/// that nothing was giving.
///
/// The trailing trim cannot be made injective (see the section header),
/// so the two declared names legitimately arrive at one canonical
/// spelling and one of the pair has to wear a disambiguator. That is
/// the row's own acceptable outcome and is NOT what is asserted away
/// here: what is asserted is that no payload is lost, that the pair
/// really did collapse, and that the job log names the file the user is
/// left with.
///
/// WHICH DISAMBIGUATOR DEPENDS ON WHO RESOLVES IT, and that asymmetry
/// is measured rather than assumed - it is why `declared_in_log` is a
/// parameter instead of a constant:
///
///   * CLEAN, both members arrive: `unpack::PublishedNames` sees the
///     collision at publish time and the second member takes the
///     house `{slot:03}-` convention (`001-spacecol.bin`). The log's
///     `[extract] renamed <posted> → 001-<name>` line names it.
///   * DAMAGED, one member goes through repair: that member never
///     publishes, so the publish guard never fires, and the collision
///     is resolved instead by `par2repair`'s colliding-target claim,
///     which spells it `<name>.dup-<fid>`.
///
/// Before 31 Aug 2026 the second path was SILENT. The `.dup-` name
/// appeared nowhere in the log at rc=0, while `[extract] renamed
/// <posted> → <canonical>` was left standing about a file the repair
/// had since moved aside - so the last thing the log said about that
/// payload named a path it was not at. `declared_in_log` is `Some` for
/// exactly the arms that go through that path.
///
/// The declared name is spelled as Rust `{:?}` renders it because that
/// is how the log renders it, and for M4-80's NBSP half that is the
/// point: a trailing U+00A0 is invisible in a directory listing and in
/// a raw log line, and `\u{a0}` in the message is the only place a user
/// can SEE the character that cost the name.
fn assert_twin_survived(
    log: &str,
    ok: bool,
    out: &std::path::Path,
    a: &[u8],
    b: &[u8],
    canonical: &str,
    declared_in_log: Option<&str>,
) {
    assert!(ok, "trailing-twin post failed:\n{log}");
    let tree = out_tree(out);
    let shown = || tree.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>();
    let where_of = |want: &[u8]| {
        tree.iter()
            .find(|(_, got)| got.as_slice() == want)
            .map(|(n, _)| n.clone())
            .unwrap_or_else(|| "<nowhere>".to_string())
    };
    // Neither payload is lost. This is the half both rows predicted
    // would fail ("overwrite") and that was already held - by the
    // publish guard on one path and by `par2repair`'s colliding-target
    // claim on the other. Pinned rather than fixed, so a change to
    // either cannot quietly retire it.
    let (at_a, at_b) = (where_of(a), where_of(b));
    assert!(
        !at_a.is_empty() && at_a != "<nowhere>",
        "the decorated twin's payload is on disk nowhere: {:?}\n{log}",
        shown()
    );
    assert!(
        at_b != "<nowhere>",
        "the bare twin's payload is on disk nowhere: {:?}\n{log}",
        shown()
    );
    assert!(
        tree.iter().any(|(n, _)| n == canonical),
        "nobody landed under the canonical name {canonical:?}: {:?}\n{log}",
        shown()
    );
    // Exactly one of the two holds the canonical spelling and the other
    // wears a disambiguator. Without this a run where the pair stopped
    // colliding would satisfy everything above while exercising nothing
    // - the inert-fixture shape this repo refuses in as many words.
    let displaced = if at_a == canonical {
        at_b.clone()
    } else {
        at_a.clone()
    };
    assert!(
        at_a != at_b && displaced != canonical,
        "the two declared names did not collide at all, so this fixture \
         no longer exercises the row: decorated twin at {at_a:?}, bare \
         twin at {at_b:?}\n{log}"
    );
    // The half that was missing on the repair path: the log names the
    // file the user is actually left with.
    assert!(
        log.contains(&displaced),
        "the log never names {displaced:?}, the file the user is left \
         with: tree {:?}\n{log}",
        shown()
    );
    // And on that path it names the declared name that lost, which is
    // the only thing that tells a user WHY their `*arr` skipped it.
    if let Some(declared) = declared_in_log {
        assert!(
            log.contains(declared),
            "the log never names the declared name that lost the \
             collision ({declared}): tree {:?}\n{log}",
            shown()
        );
        // EXACTLY once, not once per pass. `dupclaim::disambiguate_colliding_targets`
        // runs fresh on every pass over this set (an individually-verified
        // publish pass and the repair proper both build their own `targets`
        // and neither can see the other), so its own per-pass account is
        // honest but repeats - measured at exactly two on this fixture
        // before the caller-side dedup. The account a HUMAN reads has to
        // say it once for the job, which is a fact about the caller
        // composing the job log, not about the per-pass account itself.
        let occurrences = log.matches(declared).count();
        assert_eq!(
            occurrences,
            1,
            "the collision account for {declared} appears {occurrences} time(s) in the \
             job log, not once - a job that repairs this set across more than one pass \
             must not repeat itself to the user: {:?}\n{log}",
            shown()
        );
    }
}
