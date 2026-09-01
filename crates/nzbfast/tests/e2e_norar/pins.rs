//! Wave-4 matrix-read PINS: rows M4-10, M4-15 and M4-17.
//!
//! Cheap composition and hostile pins - an engineered CRC32 collision,
//! the FileDesc name forms the sanitizer had never been asked, and the
//! two split shapes `splitjoin` correctly refuses while PAR2 adoption
//! must still harvest. Every row here PREDICTED an outcome and was
//! measured on the 30 Aug 2026 baseline (origin/main 8fbe1c3bd) before
//! its assertion was written; the verdict each one came back with is
//! recorded in its own comment.
//!
//! A CHILD of `e2e_norar` rather than a sibling of it, which is the
//! whole reason this file exists: `mod.rs` was 8 lines under its 3,000
//! size-gate ceiling with several M4 lanes still appending to it, and a
//! child module sees the parent's private items through `use super::*`
//! where a sibling directory would need every builder made `pub(crate)`
//! on lines those lanes are also editing.

use super::*;
use crate::payloads;

/// Row M4-10 - an ENGINEERED CRC32 collision across two SFV entries.
/// MEASURED GREEN on the 30 Aug 2026 baseline (origin/main 8fbe1c3bd):
/// both entries declined, both payloads kept their posted hashes, rc=0.
/// This is a PASS pin, and the row exists because the decline is one
/// `retain` on each side of the match - a future "just take the first"
/// edit reads as a tidy-up and would hand a 32-bit coincidence the
/// authority of a name.
///
/// The collision needs no search: appending a message's own CRC32 in
/// little-endian drives EVERY message to the same residue (0x2144DF1C),
/// which is the standard CRC self-check identity. So two unrelated
/// payloads carry one checksum, exactly, by construction.
///
/// Distinct from `duplicate_sums_are_ambiguity_not_a_choice` in
/// `sfvname.rs`, which is one NAME listed twice - here the sidecar is
/// internally consistent and it is the FILES that collide, which is the
/// half `files_by_sum` has to catch. `an_sfv_sidecar_names_the_post` is
/// the CONTROL for this row: the same fixture shape with two DISTINCT
/// CRC32s lands both names, so a red here is the collision and not the
/// sidecar wiring.
#[tokio::test(flavor = "multi_thread")]
async fn an_engineered_crc32_collision_across_two_sfv_entries_declines_both() {
    let mut fx = Fixture::new("norarcrccol");
    let mut alpha = payload(60_000, 91);
    alpha.extend_from_slice(&crc32fast::hash(&alpha).to_le_bytes());
    let mut beta = payload(45_000, 92);
    beta.extend_from_slice(&crc32fast::hash(&beta).to_le_bytes());
    let crc = crc32fast::hash(&alpha);
    assert_eq!(
        crc,
        crc32fast::hash(&beta),
        "the fixture's CRC32 collision was not engineered"
    );
    assert!(alpha != beta, "the two payloads must be distinct files");
    let sfv = format!("Real.Alpha.mkv {crc:08X}\r\nReal.Beta.mkv {crc:08X}\r\n");
    fx.add_file_obfuscated("Pw4kTn86ZmR", "Pw4kTn86ZmR", &alpha, 40_000);
    fx.add_file_obfuscated("Dh7xVc29LbQ", "Dh7xVc29LbQ", &beta, 40_000);
    fx.add_file("release.sfv", sfv.as_bytes(), 40_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "crc-collision sfv post failed outright:\n{log}");
    assert!(
        !out.join("Real.Alpha.mkv").exists() && !out.join("Real.Beta.mkv").exists(),
        "M4-10: a colliding CRC32 was taken as a name - one 32-bit \
         coincidence is not evidence:\n{log}"
    );
    let got_alpha = std::fs::read(out.join("Pw4kTn86ZmR"))
        .unwrap_or_else(|e| panic!("alpha missing under its posted hash: {e}\n{log}"));
    let got_beta = std::fs::read(out.join("Dh7xVc29LbQ"))
        .unwrap_or_else(|e| panic!("beta missing under its posted hash: {e}\n{log}"));
    assert!(
        got_alpha == alpha && got_beta == beta,
        "a declined payload was not delivered byte-exact\n{log}"
    );
}

/// Row M4-15 - the hostile FileDesc name forms nothing had asked the
/// sanitizer about. MEASURED GREEN on the 30 Aug 2026 baseline: all six
/// landed at the names asserted below, byte-exact, nothing outside the
/// job directory. A PASS pin, and the reason to have it is that every
/// one of these is a security answer rather than a cosmetic one, and
/// four of the six are decided by ONE `return None` in
/// `sanitize_relpath_for` that a tree-preserving rewrite would move.
///
/// Six forms, and what decides each:
/// * interior NUL - `parse_filedesc` trims only TRAILING zeros, so the
///   NUL survives into the `String`; `sanitize_filename_for` maps it to
///   `_` like any other control byte, which is what stops a Unix
///   `create` truncating the name at it.
/// * NTFS alternate data stream - `:` carries stream meaning on
///   Windows only, and is legal and common in Unix release names
///   ("Movie: The Sequel.mkv"), so the mapping is deliberately
///   platform-conditional. What is NOT conditional is the invariant:
///   no second fork, and a full-length visible file either way.
/// * UNC and absolute - both start with a separator, so relpath
///   refuses and the flat form contains them.
/// * drive-relative - `C:\...` is a path escape on Windows however it
///   is joined (`PathBuf::push` DISCARDS the base for a prefixed
///   piece), and is refused on every platform rather than mapped.
/// * mixed separators - a Windows MultiPar `VIDEO_TS\VTS_01_1.VOB` is
///   a TREE and must land as one. See
///   `a_directory_tree_in_filedesc_names_lands_intact` for the
///   forward-slash control; the backslash spelling had no row.
#[tokio::test(flavor = "multi_thread")]
async fn hostile_filedesc_name_forms_land_contained_and_sanitized() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    // Placeholders are all 28 bytes so every FileDesc name region is 28
    // and each patched name (longest: 24) fits without resizing a packet.
    let cases: [(&str, &str, &str, usize, u8); 6] = [
        (
            "zzz-nul-aaaaaaaaaaaaaaaa.bin",
            "foo\0bar.mkv",
            "foo_bar.mkv",
            30_000,
            101,
        ),
        (
            "zzz-ads-bbbbbbbbbbbbbbbb.bin",
            "payload.mkv:hidden",
            if cfg!(windows) {
                "payload.mkv_hidden"
            } else {
                "payload.mkv:hidden"
            },
            31_000,
            102,
        ),
        (
            "zzz-unc-cccccccccccccccc.bin",
            "\\\\evilhost\\share\\loot.bin",
            "__evilhost_share_loot.bin",
            32_000,
            103,
        ),
        (
            "zzz-abs-dddddddddddddddd.bin",
            "/etc/passwd",
            "_etc_passwd",
            33_000,
            104,
        ),
        (
            "zzz-drv-eeeeeeeeeeeeeeee.bin",
            "C:\\Windows\\notepad.exe",
            if cfg!(windows) {
                "C__Windows_notepad.exe"
            } else {
                "C:_Windows_notepad.exe"
            },
            34_000,
            105,
        ),
        (
            "zzz-sep-ffffffffffffffff.bin",
            "VIDEO_TS\\VTS_01_1.VOB",
            "VIDEO_TS/VTS_01_1.VOB",
            35_000,
            106,
        ),
    ];
    let mut fx = Fixture::new("norarhostile2");
    let mut datas = Vec::new();
    for (i, (placeholder, _, _, size, seed)) in cases.iter().enumerate() {
        let data = payload(*size, *seed);
        fx.add_file_renamed_by_par2(placeholder, &format!("Hh{i}vNq83MtW"), &data, 40_000);
        datas.push(data);
    }
    let names: Vec<&str> = cases.iter().map(|c| c.0).collect();
    assert!(add_par2_patched(&mut fx, 20, &names, 40_000, |blob| {
        for (placeholder, hostile, _, _, _) in &cases {
            assert!(
                rename_filedesc(blob, placeholder, hostile) > 0,
                "the hostile-name patch matched no FileDesc for {placeholder}"
            );
        }
    }));
    // The fixture dir is `out`'s parent: nothing may appear beside it.
    let before: HashSet<String> = std::fs::read_dir(&fx.dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "hostile-name post failed:\n{log}");
    for ((_, hostile, landed, _, _), want) in cases.iter().zip(&datas) {
        let path = landed.split('/').fold(out.clone(), |p, c| p.join(c));
        let got = std::fs::read(&path).unwrap_or_else(|e| {
            panic!("M4-15: {hostile:?} did not land as {landed:?}: {e}\n{log}")
        });
        assert!(&got == want, "{landed} not byte-exact\n{log}");
    }
    let after: HashSet<String> = std::fs::read_dir(&fx.dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    // `run_norar` writes the config and the NZB into `fx.dir` itself,
    // AFTER the snapshot above - so those three are the fixture's own
    // and everything else is an escape.
    let strays: Vec<&String> = after
        .difference(&before)
        .filter(|n| !matches!(n.as_str(), "out" | "config.json" | "test.nzb"))
        .collect();
    assert!(
        strays.is_empty(),
        "M4-15: a hostile FileDesc name escaped the output directory: {strays:?}\n{log}"
    );
}

/// Row M4-17a - a GAP in the middle of a split run, with the FileDesc
/// naming the JOIN. `collect_split_sets` refuses `.001 .002 .004 .005`
/// (rule 1 wants exactly `1..=n`), and that refusal is CORRECT for a
/// joiner: concatenating around a hole produces a file that is not the
/// payload. The recovery set's answer is a different one - the parts are
/// unclaimed, so adoption harvests every block that survives in them and
/// spends parity only on the hole.
///
/// Part boundaries are block-aligned here (64,000-byte parts, a
/// 16,000-byte PAR2 block) so the arithmetic is exact and readable: 20
/// blocks, part 3's four missing, 16 adoptable, and r=60 buys 12. Off
/// that alignment the two blocks straddling each boundary would need
/// parity too - a real cost, but not the one this row is about.
///
/// `a_filedesc_naming_the_join_of_posted_halves_assembles` (F7) is the
/// CONTROL: the same shape with NO gap. So a red here is the hole and
/// not the join-naming machinery.
#[tokio::test(flavor = "multi_thread")]
async fn a_gap_in_split_parts_still_harvests_under_a_join_filedesc() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norargapjoin");
    let full = payloads::unique_payload(320_000, 76);
    std::fs::write(fx.dir.join("Gapjoin.mkv"), &full).unwrap();
    assert!(fx.add_par2_opts(60, Some(16_000), &["Gapjoin.mkv"], 40_000));
    std::fs::remove_file(fx.dir.join("Gapjoin.mkv")).unwrap();
    // Parts 1, 2, 4, 5 posted under their real split names; part 3
    // (bytes 128,000..192,000) never posted at all.
    for part in [1usize, 2, 4, 5] {
        let lo = (part - 1) * 64_000;
        fx.add_file(
            &format!("Gapjoin.mkv.{part:03}"),
            &full[lo..lo + 64_000],
            40_000,
        );
    }
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "the gapped-split post failed:\n{log}");
    let assembled = std::fs::read(out.join("Gapjoin.mkv")).unwrap_or_else(|e| {
        panic!(
            "M4-17a: the join never landed - the surviving parts' blocks \
             were not harvested for the FileDesc that names them: {e}\n{log}"
        )
    });
    assert!(assembled == full, "the join is not byte-exact\n{log}");
    // The recovery-spend bound, and the whole claim of the row. 20
    // blocks: part 1 is claimed as the target itself and verifies its 4
    // in-stream, 12 more are harvested off disk from parts 2/4/5, and
    // parity buys back only the 4 the hole took with it.
    assert!(
        log.contains("12 block(s) adopted from") && log.contains("4 block(s) rebuilt"),
        "M4-17a: the join landed, but not by harvesting - the geometry \
         says 12 blocks adopted and 4 rebuilt from parity\n{log}"
    );
    // No lost output: a part that survived the run must still be its own
    // bytes, never a half-consumed source.
    for part in [1usize, 2, 4, 5] {
        let lo = (part - 1) * 64_000;
        let p = out.join(format!("Gapjoin.mkv.{part:03}"));
        if let Ok(got) = std::fs::read(&p) {
            assert!(
                got == full[lo..lo + 64_000],
                "surviving part {part} is not byte-exact\n{log}"
            );
        }
    }
}

/// Row M4-17b - a "smart split" on NON-UNIFORM boundaries (scene cuts,
/// not a byte count), with the FileDesc naming the JOIN. Rule 4 of
/// `collect_split_sets` wants every part but the last the same size, so
/// the joiner refuses - again correctly, because unequal parts are the
/// signature of a volume set rather than a byte split.
///
/// Every boundary here IS block-aligned, so the whole join sits in the
/// parts and the expected recovery spend is ZERO: this is the row that
/// says adoption assembles from bytes on disk rather than buying them
/// back from parity. It is also the pin the row was asked for - a future
/// "join first, then repair" reorder that consumed or deleted the parts
/// before the harvest would take the join with it.
///
/// M4-17a above is the GAP; this one is complete and merely uneven.
#[tokio::test(flavor = "multi_thread")]
async fn a_non_uniform_smart_split_assembles_under_a_join_filedesc() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarsmartjoin");
    // "The expected recovery spend is ZERO", above, spelled where
    // `refuse_a_solve_that_solved_nothing` reads it. Worth noting which
    // way round the two facts sit: this row adopts every block on a
    // generator that has no repeating block at all, so adopting
    // everything is a property of a block-aligned split under a join
    // FileDesc and not of any payload's algebra. A screen keyed on
    // `payload(` could not have found it at any width, which is why
    // that guard reads the repair line instead.
    crate::adoptguard::adoption_is_the_premise(
        &fx.dir,
        "every boundary is block-aligned, so the whole join sits in the \
         parts and assembling it out of them rather than out of parity \
         is what the row asserts",
    );
    let full = payloads::unique_payload(300_000, 77);
    std::fs::write(fx.dir.join("Smartjoin.mkv"), &full).unwrap();
    assert!(fx.add_par2_opts(20, Some(12_500), &["Smartjoin.mkv"], 40_000));
    std::fs::remove_file(fx.dir.join("Smartjoin.mkv")).unwrap();
    for (part, lo, hi) in [
        (1usize, 0usize, 50_000usize),
        (2, 50_000, 175_000),
        (3, 175_000, 300_000),
    ] {
        fx.add_file(&format!("Smartjoin.mkv.{part:03}"), &full[lo..hi], 40_000);
    }
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "the smart-split post failed:\n{log}");
    let assembled = std::fs::read(out.join("Smartjoin.mkv")).unwrap_or_else(|e| {
        panic!(
            "M4-17b: the join never landed - uneven parts the joiner \
             refuses were not harvested for the FileDesc: {e}\n{log}"
        )
    });
    assert!(assembled == full, "the join is not byte-exact\n{log}");
    // Every boundary is block-aligned and every part was posted, so the
    // whole join is on disk already: the correct parity spend is ZERO.
    assert!(
        log.contains("20 block(s) adopted from") && log.contains("0 block(s) rebuilt"),
        "M4-17b: the join was bought back from parity instead of \
         harvested - all 20 blocks sit in the posted parts\n{log}"
    );
}
