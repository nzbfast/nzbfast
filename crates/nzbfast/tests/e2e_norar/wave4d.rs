//! Wave-4 matrix-read FOURTH pins: rows M4-55 and M4-60.
//!
//! Both were PREDICTIONS from a matrix read, and both were measured on
//! the 30 Aug 2026 baseline before an assertion was written. M4-55 came
//! back FAILING and its fix is in `splitjoin.rs`; M4-60 came back GREEN
//! and is a PASS PIN, landed with the measurement rather than skipped.
//!
//! A CHILD of `e2e_norar` and not a sibling directory, for the reason
//! `pins.rs` records at length: `mod.rs` was inside 100 lines of its
//! 3,000-line size-gate ceiling with several M4 lanes still appending to
//! it, and a child module sees the parent's private builders through one
//! `use super::*` where a sibling would need each of them made
//! `pub(crate)` on lines those lanes are also editing.
//!
//! The other two rows of this lane are pinned where their subjects live,
//! not here - M4-59 in `nzbkit::yenc` and `nzbkit::pool::rig_tests`,
//! M4-61 in `nzbfast::unpack::publish_name_tests` - because both are
//! about one function's answer and an e2e would have measured the whole
//! pipeline to assert it.

use super::*;

/// M4-60 - FileDesc names carrying CR, LF, a CRLF pair, and a TRAILING
/// LF. PASS PIN.
///
/// MEASURED GREEN on the 30 Aug 2026 baseline: all four land contained,
/// byte-exact, under names whose control bytes became `_`, and the job
/// finishes rc=0. The row predicted "skipped create, leftover hash, or a
/// file whose name contains a newline that breaks the grader and
/// `read_dir` consumers"; none of that happens, because
/// `sanitize_filename_for` maps every `char::is_control` to `_` before a
/// name reaches the filesystem, so no control byte is ever written to a
/// directory entry.
///
/// Distinct from `hostile_filedesc_name_forms_land_contained_and_sanitized`
/// in `pins.rs`, which is M4-15 and covers the interior NUL, the NTFS
/// stream marker, UNC, absolute, drive-relative and mixed separators.
/// The bytes here are the ones that row did NOT ask about, and one of
/// them is asymmetric in a way only this row reaches: `parse_filedesc`
/// trims TRAILING NULs (the spec's own padding) and trims nothing else,
/// so a name ending in LF keeps it and lands as `movie4.mkv_` where a
/// name ending in NUL lands as `movie4.mkv`.
///
/// This is a pin against a future "tidy" edit, and the two directions it
/// guards are opposite: stripping controls to nothing would collapse two
/// distinct FileDesc names onto one output path, and passing them
/// through would put a newline in a directory entry.
#[tokio::test(flavor = "multi_thread")]
async fn control_bytes_in_a_filedesc_name_land_sanitized_and_charged() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    // Placeholders are all 28 bytes so each FileDesc name region is 28
    // and every patched name fits without resizing a packet.
    let cases: [(&str, &str, &str, usize, u8); 4] = [
        (
            "zzz-lf0-aaaaaaaaaaaaaaaa.bin",
            "movie.mkv\nhash",
            "movie.mkv_hash",
            30_000,
            111,
        ),
        (
            "zzz-cr0-bbbbbbbbbbbbbbbb.bin",
            "movie2.mkv\rhash",
            "movie2.mkv_hash",
            31_000,
            112,
        ),
        (
            "zzz-crlf-cccccccccccccccc.bin",
            "movie3.mkv\r\n.hash",
            "movie3.mkv__.hash",
            32_000,
            113,
        ),
        (
            "zzz-tlf-dddddddddddddddd.bin",
            "movie4.mkv\n",
            "movie4.mkv_",
            33_000,
            114,
        ),
    ];
    let mut fx = Fixture::new("norarctlbytes");
    let mut datas = Vec::new();
    for (i, (placeholder, _, _, size, seed)) in cases.iter().enumerate() {
        let data = payload(*size, *seed);
        fx.add_file_renamed_by_par2(placeholder, &format!("Cc{i}vNq83MtW"), &data, 40_000);
        datas.push(data);
    }
    let names: Vec<&str> = cases.iter().map(|c| c.0).collect();
    assert!(add_par2_patched(&mut fx, 20, &names, 40_000, |blob| {
        for (placeholder, hostile, _, _, _) in &cases {
            assert!(
                rename_filedesc(blob, placeholder, hostile) > 0,
                "the control-byte patch matched no FileDesc for {placeholder}"
            );
        }
    }));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "control-byte FileDesc post failed:\n{log}");
    for ((_, hostile, landed, _, _), want) in cases.iter().zip(&datas) {
        let got = std::fs::read(out.join(landed)).unwrap_or_else(|e| {
            panic!("M4-60: {hostile:?} did not land as {landed:?}: {e}\n{log}")
        });
        assert!(&got == want, "{landed} not byte-exact\n{log}");
    }
    // No control byte reached a directory entry, whatever else landed.
    for (name, _) in out_tree(&out) {
        assert!(
            !name.chars().any(char::is_control),
            "M4-60: a control byte reached a directory entry: {name:?}\n{log}"
        );
    }
    drop(fx);
}

/// M4-55 - a RAW byte split posted as `.part01` / `.part02`, with no
/// PAR2 anywhere and nothing else on the ladder that can open it.
///
/// MEASURED on the 30 Aug 2026 baseline: `numeric_tail` required the
/// last dot-tail to be 1-4 ASCII digits, so this pair was not a split
/// set at all and both halves were left loose in the output directory.
/// `raw_split_parts_named_by_filedesc_land_and_join` in `join.rs` is the
/// CONTROL - the same shape spelled `.001` / `.002` - so a red here is
/// the spelling and not the joiner.
///
/// Posted under the split names directly rather than renamed into them
/// by a FileDesc, which is the half M4-01's trap does not reach: with no
/// recovery set there is nothing to identify the parts, exclude them as
/// donors, or price a join as missing. What is left is exactly the
/// question the row asks - does the joiner recognise the grammar.
#[tokio::test(flavor = "multi_thread")]
async fn a_part_prefixed_raw_split_joins_end_to_end() {
    let mut fx = Fixture::new("norarpartsplit");
    let full = payload(200_000, 78);
    fx.add_file("Partsplit.mkv.part01", &full[..100_000], 40_000);
    fx.add_file("Partsplit.mkv.part02", &full[100_000..], 40_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "the .partNN split post failed:\n{log}");
    let joined = std::fs::read(out.join("Partsplit.mkv"))
        .unwrap_or_else(|e| panic!("M4-55: the .partNN halves did not join: {e}\n{log}"));
    assert!(joined == full, "the joined file is not byte-exact\n{log}");
    for part in ["Partsplit.mkv.part01", "Partsplit.mkv.part02"] {
        assert!(
            !out.join(part).exists(),
            "M4-55: {part} is spent and must be gone\n{log}"
        );
    }
    drop(fx);
}
