//! Wave-4 matrix-read row M4-101: an SFX is a PROGRAM, not a name.
//!
//! The row was a PREDICTION and came back RED. Measured on the 30 Aug
//! 2026 baseline and re-measured on origin/main 31 Aug before a line was
//! written: a `feature.bin` of ordinary dump bytes with a real RAR
//! volume at offset 1024 is chased as a self-extractor by the offset-0
//! sniff, the volume's inner file is published, and the `.bin` the user
//! asked for is GONE from the output tree - with the job reporting
//! success. A `mode=raw` or Blu-ray STREAM dump is exactly that shape.
//!
//! The row's own remedy - never on a `.bin` that is also a video or
//! disc dump - is REFUTED, and that refutation is the finding rather
//! than a detail: `.bin` is this product's commonest OBFUSCATED-volume
//! extension (nine nzbkit tests model an obfuscated post as
//! `bbbb1234.bin`), so a deny list breaks the obfuscated path outright,
//! which is the path the whole one-pass design exists for. That is why
//! `.bin` is absent from `nzbkit::extract::names::PAYLOAD_CONTENT_EXTS`
//! and must stay absent.
//!
//! The answer is structural instead - `nzbkit::sfx::is_launcher_stub`,
//! whose header carries the reasoning and the rejected alternative. Both
//! fixtures below carry the SAME archive at the SAME offset under the
//! SAME name; only the PREFIX differs, so a rule that went back to
//! reading the extension fails one of them.
//!
//! A CHILD of `e2e_norar` for `pins.rs`'s reason, unchanged: `mod.rs` is
//! inside its 3,000-line size-gate ceiling with several M4 lanes still
//! appending to it, and a child sees the parent's private builders
//! through one `use super::*` where a sibling directory would need each
//! of them made `pub(crate)` on lines those lanes are also editing.

use super::*;

/// A real RAR5 volume, off the vendored fixture tree. Chance magic will
/// not do: the sniff CONFIRMS a CRC-valid main header behind every
/// signature it finds, so only a genuine archive reaches the question
/// this row is about.
fn real_rar_volume() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vendor/rars/tests/fixtures/rar50/solid.rar"
    ))
    .unwrap()
}

/// Transport-stream sync bytes: a dump, with no program header anywhere
/// in it. The thing an `.exe`/`.bin`/`.sfx` name cannot distinguish from
/// a launcher stub.
fn dump_prefix(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| {
            if i % 188 == 0 {
                0x47u8
            } else {
                (i as u8).wrapping_mul(7)
            }
        })
        .collect()
}

/// The three fields `nzbkit::sfx::is_launcher_stub` reads of a PE, then
/// filler - the minimum that makes these bytes a program.
fn program_prefix(n: usize) -> Vec<u8> {
    let mut v = vec![0x90u8; n.max(0x44)];
    v[0..2].copy_from_slice(b"MZ");
    v[2..0x40].fill(0);
    v[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    v[0x40..0x44].copy_from_slice(b"PE\0\0");
    v
}

/// M4-101: the dump lands as ITSELF, byte-exact, and nothing inside it
/// is published. This is the assertion that was failing on origin/main.
#[tokio::test(flavor = "multi_thread")]
async fn a_bin_dump_carrying_an_archive_is_not_exploded_as_a_self_extractor() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarsfxdump");
    let mut data = dump_prefix(1024);
    data.extend_from_slice(&real_rar_volume());
    fx.add_file("feature.bin", &data, 40_000);
    assert!(fx.add_par2(20, &["feature.bin"], 40_000));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "the dump post failed:\n{log}");

    let got = std::fs::read(out.join("feature.bin")).unwrap_or_else(|e| {
        let tree: Vec<String> = out_tree(&out)
            .into_iter()
            .map(|(n, b)| format!("{n:?} ({} bytes)", b.len()))
            .collect();
        panic!(
            "the dump never landed - it was taken for a self-extractor \
             and unpacked over the user's file: {e}; tree: {tree:?}\n{log}"
        )
    });
    assert!(got == data, "the dump is not byte-exact\n{log}");
    // `solid.rar`'s own members. Naming them, rather than pinning the
    // whole tree, is what makes this an assertion about EXPLODING and
    // not about whatever else a norar run leaves beside the payload.
    let names: Vec<String> = out_tree(&out).into_iter().map(|(n, _)| n).collect();
    for member in ["hello.txt", "tiny.txt"] {
        assert!(
            !names.contains(&member.to_string()),
            "the archive inside the dump was unpacked over the user's \
             file: {names:?}\n{log}"
        );
    }
}

/// The negative control, and it is the half that makes the test above
/// mean something: the SAME archive at the SAME offset under the SAME
/// name, behind a real program, is still a self-extractor and is still
/// unpacked in-stream. A fix that switched the feature off rather than
/// narrowing it passes the row above and fails here.
#[tokio::test(flavor = "multi_thread")]
async fn the_same_archive_behind_a_real_program_is_still_a_self_extractor() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarsfxprog");
    let mut data = program_prefix(1024);
    data.extend_from_slice(&real_rar_volume());
    fx.add_file("feature.bin", &data, 40_000);
    assert!(fx.add_par2(20, &["feature.bin"], 40_000));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "the self-extractor post failed:\n{log}");
    let names: Vec<String> = out_tree(&out).into_iter().map(|(n, _)| n).collect();
    for member in ["hello.txt", "tiny.txt"] {
        assert!(
            names.contains(&member.to_string()),
            "the self-extractor was left packed - the rule narrowed the \
             feature out of existence rather than narrowing it: \
             {names:?}\n{log}"
        );
    }
    // ...and it went through the one-pass mapper rather than to disk,
    // which is the whole point of the in-stream arm: the stub itself
    // never lands.
    assert!(
        !names.contains(&"feature.bin".to_string()),
        "the self-extractor materialized whole: {names:?}\n{log}"
    );
}
