//! Bug sweep 9 Nov 2026, A13: the named-RAR arm read every `Ok` from the
//! disk ladder as `Produced`, and the ladder answers `Ok` as soon as ANY
//! stem group unpacked - the groups that failed ride out in
//! `UnpackOutcome::packed`. So a sample unpacking beside a main payload
//! that did not made the level a success, on the nested pass and on the
//! offline `nzbfast extract <dir>` alike. The tail already judged the top
//! level with `rarfix::vouch::judge`; these rows pin the same rule here,
//! and pin that the decoy tolerance it was built around still holds.
use super::*;
use crate::rarfixtures::{Member, stored_archive};
use crate::testscratch::ScratchDir;

fn tmpdir(tag: &str) -> (ScratchDir, PathBuf) {
    let d = std::env::temp_dir().join(format!(
        "nzbfast-partialset-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    (ScratchDir::attach(&d), d)
}

/// Bytes that do not repeat, so a flipped byte cannot land on a twin.
fn body(len: usize) -> Vec<u8> {
    (0..len as u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect()
}

/// A single-volume store-mode set holding `member`, optionally with one
/// payload byte flipped so its CRC refuses (the store fixture carries the
/// whole-file CRC on the member header - see `rarfixtures::stored_archive`).
fn write_set(d: &std::path::Path, name: &str, member: &str, data: &[u8], damaged: bool) {
    let mut bytes = stored_archive(&[Member::bare(member.as_bytes(), data)]);
    if damaged {
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
    }
    std::fs::write(d.join(name), bytes).unwrap();
}

/// THE DEFECT: the sample unpacks, the feature (forty times its size)
/// does not. The level must not read as unpacked - and nothing is
/// deleted on the way: the sample's payload and the feature's volume are
/// both still on disk.
#[test]
fn a_packed_main_payload_beside_an_unpacked_sample_fails_the_level() {
    let (_g, d) = tmpdir("main");
    let sample = body(5_000);
    write_set(&d, "Sample.Clip.2026-GRP.rar", "sample.mkv", &sample, false);
    write_set(
        &d,
        "Feature.Film.2026-GRP.rar",
        "feature.mkv",
        &body(200_000),
        true,
    );

    let mut why = None;
    let got = extract_nested_why(&d, None, 0, &mut why, None).unwrap();
    assert_eq!(
        got,
        NestOutcome::Failed,
        "a packed main payload is not Produced"
    );
    let why = why.expect("the level names what stayed packed");
    assert!(why.contains("main payload"), "{why}");
    assert!(why.contains("feature.film"), "{why}");

    assert_eq!(
        std::fs::read(d.join("sample.mkv")).unwrap(),
        sample,
        "what did unpack stays on disk"
    );
    assert!(
        d.join("Feature.Film.2026-GRP.rar").is_file(),
        "the volume that did not unpack is kept for a retry"
    );
}

/// The offline `nzbfast extract <dir>` path reaches the same arm and
/// must exit nonzero on the same shape.
#[test]
fn offline_extract_fails_on_a_packed_main_payload() {
    let (_g, d) = tmpdir("offline");
    write_set(
        &d,
        "Sample.Clip.2026-GRP.rar",
        "sample.mkv",
        &body(5_000),
        false,
    );
    write_set(
        &d,
        "Feature.Film.2026-GRP.rar",
        "feature.mkv",
        &body(200_000),
        true,
    );
    assert!(!extract_local(&d, None).unwrap());
    assert!(d.join("sample.mkv").is_file());
}

/// CONTROL: the decoy tolerance. A SMALL damaged set beside a release
/// that unpacked is a decoy (or a corrupt sample), and must not fail a
/// good job - the rule `vouch` was written to keep.
#[test]
fn a_small_damaged_decoy_beside_an_unpacked_release_keeps_the_tolerance() {
    let (_g, d) = tmpdir("decoy");
    let feature = body(200_000);
    write_set(
        &d,
        "Feature.Film.2026-GRP.rar",
        "feature.mkv",
        &feature,
        false,
    );
    write_set(
        &d,
        "Sample.Clip.2026-GRP.rar",
        "sample.mkv",
        &body(5_000),
        true,
    );

    let mut why = None;
    let got = extract_nested_why(&d, None, 0, &mut why, None).unwrap();
    assert_eq!(got, NestOutcome::Produced);
    assert_eq!(why, None);
    assert_eq!(std::fs::read(d.join("feature.mkv")).unwrap(), feature);
}

/// CONTROL: both sets unpack - nothing is left packed and the level is
/// Produced exactly as before.
#[test]
fn two_sets_that_both_unpack_are_produced() {
    let (_g, d) = tmpdir("both");
    write_set(
        &d,
        "Feature.Film.2026-GRP.rar",
        "feature.mkv",
        &body(200_000),
        false,
    );
    write_set(
        &d,
        "Sample.Clip.2026-GRP.rar",
        "sample.mkv",
        &body(5_000),
        false,
    );
    assert_eq!(extract_nested(&d, None, 0).unwrap(), NestOutcome::Produced);
    assert!(d.join("feature.mkv").is_file() && d.join("sample.mkv").is_file());
}
