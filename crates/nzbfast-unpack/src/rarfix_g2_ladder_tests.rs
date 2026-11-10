//! G2's size rule where the disk ladder MEASURES it (TODO 358, the
//! 9 Nov 2026 pre-release sweep, review lane 4 items 1, 3 and 4). The
//! verdict itself is pinned in `rarfix::vouch::tests`; these pin that
//! the bytes handed to it are the set's real size, on every arm that
//! can leave a set packed beside one that unpacked. A sibling file so
//! rarfix.rs stays under its size-gate ceiling (mod name matches the
//! file, so the gate classifies these fns as test code).

use super::vouch::{VouchVerdict, judge};
use super::*;
use std::path::Path;

fn g2_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("nzbfast-g2ladder-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn body(n: usize, seed: u8) -> Vec<u8> {
    (0..n as u32)
        .map(|i| (i as u8).wrapping_mul(29).wrapping_add(seed))
        .collect()
}

/// An old-style (`movie.rar`, `movie.r00` ... `movie.r18`) RAR 4 store
/// set: twenty 4 KB volumes, so the first volume is a twentieth of it.
fn old_style_main(dir: &Path) -> Vec<PathBuf> {
    let vols = crate::rarfixtures::rar4_stored_volume_set(b"movie.mkv", &body(80_000, 3), 4096);
    assert!(vols.len() >= 15, "the set did not split: {}", vols.len());
    vols.iter()
        .enumerate()
        .map(|(i, v)| {
            let name = if i == 0 {
                "movie.rar".to_string()
            } else {
                format!("movie.r{:02}", i - 1)
            };
            let p = dir.join(name);
            std::fs::write(&p, v).unwrap();
            p
        })
        .collect()
}

/// A single-volume extra of `n` payload bytes that unpacks.
fn good_extra(dir: &Path, n: usize) {
    let data = body(n, 7);
    let v = nzbkit::rar::fixtures::rar5_volume(&[("extra.mkv", n as u64, &data, false, false)]);
    std::fs::write(dir.join("extra.rar"), v).unwrap();
}

/// The first volume of a two-volume extra whose second volume never
/// arrived: headers fine, and no engine can finish the member.
fn broken_extra(dir: &Path, n: usize) {
    let data = body(n, 9);
    let v = nzbkit::rar::fixtures::rar5_volume(&[("extra.mkv", 2 * n as u64, &data, false, true)]);
    std::fs::write(dir.join("extra.part1.rar"), v).unwrap();
}

fn bytes_of(paths: &[PathBuf]) -> u64 {
    paths
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .sum()
}

/// Item 1, scenario A: no PAR2, an old-style main set missing one
/// volume, and a single-volume extra larger than ONE main volume but far
/// smaller than the set. `packed_groups` admits only `.rar` names (and
/// numeric ones), so the group it hands the ladder is `movie.rar` alone,
/// and the leftover was weighed at one volume: smaller than the extra
/// that unpacked, so the job completed with the film packed.
#[test]
fn an_old_style_main_set_is_weighed_by_every_volume_when_it_fails() {
    let dir = g2_dir("old-main-fails");
    let main = old_style_main(&dir);
    std::fs::remove_file(&main[10]).unwrap();
    let left: Vec<PathBuf> = main.iter().filter(|p| p.exists()).cloned().collect();
    good_extra(&dir, 8_000);

    let o = try_unrar_outcome(&dir, None).expect("the extra unpacked");
    assert_eq!(o.packed.len(), 1, "only the main set stayed packed");
    assert_eq!(
        o.packed[0].bytes,
        bytes_of(&left),
        "the leftover must be weighed over every volume on disk, .rNN included"
    );
    assert!(matches!(
        judge(&o.packed, None, o.largest_produced),
        VouchVerdict::MainPayload { .. }
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Item 1, scenario B, the reverse: the old-style main set unpacks and a
/// small broken extra beside it does not. Measured at its first volume
/// the main set looked SMALLER than the extra, which failed a job whose
/// release had landed.
#[test]
fn an_old_style_main_set_is_weighed_by_every_volume_when_it_unpacks() {
    let dir = g2_dir("old-main-unpacks");
    let main = old_style_main(&dir);
    let main_bytes = bytes_of(&main);
    broken_extra(&dir, 8_000);

    let o = try_unrar_outcome(&dir, None).expect("the main set unpacked");
    assert_eq!(
        o.largest_produced, main_bytes,
        "what unpacked must be weighed over every volume, .rNN included"
    );
    assert_eq!(
        judge(&o.packed, None, o.largest_produced),
        VouchVerdict::Tolerated(vec!["extra".into()])
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Item 3: the re-extract feed (resumed runs, and the re-extract after a
/// PAR2 repair) unpacks the main set in-stream and spends its volumes,
/// and only a small extra demotes and then fails on the unrar rung. That
/// returned the bare ladder refusal - the job failed "the verified
/// volumes on disk could not be extracted" with the release on disk.
/// The leftover is judged against the group that unpacked HERE instead.
#[test]
fn a_failed_extra_beside_a_main_set_the_feed_unpacked_is_judged_not_failed() {
    let dir = g2_dir("reex-extra");
    let main = body(300_000, 5);
    let v = nzbkit::rar::fixtures::rar5_volume(&[("main.mkv", 300_000, &main, false, false)]);
    std::fs::write(dir.join("main.rar"), v).unwrap();
    broken_extra(&dir, 8_000);

    let o = crate::repair::reextract_dir_outcome(&dir, None)
        .unwrap()
        .expect("a delivered main set beside a broken extra is not a failed re-extract");
    assert_eq!(std::fs::read(dir.join("main.mkv")).unwrap(), main);
    assert_eq!(
        judge(&o.packed, None, o.largest_produced),
        VouchVerdict::Tolerated(vec!["extra".into()])
    );
    assert!(
        dir.join("extra.part1.rar").exists(),
        "the extra stays for a hand unpack"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// ...and the same arm with the roles swapped: the in-feed group is the
/// small one, so the leftover is the main payload and still fails.
#[test]
fn a_failed_main_set_beside_a_small_set_the_feed_unpacked_still_fails() {
    let dir = g2_dir("reex-main");
    let small = body(8_000, 5);
    let v = nzbkit::rar::fixtures::rar5_volume(&[("small.mkv", 8_000, &small, false, false)]);
    std::fs::write(dir.join("small.rar"), v).unwrap();
    let big = body(300_000, 9);
    let v = nzbkit::rar::fixtures::rar5_volume(&[("film.mkv", 600_000, &big, false, true)]);
    std::fs::write(dir.join("film.part1.rar"), v).unwrap();

    let verdict = match crate::repair::reextract_dir_outcome(&dir, None).unwrap() {
        Ok(o) => judge(&o.packed, None, o.largest_produced),
        Err(_) => VouchVerdict::MainPayload {
            names: Vec::new(),
            reason: None,
        },
    };
    assert!(
        matches!(verdict, VouchVerdict::MainPayload { .. }),
        "{verdict:?}"
    );
    assert!(dir.join("film.part1.rar").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Item 4: an obfuscated RAR5 post, no PAR2, whose main set lost its
/// FIRST volume - every later volume is a headless fragment - beside a
/// sample that extracts. `ObfReport::ok` forgives strays once any set
/// produced, and the ladder answered an empty outcome: Completed with
/// the film packed and nothing named.
#[test]
fn obfuscated_strays_that_outweigh_what_unpacked_are_the_main_payload() {
    let dir = g2_dir("obf-strays");
    for n in 1..=3u32 {
        let piece = body(60_000, n as u8);
        let v = nzbkit::rar::fixtures::rar5_volume_n(
            &[("film.mkv", 240_000, &piece, true, n < 3)],
            n as u64,
        );
        std::fs::write(dir.join(format!("{:024x}", 0xa1b2c3u64 + n as u64)), v).unwrap();
    }
    let sample = body(20_000, 11);
    let v = nzbkit::rar::fixtures::rar5_volume(&[("sample.mkv", 20_000, &sample, false, false)]);
    std::fs::write(dir.join("0f9e8d7c6b5a49382716f5e4"), v).unwrap();

    let verdict = match try_unrar_outcome(&dir, None) {
        Ok(o) => judge(&o.packed, None, o.largest_produced),
        Err(_) => VouchVerdict::MainPayload {
            names: Vec::new(),
            reason: None,
        },
    };
    assert!(
        matches!(verdict, VouchVerdict::MainPayload { .. }),
        "{verdict:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// ...and the tolerance it must keep: ONE small stray beside a set that
/// unpacked is an extra - tolerated, and named.
#[test]
fn a_small_obfuscated_stray_beside_what_unpacked_is_tolerated_and_named() {
    let dir = g2_dir("obf-small-stray");
    let film = body(400_000, 1);
    let v = nzbkit::rar::fixtures::rar5_volume(&[("film.mkv", 400_000, &film, false, false)]);
    std::fs::write(dir.join("0f9e8d7c6b5a49382716f5e4"), v).unwrap();
    let piece = body(10_000, 2);
    let v = nzbkit::rar::fixtures::rar5_volume_n(&[("orphan.mkv", 300_000, &piece, true, true)], 2);
    std::fs::write(dir.join("3ab19f7c05e2d846b1cc90fa"), v).unwrap();

    let o = try_unrar_outcome(&dir, None).expect("the film unpacked");
    assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), film);
    match judge(&o.packed, None, o.largest_produced) {
        VouchVerdict::Tolerated(names) => {
            assert_eq!(names.len(), 1, "{names:?}");
            assert!(names[0].contains("3ab19f7c05e2d846b1cc90fa"), "{names:?}");
        }
        other => panic!("{other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}
