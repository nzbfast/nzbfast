//! Numeric-only RAR volume sets (`film.001`, `film.002` …) on the disk
//! ladder. Lives in a sibling file so rarfix.rs stays under the size-gate
//! ceiling (mod name matches the file, so the gate classifies these fns
//! as test code).

use super::*;

fn numeric_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("nzbfast-numvol-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// One store-mode payload split across two real RAR5 volumes.
fn two_volumes(total: &[u8]) -> [Vec<u8>; 2] {
    use nzbkit::rar::fixtures;
    let n = total.len() as u64;
    let half = total.len() / 2;
    [
        fixtures::rar5_volume_n(&[("film.mkv", n, &total[..half], false, true)], 0),
        fixtures::rar5_volume_n(&[("film.mkv", n, &total[half..], true, false)], 1),
    ]
}

fn payload() -> Vec<u8> {
    (0..400_000u32)
        .map(|i| (i as u8).wrapping_mul(17).wrapping_add(3))
        .collect()
}

/// WinRAR's numeric naming has no `.rar` anywhere, so `release_stem` -
/// which deliberately keeps a bare numeric tail, because `Backup.2019.001`
/// is one release in the index - gave every volume its own stem. The set
/// arrived at the extractor as ONE volume of a split archive ("RAR 5 split
/// entry is incomplete"), which then fell back to an unrar that a default
/// install and the release image do not ship: a failed job with the whole
/// set sitting on disk, unpackable natively all along.
#[test]
fn numeric_only_rar_set_extracts_natively_as_a_whole_set() {
    let total = payload();
    let vols = two_volumes(&total);
    let dir = numeric_dir("numeric-set");
    std::fs::write(dir.join("film.001"), &vols[0]).unwrap();
    std::fs::write(dir.join("film.002"), &vols[1]).unwrap();

    // The volume set the unpack reads - and the set the caller deletes as
    // spent - must be BOTH volumes.
    let set = stem_volume_set(&dir, &dir.join("film.001")).unwrap();
    assert_eq!(set.len(), 2, "both numeric volumes belong to the set");

    // Deliberately the native extractor, not `try_unrar`: it is the only
    // engine a default install has, so a dev box that happens to carry
    // unrar in $PATH cannot mask the failure.
    let consumed = try_rars_native(&dir, &dir.join("film.001"), None).unwrap();
    assert_eq!(consumed.len(), 2);
    assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The numeric key is scoped to a RAR-magic lead volume for exactly this
/// reason: a byte-split `.7z.001`/`.zip.001` set belongs to another arm of
/// the ladder, and whatever this function reports gets DELETED as spent.
#[test]
fn numeric_grouping_never_swallows_a_foreign_split_container() {
    let total = payload();
    let vols = two_volumes(&total);
    let dir = numeric_dir("foreign-parts");
    std::fs::write(dir.join("film.001"), &vols[0]).unwrap();
    std::fs::write(dir.join("film.002"), &vols[1]).unwrap();
    // Same numeric base, no Rar! magic: somebody else's bytes.
    std::fs::write(dir.join("film.003"), b"PK\x03\x04not a rar volume").unwrap();

    let set = stem_volume_set(&dir, &dir.join("film.001")).unwrap();
    let names: Vec<String> = set
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["film.001".to_string(), "film.002".to_string()]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Named sets stay on exactly the old path: the numeric key only engages
/// when the FIRST volume is itself a magic-carrying numeric volume, so a
/// `.rar`/`.rNN` lead still groups by release stem and a numeric-named
/// stranger beside it is not adopted.
#[test]
fn a_named_lead_still_groups_by_release_stem() {
    let total = payload();
    let vols = two_volumes(&total);
    let dir = numeric_dir("named-lead");
    std::fs::write(dir.join("film.rar"), &vols[0]).unwrap();
    std::fs::write(dir.join("film.r00"), &vols[1]).unwrap();
    std::fs::write(dir.join("other.001"), &vols[0]).unwrap();

    let set = stem_volume_set(&dir, &dir.join("film.rar")).unwrap();
    let names: Vec<String> = set
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["film.rar".to_string(), "film.r00".to_string()]);
    let _ = std::fs::remove_dir_all(&dir);
}
