//! Two FileDescs that sanitize to ONE name AT the component cap.
//!
//! The colliding-target guard gives the second one a `.dup-<fid>`
//! destination, and it composed that 17-byte tag onto a leaf
//! `sanitize_out_name` had already capped at 255 bytes - so the
//! repaired file had nowhere to land. Measured on APFS 31 Aug 2026: a
//! 255-byte component creates and 256 is `ENAMETOOLONG` for both
//! `mkdir` and `create`, so a 272-byte one is not a name at all.
//!
//! A child of `unit_tests` for its fixture helpers - `payload`,
//! `par2_index`, `par2_volume`, `tmpdir`, `BS`, `SET` - and because
//! `unit_tests.rs` sits inside 2% of its size-gate ceiling.

use super::*;

/// The overlong stem both descriptors are built from. Any name past
/// the cap comes back at EXACTLY the cap, which is the whole premise:
/// capping is what produced the name the tag is then added to.
fn colliding_names() -> (String, String) {
    let long = "y".repeat(400);
    // An empty component puts the first on the flatten fallback, where
    // separators become `_` - so the two are distinct set members that
    // spell one on-disk name.
    (format!("sub//{long}"), format!("sub__{long}"))
}

#[test]
fn a_dup_suffixed_target_at_the_cap_is_still_a_name_the_disk_takes() {
    let dir = tmpdir("dupnamecap");
    let (first, second) = colliding_names();
    let one = crate::disk::sanitize_out_name(&first);
    assert_eq!(one.len(), 255, "the premise moved");
    assert_eq!(one, crate::disk::sanitize_out_name(&second));

    let a = payload(200, 3);
    let b = payload(97, 4);
    let files: &[(&str, &[u8])] = &[(first.as_str(), &a), (second.as_str(), &b)];
    // Only ONE file can sit at the shared name; the other descriptor's
    // bytes have to be rebuilt onto a disambiguated destination.
    std::fs::write(dir.join(&one), &a).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    std::fs::write(
        dir.join("set.vol0+4.par2"),
        par2_volume(SET, BS, files, &[0, 1, 2, 3]),
    )
    .unwrap();

    let report = match repair_dir(&dir).expect("the set repairs") {
        RepairStatus::Repaired(r) => r,
        other => panic!("expected Repaired, got {other:?}"),
    };
    assert_eq!(report.files_created.len(), 1, "{report:?}");

    // Both payloads on disk, each under a name the filesystem accepted,
    // and no component past the cap.
    let mut got: Vec<Vec<u8>> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_none_or(|x| x != "par2"))
        .inspect(|p| {
            let leaf = p.file_name().unwrap().to_string_lossy().into_owned();
            assert!(leaf.len() <= 255, "{} bytes on disk", leaf.len());
        })
        .map(|p| std::fs::read(p).unwrap())
        .collect();
    got.sort();
    let mut want = vec![a, b];
    want.sort();
    assert_eq!(got, want, "each descriptor must get its own bytes");
    let _ = std::fs::remove_dir_all(&dir);
}
