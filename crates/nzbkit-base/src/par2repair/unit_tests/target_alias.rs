//! Parfast sweep (9 Nov 2026), Repair orchestration: a second NAME for
//! a target's own file object must never become an adoption donor.
//!
//! The candidate walk excluded targets by a SPELLING key
//! (`path_identity_key`), and `disk::case_fold_key` does no Unicode
//! normalization. On APFS - case-sensitive or not, it is normalization-
//! insensitive - a member the set names in NFC and the file on disk
//! spelled in NFD are one directory entry, so the target's own file was
//! walked as a foreign candidate. Once it had donated a block and the
//! repair had made its bytes the target's, `adopt::spent_donors` proved
//! it spent: `consumed_sources` named the repaired member itself, and a
//! caller that deletes spent donors (the daemon's sweep, parfast's
//! purge) deletes it through the alias.
//!
//! A HARD LINK is the same shape on every platform - two names, one file
//! object, spellings that no fold relates - so it is the fixture here;
//! the NFD spelling is exercised too where the volume is
//! normalization-insensitive. A CHILD of `unit_tests` for
//! `padded_windows`' two reasons.

use super::*;

/// `t.bin` is damaged and identified; `u.bin` is absent and its first
/// block is byte-identical to `t.bin`'s third, so whatever second name
/// `t.bin` has is a candidate that can DONATE that block.
fn aliased_set(tag: &str) -> (PathBuf, Vec<u8>, Vec<u8>) {
    let dir = tmpdir(tag);
    let t = payload(BS * 4, 71);
    let mut u = payload(BS * 2, 72);
    u[..BS].copy_from_slice(&t[BS * 2..BS * 3]);
    let files: &[(&str, &[u8])] = &[("t.bin", &t), ("u.bin", &u)];
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    std::fs::write(
        dir.join("set.vol0+4.par2"),
        par2_volume(SET, BS, files, &[0, 1, 2, 3]),
    )
    .unwrap();
    (dir, t, u)
}

fn assert_never_its_own_donor(dir: &Path, alias: &Path, t: &[u8], u: &[u8]) {
    let report = match repair_dir(dir) {
        Ok(RepairStatus::Repaired(r)) => r,
        other => panic!("the set is repairable: {other:?}"),
    };
    assert!(
        report.consumed_sources.is_empty(),
        "a second name for a target's own file was reported spent - a caller that sweeps \
         spent donors deletes the repaired member through it: {:?}",
        report.consumed_sources
    );
    assert_eq!(std::fs::read(dir.join("t.bin")).unwrap(), t);
    assert_eq!(std::fs::read(dir.join("u.bin")).unwrap(), u);
    // NOT asserted: what the alias reads now. `t.bin` feeds `u.bin` through
    // the in-set harvest, so it is rebuilt by temp-and-rename, which gives
    // the NAME a new file object and leaves a hard link on the old one.
    assert!(alias.exists(), "nothing deleted the second name either");
}

#[test]
fn a_hard_link_to_a_target_is_never_its_donor() {
    let (dir, t, u) = aliased_set("alias-hardlink");
    let mut damaged = t.clone();
    damaged[..8].fill(0xEE);
    std::fs::write(dir.join("t.bin"), &damaged).unwrap();
    let alias = dir.join("zz-second-name.bin");
    std::fs::hard_link(dir.join("t.bin"), &alias).unwrap();
    assert_never_its_own_donor(&dir, &alias, &t, &u);
}

/// The shape the sweep traced: the member's file on disk spelled in NFD
/// under a set that names it in NFC. Runs only where the volume treats
/// the two as one entry (APFS does; ext4 and NTFS do not, and there the
/// two spellings are two files and nothing here applies).
#[test]
fn an_nfd_spelling_of_a_target_is_never_its_donor() {
    let dir = tmpdir("alias-nfd");
    let probe_nfd = dir.join("probe-cafe\u{301}");
    std::fs::write(&probe_nfd, b"x").unwrap();
    let insensitive = dir.join("probe-caf\u{e9}").exists();
    std::fs::remove_file(&probe_nfd).unwrap();
    if !insensitive {
        eprintln!("normalization-sensitive volume - the hard-link test covers this mechanism");
        return;
    }
    let t = payload(BS * 4, 73);
    let mut u = payload(BS * 2, 74);
    u[..BS].copy_from_slice(&t[BS * 2..BS * 3]);
    let nfc = "caf\u{e9}.bin";
    let nfd = "cafe\u{301}.bin";
    let files: &[(&str, &[u8])] = &[(nfc, &t), ("u.bin", &u)];
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    std::fs::write(
        dir.join("set.vol0+4.par2"),
        par2_volume(SET, BS, files, &[0, 1, 2, 3]),
    )
    .unwrap();
    let mut damaged = t.clone();
    damaged[..8].fill(0xEE);
    std::fs::write(dir.join(nfd), &damaged).unwrap();
    let report = match repair_dir(&dir) {
        Ok(RepairStatus::Repaired(r)) => r,
        other => panic!("the set is repairable: {other:?}"),
    };
    assert!(
        report.consumed_sources.is_empty(),
        "the member's own NFD spelling was reported spent: {:?}",
        report.consumed_sources
    );
    assert_eq!(std::fs::read(dir.join(nfc)).unwrap(), t);
    assert_eq!(std::fs::read(dir.join("u.bin")).unwrap(), u);
}
