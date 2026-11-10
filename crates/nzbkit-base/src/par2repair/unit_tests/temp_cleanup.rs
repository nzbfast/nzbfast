//! Parfast sweep A23 / A24 (9 Nov 2026): the repair's staging temps on
//! the error paths that used to leave them behind.
//!
//! Every temp a repair stages is created with `create_new` under a
//! `.<name>.nzbfast-repair.<n>.tmp` name and is this call's to remove on
//! ANY failure - the `cleanup` closure in `repair_dir_set_inner` and the
//! three `status::publish_failed` sites exist for exactly that. Three
//! exits did not take it: two bare `?` in the patch loop's first pass
//! (A23 - the tree-target `create_out_dirs` and the in-place open), and
//! `land_rebuilds`, which consumed the rename list and so had nothing to
//! clean with when one rename failed (A24). Each leaked every temp
//! staged before it, and a temp left in a job folder is a full-size copy
//! of a member that nothing will ever read or remove.
//!
//! A CHILD of `unit_tests` for `padded_windows`' two reasons.

use super::*;

/// Every repair staging file in `dir`, by the infix the temp name
/// carries - a test that looked for `*.tmp` would pass over a leak.
fn repair_temps(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains("nzbfast-repair"))
        .collect()
}

fn target(dir: &Path, name: &str, fid: u8) -> Target {
    Target {
        file: Par2File {
            file_id: [fid; 16],
            name: name.into(),
            length: 64,
            md5: [0u8; 16],
            md5_16k: [0u8; 16],
            blocks: Vec::new(),
        },
        path: dir.join(name),
        first_slice: fid as usize,
        n_slices: 1,
        present: vec![false],
        intact: false,
        exists: false,
        resume: None,
        md5_unfinished: false,
    }
}

fn empty_report() -> RepairReport {
    RepairReport {
        blocks_rebuilt: 0,
        blocks_adopted: 0,
        adopted_from: Vec::new(),
        files_patched: Vec::new(),
        files_created: Vec::new(),
        files_renamed: Vec::new(),
        consumed_sources: Vec::new(),
        per_file: Vec::new(),
    }
}

/// A24. The first rename fails on a set that is NOT short, which is an
/// `Err` for the whole call - and the second target's temp, which the
/// loop never reached, must not outlive it.
///
/// The failure is a rename onto a non-empty DIRECTORY, which every
/// platform refuses, so the fixture needs no fault injection. The
/// ordering is the point: the temp that leaked was always one AFTER the
/// failing rename in the list.
#[test]
fn a_failed_rename_cleans_up_the_temps_it_never_reached() {
    let dir = tmpdir("a24-land");
    let blocked = dir.join("a.bin");
    std::fs::create_dir_all(blocked.join("occupied")).unwrap();
    std::fs::write(blocked.join("occupied").join("x"), b"x").unwrap();
    let tmp_a = dir.join(".a.bin.nzbfast-repair.0.tmp");
    let tmp_b = dir.join(".b.bin.nzbfast-repair.0.tmp");
    std::fs::write(&tmp_a, [1u8; 64]).unwrap();
    std::fs::write(&tmp_b, [2u8; 64]).unwrap();
    let targets = vec![target(&dir, "a.bin", 0), target(&dir, "b.bin", 1)];
    let mut damaged = vec![0, 1];
    let mut report = empty_report();
    let err = land_rebuilds(
        vec![(tmp_a, 0), (tmp_b, 1)],
        adopt::WholeMatches {
            renames: Vec::new(),
            targets: HashSet::new(),
            cands: HashSet::new(),
        },
        &[],
        &mut damaged,
        &targets,
        None,
        &mut report,
    )
    .expect_err("a rename the filesystem refuses fails a set that is not short");
    assert!(matches!(err, RepairError::Io(_)), "{err:?}");
    assert_eq!(
        repair_temps(&dir),
        Vec::<String>::new(),
        "a staging temp outlived the failed landing"
    );
    assert!(
        !dir.join("b.bin").exists(),
        "nothing past the failure is renamed in"
    );
}

/// A24's donor guard, kept: on a whole-file match the "temp" IS the
/// donor, so the cleanup of the unreached tail must leave it where it is.
#[test]
fn a_failed_rename_never_removes_a_whole_file_donor() {
    let dir = tmpdir("a24-donor");
    let blocked = dir.join("a.bin");
    std::fs::create_dir_all(blocked.join("occupied")).unwrap();
    std::fs::write(blocked.join("occupied").join("x"), b"x").unwrap();
    let tmp_a = dir.join(".a.bin.nzbfast-repair.0.tmp");
    std::fs::write(&tmp_a, [1u8; 64]).unwrap();
    let donor = dir.join("9f2c-obfuscated");
    std::fs::write(&donor, [2u8; 64]).unwrap();
    let targets = vec![target(&dir, "a.bin", 0), target(&dir, "b.bin", 1)];
    let mut damaged = vec![0];
    let mut report = empty_report();
    land_rebuilds(
        vec![(tmp_a, 0)],
        adopt::WholeMatches {
            renames: vec![(donor.clone(), 1)],
            targets: HashSet::from([1]),
            cands: HashSet::from([0]),
        },
        &[],
        &mut damaged,
        &targets,
        None,
        &mut report,
    )
    .expect_err("the rename onto a directory fails");
    assert!(donor.exists(), "the donor is not this repair's to delete");
    assert_eq!(repair_temps(&dir), Vec::<String>::new());
}

/// A23. A two-member set whose second member lives under `sub/`, where
/// `sub` cannot be written through: the first member is staged to a temp, then
/// the second's `create_out_dirs` fails - and the first's temp must go
/// with the error. Unix-only for the symlink the fixture needs.
#[cfg(unix)]
#[test]
fn a_failed_tree_destination_cleans_up_the_temps_staged_before_it() {
    let dir = tmpdir("a23-tree");
    let a = payload(BS * 2, 91);
    let b = payload(BS * 2, 92);
    let files: &[(&str, &[u8])] = &[("a.bin", &a), ("sub/b.bin", &b)];
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    std::fs::write(
        dir.join("set.vol0+4.par2"),
        par2_volume(SET, BS, files, &[0, 1, 2, 3]),
    )
    .unwrap();
    // Neither member exists, so both are rebuilt and both stage a temp -
    // and `sub` is a SYMLINK to an empty directory, which the verify pass
    // reads through (the member is simply absent) and `create_out_dirs`
    // refuses to write through. A regular file at `sub` would not do:
    // the verify pass meets ENOTDIR first and fails before any temp is
    // staged, which is a test that cannot see the leak.
    let elsewhere = tmpdir("a23-tree-elsewhere");
    std::os::unix::fs::symlink(&elsewhere, dir.join("sub")).unwrap();
    let err = repair_dir(&dir).expect_err("the tree destination cannot be made");
    assert!(matches!(err, RepairError::Io(_)), "{err:?}");
    assert_eq!(
        repair_temps(&dir),
        Vec::<String>::new(),
        "the first member's staging temp outlived the second member's failure"
    );
    assert!(!dir.join("a.bin").exists(), "nothing is renamed in");
}
