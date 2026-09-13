//! `-p` deletes files. This is the module that proves it deletes only
//! the ones this run made.
//!
//! The defect these tests stand against (found 10 Sep 2026, fixed the
//! same day): `verify::purge` built its delete list by SYNTHESISING
//! `<member>.1` through `<member>.9` for every member of the set and
//! keeping whatever `exists()`. A name is not provenance. A set that
//! legitimately protects both `payload.bin` and `payload.bin.1` - an
//! ordinary shape, `.1` is just a character in a filename - had its
//! SECOND MEMBER deleted by `parfast r -p` on a CLEAN set, the recovery
//! volumes deleted in the same run, and every step exited 0. No
//! diagnostic, no copy of the data left, nothing to repair from.
//!
//! So the bar here is two-sided and both sides matter: a protected
//! member and an unrelated numbered file must SURVIVE, and a backup this
//! run really made must still be REMOVED. Testing only the first would
//! pass on a `purge` that deletes nothing at all.
//!
//! Drives the built binary, not `parfast::run_with`. The reproduction
//! that found this was a CLI run and the CLI is what a user holds; a
//! harness that re-implements the argument path can agree with itself
//! about a route that ships differently.

use std::path::{Path, PathBuf};
use std::process::Command;

fn scratch(tag: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(tag);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn parfast(dir: &Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_parfast"))
        .args(args)
        .current_dir(dir)
        .env("NZBFAST_NO_ENRICH", "1")
        .output()
        .expect("parfast runs");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn payload(n: usize, seed: u32) -> Vec<u8> {
    (0..n as u32)
        .map(|i| (i.wrapping_mul(seed | 1).wrapping_add(i >> 3)) as u8)
        .collect()
}

/// The bytes' digest, or `None` when the file is gone - so a test can
/// say "unchanged" and "deleted" with the same expression.
fn digest(path: &Path) -> Option<u64> {
    let bytes = std::fs::read(path).ok()?;
    Some(bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    }))
}

fn create(dir: &Path, name: &str, files: &[&str]) {
    let mut args = vec!["c", "-s256", "-c8", name];
    args.extend_from_slice(files);
    let (code, out, err) = parfast(dir, &args);
    assert_eq!(code, 0, "create failed: {out}{err}");
}

fn damage(path: &Path, at: usize) {
    let mut b = std::fs::read(path).unwrap();
    for x in &mut b[at..at + 64] {
        *x ^= 0x5a;
    }
    std::fs::write(path, b).unwrap();
}

/// Did `-p` do the par half? Every one of these tests requires it, so a
/// purge that silently skipped everything cannot pass by deleting
/// nothing.
fn par_files_gone(dir: &Path) -> bool {
    std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .all(|e| !e.file_name().to_string_lossy().ends_with(".par2"))
}

/// The reported defect, end to end: a CLEAN set whose second member is
/// named like a backup of the first.
#[test]
fn a_clean_purge_keeps_a_member_whose_name_looks_like_a_backup() {
    let dir = scratch("purge-clean-collision");
    std::fs::write(dir.join("payload.bin"), payload(20_000, 7)).unwrap();
    std::fs::write(dir.join("payload.bin.1"), payload(15_000, 11)).unwrap();
    let before = (
        digest(&dir.join("payload.bin")),
        digest(&dir.join("payload.bin.1")),
    );

    create(&dir, "set.par2", &["payload.bin", "payload.bin.1"]);
    let (code, out, err) = parfast(&dir, &["v", "set.par2"]);
    assert_eq!(code, 0, "the set must verify clean first: {out}{err}");

    let (code, out, err) = parfast(&dir, &["r", "-p", "set.par2"]);
    assert_eq!(code, 0, "clean repair: {out}{err}");
    assert_eq!(
        (
            digest(&dir.join("payload.bin")),
            digest(&dir.join("payload.bin.1")),
        ),
        before,
        "both members must come through byte-identical:\n{out}{err}"
    );
    // Nothing was damaged, so this run made no backup - and announcing
    // a backup purge it did not do is how the old shape read.
    assert!(
        !out.contains("Purge backup files."),
        "no backup was made, so no backup half:\n{out}"
    );
    assert!(par_files_gone(&dir), "the par half still has to happen");
}

/// The same collision, but reached through a repair that really runs -
/// purge must not undo the verdict it follows.
#[test]
fn a_repair_purge_keeps_the_collided_member_it_just_verified() {
    let dir = scratch("purge-repaired-collision");
    std::fs::write(dir.join("payload.bin"), payload(20_000, 7)).unwrap();
    std::fs::write(dir.join("payload.bin.1"), payload(15_000, 11)).unwrap();
    let want = (
        digest(&dir.join("payload.bin")),
        digest(&dir.join("payload.bin.1")),
    );

    create(&dir, "set.par2", &["payload.bin", "payload.bin.1"]);
    // Damage the FIRST member, so the run takes the repair path and the
    // second member - the one that looks like a backup - is a bystander.
    damage(&dir.join("payload.bin"), 4_096);

    let (code, out, err) = parfast(&dir, &["r", "-p", "set.par2"]);
    assert_eq!(code, 0, "repair should succeed: {out}{err}");
    assert!(out.contains("Repair complete."), "{out}");
    assert_eq!(
        (
            digest(&dir.join("payload.bin")),
            digest(&dir.join("payload.bin.1")),
        ),
        want,
        "the repaired member and the bystander must both be right:\n{out}{err}"
    );
    assert!(par_files_gone(&dir), "the par half still has to happen");
}

/// A numbered file that is neither a member nor anything this run made.
/// parfast did not create it and has no business deleting it.
#[test]
fn a_stranger_numbered_file_survives_a_purge() {
    let dir = scratch("purge-stranger");
    std::fs::write(dir.join("payload.bin"), payload(20_000, 7)).unwrap();
    create(&dir, "set.par2", &["payload.bin"]);
    // Written AFTER the set, so it is in no packet: a leftover from
    // something else that happens to match the shape.
    std::fs::write(dir.join("payload.bin.1"), payload(9_000, 23)).unwrap();
    let stranger = digest(&dir.join("payload.bin.1"));

    let (code, out, err) = parfast(&dir, &["r", "-p", "set.par2"]);
    assert_eq!(code, 0, "clean repair: {out}{err}");
    assert_eq!(
        digest(&dir.join("payload.bin.1")),
        stranger,
        "an unrelated numbered file is not ours to delete:\n{out}{err}"
    );
    assert!(par_files_gone(&dir), "the par half still has to happen");
}

/// The other direction. `-p` exists to remove the backup a repair left,
/// and a purge that keeps everything is as broken as one that deletes
/// everything - it just fails quietly.
#[test]
fn a_backup_this_run_made_is_still_removed() {
    let dir = scratch("purge-real-backup");
    std::fs::write(dir.join("payload.bin"), payload(20_000, 7)).unwrap();
    create(&dir, "set.par2", &["payload.bin"]);
    damage(&dir.join("payload.bin"), 4_096);

    let (code, out, err) = parfast(&dir, &["r", "-p", "set.par2"]);
    assert_eq!(code, 0, "repair should succeed: {out}{err}");
    assert!(out.contains("Purge backup files."), "{out}");
    assert!(out.contains("Remove \"payload.bin.1\"."), "{out}");
    assert_eq!(
        digest(&dir.join("payload.bin.1")),
        None,
        "the backup this run made must be gone:\n{out}{err}"
    );
    assert!(par_files_gone(&dir), "the par half still has to happen");
}

/// A repair whose backup slot is TAKEN by a member. `.1` is declared by
/// the set, so the copy of the damaged original has to go to `.2` -
/// otherwise the backup is written over a repair target and `-p` then
/// deletes the member the engine just rebuilt.
#[test]
fn a_backup_skips_a_numbered_slot_the_set_protects() {
    let dir = scratch("purge-slot-taken");
    std::fs::write(dir.join("payload.bin"), payload(20_000, 7)).unwrap();
    std::fs::write(dir.join("payload.bin.1"), payload(15_000, 11)).unwrap();
    let want = (
        digest(&dir.join("payload.bin")),
        digest(&dir.join("payload.bin.1")),
    );
    create(&dir, "set.par2", &["payload.bin", "payload.bin.1"]);
    damage(&dir.join("payload.bin"), 4_096);

    let (code, out, err) = parfast(&dir, &["r", "-p", "set.par2"]);
    assert_eq!(code, 0, "repair should succeed: {out}{err}");
    assert_eq!(
        (
            digest(&dir.join("payload.bin")),
            digest(&dir.join("payload.bin.1")),
        ),
        want,
        "both members survive; the backup went elsewhere:\n{out}{err}"
    );
    assert_eq!(
        digest(&dir.join("payload.bin.2")),
        None,
        "and the backup that took `.2` was purged:\n{out}{err}"
    );
    assert!(par_files_gone(&dir), "the par half still has to happen");
}
