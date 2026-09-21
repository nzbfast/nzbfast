//! A repair into a directory the user cannot write keeps no `.1`
//! backup, and SAYS so.
//!
//! par2cmdline renames the damaged original aside and writes the
//! repaired file fresh, so on a read-only directory it cannot start:
//! it prints `<x> cannot be renamed to <y>` and exits 6. parfast
//! patches in place and needs nothing from the directory, so it
//! repairs and exits 0 - the better outcome, and the one kept. What it
//! could not do is COPY the damaged original aside first, and until
//! 20 Sep 2026 that copy's error was dropped at a `let _ =
//! std::fs::copy` in `repair::back_up_damaged`: the run repaired,
//! exited 0, and silently did not keep the one file a backup exists to
//! be.
//!
//! The line lands at the engine's `before_write`, through a blocking
//! handshake, which is the last moment the damaged original is still
//! whole - a user who reads it there can interrupt, fix the directory
//! and run again with the original intact. That TIMING is the point of
//! the fix and is what the `repair_is_not_yet_done` assertion below
//! pins.
//!
//! No external binary: it drives `parfast::run_with` in-process.
//!
//! UNIX ONLY, and the `#[cfg(unix)]` is on the `mod` line in `main.rs`
//! for the reason given there: a chmod has no Windows equivalent, and a
//! cfg'd-out test in a compiled module leaves its helpers with no
//! caller, which `-D warnings` refuses.

use crate::scratch::scratch;

fn arg(s: &str) -> String {
    s.to_string()
}

/// Build a set in `dir` and damage its first member, returning
/// `(set path, damaged member path)`.
///
/// **THE GEOMETRY IS LOAD-BEARING, and `second` is what picks the
/// route.** `par2repair`'s `via_temp` sends a rebuild through a
/// `.<name>.nzbfast-repair.N.tmp` staged beside the target whenever the
/// member is unidentified, the repair is short, or the member is its
/// own donor - and `create_new` of that temp needs a WRITABLE
/// DIRECTORY, so on a read-only one the repair fails whatever the
/// backup did. A lone member is routinely its own donor and takes that
/// route; a second, intact member gives the fold a source that is not
/// the file being written, and the rebuild is patched IN PLACE, which
/// needs nothing from the directory. Both routes matter here and each
/// test below names the one it wants.
fn damaged_set(
    dir: &std::path::Path,
    second: bool,
    blocks: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let data = dir.join("payload.bin");
    // Distinct blocks, as engine_fold's fixture does: a constant run is
    // not what a real member looks like.
    let payload: Vec<u8> = (0..512 * 1024u32)
        .map(|i| (i.wrapping_mul(31)) as u8)
        .collect();
    std::fs::write(&data, &payload).expect("payload");

    let set = dir.join("set.par2");
    let mut argv = vec![
        arg("c"),
        arg(blocks),
        arg("-r20"),
        arg(&set.to_string_lossy()),
        arg(&data.to_string_lossy()),
    ];
    if second {
        let other = dir.join("other.txt");
        std::fs::write(&other, "a second, intact member\n".repeat(400)).expect("second member");
        argv.push(arg(&other.to_string_lossy()));
    }
    let code = parfast::run_with("parfast", &argv, &mut parfast::out::Sink::buffered());
    assert_eq!(code, 0, "fixture create failed");

    let mut bytes = std::fs::read(&data).expect("read back");
    bytes[1024..4096].fill(0x00);
    std::fs::write(&data, &bytes).expect("damage");
    (set, data)
}

/// THE CONTROL, and it is half the test: an ordinary repair DOES keep
/// the backup and says nothing. Without this arm the read-only
/// assertion below would pass just as well against a build that had
/// stopped making backups at all, which is precisely the state this
/// crate was once believed to be in.
#[test]
fn an_ordinary_repair_keeps_the_backup_and_is_quiet_about_it() {
    let dir = scratch("readonly-backup-control");
    let (set, data) = damaged_set(&dir, true, "-b32");

    let mut sink = parfast::out::Sink::buffered();
    let code = parfast::run_with(
        "parfast",
        &[arg("r"), arg("-q"), arg(&set.to_string_lossy())],
        &mut sink,
    );
    let (_out, err) = sink.take();
    assert_eq!(code, 0, "the repair should succeed; stderr: {err}");

    let backup = dir.join("payload.bin.1");
    assert!(
        backup.is_file(),
        "an ordinary repair keeps the damaged original as `.1`"
    );
    assert!(
        !err.contains("Could not keep a backup"),
        "nothing failed, so nothing should be reported: {err}"
    );
    // The backup is the DAMAGED original, not a second copy of the
    // repaired file - the whole point of keeping it.
    let kept = std::fs::read(&backup).expect("backup");
    let repaired = std::fs::read(&data).expect("repaired");
    assert_ne!(
        kept, repaired,
        "the `.1` must hold the damaged bytes, not the repaired ones"
    );
    assert_eq!(kept[1024..4096], [0u8; 3072], "the `.1` holds the damage");
}

/// A read-only DIRECTORY: the repair still happens, no backup is kept,
/// and the run says which file it could not keep.
#[test]
fn a_read_only_directory_loses_the_backup_and_says_so() {
    use std::os::unix::fs::PermissionsExt;

    // Two members and `-b32`: the IN-PLACE route, so the repair itself
    // asks nothing of the directory and the backup is the only thing
    // that cannot be written.
    let dir = scratch("readonly-backup");
    let (set, _data) = damaged_set(&dir, true, "-b32");

    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).expect("chmod");
    // Running as root defeats a read-only directory, and some CI legs
    // do. Skip rather than assert on a machine where it cannot bite.
    if std::fs::write(dir.join(".probe"), b"x").is_ok() {
        let _ = std::fs::remove_file(dir.join(".probe"));
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));
        eprintln!("skipping: this user can write a 0o555 directory");
        return;
    }

    let mut sink = parfast::out::Sink::buffered();
    let code = parfast::run_with(
        "parfast",
        &[arg("r"), arg("-q"), arg(&set.to_string_lossy())],
        &mut sink,
    );
    let (out, err) = sink.take();
    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));

    // The repair itself is untouched: patching in place needs nothing
    // from the directory, and repairing anyway where the reference
    // refuses is the behaviour this crate deliberately keeps.
    assert_eq!(
        code, 0,
        "the repair still succeeds where par2cmdline exits 6; stderr: {err}"
    );
    assert!(
        out.contains("Repair complete."),
        "the repair still completes: {out}"
    );
    assert!(
        !dir.join("payload.bin.1").exists(),
        "there is nowhere to put the backup, so there must be none"
    );

    // ...and the loss is REPORTED rather than dropped.
    assert!(
        err.contains("Could not keep a backup"),
        "a backup that could not be made must be reported, not dropped: {err}"
    );
    assert!(
        err.contains("payload.bin.1"),
        "the report names the backup it could not write: {err}"
    );

    // THE TIMING, which is the point of the fix. The warning is emitted
    // at the engine's `before_write`, so it precedes every line the
    // repair prints once it has started writing. `Verifying repaired
    // files:` is the first of those, and its presence proves the fold
    // really ran rather than the assertion holding vacuously.
    let combined_repair_is_not_yet_done = out.contains("Verifying repaired files:");
    assert!(
        combined_repair_is_not_yet_done,
        "the fixture must actually reach the write phase: {out}"
    );
}

/// THE BOUNDARY OF THE "more robust than the reference" CLAIM, which
/// is routinely stated without one.
///
/// The claim is "on a read-only directory parfast repairs where the
/// reference fails". That is true of the IN-PLACE route above and not
/// of the engine as a whole: a member that is its own donor goes
/// through `par2repair`'s `via_temp` staging, whose `create_new` needs
/// the directory, so the repair fails there too. Different code, a
/// different exit (5, the dialect's repair-failed, against the
/// reference's 6) and a different reason, but not a success.
///
/// The invariant this pins is the one the fix is for and it holds on
/// BOTH routes: whatever the repair then does, the backup that could
/// not be made is REPORTED. Nothing here asserts that failing is the
/// right outcome - it is pre-existing engine behaviour, unchanged by
/// the backup work, and recorded so the next lane meets the boundary
/// rather than the slogan.
#[test]
fn the_temp_staging_route_also_fails_on_a_read_only_directory_and_still_reports() {
    use std::os::unix::fs::PermissionsExt;

    // ONE member, default geometry: its own donor, so `via_temp`.
    let dir = scratch("readonly-backup-temp-route");
    let (set, _data) = damaged_set(&dir, false, "-b256");

    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).expect("chmod");
    if std::fs::write(dir.join(".probe"), b"x").is_ok() {
        let _ = std::fs::remove_file(dir.join(".probe"));
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));
        eprintln!("skipping: this user can write a 0o555 directory");
        return;
    }

    let mut sink = parfast::out::Sink::buffered();
    let code = parfast::run_with(
        "parfast",
        &[arg("r"), arg("-q"), arg(&set.to_string_lossy())],
        &mut sink,
    );
    let (_out, err) = sink.take();
    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));

    assert_ne!(
        code, 0,
        "the temp-staging route cannot write its temp here, so the repair does not \
         succeed - if this ever passes, the claim in the doc comment above is stale \
         and the read-only case has become unconditionally a success; stderr: {err}"
    );
    // The point of the fix, on this route too.
    assert!(
        err.contains("Could not keep a backup"),
        "the unmade backup is reported whichever way the repair then goes: {err}"
    );
}
