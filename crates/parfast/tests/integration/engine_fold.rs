//! The repair front's behaviour when the ENGINE folds before it has
//! surveyed anything.
//!
//! No external binary, so nothing to skip on: it drives
//! `parfast::run_with` in-process, which is what `src/main.rs` exists to
//! keep possible.
//!
//! Scratch lives under `CARGO_TARGET_TMPDIR` rather than `$TMPDIR`,
//! because cargo owns that directory and `cargo clean` takes it. That
//! used to be the whole story and it was not enough: the path was fixed
//! for all time and opened by removing it, so two concurrent runs of
//! this binary deleted each other's working directory mid-run. It comes
//! from `crate::scratch` now, which scopes it to the process and removes
//! it on the way out - the reasoning is in that module's header.
//!
//! UNIX ONLY, and the `#[cfg(unix)]` is on the `mod` line in `main.rs`
//! rather than on the test below: the fold is reached by making a
//! recovery volume unreadable with a `PermissionsExt` 0o000, which
//! Windows has no equivalent for, and a cfg'd-out test inside a compiled
//! module leaves `scratch` and `arg` with no caller there - which
//! `-D warnings` refuses.

use crate::scratch::scratch;

fn arg(s: &str) -> String {
    s.to_string()
}

/// An engine fold BEFORE the survey exits with the dialect's own
/// repair-failed code and prints its reason, instead of aborting the
/// process.
///
/// `repair::run` used to reach `surveyed.expect(...)` on that path, and
/// the two sides of the run genuinely disagree about which sets load:
/// `verify::load` tolerates a `.par2` it cannot read
/// (`std::fs::read(p).ok()`), while the engine's `PacketCatalog`
/// propagates the I/O error with `?` from a scan that runs BEFORE the
/// survey observer is wrapped. So the loader returns an `Ok` set whose
/// recovery-set id matches, the engine returns an `Err`, no survey was
/// ever produced, and the `expect` fired - exit 101, or an abort under
/// `panic = "abort"`, out of a crate whose entire interface is its
/// par2cmdline-compatible exit codes.
///
/// An unreadable member is the cheapest way to reach it. The everyday
/// one is a set whose Main packet names a file id with no FileDesc
/// packet: `par2repair` refuses that outright, and
/// `Par2Set::parse_inner_with` deliberately drops the id and carries on.
#[test]
fn an_engine_fold_before_the_survey_is_an_exit_code_not_a_panic() {
    use std::os::unix::fs::PermissionsExt;

    let dir = scratch("engine-fold");
    let data = dir.join("payload.bin");
    // Not all one byte: a compressible constant run is not what a real
    // member looks like and the block digests want distinct blocks.
    let payload: Vec<u8> = (0..512 * 1024u32)
        .map(|i| (i.wrapping_mul(31)) as u8)
        .collect();
    std::fs::write(&data, &payload).expect("payload");

    let set = dir.join("set.par2");
    let code = parfast::run_with(
        "parfast",
        &[
            arg("c"),
            arg("-r20"),
            arg(&set.to_string_lossy()),
            arg(&data.to_string_lossy()),
        ],
        &mut parfast::out::Sink::buffered(),
    );
    assert_eq!(code, 0, "fixture create failed");

    // Damage the payload so a repair is genuinely attempted...
    let mut bytes = std::fs::read(&data).expect("read back");
    bytes[1024..4096].fill(0x00);
    std::fs::write(&data, &bytes).expect("damage");

    // ...and make ONE recovery volume unreadable. The loader skips it;
    // the engine's catalog scan does not.
    let vol = std::fs::read_dir(&dir)
        .expect("listing")
        .flatten()
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().contains(".vol"))
        })
        .expect("the create produced a recovery volume");
    std::fs::set_permissions(&vol, std::fs::Permissions::from_mode(0o000)).expect("chmod");

    // Running as root defeats a 0o000, and some CI legs do. Skip rather
    // than assert on a machine where the fixture cannot bite.
    if std::fs::read(&vol).is_ok() {
        eprintln!("skipping: this user can read a 0o000 file");
        return;
    }

    let mut sink = parfast::out::Sink::buffered();
    let code = parfast::run_with(
        "parfast",
        &[arg("r"), arg(&set.to_string_lossy())],
        &mut sink,
    );
    let (_out, err) = sink.take();
    assert_eq!(
        code, 5,
        "an engine fold is EXIT_REPAIR_FAILED, not an abort; stderr: {err}"
    );
    // `Repair Failed.` and not the older `Repair failed:`: both of
    // repair.rs's failure arms went through `repair_failed_line` on
    // 20 Sep 2026, so that SABnzbd's `startswith("Repair Failed.")`
    // branch fires and the reason reaches the user. The divergence from
    // par2cmdline 1.2.0 is deliberate and argued at that function.
    assert!(
        err.contains("Repair Failed."),
        "the fold's own error is the whole verdict and must be printed: {err}"
    );

    let _ = std::fs::set_permissions(&vol, std::fs::Permissions::from_mode(0o644));
}
