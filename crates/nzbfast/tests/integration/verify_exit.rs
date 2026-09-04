//! `nzbfast verify`'s exit code, over the PAR2 arm (TODO 310).
//!
//! The defect this pins: the PAR2 arm exited 0 on PAR2-detected damage
//! for as long as the command has shipped, because `unpack::verify_dir`
//! returned one bool for two different answers - `false` was both
//! "damaged" and "there was nothing to verify" - so the caller could not
//! act on it and discarded it. The manifest arm of the same command has
//! always exited 1 on damage, pinned by `daemon_manifest`'s A/B row,
//! which is the shape mirrored here: run the REAL binary against a real
//! directory and read the process exit code, because an exit code is the
//! only part of this a script can see and a unit test on the enum cannot
//! observe it.
//!
//! The compatibility call was taken on 2 Sep 2026: damage exits 1.
//! "Nothing to verify" exits 0 and says so on stderr - the same shape as
//! the manifest arm over an absent manifest, and the reason that arm is
//! not a conviction is that a directory whose .par2 files the cleanup
//! default already removed is the normal state of a finished job.
//!
//! The set is built by `nzbkit::par2gen` rather than by shelling out to
//! par2cmdline: CI's par2 is 0.8.1 where the dev boxes carry 1.3.0, so a
//! fixture that needs an external creator is a version question waiting
//! to happen, and this crate already owns a creator whose output
//! par2cmdline verifies (`par2gen_interop`).

use std::path::Path;
use std::process::Command;

use nzbkit::par2gen::{Member, Par2Spec, create_into};

use crate::scratch;

/// Deterministic payload, so a flipped byte is flipped in a file whose
/// every other byte is known.
fn payload(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8) ^ seed ^ 0x5a).collect()
}

/// Run the shipped binary's `verify` over `dir` and return its exit code.
fn verify_exit(dir: &Path) -> i32 {
    verify_exit_with(dir, &[], &[])
}

/// [`verify_exit`] with extra arguments and extra environment - the two
/// surfaces that switch the fast final check on from outside the daemon.
fn verify_exit_with(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> i32 {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
    cmd.arg("verify").arg(dir).args(args);
    cmd.env("NZBFAST_NO_ENRICH", "1");
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.status().expect("verify ran").code().unwrap_or(-1)
}

/// Write two payload files into `dir` and a PAR2 set covering both.
fn seed_covered_dir(dir: &Path) {
    std::fs::write(dir.join("one.bin"), payload(120_000, 3)).unwrap();
    std::fs::write(dir.join("two.bin"), payload(90_000, 41)).unwrap();
    let members = vec![
        Member {
            name: "one.bin".into(),
            path: dir.join("one.bin"),
        },
        Member {
            name: "two.bin".into(),
            path: dir.join("two.bin"),
        },
    ];
    create_into(
        dir,
        &members,
        "set",
        &Par2Spec {
            redundancy_pct: 10,
            block_size: Some(8_192),
        },
    )
    .expect("par2 set written");
}

#[test]
fn a_par2_covered_dir_that_checks_out_exits_zero() {
    let dir = std::env::temp_dir().join(format!("nzbfast-vexit-clean-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    seed_covered_dir(&dir);

    assert_eq!(
        verify_exit(&dir),
        0,
        "an undamaged PAR2-covered directory must verify clean"
    );
}

#[test]
fn par2_detected_damage_exits_one_like_the_manifest_arm() {
    let dir = std::env::temp_dir().join(format!("nzbfast-vexit-damaged-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    seed_covered_dir(&dir);

    // Flip one byte mid-payload, exactly the damage the manifest arm's
    // A/B row convicts. Both the block CRC and the whole-file MD5 fail.
    let target = dir.join("one.bin");
    let mut bytes = std::fs::read(&target).unwrap();
    bytes[50_000] ^= 0x20;
    std::fs::write(&target, &bytes).unwrap();

    assert_eq!(
        verify_exit(&dir),
        1,
        "a flipped byte under a PAR2 set must exit 1 (TODO 310) - this \
         exited 0 for every release before 2 Sep 2026"
    );
}

#[test]
fn a_missing_member_exits_one_too() {
    let dir = std::env::temp_dir().join(format!("nzbfast-vexit-missing-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    seed_covered_dir(&dir);
    std::fs::remove_file(dir.join("two.bin")).unwrap();

    assert_eq!(
        verify_exit(&dir),
        1,
        "a member the set names and the disk does not hold is damage, \
         not an absence of evidence"
    );
}

#[test]
fn a_directory_with_nothing_to_verify_exits_zero() {
    let dir = std::env::temp_dir().join(format!("nzbfast-vexit-empty-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    // Payload with no PAR2 set and no settle manifest: nothing to check
    // against. The documented answer is 0 with a line on stderr, NOT a
    // conviction - a finished job whose .par2 files the cleanup default
    // removed lands in exactly this state.
    std::fs::write(dir.join("lonely.bin"), payload(4_096, 9)).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_nzbfast"))
        .arg("verify")
        .arg(&dir)
        .env("NZBFAST_NO_ENRICH", "1")
        .output()
        .expect("verify ran");
    assert_eq!(
        out.status.code().unwrap_or(-1),
        0,
        "nothing to verify is not damage"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("nothing to verify"),
        "the no-verdict case must SAY so, and on stderr so a redirected \
         report still shows it - stderr was {err:?}"
    );
}

// -- The fast final check, off by default (audit section 21) -----------
//
// `--fast` proves each member from the PAR2 set's per-block checksums
// alone and skips the whole-file digest. It is a VERDICT change, not
// only a speed change, so what these pin is that the verdict does not
// move on either shape a real user has: a clean directory stays clean
// and a damaged one stays damaged. The one set where the two answers
// differ is spec-legal but malformed, cannot be built by accident, and
// is pinned in the engine by
// `the_ifsc_only_tier_diverges_only_on_the_h7_shape`.

#[test]
fn the_fast_final_check_agrees_with_the_default_on_a_clean_directory() {
    let dir = std::env::temp_dir().join(format!("nzbfast-vexit-fast-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    seed_covered_dir(&dir);

    assert_eq!(
        verify_exit_with(&dir, &["--fast"], &[]),
        0,
        "--fast on an undamaged directory is the case it exists for"
    );
    // The environment variable is the third surface and the lowest rung
    // of the precedence. It has to reach the same code, or the CLI and
    // the daemon would be answering under different rules - the one
    // constraint section 21 calls load-bearing.
    assert_eq!(
        verify_exit_with(&dir, &[], &[("NZBFAST_VERIFY_IFSC_ONLY", "1")]),
        0,
        "the variable reaches the same tier the flag does"
    );
}

#[test]
fn the_fast_final_check_still_convicts_damage() {
    let dir = std::env::temp_dir().join(format!("nzbfast-vexit-fastbad-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    seed_covered_dir(&dir);

    let target = dir.join("one.bin");
    let mut bytes = std::fs::read(&target).unwrap();
    bytes[50_000] ^= 0x20;
    std::fs::write(&target, &bytes).unwrap();

    // A failing block declines the tier and runs the unchanged path, so
    // this is the SAME answer as without the flag, arrived at the same
    // way. A fast check that could not still find a flipped byte would
    // not be worth shipping at any speed.
    assert_eq!(
        verify_exit_with(&dir, &["--fast"], &[]),
        1,
        "--fast must not soften the verdict on real damage"
    );
}

#[test]
fn a_missing_member_is_damage_under_the_fast_final_check_too() {
    let dir = std::env::temp_dir().join(format!("nzbfast-vexit-fastgone-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    seed_covered_dir(&dir);
    std::fs::remove_file(dir.join("two.bin")).unwrap();

    assert_eq!(
        verify_exit_with(&dir, &["--fast"], &[]),
        1,
        "a member the disk does not hold has no blocks to prove"
    );
}
