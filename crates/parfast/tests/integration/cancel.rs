//! Ctrl-C is the engine's clean cancel, not a kill (12 Sep 2026).
//!
//! Until then the binary handed the engine no control, so an interrupt
//! mid-fold left temp-staged members on disk and said nothing. These
//! hold the two promises the engine states on `RepairError::Cancelled`:
//! before the patch the directory is exactly as the survey found it;
//! during it nothing is worse and the run's own backups are all that is
//! new. And the one this crate adds: exit 130, a "Cancelled" line on
//! stderr, and a second run that finishes the job.
//!
//! The interrupt is sent when the meter's first fragment for the phase
//! under test shows on stdout, so the test never guesses at timing; the
//! sets are sized and `-t1` so the phase outlives the signal's latency
//! by orders of magnitude. A run that completes before the interrupt
//! FAILS loudly rather than passing on the other route.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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

/// `mib` MiB of non-repeating bytes, written in chunks.
fn write_payload(path: &Path, mib: usize, seed: u64) {
    let mut f = std::fs::File::create(path).unwrap();
    let mut x = seed | 1;
    let mut chunk = vec![0u8; 1 << 20];
    for _ in 0..mib {
        for w in chunk.as_chunks_mut::<8>().0 {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            w.copy_from_slice(&x.to_le_bytes());
        }
        f.write_all(&chunk).unwrap();
    }
}

fn digest(path: &Path) -> u64 {
    let bytes = std::fs::read(path).unwrap();
    bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// Flip every byte in `[from, to)`: every block in the span is lost.
fn destroy(path: &Path, from: usize, to: usize) {
    let mut b = std::fs::read(path).unwrap();
    for x in &mut b[from..to] {
        *x ^= 0xa5;
    }
    std::fs::write(path, b).unwrap();
}

fn names(dir: &Path) -> BTreeSet<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect()
}

struct Interrupted {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Run `parfast r -t1` and send SIGINT the moment `marker` shows on
/// stdout. Panics, with the run's output, if the run ends first.
fn interrupt_at(dir: &Path, marker: &str) -> Interrupted {
    interrupt_running(dir, &["r", "-t1", "set.par2"], marker)
}

/// [`interrupt_at`] for any command line: the create's cancel is the
/// same promise read on a different subcommand.
fn interrupt_running(dir: &Path, args: &[&str], marker: &str) -> Interrupted {
    let mut child = Command::new(env!("CARGO_BIN_EXE_parfast"))
        .args(args)
        .current_dir(dir)
        .env("NZBFAST_NO_ENRICH", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("parfast spawns");
    let mut stdout = child.stdout.take().unwrap();
    let mut seen = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        let n = stdout.read(&mut buf).expect("read stdout");
        if n == 0 {
            let status = child.wait().unwrap();
            panic!(
                "the run finished (status {status}) before {marker:?} was seen - the window \
                 this test needs was missed, so nothing here was tested:\n{}",
                String::from_utf8_lossy(&seen)
            );
        }
        seen.extend_from_slice(&buf[..n]);
        if String::from_utf8_lossy(&seen).contains(marker) {
            break;
        }
    }
    let kill = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .expect("kill runs");
    assert!(kill.success(), "kill -INT failed");
    // Drain to EOF, then reap.
    let _ = stdout.read_to_end(&mut seen);
    let status = child.wait().unwrap();
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    Interrupted {
        code: status.code(),
        stdout: String::from_utf8_lossy(&seen).into_owned(),
        stderr: err,
    }
}

/// Ctrl-C inside the fold: exit 130, the line on stderr, no temp-staged
/// member left behind, the damaged member no worse, and a second run
/// repairs to the byte.
#[test]
fn an_interrupt_during_the_fold_is_clean_and_the_set_still_repairs() {
    let dir = scratch("cancel-fold");
    let member = dir.join("payload.bin");
    write_payload(&member, 128, 7);
    let before = digest(&member);
    // 40% recovery, and 30% of the member destroyed: ~600 of ~2,000
    // blocks to reconstruct, a fold a single thread spends seconds in.
    let (code, out, err) = parfast(&dir, &["c", "-r40", "set.par2", "payload.bin"]);
    assert_eq!(code, 0, "create failed: {out}{err}");
    let len = std::fs::metadata(&member).unwrap().len() as usize;
    destroy(&member, len / 10, len * 4 / 10);
    let originals = names(&dir);

    let run = interrupt_at(&dir, "Repairing: ");

    assert_eq!(
        run.code,
        Some(130),
        "stdout:\n{}\nstderr:\n{}",
        run.stdout,
        run.stderr
    );
    assert!(
        run.stderr
            .contains("Cancelled. No file is worse than it was"),
        "stderr: {}",
        run.stderr
    );
    assert!(
        !run.stdout.contains("Repair complete."),
        "stdout: {}",
        run.stdout
    );
    // The meter's fragment was ended before the stderr line, so a
    // terminal shows the two on separate lines.
    assert!(
        run.stdout.ends_with('\n'),
        "stdout tail: {:?}",
        &run.stdout[run.stdout.len().saturating_sub(40)..]
    );
    // Nothing new on disk but the run's own backup of the damaged member.
    for name in names(&dir) {
        let backup_of = name.strip_suffix(".1").map(str::to_owned);
        assert!(
            originals.contains(&name) || backup_of.is_some_and(|b| originals.contains(&b)),
            "left behind by the cancelled repair: {name}"
        );
    }
    assert_eq!(
        std::fs::metadata(&member).unwrap().len() as usize,
        len,
        "the member's length changed under a cancel"
    );

    let (code, out, err) = parfast(&dir, &["r", "set.par2"]);
    assert_eq!(code, 0, "the second run did not finish the job: {out}{err}");
    assert!(out.contains("Repair complete."), "{out}");
    assert_eq!(
        digest(&member),
        before,
        "repaired bytes differ from the original"
    );
}

/// Ctrl-C inside the verify pass, before anything is decided: the
/// directory is exactly as it was - not even a backup - and the main
/// thread does not answer the interrupt with a second verify of its own.
#[test]
fn an_interrupt_during_the_verify_pass_leaves_the_directory_untouched() {
    let dir = scratch("cancel-verify");
    let member = dir.join("payload.bin");
    write_payload(&member, 96, 11);
    let (code, out, err) = parfast(&dir, &["c", "-r10", "set.par2", "payload.bin"]);
    assert_eq!(code, 0, "create failed: {out}{err}");
    let len = std::fs::metadata(&member).unwrap().len() as usize;
    destroy(&member, len / 2, len / 2 + 4096);
    let damaged = digest(&member);
    let originals = names(&dir);

    let run = interrupt_at(&dir, "Scanning: ");

    assert_eq!(
        run.code,
        Some(130),
        "stdout:\n{}\nstderr:\n{}",
        run.stdout,
        run.stderr
    );
    assert!(run.stderr.contains("Cancelled."), "stderr: {}", run.stderr);
    assert!(
        !run.stdout.contains("Repair is required."),
        "the survey was still printed: {}",
        run.stdout
    );
    assert_eq!(
        names(&dir),
        originals,
        "the directory changed under a verify-phase cancel"
    );
    assert_eq!(
        digest(&member),
        damaged,
        "the member changed under a verify-phase cancel"
    );
}

/// Ctrl-C during a CREATE: exit 130, the line on stderr, and NOTHING of
/// the recovery set left on disk.
///
/// The last claim is the one that matters and the reason the engine
/// unlinks rather than leaving what it wrote (`Par2GenError::
/// Cancelled`): a volume is written to its FINAL name and the critical
/// packets are patched in LAST, so a create killed halfway leaves files
/// that name no member and verify against nothing - real enough for the
/// next tool to try, broken enough to fail.
///
/// Anchored on the last `Opening:` line, which the create prints before
/// it opens a single member, and sized so the arithmetic after it runs
/// for seconds: `-t1`, 64 MiB, 50% recovery. A run that finishes first
/// fails loudly in `interrupt_running` rather than passing.
#[test]
fn an_interrupt_during_a_create_leaves_no_recovery_set() {
    let dir = scratch("cancel-create");
    let member = dir.join("payload.bin");
    write_payload(&member, 64, 11);
    let before = digest(&member);
    let originals = names(&dir);

    let run = interrupt_running(
        &dir,
        &["c", "-t1", "-r50", "set.par2", "payload.bin"],
        "Opening: payload.bin",
    );

    assert_eq!(
        run.code,
        Some(130),
        "stdout:\n{}\nstderr:\n{}",
        run.stdout,
        run.stderr
    );
    assert!(run.stderr.contains("Cancelled."), "stderr: {}", run.stderr);
    // Not the repair's sentence: no file was worse than it was because
    // a create never touches one.
    assert!(
        !run.stderr.contains("No file is worse"),
        "stderr: {}",
        run.stderr
    );
    assert!(!run.stdout.contains("Done"), "stdout: {}", run.stdout);
    // THE PROMISE: not one file of the set, index included.
    assert_eq!(
        names(&dir),
        originals,
        "a cancelled create left part of a recovery set behind"
    );
    assert_eq!(
        digest(&member),
        before,
        "a create must not touch its source"
    );

    // And a second run writes the whole set, so the cancel cost the
    // work and nothing else.
    let (code, out, err) = parfast(&dir, &["c", "-r50", "set.par2", "payload.bin"]);
    assert_eq!(code, 0, "the second create failed: {out}{err}");
    assert!(dir.join("set.par2").exists(), "{out}");
    let (code, out, err) = parfast(&dir, &["v", "set.par2"]);
    assert_eq!(
        code, 0,
        "the set the second run wrote does not verify: {out}{err}"
    );
}
