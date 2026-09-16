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
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use crate::scratch::scratch;

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

/// How long [`interrupt_running`] waits for the marker before it FAILS
/// with a diagnostic, and how long it then allows the interrupted child
/// to close stdout and exit.
///
/// NEITHER IS A TIME TOLERANCE ON ANYTHING THESE TESTS ASSERT. Each is
/// orders of magnitude past the step it bounds, so crossing one means a
/// step that cannot finish rather than one that was slow. They exist
/// because the three blocking calls this helper used to make were
/// UNBOUNDED, and an unbounded wait in a test is a HANG: nextest kills
/// it at the `ci` profile's 600 s ceiling and then RETRIES it, so a
/// passing retry reports the whole shard as "N passed (1 flaky)" at
/// exit 0 and only `tools/wedge-gate.py`'s junit arm reddens. That is
/// exactly what happened on 16 Sep 2026 (ci-private runs 35049187493
/// and 35050641144), where the cause turned out to be the fixture's own
/// size on the slow half of GitHub's ubuntu-latest fleet and was found
/// by reading the shard's OTHER tests as calibrators, because this
/// helper itself said nothing. A test that fails with a message cannot
/// hide that way.
///
/// The worst end-to-end wall this test has ever been measured at is
/// 108.5 s, on that slow class, so the marker alone gets more than
/// twice the whole test's worst reading.
const MARKER_DEADLINE: Duration = Duration::from_secs(240);
/// The post-interrupt half: the engine answers an interrupt in a
/// measured 2-133 ms (15 in a row, 16 Sep 2026), so a minute is three
/// orders of magnitude of headroom.
const REAP_DEADLINE: Duration = Duration::from_secs(60);

/// `wait()` with a deadline. A child that will not exit is killed and
/// FAILS the test by name, rather than hanging until nextest's ceiling
/// turns it into a retry that can pass.
fn reap(child: &mut Child, after: &str) -> ExitStatus {
    let deadline = Instant::now() + REAP_DEADLINE;
    loop {
        match child.try_wait().expect("try_wait on the parfast child") {
            Some(status) => return status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the parfast child had not exited {REAP_DEADLINE:?} after {after}");
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

/// [`interrupt_at`] for any command line: the create's cancel is the
/// same promise read on a different subcommand.
///
/// BOTH PIPES GET A READER THREAD, from the moment the child is up, and
/// every wait here carries a deadline. The two hazards that shape this
/// are latent rather than historical, and both are the same class: a
/// blocking call with nothing to end it.
///
/// - stderr used to be read only AFTER `child.wait()` returned, which
///   is a deadlock as written: a child that fills the 64 KiB pipe
///   buffer blocks in `write`, so it never exits and `wait()` never
///   returns. The cancel path writes one line there today, and the
///   16 Sep 2026 diagnosis measured ZERO bytes on stderr before the
///   marker, which is why this was never that day's cause. But "the
///   child happens not to be chatty" is not a property any test here
///   asserts, and one more line on the cancel path would make it one.
/// - the marker loop blocked in `read` with no bound, so a child that
///   was alive but silent produced no EOF and therefore never reached
///   the loud panic the loop already has for a run that ends early.
fn interrupt_running(dir: &Path, args: &[&str], marker: &str) -> Interrupted {
    let mut child = Command::new(env!("CARGO_BIN_EXE_parfast"))
        .args(args)
        .current_dir(dir)
        .env("NZBFAST_NO_ENRICH", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("parfast spawns");
    let mut errpipe = child.stderr.take().unwrap();
    let errt = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = errpipe.read_to_end(&mut bytes);
        bytes
    });
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let mut outpipe = child.stdout.take().unwrap();
    let outt = std::thread::spawn(move || {
        let mut buf = [0u8; 256];
        while let Ok(n) = outpipe.read(&mut buf) {
            if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });

    let mut seen = Vec::new();
    let deadline = Instant::now() + MARKER_DEADLINE;
    loop {
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(chunk) => {
                seen.extend_from_slice(&chunk);
                if String::from_utf8_lossy(&seen).contains(marker) {
                    break;
                }
            }
            // stdout is at EOF: the run ended without printing the
            // marker, so the window this test needs was missed.
            Err(RecvTimeoutError::Disconnected) => {
                let status = reap(&mut child, "stdout reached EOF");
                panic!(
                    "the run finished (status {status}) before {marker:?} was seen - the window \
                     this test needs was missed, so nothing here was tested:\n{}",
                    String::from_utf8_lossy(&seen)
                );
            }
            Err(RecvTimeoutError::Timeout) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "{marker:?} never reached stdout in {MARKER_DEADLINE:?} and the run was still \
                     alive and silent, so the interrupt under test was never sent. This is the \
                     hang that used to be a 600 s nextest kill and a passing retry; read the \
                     stdout below and the shard's other tests before reaching for the \
                     ceiling:\n{}",
                    String::from_utf8_lossy(&seen)
                );
            }
        }
    }

    let kill = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .expect("kill runs");
    assert!(kill.success(), "kill -INT failed");

    // Drain stdout to EOF, on a deadline, then reap.
    let drain_by = Instant::now() + REAP_DEADLINE;
    loop {
        match rx.recv_timeout(drain_by.saturating_duration_since(Instant::now())) {
            Ok(chunk) => seen.extend_from_slice(&chunk),
            Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "stdout was still open {REAP_DEADLINE:?} after the interrupt, so the cancel \
                     never reached the exit path:\n{}",
                    String::from_utf8_lossy(&seen)
                );
            }
        }
    }
    let status = reap(&mut child, "the interrupt");
    let err = errt.join().expect("the stderr reader thread");
    outt.join().expect("the stdout reader thread");
    Interrupted {
        code: status.code(),
        stdout: String::from_utf8_lossy(&seen).into_owned(),
        stderr: String::from_utf8_lossy(&err).into_owned(),
    }
}

/// Ctrl-C inside the fold: exit 130, the line on stderr, no temp-staged
/// member left behind, the damaged member no worse, and a second run
/// repairs to the byte.
#[test]
fn an_interrupt_during_the_fold_is_clean_and_the_set_still_repairs() {
    let dir = scratch("cancel-fold");
    let member = dir.join("payload.bin");
    // 16 MiB, NOT the 128 MiB this was written with on 12 Sep 2026.
    //
    // The engine picks ~2,000 data blocks whatever the member's size, so
    // the payload sets the BLOCK SIZE and nothing else: every claim below
    // is block-count arithmetic and reads the same at either size, while
    // the two full folds this test pays for - the create, and the second
    // complete repair at the foot - cost bytes. 128 MiB made this the
    // most expensive test in the whole repo by a factor of four, and on
    // the slower half of GitHub's ubuntu-latest fleet it ran past
    // nextest's 600 s ceiling: measured 151.7 s on a fast runner and
    // 509.4 / 506.5 s on slow ones, with the 600 s kill landing whenever
    // a slow runner also had the rest of the shard beside it (ci-private
    // runs 35049187493, 35050641144, 35057017045; wedge-gate's junit arm
    // was the only thing that reddened, because nextest's retry then
    // passed). The fleet spread is the runner and not this test: in the
    // same shard of the same commit, `forney::joint::tests::
    // a_short_last_stripe_is_padded_and_still_exact` went 20.1 s to
    // 135.4 s and `sevenz::tests::multi_threaded_lzma2_is_deterministic
    // _and_matches_single_threaded_below_a_chunk` 39.5 s to 72.6 s.
    //
    // WHY SHRINKING IS SAFE HERE AND IS NOT A TIME TOLERANCE. The window
    // this test needs is the one between the fold's first `Repairing:`
    // fragment and the end of the fold, because that is where the signal
    // has to land; the fold's work is recovery blocks times input blocks
    // times block size, so at 16 MiB the window between that fragment
    // and the end of an uninterrupted `-t1` run is a measured 19.3 s
    // against the interrupt's 20 ms ceiling
    // (`control::install_interrupt`), which is
    // the same three orders of magnitude the module doc claims. Measured
    // on the dev Mac, 16 Sep 2026: the test is 11.5 s at 128 MiB and
    // 2.1 s at 16 MiB, three runs each on an idle box, and 15 interrupts
    // in a row were answered in 2-133 ms. AND MEASURED ON THE RIG, three
    // ci-private runs after the change: 21.6 s on a fast runner (run
    // 35063798711) against the 151.7 s that class used to take, and
    // 108.5 / 108.3 s on two slow ones (35066171324, 35063777117)
    // against the 509.4 / 506.5 s and the 600 s kills that class used to
    // take. Still over nextest's 60 s SLOW notice on the slow class, and
    // 5.5x under the ceiling rather than over it. Do NOT read the same
    // argument across to the two tests below it: their window is a VERIFY pass,
    // which is one linear hash of the member, so their size buys the
    // window directly and shrinking them shortens what they aim at.
    write_payload(&member, 16, 7);
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
    // 96 MiB and `-r2`, and only the second of those moved (from -r10,
    // 16 Sep 2026). THE PAYLOAD IS THE WINDOW and is deliberately left
    // alone: the span the signal has to land in is the rest of the
    // repair's verify scan after its first `Scanning:` fragment, and
    // that scan is one linear pass over this member, so a smaller
    // payload would shorten the very thing this test aims at. The
    // create's `-r` is not in that span - this create runs to
    // completion before the pass under test begins - and cutting it
    // fivefold takes about 7.7 MiB of recovery volume out of a ~106 MiB
    // scan, so the window loses under 10% while the create's fold, which
    // is recovery blocks times input blocks times block size, loses 80%.
    //
    // Measured 16 Sep 2026 on the dev Mac under load ~81-112 (the whole
    // test, `--test-threads=1`): 15.52 s before, 6.81-7.82 s after, with
    // the load higher for the second reading. On the slow half of
    // GitHub's ubuntu-latest fleet it was 229.2 s - the largest single
    // test in the job that was being cap-killed (GAP 4 of that same
    // note).
    write_payload(&member, 96, 11);
    let (code, out, err) = parfast(&dir, &["c", "-r2", "set.par2", "payload.bin"]);
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
    //
    // `-r5`, NOT the `-r50` the interrupted create above uses, and the
    // asymmetry is the point rather than an oversight. THIS create is
    // never interrupted: it carries no window, it is here only to show
    // that the set the cancel refused to leave behind can still be
    // written, and a create's fold is recovery blocks times input
    // blocks times block size - so ten times less recovery is ten times
    // less fold for a claim that reads identically at either figure.
    // The create ABOVE keeps `-r50` precisely because its `-r` IS the
    // window: the signal has to land between `Opening:` and the end of
    // a `-t1` create, and that span is what `-r` sets.
    //
    // Measured 16 Sep 2026 on the dev Mac under load ~81-112 (the whole
    // test, `--test-threads=1`): 20.16 s before, 12.85-13.11 s after,
    // and the load was HIGHER for the second reading than the first, so
    // the true gain is larger than the ratio shows. 20 consecutive runs
    // of this test and its sibling green at load 98-142. On the slow
    // half of GitHub's ubuntu-latest fleet this test was 176.7 s, which
    // is what made `unit-one-process` too big for its cap (GAP 4 of the
    // 16 Sep 2026 one-process coverage note, which is in the private
    // tree, so it is not named here).
    let (code, out, err) = parfast(&dir, &["c", "-r5", "set.par2", "payload.bin"]);
    assert_eq!(code, 0, "the second create failed: {out}{err}");
    assert!(dir.join("set.par2").exists(), "{out}");
    let (code, out, err) = parfast(&dir, &["v", "set.par2"]);
    assert_eq!(
        code, 0,
        "the set the second run wrote does not verify: {out}{err}"
    );
}
