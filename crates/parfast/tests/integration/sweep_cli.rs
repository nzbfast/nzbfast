//! The 9 Nov 2026 sweep's front-end findings that need the BUILT binary
//! or a whole repair: `-a` dropping its donor, a non-UTF-8 argument, and
//! an inherited ignored SIGINT. Each had a NEGATIVE CONTROL run when it
//! landed: the fixed line put back, the test seen to fail, the line
//! restored.

use std::path::Path;

use crate::inproc::in_process;
use crate::scratch::scratch;

fn arg(s: &str) -> String {
    s.to_string()
}

fn path(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// Non-repeating bytes, so no block of the payload matches another.
fn payload(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (x >> 33) as u8
        })
        .collect()
}

/// `parfast r -a set.par2 <donor>` with the set EXISTING: the first bare
/// argument is a data file, as it is on create and as par2cmdline 1.2.0
/// takes it (measured 9 Nov 2026: it repairs from it). The parser had
/// put it in `par2`, which `verify::locate` never reads once the archive
/// exists, so the repair ran with no donor at all.
///
/// The donor sits OUTSIDE the set's directory, so only the argument can
/// reach it, and a stray file sits INSIDE, so the "is there any candidate
/// at all" gate in `repair.rs` hands the verdict to the engine instead of
/// printing "Repair is not possible." on the block count alone.
#[test]
fn an_archive_name_keeps_the_first_bare_argument_as_a_donor() {
    let parfast = in_process();
    let dir = scratch("sweep-archive-donor");
    let set_dir = dir.join("set");
    let backup = dir.join("backup");
    std::fs::create_dir_all(&set_dir).unwrap();
    std::fs::create_dir_all(&backup).unwrap();
    let member = set_dir.join("m.bin");
    let bytes = payload(64 * 1024, 7);
    std::fs::write(&member, &bytes).unwrap();
    let set = set_dir.join("set.par2");
    let (code, _, err) = parfast.run(&[
        arg("c"),
        arg("-q"),
        arg("-s4096"),
        arg("-c1"),
        path(&set),
        path(&member),
    ]);
    assert_eq!(code, 0, "fixture create: {err}");

    let donor = backup.join("donor.dat");
    std::fs::rename(&member, &donor).unwrap();
    std::fs::write(set_dir.join("unrelated.txt"), b"not a member\n").unwrap();

    let (code, out, err) = parfast.run(&[arg("r"), format!("-a{}", path(&set)), path(&donor)]);
    assert_eq!(code, 0, "stdout:\n{out}\nstderr:\n{err}");
    assert_eq!(
        std::fs::read(&member).expect("the member is back"),
        bytes,
        "repaired from the donor"
    );
}

/// A8: a non-UTF-8 argument is refused at exit 3 with its name on
/// stderr. `std::env::args()` panicked on it - exit 101 before a line of
/// par2 output.
#[cfg(unix)]
#[test]
fn a_non_utf8_argument_is_refused_not_a_panic() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::process::{Command, Output};
    let dir = scratch("sweep-non-utf8");
    let out: Output = Command::new(env!("CARGO_BIN_EXE_parfast"))
        .arg("r")
        .arg("set.par2")
        .arg(OsStr::from_bytes(b"caf\xe9.bin"))
        .current_dir(&*dir)
        .env("NZBFAST_NO_ENRICH", "1")
        .output()
        .expect("parfast runs");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(3), "stderr: {err}");
    assert!(err.contains("not valid UTF-8"), "{err}");
    assert!(!err.contains("panicked"), "{err}");
}

/// A18: a process started with SIGINT IGNORED keeps it ignored - the
/// shape a POSIX shell gives a background job (`parfast v set.par2 &`),
/// so a Ctrl-C meant for the foreground does not cancel it.
///
/// The verify reads its member list from stdin (`@`), which parks the
/// process on the read with the handlers already in place; SIGINT lands
/// there, and only then is the list sent. Without the fix the handler
/// took the signal, the gate was cancelled before the first member, and
/// the verify answered "Cancelled." at exit 130 over an intact set.
///
/// It discriminates on macOS, where nothing reads stdin before the hook.
/// On linux-gnu `main` parses argv once BEFORE the hook (the mmap
/// threshold decision), so the stdin read - and the signal - land before
/// any handler exists and both arms pass; it is still a correct test
/// there, only not a discriminating one.
#[cfg(unix)]
#[test]
fn an_inherited_ignored_sigint_stays_ignored() {
    use std::io::Write as _;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let dir = scratch("sweep-sig-ign");
    std::fs::write(dir.join("m.bin"), payload(64 * 1024, 11)).unwrap();
    let made = Command::new(env!("CARGO_BIN_EXE_parfast"))
        .args(["c", "-q", "-s4096", "-c1", "set.par2", "m.bin"])
        .current_dir(&*dir)
        .env("NZBFAST_NO_ENRICH", "1")
        .output()
        .expect("fixture create");
    assert!(made.status.success(), "{made:?}");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_parfast"));
    cmd.args(["v", "-q", "set.par2", "@"])
        .current_dir(&*dir)
        .env("NZBFAST_NO_ENRICH", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: `signal` is async-signal-safe and touches no Rust state;
    // it runs in the forked child before exec, which is what `pre_exec`
    // is for.
    unsafe {
        cmd.pre_exec(|| {
            libc::signal(libc::SIGINT, libc::SIG_IGN);
            Ok(())
        });
    }
    let mut child = cmd.spawn().expect("parfast runs");
    // Long enough for the binary to reach the stdin read on a loaded box;
    // a signal that lands earlier is ignored by the inherited disposition
    // in both arms, which makes the run pass rather than fail.
    std::thread::sleep(std::time::Duration::from_secs(3));
    // SAFETY: `kill` on our own child's pid.
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGINT);
    }
    std::thread::sleep(std::time::Duration::from_millis(200));
    {
        let mut stdin = child.stdin.take().expect("stdin");
        stdin.write_all(b"m.bin\n").unwrap();
    }
    let out = child.wait_with_output().expect("parfast exits");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr: {err}");
    assert!(!err.contains("Cancelled"), "{err}");
}

/// A6 review, the reviewer's own command line: the set named by an
/// ABSOLUTE path that runs through a symlink, the member by a RELATIVE
/// name, from inside the directory. macOS's `$TMPDIR` is exactly this
/// (`/var` is a link to `/private/var`); here the link is made, so the
/// test does not depend on the platform's layout. The child's cwd is the
/// link, and the OS reports it as the real directory, so the first cut of
/// A6 compared a typed `/.../link/` against a joined `/.../real/a.bin`,
/// printed "Ignoring out of basepath source file" and exited 3 - where
/// every earlier build stored `a.bin`.
#[cfg(unix)]
#[test]
fn a_relative_member_beside_a_set_named_through_a_link() {
    use std::process::Command;
    let dir = scratch("sweep-a6-link");
    std::fs::create_dir_all(dir.join("real")).unwrap();
    std::os::unix::fs::symlink(dir.join("real"), dir.join("link")).unwrap();
    std::fs::write(dir.join("real").join("a.bin"), payload(16 * 1024, 13)).unwrap();
    let set = dir.join("link").join("p1.par2");
    let out = Command::new(env!("CARGO_BIN_EXE_parfast"))
        .args(["c", "-s4096", "-c1"])
        .arg(&set)
        .arg("a.bin")
        .current_dir(dir.join("link"))
        .env("NZBFAST_NO_ENRICH", "1")
        .output()
        .expect("parfast runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!stdout.contains("Ignoring out of basepath"), "{stdout}");
    let index = std::fs::read(dir.join("real").join("p1.par2")).unwrap();
    let parsed = nzbkit::par2::Par2Set::parse(&[&index]).expect("our own set parses");
    let names: Vec<&str> = parsed.files.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, vec!["a.bin"]);
}
