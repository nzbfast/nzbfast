//! What the generated profile and argv actually SAY - one arm per
//! platform, both compiled and run on every host (see the note on
//! `mod mac` / `mod linux` in the parent).
//!
//! These are string and vector assertions on purpose. The thing that
//! goes wrong with a sandbox is not that it fails to build, it is that
//! it builds a policy nobody read - so the tests read it.

use super::*;

fn tool_policy(dir: &str) -> Policy {
    Policy::tool("unrar", Path::new(dir))
}

/// How a policy will SPELL `dir`, for the argv tests below.
///
/// These tests run on every host (see the module doc) but the
/// constructors send every path through `resolve`, whose answer is the
/// HOST's - so a literal in an expectation is only right where nothing
/// on the way to that path exists. On Windows that is never.
///
/// The account this comment used to give was wrong in a way worth
/// correcting rather than deleting, because it is the belief that left
/// four arms behind: it said the trigger was a runner that "turned out
/// to have a real `D:\downloads`". `resolve` walks up to the longest
/// EXISTING prefix, and the drive root always exists - measured on a
/// native x86 Windows box with no `C:\jobs`, no `C:\downloads` and no
/// `D:` drive at all: `canonicalize("/")` answers `Ok("\\?\C:\")` and
/// `/jobs/x` comes back `\\?\C:\jobs\x`. So every fixture path here
/// is rewritten on Windows, not just one that happens to be real; a
/// path that does not exist is NOT safe. Working:
/// `research/NOTE-2026-09-02-SANDBOX-TESTS-RESOLVE-ON-WINDOWS.md`.
///
/// The subject of the argv arms is the argv SHAPE, so ask `resolve` for
/// the spelling and keep asserting the shape exactly. `resolve`'s own
/// behaviour is covered by
/// `a_policy_path_is_resolved_to_what_the_kernel_sees`.
fn spelled(dir: &str) -> String {
    resolve(Path::new(dir)).to_string_lossy().into_owned()
}

/// A tool policy that names `dir` VERBATIM - no `resolve`, no host.
///
/// `spelled` above is the right answer where the subject is the argv
/// shape, because there the path is passed through and any spelling is
/// as good as another. It is the wrong answer where the subject is what
/// the profile writer DOES to the path: `mac::profile` escapes it, so an
/// expectation built by escaping `spelled(..)` in the test would be
/// asserting `sbpl_escape` against a second copy of itself and would
/// pass however wrong both were.
///
/// So these arms name the bytes they assert on. `Policy`'s fields are
/// `pub`, and the constructor's own behaviour - resolving a path to what
/// the kernel sees - is covered by
/// `a_policy_path_is_resolved_to_what_the_kernel_sees`, which is where
/// it belongs. A pure function's test should not depend on the host
/// filesystem, which is the whole of what went wrong on 2 Sep 2026:
/// `89fa01a07` fixed the two bwrap arms this way and the four profile
/// arms below were left asserting `/jobs/x` through `resolve`, so
/// `a_quote_in_a_path_cannot_end_the_profile_literal` - one of the two
/// arms CI named - was byte-identical to the run that reddened.
fn verbatim_tool_policy(dir: &str) -> Policy {
    Policy {
        label: "unrar",
        writable: vec![PathBuf::from(dir)],
        readable: Vec::new(),
        read_all: false,
        network: false,
        tie_lifetime: true,
    }
}

// ------------------------------------------------------------- macOS

#[test]
fn a_tool_profile_denies_by_default_and_confines_reads_writes_and_network() {
    let p = mac::profile(
        Path::new("/opt/homebrew/bin/unrar"),
        &verbatim_tool_policy("/jobs/x"),
        true,
    )
    .expect("a UTF-8 policy has a profile");
    assert!(p.starts_with("(version 1)\n(deny default)\n"), "{p}");
    // Load-bearing, and measured: without the import the child aborts
    // at dyld time, and without file-map-executable it never reaches
    // `main`. See the module doc's stated limits.
    assert!(p.contains(&format!("(import \"{BSD_PROFILE}\")")), "{p}");
    assert!(p.contains("(allow file-map-executable)"), "{p}");
    assert!(p.contains("(deny network*)"), "{p}");
    assert!(
        p.contains("(allow file-read* file-write* (subpath \"/jobs/x\"))"),
        "{p}"
    );
    // The tool's own directory is readable; the user's home is not.
    assert!(p.contains("(subpath \"/opt/homebrew/bin\")"), "{p}");
    assert!(!p.contains("(allow default)"), "{p}");
    for dir in mac::SYSTEM_READ {
        assert!(p.contains(&format!("(subpath \"{dir}\")")), "{dir} in {p}");
    }
}

/// The fixture paths are chosen NOT to exist: `Policy` resolves symlinks
/// and case (`/library` canonicalizes to `/Library` on an APFS volume),
/// so a path that is real on the test host would be rewritten under the
/// assertion.
#[test]
fn a_script_profile_keeps_reads_and_network_and_confines_only_writes() {
    // Verbatim for the same reason as the tool arms above: this asserts
    // the SPELLING the profile writer emits, so the fixture must not go
    // through `resolve` and pick up the host's answer.
    let policy = Policy {
        label: "script",
        writable: vec![
            PathBuf::from("/downloads/job"),
            PathBuf::from("/nzbfast-test/library"),
        ],
        readable: Vec::new(),
        read_all: true,
        network: true,
        tie_lifetime: false,
    };
    let p = mac::profile(Path::new("/usr/local/bin/pp.sh"), &policy, true)
        .expect("a UTF-8 policy has a profile");
    // The deliberate asymmetry with the tool policy, and the module doc
    // says why: a notifier needs the network and a filer needs to read
    // a media tree, so a policy that took either would be turned off
    // wholesale and the write confinement would go with it.
    assert!(p.contains("(allow default)"), "{p}");
    assert!(p.contains("(deny file-write*)"), "{p}");
    assert!(!p.contains("(deny network*)"), "{p}");
    assert!(!p.contains("(deny default)"), "{p}");
    for dir in ["/downloads/job", "/nzbfast-test/library"] {
        assert!(
            p.contains(&format!(
                "(allow file-read* file-write* (subpath \"{dir}\"))"
            )),
            "{p}"
        );
    }
}

#[test]
fn a_tool_profile_degrades_to_write_confinement_without_the_bsd_profile() {
    let p = mac::profile(
        Path::new("/usr/bin/unrar"),
        &verbatim_tool_policy("/jobs/x"),
        false,
    )
    .expect("a UTF-8 policy has a profile");
    // Still no network and still no writes outside the job - only the
    // read confinement is lost, which is the whole of the degradation.
    assert!(p.contains("(allow default)"), "{p}");
    assert!(p.contains("(deny file-write*)"), "{p}");
    assert!(p.contains("(deny network*)"), "{p}");
    assert!(
        p.contains("(allow file-read* file-write* (subpath \"/jobs/x\"))"),
        "{p}"
    );
    assert!(!p.contains(BSD_PROFILE), "{p}");
}

#[test]
fn a_quote_in_a_path_cannot_end_the_profile_literal() {
    let p = mac::profile(
        Path::new("/usr/bin/unrar"),
        &verbatim_tool_policy("/jobs/a\"b\\c"),
        true,
    )
    .expect("a UTF-8 policy has a profile");
    assert!(p.contains(r#"(subpath "/jobs/a\"b\\c")"#), "{p}");
}

#[test]
#[cfg(unix)]
fn a_path_that_is_not_utf8_gets_no_profile_rather_than_a_lossy_one() {
    use std::os::unix::ffi::OsStrExt;
    let dir = PathBuf::from(std::ffi::OsStr::from_bytes(b"/jobs/\xff\xfe"));
    let policy = Policy::tool("unrar", &dir);
    // `None` means "spawn unconfined and say so", which is right:
    // a lossy conversion would confine a directory that is not the
    // one the job is in.
    assert!(mac::profile(Path::new("/usr/bin/unrar"), &policy, true).is_none());
}

/// A policy names paths the way the KERNEL will, not the way the caller
/// spelled them. On macOS `/tmp` is a symlink to `/private/tmp`, and a
/// rule written against the symlink matches nothing the child opens -
/// the one failure mode a sandbox must not have, because it looks
/// exactly like a sandbox that is working.
#[test]
#[cfg(target_os = "macos")]
fn a_policy_path_is_resolved_to_what_the_kernel_sees() {
    let p = Policy::tool("unrar", Path::new("/tmp"));
    assert_eq!(p.writable, vec![PathBuf::from("/private/tmp")]);
    // And a directory that does not exist yet keeps its tail rather
    // than collapsing to the nearest real ancestor.
    let p = Policy::tool("unrar", Path::new("/tmp/nzbfast-no-such-dir/x"));
    assert_eq!(
        p.writable,
        vec![PathBuf::from("/private/tmp/nzbfast-no-such-dir/x")]
    );
}

// ------------------------------------------------------------- Linux

#[test]
fn bwrap_argv_for_a_tool_is_the_policy_word_for_word() {
    let a: Vec<String> = linux::bwrap_args(&tool_policy("/jobs/x"))
        .iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect();
    let mut want = vec![
        "--die-with-parent".to_string(),
        "--unshare-net".to_string(),
        "--unshare-ipc".to_string(),
        "--unshare-uts".to_string(),
    ];
    for dir in linux::SYSTEM_READ {
        want.extend([
            "--ro-bind-try".to_string(),
            dir.to_string(),
            dir.to_string(),
        ]);
    }
    want.extend([
        "--proc".to_string(),
        "/proc".to_string(),
        "--dev".to_string(),
        "/dev".to_string(),
        // Private, and AFTER nothing that could be written through: the
        // job bind below lands on top of it, so a job directory under
        // /tmp is still the real one.
        "--tmpfs".to_string(),
        "/tmp".to_string(),
        "--bind-try".to_string(),
        spelled("/jobs/x"),
        spelled("/jobs/x"),
        "--".to_string(),
    ]);
    assert_eq!(a, want);
    // Never: it would make bwrap pid 1 of the namespace, and tearing
    // the sandbox down would kill a script's backgrounded descendant.
    assert!(!a.iter().any(|s| s == "--unshare-pid"));
}

#[test]
fn bwrap_argv_for_a_script_keeps_the_network_and_the_whole_tree_readable() {
    let a: Vec<String> = linux::bwrap_args(&Policy::script(vec![PathBuf::from("/downloads")]))
        .iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        a,
        vec![
            "--unshare-ipc".to_string(),
            "--unshare-uts".to_string(),
            "--ro-bind".to_string(),
            "/".to_string(),
            "/".to_string(),
            "--proc".to_string(),
            "/proc".to_string(),
            "--dev".to_string(),
            "/dev".to_string(),
            // No --tmpfs: a script keeps the real /tmp, which its
            // writable set already covers.
            "--bind-try".to_string(),
            spelled("/downloads"),
            spelled("/downloads"),
            "--".to_string(),
        ]
    );
    // A script may background a transcode and exit; `--die-with-parent`
    // would kill it when the daemon stops.
    assert!(!a.iter().any(|s| s == "--die-with-parent"));
}

#[test]
fn unshare_argv_is_the_network_only_rung() {
    let a: Vec<String> = linux::unshare_args(&tool_policy("/jobs/x"))
        .iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect();
    assert_eq!(a, vec!["--user", "--map-current-user", "--net", "--"]);
    let s: Vec<String> = linux::unshare_args(&Policy::script(vec![]))
        .iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect();
    assert_eq!(s, vec!["--user", "--map-current-user", "--"]);
}

// The four arms below name `/usr/bin/bwrap` as a literal and are NOT
// subject to the `spelled` trap at the top of this file: these builders
// never call `resolve`, and `Path::display` rewrites no separator, so
// the string is the same byte-for-byte on a Windows runner.

#[test]
fn a_bwrap_that_refused_the_probe_is_never_reported_as_missing() {
    let m = linux::bwrap_refused(
        Path::new("/usr/bin/bwrap"),
        "bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted\n",
    );
    // The whole defect this arm exists for: the row used to say the
    // package was not installed about a package that is installed, which
    // is the one sentence that sends its reader nowhere.
    assert!(!m.contains("not installed"), "{m}");
    assert!(!m.contains("neither"), "{m}");
    assert!(m.contains("/usr/bin/bwrap"), "{m}");
    // The child's own line, quoted rather than guessed at.
    assert!(
        m.contains("(bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted)"),
        "{m}"
    );
    // And a remedy that is actually the remedy on the distribution this
    // was measured on.
    assert!(m.contains("/etc/apparmor.d/bwrap"), "{m}");
    assert!(m.contains("apparmor_parser -r"), "{m}");
    // The second cause, because our own packaged unit can do it too.
    assert!(m.contains("RestrictNamespaces"), "{m}");
}

#[test]
fn a_refused_unshare_names_bubblewrap_and_the_profile_it_needs() {
    let m = linux::unshare_refused(
        Path::new("/usr/bin/unshare"),
        "unshare: write failed /proc/self/uid_map: Operation not permitted\n",
    );
    assert!(!m.contains("not installed"), "{m}");
    assert!(m.contains("/usr/bin/unshare"), "{m}");
    assert!(
        m.contains("(unshare: write failed /proc/self/uid_map: Operation not permitted)"),
        "{m}"
    );
    // This rung's remedy is NOT the bwrap profile on its own - the
    // profile names bwrap, so bubblewrap has to arrive with it.
    assert!(m.contains("install bubblewrap"), "{m}");
    assert!(m.contains("/etc/apparmor.d/bwrap"), "{m}");
}

#[test]
fn a_refusal_with_nothing_on_stderr_is_still_a_refusal_with_a_remedy() {
    let m = linux::bwrap_refused(Path::new("/usr/bin/bwrap"), "   \n\n");
    // No empty parenthesis where the quote would have gone.
    assert!(!m.contains("()"), "{m}");
    assert!(m.contains("would not start,"), "{m}");
    assert!(m.contains("/etc/apparmor.d/bwrap"), "{m}");
    assert!(!m.contains("not installed"), "{m}");
}

#[test]
fn the_probe_reason_is_the_last_line_stripped_of_control_bytes_and_capped() {
    // Last non-empty line, not the first: a wrapper prints its fatal
    // reason last.
    assert_eq!(
        linux::probe_reason("bwrap: warning: something\nbwrap: the real reason\n").as_deref(),
        Some("bwrap: the real reason")
    );
    // A tab becomes a space rather than vanishing, so the words it
    // separated stay separated; the escape BYTE goes and its `[31m`
    // tail is left, which the builder documents as deliberate.
    assert_eq!(
        linux::probe_reason("a\tb\x1b[31mc\r\n").as_deref(),
        Some("a b [31mc")
    );
    // Nothing usable is None, so the caller writes no parentheses.
    assert_eq!(linux::probe_reason(""), None);
    assert_eq!(linux::probe_reason("\n \r\n"), None);
    // Capped, and the cap counts CHARACTERS - a multi-byte line must not
    // be cut inside one.
    let long = "\u{e9}".repeat(400);
    let r = linux::probe_reason(&long).expect("a long line still reads");
    assert_eq!(r, format!("{}...", "\u{e9}".repeat(160)));
    assert_eq!(r.chars().count(), 163);
}

#[test]
fn nothing_on_path_still_says_install_bubblewrap_and_claims_no_probe() {
    let m = linux::NOTHING_INSTALLED;
    assert!(m.contains("install bubblewrap"), "{m}");
    assert!(m.contains("$PATH"), "{m}");
    // It must not read as a probe verdict - that is the other branch.
    assert!(!m.contains("would not start"), "{m}");
}

// ----------------------------------------------------------- Windows

#[test]
fn the_job_object_spec_for_a_tool_ties_lifetime_caps_processes_and_takes_the_ui() {
    let l = windows::limits(&tool_policy("/jobs/x"));
    assert_eq!(
        l,
        windows::Limits {
            // Policy::tool sets tie_lifetime, and KILL_ON_JOB_CLOSE is
            // what honours it. Measured both ways on a native x86 box,
            // 2 Sep 2026 - see the module doc's stated limits.
            tie: true,
            ui: true,
            procs: windows::TOOL_ACTIVE_PROCESSES,
        }
    );
    assert_eq!(windows::spec(&l), "v1:tie=1,ui=1,procs=64");
}

/// The same deliberate asymmetry the macOS profile and the bwrap argv
/// carry: a script keeps what a user's own code plausibly needs.
#[test]
fn the_job_object_spec_for_a_script_keeps_the_ui_and_caps_nothing() {
    let l = windows::limits(&Policy::script(vec![PathBuf::from("/downloads")]));
    assert_eq!(
        l,
        windows::Limits {
            // A script may background a transcode and exit; tying the
            // job's lifetime would kill it when the daemon stops, which
            // is exactly why `Policy::script` clears `tie_lifetime`.
            tie: false,
            ui: false,
            procs: 0,
        }
    );
    assert_eq!(windows::spec(&l), "v1:tie=0,ui=0,procs=0");
}

/// The helper is RESOLVED rather than linked - in a test build it may be
/// a different build's `nzbfast.exe` - so a spec it half-understood
/// would confine less than the caller believes. Round-trip, and refuse
/// everything else.
#[test]
fn a_spec_the_helper_cannot_read_whole_is_refused_rather_than_guessed() {
    for policy in [tool_policy("/jobs/x"), Policy::script(vec![])] {
        let l = windows::limits(&policy);
        assert_eq!(windows::parse_spec(&windows::spec(&l)), Some(l));
    }
    for bad in [
        "",
        "tie=1,ui=1,procs=64",        // no version tag
        "v2:tie=1,ui=1,procs=64",     // a tag this build does not write
        "v1:tie=1,ui=1",              // a field missing
        "v1:tie=1,ui=1,procs=64,x=1", // a field this build does not know
        "v1:tie=yes,ui=1,procs=64",   // not a bit
        "v1:tie=1,ui=1,procs=-4",     // not a count
        "v1:tie",                     // no value at all
    ] {
        assert_eq!(windows::parse_spec(bad), None, "{bad:?} must not parse");
    }
}

/// Everything the caller appends still lands after the program, which is
/// [`command`]'s whole contract. Same shape as `mac::wrap`.
#[test]
fn the_helper_argv_puts_the_program_last_so_the_callers_arguments_follow() {
    let policy = tool_policy("/jobs/x");
    let mut c = windows::wrap(
        Path::new("/opt/nzbfast/nzbfast"),
        &windows::confine_args(&policy),
        Path::new("/usr/bin/unrar"),
    );
    c.args(["x", "-y"]);
    let argv: Vec<String> = c
        .get_args()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        c.get_program(),
        Path::new("/opt/nzbfast/nzbfast").as_os_str()
    );
    assert_eq!(
        argv,
        vec![
            windows::CONFINE_FLAG.to_string(),
            "v1:tie=1,ui=1,procs=64".to_string(),
            "/usr/bin/unrar".to_string(),
            "x".to_string(),
            "-y".to_string(),
        ]
    );
}

/// The exit codes the helper reserves must not be mistakable for a
/// tool's own verdict. `par2cmdline` exits 0 to 8 and `unrar` 0 to 11,
/// and both call sites read those numbers.
#[test]
fn the_helpers_own_exit_codes_are_outside_every_tools_range() {
    assert!(
        windows::EXIT_NOT_CONFINED > 128,
        "must not look like a tool"
    );
    assert_ne!(windows::EXIT_NOT_CONFINED, windows::EXIT_NO_CHILD);
    for tool_code in 0..=11 {
        assert_ne!(windows::EXIT_NOT_CONFINED, tool_code);
        assert_ne!(windows::EXIT_NO_CHILD, tool_code);
    }
}

/// **On Windows a bare name is not a program.** `CreateProcessW` appends
/// `.exe` to a name with no extension and consults no `PATHEXT`, so the
/// `$PATH` walk has to look for what `Command::new` would actually run.
/// Looking for the bare name is why the confinement was unreachable on
/// Windows for every `$PATH`-resolved tool until 2 Sep 2026.
#[test]
fn a_path_walk_looks_for_what_command_new_would_actually_run() {
    assert_eq!(path_candidates("unrar", true), vec!["unrar.exe"]);
    assert_eq!(path_candidates("unrar", false), vec!["unrar"]);
    // Already spelled with one: taken as written, on both.
    assert_eq!(path_candidates("unrar.exe", true), vec!["unrar.exe"]);
    // And a version in the name IS an extension as far as the loader is
    // concerned, so it is taken as written rather than grown a second
    // one. `par2-0.8.1` is a real binary name on the Windows test box.
    assert_eq!(path_candidates("par2-0.8.1", true), vec!["par2-0.8.1"]);
}

/// End to end, on Windows only: a real child runs under a real job
/// object and its exit code arrives untouched.
///
/// Skipped, loudly, where no helper answered - a test binary cannot be
/// one (libtest owns its argv) and the real `nzbfast.exe` is not always
/// built beside it. That is the documented degradation, not a failure.
#[test]
#[cfg(windows)]
fn a_confined_child_on_windows_returns_its_own_exit_code() {
    if detect().mechanism != Mechanism::JobObject {
        eprintln!(
            "no job-object helper on this box ({}) - skipped",
            detect().detail
        );
        return;
    }
    let cmd_exe = PathBuf::from(std::env::var_os("COMSPEC").expect("COMSPEC"));
    for want in [0, 7] {
        let st = command(&cmd_exe, &tool_policy("/jobs/x"))
            .args(["/c", &format!("exit {want}")])
            .stdin(std::process::Stdio::null())
            .status()
            .expect("the helper runs");
        assert_eq!(
            st.code(),
            Some(want),
            "a helper that rounds a tool's verdict off is worse than no helper"
        );
    }
}

/// **`tie_lifetime`, end to end and both ways.** A tool's descendant
/// must not outlive nzbfast; a script's must.
///
/// This is the one thing the Windows arm actually buys, so it is
/// measured rather than argued. The child is `cmd /c start /b ...`,
/// which returns at once and leaves a GRANDCHILD behind - the shape a
/// compromised `unrar` would use to survive, and the shape a
/// post-processing script uses on purpose when it backgrounds a
/// transcode. The helper exits as soon as `cmd` does, which closes the
/// job handle; whether the grandchild lives long enough to write its
/// marker is the whole assertion.
#[test]
#[cfg(windows)]
fn a_tools_descendant_dies_with_the_daemon_and_a_scripts_does_not() {
    if detect().mechanism != Mechanism::JobObject {
        eprintln!(
            "no job-object helper on this box ({}) - skipped",
            detect().detail
        );
        return;
    }
    let cmd_exe = PathBuf::from(std::env::var_os("COMSPEC").expect("COMSPEC"));
    let dir = std::env::temp_dir().join(format!("nzbfast-sandbox-tie-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch");

    // (policy, may the grandchild finish?)
    let cases: [(Policy, bool); 2] = [
        (Policy::tool("tie", &dir), false),
        (Policy::script(vec![dir.clone()]), true),
    ];
    for (policy, expect_marker) in cases {
        let marker = dir.join(format!("{}.txt", policy.label));
        let _ = std::fs::remove_file(&marker);
        // Through a .bat rather than a `cmd /c "..."` string, and that is
        // not fastidiousness: `Command` escapes an embedded quote as
        // `\"`, which is C runtime convention and NOT cmd's, so a nested
        // quoted command line arrives at cmd as a program name it cannot
        // find. The batch file is written by this test, so every quote
        // inside it is one cmd itself parses.
        let bat = dir.join(format!("{}.bat", policy.label));
        std::fs::write(
            &bat,
            format!(
                "@echo off\r\nping -n 4 127.0.0.1 >NUL\r\necho survived>\"{}\"\r\n",
                marker.display()
            ),
        )
        .expect("worker.bat");
        let st = command(&cmd_exe, &policy)
            // `start /b "" <path>`: the empty title is load-bearing,
            // because `start` reads a first QUOTED argument as a window
            // title and would otherwise take the batch file for one.
            .args(["/c", "start", "/b", ""])
            .arg(&bat)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .status()
            .expect("the helper runs");
        assert!(st.success(), "{} launcher exited {st}", policy.label);
        // Comfortably past the grandchild's own 3 s of pinging.
        std::thread::sleep(std::time::Duration::from_secs(6));
        assert_eq!(
            marker.is_file(),
            expect_marker,
            "{}: KILL_ON_JOB_CLOSE is what honours tie_lifetime, both ways",
            policy.label
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------- the live wrapper

/// **A tool that is not installed is spawned BARE**, so the caller's own
/// `ErrorKind::NotFound` arm still fires.
///
/// This is the regression `e2e_repair` caught: wrapping a missing binary
/// makes the SPAWN succeed (it is the wrapper that starts) and turns
/// "par2 is not installed" into "the child exited 71", which reads as a
/// tool that ran and refused. `rarfix` and `repair` both branch on that
/// distinction and both said the wrong thing.
#[test]
fn an_uninstalled_tool_is_spawned_bare() {
    let missing = Path::new("nzbfast-no-such-tool-9d4c");
    let cmd = command(missing, &tool_policy("/jobs/x"));
    assert_eq!(cmd.get_program(), missing.as_os_str(), "{cmd:?}");
    let err = std::process::Command::new(missing)
        .stdin(std::process::Stdio::null())
        .status()
        .expect_err("nothing by that name exists");
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    // And an absolute path to nothing takes the same arm.
    let missing = Path::new("/nzbfast-no-such-dir-9d4c/par2");
    let cmd = command(missing, &tool_policy("/jobs/x"));
    assert_eq!(cmd.get_program(), missing.as_os_str(), "{cmd:?}");
}

/// A file with no execute bit is not a program: `execvp` walks past it,
/// so the wrapper must not resolve to it either.
#[test]
#[cfg(unix)]
fn a_file_with_no_execute_bit_is_not_located() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = crate::testscratch::ScratchDir::attach(
        &std::env::temp_dir().join(format!("nzbfast-sandbox-mode-{}", std::process::id())),
    );
    let f = dir.join("notatool");
    std::fs::write(&f, "#!/bin/sh\ntrue\n").unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
    let cmd = command(&f, &tool_policy("/jobs/x"));
    assert_eq!(cmd.get_program(), f.as_os_str(), "{cmd:?}");
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
    if detect().mechanism != Mechanism::None {
        let cmd = command(&f, &tool_policy("/jobs/x"));
        assert_ne!(cmd.get_program(), f.as_os_str(), "now it is a program");
    }
}

/// The health row is always answerable, and always names its mechanism.
#[test]
fn the_health_row_names_a_mechanism_and_explains_itself() {
    let h = health();
    let m = h["mechanism"].as_str().expect("a mechanism string");
    assert!(
        ["sandbox-exec", "bwrap", "unshare", "job-object", "none"].contains(&m),
        "{h}"
    );
    assert_eq!(h["confined"].as_bool(), Some(m != "none"));
    // Three axes, not one. `confined: true` used to be the only thing a
    // reader had, and it says the same for a bwrap child (reads, writes
    // and network all confined) as for an `unshare` one (network only)
    // or a Windows job object (none of the three). Each axis is now
    // answerable on its own, and no axis may be true where nothing is
    // in force.
    for axis in ["reads_confined", "writes_confined", "network_confined"] {
        let v = h[axis].as_bool().unwrap_or_else(|| panic!("{axis} in {h}"));
        assert!(!(v && m == "none"), "{axis} true with no mechanism: {h}");
    }
    // A read-confining mechanism confines writes too - every arm that
    // can restrict what a child OPENS restricts what it WRITES first.
    // The converse does not hold, which is the point of having both.
    assert!(
        !h["reads_confined"].as_bool().unwrap() || h["writes_confined"].as_bool().unwrap(),
        "{h}"
    );
    assert!(
        h["detail"].as_str().is_some_and(|d| d.len() > 20),
        "the detail is what a user reads: {h}"
    );
}

/// End to end on whatever this box has: a confined `sh` may write
/// inside the policy's directory and may not write outside it.
///
/// Skipped, loudly, where no mechanism is available - which is the
/// documented degradation, not a failure. A CI runner with no bwrap
/// takes that arm; the dev Mac does not.
#[test]
#[cfg(unix)]
fn a_confined_child_writes_inside_the_policy_and_not_outside_it() {
    if detect().mechanism == Mechanism::None {
        eprintln!("no confinement on this box ({}) - skipped", detect().detail);
        return;
    }
    let dir = crate::testscratch::ScratchDir::attach(
        &std::env::temp_dir().join(format!("nzbfast-sandbox-{}", std::process::id())),
    );
    let outside = dir.join("outside.txt");
    let inside = dir.join("work");
    std::fs::create_dir_all(&inside).expect("work dir");
    let policy = Policy::tool("test", &inside);
    let sh = Path::new("/bin/sh");

    let st = command(sh, &policy)
        .arg("-c")
        .arg(format!("echo ok > {}", inside.join("in.txt").display()))
        .status()
        .expect("sh runs");
    assert!(
        st.success(),
        "a confined child must still work inside its own directory"
    );
    assert!(inside.join("in.txt").is_file());

    let st = command(sh, &policy)
        .arg("-c")
        .arg(format!("echo pwned > {}", outside.display()))
        .status()
        .expect("sh runs");
    // THE assertion, and the only one of the two that is about security:
    // the host file is not there.
    //
    // **The two mechanisms refuse this write differently, and only one
    // of them fails the child.** Measured 2 Sep 2026 on Ubuntu 24.04
    // with a working bwrap: `sandbox-exec` denies the open and `sh`
    // exits non-zero, while bwrap's strict arm has mounted a PRIVATE
    // tmpfs over `/tmp` - so the child writes its `pwned` into a
    // filesystem of its own that dies with it, and exits 0. Asserting
    // the exit status unconditionally, which this did until then, made
    // the macOS run the only run this test had: on Linux it failed on a
    // confinement that had just worked, and the failure said "a write
    // outside the policy must be refused" about a write that was.
    assert!(
        !outside.exists(),
        "a write outside the policy must not land"
    );
    if cfg!(target_os = "macos") {
        assert!(!st.success(), "sandbox-exec must refuse the write itself");
    }
}

/// A real, confined `unrar` still extracts a real fixture into the job
/// directory. TODO 314 stage 1's whole point, end to end.
///
/// The fixture is `vendor/rars`'s own WinRAR m3 archive, so no `rar`
/// binary is needed to make one. Skipped where no `unrar` is installed
/// or no confinement is available - both are documented states, and the
/// daemon suite's `prefer_external_unrar_setting_routes_unpack_to_subprocess`
/// drives the same spawn through the whole daemon where a runner has one.
#[test]
#[cfg(unix)]
fn a_confined_unrar_still_extracts_a_real_archive() {
    let Some(unrar) = std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p)
            .map(|d| d.join("unrar"))
            .find(|p| p.is_file())
    }) else {
        eprintln!("skipping: no unrar on PATH");
        return;
    };
    if detect().mechanism == Mechanism::None {
        eprintln!("skipping: no confinement on this box ({})", detect().detail);
        return;
    }
    let dir = crate::testscratch::ScratchDir::attach(
        &std::env::temp_dir().join(format!("nzbfast-sandbox-unrar-{}", std::process::id())),
    );
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vendor/rars/tests/fixtures/rar50/m3_default.rar");
    std::fs::copy(&fixture, dir.join("a.rar")).expect("the fixture is in the tree");

    let st = command(&unrar, &Policy::tool("unrar", &dir))
        .args(["x", "-y", "-o+", "-p-", "-idq", "./a.rar"])
        .stdin(std::process::Stdio::null())
        .current_dir(&dir)
        .status()
        .expect("unrar runs");
    let produced: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name())
        .filter(|n| n != "a.rar")
        .collect();
    assert!(
        st.success(),
        "confined unrar exited {st}, produced {produced:?}"
    );
    assert!(
        !produced.is_empty(),
        "confined unrar exited 0 but wrote nothing into the job directory"
    );
}
