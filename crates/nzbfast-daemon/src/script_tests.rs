//! §163 item 3: `SAB_FILES`, SABnzbd 5.1.0's list of what a job
//! produced. Everything here pins the SHAPE of somebody else's contract
//! rather than our own behaviour, in the same spirit as
//! `nzbget_script_tests`: a list that is right but comma-separated, or
//! absolute where SAB is relative, runs perfectly and breaks every
//! third-party script that reads it.

use super::*;

/// A finished job's facts, with only the fields [`Daemon::sab_files`]
/// reads set to anything meaningful.
fn facts(out_dir: &std::path::Path) -> ScriptFacts {
    ScriptFacts {
        out_dir: out_dir.to_path_buf(),
        name: "Show.S01E01.1080p-GRP".into(),
        cat: "tv".into(),
        status: "0",
        fail_msg: String::new(),
        nzo_id: "SABnzbd_nzo_test".into(),
        bytes: 0,
        downloaded: 0,
        failure_link: String::new(),
        repaired: false,
        shape: String::new(),
        nzb_path: PathBuf::new(),
        dupe_key: String::new(),
        pp_params: Vec::new(),
        filed: false,
        filed_stem: String::new(),
        filed_tail: crate::smart::FiledTail::default(),
    }
}

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("nzbfast-sabfiles-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn parse(json: &str) -> Vec<String> {
    serde_json::from_str(json).expect("SAB_FILES must be valid JSON")
}

/// The format is SAB's documented one: "File paths created by the job,
/// paths are relative to SAB_COMPLETE_DIR", **JSON encoded array**.
/// Relative, not absolute; nested, not flattened; and parseable with
/// `json.loads`, which is the whole reason a separator was never an
/// option.
#[test]
fn sab_files_is_a_json_array_of_paths_relative_to_the_complete_dir() {
    let dir = scratch("rel");
    std::fs::create_dir_all(dir.join("Subs")).unwrap();
    for p in ["Show.S01E01.mkv", "Show.S01E01.nfo", "Subs/eng.srt"] {
        std::fs::write(dir.join(p), b"x").unwrap();
    }
    let f = facts(&dir);
    let got = Daemon::sab_files(&dir.to_string_lossy(), &f);
    assert_eq!(
        parse(&got),
        vec!["Show.S01E01.mkv", "Show.S01E01.nfo", "Subs/eng.srt"],
        "{got}"
    );
    // Nothing absolute leaked in - the whole point of "relative to
    // SAB_COMPLETE_DIR" is that a script joins them itself.
    assert!(!got.contains(dir.to_str().unwrap()), "{got}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Our own bookkeeping is not the job's output. `.nzbfast.journal` is
/// the resume record and `.nzbfast-trash` is the cleanup staging area;
/// a script that "processes every file the job made" must not be handed
/// either.
#[test]
fn sab_files_leaves_out_our_own_bookkeeping() {
    let dir = scratch("dot");
    std::fs::create_dir_all(dir.join(".nzbfast-trash")).unwrap();
    std::fs::write(dir.join(".nzbfast-trash/gone.par2"), b"x").unwrap();
    std::fs::write(dir.join(".nzbfast.journal"), b"x").unwrap();
    std::fs::write(dir.join("payload.mkv"), b"x").unwrap();
    let f = facts(&dir);
    assert_eq!(
        parse(&Daemon::sab_files(&dir.to_string_lossy(), &f)),
        vec!["payload.mkv"]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A TV-filed job's complete dir is the SHARED `Show/Season NN` library
/// folder, so a plain listing hands a script every episode of the season
/// as though this one job had produced them - and a script that files,
/// renames or notifies per file would then act on the user's whole
/// library. Only this release's own files are listed, by the same
/// ownership rule a filed delete uses.
#[test]
fn a_tv_filed_job_lists_only_its_own_episode() {
    let dir = scratch("filed");
    for p in [
        "Show - S01E01 [1080p].mkv",
        "Show - S01E01 [1080p].nfo",
        "Show - S01E02 [1080p].mkv",
        "Show - S01E03 [720p].mkv",
    ] {
        std::fs::write(dir.join(p), b"x").unwrap();
    }
    let mut f = facts(&dir);
    f.filed = true;
    f.filed_stem = "Show.S01E01.1080p.WEB.x264-GRP".into();
    f.filed_tail = crate::smart::FiledTail {
        title: String::new(),
        suffix: " [1080p]".into(),
    };
    assert_eq!(
        parse(&Daemon::sab_files(&dir.to_string_lossy(), &f)),
        vec!["Show - S01E01 [1080p].mkv", "Show - S01E01 [1080p].nfo"],
        "the siblings belong to other jobs"
    );
    // The narrowing is tied to the directory filing wrote into. Once a
    // chain link has moved the job somewhere else with
    // `[NZB] DIRECTORY=`, whatever is there is the job's again.
    let moved = scratch("filed-moved");
    std::fs::write(moved.join("Show - S01E01 [1080p].mkv"), b"x").unwrap();
    std::fs::write(moved.join("anything.txt"), b"x").unwrap();
    assert_eq!(
        parse(&Daemon::sab_files(&moved.to_string_lossy(), &f)).len(),
        2,
        "a moved job owns its new directory whole"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&moved);
}

/// The cap, and the reason it exists: one environment variable gets 128
/// KiB on Linux and exceeding it fails the `exec` outright rather than
/// truncating, so an uncapped list would stop a big job running its
/// post-processing script at all. Truncated or not, the value stays
/// valid JSON - a script that cannot parse it is worse off than one that
/// sees a short list.
#[test]
fn sab_files_stays_inside_one_environment_variable() {
    let dir = scratch("cap");
    // 300 names of ~244 bytes is ~75 KB of JSON, past the 64 KiB cap by a
    // clear margin; 900 was ten seconds of APFS metadata for the same proof.
    let long = "n".repeat(240);
    for i in 0..300 {
        std::fs::write(dir.join(format!("{long}{i:04}.bin")), b"x").unwrap();
    }
    let f = facts(&dir);
    let got = Daemon::sab_files(&dir.to_string_lossy(), &f);
    assert!(got.len() < SAB_FILES_MAX_BYTES, "{} bytes", got.len());
    let listed = parse(&got);
    assert!(!listed.is_empty(), "a cap is not a blank");
    assert!(listed.len() < 900, "this fixture must actually trip it");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A symlinked directory is classified, never followed. A completed job
/// containing `extras -> /media/shared` must not put somebody else's
/// library into a variable we hand to a script - the same boundary the
/// cleanup walkers hold, and for a stronger reason here, because this
/// one leaves the process.
#[cfg(unix)]
#[test]
fn sab_files_does_not_walk_through_a_directory_symlink() {
    let dir = scratch("link");
    let outside = scratch("link-outside");
    std::fs::write(outside.join("someone-elses.mkv"), b"x").unwrap();
    std::fs::write(dir.join("payload.mkv"), b"x").unwrap();
    std::os::unix::fs::symlink(&outside, dir.join("extras")).unwrap();
    let f = facts(&dir);
    assert_eq!(
        parse(&Daemon::sab_files(&dir.to_string_lossy(), &f)),
        vec!["payload.mkv"]
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&outside);
}

// ---------------------------------------------- TODO 314 stage 1

/// A confined script may write where the policy says and nowhere else,
/// and the setting turns it off.
///
/// The whole point of `script_confined` is that it is a USER decision:
/// a script that legitimately writes outside the daemon's folders has
/// to keep working once its owner says so. Both halves are asserted
/// here, because only the pair says the switch does anything.
///
/// Skipped, loudly, where this box has no confinement mechanism - the
/// documented degradation (`crate::sandbox`), not a failure.
#[test]
#[cfg(unix)]
fn a_confined_script_may_not_write_outside_the_daemons_folders() {
    if crate::sandbox::detect().mechanism == crate::sandbox::Mechanism::None {
        eprintln!(
            "skipping: no confinement on this box ({})",
            crate::sandbox::detect().detail
        );
        return;
    }
    // Under `target/`, NOT under $TMPDIR: the policy grants the system
    // temp directory (a script that writes a temp file is not doing
    // anything a confinement should stop), so a scratch tree in the
    // usual place would put "outside" inside the policy and the test
    // would pass for the wrong reason.
    let root = crate::testscratch::ScratchDir::attach(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!("nzbfast-scriptconfine-{}", std::process::id())),
    );
    let d = crate::testutil::test_daemon(&root);
    // NOT under the download root (`<root>/out`), the move destinations
    // or the watch folder, so the policy excludes it.
    let outside = root.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    let target = outside.join("pwned.txt");
    let script = root.join("pp.sh");
    std::fs::write(
        &script,
        format!("#!/bin/sh\nexec echo ok > {}\n", target.display()),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();

    let run = || {
        let cmd = confined_command(&d, &script, &[]);
        run_capped_capture(cmd, 30).expect("the script launches").0
    };

    // On, the default: refused, and nothing landed.
    assert!(d.script_confined.load(Ordering::Relaxed), "default is ON");
    let st = run();
    assert!(
        st.is_some_and(|s| !s.success()),
        "a confined script wrote outside its policy"
    );
    assert!(!target.exists(), "the write landed despite the refusal");

    // Off: the user's call, and it works exactly as it did before this
    // setting existed.
    d.script_confined.store(false, Ordering::Relaxed);
    let st = run();
    assert!(
        st.is_some_and(|s| s.success()),
        "script_confined=0 must run the script unconfined"
    );
    assert!(target.is_file(), "the unconfined write did not land");
}

/// And the writable set is not empty theatre: the job's own directory,
/// and the daemon's download root, are in it.
#[test]
fn the_script_writable_set_covers_the_job_and_the_download_root() {
    let root = crate::testscratch::ScratchDir::attach(
        &std::env::temp_dir().join(format!("nzbfast-scriptwritable-{}", std::process::id())),
    );
    let d = crate::testutil::test_daemon(&root);
    let job = root.join("complete/Some.Job");
    let set = script_writable(&d, &[job.as_path()]);
    for want in [
        job.clone(),
        crate::naming::out_dir(&d),
        std::env::temp_dir(),
    ] {
        assert!(
            set.contains(&want),
            "{} missing from {set:?}",
            want.display()
        );
    }
}
