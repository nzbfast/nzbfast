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
    let long = "n".repeat(200);
    for i in 0..900 {
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
