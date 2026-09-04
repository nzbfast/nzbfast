//! The never-adopt rule for the extraction scratch directories.
//!
//! Codex read-only sweep of 3 Aug 2026 listed "predictable extraction
//! staging remains vulnerable to pre-existing-path interference/deletion"
//! among three older items it rechecked and left undispositioned.
//! Re-derived 23 Aug 2026: the paths ARE predictable - `.nzbfast-nest*`
//! is fixed and `.nzbfast-extract-<pid>-<n>` carries a pid the OS
//! recycles - and what makes that safe is not secrecy but `create_dir`,
//! which fails on a path that exists AT ALL (a directory, a file, a
//! symlink), so neither creator can ever adopt or clear something it did
//! not make. Both got there by incident, and neither had a test.
//!
//! `nest_scratch_dir` earned the rule on 25 Jul 2026: it was a fixed
//! `.nzbfast-nest` preceded by an unconditional `remove_dir_all`, and the
//! recursive snapshot skips `.nzbfast*`, so a legitimate archive payload
//! that extracted to `.nzbfast-nest/` was invisible to every protection
//! and simply deleted. `ExtractStaging::new` opened with the same
//! `remove_dir_all` until 14 Aug 2026 (`1ec072ba0`), on a name carrying
//! this process's pid - so after a restart onto a recycled pid it cleared
//! a staging directory a previous run had deliberately KEPT, which is the
//! only copy of a payload whose publish had failed.

use super::*;

static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "nzbfast-scratch-{tag}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The name is fixed, so this test can pre-create the exact path the old
/// code would have swept - which is what a crashed run, or anything else
/// in the output directory, leaves behind.
#[test]
fn nest_scratch_never_adopts_or_clears_an_existing_path() {
    let dir = temp_dir("nest");
    let squatter = dir.join(".nzbfast-nest");
    std::fs::create_dir(&squatter).unwrap();
    std::fs::write(squatter.join("payload.mkv"), b"NOT YOURS").unwrap();

    let got = nest_scratch_dir(&dir).unwrap();
    assert_ne!(got, squatter, "the scratch dir adopted an existing path");
    assert!(got.is_dir() && std::fs::read_dir(&got).unwrap().next().is_none());
    assert_eq!(
        std::fs::read(squatter.join("payload.mkv")).unwrap(),
        b"NOT YOURS",
        "the scratch creator destroyed a path it did not make"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A file, not a directory, at the name - `create_dir` refuses either
/// way, which is the point of using it over `create_dir_all`.
#[test]
fn nest_scratch_steps_over_a_plain_file_of_the_same_name() {
    let dir = temp_dir("nestfile");
    std::fs::write(dir.join(".nzbfast-nest"), b"i am a file").unwrap();
    let got = nest_scratch_dir(&dir).unwrap();
    assert_eq!(got, dir.join(".nzbfast-nest1"));
    assert_eq!(
        std::fs::read(dir.join(".nzbfast-nest")).unwrap(),
        b"i am a file"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `ExtractStaging`'s name carries a per-process counter, so the occupied
/// name here is one this process just took rather than one written by
/// hand - which is exactly the collision the pid recycle produces, and
/// exactly what the removed `remove_dir_all` used to resolve by deleting
/// the contents.
#[test]
fn extraction_staging_never_clears_an_occupied_name() {
    let dir = temp_dir("staging");
    let mut kept = ExtractStaging::new(&dir).unwrap();
    // What a failed publish leaves for the operator.
    kept.keep = true;
    let kept_dir = kept.path().to_path_buf();
    std::fs::write(kept_dir.join("payload.mkv"), b"LEFT FOR THE OPERATOR").unwrap();
    drop(kept);

    let fresh = ExtractStaging::new(&dir).unwrap();
    assert_ne!(fresh.path(), kept_dir, "staging reused an occupied name");
    assert!(std::fs::read_dir(fresh.path()).unwrap().next().is_none());
    assert_eq!(
        std::fs::read(kept_dir.join("payload.mkv")).unwrap(),
        b"LEFT FOR THE OPERATOR",
        "staging cleared a directory a previous run kept on purpose"
    );
    drop(fresh);
    let _ = std::fs::remove_dir_all(&dir);
}
