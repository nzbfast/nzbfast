//! §296 unit rigs. The measured A/B lives in
//! `tests/daemon_earlyfile/mod.rs`; these pin the decisions this module
//! makes on its own - what it refuses, what it copies, and what it does
//! when the tail moves underneath it.

use super::*;
use crate::testutil::test_daemon;

fn scratch(name: &str) -> crate::testscratch::ScratchDir {
    crate::testscratch::ScratchDir::attach(&std::env::temp_dir().join(format!(
        "nzbfast-early-{}-{name}-{:?}",
        std::process::id(),
        std::thread::current().id()
    )))
}

/// A job in `d`'s out-root, holding `files`.
fn job_with(d: &Arc<Daemon>, dir: &Path, files: &[(&str, &[u8])]) -> Arc<Mutex<Job>> {
    std::fs::create_dir_all(dir).unwrap();
    for (n, b) in files {
        std::fs::write(dir.join(n), b).unwrap();
    }
    let job = crate::testutil::job(serde_json::json!({
        "nzo_id": "SABnzbd_nzo_early1",
        "name": "Some.Release",
        "nzb_path": dir.join("job.nzb").to_string_lossy(),
        "state": "Queued",
        "out_dir": dir.to_string_lossy(),
    }));
    let _ = d;
    Arc::new(Mutex::new(job))
}

/// The refusal list is the feature: an early copy is only safe when the
/// finalize tail will not rename, file or sweep the file afterwards, and
/// every one of those passes is a live setting. A test per switch,
/// because a gate that loses one arm loses it silently - the copy still
/// lands, and the damage shows up as a duplicate or an orphan hours
/// later.
#[test]
fn every_tail_pass_that_could_move_a_file_refuses_the_early_publish() {
    let dir = scratch("gate");
    let d = test_daemon(&dir);
    *d.move_completed.write_ok() = Some(dir.join("nas"));
    d.early_file_publish.store(true, Ordering::Relaxed);
    // Every naming/sweep pass off is the *arr-recommended shape, and the
    // one configuration this feature engages for.
    for f in [
        &d.auto_rename,
        &d.rename.junk,
        &d.rename.media_only,
        &d.rename.from_nzb,
    ] {
        f.store(false, Ordering::Relaxed);
    }
    let out = crate::naming::out_dir(&d).join("Some.Release");
    std::fs::create_dir_all(&out).unwrap();
    assert_eq!(
        d.early_publish_dest(&out, "", false),
        Some(dir.join("nas").join("Some.Release")),
        "the *arr shape is exactly what this is for"
    );
    // TV filing decides a whole directory SHAPE, so the folder the files
    // end up in is not the one they are in now.
    assert_eq!(
        d.early_publish_dest(&out, "", true),
        None,
        "tv_sort moves the folder"
    );
    for (label, f) in [
        ("auto_rename", &d.auto_rename),
        ("rename_junk", &d.rename.junk),
        ("rename_media_only", &d.rename.media_only),
        ("rename_from_nzb", &d.rename.from_nzb),
    ] {
        f.store(true, Ordering::Relaxed);
        assert_eq!(
            d.early_publish_dest(&out, "", false),
            None,
            "{label} can move or delete a file after the copy was taken"
        );
        f.store(false, Ordering::Relaxed);
    }
    // ...and the master switch itself.
    d.early_file_publish.store(false, Ordering::Relaxed);
    assert_eq!(d.early_publish_dest(&out, "", false), None);
}

/// The destination this module publishes to and the one the whole-job
/// move will use are the SAME derivation, not two that agree today.
///
/// A file published to a directory the move never visits is a payload
/// split across two folders with nothing on the record to say so - the
/// sharper version of the lane-key rule `move_dest_root` documents.
#[test]
fn the_early_destination_is_the_movers_own() {
    let dir = scratch("dest");
    let d = test_daemon(&dir);
    let nas = dir.join("nas");
    *d.move_completed.write_ok() = Some(nas.clone());
    d.early_file_publish.store(true, Ordering::Relaxed);
    for f in [
        &d.auto_rename,
        &d.rename.junk,
        &d.rename.media_only,
        &d.rename.from_nzb,
    ] {
        f.store(false, Ordering::Relaxed);
    }
    let out = crate::naming::out_dir(&d).join("tv").join("Some.Release");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("ep1.mkv"), b"x").unwrap();
    let early = d.early_publish_dest(&out, "tv", false).unwrap();
    let (moved, _, _) = d.relocate_completed(&out, "tv", None);
    assert_eq!(
        moved.as_deref(),
        Some(early.as_path()),
        "early publish must aim where the mover lands"
    );
}

/// One candidate for `early_publish_one`, addressed the way the pass
/// would address it.
fn cand(out: &Path, name: &str) -> Candidate {
    Candidate {
        slot: 0,
        src: out.join(name),
        name: name.to_string(),
        nzf_id: format!("h-{name}"),
    }
}

/// A partially-written file must never be visible at the destination:
/// an *arr scanning the completed folder would import it, and a partial
/// with a plausible name is the one failure nobody notices until the
/// episode plays for four minutes and stops.
#[test]
fn a_published_file_appears_whole_or_not_at_all() {
    let dir = scratch("atomic");
    let d = test_daemon(&dir);
    *d.move_completed.write_ok() = Some(dir.join("nas"));
    let out = crate::naming::out_dir(&d).join("Some.Release");
    let body = vec![7u8; 9 << 20];
    let job = job_with(&d, &out, &[("ep1.mkv", &body)]);
    job.lock_ok().state = JobState::Downloading;
    let dest = d.move_dest_for(&out, "").unwrap();
    let dst = dest.join("ep1.mkv");
    // The pace hook asserts the destination is never observable in a
    // half-written state: it runs between chunks, which is exactly when
    // a non-atomic copy would have a short file sitting there.
    let seen: std::sync::Mutex<Vec<u64>> = std::sync::Mutex::new(Vec::new());
    let pace = |n: u64| {
        seen.lock_ok().push(n);
        assert!(
            !dst.exists(),
            "the destination name must not exist until the copy is whole"
        );
    };
    let got = d.early_publish_one(
        &job,
        "SABnzbd_nzo_early1",
        &dest,
        &cand(&out, "ep1.mkv"),
        &pace,
    );
    let Publish::Landed(n) = got else {
        panic!("a clean candidate must land");
    };
    assert_eq!(n, body.len() as u64);
    assert_eq!(std::fs::read(&dst).unwrap(), body);
    assert!(
        seen.lock_ok().len() > 1,
        "a 9 MiB copy is several paced chunks, not one burst"
    );
    let rec = job.lock_ok().early_published.clone();
    assert_eq!(rec.len(), 1, "the landed copy goes on the record");
    assert_eq!(rec[0].name, "ep1.mkv");
    assert_eq!(rec[0].len, body.len() as u64);
    // The commit released the custody fence behind itself.
    assert!(!d.moving.lock_ok().contains("SABnzbd_nzo_early1"));
    // Nothing left behind under the staging name.
    let strays: Vec<_> = std::fs::read_dir(&dest)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.starts_with(".nzbfast-early-"))
        .collect();
    assert!(strays.is_empty(), "staging left behind: {strays:?}");
}

/// "Already there" has to mean an ENTRY, not a name that RESOLVES
/// (31 Aug 2026 rename-occupancy census). `dest` is the user's completed
/// folder, so a link into a library or onto a share that is not mounted
/// is ordinary there; `Path::exists` follows it and answers false on any
/// error, while the commit's `rename(2)` removes whatever entry is at
/// the destination and never resolves it - so the guard did not fire and
/// the commit deleted the link.
///
/// THE PRE-COPY GUARD, and pinned by what it SAVES rather than by its
/// verdict. Both guards answer `Skipped`, so a test that only reads the
/// verdict is satisfied by either of them and neither is falsifiable -
/// the trap `b71c37e33` records. What separates them is that this one
/// runs before the copy: with it, the pace hook is never called at all.
#[test]
fn a_destination_name_an_entry_already_holds_is_never_copied_for() {
    let body = vec![7u8; 9 << 20];

    // PORTABLE half: an ordinary file at the destination, which was
    // refused before this decision too, so the windows-unit shards run
    // the guard and the change stays specific to what a symlink does.
    let dir = scratch("entry-file");
    let d = test_daemon(&dir);
    *d.move_completed.write_ok() = Some(dir.join("nas"));
    let out = crate::naming::out_dir(&d).join("Some.Release");
    let job = job_with(&d, &out, &[("ep1.mkv", &body)]);
    job.lock_ok().state = JobState::Downloading;
    let dest = d.move_dest_for(&out, "").unwrap();
    std::fs::create_dir_all(&dest).unwrap();
    std::fs::write(dest.join("ep1.mkv"), b"an earlier grab").unwrap();
    let copied = std::sync::atomic::AtomicBool::new(false);
    let pace = |_: u64| copied.store(true, std::sync::atomic::Ordering::Relaxed);
    let got = d.early_publish_one(
        &job,
        "SABnzbd_nzo_early1",
        &dest,
        &cand(&out, "ep1.mkv"),
        &pace,
    );
    assert!(matches!(got, Publish::Skipped));
    assert!(
        !copied.load(std::sync::atomic::Ordering::Relaxed),
        "nine mebibytes must not be copied for a name that is already taken"
    );
    assert_eq!(
        std::fs::read(dest.join("ep1.mkv")).unwrap(),
        b"an earlier grab"
    );

    #[cfg(unix)]
    {
        let dir = scratch("entry-link");
        let d = test_daemon(&dir);
        *d.move_completed.write_ok() = Some(dir.join("nas"));
        let out = crate::naming::out_dir(&d).join("Some.Release");
        let job = job_with(&d, &out, &[("ep1.mkv", &body)]);
        job.lock_ok().state = JobState::Downloading;
        let dest = d.move_dest_for(&out, "").unwrap();
        std::fs::create_dir_all(&dest).unwrap();
        std::os::unix::fs::symlink(dest.join("on-the-nas"), dest.join("ep1.mkv")).unwrap();
        let copied = std::sync::atomic::AtomicBool::new(false);
        let pace = |_: u64| copied.store(true, std::sync::atomic::Ordering::Relaxed);
        let got = d.early_publish_one(
            &job,
            "SABnzbd_nzo_early1",
            &dest,
            &cand(&out, "ep1.mkv"),
            &pace,
        );
        assert!(
            matches!(got, Publish::Skipped),
            "a dangling link is an entry, so the destination name is taken"
        );
        assert!(
            !copied.load(std::sync::atomic::Ordering::Relaxed),
            "and the refusal happens before the copy, not after it"
        );
        assert!(
            std::fs::symlink_metadata(dest.join("ep1.mkv"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "the user's link must still be a link"
        );
        assert!(job.lock_ok().early_published.is_empty());
    }
}

/// THE AT-COMMIT GUARD, which is the one the pre-copy guard cannot stand
/// in for: the entry APPEARS during the copy, which is the case that
/// guard's own comment names. The pace hook is what creates it, so the
/// pre-copy check has already run and passed by then and only the
/// re-check at the commit can refuse.
#[cfg(unix)]
#[test]
fn an_entry_that_appears_during_the_copy_is_never_published_over() {
    let dir = scratch("entry-midcopy");
    let d = test_daemon(&dir);
    *d.move_completed.write_ok() = Some(dir.join("nas"));
    let out = crate::naming::out_dir(&d).join("Some.Release");
    let job = job_with(&d, &out, &[("ep1.mkv", &vec![7u8; 9 << 20])]);
    job.lock_ok().state = JobState::Downloading;
    let dest = d.move_dest_for(&out, "").unwrap();
    std::fs::create_dir_all(&dest).unwrap();
    let dst = dest.join("ep1.mkv");
    let pace = |_: u64| {
        if std::fs::symlink_metadata(&dst).is_err() {
            std::os::unix::fs::symlink(dest.join("on-the-nas"), &dst).unwrap();
        }
    };
    let got = d.early_publish_one(
        &job,
        "SABnzbd_nzo_early1",
        &dest,
        &cand(&out, "ep1.mkv"),
        &pace,
    );
    assert!(
        matches!(got, Publish::Skipped),
        "an entry that appeared mid-copy holds the name"
    );
    assert!(
        std::fs::symlink_metadata(&dst)
            .unwrap()
            .file_type()
            .is_symlink(),
        "the link that appeared must still be a link"
    );
    assert!(job.lock_ok().early_published.is_empty());
    // And no staging file is left wearing a name an importer would take.
    let strays: Vec<_> = std::fs::read_dir(&dest)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.starts_with(".nzbfast-early-"))
        .collect();
    assert!(strays.is_empty(), "staging left behind: {strays:?}");
}

/// A copy whose source goes away underneath it - the shape a whole-job
/// move racing the pass leaves behind - publishes nothing and leaves no
/// staging file. The open handle keeps the bytes readable to the end,
/// so the guard that catches it is the post-copy length re-read, not
/// the read loop.
#[test]
fn a_source_that_vanishes_mid_copy_publishes_nothing() {
    let dir = scratch("failcopy");
    let d = test_daemon(&dir);
    *d.move_completed.write_ok() = Some(dir.join("nas"));
    let out = crate::naming::out_dir(&d).join("Some.Release");
    let body = vec![7u8; 9 << 20];
    let job = job_with(&d, &out, &[("ep1.mkv", &body)]);
    job.lock_ok().state = JobState::Downloading;
    let dest = d.move_dest_for(&out, "").unwrap();
    let src = out.join("ep1.mkv");
    let pace = |_: u64| {
        // First chunk boundary: the move has carried the source away.
        let _ = std::fs::remove_file(&src);
    };
    let got = d.early_publish_one(
        &job,
        "SABnzbd_nzo_early1",
        &dest,
        &cand(&out, "ep1.mkv"),
        &pace,
    );
    assert!(matches!(got, Publish::Skipped));
    assert!(!dest.join("ep1.mkv").exists());
    assert!(job.lock_ok().early_published.is_empty());
    let left: Vec<_> = std::fs::read_dir(&dest)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert!(left.is_empty(), "left behind: {left:?}");
}

/// The S1 race, run deterministically through the storecut seam: the
/// job settles FAILED after the copy's rename has landed and before the
/// record push, and park's failed arm runs its take-back inside that
/// window - with the in-flight file on no record, so the take cannot
/// see it. The widened relock is what stands between this interleaving
/// and a FAILED job with an episode in the completed folder.
#[test]
fn a_job_that_fails_mid_copy_never_lands_a_file() {
    let dir = scratch("s1fail");
    let d = test_daemon(&dir);
    *d.move_completed.write_ok() = Some(dir.join("nas"));
    let out = crate::naming::out_dir(&d).join("Some.Release");
    let body = vec![7u8; 2 << 20];
    let job = job_with(&d, &out, &[("ep1.mkv", &body)]);
    job.lock_ok().state = JobState::Downloading;
    let dest = d.move_dest_for(&out, "").unwrap();
    let job2 = job.clone();
    crate::storecut::on_early_rename_gap(move |d| {
        let taken = {
            let mut g = job2.lock_ok();
            g.state = JobState::Failed;
            d.early_take(&mut g)
        };
        assert!(
            taken.is_empty(),
            "the in-flight file is on no record yet - that gap IS the race"
        );
        early_unlink(&taken);
    });
    let pace = |_: u64| {};
    let got = d.early_publish_one(
        &job,
        "SABnzbd_nzo_early1",
        &dest,
        &cand(&out, "ep1.mkv"),
        &pace,
    );
    crate::storecut::disarm();
    assert!(matches!(got, Publish::Stop));
    assert!(
        !dest.join("ep1.mkv").exists(),
        "a FAILED job must not leave an episode in the completed folder"
    );
    assert!(
        job.lock_ok().early_published.is_empty(),
        "nothing may be pushed onto a job already filed in history"
    );
    assert!(
        out.join("ep1.mkv").exists(),
        "the source is settle's business, not this pass's"
    );
}

/// Codex C08: the queue store refuses AFTER the rename landed. The
/// record push and the destination file are one custody transaction, so
/// a save that cannot land takes both back - a restart must not restore
/// a job that has never heard of a completed copy already on disk. The
/// whole-job move still carries the file, so Skipped is the honest
/// verdict.
#[test]
fn a_refused_queue_save_takes_the_published_copy_back() {
    use crate::storecut::{Store, arm_store_cut, disarm};
    let dir = scratch("storecut");
    let d = test_daemon(&dir);
    *d.move_completed.write_ok() = Some(dir.join("nas"));
    let out = crate::naming::out_dir(&d).join("Some.Release");
    let body = vec![7u8; 2 << 20];
    let job = job_with(&d, &out, &[("ep1.mkv", &body)]);
    job.lock_ok().state = JobState::Downloading;
    let dest = d.move_dest_for(&out, "").unwrap();
    let pace = |_: u64| {};
    arm_store_cut(&[Store::Queue]);
    let got = d.early_publish_one(
        &job,
        "SABnzbd_nzo_early1",
        &dest,
        &cand(&out, "ep1.mkv"),
        &pace,
    );
    disarm();
    assert!(matches!(got, Publish::Skipped));
    assert!(
        !dest.join("ep1.mkv").exists(),
        "an unrecorded destination copy is exactly what the rollback exists to prevent"
    );
    assert!(
        job.lock_ok().early_published.is_empty(),
        "the record and the store must agree - the push was taken back with the file"
    );
    assert!(
        out.join("ep1.mkv").exists(),
        "the source is untouched: the whole-job move still carries it"
    );
    // The commit released the custody fence behind itself.
    assert!(!d.moving.lock_ok().contains("SABnzbd_nzo_early1"));
}

/// A job that has already settled by commit time is refused BEFORE the
/// rename: the destination never sees the file at all.
#[test]
fn a_job_already_settled_at_commit_time_publishes_nothing() {
    let dir = scratch("settled");
    let d = test_daemon(&dir);
    *d.move_completed.write_ok() = Some(dir.join("nas"));
    let out = crate::naming::out_dir(&d).join("Some.Release");
    let body = vec![7u8; 2 << 20];
    let job = job_with(&d, &out, &[("ep1.mkv", &body)]);
    job.lock_ok().state = JobState::Failed;
    let dest = d.move_dest_for(&out, "").unwrap();
    let pace = |_: u64| {};
    let got = d.early_publish_one(
        &job,
        "SABnzbd_nzo_early1",
        &dest,
        &cand(&out, "ep1.mkv"),
        &pace,
    );
    assert!(matches!(got, Publish::Stop));
    assert!(!dest.join("ep1.mkv").exists());
    assert!(job.lock_ok().early_published.is_empty());
    let strays: Vec<_> = std::fs::read_dir(&dest)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert!(strays.is_empty(), "left behind: {strays:?}");
}

/// While another actor holds the custody fence - the mover mid-move, a
/// delete, a recategorize - the publish abandons its staging copy and
/// stops. The whole-job move carries the file; nothing may commit under
/// someone else's custody. And the abandon must not RELEASE the fence
/// it failed to take.
#[test]
fn anothers_custody_of_the_files_stops_the_publish() {
    let dir = scratch("fence");
    let d = test_daemon(&dir);
    *d.move_completed.write_ok() = Some(dir.join("nas"));
    let out = crate::naming::out_dir(&d).join("Some.Release");
    let body = vec![7u8; 2 << 20];
    let job = job_with(&d, &out, &[("ep1.mkv", &body)]);
    job.lock_ok().state = JobState::Downloading;
    let dest = d.move_dest_for(&out, "").unwrap();
    assert!(d.moving.lock_ok().insert("SABnzbd_nzo_early1".to_string()));
    let pace = |_: u64| {};
    let got = d.early_publish_one(
        &job,
        "SABnzbd_nzo_early1",
        &dest,
        &cand(&out, "ep1.mkv"),
        &pace,
    );
    assert!(matches!(got, Publish::Stop));
    assert!(!dest.join("ep1.mkv").exists());
    assert!(job.lock_ok().early_published.is_empty());
    assert!(
        d.moving.lock_ok().contains("SABnzbd_nzo_early1"),
        "a failed insert must leave the holder's fence alone"
    );
    let strays: Vec<_> = std::fs::read_dir(&dest)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert!(strays.is_empty(), "left behind: {strays:?}");
}

/// S2: an occupied destination name is an EARLIER grab's finished file,
/// and `std::fs::rename` would replace it on both platforms. The
/// publish refuses instead - the whole-job move resolves the meeting
/// with a "(2)" name, which is the baseline - and remembers the refusal
/// so the poll loop does not re-copy gigabytes every second.
#[test]
fn an_occupied_destination_is_never_overwritten() {
    let dir = scratch("occupied");
    let d = test_daemon(&dir);
    *d.move_completed.write_ok() = Some(dir.join("nas"));
    let out = crate::naming::out_dir(&d).join("Some.Release");
    let body = vec![7u8; 2 << 20];
    let job = job_with(&d, &out, &[("ep1.mkv", &body)]);
    job.lock_ok().state = JobState::Downloading;
    let dest = d.move_dest_for(&out, "").unwrap();
    std::fs::create_dir_all(&dest).unwrap();
    std::fs::write(dest.join("ep1.mkv"), b"the earlier grab's finished file").unwrap();
    let pace = |_: u64| {};
    for _ in 0..2 {
        let got = d.early_publish_one(
            &job,
            "SABnzbd_nzo_early1",
            &dest,
            &cand(&out, "ep1.mkv"),
            &pace,
        );
        assert!(matches!(got, Publish::Skipped));
    }
    assert_eq!(
        std::fs::read(dest.join("ep1.mkv")).unwrap(),
        b"the earlier grab's finished file",
        "the finished file must survive byte for byte"
    );
    assert!(
        job.lock_ok().early_published.is_empty(),
        "a refused file must never reach the record - reconcile would delete \
         the finished copy it does not own"
    );
    assert!(
        job.lock_ok().early_refused.contains("ep1.mkv"),
        "the refusal is remembered, so the next pass skips the candidate"
    );
}

/// The three ways the tail can move underneath an early copy, and the
/// one rule that catches all of them.
///
/// Unchanged (name, len, mtime) is the only case where the destination
/// copy is kept and the source removed. A rename (settle publishing a
/// slot's real PAR2 name over an obfuscated one) and a rewrite (repair
/// patching a file whose blocks passed in stream and failed the
/// read-back) both discard the copy, and the ordinary whole-job move
/// then carries the file - which is the baseline behaviour for it and
/// nothing worse.
#[test]
fn reconcile_keeps_only_a_copy_the_tail_has_not_moved() {
    let dir = scratch("reconcile");
    let d = test_daemon(&dir);
    let nas = dir.join("nas");
    *d.move_completed.write_ok() = Some(nas.clone());
    let out = crate::naming::out_dir(&d).join("Some.Release");
    let job = job_with(
        &d,
        &out,
        &[
            ("keep.mkv", b"keep-bytes"),
            ("rewritten.mkv", b"old-bytes"),
            ("renamed.bin", b"obfuscated"),
        ],
    );
    std::fs::create_dir_all(&nas).unwrap();
    let dest = d.move_dest_for(&out, "").unwrap();
    let mut recs = Vec::new();
    for n in ["keep.mkv", "rewritten.mkv", "renamed.bin"] {
        std::fs::copy(out.join(n), {
            std::fs::create_dir_all(&dest).unwrap();
            dest.join(n)
        })
        .unwrap();
        let (len, mtime_ns) = stamp(&out.join(n)).unwrap();
        recs.push(EarlyFile {
            name: n.to_string(),
            len,
            mtime_ns,
            nzf_id: format!("h-{n}"),
            dest: Some(dest.clone()),
        });
    }
    job.lock_ok().early_published = recs;
    // The tail moves two of the three: one file is rewritten in place
    // (repair), one is renamed (settle's PAR2 deobfuscation).
    std::thread::sleep(std::time::Duration::from_millis(20));
    std::fs::write(out.join("rewritten.mkv"), b"NEW-bytes").unwrap();
    std::fs::rename(out.join("renamed.bin"), out.join("Real.Name.mkv")).unwrap();

    d.early_reconcile(&job);

    assert!(
        !out.join("keep.mkv").exists(),
        "an unchanged file is already at the destination - the source must go"
    );
    assert!(dest.join("keep.mkv").exists());
    assert!(
        out.join("rewritten.mkv").exists() && !dest.join("rewritten.mkv").exists(),
        "a repaired file's stale copy must go, and the move carries the real one"
    );
    assert!(
        out.join("Real.Name.mkv").exists() && !dest.join("renamed.bin").exists(),
        "a renamed file's copy is published under a name the job no longer has"
    );
    assert!(
        job.lock_ok().early_published.is_empty(),
        "the record is spent"
    );
}

/// The one outcome reconcile must never produce: both copies surviving.
///
/// `move_tree`'s merge resolves an occupied target with
/// `reserve_free_name`, so a source and a destination copy of one file
/// publishes the payload a second time as "Episode (2).mkv" - the same
/// mangling `relocate_completed`'s `same_place` guard exists to prevent
/// one directory over.
#[test]
fn reconcile_never_leaves_a_file_in_both_places() {
    let dir = scratch("both");
    let d = test_daemon(&dir);
    *d.move_completed.write_ok() = Some(dir.join("nas"));
    let out = crate::naming::out_dir(&d).join("Some.Release");
    let job = job_with(&d, &out, &[("ep1.mkv", b"payload")]);
    let dest = d.move_dest_for(&out, "").unwrap();
    std::fs::create_dir_all(&dest).unwrap();
    std::fs::copy(out.join("ep1.mkv"), dest.join("ep1.mkv")).unwrap();
    let (len, mtime_ns) = stamp(&out.join("ep1.mkv")).unwrap();
    job.lock_ok().early_published = vec![EarlyFile {
        name: "ep1.mkv".into(),
        len,
        mtime_ns,
        nzf_id: "h-ep1".into(),
        dest: Some(dest.clone()),
    }];
    d.early_reconcile(&job);
    assert!(
        out.join("ep1.mkv").exists() ^ dest.join("ep1.mkv").exists(),
        "exactly one copy survives"
    );
}

/// Sweep S6: the destination moved out from under the record - a
/// `move_completed` repoint, a recategorize - and the copies are at the
/// OLD root, where the record says they are. Spending the record
/// against the new root looked for them there, found nothing, called
/// them "re-sent with the job", and left the real copies stranded: full
/// payload at the new destination plus orphan episodes at the old one.
/// The recorded dest is what lets reconcile take them back instead.
#[test]
fn reconcile_takes_back_copies_at_a_destination_the_job_left() {
    let dir = scratch("repoint");
    let d = test_daemon(&dir);
    let old_nas = dir.join("old-nas");
    *d.move_completed.write_ok() = Some(old_nas.clone());
    let out = crate::naming::out_dir(&d).join("Some.Release");
    let job = job_with(&d, &out, &[("ep1.mkv", b"payload"), ("ep2.mkv", b"more")]);
    let old_dest = d.move_dest_for(&out, "").unwrap();
    std::fs::create_dir_all(&old_dest).unwrap();
    let mut recs = Vec::new();
    for n in ["ep1.mkv", "ep2.mkv"] {
        std::fs::copy(out.join(n), old_dest.join(n)).unwrap();
        let (len, mtime_ns) = stamp(&out.join(n)).unwrap();
        recs.push(EarlyFile {
            name: n.to_string(),
            len,
            mtime_ns,
            nzf_id: format!("h-{n}"),
            dest: Some(old_dest.clone()),
        });
    }
    job.lock_ok().early_published = recs;
    // The user repoints the completed folder while the job downloads.
    *d.move_completed.write_ok() = Some(dir.join("new-nas"));

    d.early_reconcile(&job);

    for n in ["ep1.mkv", "ep2.mkv"] {
        assert!(
            !old_dest.join(n).exists(),
            "{n}: the copy at the old destination is a stray and must go"
        );
        assert!(
            out.join(n).exists(),
            "{n}: the source travels with the job to the NEW destination"
        );
    }
    assert!(
        job.lock_ok().early_published.is_empty(),
        "every entry settled - the record is spent"
    );
}

/// Sweep S6, the harder half: the destination is not repointed but
/// UNCONFIGURED - `move_dest_for` answers None. A pre-dest record could
/// only warn and forget; a recorded dest still knows where the copies
/// are, and they come back rather than sitting as a partial duplicate
/// of the payload that now stays in the download folder.
#[test]
fn reconcile_takes_back_copies_when_the_destination_is_unconfigured() {
    let dir = scratch("unconf");
    let d = test_daemon(&dir);
    *d.move_completed.write_ok() = Some(dir.join("nas"));
    let out = crate::naming::out_dir(&d).join("Some.Release");
    let job = job_with(&d, &out, &[("ep1.mkv", b"payload")]);
    let dest = d.move_dest_for(&out, "").unwrap();
    std::fs::create_dir_all(&dest).unwrap();
    std::fs::copy(out.join("ep1.mkv"), dest.join("ep1.mkv")).unwrap();
    let (len, mtime_ns) = stamp(&out.join("ep1.mkv")).unwrap();
    job.lock_ok().early_published = vec![EarlyFile {
        name: "ep1.mkv".into(),
        len,
        mtime_ns,
        nzf_id: "h-ep1".into(),
        dest: Some(dest.clone()),
    }];
    // Move-completed switched off mid-download.
    *d.move_completed.write_ok() = None;

    d.early_reconcile(&job);

    assert!(
        !dest.join("ep1.mkv").exists(),
        "with no move owed, the early copy is a stray duplicate"
    );
    assert!(
        out.join("ep1.mkv").exists(),
        "the payload stays whole in the download folder"
    );
    assert!(job.lock_ok().early_published.is_empty());
}

/// A copy the user already moved or removed from the destination is a
/// settled verdict, not an unreachable one: nothing is there, the move
/// re-sends the source, and the record entry is spent - NOT deferred,
/// which would carry a dead entry from attempt to attempt forever.
#[test]
fn a_copy_already_gone_from_the_destination_settles_as_resent() {
    let dir = scratch("gonedst");
    let d = test_daemon(&dir);
    *d.move_completed.write_ok() = Some(dir.join("nas"));
    let out = crate::naming::out_dir(&d).join("Some.Release");
    let job = job_with(&d, &out, &[("ep1.mkv", b"payload")]);
    let dest = d.move_dest_for(&out, "").unwrap();
    std::fs::create_dir_all(&dest).unwrap();
    let (len, mtime_ns) = stamp(&out.join("ep1.mkv")).unwrap();
    job.lock_ok().early_published = vec![EarlyFile {
        name: "ep1.mkv".into(),
        len,
        mtime_ns,
        nzf_id: "h-ep1".into(),
        dest: Some(dest.clone()),
    }];
    // No copy at the destination: the user took it.

    d.early_reconcile(&job);

    assert!(
        out.join("ep1.mkv").exists(),
        "the source travels with the job"
    );
    assert!(
        job.lock_ok().early_published.is_empty(),
        "nothing-at-the-destination is a verdict, and the record is spent"
    );
}

/// Sweep S7: a destination that does not ANSWER - the NAS dropped at
/// the tail - is not a verdict. The old code read the metadata failure
/// as "not the same file", spent the record on the first attempt, and
/// the move retry then merged into a folder still holding
/// byte-identical early copies: `reserve_free_name` minted "(2)" for
/// every one. The entry has to stay on the record, so the retry's own
/// reconcile can settle it once the volume is back.
///
/// Unix-only for the fault injection: an unsearchable directory is what
/// makes `metadata` fail with something other than NotFound, and
/// Windows mode bits do not express it.
#[cfg(unix)]
#[test]
fn an_unreachable_destination_leaves_the_record_for_the_next_attempt() {
    use std::os::unix::fs::PermissionsExt;

    let dir = scratch("s7defer");
    let d = test_daemon(&dir);
    *d.move_completed.write_ok() = Some(dir.join("nas"));
    let out = crate::naming::out_dir(&d).join("Some.Release");
    let job = job_with(&d, &out, &[("ep1.mkv", b"payload")]);
    let dest = d.move_dest_for(&out, "").unwrap();
    std::fs::create_dir_all(&dest).unwrap();
    std::fs::copy(out.join("ep1.mkv"), dest.join("ep1.mkv")).unwrap();
    let (len, mtime_ns) = stamp(&out.join("ep1.mkv")).unwrap();
    job.lock_ok().early_published = vec![EarlyFile {
        name: "ep1.mkv".into(),
        len,
        mtime_ns,
        nzf_id: "h-ep1".into(),
        dest: Some(dest.clone()),
    }];

    // The NAS drops: the destination directory stops answering.
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o000)).unwrap();
    d.early_reconcile(&job);
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert_eq!(
        job.lock_ok().early_published.len(),
        1,
        "no verdict was possible, so the entry must survive for the retry"
    );
    assert!(
        out.join("ep1.mkv").exists(),
        "the source must not be removed on a copy nothing could verify"
    );
    assert!(
        dest.join("ep1.mkv").exists(),
        "the copy is intact - removing it blind is the other wrong answer"
    );

    // The volume is back: the retry's reconcile settles it the ordinary
    // way - the copy is kept, the source goes, the record is spent.
    d.early_reconcile(&job);
    assert!(job.lock_ok().early_published.is_empty(), "now it settles");
    assert!(dest.join("ep1.mkv").exists());
    assert!(!out.join("ep1.mkv").exists());
}

/// A delete takes the destination copies back. The record is spent under
/// the job lock and the unlinks happen outside it, so a destination that
/// has gone offline cannot wedge the queue.
#[test]
fn a_delete_takes_back_what_was_published() {
    let dir = scratch("discard");
    let d = test_daemon(&dir);
    *d.move_completed.write_ok() = Some(dir.join("nas"));
    let out = crate::naming::out_dir(&d).join("Some.Release");
    let job = job_with(&d, &out, &[("ep1.mkv", b"payload")]);
    let dest = d.move_dest_for(&out, "").unwrap();
    std::fs::create_dir_all(&dest).unwrap();
    std::fs::copy(out.join("ep1.mkv"), dest.join("ep1.mkv")).unwrap();
    job.lock_ok().early_published = vec![EarlyFile {
        name: "ep1.mkv".into(),
        len: 7,
        mtime_ns: 0,
        nzf_id: "h-ep1".into(),
        // A pre-dest record, deliberately: this pins the legacy
        // fallback - spend re-derives through `move_dest_for`, which is
        // what every record written before the field did.
        dest: None,
    }];
    let taken = {
        let mut g = job.lock_ok();
        d.early_take(&mut g)
    };
    assert_eq!(taken, vec![dest.join("ep1.mkv")]);
    assert!(job.lock_ok().early_published.is_empty());
    early_unlink(&taken);
    assert!(!dest.join("ep1.mkv").exists());
    assert!(
        !dest.exists(),
        "an emptied job folder at the destination goes with it"
    );
    assert!(
        out.join("ep1.mkv").exists(),
        "the download's own copy is the delete handler's business, not this one's"
    );
}

/// Sweep S6 on the delete path: the take-back addresses each copy where
/// its record says it is, not where the settings point today - so a
/// repoint between publish and delete cannot orphan the copies at the
/// old root.
#[test]
fn a_delete_after_a_repoint_takes_back_the_recorded_paths() {
    let dir = scratch("takerepoint");
    let d = test_daemon(&dir);
    let old_nas = dir.join("old-nas");
    *d.move_completed.write_ok() = Some(old_nas.clone());
    let out = crate::naming::out_dir(&d).join("Some.Release");
    let job = job_with(&d, &out, &[("ep1.mkv", b"payload")]);
    let old_dest = d.move_dest_for(&out, "").unwrap();
    std::fs::create_dir_all(&old_dest).unwrap();
    std::fs::copy(out.join("ep1.mkv"), old_dest.join("ep1.mkv")).unwrap();
    job.lock_ok().early_published = vec![EarlyFile {
        name: "ep1.mkv".into(),
        len: 7,
        mtime_ns: 0,
        nzf_id: "h-ep1".into(),
        dest: Some(old_dest.clone()),
    }];
    *d.move_completed.write_ok() = Some(dir.join("new-nas"));
    let taken = {
        let mut g = job.lock_ok();
        d.early_take(&mut g)
    };
    assert_eq!(
        taken,
        vec![old_dest.join("ep1.mkv")],
        "the copy is where it was published, not where the settings point now"
    );
    early_unlink(&taken);
    assert!(!old_dest.join("ep1.mkv").exists());
    assert!(!old_dest.exists(), "the emptied job folder goes with it");
}

/// What counts as plain payload. The extractor and repair own archive
/// volumes and split parts, and §296 publishes neither - a member whose
/// own head carries no magic (part 2 of a byte split) is caught by NAME
/// because nothing else can catch it.
#[test]
fn only_plain_payload_is_publishable() {
    let dir = scratch("plain");
    let mkv = dir.join("ep1.mkv");
    std::fs::write(&mkv, b"\x1a\x45\xdf\xa3 not an archive").unwrap();
    assert!(plain_payload(&mkv));
    for n in [
        "set.rar",
        "set.r00",
        "set.001",
        "set.7z",
        "set.zip",
        "set.par2",
        "set.part01",
        "set.part1",
        "set.z01",
    ] {
        let p = dir.join(n);
        std::fs::write(&p, b"not really an archive, judged by name").unwrap();
        assert!(!plain_payload(&p), "{n} must not be published early");
    }
    // ...and by MAGIC, for the obfuscated volume that wears no
    // telling extension at all.
    let obf = dir.join("a1b2c3d4");
    std::fs::write(&obf, b"Rar!\x1a\x07\x01\x00rest").unwrap();
    assert!(!plain_payload(&obf), "an obfuscated rar is still a rar");
}

/// A record written before §296 says "nothing was published early", and
/// one written by it survives a round trip through the store. Without
/// the persisted list a restart's whole-job move merges over copies it
/// no longer knows about and publishes the payload twice.
#[test]
fn the_published_list_survives_the_store() {
    let j = crate::testutil::job(serde_json::json!({
        "nzo_id": "SABnzbd_nzo_early2",
        "name": "Some.Release",
        "nzb_path": "/tmp/job.nzb",
        "state": "Queued",
        "out_dir": "/tmp/out",
    }));
    assert!(
        j.early_published.is_empty(),
        "a record with no key reads as nothing published"
    );
    let mut j = j;
    j.early_published = vec![
        EarlyFile {
            name: "ep1.mkv".into(),
            len: 42,
            mtime_ns: 99,
            nzf_id: "0123456789abcdef".into(),
            dest: Some(PathBuf::from("/tmp/nas/Some.Release")),
        },
        // A record written before the dest field: absent must read as
        // None ("re-derive at spend"), never as a path.
        EarlyFile {
            name: "ep2.mkv".into(),
            len: 7,
            mtime_ns: 0,
            nzf_id: String::new(),
            dest: None,
        },
    ];
    let wire = crate::job::job_json(&j);
    let back = crate::job::job_from_json(&wire).expect("round trip");
    assert_eq!(back.early_published, j.early_published);
    // And the compat arm the round trip cannot see: a wire record with
    // NO dest key at all - what every pre-S6 store holds - parses, and
    // parses to None.
    let mut wire2 = wire.clone();
    for e in wire2["early_published"].as_array_mut().unwrap() {
        e.as_object_mut().unwrap().remove("dest");
    }
    let back2 = crate::job::job_from_json(&wire2).expect("pre-dest round trip");
    assert_eq!(back2.early_published.len(), 2);
    assert!(
        back2.early_published.iter().all(|e| e.dest.is_none()),
        "an absent dest key must read as re-derive, not a path"
    );
}

/// H2's other door (29 Aug 2026 sweep). The whole-job move refuses a
/// destination inside its own source; this pass derives the SAME path
/// and stages its own copies rather than going through `move_tree`, so
/// without the same refusal it publishes files into a folder the move
/// then declines to visit - a payload split across two directories with
/// nothing to say so.
#[test]
fn nothing_is_published_early_into_a_folder_inside_the_job() {
    let dir = scratch("nested-dest");
    let d = test_daemon(&dir);
    d.early_file_publish.store(true, Ordering::Relaxed);
    for f in [
        &d.auto_rename,
        &d.rename.junk,
        &d.rename.media_only,
        &d.rename.from_nzb,
    ] {
        f.store(false, Ordering::Relaxed);
    }
    let out = crate::naming::out_dir(&d).join("Some.Release");
    std::fs::create_dir_all(&out).unwrap();
    // `move_completed` under this job's own folder: the mirrored layout
    // then puts the target at <job>/done/Some.Release.
    *d.move_completed.write_ok() = Some(out.join("done"));
    assert!(
        d.move_dest_for(&out, "")
            .is_some_and(|p| p.starts_with(&out)),
        "fixture is not the shape under test - the target must be inside the job"
    );
    assert!(
        d.early_publish_dest(&out, "", false).is_none(),
        "the early publish must refuse a destination inside the job it is publishing from"
    );
    // ...and an ordinary sibling destination is untouched.
    *d.move_completed.write_ok() = Some(dir.join("nas"));
    assert!(d.early_publish_dest(&out, "", false).is_some());
}

/// The at-commit guard is a CLAIM, so a release name that lands at the
/// destination while the copy is running cannot be renamed over.
///
/// THIS IS THE DOOR OF THE NINE ON THE 31 Aug OCCUPANCY CENSUS WHOSE
/// WINDOW WAS NEVER HYPOTHETICAL: the concurrent creator is named in
/// the guard's own comment - "another job's move landing the same
/// release name" - and `dest` is the user's completed folder, so the
/// loser is a finished file. The `symlink_metadata` this door carried
/// until then answers the occupancy question exactly as `create_new`
/// does; what separates them is the gap behind the answer, so this has
/// to race. VERIFIED red with the at-commit guard alone reverted to
/// the `lstat`. See `crate::renameclaim` for the measurement and for
/// why the arrival hunts the rename rather than sweeping a fixed span.
///
/// 100 trials rather than the 300 the other pins take, because every
/// one of them copies a whole `EARLY_MIN_BYTES` payload twice over -
/// the pass refuses anything smaller, so there is no cheaper candidate
/// to race. The harness floors the exercised population at a twentieth
/// either way.
///
/// The PRE-COPY guard is untouched by this and is not what is being
/// pinned: an arrival that beats it makes the door decline early, which
/// is correct and is counted as a correct decline here.
#[test]
fn an_early_publish_never_lands_on_a_name_created_beside_it() {
    let dir = scratch("claim-race");
    let d = test_daemon(&dir);
    *d.move_completed.write_ok() = Some(dir.join("nas"));
    let out = crate::naming::out_dir(&d).join("Some.Release");
    let body = vec![7u8; 1 << 20];
    let job = job_with(&d, &out, &[("ep1.mkv", &body)]);
    job.lock_ok().state = JobState::Downloading;
    let dest = d.move_dest_for(&out, "").unwrap();
    std::fs::create_dir_all(&dest).unwrap();
    let dst = dest.join("ep1.mkv");
    let src = out.join("ep1.mkv");
    let pace = |_: u64| {};
    crate::renameclaim::never_renames_over_a_neighbour(
        &dst,
        100,
        || {
            std::fs::write(&src, &body).unwrap();
            let mut g = job.lock_ok();
            g.early_published.clear();
            g.early_refused.clear();
        },
        || {
            let _ = d.early_publish_one(
                &job,
                "SABnzbd_nzo_early1",
                &dest,
                &cand(&out, "ep1.mkv"),
                &pace,
            );
        },
    );
}

/// §296's staging sibling decorates the member's OWN name, and that name
/// is a `sanitize_out_name` result - so for a long posted name it is
/// EXACTLY the 255-byte component cap, capping being what produced it.
/// The prefix on top of that is a name no filesystem creates (measured on
/// APFS 31 Aug 2026: 255 creates, 256 is `ENAMETOOLONG`), so `stage_copy`
/// failed, the file never published early, and the poll loop logged the
/// same failure again every tick until the job settled - which means the
/// longest-named posts were exactly the ones that never got what §296
/// buys.
///
/// Asserted by WRITING the name, not by counting its bytes: the byte
/// count is what the disk answer is standing in for everywhere else.
#[test]
fn a_member_named_at_the_cap_still_gets_a_writable_staging_name() {
    let dir = std::env::temp_dir().join(format!(
        "nzbfast-earlystage-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let leaf = nzbkit::disk::sanitize_out_name(&format!("{}.mkv", "y".repeat(400)));
    assert_eq!(leaf.len(), 255, "the premise moved");
    let staging = staging_name(&dir.join(&leaf));
    std::fs::write(&staging, b"x").unwrap_or_else(|e| panic!("{staging:?} is unwritable: {e}"));

    // And it is still recognisable as ours, which is what the sweep and
    // every reader of the completed folder go by - the cap falls at the
    // TAIL for that reason.
    let name = staging.file_name().unwrap().to_string_lossy().into_owned();
    assert!(name.starts_with(".nzbfast-early-"), "{name}");
    assert_eq!(
        staging.parent(),
        Some(dir.as_path()),
        "a sibling of the target"
    );

    // Nothing that works today moves: inside the cap this is the plain
    // `format!`, byte for byte.
    let plain = staging_name(&dir.join("episode.mkv"));
    assert_eq!(
        plain.file_name().unwrap().to_string_lossy(),
        format!(".nzbfast-early-{}-episode.mkv", std::process::id())
    );

    let _ = std::fs::remove_dir_all(&dir);
}
