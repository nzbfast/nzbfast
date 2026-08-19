//! §188: the history label re-derivation.
//!
//! The two cases that define the feature are the first two here, and
//! they pull in opposite directions on purpose: a row whose payload is
//! still on disk MUST be corrected, and a row whose payload is gone MUST
//! come through untouched. Getting the second one wrong is worse than
//! shipping nothing, because it would blank or guess at the record of a
//! download nobody can play or re-check.

use super::*;
use serde_json::json;

fn tdir(name: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("nzbfast-hm-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// A 1.1.3-era chip: the label a since-fixed `res_label` produced, with
/// no raw frame size beside it, exactly as those rows were written.
fn stale_facts(res: &str) -> nzbkit::mediaprobe::MediaFacts {
    nzbkit::mediaprobe::MediaFacts {
        res: Some(res.to_string()),
        vcodec: Some("H.264".into()),
        audio: Some("AAC 2.0".into()),
        duration_ms: Some(60_000),
        container: Some("mkv".into()),
        complete: true,
        ..Default::default()
    }
}

/// A history row for `name`, its payload directory at `out_dir`.
fn hist_row(
    d: &Daemon,
    name: &str,
    out_dir: &std::path::Path,
    facts: nzbkit::mediaprobe::MediaFacts,
) -> Arc<Mutex<Job>> {
    let mut j = super::job_from_json(&json!({
        "nzo_id": "hm1",
        "name": name,
        "nzb_path": "/spool/hm1.nzb",
        "out_dir": out_dir.to_string_lossy(),
        "state": "Completed",
    }))
    .expect("job_from_json");
    j.media = Some(facts);
    j.downloaded_bytes = 4242;
    j.elapsed_secs = 12.5;
    let job = Arc::new(Mutex::new(j));
    d.history.lock_ok().push(job.clone());
    job
}

/// The payload the probe will read: 1920x1080, so `res_label` says
/// "1080p" and the stale "1440p" on the row is provably wrong.
fn write_payload(dir: &std::path::Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("movie.mkv"),
        nzbkit::mediaprobe::testmux::mkv_full(),
    )
    .unwrap();
}

// -------------------------------------------------------------------
// The two that define the feature
// -------------------------------------------------------------------

/// The whole point of part one: the file is there, so the label is a
/// view that can be recomputed, and it is.
#[test]
fn a_row_whose_file_is_still_there_is_corrected() {
    let dir = tdir("present");
    let d = super::super::testutil::test_daemon(&dir);
    let out = dir.join("payload");
    write_payload(&out);
    let job = hist_row(&d, "Movie.2019.1080p.x264-GRP", &out, stale_facts("1440p"));

    let notice = run_pass(&d);

    let m = job.lock_ok().media.clone().expect("media survives");
    assert_eq!(
        m.res.as_deref(),
        Some("1080p"),
        "a row whose payload is still on disk must be re-derived, not left with the old label"
    );
    assert_eq!(notice.corrected, 1);
    assert_eq!(notice.kept, 0);
}

/// The other half, and the one that must never be traded away: nothing
/// on disk means nothing to re-derive FROM, so the row keeps exactly
/// what it was written with. Not blanked, not guessed at.
#[test]
fn a_row_whose_file_is_gone_comes_through_unchanged() {
    let dir = tdir("gone");
    let d = super::super::testutil::test_daemon(&dir);
    // Never created: the payload was deleted, or the download failed.
    let out = dir.join("no-such-payload");
    let before = stale_facts("1440p");
    let job = hist_row(&d, "Movie.2019.1080p.x264-GRP", &out, before.clone());

    let notice = run_pass(&d);

    assert_eq!(
        job.lock_ok().media.as_ref(),
        Some(&before),
        "a row with no payload on disk must be left exactly as written"
    );
    assert_eq!(notice.corrected, 0);
    assert_eq!(notice.kept, 1, "and it must be counted as kept, not fixed");
}

// -------------------------------------------------------------------
// The structural half
// -------------------------------------------------------------------

/// Part two's payoff, and the reason it is worth storing raw inputs at
/// all: this row's payload is GONE, and it is still corrected, because
/// the frame size the rule misread is on the row. This is the case the
/// re-probe can never reach.
#[test]
fn a_stored_frame_size_re_derives_with_no_file_at_all() {
    let dir = tdir("stored");
    let d = super::super::testutil::test_daemon(&dir);
    let mut facts = stale_facts("1440p");
    // 2592x1080 - the scope encode 67f212a4 stopped promoting.
    facts.width = Some(2592);
    facts.height = Some(1080);
    let job = hist_row(&d, "Movie.2019.1080p.x264-GRP", &dir.join("absent"), facts);

    let notice = run_pass(&d);

    assert_eq!(
        job.lock_ok().media.as_ref().and_then(|m| m.res.as_deref()),
        Some("1080p"),
        "a stored frame size must re-derive without the file"
    );
    assert_eq!(notice.corrected, 1);
    assert_eq!(notice.kept, 0, "nothing was skipped: no disk was needed");
}

/// Correcting the label has to correct the accusation built ON the
/// label. The old row said "the name claims 1080p but the file is
/// 1440p"; once the label is right, both halves of that sentence agree
/// and it must be gone, or the fix would swap a wrong label for a wrong
/// allegation.
#[test]
fn re_deriving_the_label_withdraws_the_mismatch_it_produced() {
    let dir = tdir("mismatch");
    let d = super::super::testutil::test_daemon(&dir);
    let mut facts = stale_facts("1440p");
    facts.width = Some(2592);
    facts.height = Some(1080);
    facts.mismatch = vec![nzbkit::mediaprobe::facts::Mismatch {
        field: nzbkit::mediaprobe::facts::Field::Resolution,
        claimed: "1080p".into(),
        actual: "1440p".into(),
    }];
    let job = hist_row(&d, "Movie.2019.1080p.x264-GRP", &dir.join("absent"), facts);

    run_pass(&d);

    let m = job.lock_ok().media.clone().unwrap();
    assert_eq!(m.res.as_deref(), Some("1080p"));
    assert!(
        m.mismatch.is_empty(),
        "the resolution mismatch was derived from the wrong label and must go with it: {:?}",
        m.mismatch
    );
}

/// A genuine mismatch is not swept away by the re-derivation. Only the
/// stale one goes.
#[test]
fn a_mismatch_that_is_still_true_survives() {
    let dir = tdir("truemm");
    let d = super::super::testutil::test_daemon(&dir);
    let mut facts = stale_facts("1440p");
    facts.width = Some(1280);
    facts.height = Some(720);
    let job = hist_row(&d, "Movie.2019.2160p.x264-GRP", &dir.join("absent"), facts);

    run_pass(&d);

    let m = job.lock_ok().media.clone().unwrap();
    assert_eq!(m.res.as_deref(), Some("720p"));
    assert_eq!(
        m.mismatch.len(),
        1,
        "a 720p file named 2160p is still a mislabel"
    );
    assert_eq!(m.mismatch[0].claimed, "2160p");
    assert_eq!(m.mismatch[0].actual, "720p");
}

// -------------------------------------------------------------------
// What must never be rewritten
// -------------------------------------------------------------------

/// The recorded facts are a record of what happened, not a view of a
/// file, and re-deriving the chip must not touch one of them.
#[test]
fn the_recorded_facts_are_never_rewritten() {
    let dir = tdir("facts");
    let d = super::super::testutil::test_daemon(&dir);
    let out = dir.join("payload");
    write_payload(&out);
    let job = hist_row(&d, "Movie.2019.1080p.x264-GRP", &out, stale_facts("1440p"));
    let (bytes, secs, name, state) = {
        let j = job.lock_ok();
        (j.downloaded_bytes, j.elapsed_secs, j.name.clone(), j.state)
    };

    run_pass(&d);

    let j = job.lock_ok();
    assert_eq!(j.downloaded_bytes, bytes, "bytes are a recorded fact");
    assert_eq!(j.elapsed_secs, secs, "timings are a recorded fact");
    assert_eq!(j.name, name, "the posted name is a recorded fact");
    assert_eq!(j.state, state, "the outcome is a recorded fact");
}

/// A failed download has no chip to re-derive and no payload to read.
/// It must cost nothing and change nothing - in particular it is NOT a
/// "kept" row, because there was never a label to keep.
#[test]
fn a_row_with_no_chip_is_left_alone_and_not_counted() {
    let dir = tdir("nochip");
    let d = super::super::testutil::test_daemon(&dir);
    let mut j = super::job_from_json(&json!({
        "nzo_id": "hm2", "name": "Broken.Release", "nzb_path": "/spool/hm2.nzb",
        "out_dir": dir.join("absent").to_string_lossy(), "state": "Failed",
    }))
    .expect("job_from_json");
    j.media = None;
    let job = Arc::new(Mutex::new(j));
    d.history.lock_ok().push(job.clone());

    let notice = run_pass(&d);

    assert!(job.lock_ok().media.is_none());
    assert_eq!(notice.corrected, 0);
    assert_eq!(notice.kept, 0, "no label was kept, because there was none");
}

/// The pass is idempotent, and self-accelerating: the second run finds
/// nothing to do, which is what makes a restart mid-pass cheap enough
/// that no cursor is needed.
#[test]
fn a_second_pass_finds_nothing_left_to_do() {
    let dir = tdir("twice");
    let d = super::super::testutil::test_daemon(&dir);
    let out = dir.join("payload");
    write_payload(&out);
    let job = hist_row(&d, "Movie.2019.1080p.x264-GRP", &out, stale_facts("1440p"));

    assert_eq!(run_pass(&d).corrected, 1);
    let after_first = job.lock_ok().media.clone();
    let second = run_pass(&d);

    assert_eq!(second.corrected, 0, "the second pass must be a no-op");
    assert_eq!(
        job.lock_ok().media.clone(),
        after_first,
        "and must not perturb the row it already corrected"
    );
    assert!(
        after_first.and_then(|m| m.width).is_some(),
        "the re-probe must also leave the raw frame size behind, so the \
         next pass needs no disk"
    );
}

// -------------------------------------------------------------------
// The notice
// -------------------------------------------------------------------

/// The notice is spent by dismissing it, and survives until then.
#[test]
fn the_notice_persists_until_it_is_dismissed() {
    let dir = tdir("notice");
    let d = super::super::testutil::test_daemon(&dir);
    d.raise_hist_notice(&MigrateNotice {
        corrected: 3,
        kept: 1,
        at: 1_700_000_000,
    });

    // A fresh read sees it: this is what an auto-update restart does.
    assert_eq!(
        d.hist_notice().map(|n| n.corrected),
        Some(3),
        "the notice must survive the restart that raised it"
    );

    let rev = d.queue_rev.load(Ordering::Relaxed);
    assert!(d.dismiss_hist_migrate());
    assert!(d.hist_notice().is_none());
    assert!(
        d.queue_rev.load(Ordering::Relaxed) > rev,
        "the strip rides the revisioned queue payload, so spending it must \
         move the revision or an idle dashboard keeps showing it"
    );
    assert!(
        !d.dismiss_hist_migrate(),
        "dismissing twice is a no-op, and must not bump the revision again"
    );
}

/// A pass that corrected nothing says nothing. A strip that appears
/// after every upgrade to report no news is a strip people learn to
/// close unread.
#[test]
fn a_pass_with_nothing_to_report_raises_no_notice() {
    let dir = tdir("quiet");
    let d = super::super::testutil::test_daemon(&dir);
    let out = dir.join("payload");
    write_payload(&out);
    // Already correct, and already carrying its frame size.
    let mut facts = stale_facts("1080p");
    facts.width = Some(1920);
    facts.height = Some(1080);
    hist_row(&d, "Movie.2019.1080p.x264-GRP", &out, facts);

    assert_eq!(run_pass(&d).corrected, 0);
    assert!(
        d.hist_notice().is_none(),
        "nothing changed, so there is nothing to tell the user"
    );
}

/// A row whose label was RIGHT all along still gets its frame size
/// written, so it never needs the disk again - but it is not a
/// correction, and the user must not be told it was one. Conflating the
/// two would inflate the notice's count with rows nothing changed on.
#[test]
fn gaining_the_frame_size_is_not_reported_as_a_correction() {
    let dir = tdir("gain");
    let d = super::super::testutil::test_daemon(&dir);
    let out = dir.join("payload");
    write_payload(&out);
    // Exactly what the probe will read back from `mkv_full` (its
    // strongest audio track is the 6-channel AC3, not the stereo AAC),
    // but with no frame size: a CORRECT 1.1.3-era row.
    let mut facts = stale_facts("1080p");
    facts.audio = Some("DD 5.1".into());
    let job = hist_row(&d, "Movie.2019.1080p.x264-GRP", &out, facts);

    let notice = run_pass(&d);

    let m = job.lock_ok().media.clone().unwrap();
    assert_eq!(
        m.res.as_deref(),
        Some("1080p"),
        "the label was already right"
    );
    assert_eq!(
        m.width,
        Some(1920),
        "and the row still gains its raw inputs"
    );
    assert_eq!(
        notice.corrected, 0,
        "but nothing the user can see changed, so it is not a correction"
    );
    assert!(
        d.hist_notice().is_none(),
        "and it must not raise a notice on its own"
    );
}

// -------------------------------------------------------------------
// Durability: the stamp must not outrun the write
// -------------------------------------------------------------------

/// Codex sweep 7, M5: the stamp is written through a different door
/// from the corrections it claims to have made.
///
/// Appending to `history.jsonl` needs write permission ON THE FILE;
/// stamping `hist-media.json` goes through `persist::write_atomic`, a
/// temp file and a rename, which needs only the DIRECTORY. So a store
/// that is 0444, owned by another uid, uchg-flagged, or on a filesystem
/// failing that descriptor loses every corrected line while the stamp
/// lands anyway - and the next boot returns at the version check with
/// the rows still wrong. The pass is idempotent and cheap by
/// construction, so the honest answer to a failed write is to leave the
/// stamp alone and re-run.
#[cfg(unix)]
#[test]
fn a_correction_that_could_not_be_written_does_not_stamp_the_version() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tdir("nowrite");
    let d = super::super::testutil::test_daemon(&dir);
    let out = dir.join("payload");
    write_payload(&out);
    let job = hist_row(&d, "Movie.2019.1080p.x264-GRP", &out, stale_facts("1440p"));

    let store = d.history_store_path();
    std::fs::write(&store, "").unwrap();
    std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o444)).unwrap();
    migrate_once(&d);
    // Restored before the assertions so a failure does not leave an
    // undeletable directory behind for the next run of this test.
    std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o644)).unwrap();

    assert_eq!(
        job.lock_ok().media.as_ref().and_then(|m| m.res.as_deref()),
        Some("1080p"),
        "precondition: the correction itself was derived"
    );
    assert_ne!(
        d.hist_migrate_state().version,
        env!("CARGO_PKG_VERSION"),
        "the corrected row never reached the store, so the pass must not \
         be recorded as done for this build"
    );
    assert!(
        d.hist_notice().is_none(),
        "and the user must not be told that rows were corrected when \
         nothing durably was"
    );
}

// -------------------------------------------------------------------
// Gone is not the same as could-not-look
// -------------------------------------------------------------------

/// Codex sweep 7, M6: "no file" and "could not read" were the same
/// answer, and the pass stamped the build over both.
///
/// The daemon starts from launchd or systemd, often before a NAS has
/// come up and sometimes before the OS will grant it the download
/// folder at all. Every row on that volume then reads as a deleted
/// payload, is counted as kept, and the stamp closes the pass for the
/// whole build - on the very build whose labels the pass exists to fix.
/// A directory that refuses to be opened must leave the stamp alone so
/// the next boot, with the volume up, tries again.
#[cfg(unix)]
#[test]
fn a_row_whose_volume_will_not_open_does_not_stamp_the_version() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tdir("unreadable");
    let d = super::super::testutil::test_daemon(&dir);
    let out = dir.join("payload");
    write_payload(&out);
    let before = stale_facts("1440p");
    let job = hist_row(&d, "Movie.2019.1080p.x264-GRP", &out, before.clone());

    // The payload IS there; the daemon just cannot look at it.
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o000)).unwrap();
    migrate_once(&d);
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert_eq!(
        job.lock_ok().media.as_ref(),
        Some(&before),
        "nothing could be read, so the row is left exactly as written"
    );
    assert_ne!(
        d.hist_migrate_state().version,
        env!("CARGO_PKG_VERSION"),
        "a row nobody could look at must not seal the pass for this build"
    );
}

/// The other side of that split, and the one it must not cost: a
/// payload that is genuinely gone is an answer, not a failure. Those
/// rows keep their labels, the notice says so, and the pass is finished
/// - re-running every boot forever would be a walk over the whole
/// history that can never find anything.
#[test]
fn a_payload_that_is_genuinely_gone_still_finishes_the_pass() {
    let dir = tdir("goneseal");
    let d = super::super::testutil::test_daemon(&dir);
    hist_row(
        &d,
        "Movie.2019.1080p.x264-GRP",
        &dir.join("no-such-payload"),
        stale_facts("1440p"),
    );

    migrate_once(&d);

    assert_eq!(
        d.hist_migrate_state().version,
        env!("CARGO_PKG_VERSION"),
        "a deleted payload is a settled answer, so the pass is done"
    );
}

/// Not stamping is a promise to try again, and a promise to try again
/// forever is a walk over the whole history at every start of this
/// build. A volume that is never coming back gets a bounded number of
/// boots to prove otherwise, then the pass gives up and says so by
/// stamping - which is the same outcome those rows had before, reached
/// only after the retries are spent.
#[cfg(unix)]
#[test]
fn a_volume_that_never_comes_back_stops_being_walked() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tdir("giveup");
    let d = super::super::testutil::test_daemon(&dir);
    let out = dir.join("payload");
    write_payload(&out);
    hist_row(&d, "Movie.2019.1080p.x264-GRP", &out, stale_facts("1440p"));
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o000)).unwrap();

    for _ in 1..MAX_ATTEMPTS {
        migrate_once(&d);
        assert!(
            migrate_owed(&d.hist_migrate_state()),
            "the volume may still come up: the next boot must try again"
        );
    }
    migrate_once(&d);
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert!(
        !migrate_owed(&d.hist_migrate_state()),
        "and after {MAX_ATTEMPTS} boots against a disk that will not \
         answer, the pass stops re-walking the history"
    );
}

/// A job the mover is emptying has an `out_dir` that names where the
/// bytes are GOING while the same-device merge path is still taking
/// them off the source entry by entry. Re-deriving off that half-moved
/// directory, and then recording the miss as a deleted payload, would
/// seal the row on the strength of a millisecond.
#[test]
fn a_row_whose_payload_is_mid_move_is_not_recorded_as_gone() {
    let dir = tdir("midmove");
    let d = super::super::testutil::test_daemon(&dir);
    let out = dir.join("payload");
    write_payload(&out);
    let before = stale_facts("1440p");
    let job = hist_row(&d, "Movie.2019.1080p.x264-GRP", &out, before.clone());
    d.moving.lock_ok().insert(job.lock_ok().nzo_id.clone());

    migrate_once(&d);

    assert_eq!(
        job.lock_ok().media.as_ref(),
        Some(&before),
        "the directory is in motion, so nothing is read off it"
    );
    assert_ne!(
        d.hist_migrate_state().version,
        env!("CARGO_PKG_VERSION"),
        "and the pass is not finished: this row is owed another look"
    );
}

// -------------------------------------------------------------------
// The notice, told honestly
// -------------------------------------------------------------------

/// Codex sweep 7, L3: a dismissal that could not remove the file said
/// it had.
///
/// The strip's whole flag is the existence of `hist-notice.json`, so an
/// unlink that fails leaves it owed - and the next payload builds the
/// strip again. Nobody reads the status today (the dashboard re-renders
/// from the live payload), so this is not a falsehood the user is
/// shown; it is a status field that means nothing and an error thrown
/// away. Both are worth having back.
#[cfg(unix)]
#[test]
fn a_dismissal_that_could_not_remove_the_notice_reports_failure() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tdir("nodismiss");
    let d = super::super::testutil::test_daemon(&dir);
    d.raise_hist_notice(&MigrateNotice {
        corrected: 2,
        kept: 0,
        at: 1_700_000_000,
    });

    // Unlinking needs write permission on the DIRECTORY, not the file.
    let spool = dir.join("spool");
    std::fs::set_permissions(&spool, std::fs::Permissions::from_mode(0o555)).unwrap();
    let rev = d.queue_rev.load(Ordering::Relaxed);
    let said = d.dismiss_hist_migrate();
    std::fs::set_permissions(&spool, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert!(
        !said,
        "the notice is still on disk and will be shown again, so the \
         dismissal must not report success"
    );
    assert!(
        d.hist_notice().is_some(),
        "precondition: the unlink really did fail"
    );
    assert_eq!(
        d.queue_rev.load(Ordering::Relaxed),
        rev,
        "nothing changed, so nothing should have been published"
    );
}

/// A second pass must not silently spend the first one's notice.
///
/// `raise_hist_notice` wrote the file outright, so a notice the user
/// had not read yet was replaced by the next one and its counts were
/// gone - nobody having dismissed anything. The strip reports what this
/// install has had corrected, so a fresh raise ADDS to what is still
/// owed.
#[test]
fn a_second_notice_adds_to_one_the_user_has_not_read() {
    let dir = tdir("mergenotice");
    let d = super::super::testutil::test_daemon(&dir);
    d.raise_hist_notice(&MigrateNotice {
        corrected: 2,
        kept: 1,
        at: 1_700_000_000,
    });
    d.raise_hist_notice(&MigrateNotice {
        corrected: 3,
        kept: 4,
        at: 1_700_000_900,
    });

    let n = d.hist_notice().expect("a notice is still owed");
    assert_eq!(
        n.corrected, 5,
        "a row corrected by the first pass is not corrected again by the \
         second, so the counts are of different rows and add up"
    );
    assert_eq!(
        n.kept, 4,
        "kept rows ARE re-counted every pass - the same payloads are \
         still missing - so the larger count stands rather than the sum"
    );
    assert_eq!(n.at, 1_700_000_900, "and the strip dates from the latest");

    assert!(d.dismiss_hist_migrate());
    assert!(
        d.hist_notice().is_none(),
        "one dismissal still spends the whole strip"
    );
}
