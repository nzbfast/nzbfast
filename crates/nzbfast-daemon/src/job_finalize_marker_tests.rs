//! The finalize marker's crash contract: post-processing must not
//! begin unless the marker it is insured by is durable, and must not
//! leave one behind if it does not run.
//!
//! Split out of `job.rs` for the size gate (TODO 106) - the parent was
//! at its 3,000-line ceiling. Same module, its own file, unix-only for
//! the permission bits it makes the spool unwritable with.

use super::*;
use crate::testutil::test_daemon;
use std::os::unix::fs::PermissionsExt;

/// M6 (Codex sweep 5 Aug): `finalize_completed` wrote the
/// finalizing marker, ignored `save_queue()`'s answer, and began
/// relocating the payload anyway - so a crash mid-move with an
/// unwritable spool restored a clean Completed record over a
/// half-moved payload. With the marker unwritable, post-processing
/// must not begin: the files stay exactly where the record says.
#[tokio::test(flavor = "multi_thread")]
async fn an_unwritable_finalize_marker_skips_post_processing() {
    let dir = std::env::temp_dir().join(format!("nzbfast-finmark-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = test_daemon(&dir);
    let out = dir.join("out").join("Some.Job");
    std::fs::create_dir_all(&out).unwrap();
    // A sidecar the default par2 sweep deletes: if post-processing
    // runs regardless, this file is gone and the assert names it.
    std::fs::write(out.join("some.job.par2"), b"par2").unwrap();
    // X5-03: and the article journal the engine handed us to retire
    // (`get::JournalOwner::Caller`). Its retirement is ORDERED after the
    // marker's `save_queue`, and that order is the crash transaction -
    // see the assert below.
    let journal = out.join(nzbkit::journal::JOURNAL_LEAF);
    std::fs::write(&journal, b"nzbfast-journal v1 x\n").unwrap();
    let job = Arc::new(Mutex::new(
        job_from_json(&json!({
            "nzo_id": "SABnzbd_nzo_finmark",
            "name": "Some.Job",
            "nzb_path": dir.join("some.nzb").to_string_lossy(),
            "out_dir": out.to_string_lossy(),
            "state": "Completed",
        }))
        .unwrap(),
    ));
    let spool = dir.join("spool");
    std::fs::set_permissions(&spool, std::fs::Permissions::from_mode(0o555)).unwrap();
    finalize_completed(&d, &job).await;
    std::fs::set_permissions(&spool, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert!(
        out.join("some.job.par2").exists(),
        "post-processing ran with no durable finalize marker"
    );
    // X5-03, THE ORDERING - and it is the ordering that IS the crash
    // transaction rather than either statement on its own. The engine no
    // longer retires a daemon job's journal; `retire_deferred_journal`
    // does, and it must run strictly AFTER the `save_queue` that makes
    // the row's own record durable. Put it one line earlier and the
    // window X5-03 names reopens - narrower, and just as real - with
    // nothing in the crash probe able to see it: that probe kills at the
    // engine's barrier, minutes before either statement runs.
    //
    // This arm is where the ordering becomes DETERMINISTICALLY visible,
    // with no race to catch. The save FAILED, so the row is still in the
    // resume-from-journal regime and the message above tells the user to
    // retry the job - advice this file is the only thing that keeps
    // honest, because a retry with the journal already gone refetches
    // every byte of a download that had completely finished.
    assert!(
        journal.exists(),
        "the journal was retired before the finalize marker was durable - the row is \
         still resume-from-journal and its own message promises a retry that would \
         now refetch the whole job"
    );
    let j = job.lock_ok();
    assert!(!j.finalizing, "the in-memory marker must be cleared");
    assert!(
        j.unpack_blocked_by.contains("queue file"),
        "the row does not say why: {:?}",
        j.unpack_blocked_by
    );
    drop(j);
    let _ = std::fs::remove_dir_all(&dir);
}

/// ...and when we ALREADY HOLD the password, the affordance is not
/// the answer - delivering the payload is.
///
/// The 11 Aug fix taught the failed path to SEE the lock but
/// deliberately stopped there, because unlocking belonged to jobs
/// that COMPLETE. So with the right line sitting in the operator's
/// passwords file we raised a prompt for a password we had already
/// read, while SABnzbd - which tries its `password_file` here -
/// simply unpacked it (advQ, the four-way correctness round, 12 Aug).
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_job_spends_a_password_it_already_holds() {
    use nzbkit::zip::fixtures::{Encrypt, Spec, zip_of};
    let dir = std::env::temp_dir().join(format!("nzbfast-lockedspend-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = test_daemon(&dir);
    let list = dir.join("pw.txt");
    // A wrong line first: the ladder must sweep, not take line one.
    std::fs::write(&list, "not-this\nopensesame\n").unwrap();
    *d.password_file.lock_ok() = list;

    let out = dir.join("out").join("Locked.Job");
    std::fs::create_dir_all(&out).unwrap();
    let payload: Vec<u8> = (0..30_000u32).map(|i| (i * 3 + 7) as u8).collect();
    std::fs::write(
        out.join("payload.zip"),
        zip_of(&[Spec {
            encrypt: Some(Encrypt::Ae {
                password: "opensesame",
                strength: 3,
                vendor_version: 2,
            }),
            ..Spec::deflated("movie.mkv", &payload)
        }]),
    )
    .unwrap();
    let job = Arc::new(Mutex::new(
        job_from_json(&json!({
            "nzo_id": "SABnzbd_nzo_lockedspend",
            "name": "Locked.Job",
            "nzb_path": dir.join("locked.nzb").to_string_lossy(),
            "out_dir": out.to_string_lossy(),
            "state": "Failed",
            "fail_message": "an archive in the output directory could not be unpacked",
        }))
        .unwrap(),
    ));
    finalize_completed(&d, &job).await;

    assert_eq!(
        std::fs::read(out.join("movie.mkv")).unwrap(),
        payload,
        "the payload we held the password for must be delivered"
    );
    let j = job.lock_ok();
    assert_eq!(
        j.state,
        JobState::Completed,
        "it is a completion, not a failure"
    );
    assert!(j.fail_message.is_empty(), "{:?}", j.fail_message);
    assert!(!j.password_required, "nothing left to ask for");
    assert_eq!(
        j.password.as_deref(),
        Some("opensesame"),
        "the winner is recorded, so a retry needs no second sweep"
    );
    drop(j);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A FAILED job whose output holds a locked archive still owes the
/// user the password affordance. The whole post-processing tail runs
/// for completions only - an encrypted RAR set gets there because it
/// COMPLETES, but a header-encrypted 7z fails the unpack outright, so
/// before this the drawer offered "show the folder" for a job whose
/// only remedy is a password (soak round 3, 11 Aug, advQ).
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_job_holding_a_locked_archive_still_asks_for_the_password() {
    let dir = std::env::temp_dir().join(format!("nzbfast-lockedfail-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = test_daemon(&dir);
    let out = dir.join("out").join("Locked.Job");
    std::fs::create_dir_all(&out).unwrap();
    // The real thing: a `-mhe` container, same fixture the probe
    // test pins. A stub would prove nothing - the detector reads
    // the 7z header chain.
    std::fs::copy(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../nzbkit-base/tests/fixtures/sevenz/header-encrypted.7z"
        ),
        out.join("payload.7z"),
    )
    .unwrap();
    let job = Arc::new(Mutex::new(
        job_from_json(&json!({
            "nzo_id": "SABnzbd_nzo_lockedfail",
            "name": "Locked.Job",
            "nzb_path": dir.join("locked.nzb").to_string_lossy(),
            "out_dir": out.to_string_lossy(),
            "state": "Failed",
            "fail_message": "an archive in the output directory could not be unpacked",
        }))
        .unwrap(),
    ));
    finalize_completed(&d, &job).await;

    let j = job.lock_ok();
    assert!(
        j.password_required,
        "a failed job sitting on a locked 7z must ask for the password"
    );
    assert_eq!(
        fail_action(
            fail_kind(&j.fail_message),
            fail_hint(&j.fail_message),
            &j.fail_message,
            j.password_required,
        ),
        "password",
        "and the drawer must offer the unlock, not the folder"
    );
    // Detection only: the payload is untouched (no sweep, no move).
    assert!(out.join("payload.7z").exists(), "the archive was disturbed");
    drop(j);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The other half of that probe: a locked archive in the folder is
/// not an answer to a failure that was never about unpacking.
/// `password_required` gates `auto_retry_eligible`, so raising it on
/// a transport failure took the M32 automatic retry away from every
/// encrypted release whose download hit a connection blip - and
/// `post_job_plan` then reported that live post to the indexer as
/// failed. A full disk is `Local` too and already has its own
/// remedy; the unlock button must not cover it.
#[tokio::test(flavor = "multi_thread")]
async fn a_failure_that_is_not_about_unpacking_keeps_its_own_remedy() {
    let dir = std::env::temp_dir().join(format!("nzbfast-lockedskip-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = test_daemon(&dir);
    for (id, message) in [
        (
            "transport",
            "download failed on connection errors: every server refused",
        ),
        (
            "diskfull",
            "out of disk space - the output volume filled during the download",
        ),
        (
            "corrupt",
            "the articles did not decode: 4001 damaged article(s)",
        ),
    ] {
        let out = dir.join("out").join(id);
        std::fs::create_dir_all(&out).unwrap();
        std::fs::copy(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../nzbkit-base/tests/fixtures/sevenz/header-encrypted.7z"
            ),
            out.join("payload.7z"),
        )
        .unwrap();
        let job = Arc::new(Mutex::new(
            job_from_json(&json!({
                "nzo_id": format!("SABnzbd_nzo_{id}"),
                "name": id,
                "nzb_path": dir.join("x.nzb").to_string_lossy(),
                "out_dir": out.to_string_lossy(),
                "state": "Failed",
                "fail_message": message,
            }))
            .unwrap(),
        ));
        finalize_completed(&d, &job).await;
        let j = job.lock_ok();
        assert!(
            !j.password_required,
            "{id}: a locked archive is not why this job failed"
        );
        assert_ne!(
            fail_action(
                fail_kind(&j.fail_message),
                fail_hint(&j.fail_message),
                &j.fail_message,
                j.password_required,
            ),
            "password",
            "{id}: the drawer must keep the remedy that fits"
        );
    }
    // The transport failure is the one that also owed a retry.
    let job = Arc::new(Mutex::new(
        job_from_json(&json!({
            "nzo_id": "SABnzbd_nzo_transport",
            "name": "transport",
            "nzb_path": dir.join("x.nzb").to_string_lossy(),
            "out_dir": dir.join("out").join("transport").to_string_lossy(),
            "state": "Failed",
            "fail_message": "download failed on connection errors: every server refused",
        }))
        .unwrap(),
    ));
    finalize_completed(&d, &job).await;
    assert!(
        auto_retry_eligible(&job.lock_ok(), 300),
        "the one automatic retry must survive an encrypted volume on disk"
    );
    // A locked archive DOES still answer a plain unpack failure.
    assert!(
        fail_kind("an archive in the output directory could not be unpacked") == FailKind::Local
            && fail_hint("an archive in the output directory could not be unpacked").is_empty(),
        "the probe's own gate must still admit the unpack failure"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
