//! Custody tests for the queue's write verbs: what a delete, a retry
//! and a recategorise may do to a record another lane already owns.
//!
//! A sibling file rather than an inline `mod`, for the size gate
//! (TODO 106): test code moves out of `serve/api/queue.rs`, the baseline
//! does not move up.

use super::*;
use crate::serve::testutil::test_daemon;

const NZB: &[u8] = br#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb"><file poster="x" date="0" subject="&quot;a.bin&quot; yEnc (1/1)"><groups><group>g</group></groups><segments><segment bytes="1000" number="1">one@x</segment></segments></file></nzb>"#;

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("nzbfast-qcust-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("temp dir");
    d
}

/// "Download it again" pressed twice at once adds the release ONCE.
///
/// http.rs runs eight worker threads over the one listener, so two
/// dashboard tabs (or a tab and a scripted call) genuinely overlap.
/// The notice used to be cloned and only removed after a successful
/// admission, so both calls passed the find, both read the spool
/// copy and both enqueued - with `allow_dupe` set, so nothing held
/// the second, and `choose_out_dir` gave it a suffixed folder of its
/// own: one press, two complete downloads (Codex sweep 3, L3).
#[test]
fn two_overlapping_retries_of_one_notice_add_the_release_once() {
    let dir = tmp("keptrace");
    let d = test_daemon(&dir);
    let nzb = d.spool.join("Raced.Release.nzb");
    std::fs::write(&nzb, NZB).expect("spool copy");
    let out = d.out_dir().join("Raced.Release");
    d.note_delete_kept("Raced.Release", &out, "the Trash refused it", Some(&nzb));
    let path = out.display().to_string();

    KEPT_RETRY_STALL_MS.store(600, Ordering::Relaxed);
    let d2 = d.clone();
    let p2 = path.clone();
    let first = std::thread::spawn(move || retry_kept_notice(&d2, &p2));
    // Well inside the stall: the second call lands while the first
    // is holding the notice and has already read its bytes.
    std::thread::sleep(std::time::Duration::from_millis(150));
    let second = retry_kept_notice(&d, &path);
    let first = first.join().expect("first retry");
    KEPT_RETRY_STALL_MS.store(0, Ordering::Relaxed);

    let admitted = [&first, &second]
        .iter()
        .filter(|v| v["status"] == serde_json::Value::Bool(true))
        .count();
    assert_eq!(
        admitted, 1,
        "both presses were admitted: {first} / {second}"
    );
    assert_eq!(
        d.queue.lock_ok().len(),
        1,
        "one press on the notice, one download"
    );
    assert!(
        d.delete_kept.lock_ok().is_empty(),
        "the spent notice must not come back"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A failed add puts the notice BACK: the folder is still there, so
/// the strip and its button have to survive it.
#[test]
fn a_failed_retry_leaves_the_notice_where_it_was() {
    let dir = tmp("keptback");
    let d = test_daemon(&dir);
    // Two notices, so the restore has to land in the right slot.
    let first = d.out_dir().join("First.Release");
    let nzb1 = d.spool.join("First.Release.nzb");
    std::fs::write(&nzb1, NZB).expect("spool copy");
    d.note_delete_kept("First.Release", &first, "refused", Some(&nzb1));
    let second = d.out_dir().join("Second.Release");
    let nzb2 = d.spool.join("Second.Release.nzb");
    // Not an NZB at all, so `enqueue` refuses it.
    std::fs::write(&nzb2, b"not xml").expect("spool copy");
    d.note_delete_kept("Second.Release", &second, "refused", Some(&nzb2));

    let answer = retry_kept_notice(&d, &second.display().to_string());
    assert_eq!(
        answer["status"],
        serde_json::Value::Bool(false),
        "a spool copy that does not parse cannot be admitted"
    );
    let ring = d.delete_kept.lock_ok().clone();
    assert_eq!(ring.len(), 2, "the unspent notice was dropped");
    assert_eq!(
        ring[1].path,
        second.display().to_string(),
        "restored out of order"
    );
    assert!(nzb2.exists(), "an unspent notice keeps its spool copy");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A recategorize with NO sidecar live still takes the job's
/// part-downloaded files with it.
///
/// The adoption that moves them runs on the prefetch task's exit
/// path and nowhere else, so a job that was prefetched and then
/// stopped - an error, a pause, an earlier poke - has its journal
/// and part-files sitting in the old directory with the slot already
/// empty. The recategorize then re-pointed the record and poked
/// nothing, so the primary run started at the new directory from
/// zero and refetched the whole release over the same provider
/// quota, and the old folder was named by no record at all (Codex
/// sweep 3, M12).
#[test]
fn a_recategorize_with_no_sidecar_moves_the_partial_files() {
    let dir = tmp("recat");
    let d = test_daemon(&dir);
    let old = d.out_dir().join("Repointed.Release");
    std::fs::create_dir_all(&old).expect("old dir");
    std::fs::write(old.join(".nzbfast.journal"), b"journal").expect("journal");
    std::fs::write(old.join("part01.rar"), b"landed bytes").expect("part file");

    let job = Arc::new(Mutex::new(
        job_from_json(&serde_json::json!({
            "nzo_id": "nzo-recat-1",
            "name": "Repointed.Release",
            "nzb_path": "/tmp/x.nzb",
            "out_dir": old.to_string_lossy(),
            "state": "Queued",
        }))
        .expect("job"),
    ));
    d.queue.lock_ok().push_back(job.clone());
    assert!(
        d.sidecar.lock_ok().is_none(),
        "the shape under test is the one with no sidecar live"
    );

    requeue_category(&d, &job, "Repointed.Release", "movies").expect("recategorize");
    let now = job.lock_ok().out_dir.clone();
    assert_ne!(now, old, "the whole point of the call is a new directory");
    assert!(
        now.join("part01.rar").exists() && now.join(".nzbfast.journal").exists(),
        "the part-downloaded release stayed behind, so the job refetches it all"
    );
    assert!(
        !old.exists(),
        "the old directory is named by no record now and must not survive"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Codex C10: the queue store refuses AFTER the recategorize moved the
/// partial tree. The relocation fence prevents the live scheduling
/// race, not a restart after refused persistence - so the refused save
/// has to roll the whole transaction back, record and bytes together,
/// or the durable row restores the old path while the partial bytes sit
/// orphaned at the new one.
#[test]
fn a_refused_save_rolls_the_recategorize_back_whole() {
    use crate::serve::storecut::{Store, arm_store_cut, disarm};
    let dir = tmp("recatcut");
    let d = test_daemon(&dir);
    let old = d.out_dir().join("Rolled.Release");
    std::fs::create_dir_all(&old).expect("old dir");
    std::fs::write(old.join(".nzbfast.journal"), b"journal").expect("journal");
    std::fs::write(old.join("part01.rar"), b"landed bytes").expect("part file");

    let job = Arc::new(Mutex::new(
        job_from_json(&serde_json::json!({
            "nzo_id": "nzo-recat-2",
            "name": "Rolled.Release",
            "nzb_path": "/tmp/x.nzb",
            "out_dir": old.to_string_lossy(),
            "state": "Queued",
        }))
        .expect("job"),
    ));
    let old_cat = job.lock_ok().category.clone();
    d.queue.lock_ok().push_back(job.clone());

    arm_store_cut(&[Store::Queue]);
    let fence = requeue_category(&d, &job, "Rolled.Release", "movies").expect("recategorize");
    let newdir = job.lock_ok().out_dir.clone();
    assert_ne!(newdir, old, "the transaction re-pointed the record");
    assert!(
        !persist_relocations(&d, vec![fence]),
        "the armed cut must refuse the save"
    );
    disarm();

    let (cat, out, relocating) = {
        let g = job.lock_ok();
        (g.category.clone(), g.out_dir.clone(), g.relocating)
    };
    assert_eq!(cat, old_cat, "the label went back with the refusal");
    assert_eq!(out, old, "the record names the old path again");
    assert_eq!(relocating, 0, "the fence lifted after the rollback");
    assert!(
        old.join("part01.rar").exists() && old.join(".nzbfast.journal").exists(),
        "the partial tree came back to the path the durable row still names"
    );
    assert!(
        !newdir.exists(),
        "no orphaned bytes may stay at the path no record names"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A history-less delete of a LIVE job drops the queue row durably at
/// once and unlinks the spooled `.nzb` only when the download drains
/// (`spend_deferred_delete`). A kill in that window left an adoptable
/// spool file behind, so `recover_orphaned_spool` re-added - and
/// re-downloaded - the release an *arr had just cancelled.
#[test]
fn a_deleted_live_jobs_spool_copy_is_not_re_adopted_by_recovery() {
    let dir = tmp("maskdel");
    let d = test_daemon(&dir);
    let e = d
        .enqueue(
            NZB,
            "Cancelled.Release.nzb",
            "",
            -100,
            None,
            None,
            "test",
            false,
        )
        .expect("enqueue");
    // A control of the SAME shape under an unknown id: it must come
    // back, or this test would pass against a matcher that adopts
    // nothing at all.
    // Distinct bytes, so it is adopted on its own account rather than
    // removed as a spare copy of something the queue already holds.
    let control = d.spool.join("SABnzbd_nzo_nzbfast9001-Other.Release.nzb");
    let other = String::from_utf8_lossy(NZB).replace("one@x", "two@x");
    std::fs::write(&control, other).expect("control copy");

    let job = d.queue.lock_ok()[0].clone();
    let original = {
        let mut g = job.lock_ok();
        g.state = JobState::Downloading;
        g.tombstone = true;
        let original = g.nzb_path.clone();
        payload::mask_spool_from_recovery(&mut g);
        original
    };
    // The delete's own effect: the row is gone from the live queue and
    // from queue.json, park has not run yet.
    d.queue.lock_ok().clear();

    let masked = job.lock_ok().nzb_path.clone();
    assert!(!original.exists(), "the adoptable name is gone");
    assert!(
        masked.exists() && masked.to_string_lossy().ends_with(".nzb.deleting"),
        "park's unlink must still name the real file: {}",
        masked.display()
    );
    assert_eq!(
        d.recover_orphaned_spool(),
        1,
        "only the control is an orphan"
    );
    let back: Vec<String> = d
        .queue
        .lock_ok()
        .iter()
        .map(|j| j.lock_ok().nzo_id.clone())
        .collect();
    assert!(
        !back.contains(&e.nzo_id),
        "the cancelled release came back: {back:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A non-active delete whose spool unlink is REFUSED must not have the
/// release re-adopted at the next start.
///
/// The record is dropped durably at the delete, so the surviving file
/// names nothing and `recover_orphaned_spool` reads it as a job whose
/// record never reached disk: the release the user cancelled came back
/// and downloaded again. A read-only spool directory refuses the rename
/// as well as the unlink, which is why `drop_spool` has the third
/// resort this leans on.
#[cfg(unix)]
#[test]
fn a_delete_whose_spool_unlink_is_refused_is_not_re_adopted() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tmp("unlinkdeny");
    let d = test_daemon(&dir);
    let e = d
        .enqueue(
            NZB,
            "Cancelled.Release.nzb",
            "",
            -100,
            None,
            None,
            "test",
            false,
        )
        .expect("enqueue");
    // A control of the same shape under an unknown id, so this cannot
    // pass against a matcher that adopts nothing at all.
    let control = d.spool.join("SABnzbd_nzo_nzbfast9002-Other.Release.nzb");
    let other = String::from_utf8_lossy(NZB).replace("one@x", "two@x");
    std::fs::write(&control, other).expect("control copy");

    let job = d.queue.lock_ok()[0].clone();
    let (nzb, out_dir) = {
        let g = job.lock_ok();
        (g.nzb_path.clone(), g.out_dir.clone())
    };
    let was = std::fs::metadata(&d.spool)
        .expect("spool")
        .permissions()
        .mode();
    std::fs::set_permissions(&d.spool, std::fs::Permissions::from_mode(0o555)).expect("chmod");
    let mut held = std::collections::HashMap::new();
    hold_or_drop_spool(false, &out_dir, &nzb, &mut held);
    // The delete's own effect: the record is gone for good.
    d.queue.lock_ok().clear();
    assert!(
        nzb.exists(),
        "the fault under test is an unlink that was refused"
    );
    std::fs::set_permissions(&d.spool, std::fs::Permissions::from_mode(was)).expect("chmod back");

    assert_eq!(
        d.recover_orphaned_spool(),
        1,
        "only the control is an orphan"
    );
    let back: Vec<String> = d
        .queue
        .lock_ok()
        .iter()
        .map(|j| j.lock_ok().nzo_id.clone())
        .collect();
    assert!(
        !back.contains(&e.nzo_id),
        "the cancelled release came back: {back:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Recovery must never remove the spool path a row it just made durable
/// names.
///
/// The orphan list and the `nzb_sha` set are snapshotted before any
/// adoption, and `enqueue_as` writes its own copy under the name the
/// add path derives - which can be a name this very scan snapshotted as
/// a second orphan. That copy is then byte-identical to the one just
/// adopted, so the duplicate arm removed it and left the durable row
/// pointing at nothing: unrecoverable, because the row keeps the next
/// start from seeing an orphan at all.
#[test]
fn recovery_leaves_every_durable_rows_nzb_in_place() {
    let dir = tmp("twopath");
    let d = test_daemon(&dir);
    // Old-layout orphan (no stem) beside the byte-identical copy under
    // the name the add path derives for it. Sorted stem-first, so the
    // old-layout one is adopted and the other is the "spare copy".
    let old = d.spool.join("SABnzbd_nzo_nzbfast4242.nzb");
    std::fs::write(&old, NZB).expect("orphan");
    let derived = {
        let probe = tmp("twopath-probe");
        let p = test_daemon(&probe);
        std::fs::write(p.spool.join("SABnzbd_nzo_nzbfast4242.nzb"), NZB).expect("probe orphan");
        assert_eq!(p.recover_orphaned_spool(), 1, "probe adoption");
        let name = p.queue.lock_ok()[0].lock_ok().nzb_path.clone();
        let name = name.file_name().expect("file name").to_os_string();
        let _ = std::fs::remove_dir_all(&probe);
        d.spool.join(name)
    };
    assert_ne!(derived, old, "the two-path shape needs two names");
    std::fs::write(&derived, NZB).expect("second copy");

    assert_eq!(d.recover_orphaned_spool(), 1, "one job, two copies of it");
    for j in d.queue.lock_ok().iter() {
        let p = j.lock_ok().nzb_path.clone();
        assert!(
            p.exists(),
            "the durable row's NZB was removed as a spare copy: {}",
            p.display()
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}
