//! TODO 16g / A12: `enqueue` tells its caller whether the record reached
//! disk, and `recover_orphaned_spool` adopts back, exactly once, every
//! spooled NZB whose record never did.
//!
//! A child of daemon_tests on the `#[path]` convention, so size-gate.py
//! reads it as test code; `use super::*` brings `with_daemon`, `restart`
//! and `one_file_nzb`.

use super::*;

fn add(d: &Arc<Daemon>, seg: &str, name: &str) -> Result<Enqueued> {
    d.enqueue(
        one_file_nzb(seg).as_bytes(),
        name,
        "",
        -100,
        None,
        None,
        "test",
        false,
    )
}

fn spool_nzbs(d: &Arc<Daemon>) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(&d.spool)
        .expect("spool dir")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|f| f.ends_with(".nzb"))
        .collect();
    v.sort();
    v
}

fn queued_ids(d: &Arc<Daemon>) -> Vec<String> {
    d.queue
        .lock_ok()
        .iter()
        .map(|j| j.lock_ok().nzo_id.clone())
        .collect()
}

fn stored_queue_ids(d: &Arc<Daemon>) -> Vec<String> {
    crate::persist::load_json_with_backup(&d.spool.join("queue.json"))
        .and_then(|v| v.get("queue").and_then(Value::as_array).cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|j| j.get("nzo_id").and_then(Value::as_str).map(str::to_string))
        .collect()
}

#[test]
fn a_successful_enqueue_is_reported_durable_and_lands_in_queue_json() {
    with_daemon("a12-durable", |d| {
        let e = add(d, "one", "Some.Release.nzb").expect("enqueue");
        assert!(e.durable, "the save landed, so the caller must be told so");
        assert_eq!(queued_ids(d), vec![e.nzo_id.clone()]);
        assert_eq!(stored_queue_ids(d), vec![e.nzo_id.clone()]);
        // And there is nothing for recovery to do.
        let d2 = restart(d);
        assert_eq!(d2.recover_orphaned_spool(), 0);
        assert_eq!(queued_ids(&d2), vec![e.nzo_id]);
    });
}

#[test]
fn a_failed_persist_is_visible_to_the_caller() {
    with_daemon("a12-unsaved", |d| {
        crate::serve::storecut::arm_cut(0);
        let e = add(d, "one", "Some.Release.nzb").expect("enqueue still accepts the job");
        crate::serve::storecut::disarm();
        assert!(!e.durable, "queue.json was never written");
        // Accepted in memory only: live now, absent from disk.
        assert_eq!(queued_ids(d), vec![e.nzo_id.clone()]);
        assert!(stored_queue_ids(d).is_empty());
        // The spool copy is the one trace the job left.
        assert_eq!(spool_nzbs(d).len(), 1);
    });
}

/// The headline: a daemon accepts a job, cannot save, dies. The next
/// start adopts the spool file back under the SAME id, saves, and the
/// start after that finds nothing to do.
#[test]
fn an_orphaned_spool_nzb_is_recovered_exactly_once() {
    with_daemon("a12-orphan", |d| {
        crate::serve::storecut::arm_cut(0);
        let lost = add(d, "one", "Some.Release.nzb").expect("enqueue");
        crate::serve::storecut::disarm();
        assert!(!lost.durable);
        let orphan = spool_nzbs(d);
        assert_eq!(orphan.len(), 1);

        // Restart 1: the record is gone, the file is not.
        let d2 = restart(d);
        assert!(queued_ids(&d2).is_empty(), "nothing reached queue.json");
        assert_eq!(d2.recover_orphaned_spool(), 1);
        assert_eq!(
            queued_ids(&d2),
            vec![lost.nzo_id.clone()],
            "same id, not a fresh one"
        );
        let recovered = d2.queue.lock_ok()[0].clone();
        {
            let g = recovered.lock_ok();
            assert_eq!(g.origin, "recovered");
            assert_eq!(g.name, "Some.Release");
            assert_eq!(g.nzb_sha, nzb_sha(one_file_nzb("one").as_bytes()));
            assert!(g.nzb_path.exists(), "the adopted job's NZB is in place");
        }
        assert_eq!(
            stored_queue_ids(&d2),
            vec![lost.nzo_id.clone()],
            "and it is durable now"
        );
        assert_eq!(spool_nzbs(&d2).len(), 1, "no second copy left behind");

        // Restart 2: the record is there, so the file is not an orphan.
        let d3 = restart(&d2);
        assert_eq!(d3.recover_orphaned_spool(), 0);
        assert_eq!(queued_ids(&d3), vec![lost.nzo_id.clone()]);
        assert_eq!(spool_nzbs(&d3).len(), 1);
        // And the allocator can never hand the recovered number out again.
        let again = add(&d3, "two", "Other.Release.nzb").expect("enqueue");
        assert_ne!(again.nzo_id, lost.nzo_id);
    });
}

/// Recovery whose own save fails leaves the file for the next start -
/// the same id is asked for again, so nothing is doubled.
#[test]
fn an_undurable_readoption_is_retried_at_the_next_start() {
    with_daemon("a12-retry", |d| {
        crate::serve::storecut::arm_cut(0);
        let lost = add(d, "one", "Some.Release.nzb").expect("enqueue");
        crate::serve::storecut::disarm();

        let d2 = restart(d);
        crate::serve::storecut::arm_cut(0);
        assert_eq!(d2.recover_orphaned_spool(), 0, "not durable = not counted");
        crate::serve::storecut::disarm();
        assert_eq!(
            queued_ids(&d2),
            vec![lost.nzo_id.clone()],
            "live in memory though"
        );
        assert_eq!(spool_nzbs(&d2).len(), 1, "the file stays");

        let d3 = restart(&d2);
        assert_eq!(d3.recover_orphaned_spool(), 1);
        assert_eq!(queued_ids(&d3), vec![lost.nzo_id]);
        assert_eq!(spool_nzbs(&d3).len(), 1);
    });
}

/// Files a record or a kept-files notice names are not orphans, whatever
/// their name looks like; a spare byte-identical copy of a held NZB is
/// litter, not a lost job.
#[test]
fn recovery_leaves_named_files_and_removes_spare_copies() {
    with_daemon("a12-named", |d| {
        let kept = add(d, "one", "Some.Release.nzb").expect("enqueue");
        // A kept-files notice holding a spool file of its own.
        let note_nzb = d.spool.join("SABnzbd_nzo_nzbfast900-Deleted.Release.nzb");
        std::fs::write(&note_nzb, one_file_nzb("nine")).expect("write");
        d.delete_kept.lock_ok().push_back(KeptNote {
            name: "Deleted.Release".into(),
            path: "/tmp/deleted".into(),
            why: "test".into(),
            at: 0,
            nzb: note_nzb.display().to_string(),
        });
        // A stale sibling of a KNOWN id under another name: left alone.
        let sibling = d.spool.join(format!("{}-Older.Name.nzb", kept.nzo_id));
        std::fs::write(&sibling, one_file_nzb("sib")).expect("write");
        // A spare copy of the held NZB under an unknown id: removed.
        let spare = d.spool.join("SABnzbd_nzo_nzbfast901-Some.Release.nzb");
        std::fs::write(&spare, one_file_nzb("one")).expect("write");
        // Not ours at all.
        std::fs::write(d.spool.join("hand-dropped.nzb"), one_file_nzb("x")).expect("write");

        assert_eq!(d.recover_orphaned_spool(), 0);
        assert_eq!(queued_ids(d), vec![kept.nzo_id]);
        assert!(note_nzb.exists(), "the notice's file is not an orphan");
        assert!(sibling.exists(), "a known id's sibling is not adopted");
        assert!(!spare.exists(), "a spare copy of a held NZB is removed");
        assert!(d.spool.join("hand-dropped.nzb").exists());
    });
}

/// A release re-added under another NZB while this one was unrecorded
/// comes back as an ALTERNATIVE behind it - the ordinary duplicate hold,
/// not a second download.
#[test]
fn a_recovered_duplicate_is_held_behind_the_live_original() {
    with_daemon("a12-dupe", |d| {
        let live = add(d, "a", "Show.S03E04.1080p.nzb").expect("enqueue");
        let orphan = d.spool.join("SABnzbd_nzo_nzbfast77-Show.S03E04.720p.nzb");
        std::fs::write(&orphan, one_file_nzb("b")).expect("write");
        assert_eq!(d.recover_orphaned_spool(), 1);
        let q = d.queue.lock_ok();
        let held = q
            .iter()
            .find(|j| j.lock_ok().nzo_id == "SABnzbd_nzo_nzbfast77")
            .expect("recovered under its own id");
        let g = held.lock_ok();
        assert_eq!(g.held_for, live.nzo_id);
        assert!(g.paused);
        assert_eq!(g.priority, DUPE_PRIORITY);
    });
}

/// The category the user CHOSE survives the loss of the record it was
/// written in.
///
/// Before the sidecar, an adopted job was enqueued under an empty
/// category and took whatever §218's inference made of the NZB - so a
/// release the user filed under one category came back under another,
/// in a different folder, and nothing said it had moved. The one place
/// the choice can be kept is beside the spool copy, because that copy is
/// the only thing a run whose saves never landed leaves behind.
#[test]
fn a_recovered_job_keeps_the_category_the_user_chose() {
    with_daemon("a12-category", |d| {
        crate::serve::storecut::arm_cut(0);
        let lost = d
            .enqueue(
                one_file_nzb("one").as_bytes(),
                "Some.Release.nzb",
                "films",
                -100,
                None,
                None,
                "test",
                false,
            )
            .expect("enqueue");
        crate::serve::storecut::disarm();
        assert!(!lost.durable, "the record never reached disk");

        let d2 = restart(d);
        assert_eq!(d2.recover_orphaned_spool(), 1);
        let row = d2.queue.lock_ok()[0].clone();
        let g = row.lock_ok();
        assert_eq!(g.nzo_id, lost.nzo_id);
        assert_eq!(g.category, "films", "the chosen category was not recovered");
        assert!(
            g.out_dir.components().any(|c| c.as_os_str() == "films"),
            "and the payload must land where that category files it: {}",
            g.out_dir.display()
        );
    });
}

/// An orphan with no sidecar beside it - a copy written before this
/// existed, an add that chose no category, or a sidecar write the same
/// failing disk refused - is adopted exactly as it was before, with the
/// inference deciding. The sidecar adds a case; it does not replace the
/// old one.
#[test]
fn an_orphan_with_no_sidecar_is_adopted_as_it_always_was() {
    with_daemon("a12-no-sidecar", |d| {
        let orphan = d.spool.join("SABnzbd_nzo_nzbfast55-Hand.Written.nzb");
        std::fs::write(&orphan, one_file_nzb("z")).expect("write");
        assert_eq!(d.recover_orphaned_spool(), 1);
        assert_eq!(queued_ids(d), vec!["SABnzbd_nzo_nzbfast55".to_string()]);
    });
}

/// The sidecar belongs to the spool copy: it goes when the copy goes,
/// it is never mistaken for an orphan of its own, and one left behind
/// by any other route is swept at the next start.
#[test]
fn a_category_sidecar_lives_and_dies_with_its_spool_copy() {
    with_daemon("a12-sidecar-life", |d| {
        let job = d
            .enqueue(
                one_file_nzb("one").as_bytes(),
                "Some.Release.nzb",
                "films",
                -100,
                None,
                None,
                "test",
                false,
            )
            .expect("enqueue");
        let nzb = d.queue.lock_ok()[0].lock_ok().nzb_path.clone();
        let side = crate::serve::job::spool_cat_path(&nzb);
        assert_eq!(std::fs::read_to_string(&side).unwrap_or_default(), "films");
        // A sidecar is not an adoptable orphan, whatever else is here.
        assert_eq!(d.recover_orphaned_spool(), 0);
        assert_eq!(queued_ids(d), vec![job.nzo_id]);
        assert!(side.exists(), "and the live job's own sidecar stays");

        // One whose copy has gone has no reader left.
        let dangling = d.spool.join("SABnzbd_nzo_nzbfast800-Gone.nzb.cat");
        std::fs::write(&dangling, "tv").expect("write");
        assert_eq!(d.recover_orphaned_spool(), 0);
        assert!(!dangling.exists(), "a sidecar with no copy is swept");
        assert!(side.exists());

        // And a delete takes the copy's sidecar with it.
        drop_spool(&nzb);
        assert!(!nzb.exists());
        assert!(
            !side.exists(),
            "the sidecar outlived the copy it belongs to"
        );
    });
}
