//! Custody tests for the queue's write verbs: what a delete, a retry
//! and a recategorise may do to a record another lane already owns.
//!
//! A sibling file rather than an inline `mod` because queue.rs sits on
//! the size gate's file ceiling (TODO 106): test code moves out, the
//! baseline does not move up.

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
