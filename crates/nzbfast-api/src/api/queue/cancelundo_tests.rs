//! GH #86: the cancel grace window, end to end through the two arms
//! that make it up.
//!
//! A sibling file rather than an inline `mod`, like `custody_tests`
//! beside it and for the same reason (TODO 106 size gate).
//!
//! These drive `delete_arm` and `undelete_arm` rather than the daemon
//! helpers directly, because the property under test is not "the store
//! holds bytes" - it is "the thing the page presses gives the user their
//! download back". The daemon half is reachable from a unit test and
//! proves nothing about the wiring.

use super::*;
use crate::testutil::test_daemon;

const NZB: &[u8] = br#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb"><file poster="x" date="0" subject="&quot;a.bin&quot; yEnc (1/1)"><groups><group>g</group></groups><segments><segment bytes="1000" number="1">one@x</segment></segments></file></nzb>"#;

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("nzbfast-qundo-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("temp dir");
    d
}

fn params(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

/// The whole point, in one test: a cancelled download comes back with
/// the things that make it a download.
///
/// NOT a membership check, and that distinction is the reason this file
/// exists. "The row is back" is true whether or not the NZB came back
/// with it, so a test that only counts rows passes over a window that
/// restores an unrunnable job - the exact silent downgrade the audit
/// records on the history side (section 5). So this asserts on the
/// SPOOL: the restored record names a file, that file parses, and the
/// id, category, priority and paused flag are the ones the user had.
#[test]
fn an_undone_cancel_gives_the_download_back_with_its_nzb() {
    let dir = tmp("roundtrip");
    let d = test_daemon(&dir);
    let e = d
        .enqueue(
            NZB,
            "Undone.Release.nzb",
            "tv",
            1,
            None,
            None,
            "test",
            false,
        )
        .expect("enqueue");
    {
        let q = d.queue.lock_ok();
        let mut g = q[0].lock_ok();
        g.paused = true;
    }

    let j = payload::delete_arm(&d, &params(&[("name", "delete")]), "delete", &e.nzo_id);
    assert_eq!(j["status"], serde_json::json!(true), "the delete: {j}");
    assert!(d.queue.lock_ok().is_empty(), "the row did not leave");
    let token = j["undo"]["token"]
        .as_str()
        .unwrap_or_else(|| panic!("no undo token on a files-kept cancel: {j}"))
        .to_string();
    assert_eq!(j["undo"]["rows"], serde_json::json!(1));

    let back = payload::undelete_arm(&d, &token);
    assert_eq!(back["status"], serde_json::json!(true), "the undo: {back}");
    assert_eq!(
        back["failed"],
        serde_json::json!([]),
        "a partial restore must say so: {back}"
    );

    let q = d.queue.lock_ok();
    assert_eq!(q.len(), 1, "one cancel, one undo, one row");
    let g = q[0].lock_ok();
    assert_eq!(
        g.nzo_id, e.nzo_id,
        "the id changed, so an *arr's handle died in the undo"
    );
    assert_eq!(g.category, "tv", "the filing decision was lost");
    assert_eq!(g.priority, 1, "the priority was lost");
    assert!(g.paused, "a paused row came back running");
    // The half a membership check cannot see.
    let bytes = std::fs::read(&g.nzb_path).expect("the restored row names no spool copy");
    assert!(
        nzbkit::nzb::Nzb::parse(&bytes).is_ok(),
        "the restored row's spool copy is not an NZB - it can never be run"
    );

    drop(g);
    drop(q);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A token is spent ONCE. The toast can be clicked twice (it is a
/// `role="button"` with a keyboard path as well as a click), and the
/// second press must refuse rather than add the release a second time -
/// which is the shape `two_overlapping_retries_of_one_notice_add_the_release_once`
/// already guards on the kept-files notice next door.
#[test]
fn an_undo_token_cannot_be_spent_twice() {
    let dir = tmp("twice");
    let d = test_daemon(&dir);
    let e = d
        .enqueue(
            NZB,
            "Twice.Release.nzb",
            "",
            -100,
            None,
            None,
            "test",
            false,
        )
        .expect("enqueue");
    let j = payload::delete_arm(&d, &params(&[("name", "delete")]), "delete", &e.nzo_id);
    let token = j["undo"]["token"].as_str().expect("token").to_string();

    assert_eq!(
        payload::undelete_arm(&d, &token)["status"],
        serde_json::json!(true)
    );
    let again = payload::undelete_arm(&d, &token);
    assert_eq!(
        again["status"],
        serde_json::json!(false),
        "the same token worked twice: {again}"
    );
    assert!(
        again["error"].as_str().is_some_and(|s| !s.is_empty()),
        "a refusal says something: {again}"
    );
    assert_eq!(d.queue.lock_ok().len(), 1, "one undo, one row");

    let _ = std::fs::remove_dir_all(&dir);
}

/// THE FILES HALF GETS NO TOKEN.
///
/// `del_files=1` can defer the removal to `park()` or to the prefetch
/// drain - that is `FilesVerdict::pending` - so at the moment this
/// answers, the daemon has not settled what happened to the directory.
/// An Undo offered on top of that is a promise nobody has kept, and the
/// page would show it as confidently as any other.
#[test]
fn a_delete_that_asked_for_the_files_offers_no_undo() {
    let dir = tmp("delfiles");
    let d = test_daemon(&dir);
    let e = d
        .enqueue(
            NZB,
            "Files.Release.nzb",
            "",
            -100,
            None,
            None,
            "test",
            false,
        )
        .expect("enqueue");
    let j = payload::delete_arm(
        &d,
        &params(&[("name", "delete"), ("del_files", "1")]),
        "delete",
        &e.nzo_id,
    );
    assert_eq!(j["status"], serde_json::json!(true));
    assert!(
        j["files"].is_object(),
        "the files verdict is the key that IS owed here: {j}"
    );
    assert!(
        j.get("undo").is_none(),
        "a files delete handed out an undo token: {j}"
    );
    // And nothing is left holding the inode open for ten minutes.
    assert!(
        std::fs::read_dir(d.cancel_undo_dir())
            .map(|r| r.flatten().count())
            .unwrap_or(0)
            == 0,
        "the undo store kept a copy for a cancel it will never offer back"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// An emptied retained copy REFUSES rather than restoring a row that
/// can only fail.
///
/// This is not a hypothetical: `drop_spool`'s third resort empties the
/// spool file when both the unlink and the rename are refused (a Windows
/// sharing violation, a `uchg` flag, a read-only spool directory), and
/// the retained copy is a hard LINK, so that truncation goes through the
/// inode they share. `recover_orphaned_spool` skips an empty copy for
/// exactly this reason; so does the undo, and it says so out loud
/// instead of queueing a job with no articles in it.
#[test]
fn an_emptied_copy_refuses_instead_of_restoring_an_unrunnable_row() {
    let dir = tmp("emptied");
    let d = test_daemon(&dir);
    let e = d
        .enqueue(
            NZB,
            "Emptied.Release.nzb",
            "",
            -100,
            None,
            None,
            "test",
            false,
        )
        .expect("enqueue");
    let j = payload::delete_arm(&d, &params(&[("name", "delete")]), "delete", &e.nzo_id);
    let token = j["undo"]["token"].as_str().expect("token").to_string();

    // What the fault path does, done to the retained copy directly.
    let held = d.cancel_undo_dir().join(format!("{}.nzb", e.nzo_id));
    assert!(held.exists(), "nothing was held: {}", held.display());
    std::fs::write(&held, b"").expect("empty the held copy");

    let back = payload::undelete_arm(&d, &token);
    assert_eq!(
        back["status"],
        serde_json::json!(false),
        "an empty copy was restored as a job: {back}"
    );
    assert!(
        d.queue.lock_ok().is_empty(),
        "a row with no articles in it was put back in the queue"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// ALL OR NOTHING. A batch that can only put some of its rows back gets
/// no token at all, and the copies it did hold are released.
///
/// A partial undo is the same silent downgrade as a missing NZB: the
/// user presses one affordance, the toast says it worked, and part of
/// their queue is simply gone. The window here is forced by taking the
/// second row's spool copy away before the delete runs, which is what a
/// spool on a volume that has just gone offline looks like.
#[test]
fn a_batch_that_cannot_hold_every_row_offers_no_undo() {
    let dir = tmp("partial");
    let d = test_daemon(&dir);
    let a = d
        .enqueue(
            NZB,
            "First.Release.nzb",
            "",
            -100,
            None,
            None,
            "test",
            false,
        )
        .expect("enqueue a");
    let other = String::from_utf8_lossy(NZB).replace("one@x", "two@x");
    let b = d
        .enqueue(
            other.as_bytes(),
            "Second.Release.nzb",
            "",
            -100,
            None,
            None,
            "test",
            false,
        )
        .expect("enqueue b");
    {
        let q = d.queue.lock_ok();
        let g = q[1].lock_ok();
        std::fs::remove_file(&g.nzb_path).expect("take the second row's copy away");
    }

    let j = payload::delete_arm(&d, &params(&[("name", "delete")]), "delete", "all");
    assert_eq!(j["removed"], serde_json::json!(2), "both rows left: {j}");
    assert!(
        j.get("undo").is_none(),
        "a batch offered an undo that could only put one of two rows back: {j}"
    );
    assert_eq!(
        std::fs::read_dir(d.cancel_undo_dir())
            .map(|r| r.flatten().count())
            .unwrap_or(0),
        0,
        "the refused batch left its copies behind"
    );
    let _ = (a, b);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A restart is a purge, not a resurrection.
///
/// The index is in memory, so after a restart no token can reach these
/// files; leaving them would be a leak. Leaving them under the ADOPTABLE
/// name in the spool ROOT would be worse - `recover_orphaned_spool`
/// would re-add the release the user cancelled, which is the defect
/// `mask_spool_path` exists to prevent and which this repo has already
/// paid for twice. So the second assertion is the load-bearing one: the
/// recovery pass walks straight past the store.
#[test]
fn the_undo_store_does_not_survive_a_restart_or_tempt_the_recovery() {
    let dir = tmp("restart");
    let d = test_daemon(&dir);
    let e = d
        .enqueue(
            NZB,
            "Restart.Release.nzb",
            "",
            -100,
            None,
            None,
            "test",
            false,
        )
        .expect("enqueue");
    payload::delete_arm(&d, &params(&[("name", "delete")]), "delete", &e.nzo_id);
    let held = d.cancel_undo_dir().join(format!("{}.nzb", e.nzo_id));
    assert!(held.exists(), "nothing was held");

    // What a start does, in the order a start does it.
    assert_eq!(
        d.recover_orphaned_spool(),
        0,
        "the recovery adopted a cancelled release out of the undo store"
    );
    assert!(
        d.queue.lock_ok().is_empty(),
        "the cancelled release came back"
    );
    assert!(
        !held.exists(),
        "the held copy outlived the restart that made it unreachable"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A held SPARE comes back a spare, not a download.
///
/// The worst undo this file could ship: the user presses ✕ on a paused
/// "alternative" row, changes their mind, and gets back a download
/// nobody asked for - running, because nothing holds it any more. The
/// row's own shape (`is_held_alternative` = paused at Duplicate
/// priority) travels with `paused` and `priority`, but what it is held
/// AGAINST does not, and that is `held_for`: without it the restored
/// spare never releases and never gets promoted, and `hold_for`'s own
/// refusal - a spare whose original has gone in the meantime - cannot
/// fire either.
#[test]
fn an_undone_spare_comes_back_held_against_the_job_it_was_held_against() {
    let dir = tmp("spare");
    let d = test_daemon(&dir);
    let first = d
        .enqueue(
            NZB,
            "Show.S01E01.1080p.WEB.nzb",
            "",
            -100,
            None,
            None,
            "test",
            false,
        )
        .expect("enqueue original");
    // The same release under a different NZB: the duplicate ladder holds
    // it behind the first as an alternative rather than queueing it.
    let other = String::from_utf8_lossy(NZB).replace("one@x", "two@x");
    let spare = d
        .enqueue(
            other.as_bytes(),
            "Show.S01E01.1080p.WEB.nzb",
            "",
            -100,
            None,
            None,
            "test",
            false,
        )
        .expect("enqueue spare");
    let (was_paused, was_prio, was_held) = {
        let q = d.queue.lock_ok();
        let g = q
            .iter()
            .map(|j| j.lock_ok())
            .find(|g| g.nzo_id == spare.nzo_id)
            .expect("the spare is in the queue");
        (g.paused, g.priority, g.held_for.clone())
    };
    // The fixture has to actually produce a held spare, or this test
    // passes over a plain second download and says nothing.
    assert!(
        was_paused && !was_held.is_empty(),
        "the fixture queued a second download rather than a held spare \
         (paused {was_paused}, held_for {was_held:?}) - fix the fixture"
    );
    assert_eq!(was_held, first.nzo_id, "held against the wrong job");

    let j = payload::delete_arm(&d, &params(&[("name", "delete")]), "delete", &spare.nzo_id);
    let token = j["undo"]["token"].as_str().expect("token").to_string();
    let back = payload::undelete_arm(&d, &token);
    assert_eq!(back["status"], serde_json::json!(true), "the undo: {back}");

    let q = d.queue.lock_ok();
    let g = q
        .iter()
        .map(|j| j.lock_ok())
        .find(|g| g.nzo_id == spare.nzo_id)
        .expect("the spare did not come back");
    assert_eq!(g.paused, was_paused, "the spare came back running");
    assert_eq!(
        g.priority, was_prio,
        "the spare came back at its own priority"
    );
    assert_eq!(
        g.held_for, was_held,
        "the spare came back holding against nothing, so nothing will \
         ever promote or release it"
    );

    drop(g);
    drop(q);
    let _ = std::fs::remove_dir_all(&dir);
}

/// THE PARTIAL DATA IS PART OF THE PROMISE, and putting the row back is
/// not enough to keep it.
///
/// The stop button's own copy says "the partial data stays on disk", and
/// it does - but an undo that gives the row back pointed at a DIFFERENT
/// folder has taken the resume away all the same, and the page looks
/// identical either way. `enqueue_as` is a fresh placement, so
/// `dir_claim_for_add` sees a directory holding files that no record
/// names, answers `Occupied` and climbs to `<stem>.2`; the restored job
/// then downloads from byte zero and the bytes it already had sit beside
/// it, orphaned. `Daemon::reuse_cancelled_dir` is what stops that, and
/// this is the test that watches it.
///
/// Three assertions, and the third is the one a lazier version would
/// leave out: the climbed directory must not be left behind either.
#[test]
fn an_undone_cancel_keeps_the_partial_data_it_promised_to_keep() {
    let dir = tmp("partialdata");
    let d = test_daemon(&dir);
    let e = d
        .enqueue(
            NZB,
            "Partial.Release.nzb",
            "",
            -100,
            None,
            None,
            "test",
            false,
        )
        .expect("enqueue");
    let out = {
        let q = d.queue.lock_ok();
        let g = q[0].lock_ok();
        g.out_dir.clone()
    };
    // What a download that has started looks like from here.
    std::fs::create_dir_all(&out).expect("mkdir");
    std::fs::write(out.join("part01.rar"), b"already fetched").expect("partial");

    let j = payload::delete_arm(&d, &params(&[("name", "delete")]), "delete", &e.nzo_id);
    let token = j["undo"]["token"].as_str().expect("token").to_string();
    let back = payload::undelete_arm(&d, &token);
    assert_eq!(back["status"], serde_json::json!(true), "the undo: {back}");

    let after = {
        let q = d.queue.lock_ok();
        let g = q[0].lock_ok();
        g.out_dir.clone()
    };
    assert_eq!(
        after, out,
        "the restored row points somewhere else, so it starts again from \
         zero and the bytes it already had are orphaned"
    );
    assert!(
        out.join("part01.rar").exists(),
        "the partial data the stop button promised to keep is gone"
    );
    let climbed = out.with_file_name("Partial.Release.2");
    assert!(
        !climbed.exists(),
        "the placement the add made was left behind at {}",
        climbed.display()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// ...and it goes back to that directory only if it is still FREE.
///
/// The guard that separates "reuse the folder my own cancelled job was
/// filling" from data loss. `DirClaim::Payload` is a COMPLETED result of
/// ours sitting at that path, and the only way a new download may ever
/// take that name is `replaces` - download elsewhere, verify, then
/// publish over it - so a restore that simply moved in would have the
/// first decoded article truncate a verified payload. The same holds for
/// `Active`, one job's directory being handed to another.
///
/// The window makes this reachable rather than theoretical: ten minutes
/// is long enough for a retry, an *arr re-grab or a second add to finish
/// into the very directory the cancelled row was using.
#[test]
fn an_undo_leaves_a_completed_payload_at_the_old_path_alone() {
    let dir = tmp("payloadguard");
    let d = test_daemon(&dir);
    let e = d
        .enqueue(
            NZB,
            "Contested.Release.nzb",
            "",
            -100,
            None,
            None,
            "test",
            false,
        )
        .expect("enqueue");
    let out = {
        let q = d.queue.lock_ok();
        let g = q[0].lock_ok();
        g.out_dir.clone()
    };
    std::fs::create_dir_all(&out).expect("mkdir");
    std::fs::write(out.join("part01.rar"), b"already fetched").expect("partial");

    let j = payload::delete_arm(&d, &params(&[("name", "delete")]), "delete", &e.nzo_id);
    let token = j["undo"]["token"].as_str().expect("token").to_string();

    // What the window makes room for: something else finished into that
    // very directory while the undo was still on offer.
    std::fs::write(out.join("payload.bin"), b"a verified result").expect("result");
    let winner = Arc::new(Mutex::new(
        crate::job_from_json(&serde_json::json!({
            "nzo_id": "SABnzbd_nzo_winner",
            "name": "Contested.Release",
            "nzb_path": dir.join("winner.nzb").to_string_lossy(),
            "out_dir": out.to_string_lossy(),
            "state": "Completed",
        }))
        .expect("history row"),
    ));
    d.history.lock_ok().push(winner);

    let back = payload::undelete_arm(&d, &token);
    assert_eq!(back["status"], serde_json::json!(true), "the undo: {back}");
    let after = {
        let q = d.queue.lock_ok();
        let g = q[0].lock_ok();
        g.out_dir.clone()
    };
    assert_ne!(
        after, out,
        "the restored row moved into a completed payload's directory - \
         its first decoded article truncates a verified result"
    );
    assert_eq!(
        std::fs::read(out.join("payload.bin")).expect("the completed result is gone"),
        b"a verified result",
        "the completed result was disturbed"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
