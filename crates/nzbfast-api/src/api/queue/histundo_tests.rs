//! GH #86: the history grace window, end to end through the two arms
//! that make it up.
//!
//! A sibling file rather than an inline `mod`, like `cancelundo_tests`
//! beside it and for the same reason (TODO 106 size gate).
//!
//! These drive `hist_delete_arm` and `hist_undelete_arm` rather than the
//! daemon helpers, for the reason `cancelundo_tests` states: what is
//! under test is not "the store holds bytes", it is "the thing the page
//! presses gives the user their download back". `hist_delete_arm` came
//! out of `m_history` so that this file could exist - the handler takes
//! a `&mut tiny_http::Request` and nothing in a unit test can hand it
//! one.
//!
//! EVERY assertion here was negative-controlled by mutating the code
//! under it and watching it fail, not by reading it.

use super::*;
use crate::testutil::test_daemon;
use payload::{hist_delete_arm, hist_undelete_arm};

const NZB: &[u8] = br#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb"><file poster="x" date="0" subject="&quot;a.bin&quot; yEnc (1/1)"><groups><group>g</group></groups><segments><segment bytes="1000" number="1">one@x</segment></segments></file></nzb>"#;

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("nzbfast-hundo-{tag}-{}", std::process::id()));
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

/// File one finished record into history, with a real spool copy beside
/// it and a real payload in its own folder.
///
/// The spool copy is what a Retry reads, so it is NZB bytes rather than
/// a marker: a fixture whose `nzb_path` names a file of `b"x"` would
/// pass the "a file is there" half of every test below while proving
/// nothing about the half that matters.
fn filed(d: &Arc<Daemon>, id: &str, name: &str) -> Arc<Mutex<Job>> {
    let out = crate::naming::out_dir(d).join(name);
    std::fs::create_dir_all(&out).expect("out dir");
    std::fs::write(out.join("a.bin"), b"payload").expect("payload");
    let nzb = d.spool.join(format!("SABnzbd_nzo_nzbfast_{id}.nzb"));
    std::fs::create_dir_all(&d.spool).expect("spool");
    std::fs::write(&nzb, NZB).expect("spool copy");
    let job = Arc::new(Mutex::new(
        job_from_json(&serde_json::json!({
            "nzo_id": id, "name": name,
            "out_dir": out.to_string_lossy(),
            "nzb_path": nzb.to_string_lossy(),
            "state": "Completed",
        }))
        .expect("job"),
    ));
    d.history.lock_ok().push(job.clone());
    job
}

fn ids(d: &Arc<Daemon>) -> Vec<String> {
    d.history
        .lock_ok()
        .iter()
        .map(|j| j.lock_ok().nzo_id.clone())
        .collect()
}

/// THE WHOLE POINT, in one test: an undone history delete gives back an
/// entry that can still be RETRIED.
///
/// Not a membership check, and that distinction is the reason this file
/// exists. "The row is back" is true whether or not the spooled `.nzb`
/// came back with it, and a history row without one is exactly the
/// silent downgrade audit section 5 refused to ship: the entry looks
/// identical, its Retry button is there, and pressing it can only fail.
/// So the assertion is on the BYTES - the restored record names a file,
/// and that file parses as the NZB the job was created from.
#[test]
fn an_undone_history_delete_comes_back_retryable() {
    let dir = tmp("roundtrip");
    let d = test_daemon(&dir);
    let job = filed(&d, "SABnzbd_nzo_h1", "Undone.Release");
    let nzb_path = job.lock_ok().nzb_path.clone();

    let j = hist_delete_arm(&d, &params(&[("name", "delete")]), "SABnzbd_nzo_h1");
    assert_eq!(j["status"], serde_json::json!(true), "the delete: {j}");
    assert!(d.history.lock_ok().is_empty(), "the row did not leave");
    assert!(
        !nzb_path.exists(),
        "the delete kept the spool copy, so this test can no longer see the fix"
    );
    let token = j["undo"]["token"]
        .as_str()
        .unwrap_or_else(|| panic!("no undo token on a files-kept history delete: {j}"))
        .to_string();
    assert_eq!(j["undo"]["rows"], serde_json::json!(1));

    let back = hist_undelete_arm(&d, &token);
    assert_eq!(back["status"], serde_json::json!(true), "the undo: {back}");
    assert_eq!(
        back["failed"],
        serde_json::json!([]),
        "a partial restore must say so: {back}"
    );

    assert_eq!(ids(&d), ["SABnzbd_nzo_h1"], "one delete, one undo, one row");
    let g = job.lock_ok();
    assert!(
        !g.tombstone,
        "the record came back still tombstoned, so the mover and the park \
         tail both stand down on a live row"
    );
    // The half a membership check cannot see.
    let bytes = std::fs::read(&g.nzb_path).expect("the restored entry names no spool copy");
    assert!(
        nzbkit::nzb::Nzb::parse(&bytes).is_ok(),
        "the restored entry's spool copy is not an NZB - Retry can only fail"
    );
    drop(g);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A restored row goes back WHERE IT WAS, not on the end.
///
/// `history_restore` was written for the refused-tombstone rollback and
/// puts rows back at their exact indices; taking that route rather than
/// a re-add is most of why this half is shorter than the queue's. An
/// undo that reorders the list is not wrong in the way a missing NZB is,
/// but it is an undo the user can see is not an undo.
#[test]
fn an_undone_delete_goes_back_where_it_was() {
    let dir = tmp("position");
    let d = test_daemon(&dir);
    filed(&d, "SABnzbd_nzo_ha", "A.Release");
    filed(&d, "SABnzbd_nzo_hb", "B.Release");
    filed(&d, "SABnzbd_nzo_hc", "C.Release");

    let j = hist_delete_arm(&d, &params(&[("name", "delete")]), "SABnzbd_nzo_hb");
    let token = j["undo"]["token"].as_str().expect("token").to_string();
    assert_eq!(ids(&d), ["SABnzbd_nzo_ha", "SABnzbd_nzo_hc"]);

    assert_eq!(
        hist_undelete_arm(&d, &token)["status"],
        serde_json::json!(true)
    );
    assert_eq!(
        ids(&d),
        ["SABnzbd_nzo_ha", "SABnzbd_nzo_hb", "SABnzbd_nzo_hc"],
        "the restored entry landed somewhere else in the list"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// THE TOMBSTONE IS DURABLE, so the undo has to answer it durably.
///
/// The delete appends `{"deleted": true}` before it destroys anything
/// (P2-1), and replay drops a row on that line. An undo that only put
/// the record back in MEMORY would give the user their entry back and
/// then lose it again at the next restart, with nothing said - the same
/// class of quiet half-success as a row restored without its NZB. So
/// this restarts the daemon off the bytes on disk and reads the answer
/// there.
#[test]
fn an_undone_delete_survives_a_restart() {
    let dir = tmp("durable");
    let d = test_daemon(&dir);
    filed(&d, "SABnzbd_nzo_hd", "Durable.Release");

    let j = hist_delete_arm(&d, &params(&[("name", "delete")]), "SABnzbd_nzo_hd");
    let token = j["undo"]["token"].as_str().expect("token").to_string();
    assert_eq!(
        hist_undelete_arm(&d, &token)["status"],
        serde_json::json!(true)
    );

    let (rows, _) = d.history_replay();
    let replayed: Vec<String> = rows.iter().map(|j| j.nzo_id.clone()).collect();
    assert_eq!(
        replayed,
        ["SABnzbd_nzo_hd"],
        "the restored entry is not in the store, so a restart deletes it again"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A DELETE MARK IS THE USER SAYING THEY NO LONGER HOLD THE RELEASE, and
/// an undo is them taking it back.
///
/// `note_releases_deleted` stamps every removed name, and the duplicate
/// check reads it for a day: left alone after a restore, the user holds
/// the release in their list and a re-add of the same release is waved
/// through as "you deleted this". The queue half spends the mark through
/// `enqueue_as`'s `DupeExempt::Anybody`; there is no add here, so the
/// spend is explicit and this is what pins it.
#[test]
fn an_undone_delete_takes_back_the_delete_mark() {
    let dir = tmp("dupemark");
    let d = test_daemon(&dir);
    filed(&d, "SABnzbd_nzo_he", "Marked.Release");

    let j = hist_delete_arm(&d, &params(&[("name", "delete")]), "SABnzbd_nzo_he");
    let token = j["undo"]["token"].as_str().expect("token").to_string();
    assert!(
        d.deleted_recently("Marked.Release").is_some(),
        "the delete did not mark the release, so this test proves nothing"
    );

    assert_eq!(
        hist_undelete_arm(&d, &token)["status"],
        serde_json::json!(true)
    );
    assert!(
        d.deleted_recently("Marked.Release").is_none(),
        "the release is back in the list and still marked as deleted - the next \
         add of it skips the duplicate hold"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A ROW WITH EARLY COPIES TAKES ITS BATCH'S UNDO WITH IT, and this is
/// the judgement the whole file rests on.
///
/// `early_take` runs on a plain delete too and `early_unlink` removes
/// what it returns, so those destination copies are gone and nothing can
/// name them again. Offering an undo over that would hand back a record
/// pointing at files that are not there; holding the files back instead
/// would strand them at the destination on any unclean stop inside the
/// window, with the tombstone already durable. So the row is refused,
/// and ALL OR NOTHING takes the clean row's token with it - a user who
/// presses Undo on a two-row sweep must not get one row back.
#[test]
fn a_row_with_early_copies_refuses_the_whole_batch() {
    let dir = tmp("early");
    let d = test_daemon(&dir);
    let clean = filed(&d, "SABnzbd_nzo_hf", "Clean.Release");
    let early = filed(&d, "SABnzbd_nzo_hg", "Early.Release");
    let nas = dir.join("nas").join("Early.Release");
    std::fs::create_dir_all(&nas).expect("dest dir");
    std::fs::write(nas.join("a.bin"), b"payload").expect("early copy");
    early.lock_ok().early_published = vec![nzbfast_daemon::earlyfile::EarlyFile {
        name: "a.bin".into(),
        len: 7,
        mtime_ns: 0,
        nzf_id: String::new(),
        dest: Some(nas.clone()),
    }];

    let j = hist_delete_arm(&d, &params(&[("name", "delete")]), "all");
    assert_eq!(j["removed"], serde_json::json!(2), "both rows left: {j}");
    assert!(
        j.get("undo").is_none(),
        "an undo was offered over destination copies it cannot give back: {j}"
    );
    assert!(
        !nas.join("a.bin").exists(),
        "the early copy stayed at the destination, which is the orphan the \
         delete arm exists to prevent"
    );
    assert_eq!(
        std::fs::read_dir(d.cancel_undo_dir())
            .map(|r| r.flatten().count())
            .unwrap_or(0),
        0,
        "the refused batch left the clean row's copy behind"
    );
    let _ = clean;

    let _ = std::fs::remove_dir_all(&dir);
}

/// The files half gets NO token, and the two doors that ask for it keep
/// their dialogs saying so.
///
/// Same rule and same reason as the queue's: with `del_files=1` the
/// removal can be REFUSED (a Trash that would not take it) and the user
/// is left holding a folder and a kept-files notice, so "it is as it
/// was" is not something this request can promise when it answers.
#[test]
fn a_history_delete_that_asked_for_the_files_offers_no_undo() {
    let dir = tmp("delfiles");
    let d = test_daemon(&dir);
    let job = filed(&d, "SABnzbd_nzo_hh", "Files.Release");
    let out = job.lock_ok().out_dir.clone();

    let j = hist_delete_arm(
        &d,
        &params(&[("name", "delete"), ("del_files", "1")]),
        "SABnzbd_nzo_hh",
    );
    assert_eq!(j["status"], serde_json::json!(true), "the delete: {j}");
    assert!(
        j.get("undo").is_none(),
        "an undo was offered over a removal that had not settled: {j}"
    );
    assert!(
        !out.exists(),
        "the files half did not run: {}",
        out.display()
    );
    assert_eq!(
        std::fs::read_dir(d.cancel_undo_dir())
            .map(|r| r.flatten().count())
            .unwrap_or(0),
        0,
        "the files arm held a copy nothing can ever spend"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// An EMPTIED held copy refuses instead of restoring an entry whose
/// Retry can only fail.
///
/// `drop_spool`'s third resort truncates the spool file when it can
/// neither unlink nor rename it (a Windows sharing violation, a `uchg`
/// flag, a read-only spool), and that truncation goes through the inode
/// the retained hard link shares - so this is the one fault where the
/// held path is still there and the bytes are not.
#[test]
fn an_emptied_held_copy_refuses_instead_of_restoring() {
    let dir = tmp("emptied");
    let d = test_daemon(&dir);
    filed(&d, "SABnzbd_nzo_hi", "Emptied.Release");

    let j = hist_delete_arm(&d, &params(&[("name", "delete")]), "SABnzbd_nzo_hi");
    let token = j["undo"]["token"].as_str().expect("token").to_string();
    let held = d.cancel_undo_dir().join("hist-SABnzbd_nzo_hi.nzb");
    assert!(held.exists(), "nothing was held: {}", held.display());
    std::fs::write(&held, b"").expect("empty the held copy");

    let back = hist_undelete_arm(&d, &token);
    assert_eq!(
        back["status"],
        serde_json::json!(false),
        "an empty copy was restored as an entry: {back}"
    );
    assert!(
        d.history.lock_ok().is_empty(),
        "an entry whose Retry can only fail was put back in the list"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// ALL OR NOTHING. A batch that can only put some of its rows back gets
/// no token at all, and the copies it did hold are released.
///
/// The window is forced by taking the second row's spool copy away
/// before the delete runs, which is what a spool on a volume that has
/// just gone offline looks like.
#[test]
fn a_history_batch_that_cannot_hold_every_row_offers_no_undo() {
    let dir = tmp("partial");
    let d = test_daemon(&dir);
    filed(&d, "SABnzbd_nzo_hj", "First.Release");
    let second = filed(&d, "SABnzbd_nzo_hk", "Second.Release");
    std::fs::remove_file(&second.lock_ok().nzb_path).expect("take the second copy away");

    let j = hist_delete_arm(&d, &params(&[("name", "delete")]), "all");
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

    let _ = std::fs::remove_dir_all(&dir);
}

/// A token is spent ONCE, and a QUEUE token is not a history token.
///
/// The toast is a `role="button"` with a keyboard path as well as a
/// click, so a second press is ordinary rather than exotic - and the two
/// stores now answer the same verb name on two modes, so a token handed
/// to the wrong one has to MISS rather than half-match. The `hundo`
/// prefix is what makes that structural.
#[test]
fn a_history_token_is_spent_once_and_is_not_a_queue_token() {
    let dir = tmp("twice");
    let d = test_daemon(&dir);
    filed(&d, "SABnzbd_nzo_hl", "Twice.Release");

    let j = hist_delete_arm(&d, &params(&[("name", "delete")]), "SABnzbd_nzo_hl");
    let token = j["undo"]["token"].as_str().expect("token").to_string();
    assert!(
        token.starts_with("hundo"),
        "a history token that cannot be told from a queue one: {token}"
    );
    assert_eq!(
        hist_undelete_arm(&d, &token)["status"],
        serde_json::json!(true)
    );
    let again = hist_undelete_arm(&d, &token);
    assert_eq!(
        again["status"],
        serde_json::json!(false),
        "a second press restored the entry twice: {again}"
    );
    assert_eq!(ids(&d).len(), 1, "the list grew on the second press");
    // And the other door refuses it outright rather than reaching into
    // the wrong store.
    assert_eq!(
        payload::undelete_arm(&d, &token)["status"],
        serde_json::json!(false),
        "the queue's undelete answered a history token"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// An id that came BACK on its own is not overwritten.
///
/// Ten minutes is long enough for the same nzo_id to be live again: a
/// retry moves the record into the queue keeping its id, and
/// `recover_orphaned_spool` re-adopts one at a start. Restoring on top
/// of that would put two records with one id in front of every caller
/// that resolves by id, which is worse than refusing.
#[test]
fn an_undo_refuses_an_id_that_is_live_again() {
    let dir = tmp("twin");
    let d = test_daemon(&dir);
    filed(&d, "SABnzbd_nzo_hm", "Twin.Release");

    let j = hist_delete_arm(&d, &params(&[("name", "delete")]), "SABnzbd_nzo_hm");
    let token = j["undo"]["token"].as_str().expect("token").to_string();
    // The same id, live in the other list.
    d.enqueue_as(
        Some("SABnzbd_nzo_hm"),
        NZB,
        "Twin.Release",
        "",
        -100,
        None,
        None,
        "test",
        DupeExempt::Anybody,
        None,
    )
    .expect("re-add under the old id");

    let back = hist_undelete_arm(&d, &token);
    assert_eq!(
        back["status"],
        serde_json::json!(false),
        "a second record with a live id was put in the list: {back}"
    );
    assert!(
        d.history.lock_ok().is_empty(),
        "the list holds a twin of a queued job"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The store does not survive a restart, and does not tempt the
/// recovery scan on the way past.
///
/// Both halves share one directory and one purge for that reason: a
/// retained copy left under the adoptable `SABnzbd_nzo_nzbfast*.nzb`
/// shape in the spool ROOT is the "the deleted release downloaded again
/// at the next start" defect this repo has already paid for twice.
#[test]
fn the_history_undo_store_does_not_survive_a_restart() {
    let dir = tmp("restart");
    let d = test_daemon(&dir);
    filed(&d, "SABnzbd_nzo_hn", "Restart.Release");

    let j = hist_delete_arm(&d, &params(&[("name", "delete")]), "SABnzbd_nzo_hn");
    assert!(j["undo"]["token"].is_string(), "no token: {j}");
    let held = d.cancel_undo_dir().join("hist-SABnzbd_nzo_hn.nzb");
    assert!(held.exists(), "nothing was held");

    // What a start does, in the order a start does it. A second
    // `Daemon` is not the door here: `purge_cancel_undo` hangs off
    // `recover_orphaned_spool`, which is the pass that walks the spool,
    // and it is that pass - not the `load_queue` around it - whose
    // walking past the store is the property under test.
    assert_eq!(
        d.recover_orphaned_spool(),
        0,
        "the recovery adopted a deleted release out of the undo store"
    );
    assert!(
        d.queue.lock_ok().is_empty(),
        "the deleted release came back as a download"
    );
    assert!(
        !held.exists(),
        "the retained copy outlived the restart that made it unreachable: {}",
        held.display()
    );

    let _ = std::fs::remove_dir_all(&dir);
}
