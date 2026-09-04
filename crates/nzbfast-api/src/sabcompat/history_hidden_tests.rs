//! NZBGet's `HistoryDelete` is a HIDE, not an erase - the half of the
//! pair `delete_durability_tests.rs` cannot ask about, because nothing
//! this verb does destroys anything.
//!
//! The two verbs shared one arm until 4 Sep 2026 (Codex triage finding
//! 8, first named by the Cursor read-only sweep's item 17). Sonarr's
//! `NzbgetProxy.RemoveItem` sends `HistoryDelete`, and its "Remove
//! completed downloads" option fires it after every import, so under
//! the shared arm every release an *arr imported left our history
//! outright - and with it the Completed row `dupe_collision` and
//! `owned_dupe_keys` read, so a re-grab of the identical release was
//! not held and the wall lost its "you have this" badge.
//!
//! What each test here pins is therefore a PAIR: the row is gone from
//! what the user is shown, and present for everything that answers "do
//! we already have this". Either half alone is the defect.

use super::*;

/// A history record on disk under `id`, with a spooled `.nzb` beside it
/// so the "hide keeps the spool" claim has something to look at.
fn seeded(d: &Arc<Daemon>, dir: &std::path::Path, id: &str, name: &str) -> Arc<Mutex<Job>> {
    let nzb = dir.join(format!("{name}.nzb"));
    std::fs::write(&nzb, b"<nzb/>").expect("spool copy");
    let job = Arc::new(Mutex::new(
        job_from_json(&json!({
            "nzo_id": format!("SABnzbd_nzo_{id}"), "name": name,
            "out_dir": crate::naming::out_dir(d).join(name).to_string_lossy(),
            "nzb_path": nzb.to_string_lossy(), "state": "Completed",
            "dupe_key": dupe_key(name),
        }))
        .expect("job"),
    ));
    d.history.lock_ok().push(job.clone());
    assert!(
        d.history_upsert(std::slice::from_ref(&job)),
        "the fixture's premise: the record is in the store"
    );
    job
}

/// A temp dir + daemon of this test's own, cleaned by the caller.
fn scratch(tag: &str) -> (std::path::PathBuf, Arc<Daemon>) {
    let dir = std::env::temp_dir().join(format!("nzbfast-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let d = crate::testutil::test_daemon(&dir);
    (dir, d)
}

/// The whole of `HistoryDelete`: the row leaves every listing and stays
/// in history, keeping its spool copy and its identity.
///
/// Four listings, because they are four different doors onto the same
/// store and an *arr, a phone client and the dashboard each use a
/// different one: NZBGet `history()` (the default, which is what Sonarr
/// and Radarr call), NZBGet `history(true)` (the hidden view, the only
/// thing that can still see the row), and the SAB history body the
/// dashboard renders. Three must omit it and one must show it.
#[test]
fn a_history_delete_hides_the_row_without_destroying_anything() {
    let (dir, d) = scratch("histhide");
    let job = seeded(&d, &dir, "7801", "Hidden.Release.S01E01.1080p.WEB-AAA");
    let nzb = job.lock_ok().nzb_path.clone();

    let mut rpc_error = None;
    let answer = jr_editqueue(
        &d,
        &[json!("HistoryDelete"), json!(0), json!([7801])],
        &mut rpc_error,
    );
    assert!(rpc_error.is_none(), "the hide was refused: {rpc_error:?}");
    assert_eq!(answer, json!(true));

    // The row is still there, and marked.
    assert_eq!(d.history.lock_ok().len(), 1, "a hide removes nothing");
    assert!(job.lock_ok().hidden, "the row is marked hidden");
    assert!(
        !job.lock_ok().tombstone,
        "hidden is not tombstoned - the record is alive, just unlisted"
    );
    assert!(
        nzb.exists(),
        "the spooled .nzb is what HistoryRedownload re-runs from, so a hide keeps it"
    );

    // ...and invisible to the three listings that are not asking for it.
    let plain = jr_history(&d, &[]);
    assert_eq!(
        plain.as_array().map(Vec::len),
        Some(0),
        "the default NZBGet listing must not show a hidden row: {plain}"
    );
    let with_hidden = jr_history(&d, &[json!(true)]);
    assert_eq!(
        with_hidden[0]["NZBID"],
        json!(7801),
        "history(true) is the one view that still lists it: {with_hidden}"
    );
    let sab = history_json(&d, &std::collections::HashMap::new());
    assert_eq!(
        sab["history"]["slots"].as_array().map(Vec::len),
        Some(0),
        "the SAB history body (and so the dashboard) must not show it: {sab}"
    );
    assert_eq!(
        sab["history"]["noofslots"],
        json!(0),
        "the count has to agree with the rows under it"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The identity half, which is the reason the flag exists at all: a
/// hidden Completed row still answers "you already have this".
///
/// `dupe_collision` is gated on the `indexer` feature in a non-test
/// build of the daemon crate, so the check itself is pinned from that
/// crate's own suite
/// (`daemon_tests::a_hidden_history_row_is_still_a_duplicate`). What
/// this test owns is the state that check reads: after the verb an
/// *arr actually sends, the Completed row and its `dupe_key` are still
/// in `d.history`. The pair is what makes the fix true - a hide that
/// dropped the row from the store would pass the listing test above and
/// leave the defect exactly where it was.
#[test]
fn a_hidden_row_keeps_the_completed_state_and_dupe_key_the_checks_read() {
    let (dir, d) = scratch("histhidedupe");
    let name = "Kept.Identity.S03E04.1080p.WEB-BBB";
    seeded(&d, &dir, "7802", name);

    let mut rpc_error = None;
    jr_editqueue(
        &d,
        &[json!("HistoryDelete"), json!(0), json!([7802])],
        &mut rpc_error,
    );
    assert!(rpc_error.is_none(), "the hide was refused: {rpc_error:?}");

    let h = d.history.lock_ok();
    let g = h.first().expect("the row survives the hide").lock_ok();
    assert!(g.hidden);
    assert_eq!(
        g.state,
        JobState::Completed,
        "the duplicate scan and owned_dupe_keys both test Completed"
    );
    assert_eq!(g.dupe_key, dupe_key(name), "the key they join on");
    // ...and a hide is NOT the user saying they no longer have it, so
    // it must not stamp the mark that releases the duplicate hold.
    drop(g);
    drop(h);
    assert_eq!(
        d.deleted_recently(name),
        None,
        "a hidden release is one we still have - only the erase says otherwise"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `HistoryFinalDelete` erases, and stamps the delete mark the REST
/// door has always stamped.
///
/// The mark is what tells the duplicate check "you deleted this
/// recently, so this re-add is the download you asked for". Only
/// `editqueue_delete.rs` and the REST payload arms called
/// `note_releases_deleted`, so a user whose client type was NZBGet got
/// their re-add held against the copy they had just thrown away.
#[test]
fn a_history_final_delete_erases_the_row_and_marks_the_release_deleted() {
    let (dir, d) = scratch("histfinalmark");
    let name = "Erased.Release.S01E02.1080p.WEB-CCC";
    seeded(&d, &dir, "7803", name);

    let mut rpc_error = None;
    let answer = jr_editqueue(
        &d,
        &[json!("HistoryFinalDelete"), json!(0), json!([7803])],
        &mut rpc_error,
    );
    assert!(rpc_error.is_none(), "the delete was refused: {rpc_error:?}");
    assert_eq!(answer, json!(true));
    assert!(d.history.lock_ok().is_empty(), "the erase removes the row");
    assert_eq!(
        d.deleted_recently(name),
        Some(name.to_string()),
        "the NZBGet door owes the same mark the REST door stamps"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A hide that did not survive a restart would put every release an
/// *arr has ever imported back in front of the user at the next start,
/// which is the same complaint from the other side.
///
/// The assertion is made against a second `Daemon` over the same spool -
/// bytes a stop really would have left, not a fixture written to match
/// a belief about them - exactly as `delete_durability_tests::restart`
/// does it for the erase.
#[test]
fn a_hidden_row_comes_back_from_the_store_still_hidden() {
    let (dir, d) = scratch("histhidereplay");
    seeded(&d, &dir, "7804", "Replayed.Release.S02E02.1080p.WEB-DDD");
    // A visible sibling, so this cannot pass against a replay that
    // simply loses everything or hides everything.
    seeded(&d, &dir, "7805", "Visible.Release.S02E03.1080p.WEB-EEE");

    let mut rpc_error = None;
    jr_editqueue(
        &d,
        &[json!("HistoryDelete"), json!(0), json!([7804])],
        &mut rpc_error,
    );
    assert!(rpc_error.is_none(), "the hide was refused: {rpc_error:?}");

    let d2 = crate::testutil::test_daemon(&dir);
    d2.load_queue();
    let flags: Vec<(String, bool)> = d2
        .history
        .lock_ok()
        .iter()
        .map(|j| {
            let g = j.lock_ok();
            (g.nzo_id.clone(), g.hidden)
        })
        .collect();
    assert_eq!(
        flags,
        vec![
            ("SABnzbd_nzo_7804".to_string(), true),
            ("SABnzbd_nzo_7805".to_string(), false),
        ],
        "the hide is durable and speaks for one row only"
    );
    let plain = jr_history(&d2, &[]);
    assert_eq!(
        plain.as_array().map(Vec::len),
        Some(1),
        "and the restarted daemon renders the same listing: {plain}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
