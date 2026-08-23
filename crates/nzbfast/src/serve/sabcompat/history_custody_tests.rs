//! Custody of a deleted history record's spooled `.nzb` on the JSON-RPC
//! facade: what the delete leaves on disk when the unlink is REFUSED.
//!
//! A sibling file rather than `delete_durability_tests.rs`'s, which is
//! about the queue-to-history handover, and rather than
//! `sabcompat.rs`'s, which sits on the size gate's 3,000-line ceiling
//! (TODO 106). Same module either way.
//!
//! THIS WHOLE FILE IS UNIX-ONLY, and nothing in it shows that: the
//! `#[cfg(all(test, unix))]` that decides it sits on the `mod`
//! declaration in `sabcompat.rs`. It is there because the one test
//! below forces the unlink refusal with a read-only spool DIRECTORY,
//! which Windows mode bits do not express, and because leaving the
//! file ungated put `use super::*` and `NZB` on the dead-code list the
//! moment a Windows target compiled them - two of the four `-D
//! warnings` errors that held windows-clippy and windows-arm64 red on
//! main on 23 Aug 2026 (fixed in 804be72b9). Gating the declaration
//! rather than the items follows `smart/out_umask_tests.rs` and
//! `serve/job_finalize_marker_tests.rs`, the tree's other two, and
//! keeps `tools/win-portability-gate.py` able to see the exemption -
//! reading the parent file's `mod` line is one of the four things that
//! gate counts as enclosing.
//!
//! So BEFORE adding a test here that could run on Windows: widen the
//! declaration, or put it in a file that is not gated. A
//! Windows-capable test added to this file is not compiled on Windows
//! at all, so it does not reach even nextest's skipped count, and no
//! row in any windows-unit shard says it did not run. It passes on
//! this box and is simply absent there.

use super::*;

const NZB: &[u8] = br#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb"><file poster="x" date="0" subject="&quot;a.bin&quot; yEnc (1/1)"><groups><group>g</group></groups><segments><segment bytes="1000" number="1">one@x</segment></segments></file></nzb>"#;

/// `HistoryDelete` whose spool unlink is REFUSED must not have the
/// release re-adopted at the next start.
///
/// The history row is dropped right here and the tombstone written, so
/// a surviving copy under the adoptable name is a file no record names:
/// `recover_orphaned_spool` reads it as a job whose record never
/// reached disk and downloads the release the user just deleted for
/// good. This facade swallowed the `remove_file` outright, so the whole
/// fault was invisible - the REST history delete has gone through
/// `hold_or_drop_spool` (and so `drop_spool`) since Codex F-05, and
/// which client type the user configured decided whether the bug was
/// reachable, exactly as it did for the active-job delete before it.
///
/// A read-only spool DIRECTORY refuses the rename as well as the
/// unlink, which is why the assertion here is on `drop_spool`'s third
/// resort - an emptied file, which recovery skips.
#[cfg(unix)]
#[test]
fn a_history_delete_whose_spool_unlink_is_refused_is_not_re_adopted() {
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join(format!("nzbfast-histcust-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let d = crate::serve::testutil::test_daemon(&dir);

    let nzb = d
        .spool
        .join("SABnzbd_nzo_nzbfast7311-Cancelled.Release.nzb");
    std::fs::write(&nzb, NZB).expect("spool copy");
    // A control of the same shape under an unknown id, so this cannot
    // pass against a matcher that adopts nothing at all. Distinct bytes,
    // so it is adopted on its own account rather than removed as a spare
    // copy of something the queue already holds.
    let control = d.spool.join("SABnzbd_nzo_nzbfast7312-Other.Release.nzb");
    let other = String::from_utf8_lossy(NZB).replace("one@x", "two@x");
    std::fs::write(&control, other).expect("control copy");

    let job = Arc::new(Mutex::new(
        job_from_json(&json!({
            "nzo_id": "SABnzbd_nzo_nzbfast7311", "name": "Cancelled.Release",
            "out_dir": d.out_dir().join("Cancelled.Release").to_string_lossy(),
            "nzb_path": nzb.to_string_lossy(), "state": "Completed",
        }))
        .expect("job"),
    ));
    d.history.lock_ok().push(job);

    let was = std::fs::metadata(&d.spool)
        .expect("spool")
        .permissions()
        .mode();
    std::fs::set_permissions(&d.spool, std::fs::Permissions::from_mode(0o555)).expect("chmod");
    let mut rpc_error = None;
    let answer = jr_editqueue(
        &d,
        &[json!("HistoryDelete"), json!(0), json!([7311])],
        &mut rpc_error,
    );
    std::fs::set_permissions(&d.spool, std::fs::Permissions::from_mode(was)).expect("chmod back");

    assert!(rpc_error.is_none(), "the delete was refused: {rpc_error:?}");
    assert_eq!(answer, json!(true), "the history row was not deleted");
    assert!(
        d.history.lock_ok().is_empty(),
        "the record is gone for good - that is what makes the survivor an orphan"
    );
    assert!(
        nzb.exists(),
        "the fault under test is an unlink that was refused"
    );
    assert_eq!(
        std::fs::metadata(&nzb).expect("spool copy").len(),
        0,
        "the refused unlink was swallowed: the adoptable copy still holds its articles"
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
        !back.contains(&"SABnzbd_nzo_nzbfast7311".to_string()),
        "the deleted release came back: {back:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
