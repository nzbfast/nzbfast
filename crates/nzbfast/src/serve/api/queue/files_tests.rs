//! TODO 274 (e): which of the three answers `mode=get_files` gives, and
//! when.
//!
//! `listing` has three sources and they are not interchangeable: the
//! ACTIVE run's live table, the frozen table of a run whose TAIL is
//! still going, and - for a job that has not started - a parse of its
//! spooled `.nzb`, which carries names and sizes and no state at all.
//! Picking the third for a job in its tail is the defect this arm was
//! added for: measured on the live daemon 24 Aug 2026, every one of 264
//! polls across a 4.5-minute Repairing tail answered "queued, 0 of
//! 63 MB" for all 88 files of a post that had downloaded every byte,
//! because the next job's start had dropped the table.
//!
//! A sibling file rather than an inline `mod`, per this directory's
//! convention (see `caps_tests.rs`).

use super::*;
use crate::serve::testutil::test_daemon;

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("nzbfast-getfiles-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("temp dir");
    d
}

/// Two files, one payload and one recovery volume the plan never
/// queued, with the payload three articles short - the shape that makes
/// the state words say something a block count cannot.
fn frozen_table() -> crate::streamhub::TailTable {
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    let slot = std::sync::Arc::new(crate::unpack::FileSlot {
        hint: "pack.part01.rar".into(),
        hint_is_posted_name: nzbkit::release::stem_is_a_name("pack.part01.rar"),
        name_choice: std::sync::atomic::AtomicU8::new(crate::unpack::NAME_UNDECIDED),
        is_par2_main: false,
        sample_skipped: false,
        par2_sniffed: AtomicBool::new(false),
        total_segments: 10,
        remaining: AtomicUsize::new(0),
        missing: AtomicUsize::new(3),
        errors: AtomicUsize::new(0),
        deferred: AtomicUsize::new(0),
        abandoned: AtomicUsize::new(0),
        capture: std::sync::Mutex::new(None),
    });
    let rows = vec![
        crate::streamhub::JobFileRow {
            id: "aaaaaaaaaaaaaaaa".into(),
            name: "pack.part01.rar".into(),
            bytes: 1_000_000,
            segments: 10,
            slot: Some(0),
        },
        crate::streamhub::JobFileRow {
            id: "bbbbbbbbbbbbbbbb".into(),
            name: "pack.vol000+01.par2".into(),
            bytes: 40_000,
            segments: 2,
            slot: None,
        },
    ];
    crate::streamhub::TailTable::settled(std::sync::Arc::new(crate::streamhub::freeze_rows(
        &rows,
        &[slot],
    )))
}

/// A queue row for `id`, pointing its `nzb_path` at a file that does not
/// exist - so the spooled-`.nzb` arm, if it is reached, answers with an
/// empty listing and the test can tell the two apart without asserting
/// on a fixture NZB.
fn queue_row(d: &std::sync::Arc<crate::serve::Daemon>, id: &str) {
    let v = json!({
        "nzo_id": id, "name": id, "nzb_path": "/nonexistent/spool.nzb",
        "out_dir": "/tmp/out", "state": "Downloading", "priority": 0,
    });
    let job = crate::serve::job_from_json(&v).expect("job_from_json");
    d.queue
        .lock_ok()
        .push_back(std::sync::Arc::new(Mutex::new(job)));
}

/// The tail arm: a job past its network phase is answered from the table
/// its run left behind, with the run's own words.
///
/// The two rows are the whole point of the drawer this feeds. "damaged"
/// is articles that never arrived, and it is a different fact from the
/// verify line's block count - a user watching Repairing is asking which
/// FILE is short. The volume with no slot stays in the listing and stays
/// marked as recovery, because a listing that drops the repair set does
/// not describe the post.
#[test]
fn a_job_in_its_tail_is_listed_from_the_table_its_run_left_behind() {
    let dir = tmp("tail");
    let d = test_daemon(&dir);
    queue_row(&d, "nzo_tail");
    crate::streamhub::keep_tail_table(
        &mut d.hub.tail_files.lock_ok(),
        "nzo_tail".into(),
        frozen_table(),
    );
    // The same word the queue payload's status comes from, so the
    // listing and the row it is drawn under cannot disagree.
    d.hub
        .activity
        .lock_ok()
        .insert("nzo_tail".into(), "repairing");

    let rows = listing(&d, "nzo_tail").expect("a queued job answers");
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[0]["filename"], "pack.part01.rar");
    assert_eq!(rows[0]["state"], "damaged", "{rows:?}");
    assert_eq!(rows[0]["segments_missing"], 3, "{rows:?}");
    assert_eq!(rows[0]["bytes_left"], 0, "nothing is still owed: {rows:?}");
    assert_eq!(rows[0]["status"], "finished", "SAB's word for it: {rows:?}");
    assert_eq!(rows[1]["state"], "recovery", "{rows:?}");
    assert_eq!(rows[1]["recovery"], true, "{rows:?}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// ...and ONLY in its tail. A retry re-queues the same nzo_id, and the
/// entry outlives its job by design (it is bounded by a cap, not by a
/// park hook), so a listing keyed on the id alone would report the
/// previous run's damage against a job that has not started.
///
/// Same daemon, same table, the phase word taken away: the answer must
/// fall through to the spooled `.nzb`, which here is missing - an empty
/// listing rather than the frozen rows.
#[test]
fn a_job_that_is_not_in_its_tail_is_never_answered_from_a_retired_table() {
    let dir = tmp("notail");
    let d = test_daemon(&dir);
    queue_row(&d, "nzo_retry");
    crate::streamhub::keep_tail_table(
        &mut d.hub.tail_files.lock_ok(),
        "nzo_retry".into(),
        frozen_table(),
    );
    assert!(
        d.tail_phase("nzo_retry").is_none(),
        "the fixture must not have a phase word for this arm to mean anything"
    );

    let rows = listing(&d, "nzo_retry").expect("the queue row still answers");
    assert!(
        rows.is_empty(),
        "a job with no tail phase must not wear its previous run's rows: {rows:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A file row for `live_row`, with no articles arrived and the given
/// deferred/abandoned split - the two counters the "deferred" arm reads.
fn row_with(
    deferred: usize,
    abandoned: usize,
) -> (
    crate::streamhub::JobFileRow,
    crate::streamhub::FileSlotCounts,
) {
    let r = crate::streamhub::JobFileRow {
        id: "cccccccccccccccc".into(),
        name: "pack.part02.rar".into(),
        bytes: 500_000,
        segments: 5,
        slot: Some(0),
    };
    let c = crate::streamhub::FileSlotCounts {
        // arrived = total - remaining - missing - deferred - abandoned,
        // so this must equal deferred + abandoned for arrived == 0 - the
        // shape the "deferred" arm is gated on.
        total_segments: deferred + abandoned,
        remaining: 0,
        missing: 0,
        deferred,
        abandoned,
        errors: 0,
        is_par2: false,
        sample_skipped: false,
    };
    (r, c)
}

/// `abandoned` is damage - the settle read-back counts those blocks bad
/// and repair heals them (`unpack.rs`'s `FileSlot::abandoned` doc) - so a
/// file whose segments were ALL abandoned must read "damaged" exactly
/// like one whose segments never arrived at all, never "deferred".
#[test]
fn all_abandoned_segments_read_damaged_not_deferred() {
    let (r, c) = row_with(0, 3);
    let row = live_row(&r, Some(&c), &Default::default());
    assert_eq!(row["state"], "damaged", "{row:?}");
}

/// The pure-deferral shape - a skipped sample, a recognised recovery
/// volume - stays "deferred": a choice, not damage.
#[test]
fn all_deferred_segments_read_deferred() {
    let (r, c) = row_with(3, 0);
    let row = live_row(&r, Some(&c), &Default::default());
    assert_eq!(row["state"], "deferred", "{row:?}");
}

/// A phase word for an id with no queue row answers nobody.
///
/// `activity` is keyed by nzo_id and cleared at park, but a retired
/// table is not, so the queue row is what keeps a departed job from
/// being listed out of the residue. `None` here is what the caller
/// turns into "unknown nzo_id".
#[test]
fn a_retired_table_alone_is_not_a_job() {
    let dir = tmp("gone");
    let d = test_daemon(&dir);
    crate::streamhub::keep_tail_table(
        &mut d.hub.tail_files.lock_ok(),
        "nzo_gone".into(),
        frozen_table(),
    );
    d.hub
        .activity
        .lock_ok()
        .insert("nzo_gone".into(), "repairing");

    assert!(listing(&d, "nzo_gone").is_none());

    let _ = std::fs::remove_dir_all(&dir);
}

/// §296: a file already at the destination says so, and the join is by
/// §274's opaque HANDLE rather than by filename.
///
/// The name join is the one that looks obviously right and is wrong: a
/// row's `filename` is the poster's subject hint while the early-publish
/// record carries the ON-DISK name, and on an obfuscated post those are
/// different strings - so a name-keyed overlay would go quiet for
/// exactly the posts whose drawer is worth opening. The fixture makes
/// them differ on purpose.
#[test]
fn a_published_file_says_so_and_is_joined_by_handle_not_by_name() {
    let mut r = crate::streamhub::JobFileRow {
        id: "dddddddddddddddd".into(),
        // The SUBJECT hint, deliberately unlike the on-disk name an
        // obfuscated post writes.
        name: "Show.S01E01.1080p-GRP.mkv".into(),
        bytes: 500_000,
        segments: 5,
        slot: Some(0),
    };
    let c = crate::streamhub::FileSlotCounts {
        total_segments: 5,
        remaining: 0,
        missing: 0,
        deferred: 0,
        abandoned: 0,
        errors: 0,
        is_par2: false,
        sample_skipped: false,
    };
    // Nothing published: the ordinary word.
    assert_eq!(
        live_row(&r, Some(&c), &Default::default())["state"],
        "complete"
    );
    let pub_set: std::collections::HashSet<String> =
        ["dddddddddddddddd".to_string()].into_iter().collect();
    let row = live_row(&r, Some(&c), &pub_set);
    assert_eq!(row["state"], "published", "{row:?}");
    // SAB's own word is untouched: a client switching on `status` must
    // never meet a token SAB cannot produce.
    assert_eq!(row["status"], "finished", "{row:?}");
    // A different handle is a different file, however alike the names.
    r.id = "eeeeeeeeeeeeeeee".into();
    assert_eq!(live_row(&r, Some(&c), &pub_set)["state"], "complete");
}

/// The overlay refines "complete" and nothing else.
///
/// A published file was PAR2-vouched before the copy was taken, so it
/// cannot honestly read as damaged - but the RECORD outlives the
/// verdict: settle can find at read-back what the in-stream check did
/// not, and between that moment and the reconcile the row is both
/// published and damaged. Damage is the sharper fact and keeps the row.
#[test]
fn damage_outranks_a_stale_published_record() {
    let (mut r, c) = row_with(0, 3);
    r.id = "ffffffffffffffff".into();
    let pub_set: std::collections::HashSet<String> =
        ["ffffffffffffffff".to_string()].into_iter().collect();
    let row = live_row(&r, Some(&c), &pub_set);
    assert_eq!(row["state"], "damaged", "{row:?}");
}

/// Every state word this file can put on a row has a label in the
/// dashboard's own table, so a user never meets a raw wire token.
///
/// The drawer renders `t(...JF_STATE[state])`, a table lookup on the
/// word the daemon sent, and `jfState` falls back to the RAW TOKEN when
/// the table has no entry. So the day someone adds an eighth state here
/// and stops there, every one of the 27 dashboards prints an English
/// identifier - and nothing else in the tree would say so, because the
/// i18n gates hold the catalogues to the reference and the reference is
/// built from a hand list in `extract.js` that has no idea this file
/// exists. §296 added the seventh word and this is the check that pass
/// should have been able to run.
///
/// A source scan, in the shape `tests/integration/settings_catalogue.rs`
/// uses for
/// the same class of hand-kept pair. FAILING TO FIND IS FAILING: an
/// extraction that stops matching would otherwise read as a clean tree
/// forever, so the token count is floored and the ladder must parse.
#[test]
fn every_state_word_has_a_dashboard_label() {
    let src = include_str!("files.rs");
    // Comments first, or the prose above each arm donates its own
    // quoted words to the roster.
    let code: String = src
        .lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n");
    let quoted = |hay: &str| -> Vec<String> {
        let mut out = Vec::new();
        let b = hay.as_bytes();
        let mut i = 0;
        while let Some(q) = hay[i..].find('"') {
            let start = i + q + 1;
            let Some(e) = hay[start..].find('"') else {
                break;
            };
            let w = &hay[start..start + e];
            if !w.is_empty() && w.bytes().all(|c| c.is_ascii_lowercase()) {
                out.push(w.to_string());
            }
            i = start + e + 1;
            let _ = b;
        }
        out
    };
    let mut tokens: std::collections::BTreeSet<String> = Default::default();
    // (a) the `let state = if ... };` ladder - the live row's own words.
    let at = code
        .find("let state = if")
        .expect("the state ladder moved or was renamed");
    let end = code[at..]
        .find("};")
        .expect("the state ladder does not close")
        + at;
    tokens.extend(quoted(&code[at..end]));
    // (b) every `"state".into(), json!("word")` - the queued row, the
    // no-slot recovery arm, and §296's refinement.
    for (i, _) in code.match_indices("\"state\".into()") {
        // The enclosing STATEMENT, which is exactly "up to the next
        // semicolon": every arm of every `json!(...)` here sits inside
        // one `o.insert(...);` and none of them carries a `;` of its
        // own. A fixed-size window would bleed into the neighbouring
        // inserts instead, and their values are the kind of thing that
        // joins a roster quietly and is never noticed.
        let end = code[i..].find(';').map(|e| i + e).unwrap_or(code.len());
        tokens.extend(quoted(&code[i..end]));
    }
    tokens.remove("state");
    assert!(
        tokens.len() >= 7,
        "only found {} state word(s) - the extraction stopped matching: {tokens:?}",
        tokens.len()
    );
    // The dashboard's table, read the same way.
    let dash = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../web/dashboard.html"),
    )
    .expect("web/dashboard.html");
    let jf = dash
        .find("const JF_STATE={")
        .expect("JF_STATE moved or was renamed");
    let jf_end = dash[jf..].find("};").expect("JF_STATE does not close") + jf;
    let table = &dash[jf..jf_end];
    for w in &tokens {
        assert!(
            table.contains(&format!("{w}:[")),
            "the daemon can send state {w:?} and the dashboard has no label for it - \
             add it to JF_STATE, to extract.js's hand list, and to all 27 catalogues"
        );
    }
}
