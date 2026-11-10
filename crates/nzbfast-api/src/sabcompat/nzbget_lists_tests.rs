//! TODO 358 item 4: `listfiles`, `postqueue` and `servervolumes`, held
//! to what NZBGet itself sends.
//!
//! The oracle is `nzbget_recorded.json`: the three replies a scratch
//! NZBGet 26.3 gave on 9 Nov 2026 (see `nzbget_lists.rs`). Every key a
//! recorded row carries must be in ours WITH THE SAME JSON TYPE, down
//! through nested arrays and objects - issue #118 was a strict decoder
//! rejecting a whole reply over one absent key, and a number where a
//! decoder wants a bool fails it the same way. Extra keys are allowed,
//! as in `nzbget_fields_tests.rs`. Against the old arms (`[]`) every
//! test here is red: there is no row to compare.

use super::nzbget_lists::*;
use super::*;

fn recorded(method: &str) -> Vec<Value> {
    let fix: Value =
        serde_json::from_str(include_str!("nzbget_recorded.json")).expect("fixture parses");
    fix[method]
        .as_array()
        .unwrap_or_else(|| panic!("fixture has no {method} array"))
        .clone()
}

fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(n) if n.is_f64() => "float",
        Value::Number(_) => "int",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Every place `ours` differs from `theirs` in shape: a key theirs has
/// and ours lacks, or a value of another JSON type. Arrays compare
/// their first elements, when both have one.
fn shape_gaps(path: &str, theirs: &Value, ours: &Value, out: &mut Vec<String>) {
    if kind(theirs) != kind(ours) {
        out.push(format!(
            "{path}: NZBGet {} vs ours {}",
            kind(theirs),
            kind(ours)
        ));
        return;
    }
    match (theirs, ours) {
        (Value::Object(t), Value::Object(o)) => {
            for (k, tv) in t {
                match o.get(k) {
                    None => out.push(format!("{path}.{k}: missing")),
                    Some(ov) => shape_gaps(&format!("{path}.{k}"), tv, ov, out),
                }
            }
        }
        (Value::Array(t), Value::Array(o)) => {
            if let (Some(tv), Some(ov)) = (t.first(), o.first()) {
                shape_gaps(&format!("{path}[0]"), tv, ov, out);
            }
        }
        _ => {}
    }
}

fn assert_shape(what: &str, theirs: &Value, ours: &Value) {
    let mut gaps = Vec::new();
    shape_gaps(what, theirs, ours, &mut gaps);
    assert_eq!(gaps, Vec::<String>::new(), "{what}: {ours:#}");
}

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("nzbfast-nzbget-lists-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("temp dir");
    d
}

/// A two-file post: a payload of two 700,000-byte articles and a
/// recovery VOLUME, the shape NZBGet holds paused on add.
const NZB: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
<file poster="p" date="1700000000" subject="Test [1/2] - &quot;a.rar&quot; yEnc (1/2)"><groups><group>alt.binaries.test</group></groups><segments><segment bytes="700000" number="1">a1@x</segment><segment bytes="700000" number="2">a2@x</segment></segments></file>
<file poster="p" date="1700000100" subject="Test [2/2] - &quot;a.vol00+01.par2&quot; yEnc (1/1)"><groups><group>alt.binaries.test</group></groups><segments><segment bytes="5000" number="1">b1@x</segment></segments></file>
</nzb>
"#;

/// A queue row `SABnzbd_nzo_<id>` in `state`, whose spool is `NZB`
/// above. The state is set AFTER the load, which re-queues an
/// interrupted download (a restored row is never mid-transfer).
fn queued(d: &Arc<Daemon>, dir: &std::path::Path, id: &str, state: JobState) {
    let nzb = dir.join(format!("Some.Release.{id}.nzb"));
    std::fs::write(&nzb, NZB).expect("write nzb");
    let mut job = job_from_json(&json!({
        "nzo_id": format!("SABnzbd_nzo_{id}"), "name": format!("Some.Release.{id}"),
        "out_dir": dir.join("out").join(id).to_string_lossy(),
        "nzb_path": nzb.to_string_lossy(), "state": "Queued", "total_bytes": 1_405_000u64,
    }))
    .expect("job");
    job.state = state;
    d.queue.lock_ok().push_back(Arc::new(Mutex::new(job)));
}

#[test]
fn listfiles_rows_carry_nzbgets_fields_and_types() {
    let dir = tmp("lf");
    let d = crate::testutil::test_daemon(&dir);
    queued(&d, &dir, "41", JobState::Queued);
    queued(&d, &dir, "43", JobState::Queued);
    let theirs = &recorded("listfiles")[0];

    let all = jr_listfiles(&d, &[json!(0), json!(0), json!(0)]);
    let rows = all.as_array().expect("an array");
    assert_eq!(rows.len(), 4, "two files each, every file listed: {all:#}");
    for (i, r) in rows.iter().enumerate() {
        assert_shape(&format!("listfiles[{i}]"), theirs, r);
    }
    let r = &rows[0];
    // The derived id: NZBID * 10,000 + the file's 1-based NZB position.
    assert_eq!(r["ID"], json!(410_001));
    assert_eq!(rows[1]["ID"], json!(410_002));
    assert_eq!(r["NZBID"], json!(41));
    assert_eq!(r["Filename"], json!("a.rar"));
    assert_eq!(r["NZBFilename"], json!("Some.Release.41.nzb"));
    assert_eq!(r["FileSizeLo"], json!(1_400_000));
    assert_eq!(r["RemainingSizeLo"], json!(1_400_000));
    assert_eq!(r["PostTime"], json!(1_700_000_000i64));
    assert_eq!(r["Progress"], json!(0));
    assert_eq!(r["Paused"], json!(false));
    // NZBGet holds a recovery volume paused on add; a queued one here
    // says the same, because the plan will not fetch it either.
    assert_eq!(rows[1]["Paused"], json!(true), "{all:#}");

    // NZBGet's filter: a positive NZBID is that group alone...
    let one = jr_listfiles(&d, &[json!(0), json!(0), json!(43)]);
    let ids: Vec<&Value> = one.as_array().unwrap().iter().map(|r| &r["ID"]).collect();
    assert_eq!(ids, [&json!(430_001), &json!(430_002)], "{one:#}");
    // ...otherwise an id range, inclusive.
    let range = jr_listfiles(&d, &[json!(410_002), json!(430_001), json!(0)]);
    let ids: Vec<&Value> = range.as_array().unwrap().iter().map(|r| &r["ID"]).collect();
    assert_eq!(ids, [&json!(410_002), &json!(430_001)], "{range:#}");
    // An unknown group lists nothing, not everything.
    assert_eq!(
        jr_listfiles(&d, &[json!(0), json!(0), json!(99)]),
        json!([])
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A run's frozen table: `a.rar` half arrived (5 of 10 articles still
/// owed), `b.rar` complete, and a recovery volume the plan never queued.
fn half_done_table() -> crate::streamhub::TailTable {
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    let slot = |hint: &str, remaining: usize| {
        Arc::new(crate::unpack::FileSlot {
            hint: hint.into(),
            hint_is_posted_name: nzbkit::release::stem_is_a_name(hint),
            yenc_votes: Default::default(),
            name_choice: std::sync::atomic::AtomicU8::new(crate::unpack::NAME_UNDECIDED),
            is_par2_main: false,
            sample_skipped: false,
            par2_name_demoted: Default::default(),
            par2_sniffed: AtomicBool::new(false),
            total_segments: 10,
            posted_bytes: 0,
            remaining: AtomicUsize::new(remaining),
            missing: AtomicUsize::new(0),
            errors: AtomicUsize::new(0),
            deferred: AtomicUsize::new(0),
            abandoned: AtomicUsize::new(0),
            capture: std::sync::Mutex::new(None),
        })
    };
    let row = |id: &str, name: &str, slot| crate::streamhub::JobFileRow {
        id: id.into(),
        name: name.into(),
        bytes: 1_000_000,
        date: 1_690_000_000,
        segments: 10,
        slot,
    };
    let rows = vec![
        row("aaaaaaaaaaaaaaaa", "a.rar", Some(0)),
        row("bbbbbbbbbbbbbbbb", "b.rar", Some(1)),
        row("cccccccccccccccc", "a.vol00+01.par2", None),
    ];
    crate::streamhub::TailTable::settled(Arc::new(crate::streamhub::freeze_rows(
        &rows,
        &[slot("a.rar", 5), slot("b.rar", 0)],
    )))
}

/// A job with a plan is listed off its counters: a complete file drops
/// out (NZBGet removes a finished file from its group), a half-done one
/// reads Progress 500 - the figure NZBGet itself sent with one of two
/// articles in - and the never-queued volume is held Paused.
#[test]
fn listfiles_reads_a_planned_job_off_its_counters() {
    let dir = tmp("lfplan");
    let d = crate::testutil::test_daemon(&dir);
    queued(&d, &dir, "44", JobState::Downloading);
    crate::streamhub::keep_tail_table(
        &mut d.hub.tail_files.lock_ok(),
        "SABnzbd_nzo_44".into(),
        half_done_table(),
    );
    d.hub
        .activity
        .lock_ok()
        .insert("SABnzbd_nzo_44".into(), "repairing");

    let got = jr_listfiles(&d, &[json!(0), json!(0), json!(44)]);
    let rows = got.as_array().expect("an array");
    let names: Vec<&Value> = rows.iter().map(|r| &r["Filename"]).collect();
    assert_eq!(
        names,
        [&json!("a.rar"), &json!("a.vol00+01.par2")],
        "{got:#}"
    );
    assert_eq!(rows[0]["Progress"], json!(500), "{got:#}");
    assert_eq!(rows[0]["RemainingSizeLo"], json!(500_000), "{got:#}");
    assert_eq!(rows[0]["Paused"], json!(false));
    // The ids skip the dropped file rather than renumbering past it:
    // the id is the NZB position, so it is the same id on every poll.
    assert_eq!(rows[1]["ID"], json!(440_003), "{got:#}");
    assert_eq!(rows[1]["Paused"], json!(true), "{got:#}");
    for (i, r) in rows.iter().enumerate() {
        assert_shape(&format!("listfiles[{i}]"), &recorded("listfiles")[0], r);
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// `postqueue` lists the rows past their network phase and nothing
/// else, in NZBGet's whole field set (its per-NZB block included), and
/// exactly the rows `listgroups` calls a post-processing stage.
#[test]
fn postqueue_lists_the_jobs_in_their_tail_with_nzbgets_fields() {
    let dir = tmp("pq");
    let d = crate::testutil::test_daemon(&dir);
    queued(&d, &dir, "51", JobState::Downloading);
    queued(&d, &dir, "52", JobState::Queued);
    queued(&d, &dir, "53", JobState::Finishing);
    d.hub
        .activity
        .lock_ok()
        .insert("SABnzbd_nzo_51".into(), "repairing");

    let got = jr_postqueue(&d, &[json!(10)]);
    let rows = got.as_array().expect("an array");
    let ids: Vec<&Value> = rows.iter().map(|r| &r["NZBID"]).collect();
    assert_eq!(
        ids,
        [&json!(51), &json!(53)],
        "the queued job is not in post: {got:#}"
    );
    let theirs = &recorded("postqueue")[0];
    for (i, r) in rows.iter().enumerate() {
        // `Log` is compared as an array of entries only when both have
        // one; this fixture's jobs never ran, so ours is empty.
        assert_shape(&format!("postqueue[{i}]"), theirs, r);
    }
    assert_eq!(rows[0]["ID"], json!(51));
    assert_eq!(rows[0]["Stage"], json!("REPAIRING"));
    assert_eq!(rows[0]["ProgressLabel"], json!("Repairing"));
    assert_eq!(rows[0]["InfoName"], json!("Some.Release.51"));
    assert_eq!(rows[0]["FileSizeLo"], json!(1_405_000));
    assert_eq!(
        rows[1]["Stage"],
        json!("MOVING"),
        "Finishing is the move window"
    );
    assert_eq!(
        rows[0]["Log"],
        json!([]),
        "a job that never ran has no span"
    );

    // The same jobs, the same words, in listgroups.
    let groups = jr_listgroups(&d);
    let status: Vec<(&Value, &Value)> = groups
        .as_array()
        .unwrap()
        .iter()
        .map(|g| (&g["NZBID"], &g["Status"]))
        .collect();
    assert_eq!(
        status,
        [
            (&json!(51), &json!("REPAIRING")),
            (&json!(52), &json!("QUEUED")),
            (&json!(53), &json!("MOVING")),
        ]
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The recorded log entry's shape is ours too: captured lines go out as
/// NZBGet `{ID, Kind, Time, Text}` entries, numbered from 1. The ring
/// itself is filled only by `logtee::install`, which a unit test must
/// not call, so the renderer is tested on its own and the arm only for
/// its sentinels.
#[test]
fn postqueue_log_entries_have_nzbgets_shape() {
    let lines = vec!["first".to_string(), "second".to_string()];
    let ours = log_entries(&lines, 1_794_245_053);
    assert_eq!(ours.len(), 2);
    let theirs = recorded("postqueue")[0]["Log"].clone();
    assert_shape("postqueue.Log", &theirs, &json!(ours));
    assert_eq!(ours[1]["ID"], json!(2));
    assert_eq!(ours[1]["Text"], json!("second"));

    let dir = tmp("pqlog");
    let d = crate::testutil::test_daemon(&dir);
    queued(&d, &dir, "54", JobState::Finishing);
    // Mark 0 is the nothing-to-slice sentinel `mode=report` honours: a
    // job restored across a restart, whose span would otherwise read as
    // the tail of the whole ring.
    assert_eq!(jr_postqueue(&d, &[json!(5)])[0]["Log"], json!([]));
    // NumberOfLogEntries 0 (or absent) asks for no log at all.
    assert_eq!(jr_postqueue(&d, &[])[0]["Log"], json!([]));

    let _ = std::fs::remove_dir_all(&dir);
}

/// 9 Nov 2026 12:21:23 UTC, the recording's own `DataTime` minute.
const NOW: i64 = 1_794_244_883;

fn ledger() -> serde_json::Map<String, Value> {
    json!({
        "2026-11-07": {"news.a.example": 1000u64, "news.b.example": 30u64},
        "2026-11-09": {"news.a.example": 4u64 << 30},
        "lifetime": {"news.a.example": (4u64 << 30) + 9000, "news.b.example": 30u64},
        "reliability": {"news.a.example": {"tried": 9, "missing": 2}},
        "article_days": {"news.a.example": {"2026-11-09": {"tried": 9, "missing": 2}}},
        "block_base": {"news.a.example": 7u64},
    })
    .as_object()
    .cloned()
    .unwrap()
}

#[test]
fn servervolumes_is_the_total_then_each_server_in_nzbgets_shape() {
    let hosts = ["news.a.example".to_string(), "news.b.example".to_string()];
    let got = servervolumes_json(&ledger(), &hosts, NOW);
    let rows = got.as_array().expect("an array");
    assert_eq!(rows.len(), 3, "element 0 is the total, then one per server");
    let theirs = recorded("servervolumes");
    for (i, r) in rows.iter().enumerate() {
        assert_shape(&format!("servervolumes[{i}]"), &theirs[i.min(1)], r);
        assert_eq!(r["ServerID"], json!(i));
        // NZBGet's ring lengths, recorded: 60 seconds, 60 minutes, 24 hours.
        for (k, n) in [
            ("BytesPerSeconds", 60),
            ("BytesPerMinutes", 60),
            ("BytesPerHours", 24),
        ] {
            assert_eq!(r[k].as_array().map(Vec::len), Some(n), "{k}");
        }
        // The day series runs FirstDay..=today, one cell per day.
        let slot = r["DaySlot"].as_u64().unwrap() as usize;
        assert_eq!(r["BytesPerDays"].as_array().unwrap().len(), slot + 1);
        assert_eq!(r["ArticlesPerDays"].as_array().unwrap().len(), slot + 1);
    }
    let (total, a, b) = (&rows[0], &rows[1], &rows[2]);
    // The oldest ledger day, as NZBGet's day number, and today two later.
    assert_eq!(total["FirstDay"], json!(20_764));
    assert_eq!(total["DaySlot"], json!(2));
    assert_eq!(total["SecSlot"], json!(23));
    assert_eq!(total["MinSlot"], json!(21));
    assert_eq!(
        total["HourSlot"],
        json!(17),
        "UTC, the ledger's day boundary"
    );
    // Lifetime, split the NZBGet way: 4 GiB + 9000 is Hi 1, Lo 9000.
    assert_eq!(a["TotalSizeHi"], json!(1));
    assert_eq!(a["TotalSizeLo"], json!(9000));
    assert_eq!(
        total["TotalSizeLo"],
        json!(9030),
        "the total sums the hosts"
    );
    assert_eq!(b["TotalSizeLo"], json!(30));
    // The days are the ledger's, per server and summed.
    assert_eq!(a["BytesPerDays"][0]["SizeLo"], json!(1000));
    assert_eq!(
        a["BytesPerDays"][1]["SizeLo"],
        json!(0),
        "a day with no bill"
    );
    assert_eq!(a["BytesPerDays"][2]["SizeHi"], json!(1));
    assert_eq!(total["BytesPerDays"][0]["SizeLo"], json!(1030));
    assert_eq!(b["BytesPerDays"][2]["SizeLo"], json!(0));
    assert_eq!(a["ArticlesPerDays"][2], json!({"Failed": 2, "Success": 7}));
    assert_eq!(b["ArticlesPerDays"][2], json!({"Failed": 0, "Success": 0}));
    // The halves the ledger has no grain for are zero, never estimated.
    for r in rows {
        for k in ["BytesPerSeconds", "BytesPerMinutes", "BytesPerHours"] {
            assert!(
                r[k].as_array()
                    .unwrap()
                    .iter()
                    .all(|c| c["SizeLo"] == 0 && c["SizeHi"] == 0),
                "{k} must be all zero: {r:#}"
            );
        }
    }
}

/// An empty ledger is NZBGet's fresh-install answer: one day, today,
/// at zero - not an empty array a client indexes off the end of.
#[test]
fn servervolumes_on_an_empty_ledger_is_one_zero_day() {
    let got = servervolumes_json(&Default::default(), &["h.example".into()], NOW);
    let r = &got[1];
    assert_eq!(r["FirstDay"], json!(NOW / 86_400));
    assert_eq!(r["DaySlot"], json!(0));
    assert_eq!(
        r["BytesPerDays"],
        json!([{"SizeLo": 0, "SizeHi": 0, "SizeMB": 0}])
    );
    assert_eq!(r["ArticlesPerDays"], json!([{"Failed": 0, "Success": 0}]));
    assert_shape("servervolumes[1]", &recorded("servervolumes")[1], r);
}

/// The daemon-facing arm reads the configured server list: one element
/// per server in the config, after the total.
#[test]
fn servervolumes_lists_every_configured_server() {
    let dir = tmp("sv");
    let d = crate::testutil::test_daemon(&dir);
    std::fs::write(
        &d.cfg_path,
        r#"{"servers":[{"host":"news.a.example","enabled":true},{"host":"news.b.example","enabled":false}]}"#,
    )
    .expect("config");
    *d.usage.lock_ok() = ledger();
    let got = jr_servervolumes(&d);
    let ids: Vec<&Value> = got
        .as_array()
        .unwrap()
        .iter()
        .map(|r| &r["ServerID"])
        .collect();
    assert_eq!(
        ids,
        [&json!(0), &json!(1), &json!(2)],
        "a disabled server is still listed"
    );
    assert_eq!(got[2]["TotalSizeLo"], json!(30));

    let _ = std::fs::remove_dir_all(&dir);
}

/// TODO 358 sweep E1: `listgroups`' `FirstID`/`LastID` are NZBGet's
/// first and last FILE ids of the group, so a client that pages a
/// group's files with `listfiles(FirstID, LastID, 0)` must get them -
/// it got nothing while both were the bare NZBID, which is in no
/// file's id range. `FileCount`/`RemainingFileCount` must agree with
/// the rows `listfiles` lists, rather than read 0 beside two rows.
#[test]
fn listgroups_file_ids_and_counts_are_listfiles_own() {
    let dir = tmp("lgids");
    let d = crate::testutil::test_daemon(&dir);
    queued(&d, &dir, "41", JobState::Queued);
    let groups = jr_listgroups(&d);
    let row = &groups.as_array().expect("an array")[0];
    assert_eq!(row["FirstID"], json!(410_001), "{row:#}");
    assert_eq!(row["LastID"], json!(410_002), "{row:#}");
    assert_eq!(row["FileCount"], json!(2), "{row:#}");
    assert_eq!(row["RemainingFileCount"], json!(2), "{row:#}");
    let files = jr_listfiles(
        &d,
        &[row["FirstID"].clone(), row["LastID"].clone(), json!(0)],
    );
    assert_eq!(
        files.as_array().map(Vec::len),
        Some(2),
        "listfiles(FirstID, LastID, 0) lists the group: {files:#}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// TODO 358 sweep E1: a planned job's counts are its counters - the
/// complete file is not remaining, as it is not listed either.
#[test]
fn listgroups_remaining_file_count_follows_the_counters() {
    let dir = tmp("lgplan");
    let d = crate::testutil::test_daemon(&dir);
    queued(&d, &dir, "44", JobState::Downloading);
    crate::streamhub::keep_tail_table(
        &mut d.hub.tail_files.lock_ok(),
        "SABnzbd_nzo_44".into(),
        half_done_table(),
    );
    d.hub
        .activity
        .lock_ok()
        .insert("SABnzbd_nzo_44".into(), "repairing");
    let groups = jr_listgroups(&d);
    let row = &groups.as_array().expect("an array")[0];
    assert_eq!(row["FileCount"], json!(3), "{row:#}");
    assert_eq!(row["RemainingFileCount"], json!(2), "{row:#}");
    assert_eq!(row["FirstID"], json!(440_001), "{row:#}");
    assert_eq!(row["LastID"], json!(440_003), "{row:#}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// TODO 358 sweep E3: an id range names its groups (`id / 10,000`), so
/// a range inside one group must not parse the other groups' NZBs.
/// Observed through the parse cache, which only a parse fills; the
/// spool paths are this test's own, so no other test can fill them.
#[test]
fn listfiles_id_range_parses_only_the_groups_it_names() {
    let dir = tmp("lfnarrow");
    let d = crate::testutil::test_daemon(&dir);
    queued(&d, &dir, "51", JobState::Queued);
    queued(&d, &dir, "53", JobState::Queued);
    let got = jr_listfiles(&d, &[json!(530_001), json!(530_002), json!(0)]);
    assert_eq!(got.as_array().map(Vec::len), Some(2), "{got:#}");
    assert!(
        crate::api::queue::files::queued_rows_cached(&dir.join("Some.Release.53.nzb")),
        "the named group was parsed"
    );
    assert!(
        !crate::api::queue::files::queued_rows_cached(&dir.join("Some.Release.51.nzb")),
        "a group outside the range must not be parsed"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// TODO 358 sweep E2: a day before 2000 is a clock that was wrong when
/// it was billed (a board with no RTC boots at 1970), and one such key
/// must not stretch every reply back to it - ~20,000 cells per element.
#[test]
fn servervolumes_ignores_a_pre_2000_day() {
    let mut u = ledger();
    u.insert("1970-01-01".into(), json!({"news.a.example": 5u64}));
    let got = servervolumes_json(&u, &["news.a.example".into()], NOW);
    assert_eq!(got[0]["FirstDay"], json!(20_764), "{:#}", got[0]);
}

/// TODO 358 sweep E2: the series is bounded at read, so no key the
/// ledger holds - a sparse one, or one billed under a clock set years
/// back - makes a reply longer than a year of day cells.
#[test]
fn servervolumes_day_series_is_bounded() {
    let mut u = ledger();
    u.insert("2001-01-01".into(), json!({"news.a.example": 5u64}));
    let got = servervolumes_json(&u, &["news.a.example".into()], NOW);
    let cells = got[1]["BytesPerDays"].as_array().map_or(0, Vec::len);
    assert!(cells <= SERVERVOLUME_DAYS as usize, "{cells} day cells");
    assert_eq!(
        got[1]["DaySlot"].as_u64().map(|s| s as usize + 1),
        Some(cells)
    );
}
