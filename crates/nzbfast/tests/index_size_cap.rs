#![cfg(feature = "indexer")]
//! M34: the index size cap, its settings, and - the part that matters -
//! what it refuses to delete, driven against the real binary.
//!
//! The feature deletes user data, so the tests here are mostly about the
//! guards rather than the deleting:
//!
//!  * the four settings round-trip through the API, validate, and survive
//!    a restart;
//!  * `index_evict` defaults OFF and NOTHING is evicted while it is off,
//!    including by the scan loop's own timer;
//!  * `index_shrink_to` reaches the size it was asked for, or says why it
//!    could not;
//!  * all four protected categories - watchlisted, queued, downloaded,
//!    recently opened - survive a shrink that would otherwise take them;
//!  * the two new modes sit behind the FULL key, not the add-only NZB key.

// The shared daemon launcher (free_port / KillOnDrop / DaemonLog /
// serve_blocking / wait_ready), one copy for every suite that spawns a
// daemon.
mod harness;
mod scratch;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;

use harness::Daemon;

use nzbkit::nntp::OverEntry;

fn http(port: u16, req: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect daemon");
    write!(
        s,
        "GET {req} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out.split("\r\n\r\n").nth(1).unwrap_or("").to_string()
}

fn api(port: u16, q: &str) -> serde_json::Value {
    let body = http(port, &format!("/api?output=json&{q}"));
    serde_json::from_str(&body).unwrap_or_else(|e| panic!("bad JSON for {q:?}: {e}\n{body}"))
}

fn over(number: u64, subject: &str, msgid: &str, date: i64) -> OverEntry {
    OverEntry {
        number,
        subject: subject.into(),
        from: "poster@x".into(),
        // Fat enough to dodge the tiny-post junk score, so these behave
        // like real releases in browse/curation.
        bytes: 50 << 20,
        message_id: msgid.into(),
        date,
    }
}

/// A scratch install. `settings` is written as settings.json, which ALSO
/// marks this as an existing install so no first-run API key is minted
/// behind the test's back.
///
/// `index_enabled` is stamped in unless the caller set it: the indexer's
/// master switch defaults OFF, and every test in this file is about the
/// index database, which the daemon will not even open while it is off.
fn scratch(name: &str, settings: &str) -> scratch::ScratchDir {
    let dir = std::env::temp_dir().join(format!("nzbfast-sizecap-{}-{name}", std::process::id()));
    let dir = scratch::ScratchDir::attach(&dir);
    std::fs::write(dir.join("config.json"), "{\"servers\":[]}").unwrap();
    std::fs::write(dir.join("settings.json"), with_indexer_on(settings)).unwrap();
    dir
}

/// Add `"index_enabled": true` to a settings.json literal, leaving an
/// explicit choice alone. Textual rather than a serde round-trip so the
/// tests' hand-written JSON stays exactly as written in the diff.
fn with_indexer_on(settings: &str) -> String {
    if settings.contains("index_enabled") {
        return settings.to_string();
    }
    let t = settings.trim();
    let inner = t
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or("")
        .trim();
    if inner.is_empty() {
        "{\"index_enabled\": true}".to_string()
    } else {
        format!("{{\"index_enabled\": true, {inner}}}")
    }
}

/// Put `stems` into the index db as real releases, newest first. Returns
/// nothing - the tests read ids back through the API, the way the UI does.
fn seed_index(dir: &Path, stems: &[&str]) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut ix = nzbkit::index::Index::open(&dir.join("index.db")).unwrap();
    let entries: Vec<OverEntry> = stems
        .iter()
        .enumerate()
        .map(|(i, stem)| {
            over(
                i as u64 + 1,
                &format!("\"{stem}.rar\" yEnc (1/1)"),
                &format!("<seed{i}@x>"),
                // Spread the ages so an age-ordered eviction has
                // something to order by.
                now - (i as i64 + 1) * 5 * 86_400,
            )
        })
        .collect();
    ix.ingest("alt.binaries.teevee", &entries, now - 3600)
        .unwrap();
}

fn serve(dir: &Path) -> Daemon {
    harness::serve_blocking(dir, |port| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        cmd.env("NZBFAST_NO_ENRICH", "1")
            .env_remove("NZBFAST_OPEN")
            .arg("--config")
            .arg(dir.join("config.json"))
            .arg("serve")
            // Loopback only. This suite never needs LAN reach, and binding
            // 0.0.0.0 makes the macOS firewall raise a prompt for every
            // freshly built test binary, which is a new path on every run.
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--index-db")
            .arg(dir.join("index.db"));
        cmd
    })
}

fn cfg(port: u16, name: &str, value: &str) -> serde_json::Value {
    api(port, &format!("mode=config&name={name}&value={value}"))
}

/// The settings block get_config hands the UI.
fn live(port: u16) -> serde_json::Value {
    api(port, "mode=get_config")["config"]["nzbfast"].clone()
}

fn stats(port: u16) -> serde_json::Value {
    api(port, "mode=index_stats")
}

// ---------------------------------------------------------------------------

/// All four settings, in and out again - including the SAB-style size
/// input the rest of the daemon's size gates already take, and the
/// validation that keeps a typo from silently changing what gets deleted.
#[test]
fn size_cap_settings_round_trip_validate_and_survive_a_restart() {
    let dir = scratch("settings", "{}");
    let d = serve(&dir);

    // Defaults first, because one of them is a promise: eviction is OFF
    // on a fresh install and the cap is unlimited, so nothing about this
    // feature can delete anything until the user says so.
    let l = live(d.port);
    assert_eq!(l["index_max_bytes"], 0, "the cap defaults to unlimited");
    assert_eq!(l["index_evict"], false, "eviction must default OFF");
    assert_eq!(l["index_evict_order"], "ladder");
    assert_eq!(l["index_evict_kinds"], serde_json::json!([]));

    // SAB-style sizes, same as min_free/quota.
    assert_eq!(cfg(d.port, "index_max_bytes", "20G")["status"], true);
    assert_eq!(live(d.port)["index_max_bytes"], 20_000_000_000u64);
    assert_eq!(cfg(d.port, "index_max_bytes", "500M")["status"], true);
    assert_eq!(live(d.port)["index_max_bytes"], 500_000_000u64);
    // 0 = unlimited, and it must be settable BACK to unlimited.
    assert_eq!(cfg(d.port, "index_max_bytes", "0")["status"], true);
    assert_eq!(live(d.port)["index_max_bytes"], 0);
    let bad = cfg(d.port, "index_max_bytes", "twenty");
    assert_eq!(bad["status"], false, "a non-size must be refused: {bad}");

    // Order: closed set, case-insensitive, typos refused rather than
    // silently defaulted.
    for o in ["ladder", "oldest", "newest", "largest", "smallest"] {
        assert_eq!(
            cfg(d.port, "index_evict_order", o)["status"],
            true,
            "order {o}"
        );
        assert_eq!(live(d.port)["index_evict_order"], o);
    }
    let bad = cfg(d.port, "index_evict_order", "biggest");
    assert_eq!(bad["status"], false);
    assert!(
        bad["error"].as_str().unwrap_or_default().contains("ladder"),
        "the error should list the valid orders: {bad}"
    );
    assert_eq!(
        live(d.port)["index_evict_order"],
        "smallest",
        "a refused write changes nothing"
    );

    // Kinds: comma list, empty = every kind.
    assert_eq!(
        cfg(d.port, "index_evict_kinds", "movie,other")["status"],
        true
    );
    assert_eq!(
        live(d.port)["index_evict_kinds"],
        serde_json::json!(["movie", "other"])
    );
    let bad = cfg(d.port, "index_evict_kinds", "movie,film");
    assert_eq!(bad["status"], false);
    assert!(
        bad["error"].as_str().unwrap_or_default().contains("film"),
        "{bad}"
    );
    assert_eq!(cfg(d.port, "index_evict_kinds", "")["status"], true);
    assert_eq!(live(d.port)["index_evict_kinds"], serde_json::json!([]));

    // The switch.
    assert_eq!(cfg(d.port, "index_evict", "1")["status"], true);
    assert_eq!(live(d.port)["index_evict"], true);

    // Persist across a restart - a UI setting that forgets itself is the
    // bug this project has hit before (see the groups_add_matching test).
    assert_eq!(cfg(d.port, "index_max_bytes", "7G")["status"], true);
    assert_eq!(cfg(d.port, "index_evict_order", "oldest")["status"], true);
    assert_eq!(cfg(d.port, "index_evict_kinds", "tv")["status"], true);
    let _log = d.stop();
    let d = serve(&dir);
    let l = live(d.port);
    assert_eq!(l["index_max_bytes"], 7_000_000_000u64);
    assert_eq!(l["index_evict"], true);
    assert_eq!(l["index_evict_order"], "oldest");
    assert_eq!(l["index_evict_kinds"], serde_json::json!(["tv"]));
}

/// index_stats is where a user finds out how big the database has grown -
/// which, before this feature, nothing in the API told them.
#[test]
fn index_stats_reports_size_cap_and_pending_compact() {
    let dir = scratch("stats", "{}");
    seed_index(&dir, &["Alpha.Show.S01E01.1080p.WEB.x264-GRP"]);
    let d = serve(&dir);

    let s = stats(d.port);
    assert!(
        s["db_bytes"].as_u64().unwrap_or(0) > 0,
        "db_bytes must be reported: {s}"
    );
    assert_eq!(s["index_max_bytes"], 0);
    assert_eq!(s["over_cap"], false, "no cap set, so never over it");
    assert_eq!(s["compact_pending"], false);
    assert_eq!(s["index_evict"], false);

    // A cap below the current size shows up as over_cap even with
    // eviction off - seeing the problem is the point of the readout.
    assert_eq!(cfg(d.port, "index_max_bytes", "1")["status"], true);
    let s = stats(d.port);
    assert_eq!(s["index_max_bytes"], 1);
    assert_eq!(s["over_cap"], true, "{s}");
    assert_eq!(
        s["index_evict"], false,
        "and still nothing has been deleted"
    );
}

/// The hard rule: with `index_evict` off, nothing evicts. Not on demand,
/// and not on the scan loop's own timer either - which is the one that
/// would do it behind the user's back.
#[test]
fn eviction_never_runs_while_the_toggle_is_off() {
    let stems = [
        "Alpha.Show.S01E01.1080p.WEB.x264-GRP",
        "Beta.Movie.2019.1080p.BluRay.x264-GRP",
        "Gamma.Movie.2018.1080p.BluRay.x264-GRP",
        "Delta.Show.S02E03.1080p.WEB.x264-GRP",
    ];
    let dir = scratch("toggle-off", "{}");
    seed_index(&dir, &stems);
    let d = serve(&dir);
    let before = stats(d.port)["releases"].as_u64().unwrap();
    assert_eq!(before, stems.len() as u64);

    // A cap far below the current size, and the switch left alone.
    assert_eq!(cfg(d.port, "index_max_bytes", "1")["status"], true);

    // On demand: refused, and the error names the setting to change.
    let r = api(d.port, "mode=index_evict_now");
    assert_eq!(r["status"], false, "{r}");
    let e = r["error"].as_str().unwrap_or_default();
    assert!(
        e.contains("index_evict"),
        "the error must name the switch: {r}"
    );

    // On the timer: the scan loop re-checks every 15 s when no groups are
    // configured, so this window covers several of its passes.
    std::thread::sleep(std::time::Duration::from_secs(40));
    let s = stats(d.port);
    assert_eq!(
        s["releases"].as_u64().unwrap(),
        before,
        "the scan loop evicted with the toggle OFF: {s}"
    );
    assert_eq!(
        s["compact_pending"], false,
        "nothing pruned, so nothing to compact"
    );

    // ...and the other half of the same wiring: the moment the switch is
    // on, the scan loop's next pass enforces the cap without anyone
    // asking again. (Otherwise the test above would pass on a feature
    // that simply never worked.)
    assert_eq!(cfg(d.port, "index_evict", "1")["status"], true);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    loop {
        let s = stats(d.port);
        if s["releases"].as_u64().unwrap() < before {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the scan loop never enforced the cap after the toggle went on: {s}"
        );
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
}

/// The user's explicit choice: reclaiming the disk must never interrupt
/// anything, so the VACUUM a prune asks for waits for an idle moment and
/// then actually happens. This drives the real loop rather than the
/// verdict function the unit test covers.
#[test]
fn a_pending_compact_fires_at_the_next_idle_window() {
    let dir = scratch("compact", "{}");
    seed_index(
        &dir,
        &[
            "Alpha.Show.S01E01.1080p.WEB.x264-GRP",
            "Beta.Movie.2019.1080p.BluRay.x264-GRP",
            "Gamma.Movie.2018.1080p.BluRay.x264-GRP",
        ],
    );
    let d = serve(&dir);

    let r = api(d.port, "mode=index_shrink_to&value=1");
    assert_eq!(r["status"], true, "{r}");
    assert_eq!(
        r["compact_pending"], true,
        "the prune must queue a compact: {r}"
    );

    // Nothing is downloading and nothing is scanning, so the idle loop
    // (60 s tick) should pick it up on its first or second look.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
    loop {
        let s = stats(d.port);
        if s["compact_pending"] == false {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the deferred compact never ran at idle: {s}"
        );
        std::thread::sleep(std::time::Duration::from_secs(3));
    }
    let log = d.log();
    assert!(
        log.contains("compacted at idle"),
        "the compact should say so in the log:\n{log}"
    );
}

/// `index_shrink_to` is the user's "shrink the database to X". It either
/// gets there, or it reports what stopped it - it never quietly leaves an
/// oversized database and calls that success.
#[test]
fn shrink_to_reaches_its_target_or_reports_why_not() {
    let stems = [
        "Alpha.Show.S01E01.1080p.WEB.x264-GRP",
        "Beta.Movie.2019.1080p.BluRay.x264-GRP",
        "Gamma.Movie.2018.1080p.BluRay.x264-GRP",
        "Delta.Show.S02E03.1080p.WEB.x264-GRP",
        "Epsilon.Movie.2017.2160p.BluRay.x265-GRP",
    ];
    let dir = scratch("shrink", "{}");
    seed_index(&dir, &stems);
    let d = serve(&dir);
    assert_eq!(
        stats(d.port)["releases"].as_u64().unwrap(),
        stems.len() as u64
    );

    // No size at all is a caller error, not a silent full wipe.
    let r = api(d.port, "mode=index_shrink_to");
    assert_eq!(r["status"], false, "{r}");

    // A target the index is already under: success, nothing removed.
    let r = api(d.port, "mode=index_shrink_to&value=100G");
    assert_eq!(r["status"], true, "{r}");
    assert_eq!(r["removed"], 0);
    assert_eq!(r["reached"], true);
    assert_eq!(
        stats(d.port)["releases"].as_u64().unwrap(),
        stems.len() as u64
    );

    // Nothing here is watchlisted, queued, downloaded or opened, so a
    // 1-byte target should shed every row it can.
    let r = api(d.port, "mode=index_shrink_to&value=1");
    assert_eq!(r["status"], true, "{r}");
    assert!(
        r["removed"].as_u64().unwrap() > 0,
        "nothing was pruned at all: {r}"
    );
    assert!(
        r["bytes_after"].as_u64().unwrap() <= r["bytes_before"].as_u64().unwrap(),
        "{r}"
    );
    if r["reached"] == false {
        // Allowed - a SQLite file has a floor (schema + indexes) that no
        // amount of row deletion reaches. What is NOT allowed is failing
        // silently: it must say so, and with nothing protected it must
        // not blame protection.
        let e = r["error"].as_str().unwrap_or_default();
        assert!(
            !e.is_empty(),
            "fell short of the target without saying why: {r}"
        );
        assert_eq!(r["protected_keys"], 0, "{r}");
        assert!(
            e.contains("nothing is protected"),
            "misattributed the shortfall: {r}"
        );
    }
    assert_eq!(
        stats(d.port)["releases"].as_u64().unwrap(),
        0,
        "every unprotected row goes"
    );

    // Reclaiming the disk is a VACUUM, and that is deferred to an idle
    // window rather than run inside this request.
    assert_eq!(
        stats(d.port)["compact_pending"],
        true,
        "a prune that frees pages must queue the compact"
    );
}

/// The heart of it. All four protections the user asked for, against a
/// shrink target of one byte - which without them would take everything.
#[test]
fn the_size_cap_never_touches_protected_releases() {
    // 1 watchlisted, 2 queued, 3 downloaded, 4 recently opened (two ways:
    // a detail-sheet open and an NZB fetch), plus two rows with no claim
    // on them at all.
    let watched = "Watched.Show.S01E01.1080p.WEB.x264-GRP";
    let queued = "Queued.Movie.2016.1080p.BluRay.x264-GRP";
    let owned = "Owned.Movie.2019.1080p.BluRay.x264-GRP";
    let opened = "Opened.Movie.2018.1080p.BluRay.x264-GRP";
    let fetched = "Fetched.Movie.2017.1080p.BluRay.x264-GRP";
    let junk_a = "Junk.Movie.2001.1080p.BluRay.x264-GRP";
    let junk_b = "Rubbish.Show.S09E09.1080p.WEB.x264-GRP";

    let dir = scratch(
        "protect",
        // The watchlist is a live setting; seeding it here is the same
        // path a dashboard edit takes on the next restart.
        r#"{"watchlist":[{"id":1,"kind":"tv","title":"Watched Show",
                          "target_quality":"1080p","enabled":true}]}"#,
    );
    seed_index(
        &dir,
        &[watched, queued, owned, opened, fetched, junk_a, junk_b],
    );

    // A queued job and a completed one, written the way a restart reads
    // them back. The queued record is paused so the scheduler leaves it
    // in the queue (there are no servers to run it against).
    let spool = dir.join(".spool");
    std::fs::create_dir_all(&spool).unwrap();
    let rec = |id: &str, name: &str, state: &str, paused: bool| {
        serde_json::json!({
            "nzo_id": id, "name": name, "state": state, "paused": paused,
            "nzb_path": dir.join(format!("{id}.nzb")).to_string_lossy(),
            "out_dir": dir.join("complete").join(id).to_string_lossy(),
        })
    };
    std::fs::write(
        spool.join("queue.json"),
        serde_json::json!({
            "next_id": 9,
            "queue": [rec("nq1", queued, "Queued", true)],
            "history": [rec("nh1", owned, "Completed", false)],
        })
        .to_string(),
    )
    .unwrap();

    let d = serve(&dir);
    assert_eq!(stats(d.port)["releases"].as_u64().unwrap(), 7);

    // Find the seeded rows' ids and keys through the API.
    let rows = api(d.port, "mode=index_browse&limit=200&all=1");
    let find = |stem: &str| -> (i64, String) {
        let r = rows["results"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"].as_str() == Some(stem))
            .unwrap_or_else(|| panic!("{stem} missing from browse: {rows}"));
        (
            r["id"].as_i64().unwrap(),
            r["key"].as_str().unwrap().to_string(),
        )
    };
    let (_, opened_key) = find(opened);
    let (fetched_id, _) = find(fetched);

    // 4a: open the card's detail sheet (a title_key-scoped browse - the
    // exact request the wall's sheet makes).
    let sheet = api(
        d.port,
        &format!(
            "mode=index_browse&limit=50&title_key={}",
            urlencode(&opened_key)
        ),
    );
    assert!(
        sheet["results"].as_array().is_some_and(|a| !a.is_empty()),
        "{sheet}"
    );
    // 4b: pull the NZB, the way a grab does.
    let nzb = http(d.port, &format!("/getnzb/{fetched_id}.nzb"));
    assert!(nzb.contains("<nzb"), "getnzb did not return an NZB: {nzb}");

    // Now ask for a size nothing could satisfy without eating the lot.
    let r = api(d.port, "mode=index_shrink_to&value=1");
    assert_eq!(r["status"], true, "{r}");
    assert!(
        r["protected_keys"].as_u64().unwrap() >= 4,
        "all four categories should have contributed keys: {r}"
    );
    // It cannot reach 1 byte while holding protected rows, and it must
    // say that rather than pretend.
    assert_eq!(r["reached"], false, "{r}");
    // And it must say it was STOPPED, not merely that it ran out of
    // estimate - the two look identical from `removed` alone, and only
    // the first means retrying is pointless.
    assert_eq!(r["blocked"], true, "{r}");
    let e = r["error"].as_str().unwrap_or_default();
    assert!(e.contains("protected"), "{r}");

    let left: Vec<String> = api(d.port, "mode=index_browse&limit=200&all=1")["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap_or_default().to_string())
        .collect();
    for (stem, why) in [
        (watched, "watchlisted"),
        (queued, "queued"),
        (owned, "already downloaded"),
        (opened, "opened in detail"),
        (fetched, "fetched via getnzb"),
    ] {
        assert!(
            left.contains(&stem.to_string()),
            "{why} release was evicted: {left:?}"
        );
    }
    // ...and the rows with no claim on them are gone, or the test proved
    // nothing.
    assert!(
        !left.contains(&junk_a.to_string()),
        "nothing was evicted at all: {left:?}"
    );
    assert!(
        !left.contains(&junk_b.to_string()),
        "nothing was evicted at all: {left:?}"
    );
}

/// A watch item that names a whole custom category (empty title) is the
/// only watchlist shape with no identity key of its own, and it used to
/// protect nothing at all: the per-title resolver hands back an empty
/// list for an empty title, so under size pressure the user's category
/// was evicted like anything else - the one thing they explicitly said
/// they were following.
#[test]
fn a_whole_category_watch_item_protects_the_whole_category() {
    // Two rounds of the same series: separate title keys, so this cannot
    // pass by protecting one key and calling it done.
    let hungary = "Formula1.2026.Round11.Hungary.Race.F1TV.WEB-DL.1080p.H265-MWR";
    let spa = "Formula1.2026.Round12.Spa.Race.F1TV.WEB-DL.1080p.H265-MWR";
    let junk_a = "Junk.Movie.2001.1080p.BluRay.x264-GRP";
    let junk_b = "Rubbish.Show.S09E09.1080p.WEB.x264-GRP";

    let cats = r#"[{"slug":"formula-1","name":"Formula 1",
                    "match":"^formula\\.?1\\.","base":"movie"}]"#;
    let dir = scratch(
        "wholecat",
        // An empty title is how the UI says "the whole category".
        &format!(
            r#"{{"custom_categories":{cats},
                 "watchlist":[{{"id":1,"kind":"formula-1","title":"",
                                "target_quality":"1080p","enabled":true}}]}}"#
        ),
    );
    seed_index(&dir, &[hungary, spa, junk_a, junk_b]);
    // Classify the seeded rows the way the daemon's own ingest would with
    // these categories installed - same JSON, so the two cannot drift.
    {
        let mut ix = nzbkit::index::Index::open(&dir.join("index.db")).unwrap();
        ix.set_custom(serde_json::from_str(cats).unwrap());
        ix.reclassify_custom().unwrap();
    }

    let d = serve(&dir);
    assert_eq!(stats(d.port)["releases"].as_u64().unwrap(), 4);
    // The category really is installed, or the rest proves nothing.
    let all = api(d.port, "mode=index_browse&limit=200&all=1");
    let f1 = all["results"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["kind"] == "formula-1")
        .count();
    assert_eq!(
        f1, 2,
        "both rounds must be classified into the category: {all}"
    );

    let r = api(d.port, "mode=index_shrink_to&value=1");
    assert_eq!(r["status"], true, "{r}");
    assert!(
        r["protected_keys"].as_u64().unwrap() >= 2,
        "every title key in the watched category should be protected: {r}"
    );
    let left: Vec<String> = api(d.port, "mode=index_browse&limit=200&all=1")["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap_or_default().to_string())
        .collect();
    for stem in [hungary, spa] {
        assert!(
            left.contains(&stem.to_string()),
            "a watched category row was evicted: {left:?}"
        );
    }
    // ...and the unclaimed rows are gone, or nothing was evicted at all
    // and the survival above means nothing.
    assert!(
        !left.contains(&junk_a.to_string()),
        "nothing was evicted at all: {left:?}"
    );
    assert!(
        !left.contains(&junk_b.to_string()),
        "nothing was evicted at all: {left:?}"
    );
}

/// The bug that made this feature unusable, pinned end to end.
///
/// SQLite's DELETE hands pages to the freelist without shortening the
/// file, so the on-disk size cannot fall until a compact runs. The daemon
/// originally compared the user's cap against that on-disk size, which
/// meant a database that had just been emptied was STILL over its cap on
/// the very next scan pass - so automatic eviction re-fired forever,
/// taking the write lock and re-arming the compact every time.
///
/// The cap is measured against `live_bytes` instead: the size the file
/// would have once compacted. This test sets a cap that the file does not
/// fit but the live content does, which is precisely the window the old
/// code got wrong.
#[test]
fn the_cap_is_measured_against_live_content_not_the_unshrunk_file() {
    // Big enough that deleting everything is certain to free whole pages -
    // a handful of rows can vanish inside already-partial pages and leave
    // no freelist at all.
    let stems: Vec<String> = (0..300)
        .map(|i| format!("Filler{i}.Show.S01E01.1080p.WEB.x264-GRP"))
        .collect();
    let refs: Vec<&str> = stems.iter().map(String::as_str).collect();
    let dir = scratch("livebytes", "{}");
    seed_index(&dir, &refs);
    let d = serve(&dir);
    assert_eq!(
        stats(d.port)["releases"].as_u64().unwrap(),
        stems.len() as u64
    );

    let r = api(d.port, "mode=index_shrink_to&value=1");
    assert_eq!(r["status"], true, "{r}");
    assert!(
        r["removed"].as_u64().unwrap() > 0,
        "nothing was pruned: {r}"
    );

    // Read the two sizes before the idle loop's compact can close the gap.
    let s = stats(d.port);
    let db = s["db_bytes"].as_u64().unwrap();
    let live = s["live_bytes"].as_u64().unwrap();
    assert!(
        live < db,
        "a big delete must leave a freelist gap before the compact: {s}"
    );

    // A cap between the two: too small for the file as it sits on disk,
    // comfortably big for what is actually in it.
    let cap = (db + live) / 2;
    assert!(
        cap > live && cap < db,
        "test fixture did not straddle the gap: {s}"
    );
    assert_eq!(
        cfg(d.port, "index_max_bytes", &cap.to_string())["status"],
        true
    );
    assert_eq!(
        stats(d.port)["over_cap"],
        false,
        "over_cap must follow live content, not the space a compact will reclaim"
    );

    // And the eviction pass agrees: there is nothing to do, rather than
    // another futile round of deleting from an already-empty index.
    assert_eq!(cfg(d.port, "index_evict", "1")["status"], true);
    let r = api(d.port, "mode=index_evict_now");
    assert_eq!(r["status"], true, "{r}");
    assert_eq!(
        r["removed"], 0,
        "it kept evicting an index already under its cap: {r}"
    );
    assert_eq!(r["reached"], true, "{r}");
    assert_eq!(r["blocked"], false, "{r}");
}

/// These modes delete user data. They belong to the full API key, not the
/// add-only NZB key an *arr is handed - which is exactly the escalation
/// the /jsonrpc tier check was added to close.
#[test]
fn the_new_modes_reject_an_add_only_key() {
    let dir = scratch(
        "keys",
        r#"{"apikey":"FULLKEY0000000000000000","nzbkey":"ADDONLYKEY0000000000000"}"#,
    );
    seed_index(&dir, &["Alpha.Show.S01E01.1080p.WEB.x264-GRP"]);
    let d = serve(&dir);

    // The add-only key IS valid - it opens the add surface. Anything else
    // it is refused for is about tier, not a bad key.
    let v = api(d.port, "mode=version&apikey=ADDONLYKEY0000000000000");
    assert!(
        v["version"].is_string(),
        "the nzbkey should pass mode=version: {v}"
    );

    for mode in ["index_shrink_to&value=1", "index_evict_now"] {
        let r = api(
            d.port,
            &format!("mode={mode}&apikey=ADDONLYKEY0000000000000"),
        );
        assert_eq!(r["status"], false, "{mode} accepted the add-only key: {r}");
        assert_eq!(r["error"], "API Key Incorrect", "{mode}: {r}");
        // No key at all is refused too.
        let r = api(d.port, &format!("mode={mode}"));
        assert_eq!(r["status"], false, "{mode} ran unauthenticated: {r}");
    }
    // Nothing was deleted by any of those attempts.
    assert_eq!(
        api(d.port, "mode=index_stats&apikey=FULLKEY0000000000000000")["releases"]
            .as_u64()
            .unwrap(),
        1
    );

    // The full key reaches them.
    let r = api(
        d.port,
        "mode=index_evict_now&apikey=FULLKEY0000000000000000",
    );
    // Eviction is off and no cap is set, so this refuses on POLICY - but
    // it is a policy refusal, not an auth one.
    assert_eq!(r["status"], false, "{r}");
    assert_ne!(r["error"], "API Key Incorrect", "{r}");
}

/// Minimal percent-encoding for the one place a test puts a parse key
/// (which carries ':' and spaces) into a query string.
fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
