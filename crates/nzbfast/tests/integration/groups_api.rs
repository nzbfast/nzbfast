//! "+ Add all matches" (`mode=groups_add_matching`), against the real
//! binary.
//!
//! Two bugs this pins, both found before 1.0.9:
//!
//!  * the rewritten scan list was applied to the LIVE daemon and never
//!    written to settings.json, so a bulk subscribe the UI reported as
//!    "Added N groups" was gone on the next restart;
//!  * the handler ignored the `sub=1` ("Only groups I scan") filter the
//!    dashboard's shared query builder always sends, so the button acted
//!    on a wider set than the rows on screen.
//!
//! The catalogue normally comes from `LIST ACTIVE` on the primary server;
//! here the on-disk cache is pre-seeded instead, which is the same code
//! path a restart takes and needs no NNTP server.

use crate::scratch;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;

use crate::harness::Daemon;

/// Response body of a GET against the daemon (headers stripped).
///
/// A connection REFUSED before it produced a single byte is retried. That
/// is not the same as tolerating a bad answer: tiny_http's honest reply
/// when it cannot start a thread for a new connection is to drop the
/// socket unread, and with our request still in its receive buffer the
/// kernel turns that into an RST - which arrives here as ECONNRESET. A
/// full `cargo test` runs these suites in parallel, each test with a whole
/// daemon behind it, so `thread::Builder::spawn` really does hit EAGAIN,
/// and a test then failed on a refusal to serve rather than on anything it
/// asserts. Once a byte has come back it is an answer, and it is returned
/// (or fails) exactly as it arrived - a truncated response must never be
/// retried away.
fn http(port: u16, req: &str) -> String {
    let mut last = String::new();
    for attempt in 0..5u32 {
        match http_once(port, req) {
            Ok(out) => return out,
            Err(e) => {
                last = e.to_string();
                std::thread::sleep(std::time::Duration::from_millis(
                    100 * u64::from(attempt) + 50,
                ));
            }
        }
    }
    panic!("daemon on :{port} never served {req}: {last}");
}

/// One attempt. Returns Err ONLY when the daemon produced nothing at all;
/// a partial or malformed response is data, and is handed back for the
/// caller's assertions to judge.
fn http_once(port: u16, req: &str) -> std::io::Result<String> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    write!(
        s,
        "GET {req} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )?;
    let mut out = String::new();
    // Zero bytes back is a refusal to serve, however the peer
    // phrased it: an RST (Err) when our request was never read off
    // the receive buffer, a plain FIN (Ok) when it was read and then
    // dropped unanswered. Neither carries anything to judge, so both
    // are retried. The moment ANY byte arrives it is an answer and is
    // returned exactly as it came - errors included - because a
    // truncated body must never be retried away.
    let read = s.read_to_string(&mut out);
    if out.is_empty() {
        return Err(read.err().unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed without answering",
            )
        }));
    }
    Ok(out.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
}

fn api(port: u16, q: &str) -> serde_json::Value {
    let body = http(port, &format!("/api?output=json&{q}"));
    serde_json::from_str(&body).unwrap_or_else(|e| panic!("bad JSON for {q:?}: {e}\n{body}"))
}

/// The groups the seeded catalogue holds. Deliberately a mix: seven
/// `alt.binaries.*` and two that are not, so a pattern can match a
/// strict subset.
const CATALOGUE: &[(&str, u64)] = &[
    ("alt.binaries.teevee", 900_000),
    ("alt.binaries.moovee", 800_000),
    ("alt.binaries.sounds.mp3", 700_000),
    ("alt.binaries.e-books", 60_000),
    ("alt.binaries.comics.dcp", 50_000),
    ("alt.binaries.multimedia", 40_000),
    ("alt.binaries.hdtv", 30_000),
    ("rec.autos.sport.f1", 5_000),
    ("uk.rec.cars.modified", 900),
];

/// A scratch install: config, a settings file (so this reads as an
/// EXISTING install and no first-run API key is minted - auth is not what
/// these tests are about), and a pre-seeded group catalogue cache.
fn scratch(name: &str) -> scratch::ScratchDir {
    let dir = std::env::temp_dir().join(format!("nzbfast-groupsapi-{}-{name}", std::process::id()));
    let dir = scratch::ScratchDir::attach(&dir);
    std::fs::write(dir.join("config.json"), "{\"servers\":[]}").unwrap();
    std::fs::write(dir.join("settings.json"), "{}").unwrap();
    // groups.tsv lives beside the index db (Daemon::groups_cache_path).
    let mut tsv = String::from("#nzbfast-groups\t3\t1700000000\n");
    for (n, posts) in CATALOGUE {
        tsv.push_str(&format!("{n}\t{posts}\t0\ty\t\n"));
    }
    std::fs::write(dir.join("groups.tsv"), tsv).unwrap();
    dir
}

/// Launch `nzbfast serve` against `dir` and wait for the catalogue cache
/// to be loaded (it is parsed off the hot path, after the listener
/// binds - so `harness::serve_blocking`'s banner is necessary but not
/// sufficient here).
fn serve(dir: &Path) -> Daemon {
    let d = crate::harness::serve_blocking(dir, |port| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        cmd.env("NZBFAST_NO_ENRICH", "1")
            .env_remove("NZBFAST_OPEN")
            .arg("--config")
            .arg(dir.join("config.json"))
            .arg("serve")
            // Loopback only. These suites never need LAN reach, and binding
            // 0.0.0.0 makes the macOS firewall raise a prompt for every freshly
            // built test binary, which is a new path on every run.
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--index-db")
            .arg(dir.join("index.db"));
        cmd
    });
    for _ in 0..100 {
        let j = api(d.port, "mode=groups&limit=1");
        if j["count"].as_u64().unwrap_or(0) as usize == CATALOGUE.len() {
            return d;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("catalogue cache never loaded\n{}", d.log());
}

/// `index_groups` as the daemon reports it live.
fn live_groups(port: u16) -> Vec<String> {
    let j = api(port, "mode=get_config");
    j["config"]["nzbfast"]["index_groups"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .map(|v| v.as_str().unwrap_or("").to_string())
        .collect()
}

/// `index_groups` as it is stored on disk - what the NEXT start reads.
fn saved_groups(dir: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(dir.join("settings.json")).unwrap_or_default();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
    match v.get("index_groups").and_then(|g| g.as_array()) {
        Some(a) => a
            .iter()
            .map(|v| v.as_str().unwrap_or("").to_string())
            .collect(),
        None => Vec::new(),
    }
}

/// BUG (HIGH): the handler applied the new scan list to the live daemon
/// and threw away the value it needed to persist, so the bulk subscribe
/// the UI reported as a success did not survive a restart.
#[test]
fn add_all_matches_survives_a_restart() {
    let dir = scratch("persist");
    let r = serve(&dir);

    // Start from one hand-picked group, the way a user who has been
    // clicking rows would.
    let j = api(
        r.port,
        "mode=config&name=index_groups&value=alt.binaries.teevee",
    );
    assert_eq!(j["status"], true, "seeding index_groups failed: {j}");

    // "+ Add all matches" for every binaries group.
    let j = api(r.port, "mode=groups_add_matching&q=alt.binaries.*");
    assert_eq!(j["status"], true, "bulk add rejected: {j}");
    assert_eq!(j["matched"], 7, "wrong match count: {j}");
    assert_eq!(
        j["added"], 6,
        "teevee was already there, the other six are new: {j}"
    );
    assert_eq!(j["capped"], false, "{j}");

    // Live state is right (it always was).
    let mut live = live_groups(r.port);
    live.sort();
    assert_eq!(live.len(), 7, "live scan list wrong: {live:?}");

    // THE REGRESSION: it must also be on disk before the restart.
    let mut saved = saved_groups(&dir);
    saved.sort();
    assert_eq!(saved, live, "bulk add was never persisted to settings.json");

    // ...and the restart must come back up with it. Close this daemon,
    // keeping its log for the assertions below.
    let _r_log = r.stop();
    let r2 = serve(&dir);
    let mut after = live_groups(r2.port);
    after.sort();
    assert_eq!(after, saved, "bulk subscribe was lost across a restart");
    assert!(
        after.contains(&"alt.binaries.hdtv".to_string()),
        "{after:?}"
    );
    assert!(
        after.contains(&"alt.binaries.teevee".to_string()),
        "{after:?}"
    );

    drop(r2);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The other half of the same write: adding must not drop the other keys
/// in settings.json. `save_setting` serialises a read-modify-write for
/// exactly this reason, so the fix goes through it rather than writing
/// the file itself.
#[test]
fn add_all_matches_keeps_the_rest_of_settings() {
    let dir = scratch("other-keys");
    let r = serve(&dir);

    api(r.port, "mode=config&name=index_interval_secs&value=900");
    let j = api(r.port, "mode=groups_add_matching&q=alt.binaries.*");
    assert_eq!(j["status"], true, "{j}");

    let text = std::fs::read_to_string(dir.join("settings.json")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        v["index_interval_secs"], 900,
        "bulk add clobbered another setting: {text}"
    );
    assert!(
        v["index_groups"].as_array().is_some_and(|a| a.len() == 7),
        "{text}"
    );

    drop(r);
    let _ = std::fs::remove_dir_all(&dir);
}

/// BUG (MEDIUM): `sub=1` is the dashboard's "Only groups I scan" toggle,
/// and gbQS() puts it on BOTH the list request and the bulk-add request.
/// The handler hard-coded `only: None`, so with the toggle on the button
/// added every matching group on the server while the user was looking at
/// the two they already scan.
#[test]
fn add_all_matches_honours_the_only_i_scan_filter() {
    let dir = scratch("subfilter");
    let r = serve(&dir);

    let j = api(
        r.port,
        "mode=config&name=index_groups&value=alt.binaries.teevee,alt.binaries.moovee",
    );
    assert_eq!(j["status"], true, "{j}");

    // What the user is looking at with the toggle on: two rows.
    let list = api(r.port, "mode=groups&q=alt.binaries.*&sub=1&limit=60");
    assert_eq!(list["total"], 2, "list request: {list}");

    // The button must act on exactly those two - both already scanned, so
    // nothing to add. Before the fix this reported matched=7, added=5.
    let j = api(r.port, "mode=groups_add_matching&q=alt.binaries.*&sub=1");
    assert_eq!(j["status"], true, "{j}");
    assert_eq!(
        j["matched"], list["total"],
        "bulk add matched a different set than the list: {j}"
    );
    assert_eq!(
        j["added"], 0,
        "bulk add subscribed groups that were not on screen: {j}"
    );
    assert_eq!(
        live_groups(r.port).len(),
        2,
        "scan list grew behind the filter"
    );

    // Toggle off, same query: now it is the whole seven, as before.
    let j = api(r.port, "mode=groups_add_matching&q=alt.binaries.*");
    assert_eq!(j["matched"], 7, "unfiltered bulk add regressed: {j}");
    assert_eq!(j["added"], 5, "{j}");

    drop(r);
    let _ = std::fs::remove_dir_all(&dir);
}
