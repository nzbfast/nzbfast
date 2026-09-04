#![cfg(feature = "indexer")]
//! M12 gate: the newznab facade - Sonarr/Radarr can use nzbfast as an
//! INDEXER (caps/search/tvsearch → items → /getnzb), and the continuous
//! scan loop populates the index from a live (mock) news server.

use crate::scratch;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;

use crate::harness::serve;
use nzbkit::mock::{Chaos, MockServer, OverRow};
use nzbkit::nntp::OverEntry;

/// (status, body) of a GET against the daemon.
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
fn http_get(port: u16, req: &str) -> (u16, String) {
    let mut last = String::new();
    for attempt in 0..5u32 {
        match http_get_once(port, req) {
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
fn http_get_once(port: u16, req: &str) -> std::io::Result<(u16, String)> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    write!(
        s,
        "GET {req} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
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
    let status: u16 = out
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    Ok((
        status,
        out.split("\r\n\r\n").nth(1).unwrap_or("").to_string(),
    ))
}

/// Mark a scratch install as having the built-in indexer switched on.
/// settings.json lives beside the config file, and its presence also
/// marks the install as not-first-run, which these keyless suites
/// already arrange for themselves with NZBFAST_OPEN.
fn index_enabled(cfg: &Path) {
    std::fs::write(
        cfg.with_file_name("settings.json"),
        "{\"index_enabled\": true}",
    )
    .unwrap();
}

fn over(number: u64, subject: &str, msgid: &str, bytes: u64) -> OverEntry {
    OverEntry {
        number,
        subject: subject.into(),
        from: "poster@x".into(),
        message_id: msgid.into(),
        bytes,
        date: 0,
    }
}

/// Same, but carrying the article's own Date - which is what makes the
/// release's upload time differ from the time we indexed it.
fn over_dated(number: u64, subject: &str, msgid: &str, bytes: u64, date: i64) -> OverEntry {
    OverEntry {
        date,
        ..over(number, subject, msgid, bytes)
    }
}

/// How long [`settle_index`] will wait for the daemon's startup index
/// open to finish. See `integration/nzblnk.rs`'s copy of this constant
/// for the measurement it is based on (60 s is an 11x margin over the
/// longest settle seen under 8x concurrent load).
const SETTLE_BUDGET: std::time::Duration = std::time::Duration::from_secs(60);

/// Block until the daemon's index will answer a read.
///
/// `searches_that_miss_reach_the_d3_readout` pre-seeds its database with
/// `Index::open` before the daemon starts, then reads it back over
/// `t=tvsearch` and `mode=index_search` moments after the daemon's own
/// port is ready. Both go through `Daemon::index_read_checked`, which
/// before the daemon's first read-write open falls back to the write
/// mutex on a BOUNDED 2 s wait and reports
/// `{"busy":true,"error":"the index is busy - try again in a moment"}`
/// rather than parking an HTTP worker on it (TODO 143's second half,
/// TODO 166) - the classic `t=` newznab facade wraps the same refusal as
/// an `<error>` element instead, but it is the identical seam and the
/// identical race. Under box load that open is still running when this
/// file's first read arrives, and the assertions below admit only the
/// content the seeded rows actually carry.
///
/// Mirrors `integration/nzblnk.rs::settle_index` in seam, probe mode and
/// budget, and is duplicated rather than shared because `http_get`
/// itself is already duplicated per test module in this crate. `key`
/// is the `&apikey=...` this daemon needs, or empty where it has none.
/// An auth refusal PANICS rather than returning: a probe the
/// daemon answers "API Key Incorrect" carries no `busy` flag, so it
/// would exit the loop at once and disable the settle in silence.
///
/// UNLIKE nzblnk.rs's copy, the probe's `q` is left EMPTY rather than a
/// distinctive placeholder string: `m_index_search` calls
/// `d.note_search(..)` on every non-busy answer, and this file's own
/// test asserts on the exact d3 search-miss readout - a non-empty probe
/// query showed up in it as a third, unwanted miss the first time this
/// was tried. `note_search` returns immediately on an empty query
/// (`crates/nzbfast-daemon/src/searchlog.rs`'s own early-out), so this
/// settles the seam without writing anything the readout would see.
fn settle_index(port: u16, key: &str) {
    let started = std::time::Instant::now();
    loop {
        let last = http_get(port, &format!("/api?mode=index_search&q={key}&output=json")).1;
        assert!(
            !last.contains("API Key"),
            "the settle probe was refused, so it was never settling anything:\n{last}"
        );
        let v: serde_json::Value = serde_json::from_str(&last).unwrap_or_default();
        if v["busy"] != true {
            return;
        }
        assert!(
            started.elapsed() < SETTLE_BUDGET,
            "the index never settled in {SETTLE_BUDGET:?}:\n{last}"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// One JSON API call, with a `busy` refusal WAITED OUT rather than read
/// as this call's own answer.
///
/// [`settle_index`] waits out the daemon's STARTUP index open and says
/// nothing about any later call. This file's two WRITES -
/// `mode=search_log_clear` and `mode=wall_fix` - are refused whenever
/// the write mutex is still held after `HTTP_INDEX_WAIT`, which answers
/// `{"status": false, "busy": true, ...}` where the assertions want
/// `"status":true`. `wall.rs` went on flaking for a day on exactly that
/// after its READ half was fixed (3 Sep 2026), so the write half is
/// covered here before it is seen rather than after.
///
/// A refused write is safe to repeat: `index_write_checked`'s `Err`
/// means the mutex was never taken, so nothing was written.
fn api_settled(what: &str, send: impl Fn() -> (u16, String)) -> serde_json::Value {
    let started = std::time::Instant::now();
    loop {
        let (code, body) = send();
        assert_eq!(code, 200, "{what}: {body}");
        let v: serde_json::Value =
            serde_json::from_str(&body).unwrap_or_else(|e| panic!("{what}: {e}\n{body}"));
        if v["busy"] != true {
            return v;
        }
        assert!(
            started.elapsed() < SETTLE_BUDGET,
            "the index was still busy after {SETTLE_BUDGET:?}: {what}\n{body}"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Block until the search-miss readout accounts for `want` searches,
/// and hand back the body that said so.
///
/// `Daemon::search_log_tick` drains the in-memory search buffer into
/// the table on its own timer (`crates/nzbfast-tasks/src/tasks.rs`, one
/// second here through the documented debug seam), at a phase no caller
/// controls, and `m_search_misses`
/// (`crates/nzbfast-api/src/api/index.rs`) serves the TABLE and never
/// the buffer. So a tick landing between two of this file's requests
/// publishes a readout that is real, current and PARTIAL.
///
/// That is what made `searches_that_miss_reach_the_d3_readout` flaky:
/// it waited for one miss to appear BY NAME and then asserted exact
/// aggregate counts, so a tick between the last tvsearch and the
/// index_search after it let the test read a half-flushed table and
/// fail on the wall miss still sitting in memory. Reproduced 31 Aug
/// 2026 at 1 failure in 192 runs at 64-way concurrency, with the
/// readout naming its own cause - `"searches":4` and no
/// `"dune part three"` row. Nothing is wrong with the daemon: the
/// merge is additive, so the very next tick completed it. The test
/// stopped waiting for a state it was about to assert.
///
/// `searches` is the predicate because it is the one total this test
/// controls exactly. Flushes merge additively, and nothing else on
/// these ports records a search - the settle probe above sends an
/// empty query, which `note_search` drops - so it rises to the number
/// of recorded searches and stops there. Waiting on the value the
/// assertions need is a bound that holds by construction, rather than
/// a guess at how long a starved box takes to get there.
///
/// `key` is the `&apikey=...` this daemon needs, matching
/// [`settle_index`] above; the budget is shared with it too.
fn settle_searches(port: u16, key: &str, want: u64) -> String {
    let started = std::time::Instant::now();
    loop {
        let (code, last) = http_get(
            port,
            &format!("/api?mode=search_misses{key}&output=json&limit=20"),
        );
        assert_eq!(code, 200, "{last}");
        let v: serde_json::Value = serde_json::from_str(&last).unwrap_or_default();
        if v["searches"].as_u64() == Some(want) {
            return last;
        }
        assert!(
            started.elapsed() < SETTLE_BUDGET,
            "the readout never reached {want} searches in {SETTLE_BUDGET:?}:\n{last}"
        );
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn newznab_caps_search_and_getnzb() {
    let dir = std::env::temp_dir().join(format!("nzbfast-nn-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Seed a complete 2-file release + an incomplete one directly.
    let db = dir.join("index.db");
    {
        let mut ix = nzbkit::index::Index::open(&db).unwrap();
        ix.ingest(
            "alt.binaries.teevee",
            &[
                over(
                    1,
                    "\"Show.Name.S01E02.1080p.rar\" yEnc (1/1)",
                    "<a1@x>",
                    1000,
                ),
                over(
                    2,
                    "\"Show.Name.S01E02.1080p.par2\" yEnc (1/1)",
                    "<a2@x>",
                    200,
                ),
                over(3, "\"Partial.Movie.2026.rar\" yEnc (1/2)", "<b1@x>", 1000),
            ],
            1_700_000_000,
        )
        .unwrap();
    }

    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        "{\"servers\":[{\"host\":\"127.0.0.1\",\"port\":1,\"tls\":false}]}",
    )
    .unwrap();
    // The newznab facade IS the built-in index published over newznab,
    // and that indexer's master switch defaults OFF - a daemon with it
    // off answers every t= with <error code="101"> on purpose. These
    // tests seed a database and then ask the facade about it, so they
    // are the "switched on" case and have to say so.
    index_enabled(&cfg);
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        // The daemon mints an API key on a genuinely first run (see
        // serve::first_run_apikey). These suites drive it keyless on purpose,
        // so they take the same deliberate opt-out an operator would.
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            // Loopback only. These suites never need LAN reach, and binding
            // 0.0.0.0 makes the macOS firewall raise a prompt for every freshly
            // built test binary, which is a new path on every run.
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--index-db")
            .arg(&db);
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // Auth required.
        let (code, _) = http_get(port, "/api?t=caps");
        assert_eq!(code, 401);
        // Caps.
        let (code, body) = http_get(port, "/api?t=caps&apikey=sekrit");
        assert_eq!(code, 200);
        assert!(
            body.contains("<caps>") && body.contains("tv-search"),
            "{body}"
        );
        // Search: only the COMPLETE release is offered, categorized TV.
        let (_, body) = http_get(port, "/newznab/api?t=search&q=show&apikey=sekrit");
        assert!(body.contains("Show.Name.S01E02.1080p"), "{body}");
        assert!(body.contains("value=\"5000\""), "{body}");
        assert!(!body.contains("Partial.Movie"), "{body}");
        // tvsearch with season/ep params finds it too.
        let (_, body) = http_get(
            port,
            "/api?t=tvsearch&q=show+name&season=1&ep=2&apikey=sekrit",
        );
        assert!(body.contains("Show.Name.S01E02"), "{body}");
        // Follow the enclosure link → NZB with the seeded segment ids.
        let link = body
            .split("<link>")
            .nth(1)
            .and_then(|r| r.split("</link>").next())
            .expect("item link")
            .replace("&amp;", "&");
        let path = link
            .split(&format!(":{port}"))
            .nth(1)
            .expect("relative path");
        let (code, nzb) = http_get(port, path);
        assert_eq!(code, 200, "{nzb}");
        assert!(nzb.contains("<nzb"), "{nzb}");
        assert!(nzb.contains("a1@x") && nzb.contains("a2@x"), "{nzb}");
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn scan_loop_populates_index_live() {
    let dir = std::env::temp_dir().join(format!("nzbfast-nnscan-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Mock server with a header plane: two-file complete release.
    let rows = vec![
        OverRow {
            number: 10,
            subject: "\"Live.Show.S03E07.720p.rar\" yEnc (1/1)".into(),
            from: "poster@x".into(),
            message_id: "<lv1@x>".into(),
            bytes: 5000,
        },
        OverRow {
            number: 11,
            subject: "\"Live.Show.S03E07.720p.par2\" yEnc (1/1)".into(),
            from: "poster@x".into(),
            message_id: "<lv2@x>".into(),
            bytes: 500,
        },
    ];
    let srv = MockServer::start_full(
        Default::default(),
        Default::default(),
        rows,
        Chaos::default(),
    )
    .await;

    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false}}]}}",
            srv.addr.ip(),
            srv.addr.port()
        ),
    )
    .unwrap();
    let db = dir.join("index.db");
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
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
            .arg(&db)
            .arg("--index-groups")
            .arg("mock.group")
            .arg("--index-interval")
            .arg("30");
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // The first scan pass should land the release within seconds.
        for i in 0..100 {
            let (_, body) = http_get(port, "/api?t=search&q=live+show");
            if body.contains("Live.Show.S03E07.720p") {
                assert!(body.contains("value=\"5000\""), "{body}");
                return;
            }
            if i == 99 {
                panic!("scan loop never indexed the release:\n{body}");
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    })
    .await
    .unwrap();
}

/// Number of `<item>` elements in a feed.
fn items(body: &str) -> usize {
    body.matches("<item>").count()
}

/// Every item's `<guid>` in a feed, in document order - the one field a
/// deep-paging walk can use to tell releases apart across pages.
fn guids(body: &str) -> Vec<String> {
    body.match_indices("<guid isPermaLink=\"false\">")
        .filter_map(|(i, m)| {
            let start = i + m.len();
            body[start..].split("</guid>").next().map(str::to_string)
        })
        .collect()
}

/// The `<newznab:response>` element's `total="…"` attribute.
fn total_attr(body: &str) -> usize {
    body.split("total=\"")
        .nth(1)
        .and_then(|r| r.split('"').next())
        .and_then(|t| t.parse().ok())
        .unwrap_or_else(|| panic!("no total attr in response: {body}"))
}

/// [`http_get`] with extra request headers - the reverse-proxy hops.
fn http_get_hdrs(port: u16, req: &str, hdrs: &str) -> (u16, String) {
    let mut last = String::new();
    for attempt in 0..5u32 {
        let once = || -> std::io::Result<(u16, String)> {
            let mut s = TcpStream::connect(("127.0.0.1", port))?;
            write!(
                s,
                "GET {req} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{hdrs}Connection: close\r\n\r\n"
            )?;
            let mut out = String::new();
            let n = s.read_to_string(&mut out)?;
            if n == 0 {
                return Err(std::io::Error::other("empty"));
            }
            let code = out
                .split_whitespace()
                .nth(1)
                .and_then(|c| c.parse().ok())
                .unwrap_or(0);
            let body = out
                .split_once("\r\n\r\n")
                .map(|(_, b)| b.to_string())
                .unwrap_or_default();
            Ok((code, body))
        };
        match once() {
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

/// The numeric categories are the standard newznab tree in BOTH
/// directions: `cat=` selects the kind it names, and the id reported back
/// is the one that kind would have been asked for. Software (PC, 4000)
/// was the regression - it filtered and reported as Other, so a client
/// asking for cat=4000 saw no software at all, and software that did come
/// back was labelled 2000/8000.
#[tokio::test(flavor = "multi_thread")]
async fn newznab_categories_follow_the_standard_tree() {
    let dir = std::env::temp_dir().join(format!("nzbfast-nncat-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // One complete release per kind we carry an id for.
    let db = dir.join("index.db");
    {
        let mut ix = nzbkit::index::Index::open(&db).unwrap();
        ix.ingest(
            "alt.binaries.misc",
            &[
                over(
                    1,
                    "\"CCleaner.Pro.Plus.v6.36.x64.Setup.rar\" yEnc (1/1)",
                    "<s1@x>",
                    1000,
                ),
                over(
                    2,
                    "\"CCleaner.Pro.Plus.v6.36.x64.Setup.par2\" yEnc (1/1)",
                    "<s2@x>",
                    200,
                ),
                over(
                    3,
                    "\"Cat.Show.S04E01.1080p.rar\" yEnc (1/1)",
                    "<t1@x>",
                    1000,
                ),
                over(
                    4,
                    "\"Cat.Show.S04E01.1080p.par2\" yEnc (1/1)",
                    "<t2@x>",
                    200,
                ),
                over(
                    5,
                    "\"Cat.Movie.2019.1080p.BluRay.rar\" yEnc (1/1)",
                    "<m1@x>",
                    1000,
                ),
                over(
                    6,
                    "\"Cat.Movie.2019.1080p.BluRay.par2\" yEnc (1/1)",
                    "<m2@x>",
                    200,
                ),
            ],
            1_700_000_000,
        )
        .unwrap();
    }

    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        "{\"servers\":[{\"host\":\"127.0.0.1\",\"port\":1,\"tls\":false}]}",
    )
    .unwrap();
    // The newznab facade IS the built-in index published over newznab,
    // and that indexer's master switch defaults OFF - a daemon with it
    // off answers every t= with <error code="101"> on purpose. These
    // tests seed a database and then ask the facade about it, so they
    // are the "switched on" case and have to say so.
    index_enabled(&cfg);
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--index-db")
            .arg(&db);
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // cat=4000 selects software, and software reports 4000 back.
        let (_, body) = http_get(port, "/api?t=search&cat=4000");
        assert_eq!(items(&body), 1, "{body}");
        assert!(body.contains("CCleaner.Pro.Plus"), "{body}");
        assert!(body.contains("value=\"4000\""), "{body}");

        // A PC SUBcategory (4050 = PC/Games) rides its parent's thousand.
        let (_, body) = http_get(port, "/api?t=search&cat=4050");
        assert!(body.contains("CCleaner.Pro.Plus"), "{body}");

        // The other two kinds keep their own ids, and no longer swallow
        // software the way the old `_ => other` arm did.
        let (_, body) = http_get(port, "/api?t=search&cat=5000,5040");
        assert_eq!(items(&body), 1, "{body}");
        assert!(
            body.contains("Cat.Show.S04E01") && body.contains("value=\"5000\""),
            "{body}"
        );
        let (_, body) = http_get(port, "/api?t=search&cat=2000");
        assert_eq!(items(&body), 1, "{body}");
        assert!(
            body.contains("Cat.Movie.2019") && body.contains("value=\"2000\""),
            "{body}"
        );

        // Categories we carry nothing for (3000 Audio, 7000 Books) are an
        // empty feed - never a silently unfiltered one.
        for cat in ["3000", "7000", "6000", "1000"] {
            let (code, body) = http_get(port, &format!("/api?t=search&cat={cat}"));
            assert_eq!(code, 200, "{body}");
            assert_eq!(items(&body), 0, "cat={cat} answered with items:\n{body}");
        }

        // No cat at all still means no filter: all three come back.
        let (_, body) = http_get(port, "/api?t=search");
        assert_eq!(items(&body), 3, "{body}");

        // With no cat the OPERATION carries the kind, and the accepted
        // alias spellings mean the same operation. `t=moviesearch` and
        // `t=tv-search` used to pass dispatch but miss the kind
        // fallback, answering unfiltered - a movie search holding TV
        // (Codex sweep 5 Aug M11).
        for t in ["movie", "moviesearch"] {
            let (_, body) = http_get(port, &format!("/api?t={t}"));
            assert_eq!(items(&body), 1, "t={t} was not movie-filtered: {body}");
            assert!(body.contains("Cat.Movie.2019"), "t={t}: {body}");
            assert!(!body.contains("Cat.Show.S04E01"), "t={t}: {body}");
        }
        for t in ["tvsearch", "tv-search"] {
            let (_, body) = http_get(port, &format!("/api?t={t}"));
            assert_eq!(items(&body), 1, "t={t} was not tv-filtered: {body}");
            assert!(body.contains("Cat.Show.S04E01"), "t={t}: {body}");
            assert!(!body.contains("Cat.Movie.2019"), "t={t}: {body}");
        }

        // Caps advertise PC alongside the rest, so a client knows to ask.
        let (_, caps) = http_get(port, "/api?t=caps");
        assert!(
            caps.contains(r#"<category id="4000" name="PC"/>"#),
            "{caps}"
        );
    })
    .await
    .unwrap();
}

/// The pubDate of the feed item whose title contains `needle`.
fn pubdate_of(body: &str, needle: &str) -> String {
    for item in body.split("<item>").skip(1) {
        let item = item.split("</item>").next().unwrap_or("");
        if item.contains(needle) {
            return item
                .split("<pubDate>")
                .nth(1)
                .and_then(|r| r.split("</pubDate>").next())
                .unwrap_or_default()
                .to_string();
        }
    }
    panic!("no item for {needle} in feed:\n{body}");
}

/// A feed item is dated when it was UPLOADED, not when we indexed it.
///
/// Sonarr and Radarr take a release's age straight from pubDate and
/// reject on it twice: against the provider's retention, and against the
/// minimum-age hold that gives a bad post time to be replaced before they
/// grab it. Dating everything "now" makes a five-year-old backfilled
/// release look minutes old, so the minimum-age hold never fires and
/// retention never trims.
///
/// The other side of it: `first_posted` 0 is a live sentinel for a
/// release whose OVER Date did not parse, and dating THOSE 1970 reads as
/// infinitely old and gets them rejected wholesale. They fall back to
/// when we saw them.
#[tokio::test(flavor = "multi_thread")]
async fn feed_items_are_dated_by_upload_not_by_index_time() {
    let dir = std::env::temp_dir().join(format!("nzbfast-nndate-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // 14 Jul 2017, the upload date carried by the articles.
    const UPLOADED: i64 = 1_500_000_000;
    // 2 Feb 2026, when this install indexed them.
    const INDEXED: i64 = 1_770_000_000;

    let db = dir.join("index.db");
    {
        let mut ix = nzbkit::index::Index::open(&db).unwrap();
        // A backfilled release: posted years ago, indexed today.
        ix.ingest(
            "alt.binaries.teevee",
            &[
                over_dated(
                    1,
                    "\"Old.Show.S01E01.1080p.rar\" yEnc (1/1)",
                    "<o1@x>",
                    1000,
                    UPLOADED,
                ),
                over_dated(
                    2,
                    "\"Old.Show.S01E01.1080p.par2\" yEnc (1/1)",
                    "<o2@x>",
                    200,
                    UPLOADED,
                ),
            ],
            INDEXED,
        )
        .unwrap();
        // A release whose Date never parsed: first_seen is real, but
        // first_posted walks down to the 0 sentinel. (The MIN on conflict
        // is what a backfill leg does; first_seen is not rewritten.)
        let undated = [
            over(
                3,
                "\"Nodate.Show.S02E02.1080p.rar\" yEnc (1/1)",
                "<n1@x>",
                1000,
            ),
            over(
                4,
                "\"Nodate.Show.S02E02.1080p.par2\" yEnc (1/1)",
                "<n2@x>",
                200,
            ),
        ];
        ix.ingest("alt.binaries.teevee", &undated, INDEXED).unwrap();
        ix.ingest("alt.binaries.teevee", &undated, 0).unwrap();
    }

    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        "{\"servers\":[{\"host\":\"127.0.0.1\",\"port\":1,\"tls\":false}]}",
    )
    .unwrap();
    // The newznab facade IS the built-in index published over newznab,
    // and that indexer's master switch defaults OFF - a daemon with it
    // off answers every t= with <error code="101"> on purpose. These
    // tests seed a database and then ask the facade about it, so they
    // are the "switched on" case and have to say so.
    index_enabled(&cfg);
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--index-db")
            .arg(&db);
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        let (code, body) = http_get(port, "/api?t=search");
        assert_eq!(code, 200, "{body}");
        assert_eq!(items(&body), 2, "{body}");

        // The backfilled one advertises 2017, the year it was posted -
        // not 2026, the year we happened to scan the group.
        let old = pubdate_of(&body, "Old.Show.S01E01");
        assert!(
            old.contains(" 2017 "),
            "backfilled release is dated by index time, not upload time: {old}\n{body}"
        );

        // The unknown-date one keeps its first_seen and is NOT dated 1970.
        let nodate = pubdate_of(&body, "Nodate.Show.S02E02");
        assert!(
            nodate.contains(" 2026 "),
            "unknown-date release should fall back to when we saw it: {nodate}\n{body}"
        );
        assert!(
            !nodate.contains("1970"),
            "unknown-date release dated at the epoch: {nodate}"
        );
    })
    .await
    .unwrap();
}

/// The search-shaping parameters the *arrs actually send.
///
/// Each assertion here stands for a way the facade used to answer the
/// wrong question:
/// - `season=` with no `ep=` is Sonarr's SEASON-PACK search. The season
///   was dropped unless an episode came with it, so the answer was every
///   release of the series, at every season.
/// - a daily-series search (`ep=07/28`, or a season that is really a
///   year) has no SxxEyy to narrow by, and must keep the plain-title
///   search Sonarr then date-filters - not an `s2026` that matches
///   nothing.
/// - `<newznab:response>` is how a client learns there is a second page.
///   Absent, every response looked like the last one.
/// - an `imdbid` we hold nothing for must answer EMPTY. Ignoring it
///   returned the whole index for the *arr to title-match against.
/// - an unsupported function gets the spec's own error rather than
///   falling through to search.
#[tokio::test(flavor = "multi_thread")]
async fn newznab_honours_the_arr_search_parameters() {
    let dir = std::env::temp_dir().join(format!("nzbfast-nnsearch-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let db = dir.join("index.db");
    {
        let mut ix = nzbkit::index::Index::open(&db).unwrap();
        ix.ingest(
            "alt.binaries.teevee",
            &[
                over(
                    1,
                    "\"Cat.Show.S02E01.1080p.rar\" yEnc (1/1)",
                    "<a1@x>",
                    1000,
                ),
                over(
                    2,
                    "\"Cat.Show.S02E01.1080p.par2\" yEnc (1/1)",
                    "<a2@x>",
                    200,
                ),
                over(
                    3,
                    "\"Cat.Show.S02E02.1080p.rar\" yEnc (1/1)",
                    "<b1@x>",
                    1000,
                ),
                over(
                    4,
                    "\"Cat.Show.S02E02.1080p.par2\" yEnc (1/1)",
                    "<b2@x>",
                    200,
                ),
                over(
                    5,
                    "\"Cat.Show.S03E01.1080p.rar\" yEnc (1/1)",
                    "<c1@x>",
                    1000,
                ),
                over(
                    6,
                    "\"Cat.Show.S03E01.1080p.par2\" yEnc (1/1)",
                    "<c2@x>",
                    200,
                ),
            ],
            1_700_000_000,
        )
        .unwrap();
    }

    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        "{\"servers\":[{\"host\":\"127.0.0.1\",\"port\":1,\"tls\":false}]}",
    )
    .unwrap();
    // The newznab facade IS the built-in index published over newznab,
    // and that indexer's master switch defaults OFF - a daemon with it
    // off answers every t= with <error code="101"> on purpose. These
    // tests seed a database and then ask the facade about it, so they
    // are the "switched on" case and have to say so.
    index_enabled(&cfg);
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--index-db")
            .arg(&db);
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // Season-pack search: both season-2 episodes, and NOT season 3.
        let (_, body) = http_get(port, "/api?t=tvsearch&q=Cat.Show&season=2");
        assert_eq!(
            items(&body),
            2,
            "season alone did not narrow the search: {body}"
        );
        assert!(body.contains("S02E01") && body.contains("S02E02"), "{body}");
        assert!(
            !body.contains("S03E01"),
            "season filter leaked another season: {body}"
        );

        // Season + episode still narrows to the one episode.
        let (_, body) = http_get(port, "/api?t=tvsearch&q=Cat.Show&season=2&ep=1");
        assert_eq!(items(&body), 1, "{body}");
        assert!(body.contains("S02E01"), "{body}");

        // A daily-series search keeps the plain-title result set: there
        // is no SxxEyy to narrow by, and an empty answer would be worse
        // than one Sonarr can date-filter itself.
        let (_, body) = http_get(port, "/api?t=tvsearch&q=Cat.Show&season=2026&ep=07/28");
        assert_eq!(
            items(&body),
            3,
            "a daily search should not be narrowed: {body}"
        );

        // The page footer a client needs to ask for page two.
        let (_, body) = http_get(port, "/api?t=search&q=Cat.Show&limit=2");
        assert_eq!(items(&body), 2, "{body}");
        assert!(
            body.contains("<newznab:response"),
            "no paging element: {body}"
        );
        assert!(
            body.contains("total=\"3\""),
            "total should count matches, not the page: {body}"
        );
        assert!(body.contains("offset=\"0\""), "{body}");

        // Extended attrs ride along for the columns the *arrs show.
        assert!(body.contains("name=\"usenetdate\""), "{body}");
        assert!(body.contains("name=\"files\""), "{body}");
        assert!(body.contains("name=\"group\""), "{body}");

        // An id we hold nothing for is an empty feed, never the index.
        let (code, body) = http_get(port, "/api?t=movie&imdbid=9999999");
        assert_eq!(code, 200, "{body}");
        assert_eq!(items(&body), 0, "an unknown imdbid returned rows: {body}");
        assert!(body.contains("total=\"0\""), "{body}");

        // Unsupported and unknown functions get the spec's error codes on
        // HTTP 200, rather than being answered with a search.
        let (code, body) = http_get(port, "/api?t=music&q=Cat");
        assert_eq!(code, 200, "{body}");
        assert!(
            body.contains("code=\"203\""),
            "audio search should decline: {body}"
        );
        assert_eq!(items(&body), 0, "{body}");
        let (_, body) = http_get(port, "/api?t=frobnicate");
        assert!(body.contains("code=\"202\""), "{body}");

        // maxage is an age ceiling in days, measured on the upload date.
        // Everything here was posted in 2023, so a one-day window is empty
        // and an eternity is not.
        let (_, body) = http_get(port, "/api?t=search&q=Cat.Show&maxage=1");
        assert_eq!(items(&body), 0, "maxage did not bound the feed: {body}");
        let (_, body) = http_get(port, "/api?t=search&q=Cat.Show&maxage=99999");
        assert_eq!(items(&body), 3, "{body}");

        // Behind an HTTPS reverse proxy the links must be the proxy's,
        // or every NZB fetch is blocked as mixed content.
        let (_, body) = http_get_hdrs(
            port,
            "/api?t=search&q=Cat.Show",
            "X-Forwarded-Proto: https\r\nX-Forwarded-Host: nzb.example.com\r\n",
        );
        assert!(body.contains("https://nzb.example.com/getnzb/"), "{body}");
        assert!(!body.contains("http://127.0.0.1"), "{body}");

        // Without the hops it is still the plain Host header.
        let (_, body) = http_get(port, "/api?t=search&q=Cat.Show");
        assert!(
            body.contains(&format!("http://127.0.0.1:{port}/getnzb/")),
            "{body}"
        );
    })
    .await
    .unwrap();
}

/// The built-in indexer's master switch, end to end against the binary.
///
/// It is the whole feature's contract, so it is worth pinning rather than
/// trusting: OFF is the default, an existing install keeps working, the
/// index database is not so much as created while it is off, and the
/// facade says so instead of answering an empty search that an *arr
/// would read as "the indexer is fine, there is just nothing there".
#[tokio::test(flavor = "multi_thread")]
async fn the_indexer_switch_defaults_off_and_closes_the_facade() {
    let dir = std::env::temp_dir().join(format!("nzbfast-idxsw-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let db = dir.join("index.db");
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        "{\"servers\":[{\"host\":\"127.0.0.1\",\"port\":1,\"tls\":false}]}",
    )
    .unwrap();
    // An existing install, but one that never chose anything to index:
    // the migration must NOT read that as "was using the indexer".
    // Spots are pinned off because they default ON since TODO 131 and
    // the index database backs BOTH sources - this test guards the
    // "with both sources off the file is never created" invariant.
    std::fs::write(
        cfg.with_file_name("settings.json"),
        "{\"spot_enabled\": false}",
    )
    .unwrap();

    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--index-db")
            .arg(&db);
        c
    })
    .await;
    let port = d.port;
    let db2 = db.clone();

    tokio::task::spawn_blocking(move || {
        // Default off, and reported as such by both the settings block
        // and index_stats (the dashboard reads the second one before it
        // decides what to draw).
        let (_, body) = http_get(port, "/api?mode=get_config&output=json");
        assert!(body.contains("\"index_enabled\":false"), "{body}");
        let (_, body) = http_get(port, "/api?mode=index_stats&output=json");
        assert!(body.contains("\"enabled\":false"), "{body}");
        assert!(body.contains("\"paused\":\"off\""), "{body}");

        // No database. Not empty - absent: `with_index` refuses to open
        // it, so a user who never wanted an indexer never gets the file.
        assert!(!db2.exists(), "index.db was created with the indexer off");

        // The facade is closed, INCLUDING caps, which is what an *arr
        // tests an indexer with.
        for q in [
            "/api?t=caps",
            "/api?t=tvsearch&q=show",
            "/newznab/api?t=search&q=show",
        ] {
            let (code, body) = http_get(port, q);
            assert_eq!(code, 200, "{q}: {body}");
            assert!(body.contains("code=\"101\""), "{q} answered: {body}");
            assert!(!body.contains("<caps>"), "{q} answered: {body}");
        }

        // Switch it on: the facade opens and the database appears.
        let (_, body) = http_get(
            port,
            "/api?mode=config&name=index_enabled&value=1&output=json",
        );
        assert!(body.contains("\"status\":true"), "{body}");
        let (_, body) = http_get(port, "/api?t=caps");
        assert!(body.contains("<caps>"), "{body}");
        let (_, body) = http_get(port, "/api?mode=index_stats&output=json");
        assert!(body.contains("\"enabled\":true"), "{body}");
        assert!(
            db2.exists(),
            "index.db missing after switching the indexer on"
        );

        // And off again closes it back up, in the same process.
        let (_, body) = http_get(
            port,
            "/api?mode=config&name=index_enabled&value=0&output=json",
        );
        assert!(body.contains("\"status\":true"), "{body}");
        let (_, body) = http_get(port, "/api?t=caps");
        assert!(body.contains("code=\"101\""), "{body}");
    })
    .await
    .unwrap();
}

/// The upgrade case: an install that was already indexing keeps indexing.
/// Silently stopping somebody's working index would be a data-shaped
/// surprise, so a saved `index_groups` with no `index_enabled` seeds ON.
#[tokio::test(flavor = "multi_thread")]
async fn an_install_that_was_already_indexing_stays_on() {
    let dir = std::env::temp_dir().join(format!("nzbfast-idxmig-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        "{\"servers\":[{\"host\":\"127.0.0.1\",\"port\":1,\"tls\":false}]}",
    )
    .unwrap();
    std::fs::write(
        cfg.with_file_name("settings.json"),
        "{\"index_groups\":[\"alt.binaries.teevee\"]}",
    )
    .unwrap();

    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--index-db")
            .arg(dir.join("index.db"));
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        let (_, body) = http_get(port, "/api?mode=index_stats&output=json");
        assert!(body.contains("\"enabled\":true"), "{body}");
        let (_, body) = http_get(port, "/api?t=caps");
        assert!(body.contains("<caps>"), "{body}");
    })
    .await
    .unwrap();
}

/// TODO 131 workstream D item D3: what people searched for and could
/// not find reaches the readout, from every surface that asks the
/// index a question.
///
/// This is the test that pins the CALL SITES. The buffer, the table
/// and the retention caps have their own unit tests; what only an e2e
/// can say is that the newznab facade an *arr talks to and the wall's
/// own search box both actually record, and that the readout hands
/// back a list a human can act on.
///
/// The daemon's flush timer is shortened through the documented debug
/// env seam rather than waited out - a minute is a minute.
#[tokio::test(flavor = "multi_thread")]
async fn searches_that_miss_reach_the_d3_readout() {
    let dir = std::env::temp_dir().join(format!("nzbfast-nnmiss-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let db = dir.join("index.db");
    {
        let mut ix = nzbkit::index::Index::open(&db).unwrap();
        ix.ingest(
            "alt.binaries.teevee",
            &[
                over(
                    1,
                    "\"Cat.Show.S02E01.1080p.rar\" yEnc (1/1)",
                    "<a1@x>",
                    1000,
                ),
                over(
                    2,
                    "\"Cat.Show.S02E01.1080p.par2\" yEnc (1/1)",
                    "<a2@x>",
                    200,
                ),
            ],
            1_700_000_000,
        )
        .unwrap();
    }

    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        "{\"servers\":[{\"host\":\"127.0.0.1\",\"port\":1,\"tls\":false}]}",
    )
    .unwrap();
    index_enabled(&cfg);
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_SEARCH_LOG_FLUSH_SECS", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--index-db")
            .arg(&db);
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // Before anything is asserted: rung 1 of the index reads below
        // is refused as busy (or, over t=tvsearch, wrapped as an
        // <error>) while the daemon's own startup index open still
        // holds the write mutex, and this test demands the real content.
        settle_index(port, "&apikey=sekrit");

        // An *arr asking for something we have, and for something we
        // do not. Both are recorded; only the second is a miss.
        let (_, body) = http_get(port, "/api?t=tvsearch&q=cat+show&apikey=sekrit");
        assert!(body.contains("Cat.Show.S02E01"), "{body}");
        for _ in 0..3 {
            let (_, body) = http_get(port, "/api?t=tvsearch&q=dog+show&apikey=sekrit");
            assert!(!body.contains("<item>"), "{body}");
        }
        // FORCE THE SPLIT, which is the pin as well as the setup: wait
        // for the newznab half to reach the table BEFORE the wall miss
        // is issued at all, so that miss is provably still in memory
        // when the first readout below is served. That is exactly the
        // state this test used to reach by accident and read as final,
        // and it is now the state every run goes through - a 1-in-192
        // race turned into an ordinary step. See `settle_searches`.
        let split = settle_searches(port, "&apikey=sekrit", 4);
        assert!(
            !split.contains("\"q\":\"dune part three\""),
            "the wall miss was already flushed, so this run never split: {split}"
        );

        // And the dashboard's own search card, over a different miss.
        let (_, body) = http_get(
            port,
            "/api?mode=index_search&q=Dune.Part.Three&apikey=sekrit&output=json",
        );
        assert!(body.contains("\"results\":[]"), "{body}");

        // Wait for a flush - the query path only ever touched memory.
        // The predicate is the COMPLETE readout and never the first
        // sighting of one miss, because the assertions below are about
        // all five searches; breaking early on `dog show` is the defect
        // [`settle_searches`] documents.
        let readout = settle_searches(port, "&apikey=sekrit", 5);
        assert!(
            readout.contains("\"q\":\"dog show\""),
            "the *arr's miss never reached the readout: {readout}"
        );
        // Normalized, from the surface that asked, counted three times.
        assert!(readout.contains("\"surface\":\"newznab\""), "{readout}");
        assert!(readout.contains("\"n\":3"), "{readout}");
        // The dashboard's miss too, under the wall surface and its
        // normalized spelling.
        assert!(readout.contains("\"q\":\"dune part three\""), "{readout}");
        assert!(readout.contains("\"surface\":\"wall\""), "{readout}");
        // What we DID answer is recorded but is not a miss.
        assert!(!readout.contains("\"q\":\"cat show\""), "{readout}");
        assert!(readout.contains("\"searches\":5"), "{readout}");
        assert!(readout.contains("\"distinct\":3"), "{readout}");
        assert!(readout.contains("\"zero_searches\":4"), "{readout}");
        assert!(readout.contains("\"missing\":2"), "{readout}");

        // The privacy clear leaves nothing behind.
        //
        // Worth knowing about the LAST two assertions here:
        // `m_search_misses` answers a read it could not make with
        // `unwrap_or_default()`, so a refused read serves an empty list and
        // a zeroed summary - byte for byte what a cleared table serves.
        // Those two can therefore pass for the wrong reason, and nothing in
        // the payload tells the cases apart. The `"status":true` check
        // below is the one carrying the weight: `clear_search_log` reports
        // `IndexBusy` rather than a clear it did not do, so a busy index
        // fails there instead of passing quietly.
        let q = "/api?mode=search_log_clear&apikey=sekrit&output=json";
        let v = api_settled(q, || http_get(port, q));
        assert_eq!(v["status"], true, "{v}");
        let (_, body) = http_get(
            port,
            "/api?mode=search_misses&apikey=sekrit&output=json&days=365",
        );
        assert!(body.contains("\"misses\":[]"), "{body}");
        assert!(body.contains("\"searches\":0"), "{body}");
    })
    .await
    .unwrap();
}

/// A read the index could not ANSWER must reach an *arr as an `<error>`,
/// never as an empty feed.
///
/// Sonarr and Radarr treat `<newznab:response total="0"/>` as a fact
/// about the world - this indexer holds nothing for that query - and act
/// on it. They do not re-ask. So every way a read can FAIL has to be
/// told apart from a query that legitimately matched nothing, and the
/// facade was doing the opposite: `with_index_read(|ix| ix.browse(&bq)
/// .ok()).unwrap_or_default()` flattened a saturated pool AND a query
/// whose statements went stale under a schema change (SQLITE_SCHEMA,
/// "vtable constructor failed: rel_fts") into the same empty rss.
///
/// The pool is saturated from INSIDE with the NZBFAST_DEBUG_HOOKS-gated
/// `mode=debug_index_read_busy` - the same lever http_wedge uses, and
/// the only one that can refuse a read this handler makes rather than
/// merely a read some other request makes. Whichever reason a read
/// carries, this is the shape the caller gets.
#[tokio::test(flavor = "multi_thread")]
async fn a_read_the_index_could_not_answer_is_an_error_not_an_empty_feed() {
    let dir = std::env::temp_dir().join(format!("nzbfast-nn-unready-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let db = dir.join("index.db");
    {
        let mut ix = nzbkit::index::Index::open(&db).unwrap();
        ix.ingest(
            "alt.binaries.teevee",
            &[
                over(
                    1,
                    "\"Show.Name.S01E02.1080p.rar\" yEnc (1/1)",
                    "<u1@x>",
                    1000,
                ),
                over(
                    2,
                    "\"Show.Name.S01E02.1080p.par2\" yEnc (1/1)",
                    "<u2@x>",
                    200,
                ),
            ],
            1_700_000_000,
        )
        .unwrap();
    }

    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        "{\"servers\":[{\"host\":\"127.0.0.1\",\"port\":1,\"tls\":false}]}",
    )
    .unwrap();
    // The newznab facade IS the built-in index published over newznab,
    // and that indexer's master switch defaults OFF.
    index_enabled(&cfg);
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            // The read-pool fault injector below is gated on this.
            .env("NZBFAST_DEBUG_HOOKS", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--index-db")
            .arg(&db);
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // Sanity, and the priming the injector needs: this answer comes
        // from the read POOL only once a read-write open has run the
        // migrations, which the first query arranges by falling back to
        // the write handle. Arming before that would refuse nothing.
        let (_, body) = http_get(port, "/newznab/api?t=search&q=show&apikey=sekrit");
        assert!(
            body.contains("Show.Name.S01E02.1080p"),
            "the seed is served before anything is armed: {body}"
        );

        // Every pooled read from here on reports the pool busy.
        let (_, armed) = http_get(
            port,
            "/api?output=json&mode=debug_index_read_busy&value=0&apikey=sekrit",
        );
        assert!(armed.contains("\"armed\":0"), "hook armed: {armed}");

        let (code, body) = http_get(port, "/newznab/api?t=search&q=show&apikey=sekrit");
        assert_eq!(code, 200, "newznab errors ride HTTP 200: {body}");
        assert!(
            body.contains("<error code=\"900\""),
            "a read that failed must be an <error>, not an empty feed: {body}"
        );
        assert!(
            !body.contains("<rss"),
            "an empty rss is the answer this exists to prevent: {body}"
        );
    })
    .await
    .unwrap();
}

/// TODO 187: a TV id parameter is either HONOURED or REFUSED - never
/// dropped on the floor.
///
/// The fault this pins was measured against the live daemon on 1.1.5:
/// `t=tvsearch&tvdbid=121361&season=1&ep=1` and
/// `t=tvsearch&tvdbid=999999999&season=1&ep=1` answered with the SAME
/// 100 items, because the facade read `imdbid` and `tmdbid` and nothing
/// else. A client cannot tell that dump from a set of matches - it asked
/// about one series and got every series' first episode - so the one
/// answer we must never give is an unfiltered list. Ids we can resolve
/// (`imdbid`, and `tvmazeid` through the TVmaze show id the enricher
/// records) filter; ids we hold no mapping for at all (`tvdbid`, `rid`)
/// are an <error>.
#[tokio::test(flavor = "multi_thread")]
async fn newznab_tv_id_params_are_honoured_or_refused() {
    let dir = std::env::temp_dir().join(format!("nzbfast-nnids-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let db = dir.join("index.db");
    // Two series, so an id that resolves to one of them has something to
    // exclude: an "it filtered" assertion over a single-series index
    // passes just as well when nothing filtered at all.
    let key = {
        let mut ix = nzbkit::index::Index::open(&db).unwrap();
        for (n, stem) in [
            "Cat.Show.S02E01.1080p",
            "Cat.Show.S02E02.1080p",
            "Dog.Show.S02E01.1080p",
        ]
        .iter()
        .enumerate()
        {
            let a = (n as u64 + 1) * 10;
            ix.ingest(
                "alt.binaries.teevee",
                &[
                    over(
                        a,
                        &format!("\"{stem}.rar\" yEnc (1/1)"),
                        &format!("<{a}a@x>"),
                        1000,
                    ),
                    over(
                        a + 1,
                        &format!("\"{stem}.par2\" yEnc (1/1)"),
                        &format!("<{a}b@x>"),
                        200,
                    ),
                ],
                1_700_000_000,
            )
            .unwrap();
        }
        // The enriched title row the ids resolve through. Read the parse
        // key off a release rather than spelling it here, so the seeded
        // row is provably the one those releases carry.
        let (cards, _) = ix
            .browse_cards(
                &nzbkit::index::BrowseQuery {
                    q: "Cat.Show".into(),
                    limit: 1,
                    ..Default::default()
                },
                nzbkit::index::CardSort::Latest,
                false,
                false,
                None,
            )
            .unwrap();
        let key = cards[0].title_key.clone();
        ix.title_seed(&key, "tv", "Cat Show", 0).unwrap();
        ix.title_fill(
            &key,
            &nzbkit::index::TitleFill {
                // `tmdb_id` carries the TVmaze SHOW id on a TV row - the
                // same column, a different numbering scheme, which is
                // why the tvmaze resolver has to filter on kind. And it
                // must be LABELLED: an unlabelled '' id resolves nothing
                // since the 20 Aug sweep (it may be an AniList media id
                // written before the id_src column existed).
                tmdb_id: 4242,
                id_src: "tvmaze",
                imdb: "tt0090001",
                ..Default::default()
            },
            1_700_000_000,
        )
        .unwrap();
        key
    };
    assert!(key.starts_with("t:"), "not a TV parse key: {key}");

    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        "{\"servers\":[{\"host\":\"127.0.0.1\",\"port\":1,\"tls\":false}]}",
    )
    .unwrap();
    index_enabled(&cfg);
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--index-db")
            .arg(&db);
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // Baseline: unfiltered, this index answers with all three.
        let (_, body) = http_get(port, "/api?t=tvsearch&q=Show");
        assert_eq!(items(&body), 3, "{body}");

        // ---- ids we hold: they FILTER --------------------------------
        let (code, body) = http_get(port, "/api?t=tvsearch&imdbid=tt0090001");
        assert_eq!(code, 200, "{body}");
        assert_eq!(
            items(&body),
            2,
            "imdbid did not narrow to one series: {body}"
        );
        assert!(
            !body.contains("Dog.Show"),
            "another series leaked in: {body}"
        );

        let (_, body) = http_get(port, "/api?t=tvsearch&tvmazeid=4242&season=2&ep=1");
        assert_eq!(items(&body), 1, "tvmazeid + SxxEyy: {body}");
        assert!(body.contains("Cat.Show.S02E01"), "{body}");

        // An id we hold nothing for is an EMPTY feed, never the index.
        // This is the measured fault in its sharpest form: a nonsense id
        // used to answer exactly what a real one did.
        let (_, body) = http_get(port, "/api?t=tvsearch&tvmazeid=999999&season=2&ep=1");
        assert_eq!(items(&body), 0, "an unknown tvmazeid returned rows: {body}");
        assert!(body.contains("total=\"0\""), "{body}");
        let (_, body) = http_get(port, "/api?t=tvsearch&imdbid=tt9999999");
        assert_eq!(items(&body), 0, "an unknown imdbid returned rows: {body}");

        // ---- tvdbid: honoured, but promised only when held ----------
        // The column is empty on this index, so caps must NOT offer the
        // parameter. Sonarr switches to tvdbid the moment caps does, and
        // against an empty column every series search would answer
        // nothing - read as "this indexer has nothing", which is worse
        // than the name search it would otherwise have run.
        let (_, body) = http_get(port, "/api?t=caps");
        assert!(
            !body.contains("tvdbid"),
            "caps promised tvdbid against an empty column: {body}"
        );
        // Honoured all the same, so an id we hold nothing for is an
        // empty feed rather than a dump - the fault this whole test
        // exists for.
        let (_, body) = http_get(port, "/api?t=tvsearch&tvdbid=121361&season=2&ep=1");
        assert_eq!(items(&body), 0, "an unknown tvdbid returned rows: {body}");
        assert!(body.contains("total=\"0\""), "{body}");

        // A TVmaze id is not a TMDB id even when it is the same number:
        // one column holds both, so a movie-side param on a TV search
        // must not resolve through it.
        let (_, body) = http_get(port, "/api?t=tvsearch&tmdbid=4242");
        assert!(
            body.contains("<error code=\"201\""),
            "tmdbid on a tvsearch must be refused, not resolved: {body}"
        );

        // ---- ids we cannot speak at all: they REFUSE -----------------
        // Distinct from the empty feeds above, and the distinction is
        // the point: "we do not speak this id" is permanent and belongs
        // in an error, "we have nothing filed under it" is a fact about
        // the catalogue that a client may retry tomorrow.
        for q in [
            "t=tvsearch&rid=1234&q=Show",
            "t=tvsearch&tvrageid=1234&q=Show",
            "t=movie&tvdbid=121361",
        ] {
            let (code, body) = http_get(port, &format!("/api?{q}"));
            assert_eq!(code, 200, "newznab errors ride HTTP 200: {body}");
            assert_eq!(items(&body), 0, "{q} was answered with a dump: {body}");
            assert!(
                body.contains("<error code=\"201\""),
                "{q} must be refused by name, not ignored: {body}"
            );
        }
        // Empty is not "sent": Sonarr omits a param it has no value for
        // by sending it blank, and that must stay a plain search.
        let (_, body) = http_get(port, "/api?t=tvsearch&rid=&q=Show");
        assert_eq!(items(&body), 3, "a blank id refused a good search: {body}");

        // ---- and caps say exactly what is honoured -------------------
        let (_, body) = http_get(port, "/api?t=caps");
        let tv = body
            .lines()
            .find(|l| l.contains("<tv-search"))
            .unwrap_or_default()
            .to_string();
        assert!(tv.contains("imdbid") && tv.contains("tvmazeid"), "{tv}");
        assert!(
            !tv.contains("rid,"),
            "caps must never advertise a param the facade refuses: {tv}"
        );
    })
    .await
    .unwrap();
}

/// TODO 187, the other side of the caps gate: once the index actually
/// holds TVDB ids, the facade advertises `tvdbid` and Sonarr's primary
/// series lookup works.
///
/// The gate is data, not code, and that is deliberate. Sonarr switches
/// to tvdbid the moment caps offers it, so the promise has to follow the
/// column the enrichment backfill fills - never a release note. Its
/// companion `newznab_tv_id_params_are_honoured_or_refused` pins the
/// empty-column half: same facade, no promise.
#[tokio::test(flavor = "multi_thread")]
async fn newznab_advertises_tvdbid_once_the_index_holds_them() {
    let dir = std::env::temp_dir().join(format!("nzbfast-nntvdb-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let db = dir.join("index.db");
    {
        let mut ix = nzbkit::index::Index::open(&db).unwrap();
        for (n, stem) in ["Cat.Show.S02E01.1080p", "Dog.Show.S02E01.1080p"]
            .iter()
            .enumerate()
        {
            let a = (n as u64 + 1) * 10;
            ix.ingest(
                "alt.binaries.teevee",
                &[
                    over(
                        a,
                        &format!("\"{stem}.rar\" yEnc (1/1)"),
                        &format!("<{a}a@x>"),
                        1000,
                    ),
                    over(
                        a + 1,
                        &format!("\"{stem}.par2\" yEnc (1/1)"),
                        &format!("<{a}b@x>"),
                        200,
                    ),
                ],
                1_700_000_000,
            )
            .unwrap();
        }
        let (cards, _) = ix
            .browse_cards(
                &nzbkit::index::BrowseQuery {
                    q: "Cat.Show".into(),
                    limit: 1,
                    ..Default::default()
                },
                nzbkit::index::CardSort::Latest,
                false,
                false,
                None,
            )
            .unwrap();
        let key = cards[0].title_key.clone();
        ix.title_seed(&key, "tv", "Cat Show", 0).unwrap();
        // What the backfill lane writes after one exact TVmaze call.
        ix.title_set_tvdb(&key, 81189).unwrap();
    }

    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        "{\"servers\":[{\"host\":\"127.0.0.1\",\"port\":1,\"tls\":false}]}",
    )
    .unwrap();
    index_enabled(&cfg);
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--index-db")
            .arg(&db);
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // The promise, now that it is true.
        let (_, body) = http_get(port, "/api?t=caps");
        let tv = body
            .lines()
            .find(|l| l.contains("<tv-search"))
            .unwrap_or_default()
            .to_string();
        assert!(
            tv.contains("tvdbid"),
            "caps withheld a real capability: {tv}"
        );
        // ...and only on the TV side. A movie search has no TVDB id to
        // resolve, so offering it there would be the same false promise
        // in the other half of the index.
        let movie = body
            .lines()
            .find(|l| l.contains("<movie-search"))
            .unwrap_or_default()
            .to_string();
        assert!(!movie.contains("tvdbid"), "{movie}");

        // Sonarr's lookup: the id names the series, and the season/ep
        // narrow within it.
        let (code, body) = http_get(port, "/api?t=tvsearch&tvdbid=81189");
        assert_eq!(code, 200, "{body}");
        assert_eq!(items(&body), 1, "tvdbid did not resolve: {body}");
        assert!(body.contains("Cat.Show.S02E01"), "{body}");
        assert!(
            !body.contains("Dog.Show"),
            "another series leaked in: {body}"
        );
        let (_, body) = http_get(port, "/api?t=tvsearch&tvdbid=81189&season=2&ep=1");
        assert_eq!(items(&body), 1, "{body}");
        let (_, body) = http_get(port, "/api?t=tvsearch&tvdbid=81189&season=9&ep=9");
        assert_eq!(items(&body), 0, "{body}");

        // An id we hold nothing for stays an empty feed even now that
        // the parameter is advertised.
        let (_, body) = http_get(port, "/api?t=tvsearch&tvdbid=999999999");
        assert_eq!(items(&body), 0, "{body}");
        assert!(body.contains("total=\"0\""), "{body}");
    })
    .await
    .unwrap();
}

/// TODO 187's second measurement: `q + season + ep` answering ZERO.
///
/// It is not a fault, and this test is here so nobody "fixes" it into
/// one. The live probe asked for `Star Trek s04e04` against an index
/// that held S04E01-E03; zero was the correct answer. An episode we DO
/// hold narrows to exactly that episode, and an episode we do not hold
/// is empty - never a fall back to the season, which would hand Sonarr
/// twelve wrong grabs for the one it asked for.
#[tokio::test(flavor = "multi_thread")]
async fn newznab_episode_narrowing_is_exact() {
    let dir = std::env::temp_dir().join(format!("nzbfast-nnep-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let db = dir.join("index.db");
    {
        let mut ix = nzbkit::index::Index::open(&db).unwrap();
        for (n, stem) in ["Cat.Show.S04E01.1080p", "Cat.Show.S04E03.1080p"]
            .iter()
            .enumerate()
        {
            let a = (n as u64 + 1) * 10;
            ix.ingest(
                "alt.binaries.teevee",
                &[
                    over(
                        a,
                        &format!("\"{stem}.rar\" yEnc (1/1)"),
                        &format!("<{a}a@x>"),
                        1000,
                    ),
                    over(
                        a + 1,
                        &format!("\"{stem}.par2\" yEnc (1/1)"),
                        &format!("<{a}b@x>"),
                        200,
                    ),
                ],
                1_700_000_000,
            )
            .unwrap();
        }
    }
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        "{\"servers\":[{\"host\":\"127.0.0.1\",\"port\":1,\"tls\":false}]}",
    )
    .unwrap();
    index_enabled(&cfg);
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--index-db")
            .arg(&db);
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // The AIOStreams "Forced Query" shape, which is q + season + ep.
        let (_, body) = http_get(port, "/api?t=tvsearch&q=Cat+Show");
        assert_eq!(items(&body), 2, "{body}");
        let (_, body) = http_get(port, "/api?t=tvsearch&q=Cat+Show&season=4");
        assert_eq!(items(&body), 2, "{body}");
        let (_, body) = http_get(port, "/api?t=tvsearch&q=Cat+Show&season=4&ep=1");
        assert_eq!(items(&body), 1, "an episode we hold: {body}");
        assert!(body.contains("S04E01"), "{body}");
        let (_, body) = http_get(port, "/api?t=tvsearch&q=Cat+Show&season=4&ep=3");
        assert_eq!(items(&body), 1, "{body}");
        assert!(body.contains("S04E03"), "{body}");
        // The measured "zero", reproduced honestly: nothing to return.
        let (_, body) = http_get(port, "/api?t=tvsearch&q=Cat+Show&season=4&ep=4");
        assert_eq!(
            items(&body),
            0,
            "the season leaked past the episode: {body}"
        );
        assert!(body.contains("total=\"0\""), "{body}");
    })
    .await
    .unwrap();
}

/// POST a JSON body and return (status, body). The id plumbing is only
/// half readable from GETs: the wall's fix-match flow is a POST, and
/// what it does to a title row is what the *arr surfaces then answer
/// with.
fn http_post_json(port: u16, req: &str, body: &str) -> (u16, String) {
    let mut last = String::new();
    for attempt in 0..5u32 {
        let once = || -> std::io::Result<(u16, String)> {
            let mut s = TcpStream::connect(("127.0.0.1", port))?;
            write!(
                s,
                "POST {req} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\
                 Content-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            )?;
            let mut out = String::new();
            let read = s.read_to_string(&mut out);
            if out.is_empty() {
                return Err(read.err().unwrap_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "closed without answering",
                    )
                }));
            }
            let status: u16 = out
                .split_whitespace()
                .nth(1)
                .and_then(|c| c.parse().ok())
                .unwrap_or(0);
            Ok((
                status,
                out.split("\r\n\r\n").nth(1).unwrap_or("").to_string(),
            ))
        };
        match once() {
            Ok(out) => return out,
            Err(e) => {
                last = e.to_string();
                std::thread::sleep(std::time::Duration::from_millis(
                    100 * u64::from(attempt) + 50,
                ));
            }
        }
    }
    panic!("daemon on :{port} never served POST {req}: {last}");
}

/// Ingest one 2-file release under `stem` at article base `a`.
///
/// Sized like a real post on purpose. `junk_score` puts any media-shaped
/// stem under 10 MB at 55 - and an HD-tagged movie under 200 MB with it -
/// which is over the wall's default 50 line, and the enricher's backfill
/// queues only consider titles the wall would list. A 1 KB fixture is
/// therefore invisible to every lane that reads `VISIBLE`, so a test
/// about those lanes has to weigh something.
fn seed_release(ix: &mut nzbkit::index::Index, a: u64, stem: &str) {
    ix.ingest(
        "alt.binaries.teevee",
        &[
            over(
                a,
                &format!("\"{stem}.rar\" yEnc (1/1)"),
                &format!("<{a}a@x>"),
                300 << 20,
            ),
            over(
                a + 1,
                &format!("\"{stem}.par2\" yEnc (1/1)"),
                &format!("<{a}b@x>"),
                1 << 20,
            ),
        ],
        1_700_000_000,
    )
    .unwrap();
}

/// The parse key the index filed a release under, read back rather than
/// spelled out - so the enriched row is provably the one those releases
/// carry.
fn key_of(ix: &nzbkit::index::Index, q: &str) -> String {
    let (cards, _) = ix
        .browse_cards(
            &nzbkit::index::BrowseQuery {
                q: q.into(),
                limit: 1,
                ..Default::default()
            },
            nzbkit::index::CardSort::Latest,
            false,
            false,
            None,
        )
        .unwrap();
    cards
        .first()
        .unwrap_or_else(|| panic!("no card for {q}"))
        .title_key
        .clone()
}

/// The scratch daemon these id suites all run against.
fn id_suite_daemon(dir: &Path, db: &Path) -> impl Fn(u16) -> Command + use<> {
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        "{\"servers\":[{\"host\":\"127.0.0.1\",\"port\":1,\"tls\":false}]}",
    )
    .unwrap();
    index_enabled(&cfg);
    let (dir, db) = (dir.to_path_buf(), db.to_path_buf());
    move |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(dir.join("config.json"))
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--index-db")
            .arg(&db);
        c
    }
}

/// Codex sweep 7, H2 + M4 + M1: what an external id means, over the wire.
///
/// `titles.tmdb_id` is one column carrying four unrelated numbering
/// schemes, and until it recorded WHICH, `kind` was the only clue - so a
/// TV row enriched by AniList (the keyless anime path: no API key, and
/// the routine case for a romaji title TVmaze lacks) answered a Sonarr
/// `tvmazeid=`, and a movie row enriched by OMDb - which writes the bare
/// IMDb number into that column - answered a Radarr `tmdbid=`.
///
/// Three more things this pins, all of them about the same request:
/// an id resolves to EVERY key filed under it (one show under two
/// spellings is two keys, and answering with one of them hid the rest of
/// the series); an id we cannot resolve does not throw away a `q` the
/// client sent with it; and with no `q` it is still an empty feed, which
/// is TODO 187's guard.
#[tokio::test(flavor = "multi_thread")]
async fn newznab_ids_respect_their_namespace_and_reach_every_key() {
    let dir = std::env::temp_dir().join(format!("nzbfast-nnns-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let db = dir.join("index.db");
    {
        let mut ix = nzbkit::index::Index::open(&db).unwrap();
        for (n, stem) in [
            "Cat.Show.S02E01.1080p",
            "Cat.Show.S02E02.1080p",
            "Cat.Show.The.Reckoning.S02E03.1080p",
            "Anime.Show.S01E01.1080p",
            "Dog.Show.S02E01.1080p",
            "An.Omdb.Film.2010.1080p.BluRay.x264",
        ]
        .iter()
        .enumerate()
        {
            seed_release(&mut ix, (n as u64 + 1) * 10, stem);
        }
        let fill = |ix: &nzbkit::index::Index, key: &str, kind: &str, id: i64, src: &str| {
            ix.title_seed(key, kind, "x", 0).unwrap();
            ix.title_fill(
                key,
                &nzbkit::index::TitleFill {
                    tmdb_id: id,
                    id_src: src,
                    ..Default::default()
                },
                1_700_000_000,
            )
            .unwrap();
        };
        // One show, two spellings, two parse keys - and both enrich to
        // the same TVmaze show id, which is exactly the shape the
        // duplicate check's alias oracle is built on.
        let cat = key_of(&ix, "Cat.Show.S02E01");
        let cat_alt = key_of(&ix, "Reckoning");
        assert_ne!(cat, cat_alt, "the two spellings collapsed into one key");
        fill(&ix, &cat, "tv", 777, "tvmaze");
        fill(&ix, &cat_alt, "tv", 777, "tvmaze");
        // The keyless anime path: an AniList MEDIA id on a tv row.
        fill(&ix, &key_of(&ix, "Anime.Show"), "tv", 4242, "anilist");
        // The keyless movie path: OMDb has no TMDB id to give, so what
        // lands here is the numeric half of the tconst.
        fill(&ix, &key_of(&ix, "Omdb.Film"), "movie", 111_161, "omdb");
    }

    let d = serve(&dir, id_suite_daemon(&dir, &db)).await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // ---- M4: an id reaches every key filed under it --------------
        let (code, body) = http_get(port, "/api?t=tvsearch&tvmazeid=777");
        assert_eq!(code, 200, "{body}");
        assert_eq!(items(&body), 3, "half the show was unreachable: {body}");
        for stem in ["Cat.Show.S02E01", "Cat.Show.S02E02", "Reckoning"] {
            assert!(body.contains(stem), "{stem} missing from: {body}");
        }
        assert!(body.contains("total=\"3\""), "total disagreed: {body}");
        assert!(!body.contains("Dog.Show"), "another series leaked: {body}");

        // ---- H2: an AniList media id is not a TVmaze show id ---------
        let (_, body) = http_get(port, "/api?t=tvsearch&tvmazeid=4242");
        assert_eq!(
            items(&body),
            0,
            "an AniList id answered a tvmazeid lookup: {body}"
        );
        assert!(body.contains("total=\"0\""), "{body}");

        // ---- H2, movie side: an IMDb number is not a TMDB id ---------
        let (_, body) = http_get(port, "/api?t=movie&tmdbid=111161");
        assert_eq!(
            items(&body),
            0,
            "an OMDb-supplied IMDb number answered a tmdbid lookup: {body}"
        );

        // ---- M1: an unresolved id does not discard the query ---------
        // Our coverage of an id namespace is not the client's problem:
        // it asked for a series BY NAME as well, and we hold it.
        let (_, body) = http_get(port, "/api?t=tvsearch&tvmazeid=4242&q=Anime+Show");
        assert_eq!(items(&body), 1, "the q was thrown away with the id: {body}");
        assert!(body.contains("Anime.Show.S01E01"), "{body}");
        assert!(
            !body.contains("Cat.Show"),
            "the fallback ran unfiltered: {body}"
        );
        let (_, body) = http_get(port, "/api?t=movie&tmdbid=111161&q=Omdb+Film");
        assert_eq!(items(&body), 1, "{body}");
        assert!(body.contains("An.Omdb.Film"), "{body}");

        // ...and with NO query it is still an empty feed. That refusal
        // is TODO 187's guard, and a bare season/ep is not a query: it
        // narrows an id search, it does not replace one.
        let (_, body) = http_get(port, "/api?t=tvsearch&tvmazeid=999999");
        assert_eq!(items(&body), 0, "{body}");
        let (_, body) = http_get(port, "/api?t=tvsearch&tvmazeid=999999&season=2&ep=1");
        assert_eq!(items(&body), 0, "a season/ep became a search: {body}");
        let (_, body) = http_get(port, "/api?t=tvsearch&tvmazeid=999999&q=+");
        assert_eq!(items(&body), 0, "a blank q became a search: {body}");
    })
    .await
    .unwrap();
}

/// Codex sweep 7, M1: the `tvdbid` promise follows COVERAGE, not the
/// first row to land.
///
/// The caps gate is data rather than code on purpose (TODO 187), but it
/// asked `EXISTS(tvdb > 0)` while the data behind it is filled six rows
/// at a time by an idle backfill lane. So one id anywhere flipped the
/// promise on for the whole catalogue, and Sonarr - which switches to
/// tvdbid the moment caps offers it - then asked about every series the
/// lane had not reached yet and was told the indexer has nothing.
#[tokio::test(flavor = "multi_thread")]
async fn newznab_promises_tvdbid_only_once_the_backfill_has_drained() {
    let dir = std::env::temp_dir().join(format!("nzbfast-nndrain-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let db = dir.join("index.db");
    {
        let mut ix = nzbkit::index::Index::open(&db).unwrap();
        for (n, stem) in ["Cat.Show.S02E01.1080p", "Dog.Show.S02E01.1080p"]
            .iter()
            .enumerate()
        {
            seed_release(&mut ix, (n as u64 + 1) * 10, stem);
        }
        for (q, tvdb) in [("Cat.Show", 81189), ("Dog.Show", 0)] {
            let key = key_of(&ix, q);
            ix.title_seed(&key, "tv", "x", 0).unwrap();
            // Enriched by TVmaze, so both rows carry the show id the
            // backfill lane would ask WITH - the state that makes the
            // second one queued rather than unaskable.
            ix.title_fill(
                &key,
                &nzbkit::index::TitleFill {
                    tmdb_id: 700 + tvdb,
                    id_src: "tvmaze",
                    ..Default::default()
                },
                1_700_000_000,
            )
            .unwrap();
            if tvdb > 0 {
                ix.title_set_tvdb(&key, tvdb).unwrap();
            }
        }
    }

    let d = serve(&dir, id_suite_daemon(&dir, &db)).await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        let (_, body) = http_get(port, "/api?t=caps");
        let tv = body
            .lines()
            .find(|l| l.contains("<tv-search"))
            .unwrap_or_default()
            .to_string();
        assert!(
            !tv.contains("tvdbid"),
            "caps promised tvdbid with the backfill still running: {tv}"
        );
        // Honoured all the same - the promise can only ever be narrower
        // than what the search path delivers, never wider.
        let (_, body) = http_get(port, "/api?t=tvsearch&tvdbid=81189");
        assert_eq!(items(&body), 1, "{body}");
        assert!(body.contains("Cat.Show.S02E01"), "{body}");
    })
    .await
    .unwrap();
}

/// Codex sweep 7, M3: correcting a card's identity drops the TVDB id
/// that belonged to the series it USED to be.
///
/// `title_fill` never writes `tvdb` by design - one writer, the lane
/// that asked TVmaze - and the wall's candidate arm fills without
/// resetting. So a card corrected from series A to series B kept A's
/// TVDB id: `tvdbid=<A>` handed Sonarr B's releases, `tvdbid=<B>`
/// answered nothing, and the row could never heal itself because the
/// backfill queue wants `tvdb_tried = 0 AND tvdb = 0`.
#[tokio::test(flavor = "multi_thread")]
async fn a_wall_identity_correction_drops_the_superseded_tvdb_id() {
    let dir = std::env::temp_dir().join(format!("nzbfast-nnfix-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let db = dir.join("index.db");
    let key = {
        let mut ix = nzbkit::index::Index::open(&db).unwrap();
        seed_release(&mut ix, 10, "Cat.Show.S02E01.1080p");
        let key = key_of(&ix, "Cat.Show");
        ix.title_seed(&key, "tv", "Cat Show", 0).unwrap();
        ix.title_fill(
            &key,
            &nzbkit::index::TitleFill {
                tmdb_id: 777,
                id_src: "tvmaze",
                ..Default::default()
            },
            1_700_000_000,
        )
        .unwrap();
        ix.title_set_tvdb(&key, 81189).unwrap();
        key
    };

    let d = serve(&dir, id_suite_daemon(&dir, &db)).await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // The row as the backfill lane left it.
        let (_, body) = http_get(port, "/api?t=tvsearch&tvdbid=81189");
        assert_eq!(items(&body), 1, "{body}");

        // A human presses a candidate in the wall's fix-match list: this
        // card is not Cat Show, it is Dog Show. The provider id moves.
        let fix = format!(
            "{{\"key\":{},\"kind\":\"tv\",\"title\":\"Dog Show\",\"year\":0,\
              \"meta\":{{\"id\":888,\"provider\":\"tvmaze\",\"overview\":\"\",\
              \"rating\":0,\"genres\":\"\",\"poster_url\":\"\",\"backdrop_url\":\"\",\
              \"imdb\":\"\",\"air_date\":\"\"}}}}",
            serde_json::to_string(&key).unwrap()
        );
        let v = api_settled("mode=wall_fix", || {
            http_post_json(port, "/api?mode=wall_fix", &fix)
        });
        assert_eq!(v["status"], true, "the fix was refused: {v}");

        // The superseded id must no longer name this card. Answering
        // with it is the fault: Sonarr asked about the series that
        // really is 81189 and would have been handed Dog Show's grabs.
        let (_, body) = http_get(port, "/api?t=tvsearch&tvdbid=81189");
        assert_eq!(
            items(&body),
            0,
            "the old series' tvdbid still resolves to this card: {body}"
        );
        assert!(body.contains("total=\"0\""), "{body}");

        // ...and the NEW provider id is filed under the namespace the
        // candidate came from. The endpoint has always handed the
        // candidate's `provider` to the UI and always taken it back in
        // this payload; it simply dropped it on the way to the column,
        // leaving an unlabelled id (Codex sweep 7, H2).
        let (_, body) = http_get(port, "/api?t=tvsearch&tvmazeid=888");
        assert_eq!(items(&body), 1, "the corrected id did not resolve: {body}");
        assert!(body.contains("Cat.Show.S02E01"), "{body}");
    })
    .await
    .unwrap();
}

/// Deep paging (newznab-deep-paging-test, TODO ARR-CERTIFICATION-2026-08-28
/// B2): the facade already had one silent deep-page defect (the old path
/// pulled limit+offset rows and paged in memory - the comment at
/// `sabcompat/newznab.rs`'s `browse()` call says so), and until now every
/// test in this file asked only for `offset="0"`, leaving the
/// `offset > 0` branch of `note_search`'s guard unexercised by anything.
///
/// Walks `offset=0, N, 2N, …` over a seven-release feed with a page size
/// of three, and checks the property a naive re-query-per-page can pass
/// while still being wrong: no release seen twice (overlap), the union
/// across pages equal to the full seeded set (no gap), `total` unmoved
/// for the whole walk, and `<newznab:response offset="…">` echoing the
/// request rather than always reporting 0. Releases are ingested through
/// `Index::ingest` - the real subject classifier - never with a
/// hand-written `kind`/`title_key`, per the certification run's own
/// warning about that shortcut.
#[tokio::test(flavor = "multi_thread")]
async fn newznab_deep_paging_has_no_overlap_and_no_gaps() {
    let dir = std::env::temp_dir().join(format!("nzbfast-nndeep-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    const TOTAL: usize = 7;
    let db = dir.join("index.db");
    {
        let mut ix = nzbkit::index::Index::open(&db).unwrap();
        let mut rows = Vec::new();
        let mut n: u64 = 1;
        for i in 1..=TOTAL {
            rows.push(over(
                n,
                &format!("\"Deep.Page.Show.S01E{i:02}.1080p.rar\" yEnc (1/1)"),
                &format!("<dp{i}a@x>"),
                1000,
            ));
            n += 1;
            rows.push(over(
                n,
                &format!("\"Deep.Page.Show.S01E{i:02}.1080p.par2\" yEnc (1/1)"),
                &format!("<dp{i}b@x>"),
                200,
            ));
            n += 1;
        }
        ix.ingest("alt.binaries.teevee", &rows, 1_700_000_000)
            .unwrap();
    }

    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        "{\"servers\":[{\"host\":\"127.0.0.1\",\"port\":1,\"tls\":false}]}",
    )
    .unwrap();
    index_enabled(&cfg);
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--index-db")
            .arg(&db);
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        const PAGE: usize = 3;
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut total_seen: Option<usize> = None;
        let mut offset = 0usize;
        // TOTAL/PAGE full pages, one partial page, one empty tail page -
        // bounded generously so a defect that never terminates the walk
        // fails loudly instead of hanging the suite.
        for _ in 0..10 {
            let (code, body) = http_get(
                port,
                &format!("/api?t=search&q=Deep.Page.Show&limit={PAGE}&offset={offset}"),
            );
            assert_eq!(code, 200, "{body}");
            assert!(
                body.contains(&format!("offset=\"{offset}\"")),
                "offset should echo the request, not always report 0: {body}"
            );
            let total = total_attr(&body);
            match total_seen {
                None => total_seen = Some(total),
                Some(t) => assert_eq!(
                    t, total,
                    "total drifted mid-walk at offset {offset}: {body}"
                ),
            }
            let page_ids = guids(&body);
            if page_ids.is_empty() {
                break;
            }
            for id in page_ids {
                assert!(
                    seen.insert(id.clone()),
                    "release {id} came back on more than one page (offset {offset}, overlap): {body}"
                );
            }
            offset += PAGE;
        }
        assert_eq!(
            total_seen,
            Some(TOTAL),
            "seeded {TOTAL} releases but the facade's total said otherwise"
        );
        assert_eq!(
            seen.len(),
            TOTAL,
            "paging walk only covered {} of {TOTAL} seeded releases (gap)",
            seen.len()
        );
    })
    .await
    .unwrap();
}
/// The ingest drop census, over the wire (`mode=index_drops`).
///
/// The four `ingest_drop_*` counters were written for a day with NOTHING
/// outside a unit test reading one, while 5.8M no-filename drops piled up
/// on the live index and the no-filename admission decision they were
/// taken for could not be made from any shipped surface. This is the
/// surface, so this is the test that says it answers.
///
/// It pins the two things a reader could get wrong: the two families are
/// reported apart (`gen_depth` is a pass-budget surplus that re-arrives on
/// the next scan, so it is NOT in `dropped_total`), and a counter that has
/// never fired reads as a zero rather than as a missing field.
#[tokio::test(flavor = "multi_thread")]
async fn the_ingest_drop_census_answers_over_the_api() {
    let dir = std::env::temp_dir().join(format!("nzbfast-nndrop-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let db = dir.join("index.db");
    {
        let mut ix = nzbkit::index::Index::open(&db).unwrap();
        ix.ingest(
            "alt.binaries.teevee",
            &[
                // Two fully-obfuscated subjects: a bare token, no quotes,
                // no name.ext. Both are dropped and both are counted.
                over(1, "aGVsbG8gb2JmdXNjYXRlZA (1/50)", "<o1@x>", 700_000),
                over(2, "bm8gbmFtZSBoZXJlIGVpdGhlcg (2/50)", "<o2@x>", 700_000),
                over(
                    3,
                    "\"Kept.Show.S01E01.1080p.rar\" yEnc (1/1)",
                    "<a1@x>",
                    1000,
                ),
            ],
            1_700_000_000,
        )
        .unwrap();
    }

    let d = serve(&dir, id_suite_daemon(&dir, &db)).await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        settle_index(port, "");
        // The pool can still answer `busy` on any single request - that
        // is the contract, and it is why this mode reports it rather
        // than rendering known-nonzero totals as zeroes. Wait for an
        // answer instead of asserting on the first one.
        let started = std::time::Instant::now();
        let body = loop {
            let (code, body) = http_get(port, "/api?mode=index_drops&output=json");
            assert_eq!(code, 200, "{body}");
            let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            if v["busy"] != true {
                break v;
            }
            assert!(
                started.elapsed() < SETTLE_BUDGET,
                "the census never answered in {SETTLE_BUDGET:?}:\n{body}"
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
        };
        assert_eq!(body["index_enabled"], true, "{body}");
        let c = &body["census"];
        assert_eq!(c["dropped"]["no_filename"], 2, "{body}");
        assert_eq!(
            c["dropped"]["empty_stem"], 0,
            "a counter that never fired is a zero, not an absent field: {body}"
        );
        assert_eq!(c["dropped_total"], 2, "{body}");
        assert_eq!(
            c["over_budget"]["gen_depth"], 0,
            "the surplus family is reported apart from the drops: {body}"
        );
        assert_eq!(
            c["window_known"], true,
            "an index that started counting on its first batch knows its window: {body}"
        );
        // The generation-depth census rides the same mode, BESIDE the
        // two drop families and never inside them: `slots` is not a
        // drop and `rows` counts generation rows MINTED, so folding
        // either into `dropped_total` would be the same category error
        // the two families above are kept apart to avoid.
        let g = &c["gen_depth"];
        assert_eq!(
            g["slots"].as_object().map(|o| o.len()),
            Some(0),
            "a batch that clashed nowhere has no depth to report: {body}"
        );
        assert_eq!(c["dropped_total"], 2, "gen_depth must not reach it: {body}");
        assert!(
            g["buckets"].as_array().is_some_and(|b| b[0] == "0002"),
            "the bucket vocabulary is served in order even when empty: {body}"
        );
        // Two censuses, two independently stamped windows - which is
        // why this one carries its own rather than sharing the flag
        // above. Here they genuinely differ: the drops counted on the
        // first batch, the depth census counted nothing at all.
        assert_eq!(
            g["window_known"], false,
            "a census that has never counted must not borrow the other's window: {body}"
        );
    })
    .await
    .unwrap();
}

/// `mode=corr_confirm_stats`'s `per_day` is the budget the lane will
/// ACTUALLY spend, not the floor constant.
///
/// It reported `CONFIRM_PER_DAY` (24) until 2 Sep 2026. That was right
/// while 24 was the ceiling; the 1 Sep ruling made the ceiling derived
/// from the reference account's own quotas - up to 400 on an unmetered
/// account - and this line was not moved with it, so an operator
/// watching `spent_today` against it would have seen the lane sail past
/// its stated limit by up to 16x. Found by reading the surface right
/// after switching the lane on and noticing it disagreed with the
/// daemon's own "up to 400 lookup(s)/day" switch-on line.
///
/// Also pins the inert case as `null` rather than a number: with no
/// resolvable account the lane spends nothing, and naming a budget
/// nothing can spend is the same lie in the other direction.
#[tokio::test(flavor = "multi_thread")]
async fn the_confirm_budget_readout_is_the_derived_one_not_the_floor() {
    let dir = std::env::temp_dir().join(format!("nzbfast-nnconfbud-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let db = dir.join("index.db");
    let d = serve(&dir, id_suite_daemon(&dir, &db)).await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        let enc = |s: &str| {
            s.bytes()
                .map(|b| match b {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                        (b as char).to_string()
                    }
                    _ => format!("%{b:02X}"),
                })
                .collect::<String>()
        };
        let stats = |port: u16| -> serde_json::Value {
            let (code, body) = http_get(port, "/api?mode=corr_confirm_stats&output=json");
            assert_eq!(code, 200, "{body}");
            serde_json::from_str(&body).unwrap_or_default()
        };

        // No account named: the lane is inert and says so with a null
        // budget, not with the floor.
        let v = stats(port);
        assert_eq!(v["source_state"], "none", "{v}");
        assert!(
            v["per_day"].is_null(),
            "an unpointed lane must not advertise a budget: {v}"
        );

        // A metered account: 80% of the binding quota, well clear of
        // both the floor (24) and the unlimited number (400), so this
        // cannot pass by coincidence.
        let entry = r#"[{"name":"ref","url":"http://127.0.0.1:1/api","apikey":"k","hits_per_day":1000,"grabs_per_day":250}]"#;
        let (code, body) = http_get(
            port,
            &format!("/api?mode=config&name=indexers&value={}&output=json", enc(entry)),
        );
        assert_eq!(code, 200, "{body}");
        let (code, body) = http_get(
            port,
            "/api?mode=config&name=corr_confirm_source&value=ref&output=json",
        );
        assert_eq!(code, 200, "{body}");

        let v = stats(port);
        assert_eq!(v["source_state"], "ok", "{v}");
        assert_eq!(
            v["per_day"], 200,
            "grabs bind at 250, so the budget is 200 - not the floor, not 400: {v}"
        );

        // An account that exists but is turned off resolves to nothing,
        // so the budget goes back to null rather than staying stale.
        let off = r#"[{"name":"ref","url":"http://127.0.0.1:1/api","apikey":"k","enabled":false,"hits_per_day":1000,"grabs_per_day":250}]"#;
        let (code, body) = http_get(
            port,
            &format!("/api?mode=config&name=indexers&value={}&output=json", enc(off)),
        );
        assert_eq!(code, 200, "{body}");
        let v = stats(port);
        assert_eq!(v["source_state"], "disabled", "{v}");
        assert!(
            v["per_day"].is_null(),
            "a disabled account spends nothing: {v}"
        );
    })
    .await
    .unwrap();
}
