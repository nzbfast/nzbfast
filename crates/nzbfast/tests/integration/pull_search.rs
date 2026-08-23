#![cfg(feature = "indexer")]
//! M35 gate: pull search end to end, with no network beyond loopback.
//!
//! Our own Newznab facade is a spec-true server, so one nzbfast plays
//! the indexer (daemon A: seeded index, apikey-protected) and a second
//! nzbfast plays the client (daemon B: A configured as an external
//! indexer). B's `indexer_search` must find A's release, hand back an
//! opaque token WITHOUT leaking A's apikey or NZB links to the caller,
//! and `indexer_grab` must fetch the NZB from A and enqueue it. Budgets
//! gate visibly, and expired/unknown tokens refuse cleanly.

use crate::scratch;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;

use crate::harness::serve;

use nzbkit::nntp::OverEntry;

/// (status, body) of a GET; connection refusals retried, answers never.
/// (See tests/integration/newznab.rs for why zero-bytes-back is retried.)
fn http_get(port: u16, req: &str) -> (u16, String) {
    let mut last = String::new();
    for attempt in 0..5u32 {
        match http_once(
            port,
            &format!("GET {req} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"),
        ) {
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

fn http_post_json(port: u16, req: &str, body: &str) -> (u16, String) {
    let msg = format!(
        "POST {req} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut last = String::new();
    for attempt in 0..5u32 {
        match http_once(port, &msg) {
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

fn http_once(port: u16, msg: &str) -> std::io::Result<(u16, String)> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    s.write_all(msg.as_bytes())?;
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
}

fn pct(s: &str) -> String {
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

fn over(number: u64, subject: &str, msgid: &str, bytes: u64) -> OverEntry {
    OverEntry {
        number,
        subject: subject.into(),
        from: "poster@x".into(),
        message_id: msgid.into(),
        bytes,
        date: 1_700_000_000,
    }
}

/// Standard daemon command against a dead news server.
fn daemon_cmd(dir: &Path, cfg: &Path, db: &Path, port: u16, extra: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
    c.env("NZBFAST_OPEN", "1")
        .env("NZBFAST_NO_ENRICH", "1")
        .arg("--config")
        .arg(cfg)
        .arg("serve")
        // Loopback only - see tests/integration/newznab.rs on the macOS
        // firewall.
        .arg("--bind")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(port.to_string())
        .arg("--out")
        .arg(dir.join("complete"))
        .arg("--index-db")
        .arg(db);
    for a in extra {
        c.arg(a);
    }
    c
}

/// A stand-in indexer that records the request lines it is asked for.
///
/// Our own facade cannot play this part: it deliberately does NOT
/// advertise `imdbid` in its caps, so a client is right to never send it
/// one - which is exactly the behaviour under test here, from the other
/// side. This one DOES advertise it, so the id path can be proven end to
/// end without touching a real indexer.
struct MockIndexer {
    port: u16,
    seen: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

fn mock_indexer() -> MockIndexer {
    mock_items(
        r#"<item><title>Kill.Bill.Vol.1.2003.1080p.BluRay.x264</title><guid>mock-1</guid>
<enclosure url="http://127.0.0.1:1/nzb/mock-1" length="8000000000" type="application/x-nzb"/>
<newznab:attr name="category" value="2000"/></item>"#,
    )
}

/// The same stand-in, serving a caller-supplied set of `<item>`s - and a
/// real (if tiny) NZB at any `/nzb/` path, so a grab against ANY of the
/// copies it lists completes rather than dying on the fetch.
fn mock_items(items: &str) -> MockIndexer {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    // `item()` writes the enclosure against a `{PORT}` it cannot know
    // yet; this is the only place the bound port exists.
    let items = items.replace("{PORT}", &port.to_string());
    std::thread::spawn(move || {
        for stream in l.incoming() {
            let Ok(mut s) = stream else { break };
            let mut buf = [0u8; 2048];
            let n = s.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let line = req.lines().next().unwrap_or("").to_string();
            log.lock().unwrap().push(line.clone());
            let (ctype, body) = if line.contains("t=caps") {
                (
                    "application/rss+xml",
                    r#"<?xml version="1.0"?><caps><server title="MockDex"/>
<limits max="100" default="100"/>
<searching><search available="yes" supportedParams="q"/>
<tv-search available="yes" supportedParams="q,tvdbid,season,ep"/>
<movie-search available="yes" supportedParams="q,imdbid"/></searching>
<categories><category id="2000" name="Movies"/></categories></caps>"#
                        .to_string(),
                )
            } else if line.contains("/nzb/") {
                (
                    "application/x-nzb",
                    r#"<?xml version="1.0" encoding="utf-8"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
<file poster="p@x" date="1700000000" subject="&quot;mock.part01.rar&quot; yEnc (1/1)">
<groups><group>alt.binaries.test</group></groups>
<segments><segment bytes="100" number="1">seg1@mock</segment></segments>
</file></nzb>"#
                        .to_string(),
                )
            } else {
                (
                    "application/rss+xml",
                    format!(
                        r#"<?xml version="1.0"?><rss xmlns:newznab="http://www.newznab.com/DTD/2010/feeds/attributes/"><channel>
{items}</channel></rss>"#
                    ),
                )
            };
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    MockIndexer { port, seen }
}

/// One `<item>` for `mock_items`.
fn item(title: &str, guid: &str, size: u64) -> String {
    format!(
        r#"<item><title>{title}</title><guid>{guid}</guid>
<enclosure url="http://127.0.0.1:{{PORT}}/nzb/{guid}" length="{size}" type="application/x-nzb"/>
<newznab:attr name="category" value="5000"/></item>"#
    )
}

/// M35 phase 2: a film searched from its title page is matched on its
/// IMDb id, not on the words in its name - and the id is resolved by the
/// DAEMON from the title key, never supplied by the browser.
#[tokio::test(flavor = "multi_thread")]
async fn a_title_page_search_uses_the_imdb_id() {
    let dir = std::env::temp_dir().join(format!("nzbfast-pullid-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // A local title row carrying the id the search must pick up.
    let db = dir.join("index.db");
    {
        let ix = nzbkit::index::Index::open(&db).unwrap();
        ix.title_seed("m:kill bill:2003", "movie", "Kill Bill", 2003)
            .unwrap();
        ix.title_fill(
            "m:kill bill:2003",
            &nzbkit::index::TitleFill {
                imdb: "tt0266697",
                ..Default::default()
            },
            1_700_000_000,
        )
        .unwrap();
    }
    let mock = mock_indexer();
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        "{\"servers\":[{\"host\":\"127.0.0.1\",\"port\":1,\"tls\":false}]}",
    )
    .unwrap();
    // The id is resolved from the LOCAL titles table, which the daemon
    // will not open while the built-in indexer's master switch is off
    // (its default). A title page only exists when that switch is on
    // anyway, so this is the honest configuration for this test.
    std::fs::write(
        cfg.with_file_name("settings.json"),
        "{\"index_enabled\": true}",
    )
    .unwrap();
    let d = serve(&dir, |port| daemon_cmd(&dir, &cfg, &db, port, &[])).await;
    let port = d.port;
    let mport = mock.port;
    let seen = mock.seen.clone();

    tokio::task::spawn_blocking(move || {
        let entry =
            format!(r#"[{{"name":"mock","url":"http://127.0.0.1:{mport}/api","apikey":"k"}}]"#);
        let (_, r) = http_get(
            port,
            &format!("/api?mode=config&name=indexers&value={}&output=json", pct(&entry)),
        );
        assert!(r.contains("true"), "{r}");

        // The browser sends the TITLE KEY, never an id.
        let (_, s) = http_get(
            port,
            "/api?mode=indexer_search&q=Kill+Bill&kind=movie&title_key=m%3Akill+bill%3A2003&output=json",
        );
        let sv: serde_json::Value = serde_json::from_str(&s).unwrap_or_default();
        assert_eq!(sv["status"], true, "{s}");
        assert_eq!(sv["results"].as_array().map(Vec::len), Some(1), "{s}");

        let lines = seen.lock().unwrap().clone();
        // Caps were probed, then the search went out as t=movie carrying
        // the bare id - "tt" stripped, per the protocol.
        assert!(lines.iter().any(|l| l.contains("t=caps")), "{lines:?}");
        let search = lines.iter().find(|l| l.contains("t=movie")).unwrap_or_else(|| {
            panic!("no t=movie request; the id was not used:\n{lines:?}")
        });
        assert!(search.contains("imdbid=0266697"), "{search}");

        // A title we hold no id for degrades to a plain free-text
        // search rather than sending a bogus id.
        seen.lock().unwrap().clear();
        let (_, s2) = http_get(
            port,
            "/api?mode=indexer_search&q=Nothing&kind=movie&title_key=m%3Anothing%3A1999&output=json",
        );
        assert!(s2.contains("\"status\":true"), "{s2}");
        let lines = seen.lock().unwrap().clone();
        assert!(
            lines.iter().any(|l| l.contains("t=search")) && !lines.iter().any(|l| l.contains("imdbid=")),
            "an unknown title should not carry an id: {lines:?}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The TV half of the same rule (TODO 187 follow-up): a series searched
/// from its card carries its TheTVDB id.
///
/// This path sent no id at all for years, under a comment saying the
/// only TV id we store is a TVmaze show id in a different namespace -
/// true when it was written, and untrue since `titles.tvdb` and its
/// backfill lane landed. A stale comment is a capability nobody
/// notices missing, so the id goes on the wire in a test.
#[tokio::test(flavor = "multi_thread")]
async fn a_series_page_search_uses_the_tvdb_id() {
    let dir = std::env::temp_dir().join(format!("nzbfast-pulltv-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let db = dir.join("index.db");
    {
        let ix = nzbkit::index::Index::open(&db).unwrap();
        ix.title_seed("t:breaking bad", "tv", "Breaking Bad", 0)
            .unwrap();
        // The TVmaze show id and the TVDB series id are different
        // numbers in different namespaces, and only one of them is a
        // tvdbid. Both are set here so a fix that reached for the wrong
        // column would be visible on the wire.
        ix.title_fill(
            "t:breaking bad",
            &nzbkit::index::TitleFill {
                tmdb_id: 431,
                ..Default::default()
            },
            1_700_000_000,
        )
        .unwrap();
        ix.title_set_tvdb("t:breaking bad", 81189).unwrap();
    }
    let mock = mock_indexer();
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        "{\"servers\":[{\"host\":\"127.0.0.1\",\"port\":1,\"tls\":false}]}",
    )
    .unwrap();
    std::fs::write(
        cfg.with_file_name("settings.json"),
        "{\"index_enabled\": true}",
    )
    .unwrap();
    let d = serve(&dir, |port| daemon_cmd(&dir, &cfg, &db, port, &[])).await;
    let port = d.port;
    let mport = mock.port;
    let seen = mock.seen.clone();

    tokio::task::spawn_blocking(move || {
        let entry =
            format!(r#"[{{"name":"mock","url":"http://127.0.0.1:{mport}/api","apikey":"k"}}]"#);
        let (_, r) = http_get(
            port,
            &format!(
                "/api?mode=config&name=indexers&value={}&output=json",
                pct(&entry)
            ),
        );
        assert!(r.contains("true"), "{r}");

        let (_, s) = http_get(
            port,
            "/api?mode=indexer_search&q=Breaking+Bad&kind=tv\
             &title_key=t%3Abreaking+bad&season=1&ep=1&output=json",
        );
        assert!(s.contains("\"status\":true"), "{s}");
        let lines = seen.lock().unwrap().clone();
        let search = lines
            .iter()
            .find(|l| l.contains("t=tvsearch"))
            .unwrap_or_else(|| panic!("no t=tvsearch request; the id was not used:\n{lines:?}"));
        assert!(search.contains("tvdbid=81189"), "{search}");
        // The TVmaze show id shares a column with movie TMDB ids and is
        // NOT a tvdbid; it must never be the number sent.
        assert!(!search.contains("tvdbid=431"), "{search}");
        // The episode fields ride along, because this indexer takes them.
        assert!(
            search.contains("season=1") && search.contains("ep=1"),
            "{search}"
        );

        // A series we hold no TVDB id for sends none, and narrows with
        // the episode marker instead.
        seen.lock().unwrap().clear();
        let (_, s2) = http_get(
            port,
            "/api?mode=indexer_search&q=Unknown+Show&kind=tv\
             &title_key=t%3Aunknown+show&season=2&ep=3&output=json",
        );
        assert!(s2.contains("\"status\":true"), "{s2}");
        let lines = seen.lock().unwrap().clone();
        assert!(
            !lines.iter().any(|l| l.contains("tvdbid=")),
            "an unknown series should not carry an id: {lines:?}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// M35 phase 2: the watchlist's external leg. A watched show with
/// NOTHING in the local index finds its episode on the peer indexer and
/// grabs it.
///
/// M35b changed WHEN: the leg is on by default once an indexer account
/// exists, because a watchlist that can only see the local index cannot
/// see an obfuscated post at all. The guard rails are the per-item
/// cadence and the per-indexer daily budgets, not an off switch - and an
/// explicit off still wins, forever, including across a later change to
/// the indexer list. All three of those are asserted here.
#[tokio::test(flavor = "multi_thread")]
async fn watchlist_external_defaults_on_but_an_explicit_off_wins() {
    let dir = std::env::temp_dir().join(format!("nzbfast-pullwl-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Peer A carries the episode; our own index (B) is empty.
    let dir_a = dir.join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    let db_a = dir_a.join("index.db");
    {
        let mut ix = nzbkit::index::Index::open(&db_a).unwrap();
        ix.ingest(
            "alt.binaries.teevee",
            &[
                over(
                    1,
                    "\"Wanted.Show.S02E05.1080p.WEB.rar\" yEnc (1/1)",
                    "<w1@x>",
                    4000,
                ),
                over(
                    2,
                    "\"Wanted.Show.S02E05.1080p.WEB.par2\" yEnc (1/1)",
                    "<w2@x>",
                    400,
                ),
            ],
            1_700_000_000,
        )
        .unwrap();
    }
    let cfg_a = dir_a.join("config.json");
    std::fs::write(
        &cfg_a,
        "{\"servers\":[{\"host\":\"127.0.0.1\",\"port\":1,\"tls\":false}]}",
    )
    .unwrap();
    // A publishes its index over newznab, so its built-in indexer is on.
    // B deliberately leaves the switch at its default OFF: this test is
    // then also the regression for the watchlist's external leg working
    // with no local index at all, which is the ordinary new install.
    std::fs::write(
        cfg_a.with_file_name("settings.json"),
        "{\"index_enabled\": true}",
    )
    .unwrap();
    let a = serve(&dir_a, |port| daemon_cmd(&dir_a, &cfg_a, &db_a, port, &[])).await;
    let port_a = a.port;

    let dir_b = dir.join("b");
    std::fs::create_dir_all(&dir_b).unwrap();
    let cfg_b = dir_b.join("config.json");
    std::fs::write(
        &cfg_b,
        "{\"servers\":[{\"host\":\"127.0.0.1\",\"port\":1,\"tls\":false}]}",
    )
    .unwrap();
    let db_b = dir_b.join("index.db");
    let b = serve(&dir_b, |port| daemon_cmd(&dir_b, &cfg_b, &db_b, port, &[])).await;
    let port_b = b.port;

    tokio::task::spawn_blocking(move || {
        let entry = format!(
            r#"[{{"name":"peer","url":"http://127.0.0.1:{port_a}/api","apikey":"x"}}]"#
        );
        let (_, r) = http_get(
            port_b,
            &format!("/api?mode=config&name=indexers&value={}&output=json", pct(&entry)),
        );
        assert!(r.contains("true"), "{r}");

        // Nobody has answered the question, and an indexer now exists, so
        // the effective setting is ON - and get_config must report the
        // EFFECTIVE value or the dashboard checkbox would disagree with
        // what the watcher actually does.
        let (_, cfg) = http_get(port_b, "/api?mode=get_config&output=json");
        assert!(
            cfg.contains("\"watchlist_external\":true"),
            "an indexer is configured and nobody said otherwise, so the leg should be on:\n{cfg}"
        );

        // Now answer it explicitly OFF, BEFORE there is anything to grab.
        // (The config write answers with a status envelope, so the value
        // itself is read back through get_config.)
        let (_, r) =
            http_get(port_b, "/api?mode=config&name=watchlist_external&value=0&output=json");
        assert!(r.contains("\"status\":true"), "{r}");
        let (_, cfg) = http_get(port_b, "/api?mode=get_config&output=json");
        assert!(cfg.contains("\"watchlist_external\":false"), "{cfg}");

        // Watch the show. The local index has nothing, so the external
        // leg is the only way this could ever be grabbed.
        let wl = r#"[{"id":1,"kind":"tv","title":"Wanted Show","seasons":"","episodes":"","min_quality":"any","target_quality":"1080p","enabled":true}]"#;
        let (_, r) = http_get(
            port_b,
            &format!("/api?mode=config&name=watchlist&value={}&output=json", pct(wl)),
        );
        assert!(r.contains("true"), "{r}");

        // Explicitly off: a check now must NOT queue anything, and must
        // not spend a search either.
        http_get(port_b, "/api?mode=watchlist_check_now&output=json");
        std::thread::sleep(std::time::Duration::from_millis(1500));
        let (_, q) = http_get(port_b, "/api?mode=queue&output=json");
        assert!(
            !q.contains("Wanted.Show"),
            "the watchlist reached an indexer while the toggle was explicitly off:\n{q}"
        );

        // Editing the indexer list must not resurrect the leg. This is
        // the regression that the tri-state exists for: deriving the
        // default from "has indexers" without remembering the answer
        // would turn it back on here.
        let two = format!(
            r#"[{{"name":"peer","url":"http://127.0.0.1:{port_a}/api","apikey":"x"}},{{"name":"peer2","url":"http://127.0.0.1:{port_a}/api","apikey":"y"}}]"#
        );
        let (_, r) = http_get(
            port_b,
            &format!("/api?mode=config&name=indexers&value={}&output=json", pct(&two)),
        );
        assert!(r.contains("true"), "{r}");
        let (_, cfg) = http_get(port_b, "/api?mode=get_config&output=json");
        assert!(
            cfg.contains("\"watchlist_external\":false"),
            "adding an indexer overrode an explicit off:\n{cfg}"
        );

        // Turn it on, and the same item now finds the episode on the peer.
        let (_, r) =
            http_get(port_b, "/api?mode=config&name=watchlist_external&value=1&output=json");
        assert!(r.contains("true"), "{r}");
        http_get(port_b, "/api?mode=watchlist_check_now&output=json");
        let mut queued = String::new();
        for _ in 0..60 {
            let (_, q) = http_get(port_b, "/api?mode=queue&output=json");
            if q.contains("Wanted.Show.S02E05") {
                queued = q;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        assert!(!queued.is_empty(), "watchlist never grabbed from the indexer");
        // Attributed to the watchlist, not to a click.
        assert!(queued.contains("watchlist"), "{queued}");

        // The setting survives a get_config round-trip as a real bool.
        let (_, cfg) = http_get(port_b, "/api?mode=get_config&output=json");
        assert!(cfg.contains("\"watchlist_external\":true"), "{cfg}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn pull_search_grabs_from_a_second_nzbfast() {
    let dir = std::env::temp_dir().join(format!("nzbfast-pull-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Daemon A: the "commercial indexer". Seeded index, key-protected.
    let dir_a = dir.join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    let db_a = dir_a.join("index.db");
    {
        let mut ix = nzbkit::index::Index::open(&db_a).unwrap();
        ix.ingest(
            "alt.binaries.teevee",
            &[
                over(
                    1,
                    "\"Pull.Show.S01E02.1080p.rar\" yEnc (1/1)",
                    "<p1@x>",
                    1000,
                ),
                over(
                    2,
                    "\"Pull.Show.S01E02.1080p.par2\" yEnc (1/1)",
                    "<p2@x>",
                    200,
                ),
            ],
            1_700_000_000,
        )
        .unwrap();
    }
    let cfg_a = dir_a.join("config.json");
    std::fs::write(
        &cfg_a,
        "{\"servers\":[{\"host\":\"127.0.0.1\",\"port\":1,\"tls\":false}]}",
    )
    .unwrap();
    // A is playing the role of a third-party indexer, so its built-in
    // indexer has to be switched on - that switch defaults OFF and
    // closes the newznab facade with it. B deliberately leaves it off,
    // which is the case this whole feature exists for: pull search
    // works with no local index at all.
    std::fs::write(
        cfg_a.with_file_name("settings.json"),
        "{\"index_enabled\": true}",
    )
    .unwrap();
    let a = serve(&dir_a, |port| {
        daemon_cmd(&dir_a, &cfg_a, &db_a, port, &["--apikey", "sekrit"])
    })
    .await;
    let port_a = a.port;

    // Daemon B: the client under test. Keyless-open, empty index.
    let dir_b = dir.join("b");
    std::fs::create_dir_all(&dir_b).unwrap();
    let cfg_b = dir_b.join("config.json");
    std::fs::write(
        &cfg_b,
        "{\"servers\":[{\"host\":\"127.0.0.1\",\"port\":1,\"tls\":false}]}",
    )
    .unwrap();
    let db_b = dir_b.join("index.db");
    let b = serve(&dir_b, |port| daemon_cmd(&dir_b, &cfg_b, &db_b, port, &[])).await;
    let port_b = b.port;

    tokio::task::spawn_blocking(move || {
        // Configure A as an external indexer on B, with a 2-hit budget.
        let entry = format!(
            r#"[{{"name":"peer","url":"http://127.0.0.1:{port_a}/api","apikey":"sekrit","hits_per_day":2}}]"#
        );
        let (code, body) = http_get(
            port_b,
            &format!("/api?mode=config&name=indexers&value={}&output=json", pct(&entry)),
        );
        assert_eq!(code, 200, "{body}");
        assert!(body.contains("true"), "saving indexers failed: {body}");

        // get_config reports the entry but never echoes the key.
        let (_, cfgout) = http_get(port_b, "/api?mode=get_config&output=json");
        assert!(cfgout.contains("\"peer\""), "{cfgout}");
        assert!(cfgout.contains("\"has_key\":true"), "{cfgout}");
        assert!(!cfgout.contains("sekrit"), "apikey echoed to the UI:\n{cfgout}");

        // Test button: blank key borrows the stored one, caps answer.
        let (_, t) = http_post_json(
            port_b,
            "/api?mode=indexer_test&output=json",
            r#"{"indexer":{"name":"peer","url":"","apikey":""}}"#,
        );
        assert!(t.contains("needs a URL"), "{t}");
        let url = format!("http://127.0.0.1:{port_a}/api");
        let (_, t) = http_post_json(
            port_b,
            "/api?mode=indexer_test&output=json",
            &format!(r#"{{"indexer":{{"name":"peer","url":"{url}","apikey":""}}}}"#),
        );
        let tv: serde_json::Value = serde_json::from_str(&t).unwrap_or_default();
        assert_eq!(tv["status"], true, "indexer_test failed: {t}");
        assert_eq!(tv["server"], "nzbfast", "{t}");

        // Search B: the result comes from A, tokenized, nothing leaked.
        let (_, s) = http_get(port_b, "/api?mode=indexer_search&q=pull+show&output=json");
        let sv: serde_json::Value = serde_json::from_str(&s).unwrap_or_default();
        assert_eq!(sv["status"], true, "{s}");
        let results = sv["results"].as_array().expect("results array");
        assert_eq!(results.len(), 1, "{s}");
        let r = &results[0];
        assert_eq!(r["indexer"], "peer", "{s}");
        assert!(r["title"].as_str().unwrap().contains("Pull.Show.S01E02"), "{s}");
        assert_eq!(r["kind"], "tv", "{s}");
        assert!(!s.contains("sekrit"), "apikey leaked into search results:\n{s}");
        assert!(!s.contains("getnzb"), "raw NZB link leaked into search results:\n{s}");
        let token = r["token"].as_str().expect("token").to_string();

        // Grab by token: B fetches the NZB from A and enqueues it.
        let (_, g) = http_get(
            port_b,
            &format!("/api?mode=indexer_grab&token={token}&priority=1&output=json"),
        );
        let gv: serde_json::Value = serde_json::from_str(&g).unwrap_or_default();
        assert_eq!(gv["status"], true, "indexer_grab failed: {g}");
        assert!(gv["nzo_ids"][0].as_str().is_some(), "{g}");

        // The job really is queued, attributed to the pull search.
        let (_, q) = http_get(port_b, "/api?mode=queue&output=json");
        assert!(q.contains("Pull.Show.S01E02"), "{q}");

        // An unknown token refuses cleanly - the grab surface accepts
        // nothing the search did not mint.
        let (_, bad) = http_get(port_b, "/api?mode=indexer_grab&token=doesnotexist&output=json");
        assert!(bad.contains("expired"), "{bad}");

        // Budget: hits_per_day=2, one spent. The second search works,
        // the third is skipped VISIBLY.
        let (_, s2) = http_get(port_b, "/api?mode=indexer_search&q=pull+show&output=json");
        assert!(s2.contains("\"results\""), "{s2}");
        let (_, s3) = http_get(port_b, "/api?mode=indexer_search&q=pull+show&output=json");
        let s3v: serde_json::Value = serde_json::from_str(&s3).unwrap_or_default();
        assert_eq!(s3v["results"].as_array().map(Vec::len), Some(0), "{s3}");
        assert!(s3.contains("daily API budget reached"), "{s3}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Issue #44: the same release listed by several indexers comes back as
/// ONE row carrying every copy, and the merge fires on the differences
/// that are only formatting while refusing the ones that are not.
///
/// Three indexers at three priorities, and four items between them:
///
/// - `top` (priority 1) and `mid` (5) both list the 1080p at ~3 GB,
///   spelled differently and sized differently. ONE row, headline
///   `top`, `mid` kept as its alternate.
/// - `low` (9) lists the 2160p at almost exactly the same size. A
///   SEPARATE row: a size coincidence must never fold a resolution the
///   user did not ask for into the one they did.
/// - `mid` also lists a 1080p under the identical name at 9 GB. Also a
///   separate row: one name can still be two posts.
///
/// Then the alternate's own token is grabbed, and the job that lands
/// carries `mid`'s spelling of the name - which is the point of the
/// feature, not a detail of it: a dead NZB on your best indexer is
/// meant to be one click away from a live one somewhere else.
#[tokio::test(flavor = "multi_thread")]
async fn copies_of_one_release_group_into_one_row_with_a_grab_each() {
    let dir = std::env::temp_dir().join(format!("nzbfast-pullgrp-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    const GB: u64 = 1_000_000_000;
    let top = mock_items(&item(
        "Show.Name.S01E02.1080p.WEB-DL.x264-GRP",
        "t1",
        3 * GB,
    ));
    // Dots for spaces, all lower case, a trailing `.nzb`, and 40 MB of
    // par2 accounting between them: four ways of saying the same thing.
    let mid = mock_items(&format!(
        "{}\n{}",
        item(
            "show name s01e02 1080p web-dl x264-grp.nzb",
            "m1",
            3 * GB + 40_000_000
        ),
        item("Show.Name.S01E02.1080p.WEB-DL.x264-GRP", "m2", 9 * GB),
    ));
    let low = mock_items(&item(
        "Show.Name.S01E02.2160p.WEB-DL.x264-GRP",
        "l1",
        3 * GB + 5_000_000,
    ));

    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        "{\"servers\":[{\"host\":\"127.0.0.1\",\"port\":1,\"tls\":false}]}",
    )
    .unwrap();
    let db = dir.join("index.db");
    let d = serve(&dir, |port| daemon_cmd(&dir, &cfg, &db, port, &[])).await;
    let port = d.port;
    let (pt, pm, pl) = (top.port, mid.port, low.port);

    tokio::task::spawn_blocking(move || {
        let entry = format!(
            r#"[{{"name":"top","url":"http://127.0.0.1:{pt}/api","apikey":"k","priority":1}},
                {{"name":"mid","url":"http://127.0.0.1:{pm}/api","apikey":"k","priority":5}},
                {{"name":"low","url":"http://127.0.0.1:{pl}/api","apikey":"k","priority":9}}]"#
        );
        let (_, r) = http_get(
            port,
            &format!(
                "/api?mode=config&name=indexers&value={}&output=json",
                pct(&entry)
            ),
        );
        assert!(r.contains("true"), "{r}");

        let (_, s) = http_get(port, "/api?mode=indexer_search&q=show+name&output=json");
        let sv: serde_json::Value = serde_json::from_str(&s).unwrap_or_default();
        assert_eq!(sv["status"], true, "{s}");
        let rows = sv["results"].as_array().expect("results array");
        assert_eq!(rows.len(), 3, "four copies, three releases:\n{s}");

        let find = |needle: &str, size: u64| {
            rows.iter()
                .find(|r| {
                    r["title"].as_str().unwrap_or("").contains(needle)
                        && r["size"].as_u64().unwrap_or(0) == size
                })
                .unwrap_or_else(|| panic!("no {needle} row at {size}:\n{s}"))
        };

        // The merged row: two copies, the priority-1 indexer heading it.
        let merged = find("1080p", 3 * GB);
        assert_eq!(
            merged["indexer"], "top",
            "highest priority heads the row:\n{s}"
        );
        let srcs = merged["sources"].as_array().expect("sources array");
        assert_eq!(srcs.len(), 2, "both copies survive the merge:\n{s}");
        assert_eq!(
            srcs[0]["indexer"], "top",
            "sources[0] is the headline:\n{s}"
        );
        assert_eq!(
            srcs[1]["indexer"], "mid",
            "alternates follow in priority order:\n{s}"
        );
        assert_eq!(
            srcs[0]["token"], merged["token"],
            "the row grabs its headline:\n{s}"
        );
        assert_ne!(
            srcs[1]["token"], merged["token"],
            "each copy needs its own token:\n{s}"
        );
        // The alternate carries its OWN facts, not the headline's.
        assert_eq!(srcs[1]["size"].as_u64(), Some(3 * GB + 40_000_000), "{s}");
        assert_eq!(
            srcs[1]["title"], "show name s01e02 1080p web-dl x264-grp.nzb",
            "{s}"
        );

        // ...and the two that must NOT have been folded in are rows of
        // their own, each a single-copy list rather than no list at all.
        for (needle, size, who) in [
            ("2160p", 3 * GB + 5_000_000, "low"),
            ("1080p", 9 * GB, "mid"),
        ] {
            let row = find(needle, size);
            assert_eq!(row["indexer"], who, "{s}");
            assert_eq!(
                row["sources"].as_array().map(Vec::len),
                Some(1),
                "a lone copy still ships a one-entry list:\n{s}"
            );
        }

        // Grab the ALTERNATE. It is `mid`'s copy that must land, under
        // `mid`'s spelling of the name.
        let alt = srcs[1]["token"].as_str().expect("alternate token");
        let (_, g) = http_get(
            port,
            &format!("/api?mode=indexer_grab&token={alt}&priority=1&output=json"),
        );
        let gv: serde_json::Value = serde_json::from_str(&g).unwrap_or_default();
        assert_eq!(gv["status"], true, "grabbing an alternate failed: {g}");
        let (_, q) = http_get(port, "/api?mode=queue&output=json");
        assert!(
            q.contains("show name s01e02 1080p web-dl x264-grp"),
            "the alternate's own copy should have been queued:\n{q}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
