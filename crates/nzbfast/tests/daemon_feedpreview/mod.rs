//! TODO §239: `mode=feed_preview`, the dry run behind the RSS editor's
//! Preview button.
//!
//! A submodule of the daemon target rather than its own `tests/*.rs`,
//! for the reason every sibling here is one: a top-level file would
//! become a separate target and fall out of the standard daemon gate.
//! It also keeps daemon.rs under the size gate.
//!
//! It shipped with ZERO tests. Three code hits tree-wide -
//! `m_feed_preview` in `serve/api/servers.rs`, its dispatch arm, and
//! the dashboard's own `apiPost('feed_preview', ...)` - and nothing
//! held any of them to anything, so every part of the reply shape the
//! editor renders was free to move.
//!
//! What makes it worth a rig rather than a unit test on `rules_judge`:
//! the verdict this endpoint publishes is NOT the judgement. Two of the
//! three columns the editor shows are assembled here and nowhere else -
//! "seen" outranks the rules entirely (it is read from the poller's own
//! persisted `rss-seen.json`, so it means what the poller means), and
//! the category a grab reports falls back to the FEED's category only
//! when the deciding Accept rule named none. Neither is reachable from
//! `rules_judge`, which knows nothing about either.

use super::*;

/// One HTTP server on loopback answering `body` to the next `n`
/// requests. The preview fetches the feed for real - loopback is
/// deliberately reachable through the SSRF guard - so this is the
/// whole of the mock it needs.
fn serve_feed(body: String, n: usize) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/rss", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for sock in listener.incoming().flatten().take(n) {
            let mut sock = sock;
            let mut buf = [0u8; 2048];
            let _ = sock.read(&mut buf);
            let _ = sock.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            );
        }
    });
    url
}

/// The row the preview returned for the item whose title contains
/// `needle`, with the whole reply in the panic if there is none.
fn row<'a>(p: &'a serde_json::Value, needle: &str) -> &'a serde_json::Value {
    p["items"]
        .as_array()
        .unwrap_or_else(|| panic!("no items array: {p}"))
        .iter()
        .find(|i| i["title"].as_str().unwrap_or("").contains(needle))
        .unwrap_or_else(|| panic!("no item matching {needle:?}: {p}"))
}

/// §239: the three things the preview says about an item - the verdict,
/// the rule that decided it, and the category/priority a grab would use.
///
/// Rewritten against the shipped shapes from the version that never
/// landed: the reply carries a three-way `verdict` (`grab` / `skip` /
/// `seen`) plus `why`, not a bare `accepted` flag, and duplicate here
/// means the POLLER's duplicate - a guid already in `rss-seen.json` -
/// not a collision with the queue.
#[tokio::test]
async fn feed_preview_shows_matches_overrides_and_dupes() {
    let dir = std::env::temp_dir().join(format!("nzbfast-feedprev-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let cfg = dir.join("config.json");
    std::fs::write(&cfg, "{\"servers\":[]}").unwrap();
    // The poller's own seen-set, where the daemon will look for it
    // (`spool_dir` is the config's sibling `.spool`). Seeding it before
    // startup is what makes the "seen" arm reachable without running a
    // poll: g3 has been grabbed before, so the preview must say so even
    // though the rules would grab it again.
    std::fs::create_dir_all(dir.join(".spool")).unwrap();
    std::fs::write(dir.join(".spool").join("rss-seen.json"), r#"["g3"]"#).unwrap();

    // Four items: a rule-matched grab, a rejected one, an already-seen
    // one the rules WOULD grab, and one no Accept rule reaches.
    let feed = "<?xml version=\"1.0\"?><rss><channel>\
        <item><title>Great.Show.S03E07.1080p.WEB</title>\
        <guid>g1</guid><enclosure url=\"http://x/1\" length=\"1000\"/></item>\
        <item><title>Great.Show.S03E07.480p.WEB</title>\
        <guid>g2</guid><enclosure url=\"http://x/2\" length=\"500\"/></item>\
        <item><title>Great.Show.S03E08.1080p.WEB</title>\
        <guid>g3</guid><enclosure url=\"http://x/3\" length=\"1100\"/></item>\
        <item><title>Some.Movie.2026.720p</title>\
        <guid>g4</guid><enclosure url=\"http://x/4\" length=\"900\"/></item>\
        </channel></rss>";
    let feed_url = serve_feed(feed.to_string(), 8);

    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_OPEN", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--port")
            .arg(port.to_string())
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    // GET is refused: the body carries the feed URL, which may have
    // credentials in it, and a GET would put them in the access log.
    let g = http(port, "/api?mode=feed_preview&output=json", None);
    assert!(g.contains("POST required"), "GET must be refused: {g}");

    // A POST with no url is a refusal, not an empty preview.
    let n = http(
        port,
        "/api?mode=feed_preview&output=json",
        Some(("application/json", b"{}")),
    );
    assert!(n.contains("no url"), "an urlless preview must say so: {n}");

    let body = serde_json::json!({
        "url": feed_url,
        // The 1080p Accept carries its OWN category and priority; the
        // catch-all one below it carries neither, so its grabs must
        // fall back to the feed's category and to the no-priority
        // sentinel.
        "rules": [
            "Reject: *480p*",
            "Accept(category=tv, priority=high): *1080p*",
            "Accept: *Great.Show*",
        ],
        "category": "movies",
    })
    .to_string();
    let raw = http(
        port,
        "/api?mode=feed_preview&output=json",
        Some(("application/json", body.as_bytes())),
    );
    let p: serde_json::Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("not JSON ({e}): {raw}"));
    assert_eq!(p["status"], true, "{p}");
    assert_eq!(p["total"], 4, "every feed item is counted: {p}");
    assert_eq!(p["items"].as_array().map(Vec::len), Some(4), "{p}");

    // MATCH: the first Accept that hits decides, and says so verbatim.
    let hit = row(&p, "S03E07.1080p");
    assert_eq!(hit["verdict"], "grab", "{hit}");
    assert!(
        hit["why"].as_str().unwrap_or("").contains("*1080p*"),
        "why must name the deciding rule as written: {hit}"
    );
    assert_eq!(hit["size"], 1000, "{hit}");
    // OVERRIDE: the deciding rule's options beat the feed's category.
    assert_eq!(hit["category"], "tv", "{hit}");
    assert_eq!(hit["priority"], 1, "high = 1: {hit}");

    // A Reject short-circuits, whatever the Accepts below it say.
    let miss = row(&p, "480p");
    assert_eq!(miss["verdict"], "skip", "{miss}");
    assert!(
        miss["why"].as_str().unwrap_or("").contains("*480p*"),
        "{miss}"
    );

    // DUPE: already in the poller's seen-set. The rules would grab it -
    // it is the same 1080p pattern - so this is the arm that proves
    // "seen" outranks the judgement rather than merely agreeing with it.
    let dupe = row(&p, "S03E08");
    assert_eq!(dupe["verdict"], "seen", "an already-grabbed guid: {dupe}");

    // No Accept rule reaches it: not a Reject, still not a grab.
    let none = row(&p, "Some.Movie");
    assert_eq!(none["verdict"], "skip", "{none}");
    assert!(
        none["why"].as_str().unwrap_or("").contains("no Accept"),
        "{none}"
    );

    // FALLBACK, from the same reply: the catch-all Accept named no
    // options, so the grab reports the FEED's category and the
    // no-priority sentinel. Checked on a rule list without the
    // overriding Accept, so the item is decided by the catch-all.
    let body = serde_json::json!({
        "url": feed_url,
        "rules": ["Accept: *Great.Show*"],
        "category": "movies",
    })
    .to_string();
    let raw = http(
        port,
        "/api?mode=feed_preview&output=json",
        Some(("application/json", body.as_bytes())),
    );
    let p: serde_json::Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("not JSON ({e}): {raw}"));
    let hit = row(&p, "S03E07.1080p");
    assert_eq!(hit["verdict"], "grab", "{hit}");
    assert_eq!(hit["category"], "movies", "the FEED's category: {hit}");
    assert_eq!(hit["priority"], -100, "the no-priority sentinel: {hit}");

    // Nothing was enqueued by any of it - a dry run stays dry.
    let q = http(port, "/api?mode=queue&output=json", None);
    assert!(
        q.contains("\"slots\":[]"),
        "a preview must not enqueue: {q}"
    );

    let _log = d.stop();
    let _ = std::fs::remove_dir_all(&dir);
}
