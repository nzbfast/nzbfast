#![cfg(feature = "indexer")]
//! M13 gate seed: the poster wall - releases parse into title cards,
//! encodes of one film dedupe onto one card, TV seasons group under one
//! show, obfuscated stems stay hidden, /wall serves the UI, /m3u hands a
//! playlist to an external player.

use crate::scratch;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;

use crate::harness::serve;
use nzbkit::nntp::OverEntry;

fn http_get(port: u16, req: &str) -> (u16, String) {
    let mut request = Vec::new();
    write!(
        request,
        "GET {req} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    split_response(&raw(port, &request))
}

fn http_post(port: u16, req: &str, content_type: &str, body: &[u8]) -> (u16, String) {
    let mut request = Vec::new();
    write!(
        request,
        "POST {req} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: {content_type}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .unwrap();
    request.extend_from_slice(body);
    split_response(&raw(port, &request))
}

/// (status, body) off the wire. Lossy because /art bodies are binary.
///
/// De-chunks, because tiny_http sends `Transfer-Encoding: chunked` for
/// any response at or above its 32 KB `chunked_threshold` - which /wall
/// (~175 KB) is. Without this the "body" carries a `\r\n<hex>\r\n` chunk
/// header every 8192 bytes, wherever that falls: the substring
/// assertions below then hold only for as long as no boundary happens to
/// land inside the string being searched for, and an ordinary edit to
/// the page can move one there. (http_wedge.rs had the same helper and
/// the same latent break, but read strictly rather than lossily, so it
/// failed outright the day a boundary split a multi-byte character.)
fn split_response(bytes: &[u8]) -> (u16, String) {
    let head_end = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4);
    let head = String::from_utf8_lossy(&bytes[..head_end.unwrap_or(bytes.len())]).into_owned();
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let Some(at) = head_end else {
        return (status, String::new());
    };
    let body = &bytes[at..];
    let body = if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        dechunk(body)
    } else {
        body.to_vec()
    };
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// Minimal `Transfer-Encoding: chunked` decoder - enough for what
/// tiny_http emits (hex length, CRLF, bytes, CRLF, terminated by a
/// zero-length chunk). Chunk extensions after a `;` are tolerated.
fn dechunk(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(nl) = b.windows(2).position(|w| w == b"\r\n") {
        let line = String::from_utf8_lossy(&b[..nl]);
        let n = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16).unwrap_or(0);
        if n == 0 {
            break; // terminating chunk
        }
        let (start, end) = (nl + 2, nl + 2 + n);
        if end > b.len() {
            out.extend_from_slice(&b[start.min(b.len())..]); // truncated
            break;
        }
        out.extend_from_slice(&b[start..end]);
        b = &b[(end + 2).min(b.len())..]; // skip the chunk's trailing CRLF
    }
    out
}

/// A request to the daemon, response headers and all.
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
fn raw(port: u16, request: &[u8]) -> Vec<u8> {
    let mut last = String::new();
    for attempt in 0..5u32 {
        match raw_once(port, request) {
            Ok(out) => return out,
            Err(e) => {
                last = e.to_string();
                std::thread::sleep(std::time::Duration::from_millis(
                    100 * u64::from(attempt) + 50,
                ));
            }
        }
    }
    let line = String::from_utf8_lossy(request)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    panic!("daemon on :{port} never answered {line:?}: {last}");
}

/// One attempt. Returns Err ONLY when the daemon produced nothing at all;
/// a partial or malformed response is data, and is handed back for the
/// caller's assertions to judge.
fn raw_once(port: u16, request: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    s.write_all(request)?;
    let mut out = Vec::new();
    // Zero bytes back is a refusal to serve, however the peer
    // phrased it: an RST (Err) when our request was never read off
    // the receive buffer, a plain FIN (Ok) when it was read and then
    // dropped unanswered. Neither carries anything to judge, so both
    // are retried. The moment ANY byte arrives it is an answer and is
    // returned exactly as it came - errors included - because a
    // truncated body must never be retried away.
    let read = s.read_to_end(&mut out);
    if out.is_empty() {
        return Err(read.err().unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed without answering",
            )
        }));
    }
    Ok(out)
}

/// One-file multipart body for wall_art uploads.
fn multipart(boundary: &str, fname: &str, bytes: &[u8]) -> Vec<u8> {
    let mut mp = Vec::new();
    mp.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; \
             filename=\"{fname}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    mp.extend_from_slice(bytes);
    mp.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    mp
}

/// Mark a scratch install as having the built-in indexer switched on.
///
/// The switch defaults OFF, and while it is off the daemon will not even
/// open the index database - so every wall, browse and watchlist route
/// answers empty. This whole file drives those routes over a seeded
/// database, so it is the switched-on case. settings.json lives beside
/// the config file.
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

/// How long [`settle_index`] will wait for the daemon's startup index
/// open to finish. See `integration/nzblnk.rs`'s copy of this constant
/// for the measurement it is based on (60 s is an 11x margin over the
/// longest settle seen under 8x concurrent load).
const SETTLE_BUDGET: std::time::Duration = std::time::Duration::from_secs(60);

/// Block until the daemon's index will answer a read.
///
/// Every test below pre-seeds its database with `Index::open` before the
/// daemon starts, then reads it back over `mode=wall2` / `index_browse` /
/// `index_get` moments after the daemon's own port is ready. All three
/// go through `Daemon::index_read_checked`, which before the daemon's
/// first read-write open falls back to the write mutex on a BOUNDED 2 s
/// wait and reports `{"busy":true,"error":"the index is busy - try again
/// in a moment"}` rather than parking an HTTP worker on it (TODO 143's
/// second half, TODO 166). Under box load that open is still running
/// when this file's first read arrives, and none of the assertions below
/// admit that answer.
///
/// Mirrors `integration/nzblnk.rs::settle_index` exactly - same seam,
/// same probe mode, same budget - and is duplicated rather than shared
/// because `http_get` itself is already duplicated per test module in
/// this crate. `key` is the `&apikey=...` this daemon needs, or empty
/// where it has none. An auth refusal PANICS rather than returning: a
/// probe the daemon answers "API Key Incorrect" carries no `busy` flag,
/// so it would exit the loop at once and disable the settle in silence.
fn settle_index(port: u16, key: &str) {
    let started = std::time::Instant::now();
    loop {
        let last = http_get(
            port,
            &format!("/api?mode=index_search&q=nzbfastsettleprobe{key}&output=json"),
        )
        .1;
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

/// One JSON API read, with a `busy` answer WAITED OUT rather than read
/// as an empty one.
///
/// THE BUG THIS EXISTS TO STOP, which is a silent one. Every index-
/// reading mode - `wall2`, `index_browse`, `index_search`, `index_get`,
/// `make_nzb` - answers a read it could not serve with HTTP **200** and
/// `{"status":false,"busy":true,"error":...}`, carrying NO `cards` or
/// `results` field. The house shape for reading one of those was
/// `json[..]["cards"].as_array().cloned().unwrap_or_default()`, which
/// turns exactly that answer into an EMPTY VEC. The assertion then
/// fails somewhere else entirely - `.expect("movie card")` - naming
/// nothing about the index having been busy, which is why one of these
/// costs a session rather than a minute.
///
/// The daemon's own `m_wall2` says the same thing from the other side:
/// "a saturated read pool is not an empty wall, and drawing one as the
/// other is how a busy index comes to be reported as a broken one".
/// These tests were doing precisely what the production code is
/// carefully written not to do.
///
/// WHY [`settle_index`] IS NOT ALREADY ENOUGH, and this is the half
/// that makes it a flake rather than a hard red. `settle_index` waits
/// out the daemon's STARTUP index open and then returns on the first
/// probe that is not busy. It says nothing about any LATER read, and
/// three separate seams can make one busy at any instant:
/// `Saturated` (all four of `INDEX_READ_CONNS` in use and none free
/// within `INDEX_READ_WAIT`, which is 100 ms), `SchemaChanged` (a
/// writer changed the schema under the reader - the daemon's own first
/// `ANALYZE` creating `sqlite_stat1` is one, and it lands AFTER the
/// settle), and `TooSlow`. All three widen under box load, which is
/// why `wall_groups_dedupes_and_serves` failed once inside a full
/// 6,639-test sweep on 2 Sep 2026 and passed alone, on three
/// consecutive `binary(integration)` runs, and on a repeat of the
/// sweep.
///
/// So the wait belongs at the READ, not once at the top of the test.
/// `busy` is the daemon's "ask again in a moment" and this asks again;
/// past the budget it fails carrying the daemon's own `error` text, so
/// the non-transient `TooSlow` reads as itself rather than as a missing
/// card. Modes that report `"busy": false` on success (the stats
/// readouts) pass straight through.
fn api_json(port: u16, q: &str) -> serde_json::Value {
    api_settled(q, || http_get(port, q))
}

/// One JSON API WRITE, with a `busy` refusal waited out the same way.
///
/// THE SECOND HALF OF THE SAME FLAKE, and the half [`api_json`] could
/// not reach. The read helpers landed on 2 Sep 2026 and
/// `wall_groups_dedupes_and_serves` went on failing under load - six of
/// six concurrent `binary(integration)` sweeps on 3 Sep, four of them
/// TRY 2 FAIL, so nextest reported "flaky" rather than red. The
/// surviving failures were never reads (line numbers are the pre-fix
/// file's, kept as evidence rather than as pointers):
///
///     wall.rs:559   mode=wall_art     left: Bool(false)  right: true
///     wall.rs:1741  mode=wall_art     left: (false, "the index is busy - try again in a moment")
///                                    right: (false, "unknown title key")
///
/// `Daemon::index_write_checked` waits `HTTP_INDEX_WAIT` (5 s) for the
/// write mutex and then answers a refusal rather than parking an HTTP
/// worker on it - TODO 166, the same bargain the read side makes over
/// its own 2 s. On a box carrying several concurrent sweeps the
/// daemon's own startup index work still holds that mutex when the
/// upload arrives, so a poster upload is honestly refused and the row
/// is not stamped.
///
/// The second line above is why the flag matters more than the text.
/// A refused write and an unknown title key were the SAME shape -
/// `{"status": false, "error": <prose>}` - so nothing but the message
/// string separated "the moment was wrong" from "your key was wrong".
/// `IndexBusy::refusal` now sends `busy` on every refusal, read and
/// write alike, and this waits on that flag rather than on prose.
///
/// Retrying a refused write is safe by construction and is what the
/// user would do: `index_write_checked`'s `Err` means the mutex was
/// never taken, so the edit did not happen.
fn api_post(port: u16, q: &str, content_type: &str, body: &[u8]) -> serde_json::Value {
    api_settled(q, || http_post(port, q, content_type, body))
}

/// The one copy of "a busy answer is not this call's answer" - ask
/// again until the index will speak, or fail carrying what it said.
///
/// `send` rather than a URL because the two callers differ only in the
/// verb, and a second copy of this loop is how the write half came to
/// be missing one.
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

/// The array under `field` in an API answer, refusing an answer that
/// does not carry the field at all.
///
/// FAILING TO FIND IS FAILING: `unwrap_or_default()` here is what made
/// a busy read indistinguishable from an empty index, and [`api_json`]
/// only removes the busy half of that. A 200 with neither `busy` nor
/// the field is a shape nobody has seen, and it must say so here rather
/// than twenty lines later as a missing row.
fn api_rows(port: u16, q: &str, field: &str) -> Vec<serde_json::Value> {
    let v = api_json(port, q);
    v[field]
        .as_array()
        .cloned()
        .unwrap_or_else(|| panic!("{q}: no `{field}` array in {v}"))
}

#[tokio::test(flavor = "multi_thread")]
async fn wall_groups_dedupes_and_serves() {
    let dir = std::env::temp_dir().join(format!("nzbfast-wall-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let db = dir.join("index.db");
    {
        let mut ix = nzbkit::index::Index::open(&db).unwrap();
        ix.ingest(
            "alt.binaries.teevee",
            &[
                // Two encodes of ONE movie → one card, two releases.
                over(
                    1,
                    "\"The.Matrix.1999.2160p.BluRay.REMUX-GRP.rar\" yEnc (1/1)",
                    "<m1@x>",
                    5000,
                ),
                over(
                    2,
                    "\"The.Matrix.1999.1080p.WEB.x264-OTHER.rar\" yEnc (1/1)",
                    "<m2@x>",
                    2000,
                ),
                // Two episodes + a season pack of ONE show → one TV card.
                over(
                    3,
                    "\"Severance.S01E01.1080p.WEB-DL-NTb.rar\" yEnc (1/1)",
                    "<t1@x>",
                    1000,
                ),
                over(
                    4,
                    "\"Severance.S02E03.2160p.WEB-DL-NTb.rar\" yEnc (1/1)",
                    "<t2@x>",
                    1200,
                ),
                over(
                    5,
                    "\"Severance.S01.2160p.ATVP.WEB-DL-Cas.rar\" yEnc (1/1)",
                    "<t3@x>",
                    8000,
                ),
                // Obfuscated → hidden unless all=1.
                over(
                    6,
                    "\"2137d880a074fa4075a65ce4e21d2f95.rar\" yEnc (1/1)",
                    "<o1@x>",
                    999,
                ),
                // Software → kind=software, hidden unless all=1.
                over(
                    7,
                    "\"CCleaner.Professional.Plus.v6.36.11041.x64.Setup.rar\" yEnc (1/1)",
                    "<s1@x>",
                    500,
                ),
                // ROT13-obfuscated ("The.Wire.3x07.720p.HDTV.x264-BATV"
                // letter-rotated) → rescued onto the wall decoded.
                over(
                    8,
                    "\"Gur.Jver.3k07.720c.UQGI.k264-ONGI.rar\" yEnc (1/1)",
                    "<r1@x>",
                    800,
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
        // Before anything is asserted: rung 1 of the index reads below
        // is refused as busy while the daemon's own startup index open
        // still holds the write mutex, and this test demands the real
        // cards.
        settle_index(port, "&apikey=sekrit");

        // Cards come from wall2 now (the legacy mode=wall was removed in
        // 3b). No enrichment in this test, so read unmatched cards
        // (matched=0). The seed's tiny sizes score as junk, so the curated
        // view hides them all - the junk gate working - and all=1 reveals
        // the real grouping.
        let cards_of = |q: &str| -> Vec<serde_json::Value> { api_rows(port, q, "cards") };
        let by_title = |cs: &[serde_json::Value], t: &str| -> Option<serde_json::Value> {
            cs.iter().find(|c| c["title"] == t).cloned()
        };
        // Curated (junk-gated) view hides the low-evidence junk posts.
        let curated = cards_of("/api?mode=wall2&matched=0&apikey=sekrit");
        assert!(
            by_title(&curated, "The Matrix").is_none(),
            "junk-gated: {curated:?}"
        );

        // all=1 reveals the grouped cards. Two Matrix encodes → one movie
        // card; three Severance postings (2 eps + a season pack) → one TV
        // card; the ROT13 post is rescued onto the wall decoded.
        let all = cards_of("/api?mode=wall2&matched=0&all=1&apikey=sekrit");
        let matrix = by_title(&all, "The Matrix").expect("movie card");
        assert_eq!(matrix["kind"], "movie");
        assert_eq!(matrix["year"], 1999);
        assert_eq!(matrix["n"], 2, "two encodes group onto one card: {all:?}");
        let sev = by_title(&all, "Severance").expect("tv card");
        assert_eq!(sev["kind"], "tv");
        assert_eq!(sev["n"], 3, "episodes+pack under one show: {all:?}");
        let wire = by_title(&all, "The Wire").expect("rot13 rescue");
        assert_eq!(wire["kind"], "tv");
        let sw = by_title(&all, "CCleaner Professional Plus").expect("software card");
        assert_eq!(sw["kind"], "software");

        // Per-release detail is the card sheet: index_browse by title_key
        // (key-scoped listings skip the junk gate). Reuse the card keys.
        let enc = |k: &str| k.replace(':', "%3A").replace(' ', "%20");
        let sheet = |key: &serde_json::Value| -> Vec<serde_json::Value> {
            let q = format!(
                "/api?mode=index_browse&all=1&title_key={}&apikey=sekrit",
                enc(key.as_str().unwrap())
            );
            api_rows(port, &q, "results")
        };
        let sev_rows = sheet(&sev["key"]);
        assert_eq!(sev_rows.len(), 3, "three Severance releases: {sev_rows:?}");
        let mut seasons: Vec<u64> = sev_rows
            .iter()
            .filter_map(|r| r["season"].as_u64())
            .filter(|&s| s > 0)
            .collect();
        seasons.sort_unstable();
        seasons.dedup();
        assert_eq!(
            seasons,
            vec![1, 2],
            "two seasons under the card: {sev_rows:?}"
        );
        // The ROT13 post surfaces under its DECODED quality.
        let wire_rows = sheet(&wire["key"]);
        assert_eq!(wire_rows.len(), 1, "{wire_rows:?}");
        assert_eq!(wire_rows[0]["quality"], "720p HDTV", "{wire_rows:?}");

        // TODO 131 rung 5: `nameable` is what puts the on-demand "name
        // this" affordance on a row, so it has to mean exactly "dark and
        // unnamed" - a readable release must never be offered a probe it
        // has no use for.
        let rows = api_rows(
            port,
            "/api?mode=index_browse&all=1&apikey=sekrit",
            "results",
        );
        let nameable = |needle: &str| -> bool {
            rows.iter()
                .find(|r| r["name"].as_str().is_some_and(|n| n.contains(needle)))
                .unwrap_or_else(|| panic!("no row for {needle}: {rows:?}"))["nameable"]
                == serde_json::Value::Bool(true)
        };
        assert!(
            nameable("2137d880a074fa4075a65ce4e21d2f95"),
            "a hash-named post is exactly what the namer is for: {rows:?}"
        );
        assert!(
            !nameable("The.Matrix.1999.2160p"),
            "a readable release must not be offered the namer: {rows:?}"
        );

        // 24C: wall2&key= is a card-scoped fetch - the Releases
        // surface's hover preview and group-by-title rows pull ONE
        // title's card (total agrees, no page scan).
        let v = api_json(
            port,
            &format!(
                "/api?mode=wall2&matched=0&all=1&key={}&apikey=sekrit",
                enc(sev["key"].as_str().unwrap())
            ),
        );
        assert_eq!(v["total"], 1, "{v}");
        assert_eq!(v["cards"][0]["title"], "Severance", "{v}");
        assert_eq!(v["cards"][0]["n"], 3, "{v}");
        // ...and the new browse sorts parse and page (ordering itself is
        // unit-tested against distinct values in nzbkit::index).
        for sort in ["files", "seen", "kind"] {
            let rows = api_rows(
                port,
                &format!("/api?mode=index_browse&all=1&sort={sort}&apikey=sekrit"),
                "results",
            );
            assert!(!rows.is_empty(), "sort={sort}: {rows:?}");
        }

        // M21 custom artwork: upload a poster for The Matrix; it lands
        // in the art cache, the card links it (cache-busted), and the
        // row is stamped checked so the enricher leaves it alone.
        let key = "m%3Athe%20matrix%3A1999";
        let png = b"\x89PNG\r\n\x1a\nfake-poster-bytes";
        let v = api_post(
            port,
            &format!("/api?mode=wall_art&key={key}&apikey=sekrit"),
            "multipart/form-data; boundary=artb",
            &multipart("artb", "p.png", png),
        );
        assert_eq!(v["status"], true, "{v}");
        // After the upload the movie card is "matched" (has art), so it
        // shows in the default matched-only view (all=1 bypasses the
        // size-junk gate); its poster_full links the cache-busted image.
        let matched = cards_of("/api?mode=wall2&all=1&apikey=sekrit");
        let movie = by_title(&matched, "The Matrix").expect("matched movie card");
        let poster = movie["poster_full"].as_str().unwrap();
        assert!(
            poster.starts_with("/art/m_the_matrix_1999.jpg?v="),
            "{poster}"
        );
        let (code, art) = http_get(port, "/art/m_the_matrix_1999.jpg");
        assert_eq!(code, 200);
        assert!(art.contains("fake-poster-bytes"));
        // Non-image bytes are refused before touching the cache.
        let v = api_post(
            port,
            &format!("/api?mode=wall_art&key={key}&apikey=sekrit"),
            "multipart/form-data; boundary=artb",
            &multipart("artb", "evil.html", b"<html>not art</html>"),
        );
        assert_eq!(v["status"], false, "{v}");
        // Unknown title keys are refused.
        let v = api_post(
            port,
            "/api?mode=wall_art&key=m%3Anope%3A1900&apikey=sekrit",
            "multipart/form-data; boundary=artb",
            &multipart("artb", "p.png", png),
        );
        assert_eq!(v["status"], false, "{v}");

        // A replaced poster must replace what the GRID loads, which is
        // the lazily cached `/art/thumb_<name>` derivative and not the
        // file the upload wrote. Both PNGs below are 1x1, and make_thumb
        // hands a poster that small back verbatim, so the thumbnail's
        // bytes ARE the uploaded bytes and "which picture is the wall
        // showing" is a byte comparison.
        let red = b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d\x49\x48\x44\x52\
                    \x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90\x77\x53\xde\
                    \x00\x00\x00\x0c\x49\x44\x41\x54\x78\xda\x63\xf8\xcf\xc0\x00\x00\x03\
                    \x01\x01\x00\xf7\x03\x41\x43\x00\x00\x00\x00\x49\x45\x4e\x44\xae\x42\
                    \x60\x82";
        let blue = b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d\x49\x48\x44\x52\
                     \x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90\x77\x53\xde\
                     \x00\x00\x00\x0c\x49\x44\x41\x54\x78\xda\x63\x60\x60\xf8\x0f\x00\x01\
                     \x03\x01\x00\x36\x74\x11\x40\x00\x00\x00\x00\x49\x45\x4e\x44\xae\x42\
                     \x60\x82";
        let upload = |bytes: &[u8]| {
            let v = api_post(
                port,
                &format!("/api?mode=wall_art&key={key}&apikey=sekrit"),
                "multipart/form-data; boundary=artb",
                &multipart("artb", "p.png", bytes),
            );
            assert_eq!(v["status"], true, "{v}");
        };
        let thumb = || http_get(port, "/art/thumb_m_the_matrix_1999.jpg");
        upload(red);
        assert_eq!(
            thumb(),
            (200, String::from_utf8_lossy(red).into_owned()),
            "the thumbnail did not come from the poster just uploaded"
        );
        upload(blue);
        assert_eq!(
            thumb(),
            (200, String::from_utf8_lossy(blue).into_owned()),
            "the grid is still serving the PREVIOUS poster: the cached \
             thumbnail outlived the poster it was made from"
        );

        // The candidate arm of wall_fix, which used to be two separate
        // index writes: the rename and the picked series' metadata must
        // arrive together, and the art of the series this card just
        // stopped being must not.
        let v = api_post(
            port,
            "/api?mode=wall_fix&apikey=sekrit",
            "application/json",
            br#"{"key":"m:the matrix:1999","kind":"movie","title":"The Matrix Reloaded",
                 "year":2003,"meta":{"id":604,"overview":"Neo returns.","rating":7.2,
                 "genres":"Action","imdb":"tt0234215","air_date":"2003-05-15"}}"#,
        );
        assert_eq!(v["status"], true, "{v}");
        let fixed = cards_of("/api?mode=wall2&all=1&matched=0&apikey=sekrit");
        let m = by_title(&fixed, "The Matrix Reloaded").expect("the renamed card");
        assert_eq!(
            (
                m["year"].as_u64(),
                m["overview"].as_str(),
                m["genres"].as_str(),
                m["aired"].as_str()
            ),
            (
                Some(2003),
                Some("Neo returns."),
                Some("Action"),
                Some("2003-05-15")
            ),
            "the rename landed without the metadata that goes with it: {m}"
        );
        // No poster_url in the candidate: the art goes, thumbnail
        // included, rather than the old film's picture staying under the
        // new name.
        assert_eq!(m["poster_full"].as_str(), Some(""), "{m}");
        assert_eq!(thumb().0, 404, "the fixed card kept its old thumbnail");

        // TODO 26c: the manual half of the transient-failure sweep.
        // Its behaviour is pinned by the unit test in
        // `index/titles.rs`; what only a live daemon can say is that
        // the arm is reachable, passes its `db_maintenance_ok` gate,
        // and answers in the shape the caller reads. It also must not
        // wipe art the way `value=all` does - these rows have no card
        // to lose, so nothing is deleted.
        let v = api_json(port, "/api?mode=wall_refresh&value=blanked&apikey=sekrit");
        assert_eq!(v["status"], true, "{v}");
        assert!(v["reset"].is_number() && v["done"].is_boolean(), "{v}");
        // ...and an unrecognised target still says what the three
        // legal ones are.
        let (_, body) = http_get(port, "/api?mode=wall_refresh&apikey=sekrit");
        assert!(
            body.contains("blanked"),
            "the usage message never mentions the sweep: {body}"
        );

        // OMDb key: live setting round-trip (masked in get_config as
        // has_omdb) and signup email validation.
        let (_, body) = http_get(
            port,
            "/api?mode=config&name=omdb_key&value=k123&apikey=sekrit",
        );
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            (v["status"].as_bool(), v["live"].as_bool()),
            (Some(true), Some(true)),
            "{body}"
        );
        let (_, body) = http_get(port, "/api?mode=get_config&apikey=sekrit");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["config"]["nzbfast"]["has_omdb"], true, "{body}");
        assert!(
            !body.contains("k123"),
            "omdb key must not leak in get_config"
        );
        let (_, body) = http_post(
            port,
            "/api?mode=omdb_signup&apikey=sekrit",
            "application/json",
            br#"{"email":"not-an-email"}"#,
        );
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            v["status"], false,
            "bad email must be rejected before any network"
        );
        // The wall page itself and the player handoff.
        let (code, html) = http_get(port, "/wall");
        assert_eq!(code, 200);
        assert!(html.contains("nzbfast · wall"), "wall html served");
        // Grouped view, "Added" column: that has to ask the server for
        // arrival order, not upload order. The two genuinely disagree -
        // a set that only finishes arriving now can have been posted
        // hours ago - so mapping it to `latest` silently sorts the
        // grouped view by something the column does not say.
        //
        // Asserted against the served source because the wall's logic is
        // inline JavaScript and this repo has no JS test runner; the
        // mapping is the smallest thing that still means the behaviour.
        // Whitespace-normalized so reformatting cannot fail it.
        let js: String = html.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(
            js.contains("seen:'arrived'"),
            "the grouped view's Added sort must map to the index's arrival order"
        );
        // The handoff mints the per-job stream token, so with an apikey
        // set the keyless form is refused.
        let (code, _) = http_get(port, "/m3u/SABnzbd_nzo_test");
        assert_eq!(
            code, 401,
            "keyless /m3u must be rejected when an apikey is set"
        );
        let (code, m3u) = http_get(port, "/m3u/SABnzbd_nzo_test?apikey=sekrit");
        assert_eq!(code, 200);
        assert!(m3u.starts_with("#EXTM3U"), "{m3u}");
        assert!(m3u.contains("/stream/SABnzbd_nzo_test?t="), "{m3u}");
        // TODO 23 low1, CLI half: that per-job token opens /m3u itself,
        // so `nzbfast stream` need not put the API key in a player's
        // argv. A wrong one is still refused.
        let tok: String = m3u["#EXTM3U".len()..]
            .split("?t=")
            .nth(1)
            .unwrap_or_default()
            .chars()
            .take_while(|c| c.is_ascii_hexdigit())
            .collect();
        assert!(!tok.is_empty(), "no token in {m3u}");
        let (code, tokened) = http_get(port, &format!("/m3u/SABnzbd_nzo_test?t={tok}"));
        assert_eq!(code, 200, "tokened /m3u rejected: {tokened}");
        assert!(
            !tokened.contains("sekrit"),
            "key in the playlist: {tokened}"
        );
        assert_eq!(
            http_get(port, "/m3u/SABnzbd_nzo_test?t=deadbeef").0,
            401,
            "a wrong token opened /m3u"
        );
        // Unknown art 404s (and traversal is refused).
        assert_eq!(http_get(port, "/art/nope.jpg").0, 404);
        assert_eq!(http_get(port, "/art/../index.db").0, 404);
    })
    .await
    .unwrap();
}

/// 24D: the watcher grabs for a user category.
///
/// The wiring is the point. The matcher is unit-tested; what can rot
/// here is the loop classifying candidates with a DIFFERENT rule engine
/// than ingest used, at which point a custom item matches nothing (or,
/// worse, a built-in item grabs a release the category claimed). So this
/// drives the real daemon: two categories and a watchlist entry go in
/// through the settings API, and the queue is what answers.
#[tokio::test(flavor = "multi_thread")]
async fn watchlist_grabs_for_a_user_category() {
    let dir = std::env::temp_dir().join(format!("nzbfast-wlcat-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let quali = "Formula1.2026.Round11.Hungary.Qualifying.F1TV.WEB-DL.1080p.H265-MWR";
    let race = "Formula1.2026.Round11.Hungary.Race.F1TV.WEB-DL.1080p.H265-MWR";
    let matrix = "The.Matrix.1999.1080p.BluRay.x264-GRP";
    let motogp = "MotoGP.2026.Round05.France.Race.1080p.WEB-DL-GRP";

    let db = dir.join("index.db");
    {
        let mut ix = nzbkit::index::Index::open(&db).unwrap();
        let posts: Vec<OverEntry> = [quali, race, matrix, motogp]
            .iter()
            .enumerate()
            .map(|(i, stem)| {
                over(
                    i as u64 + 1,
                    &format!("\"{stem}.rar\" yEnc (1/1)"),
                    &format!("<f{i}@x>"),
                    50 << 20,
                )
            })
            .collect();
        ix.ingest("alt.binaries.teevee", &posts, 1_700_000_000)
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
        let set = |name: &str, value: &str| {
            let q = format!(
                "/api?mode=config&name={name}&value={}&apikey=sekrit",
                urlencoding(value)
            );
            let (code, body) = http_get(port, &q);
            assert_eq!(code, 200, "{body}");
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(v["status"], true, "set {name}: {body}");
        };
        // Two categories, so "first match wins" is exercised and MotoGP
        // is a custom kind the F1 item must still decline.
        set(
            "custom_categories",
            r#"[{"slug":"formula-1","name":"Formula 1","match":"^formula\\.?1\\.","base":"movie"},
                {"slug":"motogp","name":"MotoGP","match":"^motogp","base":"movie"}]"#,
        );
        set(
            "watchlist",
            r#"[{"id":1,"kind":"formula-1","title":"Formula1","min_quality":"any",
                 "target_quality":"1080p","upgrade":true,"enabled":true}]"#,
        );
        let (_, body) = http_get(port, "/api?mode=watchlist_check_now&apikey=sekrit");
        assert!(body.contains("true"), "{body}");

        // A grab enqueues; with a dead server the job may fail through to
        // history, so both are read. Poll rather than sleep a fixed time.
        let grabbed = || -> String {
            let (_, q) = http_get(port, "/api?mode=queue&apikey=sekrit");
            let (_, h) = http_get(port, "/api?mode=history&apikey=sekrit");
            format!("{q}{h}")
        };
        // A POLL DEADLINE, not a measurement: the loop exits the
        // instant both grabs are there, so its only job is to bound a
        // hang, and the assertions below are what decide the verdict.
        // 10 s (100 x 100 ms) was too tight for a loaded box - seen
        // once as a TRY 1 FAIL, recovering on the retry, in six
        // concurrent `binary(integration)` sweeps at box load ~150 on
        // 3 Sep 2026, with an EMPTY queue and history and no `busy`
        // anywhere: the watchlist scan simply had not run yet. 30 s
        // costs a passing run nothing.
        let mut seen = String::new();
        for _ in 0..300 {
            seen = grabbed();
            if seen.contains("Hungary.Qualifying") && seen.contains("Hungary.Race") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        // Both sessions of the round are grabbed: they are separate
        // slots, keyed on the category identity key. A "movie"-shaped
        // single slot would have taken one and called the season done.
        assert!(
            seen.contains("Hungary.Qualifying"),
            "qualifying not grabbed: {seen}"
        );
        assert!(seen.contains("Hungary.Race"), "race not grabbed: {seen}");
        // And nothing else was: not the film (a built-in kind), and not
        // the other category's release (right shape, wrong slug).
        assert!(
            !seen.contains("The.Matrix"),
            "a non-matching film was grabbed: {seen}"
        );
        assert!(
            !seen.contains("MotoGP"),
            "another category's release was grabbed: {seen}"
        );

        // ...and the job says where it came from. A watchlist grab
        // stamped "wall" takes wall-job behaviour with it and answers
        // "why is this here" with the wrong story - which is not visible
        // anywhere else, because the grab itself looks identical.
        let slots = |body: &str, envelope: &str| -> Vec<serde_json::Value> {
            serde_json::from_str::<serde_json::Value>(body)
                .ok()
                .and_then(|v| v[envelope]["slots"].as_array().cloned())
                .unwrap_or_default()
        };
        let (_, q) = http_get(port, "/api?mode=queue&apikey=sekrit");
        let (_, h) = http_get(port, "/api?mode=history&apikey=sekrit");
        let grabs: Vec<serde_json::Value> = slots(&q, "queue")
            .into_iter()
            .chain(slots(&h, "history"))
            .collect();
        let f1: Vec<&serde_json::Value> = grabs
            .iter()
            .filter(|s| {
                let name = s["filename"]
                    .as_str()
                    .or_else(|| s["name"].as_str())
                    .unwrap_or("");
                name.contains("Hungary")
            })
            .collect();
        assert_eq!(f1.len(), 2, "expected both sessions as jobs: {q}{h}");
        for slot in f1 {
            // §44's follow-up: the origin names WHICH watchlist item and
            // slot matched, not just that the watchlist did. A custom
            // category tracks on the classified identity key, so that is
            // the slot field here - and the item title is the third,
            // which is what tells two watched series apart when both
            // grab in the same pass.
            let o = slot["origin"].as_str().unwrap_or_default();
            let f: Vec<&str> = o
                .strip_prefix("watchlist:")
                .unwrap_or_else(|| panic!("not a watchlist origin: {slot}"))
                .split('|')
                .collect();
            assert_eq!(f.len(), 3, "slot|quality|title: {o}");
            assert!(f[0].starts_with("c:formula-1:"), "identity slot: {o}");
            assert_eq!(f[2], "Formula1", "the watchlist item's own title: {o}");
        }
    })
    .await
    .unwrap();
}

/// The two server contracts an open wall page depends on, probed through
/// the API rather than through the browser: the arrivals cursor and the
/// completeness predicate on a card's expanded rows.
#[tokio::test(flavor = "multi_thread")]
async fn wall_arrivals_and_expanded_rows_answer_the_page_honestly() {
    let dir = std::env::temp_dir().join(format!("nzbfast-wallapi-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Arrivals are recent uploads only (a backfilled old post is not an
    // arrival), so these have to be dated now, not at the epoch.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let db = dir.join("index.db");
    {
        let mut ix = nzbkit::index::Index::open(&db).unwrap();
        let post = |n: u64, subject: &str, id: &str| {
            let mut e = over(n, subject, id, 400 << 20);
            e.date = now - 3600;
            e
        };
        ix.ingest(
            "alt.binaries.teevee",
            &[
                // One episode whole...
                post(
                    1,
                    "\"Arrival.Show.S01E01.1080p.WEB-DL-GRP.mkv\" yEnc (1/1)",
                    "<a1@x>",
                ),
                // ...and one that is still missing a part. Same show, so
                // both land under one card and one title key.
                post(
                    2,
                    "\"Arrival.Show.S01E02.1080p.WEB-DL-GRP.mkv\" yEnc (1/2)",
                    "<a2@x>",
                ),
            ],
            now,
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
        let json = |q: &str| -> serde_json::Value { api_json(port, q) };
        // Before anything is asserted: the daemon's own startup index
        // open may still hold the write mutex, and every read below
        // (including wall_tip's flattened one) needs the settled index.
        settle_index(port, "&apikey=sekrit");

        // 26 Jul finding 28. A wall that opened on an empty index holds
        // cursor 0, and 0 is a REAL cursor - "I have seen nothing yet" -
        // not a synonym for "this is my first poll". Conflating the two
        // is why the first release to arrive on a fresh install was
        // never announced: every poll after it looked like a first poll.
        let opened = json("/api?mode=wall_tip&apikey=sekrit");
        assert_eq!(
            opened["new"], 0,
            "a first poll must not cry 'everything is new': {opened}"
        );
        assert!(opened["latest"].as_i64().unwrap_or(0) > 0, "{opened}");
        let polled = json("/api?mode=wall_tip&since=0&apikey=sekrit");
        assert_eq!(
            polled["new"], 1,
            "a cursor of zero must be honoured as a cursor, not read as an \
             uninitialized page: {polled}"
        );
        assert!(
            polled["keys"].as_array().is_some_and(|k| !k.is_empty()),
            "the arrival's key must come back with the count: {polled}"
        );

        // 26 Jul finding 18. Expanding a card asks for that title's rows
        // with the current completeness filter attached; the server has
        // to apply it to a key-scoped query, or the browser's filter
        // silently does nothing on exactly the view that shows releases.
        let cards = json("/api?mode=wall2&matched=0&all=1&apikey=sekrit");
        let key = cards["cards"]
            .as_array()
            .and_then(|cs| cs.iter().find(|c| c["title"] == "Arrival Show"))
            .map(|c| c["key"].as_str().unwrap_or_default().to_string())
            .unwrap_or_else(|| panic!("no card for the seeded show: {cards}"));
        let enc = key.replace(':', "%3A").replace(' ', "%20");
        let rows = |complete: u8| -> Vec<serde_json::Value> {
            json(&format!(
                "/api?mode=index_browse&all=1&title_key={enc}&complete={complete}&apikey=sekrit"
            ))["results"]
                .as_array()
                .cloned()
                .unwrap_or_default()
        };
        assert_eq!(rows(0).len(), 2, "unfiltered, the card holds both releases");
        let only_complete = rows(1);
        assert_eq!(
            only_complete.len(),
            1,
            "the filter must reach a key-scoped query"
        );
        assert_eq!(only_complete[0]["complete"], true, "{only_complete:?}");
    })
    .await
    .unwrap();
}

/// Grabbing from the wall has to name the job after the release, however
/// deep in the index the row sits. The name is not cosmetic: it becomes
/// the output directory, the spool file, the history label and - through
/// the duplicate key derived from it - the duplicate hold, the
/// watchlist's "already have it" check and the wall's have-badge. The old
/// lookup swept the newest rows for the id and called anything it could
/// not find in that window "release-<id>", which has no duplicate key at
/// all.
#[tokio::test(flavor = "multi_thread")]
async fn a_grab_names_the_job_from_the_index_however_deep_the_row_is() {
    let dir = std::env::temp_dir().join(format!("nzbfast-grabname-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let buried = "Buried.Movie.2011.1080p.BluRay.x264-GRP";
    let recent = "Recent.Show.S01E02.1080p.WEB-DL-GRP";
    let db = dir.join("index.db");
    {
        let mut ix = nzbkit::index::Index::open(&db).unwrap();
        // Indexed first, so it sits at the very bottom of a newest-first
        // sweep...
        ix.ingest(
            "alt.binaries.moovee",
            &[over(
                1,
                &format!("\"{buried}.rar\" yEnc (1/1)"),
                "<b1@x>",
                50 << 20,
            )],
            1_700_000_000,
        )
        .unwrap();
        // ...under more rows than that sweep ever read. Nothing stops an
        // index growing this far: the byte cap is unlimited by default
        // and eviction ships switched off.
        let filler: Vec<OverEntry> = (0..100_001u64)
            .map(|i| {
                over(
                    i + 2,
                    &format!("\"Filler.Show.S01E{i:06}.1080p.WEB-DL-GRP.rar\" yEnc (1/1)"),
                    &format!("<f{i}@x>"),
                    50 << 20,
                )
            })
            .collect();
        ix.ingest("alt.binaries.teevee", &filler, 1_700_010_000)
            .unwrap();
        ix.ingest(
            "alt.binaries.teevee",
            &[over(
                200_000,
                &format!("\"{recent}.rar\" yEnc (1/1)"),
                "<r1@x>",
                50 << 20,
            )],
            1_700_020_000,
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
        let json = |q: &str| -> serde_json::Value { api_json(port, q) };
        // Before anything is asserted: the daemon's own startup index
        // open may still hold the write mutex, and this test demands
        // the real rows on the first search page.
        settle_index(port, "&apikey=sekrit");
        // Ids the way the wall gets them: off a search page.
        let id_of = |stem: &str| -> i64 {
            let term = stem.split('.').next().unwrap();
            let page = json(&format!(
                "/api?mode=index_browse&all=1&q={term}&apikey=sekrit"
            ));
            page["results"]
                .as_array()
                .and_then(|rs| rs.iter().find(|r| r["name"].as_str() == Some(stem)))
                .and_then(|r| r["id"].as_i64())
                .unwrap_or_else(|| panic!("{stem} not on the search page: {page}"))
        };
        // The grab, then the job it made. A dead server can fail the job
        // through to history, so both lists are read.
        let grab = |id: i64| -> serde_json::Value {
            let r = json(&format!(
                "/api?mode=index_get&id={id}&priority=1&apikey=sekrit"
            ));
            assert_eq!(r["status"], true, "grab of {id}: {r}");
            let nzo = r["nzo_ids"][0].as_str().expect("a job id").to_string();
            for _ in 0..100 {
                let q = json("/api?mode=queue&apikey=sekrit");
                let h = json("/api?mode=history&apikey=sekrit");
                let slots: Vec<serde_json::Value> = q["queue"]["slots"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .chain(
                        h["history"]["slots"]
                            .as_array()
                            .cloned()
                            .unwrap_or_default(),
                    )
                    .collect();
                if let Some(s) = slots.iter().find(|s| s["nzo_id"] == nzo.as_str()) {
                    return s.clone();
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            panic!("job {nzo} never showed up in the queue or history");
        };
        let name_of = |slot: &serde_json::Value| -> String {
            slot["filename"]
                .as_str()
                .or_else(|| slot["name"].as_str())
                .unwrap_or_default()
                .to_string()
        };

        let deep = grab(id_of(buried));
        assert_eq!(
            name_of(&deep),
            buried,
            "the buried row's grab lost its name: {deep}"
        );
        assert_ne!(
            deep["duplicate_key"], "",
            "a named job must carry a duplicate key, or the duplicate hold \
             and the have-badge go quiet for it: {deep}"
        );
        // The ordinary case still works.
        let near = grab(id_of(recent));
        assert_eq!(name_of(&near), recent, "{near}");
        assert_ne!(near["duplicate_key"], "", "{near}");

        // And an id with no row behind it is still refused, rather than
        // enqueuing an empty job called release-999999999.
        let missing = json("/api?mode=index_get&id=999999999&apikey=sekrit");
        assert_eq!(missing["status"], false, "{missing}");
        assert_eq!(missing["error"], "release not found", "{missing}");
    })
    .await
    .unwrap();
}

/// The upload-session panel (mode=wall_session): an identified episode
/// surfaces the obfuscated posts that went up in the same run, and a
/// surfaced row grabs through the ordinary index_get path. Association
/// only - the sibling keeps its scrambled name until a download proves
/// better.
#[tokio::test(flavor = "multi_thread")]
async fn session_siblings_surface_on_the_sheet_and_grab() {
    let dir = std::env::temp_dir().join(format!("nzbfast-sess-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let named = "Watched.Show.S01E01.1080p.WEB-DL-GRP";
    let dark = "k9f2c7a1e5b8d3f6";
    let t0 = 1_700_000_000i64;
    let db = dir.join("index.db");
    {
        let mut ix = nzbkit::index::Index::open(&db).unwrap();
        let post = |n: u64, subj: &str, from: &str, id: &str, date: i64| OverEntry {
            number: n,
            subject: subj.into(),
            from: from.into(),
            message_id: id.into(),
            bytes: 50 << 20,
            date,
        };
        ix.ingest(
            "alt.binaries.teevee",
            &[
                post(
                    1,
                    &format!("\"{named}.rar\" yEnc (1/1)"),
                    "a@x",
                    "<s1@x>",
                    t0,
                ),
                // Same run, five minutes later, rotated handle,
                // scrambled name - the row the panel exists for.
                post(
                    2,
                    &format!("\"{dark}.rar\" yEnc (1/1)"),
                    "b@x",
                    "<s2@x>",
                    t0 + 300,
                ),
                // Nine hours out: outside the session window, must
                // not surface.
                post(
                    3,
                    "\"aa77zz9900ffee11.rar\" yEnc (1/1)",
                    "c@x",
                    "<s3@x>",
                    t0 + 9 * 3600,
                ),
            ],
            t0 + 9 * 3600,
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
        let json = |q: &str| -> serde_json::Value { api_json(port, q) };
        // Before anything is asserted: the daemon's own startup index
        // open may still hold the write mutex, and this test demands
        // the seeded show on the first search page.
        settle_index(port, "&apikey=sekrit");
        // The named episode's card key, the way the sheet gets it.
        let page = json("/api?mode=index_browse&all=1&q=Watched&apikey=sekrit");
        let row = page["results"]
            .as_array()
            .and_then(|rs| rs.iter().find(|r| r["name"].as_str() == Some(named)))
            .unwrap_or_else(|| panic!("seeded show not on the page: {page}"))
            .clone();
        let key = row["key"].as_str().expect("named row carries a key");

        let sess = json(&format!(
            "/api?mode=wall_session&key={}&apikey=sekrit",
            urlencoding(key)
        ));
        let sibs = sess["siblings"].as_array().unwrap_or_else(|| {
            panic!("no siblings array: {sess}");
        });
        let hit = sibs
            .iter()
            .find(|s| s["name"].as_str().is_some_and(|n| n.starts_with(dark)))
            .unwrap_or_else(|| panic!("the same-run dark post is missing: {sess}"));
        assert_eq!(hit["link"], "time", "{hit}");
        assert_eq!(hit["dt"], 300, "{hit}");
        assert!(
            !sibs
                .iter()
                .any(|s| s["name"].as_str().is_some_and(|n| n.starts_with("aa77zz"))),
            "a post nine hours out is not the same run: {sess}"
        );

        // A surfaced row rides the ordinary grab path and keeps its
        // scrambled name - naming happens in the download, never here.
        let sid = hit["id"].as_i64().unwrap();
        let g = json(&format!("/api?mode=index_get&id={sid}&apikey=sekrit"));
        assert_eq!(g["status"], true, "{g}");
    })
    .await
    .unwrap();
}

/// A wall2 poll seeds a titles row for every unenriched card it draws,
/// and re-polling the same page changes nothing.
///
/// The seeding itself is one transaction for the whole page now, where
/// it used to be one autocommit INSERT per card - each of which can wait
/// out SQLite's 10 s `busy_timeout` behind a scan chunk's IMMEDIATE
/// transaction, so a page of 60 cards was 60 chances to stall an
/// interactive poll on a fresh index.
///
/// What the batching must not change is that the rows appear, because
/// they are load-bearing beyond the enricher, and a freshly-scanned
/// card's only row is the one this poll writes. `OR IGNORE` is the
/// other half - a poll of an enriched page must not walk it back to
/// pending.
///
/// The endpoints that read-modify-write such a row no longer DEPEND on
/// the poll having run: `wall_art` and `wall_refresh` seed what they
/// act on, the same way `wall_fix` always has - see
/// `wall_art_and_refresh_seed_the_row_they_act_on`. This test pins the
/// poll's own seeding, which is what feeds the enricher.
///
/// The seed is a `try_with_index_mut` side-write BY DESIGN: a poll that
/// finds the index mutex held skips it rather than park an interactive
/// request behind an ingest, and the wall's next poll re-offers the
/// same cards. This test used to poll exactly twice, back to back, and
/// then assert the rows - which asserts that one of two `try_lock`s,
/// microseconds apart, won. They did not on 22 Aug 2026: the daemon's
/// first scan pass starts at boot and holds that mutex in a chain of
/// short `with_index` reads (retention clock, ANALYZE, the picker-index
/// backfill), each a few ms on a loaded box, and both polls landed
/// inside one hold (`try_with_index_mut` lost both times, traced). Solo
/// the pass is over before the first poll; under the CI sweep it is
/// not, so the test failed beside its neighbours and passed alone - the
/// fingerprint of a test-group problem, which this is not: it reproduces
/// solo with only a build as load, because the contention is inside the
/// one daemon. So this polls the way a real wall does, on an interval,
/// until the rows are there, and bounds the wait far above any hold.
/// Reads ride `open_read_only`, which runs no migration and so may open
/// under the daemon's writer; the schema is current because this test's
/// own `open` above brought it up before the daemon started.
#[tokio::test(flavor = "multi_thread")]
async fn a_wall_poll_seeds_its_page_without_disturbing_enriched_rows() {
    let dir = std::env::temp_dir().join(format!("nzbfast-wallseed-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let db = dir.join("index.db");
    {
        let mut ix = nzbkit::index::Index::open(&db).unwrap();
        ix.ingest(
            "alt.binaries.teevee",
            &[
                over(
                    1,
                    "\"The.Matrix.1999.2160p.BluRay.REMUX-GRP.rar\" yEnc (1/1)",
                    "<w1@x>",
                    5000,
                ),
                over(
                    2,
                    "\"Severance.S01E01.1080p.WEB-DL-NTb.rar\" yEnc (1/1)",
                    "<w2@x>",
                    1000,
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

    let db2 = db.clone();
    let keys = tokio::task::spawn_blocking(move || {
        // Before anything is asserted: the daemon's own startup index
        // open may still hold the write mutex, and `poll` below asserts
        // on its first call rather than retrying - it has no chance to
        // recover from a busy answer here.
        settle_index(port, "&apikey=sekrit");

        let poll = || {
            let body = api_json(port, "/api?mode=wall2&matched=0&all=1&apikey=sekrit");
            let cards = body["cards"]
                .as_array()
                .cloned()
                .unwrap_or_else(|| panic!("no `cards` array in {body}"));
            assert!(
                cards.iter().any(|c| c["title"] == "The Matrix"),
                "the poll answers with its cards: {body}"
            );
            let keys: Vec<String> = cards
                .iter()
                .filter_map(|c| c["key"].as_str().map(str::to_string))
                .collect();
            assert_eq!(keys.len(), 2, "two cards on the page: {body}");
            keys
        };
        let rows = |keys: &[String]| -> Vec<Option<nzbkit::index::TitleRow>> {
            let ix = nzbkit::index::Index::open_read_only(&db2).unwrap();
            keys.iter().map(|k| ix.title_get(k).unwrap()).collect()
        };
        // Poll on an interval until every card on the page has its
        // row, the way a real wall's refresh does. 30 s is two orders
        // above the longest first-pass hold measured (tens of ms).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let keys = loop {
            let keys = poll();
            if rows(&keys).iter().all(Option::is_some) {
                break keys;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "30 s of polling never seeded the page - the seed is a \
                 try_lock side-write, but the index mutex cannot be held \
                 this long by a two-row index's first pass: {keys:?}"
            );
            std::thread::sleep(std::time::Duration::from_millis(200));
        };
        let seeded = rows(&keys);
        for (k, row) in keys.iter().zip(&seeded) {
            let row = row.as_ref().unwrap();
            assert_eq!(row.checked, 0, "a seeded row is pending, not answered: {k}");
            assert!(!row.title.is_empty(), "seeded with a display title: {k}");
        }
        // Re-polling the same page changes nothing: `OR IGNORE` leaves
        // the rows exactly as the first seed wrote them. Two more polls
        // (the second can only see the mutex free if the first did not),
        // then compare field by field.
        for _ in 0..2 {
            assert_eq!(poll(), keys, "the page is stable across polls");
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        for (k, (before, after)) in keys.iter().zip(seeded.iter().zip(rows(&keys))) {
            let (before, after) = (before.as_ref().unwrap(), after.unwrap());
            assert_eq!(after.checked, before.checked, "re-poll walked `{k}` back");
            assert_eq!(after.title, before.title, "re-poll rewrote `{k}`");
            assert_eq!(after.year, before.year, "re-poll rewrote `{k}`");
            assert_eq!(after.kind, before.kind, "re-poll rewrote `{k}`");
        }
        keys
    })
    .await
    .unwrap();
    // `stop` rather than `drop` so the guard keeps printing the daemon's
    // log if the assert below is the one that fails.
    let _log = d.stop();
    assert!(
        keys.iter().any(|k| k.starts_with("m:")) && keys.iter().any(|k| k.starts_with("t:")),
        "both lanes are represented: {keys:?}"
    );
}

/// `wall_art` and `wall_refresh` act on a row they seed themselves.
///
/// Neither used to. `title_fill` and `title_reset` are bare UPDATEs, so
/// on a card the wall has never DRAWN - which has no `titles` row,
/// because a poll of its page is what writes one - they matched nothing
/// and the endpoint answered "unknown title key" about a perfectly good
/// title. Every way into a card that is not a poll of its own page hits
/// that: a direct link, the Releases surface's hover preview, a page the
/// user never scrolled to. `wall_fix` never had it (`title_set_identity`
/// upserts) and is the shape the other two now follow.
///
/// This daemon is never asked for a wall page, which is the whole point:
/// every row the endpoints below touch is one they seeded themselves.
/// The keys come from `index_browse`, which reads releases and seeds
/// nothing.
///
/// The distinction that has to survive: a key naming NO releases is
/// still unknown, and still says so. Seeding is for a card that exists
/// and has no row yet, never for a bad key.
#[tokio::test(flavor = "multi_thread")]
async fn wall_art_and_refresh_seed_the_row_they_act_on() {
    let dir = std::env::temp_dir().join(format!("nzbfast-wallseed2-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let db = dir.join("index.db");
    {
        let mut ix = nzbkit::index::Index::open(&db).unwrap();
        ix.ingest(
            "alt.binaries.teevee",
            &[
                over(
                    1,
                    "\"The.Matrix.1999.2160p.BluRay.REMUX-GRP.rar\" yEnc (1/1)",
                    "<s1@x>",
                    5000,
                ),
                over(
                    2,
                    "\"Severance.S01E01.1080p.WEB-DL-NTb.rar\" yEnc (1/1)",
                    "<s2@x>",
                    1000,
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

    let (movie, tv) = tokio::task::spawn_blocking(move || {
        // Before anything is asserted: the daemon's own startup index
        // open may still hold the write mutex, and this test demands
        // the real rows on the first index_browse page.
        settle_index(port, "&apikey=sekrit");

        // Release rows, not cards: index_browse hands back each row's
        // wall-card key and writes nothing to `titles`.
        let rows = api_rows(
            port,
            "/api?mode=index_browse&all=1&apikey=sekrit",
            "results",
        );
        let key_of = |needle: &str| -> String {
            rows.iter()
                .find(|r| r["name"].as_str().is_some_and(|n| n.contains(needle)))
                .unwrap_or_else(|| panic!("no row for {needle}: {rows:?}"))["key"]
                .as_str()
                .unwrap()
                .to_string()
        };
        let (movie, tv) = (key_of("The.Matrix"), key_of("Severance"));

        // A poster for a card that has never been on screen.
        let png = b"\x89PNG\r\n\x1a\nfake-poster-bytes";
        let v = api_post(
            port,
            &format!(
                "/api?mode=wall_art&key={}&apikey=sekrit",
                urlencoding(&movie)
            ),
            "multipart/form-data; boundary=artb",
            &multipart("artb", "p.png", png),
        );
        assert_eq!(
            v["status"], true,
            "an unpolled card is not an unknown title: {v}"
        );
        // ...and the art cache holds it, so the seed reached the row the
        // fill then named.
        let (code, art) = http_get(port, "/art/m_the_matrix_1999.jpg");
        assert_eq!(code, 200, "{art}");
        assert!(art.contains("fake-poster-bytes"), "{art}");

        // Refresh: same shape, and a freshly seeded row IS the
        // post-reset state, so the endpoint reports the reset it asked
        // for rather than refusing the key.
        let v = api_json(
            port,
            &format!(
                "/api?mode=wall_refresh&value={}&apikey=sekrit",
                urlencoding(&tv)
            ),
        );
        assert_eq!(
            v["status"], true,
            "an unpolled card is not an unknown title: {v}"
        );

        // A key naming no releases is a bad key, on both endpoints. This
        // is the half seeding must not swallow - "unknown title key" has
        // to keep meaning something.
        let v = api_post(
            port,
            "/api?mode=wall_art&key=m%3Anope%3A1900&apikey=sekrit",
            "multipart/form-data; boundary=artb",
            &multipart("artb", "p.png", png),
        );
        assert_eq!(
            (v["status"].as_bool(), v["error"].as_str()),
            (Some(false), Some("unknown title key")),
            "{v}"
        );
        let v = api_json(
            port,
            "/api?mode=wall_refresh&value=m%3Anope%3A1900&apikey=sekrit",
        );
        assert_eq!(
            (v["status"].as_bool(), v["error"].as_str()),
            (Some(false), Some("unknown title key")),
            "{v}"
        );
        (movie, tv)
    })
    .await
    .unwrap();

    // Read the db with the daemon gone - it holds the write connection.
    // `stop` keeps its log printing on a failure below; see `Daemon::stop`.
    let _log = d.stop();
    let ix = nzbkit::index::Index::open(&db).unwrap();
    let art = ix
        .title_get(&movie)
        .unwrap()
        .unwrap_or_else(|| panic!("wall_art seeds `{movie}` before filling it"));
    // Seeded from the release stem, not blank: the row has to carry the
    // display title a card without metadata is drawn under.
    assert_eq!(
        (art.title.as_str(), art.year),
        ("The Matrix", 1999),
        "{art:?}"
    );
    assert_eq!(art.poster, "m_the_matrix_1999.jpg", "{art:?}");
    assert!(
        art.checked > 0,
        "hand-picked art answers the lookup: {art:?}"
    );
    let refreshed = ix
        .title_get(&tv)
        .unwrap()
        .unwrap_or_else(|| panic!("wall_refresh seeds `{tv}` before resetting it"));
    assert_eq!(refreshed.title, "Severance", "{refreshed:?}");
    assert_eq!(refreshed.kind, "tv", "{refreshed:?}");
    assert_eq!(
        (refreshed.checked, refreshed.poster.as_str()),
        (0, ""),
        "a reset row is pending with no art: {refreshed:?}"
    );
}

/// Percent-encode a settings value for the GET config API.
fn urlencoding(v: &str) -> String {
    v.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// THE SHAPE [`api_json`] AND [`api_rows`] ARE WRITTEN AGAINST: a wall
/// read the index could not answer is HTTP 200 with `busy` and NO
/// `cards` field - never an empty wall.
///
/// This is the production side of the flake those two helpers exist to
/// stop. `wall_groups_dedupes_and_serves` failed once inside a full
/// 6,639-test sweep on 2 Sep 2026 and passed alone, on three
/// consecutive `binary(integration)` runs, and on a repeat of the
/// sweep. Its read helper was
/// `json[..]["cards"].as_array().cloned().unwrap_or_default()`, which
/// reads the answer below as a wall with no cards on it, so the test
/// died twenty lines later on `.expect("movie card")` - a message that
/// names nothing about the index having been busy.
///
/// All three assertions are load-bearing, and each pins a different way
/// the helpers could silently stop working:
///
/// - **200.** A test that only checks the status code learns nothing
///   here, which is why `api_json`'s `assert_eq!(code, 200)` cannot be
///   the busy check.
/// - **`busy` is `true`.** The flag `api_json` waits on. Modes that
///   report `"busy": false` on success must keep doing so, or every
///   read through these helpers would spin for `SETTLE_BUDGET`.
/// - **No `cards` array at all.** This is the one that made the bug
///   silent. If the daemon ever answered `"cards": []` alongside
///   `busy`, `as_array()` would succeed and `api_rows`' refusal would
///   go back to being unreachable.
///
/// The pool is saturated from INSIDE, with the NZBFAST_DEBUG_HOOKS-gated
/// `mode=debug_index_read_busy` - the same lever
/// `newznab::a_read_the_index_could_not_answer_is_an_error_not_an_empty_feed`
/// takes, and the only one that can refuse a read THIS handler makes
/// rather than a read some other request makes.
///
/// What is deliberately NOT pinned here is `api_rows` panicking on a
/// busy answer. The injector arms one way - `arm_debug_read_budget`
/// clamps to zero, so nothing can disarm it - so reaching that panic
/// costs a full `SETTLE_BUDGET` of wall clock, 60 s, to assert what the
/// three lines below already establish.
#[tokio::test(flavor = "multi_thread")]
async fn a_busy_wall_read_is_not_an_empty_wall() {
    let dir = std::env::temp_dir().join(format!("nzbfast-wallbusy-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let db = dir.join("index.db");
    {
        let mut ix = nzbkit::index::Index::open(&db).unwrap();
        ix.ingest(
            "alt.binaries.teevee",
            &[over(
                1,
                "\"The.Matrix.1999.2160p.BluRay.REMUX-GRP.rar\" yEnc (1/1)",
                "<b1@x>",
                5000,
            )],
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
        settle_index(port, "&apikey=sekrit");

        // The control arm, and the priming the injector needs: the
        // answer has to come off the read POOL, which only happens once
        // a read-write open has run the migrations. Arming before that
        // would refuse nothing.
        let cards = api_rows(
            port,
            "/api?mode=wall2&matched=0&all=1&apikey=sekrit",
            "cards",
        );
        assert!(
            cards.iter().any(|c| c["title"] == "The Matrix"),
            "the seeded card is served before anything is armed: {cards:?}"
        );

        // Every pooled read from here on reports the pool busy.
        let (_, armed) = http_get(
            port,
            "/api?output=json&mode=debug_index_read_busy&value=0&apikey=sekrit",
        );
        assert!(armed.contains("\"armed\":0"), "hook armed: {armed}");

        let (code, body) = http_get(port, "/api?mode=wall2&matched=0&all=1&apikey=sekrit");
        assert_eq!(code, 200, "a busy read still rides HTTP 200: {body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["busy"], true, "a refused read says so: {body}");
        assert!(
            v["cards"].as_array().is_none(),
            "a busy answer must carry NO cards array - an empty one is \
             indistinguishable from a wall with nothing on it, which is \
             the bug `api_rows` exists to refuse: {body}"
        );
    })
    .await
    .unwrap();
}
