#![cfg(feature = "indexer")]
//! The 28 Jul 2026 all-workers-wedged hang, as a regression test.
//!
//! Mechanism of the incident: a catch-up ingest held the shared index
//! connection for 62s straight; the dashboard header pill polls
//! mode=index_stats every 15s and that handler blocked on the same
//! mutex; each poll parked another of the daemon's 4 HTTP workers, so
//! within a minute ONE open dashboard tab left the daemon serving
//! nothing at all - a curl to / hung indefinitely.
//!
//! The fix has three parts, and this file pins all of them:
//!
//!  * index_stats is served from a try_lock + cached figures and never
//!    blocks on the index mutex (stale-by-seconds counts are fine for a
//!    status pill);
//!  * the interactive query endpoints (wall2, search, browse, getnzb,
//!    the newznab facade) run on a dedicated READ-ONLY connection - the
//!    database is WAL, so they answer while an ingest holds the
//!    read-write connection (measured pre-fix: a wall2 curl queued
//!    62.4s behind a deepening pass);
//!  * the worker pool is big enough that the rare handlers which DO
//!    still take the index lock (the mutating ones) cannot consume
//!    every worker the moment a handful queue up behind a scan batch.
//!
//! The long lock hold is synthesized with the NZBFAST_DEBUG_HOOKS-gated
//! mode=debug_hold_index, which sleeps inside with_index - the same
//! mutex a real ingest batch holds.
//!
//! 2 Aug 2026: the same daemon went silent again, and it was the same
//! shape one mutex further along. The read-only connection above was a
//! SINGLE connection behind a single mutex, whose holds were assumed -
//! never enforced - to be short. At 32M releases they were not: `wall2`
//! took 85s and `wall_tip` 76s, both full scans, so every query handler
//! serialized behind whichever was slowest and parked a worker waiting.
//! The read path is now a bounded POOL that refuses rather than queues
//! (`INDEX_READ_CONNS`), which caps how many workers any amount of slow
//! query work can occupy; `a_slow_index_read_cannot_starve_the_http_pool`
//! pins it, via the sibling hook mode=debug_hold_index_read. The two
//! queries that triggered it were fixed as well - see `Index::optimize`
//! (the database had never been ANALYZEd) and the `INDEXED BY` hint in
//! `wall_tip` - but the ceiling is what makes the NEXT slow query a slow
//! query rather than an outage.
//!
//! 25 Aug 2026, TODO 300: the ceiling turned out to bound the QUEUE and
//! not the query already inside a connection, and the next slow query
//! duly arrived. `mode=wall2&matched=0&all=1` - the empty state's "Show
//! unmatched" button, so a fresh install reaches it - measured 57.8 s
//! warm and over 120 s cold on the live 50 GB index, because show-all
//! drops the `junk < 50` predicate that `idx_rel_visible_posted` covers
//! and the aggregate grows from 1,450 groups to 1,251,672. Four polls of
//! it hold every connection, and an abandoned tab does not shorten one
//! of them. Pooled reads now carry a per-query BUDGET that abandons the
//! query and reports it (`nzbkit::index::deadline`,
//! `serve::daemon::index_read_budget`);
//! `a_query_that_outruns_its_budget_is_abandoned_and_the_pool_recovers`
//! pins both halves, via the third hook mode=debug_slow_index_read -
//! which runs real SQL rather than sleeping, because a sleep is the one
//! thing a progress callback cannot interrupt.

// The forward guard on the repeating-payload trap, and the waiver that
// says a fixture is deliberately in it. A sibling the way `harness` is,
// and reached from `harness::DaemonLog`'s own Drop, so every daemon this
// binary starts is read whether or not the suite looks at its log.
mod adoptguard;
mod harness;
mod scratch;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use nzbkit::nntp::OverEntry;

use harness::Daemon;

/// One attempt, returning the response BODY. Err ONLY when the daemon
/// produced nothing at all; anything that produced a byte is an answer,
/// and is handed back for the caller's assertions to judge.
///
/// Reads BYTES and de-chunks, rather than `read_to_string` over the raw
/// stream. tiny_http switches to `Transfer-Encoding: chunked` for any
/// response at or above its 32 KB `chunked_threshold`, and the dashboard
/// at `/` is ~450 KB - so `/` has always come back chunked here.
///
/// Reading that stream as a String is not merely untidy, it is
/// intermittently WRONG: a chunk header lands every 8192 bytes wherever
/// that falls, including in the middle of a multi-byte character, and
/// `read_to_string` then fails the whole read with "stream did not
/// contain valid UTF-8". Whether it does is decided by the page's byte
/// layout, so the test passed for as long as no boundary happened to
/// split one - and a UI change that shifted the bytes broke it with
/// nothing wrong in the daemon at all. The panic also killed the daemon
/// through `KillOnDrop`, which made every other thread's request look
/// like an empty body and buried the cause.
fn http_once(port: u16, req: &str) -> std::io::Result<String> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    write!(
        s,
        "GET {req} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )?;
    let mut raw = Vec::new();
    // Zero bytes back is a refusal to serve, however the peer phrased
    // it: ECONNREFUSED when the accept never happened, an RST or a bare
    // FIN when it did and the socket was dropped unread. None of those
    // carry anything to judge. A read that failed AFTER bytes landed is
    // an answer, and is used exactly as it arrived - a truncated body
    // must never be retried away.
    let read = s.read_to_end(&mut raw);
    if raw.is_empty() {
        return Err(read.err().unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed without answering",
            )
        }));
    }
    let Some(at) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Ok(String::new()); // no headers at all - the caller asserts
    };
    let (head, body) = raw.split_at(at + 4);
    let chunked = String::from_utf8_lossy(head)
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked");
    let body = if chunked {
        dechunk(body)
    } else {
        body.to_vec()
    };
    Ok(String::from_utf8(body).expect("response body is UTF-8"))
}

/// Same terms as the daemon suite's helper, and for the same reason: a
/// refusal that arrives before a single byte does is the machine being
/// out of capacity, not the daemon answering wrongly. This file's own
/// `connect(..).expect("connect daemon")` failed with ECONNREFUSED about
/// one full-suite run in ten on a box also running another checkout's
/// suite - four daemons here, eight HTTP workers each, plus everything
/// else `cargo test` has in flight.
///
/// This cannot hide the wedge the file exists to catch. A wedged daemon
/// ACCEPTS and then never answers, so `connect` succeeds and the read
/// blocks - no retry is reachable - and the elapsed-time bounds around
/// these calls (3s, against a total retry budget of 0.8s) still fail.
/// Only a pre-byte refusal is retried, and only five times.
fn http(port: u16, req: &str) -> String {
    let mut last = String::new();
    for attempt in 0..5u32 {
        match http_once(port, req) {
            Ok(out) => return out,
            Err(e) => {
                last = e.to_string();
                std::thread::sleep(Duration::from_millis(100 * u64::from(attempt) + 50));
            }
        }
    }
    panic!("daemon on :{port} never served {req}: {last}");
}

/// Minimal `Transfer-Encoding: chunked` decoder - enough for what
/// tiny_http emits (hex length, CRLF, bytes, CRLF, terminated by a
/// zero-length chunk). Chunk extensions after a `;` are tolerated.
fn dechunk(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(nl) = b.windows(2).position(|w| w == b"\r\n") {
        let line = String::from_utf8_lossy(&b[..nl]);
        let size = line.split(';').next().unwrap_or("").trim();
        let n = usize::from_str_radix(size, 16).unwrap_or(0);
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

fn api(port: u16, q: &str) -> serde_json::Value {
    let body = http(port, &format!("/api?output=json&{q}"));
    serde_json::from_str(&body).unwrap_or_else(|e| panic!("bad JSON for {q:?}: {e}\n{body}"))
}

fn over(number: u64, subject: &str, msgid: &str, date: i64) -> OverEntry {
    OverEntry {
        number,
        subject: subject.into(),
        from: "poster@x".into(),
        bytes: 50 << 20,
        message_id: msgid.into(),
        date,
    }
}

fn scratch(name: &str) -> scratch::ScratchDir {
    let dir = std::env::temp_dir().join(format!("nzbfast-wedge-{}-{name}", std::process::id()));
    let dir = scratch::ScratchDir::attach(&dir);
    std::fs::write(dir.join("config.json"), "{\"servers\":[]}").unwrap();
    // An existing install (no first-run key minted) with the indexer on -
    // the whole test is about the index connection.
    std::fs::write(dir.join("settings.json"), "{\"index_enabled\": true}").unwrap();
    dir
}

fn seed_index(dir: &Path, n: usize) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut ix = nzbkit::index::Index::open(&dir.join("index.db")).unwrap();
    let entries: Vec<OverEntry> = (0..n)
        .map(|i| {
            over(
                i as u64 + 1,
                &format!("\"Wedge.Test.S01E{i:02}.720p-GRP.rar\" yEnc (1/1)"),
                &format!("<wedge{i}@x>"),
                now - (i as i64 + 1) * 86_400,
            )
        })
        .collect();
    ix.ingest("alt.binaries.teevee", &entries, now - 3600)
        .unwrap();
}

fn serve(dir: &Path) -> Daemon {
    serve_with_hooks(dir, true, None)
}

/// `hooks` gates NZBFAST_DEBUG_HOOKS. Every daemon in this file goes
/// through here, including the one that must run WITHOUT the hook:
/// launching inline instead cost that test the port-race handling in
/// `harness::serve_blocking`, and it failed with ECONNREFUSED under a
/// loaded box - it waited 30s for a banner that a daemon which had
/// already lost :port and exited was never going to print, then talked
/// to nothing.
///
/// `budget_secs` overrides TODO 300's per-query read budget, whose
/// default is 20 s. `None` leaves the default alone, which is what every
/// test here but one wants: the point of the other legs is a connection
/// that is OCCUPIED (a sleep inside the borrow), and a sleep is not
/// something a budget can interrupt.
fn serve_with_hooks(dir: &Path, hooks: bool, budget_secs: Option<u64>) -> Daemon {
    harness::serve_blocking(dir, |port| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        if hooks {
            cmd.env("NZBFAST_DEBUG_HOOKS", "1");
        } else {
            cmd.env_remove("NZBFAST_DEBUG_HOOKS");
        }
        if let Some(secs) = budget_secs {
            cmd.env("NZBFAST_INDEX_READ_BUDGET_SECS", secs.to_string());
        }
        cmd.env("NZBFAST_NO_ENRICH", "1")
            .env_remove("NZBFAST_OPEN")
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
            .arg(dir.join("index.db"));
        cmd
    })
}

/// One dashboard tab + one long index-lock hold must leave the daemon
/// fully responsive: / and index_stats both answer in well under a
/// second for the whole duration of the hold, and index_stats keeps
/// reporting the real figures (from its cache) rather than zeros.
#[test]
fn held_index_lock_does_not_wedge_the_api() {
    let dir = scratch("hold");
    seed_index(&dir, 8);
    let d = serve(&dir);
    let port = d.port;

    // Prime: one unlocked poll computes fresh figures and fills the cache.
    let fresh = api(port, "mode=index_stats");
    assert_eq!(
        fresh["releases"], 8,
        "seed visible before the hold: {fresh}"
    );

    // Prime `/` too, for the same reason and before any hold is armed.
    // Its page is built once per process and cached (`SHELL_CACHE` in
    // serve/webasset.rs), so the FIRST request pays a build - the
    // substitutions over 1.4 MB of HTML, an FNV over the result and a
    // level-6 deflate of that - which is a fixed process-lifetime
    // constant and not contention. Measured 31 Aug 2026 against a debug
    // daemon on a Core Ultra 9 laptop (Windows 11, MSVC), with nothing
    // else touching it: 2537 ms cold against 252-277 ms warm. Sampled
    // cold that sits between the two bounds below, so the loop would
    // report a starved pool on a box whose pool was idle. Priming it
    // HERE rather than beside the loop matters: a genuinely starved
    // daemon must miss the timed bound and say so, not exhaust `http`'s
    // retries at a warm-up. The same trap cost
    // dashboard_load::five_tabs_cannot_starve_the_pool a permanent red
    // on that box; the comment there carries the full measurement.
    let _ = http(port, "/");

    // The synthetic 62s batch, scaled to 15s of test time. It answers
    // {"held": true} only after the sleep, so join() doubles as proof
    // the lock really was held while we measured below.
    let holder = std::thread::spawn(move || api(port, "mode=debug_hold_index&value=15"));
    // The hook is inside the lock within milliseconds; a beat to be sure.
    std::thread::sleep(Duration::from_millis(500));

    // The dashboard tab of the incident: an index_stats poll every
    // second (compressed from 15s) for the length of the hold. In the
    // wedge these were exactly what parked the workers.
    let poller = std::thread::spawn(move || {
        for _ in 0..10 {
            let t = Instant::now();
            let s = api(port, "mode=index_stats");
            assert!(
                t.elapsed() < Duration::from_secs(3),
                "index_stats blocked {}ms behind the held index lock",
                t.elapsed().as_millis()
            );
            // Served from the cache, not zeros - the pill must not read
            // "empty index" every time a scan batch is busy.
            assert_eq!(
                s["releases"], 8,
                "stale-but-real figures during the hold: {s}"
            );
            std::thread::sleep(Duration::from_secs(1));
        }
    });

    // The index-backed QUERY endpoints answer during the hold too, with
    // real rows, via the read-only connection - not "busy", not empty,
    // not a 62s queue behind the held read-write connection.
    let querier = std::thread::spawn(move || {
        for _ in 0..8 {
            let t = Instant::now();
            let s = api(port, "mode=index_search&q=wedge");
            assert!(
                t.elapsed() < Duration::from_secs(3),
                "index_search blocked {}ms behind the held index lock",
                t.elapsed().as_millis()
            );
            let hits = s["results"].as_array().expect("results array").len();
            assert_eq!(hits, 8, "search finds the seed during the hold: {s}");
            let id = s["results"][0]["id"].as_i64().expect("hit id");

            let t = Instant::now();
            let w = api(port, "mode=wall2&all=1&matched=0");
            assert!(
                t.elapsed() < Duration::from_secs(3),
                "wall2 blocked {}ms behind the held index lock",
                t.elapsed().as_millis()
            );
            assert!(
                w["cards"].as_array().is_some_and(|c| !c.is_empty()),
                "wall2 serves cards during the hold: {w}"
            );

            // The newznab facade's NZB fetch - make_nzb is a read.
            let t = Instant::now();
            let nzb = http(port, &format!("/getnzb/{id}.nzb"));
            assert!(
                t.elapsed() < Duration::from_secs(3),
                "getnzb blocked {}ms behind the held index lock",
                t.elapsed().as_millis()
            );
            assert!(
                nzb.contains("<nzb"),
                "getnzb serves the NZB during the hold: {nzb}"
            );
            std::thread::sleep(Duration::from_secs(1));
        }
    });

    // Meanwhile the daemon as a whole stays alive: / (the curl of the
    // incident report) and a non-index API mode answer promptly.
    for _ in 0..8 {
        let t = Instant::now();
        let page = http(port, "/");
        assert!(!page.is_empty(), "/ served nothing");
        assert!(
            t.elapsed() < Duration::from_secs(3),
            "/ took {}ms during the index hold",
            t.elapsed().as_millis()
        );
        let t = Instant::now();
        let q = api(port, "mode=queue");
        assert!(q.get("queue").is_some(), "mode=queue answered: {q}");
        assert!(
            t.elapsed() < Duration::from_secs(3),
            "mode=queue took {}ms during the index hold",
            t.elapsed().as_millis()
        );
        std::thread::sleep(Duration::from_secs(1));
    }

    poller.join().expect("poller thread");
    querier.join().expect("querier thread");
    let held = holder.join().expect("holder thread");
    assert_eq!(held["held"], true, "the hook really held the lock: {held}");

    // Lock free again: the fresh path resumes (still the same figures).
    let after = api(port, "mode=index_stats");
    assert_eq!(after["releases"], 8, "fresh path after the hold: {after}");
}

/// A handler that reads the index TWICE has to stay honest on the
/// SECOND read too. `rar_name` did not: its classification read used
/// `index_read_checked` and reported busy, then its file-rows read used
/// `with_index_read`, which maps a saturated pool to None, and
/// `unwrap_or_default` turned that into "no such release" - about a
/// release that plainly exists (read-only sweep 2, 15 Aug 2026, L5).
///
/// Holding connections from other requests cannot reach this: it can
/// only ever make the FIRST read busy. The window between one handler's
/// two reads is microseconds wide from outside and wide open on a live
/// daemon, so the pool is saturated from INSIDE instead, with the
/// hooks-gated `mode=debug_index_read_busy` - one read through, every
/// read after it refused.
#[test]
fn a_busy_second_read_is_not_a_missing_release() {
    let dir = scratch("rarname_busy");
    seed_index(&dir, 4);
    let d = serve(&dir);
    let port = d.port;

    // Prime the read path so `index_migrated` is set and the pool is
    // what answers, not the startup fallback to with_index.
    let s = api(port, "mode=index_search&q=wedge");
    assert_eq!(
        s["results"].as_array().map(Vec::len),
        Some(4),
        "seed visible: {s}"
    );
    let id = s["results"][0]["id"].as_i64().expect("a seeded release id");

    // Sanity: with the pool free, the release is found - the handler
    // gets past both reads and on to the wire, which has no server
    // configured, so the answer is about the FETCH, never "no such
    // release".
    let ok = api(port, &format!("mode=rar_name&id={id}"));
    assert_ne!(
        ok["error"], "no such release",
        "the seeded release is readable before anything is armed: {ok}"
    );

    // One read through - the classification read - then the pool is
    // busy for everything after it, which is the file-rows read.
    let armed = api(port, "mode=debug_index_read_busy&value=1");
    assert_eq!(armed["armed"], 1, "hook armed: {armed}");

    let r = api(port, &format!("mode=rar_name&id={id}"));
    assert_eq!(
        r["busy"], true,
        "a busy second read must say so, not deny the release exists: {r}"
    );
    assert_ne!(r["error"], "no such release", "{r}");
}

/// The 2 Aug 2026 wedge: the SAME silence as 28 Jul, one mutex further
/// along.
///
/// The 28 Jul fix moved the query endpoints off the read-write mutex and
/// onto a dedicated read-only connection, on the stated assumption that
/// "every hold of THIS mutex is a short query". On a 32M-release index
/// that assumption failed: `wall2` spent 85s on its card COUNT and
/// `wall_tip` 76s on a full scan, each holding that one connection, so
/// every other query handler queued behind it - and a queued request
/// holds the HTTP worker that is waiting. Eight of those and the daemon
/// answered nothing at all: `mode=version`, which touches no database,
/// timed out at 45s while the process sat there logging happily.
///
/// Reproduced against the live 45 GB index before this was written:
/// eight concurrent wall2 calls, and then `/` and `mode=version` both
/// returned nothing for the duration.
///
/// What must hold now, and what this pins: however many slow reads are
/// in flight, the number of workers they can occupy is capped, so the
/// rest of the API is untouched. Past `INDEX_READ_CONNS` a read is told
/// the index is busy INSTEAD of queueing - the worker goes back to the
/// pool rather than waiting out the slow query.
#[test]
fn a_slow_index_read_cannot_starve_the_http_pool() {
    let dir = scratch("readpool");
    seed_index(&dir, 8);
    let d = serve(&dir);
    let port = d.port;

    // Prime the read path so `index_migrated` is set and the pool is the
    // thing under test rather than the startup fallback to with_index.
    let s = api(port, "mode=index_search&q=wedge");
    assert_eq!(
        s["results"].as_array().map(Vec::len),
        Some(8),
        "seed visible before the holds: {s}"
    );

    // Prime `/` too, for the same reason and before any hold is armed.
    // Its page is built once per process and cached (`SHELL_CACHE` in
    // serve/webasset.rs), so the FIRST request pays a build - the
    // substitutions over 1.4 MB of HTML, an FNV over the result and a
    // level-6 deflate of that - which is a fixed process-lifetime
    // constant and not contention. Measured 31 Aug 2026 against a debug
    // daemon on a Core Ultra 9 laptop (Windows 11, MSVC), with nothing
    // else touching it: 2537 ms cold against 252-277 ms warm. Sampled
    // cold that sits between the two bounds below, so the loop would
    // report a starved pool on a box whose pool was idle. Priming it
    // HERE rather than beside the loop matters: a genuinely starved
    // daemon must miss the timed bound and say so, not exhaust `http`'s
    // retries at a warm-up. The same trap cost
    // dashboard_load::five_tabs_cannot_starve_the_pool a permanent red
    // on that box; the comment there carries the full measurement.
    let _ = http(port, "/");

    // Twelve concurrent slow reads - more than the 8 HTTP workers, so in
    // the pre-fix daemon this is the wedge exactly. Only INDEX_READ_CONNS
    // of them can hold a connection; the rest must come back "busy"
    // promptly rather than parking a worker apiece.
    let holders: Vec<_> = (0..12)
        .map(|_| std::thread::spawn(move || api(port, "mode=debug_hold_index_read&value=15")))
        .collect();
    std::thread::sleep(Duration::from_millis(750));

    // The whole point: endpoints that touch no index at all keep
    // answering, at full speed, for the entire hold. `mode=version` is
    // the exact call that went silent live, and `/` is the curl from the
    // 28 Jul report.
    for _ in 0..12 {
        let t = Instant::now();
        let v = api(port, "mode=version");
        assert!(
            v.get("version").is_some(),
            "mode=version answered during the read holds: {v}"
        );
        assert!(
            t.elapsed() < Duration::from_secs(2),
            "mode=version took {}ms behind slow index reads - the pool is starved again",
            t.elapsed().as_millis()
        );
        let t = Instant::now();
        let page = http(port, "/");
        assert!(!page.is_empty(), "/ served nothing during the read holds");
        assert!(
            t.elapsed() < Duration::from_secs(2),
            "/ took {}ms behind slow index reads",
            t.elapsed().as_millis()
        );
        let t = Instant::now();
        let q = api(port, "mode=queue");
        assert!(q.get("queue").is_some(), "mode=queue answered: {q}");
        assert!(
            t.elapsed() < Duration::from_secs(2),
            "mode=queue took {}ms behind slow index reads",
            t.elapsed().as_millis()
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // A query endpoint asked while the pool is saturated must be TOLD
    // so, quickly, rather than blanking or hanging: a busy index reading
    // as an empty one is how "the wall is broken" gets reported for what
    // is really "ask again in a moment".
    let t = Instant::now();
    let w = api(port, "mode=wall2&all=1&matched=0");
    assert!(
        t.elapsed() < Duration::from_secs(2),
        "wall2 waited {}ms on a saturated pool instead of answering busy",
        t.elapsed().as_millis()
    );
    assert_eq!(w["busy"], true, "wall2 says the index is busy: {w}");

    // And the same honesty for search: a saturated pool used to be
    // flattened to `results: []`, which the dashboard drew as "nothing
    // matched" over a list it then threw away (Codex sweep 5 Aug M10).
    let t = Instant::now();
    let s = api(port, "mode=index_search&q=wedge");
    assert!(
        t.elapsed() < Duration::from_secs(2),
        "index_search waited {}ms on a saturated pool instead of answering busy",
        t.elapsed().as_millis()
    );
    assert_eq!(s["busy"], true, "search says the index is busy: {s}");
    assert!(
        s.get("results").is_none(),
        "a busy search must not look like an empty one: {s}"
    );

    let answers: Vec<serde_json::Value> = holders
        .into_iter()
        .map(|h| h.join().expect("holder thread"))
        .collect();
    let held = answers.iter().filter(|a| a["held"] == true).count();
    let busy = answers.iter().filter(|a| a["busy"] == true).count();
    // Exactly the ceiling got in. Not "at most": a pool that handed out
    // fewer would pass every assertion above while quietly serializing
    // the query surface, which is the bug this replaced.
    assert_eq!(
        held, 4,
        "INDEX_READ_CONNS reads ran concurrently, the rest were refused: \
         {held} held, {busy} busy"
    );
    assert_eq!(held + busy, 12, "every request got a verdict: {answers:?}");

    // And the pool recovers: with the holds finished, reads are normal
    // again - the refusals above were backpressure, not a broken handle.
    let after = api(port, "mode=index_search&q=wedge");
    assert_eq!(
        after["results"].as_array().map(Vec::len),
        Some(8),
        "reads resume once the holds end: {after}"
    );
}

/// The FOURTH shape, and the hole the three above leave (TODO 300).
///
/// `INDEX_READ_CONNS` caps how many workers slow query work can occupy;
/// `INDEX_READ_WAIT` caps how long a caller queues for a connection.
/// Neither says anything about the query already INSIDE one, and until
/// 25 Aug 2026 nothing did - so a borrowed connection was held for
/// exactly as long as `sqlite3_step` took, however long that was, and an
/// abandoned browser tab did not shorten it by a millisecond. Measured
/// on the live 50 GB index that day: `mode=wall2&matched=0&all=1` is
/// 57.8 s warm and over 120 s cold, because show-all drops the
/// `junk < 50` predicate a partial index covers and the aggregate goes
/// from 1,450 groups to 1,251,672. Four of those and the pool is gone -
/// the 2 Aug wedge again, reached through the wall rather than a lock.
///
/// The budget is what makes that a slow page rather than an outage. Two
/// halves, and both matter: the query is ABANDONED (so the connection
/// comes back), and the caller is TOLD (so a wall that could not be
/// built does not read as a wall with nothing on it).
///
/// One second here rather than the 20 s default - the mechanism is the
/// subject, not the number - and the query is a real endless one rather
/// than a sleep, because a progress callback fires between VM
/// instructions and has no opinion about a sleeping handler.
#[test]
fn a_query_that_outruns_its_budget_is_abandoned_and_the_pool_recovers() {
    let dir = scratch("readbudget");
    seed_index(&dir, 8);
    let d = serve_with_hooks(&dir, true, Some(1));
    let port = d.port;

    // Prime, so `index_migrated` is set and the pool is what answers -
    // the pre-migration fallback runs on the write mutex and carries no
    // budget.
    let s = api(port, "mode=index_search&q=wedge");
    assert_eq!(
        s["results"].as_array().map(Vec::len),
        Some(8),
        "seed visible before the budget legs: {s}"
    );

    // Eight endless queries: twice INDEX_READ_CONNS, and one per HTTP
    // worker. Pre-fix this is terminal - none of them ever returns, so
    // the four that got a connection keep it for the life of the process
    // and every query endpoint answers busy forever.
    //
    // Collected through a channel with a DEADLINE rather than by joining
    // the threads, and that is not fussiness: pre-fix these requests
    // never return at all, so a join is a test that HANGS where it means
    // to fail. A hung test burns a CI slot until somebody notices;
    // nextest's default profile carries no `terminate-after`, on purpose
    // (see .config/nextest.toml), so nothing would end it.
    let (tx, rx) = std::sync::mpsc::channel();
    for _ in 0..8 {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(api(port, "mode=debug_slow_index_read"));
        });
    }
    drop(tx);
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut answers: Vec<serde_json::Value> = Vec::new();
    while answers.len() < 8 {
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(a) => answers.push(a),
            Err(_) => panic!(
                "only {} of 8 endless queries came back inside 30s - a query with no \
                 budget never comes back, which is the wedge this bounds",
                answers.len()
            ),
        }
    }

    // Every one got a verdict, and each is one of the two honest ones:
    // it held a connection and was abandoned, or it never got one.
    for a in &answers {
        assert_eq!(a["busy"], true, "an endless query is never a success: {a}");
    }
    let abandoned = answers
        .iter()
        .filter(|a| {
            a["error"]
                .as_str()
                .is_some_and(|e| e.contains("too much of the index to search at once"))
        })
        .count();
    assert!(
        abandoned >= 1,
        "at least the connections that were LENT OUT report the budget \
         rather than a busy pool: {answers:?}"
    );

    // The half that is the whole point: the connections came BACK. A
    // budget that reported without releasing would pass every assertion
    // above and still be the wedge.
    let after = api(port, "mode=index_search&q=wedge");
    assert_eq!(
        after["results"].as_array().map(Vec::len),
        Some(8),
        "the pool is whole again once the budgets expire: {after}"
    );
    let w = api(port, "mode=wall2");
    assert!(
        w.get("cards").is_some(),
        "and the wall draws again rather than reporting busy: {w}"
    );
}

/// The third wedge shape, found by the 2 Aug bug sweep before it fired
/// live: `index_migrated` is sticky, so once the index database file
/// vanishes (index_wipe deletes it; here the test deletes it directly)
/// every query's read-only open FAILS - and the pre-fix fallback for
/// that case was the UNBOUNDED read-write mutex. With anything long
/// holding that mutex (a chunked compaction pass, the daily ANALYZE;
/// here the debug hook), every query worker parked on it and the
/// daemon went silent again. The fallback is now try-lock shaped: a
/// held mutex means a prompt empty answer, never a parked worker.
#[test]
fn a_missing_index_db_plus_a_held_write_mutex_cannot_park_queries() {
    let dir = scratch("unavail");
    seed_index(&dir, 8);
    let d = serve(&dir);
    let port = d.port;

    // Prime: sets index_migrated, so the pool (not the startup
    // fallback) is what serves queries from here on.
    let s = api(port, "mode=index_search&q=wedge");
    assert_eq!(
        s["results"].as_array().map(Vec::len),
        Some(8),
        "seed visible before the hold: {s}"
    );

    // A long hold of the read-write mutex - the compaction/ANALYZE
    // stand-in. 12s: far above the promptness bound below, so a parked
    // query is unambiguous.
    let holder = std::thread::spawn(move || api(port, "mode=debug_hold_index&value=12"));
    std::thread::sleep(Duration::from_millis(500));

    // Delete the database out from under the daemon - what index_wipe
    // does. (On Windows the delete can fail against the open handle;
    // then the read-only opens keep succeeding, the fallback is never
    // reached, and the assertions below hold trivially - the pre-fix
    // park cannot happen there either.)
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(dir.join(format!("index.db{suffix}")));
    }

    // More concurrent queries than the pool has idle connections: the
    // surplus hits the failing read-only open. Pre-fix each of these
    // parked on the held mutex for the rest of the hold; now every one
    // must answer promptly, whatever the answer is.
    let queries: Vec<_> = (0..6)
        .map(|_| {
            std::thread::spawn(move || {
                let t = Instant::now();
                let _ = api(port, "mode=index_search&q=wedge");
                t.elapsed()
            })
        })
        .collect();
    for q in queries {
        let took = q.join().expect("query thread");
        assert!(
            took < Duration::from_secs(5),
            "query parked {}ms on the held write mutex behind a missing index db",
            took.as_millis()
        );
    }

    // And the daemon as a whole never lost its workers to the park.
    let t = Instant::now();
    let v = api(port, "mode=version");
    assert!(v.get("version").is_some(), "version answered: {v}");
    assert!(
        t.elapsed() < Duration::from_secs(2),
        "mode=version took {}ms behind the held mutex",
        t.elapsed().as_millis()
    );

    let held = holder.join().expect("holder thread");
    assert_eq!(held["held"], true, "the hook really held the lock: {held}");
}

/// The debug hook must not exist without its env var - it ties up a
/// worker and the index lock on demand, which is exactly what an open
/// API must not offer. (The gate is the environment, not a build flag,
/// so this checks the released binary's behavior too.)
#[test]
fn debug_hook_absent_without_env() {
    let dir = scratch("nohook");
    let d = serve_with_hooks(&dir, false, None);
    let port = d.port;
    let t = Instant::now();
    let r = api(port, "mode=debug_hold_index&value=30");
    // An unknown mode's error answer, immediately - not a 30s stall.
    assert!(
        r.get("held").is_none(),
        "hook must not run without the env var: {r}"
    );
    assert!(
        t.elapsed() < Duration::from_secs(5),
        "unknown-mode answer took {}ms - did the hook run?",
        t.elapsed().as_millis()
    );
    // Its read-pool sibling is gated on the same variable and would tie
    // up a pooled connection just as happily.
    let t = Instant::now();
    let r = api(port, "mode=debug_hold_index_read&value=30");
    assert!(
        r.get("held").is_none(),
        "read hook must not run without the env var: {r}"
    );
    assert!(
        t.elapsed() < Duration::from_secs(5),
        "unknown-mode answer took {}ms - did the read hook run?",
        t.elapsed().as_millis()
    );
    // And the fault injector, which would make every later index read
    // on this daemon answer "busy" for as long as it ran.
    let r = api(port, "mode=debug_index_read_busy&value=1");
    assert!(
        r.get("armed").is_none(),
        "the read-pool fault injector must not arm without the env var: {r}"
    );
    let w = api(port, "mode=wall2&all=1&matched=0");
    assert_ne!(
        w["busy"], true,
        "nothing was armed, so the index must not be reporting busy: {w}"
    );
}

/// Watches a socket we have gone silent on: the DAEMON must be the one to
/// let go. Returns how long that took; fails if it is still open at `bound`.
///
/// Ok(0) is the daemon's FIN; a reset also counts (either way the daemon's
/// side has left ESTABLISHED). Bytes before that (a 408, say) are fine -
/// they are the daemon acting, not retention.
fn assert_daemon_closes(mut s: TcpStream, what: &str, bound: Duration) -> Duration {
    let t = Instant::now();
    s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let mut buf = [0u8; 4096];
    loop {
        match s.read(&mut buf) {
            Ok(0) => return t.elapsed(),
            Ok(_) => {}
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                assert!(
                    t.elapsed() < bound,
                    "{what}: daemon still holds the socket after {:?}",
                    t.elapsed()
                );
            }
            Err(_) => return t.elapsed(),
        }
    }
}

/// The other observation from the 28 Jul investigation: the daemon retained
/// ESTABLISHED sockets for HTTP clients that died mid-request. A peer that
/// vanishes without a FIN (power loss, network drop, kill -9 behind a
/// dead NAT) is indistinguishable from these two probes, so the daemon must
/// cut both loose on its own - the vendored tiny_http's 30s socket timeout
/// (patch 4) is the mechanism, and this pins that the released binary
/// actually applies it on its accept path.
#[test]
fn a_client_that_vanishes_mid_request_is_released() {
    let dir = scratch("vanish");
    let d = serve(&dir);
    let port = d.port;

    // Half a request, then silence.
    let mut half = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(half, "GET /api?output=json&mode=queue HTTP/1.1\r\nHost: x").unwrap();
    // And its connect-and-say-nothing sibling.
    let silent = TcpStream::connect(("127.0.0.1", port)).unwrap();

    // The socket timeout is 30s; anything near it is compliance, 45s is
    // retention.
    let bound = Duration::from_secs(45);
    let h = std::thread::spawn(move || assert_daemon_closes(half, "half-request socket", bound));
    let s = std::thread::spawn(move || assert_daemon_closes(silent, "silent socket", bound));

    // Meanwhile the abandoned sockets cost nobody else anything.
    std::thread::sleep(Duration::from_secs(2));
    let q = api(port, "mode=queue");
    assert!(
        q.get("queue").is_some(),
        "daemon healthy beside dead clients: {q}"
    );

    let half_took = h.join().expect("half-request watcher");
    let silent_took = s.join().expect("silent watcher");

    // And afterwards, with both sockets reclaimed, still healthy.
    let q = api(port, "mode=queue");
    assert!(
        q.get("queue").is_some(),
        "daemon healthy after reclaiming: {q}"
    );
    eprintln!("daemon released: half-request in {half_took:?}, silent in {silent_took:?}");
}

/// One keep-alive GET on an already-open connection; the response must
/// arrive on THAT connection (an EOF mid-response is the daemon having
/// dropped a keep-alive peer it should have kept).
fn keepalive_get(s: &mut TcpStream, path: &str) -> serde_json::Value {
    write!(s, "GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match s.read(&mut b) {
            Ok(1) => head.push(b[0]),
            Ok(_) => panic!("daemon closed a live keep-alive connection mid-response"),
            Err(e) => panic!("keep-alive read failed: {e}"),
        }
        assert!(head.len() < 64 * 1024, "unterminated response header");
    }
    let head = String::from_utf8_lossy(&head);
    let len: usize = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse().unwrap())
        })
        .expect("response carries a Content-Length");
    let mut body = vec![0u8; len];
    s.read_exact(&mut body).expect("full keep-alive body");
    serde_json::from_slice(&body).unwrap_or_else(|e| panic!("bad JSON over keep-alive: {e}"))
}

/// The flip side of cutting dead sockets loose: the dashboard's slowest
/// poll (the index_stats pill, every 15s) rides one keep-alive connection.
/// Whatever closes abandoned sockets must not close a connection that is
/// merely between polls - so a second request 16s after the first still
/// gets its answer on the same connection.
#[test]
fn dashboard_keepalive_outlives_its_poll_interval() {
    let dir = scratch("keepalive");
    let d = serve(&dir);
    let port = d.port;

    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();

    let first = keepalive_get(&mut s, "/api?output=json&mode=queue");
    assert!(
        first.get("queue").is_some(),
        "first poll on the connection: {first}"
    );

    std::thread::sleep(Duration::from_secs(16));

    let second = keepalive_get(&mut s, "/api?output=json&mode=queue");
    assert!(
        second.get("queue").is_some(),
        "poll after 16s idle: {second}"
    );
}
