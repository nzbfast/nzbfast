//! TODO §129 phase 1d: the load gates. A one-year history must not tax
//! an unchanged one-second refresh, and five open dashboard tabs must
//! not starve the 8-worker HTTP pool. Harness pattern follows
//! tests/http_wedge.rs (banner readiness, raw sockets, elapsed bounds,
//! retry only on a pre-byte refusal).

use crate::scratch;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;

use crate::harness::Daemon;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

fn http_once(port: u16, req: &str) -> std::io::Result<Vec<u8>> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    write!(
        s,
        "GET {req} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )?;
    let mut raw = Vec::new();
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
        return Ok(Vec::new());
    };
    let (head, body) = raw.split_at(at + 4);
    let chunked = String::from_utf8_lossy(head)
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked");
    Ok(if chunked {
        dechunk(body)
    } else {
        body.to_vec()
    })
}

fn dechunk(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(nl) = b.windows(2).position(|w| w == b"\r\n") {
        let line = String::from_utf8_lossy(&b[..nl]);
        let size = line.split(';').next().unwrap_or("").trim();
        let n = usize::from_str_radix(size, 16).unwrap_or(0);
        if n == 0 {
            break;
        }
        let (start, end) = (nl + 2, nl + 2 + n);
        if end > b.len() {
            out.extend_from_slice(&b[start.min(b.len())..]);
            break;
        }
        out.extend_from_slice(&b[start..end]);
        b = &b[(end + 2).min(b.len())..];
    }
    out
}

fn http(port: u16, req: &str) -> Vec<u8> {
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

fn api(port: u16, q: &str) -> Value {
    let body = http(port, &format!("/api?output=json&apikey=sekrit&{q}"));
    let text = String::from_utf8(body).expect("API body is UTF-8");
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("bad JSON for {q:?}: {e}\n{text}"))
}

fn api_raw(port: u16, q: &str) -> (Value, usize) {
    let body = http(port, &format!("/api?output=json&apikey=sekrit&{q}"));
    let n = body.len();
    let text = String::from_utf8(body).expect("API body is UTF-8");
    let v =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("bad JSON for {q:?}: {e}\n{text}"));
    (v, n)
}

fn scratch(name: &str) -> scratch::ScratchDir {
    let dir = std::env::temp_dir().join(format!("nzbfast-dload-{}-{name}", std::process::id()));
    let dir = scratch::ScratchDir::attach(&dir);
    std::fs::write(dir.join("config.json"), "{\"servers\":[]}").unwrap();
    std::fs::write(dir.join("settings.json"), "{\"index_enabled\": false}").unwrap();
    dir
}

/// Seed a history of `n` rows in the NEW layout: `.spool/history.jsonl`,
/// one compact record per line, oldest first - the file the phase-1a
/// store writes. 8760 = one finished job per hour for a year.
fn seed_history_jsonl(dir: &Path, n: usize) {
    let spool = dir.join(".spool");
    std::fs::create_dir_all(&spool).unwrap();
    std::fs::write(
        spool.join("queue.json"),
        serde_json::to_string(&json!({"next_id": 9_000_000, "queue": []})).unwrap(),
    )
    .unwrap();
    let mut out = String::with_capacity(n * 256);
    for i in 0..n {
        let (name, state, fail) = if i % 10 == 0 {
            (
                format!("Beta.Show.S01E{:02}.{i}", i % 100),
                "Failed",
                "articles missing",
            )
        } else {
            (format!("Alpha.Movie.{i:05}.1080p"), "Completed", "")
        };
        let rec = json!({
            "nzo_id": format!("SABnzbd_nzo_y{i}"),
            "name": name,
            "nzb_path": dir.join(format!("spool-{i}.nzb")).to_string_lossy(),
            "out_dir": dir.join("complete").join(&name).to_string_lossy(),
            "state": state,
            "category": if i % 3 == 0 { "tv" } else { "movies" },
            "total_bytes": 1_000_000 + i as u64,
            "finished_unix": 1_722_000_000i64 + (i as i64) * 3600,
            "fail_message": fail,
        });
        out.push_str(&serde_json::to_string(&rec).unwrap());
        out.push('\n');
    }
    std::fs::write(spool.join("history.jsonl"), out).unwrap();
}

fn serve(dir: &Path) -> Daemon {
    crate::harness::serve_blocking(dir, |port| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        cmd.env("NZBFAST_NO_ENRICH", "1")
            .env_remove("NZBFAST_OPEN")
            .arg("--config")
            .arg(dir.join("config.json"))
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"));
        cmd
    })
}

/// Gate 1: an unchanged 1 s refresh costs the same at any history size.
/// Pinned two ways: the unchanged body against a YEAR of history stays
/// under 4 KB (a full history dump at this size is megabytes, three
/// orders of magnitude away - no flaky margin), and it is within noise
/// of the same daemon's 10-row sibling.
#[test]
fn a_year_of_history_does_not_tax_an_unchanged_refresh() {
    // The year-deep daemon.
    let big = scratch("year");
    seed_history_jsonl(&big, 8760);
    let d_big = serve(&big);

    // The near-empty control.
    let small = scratch("tenrow");
    seed_history_jsonl(&small, 10);
    let d_small = serve(&small);

    let handshake = |port: u16| -> (u64, u64, u64) {
        let first = api(port, "mode=dashboard&hist_limit=50");
        (
            first["queue_revision"].as_u64().expect("queue_revision"),
            first["history_revision"]
                .as_u64()
                .expect("history_revision"),
            first["events_seq"].as_u64().expect("events_seq"),
        )
    };
    let unchanged = |port: u16, (q, h, s): (u64, u64, u64)| -> usize {
        let (v, n) = api_raw(
            port,
            &format!("mode=dashboard&queue_rev={q}&history_rev={h}&events={s}&hist_limit=50"),
        );
        assert!(v["history"].is_null(), "history resent unchanged: {v}");
        assert!(v["queue"].is_null(), "queue resent unchanged: {v}");
        n
    };

    let big_rev = handshake(d_big.port);
    let small_rev = handshake(d_small.port);

    // Warm once, then measure a run of unchanged polls.
    unchanged(d_big.port, big_rev);
    unchanged(d_small.port, small_rev);
    let mut big_bytes = 0usize;
    let mut small_bytes = 0usize;
    let t = Instant::now();
    for _ in 0..20 {
        big_bytes = big_bytes.max(unchanged(d_big.port, big_rev));
        small_bytes = small_bytes.max(unchanged(d_small.port, small_rev));
    }
    let elapsed = t.elapsed();

    assert!(
        big_bytes < 4096,
        "unchanged refresh against a year of history weighed {big_bytes} bytes"
    );
    // Size-independence: the year-deep answer is the same order as the
    // 10-row answer (stats content wobbles a little; 2x is generous).
    assert!(
        big_bytes <= small_bytes.saturating_mul(2) + 512,
        "unchanged refresh grew with history size: {big_bytes} vs {small_bytes} bytes"
    );
    // 40 unchanged polls in well under the 20 s a 1 Hz dashboard would
    // spread them over - each one must be effectively free. The bound is
    // deliberately loose (loaded CI); the wedge shape it catches is an
    // O(history) rebuild per poll, which at 8760 rows costs whole
    // seconds per call.
    assert!(
        elapsed < Duration::from_secs(20),
        "40 unchanged polls took {elapsed:?} - the idle refresh is doing O(history) work"
    );

    // And a CHANGED window is a page, not the year: ask for a window
    // deep in the stack with a fresh client (rev 0).
    let (page, n) = api_raw(d_big.port, "mode=dashboard&hist_start=8000&hist_limit=50");
    assert_eq!(
        page["history"]["slots"].as_array().map(Vec::len),
        Some(50),
        "{page}"
    );
    assert_eq!(page["history"]["noofslots"], 8760, "{page}");
    assert!(
        n < 128 * 1024,
        "a 50-row page from a year-deep history weighed {n} bytes - paging is not at the store"
    );
}

/// Gate 3: a bare `mode=history` is a page, not the whole store.
///
/// The SAB facade page is ungated - unlike the dashboard poll, which
/// api/queue.rs revision-gates and clamps to 1..=500 - so before
/// `HISTORY_DEFAULT_LIMIT` every bare request rendered every row of
/// every client's poll: 554 ms and 512 MB of transient allocation at
/// 105,000 rows (20 Aug measurement, "C8 measured"). The bound has to
/// hold without taking anything away from a client that asks properly,
/// so all four halves are pinned together: the default caps, an
/// explicit `limit=0` reads as SAB reads it, a bigger explicit window
/// is still served in full, and a named id is still found past the cap.
#[test]
fn a_bare_history_request_is_bounded() {
    let dir = scratch("barehist");
    seed_history_jsonl(&dir, 8760);
    let d = serve(&dir);
    let port = d.port;

    // The default cap, and the total still reported in full so a client
    // knows how far it has to page.
    let (bare, bare_bytes) = api_raw(port, "mode=history");
    assert_eq!(
        bare["history"]["slots"].as_array().map(Vec::len),
        Some(500),
        "a bare mode=history was not capped: {}",
        bare["history"]["noofslots"]
    );
    assert_eq!(bare["history"]["noofslots"], 8760, "{bare}");

    // SAB's `if not limit` treats an explicit zero as "none given"; so
    // do we. This is the shape an older client borrows from the queue
    // call, and answering it with the year would reopen the hole.
    let zero = api(port, "mode=history&limit=0");
    assert_eq!(
        zero["history"]["slots"].as_array().map(Vec::len),
        Some(500),
        "limit=0 was read as unbounded: {}",
        zero["history"]["noofslots"]
    );

    // Asking IS still answered: an explicit window past the default is
    // served whole - paging is the escape hatch for the whole store.
    let wide = api(port, "mode=history&start=0&limit=1000");
    assert_eq!(
        wide["history"]["slots"].as_array().map(Vec::len),
        Some(1000),
        "an explicit limit was clamped: {}",
        wide["history"]["noofslots"]
    );

    // And the cap is what makes the difference, not some other filter:
    // the whole-store render is an order of magnitude heavier.
    let (all, all_bytes) = api_raw(port, "mode=history&start=0&limit=8760");
    assert_eq!(
        all["history"]["slots"].as_array().map(Vec::len),
        Some(8760),
        "{}",
        all["history"]["noofslots"]
    );
    assert!(
        bare_bytes * 8 < all_bytes,
        "the bare page weighed {bare_bytes} bytes against {all_bytes} for the whole store - \
         the default cap is not bounding anything"
    );

    // Direct id selection bypasses the window, as it always has (SAB
    // semantics). y10 is the 8750th row newest-first: far outside any
    // window, and the only way the dashboard's row drawer and an *arr
    // asking about one grab can find it.
    let byid = api(port, "mode=history&nzo_ids=SABnzbd_nzo_y10");
    let slots = byid["history"]["slots"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(slots.len(), 1, "{byid}");
    assert_eq!(slots[0]["nzo_id"], "SABnzbd_nzo_y10", "{byid}");
}

/// Gate 2: five open tabs cannot starve the 8-worker pool. Five threads
/// poll the revisioned round-trip at 1 Hz against the year-deep daemon
/// while a sixth pages through history; throughout, `mode=version` and
/// `/` (the calls that went silent in the 28 Jul and 2 Aug wedges)
/// answer promptly.
#[test]
fn five_tabs_cannot_starve_the_pool() {
    let dir = scratch("fivetabs");
    seed_history_jsonl(&dir, 8760);
    let d = serve(&dir);
    let port = d.port;

    let first = api(port, "mode=dashboard&hist_limit=50");
    let qrev = first["queue_revision"].as_u64().expect("queue_revision");
    let hrev = first["history_revision"]
        .as_u64()
        .expect("history_revision");
    let seq = first["events_seq"].as_u64().expect("events_seq");

    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    // Five dashboard tabs, mostly-unchanged polls at 1 Hz.
    let tabs: Vec<_> = (0..5)
        .map(|_| {
            let stop = stop.clone();
            std::thread::spawn(move || {
                let mut polls = 0u32;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let t = Instant::now();
                    let v = api(
                        port,
                        &format!(
                            "mode=dashboard&queue_rev={qrev}&history_rev={hrev}&events={seq}&hist_limit=50"
                        ),
                    );
                    assert!(v.get("stats").is_some(), "a tab poll lost its stats: {v}");
                    assert!(
                        t.elapsed() < Duration::from_secs(3),
                        "a tab poll took {}ms",
                        t.elapsed().as_millis()
                    );
                    polls += 1;
                    std::thread::sleep(Duration::from_millis(1000));
                }
                polls
            })
        })
        .collect();
    // A sixth user paging through deep history the whole time.
    let pager = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            let mut start = 0usize;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let t = Instant::now();
                let v = api(port, &format!("mode=history&start={start}&limit=50"));
                assert_eq!(
                    v["history"]["slots"].as_array().map(Vec::len),
                    Some(50),
                    "{v}"
                );
                assert!(
                    t.elapsed() < Duration::from_secs(3),
                    "a history page took {}ms",
                    t.elapsed().as_millis()
                );
                start = (start + 500) % 8000;
                std::thread::sleep(Duration::from_millis(200));
            }
        })
    };

    // Meanwhile: the canary calls answer promptly, every time.
    //
    // WARM `/` FIRST, and this is not a convenience - without it the
    // first sample below measures something that is not contention at
    // all. `/` is served out of a per-process cache (`SHELL_CACHE` in
    // serve/webasset.rs), so the first request for it pays a one-time
    // build - the substitutions over 1.4 MB of HTML, an FNV over the
    // result and a level-6 deflate of that - and every request after it
    // is a cache hit. That build is a fixed process-lifetime constant.
    //
    // Measured 31 Aug 2026 on a Core Ultra 9 laptop (Windows 11, MSVC,
    // debug) with NO tabs polling at all: the first `/` took 2537 ms and
    // the next nine 252-277 ms. So the assertion below fired on that
    // first call and reported it as "behind five dashboard tabs", which
    // was untrue - nothing was behind anything, and the same box failed
    // it identically with the whole load absent. Warm, and under the
    // full five-tab load, that box serves `/` in 245-322 ms.
    //
    // It is a DEBUG-build cost and not a user-facing one: the same cold
    // call is 30 ms on a release binary and 212-607 ms on a debug one,
    // both on the dev Mac, against 4-17 ms warm.
    //
    // Warming does not weaken the gate. The wedge being replayed is
    // every worker parked on the index mutex, and a starved `/` misses
    // the bound whether its page is built or cached; what the warm-up
    // drops is the one sample that could never have been about the pool.
    let _ = http(port, "/");
    for _ in 0..10 {
        let t = Instant::now();
        let v = api(port, "mode=version");
        assert!(v.get("version").is_some(), "mode=version answered: {v}");
        assert!(
            t.elapsed() < Duration::from_secs(2),
            "mode=version took {}ms behind five dashboard tabs",
            t.elapsed().as_millis()
        );
        let t = Instant::now();
        let page = http(port, "/");
        assert!(!page.is_empty(), "/ served nothing");
        assert!(
            t.elapsed() < Duration::from_secs(2),
            "/ took {}ms behind five dashboard tabs",
            t.elapsed().as_millis()
        );
        std::thread::sleep(Duration::from_millis(800));
    }

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for t in tabs {
        let polls = t.join().expect("tab thread");
        assert!(polls >= 5, "a tab managed only {polls} polls in ~8s");
    }
    pager.join().expect("pager thread");
}
