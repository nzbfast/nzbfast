//! TODO §129 phase 1 contract: history in its own store (unlimited,
//! paged, searchable) and the revisioned `mode=dashboard` round-trip.
//! Written BEFORE the implementation, per the phase's "pin the contract
//! with tests first" rule - see
//! research/PLAN-2026-08-08-129-phase1-history-dashboard.md.
//!
//! Everything here is black-box over HTTP against a spawned daemon with
//! no news servers (the scratch-daemon pattern): history rows are seeded
//! by writing the persistence files the daemon itself reads, which is
//! also how the migration contract gets exercised for free.

use crate::scratch;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;

use crate::harness::Daemon;
use std::time::Duration;

use serde_json::{Value, json};

/// One attempt, returning the response BODY - the http_wedge.rs shape:
/// bytes first, de-chunk, UTF-8 last (tiny_http chunks anything over
/// 32 KB and a chunk header can land mid-codepoint).
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

/// Retried only when the daemon produced NOTHING (pre-byte refusal on a
/// loaded box); an answered request is never retried.
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

/// Same call, but the caller wants the raw body size too (the phase-1d
/// "unchanged refresh is small" gate lives on bytes, not parsed shape).
fn api_raw(port: u16, q: &str) -> (Value, usize) {
    let body = http(port, &format!("/api?output=json&apikey=sekrit&{q}"));
    let n = body.len();
    let text = String::from_utf8(body).expect("API body is UTF-8");
    let v =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("bad JSON for {q:?}: {e}\n{text}"));
    (v, n)
}

fn scratch(name: &str) -> scratch::ScratchDir {
    let dir = std::env::temp_dir().join(format!("nzbfast-drev-{}-{name}", std::process::id()));
    let dir = scratch::ScratchDir::attach(&dir);
    std::fs::write(dir.join("config.json"), "{\"servers\":[]}").unwrap();
    // An existing install (no first-run key minted; the key comes from
    // --apikey), indexer off - nothing here needs it.
    std::fs::write(dir.join("settings.json"), "{\"index_enabled\": false}").unwrap();
    dir
}

/// Same scratch, but pointed at a mock NNTP server that holds NO
/// articles, so a job added here is picked, asks for its one segment,
/// is told 430, and fails - the fast add-to-park arc.
///
/// For the two lifecycle tests only. They need a job that walks that
/// whole arc, and until TODO §154 they got it from the plain
/// `servers: []` scratch above: a job on a serverless daemon was picked
/// and failed inside ~500 ms. §154 is exactly the decision that this
/// must no longer happen - with no server configured the runner HOLDS
/// the queue instead of failing the job, because a Failed row on the SAB
/// facade is a blocklist-and-research signal to an *arr. So the arc
/// these tests are about now needs a daemon with somewhere to dial.
/// Nothing about their subject changed, only how the failure is
/// provoked. (An unreachable address is NOT the way: the pool treats a
/// refused connect as a server having a bad minute and retries it
/// indefinitely, so the job never fails at all.)
fn scratch_with_empty_server(name: &str) -> scratch::ScratchDir {
    let dir = scratch(name);
    let addr = empty_mock_server();
    std::fs::write(
        dir.join("config.json"),
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false}}]}}",
            addr.ip(),
            addr.port()
        ),
    )
    .unwrap();
    dir
}

/// Start a mock NNTP server holding nothing, on a thread of its own, and
/// return its address. Deliberately never shut down: this file's tests
/// are synchronous, the server has to outlive the daemon that dials it,
/// and a test binary exiting takes its threads with it.
fn empty_mock_server() -> std::net::SocketAddr {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let srv = nzbkit::mock::MockServer::start(
                    std::collections::HashMap::new(),
                    nzbkit::mock::Chaos::default(),
                )
                .await;
                tx.send(srv.addr).unwrap();
                std::future::pending::<()>().await;
            });
    });
    rx.recv().expect("the mock server never bound")
}

/// One synthetic finished-job record in the persisted `job_json` shape.
/// Only the fields `job_from_json` requires plus what the assertions
/// read; everything else exercises the absent-key legacy paths.
fn hist_record(dir: &Path, i: usize, name: &str, state: &str, category: &str) -> Value {
    json!({
        "nzo_id": format!("SABnzbd_nzo_h{i}"),
        "name": name,
        "nzb_path": dir.join(format!("spool-{i}.nzb")).to_string_lossy(),
        "out_dir": dir.join("complete").join(name).to_string_lossy(),
        "state": state,
        "category": category,
        "total_bytes": 1000 + i as u64,
        "finished_unix": 1_754_000_000i64 + i as i64,
        "fail_message": if state == "Failed" { "articles missing" } else { "" },
    })
}

/// Seed history the LEGACY way: a queue.json still carrying a "history"
/// array. The daemon must both read it and split it out (migration).
fn seed_legacy(dir: &Path, records: &[Value]) {
    let spool = dir.join(".spool");
    std::fs::create_dir_all(&spool).unwrap();
    let v = json!({"next_id": 100_000, "queue": [], "history": records});
    std::fs::write(
        spool.join("queue.json"),
        serde_json::to_string_pretty(&v).unwrap(),
    )
    .unwrap();
}

fn serve(dir: &Path) -> Daemon {
    serve_env(dir, &[])
}

/// Same daemon, with extra environment on the child - the quota test
/// pins TZ=UTC so a ledger seeded at UTC midnight stays this period's.
fn serve_env(dir: &Path, envs: &[(&str, &str)]) -> Daemon {
    crate::harness::serve_blocking(dir, |port| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        for (k, v) in envs {
            cmd.env(k, v);
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
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"));
        cmd
    })
}

fn slots(v: &Value) -> Vec<Value> {
    v["history"]["slots"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

/// 1+2: history survives a restart in its own file, and a legacy
/// queue.json (history array inside) is split on first boot - read,
/// migrated out, and never lost.
#[test]
fn history_survives_restart_in_its_own_file() {
    let dir = scratch("ownfile");
    seed_legacy(
        &dir,
        &[
            hist_record(&dir, 1, "Alpha.Movie.2020", "Completed", "movies"),
            hist_record(&dir, 2, "Beta.Show.S01E01", "Failed", "tv"),
        ],
    );

    {
        let d = serve(&dir);
        let h = api(d.port, "mode=history");
        assert_eq!(slots(&h).len(), 2, "legacy rows visible after boot: {h}");
        // The split happened: history has its own file, queue.json no
        // longer carries the array. (Poll briefly - the migration runs
        // at load, but give a slow CI disk a beat.)
        let spool = dir.join(".spool");
        let mut split = false;
        for _ in 0..50 {
            let q: Value = serde_json::from_str(
                &std::fs::read_to_string(spool.join("queue.json")).unwrap_or_default(),
            )
            .unwrap_or(Value::Null);
            let gone = q
                .get("history")
                .and_then(Value::as_array)
                .is_none_or(|a| a.is_empty());
            if spool.join("history.jsonl").exists() && gone {
                split = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(split, "queue.json was not split into history.jsonl");
    }

    // A second boot reads the new layout.
    let d = serve(&dir);
    let h = api(d.port, "mode=history");
    let s = slots(&h);
    assert_eq!(s.len(), 2, "rows survive the restart: {h}");
    // Newest first: record 2 finished later.
    assert_eq!(s[0]["name"], "Beta.Show.S01E01", "{h}");
    assert_eq!(s[0]["status"], "Failed", "{h}");
    assert_eq!(s[1]["status"], "Completed", "{h}");
}

/// 3: paging and search live at the store - `start`/`limit` windows,
/// `noofslots` counts the FILTERED total, `search=` narrows by name
/// case-insensitively, `nzo_ids=` bypasses the window, facet `counts`
/// ride the reply, and the existing filters still compose.
#[test]
fn history_paging_and_search() {
    let dir = scratch("paging");
    let records: Vec<Value> = (0..40)
        .map(|i| {
            let (name, state, cat) = if i % 4 == 0 {
                (format!("Beta.Show.S01E{i:02}"), "Failed", "tv")
            } else {
                (format!("Alpha.Movie.{i:02}"), "Completed", "movies")
            };
            hist_record(&dir, i, &name, state, cat)
        })
        .collect();
    seed_legacy(&dir, &records);
    let d = serve(&dir);
    let port = d.port;

    // The unpaged facade answer: newest first, and everything here
    // because 40 rows is inside HISTORY_DEFAULT_LIMIT. The cap
    // itself is gated in tests/integration/dashboard_load.rs, which
    // has a history deep enough to reach it.
    let all = api(port, "mode=history");
    assert_eq!(slots(&all).len(), 40, "{all}");
    assert_eq!(all["history"]["noofslots"], 40, "{all}");

    // A window: 10 rows starting at 5, total still 40.
    let page = api(port, "mode=history&start=5&limit=10");
    let s = slots(&page);
    assert_eq!(s.len(), 10, "{page}");
    assert_eq!(page["history"]["noofslots"], 40, "{page}");
    // Newest-first means row 5 is the record with the 5th-highest
    // finished_unix: i=34.
    assert_eq!(s[0]["nzo_id"], "SABnzbd_nzo_h34", "{page}");

    // Search narrows, case-insensitively, and noofslots follows.
    let found = api(port, "mode=history&search=beta.show");
    assert_eq!(slots(&found).len(), 10, "{found}");
    assert_eq!(found["history"]["noofslots"], 10, "{found}");
    // Search + window compose.
    let found = api(port, "mode=history&search=BETA&start=0&limit=3");
    assert_eq!(slots(&found).len(), 3, "{found}");
    assert_eq!(found["history"]["noofslots"], 10, "{found}");
    // A search that matches nothing says so rather than answering all.
    let none = api(port, "mode=history&search=zzz-not-here");
    assert_eq!(slots(&none).len(), 0, "{none}");
    assert_eq!(none["history"]["noofslots"], 0, "{none}");

    // nzo_ids always finds its row, whatever window would hide it.
    let byid = api(port, "mode=history&start=0&limit=2&nzo_ids=SABnzbd_nzo_h0");
    assert_eq!(slots(&byid).len(), 1, "{byid}");
    assert_eq!(slots(&byid)[0]["nzo_id"], "SABnzbd_nzo_h0", "{byid}");

    // Facet counts for the dashboard's bucket chips: computed over the
    // search/category-filtered set, additive key.
    let c = &all["history"]["counts"];
    assert_eq!(c["all"], 40, "{all}");
    assert_eq!(c["done"], 30, "{all}");
    assert_eq!(c["failed"], 10, "{all}");
    assert_eq!(c["locked"], 0, "{all}");

    // The existing filters still compose with the new ones.
    let f = api(port, "mode=history&failed_only=1&category=tv&limit=4");
    assert_eq!(slots(&f).len(), 4, "{f}");
    assert_eq!(f["history"]["noofslots"], 10, "{f}");
    for s in slots(&f) {
        assert_eq!(s["status"], "Failed", "{f}");
    }
}

/// 4: the SAB facade row is byte-stable - the exact key set external
/// clients see today, no key dropped, none renamed. New capability is
/// additive only.
#[test]
fn mode_history_facade_is_stable() {
    let dir = scratch("facade");
    seed_legacy(
        &dir,
        &[hist_record(
            &dir,
            1,
            "Alpha.Movie.2020",
            "Completed",
            "movies",
        )],
    );
    let d = serve(&dir);
    let h = api(d.port, "mode=history");
    let s = slots(&h);
    assert_eq!(s.len(), 1, "{h}");
    let row = s[0].as_object().expect("row is an object");
    // The pre-phase-1 contract, key for key (history.rs history_json).
    for key in [
        "nzo_id",
        "name",
        "nzb_name",
        "origin",
        "nzb_path",
        "category",
        "status",
        "fail_message",
        "fail_detail",
        "disk_full",
        "space_needed",
        "fail_kind",
        "auto_retry_at",
        "auto_retry_why",
        "fail_hint",
        "fail_action",
        "retry",
        "library",
        "duplicate_key",
        "storage",
        "path",
        "bytes",
        "size",
        "downloaded_bytes",
        "elapsed_secs",
        "completed",
        "bad_blocks",
        "verify_blocks",
        "password_required",
        "has_password",
        "unpack_blocked_by",
        "move_split",
        "move_failed",
        "move_pending",
        "archive_shape",
        "media",
        "identity_name",
        "identity_imdb",
        "identity_src",
        "filed_as",
        "smart_rule",
        "moved_to",
        "cleaned_files",
        "cleaned_par2",
        "cleaned_trash",
        "identify",
        "script_line",
    ] {
        assert!(row.contains_key(key), "facade key {key} missing: {h}");
    }
    assert_eq!(row["status"], "Completed", "{h}");
    assert_eq!(row["bytes"], 1001, "{h}");
}

/// 5: the revisioned round-trip. First call returns everything plus the
/// revision handles; an unchanged repeat returns no collections and a
/// SMALL body; a history mutation bumps the revision and the collection
/// comes back.
#[test]
fn dashboard_mode_revisions() {
    let dir = scratch("revs");
    let records: Vec<Value> = (0..30)
        .map(|i| {
            hist_record(
                &dir,
                i,
                &format!("Alpha.Movie.{i:02}"),
                "Completed",
                "movies",
            )
        })
        .collect();
    seed_legacy(&dir, &records);
    let d = serve(&dir);
    let port = d.port;

    // First poll: no revisions offered, everything comes back.
    let first = api(port, "mode=dashboard&hist_limit=10");
    let qrev = first["queue_revision"].as_u64().expect("queue_revision");
    let hrev = first["history_revision"]
        .as_u64()
        .expect("history_revision");
    let seq = first["events_seq"].as_u64().expect("events_seq");
    assert!(
        first["queue"].is_object(),
        "first poll carries the queue: {first}"
    );
    assert!(
        first["history"].is_object(),
        "first poll carries history: {first}"
    );
    let hist = &first["history"];
    assert_eq!(
        hist["slots"].as_array().map(Vec::len),
        Some(10),
        "the requested window, not everything: {first}"
    );
    assert_eq!(hist["noofslots"], 30, "{first}");
    assert!(first["stats"].is_object(), "stats always ride: {first}");
    // Summary rows are COMPACT: the heavyweight drawer-only keys stay
    // off the per-second wire.
    let srow = hist["slots"][0].as_object().unwrap();
    for key in ["nzo_id", "name", "status", "bytes", "completed", "category"] {
        assert!(srow.contains_key(key), "summary key {key} missing: {first}");
    }
    for absent in ["fail_detail", "identify", "script_line", "cleaned_files"] {
        assert!(
            !srow.contains_key(absent),
            "summary rows must not carry {absent}: {first}"
        );
    }

    // Unchanged repeat: no collections, and the body is small however
    // large history is (the phase-1d gate in miniature).
    let (again, n) = api_raw(
        port,
        &format!("mode=dashboard&queue_rev={qrev}&history_rev={hrev}&events={seq}&hist_limit=10"),
    );
    assert!(
        again["queue"].is_null(),
        "unchanged queue must not be resent: {again}"
    );
    assert!(
        again["history"].is_null(),
        "unchanged history must not be resent: {again}"
    );
    assert!(again["stats"].is_object(), "stats still ride: {again}");
    assert!(
        n < 4096,
        "unchanged refresh weighed {n} bytes - the idle poll must stay small"
    );

    // A history mutation bumps the revision and the page returns.
    let del = api(
        port,
        "mode=history&name=delete&value=SABnzbd_nzo_h29&del_files=0",
    );
    assert_eq!(del["status"], true, "{del}");
    let after = api(
        port,
        &format!("mode=dashboard&queue_rev={qrev}&history_rev={hrev}&events={seq}&hist_limit=10"),
    );
    let hrev2 = after["history_revision"]
        .as_u64()
        .expect("history_revision");
    assert!(
        hrev2 != hrev,
        "a delete must bump the history revision: {after}"
    );
    assert!(
        after["history"].is_object(),
        "changed history is resent: {after}"
    );
    assert_eq!(after["history"]["noofslots"], 29, "{after}");

    // The events cursor: nothing new means an empty list, not a replay;
    // a cursor from before the ring means an explicit reset signal.
    let ev = after["events"].as_array().expect("events array");
    // (a delete is not a lifecycle event; whatever arrived, seqs are
    // monotonic and past our cursor)
    for e in ev {
        assert!(e["seq"].as_u64().expect("event seq") > seq, "{after}");
    }
    assert_eq!(after["events_reset"], false, "{after}");
}

/// One multipart POST - enough for mode=addfile.
fn http_post_nzb(port: u16, name: &str, nzb: &str) -> Value {
    let boundary = "xxNZBFASTBOUNDARYxx";
    let body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"nzbfile\"; \
         filename=\"{name}\"\r\nContent-Type: text/xml\r\n\r\n{nzb}\r\n--{boundary}--\r\n"
    );
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        s,
        "POST /api?mode=addfile&output=json&apikey=sekrit HTTP/1.1\r\nHost: x\r\n\
         Content-Type: multipart/form-data; boundary={boundary}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let at = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("headers");
    let (head, body) = raw.split_at(at + 4);
    let body = if String::from_utf8_lossy(head)
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        dechunk(body)
    } else {
        body.to_vec()
    };
    serde_json::from_slice(&body).expect("addfile answers JSON")
}

/// 5b: lifecycle events ride the round-trip. A page that primed its
/// cursor (first poll OMITS the events param - no replay) then sees a
/// job fail is handed a `job.failed` event past its cursor - including
/// the daemon's FIRST event ever, i.e. a numeric cursor of 0 is "give
/// me everything after 0", never a second prime.
#[test]
fn lifecycle_events_reach_a_watching_client() {
    let dir = scratch_with_empty_server("events");
    let d = serve(&dir);
    let port = d.port;

    // Prime: no events param at all -> current seq, no backlog.
    let first = api(port, "mode=dashboard");
    let seq0 = first["events_seq"].as_u64().expect("events_seq");
    assert_eq!(first["events"].as_array().map(Vec::len), Some(0), "{first}");

    // A job whose one server holds none of its articles fails and
    // parks (see scratch_with_empty_server).
    let nzb = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
        <nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
        <file poster=\"t@t\" date=\"1722000000\" subject=\"&quot;Event.Test&quot; yEnc (1/1)\">\
        <groups><group>alt.binaries.test</group></groups>\
        <segments><segment bytes=\"5000\" number=\"1\">evt1@test</segment></segments>\
        </file></nzb>";
    let added = http_post_nzb(port, "event-test.nzb", nzb);
    assert_eq!(added["status"], true, "{added}");

    // The event arrives past our cursor.
    let mut got = None;
    for _ in 0..150 {
        let r = api(port, &format!("mode=dashboard&events={seq0}"));
        let evs = r["events"].as_array().cloned().unwrap_or_default();
        if let Some(e) = evs.iter().find(|e| e["kind"] == "job.failed") {
            got = Some(e.clone());
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let e = got.expect("a job.failed event reached the events cursor");
    assert!(e["seq"].as_u64().unwrap_or(0) > seq0, "{e}");
    assert!(e["nzo_id"].as_str().is_some_and(|s| !s.is_empty()), "{e}");
    assert!(
        e["fail_message"].as_str().is_some_and(|s| !s.is_empty()),
        "{e}"
    );

    // A fresh page arriving NOW still never replays it.
    let fresh = api(port, "mode=dashboard");
    assert_eq!(fresh["events"].as_array().map(Vec::len), Some(0), "{fresh}");
    assert!(fresh["events_seq"].as_u64().unwrap_or(0) > seq0, "{fresh}");
}

/// 6: retention knobs exist, ship OFF (unlimited is the default - the
/// recorded product ruling), and enforce a count cap when set.
#[test]
fn retention_knobs_off_by_default_and_enforced_when_set() {
    // Default: nothing purges. 60 seeded rows are all present after boot.
    let dir = scratch("keepdef");
    let records: Vec<Value> = (0..60)
        .map(|i| {
            hist_record(
                &dir,
                i,
                &format!("Alpha.Movie.{i:02}"),
                "Completed",
                "movies",
            )
        })
        .collect();
    seed_legacy(&dir, &records);
    {
        let d = serve(&dir);
        let h = api(d.port, "mode=history");
        assert_eq!(h["history"]["noofslots"], 60, "unlimited by default: {h}");
    }
    drop(dir);

    // With history_keep_count=50: the 10 oldest go, the newest 50 stay.
    let dir = scratch("keepcap");
    let records: Vec<Value> = (0..60)
        .map(|i| {
            hist_record(
                &dir,
                i,
                &format!("Alpha.Movie.{i:02}"),
                "Completed",
                "movies",
            )
        })
        .collect();
    seed_legacy(&dir, &records);
    std::fs::write(
        dir.join("settings.json"),
        "{\"index_enabled\": false, \"history_keep_count\": 50}",
    )
    .unwrap();
    let d = serve(&dir);
    let h = api(d.port, "mode=history");
    assert_eq!(h["history"]["noofslots"], 50, "count cap enforced: {h}");
    let s = slots(&h);
    assert_eq!(s.len(), 50, "{h}");
    // Newest kept, oldest gone.
    assert_eq!(s[0]["nzo_id"], "SABnzbd_nzo_h59", "{h}");
    assert!(
        !s.iter().any(|r| r["nzo_id"] == "SABnzbd_nzo_h9"),
        "the oldest rows were not purged: {h}"
    );
}

/// Issue #45: the age rule works below a day, and still only
/// ever takes COMPLETED rows.
///
/// The knob was `history_keep_days` and is now `history_keep_secs`, for
/// the reason the issue gave: the reporter wanted entries gone "after XY
/// minutes", which whole days cannot say. Days-only also hid the second
/// half of the rule, because at that scale nobody notices which rows it
/// spares - a failed download stays until the user retries it or deletes
/// it, since it is a decision they have not made yet, and a ten-minute
/// rule makes that visible within the hour.
///
/// Seeded relative to NOW, unlike the count-cap test above: a fixed
/// timestamp is "old" under every possible age rule, which is exactly
/// the distinction this test exists to draw.
#[test]
fn the_age_rule_works_in_minutes_and_spares_failed_rows() {
    let dir = scratch("keepage");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let row = |i: usize, name: &str, state: &str, ago: i64| {
        let mut r = hist_record(&dir, i, name, state, "movies");
        r["finished_unix"] = json!(now - ago);
        r
    };
    let records = vec![
        // Inside the window: stays whatever the rule is.
        row(1, "Recent.Completed", "Completed", 60),
        // Past a ten-minute window, and completed: goes.
        row(2, "Stale.Completed", "Completed", 3_600),
        // Past it too, but FAILED: the age rule never takes these.
        row(3, "Stale.Failed", "Failed", 3_600),
    ];
    seed_legacy(&dir, &records);
    std::fs::write(
        dir.join("settings.json"),
        "{\"index_enabled\": false, \"history_keep_secs\": 600}",
    )
    .unwrap();

    let d = serve(&dir);
    let h = api(d.port, "mode=history");
    let names: Vec<String> = slots(&h)
        .iter()
        .map(|r| r["name"].as_str().unwrap_or_default().to_string())
        .collect();
    assert!(
        names.iter().any(|n| n == "Recent.Completed"),
        "a row inside the window was purged: {h}"
    );
    assert!(
        !names.iter().any(|n| n == "Stale.Completed"),
        "a completed row an hour past a ten-minute rule survived - the \
         age cutoff is still being read as days: {h}"
    );
    assert!(
        names.iter().any(|n| n == "Stale.Failed"),
        "the age rule took a FAILED row; only the count cap may do that: {h}"
    );
}

/// §129 4a: the lifecycle schema is versioned and the add-to-park arc
/// emits its stages in order. One job on a daemon whose only server
/// holds nothing walks
/// job.added -> job.started -> job.failed -> queue.idle, every event
/// stamped schema_version 1, and the added payload names its origin.
#[test]
fn the_lifecycle_arc_is_versioned_and_ordered() {
    let dir = scratch_with_empty_server("lifearc");
    let d = serve(&dir);
    let port = d.port;

    let first = api(port, "mode=dashboard");
    let seq0 = first["events_seq"].as_u64().expect("events_seq");

    let nzb = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
        <nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
        <file poster=\"t@t\" date=\"1722000000\" subject=\"&quot;Arc.Test&quot; yEnc (1/1)\">\
        <groups><group>alt.binaries.test</group></groups>\
        <segments><segment bytes=\"5000\" number=\"1\">arc1@test</segment></segments>\
        </file></nzb>";
    let added = http_post_nzb(port, "arc-test.nzb", nzb);
    assert_eq!(added["status"], true, "{added}");

    // Collect until the arc has fully played out.
    let mut evs: Vec<Value> = Vec::new();
    for _ in 0..150 {
        let r = api(port, &format!("mode=dashboard&events={seq0}"));
        evs = r["events"].as_array().cloned().unwrap_or_default();
        if evs.iter().any(|e| e["kind"] == "queue.idle") {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let pos = |kind: &str| {
        evs.iter()
            .position(|e| e["kind"] == kind)
            .unwrap_or_else(|| panic!("no {kind} event in {evs:?}"))
    };
    let (added, started, failed, idle) = (
        pos("job.added"),
        pos("job.started"),
        pos("job.failed"),
        pos("queue.idle"),
    );
    assert!(
        added < started && started < failed && failed < idle,
        "arc out of order: {evs:?}"
    );
    for e in &evs {
        assert_eq!(e["schema_version"], 1, "unversioned event: {e}");
        assert!(e["seq"].as_u64().is_some(), "{e}");
        assert!(e["at"].as_u64().is_some(), "{e}");
    }
    let a = &evs[added];
    assert_eq!(a["origin"], "dashboard", "{a}");
    assert_eq!(a["duplicate"], false, "{a}");
    assert!(a["name"].as_str().is_some_and(|s| !s.is_empty()), "{a}");
    let s = &evs[started];
    assert_eq!(s["resumed"], false, "{s}");

    // queue.idle is a transition: a second quiet poll must not repeat it.
    let last = evs.last().and_then(|e| e["seq"].as_u64()).unwrap();
    let quiet = api(port, &format!("mode=dashboard&events={last}"));
    assert_eq!(quiet["events"].as_array().map(Vec::len), Some(0), "{quiet}");
}

/// The header state rides the revisioned queue payload, so going offline
/// (or pausing) has to bump the revision even though no job row moved.
///
/// It did not, and on an IDLE daemon - nothing downloading, so the
/// `any_active` escape hatch does not fire either - the poll answered
/// `"queue": null`, the page kept the queue object it had last applied,
/// and `paintNet()` repainted "Online" a second after the click over a
/// daemon that really was offline. Pause hid the same staleness only
/// because it is normally pressed mid-download.
#[test]
fn offline_bumps_the_queue_revision_on_an_idle_daemon() {
    let dir = scratch("offlinerev");
    let d = serve(&dir);
    let port = d.port;

    let first = api(port, "mode=dashboard");
    let qrev = first["queue_revision"].as_u64().expect("queue_revision");
    assert_eq!(first["queue"]["offline"], false, "{first}");

    // Nothing changed: the gate still holds (this is what made the bug
    // invisible to a test that only checked the offline flag itself).
    let idle = api(port, &format!("mode=dashboard&queue_rev={qrev}"));
    assert!(idle["queue"].is_null(), "idle poll must stay empty: {idle}");

    assert_eq!(api(port, "mode=offline")["offline"], true);
    let after = api(port, &format!("mode=dashboard&queue_rev={qrev}"));
    assert!(
        after["queue_revision"].as_u64() != Some(qrev),
        "going offline must bump the queue revision: {after}"
    );
    assert_eq!(
        after["queue"]["offline"], true,
        "the page has no other source for the header state: {after}"
    );
    // Offline pauses the queue, and that flag rides the same payload.
    assert_eq!(after["queue"]["paused"], true, "{after}");

    let qrev2 = after["queue_revision"].as_u64().unwrap();
    assert_eq!(api(port, "mode=online")["offline"], false);
    let back = api(port, &format!("mode=dashboard&queue_rev={qrev2}"));
    assert_eq!(back["queue"]["offline"], false, "{back}");
    assert_eq!(back["queue"]["paused"], false, "{back}");
}

/// The other half of the same defect: the header's speed-limit control.
/// `speedlimit_abs` / `auto_speed` / `limit_source` ride the same payload,
/// and a settings write bumped nothing - so on an idle daemon the
/// dropdown snapped back to its old value exactly the way the Offline
/// button did. Covers both seams: `apply_and_save` (this API, the
/// settings page) and `set_speed_ceiling_from` (a schedule entry firing,
/// the NZBGet `rate` facade).
#[test]
fn a_settings_change_bumps_the_queue_revision_on_an_idle_daemon() {
    let dir = scratch("cfgrev");
    let d = serve(&dir);
    let port = d.port;

    let mut rev = api(port, "mode=dashboard")["queue_revision"]
        .as_u64()
        .expect("queue_revision");
    // Untouched: the poll must still answer empty, or this fix has just
    // put the queue back on the wire every second. ADOPTING a bump or
    // two first, bounded: a freshly served daemon's noservers hold
    // latches asynchronously and legitimately bumps the revision once,
    // and on a loaded runner that bump lands BETWEEN this test's first
    // two calls - windows-unit failed exactly here on 28 Aug 2026 (run
    // 33219214125, green on the runs either side) with the full payload
    // and the hold present where the fast box had already folded it into
    // the first read. What is asserted is what the test is about: the
    // revision goes QUIET, and only a settings write moves it after.
    let mut idle = api(port, &format!("mode=dashboard&queue_rev={rev}"));
    for _ in 0..5 {
        if idle["queue"].is_null() {
            break;
        }
        rev = idle["queue_revision"].as_u64().expect("queue_revision");
        idle = api(port, &format!("mode=dashboard&queue_rev={rev}"));
    }
    assert!(idle["queue"].is_null(), "idle poll must stay empty: {idle}");

    // (`speedlimit_abs` is a string in the payload - SAB's units are
    // strings and the facade keeps them that way.)
    for (setting, value, field, want) in [
        ("speedlimit", "4M", "speedlimit_abs", json!("4000000")),
        ("auto_speed", "1", "auto_speed", json!(true)),
        ("auto_speed", "0", "auto_speed", json!(false)),
        ("speedlimit", "0", "speedlimit_abs", json!("0")),
    ] {
        let set = api(port, &format!("mode=config&name={setting}&value={value}"));
        assert_ne!(set["status"], false, "{setting}={value} refused: {set}");
        let after = api(port, &format!("mode=dashboard&queue_rev={rev}"));
        assert!(
            !after["queue"].is_null(),
            "{setting}={value} must resend the queue: {after}"
        );
        assert_eq!(after["queue"][field], want, "{setting}={value}: {after}");
        rev = after["queue_revision"].as_u64().expect("queue_revision");
    }
}

/// §154's hold rides the same revisioned payload, and setting it moved
/// nothing - so on a queue that has just STOPPED (every job Queued, so
/// `any_active` is false too) an open dashboard kept the snapshot it had
/// last applied and never drew the banner the hold exists to draw. The
/// clear edge is the same defect from the other side: the banner would
/// have stayed on screen after a server was added.
///
/// Both edges, and the idle poll between them stays empty - a hold
/// re-published every tick would put the whole queue back on the wire
/// once a second.
#[test]
fn the_no_servers_hold_bumps_the_queue_revision_on_both_edges() {
    let dir = scratch_with_empty_server("noservrev");
    let cfg = dir.join("config.json");
    let server_cfg = std::fs::read_to_string(&cfg).unwrap();
    let d = serve(&dir);
    let port = d.port;

    let first = api(port, "mode=dashboard");
    let mut rev = first["queue_revision"].as_u64().expect("queue_revision");
    assert!(first["queue"]["hold"].is_null(), "{first}");
    let idle = api(port, &format!("mode=dashboard&queue_rev={rev}"));
    assert!(idle["queue"].is_null(), "idle poll must stay empty: {idle}");

    // The last server goes away. The runner re-reads the config every
    // tick, so the hold lands within about a second.
    std::fs::write(&cfg, "{\"servers\":[]}").unwrap();
    let held = poll_until(port, rev, |q| q["hold"]["reason"] == "noservers");
    rev = held["queue_revision"].as_u64().expect("queue_revision");
    assert!(
        api(port, &format!("mode=dashboard&queue_rev={rev}"))["queue"].is_null(),
        "the hold must not re-publish the queue every tick"
    );

    // And a server comes back.
    std::fs::write(&cfg, &server_cfg).unwrap();
    let cleared = poll_until(port, rev, |q| q["hold"].is_null());
    assert!(cleared["queue"]["hold"].is_null(), "{cleared}");
}

/// §156 item 6: the disk hold rides the same revisioned payload as the
/// §154 no-servers hold above, and had the identical omission - it set
/// and cleared `queue_hold` with no revision bump, so a long-poll client
/// on an idle queue never drew the banner and kept it after the hold
/// lifted.
///
/// The hold is driven through `min_free` over the API, and a settings
/// write bumps the revision once itself (deliberately blunt - see
/// `apply_and_save`), so `poll_edge` re-anchors on every payload it
/// sees: after the settings bump is consumed, only the runner's own
/// edge bump can deliver the payload that satisfies the predicate.
#[test]
fn the_disk_hold_bumps_the_queue_revision_on_both_edges() {
    let dir = scratch_with_empty_server("diskrev");
    let d = serve(&dir);
    let port = d.port;

    let first = api(port, "mode=dashboard");
    let rev = first["queue_revision"].as_u64().expect("queue_revision");
    assert!(first["queue"]["hold"].is_null(), "{first}");

    // A minimum no disk satisfies.
    let set = api(port, "mode=config&name=min_free&value=1000T");
    assert_ne!(set["status"], false, "{set}");
    let rev = poll_edge(port, rev, |q| q["hold"]["reason"] == "disk");
    assert!(
        api(port, &format!("mode=dashboard&queue_rev={rev}"))["queue"].is_null(),
        "the standing hold must not re-publish the queue every pass"
    );

    let set = api(port, "mode=config&name=min_free&value=0");
    assert_ne!(set["status"], false, "{set}");
    poll_edge(port, rev, |q| q["hold"].is_null());
}

/// §156 item 6, the quota half - same defect, same shape as the disk
/// test above. The spend is seeded into the period's ledger before the
/// daemon opens it (the daemon.rs quota test's pattern): `start` is
/// this period's UTC midnight and the daemon is pinned to TZ=UTC, or
/// `open` treats the window as stale and zeroes the count.
#[test]
fn the_quota_hold_bumps_the_queue_revision_on_both_edges() {
    let dir = scratch_with_empty_server("quotarev");
    let spool = dir.join(".spool");
    std::fs::create_dir_all(&spool).unwrap();
    let midnight = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 86_400
        * 86_400;
    std::fs::write(
        spool.join("quota.json"),
        format!("{{\"start\":{midnight},\"bytes\":9000000000}}"),
    )
    .unwrap();
    let d = serve_env(&dir, &[("TZ", "UTC")]);
    let port = d.port;

    let first = api(port, "mode=dashboard");
    let rev = first["queue_revision"].as_u64().expect("queue_revision");
    assert!(first["queue"]["hold"].is_null(), "{first}");

    // A cap far under the 9 GB the ledger already says was spent.
    let set = api(port, "mode=config&name=quota&value=1G");
    assert_ne!(set["status"], false, "{set}");
    let rev = poll_edge(port, rev, |q| q["hold"]["reason"] == "quota");
    assert!(
        api(port, &format!("mode=dashboard&queue_rev={rev}"))["queue"].is_null(),
        "the standing hold must not re-publish the queue every pass"
    );

    // Lifting the cap clears the hold.
    let set = api(port, "mode=config&name=quota&value=0");
    assert_ne!(set["status"], false, "{set}");
    poll_edge(port, rev, |q| q["hold"].is_null());
}

/// Like `poll_until`, but re-anchors: every answered poll advances the
/// revision it polls with, so the predicate can only be satisfied by a
/// payload published with a bump AFTER the last unrelated one - which
/// is what pins a hold's own edge bump when the settings write that
/// provoked it has already moved the revision once. The window is wider
/// than `poll_until`'s because a standing disk hold paces the runner at
/// one pass per five seconds. Returns the satisfying payload's revision.
fn poll_edge(port: u16, mut rev: u64, want: impl Fn(&serde_json::Value) -> bool) -> u64 {
    for _ in 0..100 {
        let a = api(port, &format!("mode=dashboard&queue_rev={rev}"));
        if !a["queue"].is_null() {
            let got = a["queue_revision"].as_u64().expect("queue_revision");
            if want(&a["queue"]) {
                return got;
            }
            rev = got;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    panic!(
        "no revision bump ever published the expected payload: {}",
        api(port, &format!("mode=dashboard&queue_rev={rev}"))
    );
}

/// Poll the revisioned dashboard endpoint from `rev` until the queue
/// payload arrives AND satisfies `want`. Returns the whole answer.
fn poll_until(port: u16, rev: u64, want: impl Fn(&serde_json::Value) -> bool) -> serde_json::Value {
    for _ in 0..60 {
        let a = api(port, &format!("mode=dashboard&queue_rev={rev}"));
        if !a["queue"].is_null() && want(&a["queue"]) {
            return a;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!(
        "the queue payload never moved: {}",
        api(port, &format!("mode=dashboard&queue_rev={rev}"))
    );
}
