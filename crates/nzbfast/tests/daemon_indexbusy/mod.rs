//! TODO 166: a user's index WRITE waits for the write mutex, but not
//! for ever - and when the budget runs out the click is REFUSED, never
//! silently dropped and never reported as done.
//!
//! The hazard is measured, not theoretical: the realtime tip watcher
//! holds the write mutex for a whole header-ingest transaction (~80 s
//! on the live daemon, 14 Aug 2026), and four HTTP workers queued
//! behind a 62 s hold is how one dashboard tab wedged the whole daemon
//! on 28 Jul. Every handler in `api/wall.rs` and `api/index.rs` that
//! writes on the user's behalf used to park on that mutex with no bound
//! at all.
//!
//! `try_with_index_mut` is NOT the fix and this leg is what says so: the
//! busy answer has to be distinguishable from success, because the edit
//! did not happen. A `try_` would have produced the same "failed"
//! whenever a scan batch held the mutex for a millisecond, which is why
//! the wait is kept and only its length is bounded.
//!
//! A sibling-dir child of daemon.rs (the daemon_finish pattern) so the
//! parent stays inside its size-gate baseline. Declared from daemon.rs,
//! so this runs in that binary against those fixtures; harness via
//! `use super::*`.

use super::*;

/// The rule this leg writes, and looks for in the list either side of
/// the hold. `rule_add` lowercases its value.
const RULE: &str = "busytest";

/// The rules the daemon currently holds, by value.
fn rule_values(port: u16) -> Vec<String> {
    let r = http(port, "/api?mode=wall_rules&output=json", None);
    let v: serde_json::Value = serde_json::from_str(&r).unwrap_or(serde_json::Value::Null);
    v["rules"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x["value"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// A write the user asked for, behind a write mutex somebody else is
/// holding for longer than the budget: the handler answers "busy" in
/// bounded time, the rule is NOT in the index, and the same click
/// straight afterwards works.
///
/// The 80 s ingest is synthesized with the NZBFAST_DEBUG_HOOKS-gated
/// mode=debug_hold_index, which sleeps inside `with_index` - the same
/// mutex a real ingest batch holds (http_wedge's rig, and the reason
/// this daemon is launched with the hook).
#[tokio::test(flavor = "multi_thread")]
async fn a_held_index_write_mutex_refuses_the_edit_rather_than_parking_the_worker() {
    let dir = std::env::temp_dir().join(format!("nzbfast-busy166-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.json");
    std::fs::write(&cfg, "{\"servers\":[]}").unwrap();
    // The whole subject is the index connection, so the index is on -
    // and nothing else about this daemon matters.
    std::fs::write(dir.join("settings.json"), "{\"index_enabled\": true}").unwrap();
    let db = dir.join("index.db");

    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_DEBUG_HOOKS", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--index-db")
            .arg(&db)
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        let add = |v: &str| {
            let r = http(
                port,
                &format!("/api?mode=wall_rule_add&name=group&value={v}&output=json"),
                None,
            );
            serde_json::from_str::<serde_json::Value>(&r)
                .unwrap_or_else(|e| panic!("bad JSON from wall_rule_add: {e}\n{r}"))
        };

        // Control: an uncontended index takes the write. Without this
        // the busy assertion below could pass on a daemon that simply
        // cannot add rules at all.
        assert_eq!(add("control")["status"], true);
        assert!(rule_values(port).iter().any(|v| v == "control"));

        // The 62 s batch of the incident, scaled to test time. The hold
        // runs comfortably longer than HTTP_INDEX_WAIT (5 s), so the
        // handler below meets a mutex that is still held when its
        // budget runs out.
        let holder = std::thread::spawn(move || {
            http(
                port,
                "/api?mode=debug_hold_index&value=12&output=json",
                None,
            )
        });
        // The hook is inside the lock within milliseconds; a beat to be
        // sure it is in before the write asks for it.
        std::thread::sleep(std::time::Duration::from_millis(500));

        let t = std::time::Instant::now();
        let j = add(RULE);
        let waited = t.elapsed();

        // Bounded: the worker is back in the pool long before the hold
        // ends. An unbounded `with_index` waits out the whole hold, and
        // then reports the edit as saved.
        assert!(
            waited < std::time::Duration::from_secs(15),
            "the write parked {}ms behind the held index mutex",
            waited.as_millis()
        );
        // ...and it really did wait. A `try_` would have come back
        // instantly, which is the trade this bound exists to refuse.
        assert!(
            waited >= std::time::Duration::from_secs(4),
            "the write gave up after {}ms - the WAIT is what keeps the edit",
            waited.as_millis()
        );
        // Refused, and told the user why. `status: true` here would be
        // the whole defect: an edit reported as saved that no index
        // ever saw.
        assert_eq!(j["status"], false, "a busy index must not report success");
        assert!(
            j["error"].as_str().unwrap_or("").contains("busy"),
            "the busy reason has to reach the toast: {j}"
        );
        // ...and said it in a field, not only in prose. THE FLAG IS
        // THE CONTRACT: a refused write and a refused ARGUMENT were the
        // same shape - `{"status": false, "error": <sentence>}` - so
        // nothing but the message text separated "the moment was wrong,
        // press it again" from "your key was wrong, do not". That cost
        // `wall_groups_dedupes_and_serves` two days of intermittent
        // failure under load: its `wall_art` assertion read the busy
        // refusal as the daemon's real answer, and its sibling compared
        // the busy SENTENCE against "unknown title key". Every refusal
        // out of `IndexBusy::refusal` carries `busy` now, reads and
        // writes alike, and this is what holds it there.
        assert_eq!(j["busy"], true, "a refused write says so in a field: {j}");
        // Nothing was written. The pooled read answers while the write
        // mutex is held, which is what makes this checkable DURING the
        // hold rather than after it.
        assert!(
            !rule_values(port).iter().any(|v| v == RULE),
            "a refused write must leave the index alone"
        );

        // The hold ends, and the same click - the retry the toast asks
        // for - lands.
        let held = holder.join().expect("holder thread");
        assert!(
            held.contains("\"held\":true"),
            "the hook held the lock: {held}"
        );
        assert_eq!(add(RULE)["status"], true);
        assert!(
            rule_values(port).iter().any(|v| v == RULE),
            "the retry after a busy answer must actually stick"
        );
    })
    .await
    .unwrap();
}

/// One-file multipart body for a `wall_art` upload.
fn art_multipart(boundary: &str, bytes: &[u8]) -> Vec<u8> {
    let mut mp = Vec::new();
    mp.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; \
             filename=\"p.png\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    mp.extend_from_slice(bytes);
    mp.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    mp
}

/// Two 1x1 PNGs, one red and one blue, so "which picture is on disk" is
/// a byte comparison. Both decode, which matters: the poster has to be
/// real enough for the thumbnail route to cache a derivative of it.
const RED_PNG: &[u8] = b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d\x49\x48\x44\x52\
    \x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90\x77\x53\xde\
    \x00\x00\x00\x0c\x49\x44\x41\x54\x78\xda\x63\xf8\xcf\xc0\x00\x00\x03\
    \x01\x01\x00\xf7\x03\x41\x43\x00\x00\x00\x00\x49\x45\x4e\x44\xae\x42\x60\x82";

/// The replacement the busy write must NOT publish. See `RED_PNG`.
const BLUE_PNG: &[u8] = b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d\x49\x48\x44\x52\
    \x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90\x77\x53\xde\
    \x00\x00\x00\x0c\x49\x44\x41\x54\x78\xda\x63\x60\x60\xf8\x0f\x00\x01\
    \x03\x01\x00\x36\x74\x11\x40\x00\x00\x00\x00\x49\x45\x4e\x44\xae\x42\x60\x82";

/// F-07 and F-08, one hold: the two `api/wall.rs` writes that a held
/// index mutex used to catch out.
///
/// F-07 - `art_name` is a pure function of the title key, so a
/// REPLACEMENT poster lands on exactly the path the existing row already
/// names. The upload used to write those bytes, and drop the cached
/// thumbnail, BEFORE it looked at the index write's result: a busy mutex
/// then answered `status: false` over an image that had already changed
/// on the wall, with the previous one gone for good. The bytes now stage
/// beside the live file and are published by rename only once the row
/// write has landed.
///
/// F-08 - `wall_refresh&value=blanked` called the UNBOUNDED `with_index`.
/// Only `value=all` is classified as a deliberately blocking admin reset
/// (TODO 166); this arm was added later and inherited the wrong door, so
/// it parked an HTTP worker for a whole ingest transaction.
#[tokio::test(flavor = "multi_thread")]
async fn a_held_index_leaves_the_poster_alone_and_bounds_the_blanked_sweep() {
    let dir = std::env::temp_dir().join(format!("nzbfast-busyart-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.json");
    std::fs::write(&cfg, "{\"servers\":[]}").unwrap();
    std::fs::write(dir.join("settings.json"), "{\"index_enabled\": true}").unwrap();
    let db = dir.join("index.db");
    // One release, so the title key below resolves to a card. The
    // upload seeds its own row from that card, which is the ordinary
    // first-poster path.
    {
        let mut ix = nzbkit::index::Index::open(&db).unwrap();
        ix.ingest(
            "alt.binaries.teevee",
            &[nzbkit::nntp::OverEntry {
                number: 1,
                subject: "\"The.Matrix.1999.2160p.BluRay.REMUX-GRP.rar\" yEnc (1/1)".into(),
                from: "poster@x".into(),
                message_id: "<m1@x>".into(),
                bytes: 5000,
                date: 0,
            }],
            1_700_000_000,
        )
        .unwrap();
    }

    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_DEBUG_HOOKS", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--index-db")
            .arg(&db)
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;
    let art = dir.join(".spool").join("art");

    tokio::task::spawn_blocking(move || {
        let first = RED_PNG;
        let second = BLUE_PNG;
        let upload = |bytes: &[u8]| -> serde_json::Value {
            let body = art_multipart("artb", bytes);
            let r = http(
                port,
                "/api?mode=wall_art&key=m%3Athe%20matrix%3A1999&output=json",
                Some(("multipart/form-data; boundary=artb", &body)),
            );
            serde_json::from_str::<serde_json::Value>(&r)
                .unwrap_or_else(|e| panic!("bad JSON from wall_art: {e}\n{r}"))
        };
        let poster = art.join("m_the_matrix_1999.jpg");
        let thumb = art.join("thumb_m_the_matrix_1999.jpg");

        // Control: an uncontended index publishes the first poster.
        assert_eq!(upload(first)["status"], true);
        assert_eq!(std::fs::read(&poster).unwrap(), first, "the poster landed");
        // The grid's derivative, generated on first request and cached
        // under a name of its own. It has to exist before the refused
        // replacement, or "the thumbnail survived" says nothing.
        let _ = http(port, "/art/thumb_m_the_matrix_1999.jpg", None);
        assert!(thumb.exists(), "the thumbnail was never cached");

        let holder = std::thread::spawn(move || {
            http(
                port,
                "/api?mode=debug_hold_index&value=12&output=json",
                None,
            )
        });
        std::thread::sleep(std::time::Duration::from_millis(500));

        // F-07. The replacement is refused, and refused means the wall
        // still shows the picture the user had.
        let t = std::time::Instant::now();
        let j = upload(second);
        let waited = t.elapsed();
        assert!(
            waited < std::time::Duration::from_secs(11),
            "the upload parked {}ms behind the held index mutex",
            waited.as_millis()
        );
        assert_eq!(j["status"], false, "a busy index must not report success");
        assert!(
            j["error"].as_str().unwrap_or("").contains("busy"),
            "the busy reason has to reach the toast: {j}"
        );
        // See the same pair in the rules leg above: the flag is what a
        // caller can act on, and `m_wall_art`'s own "unknown title key"
        // is the answer it would otherwise be confused with.
        assert_eq!(j["busy"], true, "a refused upload says so in a field: {j}");
        assert_eq!(
            std::fs::read(&poster).unwrap(),
            first,
            "a refused upload destroyed the poster it said it had not replaced"
        );
        assert!(
            thumb.exists(),
            "a refused upload dropped the thumbnail of the poster that is still there"
        );
        // The staging file is the fix's own residue, and it must not
        // outlive the request that made it.
        let strays: Vec<String> = std::fs::read_dir(&art)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .filter(|n| n.contains(".new-"))
            .collect();
        assert!(strays.is_empty(), "abandoned staging files: {strays:?}");

        // F-08. The manual blanked sweep answers on the same bounded
        // contract instead of waiting out the hold.
        let t = std::time::Instant::now();
        let r = http(
            port,
            "/api?mode=wall_refresh&value=blanked&output=json",
            None,
        );
        let waited = t.elapsed();
        let v: serde_json::Value = serde_json::from_str(&r)
            .unwrap_or_else(|e| panic!("bad JSON from wall_refresh: {e}\n{r}"));
        assert!(
            waited < std::time::Duration::from_secs(11),
            "the blanked sweep parked {}ms on the index mutex",
            waited.as_millis()
        );
        assert_eq!(v["status"], false, "{v}");
        assert!(
            v["error"].as_str().unwrap_or("").contains("busy"),
            "the blanked sweep has to say why it refused: {v}"
        );
        assert_eq!(v["busy"], true, "a refused sweep says so in a field: {v}");

        // The hold ends and the retry the toast asks for publishes.
        let held = holder.join().expect("holder thread");
        assert!(
            held.contains("\"held\":true"),
            "the hook held the lock: {held}"
        );
        assert_eq!(upload(second)["status"], true);
        assert_eq!(
            std::fs::read(&poster).unwrap(),
            second,
            "the retry after a busy answer must actually publish"
        );
        assert!(
            !thumb.exists(),
            "the stale thumbnail outlived the poster it was made from"
        );
    })
    .await
    .unwrap();
}

/// The recorded searches read off the pool, by query. `search_misses`
/// answers on the READ path, so this is checkable DURING a hold on the
/// write mutex - which is what makes "the busy clear left the rows
/// alone" an assertion rather than an inference.
fn recorded(port: u16) -> Vec<String> {
    let r = http(port, "/api?mode=search_misses&output=json", None);
    let v: serde_json::Value = serde_json::from_str(&r).unwrap_or(serde_json::Value::Null);
    v["misses"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x["q"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// TODO 166's residue, found on origin/main after the 15 documented
/// sites had landed: `clear_search_log`. The section audited
/// `api/wall.rs` and `api/index.rs` and this write lives in
/// `crates/nzbfast-daemon/src/searchlog.rs`, whose own module note is TODO 166's argument
/// verbatim - every search-log write is kept off the write mutex
/// BECAUSE an HTTP worker must never park on it - and whose only
/// user-facing door then reached that mutex through the unbounded
/// `with_index` anyway. Two callers, and they need different answers:
///
///  - `mode=search_log_clear`, the Clear button: it already reports a
///    status, so a busy index is REPORTED and the user clicks again.
///    That is the shipped contract for all 15 sites.
///  - the `index_search_log` switch going off: by then the switch has
///    landed and answered, so there is no second button to offer. A
///    busy index would drop the clear silently, which is the shape this
///    whole section refuses - "a privacy switch that leaves the history
///    behind is not one". It LATCHES, and the 60 s searchlog tick runs
///    it on the writer's own thread where waiting is correct.
#[tokio::test(flavor = "multi_thread")]
async fn a_held_index_refuses_the_clear_button_but_never_loses_the_privacy_switch() {
    let dir = std::env::temp_dir().join(format!("nzbfast-busyslog-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.json");
    std::fs::write(&cfg, "{\"servers\":[]}").unwrap();
    std::fs::write(dir.join("settings.json"), "{\"index_enabled\": true}").unwrap();
    let db = dir.join("index.db");

    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_DEBUG_HOOKS", "1")
            // The tick is what retries the deferred clear, so test time
            // needs it faster than a minute. Documented seam, clamped
            // to 1 s at the low end.
            .env("NZBFAST_SEARCH_LOG_FLUSH_SECS", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--index-db")
            .arg(&db)
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // A search nothing can answer, which is exactly what the log is
        // for. It merges in memory and reaches the table on the tick.
        //
        // The search is RE-ISSUED on every turn of the loop, and that
        // is the point of it rather than a detail. `mode=index_search`
        // records a query only when the read pool actually answered:
        // on a busy index it returns `{"status":false,"busy":true}` and
        // deliberately notes nothing - "that is not a miss"
        // (`m_index_search` in `api/index.rs`, and it is right).
        // The daemon runs an index lap as it starts (spots plus
        // maintenance, 3.8 s of work in the failing log below), so on a
        // loaded box that one search can meet a busy pool - and a loop
        // that then polled for the record of a search it had already
        // spent could never succeed, whatever its bound. Re-issuing
        // makes this bound measure how long the index stays busy,
        // which is a thing that ends, rather than wait on an event
        // that was lost. `note_search` merges by query, so repeating
        // it costs one bucket's counters and no extra row.
        //
        // Measured 2 Sep 2026 on a 32-core mac dev box at load
        // average 20-34, with six copies of this test running against
        // each other: 3 hard failures in 30 runs before this change,
        // every one of them "the search log never recorded zzcontrol:
        // []" at 12.9-14.1 s with an EMPTY table - which is the
        // signature of the lost search, not of a slow one. That is the
        // TRY 2 FAIL of run 1 in
        // research/DAEMON-SUITE-FLAKES-2026-09-02.md.
        let record = |q: &str| {
            let mut answer = String::new();
            for _ in 0..40 {
                answer = http(
                    port,
                    &format!("/api?mode=index_search&q={q}&output=json"),
                    None,
                );
                if recorded(port).iter().any(|r| r == q) {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
            // The last answer goes in the message: a busy verdict here
            // means the index never freed up inside the bound, and a
            // successful one means the flush task is the subject. The
            // failure this replaced printed neither, and cost a
            // rebuild to tell the two apart.
            panic!(
                "the search log never recorded {q}: {:?} - last search answered {answer}",
                recorded(port)
            );
        };
        let clear = || {
            let r = http(port, "/api?mode=search_log_clear&output=json", None);
            serde_json::from_str::<serde_json::Value>(&r)
                .unwrap_or_else(|e| panic!("bad JSON from search_log_clear: {e}\n{r}"))
        };

        // Control: an uncontended index takes the delete. Without this
        // the busy assertion below could pass on a daemon whose clear
        // never worked at all.
        record("zzcontrol");
        assert_eq!(clear()["status"], true);
        assert!(recorded(port).is_empty(), "the control clear left rows");

        record("zzresidue");
        let holder = std::thread::spawn(move || {
            http(
                port,
                "/api?mode=debug_hold_index&value=12&output=json",
                None,
            )
        });
        std::thread::sleep(std::time::Duration::from_millis(500));

        // The button. Bounded, refused, and the rows are still there.
        let t = std::time::Instant::now();
        let j = clear();
        let waited = t.elapsed();
        assert!(
            waited < std::time::Duration::from_secs(11),
            "the clear parked {}ms behind the held index mutex",
            waited.as_millis()
        );
        // ...and it really did WAIT. A `try_` comes back instantly,
        // which is the trade this bound exists to refuse.
        assert!(
            waited >= std::time::Duration::from_secs(4),
            "the clear gave up after {}ms - the WAIT is what keeps the edit",
            waited.as_millis()
        );
        assert_eq!(j["status"], false, "a busy index must not report a clear");
        assert!(
            j["error"].as_str().unwrap_or("").contains("busy"),
            "the busy reason has to reach the toast: {j}"
        );
        assert_eq!(j["busy"], true, "a refused clear says so in a field: {j}");
        assert!(
            recorded(port).iter().any(|r| r == "zzresidue"),
            "a refused clear must leave the table alone"
        );

        // The switch, under the same hold. It lands - it is a settings
        // write, and it never depended on the index - and the clear it
        // owes is latched rather than dropped.
        let sw = http(
            port,
            "/api?mode=config&name=index_search_log&value=0&output=json",
            None,
        );
        let sv: serde_json::Value =
            serde_json::from_str(&sw).unwrap_or_else(|e| panic!("bad JSON from config: {e}\n{sw}"));
        assert_eq!(
            sv["status"], true,
            "the switch itself must still land: {sv}"
        );
        assert!(
            recorded(port).iter().any(|r| r == "zzresidue"),
            "the busy index cannot have cleared anything yet"
        );

        let held = holder.join().expect("holder thread");
        assert!(
            held.contains("\"held\":true"),
            "the hook held the lock: {held}"
        );

        // ...and once the mutex is free the tick runs the clear the
        // switch could not. THIS is the assertion the section is about:
        // with a plain `try_`, or with the busy verdict simply reported
        // to a caller that has nowhere to put it, the row below is
        // still on disk with the switch showing off.
        for _ in 0..60 {
            if recorded(port).is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        assert!(
            recorded(port).is_empty(),
            "the switch's clear was lost to the busy index: {:?}",
            recorded(port)
        );
        // The switch really is off, so "empty" is not just a table
        // nobody has written to since.
        let m = http(port, "/api?mode=search_misses&output=json", None);
        let mv: serde_json::Value = serde_json::from_str(&m).unwrap();
        assert_eq!(mv["enabled"], false, "{mv}");
    })
    .await
    .unwrap();
}
