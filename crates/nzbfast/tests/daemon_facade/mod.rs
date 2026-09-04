//! The two client facades - the SABnzbd-compatible API and the NZBGet
//! JSON-RPC one - as a real client sees them: the shape of every answer,
//! and the verbs a remote app and an *arr actually send.
//!
//! A sibling-dir child of daemon.rs (the daemon_authkey pattern) so the
//! parent stays inside its size-gate baseline. Declared from daemon.rs,
//! so these still run in that binary against those fixtures; harness via
//! `super::*`.
//!
//! One subject, and four of the six legs state it in the same words:
//! the daemon carries TWO client vocabularies over one queue, they had
//! drifted apart, and which client type the user happened to configure
//! decided whether a documented verb worked at all - the priority write
//! that releases a duplicate hold, `change_cat`, the idle edge a
//! lifecycle hook listens for. The other two pin the payload SHAPE each
//! side's parser expects, key by key and with the type that side sends,
//! because a missing key and a wrongly-typed one fail a strongly-typed
//! client identically. They belong beside each other rather than
//! interleaved with the download legs they grew up among.

use super::*;

/// M14a/b: the extended SABnzbd facade - two-tier keys, priorities
/// (incl. Force-runs-while-paused and add-paused), park-to-history,
/// retry, failed_only, pagination, del_files.
#[tokio::test(flavor = "multi_thread")]
async fn sab_facade_priorities_and_retry() {
    let dir = std::env::temp_dir().join(format!("nzbfast-facade-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(200_000, 5);
    let mut articles = HashMap::new();
    let segs = make_file_articles("good.bin", &data, 40_000, "gd", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let nzb_for = |name: &str, segs: &[(String, u64, u32)]| {
        let mut xml = String::from(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
        );
        xml.push_str(&format!(
            "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        ));
        for (id, bytes, num) in segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n</nzb>\n");
        xml
    };
    let good_xml = nzb_for("good.bin", &segs);
    // Articles that don't exist on the server → the job must fail and park.
    let ghost_segs: Vec<(String, u64, u32)> = (1..=3)
        .map(|n| (format!("ghost{n}@x"), 40_000, n))
        .collect();
    let bad_xml = nzb_for("bad.bin", &ghost_segs);

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
            .arg("--nzbkey")
            .arg("addonly")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("2");
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        let upload = |xml: &str, extra: &str| -> String {
            let boundary = "----facadeb";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"j.nzb\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let r = http(
                port,
                &format!("/api?mode=addfile&output=json{extra}"),
                Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
            );
            assert!(r.contains("\"status\":true"), "{r}");
            r.split("SABnzbd_nzo_").nth(1).unwrap().split('"').next()
                .map(|s| format!("SABnzbd_nzo_{s}")).unwrap()
        };
        let poll_history = |pred: &dyn Fn(&str) -> bool, what: &str| {
            for _ in 0..150 {
                let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
                if pred(&h) {
                    return h;
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            panic!("timed out waiting for {what}");
        };

        // Two-tier keys: the NZB key may add but not read.
        let r = http(port, "/api?mode=queue&apikey=addonly&output=json", None);
        assert!(r.contains("API Key Incorrect"), "{r}");
        let r = http(port, "/api?mode=get_cats&apikey=sekrit&output=json", None);
        assert!(r.contains("\"tv\""), "{r}");

        // Pause the whole queue, then add: bad (normal prio, via NZB key),
        // good (Force via priority change) - Force must run while paused.
        http(port, "/api?mode=pause&apikey=sekrit&output=json", None);
        let bad_id = upload(&bad_xml, "&apikey=addonly");
        let good_id = upload(&good_xml, "&apikey=sekrit&cat=tv");
        let r = http(
            port,
            &format!("/api?mode=queue&name=priority&value={good_id}&value2=2&apikey=sekrit&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let h = poll_history(&|h: &str| h.contains("Completed"), "force job while paused");
        assert!(history_has(&h, &good_id), "{h}");
        // The bad job must still be queued: the queue is paused.
        let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
        assert!(queue_has(&q, &bad_id), "{q}");
        assert!(q.contains("\"priority\":\"Normal\""), "{q}");

        // Resume: the bad job runs, fails, parks in history.
        http(port, "/api?mode=resume&apikey=sekrit&output=json", None);
        let h = poll_history(&|h: &str| h.contains("Failed"), "bad job to fail");
        assert!(history_has(&h, &bad_id), "{h}");

        // failed_only filters the completed one out.
        let h = http(port, "/api?mode=history&failed_only=1&apikey=sekrit&output=json", None);
        assert!(history_has(&h, &bad_id) && !history_has(&h, &good_id), "{h}");
        // Pagination: limit=1 returns one slot but reports both.
        let h = http(port, "/api?mode=history&start=0&limit=1&apikey=sekrit&output=json", None);
        assert!(h.contains("\"noofslots\":2"), "{h}");
        assert_eq!(h.matches("nzo_id").count(), 1, "{h}");

        // Retry sends it back through the queue; it fails again and the
        // history entry now records the attempt.
        let r = http(
            port,
            &format!("/api?mode=retry&value={bad_id}&apikey=sekrit&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        // The COUNT is `retries`; `retry` is SABnzbd's boolean "this one
        // can be asked for again" (issue #34).
        let h = poll_history(
            &|h: &str| h.contains("\"retries\":1") && h.contains("Failed"),
            "retried job to fail again",
        );
        assert!(history_has(&h, &bad_id), "{h}");

        // add-paused (priority -2) holds the job until per-job resume.
        let paused_id = upload(&good_xml, "&apikey=sekrit&priority=-2");
        std::thread::sleep(std::time::Duration::from_millis(600));
        let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
        assert!(q.contains("\"Paused\""), "{q}");
        http(
            port,
            &format!("/api?mode=queue&name=resume&value={paused_id}&apikey=sekrit&output=json"),
            None,
        );
        poll_history(&|h: &str| h.matches("Completed").count() >= 2, "paused job after resume");

        // History delete with del_files removes the storage dir.
        let out_dir = dir2.join("complete/tv/j");
        assert!(out_dir.exists(), "expected {}", out_dir.display());
        http(
            port,
            &format!("/api?mode=history&name=delete&value={good_id}&del_files=1&apikey=sekrit&output=json"),
            None,
        );
        assert!(!out_dir.exists(), "del_files should remove {}", out_dir.display());
    })
    .await
    .unwrap();
}

/// Issue #34: the SAB facade's queue and history bodies carry the whole
/// shape real SABnzbd sends, not just the keys our own dashboard reads.
///
/// The reporter's phone remote (NZB360) sat at "Connecting" for both
/// Queue and History on v1.0.21 while `mode=addfile` - which reads
/// neither body - worked throughout, so auth and the add route were
/// never the problem. The precedent is SAB's own: sabnzbd/sabnzbd#872,
/// where SAB 2.0 trimmed these same header fields, NZB360's history
/// stopped working, and the fix was to put `version` back. That issue
/// also carries a debug log of NZB360's actual traffic, which is the
/// exact pair replayed at the bottom of this test.
///
/// Every key is checked with the TYPE SAB sends, because a missing key
/// and a wrongly-typed one fail a strongly-typed client identically -
/// `retry` went out as our try COUNT under the name SAB uses for a
/// boolean, which is a parse error before it is a wrong number.
///
/// Field names and formats come from sabnzbd/api.py (`build_header`,
/// `build_queue`, `_api_history_default`) and sabnzbd/database.py
/// (`unpack_history_info`), read at the source rather than from the
/// wiki - §105.4's own rule for this class.
#[tokio::test(flavor = "multi_thread")]
async fn sab_facade_carries_sabnzbds_own_queue_and_history_shape() {
    let dir = std::env::temp_dir().join(format!("nzbfast-sabshape-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(200_000, 9);
    let mut articles = HashMap::new();
    let segs = make_file_articles("shape.bin", &data, 40_000, "sh", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    xml.push_str(&format!(
        "  <file poster=\"x\" date=\"0\" subject=\"&quot;shape.bin&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        segs.len()
    ));
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
            .arg("--connections")
            .arg("2");
        c
    })
    .await;
    let port = d.port;
    // The one configured server's host, so the `servers` census below
    // asserts against what was WRITTEN into the config rather than a
    // literal that a differently-bound mock would falsify.
    let srv_host = srv.addr.ip().to_string();

    tokio::task::spawn_blocking(move || {
        use serde_json::Value;

        // What SAB's own JSON says a key is. `Str` and friends are what
        // a client's declared field type would be; `Null` is a key SAB
        // sends as null with the feature off, and a client that reads
        // it must still FIND it.
        #[derive(Clone, Copy, PartialEq, Debug)]
        enum Ty {
            Str,
            Num,
            Bool,
            Arr,
            Null,
        }
        let check = |obj: &Value, where_: &str, want: &[(&str, Ty)]| {
            let m = obj
                .as_object()
                .unwrap_or_else(|| panic!("{where_} is not an object: {obj}"));
            for (key, ty) in want {
                let v = m
                    .get(*key)
                    .unwrap_or_else(|| panic!("{where_}: SAB sends `{key}` and we do not: {obj}"));
                let ok = match ty {
                    Ty::Str => v.is_string(),
                    Ty::Num => v.is_number(),
                    Ty::Bool => v.is_boolean(),
                    Ty::Arr => v.is_array(),
                    Ty::Null => v.is_null(),
                };
                assert!(ok, "{where_}: `{key}` should be {ty:?}, got {v}: {obj}");
            }
        };
        let get = |q: &str| -> Value {
            let body = http(port, &format!("/api?{q}"), None);
            serde_json::from_str(&body).unwrap_or_else(|e| panic!("not JSON ({e}): {body}"))
        };

        // A slot to describe: pause first so the job stays in the queue
        // long enough to be read.
        http(port, "/api?mode=pause&output=json", None);
        let boundary = "----shapeb";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"shape.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let r = http(
            port,
            "/api?mode=addfile&output=json&cat=tv",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );
        assert!(r.contains("\"status\":true"), "{r}");

        // --- the queue body -------------------------------------------
        let q = get("mode=queue&output=json");
        let queue = &q["queue"];
        check(
            queue,
            "queue",
            &[
                // build_header()
                ("version", Ty::Str),
                ("paused", Ty::Bool),
                ("paused_all", Ty::Bool),
                ("pause_int", Ty::Str),
                ("diskspace1", Ty::Str),
                ("diskspace2", Ty::Str),
                ("diskspace1_norm", Ty::Str),
                ("diskspace2_norm", Ty::Str),
                ("diskspacetotal1", Ty::Str),
                ("diskspacetotal2", Ty::Str),
                ("speedlimit", Ty::Str),
                ("speedlimit_abs", Ty::Str),
                ("have_warnings", Ty::Str),
                ("finishaction", Ty::Null),
                ("quota", Ty::Str),
                ("have_quota", Ty::Bool),
                ("left_quota", Ty::Str),
                ("cache_art", Ty::Str),
                ("cache_size", Ty::Str),
                // build_queue()
                ("kbpersec", Ty::Str),
                ("speed", Ty::Str),
                ("mb", Ty::Str),
                ("mbleft", Ty::Str),
                ("size", Ty::Str),
                ("sizeleft", Ty::Str),
                ("noofslots", Ty::Num),
                ("noofslots_total", Ty::Num),
                ("start", Ty::Num),
                ("limit", Ty::Num),
                ("finish", Ty::Num),
                ("status", Ty::Str),
                ("timeleft", Ty::Str),
                ("slots", Ty::Arr),
            ],
        );
        assert_eq!(queue["version"], "4.5.0", "{q}");
        let slots = queue["slots"].as_array().expect("slots array");
        assert_eq!(slots.len(), 1, "one paused job should be listed: {q}");
        check(
            &slots[0],
            "queue slot",
            &[
                ("index", Ty::Num),
                ("nzo_id", Ty::Str),
                ("unpackopts", Ty::Str),
                ("priority", Ty::Str),
                ("script", Ty::Str),
                ("filename", Ty::Str),
                ("labels", Ty::Arr),
                ("password", Ty::Str),
                ("cat", Ty::Str),
                ("mb", Ty::Str),
                ("mbleft", Ty::Str),
                ("size", Ty::Str),
                ("sizeleft", Ty::Str),
                ("percentage", Ty::Str),
                ("mbmissing", Ty::Str),
                ("direct_unpack", Ty::Null),
                ("status", Ty::Str),
                ("avg_age", Ty::Str),
                ("time_added", Ty::Num),
                ("timeleft", Ty::Str),
            ],
        );
        // The password itself never leaves the daemon (M24), so SAB's
        // slot field is present and empty rather than absent.
        assert_eq!(slots[0]["password"], "", "{q}");

        // --- and the VALUES, which a key-and-type census cannot see ---
        //
        // Everything above this line is names and types, and that half
        // was complete: measured 31 Aug 2026 against SAB 5.1.2, neither
        // body nor either slot has a key SAB sends and we do not. Every
        // defect the audit that day found was a WRONG STRING in a key
        // that was present and correctly typed - `"2089.6 G"` for a 2 TB
        // disk, `"5"` for a five-minute pause, `Duplicate` in a field
        // whose vocabulary is five words and does not include it. So
        // these arms check what the strings SAY.
        //
        // The exact formats live in `sabcompat/units.rs`, pinned
        // against a transliteration of SAB's own `to_units`; what is
        // asserted HERE is the part that needs a live payload - that
        // the wire really carries those shapes, on a real row, through
        // the real handler.

        // SAB's INTERFACE_PRIORITIES, and nothing outside it. SAB keeps
        // a STATE out of this field by construction (`set_priority`
        // applies the state, then `set_stateless_priority`), which is
        // why five words is the whole set a client can be written
        // against.
        const SAB_PRIORITIES: [&str; 5] = ["Force", "Repair", "High", "Normal", "Low"];
        let prio = slots[0]["priority"].as_str().unwrap_or_default();
        assert!(
            SAB_PRIORITIES.contains(&prio),
            "queue slot priority {prio:?} is not one of SAB's \
             INTERFACE_PRIORITIES words {SAB_PRIORITIES:?}: {q}"
        );

        // SAB's `to_units(x, "B")`: a number, a space, an optional tier
        // letter, then B. The tier letter must be one SAB has - the
        // ladder stopped at G here until 31 Aug 2026, so a terabyte
        // queue published "1024.0 GB" against SAB's "1.0 TB".
        for (where_, v) in [
            ("queue size", &queue["size"]),
            ("queue sizeleft", &queue["sizeleft"]),
            ("slot size", &slots[0]["size"]),
            ("slot sizeleft", &slots[0]["sizeleft"]),
            ("quota", &queue["quota"]),
            ("left_quota", &queue["left_quota"]),
            ("cache_size", &queue["cache_size"]),
        ] {
            let s = v.as_str().unwrap_or_default();
            let tail = s.rsplit_once(' ').map(|(_, t)| t).unwrap_or("");
            assert!(
                ["B", "KB", "MB", "GB", "TB", "PB"].contains(&tail),
                "{where_} {s:?} does not end in a SAB unit: {q}"
            );
        }

        // ...and the BARE form carries no unit at all below 1024, which
        // is SAB's `if n == 0 and postfix == ""` arm. This sent a
        // trailing space, so an idle daemon's `speed` was `"0 "` where
        // SAB says `"0"` - and a client handing that to a strict
        // numeric parse (Kotlin's `String.toInt()` refuses trailing
        // whitespace) sees the difference.
        for (where_, v) in [
            ("speed", &queue["speed"]),
            ("diskspace1_norm", &queue["diskspace1_norm"]),
        ] {
            let s = v.as_str().unwrap_or_default();
            assert_eq!(s, s.trim_end(), "{where_} {s:?} has a trailing space: {q}");
        }

        // SAB's `pause_int` is "minutes:seconds", or a bare "0" when
        // nothing is scheduled. Unpaused here, so it is the "0".
        assert_eq!(queue["pause_int"], "0", "{q}");
        // SAB's `"%.2f" % (bps / KIBI)` - two decimals, always.
        let kb = queue["kbpersec"].as_str().unwrap_or_default();
        assert!(
            kb.rsplit_once('.').is_some_and(|(_, d)| d.len() == 2),
            "kbpersec {kb:?} should carry SAB's two decimals: {q}"
        );

        // --- mode=status and mode=fullstatus --------------------------
        //
        // SAB's `_api_table` reaches `_api_fullstatus` under BOTH names,
        // so the two bodies are one object there and a client is
        // entitled to read either. Here they were two arms with two
        // different key sets - `fullstatus` had no `warnings`,
        // `have_warnings`, `pause_int`, `cache_art`, `cache_size`,
        // `finishaction`, `servers` or `diskspace1_norm`, and `status`
        // had no `diskspace2` or `speedlimit` - so which absent-key
        // crash a statically-typed client met depended only on which
        // spelling it happened to send. NZB Donkey sends `status` and
        // NZB Unity sends `fullstatus` (`serve/http.rs`), so both have
        // real callers. Held to the same table as the queue body above,
        // because both come from SAB's `build_header`.
        let want_status: &[(&str, Ty)] = &[
            ("version", Ty::Str),
            ("uptime", Ty::Str),
            ("color_scheme", Ty::Str),
            ("paused", Ty::Bool),
            ("paused_all", Ty::Bool),
            ("pause_int", Ty::Str),
            ("diskspace1", Ty::Str),
            ("diskspace2", Ty::Str),
            ("diskspace1_norm", Ty::Str),
            ("diskspace2_norm", Ty::Str),
            ("diskspacetotal1", Ty::Str),
            ("diskspacetotal2", Ty::Str),
            ("speedlimit", Ty::Str),
            ("speedlimit_abs", Ty::Str),
            ("have_warnings", Ty::Str),
            ("warnings", Ty::Arr),
            ("finishaction", Ty::Null),
            ("quota", Ty::Str),
            ("have_quota", Ty::Bool),
            ("left_quota", Ty::Str),
            ("cache_art", Ty::Str),
            ("cache_size", Ty::Str),
            ("servers", Ty::Arr),
            ("complete_dir", Ty::Str),
            ("completedir", Ty::Str),
        ];
        let st = get("mode=status&output=json");
        let fs = get("mode=fullstatus&output=json");
        check(&st["status"], "status", want_status);
        check(&fs["status"], "fullstatus", want_status);
        // ONE DAEMON, ONE DISK, ONE STRING. Read-only sweep finding 12
        // (31 Aug 2026): the queue header runs the raw byte count through
        // `sab_units` - GH #69's own fix - while both status arms still
        // wrote `format!("{free:.1} G")` over a GIGABYTE figure. The two
        // disagree for every non-zero disk and by a whole unit tier past
        // a terabyte, so a client that reads `mode=status` rather than
        // the queue header saw a different number for the same
        // filesystem. Held as an equality rather than to a literal
        // because the runner's free space is not ours to choose; the
        // shape census above already pins the unit vocabulary.
        for (name, body) in [("status", &st), ("fullstatus", &fs)] {
            for key in ["diskspace1_norm", "diskspace2_norm"] {
                assert_eq!(
                    body["status"][key], queue[key],
                    "{name}.{key} and the queue header describe the same disk \
                     and must render it the same way: {body}"
                );
            }
        }
        // Every CONFIGURED server, one object per row, fifteen fields
        // (`build_status`, identical in 4.5.0, 5.1.2 and develop - only
        // the internal `connected`/`ready` predicate moved). Ours was a
        // literal `[]` until 31 Aug 2026 on an install with servers
        // configured and downloading, so a remote app's Servers pane was
        // permanently blank: GH #69 finding 3's defect (a configured
        // server missing from a payload about servers) one mode over.
        //
        // ASSERTED WITH NO RUN IN FLIGHT, which is the point of putting
        // it here rather than after the resume below: the daemon is
        // PAUSED with one job queued, so `hub.pool_live` - the live
        // fleet the counters come from - does not exist. A list built
        // from that handle answers `[]` again the moment nothing is
        // downloading, which is finding 3's mistake made a second time,
        // and no shape census would ever catch it. The row below has to
        // be here, with its live half zeroed, off the CONFIG.
        let servers = st["status"]["servers"]
            .as_array()
            .expect("status.servers is an array");
        assert_eq!(
            servers.len(),
            1,
            "one server is configured and it must be listed even with nothing downloading: {st}"
        );
        check(
            &servers[0],
            "status.servers[0]",
            &[
                ("servername", Ty::Str),
                ("serveractive", Ty::Bool),
                ("serveractiveconn", Ty::Num),
                ("servertotalconn", Ty::Num),
                ("serverconnections", Ty::Arr),
                ("serverssl", Ty::Bool),
                ("serversslinfo", Ty::Str),
                // Null in SAB too until a connection exists and the
                // address is resolved, so a client already handles it;
                // an invented address would be worse than the null.
                ("serveripaddress", Ty::Null),
                ("servercanonname", Ty::Null),
                ("serverwarning", Ty::Str),
                ("servererror", Ty::Str),
                ("serverpriority", Ty::Num),
                ("serveroptional", Ty::Bool),
                // A STRING through SAB's `to_units`, not a number -
                // the same mistake `get_files.bytes` was crashing
                // clients with.
                ("serverbps", Ty::Str),
            ],
        );
        assert_eq!(
            servers[0]["servername"], srv_host,
            "the row must name the CONFIGURED server: {st}"
        );
        assert_eq!(
            servers[0]["serveractiveconn"], 0,
            "nothing is on the wire, so the live half reads zero rather than being absent: {st}"
        );
        // `fullstatus` is the same body, so it carries the same rows -
        // the key-set assertion below cannot see inside the array.
        assert_eq!(
            fs["status"]["servers"], st["status"]["servers"],
            "SAB answers both mode names from one function\nstatus: {st}\nfullstatus: {fs}"
        );

        // And the two carry the SAME key set, not merely both supersets
        // of the table above - a table is a floor and this is the
        // property that was actually broken. `speedlimit_abs` is the one
        // field whose VALUE the two still spell differently, and that is
        // a deliberate deviation with a named client behind it (see the
        // `fullstatus` arm); the KEY is present in both.
        let keys = |v: &Value| {
            let mut k: Vec<String> = v["status"]
                .as_object()
                .expect("status object")
                .keys()
                .cloned()
                .collect();
            k.sort();
            k
        };
        assert_eq!(
            keys(&st),
            keys(&fs),
            "SAB answers both mode names from one function; these must not drift apart\nstatus: {st}\nfullstatus: {fs}"
        );

        // --- the history body -----------------------------------------
        http(port, "/api?mode=resume&output=json", None);
        let h = (0..150)
            .find_map(|_| {
                let h = get("mode=history&output=json");
                h["history"]["slots"]
                    .as_array()
                    .filter(|s| s.first().is_some_and(|r| r["status"] == "Completed"))
                    .is_some()
                    .then_some(h)
                    .or_else(|| {
                        std::thread::sleep(std::time::Duration::from_millis(200));
                        None
                    })
            })
            .expect("timed out waiting for the job to complete");
        let hist = &h["history"];
        check(
            hist,
            "history",
            &[
                ("version", Ty::Str),
                ("total_size", Ty::Str),
                ("month_size", Ty::Str),
                ("week_size", Ty::Str),
                ("day_size", Ty::Str),
                ("slots", Ty::Arr),
                ("ppslots", Ty::Num),
                ("noofslots", Ty::Num),
                ("last_history_update", Ty::Num),
            ],
        );
        assert_eq!(hist["version"], "4.5.0", "{h}");
        check(
            &hist["slots"][0],
            "history slot",
            &[
                ("completed", Ty::Num),
                ("name", Ty::Str),
                ("nzb_name", Ty::Str),
                ("category", Ty::Str),
                ("pp", Ty::Str),
                ("script", Ty::Str),
                ("report", Ty::Str),
                ("url", Ty::Str),
                ("status", Ty::Str),
                ("nzo_id", Ty::Str),
                ("storage", Ty::Str),
                ("path", Ty::Str),
                ("script_line", Ty::Str),
                ("download_time", Ty::Num),
                ("postproc_time", Ty::Num),
                ("stage_log", Ty::Arr),
                ("downloaded", Ty::Num),
                ("completeness", Ty::Num),
                ("fail_message", Ty::Str),
                ("url_info", Ty::Str),
                ("bytes", Ty::Num),
                ("size", Ty::Str),
                ("meta", Ty::Null),
                ("series", Ty::Str),
                ("duplicate_key", Ty::Str),
                ("md5sum", Ty::Str),
                ("password", Ty::Str),
                ("action_line", Ty::Str),
                ("loaded", Ty::Bool),
                ("retry", Ty::Bool),
                ("archive", Ty::Bool),
                ("time_added", Ty::Num),
                // Ours, and the reason `retry` could change type: the
                // attempt count keeps its meaning under its own name.
                ("retries", Ty::Num),
            ],
        );
        // A Completed job cannot be retried, which is what SAB's boolean
        // says here.
        assert_eq!(hist["slots"][0]["retry"], false, "{h}");
        // SAB's own suffix convention (to_units + "B"), not a bare MB,
        // and a tier letter from SAB's own ladder rather than a prefix
        // of it.
        let size = hist["slots"][0]["size"].as_str().unwrap_or_default();
        let tail = size.rsplit_once(' ').map(|(_, t)| t).unwrap_or("");
        assert!(
            ["B", "KB", "MB", "GB", "TB", "PB"].contains(&tail),
            "history size should be SAB-shaped: {size}"
        );
        // The four history totals take the BARE form, which carries no
        // unit at all below 1024 - so no trailing space. They read
        // `"0 "` until 31 Aug 2026.
        for k in ["total_size", "month_size", "week_size", "day_size"] {
            let v = hist[k].as_str().unwrap_or_default();
            assert_eq!(v, v.trim_end(), "history {k} {v:?} has a trailing space: {h}");
        }

        // --- SAB's `cat` spelling, on both modes ----------------------
        //
        // SAB reads `kwargs.get("cat") or kwargs.get("category")` in
        // `_api_queue_default` AND `_api_history_default`, in 4.5.0 and
        // 5.1.2 alike, so a client may send either. Only `category` was
        // read here until 31 Aug 2026 - and an unread filter does not
        // fail, it returns EVERYTHING, so a client asking for one
        // category was quietly handed the whole list. Both spellings,
        // and a category that matches nothing, so a filter that has
        // stopped filtering fails here rather than reading as a
        // generous match.
        //
        // The job added above carries `cat=tv`; it has completed by
        // now, so the queue arm is exercised against the history one's
        // sibling parameter on an empty queue - the assertion that
        // matters for it is the NEGATIVE, which an ignored filter
        // cannot satisfy.
        for k in ["cat", "category"] {
            let h = get(&format!("mode=history&output=json&{k}=tv"));
            assert_eq!(
                h["history"]["slots"].as_array().map(Vec::len),
                Some(1),
                "history {k}=tv should match the one tv job: {h}"
            );
            let h = get(&format!("mode=history&output=json&{k}=nosuchcategory"));
            assert_eq!(
                h["history"]["slots"].as_array().map(Vec::len),
                Some(0),
                "history {k}= a category nothing carries must match nothing: {h}"
            );
            let q = get(&format!("mode=queue&output=json&{k}=nosuchcategory"));
            assert_eq!(
                q["queue"]["noofslots"], 0,
                "queue {k}= a category nothing carries must match nothing: {q}"
            );
        }

        // --- NZB360's literal traffic ---------------------------------
        // From the SAB debug log in sabnzbd/sabnzbd#872: `output` arrives
        // TWICE and the queue call carries `start` with no `limit`.
        let q = get("output=json&output=json&mode=queue&start=0");
        assert!(q["queue"]["slots"].is_array(), "{q}");
        let h = get("output=json&output=json&limit=20&mode=history&start=0");
        assert_eq!(h["history"]["slots"].as_array().map(Vec::len), Some(1), "{h}");

        // --- casing, settled at each dialect's source -----------------
        // SAB reads `mode` and looks it up with no normalisation
        // (sabnzbd/api.py: `mode = kwargs.get("mode", "")`, then an exact
        // `_api_table` lookup), so an uppercase mode is NOT the same
        // call. §105.4 left this open rather than lowercasing on a
        // hunch; matching SAB means leaving it case-sensitive, and this
        // pins that so nobody "fixes" it later.
        let up = get("mode=QUEUE&output=json");
        assert!(
            up.get("queue").is_none(),
            "an uppercase mode must not be treated as the lowercase one: {up}"
        );
        // NZBGet is the opposite, and its source says so: every method
        // name in XmlRpcProcessor::CreateCommand is compared with
        // strcasecmp. So the JSON-RPC facade lowercases first, and a
        // mixed-case method IS the call - the other half of §105.4's
        // "the NZBGet dialect's equivalents".
        let mixed = http(
            port,
            "/jsonrpc",
            Some((
                "application/json",
                b"{\"method\":\"ListGroups\",\"params\":[],\"id\":7}".as_slice(),
            )),
        );
        let mixed: Value = serde_json::from_str(&mixed).unwrap_or(Value::Null);
        assert!(
            mixed.get("result").is_some(),
            "NZBGet matches methods case-insensitively (strcasecmp): {mixed}"
        );
    })
    .await
    .unwrap();
}

/// M21: the NZBGet JSON-RPC facade - a remote-control app's whole
/// session: version, append (base64 NZB), listgroups, pause/resume via
/// status, editqueue GroupDelete, rate.
#[tokio::test(flavor = "multi_thread")]
async fn nzbget_jsonrpc_facade_cycle() {
    let dir = std::env::temp_dir().join(format!("nzbfast-jsonrpc-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(200_000, 5);
    let mut articles = HashMap::new();
    let segs = make_file_articles("show.bin", &data, 40_000, "jr", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;show.bin&quot; yEnc (1/6)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    // Simple std base64 encoder for the append payload.
    fn b64(data: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for c in data.chunks(3) {
            let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(A[(n >> 18) as usize & 63] as char);
            out.push(A[(n >> 12) as usize & 63] as char);
            out.push(if c.len() > 1 {
                A[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if c.len() > 2 {
                A[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    tokio::task::spawn_blocking(move || {
        let rpc = |method: &str, params: String| -> String {
            let body = format!("{{\"method\":\"{method}\",\"params\":{params},\"id\":7}}");
            http(
                port,
                "/jsonrpc",
                Some(("application/json", body.as_bytes())),
            )
        };
        // version
        let v = rpc("version", "[]".into());
        assert!(v.contains("21.0"), "{v}");
        // append (v13 param order), paused via priority 0 - it will start
        // downloading from the mock; that's fine.
        let ap = rpc(
            "append",
            format!(
                "[\"show.nzb\",\"{}\",\"tv\",0,false,false,\"\",0,\"SCORE\"]",
                b64(xml.as_bytes())
            ),
        );
        let nzbid: i64 = serde_json::from_str::<serde_json::Value>(&ap)
            .ok()
            .and_then(|v| v.get("result").and_then(|r| r.as_i64()))
            .unwrap_or(0);
        assert!(nzbid > 0, "append failed: {ap}");
        // listgroups sees it (or it may already be in history if tiny+fast;
        // poll both).
        let mut seen = false;
        for _ in 0..50 {
            let lg = rpc("listgroups", "[]".into());
            let hi = rpc("history", "[]".into());
            if lg.contains("show.nzb")
                || lg.contains("\"NZBID\"") && lg.contains(&nzbid.to_string())
                || hi.contains(&format!("\"NZBID\":{nzbid}"))
            {
                seen = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(seen, "job never visible via listgroups/history");
        // pause / status / resume
        rpc("pausedownload", "[]".into());
        let st = rpc("status", "[]".into());
        assert!(st.contains("\"DownloadPaused\":true"), "{st}");
        rpc("resumedownload", "[]".into());
        let st = rpc("status", "[]".into());
        assert!(st.contains("\"DownloadPaused\":false"), "{st}");
        // rate limit round-trip
        rpc("rate", "[2500]".into());
        let st = rpc("status", "[]".into());
        assert!(
            st.contains(&format!("\"DownloadLimit\":{}", 2500 * 1024)),
            "{st}"
        );
        rpc("rate", "[0]".into());
        // The history hide op, over the real HTTP surface, once the
        // download has landed there. `HistoryDelete` is NZBGet's HIDE
        // (the erase is `HistoryFinalDelete`), which is the verb Sonarr
        // and Radarr actually send - so this is the *arr round trip.
        for _ in 0..100 {
            let hi = rpc("history", "[]".into());
            if hi.contains(&format!("\"NZBID\":{nzbid}")) {
                let del = rpc("editqueue", format!("[\"HistoryDelete\",\"\",[{nzbid}]]"));
                assert!(del.contains("true"), "{del}");
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        panic!("download never completed into history");
    })
    .await
    .unwrap();
}

/// The NZBGet JSON-RPC facade announces the idle edge (Codex sweep
/// 14 Aug M4). GroupPause on the sole runnable job and a non-active
/// GroupDelete each idle the queue with no park, and the REST arms have
/// said `queue.idle` for both since the 10 Aug sweep - this facade
/// answered true and said nothing, so which client type the user
/// configured decided whether lifecycle hooks heard about it. Global
/// pause keeps the jobs Queued (and Queued-unpaused is NOT idle), so
/// each edge here is exactly the job-level transition under test.
#[tokio::test(flavor = "multi_thread")]
async fn jsonrpc_pause_and_delete_announce_the_idle_edge() {
    let dir = std::env::temp_dir().join(format!("nzbfast-jridle-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(80_000, 3);
    let mut articles = HashMap::new();
    let segs = make_file_articles("idle.bin", &data, 40_000, "jri", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;
    let nzb_for = |name: &str| {
        let mut xml = format!(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        );
        for (id, bytes, num) in &segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n</nzb>\n");
        xml
    };
    let xml_a = nzb_for("Alpha.Idle.Test");
    let xml_b = nzb_for("Beta.Idle.Test");

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
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        fn b64(data: &[u8]) -> String {
            const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut out = String::new();
            for c in data.chunks(3) {
                let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
                let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
                out.push(A[(n >> 18) as usize & 63] as char);
                out.push(A[(n >> 12) as usize & 63] as char);
                out.push(if c.len() > 1 {
                    A[(n >> 6) as usize & 63] as char
                } else {
                    '='
                });
                out.push(if c.len() > 2 {
                    A[n as usize & 63] as char
                } else {
                    '='
                });
            }
            out
        }
        let rpc = |method: &str, params: String| -> String {
            let body = format!("{{\"method\":\"{method}\",\"params\":{params},\"id\":9}}");
            http(
                port,
                "/jsonrpc",
                Some(("application/json", body.as_bytes())),
            )
        };
        let append = |name: &str, xml: &str| -> i64 {
            let ap = rpc(
                "append",
                format!(
                    "[\"{name}\",\"{}\",\"\",0,false,false,\"\",0,\"SCORE\"]",
                    b64(xml.as_bytes())
                ),
            );
            let id = serde_json::from_str::<serde_json::Value>(&ap)
                .ok()
                .and_then(|v| v.get("result").and_then(|r| r.as_i64()))
                .unwrap_or(0);
            assert!(id > 0, "append failed: {ap}");
            id
        };
        // Idle events since the cursor, in ring order.
        let idles = |since: u64| -> Vec<u64> {
            let body = http(
                port,
                &format!("/api?mode=dashboard&events={since}&output=json"),
                None,
            );
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            v["events"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|e| e["kind"] == "queue.idle")
                .filter_map(|e| e["seq"].as_u64())
                .collect()
        };
        let wait_idles = |since: u64, want: usize| -> Vec<u64> {
            for _ in 0..50 {
                let got = idles(since);
                if got.len() >= want {
                    return got;
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            panic!("never saw {want} queue.idle event(s) past seq {since}");
        };
        let seq0 = {
            let body = http(port, "/api?mode=dashboard&output=json", None);
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            v["events_seq"].as_u64().expect("events_seq")
        };
        // Global pause first, so the appended jobs stay Queued and
        // unpaused - runnable, hence NOT idle - instead of downloading.
        rpc("pausedownload", "[]".into());

        // Edge 1: GroupPause on the sole runnable job.
        let a = append("alpha-idle.nzb", &xml_a);
        let r = rpc("editqueue", format!("[\"GroupPause\",\"\",[{a}]]"));
        assert!(r.contains("true"), "{r}");
        let after_pause = wait_idles(seq0, 1);
        assert_eq!(
            after_pause.len(),
            1,
            "GroupPause must announce exactly one idle edge: {after_pause:?}"
        );

        // Edge 2: a non-active delete. The add of B re-arms the latch;
        // deleting B (A still paused) idles the queue again.
        let b = append("beta-idle.nzb", &xml_b);
        let r = rpc("editqueue", format!("[\"GroupDelete\",\"\",[{b}]]"));
        assert!(r.contains("true"), "{r}");
        let after_delete = wait_idles(seq0, 2);
        assert_eq!(
            after_delete.len(),
            2,
            "GroupDelete must announce exactly one more idle edge: {after_delete:?}"
        );

        // Still a transition: a paused queue poked again stays silent.
        let r = rpc("editqueue", format!("[\"GroupPause\",\"\",[{a}]]"));
        assert!(r.contains("true"), "{r}");
        std::thread::sleep(std::time::Duration::from_millis(400));
        assert_eq!(idles(seq0).len(), 2, "the latch must keep repeats silent");
    })
    .await
    .unwrap();
}

/// The NZBGet facade answers with NZBGet's own vocabulary.
///
/// Two gaps this pins. Every failure used to report `FAILURE/PAR` with
/// `ParStatus: FAILURE` - one bit, so "needs a password", "the disk
/// filled up" and "the post is missing articles" were indistinguishable
/// to a client, and all three were blamed on a repair that in two of the
/// three cases never ran. And an unimplemented method returned a null
/// RESULT, which on the wire is what "succeeded, nothing to report"
/// looks like, so a client could not tell the two apart.
#[tokio::test(flavor = "multi_thread")]
async fn nzbget_facade_reports_real_statuses_and_real_errors() {
    let dir = std::env::temp_dir().join(format!("nzbfast-nzbgstat-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}",
            free_port()
        ),
    )
    .unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_NO_ENRICH", "1")
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
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        let rpc = |method: &str, params: &str| -> String {
            let body = format!("{{\"method\":\"{method}\",\"params\":{params},\"id\":1}}");
            let mut request = Vec::new();
            write!(
                request,
                "POST /jsonrpc HTTP/1.1\r\nHost: x\r\nConnection: close\r\nAuthorization: Basic eDpzZWtyaXQ=\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            request.extend_from_slice(body.as_bytes());
            String::from_utf8_lossy(&raw(port, &request)).to_string()
        };

        // A method we do not implement is an ERROR, not an empty success.
        let r = rpc("makecoffee", "[]");
        assert!(r.contains("\"error\""), "{r}");
        assert!(r.contains("no such method"), "{r}");
        assert!(!r.contains("\"error\":null"), "unknown method answered as success: {r}");

        // Same for an editqueue command we do not implement - `false`
        // was also the answer for "that job does not exist".
        let r = rpc("editqueue", "[\"GroupSetDupeKey\",\"x\",[1]]");
        assert!(r.contains("unsupported editqueue command"), "{r}");

        // Implemented ones still answer as results, error null.
        let r = rpc("version", "[]");
        assert!(r.contains("\"error\":null"), "{r}");
        let r = rpc("status", "[]");
        assert!(r.contains("\"error\":null"), "{r}");
        // Including the ones that are honest no-ops for us: we have one
        // pause covering the whole pipeline, not a separate post queue.
        let r = rpc("pausepost", "[]");
        assert!(r.contains("\"error\":null"), "{r}");

        // Sonarr rejects a client reporting KeepHistory 0, so the config
        // dump must keep carrying a non-zero one.
        let r = rpc("config", "[]");
        assert!(r.contains("KeepHistory"), "{r}");
        assert!(!r.contains("\"Value\":\"0\""), "KeepHistory went to 0, which Sonarr refuses: {r}");
    })
    .await
    .unwrap();
}

/// The SAB surface a remote app and an *arr actually poll.
///
/// Four gaps, each one a thing a client asks for and used to be told
/// nothing about: `mode=warnings` was a permanent empty list, so "no
/// server configured" was invisible in every app that has a warnings
/// pane; there was no `mode=status` or `mode=get_scripts` at all, which
/// is what the mobile remotes poll rather than `fullstatus`; and
/// `change_cat` existed only on the NZBGet side, so which client type
/// the user picked decided whether recategorizing a queued job worked.
#[tokio::test(flavor = "multi_thread")]
async fn sab_facade_status_warnings_and_change_cat() {
    let dir = std::env::temp_dir().join(format!("nzbfast-sabstat-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    // A config with NO servers: the first-run state, and the one a user
    // wiring up Sonarr is most likely to be sitting in.
    let cfg = dir.join("config.json");
    std::fs::write(&cfg, "{\"servers\":[]}").unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_NO_ENRICH", "1")
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
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // The condition is real and currently stopping all work, so it
        // must reach a client that shows warnings.
        let r = http(port, "/api?mode=warnings&apikey=sekrit&output=json", None);
        assert!(r.contains("No Usenet server"), "warnings stayed empty: {r}");

        // mode=status carries the same warning, plus what a remote app
        // badges: the count, the pause state, free space.
        let r = http(port, "/api?mode=status&apikey=sekrit&output=json", None);
        assert!(r.contains("\"have_warnings\":\"1\""), "{r}");
        assert!(r.contains("No Usenet server"), "{r}");
        assert!(r.contains("\"paused\""), "{r}");
        assert!(r.contains("\"diskspace1\""), "{r}");
        assert!(r.contains("\"completedir\""), "{r}");

        // An empty script list makes a client show no dropdown at all,
        // so "None" is the honest floor.
        let r = http(port, "/api?mode=get_scripts&apikey=sekrit&output=json", None);
        assert!(r.contains("\"None\""), "{r}");

        // Every category SAB serializes carries SEVEN keys
        // (`ConfigCat.get_dict`, identical in 4.5.0, 5.1.2 and develop,
        // read 30 Aug 2026) and we sent five: `order` and `newzbin` were
        // absent outright. That is GH #69's absent-key half in the
        // payload the *arrs and every remote app read to fill a category
        // dropdown - a client with a non-nullable field for either dies
        // before it sees a category name.
        let r = http(port, "/api?mode=get_config&apikey=sekrit&output=json", None);
        let cfg_body: serde_json::Value = serde_json::from_str(&r).expect("get_config is JSON");
        let cats = cfg_body["config"]["categories"]
            .as_array()
            .expect("a categories array");
        assert!(!cats.is_empty(), "the built-in categories must be listed: {r}");
        for (i, c) in cats.iter().enumerate() {
            for key in ["name", "order", "pp", "script", "dir", "newzbin", "priority"] {
                assert!(
                    c.get(key).is_some(),
                    "SAB sends `{key}` on every category and we do not: {c}"
                );
            }
            assert_eq!(
                c["order"].as_u64(),
                Some(i as u64),
                "`order` is the position in the list we just sent: {c}"
            );
            assert!(c["newzbin"].is_string(), "{c}");
            assert!(c["priority"].is_number(), "{c}");
        }

        // Pause before queueing, and it has to be before: "no server, so
        // it never starts" is not true. With an empty server list the job
        // IS picked up, fails "config has no servers" inside half a
        // second, and parks to history. In isolation the three round
        // trips below beat that; under the full suite's load they did not,
        // and the queue read found an empty slot list perhaps one run in
        // six. A paused queue is never picked from, so the job stays
        // Queued for as long as this test needs it.
        let r = http(port, "/api?mode=pause&apikey=sekrit&output=json", None);
        assert!(r.contains("\"status\":true"), "pause refused: {r}");

        // Queue a job and move it to another category. Nothing has been
        // written, so this re-derives the output directory rather than
        // moving files.
        let nzb = "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;chg.bin&quot; yEnc (1/1)\">\n    <groups><group>g</group></groups>\n    <segments><segment bytes=\"100\" number=\"1\">&lt;a@x&gt;</segment></segments>\n  </file>\n</nzb>\n";
        let body = format!(
            "--BB\r\nContent-Disposition: form-data; name=\"nzbfile\"; filename=\"Chg.Show.S01E01.1080p.nzb\"\r\nContent-Type: application/xml\r\n\r\n{nzb}\r\n--BB--\r\n"
        );
        let r = http(
            port,
            "/api?mode=addfile&apikey=sekrit&cat=tv&output=json",
            Some(("multipart/form-data; boundary=BB", body.as_bytes())),
        );
        let id = r
            .split("\"nzo_ids\":[\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .expect("no nzo_id in addfile response")
            .to_string();

        let r = http(
            port,
            &format!("/api?mode=change_cat&value={id}&value2=movies&apikey=sekrit&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "change_cat refused: {r}");
        let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
        assert!(q.contains("\"cat\":\"movies\""), "category did not change: {q}");

        // An unknown id is an error, not a silent success.
        let r = http(
            port,
            "/api?mode=change_cat&value=nope&value2=tv&apikey=sekrit&output=json",
            None,
        );
        assert!(r.contains("\"status\":false"), "{r}");
    })
    .await
    .unwrap();
}

/// `mode=status.servers` is FULL-KEY, and the add-only tier keeps the
/// empty array it has always had.
///
/// Not a shape question and not settled by anything that shipped. SAB's
/// `status` is on the add-only NZB key's allowlist here (`serve/http.rs`)
/// so a push extension's "test connection" button works, and that tier's
/// stated promise is a version string, paused/warning/disk numbers and
/// the category names, with queue contents and the filesystem layout
/// full-key. A list of the user's configured provider HOSTNAMES is none
/// of those.
///
/// Our own tree answers the wider question both ways - `out_dir_for`
/// blanks the download path for this tier, while `sab_warnings`
/// deliberately DOES name an exhausted provider's host to it with a
/// stated reason - so there is no house rule to appeal to, and picking
/// one is J4 of `research/SAB-MODE-SHAPE-AUDIT-2026-08-31.md` - a
/// product decision, deliberately left open. Filling the array for
/// full-key callers changes nothing the add-only key can already see,
/// which is why it did not have to wait for that answer. This test is what makes the decision VISIBLE: whichever way
/// J4 lands, the line moves in a diff instead of by accident.
#[tokio::test(flavor = "multi_thread")]
async fn sab_status_servers_are_full_key_only() {
    let dir = std::env::temp_dir().join(format!("nzbfast-sabsrvtier-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    // Two rows on ONE hostname, which is the shape that makes a
    // host-keyed lookup wrong (a flat-rate account plus a small block
    // fill at the same provider is ordinary), plus a switched-off third.
    // Never dialled: nothing here downloads.
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        r#"{"servers":[
             {"host":"news.invalid","port":563,"tls":true,"connections":8,"level":0},
             {"host":"news.invalid","port":119,"tls":false,"connections":2,"level":1},
             {"host":"off.invalid","port":563,"tls":true,"connections":4,"level":2,"enabled":false}
           ]}"#,
    )
    .unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_NO_ENRICH", "1")
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
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        let body = |q: &str| -> serde_json::Value {
            let r = http(port, &format!("/api?{q}"), None);
            serde_json::from_str(&r).unwrap_or_else(|e| panic!("not JSON ({e}): {r}"))
        };
        let rows = |v: &serde_json::Value| -> Vec<serde_json::Value> {
            v["status"]["servers"]
                .as_array()
                .unwrap_or_else(|| panic!("status.servers is an array: {v}"))
                .clone()
        };

        // Full key: every CONFIGURED row, including the switched-off
        // one, which SAB reports as inactive rather than dropping.
        let full = body("mode=status&apikey=sekrit&output=json");
        let r = rows(&full);
        assert_eq!(r.len(), 3, "one row per configured server: {full}");
        assert_eq!(r[0]["servername"], "news.invalid");
        assert_eq!(
            r[0]["servertotalconn"], 8,
            "SAB's threads is the CONFIGURED count"
        );
        assert_eq!(r[0]["serverpriority"], 0);
        assert_eq!(r[0]["serverssl"], true);
        // The second row on the same hostname keeps its OWN numbers: a
        // lookup keyed by host would hand it the first row's.
        assert_eq!(r[1]["servername"], "news.invalid");
        assert_eq!(r[1]["servertotalconn"], 2);
        assert_eq!(r[1]["serverssl"], false);
        assert_eq!(
            r[2]["serveractive"], false,
            "a switched-off server never joins a pool, which is SAB's inactive: {full}"
        );
        assert_eq!(r[0]["serveractive"], true);
        // Nothing is downloading, so the live half is zeroed rather than
        // absent - and the rows are here at all, which is the defect.
        for row in &r {
            assert_eq!(row["serveractiveconn"], 0, "{row}");
            assert_eq!(row["serverbps"], "0", "{row}");
            assert_eq!(row["serverconnections"], serde_json::json!([]), "{row}");
        }
        // Both spellings, since SAB answers them from one function.
        assert_eq!(
            rows(&body("mode=fullstatus&apikey=sekrit&output=json")),
            r,
            "fullstatus must carry the same rows: {full}"
        );

        // Now the add-only key. Minted through the API so the tier is
        // reached exactly as a push extension reaches it.
        let mk = http(
            port,
            "/api?mode=config&name=nzbkey&value=addonly&apikey=sekrit&output=json",
            None,
        );
        assert!(
            mk.contains("\"status\":true"),
            "could not set an nzbkey: {mk}"
        );
        for mode in ["status", "fullstatus"] {
            let v = body(&format!("mode={mode}&apikey=addonly&output=json"));
            assert!(
                v["status"]["version"].is_string(),
                "the add-only key must still reach {mode} at all: {v}"
            );
            assert_eq!(
                rows(&v),
                Vec::<serde_json::Value>::new(),
                "the add-only tier must not be handed the provider list ({mode}): {v}"
            );
        }
        // And the key that is allowed to see them still does, so the
        // assertion above is about the TIER and not about the daemon
        // having forgotten its servers.
        assert_eq!(
            rows(&body("mode=status&apikey=sekrit&output=json")).len(),
            3,
            "the full key still sees every configured server"
        );
    })
    .await
    .unwrap();
}

/// The WRITE arms of `mode=queue` and `mode=history`, against the shapes
/// SAB answers with - the half `sab_facade_carries_sabnzbds_own_queue_and_history_shape`
/// above deliberately did not cover, and the one where getting it wrong
/// DESTROYS something.
///
/// Read off `sabnzbd/api.py`'s `_api_queue_table` / `_api_history_table`
/// at tag 5.1.2, cross-checked at 4.5.0 (the version `SAB_VERSION`
/// advertises: the two are identical on every queue arm but for typing
/// syntax). Every arm answers `report(keyword="", data={...})`, and
/// `report` puts a dict with a falsy keyword out as the WHOLE body, so
/// `{"status": ..., "nzo_ids": [...]}` is the top-level object.
///
/// Five things it pins, each of which was live on origin/main on 31 Aug
/// 2026 and every one of which the key-and-type census above was blind
/// to, because a verb with no arm and a verb with a wrong value both
/// answer valid JSON:
///
/// 1. `nzo_ids` on delete / purge / pause / resume. SAB's own answer;
///    absent here, so a client batching a write and reconciling by the
///    returned list got `null` and could not tell WHICH ids were acted
///    on. Same absent-key class as GH #69's `server_stats`.
/// 2. `search=` narrowing the SWEEPS. Ignored on both delete arms, and
///    an unread filter on a DELETE does not fail - it deletes
///    everything. `value=all&search=Alpha` swept a whole queue and a
///    whole history.
/// 3. `purge`, `delete_nzf` and `mark_as_completed` had NO arm and fell
///    through to the payload default, so a destructive verb answered
///    with the queue LISTING - an object with no `status` key anywhere
///    in it, which is exactly the shape that crashed #69's client - and
///    swept nothing.
/// 4. `rename` with no `value2` renamed the job to the empty string and
///    answered `{"status": true}`. The name is the only handle anyone
///    has on the row.
/// 5. `priority` answered a hardcoded `position: -1`, which is the value
///    SAB reserves for "incorrect job-id", so a client checking
///    `position >= 0` read every success as a failure.
///
/// A paused queue throughout: `pick_job` never runs, so the rows stay
/// Queued for as long as the assertions need them - the reason the
/// `change_cat` leg above pauses first, in its own words.
#[tokio::test(flavor = "multi_thread")]
async fn sab_facade_write_arms_answer_sabnzbds_own_shapes() {
    let dir = std::env::temp_dir().join(format!("nzbfast-sabwrite-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Seeded BEFORE the daemon starts, the way `daemon_delete` does it:
    // the history sweep half needs rows in four (name, state) shapes and
    // waiting for four real downloads would buy nothing this asks about.
    let spool = dir.join("complete/.spool");
    std::fs::create_dir_all(&spool).unwrap();
    let mut seeded = String::new();
    for (id, name, state) in [
        ("SABnzbd_nzo_wr1", "Alpha.Done", "Completed"),
        ("SABnzbd_nzo_wr2", "Beta.Done", "Completed"),
        ("SABnzbd_nzo_wr3", "Alpha.Bad", "Failed"),
        ("SABnzbd_nzo_wr4", "Gamma.Bad", "Failed"),
    ] {
        let out = dir.join("complete").join(name);
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("p.mkv"), b"x").unwrap();
        let row = serde_json::json!({
            "nzo_id": id, "name": name, "state": state,
            "nzb_path": dir.join(format!("{name}.nzb")).to_string_lossy(),
            "out_dir": out.to_string_lossy(),
            "category": "", "total_bytes": 1u64,
            "finished_unix": 1_722_000_000i64, "fail_message": "",
        });
        seeded.push_str(&serde_json::to_string(&row).unwrap());
        seeded.push('\n');
    }
    std::fs::write(spool.join("history.jsonl"), seeded).unwrap();

    let srv = MockServer::start(HashMap::new(), Chaos::default()).await;
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
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_NO_ENRICH", "1")
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
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        use serde_json::Value;

        let call = |q: &str| -> Value {
            let r = http(port, &format!("/api?apikey=sekrit&output=json&{q}"), None);
            serde_json::from_str(&r).unwrap_or_else(|e| panic!("{q} answered non-JSON ({e}): {r}"))
        };
        // Names in queue order, so an assertion can say WHICH rows a
        // sweep left rather than how many.
        let names = || -> Vec<String> {
            call("mode=queue")["queue"]["slots"]
                .as_array()
                .expect("slots")
                .iter()
                .map(|s| s["filename"].as_str().unwrap_or_default().to_string())
                .collect()
        };
        let ids_of = |v: &Value| -> Vec<String> {
            v["nzo_ids"]
                .as_array()
                .unwrap_or_else(|| panic!("SAB answers this write with `nzo_ids`: {v}"))
                .iter()
                .map(|s| s.as_str().unwrap_or_default().to_string())
                .collect()
        };
        let add = |name: &str| -> String {
            let nzb = "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;w.bin&quot; yEnc (1/1)\">\n    <groups><group>g</group></groups>\n    <segments><segment bytes=\"100\" number=\"1\">&lt;a@x&gt;</segment></segments>\n  </file>\n</nzb>\n";
            let body = format!(
                "--BB\r\nContent-Disposition: form-data; name=\"nzbfile\"; filename=\"{name}.nzb\"\r\nContent-Type: application/xml\r\n\r\n{nzb}\r\n--BB--\r\n"
            );
            let r = http(
                port,
                "/api?mode=addfile&apikey=sekrit&output=json",
                Some(("multipart/form-data; boundary=BB", body.as_bytes())),
            );
            r.split("\"nzo_ids\":[\"")
                .nth(1)
                .and_then(|s| s.split('"').next())
                .unwrap_or_else(|| panic!("no nzo_id from addfile: {r}"))
                .to_string()
        };

        assert_eq!(call("mode=pause")["status"], Value::Bool(true));
        let a = add("Alpha.One");
        let b = add("Beta.Two");
        let c = add("Alpha.Three");
        assert_eq!(names(), ["Alpha.One", "Beta.Two", "Alpha.Three"]);

        // (1) pause / resume carry the ids they acted on. Ours reports
        // the rows that TOOK the write; SAB's own arm echoes back every
        // id it was handed, because `pause_multiple_nzo` appends
        // unconditionally - an upstream slip, written up in
        // research/SAB-WRITE-ARM-SHAPES-2026-08-31.md and deliberately
        // not copied. Either way the KEY is there and is an array.
        let r = call(&format!("mode=queue&name=pause&value={a}"));
        assert_eq!(r["status"], Value::Bool(true), "{r}");
        assert_eq!(ids_of(&r), *std::slice::from_ref(&a), "{r}");
        // A miss is an empty array, never a missing key: a client that
        // declared `List<String>` must be able to read the failure too.
        let r = call("mode=queue&name=pause&value=nzo_not_here");
        assert_eq!(r["status"], Value::Bool(false), "{r}");
        assert!(ids_of(&r).is_empty(), "{r}");
        let r = call(&format!("mode=queue&name=resume&value={a}"));
        assert_eq!(ids_of(&r), *std::slice::from_ref(&a), "{r}");

        // (5) `position` is the row's index after the write, not a
        // constant. -1 is SAB's "incorrect job-id" and must mean only
        // that.
        let r = call(&format!("mode=queue&name=priority&value={a}&value2=1"));
        assert_eq!(r["status"], Value::Bool(true), "{r}");
        assert_eq!(
            r["position"].as_i64(),
            Some(0),
            "the High job runs first, so it is at index 0: {r}"
        );
        let r = call("mode=queue&name=priority&value=nzo_not_here&value2=1");
        assert_eq!(r["status"], Value::Bool(false), "{r}");
        assert_eq!(r["position"].as_i64(), Some(-1), "{r}");

        // ...and a priority that is missing, or present and unreadable,
        // is refused rather than silently read as Normal. Both demoted a
        // Force job under a `"status": true` until 31 Aug 2026.
        for q in [
            format!("mode=queue&name=priority&value={a}"),
            format!("mode=queue&name=priority&value={a}&value2=notaprio"),
        ] {
            let r = call(&q);
            assert_eq!(r["status"], Value::Bool(false), "{q}: {r}");
            assert!(r["error"].is_string(), "{q} must say why: {r}");
        }
        let still_high = call("mode=queue")["queue"]["slots"][0]["priority"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert_eq!(still_high, "High", "a refused priority write changed it");

        // (4) a rename with no new name is a refusal, and it must leave
        // the label alone - the whole defect was that it did not.
        for q in [
            format!("mode=queue&name=rename&value={b}"),
            format!("mode=queue&name=rename&value={b}&value2="),
            format!("mode=queue&name=rename&value={b}&value2=%20"),
        ] {
            let r = call(&q);
            assert_eq!(r["status"], Value::Bool(false), "{q}: {r}");
            assert!(
                names().iter().any(|n| n == "Beta.Two"),
                "{q} renamed the job anyway: {:?}",
                names()
            );
        }
        let r = call(&format!("mode=queue&name=rename&value={b}&value2=Beta.Renamed"));
        assert_eq!(r["status"], Value::Bool(true), "a real rename: {r}");
        assert!(names().iter().any(|n| n == "Beta.Renamed"), "{:?}", names());

        // (3) a verb we do not implement answers in SAB's SHAPE, never
        // with the payload the mode's default arm builds. `status` is
        // the key that has to be there; `queue` / `history` is the key
        // that must not.
        let r = call(&format!("mode=queue&name=delete_nzf&value={a}&value2=nzf_1"));
        assert!(r["status"].is_boolean(), "{r}");
        assert!(r["nzf_ids"].is_array(), "SAB answers delete_nzf with nzf_ids: {r}");
        assert!(r.get("queue").is_none(), "answered with the queue listing: {r}");
        let r = call("mode=history&name=mark_as_completed&value=SABnzbd_nzo_wr3");
        assert!(r["status"].is_boolean(), "{r}");
        assert!(r.get("history").is_none(), "answered with the history listing: {r}");

        // (2) `search` narrows a SWEEP. Ignoring it deleted everything.
        let r = call("mode=queue&name=delete&value=all&search=Alpha");
        assert_eq!(r["status"], Value::Bool(true), "{r}");
        let mut got = ids_of(&r);
        got.sort();
        let mut want = vec![a.clone(), c.clone()];
        want.sort();
        assert_eq!(got, want, "only the two Alpha rows: {r}");
        assert_eq!(names(), ["Beta.Renamed"], "the sweep took an unmatched row");

        // ...and never an explicit id list, which SAB threads it into
        // neither: `remove_all` takes `search`, `remove_multiple` does
        // not.
        let d1 = add("Delta.Keep");
        let r = call(&format!("mode=queue&name=delete&value={d1}&search=nothing-matches-this"));
        assert_eq!(ids_of(&r), *std::slice::from_ref(&d1), "a named id is not search-filtered: {r}");

        // (3) `purge` is SAB's delete-everything, and it takes `search`
        // too. It had no arm at all, so it answered with the listing and
        // swept nothing.
        let e1 = add("Echo.Purge");
        let f1 = add("Foxtrot.Purge");
        let r = call("mode=queue&name=purge&search=Echo");
        assert!(r.get("queue").is_none(), "purge answered with the listing: {r}");
        assert_eq!(ids_of(&r), *std::slice::from_ref(&e1), "{r}");
        let r = call("mode=queue&name=purge");
        assert_eq!(r["status"], Value::Bool(true), "{r}");
        assert!(ids_of(&r).contains(&f1), "a bare purge takes the rest: {r}");
        assert!(names().is_empty(), "purge left rows behind: {:?}", names());

        // The history half of (1) and (2), on the store seeded above.
        // `removed` and `nzo_ids` are both additive here - SAB answers a
        // bare `report()` - but the sweep narrowing is not: it destroys.
        let before: Vec<String> = call("mode=history")["history"]["slots"]
            .as_array()
            .expect("slots")
            .iter()
            .map(|s| s["name"].as_str().unwrap_or_default().to_string())
            .collect();
        assert_eq!(before.len(), 4, "seeded history did not load: {before:?}");
        let r = call("mode=history&name=delete&value=all&search=Alpha");
        assert_eq!(r["status"], Value::Bool(true), "{r}");
        let mut got = ids_of(&r);
        got.sort();
        assert_eq!(got, ["SABnzbd_nzo_wr1", "SABnzbd_nzo_wr3"], "{r}");
        let left: Vec<String> = call("mode=history")["history"]["slots"]
            .as_array()
            .expect("slots")
            .iter()
            .map(|s| s["name"].as_str().unwrap_or_default().to_string())
            .collect();
        assert_eq!(left.len(), 2, "the sweep took an unmatched row: {left:?}");
        assert!(!left.iter().any(|n| n.starts_with("Alpha")), "{left:?}");
    })
    .await
    .unwrap();
}

/// The dashboard's "Clear failed" one-click - `mode=history&name=delete
/// &value=failed` - end to end. It takes the plain failure and leaves a
/// Completed row alone, and it must ALSO leave a password-locked row
/// alone whether that row's state is Completed or Failed:
/// `settle_locked_failure` sets `password_required` on a job whose
/// unpack failed for want of a password, and that history row is the
/// only thing carrying the 🔑 to unlock it. Same guarantee
/// `plan_history_delete`'s unit coverage pins in
/// `clear_completed_and_clear_failed_spare_password_locked_records`,
/// checked here against the real facade response rather than the
/// planner's own return value.
#[tokio::test(flavor = "multi_thread")]
async fn clear_failed_sweeps_failures_and_spares_locked_rows() {
    let dir = std::env::temp_dir().join(format!("nzbfast-histclearfail-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let spool = dir.join("complete/.spool");
    std::fs::create_dir_all(&spool).unwrap();
    let mut seeded = String::new();
    for (id, name, state, locked) in [
        ("SABnzbd_nzo_cf1", "Alpha.Done", "Completed", false),
        ("SABnzbd_nzo_cf2", "Beta.Bad", "Failed", false),
        ("SABnzbd_nzo_cf3", "Gamma.Locked", "Completed", true),
        ("SABnzbd_nzo_cf4", "Delta.Locked.Bad", "Failed", true),
    ] {
        let out = dir.join("complete").join(name);
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("p.mkv"), b"x").unwrap();
        let row = serde_json::json!({
            "nzo_id": id, "name": name, "state": state,
            "nzb_path": dir.join(format!("{name}.nzb")).to_string_lossy(),
            "out_dir": out.to_string_lossy(),
            "category": "", "total_bytes": 1u64,
            "finished_unix": 1_722_000_000i64, "fail_message": "",
            "password_required": locked,
        });
        seeded.push_str(&serde_json::to_string(&row).unwrap());
        seeded.push('\n');
    }
    std::fs::write(spool.join("history.jsonl"), seeded).unwrap();

    let srv = MockServer::start(HashMap::new(), Chaos::default()).await;
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
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_NO_ENRICH", "1")
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
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        let hist = http(port, "/api?apikey=sekrit&output=json&mode=history", None);
        for id in [
            "SABnzbd_nzo_cf1",
            "SABnzbd_nzo_cf2",
            "SABnzbd_nzo_cf3",
            "SABnzbd_nzo_cf4",
        ] {
            assert!(history_has(&hist, id), "seed did not load {id}: {hist}");
        }
        // The button's own visibility question: only the one plain
        // failure is clearable - both locked rows carry the 🔑 and must
        // not be counted as available for the bulk sweep.
        let v: serde_json::Value = serde_json::from_str(&hist).unwrap();
        assert_eq!(v["history"]["counts"]["clearable_failed"], 1, "{hist}");

        let r = http(
            port,
            "/api?apikey=sekrit&output=json&mode=history&name=delete&value=failed",
            None,
        );
        let rv: serde_json::Value =
            serde_json::from_str(&r).unwrap_or_else(|e| panic!("bad delete response ({e}): {r}"));
        assert_eq!(rv["status"], serde_json::Value::Bool(true), "{r}");

        let hist2 = http(port, "/api?apikey=sekrit&output=json&mode=history", None);
        assert!(
            !history_has(&hist2, "SABnzbd_nzo_cf2"),
            "the plain failure must be gone: {hist2}"
        );
        for id in ["SABnzbd_nzo_cf1", "SABnzbd_nzo_cf3", "SABnzbd_nzo_cf4"] {
            assert!(
                history_has(&hist2, id),
                "{id} must survive value=failed: {hist2}"
            );
        }
    })
    .await
    .unwrap();
}
