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
    let _ = std::fs::remove_dir_all(&dir);
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
        // SAB's own suffix convention (to_units + "B"), not a bare MB.
        let size = hist["slots"][0]["size"].as_str().unwrap_or_default();
        assert!(
            size.ends_with('B') && size.contains(' '),
            "history size should be SAB-shaped: {size}"
        );

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
    let _ = std::fs::remove_dir_all(&dir);
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

    let dir2 = dir.clone();
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
        // history cleanup op is exercised by HistoryDelete once done.
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
    let _ = std::fs::remove_dir_all(&dir2);
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

    let dir2 = dir.clone();
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
    let _ = std::fs::remove_dir_all(&dir2);
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
    let _ = std::fs::remove_dir_all(&dir);
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
    let _ = std::fs::remove_dir_all(&dir);
}
