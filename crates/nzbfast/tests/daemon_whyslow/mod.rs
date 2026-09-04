//! TODO 207: the "Why is this slow?" verdict, from the wire into
//! history and back out of a restarted daemon.
//!
//! The verdict used to die with the job: it lived in the whyslow core's
//! memory, was published only through the queue payload, and was gone
//! the moment the download stopped - so the one client that can
//! attribute a shortfall to a layer forgot the attribution at exactly
//! the moment the user went looking for it. These two legs pin both
//! halves of the fix: a job that really was slow carries its verdict
//! across a kill -9, and a record written before the field existed
//! reads as ABSENT - not as `unknown`, and not as `line`.
//!
//! A sibling-dir child of daemon.rs (the daemon_finish pattern) so the
//! parent stays inside its size-gate baseline. Declared from daemon.rs,
//! so these run in that binary against those fixtures; harness via
//! `super::*`.

use super::*;

/// The layers that mean "something held this download back". `line`
/// and `unknown` are excluded for the same reason the queue row's
/// verdict chip excludes them: one is not a shortfall and the other is
/// not a verdict.
///
/// This IS that chip's list, and must stay it: `web/dashboard.html`
/// carries the same eight tokens twice (the row's verdict clause and
/// the history drawer's row), and a layer in one list and not the other
/// is a verdict the page shows and this suite reads as "not a
/// shortfall". `fleet` and `knee` joined on 28 Aug 2026 - the first was
/// missed when TODO 312 item 3 added it, and item 7 found the gap while
/// adding the second.
const SHORTFALL: [&str; 8] = [
    "provider", "cpu", "client", "disk", "limit", "missing", "fleet", "knee",
];

/// A mock server slow enough that the core has time to reach a verdict.
///
/// The window is twenty one-second ticks and a layer needs twelve of
/// them, so a job that finishes in two seconds is judged `unknown` and
/// rightly persists nothing. 100 articles behind a 400 ms per-BODY
/// delay over two connections is about twenty seconds on the wire,
/// which clears the majority with time to spare on either side.
async fn slow_job(seed: u8) -> (MockServer, String) {
    let data = payload(100 * 20_000, seed);
    let mut articles = HashMap::new();
    let segs = make_file_articles("slow.bin", &data, 20_000, "sl", &mut articles);
    let srv = MockServer::start(
        articles,
        Chaos {
            delay_ms: 400,
            ..Chaos::default()
        },
    )
    .await;
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;slow.bin&quot; yEnc (1/100)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");
    (srv, xml)
}

fn upload(port: u16, xml: &str) -> String {
    let boundary = "----whyslowb";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"j.nzb\"\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(xml.as_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let r = http(
        port,
        "/api?mode=addfile&output=json",
        Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
    );
    assert!(r.contains("\"status\":true"), "{r}");
    r.split("SABnzbd_nzo_")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .map(|s| format!("SABnzbd_nzo_{s}"))
        .unwrap()
}

/// The one history slot for `id`, or None while it is not filed yet.
fn history_slot(port: u16, id: &str) -> Option<serde_json::Value> {
    let h = http(port, "/api?mode=history&output=json", None);
    let v: serde_json::Value = serde_json::from_str(&h).unwrap_or(serde_json::Value::Null);
    v["history"]["slots"]
        .as_array()?
        .iter()
        .find(|s| s["nzo_id"].as_str() == Some(id))
        .cloned()
}

fn wait_for_history(port: u16, id: &str, secs: u64) -> serde_json::Value {
    for _ in 0..(secs * 5) {
        if let Some(s) = history_slot(port, id) {
            return s;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    panic!("{id} never reached history on :{port}");
}

/// A download that really was slow keeps its verdict: captured at
/// network-drain, filed with the history record, and still there after
/// the daemon has been killed and restarted.
///
/// Driven against a deliberately slow mock with the line speed declared
/// at 1 Gbit, so the shortfall against the anchor is real and the core
/// has something to attribute. WHICH layer it names is the core's
/// business and is pinned by its own unit tests - what this leg proves
/// is that a verdict is reached, persisted, and read back identically
/// by a process that never saw the download.
#[tokio::test(flavor = "multi_thread")]
async fn a_slow_jobs_verdict_reaches_history_and_survives_a_restart() {
    let dir = std::env::temp_dir().join(format!("nzbfast-why207-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let (srv, xml) = slow_job(3).await;
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false,\"connections\":2}}]}}",
            srv.addr.ip(),
            srv.addr.port()
        ),
    )
    .unwrap();
    // A declared line speed IS the anchor until a measurement beats it
    // (linkpeak), and without an anchor "slow" is undefined and the
    // core votes `unknown` forever - by design, since inventing a
    // ceiling is the one thing this surface must never do.
    std::fs::write(
        dir.join("settings.json"),
        "{\"line_speed\": 125000000, \"index_enabled\": false}",
    )
    .unwrap();
    let build = |port: u16| {
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
    };

    let a = serve(&dir, &build).await;
    let port_a = a.port;
    let (id, verdict) = tokio::task::spawn_blocking(move || {
        let id = upload(port_a, &xml);
        // The job is on the wire long enough for the core to publish a
        // verdict; watching it live is also the proof that the two
        // surfaces are talking about the same thing.
        let mut live = String::new();
        for _ in 0..300 {
            let q = http(port_a, "/api?mode=queue&output=json", None);
            let v: serde_json::Value = serde_json::from_str(&q).unwrap();
            let w = &v["queue"]["whyslow"];
            if w["nzo_id"].as_str() == Some(id.as_str())
                && SHORTFALL.contains(&w["layer"].as_str().unwrap_or(""))
            {
                live = w["layer"].as_str().unwrap().to_string();
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(
            !live.is_empty(),
            "the core never reached a shortfall verdict for the slow job"
        );

        let slot = wait_for_history(port_a, &id, 120);
        let w = slot["whyslow"].clone();
        assert!(
            w.is_object(),
            "the finished job carries no verdict: {slot:#}"
        );
        assert!(
            SHORTFALL.contains(&w["layer"].as_str().unwrap_or("")),
            "a slow job must not be filed as line speed or unknown: {w:#}"
        );
        // The claim carries its own weight: how long that layer was the
        // verdict, and how long the run was, so "for 8 of 20 seconds"
        // is readable as what it is.
        let held = w["held_secs"].as_u64().expect("held_secs");
        let total = w["total_secs"].as_u64().expect("total_secs");
        assert!(held >= 1 && held <= total, "held {held} of {total}");
        // ...and the report - the artefact a user actually sends - says
        // it too, now that the job is off the wire.
        let rep = http(port_a, &format!("/api?mode=report&value={id}"), None);
        let rv: serde_json::Value = serde_json::from_str(&rep).unwrap();
        let txt = rv["report"].as_str().unwrap_or("");
        assert!(txt.contains("== why it was slow =="), "{txt}");
        assert!(
            txt.contains(&format!("[{}", w["layer"].as_str().unwrap())),
            "the token is missing from the report: {txt}"
        );
        (id, w)
    })
    .await
    .unwrap();

    // kill -9 and come back on a fresh port, same spool. The samples
    // behind the verdict are gone with the process - they index a ring
    // this daemon never filled - but the verdict is a statement about
    // the download and has to survive.
    drop(a);
    let b = serve(&dir, &build).await;
    let port_b = b.port;
    tokio::task::spawn_blocking(move || {
        let slot = wait_for_history(port_b, &id, 30);
        assert_eq!(
            slot["whyslow"], verdict,
            "the verdict changed across the restart"
        );
    })
    .await
    .unwrap();
    drop(b);
}

/// ...and the other half of the rule: a history record written before
/// the field existed has to read as ABSENT through the API. Not as
/// `unknown` (which is a verdict this surface really does emit, meaning
/// the evidence disagreed with itself) and not as `line` (which would
/// tell the reader the download was fine). Same trap `bad_blocks` was
/// fixed for in the Verification row.
#[tokio::test(flavor = "multi_thread")]
async fn a_history_record_from_before_the_field_reads_as_absent() {
    let dir = std::env::temp_dir().join(format!("nzbfast-why207old-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let spool = dir.join(".spool");
    std::fs::create_dir_all(&spool).unwrap();
    std::fs::write(dir.join("config.json"), "{\"servers\":[]}").unwrap();
    std::fs::write(dir.join("settings.json"), "{\"index_enabled\": false}").unwrap();
    std::fs::write(
        spool.join("queue.json"),
        "{\"next_id\": 9000000, \"queue\": []}",
    )
    .unwrap();
    // Two records, one line each, exactly as the store writes them: the
    // pre-upgrade one with no `whyslow` key at all, and one carrying a
    // verdict, so the leg proves the reader can tell them apart rather
    // than that it drops the field on the floor for everybody.
    let old = serde_json::json!({
        "nzo_id": "SABnzbd_nzo_old207",
        "name": "Old.Record.Before.The.Field",
        "nzb_path": dir.join("old.nzb").to_string_lossy(),
        "out_dir": dir.join("complete/Old").to_string_lossy(),
        "state": "Completed",
        "total_bytes": 1_000_000u64,
        "elapsed_secs": 120.0,
        "downloaded_bytes": 1_000_000u64,
        "finished_unix": 1_722_000_000i64,
    });
    let new = serde_json::json!({
        "nzo_id": "SABnzbd_nzo_new207",
        "name": "New.Record.With.A.Verdict",
        "nzb_path": dir.join("new.nzb").to_string_lossy(),
        "out_dir": dir.join("complete/New").to_string_lossy(),
        "state": "Completed",
        "total_bytes": 1_000_000u64,
        "elapsed_secs": 900.0,
        "downloaded_bytes": 1_000_000u64,
        "finished_unix": 1_722_003_600i64,
        "whyslow": {"layer": "provider", "detail": "news.example.invalid",
                    "held_secs": 640u64, "total_secs": 900u64},
    });
    std::fs::write(spool.join("history.jsonl"), format!("{old}\n{new}\n")).unwrap();

    let cfg = dir.join("config.json");
    let build = |port: u16| {
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
    };
    let d = serve(&dir, &build).await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        let old = wait_for_history(port, "SABnzbd_nzo_old207", 30);
        assert!(
            old["whyslow"].is_null(),
            "a pre-field record must answer with nothing at all: {old:#}"
        );
        // Emphatically not these two, which is the whole point.
        let s = old.to_string();
        assert!(!s.contains("\"unknown\""), "{s}");
        assert!(!s.contains("\"whyslow\":\"line\""), "{s}");
        let new = wait_for_history(port, "SABnzbd_nzo_new207", 30);
        assert_eq!(new["whyslow"]["layer"], "provider", "{new:#}");
        assert_eq!(new["whyslow"]["detail"], "news.example.invalid");
        assert_eq!(new["whyslow"]["held_secs"], 640);
        assert_eq!(new["whyslow"]["total_secs"], 900);
        // The report follows the record either way: a section for the
        // one that has a verdict, silence for the one that does not.
        let rep = |id: &str| -> String {
            let r = http(port, &format!("/api?mode=report&value={id}"), None);
            let v: serde_json::Value = serde_json::from_str(&r).unwrap();
            v["report"].as_str().unwrap_or("").to_string()
        };
        assert!(!rep("SABnzbd_nzo_old207").contains("== why it was slow =="));
        let with = rep("SABnzbd_nzo_new207");
        assert!(with.contains("== why it was slow =="), "{with}");
        assert!(with.contains("640s of 900s"), "{with}");
    })
    .await
    .unwrap();
    // Close the daemon, keeping its log for whatever fails below.
    let _log = d.stop();
}

/// TODO 312 items 1+3, closing the coverage hole they shipped with:
/// the `fleet` verdict produced END TO END on a running daemon - the
/// setting seeds the pool's gauges, `whyslow::feed` reads them off
/// `pool_live`, `classify` reaches the fleet arm, the majority window
/// publishes it, and the queue payload carries the four receipts. The
/// unit tests in whyslow.rs pin the decision core in both
/// directions; nothing before this drove the whole chain.
///
/// The rig HAS to be a slow mock rather than a plain mockserve run,
/// and that was measured rather than assumed: loopback at full speed parks the
/// workers on the decode channel, `blocked_pct` reads ~100% and
/// `classify` correctly answers `client` one arm ABOVE the fleet check
/// - with every fleet number already in its firing range. A 400 ms
/// per-BODY delay keeps each socket under-carrying (well below
/// `LINE_CAP_SOCKET_BPS`) while the declared 1 Gbit line has headroom,
/// which is GH #62's regime and this arm's trigger.
///
/// The numbers: `line_cap_fleet` typed at 2 (typed = `line_cap_auto`
/// false, so the "cap can still fix itself" gate stays open and the
/// governor is pinned) against an account offering 4, so the cap is
/// taking sockets away; the two sockets carry ~100 KB/s against a
/// 125 MB/s anchor, so the supply gate is open and the implied fleet
/// dwarfs the cap.
#[tokio::test(flavor = "multi_thread")]
async fn the_fleet_verdict_is_produced_end_to_end_on_a_running_daemon() {
    let dir = std::env::temp_dir().join(format!("nzbfast-why312-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // 400 articles behind a 400 ms per-BODY delay over the 2 sockets
    // the cap allows is ~80 s on the wire: the verdict needs twelve
    // one-second Fleet votes before it publishes, and the job must
    // still own the wire when the payload is read.
    let data = payload(400 * 20_000, 7);
    let mut articles = HashMap::new();
    let segs = make_file_articles("fleet.bin", &data, 20_000, "fl", &mut articles);
    let srv = MockServer::start(
        articles,
        Chaos {
            delay_ms: 400,
            ..Chaos::default()
        },
    )
    .await;
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;fleet.bin&quot; yEnc (1/400)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
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
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false,\"connections\":4}}]}}",
            srv.addr.ip(),
            srv.addr.port()
        ),
    )
    .unwrap();
    // The declared line speed is the anchor (linkpeak) - without one
    // "slow" is undefined and the core votes `unknown` forever. The
    // typed fleet of 2 is what `get::fleet_knobs::line_cap_plan` reads
    // at job build and what seeds the pool's `line_cap_fleet` gauge.
    std::fs::write(
        dir.join("settings.json"),
        "{\"line_speed\": 125000000, \"line_cap_fleet\": 2, \"index_enabled\": false}",
    )
    .unwrap();
    let build = |port: u16| {
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
            .arg("4");
        c
    };
    let d = serve(&dir, &build).await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        let id = upload(port, &xml);
        // Poll until the published verdict IS the fleet layer - votes
        // bank at one a second, so this converges in roughly fifteen
        // seconds and the wire holds for eighty.
        for _ in 0..450 {
            let q = http(port, "/api?mode=queue&output=json", None);
            let v: serde_json::Value = serde_json::from_str(&q).unwrap();
            let w = &v["queue"]["whyslow"];
            if w["layer"].as_str() == Some("fleet") {
                assert_eq!(w["nzo_id"].as_str(), Some(id.as_str()), "{q}");
                // The four receipts the panel renders, exactly as the
                // gauges seeded them: the cap in force, what the
                // account would have dialled, and that the cap is
                // TYPED rather than the curve's own number.
                assert_eq!(w["fleet_cap"].as_u64(), Some(2), "{q}");
                assert_eq!(w["fleet_configured"].as_u64(), Some(4), "{q}");
                assert_eq!(w["fleet_auto"].as_bool(), Some(false), "{q}");
                // ...and the two measurements: a per-socket carry was
                // really measured on a supply-gate-open tick, and the
                // fleet it implies exceeds the cap it convicts.
                let carry = w["fleet_carry_bps"].as_u64().unwrap();
                assert!(carry > 0, "a fleet verdict with no measured carry: {q}");
                let implied = w["fleet_implied"].as_u64().unwrap();
                assert!(implied > 2, "the implied fleet must exceed the cap: {q}");
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        panic!("the fleet verdict never reached the queue payload");
    })
    .await
    .unwrap();

    // Close the daemon, keeping its log for whatever fails below.
    let _log = d.stop();
}

/// `conntune::SCHEMA`, which the test binary cannot name directly: these
/// suites link the BINARY, not the library, so the crate's own modules
/// are out of reach. Kept as one function with the constant's name in it
/// so a bump has something to grep for rather than a bare 2 in a JSON
/// literal.
fn nzbfast_schema() -> u32 {
    2
}

/// TODO 312 item 7: the `knee` verdict, end to end on a running daemon.
///
/// The sibling above drives a TYPED fleet cap and convicts it. This one
/// drives OUR OWN STALE MEASUREMENT and must convict that instead, on a
/// second where the cap is provably not what binds: the fleet cap is
/// left at the curve's own floor, well above the two sockets a knee of
/// 2 allows, so `fleet_bound`'s `configured > cap` is FALSE throughout.
/// Before this verdict existed the same second read as `provider` -
/// our own auto-tune blamed on the provider it had measured.
///
/// The knee is written into `conntune.json` eight days back, one day
/// past `conntune::STALE_SECS`. That is the whole point: a knee inside
/// its re-probe appointment is a measurement the prober stands by and
/// `conntune::stale_knee` deliberately reports nothing for it.
#[tokio::test(flavor = "multi_thread")]
async fn the_knee_verdict_is_produced_end_to_end_on_a_running_daemon() {
    let dir = std::env::temp_dir().join(format!("nzbfast-why312k-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Same arithmetic as the fleet leg: 400 articles behind a 400 ms
    // per-BODY delay over the two sockets the knee allows is ~80 s on
    // the wire, and the verdict needs twelve one-second votes before it
    // publishes.
    let data = payload(400 * 20_000, 11);
    let mut articles = HashMap::new();
    let segs = make_file_articles("knee.bin", &data, 20_000, "kn", &mut articles);
    let srv = MockServer::start(
        articles,
        Chaos {
            delay_ms: 400,
            ..Chaos::default()
        },
    )
    .await;
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;knee.bin&quot; yEnc (1/400)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

    let cfg = dir.join("config.json");
    let host = srv.addr.ip().to_string();
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{host}\",\"port\":{},\"tls\":false,\"connections\":8}}]}}",
            srv.addr.port()
        ),
    )
    .unwrap();
    // No `line_cap_fleet`: the curve's own floor is far above the two
    // sockets this knee leaves, so the cap takes nothing and only the
    // knee can be what binds. The declared line speed is the anchor -
    // without one "slow" is undefined and the core votes `unknown`.
    std::fs::write(
        dir.join("settings.json"),
        "{\"line_speed\": 125000000, \"index_enabled\": false}",
    )
    .unwrap();
    let checked = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 8 * 86_400;
    // `v` and `limit` are LOAD-BEARING on the daemon path and are what
    // separate this fixture from the pure `get::fleet` one, which never
    // starts a daemon. `tasks/tuner.rs` runs
    // `conntune::reopen_for_install` at startup, and that sweep RETIRES
    // every pre-v2 entry (suspect, `checked: 0`) and also reopens a knee
    // measured under a ceiling the user has since raised. Without the
    // schema stamp and a `limit` equal to today's ceiling the knee is
    // retired before the first job builds, the fleet dials all eight
    // sockets, and the verdict under test can never form.
    std::fs::write(
        dir.join("conntune.json"),
        format!(
            "{{\"{host}\":{{\"connections\":2,\"granted\":2,\"asked\":8,\"gbps\":0.01,\"checked\":{checked},\"source\":\"manual\",\"limit\":8,\"v\":{}}}}}",
            nzbfast_schema()
        ),
    )
    .unwrap();
    let build = |port: u16| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            // The bench arms select the fleet cap and live tuning from
            // the environment and outrank every file this fixture
            // writes; under one of those shells it is not the
            // configuration under test.
            .env_remove("NZBFAST_LINE_CAP")
            .env_remove("NZBFAST_LIVE_TUNE")
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
            .arg("8");
        c
    };
    let d = serve(&dir, &build).await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        let id = upload(port, &xml);
        for _ in 0..450 {
            let q = http(port, "/api?mode=queue&output=json", None);
            let v: serde_json::Value = serde_json::from_str(&q).unwrap();
            let w = &v["queue"]["whyslow"];
            if w["layer"].as_str() == Some("knee") {
                assert_eq!(w["nzo_id"].as_str(), Some(id.as_str()), "{q}");
                // The detail and `knee_host` are the same host by two
                // routes: the sentence takes the first, the remedy
                // button hands the second to `landOnServer`, which
                // matches the server list by EXACT host.
                assert_eq!(w["detail"].as_str(), Some(host.as_str()), "{q}");
                assert_eq!(w["knee_host"].as_str(), Some(host.as_str()), "{q}");
                // The receipts, exactly as the fixture seeded them: the
                // knee itself, the six sockets it costs against the
                // account's eight, and an age past the re-probe
                // appointment.
                assert_eq!(w["knee_at"].as_u64(), Some(2), "{q}");
                assert_eq!(w["knee_takes"].as_u64(), Some(6), "{q}");
                let age = w["knee_age_secs"].as_u64().unwrap();
                assert!(age >= 7 * 86_400, "the knee must read as stale: {q}");
                // ...and the two measurements, taken on a tick where
                // the supply gate was open.
                let carry = w["knee_carry_bps"].as_u64().unwrap();
                assert!(carry > 0, "a knee verdict with no measured carry: {q}");
                let implied = w["knee_implied"].as_u64().unwrap();
                assert!(implied > 2, "the implied fleet must exceed the knee: {q}");
                // The cap is provably NOT what binds, which is what
                // separates this verdict from its sibling: the fleet
                // the accounts would dial is at or under the cap in
                // force, so `fleet_bound` cannot have fired.
                let cap = w["fleet_cap"].as_u64().unwrap();
                let configured = w["fleet_configured"].as_u64().unwrap();
                assert!(
                    cap == 0 || configured <= cap,
                    "the cap must take nothing here, or this is the fleet verdict's case: {q}"
                );
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        panic!("the knee verdict never reached the queue payload");
    })
    .await
    .unwrap();

    // Close the daemon, keeping its log for whatever fails below.
    let _log = d.stop();
}
