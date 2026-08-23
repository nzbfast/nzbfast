//! TODO §138 (issue #29): the opt-in give-up on posts no server can
//! supply. A sibling-dir child of daemon.rs (the daemon_chip6 pattern)
//! so the parent stays inside its size-gate baseline; harness via
//! `super::*`.

use super::*;

/// TODO §138 (issue #29), the opt-in give-up: a post every configured
/// server confirms missing fails BEFORE it is downloaded, and one that
/// only a subset confirmed does not.
///
/// Both legs run in one daemon against one dead post, and the second
/// server is the whole experiment: while it is unreachable the fleet has
/// not spoken, so the job may only be badged red and reordered - the §77
/// rule, unchanged. Drop it from the config and the same evidence
/// becomes unanimous, and only then may the job end.
///
/// The failure has to arrive as NZBGet's `FAILURE/HEALTH` with no
/// automatic retry armed: that pairing is what makes Sonarr blocklist
/// the release and search again rather than ask us for it a second time,
/// and it is the entire point of the feature.
#[tokio::test(flavor = "multi_thread")]
async fn health_giveup_needs_every_server_to_confirm() {
    let dir = std::env::temp_dir().join(format!("nzbfast-healthgiveup-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let mut articles = HashMap::new();
    let data = payload(60_000, 11);
    let segs = make_file_articles("dead.bin", &data, 20_000, "gone", &mut articles);
    // Gone everywhere: 430 to STAT and to BODY alike.
    let missing: std::collections::HashSet<String> =
        segs.iter().map(|(id, _, _)| format!("<{id}>")).collect();
    let srv = MockServer::start(
        articles,
        Chaos {
            missing,
            ..Default::default()
        },
    )
    .await;
    // Nothing ever listens here: this is the server that has not
    // answered, which `score` drops from the verdict and
    // `no_server_can_supply` refuses to treat as a vote.
    let silent_port = free_port();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // 30 days old: well past GONE_MIN_AGE_DAYS, so propagation is no
    // longer an explanation and the verdict may reach red at all.
    let date = now - 30 * 86_400;
    let mut xml = format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"{date}\" subject=\"&quot;dead.bin&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        segs.len()
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

    let cfg = dir.join("config.json");
    let two_servers = format!(
        "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false}},\
         {{\"host\":\"127.0.0.1\",\"port\":{silent_port},\"tls\":false}}]}}",
        srv.addr.ip(),
        srv.addr.port()
    );
    let one_server = format!(
        "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false}}]}}",
        srv.addr.ip(),
        srv.addr.port()
    );
    std::fs::write(&cfg, &two_servers).unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_HEALTH_TICK_SECS", "1")
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
        let r = http(
            port,
            "/api?mode=config&name=post_health_fail&value=1&output=json",
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        // Queue paused throughout leg one: the runner is the seam that
        // decides, so this proves the verdict alone never fails a job.
        http(port, "/api?mode=pause&output=json", None);
        let id = upload_nzb(port, &xml, "dead.nzb");

        let slot = || -> serde_json::Value {
            let q = http(port, "/api?mode=queue&output=json", None);
            let v: serde_json::Value = serde_json::from_str(&q).unwrap_or_default();
            v["queue"]["slots"]
                .as_array()
                .and_then(|a| a.iter().find(|s| s["nzo_id"] == id).cloned())
                .unwrap_or(serde_json::Value::Null)
        };
        for _ in 0..200 {
            if slot()["health"]["bucket"] == "red" {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        let s = slot();
        assert_eq!(s["health"]["bucket"], "red", "never scored red: {s}");
        // The evidence, spelled out: one server voted, two were tried.
        assert_eq!(s["health"]["answered"], 1, "{s}");
        assert_eq!(s["health"]["servers"], 2, "{s}");

        // Leg one. Let it run: with a server still silent the give-up
        // bar is not met, so the job must go down the ORDINARY path and
        // actually start fetching. Reaching Downloading at all is the
        // assertion - the give-up parks a job into history without ever
        // touching the network, so the two outcomes cannot be confused.
        // (What the doomed download then does is §77's business, and the
        // auto-defer test already covers it; waiting it out here would
        // only buy a second copy of that at the cost of minutes against
        // an unreachable host's retry ladder.)
        http(port, "/api?mode=resume&output=json", None);
        let mut started = false;
        for _ in 0..600 {
            let h = http(port, "/api?mode=history&output=json", None);
            assert!(
                !h.contains("give up on posts no server can supply"),
                "a job one server never answered about was given up on\n{h}"
            );
            let st = slot()["status"].as_str().unwrap_or_default().to_string();
            if st == "Downloading" || st == "Fetching" || h.contains(&id) {
                started = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(
            started,
            "the job never started: it must download, not be given up on"
        );
        // Take it away again before it can compete with leg two for the
        // runner (and for the prober, which stands down while anything
        // is downloading). The delete only ASKS - what proves leg one's
        // transfer actually stopped is leg two getting probed at all,
        // which is the barrier below.
        http(port, "/api?mode=pause&output=json", None);
        http(
            port,
            &format!("/api?mode=queue&name=delete&value={id}&output=json"),
            None,
        );

        // Leg two. Same post, same evidence, but the unreachable server
        // is gone from the config, so the fleet is now unanimous.
        std::fs::write(&cfg, &one_server).unwrap();
        http(port, "/api?mode=pause&output=json", None);
        let id2 = upload_nzb(port, &xml, "dead2.nzb");
        // The barrier leg two stands on, WAITED for rather than sampled.
        // Everything after this line assumes the fleet has spoken
        // unanimously about the second job, and only the prober can put
        // that on the record - so if it has not, stop HERE and say so.
        // Falling through on a timeout is what made this test
        // intermittent (16 Aug 2026): the prober stands down while
        // anything is downloading, a delete whose stop signal was
        // swallowed left leg one's doomed transfer running for its whole
        // ladder, and the unprobed job then went down the ordinary
        // download path against the same unreachable host - surfacing
        // two minutes later as "the second job never finished" with an
        // empty history and no hint of why.
        //
        // Bounded far above the 1 s NZBFAST_HEALTH_TICK_SECS this daemon
        // runs at, so a prober that is genuinely wedged still fails.
        let mut ev = serde_json::Value::Null;
        let t = std::time::Instant::now();
        while t.elapsed() < std::time::Duration::from_secs(40) {
            let q = http(port, "/api?mode=queue&output=json", None);
            let v: serde_json::Value = serde_json::from_str(&q).unwrap_or_default();
            let found = v["queue"]["slots"]
                .as_array()
                .and_then(|a| a.iter().find(|s| s["nzo_id"] == id2).cloned())
                .unwrap_or(serde_json::Value::Null);
            ev = found["health"].clone();
            if ev["answered"] == 1 && ev["servers"] == 1 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(
            ev["answered"] == 1 && ev["servers"] == 1,
            "leg two never got its unanimous verdict on the record after \
             {:.1} s - the give-up cannot fire without it, so the job \
             below would download instead of ending. The prober stands \
             down while anything is downloading, so the usual cause is \
             leg one's transfer still running after its delete. \
             health = {ev}",
            t.elapsed().as_secs_f64()
        );
        http(port, "/api?mode=resume&output=json", None);
        let mut h2 = String::new();
        for _ in 0..600 {
            h2 = http(port, "/api?mode=history&output=json", None);
            if h2.contains(&id2) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(h2.contains(&id2), "the second job never finished: {h2}");
        let v: serde_json::Value = serde_json::from_str(&h2).unwrap();
        let row = v["history"]["slots"]
            .as_array()
            .and_then(|a| a.iter().find(|s| s["nzo_id"] == id2).cloned())
            .expect("the second job must be in history");
        let msg = row["fail_message"].as_str().unwrap_or_default();
        assert!(
            msg.starts_with("post is gone"),
            "the give-up must classify as Gone, not as an ordinary short download\n{msg}"
        );
        assert!(
            msg.contains("give up on posts no server can supply"),
            "the failure must name the setting that decided it\n{msg}"
        );
        // Not a byte fetched: this is the entire point of failing early.
        assert_eq!(row["downloaded_bytes"].as_u64().unwrap_or(1), 0, "{row}");
        assert_eq!(row["status"], "Failed", "{row}");
        // The classifier the *arr mapping and the drawer both read.
        // `gone` is what becomes NZBGet's FAILURE/HEALTH ("the post is
        // the problem, go find another release") and what suppresses the
        // Retry button - pinned end to end in tests_grabs.rs.
        assert_eq!(row["fail_kind"], "gone", "{row}");
        // And no automatic retry armed against a post nothing carries.
        assert!(
            row["auto_retry_at"].is_null(),
            "a Gone verdict must not arm an automatic retry\n{row}"
        );
    })
    .await
    .unwrap();
    // Close the daemon, keeping its log for whatever fails below.
    let _log = d.stop();
    let _ = std::fs::remove_dir_all(&dir);
}
