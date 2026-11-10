//! TODO 358 item 1 (decision D1): the parallel start sample and the
//! 20 s cap fix, end to end through a real daemon. A child of
//! `daemon_health` so the opt-in give-up's tests sit together; harness
//! via `super::*`.
//!
//! Every mock here refuses an article it does not have only after
//! `missing_delay_ms`, one at a time per connection - the slow 430 of
//! the 13 Oct round (0.47-2.2 s an article on four of five live
//! accounts), scaled down so a suite run stays short. 400 ms is chosen
//! so that the OLD single-connection 64-article pass (25.6 s) cannot
//! finish inside its 20 s ceiling: these tests fail on the code before
//! the fix, not merely run slower.

use super::*;

/// Ghost segments (ids no server holds), posted `age_days` ago.
fn ghost_nzb(tag: &str, n: usize, age_days: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let date = now - age_days * 86_400;
    let mut xml = format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  \
         <file poster=\"x\" date=\"{date}\" subject=\"&quot;{tag}.bin&quot; yEnc (1/{n})\">\n    \
         <groups><group>g</group></groups>\n    <segments>\n"
    );
    for k in 1..=n {
        xml.push_str(&format!(
            "      <segment bytes=\"40000\" number=\"{k}\">{tag}ghost{k}@x</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");
    xml
}

/// The NZB for real segments, posted `age_days` ago.
fn real_nzb(name: &str, segs: &[(String, u64, u32)], age_days: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let date = now - age_days * 86_400;
    let mut xml = format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  \
         <file poster=\"x\" date=\"{date}\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    \
         <groups><group>g</group></groups>\n    <segments>\n",
        segs.len()
    );
    for (id, bytes, num) in segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");
    xml
}

fn servers_json(srvs: &[&MockServer], connections: u32) -> String {
    let rows: Vec<String> = srvs
        .iter()
        .map(|s| {
            format!(
                "{{\"host\":\"{}\",\"port\":{},\"tls\":false,\"connections\":{connections}}}",
                s.addr.ip(),
                s.addr.port()
            )
        })
        .collect();
    format!("{{\"servers\":[{}]}}", rows.join(","))
}

async fn launch(dir: &Path, cfg: &Path, tick: &str) -> Daemon {
    let (dir, cfg, tick) = (dir.to_path_buf(), cfg.to_path_buf(), tick.to_string());
    serve(&dir.clone(), move |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_HEALTH_TICK_SECS", &tick)
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
    .await
}

fn history_row(port: u16, id: &str) -> Option<serde_json::Value> {
    let h = http(port, "/api?mode=history&output=json", None);
    let v: serde_json::Value = serde_json::from_str(&h).ok()?;
    v["history"]["slots"]
        .as_array()
        .and_then(|a| a.iter().find(|s| s["nzo_id"] == id).cloned())
}

fn queue_slot(port: u16, id: &str) -> serde_json::Value {
    let q = http(port, "/api?mode=queue&output=json", None);
    let v: serde_json::Value = serde_json::from_str(&q).unwrap_or_default();
    v["queue"]["slots"]
        .as_array()
        .and_then(|a| a.iter().find(|s| s["nzo_id"] == id).cloned())
        .unwrap_or(serde_json::Value::Null)
}

fn wait_history(port: u16, id: &str, within: std::time::Duration) -> serde_json::Value {
    let t = std::time::Instant::now();
    while t.elapsed() < within {
        if let Some(r) = history_row(port, id) {
            return r;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!(
        "{id} never reached history in {within:?}; queue row: {}",
        queue_slot(port, id)
    );
}

/// The *arr case the whole item exists for: a dead post grabbed onto an
/// IDLE daemon. The prober never gets a look (its tick is pushed out of
/// reach here, and in the field it is 15 s against a 500 ms pick), so
/// before the start sample the give-up had no verdict and the job went
/// the long way round. Now it fails at prestart, as Gone, at full width,
/// before a single BODY - in seconds against two slow-430 servers.
#[tokio::test(flavor = "multi_thread")]
async fn a_dead_post_grabbed_onto_an_idle_daemon_fails_at_start() {
    let dir = std::env::temp_dir().join(format!("nzbfast-startdead-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let slow = || Chaos {
        missing_delay_ms: 400,
        ..Default::default()
    };
    let a = MockServer::start(HashMap::new(), slow()).await;
    let b = MockServer::start(HashMap::new(), slow()).await;
    let cfg = dir.join("config.json");
    std::fs::write(&cfg, servers_json(&[&a, &b], 20)).unwrap();
    let d = launch(&dir, &cfg, "3600").await;
    let port = d.port;
    let (a_log, b_log) = (a.body_log.clone(), b.body_log.clone());

    tokio::task::spawn_blocking(move || {
        let r = http(
            port,
            "/api?mode=config&name=post_health_fail&value=1&output=json",
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let xml = ghost_nzb("dead", 300, 30);
        let t = std::time::Instant::now();
        let id = upload_nzb(port, &xml, "Dead.Show.S01E01.1080p.nzb");
        let row = wait_history(port, &id, std::time::Duration::from_secs(60));
        let took = t.elapsed();
        let msg = row["fail_message"].as_str().unwrap_or_default();
        assert_eq!(row["status"], "Failed", "{row}");
        assert_eq!(row["fail_kind"], "gone", "{row}");
        assert!(msg.starts_with("post is gone"), "{msg}");
        assert!(
            msg.contains("all 64 sampled article(s)"),
            "the verdict must be the full width, never the k=8 shortcut: {msg}"
        );
        assert!(msg.contains("your 2 configured server(s)"), "{msg}");
        assert_eq!(row["downloaded_bytes"].as_u64().unwrap_or(1), 0, "{row}");
        assert!(row["auto_retry_at"].is_null(), "{row}");
        assert!(
            a_log.lock().unwrap().is_empty(),
            "a BODY was spent: {:?}",
            a_log.lock().unwrap()
        );
        assert!(
            b_log.lock().unwrap().is_empty(),
            "a BODY was spent: {:?}",
            b_log.lock().unwrap()
        );
        // k=8 over 8 connections is one 0.4 s refusal per session, and
        // 64 over 19 is four in series (1.6 s): a couple of seconds of
        // probe. The bound is loose for a loaded box, and still far
        // inside what the old single-connection pass could even finish.
        assert!(
            took < std::time::Duration::from_secs(20),
            "time to Failed: {took:?}"
        );
    })
    .await
    .unwrap();
    let _log = d.stop();
}

/// The misfire guard through the real seam: a damaged-but-suppliable
/// post (tv4-dmg60's shape - 60% of the articles missing on one server,
/// every one of them still on the other) must DOWNLOAD and complete with
/// the give-up on. And the start sample must not hold it up: the refusals
/// cost it one slow 430 per session, never an escalation.
#[tokio::test(flavor = "multi_thread")]
async fn a_damaged_but_suppliable_post_downloads_with_the_giveup_on() {
    let dir = std::env::temp_dir().join(format!("nzbfast-startdmg-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let mut articles = HashMap::new();
    let data = payload(200_000, 23);
    let segs = make_file_articles("dmg.bin", &data, 4_000, "dmg", &mut articles);
    let missing: std::collections::HashSet<String> = segs
        .iter()
        .enumerate()
        .filter(|(i, _)| (i * 37) % 100 < 60)
        .map(|(_, (id, _, _))| format!("<{id}>"))
        .collect();
    assert!(
        missing.len() * 2 > segs.len(),
        "the fixture must be badly damaged"
    );
    let a = MockServer::start(
        articles.clone(),
        Chaos {
            missing,
            missing_delay_ms: 400,
            ..Default::default()
        },
    )
    .await;
    let b = MockServer::start(articles, Chaos::default()).await;
    let cfg = dir.join("config.json");
    std::fs::write(&cfg, servers_json(&[&a, &b], 8)).unwrap();
    let d = launch(&dir, &cfg, "3600").await;
    let port = d.port;
    let a_stats = a.stats.clone();

    tokio::task::spawn_blocking(move || {
        let r = http(
            port,
            "/api?mode=config&name=post_health_fail&value=1&output=json",
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let xml = real_nzb("dmg.bin", &segs, 400);
        let id = upload_nzb(port, &xml, "Dmg.Show.S01E01.1080p.nzb");
        let row = wait_history(port, &id, std::time::Duration::from_secs(120));
        assert_eq!(
            row["status"], "Completed",
            "a post every article of which is on some server was not downloaded: {row}"
        );
        // The start sample ran (the post is old enough) and stopped at
        // its k=8 burst: server b answered every article present.
        let n = a_stats.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            (1..=8).contains(&n),
            "the start sample must STAT the k=8 burst and never escalate: {n} STATs"
        );
    })
    .await
    .unwrap();
    let _log = d.stop();
}

/// The verdict is JOURNALED and a restart keeps it - and this is also
/// the cap fix seen from the prober's side.
///
/// Leg one, queue paused: the idle prober samples the dead post, finds
/// its k=8 burst red, and escalates. At 400 ms a refusal its old
/// single-connection 64-wide pass needed 25.6 s against a 20 s ceiling
/// and could never come back unanimous; split over the account's
/// connections it does, and the 64-wide red lands on the queue row (and
/// so in `queue.json`). The daemon is then KILLED.
///
/// Leg two, a fresh process over the same spool: the job is still
/// queued with that verdict, the give-up reads it off the record and
/// fails the job at start WITHOUT A SINGLE NEW STAT - the start sample
/// never ran, because the journal already answered. Leg three, killed
/// and restarted again: the failure, its reason and its class are all
/// still there.
#[tokio::test(flavor = "multi_thread")]
async fn a_journaled_verdict_survives_a_restart_and_fails_the_job_without_a_reprobe() {
    let dir = std::env::temp_dir().join(format!("nzbfast-startjournal-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let srv = MockServer::start(
        HashMap::new(),
        Chaos {
            missing_delay_ms: 400,
            ..Default::default()
        },
    )
    .await;
    let cfg = dir.join("config.json");
    std::fs::write(&cfg, servers_json(&[&srv], 8)).unwrap();
    let stats = srv.stats.clone();
    let body_log = srv.body_log.clone();

    let d = launch(&dir, &cfg, "1").await;
    let port = d.port;
    let id = tokio::task::spawn_blocking(move || {
        let r = http(
            port,
            "/api?mode=config&name=post_health_fail&value=1&output=json",
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        http(port, "/api?mode=pause&output=json", None);
        let id = upload_nzb(port, &ghost_nzb("jrnl", 200, 30), "Jrnl.Show.S01E01.nzb");
        let t = std::time::Instant::now();
        let mut s = serde_json::Value::Null;
        while t.elapsed() < std::time::Duration::from_secs(90) {
            s = queue_slot(port, &id);
            if s["health"]["sampled"] == 64 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        let h = &s["health"];
        assert_eq!(h["sampled"], 64, "the prober never escalated to 64: {s}");
        assert_eq!(
            h["absent"], 64,
            "the escalated pass did not finish on a slow-430 server (the 20 s cap defect): {h}"
        );
        assert_eq!(h["bucket"], "red", "{h}");
        assert_eq!(s["status"], "Queued", "{s}");
        id
    })
    .await
    .unwrap();
    // Give the prober's queue save a moment past the verdict it
    // published, then kill: no clean shutdown, no final save.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let _log1 = d.stop();
    let stats_at_kill = stats.load(std::sync::atomic::Ordering::Relaxed);

    let d = launch(&dir, &cfg, "3600").await;
    let port = d.port;
    let id2 = id.clone();
    let msg = tokio::task::spawn_blocking(move || {
        http(port, "/api?mode=resume&output=json", None);
        let row = wait_history(port, &id2, std::time::Duration::from_secs(60));
        assert_eq!(row["status"], "Failed", "{row}");
        assert_eq!(row["fail_kind"], "gone", "{row}");
        let msg = row["fail_message"].as_str().unwrap_or_default().to_string();
        assert!(msg.contains("all 64 sampled article(s)"), "{msg}");
        msg
    })
    .await
    .unwrap();
    assert_eq!(
        stats.load(std::sync::atomic::Ordering::Relaxed),
        stats_at_kill,
        "the restart re-probed a post whose verdict was already in the journal"
    );
    assert!(body_log.lock().unwrap().is_empty(), "a BODY was spent");
    let _log2 = d.stop();

    let d = launch(&dir, &cfg, "3600").await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        let row = history_row(port, &id).expect("the failed job must still be in history");
        assert_eq!(row["status"], "Failed", "{row}");
        assert_eq!(row["fail_kind"], "gone", "{row}");
        assert_eq!(
            row["fail_message"].as_str().unwrap_or_default(),
            msg,
            "{row}"
        );
    })
    .await
    .unwrap();
    let _log3 = d.stop();
}

/// Retry is the user overruling the give-up, and since the start sample
/// a cleared verdict would no longer stop it re-firing: the next start
/// would re-sample the same dead post and fail the job again seconds
/// after the user asked for it to run. So a retry of a give-up failure
/// keeps the verdict WAIVED, and the retried job takes the ordinary
/// download path - whatever that then concludes, it is not the give-up.
///
/// Also the small-post width rule end to end: 30 articles is fewer than
/// the 64-wide sample, so the wide pass draws all of them, and the whole
/// post sampled unanimous is enough to fail on.
#[tokio::test(flavor = "multi_thread")]
async fn a_retried_giveup_downloads_instead_of_failing_again() {
    let dir = std::env::temp_dir().join(format!("nzbfast-startretry-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let srv = MockServer::start(HashMap::new(), Chaos::default()).await;
    let cfg = dir.join("config.json");
    std::fs::write(&cfg, servers_json(&[&srv], 8)).unwrap();
    let d = launch(&dir, &cfg, "3600").await;
    let port = d.port;
    let body_log = srv.body_log.clone();

    tokio::task::spawn_blocking(move || {
        let r = http(
            port,
            "/api?mode=config&name=post_health_fail&value=1&output=json",
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let id = upload_nzb(port, &ghost_nzb("retry", 30, 30), "Retry.Show.S01E01.nzb");
        let row = wait_history(port, &id, std::time::Duration::from_secs(60));
        let msg = row["fail_message"].as_str().unwrap_or_default();
        assert!(
            msg.contains("give up on posts no server can supply"),
            "{msg}"
        );
        assert!(
            msg.contains("all 30 sampled article(s)"),
            "the whole small post: {msg}"
        );
        assert!(
            body_log.lock().unwrap().is_empty(),
            "the give-up spent a BODY"
        );

        let r = http(
            port,
            &format!("/api?mode=retry&value={id}&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        // Wait for the retried run to END, which it does the long way:
        // the download itself asks for the bodies.
        let t = std::time::Instant::now();
        let mut row = serde_json::Value::Null;
        while t.elapsed() < std::time::Duration::from_secs(120) {
            let asked = !body_log.lock().unwrap().is_empty();
            if let Some(r) = history_row(port, &id).filter(|_| asked) {
                row = r;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(
            !body_log.lock().unwrap().is_empty(),
            "the retried job never downloaded - the give-up fired again: {}",
            queue_slot(port, &id)
        );
        let msg = row["fail_message"].as_str().unwrap_or_default();
        assert!(
            !msg.contains("give up on posts no server can supply"),
            "a retried give-up was given up on again: {msg}"
        );
    })
    .await
    .unwrap();
    let _log = d.stop();
}

/// 9 Nov 2026 sweep: a PAUSE that lands while the start sample runs must
/// stop the job before its pipeline launches. The job is `Downloading`
/// from the pick on, so the pause takes the running-job path - it marks
/// the record suspended and re-fires a wind-down at whatever owns the
/// hub - but nothing owns the hub yet, and the sample's `Pass` arm never
/// looked at the record again, so the pipeline launched over the pause
/// (and downloaded in full when the sample outlasted the wind-down's
/// ~60 s of re-fires). Two servers: one holds every article and answers
/// at once, so the verdict is a Pass; the other holds none and refuses
/// each after 3 s, which holds the burst open long enough to pause into.
#[tokio::test(flavor = "multi_thread")]
async fn a_pause_during_the_start_sample_stops_the_job_before_it_downloads() {
    let dir = std::env::temp_dir().join(format!("nzbfast-startpause-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let mut articles = HashMap::new();
    let data = payload(200_000, 29);
    let segs = make_file_articles("hold.bin", &data, 4_000, "hold", &mut articles);
    let full = MockServer::start(articles, Chaos::default()).await;
    let slow = MockServer::start(
        HashMap::new(),
        Chaos {
            missing_delay_ms: 3_000,
            ..Default::default()
        },
    )
    .await;
    let cfg = dir.join("config.json");
    std::fs::write(&cfg, servers_json(&[&full, &slow], 8)).unwrap();
    let d = launch(&dir, &cfg, "3600").await;
    let port = d.port;
    let (full_log, slow_stats) = (full.body_log.clone(), slow.stats.clone());

    let log = tokio::task::spawn_blocking(move || {
        let r = http(
            port,
            "/api?mode=config&name=post_health_fail&value=1&output=json",
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let xml = real_nzb("hold.bin", &segs, 400);
        let id = upload_nzb(port, &xml, "Hold.Show.S01E01.1080p.nzb");
        // The sample is in flight once the slow server has been asked.
        harness::wait_until(
            "the start sample to reach the slow server",
            std::time::Duration::from_secs(30),
            || slow_stats.load(std::sync::atomic::Ordering::Relaxed) > 0,
        );
        let r = http(
            port,
            &format!("/api?mode=queue&name=pause&value={id}&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        d.wait_for("start sample in");
        // Time for a launch to show, had one happened.
        std::thread::sleep(std::time::Duration::from_secs(3));
        let log = d.log();
        assert_eq!(
            log.matches(" MB eager of ").count(),
            0,
            "the pipeline launched over a pause taken during the start sample\n--- log ---\n{log}"
        );
        assert!(
            full_log.lock().unwrap().is_empty(),
            "a BODY was fetched for a paused job: {:?}",
            full_log.lock().unwrap()
        );
        assert_eq!(
            queue_slot(port, &id)["status"],
            "Paused",
            "the job must sit in the queue Paused\n--- log ---\n{log}"
        );
        // And resuming it downloads it, from where it stood.
        let r = http(
            port,
            &format!("/api?mode=queue&name=resume&value={id}&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let row = wait_history(port, &id, std::time::Duration::from_secs(120));
        assert_eq!(row["status"], "Completed", "{row}");
        d
    })
    .await
    .unwrap();
    let _log = log.stop();
}

/// The same window for a DELETE, which the 9 Nov 2026 sweep suspected of
/// the same defect and which measured clean: the delete takes the row out
/// of the queue, tombstones it and masks its spool copy, so the launch
/// after the sample's `Pass` finds no NZB and fetches nothing, and the
/// tail parks the tombstone. A guard, not a proof of a fix - it passes on
/// the code before the pause half of that sweep's re-check too - pinning
/// that nothing is fetched and the job ends up in neither the queue nor
/// history.
#[tokio::test(flavor = "multi_thread")]
async fn a_delete_during_the_start_sample_never_starts_the_download() {
    let dir = std::env::temp_dir().join(format!("nzbfast-startdel-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let mut articles = HashMap::new();
    let data = payload(200_000, 31);
    let segs = make_file_articles("gone.bin", &data, 4_000, "gone", &mut articles);
    let full = MockServer::start(articles, Chaos::default()).await;
    let slow = MockServer::start(
        HashMap::new(),
        Chaos {
            missing_delay_ms: 3_000,
            ..Default::default()
        },
    )
    .await;
    let cfg = dir.join("config.json");
    std::fs::write(&cfg, servers_json(&[&full, &slow], 8)).unwrap();
    let d = launch(&dir, &cfg, "3600").await;
    let port = d.port;
    let (full_log, slow_stats) = (full.body_log.clone(), slow.stats.clone());

    let d = tokio::task::spawn_blocking(move || {
        let r = http(
            port,
            "/api?mode=config&name=post_health_fail&value=1&output=json",
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let xml = real_nzb("gone.bin", &segs, 400);
        let id = upload_nzb(port, &xml, "Gone.Show.S01E01.1080p.nzb");
        harness::wait_until(
            "the start sample to reach the slow server",
            std::time::Duration::from_secs(30),
            || slow_stats.load(std::sync::atomic::Ordering::Relaxed) > 0,
        );
        let r = http(
            port,
            &format!("/api?mode=queue&name=delete&value={id}&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        d.wait_for("start sample in");
        std::thread::sleep(std::time::Duration::from_secs(3));
        let log = d.log();
        assert_eq!(
            log.matches(" MB eager of ").count(),
            0,
            "the pipeline launched for a job deleted during the start sample\n--- log ---\n{log}"
        );
        assert!(
            full_log.lock().unwrap().is_empty(),
            "a BODY was fetched for a deleted job: {:?}",
            full_log.lock().unwrap()
        );
        assert!(queue_slot(port, &id).is_null(), "still queued\n{log}");
        assert!(
            history_row(port, &id).is_none(),
            "filed into history\n{log}"
        );
        d
    })
    .await
    .unwrap();
    let _log = d.stop();
}
