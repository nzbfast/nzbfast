//! Queue-finished actions end to end, against the real binary: an armed
//! shutdown must fire exactly once when the last download finishes, must
//! not fire while anything is still waiting, and must be stoppable from
//! the dashboard before it runs.
//!
//! Every leg here arms a REAL shutdown and runs the daemon with
//! `NZBFAST_FINISH_DRY_RUN=1`, so the trigger is exercised at full
//! strength and the command is the only thing withheld. Testing the
//! script action instead would prove the wiring while leaving the one
//! path that turns a machine off unexercised, which is backwards - the
//! destructive action is precisely the one whose edge needs pinning.
//!
//! A sibling-dir child of daemon.rs (the daemon_chip6 pattern) so the
//! parent stays inside its size-gate baseline. Declared from daemon.rs,
//! so these run in that binary against those fixtures; harness via
//! `super::*`.

use super::*;

/// A mock server plus the NZB that names it: one small file, whole in a
/// few articles, so a download completes in about a second.
async fn one_file_job(dir: &Path, seed: u8) -> (MockServer, String) {
    let data = payload(60_000, seed);
    let mut articles = HashMap::new();
    let segs = make_file_articles("f.bin", &data, 30_000, "ff", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;f.bin&quot; yEnc (1/2)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");
    let _ = dir;
    (srv, xml)
}

/// Two DISTINCT posts on one mock - disjoint articles, different
/// payloads - for the legs that queue a pair. One post added twice
/// stopped being a usable stand-in the day §292 landed: the second add
/// of the same articles is now held as a duplicate of the first
/// (correctly - the user already has that post queued), so a fixture
/// that wants "a paused job AND a job that runs" has to queue two
/// actual posts, exactly as a user would.
async fn two_file_jobs(seed: u8) -> (MockServer, String, String) {
    let mut articles = HashMap::new();
    let wrap = |name: &str, segs: &[(String, u64, u32)]| {
        let mut xml = format!(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/2)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        );
        for (id, bytes, num) in segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n</nzb>\n");
        xml
    };
    let a = make_file_articles(
        "f.bin",
        &payload(60_000, seed),
        30_000,
        "ffa",
        &mut articles,
    );
    let b = make_file_articles(
        "g.bin",
        &payload(60_000, seed.wrapping_add(1)),
        30_000,
        "ffb",
        &mut articles,
    );
    let (xml_a, xml_b) = (wrap("f.bin", &a), wrap("g.bin", &b));
    let srv = MockServer::start(articles, Chaos::default()).await;
    (srv, xml_a, xml_b)
}

/// Spawn a daemon against `dir` with the finish commands withheld.
async fn finish_daemon(dir: &Path, cfg: &Path) -> Daemon {
    let cfg = cfg.to_path_buf();
    let dir = dir.to_path_buf();
    serve(&dir.clone(), move |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_NO_ENRICH", "1")
            // No key: every request here is a plain loopback call, and
            // minting one would only make each of them carry it.
            .env("NZBFAST_OPEN", "1")
            // The whole point of this suite: arm the real thing, run the
            // real trigger, stop one statement short of the OS call.
            .env("NZBFAST_FINISH_DRY_RUN", "1")
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
    .await
}

fn write_config(cfg: &Path, srv_port: u16) {
    std::fs::write(
        cfg,
        format!("{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{srv_port},\"tls\":false,\"connections\":2}}]}}"),
    )
    .unwrap();
}

fn add_nzb(port: u16, xml: &str, extra: &str) -> String {
    let boundary = "----finishb";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"f.nzb\"\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(xml.as_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let added = http(
        port,
        &format!("/api?mode=addfile&output=json{extra}"),
        Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
    );
    added
        .split("\"nzo_ids\":[\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap_or_else(|| panic!("no nzo_id in {added}"))
        .to_string()
}

fn set_cfg(port: u16, name: &str, value: &str) {
    let out = http(
        port,
        &format!("/api?mode=config&name={name}&value={value}&output=json"),
        None,
    );
    assert!(out.contains("\"status\":true"), "setting {name}: {out}");
}

fn log_of(d: &Daemon) -> String {
    d.log()
}

/// Poll the log until `needle` appears, or give up after ~`secs`.
fn wait_log(d: &Daemon, needle: &str, secs: u64) -> String {
    let mut log = String::new();
    for _ in 0..(secs * 10) {
        log = log_of(d);
        if log.contains(needle) {
            return log;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    log
}

/// The headline: a shutdown armed before the download, fired once the
/// queue is genuinely finished - and fired ONCE.
///
/// The "once" half is the whole reason this hangs off `note_queue_idle`'s
/// latch CAS rather than off a poll of the queue. A poller would find the
/// same empty queue on every pass, so the assertion below (still exactly
/// one "fired" line four seconds later, with the queue still empty) is
/// what tells the two designs apart.
#[tokio::test(flavor = "multi_thread")]
async fn shutdown_fires_once_when_the_last_download_finishes() {
    let dir = std::env::temp_dir().join(format!("nzbfast-finfire-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let (srv, xml) = one_file_job(&dir, 3).await;
    let cfg = dir.join("config.json");
    write_config(&cfg, srv.addr.port());
    let d = finish_daemon(&dir, &cfg).await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // A one-second warning: long enough that the countdown is a real
        // state the payload reports, short enough not to pad the suite.
        set_cfg(port, "queue_finished_action", "shutdown");
        set_cfg(port, "queue_finished_delay_secs", "1");

        add_nzb(port, &xml, "");
        let log = wait_log(&d, "queue-finished action shutdown fired", 30);
        assert!(
            log.contains("queue-finished action shutdown armed"),
            "the countdown must be announced before it runs:\n{log}"
        );
        assert!(
            log.contains("NZBFAST_FINISH_DRY_RUN=1, command not run"),
            "the dry run must say it withheld the command:\n{log}"
        );

        // Firing DISARMS it, on disk as well as live - a machine that
        // wakes to the same empty queue must not sleep again, and a
        // restart must not re-arm what has already been spent.
        let cfgj = http(port, "/api?mode=get_config&output=json", None);
        assert!(
            cfgj.contains("\"queue_finished_action\":\"none\""),
            "must disarm itself after firing:\n{cfgj}"
        );
        let saved =
            std::fs::read_to_string(cfg.with_file_name("settings.json")).unwrap_or_default();
        assert!(
            saved.contains("\"queue_finished_action\": \"none\""),
            "the disarm must be persisted:\n{saved}"
        );

        // ...and exactly once. The queue is still empty and still idle;
        // several more lane passes go by and nothing fires again.
        std::thread::sleep(std::time::Duration::from_secs(4));
        let later = log_of(&d);
        assert_eq!(
            later
                .matches("queue-finished action shutdown fired")
                .count(),
            1,
            "one drain, one action:\n{later}"
        );
        // The drain was a real COMPLETION, not a failure that happened to
        // empty the queue. Asked here rather than after the block: `d`
        // owns the child, and it is killed the moment this closure ends.
        assert!(
            http(port, "/api?mode=history&output=json", None).contains("\"Completed\""),
            "the job must have completed:\n{later}"
        );
    })
    .await
    .unwrap();
}

/// A paused download left in the queue holds the action - and does NOT
/// spend the arm, so finishing it later still gets what was asked for.
///
/// `queue.idle` fires here (a paused job does not keep the queue busy, by
/// design), which is exactly why the second, stricter check exists: a
/// machine that powered off over a job the user paused and meant to come
/// back to did the one thing they were not expecting.
#[tokio::test(flavor = "multi_thread")]
async fn a_paused_download_left_in_the_queue_holds_the_shutdown() {
    let dir = std::env::temp_dir().join(format!("nzbfast-finhold-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let (srv, xml_held, xml_runs) = two_file_jobs(5).await;
    let cfg = dir.join("config.json");
    write_config(&cfg, srv.addr.port());
    let d = finish_daemon(&dir, &cfg).await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        set_cfg(port, "queue_finished_action", "shutdown");
        set_cfg(port, "queue_finished_delay_secs", "1");

        // Paused on arrival (SAB's priority -2), and never touched again.
        // A DIFFERENT post from the one that runs: the same post twice
        // would be held as a duplicate (§292) rather than sit paused.
        let held = add_nzb(port, &xml_held, "&priority=-2");
        // ...then a job that runs and finishes, which is what drains the
        // queue and offers the action its edge.
        add_nzb(port, &xml_runs, "");

        let log = wait_log(&d, "queue-finished action (shutdown) not run", 30);
        assert!(
            log.contains("not run: a paused download is still in the queue"),
            "the refusal must name what blocked it:\n{log}"
        );
        assert!(
            !log.contains("queue-finished action shutdown fired"),
            "nothing may fire over a paused job:\n{log}"
        );
        // The arm survives a refusal: the user still wants this when the
        // queue really does finish.
        let cfgj = http(port, "/api?mode=get_config&output=json", None);
        assert!(
            cfgj.contains("\"queue_finished_action\":\"shutdown\""),
            "a refused drain must not spend the arm:\n{cfgj}"
        );

        // Resume the held job. Its completion is a real drain, and now
        // the action fires.
        http(
            port,
            &format!("/api?mode=queue&name=resume&value={held}&output=json"),
            None,
        );
        let log = wait_log(&d, "queue-finished action shutdown fired", 40);
        assert!(
            log.contains("queue-finished action shutdown fired"),
            "the action must still be there for the real drain:\n{log}"
        );
    })
    .await
    .unwrap();
}

/// The countdown is stoppable, and stopping it switches the arm off.
///
/// Also pins the payload the banner is drawn from: `in_secs` counts down
/// while the warning runs and is null once it does not.
#[tokio::test(flavor = "multi_thread")]
async fn the_countdown_can_be_stopped_from_the_dashboard() {
    let dir = std::env::temp_dir().join(format!("nzbfast-fincancel-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let (srv, xml) = one_file_job(&dir, 7).await;
    let cfg = dir.join("config.json");
    write_config(&cfg, srv.addr.port());
    let d = finish_daemon(&dir, &cfg).await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        set_cfg(port, "queue_finished_action", "shutdown");
        // Long enough that the test can reach the cancel with room to
        // spare; the fire path's timing is the other test's subject.
        set_cfg(port, "queue_finished_delay_secs", "120");
        add_nzb(port, &xml, "");

        // Wait for the countdown to be live in the payload the dashboard
        // polls - the banner's own source, not the log.
        let mut q = String::new();
        for _ in 0..400 {
            q = http(port, "/api?mode=queue&output=json", None);
            if q.contains("\"finish_action\"") && !q.contains("\"in_secs\":null") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(
            q.contains("\"armed\":\"shutdown\"") && !q.contains("\"in_secs\":null"),
            "the countdown must ride the queue payload:\n{q}"
        );

        let out = http(
            port,
            "/api?mode=config&name=queue_finished_cancel&value=1&output=json",
            None,
        );
        assert!(out.contains("\"cancelled\":true"), "{out}");
        assert!(out.contains("\"disarmed\":true"), "{out}");

        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(q.contains("\"in_secs\":null"), "countdown gone:\n{q}");
        assert!(q.contains("\"armed\":\"none\""), "and disarmed:\n{q}");

        // Nothing fires afterwards, however long the lane runs.
        std::thread::sleep(std::time::Duration::from_secs(4));
        let log = log_of(&d);
        assert!(
            !log.contains("shutdown fired"),
            "a cancelled countdown must never run:\n{log}"
        );
        assert!(
            log.contains("queue-finished action shutdown cancelled"),
            "and must say it was cancelled:\n{log}"
        );
        // A second press has nothing left to stop and says so honestly.
        let again = http(
            port,
            "/api?mode=config&name=queue_finished_cancel&value=1&output=json",
            None,
        );
        assert!(again.contains("\"cancelled\":false"), "{again}");
    })
    .await
    .unwrap();
}

/// The default install is inert. A daemon that has never been told to do
/// anything at the end of a queue must run a download, drain, and leave
/// the machine alone - with nothing in the log claiming otherwise.
#[tokio::test(flavor = "multi_thread")]
async fn an_unarmed_daemon_does_nothing_at_the_end_of_a_queue() {
    let dir = std::env::temp_dir().join(format!("nzbfast-finoff-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let (srv, xml) = one_file_job(&dir, 11).await;
    let cfg = dir.join("config.json");
    write_config(&cfg, srv.addr.port());
    let d = finish_daemon(&dir, &cfg).await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        add_nzb(port, &xml, "");
        let mut done = false;
        for _ in 0..300 {
            if http(port, "/api?mode=history&output=json", None).contains("\"Completed\"") {
                done = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(done, "the fixture job never completed");
        std::thread::sleep(std::time::Duration::from_secs(4));
        let log = log_of(&d);
        assert!(
            !log.contains("queue-finished action"),
            "an unarmed daemon must say nothing about finish actions:\n{log}"
        );
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(q.contains("\"armed\":\"none\""), "{q}");
        assert!(q.contains("\"in_secs\":null"), "{q}");
    })
    .await
    .unwrap();
}
