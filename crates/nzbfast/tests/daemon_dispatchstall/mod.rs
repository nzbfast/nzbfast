//! TODO 358 item 3 (Weaver parity): the dispatch-stall watchdog, end to
//! end through the real daemon.
//!
//! The provider here ACCEPTS and then goes silent: `Chaos::mute_after_bodies`
//! serves each connection a few bodies and then never answers that
//! connection again, holding the socket open in dead air - the CGNAT
//! eviction shape, and the one a socket count reads as healthy. A fresh
//! connection is served again, which is exactly what makes a dispatch
//! reset (a fresh fleet over the journal) the thing that recovers it.
//!
//! The pool's own ways out of dead air are switched off for these legs -
//! the adaptive pre-byte budget, hedging, tail fan-out and the slope
//! recycle, plus a ten-minute read bound - so the ONLY thing that can
//! move a stalled run inside a test's budget is the watchdog under test.
//! That is what lets each leg's assertion mean what it says rather than
//! "something recovered it".
//!
//! Timed, so it lives in the daemon binary's serial group (invariant 4),
//! with short test-only thresholds: the reset at a few seconds, the
//! engine's deadlock window a few seconds beyond it.
//!
//! A sibling-dir child module of the daemon target, like every other
//! here, so it rides the standard daemon gate and keeps daemon.rs under
//! its size-gate ceiling.

use super::*;

/// The reset line `dispatch_stall.rs` writes, and its second-stage line.
const RESET: &str = "Resetting dispatch";
const AGAIN: &str = "not resetting twice";
/// The engine deadlock watchdog's abort, which is the second stage.
const ENGINE_ABORT: &str = "download stalled";

/// A mute-after-N provider with `n_articles` 20 kB articles behind it,
/// and the NZB that names them.
async fn mute_fixture(
    tag: &str,
    n_articles: usize,
    mute_after: u64,
) -> (MockServer, String, Vec<u8>) {
    let data = payloads::unique_payload(n_articles * 20_000, 0x0358_0003 ^ n_articles as u64);
    let mut articles = HashMap::new();
    let segs = make_file_articles(&format!("{tag}.bin"), &data, 20_000, tag, &mut articles);
    assert_eq!(segs.len(), n_articles);
    let srv = MockServer::start(
        articles,
        Chaos {
            mute_after_bodies: mute_after,
            ..Chaos::default()
        },
    )
    .await;
    let mut xml = format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  \
         <file poster=\"x\" date=\"0\" subject=\"&quot;{tag}.bin&quot; yEnc (1/{n})\">\n    \
         <groups><group>g</group></groups>\n    <segments>\n",
        n = segs.len()
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");
    (srv, xml, data)
}

/// A daemon on one server at two connections, with the pool's own
/// dead-air escapes off and the two watchdog windows given.
async fn mute_daemon(dir: &Path, srv: &MockServer, reset_secs: u64, abort_secs: u64) -> Daemon {
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
    let (reset, abort) = (reset_secs.to_string(), abort_secs.to_string());
    serve(dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_DISPATCH_RESET_SECS", &reset)
            .env("NZBFAST_STALL_ABORT_SECS", &abort)
            // The pool's own ways out of dead air, all off: see the
            // module header for why each must be.
            .env("NZBFAST_READ_TIMEOUT_SECS", "600")
            .env("NZBFAST_ADAPTIVE_TIMEOUT", "0")
            .env("NZBFAST_HEDGE", "0")
            .env("NZBFAST_TAIL_FANOUT", "0")
            .env("NZBFAST_RECYCLE_SLOPE", "0")
            // A 1 s watchdog tick (window / 6) so the reset lands within
            // a second of its threshold. One job in the queue, so no
            // demotion arm can fire whatever the window.
            .env("NZBFAST_DEFER_WINDOW_SECS", "6")
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

fn wait_history(port: u16, nzo: &str, within: std::time::Duration) -> serde_json::Value {
    let t0 = std::time::Instant::now();
    loop {
        let h = http(port, "/api?mode=history&output=json", None);
        if history_has(&h, nzo) {
            return history_slot(&h, nzo);
        }
        assert!(
            t0.elapsed() < within,
            "{nzo} never reached history within {within:?}\n{h}"
        );
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

fn wait_downloading(port: u16, nzo: &str) {
    harness::wait_until(
        "the job to start downloading",
        std::time::Duration::from_secs(30),
        || {
            queue_slot(&http(port, "/api?mode=queue&output=json", None), nzo)["status"]
                == "Downloading"
        },
    );
}

/// STAGE ONE RECOVERS. A provider that goes silent on every connection
/// after a handful of bodies stalls the run with articles still queued
/// and sockets still open; the watchdog resets dispatch, the fresh fleet
/// is served again, and the job COMPLETES byte-exact - well inside a
/// read bound of ten minutes and with the engine's abort never reached.
///
/// Without the reset this job cannot finish inside the test's budget at
/// all: the pool would wait the 600 s read bound on its dead sessions,
/// or the engine would abort it at 60 s and fail it. So `Completed`
/// here is the reset's doing and nothing else's.
#[tokio::test(flavor = "multi_thread")]
async fn a_provider_that_goes_mute_is_reset_and_the_job_completes() {
    let dir = std::env::temp_dir().join(format!("nzbfast-dstall-ok-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    // 24 articles, 8 bodies per connection before it goes mute, 2
    // connections: the first fleet lands about 16, the reset fleet has
    // room for 16 more - the rest plus whatever was in dead air.
    let (srv, xml, data) = mute_fixture("mute", 24, 8).await;
    let d = mute_daemon(&dir, &srv, 4, 60).await;
    let port = d.port;
    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        let nzo = upload_nzb(port, &xml, "Mute.Recover.nzb");
        let t0 = std::time::Instant::now();
        let slot = wait_history(port, &nzo, std::time::Duration::from_secs(50));
        let log = d.log();
        assert_eq!(
            slot["status"], "Completed",
            "the reset fleet should have finished the job\n{slot}\n--- log ---\n{log}"
        );
        assert_eq!(
            log.matches(RESET).count(),
            1,
            "exactly one dispatch reset expected\n--- log ---\n{log}"
        );
        assert!(
            !log.contains(ENGINE_ABORT),
            "the engine's abort fired - the reset did not recover the run\n--- log ---\n{log}"
        );
        // Two runs: the stalled one and the reset one. The engine's
        // launch banner is written once per run.
        assert_eq!(
            log.matches(" MB eager of ").count(),
            2,
            "the reset should have started exactly one fresh run\n--- log ---\n{log}"
        );
        // Back in the queue where it stood, never through history.
        assert!(
            log.contains("parked back in the queue"),
            "the reset must re-queue through the suspended arm\n--- log ---\n{log}"
        );
        eprintln!("recovered in {:?}", t0.elapsed());
        assert_eq!(
            std::fs::read(dir2.join("complete/Mute.Recover/mute.bin")).unwrap(),
            data,
            "the recovered output is not byte-identical"
        );
    })
    .await
    .unwrap();
    // The provider served more than the first fleet could ever reach.
    let served = srv.served.load(std::sync::atomic::Ordering::Relaxed);
    assert!(served >= 24, "only {served} bodies served");
}

/// FORCE IS RESET TOO (9 Nov 2026). The same mute provider and the same
/// recovery, for a Force-priority job running through a queue pause -
/// the one kind of job a pause's wind-down spares. The reset used to go
/// through that same wind-down, so for a Force job it marked nothing and
/// stopped nothing: the watchdog spent the attempt's one reset, logged
/// "Resetting dispatch" and a "keeps downloading ... queue is paused"
/// line, and the run sat in dead air until the engine's abort failed it.
/// A reset is not a pause, so it must reach Force, and the job must
/// complete exactly as the ordinary-priority leg above does.
#[tokio::test(flavor = "multi_thread")]
async fn a_force_job_that_goes_mute_is_reset_too() {
    let dir = std::env::temp_dir().join(format!("nzbfast-dstall-force-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let (srv, xml, data) = mute_fixture("force", 24, 8).await;
    let d = mute_daemon(&dir, &srv, 4, 60).await;
    let port = d.port;
    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        // Queue paused first, so the job can only run as Force: what
        // starts it is the priority, which is the exemption under test.
        let r = http(port, "/api?mode=pause&output=json", None);
        assert!(r.contains("\"status\":true"), "{r}");
        let nzo = upload_nzb(port, &xml, "Mute.Force.nzb");
        let r = http(
            port,
            &format!("/api?mode=queue&name=priority&value={nzo}&value2=2&output=json"),
            None,
        );
        assert!(!r.contains("\"status\":false"), "{r}");
        let slot = wait_history(port, &nzo, std::time::Duration::from_secs(50));
        let log = d.log();
        assert_eq!(
            slot["status"], "Completed",
            "the reset must reach a Force job and its fresh fleet finish it\n{slot}\n--- log ---\n{log}"
        );
        assert_eq!(
            log.matches(RESET).count(),
            1,
            "exactly one dispatch reset expected\n--- log ---\n{log}"
        );
        assert!(
            !log.contains("keeps downloading"),
            "the reset is not a pause and must not be reported as one\n--- log ---\n{log}"
        );
        assert!(
            !log.contains(ENGINE_ABORT),
            "the engine's abort fired - the reset did not recover the run\n--- log ---\n{log}"
        );
        assert_eq!(
            log.matches(" MB eager of ").count(),
            2,
            "the reset should have started exactly one fresh run\n--- log ---\n{log}"
        );
        assert!(
            log.contains("parked back in the queue"),
            "the reset must re-queue through the suspended arm\n--- log ---\n{log}"
        );
        assert_eq!(
            std::fs::read(dir2.join("complete/Mute.Force/force.bin")).unwrap(),
            data,
            "the recovered output is not byte-identical"
        );
    })
    .await
    .unwrap();
}

/// STAGE TWO BOOKS THE REST MISSING. The same provider, but a post far
/// bigger than two fleets' worth of bodies: the reset fleet lands its
/// share and goes mute too. The watchdog must NOT reset a second time,
/// and the engine's deadlock watchdog then aborts the pool and books
/// what is left as missing through the normal tail, so the job reaches
/// a TERMINAL history row - Failed here, there being no parity to
/// repair from - instead of sitting at 0 B/s for ever.
#[tokio::test(flavor = "multi_thread")]
async fn a_run_that_stalls_again_after_its_reset_is_booked_missing() {
    let dir = std::env::temp_dir().join(format!("nzbfast-dstall-two-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let (srv, xml, _) = mute_fixture("twice", 80, 8).await;
    let d = mute_daemon(&dir, &srv, 4, 12).await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        let nzo = upload_nzb(port, &xml, "Mute.Twice.nzb");
        let slot = wait_history(port, &nzo, std::time::Duration::from_secs(90));
        let log = d.log();
        assert_eq!(
            slot["status"], "Failed",
            "a twice-stalled run with no parity must end Failed\n{slot}\n--- log ---\n{log}"
        );
        assert_eq!(
            log.matches(RESET).count(),
            1,
            "the reset is once per attempt\n--- log ---\n{log}"
        );
        assert!(
            log.contains(AGAIN),
            "the second stall must be named as the second stage\n--- log ---\n{log}"
        );
        assert!(
            log.contains(ENGINE_ABORT),
            "the engine's deadlock watchdog is what books the rest missing\n--- log ---\n{log}"
        );
        // Ordered: reset, then the second stall, then the abort.
        let (a, b, c) = (
            log.find(RESET).unwrap(),
            log.find(AGAIN).unwrap(),
            log.rfind(ENGINE_ABORT).unwrap(),
        );
        assert!(a < b && b < c, "out of order ({a}, {b}, {c})\n{log}");
    })
    .await
    .unwrap();
}

/// NEVER ON A DELIBERATE BACKOFF. A provider whose every dial fails is
/// the shape Weaver's literal rule (queued work, no connection) fires
/// on, and here it must not: the pool is riding its own bounce ladder,
/// `down_since` names the outage, and a reset would only redial into it.
/// The outage outlasts three reset windows, then lifts, and the job
/// completes with no reset anywhere in the log.
#[tokio::test(flavor = "multi_thread")]
async fn a_provider_in_a_dial_backoff_is_never_reset() {
    let dir = std::env::temp_dir().join(format!("nzbfast-dstall-down-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let data = payloads::unique_payload(200_000, 0x0358_0004);
    let mut articles = HashMap::new();
    let segs = make_file_articles("down.bin", &data, 20_000, "dn", &mut articles);
    let srv = MockServer::start(
        articles,
        Chaos {
            outage: true,
            ..Chaos::default()
        },
    )
    .await;
    let outage = srv.outage_control();
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  \
         <file poster=\"x\" date=\"0\" subject=\"&quot;down.bin&quot; yEnc (1/10)\">\n    \
         <groups><group>g</group></groups>\n    <segments>\n",
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");
    let d = mute_daemon(&dir, &srv, 3, 120).await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        let nzo = upload_nzb(port, &xml, "Down.Backoff.nzb");
        wait_downloading(port, &nzo);
        // Three reset windows and more, with every dial failing.
        std::thread::sleep(std::time::Duration::from_secs(10));
        let during = d.log();
        assert!(
            !during.contains(RESET),
            "a dial backoff was reset\n--- log ---\n{during}"
        );
        outage.end_outage();
        let slot = wait_history(port, &nzo, std::time::Duration::from_secs(120));
        let log = d.log();
        assert_eq!(slot["status"], "Completed", "{slot}\n--- log ---\n{log}");
        assert!(
            !log.contains(RESET),
            "a dial backoff was reset\n--- log ---\n{log}"
        );
    })
    .await
    .unwrap();
}

/// NEVER WHILE PAUSED OR OFFLINE, AND THE CLOCK RESTARTS. The mute
/// provider again, so every run stalls within a second of starting.
/// Paused for three reset windows: no reset. Resumed and taken offline
/// for three more: no reset. Back online: the stall is a fresh episode,
/// and the reset now fires - which is what proves the watchdog was live
/// the whole time and that the idle spells restarted its clock rather
/// than being counted towards it.
///
/// What this leg does NOT pin on its own: a pause and offline both wind
/// the run off the hub, so the watchdog has no run to read while they
/// last, and the leg stays green with the `Idle` arms for them deleted
/// (checked by hand, 9 Nov 2026). The arms are for the window between
/// the flag and the wind-down landing; their teeth are the unit tests
/// in `nzbfast-tasks/src/tasks/dispatch_stall_tests.rs`. The backoff leg
/// above is the one that reds when its arm goes.
#[tokio::test(flavor = "multi_thread")]
async fn a_paused_or_offline_stall_is_never_reset() {
    let dir = std::env::temp_dir().join(format!("nzbfast-dstall-idle-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let (srv, xml, _) = mute_fixture("idle", 200, 4).await;
    let d = mute_daemon(&dir, &srv, 5, 120).await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        let nzo = upload_nzb(port, &xml, "Mute.Idle.nzb");
        wait_downloading(port, &nzo);
        let r = http(port, "/api?mode=pause&output=json", None);
        assert!(r.contains("\"status\":true"), "{r}");
        std::thread::sleep(std::time::Duration::from_secs(16));
        let paused = d.log();
        assert!(!paused.contains(RESET), "reset while paused\n{paused}");

        let r = http(port, "/api?mode=resume&output=json", None);
        assert!(r.contains("\"status\":true"), "{r}");
        wait_downloading(port, &nzo);
        let r = http(port, "/api?mode=offline&output=json", None);
        assert!(r.contains("\"offline\":true"), "{r}");
        std::thread::sleep(std::time::Duration::from_secs(16));
        let offline = d.log();
        assert!(!offline.contains(RESET), "reset while offline\n{offline}");

        let r = http(port, "/api?mode=online&output=json", None);
        assert!(r.contains("\"offline\":false"), "{r}");
        http(port, "/api?mode=resume&output=json", None);
        // The positive control: the same stall, no idle state, resets.
        d.wait_for(RESET);
    })
    .await
    .unwrap();
}
