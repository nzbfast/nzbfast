//! The single-fault provider rigs: one server misbehaving in exactly
//! one way, end to end through the mock, asserting that the run still
//! ends HONESTLY and FAST. A ghost capacity cap, a total outage and its
//! paced prober, three shapes of mute session, a desynced pipeline, a
//! brownout that heals, a mid-job takedown, and the auth blip that is
//! terminal by design.
//!
//! NOT `pool/fault_rigs.rs`, which is the other direction: everything
//! there runs MORE THAN ONE fault at a time and reads the per-index
//! gauges for it. Here the point of each leg is that the fault is
//! singular, so the client's answer to it is unambiguous.
//!
//! Out of `unit_tests.rs` under the size gate (TODO 106) on 31 Aug
//! 2026, the same way and for the same reason as its four siblings -
//! that file was 41 lines from its 3,000 ceiling, which is one test, in
//! the most actively edited area of the tree. Moved VERBATIM: these
//! rigs share none of the parent's helpers (`server`, `fresh`, `work`),
//! so the whole cost of the move is the two `use` lines below, and the
//! bodies are byte-identical to what stood in the parent.

use super::super::*;
use crate::config::ServerConfig;
use crate::mock::{Chaos, MockServer, make_file_articles};

// The five rigs below moved verbatim from pool.rs's inline `tests`
// mod (6 Aug): the resilience-chip landings regrew pool.rs past its
// size-gate entry, and the gate's rule is that test code moves into
// a child module. Self-contained rigs only - they use the mock and
// `super::*`, none of the inline mod's shared helpers.
/// Issue #16, both halves: a restart's ghost sessions hold the
/// account cap for a while (every dial bounces off the capacity
/// refusal), then the lease expires. The fleet must SURVIVE the
/// window - the old ladder retired every worker in ~5 bounces and
/// failed the job inside it - and it must come back at full width
/// when the window clears, not crawl the rest of the job on the
/// lone prober. Margins are structural: completion inside the
/// bound needs the parked fleet back (one connection cannot move
/// the corpus in time), and the pre-fix behaviour is a hard job
/// failure, not a slow number.
#[tokio::test(flavor = "multi_thread")]
async fn cap_ghost_window_parks_the_fleet_then_rejoins() {
    use crate::mock::{Chaos, MockServer, Throttle};
    let data: Vec<u8> = (0..1_200_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("gw.bin", &data, 20_000, "gw", &mut articles);
    let srv = MockServer::start(
        articles,
        Chaos {
            cap_ghost_ms: 1_500,
            throttle: Throttle {
                per_conn_bps: 100_000,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    let mut server = srv.server_config();
    server.username = Some("u".into());
    server.password = Some("p".into());
    const CONNS: usize = 6;
    let cfg = PoolConfig {
        connections: CONNS,
        ramp_delay: Duration::ZERO,
        connect_backoff: Duration::from_millis(100),
        ..Default::default()
    };
    let ids: Vec<String> = segs.iter().map(|(id, _, _)| format!("<{id}>")).collect();
    let reqs: Vec<ArticleReq> = ids.iter().cloned().map(ArticleReq::fresh).collect();
    let (tx, mut rx) = mpsc::channel(256);
    let t0 = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(30),
        fetch_all_multi(&[(server, cfg)], reqs, tx),
    )
    .await
    .expect("run hung on the ghost-cap window");
    let wall = t0.elapsed();
    let (mut done, mut other) = (0usize, 0usize);
    while let Ok(o) = rx.try_recv() {
        match o {
            FetchOutcome::Done { .. } => done += 1,
            _ => other += 1,
        }
    }
    assert_eq!(
        done,
        ids.len(),
        "articles failed across a 1.5 s ghost window ({other} non-Done outcomes)"
    );
    // 1.2 MB at 100 KB/s per connection: the full fleet clears it
    // in ~2 s after the window, the lone prober would need ~12 s.
    // 10 s = window + full-width finish + generous suite-load
    // slack, still far under the crawl.
    assert!(
        wall < Duration::from_secs(10),
        "fleet did not rejoin after the ghost window cleared ({wall:?})"
    );
}

/// The outage keeper: a transient TOTAL outage (wifi drop, VPN
/// reconnect, router reboot) shows up as hard connect failures -
/// every accepted connection dies before the greeting, nothing to
/// classify. The old ladder retired every worker after
/// `max_connect_attempts` and failed or stranded the whole job
/// inside the window; the keeper parks the fleet behind one paced
/// prober (the issue #16 machinery) and rejoins at full width on
/// the first successful connect. Same margins as the ghost-cap
/// twin above: completion inside the bound needs the parked fleet
/// back, and the pre-fix behaviour is a hard job failure.
#[tokio::test(flavor = "multi_thread")]
async fn hard_outage_window_parks_the_fleet_then_rejoins() {
    use crate::mock::{Chaos, MockServer, Throttle};
    let data: Vec<u8> = (0..1_200_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("ow.bin", &data, 20_000, "ow", &mut articles);
    let srv = MockServer::start(
        articles,
        Chaos {
            refuse_connect_ms: 1_500,
            throttle: Throttle {
                per_conn_bps: 100_000,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    let server = srv.server_config();
    const CONNS: usize = 6;
    // A tight ladder so the fleet exhausts its connect attempts and
    // parks WELL INSIDE the 1.5 s window - the pre-fix behaviour
    // (every worker retired for good) is what this must rule out.
    let cfg = PoolConfig {
        connections: CONNS,
        ramp_delay: Duration::ZERO,
        connect_backoff: Duration::from_millis(50),
        max_connect_attempts: 3,
        ..Default::default()
    };
    let ids: Vec<String> = segs.iter().map(|(id, _, _)| format!("<{id}>")).collect();
    let reqs: Vec<ArticleReq> = ids.iter().cloned().map(ArticleReq::fresh).collect();
    let (tx, mut rx) = mpsc::channel(256);
    let t0 = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(30),
        fetch_all_multi(&[(server, cfg)], reqs, tx),
    )
    .await
    .expect("run hung on the outage window");
    let wall = t0.elapsed();
    let (mut done, mut other) = (0usize, 0usize);
    while let Ok(o) = rx.try_recv() {
        match o {
            FetchOutcome::Done { .. } => done += 1,
            _ => other += 1,
        }
    }
    assert_eq!(
        done,
        ids.len(),
        "articles failed across a 1.5 s hard outage ({other} non-Done outcomes)"
    );
    // 1.2 MB at 100 KB/s per connection: the full fleet clears it
    // in ~2 s after the window, the lone prober would need ~12 s.
    // 10 s = window + full-width finish + generous suite-load
    // slack, still far under the crawl.
    assert!(
        wall < Duration::from_secs(10),
        "fleet did not rejoin after the outage cleared ({wall:?})"
    );
}

/// Codex 7 Aug M1: during a from-the-start outage the prober's paced
/// bounce ladder decodes nothing and resolves nothing, so none of the
/// stall watchdog's three signals moved and its 180 s default aborted
/// jobs squarely inside the ladder's promised ~10 min horizon. Each
/// bounce now ticks the `deferred` liveness counter - prove it climbs
/// DURING the refuse window, before anything resolves.
#[tokio::test(flavor = "multi_thread")]
async fn outage_prober_bounces_tick_watchdog_liveness() {
    use crate::mock::{Chaos, MockServer};
    let data: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("lv.bin", &data, 20_000, "lv", &mut articles);
    let srv = MockServer::start(
        articles,
        Chaos {
            refuse_connect_ms: 2_500,
            ..Default::default()
        },
    )
    .await;
    let cfg = PoolConfig {
        connections: 3,
        ramp_delay: Duration::ZERO,
        connect_backoff: Duration::from_millis(50),
        max_connect_attempts: 3,
        ..Default::default()
    };
    let reqs: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    let qc = std::sync::Arc::new(QueueControl::default());
    let (tx, mut rx) = mpsc::channel(64);
    let run = {
        let qc = qc.clone();
        let server = srv.server_config();
        tokio::spawn(
            async move { fetch_all_multi_ctl(&[(server, cfg)], reqs, tx, Some(&qc)).await },
        )
    };
    // Sample liveness inside the outage window: the fleet parks within
    // a few hundred ms, then only the prober moves. Its bounces must
    // read as life on the counter the watchdog polls.
    let mut ticked = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if qc.deferred().unwrap_or(0) > 0 {
            ticked = true;
            break;
        }
    }
    assert!(
        ticked,
        "prober bounces left the watchdog's liveness counter frozen - \
         a 180 s watchdog would abort inside the recovery ladder"
    );
    tokio::time::timeout(Duration::from_secs(30), run)
        .await
        .expect("run hung on the outage window")
        .expect("pool task panicked");
    let mut done = 0usize;
    while let Ok(o) = rx.try_recv() {
        if matches!(o, FetchOutcome::Done { .. }) {
            done += 1;
        }
    }
    assert_eq!(
        done,
        segs.len(),
        "the job must still complete after recovery"
    );
}

#[tokio::test]
async fn mute_quit_server_cannot_hang_a_finished_run() {
    // Regression (the 190 GB exit-path hang): a provider that swallows
    // QUIT - TCP up, no goodbye - parked the worker's unbounded goodbye
    // read forever, and the fleet join with it, AFTER every byte was on
    // disk. quit() is now hard-bounded, so the run must return alone.
    use crate::mock::{Chaos, MockServer, make_file_articles};
    let mut articles = std::collections::HashMap::new();
    let payload: Vec<u8> = (0..40_000u32).map(|i| i as u8).collect();
    make_file_articles("f.bin", &payload, 8_000, "mq", &mut articles);
    let n = articles.len();
    let srv = MockServer::start(
        articles.clone(),
        Chaos {
            mute_quit: true,
            ..Default::default()
        },
    )
    .await;
    let cfg = PoolConfig {
        connections: 3,
        ramp_delay: Duration::ZERO,
        ..Default::default()
    };
    let reqs: Vec<ArticleReq> = articles
        .keys()
        .map(|id| ArticleReq::fresh(id.clone()))
        .collect();
    let (tx, mut rx) = mpsc::channel(64);
    let t0 = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(20),
        fetch_all_multi(&[(srv.server_config(), cfg)], reqs, tx),
    )
    .await
    .expect("run hung on a mute-QUIT server");
    // Well under EXIT_GRACE: the bounded quit alone frees the join.
    assert!(
        t0.elapsed() < Duration::from_secs(4),
        "took {:?}",
        t0.elapsed()
    );
    let mut done = 0;
    while let Ok(o) = rx.try_recv() {
        if matches!(o, FetchOutcome::Done { .. }) {
            done += 1;
        }
    }
    assert_eq!(done, n);
}

#[tokio::test]
async fn mute_greeting_straggler_does_not_hold_a_finished_run() {
    // §35: a server that accepts and never greets parks its worker
    // inside the dial. This used to cost the run a full EXIT_GRACE -
    // join_fleet's backstop was the ONLY thing that ended it, because
    // the dial itself never watched the run. Measured on the farm at
    // 5.0 s added to a 1.1 s job, on every job, for as long as the
    // unreachable entry stayed in the config. The dial now races the
    // finish, so the straggler leaves with everyone else and the
    // grace window is never entered.
    use crate::mock::{Chaos, MockServer, make_file_articles};
    let mut articles = std::collections::HashMap::new();
    let payload: Vec<u8> = (0..40_000u32).map(|i| (i * 7) as u8).collect();
    make_file_articles("g.bin", &payload, 8_000, "mg", &mut articles);
    let n = articles.len();
    let healthy = MockServer::start(articles.clone(), Chaos::default()).await;
    let mute = MockServer::start(
        std::collections::HashMap::new(),
        Chaos {
            mute_greeting: true,
            ..Default::default()
        },
    )
    .await;
    let fast = PoolConfig {
        connections: 2,
        ramp_delay: Duration::ZERO,
        ..Default::default()
    };
    let one = PoolConfig {
        connections: 1,
        ramp_delay: Duration::ZERO,
        ..Default::default()
    };
    let reqs: Vec<ArticleReq> = articles
        .keys()
        .map(|id| ArticleReq::fresh(id.clone()))
        .collect();
    let (tx, mut rx) = mpsc::channel(64);
    let t0 = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(30),
        fetch_all_multi(
            &[(healthy.server_config(), fast), (mute.server_config(), one)],
            reqs,
            tx,
        ),
    )
    .await
    .expect("run hung on a never-greeting server");
    let el = t0.elapsed();
    // Comfortably inside the grace window, not at the end of it: the
    // straggler is released by the finish, not abandoned by the join.
    assert!(
        el < EXIT_GRACE,
        "run waited out the dial of a server nobody needed: {el:?}"
    );
    let mut done = 0;
    while let Ok(o) = rx.try_recv() {
        if matches!(o, FetchOutcome::Done { .. }) {
            done += 1;
        }
    }
    assert_eq!(done, n);
}

/// §35, reached through the WARM path instead of the dial.
///
/// Claiming a parked connection validates it with a DATE round-trip
/// bounded by `warmpool::VALIDATE_TIMEOUT` - 8 s, against EXIT_GRACE's
/// 5 s. A worker validating a peer that has gone mute therefore could
/// not return before `join_fleet` gave up on it, so the run paid the
/// whole grace window exactly as an unanswered SYN used to make it.
/// Latent while the warm pool ships off by default, which is the
/// reason to pin it now: TODO 36 turns it on per server.
#[tokio::test(flavor = "multi_thread")]
async fn a_mute_parked_connection_does_not_hold_a_finished_run() {
    use crate::mock::{Chaos, MockServer, make_file_articles};
    // Greets, then never another word, every socket held open with no
    // RST or FIN - the shape a CGNAT idle eviction leaves behind, and
    // the one DATE validation exists to catch. Blocking std sockets on
    // their own thread so the peer keeps working regardless of what
    // the async runtime is doing.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        use std::io::Write as _;
        let mut held = Vec::new();
        while let Ok((mut s, _)) = listener.accept() {
            let _ = s.write_all(b"200 mock ready\r\n");
            let _ = s.flush();
            held.push(s);
        }
    });
    let mute = ServerConfig {
        host: addr.ip().to_string(),
        port: addr.port(),
        tls: false,
        username: None,
        password: None,
        connections: 1,
        pin_connections: false,
        rcvbuf: None,
        level: 0,
        group: None,
        retention_days: 0,
        block_bytes: None,
        block_account: false,
        bind_ip: None,
        socks5: None,
        enabled: true,
        warm_pool: false,
        idle_release_secs: None,
        idle_keep: None,
        max_source_ips: None,
        address_family: Default::default(),
        tls_hostname: None,
        warm_reserve: None,
    };

    let mut articles = std::collections::HashMap::new();
    let payload: Vec<u8> = (0..40_000u32).map(|i| (i * 3) as u8).collect();
    make_file_articles("w.bin", &payload, 8_000, "wp", &mut articles);
    let n = articles.len();
    let healthy = MockServer::start(articles.clone(), Chaos::default()).await;

    // Park a live connection to the mute peer, exactly as the previous
    // job in a queue would have left one.
    let warm = crate::warmpool::WarmPool::new(crate::warmpool::DEFAULT_MAX_IDLE, 4);
    let (c, _) = Connection::connect(&mute).await.expect("greeting");
    warm.give(&mute, c).await;
    assert_eq!(
        warm.idle_count().await,
        1,
        "the claim must have something to claim"
    );

    let fast = PoolConfig {
        connections: 2,
        ramp_delay: Duration::ZERO,
        ..Default::default()
    };
    let warmed = PoolConfig {
        connections: 1,
        ramp_delay: Duration::ZERO,
        warm: Some(warm.clone()),
        ..Default::default()
    };
    let reqs: Vec<ArticleReq> = articles
        .keys()
        .map(|id| ArticleReq::fresh(id.clone()))
        .collect();
    let (tx, mut rx) = mpsc::channel(64);
    let t0 = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(30),
        fetch_all_multi(&[(healthy.server_config(), fast), (mute, warmed)], reqs, tx),
    )
    .await
    .expect("run hung claiming a parked connection from a mute peer");
    let el = t0.elapsed();
    assert!(
        el < EXIT_GRACE,
        "run waited out the validation of a connection nobody needed: {el:?}"
    );
    let mut done = 0;
    while let Ok(o) = rx.try_recv() {
        if matches!(o, FetchOutcome::Done { .. }) {
            done += 1;
        }
    }
    assert_eq!(
        done, n,
        "the healthy server still had to deliver every article"
    );
}

// Moved verbatim from pool/rig_tests.rs (6 Aug, size-gate): its own
// baseline had no room for the desync rig. Deterministic, not a
// wall-clock payout leg, so it belongs with the unit rigs anyway.
/// Desync (echoed-id verification): the mock silently withholds every
/// Nth BODY response while consuming the request, so every later
/// response on that connection answers one pipeline slot ahead of
/// what positional attribution assumes. Without the echoed-id check
/// each shifted 222 is filed under the FRONT article - a fully valid
/// body for the wrong id, whose own pcrc32 passes - and the job
/// "completes" corrupt, with the skipped article's real bytes never
/// delivered by anyone. With the check, the first shifted response
/// reads as a session-level protocol error (IdMismatch): the session
/// is dropped and the pipeline requeued (front charged, mates
/// uncharged - the same requeue_or_fail exit every protocol error
/// takes), and the job completes byte-perfect via the refetch. Both
/// read paths are covered: flat (read_timeout) and adaptive.
#[tokio::test(flavor = "multi_thread")]
async fn desync_echoed_id_cuts_the_session_and_completes_byte_perfect() {
    for adaptive in [false, true] {
        let data: Vec<u8> = (0..400_000u32).map(|i| (i >> 2) as u8).collect();
        let mut articles = std::collections::HashMap::new();
        let segs = crate::mock::make_file_articles("d.bin", &data, 8_000, "dsy", &mut articles);
        let parts: std::collections::HashMap<String, u32> = segs
            .iter()
            .map(|(id, _, part)| (format!("<{id}>"), *part))
            .collect();
        let ids: Vec<ArticleReq> = segs
            .iter()
            .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
            .collect();
        let n = ids.len();
        let srv = crate::mock::MockServer::start(
            articles,
            crate::mock::Chaos {
                skip_nth_response: 10,
                ..Default::default()
            },
        )
        .await;
        let cfg = PoolConfig {
            window: 4,
            read_timeout: Duration::from_secs(5),
            adaptive_timeout: adaptive,
            ..Default::default()
        };
        // payout_server(&srv, 2, cfg) inlined: rig_tests' helpers
        // cannot cross into this module.
        let servers = vec![{
            let mut sc = srv.server_config();
            sc.connections = 2;
            (
                sc,
                PoolConfig {
                    connections: 2,
                    ramp_delay: Duration::from_millis(0),
                    ..cfg
                },
            )
        }];
        let (tx, mut rx) = mpsc::channel(64);
        let fetch = tokio::spawn(async move { fetch_all_multi(&servers, ids, tx).await });
        // Collect and DECODE every owned body: the desync damage is a
        // valid article under the wrong id, so identity (declared part
        // number) and full-payload reassembly are the only honest
        // verdicts - done-counting alone would pass the broken build.
        let want = data.clone();
        let collect = tokio::spawn(async move {
            let mut rebuilt = vec![0u8; want.len()];
            let mut covered = vec![false; want.len()];
            let (mut done, mut wrong_part) = (0usize, 0usize);
            let mut scratch = Vec::new();
            while let Some(o) = rx.recv().await {
                if let FetchOutcome::Done { id, raw } = o {
                    done += 1;
                    let (meta, _) =
                        crate::yenc_simd::decode_into_integrity(&raw, &mut scratch, true)
                            .expect("desync leg delivered an undecodable body");
                    if meta.part != parts.get(&*id).copied() {
                        wrong_part += 1;
                        continue;
                    }
                    let at = (meta.begin - 1) as usize;
                    rebuilt[at..at + scratch.len()].copy_from_slice(&scratch);
                    covered[at..at + scratch.len()]
                        .iter_mut()
                        .for_each(|c| *c = true);
                }
            }
            let holes = covered.iter().filter(|c| !**c).count();
            (done, wrong_part, holes, rebuilt)
        });
        tokio::time::timeout(Duration::from_secs(120), fetch)
            .await
            .expect("desync leg hung")
            .unwrap();
        let (done, wrong_part, holes, rebuilt) = collect.await.unwrap();
        let accepted = srv.accepted.load(Ordering::Relaxed);
        println!(
            "desync leg (adaptive={adaptive}): {done}/{n} done, {wrong_part} wrong-part, \
             {holes} uncovered bytes, {accepted} sessions accepted"
        );
        assert_eq!(done, n, "every article must reach a Done outcome");
        assert_eq!(
            wrong_part, 0,
            "a shifted response was filed under the wrong article"
        );
        assert_eq!(holes, 0, "a skipped article's real bytes never arrived");
        assert_eq!(rebuilt, data, "reassembled payload must be byte-perfect");
        // The whole point: a desynced connection must be CUT, not
        // ridden - 2 workers on a clean run accept exactly 2 sessions,
        // so any reconnect proves the cut happened.
        assert!(
            accepted > 2,
            "no session was ever cut on a desyncing server ({accepted} accepts)"
        );
    }
}

/// §123 chip 6, heal-after: the brownout that ENDS. Every prior
/// brownout rig models a frontend that never returns and hands the
/// job to a healthy twin; this one has no twin - the same server
/// browns out mid-run and recovers 1.5 s later, which is what a
/// frontend restart looks like from outside. The client must cut the
/// dead air (TTFB budget), keep the fleet alive through the mute
/// window, and finish on the recovered server - a heal nobody
/// retries into is indistinguishable from the permanent shape.
#[tokio::test(flavor = "multi_thread")]
async fn brownout_that_heals_resumes_on_the_same_server() {
    use crate::mock::Throttle;
    let data: Vec<u8> = (0..1_200_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = make_file_articles("bh.bin", &data, 20_000, "bh", &mut articles);
    let srv = MockServer::start(
        articles,
        Chaos {
            brownout_after: 20,
            brownout_heal_ms: 1_500,
            throttle: Throttle {
                per_conn_bps: 100_000,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    let server = srv.server_config();
    let cfg = PoolConfig {
        connections: 6,
        ramp_delay: Duration::ZERO,
        connect_backoff: Duration::from_millis(100),
        // Belt for the TTFB braces: even if the adaptive budget never
        // arms (too few samples), a hung read dies in 3 s, well
        // inside the assertion bound.
        read_timeout: Duration::from_secs(3),
        ..Default::default()
    };
    let ids: Vec<String> = segs.iter().map(|(id, _, _)| format!("<{id}>")).collect();
    let reqs: Vec<ArticleReq> = ids.iter().cloned().map(ArticleReq::fresh).collect();
    let (tx, mut rx) = mpsc::channel(256);
    let t0 = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(40),
        fetch_all_multi(&[(server, cfg)], reqs, tx),
    )
    .await
    .expect("run hung across the brownout heal");
    let wall = t0.elapsed();
    let (mut done, mut other) = (0usize, 0usize);
    while let Ok(o) = rx.try_recv() {
        match o {
            FetchOutcome::Done { .. } => done += 1,
            _ => other += 1,
        }
    }
    assert_eq!(
        done,
        ids.len(),
        "articles failed across a healed brownout ({other} non-Done outcomes)"
    );
    // Window 1.5 s + one read_timeout of hung reads + ~2 s full-width
    // transfer at 100 KB/s x 6. 20 s = that plus generous suite-load
    // slack; a client that never re-tries the healed server rides
    // read_timeout cycles to the 40 s hang guard instead.
    assert!(
        wall < Duration::from_secs(20),
        "fleet did not resume after the brownout healed ({wall:?})"
    );
}

/// §123 chip 6, vanish-after-serving: a takedown lands mid-job and
/// the whole post leaves the spool - every id refuses from that
/// moment, including ones served seconds earlier. The client's job
/// is an honest, FAST terminal verdict for the remainder (each 430
/// requeues once for a confirming repeat, then declares Missing) -
/// a mid-job vanish must never read as a wedged pool, which is
/// exactly the shape the stall watchdog's third signal (`deferred`)
/// was added for.
#[tokio::test(flavor = "multi_thread")]
async fn mid_job_takedown_declares_the_tail_missing_fast() {
    let data: Vec<u8> = (0..1_200_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = make_file_articles("vn.bin", &data, 20_000, "vn", &mut articles);
    let srv = MockServer::start(
        articles,
        Chaos {
            vanish_after: 30,
            ..Default::default()
        },
    )
    .await;
    let server = srv.server_config();
    let cfg = PoolConfig {
        connections: 4,
        ramp_delay: Duration::ZERO,
        ..Default::default()
    };
    let ids: Vec<String> = segs.iter().map(|(id, _, _)| format!("<{id}>")).collect();
    let reqs: Vec<ArticleReq> = ids.iter().cloned().map(ArticleReq::fresh).collect();
    let (tx, mut rx) = mpsc::channel(256);
    let t0 = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(30),
        fetch_all_multi(&[(server, cfg)], reqs, tx),
    )
    .await
    .expect("run hung on a mid-job takedown");
    let wall = t0.elapsed();
    let (mut done, mut missing, mut failed) = (0usize, 0usize, 0usize);
    while let Ok(o) = rx.try_recv() {
        match o {
            FetchOutcome::Done { .. } => done += 1,
            FetchOutcome::Missing { .. } => missing += 1,
            FetchOutcome::Failed { .. } => failed += 1,
        }
    }
    assert_eq!(
        done + missing + failed,
        ids.len(),
        "every article must reach a terminal outcome"
    );
    assert!(
        done >= 30 / 2,
        "the pre-takedown half should mostly land ({done} done)"
    );
    assert!(
        missing > 0 && failed == 0,
        "the vanished tail is MISSING (a content verdict), not Failed \
         (a transport verdict) - got {missing} missing / {failed} failed"
    );
    // 430s are instant on loopback and the confirming repeat doubles
    // them; anything near the hang guard means the tail wedged.
    assert!(
        wall < Duration::from_secs(10),
        "takedown tail took {wall:?} to reach a verdict"
    );
}

/// §123 chip 6, the auth blip - pinning a DESIGN, not a recovery.
/// One 481 "authentication failed" is indistinguishable from a wrong
/// password, and hammering a provider over a bad credential is worse
/// than failing, so the pool retires the server on the first
/// permanent-shaped refusal and says so (§35). This rig heals the
/// auth at 1.5 s to prove the failure is already terminal by then:
/// FAST and honest, never a hang, and nothing dials the server back
/// in. If auth blips ever earn an episode/prober treatment like
/// capacity refusals did, this test is the one that changes sides.
#[tokio::test(flavor = "multi_thread")]
async fn auth_blip_fails_fast_and_honest_by_design() {
    let data: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = make_file_articles("ab.bin", &data, 20_000, "ab", &mut articles);
    let srv = MockServer::start(
        articles,
        Chaos {
            auth_reject_ms: 1_500,
            ..Default::default()
        },
    )
    .await;
    let mut server = srv.server_config();
    server.username = Some("u".into());
    server.password = Some("p".into());
    let cfg = PoolConfig {
        connections: 4,
        ramp_delay: Duration::ZERO,
        connect_backoff: Duration::from_millis(50),
        ..Default::default()
    };
    let ids: Vec<String> = segs.iter().map(|(id, _, _)| format!("<{id}>")).collect();
    let reqs: Vec<ArticleReq> = ids.iter().cloned().map(ArticleReq::fresh).collect();
    let (tx, mut rx) = mpsc::channel(256);
    let t0 = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(30),
        fetch_all_multi(&[(server, cfg)], reqs, tx),
    )
    .await
    .expect("run hung on an auth blip");
    let wall = t0.elapsed();
    let mut done = 0usize;
    let mut terminal = 0usize;
    while let Ok(o) = rx.try_recv() {
        match o {
            FetchOutcome::Done { .. } => done += 1,
            _ => terminal += 1,
        }
    }
    assert_eq!(
        done, 0,
        "nothing can download through a refused login ({done} done)"
    );
    assert_eq!(
        terminal,
        ids.len(),
        "every article must still reach a terminal outcome"
    );
    // The refusal lands on the FIRST dial of each worker; everything
    // after is bookkeeping. 5 s is an eternity for it - and well
    // under the 1.5 s heal + any retry ladder, so a client that
    // secretly redials into the healed server would also trip this.
    assert!(
        wall < Duration::from_secs(5),
        "an auth refusal must fail the job fast, not grind ({wall:?})"
    );
}
