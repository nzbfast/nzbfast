//! The pool's own inline unit tests, moved out of pool.rs bodily (TODO 106).
//!
//! These were `mod tests` inside pool.rs and grew to 2,443 lines - a third of
//! the file - which is what kept pool.rs pinned against its size-gate entry.
//! A child module of `pool`, exactly like the sibling `unit_tests` /
//! `rig_tests` / `event_ring_tests` / `ratelimit_tests` modules, so the
//! private internals stay reachable through `super::*`.

use super::*;

/// Every `requeue_or_fail` below is a link that died: the SENTENCE
/// varies, the code does not. Named so the calls stay one-liners - this
/// file sits a handful of lines under the size gate's ceiling.
const LINK: FailCode = FailCode::Transport;

#[test]
fn retention_mask_excludes_only_outdated_servers() {
    // Servers: [unlimited, 10-day, 100-day, unlimited].
    let r = [0u32, 10, 100, 0];
    assert_eq!(retention_mask(&r, 0), 0, "fresh article: no exclusions");
    assert_eq!(retention_mask(&r, 10), 0, "age == retention still served");
    assert_eq!(retention_mask(&r, 11), 0b0010, "past 10-day server only");
    assert_eq!(retention_mask(&r, 100), 0b0010);
    assert_eq!(retention_mask(&r, 101), 0b0110, "past both limited servers");
    assert_eq!(
        retention_mask(&r, u32::MAX),
        0b0110,
        "unlimited never excluded"
    );
    assert_eq!(retention_mask(&[], 500), 0, "no servers, no bits");
}

#[test]
fn seed_masks_and_unservable_split() {
    let reqs = vec![
        ArticleReq::fresh("<fresh@x>"),
        ArticleReq {
            id: "<old@x>".into(),
            age_days: 30,
            part: 0,
            file: u32::MAX,
        },
        ArticleReq {
            id: "<ancient@x>".into(),
            age_days: 400,
            part: 0,
            file: u32::MAX,
        },
    ];
    // Both servers limited: 10-day and 90-day.
    let srv = |retention_days: u32| {
        (
            ServerConfig {
                host: "x".into(),
                port: 119,
                tls: false,
                username: None,
                password: None,
                connections: 1,
                pin_connections: false,
                rcvbuf: None,
                level: 0,
                group: None,
                retention_days,
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
            },
            PoolConfig::default(),
        )
    };
    let (shared, unservable) = Shared::new(reqs, &[srv(10), srv(90)]);
    // The 400-day article is outside every retention → never queued.
    assert_eq!(unservable, vec!["<ancient@x>".into()]);
    assert_eq!(shared.pending.load(Ordering::Relaxed), 2);
    let q = shared.queue.try_lock().unwrap();
    assert_eq!(q.len(), 2);
    assert_eq!(&*q[0].id, "<fresh@x>");
    assert_eq!(q[0].tried_430, 0);
    assert_eq!(&*q[1].id, "<old@x>");
    assert_eq!(
        q[1].tried_430, 0b01,
        "30-day article pre-excluded from the 10-day server"
    );
}

/// The retention pre-filter's Missing must carry its own cause: the
/// article was never REQUESTED, and telling the user "missing
/// segments" for a settings exclusion sent them chasing takedowns
/// (Hblife's report was undiagnosable for exactly this reason).
#[tokio::test]
async fn retention_excluded_articles_report_cause_retention() {
    use crate::mock::{Chaos, MockServer, make_file_articles};
    let mut articles = std::collections::HashMap::new();
    let payload: Vec<u8> = (0..20_000u32).map(|i| i as u8).collect();
    let segs = make_file_articles("r.bin", &payload, 8_000, "ret", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;
    let mut server = srv.server_config();
    server.retention_days = 10;

    let mut reqs: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    let n_fresh = reqs.len();
    reqs.push(ArticleReq {
        id: "<ancient@x>".into(),
        age_days: 400,
        part: 0,
        file: u32::MAX,
    });

    let cfg = PoolConfig {
        connections: 1,
        ramp_delay: Duration::ZERO,
        ..Default::default()
    };
    let (tx, mut rx) = mpsc::channel(64);
    tokio::time::timeout(
        Duration::from_secs(20),
        fetch_all_multi(&[(server, cfg)], reqs, tx),
    )
    .await
    .expect("run hung");

    let mut done = 0;
    let mut retention: Vec<Arc<str>> = Vec::new();
    while let Ok(o) = rx.try_recv() {
        match o {
            FetchOutcome::Done { .. } => done += 1,
            FetchOutcome::Missing {
                id,
                cause: MissingCause::Retention,
            } => retention.push(id),
            other => panic!("unexpected outcome: {other:?}"),
        }
    }
    assert_eq!(done, n_fresh, "fresh articles all served");
    assert_eq!(
        retention.iter().map(|s| &**s).collect::<Vec<_>>(),
        ["<ancient@x>"]
    );
}

/// TODO 96.1: the adaptive two-phase read path serves a normal run
/// byte-identically to the flat-timeout path, and the per-server
/// TTFB EWMA comes out measured. The dark flag's happy path - the
/// failure-shape behavior is pinned at the nntp level
/// (`two_phase_first_byte_budget_bounds_a_dead_connection`,
/// `paced_multiline_stalls_at_the_callers_bound`).
#[tokio::test]
async fn adaptive_timeout_serves_a_clean_run() {
    use crate::mock::{Chaos, MockServer, make_file_articles};
    let mut articles = std::collections::HashMap::new();
    let payload: Vec<u8> = (0..60_000u32).map(|i| (i * 7) as u8).collect();
    let segs = make_file_articles("a.bin", &payload, 8_000, "adapt", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;
    let server = srv.server_config();
    let reqs: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    let n = reqs.len();
    let cfg = PoolConfig {
        connections: 2,
        ramp_delay: Duration::ZERO,
        adaptive_timeout: true,
        ..Default::default()
    };
    let (tx, mut rx) = mpsc::channel(64);
    tokio::time::timeout(
        Duration::from_secs(20),
        fetch_all_multi(&[(server, cfg)], reqs, tx),
    )
    .await
    .expect("run hung");
    let mut done = 0;
    while let Ok(o) = rx.try_recv() {
        match o {
            FetchOutcome::Done { .. } => done += 1,
            other => panic!("unexpected outcome: {other:?}"),
        }
    }
    assert_eq!(done, n, "every article served through the adaptive path");
}

#[test]
fn shared_new_dedupes_repeated_ids() {
    // A malformed NZB can list the same <segment> id twice. Charging
    // `pending` per occurrence but crediting per id (claim_done) left
    // the run non-terminal forever. Repeats are dropped at build time,
    // servable and unservable alike.
    let reqs = vec![
        ArticleReq::fresh("<a@x>"),
        ArticleReq::fresh("<b@x>"),
        ArticleReq::fresh("<a@x>"), // servable repeat
        ArticleReq {
            id: "<ancient@x>".into(),
            age_days: 400,
            part: 0,
            file: u32::MAX,
        },
        ArticleReq {
            id: "<ancient@x>".into(),
            age_days: 400,
            part: 0,
            file: u32::MAX,
        }, // unservable repeat - must not report Missing twice
    ];
    let srv = (
        ServerConfig {
            host: "x".into(),
            port: 119,
            tls: false,
            username: None,
            password: None,
            connections: 1,
            pin_connections: false,
            rcvbuf: None,
            level: 0,
            group: None,
            retention_days: 10,
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
        },
        PoolConfig::default(),
    );
    let (shared, unservable) = Shared::new(reqs, &[srv]);
    assert_eq!(unservable, vec!["<ancient@x>".into()]);
    assert_eq!(shared.pending.load(Ordering::Relaxed), 2);
    let q = shared.queue.try_lock().unwrap();
    assert_eq!(q.len(), 2);
    assert_eq!(&*q[0].id, "<a@x>");
    assert_eq!(&*q[1].id, "<b@x>");
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_ids_reach_terminal_with_one_outcome_per_id() {
    // Regression (TODO §7): duplicate ids in reqs wedged
    // fetch_all_multi forever - pending charged twice, credited once.
    // With dedupe the run must RETURN, with exactly one Done per
    // unique id.
    let mut articles = std::collections::HashMap::new();
    let data: Vec<u8> = (0..50_000u32).map(|i| i as u8).collect();
    let segs = crate::mock::make_file_articles("d.bin", &data, 10_000, "dup", &mut articles);
    let srv = crate::mock::MockServer::start(articles, crate::mock::Chaos::default()).await;

    let mut reqs: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    let n_unique = reqs.len();
    reqs.push(ArticleReq::fresh(format!("<{}>", segs[0].0)));
    reqs.push(ArticleReq::fresh(format!("<{}>", segs[0].0)));
    reqs.push(ArticleReq::fresh(format!("<{}>", segs[segs.len() - 1].0)));

    let cfg = PoolConfig {
        connections: 2,
        ramp_delay: Duration::from_millis(0),
        ..PoolConfig::default()
    };
    let servers = vec![(srv.server_config(), cfg)];
    let (tx, mut rx) = mpsc::channel(16);
    let fetch = tokio::spawn(async move { fetch_all_multi(&servers, reqs, tx).await });
    // Drain in a task so a regression fails LOUD at the timeout below
    // instead of wedging the test on a channel that never closes.
    let collect = tokio::spawn(async move {
        let mut done: Vec<Arc<str>> = Vec::new();
        while let Some(o) = rx.recv().await {
            match o {
                FetchOutcome::Done { id, .. } => done.push(id),
                other => panic!("unexpected outcome: {other:?}"),
            }
        }
        done
    });
    tokio::time::timeout(Duration::from_secs(30), fetch)
        .await
        .expect("fetch_all_multi hung on duplicate ids")
        .unwrap();
    let done = collect.await.unwrap();
    assert_eq!(done.len(), n_unique, "one outcome per unique id");
    let uniq: HashSet<&str> = done.iter().map(|s| &**s).collect();
    assert_eq!(uniq.len(), n_unique, "no id reported twice");
}

/// A server whose scan found nothing takeable must NOT rescan (and
/// re-rotate) the whole queue on its next call - on a 12k-segment
/// post that only one provider still carried (live, 2026-07-20), the
/// other five servers' every-25ms full-queue scans starved the
/// serving one to a flat 0.0 MB/s. The throttle trades ≤100 ms of
/// pickup latency for that lock storm.
#[tokio::test(flavor = "multi_thread")]
async fn futile_scan_throttles_before_retrying() {
    let mk = |host: &str| {
        (
            ServerConfig {
                host: host.into(),
                port: 119,
                tls: false,
                username: None,
                password: None,
                connections: 1,
                pin_connections: false,
                level: 0,
                group: None,
                retention_days: 0,
                rcvbuf: None,
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
            },
            PoolConfig::default(),
        )
    };
    let servers = vec![mk("a"), mk("b")];
    let reqs: Vec<ArticleReq> = (0..50)
        .map(|i| ArticleReq::fresh(format!("<t{i}>")))
        .collect();
    let (shared, _) = Shared::new(reqs, &servers);
    // Both servers "live" so nothing is judged unservable.
    let _a = WorkerLife::birth(&shared, 0);
    let _b = WorkerLife::birth(&shared, 1);
    // Server 0 has 430'd the entire queue.
    for w in shared.queue.lock().await.iter_mut() {
        w.tried_430 |= 0b01;
    }
    let ctx = ServerCtx {
        idx: 0,
        bit: 0b01,
        all: 0b11,
        group_bits: 0b01,
        level: 0,
    };
    let (tx, _rx) = mpsc::channel(64);

    assert!(
        next_work(&shared, ctx, &tx, Pipeline::payload(0))
            .await
            .is_none()
    );
    assert_ne!(shared.scan_futile[0].load(Ordering::Relaxed), u64::MAX);

    // Fresh takeable work appears; within the throttle window the
    // server still sits out (documented ≤SCAN_RETRY_MS latency)…
    shared.queue.lock().await.push_front(Work {
        age_days: 0,
        part: 0,
        file: u32::MAX,
        ord: 0,
        id: "<fresh>".into(),
        attempts: 0,
        promoted: false,
        tried_430: 0,
        tried_fail: 0,
        dup: false,
        prebyte_expiries: 0,
        soft_430: 0,
        fenced: false,
        rearms: 0,
        ladder: false,
        probe: false,
    });
    assert!(
        next_work(&shared, ctx, &tx, Pipeline::payload(0))
            .await
            .is_none(),
        "throttled"
    );
    assert_eq!(shared.queue.lock().await.len(), 51, "queue untouched");

    // …and picks it up once the window passes.
    tokio::time::sleep(Duration::from_millis(SCAN_RETRY_MS + 30)).await;
    let w = next_work(&shared, ctx, &tx, Pipeline::payload(0))
        .await
        .expect("work after window");
    assert_eq!(&*w.id, "<fresh>");
}

/// M2c.4 endgame fan-out: with few articles left, a 430-laddering
/// in-flight article is raced by every untried backbone at once -
/// no rate/staleness preconditions - while the fill gate, the
/// once-per-backbone rule, and the normal-phase conditions all hold.
#[tokio::test]
async fn endgame_fans_out_dup_races_for_laddering_articles() {
    let mk = |host: &str| {
        (
            ServerConfig {
                host: host.into(),
                port: 119,
                tls: false,
                username: None,
                password: None,
                connections: 1,
                pin_connections: false,
                level: 0,
                group: None,
                retention_days: 0,
                rcvbuf: None,
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
            },
            PoolConfig::default(),
        )
    };
    let servers = vec![mk("a"), mk("b"), mk("c")];
    // 3 pending ≤ ENDGAME_MAX → endgame rules apply.
    let reqs: Vec<ArticleReq> = (0..3)
        .map(|i| ArticleReq::fresh(format!("<e{i}>")))
        .collect();
    let (shared, _) = Shared::new(reqs, &servers);
    // In flight on server 0, already 430'd by server 1's backbone.
    let lad = Work {
        age_days: 0,
        part: 0,
        file: u32::MAX,
        ord: 0,
        id: "<e0>".into(),
        attempts: 0,
        promoted: false,
        tried_430: 0b010,
        tried_fail: 0,
        dup: false,
        prebyte_expiries: 0,
        soft_430: 0,
        fenced: false,
        rearms: 0,
        ladder: false,
        probe: false,
    };
    shared.register_inflight(&lad, 0);

    // Fill gate first: a server whose required lower levels haven't
    // all 430'd yet must NOT join the race.
    assert!(
        shared
            .pick_dup(2, 0b100, 0b100, 0b011, Pipeline::payload(0), 1)
            .is_none(),
        "fill-gated"
    );
    // A pipeline with a BODY in it still refuses the probe: the
    // refusal would queue behind a whole transfer.
    assert!(
        shared
            .pick_dup(2, 0b100, 0b100, 0, Pipeline::payload(3), 1)
            .is_none(),
        "a ladder probe never rides behind payload"
    );
    // A pipeline holding only OTHER PROBES takes it. This is the whole
    // fix for the zero-throughput tail: at damage 60 the endgame
    // rule's old "empty pipeline" reading capped the fleet at one
    // verdict per connection per round trip, so the poisoned articles
    // trickled to terminal at ~6/s while the wire sat idle.
    let d = shared
        .pick_dup(2, 0b100, 0b100, 0, Pipeline::probes(3), 1)
        .expect("probes ride behind probes");
    assert_eq!(&*d.id, "<e0>");
    assert!(d.dup);
    assert!(d.ladder, "a ladder pick is marked as one");
    // Each backbone races at most once.
    assert!(
        shared
            .pick_dup(2, 0b100, 0b100, 0, Pipeline::payload(0), 1)
            .is_none(),
        "already racing"
    );
    // A backbone that 430'd it never re-tries.
    assert!(
        shared
            .pick_dup(1, 0b010, 0b010, 0, Pipeline::payload(0), 1)
            .is_none(),
        "430'd backbone"
    );

    // Normal phase (pending > ENDGAME_MAX): same shape gets NO dup -
    // owner isn't slow (all rates 0) and isn't stale yet.
    let reqs: Vec<ArticleReq> = (0..(ENDGAME_MAX + 10))
        .map(|i| ArticleReq::fresh(format!("<n{i}>")))
        .collect();
    let (big, _) = Shared::new(reqs, &servers);
    let lad2 = Work {
        age_days: 0,
        part: 0,
        file: u32::MAX,
        ord: 0,
        id: "<n0>".into(),
        attempts: 0,
        promoted: false,
        tried_430: 0b010,
        tried_fail: 0,
        dup: false,
        prebyte_expiries: 0,
        soft_430: 0,
        fenced: false,
        rearms: 0,
        ladder: false,
        probe: false,
    };
    big.register_inflight(&lad2, 0);
    assert!(
        big.pick_dup(2, 0b100, 0b100, 0, Pipeline::payload(0), 0)
            .is_none(),
        "normal phase unchanged"
    );
}

/// Tail fan-out (opt-in `PoolConfig::tail_fanout`): in the endgame
/// an IDLE primary races a HEALTHY in-flight article - a fresh
/// session on the owner's own server included - once the article
/// has been on the wire past the age floor. Off by default; fill
/// servers, busy pipelines and too-young reads never join; each
/// server races an article at most once, which spreads idle workers
/// across stragglers.
#[tokio::test]
async fn tail_fanout_races_healthy_articles_in_the_endgame() {
    let mk = |host: &str, level: u32, fanout: bool| {
        (
            ServerConfig {
                host: host.into(),
                port: 119,
                tls: false,
                username: None,
                password: None,
                connections: 1,
                pin_connections: false,
                level,
                group: None,
                retention_days: 0,
                rcvbuf: None,
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
            },
            PoolConfig {
                tail_fanout: fanout,
                ..Default::default()
            },
        )
    };
    let servers = vec![mk("a", 0, true), mk("b", 0, true), mk("block", 1, true)];
    // 3 pending ≤ ENDGAME_MAX → endgame rules apply.
    let reqs: Vec<ArticleReq> = (0..3)
        .map(|i| ArticleReq::fresh(format!("<h{i}>")))
        .collect();
    let (shared, _) = Shared::new(reqs, &servers);
    // Healthy (never 430'd) article in flight on server 0.
    let w = Work {
        age_days: 0,
        part: 0,
        file: u32::MAX,
        ord: 0,
        id: "<h0>".into(),
        attempts: 0,
        promoted: false,
        tried_430: 0,
        tried_fail: 0,
        dup: false,
        prebyte_expiries: 0,
        soft_430: 0,
        fenced: false,
        rearms: 0,
        ladder: false,
        probe: false,
    };
    shared.register_inflight(&w, 0);

    // Younger than the age floor: nobody speculates yet.
    assert!(
        shared
            .pick_dup(1, 0b010, 0b010, 0, Pipeline::payload(0), 0)
            .is_none(),
        "raced a read younger than the age floor"
    );
    shared
        .inflight
        .lock_ok()
        .get_mut("<h0>")
        .unwrap()
        .dispatched = Instant::now() - Duration::from_secs(1);
    // Aging an entry by hand is a map edit: bump the N6 gen the way
    // every production mutation path does, or the futile record the
    // too-young scan just left gates the scans below for a retry tick.
    shared.bump_inflight_gen();
    // A busy pipeline is not idle capacity.
    assert!(
        shared
            .pick_dup(1, 0b010, 0b010, 0, Pipeline::payload(2), 0)
            .is_none(),
        "a busy worker speculated"
    );
    // A fill server never spends paid bytes on speculation.
    assert!(
        shared
            .pick_dup(2, 0b100, 0b100, 0b011, Pipeline::payload(0), 1)
            .is_none(),
        "a fill server speculated"
    );
    // An idle worker on the OWNER's own server races it...
    let d = shared
        .pick_dup(0, 0b001, 0b001, 0, Pipeline::payload(0), 0)
        .expect("same-server tail race");
    assert_eq!(&*d.id, "<h0>");
    assert!(d.dup);
    // ...each server at most once...
    assert!(
        shared
            .pick_dup(0, 0b001, 0b001, 0, Pipeline::payload(0), 0)
            .is_none(),
        "server a raced twice"
    );
    // ...and a second primary joins the same article.
    let d2 = shared
        .pick_dup(1, 0b010, 0b010, 0, Pipeline::payload(0), 0)
        .expect("cross-server tail race");
    assert_eq!(&*d2.id, "<h0>");

    // A second straggler goes to the worker whose server is already
    // racing the first - idle capacity spreads, not piles.
    let w2 = Work {
        age_days: 0,
        part: 0,
        file: u32::MAX,
        ord: 0,
        id: "<h1>".into(),
        attempts: 0,
        promoted: false,
        tried_430: 0,
        tried_fail: 0,
        dup: false,
        prebyte_expiries: 0,
        soft_430: 0,
        fenced: false,
        rearms: 0,
        ladder: false,
        probe: false,
    };
    shared.register_inflight(&w2, 0);
    shared
        .inflight
        .lock_ok()
        .get_mut("<h1>")
        .unwrap()
        .dispatched = Instant::now() - Duration::from_secs(1);
    let d3 = shared
        .pick_dup(1, 0b010, 0b010, 0, Pipeline::payload(0), 0)
        .expect("second straggler race");
    assert_eq!(&*d3.id, "<h1>");

    // OFF (the default): the identical shape yields no speculation.
    let servers_off = vec![mk("a", 0, false), mk("b", 0, false)];
    let reqs: Vec<ArticleReq> = (0..3)
        .map(|i| ArticleReq::fresh(format!("<h{i}>")))
        .collect();
    let (off, _) = Shared::new(reqs, &servers_off);
    off.register_inflight(&w, 0);
    off.inflight.lock_ok().get_mut("<h0>").unwrap().dispatched =
        Instant::now() - Duration::from_secs(1);
    assert!(
        off.pick_dup(1, 0b010, 0b010, 0, Pipeline::payload(0), 0)
            .is_none(),
        "tail fan-out fired while switched off"
    );

    // Normal phase (pending > ENDGAME_MAX): fan-out stays out of it
    // even when enabled - equal rates, not yet stale, no dup.
    let servers_on = vec![mk("a", 0, true), mk("b", 0, true)];
    let reqs: Vec<ArticleReq> = (0..(ENDGAME_MAX + 10))
        .map(|i| ArticleReq::fresh(format!("<n{i}>")))
        .collect();
    let (big, _) = Shared::new(reqs, &servers_on);
    let w3 = Work {
        age_days: 0,
        part: 0,
        file: u32::MAX,
        ord: 0,
        id: "<n0>".into(),
        attempts: 0,
        promoted: false,
        tried_430: 0,
        tried_fail: 0,
        dup: false,
        prebyte_expiries: 0,
        soft_430: 0,
        fenced: false,
        rearms: 0,
        ladder: false,
        probe: false,
    };
    big.register_inflight(&w3, 0);
    big.inflight.lock_ok().get_mut("<n0>").unwrap().dispatched =
        Instant::now() - Duration::from_secs(1);
    assert!(
        big.pick_dup(1, 0b010, 0b010, 0, Pipeline::payload(0), 0)
            .is_none(),
        "speculated outside the endgame"
    );
}

/// N6 endgame idle-spin gate: an idle `pick_dup` walk that found
/// nothing arms a per-server skip for [`SCAN_RETRY_MS`]. Every map
/// mutation path bumps the generation and re-opens it immediately, so
/// a new candidate costs nothing; a candidate that arms purely by
/// CLOCK (fan-out age) is delayed at most one retry window, never
/// lost.
#[tokio::test]
async fn a_futile_idle_dup_scan_gates_until_the_map_moves_or_the_window_ends() {
    let mk = |host: &str| {
        (
            ServerConfig {
                host: host.into(),
                port: 119,
                tls: false,
                username: None,
                password: None,
                connections: 1,
                pin_connections: false,
                level: 0,
                group: None,
                retention_days: 0,
                rcvbuf: None,
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
            },
            PoolConfig {
                tail_fanout: true,
                ..Default::default()
            },
        )
    };
    let servers = vec![mk("a"), mk("b")];
    // 3 pending ≤ ENDGAME_MAX → the endgame/fan-out rules apply.
    let reqs: Vec<ArticleReq> = (0..3)
        .map(|i| ArticleReq::fresh(format!("<g{i}>")))
        .collect();
    let (shared, _) = Shared::new(reqs, &servers);

    // A busy walk never arms the gate, futile or not.
    assert!(
        shared
            .pick_dup(1, 0b010, 0b010, 0, Pipeline::payload(2), 0)
            .is_none()
    );
    assert_eq!(
        shared.dup_futile[1].load(Ordering::Relaxed),
        u64::MAX,
        "a busy picker's empty walk must not gate the idle ones"
    );

    // An idle walk of the empty map arms it.
    assert!(
        shared
            .pick_dup(1, 0b010, 0b010, 0, Pipeline::payload(0), 0)
            .is_none()
    );
    assert_ne!(
        shared.dup_futile[1].load(Ordering::Relaxed),
        u64::MAX,
        "a futile idle walk must record itself"
    );

    // Plant a raceable candidate BEHIND the gate's back: a direct map
    // edit with no gen bump (production cannot do this - every
    // mutation path bumps). The gated walk skips it...
    shared.inflight.lock_ok().insert(
        "<g0>".into(),
        Inflight {
            age_days: 0,
            part: 0,
            file: u32::MAX,
            ord: 0,
            server: 0,
            dispatched: Instant::now() - Duration::from_secs(1),
            dups: 0,
            tried_430: 0,
            dup_servers: 0,
            tried_fail: 0,
            suspect: false,
            found: 0,
        },
    );
    assert!(
        shared
            .pick_dup(1, 0b010, 0b010, 0, Pipeline::payload(0), 0)
            .is_none(),
        "inside the window with an unmoved gen the walk is skipped"
    );
    // ...a gen bump re-opens it immediately...
    shared.bump_inflight_gen();
    let d = shared
        .pick_dup(1, 0b010, 0b010, 0, Pipeline::payload(0), 0)
        .expect("a gen bump wakes the gated scanner at once");
    assert_eq!(&*d.id, "<g0>");
    assert!(d.dup);

    // ...and a candidate that arms by CLOCK alone (the fan-out age
    // floor) is delayed at most one retry window, never lost: a walk
    // that saw it too young re-arms the gate, and no gen ever moves.
    let reqs: Vec<ArticleReq> = (0..3)
        .map(|i| ArticleReq::fresh(format!("<y{i}>")))
        .collect();
    let (young, _) = Shared::new(reqs, &servers);
    young.inflight.lock_ok().insert(
        "<y0>".into(),
        Inflight {
            age_days: 0,
            part: 0,
            file: u32::MAX,
            ord: 0,
            server: 0,
            dispatched: Instant::now(),
            dups: 0,
            tried_430: 0,
            dup_servers: 0,
            tried_fail: 0,
            suspect: false,
            found: 0,
        },
    );
    assert!(
        young
            .pick_dup(1, 0b010, 0b010, 0, Pipeline::payload(0), 0)
            .is_none(),
        "younger than the age floor - futile, and the walk arms the gate"
    );
    assert_ne!(young.dup_futile[1].load(Ordering::Relaxed), u64::MAX);
    std::thread::sleep(TAIL_FANOUT_MIN_AGE + Duration::from_millis(SCAN_RETRY_MS + 20));
    let d2 = young
        .pick_dup(1, 0b010, 0b010, 0, Pipeline::payload(0), 0)
        .expect("past the retry window the walk runs again and finds the aged article");
    assert_eq!(&*d2.id, "<y0>");
}

/// §35: a bigger server must not duplicate a smaller one's work just
/// for being bigger.
///
/// `rate()` is bytes-over-wall-time, so it tracks a server's SHARE of
/// the job, and that share is set mostly by how many connections it
/// was given. Judged on shares, a server with 4x the connections reads
/// as "4x faster" even when every individual connection is identical,
/// and its idle workers then duplicated the smaller server's in-flight
/// articles as routine - the same bytes fetched twice. The question
/// the heuristic means to ask is whether the OWNER is slow, which is a
/// per-connection quantity.
#[tokio::test]
async fn a_server_with_more_connections_is_not_mistaken_for_a_faster_one() {
    let mk = |host: &str| {
        (
            ServerConfig {
                host: host.into(),
                port: 119,
                tls: false,
                username: None,
                password: None,
                connections: 1,
                pin_connections: false,
                level: 0,
                group: None,
                retention_days: 0,
                rcvbuf: None,
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
            },
            PoolConfig::default(),
        )
    };
    let servers = vec![mk("big"), mk("small")];
    // Well past ENDGAME_MAX so the endgame's unconditional fan-out
    // does not apply and only the rate rule is under test.
    let reqs: Vec<ArticleReq> = (0..(ENDGAME_MAX + 10))
        .map(|i| ArticleReq::fresh(format!("<r{i}>")))
        .collect();
    let (shared, _) = Shared::new(reqs, &servers);

    // Identical per-connection speed; server 0 simply has 4x the
    // workers, so it has moved 4x the bytes.
    shared.alive[0].store(8, Ordering::Relaxed);
    shared.alive[1].store(2, Ordering::Relaxed);
    shared.bytes[0].store(400_000_000, Ordering::Relaxed);
    shared.bytes[1].store(100_000_000, Ordering::Relaxed);

    let w = Work {
        age_days: 0,
        part: 0,
        file: u32::MAX,
        ord: 0,
        id: "<r0>".into(),
        attempts: 0,
        promoted: false,
        tried_430: 0,
        tried_fail: 0,
        dup: false,
        prebyte_expiries: 0,
        soft_430: 0,
        fenced: false,
        rearms: 0,
        ladder: false,
        probe: false,
    };
    shared.register_inflight(&w, 1); // owned by the SMALL server

    assert!(
        shared
            .pick_dup(0, 0b01, 0b01, 0, Pipeline::payload(0), 0)
            .is_none(),
        "the big server duplicated an equally fast connection's article"
    );

    // And the rule still fires when the owner really is slower per
    // connection: same worker counts, a quarter of the bytes.
    shared.bytes[1].store(25_000_000, Ordering::Relaxed);
    // In production rate changes ride the delivery/deregister paths,
    // which bump the N6 gen; a by-hand rate change must too.
    shared.bump_inflight_gen();
    let d = shared
        .pick_dup(0, 0b01, 0b01, 0, Pipeline::payload(0), 0)
        .expect("a genuinely slow owner should still be raced");
    assert_eq!(&*d.id, "<r0>");
    assert!(d.dup);
}

/// A FILL server must never race on speed, only on the endgame
/// 430-ladder (which is gated on every live lower level having
/// missed). Its bytes are billed per gigabyte, so re-fetching an
/// article a primary is already delivering is a straight loss.
///
/// This became reachable the moment the dup comparison went
/// per-worker: a fill server is given FEW connections, so by that
/// measure it looks fast exactly when it is least worth spending.
#[tokio::test]
async fn a_fill_server_never_duplicates_primary_work_on_speed() {
    let mk = |host: &str, level: u32| {
        (
            ServerConfig {
                host: host.into(),
                port: 119,
                tls: false,
                username: None,
                password: None,
                connections: 1,
                pin_connections: false,
                level,
                group: None,
                retention_days: 0,
                rcvbuf: None,
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
            },
            PoolConfig::default(),
        )
    };
    let servers = vec![mk("primary", 0), mk("block", 1)];
    let reqs: Vec<ArticleReq> = (0..(ENDGAME_MAX + 10))
        .map(|i| ArticleReq::fresh(format!("<f{i}>")))
        .collect();
    let (shared, _) = Shared::new(reqs, &servers);

    // The block server has one fast connection; the primary has many
    // slower ones. Per worker the block server wins by miles.
    shared.alive[0].store(50, Ordering::Relaxed);
    shared.alive[1].store(1, Ordering::Relaxed);
    shared.bytes[0].store(50_000_000, Ordering::Relaxed);
    shared.bytes[1].store(50_000_000, Ordering::Relaxed);

    let w = Work {
        age_days: 0,
        part: 0,
        file: u32::MAX,
        ord: 0,
        id: "<f0>".into(),
        attempts: 0,
        promoted: false,
        tried_430: 0,
        tried_fail: 0,
        dup: false,
        prebyte_expiries: 0,
        soft_430: 0,
        fenced: false,
        rearms: 0,
        ladder: false,
        probe: false,
    };
    shared.register_inflight(&w, 0); // owned by the PRIMARY

    assert!(
        shared
            .pick_dup(1, 0b10, 0b10, 0, Pipeline::payload(0), 1)
            .is_none(),
        "a block server spent paid bytes racing an article already arriving"
    );
    // Re-asking with the caller's level swapped is a synthetic shape (a
    // server's level never changes in production, so the N6 futile
    // record is level-stable there): clear it by bumping the gen.
    shared.bump_inflight_gen();
    // The primary, in its place, would take it.
    assert!(
        shared
            .pick_dup(1, 0b10, 0b10, 0, Pipeline::payload(0), 0)
            .is_some(),
        "the rate rule itself should still fire for a level-0 server"
    );
}

/// The queue side of the same rule. In the endgame a queued article
/// that has already been refused somewhere is a VERDICT PROBE, and the
/// only thing it must not queue behind is a body: a worker holding
/// nothing but other probes takes it, a worker mid-transfer leaves it
/// for someone idle.
///
/// This is the gate that produced the measured stall. With it reading
/// "any pipeline depth at all", a fleet of 20 connections could carry
/// only 20 outstanding verdicts however many articles were laddering,
/// so a 60-article damage tail cost 60x5 refusals at one per
/// connection per round trip - about ten seconds of 0.0 MB/s in front
/// of a repair that itself took two.
#[tokio::test]
async fn a_laddering_article_queues_behind_probes_but_never_behind_payload() {
    let servers = one_server();
    let (shared, _) = Shared::new(vec![ArticleReq::fresh("<lad@x>")], &servers);
    let ctx = ctx_for(&servers, 0);
    let (tx, _rx) = mpsc::channel(8);
    let _life = WorkerLife::birth(&shared, 0);
    // Refused by a backbone that is not ours, so it is takeable here
    // on the merits and only the pipeline rule can turn it away.
    // (`live_mask` is this one server, so the bit must not be ours or
    // the article is already terminal.)
    shared.queue.lock().await[0].tried_430 = 0b10;

    assert!(
        next_work(&shared, ctx, &tx, Pipeline::payload(1))
            .await
            .is_none(),
        "a probe must not queue behind a body"
    );
    assert_eq!(
        shared.queue.lock().await.len(),
        1,
        "left for an idle worker"
    );

    // Clear the futile-scan throttle the miss above armed - it is a
    // separate rule with its own test, and it would answer this one.
    shared.scan_futile[0].store(u64::MAX, Ordering::Relaxed);
    // Same worker, same article, pipeline now holding probes only.
    let w = next_work(&shared, ctx, &tx, Pipeline::probes(2))
        .await
        .expect("probes ride behind probes");
    assert_eq!(&*w.id, "<lad@x>");
    assert!(w.ladder, "and are dispatched as probes");
}

/// A corpus's ids, bracketed and interned (R9) the way the fetch plan
/// does it - the pool API takes handles, and building them inline three
/// times cost this file more lines than its size-gate ceiling had.
fn bracketed(segs: &[(String, u64, u32)]) -> Vec<Arc<str>> {
    segs.iter()
        .map(|(id, ..)| Arc::from(format!("<{id}>")))
        .collect()
}

pub(super) fn one_server() -> Vec<(ServerConfig, PoolConfig)> {
    vec![(
        ServerConfig {
            host: "s".into(),
            port: 119,
            tls: false,
            username: None,
            password: None,
            connections: 1,
            pin_connections: false,
            level: 0,
            group: None,
            retention_days: 0,
            rcvbuf: None,
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
        },
        PoolConfig::default(),
    )]
}

#[test]
fn wire_cap_accounting_charges_and_releases_symmetrically() {
    // B3: the cap gate reads the running estimate; every charge must
    // be matched by exactly one release, whichever exit path takes it.
    let (shared, _) = Shared::new(vec![ArticleReq::fresh("<w@x>")], &one_server());
    assert_eq!(shared.inflight_body_bytes.load(Ordering::Acquire), 0);
    assert!(
        !shared.wire_over_cap(EST_BODY_BYTES),
        "empty pool is under any cap"
    );

    shared.charge_wire();
    assert_eq!(
        shared.inflight_body_bytes.load(Ordering::Acquire),
        EST_BODY_BYTES
    );
    assert!(
        shared.wire_over_cap(EST_BODY_BYTES),
        "at the cap counts as over"
    );
    assert!(
        !shared.wire_over_cap(0),
        "cap 0 = uncapped, never throttles"
    );
    assert!(!shared.wire_over_cap(2 * EST_BODY_BYTES));

    // A batch release (shed / dead connection) drops the whole
    // pipeline's charge in one call.
    shared.charge_wire();
    shared.charge_wire();
    shared.release_wire(2);
    assert_eq!(
        shared.inflight_body_bytes.load(Ordering::Acquire),
        EST_BODY_BYTES
    );
    shared.release_wire(1);
    assert_eq!(shared.inflight_body_bytes.load(Ordering::Acquire), 0);
    assert!(!shared.wire_over_cap(EST_BODY_BYTES));

    // A zero-count release (empty pipeline on abort) is a no-op.
    shared.release_wire(0);
    assert_eq!(shared.inflight_body_bytes.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn a_dead_pipeline_releases_exactly_what_dispatch_charged() {
    // Carried regression: the worker used to charge the wire only
    // AFTER send_body succeeded, while the failed-send path pushes
    // that same article into the deque requeue_or_fail bulk-releases.
    // One flaky send therefore released a charge nobody took; the
    // counter wrapped to ~u64::MAX, wire_over_cap answered true for
    // the rest of the run, and every worker in the pool collapsed to
    // pipeline depth one. Model the worker's dispatch sequence.
    let servers = one_server();
    let (shared, _) = Shared::new(
        vec![ArticleReq::fresh("<f0@x>"), ArticleReq::fresh("<f1@x>")],
        &servers,
    );
    let ctx = ctx_for(&servers, 0);
    let cfg = PoolConfig::default();
    let (tx, _rx) = mpsc::channel(8);
    // Without a live worker the queue scan declares everything
    // unanimously-430 Missing before we get to dispatch it.
    let _life = WorkerLife::birth(&shared, 0);

    let mut inflight: VecDeque<Work> = VecDeque::new();
    // One article dispatched normally...
    let w0 = next_work(&shared, ctx, &tx, Pipeline::payload(0))
        .await
        .expect("queued work");
    shared.charge_wire();
    shared.register_inflight(&w0, 0);
    inflight.push_back(w0);
    // ...and the next one's send fails, so it joins the same deque as
    // the front-of-pipeline casualty.
    let w1 = next_work(&shared, ctx, &tx, Pipeline::payload(1))
        .await
        .expect("queued work");
    shared.charge_wire();
    inflight.push_front(w1);
    assert_eq!(
        shared.inflight_body_bytes.load(Ordering::Acquire),
        2 * EST_BODY_BYTES,
        "every item in a worker's pipeline carries exactly one charge"
    );

    requeue_or_fail(
        &shared,
        &tx,
        &cfg,
        ctx,
        &mut inflight,
        LINK,
        "send failed",
        true,
    )
    .await;
    assert_eq!(
        shared.inflight_body_bytes.load(Ordering::Acquire),
        0,
        "the dead pipeline must release exactly its own charges"
    );
    assert!(
        !shared.wire_over_cap(EST_BODY_BYTES),
        "counter wrapped past zero"
    );
}

#[tokio::test]
async fn a_productive_sessions_death_charges_no_article() {
    // The flap harvest recovery (chaos flap leg, 6 Aug): a session
    // that completed at least one body and THEN died must requeue
    // its pipeline uncharged - branding the innocent next-in-line
    // article with tried_fail built a twin-only backlog (~2
    // articles/s) that idled the flapping server for the whole
    // drain of its bandwidth-saturated sibling. A zero-work session
    // keeps the unconditional front charge (the RST-after-AUTH
    // livelock guard), which is also what eventually walks a
    // session-killing poison article to its terminal verdict.
    let servers = one_server();
    let (shared, _) = Shared::new(
        vec![ArticleReq::fresh("<p0@x>"), ArticleReq::fresh("<p1@x>")],
        &servers,
    );
    let ctx = ctx_for(&servers, 0);
    let cfg = PoolConfig::default();
    let (tx, _rx) = mpsc::channel(8);
    let _life = WorkerLife::birth(&shared, 0);

    let mut inflight: VecDeque<Work> = VecDeque::new();
    for slot in 0..2 {
        let w = next_work(&shared, ctx, &tx, Pipeline::payload(slot))
            .await
            .expect("queued");
        shared.charge_wire();
        shared.register_inflight(&w, 0);
        inflight.push_back(w);
    }
    // Productive session died between responses: nobody is charged.
    requeue_or_fail(&shared, &tx, &cfg, ctx, &mut inflight, LINK, "eof", false).await;
    {
        let q = shared.queue.lock().await;
        assert_eq!(q.len(), 2, "both articles requeue");
        for w in q.iter() {
            assert_eq!(w.attempts, 0, "an innocent requeue bumps nothing");
            assert_eq!(w.tried_fail, 0, "no server brand on a clean death");
        }
    }
    // Zero-work session death: the front casualty still pays, so
    // the charge-driven terminal path is intact.
    let mut inflight: VecDeque<Work> = VecDeque::new();
    for slot in 0..2 {
        let w = next_work(&shared, ctx, &tx, Pipeline::payload(slot))
            .await
            .expect("queued");
        shared.charge_wire();
        shared.register_inflight(&w, 0);
        inflight.push_back(w);
    }
    let front_id = inflight[0].id.clone();
    requeue_or_fail(&shared, &tx, &cfg, ctx, &mut inflight, LINK, "rst", true).await;
    let q = shared.queue.lock().await;
    let front = q.iter().find(|w| w.id == front_id).expect("requeued");
    assert_eq!(front.attempts, 1, "zero-work death charges the front");
    assert_eq!(front.tried_fail, ctx.bit, "and brands it with this server");
    assert!(
        q.iter()
            .filter(|w| w.id != front_id)
            .all(|w| w.attempts == 0 && w.tried_fail == 0),
        "pipeline mates stay uncharged either way"
    );
}

#[tokio::test]
async fn stream_mode_engages_on_promote_and_reader_touch() {
    // M11 stream mode: any reader touch (note_stream_active) or any
    // promote - even one that moves nothing - flips the pool into
    // shallow-pipeline mode; a fresh pool starts with it off.
    let reqs: Vec<ArticleReq> = (0..4)
        .map(|i| ArticleReq::fresh(format!("<a{i}>")))
        .collect();
    let (shared, _) = Shared::new(reqs, &one_server());
    let ctl = QueueControl::default();
    ctl.attach(&shared);
    assert!(!shared.stream_active(), "stream mode must start disengaged");
    ctl.note_stream_active();
    assert!(shared.stream_active(), "reader touch engages stream mode");

    let (shared2, _) = Shared::new(
        (0..4)
            .map(|i| ArticleReq::fresh(format!("<b{i}>")))
            .collect(),
        &one_server(),
    );
    let ctl2 = QueueControl::default();
    ctl2.attach(&shared2);
    assert_eq!(ctl2.promote(&["<zz>".into()]), 0);
    assert!(
        shared2.stream_active(),
        "a promote engages stream mode even when nothing moves"
    );
}

#[tokio::test]
async fn promoted_work_routes_to_the_faster_server() {
    // M11 stream mode: a slow server steps PAST promoted items a >2×
    // faster live server can take - leaving them at the queue front -
    // but still takes non-promoted work, and takes promoted work
    // itself when no faster server exists (never stranded).
    let mk = |host: &str| {
        (
            ServerConfig {
                host: host.into(),
                port: 119,
                tls: false,
                username: None,
                password: None,
                connections: 1,
                pin_connections: false,
                level: 0,
                group: None,
                retention_days: 0,
                rcvbuf: None,
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
            },
            PoolConfig::default(),
        )
    };
    let servers = vec![mk("slow"), mk("fast")];
    let reqs: Vec<ArticleReq> = (0..4)
        .map(|i| ArticleReq::fresh(format!("<a{i}>")))
        .collect();
    let (shared, _) = Shared::new(reqs, &servers);
    let _a = WorkerLife::birth(&shared, 0);
    let _b = WorkerLife::birth(&shared, 1);
    let ctl = QueueControl::default();
    ctl.attach(&shared);
    // Server 1 measured 10× faster than server 0.
    shared.bytes[0].store(1_000_000, Ordering::Relaxed);
    shared.bytes[1].store(10_000_000, Ordering::Relaxed);
    // Promote a1 and a2; stream mode engages via the promote.
    let ids: Vec<Arc<str>> = ["<a1>", "<a2>"].iter().map(|s| Arc::from(*s)).collect();
    assert_eq!(ctl.promote(&ids), 2);

    let slow = ServerCtx {
        idx: 0,
        bit: 0b01,
        all: 0b11,
        group_bits: 0b01,
        level: 0,
    };
    let fast = ServerCtx {
        idx: 1,
        bit: 0b10,
        all: 0b11,
        group_bits: 0b10,
        level: 0,
    };
    let (tx, _rx) = mpsc::channel(16);

    // The slow server skips a1/a2 and takes the first non-promoted
    // item; the promoted run stays at the queue front.
    let w = next_work(&shared, slow, &tx, Pipeline::payload(0))
        .await
        .expect("slow gets non-promoted work");
    assert_eq!(&*w.id, "<a0>");
    assert_eq!(
        shared.queue.lock().await.front().map(|w| w.id.clone()),
        Some("<a1>".into()),
        "promoted run must stay at the front for the fast server"
    );
    // The fast server takes the promoted item.
    let w = next_work(&shared, fast, &tx, Pipeline::payload(0))
        .await
        .expect("fast gets promoted work");
    assert_eq!(&*w.id, "<a1>");
    assert!(w.promoted);
    // A promoted item some backbone already 430'd bypasses the
    // speed-matching: latency beats routing once it's on a recovery
    // path (the live wedge: fast servers cycling 430 → requeue while
    // slow ones politely skipped).
    shared.queue.lock().await.front_mut().unwrap().tried_430 = 0b10;
    let w = next_work(&shared, slow, &tx, Pipeline::payload(0))
        .await
        .expect("slow takes the 430-recovery item");
    assert_eq!(&*w.id, "<a2>");
    assert!(w.promoted);

    // Kill the fast server; the slow one must take promoted work
    // rather than strand it.
    let reqs2: Vec<ArticleReq> = vec![ArticleReq::fresh("<b0>")];
    let (shared2, _) = Shared::new(reqs2, &servers);
    let _c = WorkerLife::birth(&shared2, 0);
    let ctl2 = QueueControl::default();
    ctl2.attach(&shared2);
    shared2.bytes[0].store(1_000_000, Ordering::Relaxed);
    shared2.bytes[1].store(10_000_000, Ordering::Relaxed);
    assert_eq!(ctl2.promote(&["<b0>".into()]), 1);
    let w = next_work(&shared2, slow, &tx, Pipeline::payload(0))
        .await
        .expect("slow takes it when alone");
    assert_eq!(&*w.id, "<b0>");
}

/// A dup that leaves flight without emitting gives the article its one
/// hedge budget BACK.
///
/// `pick_dup` charges `inf.dups += 1` at pick time, and nothing ever
/// gave it back: an article whose dup was shed (or died with its
/// connection) before reading a byte had spent its rescue on a dispatch
/// that never happened, and both pickers then refuse it forever -
/// `pick_dup` at `dups >= 1`, the TTFB rescue at `dups == 0`.
///
/// The dup rides a DIFFERENT worker's pipeline from its original, which
/// is what makes the leak reachable at all: shed together, the original
/// deregisters the whole entry on its way out and the next dispatch
/// starts from zero anyway.
#[tokio::test]
async fn a_shed_dup_gives_the_hedge_budget_back() {
    let reqs: Vec<ArticleReq> = (0..3)
        .map(|i| ArticleReq::fresh(format!("<a{i}>")))
        .collect();
    let (shared, _) = Shared::new(reqs, &one_server());

    // Worker A dispatches the original and keeps holding it.
    let original = {
        let mut q = shared.queue.lock().await;
        let w = q.pop_front().unwrap();
        shared.charge_wire();
        shared.register_inflight(&w, 0);
        w
    };
    assert_eq!(&*original.id, "<a0>");

    // Worker B races it - the pick charges the article's one budget.
    shared
        .inflight
        .lock_ok()
        .get_mut(&original.id)
        .unwrap()
        .dups += 1;
    shared.charge_wire();
    let mut b_pipeline: VecDeque<Work> = VecDeque::new();
    b_pipeline.push_back(Work {
        age_days: original.age_days,
        part: original.part,
        file: original.file,
        ord: original.ord,
        id: original.id.clone(),
        attempts: 0,
        promoted: false,
        tried_430: 0,
        tried_fail: 0,
        dup: true,
        prebyte_expiries: 0,
        soft_430: 0,
        fenced: false,
        rearms: 0,
        ladder: false,
        probe: false,
    });

    shed_pipeline(&shared, &mut b_pipeline).await;
    assert!(b_pipeline.is_empty());
    assert_eq!(
        shared.queue.lock().await.len(),
        2,
        "a dup is dropped, never requeued - the original still owns it"
    );
    assert_eq!(
        shared.inflight.lock_ok().get(&original.id).unwrap().dups,
        0,
        "the budget is back, so a later stale/TTFB rescue is still legal"
    );

    // And an entry that is already gone (the original landed while the
    // dup was in flight) is a no-op rather than a panic.
    shared.deregister_inflight(&original);
    let mut late: VecDeque<Work> = VecDeque::new();
    shared.charge_wire();
    late.push_back(Work {
        age_days: original.age_days,
        part: original.part,
        file: original.file,
        ord: original.ord,
        id: original.id.clone(),
        attempts: 0,
        promoted: false,
        tried_430: 0,
        tried_fail: 0,
        dup: true,
        prebyte_expiries: 0,
        soft_430: 0,
        fenced: false,
        rearms: 0,
        ladder: false,
        probe: false,
    });
    shed_pipeline(&shared, &mut late).await;
}

#[tokio::test]
async fn shed_pipeline_requeues_behind_promoted_run_uncharged() {
    // M11 shed: a worker abandoning its pre-stream pipeline puts the
    // in-flight items back BEHIND the promoted run, in order, without
    // charging attempts; tail dups are dropped, not requeued.
    let reqs: Vec<ArticleReq> = (0..10)
        .map(|i| ArticleReq::fresh(format!("<a{i}>")))
        .collect();
    let (shared, _) = Shared::new(reqs, &one_server());
    let ctl = QueueControl::default();
    ctl.attach(&shared);

    // Simulate a window-3 pipeline: a0..a2 popped and dispatched.
    // Dispatch charges the wire cap, so the fixture must too - every
    // item in a worker's pipeline carries exactly one charge.
    let mut inflight: VecDeque<Work> = VecDeque::new();
    {
        let mut q = shared.queue.lock().await;
        for _ in 0..3 {
            let w = q.pop_front().unwrap();
            shared.charge_wire();
            shared.register_inflight(&w, 0);
            inflight.push_back(w);
        }
    }
    // A tail dup rides the same pipeline (charged too - its response
    // is just as real).
    shared.charge_wire();
    inflight.push_back(Work {
        age_days: 0,
        part: 0,
        file: u32::MAX,
        ord: 0,
        id: "<a5>".into(),
        attempts: 0,
        promoted: false,
        tried_430: 0,
        tried_fail: 0,
        dup: true,
        prebyte_expiries: 0,
        soft_430: 0,
        fenced: false,
        rearms: 0,
        ladder: false,
        probe: false,
    });
    // A seek promotes a7 and a3 to the front (in that range order).
    let ids: Vec<Arc<str>> = ["<a7>", "<a3>"].iter().map(|s| Arc::from(*s)).collect();
    assert_eq!(ctl.promote(&ids), 2);

    shed_pipeline(&shared, &mut inflight).await;
    assert!(inflight.is_empty());
    let q = shared.queue.lock().await;
    let order: Vec<&str> = q.iter().map(|w| &*w.id).collect();
    assert_eq!(
        order,
        [
            "<a7>", "<a3>", "<a0>", "<a1>", "<a2>", "<a4>", "<a5>", "<a6>", "<a8>", "<a9>"
        ],
        "shed items must slot in behind the promoted run, in order"
    );
    assert!(
        q.iter().all(|w| w.attempts == 0),
        "an abandoned pipeline is not a failure - no attempts charged"
    );
    assert_eq!(
        q.iter().filter(|w| w.dup).count(),
        0,
        "the tail dup must be dropped, not requeued"
    );
    drop(q);
    assert!(
        shared.inflight.lock().unwrap().is_empty(),
        "shed items must be deregistered from inflight"
    );
    assert_eq!(
        shared.inflight_body_bytes.load(Ordering::Acquire),
        0,
        "the shed pipeline must release every charge it held, dup included"
    );
}

#[tokio::test]
async fn drain_signals_graceful_and_leaves_the_queue_intact() {
    // The friendly Pause plumbing: drain() flips is_draining (which the
    // worker top-up loop checks to stop admitting new articles) WITHOUT
    // touching the queue - so everything unstarted is still there for a
    // resume. Contrast abort(), which is the hard stop.
    let servers: Vec<(ServerConfig, PoolConfig)> = vec![(
        ServerConfig {
            host: "s".into(),
            port: 119,
            tls: false,
            username: None,
            password: None,
            connections: 1,
            pin_connections: false,
            level: 0,
            group: None,
            retention_days: 0,
            rcvbuf: None,
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
        },
        PoolConfig::default(),
    )];
    let reqs: Vec<ArticleReq> = (0..8)
        .map(|i| ArticleReq::fresh(format!("<a{i}>")))
        .collect();
    let (shared, _) = Shared::new(reqs, &servers);
    let ctl = QueueControl::default();
    ctl.attach(&shared);

    assert!(!ctl.is_draining());
    assert!(ctl.drain(), "drain should reach the live pool");
    assert!(
        ctl.is_draining(),
        "is_draining must reflect a requested drain"
    );
    // The queue is untouched - unstarted work is preserved for resume.
    assert_eq!(shared.queue.lock().await.len(), 8);

    // The ordering that matters in production: the engine only asks
    // AFTER the fetch call returned, which is where the pool's last
    // strong Arc dies. The answer must survive that.
    drop(shared);
    assert!(
        ctl.is_draining(),
        "a drain requested on a live pool must still read as draining once the pool is gone"
    );

    // A dead pool (Weak gone) is a no-op, never a panic - and it must
    // not latch a drain that never reached a run.
    let dead = QueueControl::default();
    assert!(!dead.drain());
    assert!(!dead.is_draining());
}

/// Drain a finished run's outcome channel into id → outcome-count.
/// `try_recv` on purpose: anything still missing here was NOT emitted
/// before the pool returned, which is exactly the contract under test.
fn tally(rx: &mut mpsc::Receiver<FetchOutcome>) -> HashMap<Arc<str>, usize> {
    let mut seen: HashMap<Arc<str>, usize> = HashMap::new();
    while let Ok(o) = rx.try_recv() {
        let id = match o {
            FetchOutcome::Done { id, .. }
            | FetchOutcome::Missing { id, .. }
            | FetchOutcome::Failed { id, .. } => id,
        };
        *seen.entry(id).or_default() += 1;
    }
    seen
}

fn assert_exactly_one_outcome_each(ids: &[Arc<str>], seen: &HashMap<Arc<str>, usize>) {
    for id in ids {
        assert_eq!(
            seen.get(id).copied().unwrap_or(0),
            1,
            "{id} must have exactly one terminal outcome, got {:?}",
            seen.get(id)
        );
    }
    assert_eq!(seen.len(), ids.len(), "unexpected extra outcomes: {seen:?}");
}

/// A15 regression: a server that never accepts a connection.
///
/// Every worker burns `max_connect_attempts` and bows out. Before the
/// seal, the last one out simply returned - `join_fleet` had no
/// postcondition, the senders dropped, and the channel closed without
/// a single word about any of the requested articles. Downstream that
/// reads as "the network said nothing", so repair ran against a
/// ledger that never recorded the failures.
#[tokio::test]
async fn dead_server_seals_every_article_before_returning() {
    // Bind then drop: a port with nothing listening, so connect()
    // fails immediately rather than hanging on a firewalled SYN.
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let mut server = one_server()[0].0.clone();
    server.host = "127.0.0.1".into();
    server.port = port;
    let cfg = PoolConfig {
        connections: 3,
        ramp_delay: Duration::ZERO,
        connect_backoff: Duration::from_millis(1),
        max_connect_attempts: 2,
        // The seal is what this test is about, not the length of
        // the road to it. At the shipped 75 the prober pays 75 real
        // connect attempts here, and a refused connect costs
        // microseconds on macOS but ~2 s on Windows (measured:
        // 152 s for 75) - so the horizon, not the pool, decided
        // whether this finished inside the timeout, and it did not
        // on Windows. Three bounces reach the same Dead episode by
        // the same path on every platform, and keep the Windows
        // wall (~2 s per dial, workers and ladder together) at
        // roughly half the 20 s guard rather than grazing it.
        cap_probe_bounces: 3,
        ..Default::default()
    };
    let ids: Vec<Arc<str>> = (0..5).map(|i| Arc::from(format!("<seal{i}@x>"))).collect();
    let reqs: Vec<ArticleReq> = ids.iter().cloned().map(ArticleReq::fresh).collect();
    let (tx, mut rx) = mpsc::channel(64);
    tokio::time::timeout(
        Duration::from_secs(20),
        fetch_all_multi(&[(server, cfg)], reqs, tx),
    )
    .await
    .expect("run hung with no reachable server");

    let seen = tally(&mut rx);
    assert_exactly_one_outcome_each(&ids, &seen);
}

/// §15e: a rejected credential is settled ONCE for the server, not
/// rediscovered by every worker.
///
/// Each worker used to burn its own `max_connect_attempts` behind its
/// own growing backoff, so the account that had already said no got
/// asked `connections x max_connect_attempts` times - here 8 x 5 = 40.
/// Nothing about that can succeed, and on a provider that refuses for
/// CAPACITY reasons (same 481) the retries re-provoke the very limit
/// being hit.
#[tokio::test]
async fn a_rejected_credential_is_asked_once_per_server_not_once_per_worker() {
    use crate::mock::{Chaos, MockServer};
    let srv = MockServer::start(
        std::collections::HashMap::new(),
        Chaos {
            auth_rejected: true,
            ..Default::default()
        },
    )
    .await;
    let mut server = srv.server_config();
    server.username = Some("u".into());
    server.password = Some("p".into());
    const CONNS: usize = 8;
    let cfg = PoolConfig {
        connections: CONNS,
        ramp_delay: Duration::ZERO,
        connect_backoff: Duration::from_millis(1),
        max_connect_attempts: 5,
        ..Default::default()
    };
    let ids: Vec<Arc<str>> = (0..4).map(|i| Arc::from(format!("<perm{i}@x>"))).collect();
    let reqs: Vec<ArticleReq> = ids.iter().cloned().map(ArticleReq::fresh).collect();
    let (tx, mut rx) = mpsc::channel(64);
    tokio::time::timeout(
        Duration::from_secs(20),
        fetch_all_multi(&[(server, cfg)], reqs, tx),
    )
    .await
    .expect("run hung on a permanently rejected server");

    // The terminal-state contract still holds.
    let seen = tally(&mut rx);
    assert_exactly_one_outcome_each(&ids, &seen);

    // Workers start concurrently, so up to `CONNS` can be in the air
    // before the first refusal is recorded - but not a single retry
    // beyond that.
    let accepted = srv.accepted.load(Ordering::Relaxed);
    assert!(
        accepted <= CONNS as u64,
        "a rejected credential was re-asked: {accepted} connections for {CONNS} workers"
    );
}

/// §15e: a CAPACITY refusal is answered by asking for fewer
/// connections, which is the only thing a simultaneous-connection or
/// simultaneous-IP cap actually accepts.
///
/// Giganews answers `481 max simultaneous IP addresses reached` for a
/// perfectly good account at its cap - the same code as a wrong
/// password, so only the text tells them apart. Retrying all workers
/// at the same count re-provokes it, and behind a multi-WAN router
/// each retry can present a fresh IP and re-exhaust the cap itself.
/// Workers yield their slots instead, leaving one still trying so a
/// cap that clears later does not strand the server for the run.
#[tokio::test]
async fn a_capacity_refusal_yields_connections_instead_of_hammering() {
    use crate::mock::{Chaos, MockServer};
    let srv = MockServer::start(
        std::collections::HashMap::new(),
        Chaos {
            auth_rejected: true,
            auth_refusal_text: Some("481 max simultaneous IP addresses reached".into()),
            ..Default::default()
        },
    )
    .await;
    let mut server = srv.server_config();
    server.username = Some("u".into());
    server.password = Some("p".into());
    const CONNS: usize = 8;
    const ATTEMPTS: u32 = 5;
    let cfg = PoolConfig {
        connections: CONNS,
        ramp_delay: Duration::ZERO,
        connect_backoff: Duration::from_millis(1),
        max_connect_attempts: ATTEMPTS,
        ..Default::default()
    };
    let ids: Vec<Arc<str>> = (0..4).map(|i| Arc::from(format!("<cap{i}@x>"))).collect();
    let reqs: Vec<ArticleReq> = ids.iter().cloned().map(ArticleReq::fresh).collect();
    let (tx, mut rx) = mpsc::channel(64);
    tokio::time::timeout(
        Duration::from_secs(20),
        fetch_all_multi(&[(server, cfg)], reqs, tx),
    )
    .await
    .expect("run hung on a server at its connection cap");

    let seen = tally(&mut rx);
    assert_exactly_one_outcome_each(&ids, &seen);

    // Each worker gets one look, then yields; the last one standing
    // probes alone on the capped 8 s bounce ladder for up to
    // CAP_PROBE_BOUNCES (issue #16: a restart's ghost sessions can
    // hold the cap for minutes, and quitting after five bounces was
    // the reported 0 MB/s stall). The 1 ms test backoff compresses
    // that whole probe window into the run; the bound is the
    // fleet's one look each plus the lone prober's budget - the old
    // failure mode was EVERY worker spending the ladder.
    let accepted = srv.accepted.load(Ordering::Relaxed);
    assert!(
        accepted <= CONNS as u64 + CAP_PROBE_BOUNCES as u64,
        "capacity refusal still hammered the cap: {accepted} connections"
    );
    assert!(
        accepted >= CONNS as u64,
        "workers should each get one look before yielding, got {accepted}"
    );
}

/// The Providers card's cap gauge: what a provider ACTUALLY grants.
///
/// Giganews granted 38 sessions against a Diamond account provisioned
/// for 100 (18 Aug 2026). It took a day to find because the only place
/// the 38 existed was daemon.log - the dashboard row read "using 0 of
/// 100", the configured number and the live number and neither of the
/// two that mattered, and when support asked for a screenshot there
/// was nothing to screenshot.
///
/// The mock's `accept_cap` is that shape exactly: two sessions get in,
/// every further dial bounces off a 502 capacity refusal at the
/// greeting. `granted_hi` must come out as the sessions the server was
/// serving when it refused - not as the configured count, and not as
/// zero.
///
/// The mock words its accept cap as a CONNECTION limit, which is what
/// `accept_cap` models. Since Codex sweep 5 M9 a simultaneous-IP refusal
/// is deliberately NOT recorded as a connection ceiling - the sessions
/// held at one are incidental, and calling them the account's cap sends
/// the user at the wrong remedy - so the wording has to be accurate.
///
/// Dials are staggered because a simultaneous fleet races the mock's
/// live count past its own cap before any accept task checks it (the
/// note on `payout_flap_breaker_collapses_ip_cap_churn`): with every
/// dial bouncing, no session is ever held and the honest answer really
/// is zero.
#[tokio::test(flavor = "multi_thread")]
async fn a_capacity_refusal_records_what_the_provider_granted() {
    use crate::mock::{Chaos, MockServer};
    const CAP: u64 = 2;
    const CONNS: usize = 6;
    let data: Vec<u8> = (0..240_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("cap.bin", &data, 10_000, "gr", &mut articles);
    let ids: Vec<Arc<str>> = bracketed(&segs);
    let srv = MockServer::start(
        articles,
        Chaos {
            accept_cap: Some(CAP),
            // Slow enough that the whole fleet gets to dial before the
            // two winners have finished the work. Without it the run is
            // over in 20 ms, workers 3..6 never dial, nothing bounces,
            // and the test proves only that a fast job is fast.
            throttle: crate::mock::Throttle {
                per_conn_bps: 60_000,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    let mut server = srv.server_config();
    server.connections = CONNS as u32;
    let live = LiveStats::for_servers(&[(server.clone(), PoolConfig::default())]);
    let cfg = PoolConfig {
        connections: CONNS,
        ramp_delay: Duration::from_millis(50),
        connect_backoff: Duration::from_millis(5),
        live: Some(live.clone()),
        ..Default::default()
    };
    let reqs: Vec<ArticleReq> = ids.iter().cloned().map(ArticleReq::fresh).collect();
    let (tx, mut rx) = mpsc::channel(64);
    tokio::time::timeout(
        Duration::from_secs(30),
        fetch_all_multi(&[(server, cfg)], reqs, tx),
    )
    .await
    .expect("run hung on a capped server");
    let seen = tally(&mut rx);
    assert_exactly_one_outcome_each(&ids, &seen);

    let s = &live.servers[0];
    // The gate: nothing is claimed until a capacity refusal is heard.
    // Every idle provider satisfies `connected < configured`, so
    // arithmetic must never be what sets this.
    assert!(
        s.capped_since.load(Ordering::Relaxed) > 0,
        "a 502 capacity refusal left no cap stamp"
    );
    let granted = s.granted_hi.load(Ordering::Relaxed);
    assert!(
        granted > 0 && granted as u64 <= CAP,
        "granted_hi should be the sessions held at the refusal (<= {CAP}), got {granted}"
    );
    // And the ask that was refused, which is what makes "capped at 2 of
    // 6" a sentence rather than a number.
    assert_eq!(
        s.capped_at.load(Ordering::Relaxed),
        CONNS,
        "capped_at should be the count we were asking for"
    );
}

/// The other half of the same rule, stated as a negative: a healthy
/// server that simply never needs its whole fleet must leave the cap
/// gauge untouched.
///
/// This is the 7 Aug mistake in the shape it would take here. 38
/// pre-byte-budget rotations painted red fault dots on a flawless 3.3
/// Gbps run because a deliberate act was counted as a failure; a row
/// that reads "capped at 4 of 16" off an idle provider would be the
/// same error with a different gauge, and it would be told on every
/// download rather than once.
#[tokio::test]
async fn an_idle_provider_never_reads_as_capped() {
    use crate::mock::{Chaos, MockServer};
    let data: Vec<u8> = (0..30_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("easy.bin", &data, 10_000, "ez", &mut articles);
    let ids: Vec<Arc<str>> = bracketed(&segs);
    let srv = MockServer::start(articles, Chaos::default()).await;
    let mut server = srv.server_config();
    // Far more connections than there is work for: every one of them
    // will sit idle, which is precisely the state that must not be
    // reported as a refusal.
    server.connections = 16;
    let live = LiveStats::for_servers(&[(server.clone(), PoolConfig::default())]);
    let cfg = PoolConfig {
        connections: 16,
        live: Some(live.clone()),
        ..Default::default()
    };
    let reqs: Vec<ArticleReq> = ids.iter().cloned().map(ArticleReq::fresh).collect();
    let (tx, mut rx) = mpsc::channel(16);
    tokio::time::timeout(
        Duration::from_secs(20),
        fetch_all_multi(&[(server, cfg)], reqs, tx),
    )
    .await
    .expect("run hung on a healthy server");
    let seen = tally(&mut rx);
    assert_exactly_one_outcome_each(&ids, &seen);
    let s = &live.servers[0];
    assert_eq!(
        s.capped_since.load(Ordering::Relaxed),
        0,
        "an idle fleet must not look like a refused one"
    );
    assert_eq!(s.granted_hi.load(Ordering::Relaxed), 0);
}

/// §34: a dead server must not hold the run open after the work is
/// done. Measured on the bench farm, one dead provider in a
/// six-server config DOUBLED per-job time (4.1 s vs 2.0 s): the bytes
/// were all in at 0.79 s and the run did not return until 3.17 s,
/// with nothing outstanding but a server that would never answer.
/// Its workers were asleep in a connect backoff that could not see
/// the run finish.
///
/// Here the live server can serve everything immediately while the
/// dead one's backoff is far longer than the work, so if the backoff
/// is not raced against the finish signal the run cannot come back
/// inside the timeout.
#[tokio::test]
async fn a_dead_server_does_not_hold_the_run_open_after_the_work_is_done() {
    use crate::mock::{Chaos, MockServer};
    let mut arts = std::collections::HashMap::new();
    let data: Vec<u8> = (0..20_000u32).map(|i| i as u8).collect();
    let segs = crate::mock::make_file_articles("t.bin", &data, 5_000, "tail", &mut arts);
    let ids: Vec<Arc<str>> = bracketed(&segs);
    let live = MockServer::start(arts, Chaos::default()).await;

    // Dead: TCP connects, AUTHINFO never succeeds.
    let dead = MockServer::start(
        std::collections::HashMap::new(),
        Chaos {
            auth_rejected: true,
            auth_refusal_text: Some("481 max simultaneous IP addresses reached".into()),
            ..Default::default()
        },
    )
    .await;
    let mut dead_cfg = dead.server_config();
    dead_cfg.username = Some("u".into());
    dead_cfg.password = Some("p".into());

    // A backoff far longer than the work: 30 s of sleeping against a
    // job that finishes in milliseconds.
    let slow = PoolConfig {
        connections: 2,
        ramp_delay: Duration::ZERO,
        connect_backoff: Duration::from_secs(30),
        max_connect_attempts: 5,
        ..Default::default()
    };
    let fast = PoolConfig {
        connections: 2,
        ramp_delay: Duration::ZERO,
        ..Default::default()
    };

    let reqs: Vec<ArticleReq> = ids.iter().cloned().map(ArticleReq::fresh).collect();
    let (tx, mut rx) = mpsc::channel(64);
    let t0 = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(20),
        fetch_all_multi(&[(live.server_config(), fast), (dead_cfg, slow)], reqs, tx),
    )
    .await
    .expect("a dead server's backoff held the run open past the work");
    let elapsed = t0.elapsed();

    let seen = tally(&mut rx);
    assert_exactly_one_outcome_each(&ids, &seen);
    // The work itself is milliseconds. Without the finish-aware
    // backoff this same test takes ~5 s, so the threshold has to
    // discriminate rather than merely bound: generous for a loaded
    // CI box, nowhere near a single 30 s backoff leg.
    assert!(
        elapsed < Duration::from_secs(2),
        "run took {elapsed:?} for work that was done immediately"
    );
}

/// The classification is the whole feature, and it keys off free-form
/// provider text, so it is pinned directly. Anything not recognisably
/// about capacity must read as Permanent: retrying a bad credential
/// forever is the worse of the two failures.
#[test]
fn auth_refusals_are_classified_by_what_the_provider_actually_says() {
    use crate::nntp::{AuthRefusal, classify_auth_refusal};
    for line in [
        "481 max simultaneous IP addresses reached",
        "502 Too many connections",
        "481 Connection limit reached",
        "482 too many sessions for this user",
        "400 no more connections available",
    ] {
        assert_eq!(
            classify_auth_refusal(line),
            AuthRefusal::Capacity,
            "should be a capacity refusal: {line}"
        );
    }
    for line in [
        "481 authentication failed",
        "481 Authentication rejected",
        "502 Permission denied",
        "481 account suspended",
        "",
    ] {
        assert_eq!(
            classify_auth_refusal(line),
            AuthRefusal::Permanent,
            "should be permanent: {line}"
        );
    }
}

/// Regression for the capacity-yield survivor rule.
///
/// `35c7ca9` decided the survivor by counting yields up to
/// `cfg.connections`. Workers also leave through the connect ladder
/// and the session bow-out, and neither increments that counter, so
/// once anyone had left by another door the target was unreachable
/// and EVERY remaining worker yielded - leaving the server with
/// nobody, on precisely the transient refusal the arm exists to ride
/// out. A single-server job then sealed the rest of its articles
/// Failed seconds before the cap cleared.
///
/// The rule under test: a worker may only yield while it leaves
/// someone behind, however the others left.
#[test]
fn a_capacity_yield_always_leaves_one_worker_behind() {
    let auth = AuthState::default();

    // Eight configured, but six already retired on the connect ladder
    // during a blip - none of them through `yielded`.
    let alive = AtomicUsize::new(2);

    // Worker 7 takes the refusal: one other is still up, so it goes.
    assert!(
        auth.claim_yield(&alive),
        "a worker with company should yield"
    );
    alive.fetch_sub(1, Ordering::SeqCst); // WorkerLife::drop

    // Worker 8 is now the last one on this server. Under the old
    // `yielded < cfg.connections` rule it saw 2 < 8 and left too.
    assert!(
        !auth.claim_yield(&alive),
        "the last worker must not yield: that strands the server for the run"
    );
    assert_eq!(
        alive.load(Ordering::SeqCst),
        1,
        "someone must still be trying"
    );

    // And it keeps refusing to leave however often the cap is hit.
    for _ in 0..5 {
        assert!(!auth.claim_yield(&alive), "still the last one out");
    }
}

/// The same rule with nobody having left early: the fleet stands
/// down, but never past the last worker however long the cap lasts.
///
/// The count it settles on is deliberately conservative (about half,
/// not one) because `yielded` also counts claims whose `alive`
/// decrement has not landed yet - see `claim_yield`. What must hold
/// for every fleet size is: fewer workers than we started with, and
/// never zero.
#[test]
fn a_yielding_fleet_shrinks_but_never_empties() {
    for start in [1usize, 2, 4, 8, 30] {
        let auth = AuthState::default();
        let alive = AtomicUsize::new(start);
        for _ in 0..100 {
            if auth.claim_yield(&alive) {
                alive.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let left = alive.load(Ordering::SeqCst);
        assert!(left >= 1, "fleet of {start} was stranded with no workers");
        assert!(left <= start, "fleet of {start} somehow grew to {left}");
        if start > 1 {
            assert!(
                left < start,
                "fleet of {start} never stood down at all, so the cap is still being hammered"
            );
        }
    }
}

/// A15 regression, the other half: the TCP connect always succeeds,
/// so this is not a connect-refused fast path - the session is simply
/// never usable. Same contract: one outcome per requested id, all of
/// them emitted before the fetch returns.
#[tokio::test]
async fn server_that_never_authenticates_seals_every_article() {
    use crate::mock::{Chaos, MockServer};
    let srv = MockServer::start(
        std::collections::HashMap::new(),
        Chaos {
            auth_rejected: true,
            ..Default::default()
        },
    )
    .await;
    let mut server = srv.server_config();
    server.username = Some("u".into());
    server.password = Some("p".into());
    let cfg = PoolConfig {
        connections: 2,
        ramp_delay: Duration::ZERO,
        connect_backoff: Duration::from_millis(1),
        max_connect_attempts: 2,
        ..Default::default()
    };
    let ids: Vec<Arc<str>> = (0..4).map(|i| Arc::from(format!("<auth{i}@x>"))).collect();
    let reqs: Vec<ArticleReq> = ids.iter().cloned().map(ArticleReq::fresh).collect();
    let (tx, mut rx) = mpsc::channel(64);
    tokio::time::timeout(
        Duration::from_secs(20),
        fetch_all_multi(&[(server, cfg)], reqs, tx),
    )
    .await
    .expect("run hung on a server that never authenticates");

    let seen = tally(&mut rx);
    assert_exactly_one_outcome_each(&ids, &seen);
    for id in &ids {
        assert!(seen.contains_key(id));
    }
}

/// A dead server must not poison a healthy one: the seal only fires
/// when the LAST worker of the whole run leaves, so articles the live
/// backbone can still serve are served, not failed out from under it.
#[tokio::test]
async fn one_dead_server_does_not_seal_work_the_live_one_can_still_do() {
    use crate::mock::{Chaos, MockServer, make_file_articles};
    let mut articles = std::collections::HashMap::new();
    let payload: Vec<u8> = (0..40_000u32).map(|i| (i * 3) as u8).collect();
    make_file_articles("h.bin", &payload, 8_000, "sl", &mut articles);
    let n = articles.len();
    let healthy = MockServer::start(articles.clone(), Chaos::default()).await;

    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let mut dead = one_server()[0].0.clone();
    dead.host = "127.0.0.1".into();
    dead.port = port;

    let live_cfg = PoolConfig {
        connections: 2,
        ramp_delay: Duration::ZERO,
        ..Default::default()
    };
    // Bows out fast, long before the healthy server finishes.
    let dead_cfg = PoolConfig {
        connections: 2,
        ramp_delay: Duration::ZERO,
        connect_backoff: Duration::from_millis(1),
        max_connect_attempts: 1,
        ..Default::default()
    };
    let ids: Vec<Arc<str>> = articles.keys().map(|k| Arc::from(k.as_str())).collect();
    let reqs: Vec<ArticleReq> = ids.iter().cloned().map(ArticleReq::fresh).collect();
    let (tx, mut rx) = mpsc::channel(256);
    let stats = tokio::time::timeout(
        Duration::from_secs(30),
        fetch_all_multi(
            &[(healthy.server_config(), live_cfg), (dead, dead_cfg)],
            reqs,
            tx,
        ),
    )
    .await
    .expect("run hung with one dead server");

    // The failure summary names servers that sat out the whole run;
    // this is the bit it reads.
    assert!(stats[0].ever_connected, "the healthy server served");
    assert!(!stats[1].ever_connected, "the dead server never connected");
    // A3: never-connected and left-mid-run are different facts, and the
    // failure summary says different things about them. A server that
    // never held a connection cannot have walked out of the run.
    assert!(
        !stats[1].left_mid_run,
        "a server that never connected was reported as having LEFT the run"
    );

    let mut done = 0;
    let mut seen: HashMap<Arc<str>, usize> = HashMap::new();
    while let Ok(o) = rx.try_recv() {
        let id = match o {
            FetchOutcome::Done { id, .. } => {
                done += 1;
                id
            }
            FetchOutcome::Missing { id, .. } | FetchOutcome::Failed { id, .. } => id,
        };
        *seen.entry(id).or_default() += 1;
    }
    assert_eq!(done, n, "the live server had to deliver every article");
    assert_exactly_one_outcome_each(&ids, &seen);
}

/// Codex sweep 2, 3 Aug M6. A budget trained down to the floor
/// by pipelined ~0 ms samples has to be able to climb back out
/// WITHIN the article retry allowance (four charged attempts by
/// default), or a provider that settles just above the floor fails
/// every article on a link the flat path would have served.
///
/// Deterministic and pool-free on purpose: with a live fleet the
/// other workers' successful samples feed the same cell, so a test
/// that drove real connections could pass on someone else's
/// evidence instead of on the escalation under test.
#[test]
fn a_pre_byte_timeout_widens_past_the_budget_that_expired() {
    // The shape the bug needed: pipelining collapsed the EWMA to
    // 1 ms, so every budget is the floor and doubling the raw
    // value (1, 2, 4, 8, 16 ms) never moves it.
    let mut ewma = 1u64;
    let mut ladder = Vec::new();
    for _ in 0..4 {
        let budget = ttfb_budget_ms(ewma);
        ladder.push(budget);
        ewma = escalated_ttfb_ms(ewma);
        // Strictly wider every time, until the ceiling - which is
        // the only place a budget is allowed to stand still.
        assert!(
            ttfb_budget_ms(ewma) > budget || budget == ADAPTIVE_FIRST_BYTE_MAX.as_millis() as u64,
            "a timeout at {budget} ms must buy the next attempt more than {budget} ms, \
             got {}",
            ttfb_budget_ms(ewma)
        );
    }
    // Floor-derived, so this moved with the 2 s -> 4 s floor
    // (14 Aug 2026): it starts a rung higher and tops out a step
    // sooner. What the test is actually about - that four charged
    // attempts cannot all be spent at the same floor - is unchanged.
    assert_eq!(ladder, vec![4_000, 8_000, 10_000, 10_000]);
    // A 2.5 s server is now served by the FIRST attempt, and a 5 s one
    // by the second - still well inside the default four, which is the
    // whole point.
    assert!(ladder[0] >= 2_500);
    assert!(ladder[1] >= 5_000);

    // The ceiling still holds however many timeouts arrive, and an
    // unmeasured server (which already budgets at the ceiling) has
    // nothing to widen.
    let mut ewma = escalated_ttfb_ms(0);
    for _ in 0..20 {
        ewma = escalated_ttfb_ms(ewma);
    }
    assert_eq!(
        ttfb_budget_ms(ewma),
        ADAPTIVE_FIRST_BYTE_MAX.as_millis() as u64
    );

    // And the ordinary path is untouched: a server whose 4x EWMA has
    // reached the floor still doubles from there on the escalation.
    assert_eq!(ttfb_budget_ms(1_000), 4_000);
    assert_eq!(ttfb_budget_ms(escalated_ttfb_ms(1_000)), 8_000);
}

/// §275 item 5: a sole-server fleet budgets against a doubled floor,
/// because its pre-byte kill has no other server to re-place the
/// article on - it re-dials the same provider and pays a handshake to
/// repeat the question. Watched live 24 Aug 2026 on a giganews-only
/// daemon: 972 of 1,002 reconnects in one job were "our pre-byte
/// budget" against a provider whose cold-spool articles take seconds
/// to first byte.
#[test]
fn a_sole_server_fleet_budgets_against_a_doubled_floor() {
    let min = ADAPTIVE_FIRST_BYTE_MIN.as_millis() as u64;
    let max = ADAPTIVE_FIRST_BYTE_MAX.as_millis() as u64;
    // Double the floor, still inside the ceiling.
    assert_eq!(sole_server_floor_ms(), (2 * min).min(max));
    assert!(sole_server_floor_ms() <= max);
    // The application is max(), so a budget the EWMA already carried
    // above the doubled floor is untouched - only floor-bound budgets
    // move. (The max() itself lives in Shared::ttfb_budget; what is
    // pinned here is the two numbers it chooses between.)
    assert!(ttfb_budget_ms(5_000).max(sole_server_floor_ms()) == ttfb_budget_ms(5_000));
    assert_eq!(
        ttfb_budget_ms(1).max(sole_server_floor_ms()),
        sole_server_floor_ms()
    );
}

#[test]
fn session_backoff_grows_then_caps() {
    let cfg = PoolConfig {
        connect_backoff: Duration::from_millis(100),
        ..Default::default()
    };
    assert_eq!(
        session_backoff_delay_with(&cfg, 1, false),
        Duration::from_millis(100)
    );
    assert_eq!(
        session_backoff_delay_with(&cfg, 2, false),
        Duration::from_millis(200)
    );
    assert_eq!(
        session_backoff_delay_with(&cfg, 4, false),
        Duration::from_millis(800)
    );
    assert_eq!(
        session_backoff_delay_with(&cfg, 9, false),
        Duration::from_millis(25_600)
    );
    assert_eq!(
        session_backoff_delay_with(&cfg, 10, false),
        SESSION_BACKOFF_MAX
    );
    // No overflow, no runaway, however deep the failure count goes.
    assert_eq!(
        session_backoff_delay_with(&cfg, u32::MAX, false),
        SESSION_BACKOFF_MAX
    );
    // A configured base of ~0 must not defeat the pacing.
    let zero = PoolConfig {
        connect_backoff: Duration::ZERO,
        ..Default::default()
    };
    assert!(session_backoff_delay_with(&zero, 2, true) >= Duration::from_millis(50));
    assert!(session_backoff_delay_with(&zero, 1, false) >= Duration::from_millis(50));
}

#[test]
fn session_backoff_immediate_first_retry_shifts_the_ladder() {
    let cfg = PoolConfig {
        connect_backoff: Duration::from_millis(100),
        ..Default::default()
    };
    // Immediate mode: 0, base, 2x, 4x... - a transient blip redials
    // instantly, a persistent refuser meets the full ladder from
    // its second failure.
    assert_eq!(session_backoff_delay_with(&cfg, 1, true), Duration::ZERO);
    assert_eq!(
        session_backoff_delay_with(&cfg, 2, true),
        Duration::from_millis(100)
    );
    assert_eq!(
        session_backoff_delay_with(&cfg, 4, true),
        Duration::from_millis(400)
    );
    assert_eq!(
        session_backoff_delay_with(&cfg, u32::MAX, true),
        SESSION_BACKOFF_MAX
    );
    // The shipped default is the immediate shape (env unset).
    if std::env::var("NZBFAST_BACKOFF_IMMEDIATE").is_err() {
        assert_eq!(session_backoff_delay(&cfg, 1), Duration::ZERO);
    }
}

/// Regression: a broken account must not be reconnect-stormed.
///
/// The shape is a provider that accepts TCP and AUTHINFO every time
/// and then answers every BODY with a non-BODY status. Before the
/// session backoff, the `Ok(Err(_))` path did `requeue_or_fail` and
/// `continue 'session` with ZERO delay, and `connect_failures` was
/// reset by the successful connect, so the connect backoff never
/// applied: connect → AUTH → BODY → error → reconnect, several times
/// a second per worker, for as long as the queue had retries left.
/// On a big single-server job that is ~a million connect+AUTH
/// attempts at full rate - what providers ban accounts for.
///
/// So this asserts on the RATE, not on eventual give-up: how many
/// connections the server accepted inside a fixed window.
#[tokio::test]
async fn broken_session_server_is_paced_not_stormed() {
    use crate::mock::{Chaos, MockServer, make_file_articles};
    let mut articles = HashMap::new();
    let payload: Vec<u8> = (0..200_000u32).map(|i| (i * 5) as u8).collect();
    make_file_articles("storm.bin", &payload, 4_000, "st", &mut articles);
    let srv = MockServer::start(
        articles.clone(),
        Chaos {
            body_error: Some(u64::MAX),
            ..Default::default()
        },
    )
    .await;
    const WORKERS: usize = 4;
    let cfg = PoolConfig {
        connections: WORKERS,
        window: 1,
        ramp_delay: Duration::ZERO,
        connect_backoff: Duration::from_millis(100),
        // Deep enough that the queue cannot drain inside the window -
        // the test must measure the storm, not the bow-out.
        article_retries: 200,
        ..Default::default()
    };
    let reqs: Vec<ArticleReq> = articles
        .keys()
        .map(|id| ArticleReq::fresh(id.clone()))
        .collect();
    let (tx, _rx) = mpsc::channel(1024);
    let window = Duration::from_secs(1);
    let t0 = Instant::now();
    // Cancel at the window: the run is deliberately unfinishable.
    let _ = tokio::time::timeout(
        window,
        fetch_all_multi(&[(srv.server_config(), cfg)], reqs, tx),
    )
    .await;
    let accepted = srv.accepted.load(Ordering::Relaxed);
    assert!(
        accepted >= WORKERS as u64,
        "every worker should have tried at least once, got {accepted}"
    );
    // Paced: 100/200/400/800 ms per worker is at most 4 connects each
    // inside a 1 s window. The generous ceiling still sits two orders
    // of magnitude below the unpaced loop (thousands over loopback).
    assert!(
        accepted <= 10 * WORKERS as u64,
        "connect storm: {accepted} connections in {:?}",
        t0.elapsed()
    );
}

/// One worker pacing itself must not pace the pool: the backoff is a
/// per-worker sleep taken with nothing held (the queue was released by
/// `requeue_or_fail` first), so a healthy backbone keeps running at
/// full speed alongside a broken one.
#[tokio::test]
async fn a_backing_off_server_does_not_slow_the_healthy_one() {
    use crate::mock::{Chaos, MockServer, make_file_articles};
    let mut articles = HashMap::new();
    let payload: Vec<u8> = (0..80_000u32).map(|i| (i * 11) as u8).collect();
    make_file_articles("mix.bin", &payload, 8_000, "mx", &mut articles);
    let n = articles.len();
    let healthy = MockServer::start(articles.clone(), Chaos::default()).await;
    let broken = MockServer::start(
        articles.clone(),
        Chaos {
            body_error: Some(u64::MAX),
            ..Default::default()
        },
    )
    .await;
    let mk = |conns| PoolConfig {
        connections: conns,
        ramp_delay: Duration::ZERO,
        connect_backoff: Duration::from_millis(100),
        article_retries: 10,
        ..Default::default()
    };
    let reqs: Vec<ArticleReq> = articles
        .keys()
        .map(|id| ArticleReq::fresh(id.clone()))
        .collect();
    let (tx, mut rx) = mpsc::channel(256);
    tokio::time::timeout(
        Duration::from_secs(30),
        fetch_all_multi(
            &[
                (healthy.server_config(), mk(2)),
                (broken.server_config(), mk(2)),
            ],
            reqs,
            tx,
        ),
    )
    .await
    .expect("run hung with one session-broken server");
    let mut done = 0;
    while let Ok(o) = rx.try_recv() {
        if matches!(o, FetchOutcome::Done { .. }) {
            done += 1;
        }
    }
    assert_eq!(done, n, "the healthy server had to deliver every article");
}

/// An account that starts working again must be picked straight back
/// up: the backoff counter is cleared by a session that did useful
/// work, so no long delay stays armed behind a recovery.
#[tokio::test]
async fn session_backoff_clears_once_the_server_works_again() {
    use crate::mock::{Chaos, MockServer, make_file_articles};
    let mut articles = HashMap::new();
    let payload: Vec<u8> = (0..80_000u32).map(|i| (i * 13) as u8).collect();
    make_file_articles("rec.bin", &payload, 8_000, "rc", &mut articles);
    let n = articles.len();
    // The first three BODYs fail; after that the server is healthy.
    let srv = MockServer::start(
        articles.clone(),
        Chaos {
            body_error: Some(3),
            ..Default::default()
        },
    )
    .await;
    let cfg = PoolConfig {
        connections: 1,
        window: 1,
        ramp_delay: Duration::ZERO,
        connect_backoff: Duration::from_millis(100),
        article_retries: 10,
        ..Default::default()
    };
    let reqs: Vec<ArticleReq> = articles
        .keys()
        .map(|id| ArticleReq::fresh(id.clone()))
        .collect();
    let (tx, mut rx) = mpsc::channel(256);
    let t0 = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(30),
        fetch_all_multi(&[(srv.server_config(), cfg)], reqs, tx),
    )
    .await
    .expect("run hung on a server that recovered");
    let el = t0.elapsed();
    let mut done = 0;
    while let Ok(o) = rx.try_recv() {
        if matches!(o, FetchOutcome::Done { .. }) {
            done += 1;
        }
    }
    assert_eq!(done, n, "every article must land once the server recovers");
    // 100 + 200 + 400 ms of pacing, and nothing left armed after the
    // first good body - not the 800 ms+ steps a counter that kept
    // climbing would have charged the rest of the run.
    assert!(el < Duration::from_secs(3), "recovery was delayed: {el:?}");
}

/// Step a paused clock in 1 ms slices for as long as the returned
/// guard lives.
///
/// A paused clock auto-advances to the NEAREST armed deadline whenever
/// the runtime idles - including while it is idling on real socket
/// I/O. With only the pool's own timers armed, that nearest deadline
/// can be a connect or read timeout the loopback exchange was about to
/// satisfy, and the test measures spurious timeouts instead of the
/// behaviour under test (measured: one connection accepted, zero
/// BODYs, every worker gone on connect exhaustion). A metronome caps
/// each jump at a millisecond, so every I/O wait is re-polled ~1 ms of
/// virtual time at a time while the long backoffs still cost nothing.
pub(super) struct Metronome(tokio::task::JoinHandle<()>);

impl Metronome {
    pub(super) fn start() -> Metronome {
        Metronome(tokio::spawn(async {
            loop {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }))
    }
}

impl Drop for Metronome {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Regression: the session pacing had no give-up ceiling.
///
/// A server that accepts every connection and answers every BODY with
/// a non-BODY status - a broken or exhausted account - was retried at
/// the 30 s cap for as long as the queue had retries left, and the
/// queue's retries are per article: on a large single-server job that
/// is hours of paced reconnects that can never produce a byte. The
/// worker now bows out at `MAX_SESSION_ATTEMPTS` the way a
/// connect-exhausted one does, and the run seals a truthful Failed.
///
/// Paused clock, so this asserts on the CEILING and not on how fast
/// the box is: the whole ladder of backoffs is spent in virtual time,
/// and the run must be over inside the bound the ceiling implies.
/// `article_retries` is absurd on purpose - the run has to end because
/// the workers bowed out, not because the articles ran out of tries.
#[tokio::test(start_paused = true)]
async fn a_server_that_never_serves_a_body_bows_out_within_the_ceiling() {
    let _tick = Metronome::start();
    use crate::mock::{Chaos, MockServer, make_file_articles};
    let mut articles = HashMap::new();
    let payload: Vec<u8> = (0..60_000u32).map(|i| (i * 17) as u8).collect();
    make_file_articles("ceil.bin", &payload, 6_000, "cl", &mut articles);
    let srv = MockServer::start(
        articles.clone(),
        Chaos {
            body_error: Some(u64::MAX),
            ..Default::default()
        },
    )
    .await;
    const WORKERS: usize = 3;
    let cfg = PoolConfig {
        connections: WORKERS,
        window: 1,
        ramp_delay: Duration::ZERO,
        // Production pacing, not a test-shrunk one: the ceiling has to
        // hold at the 30 s cap, which is where the hours came from.
        connect_backoff: Duration::from_secs(2),
        article_retries: 250,
        ..Default::default()
    };
    let ids: Vec<Arc<str>> = articles.keys().map(|k| Arc::from(k.as_str())).collect();
    let reqs: Vec<ArticleReq> = ids.iter().cloned().map(ArticleReq::fresh).collect();
    let (tx, mut rx) = mpsc::channel(256);
    // The ceiling's own arithmetic: the sleeps armed by failures
    // 1..MAX (2, 4, 8, 16 s, then the 30 s cap), after which the last
    // useless session returns without sleeping again. Plus the fleet's
    // exit grace and a little slack for the sessions themselves.
    let ladder: Duration = (1..MAX_SESSION_ATTEMPTS)
        .map(|f| session_backoff_delay(&cfg, f))
        .sum();
    let bound = ladder + EXIT_GRACE + Duration::from_secs(30);
    let t0 = tokio::time::Instant::now();
    tokio::time::timeout(
        bound,
        fetch_all_multi(&[(srv.server_config(), cfg)], reqs, tx),
    )
    .await
    .unwrap_or_else(|_| {
        panic!("no give-up ceiling: still retrying a never-serving server after {bound:?}")
    });
    let el = t0.elapsed();
    assert!(el <= bound, "over the ceiling's bound: {el:?} > {bound:?}");
    // Terminal for every article - the seal, not a silent stall.
    let seen = tally(&mut rx);
    assert_exactly_one_outcome_each(&ids, &seen);
    // And the ceiling is per worker: each one gets at most
    // MAX_SESSION_ATTEMPTS sessions out of this server, ever.
    let accepted = srv.accepted.load(Ordering::Relaxed);
    assert!(
        accepted <= WORKERS as u64 * MAX_SESSION_ATTEMPTS as u64,
        "{accepted} connections for {WORKERS} workers is past the ceiling"
    );
    // The failures under test have to be SESSION failures: every
    // worker must have got a session and asked it for a body. Without
    // this the test passes on a run that never got past connect (which
    // is exactly how it fails on a paused clock with no metronome).
    let bodies = srv.body_log.lock().unwrap().len();
    assert!(
        accepted >= WORKERS as u64 && bodies >= WORKERS,
        "not the shape under test: {accepted} sessions, {bodies} BODYs"
    );
}

/// The other side of that ceiling: it must not fire on a server that
/// comes back. This one fails one BODY short of `MAX_SESSION_ATTEMPTS`
/// and then serves normally - the counter is cleared by the first
/// well-formed response, so the job completes instead of bowing out.
#[tokio::test(start_paused = true)]
async fn a_server_recovering_just_under_the_ceiling_still_completes() {
    let _tick = Metronome::start();
    use crate::mock::{Chaos, MockServer, make_file_articles};
    let mut articles = HashMap::new();
    let payload: Vec<u8> = (0..60_000u32).map(|i| (i * 19) as u8).collect();
    make_file_articles("near.bin", &payload, 6_000, "nr", &mut articles);
    let n = articles.len();
    let srv = MockServer::start(
        articles.clone(),
        Chaos {
            body_error: Some(MAX_SESSION_ATTEMPTS as u64 - 1),
            ..Default::default()
        },
    )
    .await;
    // One connection, one BODY in flight: every failure is exactly one
    // session failure, so the counter reaches MAX - 1 and stops there.
    let cfg = PoolConfig {
        connections: 1,
        window: 1,
        ramp_delay: Duration::ZERO,
        connect_backoff: Duration::from_secs(2),
        // The retry ladder must not be what ends this run either: the
        // first article eats every one of those failed sessions.
        article_retries: 250,
        ..Default::default()
    };
    let ids: Vec<Arc<str>> = articles.keys().map(|k| Arc::from(k.as_str())).collect();
    let reqs: Vec<ArticleReq> = ids.iter().cloned().map(ArticleReq::fresh).collect();
    let (tx, mut rx) = mpsc::channel(256);
    tokio::time::timeout(
        Duration::from_secs(600),
        fetch_all_multi(&[(srv.server_config(), cfg)], reqs, tx),
    )
    .await
    .expect("a recovering server must not be given up on");
    let mut done = 0;
    while let Ok(o) = rx.try_recv() {
        if matches!(o, FetchOutcome::Done { .. }) {
            done += 1;
        }
    }
    assert_eq!(
        done, n,
        "every article must land: the server recovered before the ceiling"
    );
}

/// A SLOW WRITE SIDE is measured, and it is measured SEPARATELY from
/// anything the network did.
///
/// This is the half of the dip instrumentation that had no signal at
/// all. A dip caused by an external disk hiccuping and a dip caused
/// by a provider dropping sessions look identical on the throughput
/// graph, and they want opposite remedies. Here the network is
/// perfect and the CONSUMER is slow, so `blocked_ms` must climb while
/// `reconnects` stays at zero - if both moved, or neither, the two
/// causes would still be indistinguishable and the instrumentation
/// would be decorative.
#[tokio::test(flavor = "multi_thread")]
async fn a_slow_write_side_is_measured_and_not_confused_with_the_network() {
    use crate::mock::{Chaos, MockServer, make_file_articles};
    let mut articles = std::collections::HashMap::new();
    let payload: Vec<u8> = (0..400_000u32).map(|i| i as u8).collect();
    let segs = make_file_articles("slow.bin", &payload, 8_000, "slow", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;
    let server = srv.server_config();

    let live = LiveStats::for_servers(&[(server.clone(), PoolConfig::default())]);
    let cfg = PoolConfig {
        connections: 2,
        ramp_delay: Duration::ZERO,
        live: Some(live.clone()),
        ..Default::default()
    };
    let reqs: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();

    // Depth 1 and a consumer that dawdles: the channel is full almost
    // at once, which is exactly the shape a disk that cannot keep up
    // produces. Nothing here touches the network.
    let (tx, mut rx) = mpsc::channel(1);
    let drain = tokio::spawn(async move {
        let mut n = 0usize;
        while let Some(_o) = rx.recv().await {
            n += 1;
            tokio::time::sleep(Duration::from_millis(60)).await;
        }
        n
    });
    tokio::time::timeout(
        Duration::from_secs(60),
        fetch_all_multi(&[(server, cfg)], reqs, tx),
    )
    .await
    .expect("run hung");
    let got = drain.await.expect("drain panicked");
    assert!(got > 0, "the run delivered nothing to measure");

    let sl = &live.servers[0];
    let blocked = sl.blocked_ms.load(Ordering::Relaxed);
    let reconnects = sl.reconnects.load(Ordering::Relaxed);
    assert!(
        blocked > 0,
        "a consumer sleeping 60 ms per article registered no wait at all"
    );
    assert_eq!(
        reconnects, 0,
        "a slow CONSUMER was booked as {reconnects} network reconnect(s) - \
         the two causes are being conflated, which is the bug this exists to prevent"
    );
}

/// A3: a server that connects, serves, and then walks out while the run
/// still has work outstanding must be RECORDED as having left.
///
/// `ever_connected` stays true for such a server, and `live_mask` (alive
/// NOW) silently stops counting it, so the survivors' 430s on the
/// segments it alone still had to answer for resolve "unanimous". With
/// nothing recording the departure the failure summary could not say so,
/// which let `post_gone` fire on a healthy post and cost the run its one
/// automatic retry - and a suppressed retry is FINAL.
///
/// The four ways this happens (a permanent refusal, a spent prepaid
/// block or quota, the outage budget blown, the connect-attempt cap) all
/// end the same way: `DialStep::Quit`, the worker returns, and its
/// `WorkerLife` comes down. So the latch sits on that one path and this
/// test drives it directly rather than staging four provider deaths.
#[test]
fn a_server_that_leaves_mid_run_latches_the_marker() {
    let mut servers = one_server();
    let mut second = servers[0].clone();
    second.0.host = "t".into();
    servers.push(second);
    let reqs: Vec<ArticleReq> = (0..8)
        .map(|i| ArticleReq::fresh(format!("<lmr{i}@x>")))
        .collect();
    let (shared, _) = Shared::new(reqs, &servers);
    let leaver = WorkerLife::birth(&shared, 0);
    let _stayer = WorkerLife::birth(&shared, 1);
    // Both servers served: this is the case `ever_connected` cannot see.
    shared.connected[0].store(true, Ordering::Relaxed);
    shared.connected[1].store(true, Ordering::Relaxed);

    drop(leaver);
    assert!(
        shared.left_mid_run[0].load(Ordering::Relaxed),
        "the server that served and then lost its last worker with work \
         still pending was not recorded as having left"
    );
    assert!(
        !shared.left_mid_run[1].load(Ordering::Relaxed),
        "a server still carrying the run has not left it"
    );
}

/// The three ways the marker must stay FALSE, because none of them is a
/// server walking out on live work: a server that never connected at all
/// (that is `ever_connected == false`, its own clause and its own
/// sentence), a natural wind-down with nothing left to fetch, and a run
/// that was aborted or drained out from under the fleet.
#[test]
fn a_natural_wind_down_is_not_a_mid_run_departure() {
    let servers = one_server();
    let reqs: Vec<ArticleReq> = (0..4)
        .map(|i| ArticleReq::fresh(format!("<nwd{i}@x>")))
        .collect();

    // Never connected: not a departure, however the worker exits.
    let (never, _) = Shared::new(reqs.clone(), &servers);
    drop(WorkerLife::birth(&never, 0));
    assert!(!never.left_mid_run[0].load(Ordering::Relaxed));

    // Connected, but the queue is empty: the run is simply over.
    let (done, _) = Shared::new(reqs.clone(), &servers);
    done.connected[0].store(true, Ordering::Relaxed);
    let life = WorkerLife::birth(&done, 0);
    done.pending.store(0, Ordering::Release);
    drop(life);
    assert!(!done.left_mid_run[0].load(Ordering::Relaxed));

    // Aborted mid-flight: every worker leaves, and none of it is the
    // server's doing.
    let (aborted, _) = Shared::new(reqs, &servers);
    aborted.connected[0].store(true, Ordering::Relaxed);
    let life = WorkerLife::birth(&aborted, 0);
    aborted.aborted.store(true, Ordering::Release);
    drop(life);
    assert!(!aborted.left_mid_run[0].load(Ordering::Relaxed));
}
