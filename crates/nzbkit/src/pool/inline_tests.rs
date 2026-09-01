//! The pool's own inline unit tests, moved out of pool.rs bodily (TODO 106).
//!
//! These were `mod tests` inside pool.rs and grew to 2,443 lines - a third of
//! the file - which is what kept pool.rs pinned against its size-gate entry.
//! A child module of `pool`, exactly like the sibling `unit_tests` /
//! `rig_tests` / `event_ring_tests` / `ratelimit_tests` modules, so the
//! private internals stay reachable through `super::*`.
//!
//! Half of it now lives in `inline_tests/serverdown_tests.rs` - see the
//! comment at the `mod` below. What is left here is work DISTRIBUTION
//! across serving servers: retention masks, dedupe, the endgame dup
//! races and fan-out, wire-cap accounting, promotion/shed and drain.

use super::*;

// The other half of this file: what the fleet does about a server that
// will not serve. Moved out under the size gate (TODO 106); `Metronome`
// is re-exported below because `pool/fault_rigs.rs` reaches it by the
// `inline_tests::` path and a re-export cannot widen an item, so the
// definition over there carries `pub(in crate::pool)`.
#[cfg(test)]
mod serverdown_tests;
pub(super) use serverdown_tests::Metronome;

/// Every field of a [`Work`] at its zero value but the id. Six of this
/// file's fixtures wanted exactly that and each spelled out all
/// sixteen fields to say so, which is how adding ONE routing bit to
/// `Work` (TODO 315's `recheck_430`) cost eleven lines in a test file
/// that was four lines under its ceiling. The next bit costs one line.
///
/// `pub(super)` because `unit_tests::recheck_tests` wants the same
/// zero-valued `Work` to pin the late re-ask's queue slot, and a
/// second hand-spelled copy of sixteen fields is the thing this
/// fixture exists to stop.
pub(super) fn work(id: &str) -> Work {
    Work {
        age_days: 0,
        part: 0,
        file: u32::MAX,
        ord: 0,
        id: id.into(),
        attempts: 0,
        promoted: false,
        tried_430: 0,
        tried_fail: 0,
        dup: false,
        prebyte_expiries: 0,
        soft_430: 0,
        recheck_430: 0,
        recheck_at: 0,
        fenced: false,
        rearms: 0,
        ladder: false,
        probe: false,
    }
}

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
    shared.queue.lock().await.push_front(work("<fresh>"));
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
        recheck_430: 0,
        recheck_at: 0,
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
        recheck_430: 0,
        recheck_at: 0,
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
    let w = work("<h0>");
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
    let w2 = work("<h1>");
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
    let w3 = work("<n0>");
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

    let w = work("<r0>");
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

    let w = work("<f0>");
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
        recheck_430: 0,
        recheck_at: 0,
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
        recheck_430: 0,
        recheck_at: 0,
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
        recheck_430: 0,
        recheck_at: 0,
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
