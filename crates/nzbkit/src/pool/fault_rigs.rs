//! The multi-fault rigs: the gauntlet matrix, the fight legs where two
//! defences could punish the same article twice, early fanout and the
//! tail latch, the hedge/dup races, live-target parking, and the §129
//! 3g desync fence.
//!
//! Split off `rig_tests.rs` when that file regrew past its size-gate
//! entry (TODO 106). Same shape as its parent - a `#[cfg(test)]` child
//! of `pool`, so `use super::*` reaches the pool's private internals -
//! and the cut is where the file's own subject changes: everything
//! here runs MORE THAN ONE fault at a time, which is why these legs
//! read the per-index gauges rather than the event ring.
//!
//! The two rig helpers it shares with `rig_tests` are imported by
//! path rather than copied. A sibling `#[cfg(test)]` mod is not in
//! scope through `use super::*`, but it is perfectly reachable by
//! name, so `pub(super)` on those two is the whole of what sharing
//! costs.

use super::rig_tests::{payout_leg, payout_server};
use super::*;

mod linecap_rigs;

/// Gauntlet leg: like `payout_leg` but returns the outcome tallies
/// AND the LiveStats. The mocks all answer to the host string
/// "127.0.0.1", so per-server claims (which server got clamped, who
/// suffered session churn) must come from the per-INDEX gauges, not
/// the event ring's host field.
async fn gauntlet_leg(
    servers: Vec<(ServerConfig, PoolConfig)>,
    ids: Vec<ArticleReq>,
) -> (Duration, usize, usize, Arc<LiveStats>) {
    let live = LiveStats::for_servers(&servers);
    let servers: Vec<(ServerConfig, PoolConfig)> = servers
        .into_iter()
        .map(|(s, mut c)| {
            c.live = Some(live.clone());
            (s, c)
        })
        .collect();
    let (tx, mut rx) = mpsc::channel(64);
    let t0 = Instant::now();
    let fetch = tokio::spawn(async move { fetch_all_multi(&servers, ids, tx).await });
    let collect = tokio::spawn(async move {
        let (mut done, mut missing) = (0usize, 0usize);
        while let Some(o) = rx.recv().await {
            match o {
                FetchOutcome::Done { .. } => done += 1,
                FetchOutcome::Missing { .. } => missing += 1,
                FetchOutcome::Failed { .. } => {}
            }
        }
        (done, missing)
    });
    tokio::time::timeout(Duration::from_secs(120), fetch)
        .await
        .expect("gauntlet leg hung")
        .unwrap();
    let elapsed = t0.elapsed();
    let (done, missing) = collect.await.unwrap();
    (elapsed, done, missing, live)
}

/// Count of flap-clamp announcements in a leg's event ring. At most
/// one per server per run by construction (`flap_noted`), so this is
/// also "how many servers were clamped".
fn clamp_count(live: &LiveStats) -> usize {
    live.events
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.detail.contains("sessions flapping"))
        .count()
}

/// THE GAUNTLET (TODO 111 interaction stage): four servers, four
/// SIMULTANEOUS distinct faults in one run - an IP-cap flapper
/// (accept_cap + die-every-body), a mid-run brownout, a jittery but
/// healthy link, and a clean server - across three config tiers:
/// everything off, the shipped defaults, and everything on (shipped
/// + adaptive timeout + the dark knobs hot_spare and recycle_slow).
/// The prior rounds priced each mitigation ALONE; this run pins the
/// safety gates in combination:
///   - every article completes on every tier;
///   - everything-on is never worse than shipped by more than 10%;
///   - the flap clamp fires exactly once, and only the flapper can
///     have earned it: FLAP_DEATHS is 6, the brownout's mute
///     frontend kills at most its 3 initial established sessions
///     (post-brownout sessions never serve a byte, so their deaths
///     do not count), and the jitter/clean servers drop nothing;
///   - the jittery server suffers ZERO session kills on every tier
///     (its reconnects gauge stays 0): the flat timeout, the
///     adaptive budget, the slope recycle and the race-loss recycle
///     all sit above 1.5 s spikes alone, and must stay there when
///     armed together.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock payout measurement - run with --ignored"]
async fn gauntlet_four_faults_three_config_tiers() {
    // Sized so the mitigated legs still run ~8 s: the flap clamp
    // needs FLAP_DEATHS established-session deaths to accumulate
    // BEFORE the queue drains, and a 4 s leg raced it (measured:
    // the shipped tier finished clampless at 2.4 MB).
    let data: Vec<u8> = (0..4_800_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("g.bin", &data, 20_000, "gl", &mut articles);
    // tier 0 = everything off, 1 = shipped defaults, 2 = everything on
    let leg = |tier: u8| {
        let articles = articles.clone();
        let ids: Vec<ArticleReq> = segs
            .iter()
            .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
            .collect();
        async move {
            let flapper = crate::mock::MockServer::start(
                articles.clone(),
                crate::mock::Chaos {
                    accept_cap: Some(2),
                    drop_after: 1,
                    // Fast enough that the two cap winners cycle
                    // (serve one body, die) quickly - the clamp
                    // needs their deaths on the board early.
                    throttle: crate::mock::Throttle {
                        per_conn_bps: 100_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await;
            let brownout = crate::mock::MockServer::start(
                articles.clone(),
                crate::mock::Chaos {
                    brownout_after: 30,
                    throttle: crate::mock::Throttle {
                        per_conn_bps: 100_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await;
            let jittery = crate::mock::MockServer::start(
                articles.clone(),
                crate::mock::Chaos {
                    jitter: Some((5, 1_500)),
                    throttle: crate::mock::Throttle {
                        per_conn_bps: 100_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await;
            let clean = crate::mock::MockServer::start(
                articles,
                crate::mock::Chaos {
                    throttle: crate::mock::Throttle {
                        per_conn_bps: 150_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await;
            let cfg = PoolConfig {
                flap_breaker: tier >= 1,
                tail_fanout: tier >= 1,
                tail_fanout_early: tier >= 1,
                hedge: tier >= 1,
                recycle_slope: tier >= 1,
                adaptive_timeout: tier >= 2,
                hot_spare: tier >= 2,
                recycle_slow: tier >= 2,
                read_timeout: Duration::from_secs(12),
                connect_backoff: Duration::from_millis(100),
                ..Default::default()
            };
            // Staggered flapper dials (the other servers keep ramp 0):
            // six simultaneous dials race the mock's live count to 6
            // before any accept task checks the cap, so every one of
            // them can bounce and the capacity-yield ladder may bow
            // the whole fleet out before a single session
            // establishes. 50 ms apart, the first two win their
            // slots and the rest bounce off a genuinely full cap -
            // the shape the clamp exists for.
            let fcfg = PoolConfig {
                connections: 6,
                ramp_delay: Duration::from_millis(50),
                ..cfg.clone()
            };
            let mut fsc = flapper.server_config();
            fsc.connections = 6;
            let servers = vec![
                (fsc, fcfg),
                payout_server(&brownout, 3, cfg.clone()),
                payout_server(&jittery, 3, cfg.clone()),
                payout_server(&clean, 3, cfg),
            ];
            gauntlet_leg(servers, ids).await
        }
    };
    let (t_off, done_off, miss_off, live_off) = leg(0).await;
    let (t_ship, done_ship, miss_ship, live_ship) = leg(1).await;
    let (t_on, done_on, miss_on, live_on) = leg(2).await;
    let jitter_kills = |l: &LiveStats| l.servers[2].reconnects.load(Ordering::Relaxed);
    let clean_kills = |l: &LiveStats| l.servers[3].reconnects.load(Ordering::Relaxed);
    // Mechanism counters, for attributing any unexpected churn: the
    // ring's host field cannot tell the mocks apart, but the detail
    // text names the knob that acted.
    let recycles = |l: &LiveStats, what: &str| {
        l.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.detail.contains(what))
            .count()
    };
    println!(
        "gauntlet notes on-tier: slow-recycles {} slope-recycles {}",
        recycles(&live_on, "recycled a slow session"),
        recycles(&live_on, "recycled a degraded session"),
    );
    println!(
        "gauntlet: off {t_off:?} shipped {t_ship:?} on {t_on:?} · clamps \
         off/ship/on {}/{}/{} · jitter kills {}/{}/{} · clean kills {}/{}/{}",
        clamp_count(&live_off),
        clamp_count(&live_ship),
        clamp_count(&live_on),
        jitter_kills(&live_off),
        jitter_kills(&live_ship),
        jitter_kills(&live_on),
        clean_kills(&live_off),
        clean_kills(&live_ship),
        clean_kills(&live_on),
    );
    for (name, done, miss) in [
        ("off", done_off, miss_off),
        ("shipped", done_ship, miss_ship),
        ("on", done_on, miss_on),
    ] {
        assert_eq!(done, segs.len(), "{name} tier lost articles");
        assert_eq!(miss, 0, "{name} tier declared healthy articles Missing");
    }
    // Rig sanity is ENGAGEMENT, not a wall ordering: on loopback the
    // flapper's cap churn is free (instant redials), so the clamp
    // can trade a little wall time for the churn it removes and the
    // off tier is NOT reliably the slowest. What must be true is
    // that the faults actually bit - the unmitigated flapper churned
    // hard enough that a clamp had something to engage on.
    assert!(
        live_off.servers[0].reconnects.load(Ordering::Relaxed) >= FLAP_DEATHS as u64,
        "rig broken - the flapper never churned on the off tier"
    );
    assert!(
        t_on.as_secs_f64() < t_ship.as_secs_f64() * 1.10,
        "everything-on regressed the shipped defaults ({t_on:?} vs {t_ship:?})"
    );
    assert_eq!(
        clamp_count(&live_off),
        0,
        "the clamp fired with the breaker off - knob leak"
    );
    assert_eq!(
        clamp_count(&live_ship),
        1,
        "expected exactly the flapper clamped on the shipped tier"
    );
    assert_eq!(
        clamp_count(&live_on),
        1,
        "expected exactly the flapper clamped on the everything-on tier"
    );
    for (name, l) in [
        ("off", &live_off),
        ("shipped", &live_ship),
        ("on", &live_on),
    ] {
        assert_eq!(
            jitter_kills(l),
            0,
            "{name} tier killed sessions on the jittery-but-healthy server"
        );
        assert_eq!(
            clean_kills(l),
            0,
            "{name} tier killed sessions on the clean server"
        );
    }
}

/// FIGHT PROBE (TODO 111): dup racing + recycle_slow versus the flap
/// keeper. After the clamp, the keeper is the flapping server's only
/// session and it crawls, so the healthy server's idle workers dup
/// its articles via the rate rule and usually win. With recycle_slow
/// ON, two consecutive race losses shed the keeper's pipeline and
/// redial it - churn the clamp exists to stop, potentially
/// reintroduced by another knob. Measured claim: switching
/// recycle_slow on must not inflate the flapping server's accepted
/// sessions past 2x its knob-off churn, and must not cost wall time.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock payout measurement - run with --ignored"]
async fn fight_recycle_slow_must_not_churn_the_flap_keeper() {
    let data: Vec<u8> = (0..6_000_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("f.bin", &data, 30_000, "fk", &mut articles);
    let leg = |recycle: bool| {
        let arts_a = articles.clone();
        let arts_b = articles.clone();
        let ids: Vec<ArticleReq> = segs
            .iter()
            .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
            .collect();
        async move {
            let flapper = crate::mock::MockServer::start(
                arts_a,
                crate::mock::Chaos {
                    accept_cap: Some(2),
                    drop_after: 2,
                    throttle: crate::mock::Throttle {
                        per_conn_bps: 100_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await;
            let steady = crate::mock::MockServer::start(
                arts_b,
                crate::mock::Chaos {
                    throttle: crate::mock::Throttle {
                        per_conn_bps: 150_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await;
            let cfg = PoolConfig {
                flap_breaker: true,
                tail_fanout: true,
                tail_fanout_early: true,
                hedge: true,
                recycle_slow: recycle,
                read_timeout: Duration::from_secs(12),
                connect_backoff: Duration::from_millis(100),
                ..Default::default()
            };
            // The flapper's dials are STAGGERED (unlike payout_server's
            // ramp 0): six simultaneous dials race the mock's live
            // count to 6 before any task checks the cap, every one of
            // them bounces, and the capacity-yield ladder can bow the
            // whole fleet out before a single session establishes -
            // measured as a served-0, clampless flapper. Real dials
            // are never perfectly simultaneous; 50 ms apart, the
            // first two win their slots and the rest bounce off a
            // genuinely full cap, which is the shape the clamp is for.
            let fcfg = PoolConfig {
                connections: 6,
                ramp_delay: Duration::from_millis(50),
                ..cfg.clone()
            };
            let mut fsc = flapper.server_config();
            fsc.connections = 6;
            let servers = vec![(fsc, fcfg), payout_server(&steady, 3, cfg)];
            let r = gauntlet_leg(servers, ids).await;
            (
                r,
                flapper.accepted.load(Ordering::Relaxed),
                flapper.served.load(Ordering::Relaxed),
            )
        }
    };
    let ((t_off, done_off, _, live_off), acc_off, served_off) = leg(false).await;
    let ((t_on, done_on, _, live_on), acc_on, served_on) = leg(true).await;
    let recycles = |l: &LiveStats| {
        l.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.detail.contains("recycled a slow session"))
            .count()
    };
    println!(
        "keeper churn: off {t_off:?} accepted {acc_off} served {served_off} · \
         on {t_on:?} accepted {acc_on} served {served_on} (recycles {})",
        recycles(&live_on)
    );
    assert_eq!(done_off, segs.len());
    assert_eq!(done_on, segs.len());
    assert_eq!(
        clamp_count(&live_off),
        1,
        "rig broken - the clamp never engaged"
    );
    assert_eq!(
        clamp_count(&live_on),
        1,
        "rig broken - the clamp never engaged"
    );
    assert_eq!(
        recycles(&live_off),
        0,
        "recycle fired with the knob off - knob leak"
    );
    assert!(
        acc_on <= acc_off * 2,
        "recycle_slow redial-stormed the clamped server \
         ({acc_on} accepted sessions vs {acc_off} with the knob off)"
    );
    assert!(
        t_on.as_secs_f64() < t_off.as_secs_f64() * 1.15,
        "recycle_slow cost wall time on the clamped rig ({t_on:?} vs {t_off:?})"
    );
}

/// FIGHT PROBE (TODO 111): slope recycle + adaptive timeout on the
/// same degraded session must not double-punish. The slope rule
/// redials a session delivering under a quarter of its siblings'
/// rate; the adaptive budget's stall deadline rolls with progress,
/// so a slow-but-alive transfer must NOT also be killed as stalled
/// (a kill strikes the session and requeues its pipeline - paying
/// twice for one diagnosis). Claim: adding adaptive to slope changes
/// neither completion nor churn beyond the slope's own deliberate
/// redial, and costs no wall time.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock payout measurement (~1 min) - run with --ignored"]
async fn fight_slope_plus_adaptive_must_not_double_punish() {
    // 120 articles, like payout_slope: the slope rule only runs while
    // pending > ENDGAME_MAX (64), so a smaller queue leaves the
    // normal phase before the 10 s proof window opens and the knob
    // structurally cannot fire (measured: 72 articles, zero slope
    // recycles in either leg).
    let data: Vec<u8> = (0..6_000_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("s2.bin", &data, 50_000, "sa", &mut articles);
    let leg = |adaptive: bool| {
        let articles = articles.clone();
        let ids: Vec<ArticleReq> = segs
            .iter()
            .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
            .collect();
        async move {
            let srv = crate::mock::MockServer::start(
                articles,
                crate::mock::Chaos {
                    slow_conn: Some((1, 8_000)),
                    throttle: crate::mock::Throttle {
                        per_conn_bps: 100_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await;
            let cfg = PoolConfig {
                recycle_slope: true,
                adaptive_timeout: adaptive,
                read_timeout: Duration::from_secs(12),
                ..Default::default()
            };
            gauntlet_leg(vec![payout_server(&srv, 3, cfg)], ids).await
        }
    };
    let (t_off, done_off, _, live_off) = leg(false).await;
    let (t_on, done_on, _, live_on) = leg(true).await;
    let churn = |l: &LiveStats| l.servers[0].reconnects.load(Ordering::Relaxed);
    let slopes = |l: &LiveStats| {
        l.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.detail.contains("recycled a degraded session"))
            .count()
    };
    println!(
        "slope+adaptive: slope-only {t_off:?} ({} reconnects, {} slope) · \
         both {t_on:?} ({} reconnects, {} slope)",
        churn(&live_off),
        slopes(&live_off),
        churn(&live_on),
        slopes(&live_on),
    );
    assert_eq!(done_off, segs.len());
    assert_eq!(done_on, segs.len());
    assert!(
        slopes(&live_on) >= 1,
        "rig broken - the slope recycle never fired with adaptive on"
    );
    // The slope's own deliberate redial is the only churn either leg
    // should show; adaptive piling kills on top would read as extra
    // reconnects here.
    assert!(
        churn(&live_on) <= churn(&live_off) + 1,
        "adaptive added session kills on top of the slope recycle \
         ({} vs {})",
        churn(&live_on),
        churn(&live_off)
    );
    assert!(
        t_on.as_secs_f64() < t_off.as_secs_f64() * 1.25,
        "adaptive cost wall time on the degraded-session rig ({t_on:?} vs {t_off:?})"
    );
}

/// FIGHT PROBE (TODO 111): tail fan-out must not eat the hot spare.
/// Racers are never fresh dials - `pick_dup` hands dup work to a
/// connection that already exists (idle primaries), and the spare is
/// only claimable at session START after a death (`session_loop`
/// takes `spares[idx]` before dialling). So on a healthy run with
/// both knobs on, the accepted-session count must be exactly the
/// workers plus the one parked spare - a fan-out that dialled extra
/// sessions, or ate and re-filled the spare, would show up right
/// here. Count-based, so it runs in the normal suite.
#[tokio::test(flavor = "multi_thread")]
async fn fanout_does_not_eat_the_hot_spare() {
    let data: Vec<u8> = (0..1_200_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("h2.bin", &data, 20_000, "hs", &mut articles);
    let ids: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    let srv = crate::mock::MockServer::start(
        articles,
        crate::mock::Chaos {
            throttle: crate::mock::Throttle {
                per_conn_bps: 400_000,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    let cfg = PoolConfig {
        tail_fanout: true,
        tail_fanout_early: true,
        hot_spare: true,
        ..Default::default()
    };
    let (_, done, missing, _) = gauntlet_leg(vec![payout_server(&srv, 3, cfg)], ids).await;
    assert_eq!(done, segs.len());
    assert_eq!(missing, 0);
    let accepted = srv.accepted.load(Ordering::Relaxed);
    assert!(
        accepted <= 4,
        "expected 3 workers + 1 parked spare, got {accepted} accepted \
         sessions - something dialled beyond the budget"
    );
}

/// FIGHT PROBE (TODO 111): the flap clamp must not break 430
/// unanimity. A clamped server still counts in `live_mask` while its
/// keeper lives, so a Missing verdict needs the keeper's own 430
/// vote (or the server's full death). Six ids exist on NO server;
/// the flapping server clamps early in the run; every one of the six
/// must still reach its Missing verdict and the job must terminate -
/// a clamp that muted the keeper's vote would hang these forever.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock payout measurement - run with --ignored"]
async fn fight_flap_clamp_still_reaches_missing_verdicts() {
    let data: Vec<u8> = (0..3_000_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("m2.bin", &data, 30_000, "mv", &mut articles);
    let ghosts: Vec<String> = (0..6).map(|i| format!("<ghost-{i}@mv>")).collect();
    let ids: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| format!("<{id}>"))
        .chain(ghosts.iter().cloned())
        .map(ArticleReq::fresh)
        .collect();
    let flapper = crate::mock::MockServer::start(
        articles.clone(),
        crate::mock::Chaos {
            accept_cap: Some(2),
            drop_after: 1,
            throttle: crate::mock::Throttle {
                per_conn_bps: 60_000,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    let steady = crate::mock::MockServer::start(
        articles,
        crate::mock::Chaos {
            throttle: crate::mock::Throttle {
                per_conn_bps: 150_000,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    let cfg = PoolConfig {
        flap_breaker: true,
        tail_fanout: true,
        tail_fanout_early: true,
        hedge: true,
        recycle_slope: true,
        read_timeout: Duration::from_secs(12),
        connect_backoff: Duration::from_millis(100),
        ..Default::default()
    };
    // Staggered flapper dials, same reason as the keeper-churn probe:
    // six simultaneous dials all bounce off the mock's racing live
    // count and the capacity-yield ladder can kill the server before
    // it ever flaps.
    let fcfg = PoolConfig {
        connections: 6,
        ramp_delay: Duration::from_millis(50),
        ..cfg.clone()
    };
    let mut fsc = flapper.server_config();
    fsc.connections = 6;
    let servers = vec![(fsc, fcfg), payout_server(&steady, 3, cfg)];
    let (t, done, missing, live) = gauntlet_leg(servers, ids).await;
    println!(
        "clamp+unanimity: {t:?}, {done} done, {missing} missing, clamps {}",
        clamp_count(&live)
    );
    assert_eq!(done, segs.len(), "lost real articles");
    assert_eq!(
        missing,
        ghosts.len(),
        "the poisoned articles never reached their Missing verdicts under the clamp"
    );
    assert_eq!(
        clamp_count(&live),
        1,
        "rig broken - the clamp never engaged"
    );
}

/// Early fan-out (NZBFAST_TAIL_FANOUT=2): the tail latch arms the
/// endgame dup rules at queue-dry, well above ENDGAME_MAX pending;
/// plain fan-out (=1) still waits for the pending threshold.
#[tokio::test]
async fn early_fanout_arms_at_the_tail_latch_not_the_pending_floor() {
    let mk = |host: &str, early: bool| {
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
                tail_fanout_early: early,
                ..Default::default()
            },
        )
    };
    let mk_reqs = || -> Vec<ArticleReq> {
        (0..(ENDGAME_MAX + 40))
            .map(|i| ArticleReq::fresh(format!("<q{i}>")))
            .collect()
    };
    let w = Work {
        age_days: 0,
        part: 0,
        file: u32::MAX,
        ord: 0,
        id: "<q0>".into(),
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
    };

    // Plain fan-out, tail latched, pending far above the floor: the
    // endgame rules stay dark.
    let servers = vec![mk("a", false), mk("b", false)];
    let (plain, _) = Shared::new(mk_reqs(), &servers);
    plain
        .tail_started
        .lock_ok()
        .get_or_insert_with(Instant::now);
    plain.register_inflight(&w, 0);
    plain.inflight.lock_ok().get_mut("<q0>").unwrap().dispatched =
        Instant::now() - Duration::from_secs(1);
    assert!(
        plain
            .pick_dup(1, 0b10, 0b10, 0, Pipeline::payload(0), 0)
            .is_none(),
        "plain fan-out fired above ENDGAME_MAX"
    );

    // Early fan-out: same shape, latch armed -> healthy race fires.
    let servers = vec![mk("a", true), mk("b", true)];
    let (early, _) = Shared::new(mk_reqs(), &servers);
    early.register_inflight(&w, 0);
    early.inflight.lock_ok().get_mut("<q0>").unwrap().dispatched =
        Instant::now() - Duration::from_secs(1);
    // ...but not before the latch: no tail, no early rules.
    assert!(
        early
            .pick_dup(1, 0b10, 0b10, 0, Pipeline::payload(0), 0)
            .is_none(),
        "early fan-out fired before the queue ever ran dry"
    );
    early
        .tail_started
        .lock_ok()
        .get_or_insert_with(Instant::now);
    // The production latch site (next_work) bumps the N6 gen so gated
    // idle scanners re-walk; latching by hand must do the same.
    early.bump_inflight_gen();
    let d = early
        .pick_dup(1, 0b10, 0b10, 0, Pipeline::payload(0), 0)
        .expect("early fan-out races at the tail latch");
    assert_eq!(&*d.id, "<q0>");
    assert!(d.dup);

    // Refetch exemption: an article on its recovery leg (tried_fail
    // set by a CRC-steer or failure requeue) is never fan-out raced -
    // not even by its own server, whose same-server allowance was the
    // dup-storm path on the damage matrix legs (one lost race per
    // steered article). It still falls through to the rate rules,
    // where the same-server and my-bit gates already refuse it.
    let servers = vec![mk("a", true), mk("b", true)];
    let (steered, _) = Shared::new(mk_reqs(), &servers);
    steered
        .tail_started
        .lock_ok()
        .get_or_insert_with(Instant::now);
    let refetch = Work {
        age_days: 0,
        part: 0,
        file: u32::MAX,
        ord: 0,
        id: "<q0>".into(),
        attempts: 0,
        promoted: false,
        tried_430: 0,
        tried_fail: 0b01, // steered off server a
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
    steered.register_inflight(&refetch, 1); // recovery leg on server b
    steered
        .inflight
        .lock_ok()
        .get_mut("<q0>")
        .unwrap()
        .dispatched = Instant::now() - Duration::from_secs(1);
    assert!(
        steered
            .pick_dup(1, 0b10, 0b10, 0, Pipeline::payload(0), 0)
            .is_none(),
        "fan-out raced a steer refetch on its own server"
    );
    assert!(
        steered
            .pick_dup(0, 0b01, 0b01, 0, Pipeline::payload(0), 0)
            .is_none(),
        "the server whose copy was bad re-raced the refetch"
    );
}

/// Tail-prefetch experiment: `QueueControl::tail_pending` answers
/// None before the pool's tail latch, Some(pending) after, and None
/// again once the run's Shared is gone.
#[tokio::test]
async fn queue_control_exports_the_tail_latch() {
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
    let servers = vec![mk("a")];
    let reqs: Vec<ArticleReq> = (0..3)
        .map(|i| ArticleReq::fresh(format!("<t{i}>")))
        .collect();
    let (shared, _) = Shared::new(reqs, &servers);
    let ctl = QueueControl::default();
    ctl.attach(&shared);
    assert_eq!(ctl.tail_pending(), None, "no tail latched yet");
    shared
        .tail_started
        .lock_ok()
        .get_or_insert_with(Instant::now);
    assert_eq!(ctl.tail_pending(), Some(3), "latched tail reports pending");
    drop(shared);
    assert_eq!(ctl.tail_pending(), None, "gone run answers None");
}

/// Hedge experiment (opt-in `PoolConfig::hedge`): the dup race's
/// staleness bound adapts to the trained article-time EWMA (3x,
/// clamped [500 ms, 8 s]) instead of a flat 8 s, the Done path
/// trains the EWMA, and stale-only dups respect the issue-rate cap.
/// Off keeps the flat bound.
#[tokio::test]
async fn hedge_races_a_straggler_at_the_adaptive_bound() {
    let mk = |host: &str, hedge: bool| {
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
                hedge,
                ..Default::default()
            },
        )
    };
    let servers = vec![mk("a", true), mk("b", true)];
    // Normal phase: the endgame's own rules must stay out of the way.
    let reqs: Vec<ArticleReq> = (0..(ENDGAME_MAX + 10))
        .map(|i| ArticleReq::fresh(format!("<s{i}>")))
        .collect();
    let (shared, _) = Shared::new(reqs, &servers);

    // Bound math: untrained keeps the flat 8 s; trained is 3x the
    // EWMA clamped to [500 ms, 8 s].
    assert_eq!(shared.hedge_stale_bound(), Duration::from_secs(8));
    shared.art_ms.store(100, Ordering::Relaxed);
    assert_eq!(shared.hedge_stale_bound(), Duration::from_millis(500));
    shared.art_ms.store(400, Ordering::Relaxed);
    assert_eq!(shared.hedge_stale_bound(), Duration::from_millis(1200));
    shared.art_ms.store(10_000, Ordering::Relaxed);
    assert_eq!(shared.hedge_stale_bound(), Duration::from_secs(8));

    // The Done path trains the EWMA (first sample is taken whole).
    shared.art_ms.store(0, Ordering::Relaxed);
    let w0 = Work {
        age_days: 0,
        part: 0,
        file: u32::MAX,
        ord: 0,
        id: "<s0>".into(),
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
    };
    shared.register_inflight(&w0, 0);
    shared
        .inflight
        .lock_ok()
        .get_mut("<s0>")
        .unwrap()
        .dispatched = Instant::now() - Duration::from_secs(1);
    shared.deregister_inflight_done(&w0);
    let trained = shared.art_ms.load(Ordering::Relaxed);
    assert!(
        (900..=1200).contains(&trained),
        "one 1 s completion should train the EWMA to ~1000 ms, got {trained}"
    );

    // A healthy article 2 s in flight, equal rates: the flat rule
    // keeps waiting, the trained bound (400 ms EWMA -> 1.2 s) races
    // it and counts a hedge.
    shared.art_ms.store(400, Ordering::Relaxed);
    let w1 = Work {
        age_days: 0,
        part: 0,
        file: u32::MAX,
        ord: 0,
        id: "<s1>".into(),
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
    };
    shared.register_inflight(&w1, 0);
    shared
        .inflight
        .lock_ok()
        .get_mut("<s1>")
        .unwrap()
        .dispatched = Instant::now() - Duration::from_secs(2);
    let d = shared
        .pick_dup(1, 0b10, 0b10, 0, Pipeline::payload(0), 0)
        .expect("straggler past the adaptive bound should be hedged");
    assert_eq!(&*d.id, "<s1>");
    assert!(d.dup);
    assert_eq!(shared.hedges_issued.load(Ordering::Relaxed), 1);

    // The issue-rate cap gates stale-only dups.
    shared.hedges_issued.store(1000, Ordering::Relaxed);
    let w2 = Work {
        age_days: 0,
        part: 0,
        file: u32::MAX,
        ord: 0,
        id: "<s2>".into(),
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
    };
    shared.register_inflight(&w2, 0);
    shared
        .inflight
        .lock_ok()
        .get_mut("<s2>")
        .unwrap()
        .dispatched = Instant::now() - Duration::from_secs(2);
    assert!(
        shared
            .pick_dup(1, 0b10, 0b10, 0, Pipeline::payload(0), 0)
            .is_none(),
        "a capped hedge still issued"
    );

    // OFF (the default): 2 s is not stale against the flat 8 s.
    let servers_off = vec![mk("a", false), mk("b", false)];
    let reqs: Vec<ArticleReq> = (0..(ENDGAME_MAX + 10))
        .map(|i| ArticleReq::fresh(format!("<s{i}>")))
        .collect();
    let (off, _) = Shared::new(reqs, &servers_off);
    off.art_ms.store(400, Ordering::Relaxed);
    off.register_inflight(&w1, 0);
    off.inflight.lock_ok().get_mut("<s1>").unwrap().dispatched =
        Instant::now() - Duration::from_secs(2);
    assert!(
        off.pick_dup(1, 0b10, 0b10, 0, Pipeline::payload(0), 0)
            .is_none(),
        "hedge fired while switched off"
    );
}

/// A one-connection server for the two TODO 202 bound guards below.
/// `hedge` is always on - these rigs exist to prove the hedge fires,
/// and the parent rig above already covers the off case.
fn bound_guard_server(host: &str, tail_fanout: bool) -> (ServerConfig, PoolConfig) {
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
            hedge: true,
            tail_fanout,
            ..Default::default()
        },
    )
}

/// Register `id` as owned by server 0, on the wire for `age`, with
/// `tried_fail` already recorded against it.
fn bound_guard_straggler(shared: &Arc<Shared>, id: &str, tried_fail: u32, age: Duration) {
    let w = Work {
        age_days: 0,
        part: 0,
        file: u32::MAX,
        ord: 0,
        id: id.into(),
        attempts: 0,
        promoted: false,
        tried_430: 0,
        tried_fail,
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
    shared.register_inflight(&w, 0);
    shared.inflight.lock_ok().get_mut(id).unwrap().dispatched = Instant::now() - age;
}

/// The article time a real 1 Gbps leg trained: `art 22280 ms`, off a
/// tv4 cost-suite leg. Well above the 8 s ceiling once tripled, which
/// is what makes today's adaptive bound inert and is the whole reason
/// TODO 202 revisits it.
const TRAINED_ART_MS: u64 = 22_280;

/// TODO 202 guard: the staleness bound must stay under the pool's own
/// read timeout, or hedging is dead by construction.
///
/// This is a structural bound, not a tuning preference. A dup issued
/// after the read timeout cannot rescue anything - the timeout reaps
/// the article first - so a bound at or above `read_timeout` means the
/// stale rule never fires at all, whatever its arithmetic says. That
/// makes "an article on the wire for the whole read timeout has
/// already been raced" the weakest honest invariant available, and it
/// is the one this pins.
///
/// It is aimed at a specific near miss. The candidate TODO 202 fix
/// makes the clamp's upper bound a function of `art_ms` instead of the
/// flat 8 s, and at the EWMA below that yields `3 x 22.28 s` = 66.8 s
/// - more than twice the 30 s read timeout, so hedging would stop
/// firing entirely while every gate stayed green. The rig above cannot
/// see it: its behavioural half runs at `art_ms = 400`, where the
/// clamp is not engaged at either end, so it passes however far the
/// ceiling moves, and its one ceiling assertion is a bare constant a
/// fix must rewrite to land at all.
#[tokio::test]
async fn the_stale_bound_stays_under_the_read_timeout() {
    let servers = vec![
        bound_guard_server("a", false),
        bound_guard_server("b", false),
    ];
    let read_timeout = servers[0].1.read_timeout;
    // Normal phase, for the same reason as the rig above: the
    // endgame's own rules must stay out of the way of this answer.
    let reqs: Vec<ArticleReq> = (0..(ENDGAME_MAX + 10))
        .map(|i| ArticleReq::fresh(format!("<s{i}>")))
        .collect();
    let (shared, _) = Shared::new(reqs, &servers);

    shared.art_ms.store(TRAINED_ART_MS, Ordering::Relaxed);
    assert!(
        shared.hedge_stale_bound() < read_timeout,
        "a stale bound of {:?} is at or past the {read_timeout:?} read timeout - \
         the timeout reaps the article first, so the hedge can never fire",
        shared.hedge_stale_bound(),
    );

    // And the behaviour that bound is supposed to produce.
    bound_guard_straggler(&shared, "<s1>", 0, read_timeout);
    let d = shared
        .pick_dup(1, 0b10, 0b10, 0, Pipeline::payload(0), 0)
        .expect("an article on the wire for the whole read timeout must have been raced");
    assert_eq!(&*d.id, "<s1>");
    assert!(d.dup);
    // A hedge, not a fan-out pick: only the stale rule counts here.
    assert_eq!(shared.hedges_issued.load(Ordering::Relaxed), 1);
}

/// TODO 202 guard, damaged-post half: at the endgame a steered
/// refetch's only rescue is the stale rule, so relaxing that rule
/// takes its first casualty on the shape where hedging is
/// load-bearing rather than opportunistic.
///
/// The tail fan-out exempts refetch legs (`tried_fail != 0`) - it has
/// to, because the same-server allowance made a recovering twin race
/// its own steered refetches, measured at 33-43 dups for 0 wins on the
/// damage matrix. That exemption leaves the stale rule holding the
/// whole damaged case alone. Every wall-clock damage rig that would
/// notice it going quiet is `#[ignore]`d and runs in no CI job, so
/// this cheap deterministic one stands in for them.
#[tokio::test]
async fn a_steered_refetch_keeps_its_stale_rescue_at_the_endgame() {
    let servers = vec![bound_guard_server("a", true), bound_guard_server("b", true)];
    let read_timeout = servers[0].1.read_timeout;
    // Few enough to be inside the endgame, where the fan-out arms.
    let reqs: Vec<ArticleReq> = (0..4)
        .map(|i| ArticleReq::fresh(format!("<s{i}>")))
        .collect();
    let (shared, _) = Shared::new(reqs, &servers);
    assert!(
        shared.pending.load(Ordering::Acquire) <= ENDGAME_MAX,
        "rig broken: this leg must be in the endgame"
    );

    shared.art_ms.store(TRAINED_ART_MS, Ordering::Relaxed);
    // Server a (bit 0b01) already failed this one - a CRC-steer or a
    // plain failure requeue, now stalled on its chosen server.
    bound_guard_straggler(&shared, "<s1>", 0b01, read_timeout);

    let d = shared
        .pick_dup(1, 0b10, 0b10, 0, Pipeline::payload(0), 0)
        .expect("a stalled refetch the fan-out will not touch must still be raced");
    assert_eq!(&*d.id, "<s1>");
    // The fan-out skipped it (`tried_fail != 0`) and the stale rule
    // caught it: a fan pick would not have counted a hedge.
    assert_eq!(shared.hedges_issued.load(Ordering::Relaxed), 1);
}

/// Drive the TODO 202 line gauge into its SHUT state.
///
/// Not instant, and it cannot be: `saturated()` reads the pool's own
/// elapsed clock, and a now-rate is `None` until the 1 s window holds a
/// quarter of its time constant (~360 ms) of evidence, so no fake `now`
/// stands in for real time here. Feed a plateau for ~450 ms, then pin
/// the peak under it with the gauge's own test seam - training a peak
/// the honest way takes half the 10 s window's time constant, which no
/// unit test can spend. Pinned a factor of ten below the plateau so the
/// gate survives seconds of scheduler delay between here and the pick;
/// the gate's own arithmetic is guarded in `pool::saturation::tests`.
async fn shut_the_line_gate(shared: &Arc<Shared>) {
    for _ in 0..18 {
        tokio::time::sleep(Duration::from_millis(25)).await;
        shared
            .sat
            .note_bytes(shared.start.elapsed().as_millis() as u64, 100_000, false);
    }
    let now = shared.start.elapsed().as_millis() as u64;
    let rate = shared
        .sat
        .now_rate(now)
        .expect("rig broken: a now-rate must have trained");
    shared.sat.set_peak_bps((rate / 10.0) as u64);
    assert!(
        shared.line_saturated(shared.start.elapsed().as_millis() as u64),
        "rig broken: the line gate must read shut"
    );
}

/// TODO 202 §17: a STALLED article escapes the line gate; a merely
/// slow one does not.
///
/// The gate's argument is that on a saturated line a speculative copy
/// displaces payload byte for byte. That is true of a slow owner and
/// false of a stalled one, which delivers nothing and so competes for
/// nothing - and the gauge cannot tell them apart, because it is a
/// FLEET aggregate and one stalled connection does not move it at any
/// shipping fleet size (`one_stalled_connection_of_many_never_opens_
/// the_gate` pins that arithmetic).
///
/// So this rig drives the gate shut for real and asks the picker both
/// halves of the question. Deterministic on purpose: every wall-clock
/// rig that would notice hedging going silent is `#[ignore]`d and the
/// only `--run-ignored` in CI is `leak_soak`, and the natural A/B
/// (`payout_hedge_rescues_stalls_in_under_a_second_not_eight` at
/// `NZBFAST_RACE_SAT_PCT` 80 vs 0) runs a FOUR-connection fleet, the
/// one size where the fleet gauge opens by itself - so it passes
/// either way and says nothing.
#[tokio::test]
async fn a_stalled_article_escapes_the_shut_line_gate() {
    let servers = vec![
        bound_guard_server("a", false),
        bound_guard_server("b", false),
    ];
    assert_eq!(
        servers[0].1.race_sat_pct, 70,
        "rig broken: the line gate must be armed at the shipped default"
    );
    let read_timeout = servers[0].1.read_timeout;
    // Normal phase: the endgame's own rules must stay out of this
    // answer, exactly as in the two bound guards above.
    let reqs: Vec<ArticleReq> = (0..(ENDGAME_MAX + 10))
        .map(|i| ArticleReq::fresh(format!("<s{i}>")))
        .collect();
    let (shared, _) = Shared::new(reqs, &servers);
    shared.art_ms.store(TRAINED_ART_MS, Ordering::Relaxed);
    bound_guard_straggler(&shared, "<s1>", 0, read_timeout);
    shut_the_line_gate(&shared).await;

    // A straggler on the wire for the whole read timeout - the shape
    // `the_stale_bound_stays_under_the_read_timeout` proves is raced -
    // stands down while the fleet reads saturated. Nothing about the
    // ARTICLE has changed; only the fleet's aggregate rate.
    assert!(
        shared
            .pick_dup(1, 0b10, 0b10, 0, Pipeline::payload(0), 0)
            .is_none(),
        "the line gate should suppress a plain stale hedge"
    );
    assert_eq!(shared.sat.escapes(), 0);

    // Now the owner's read reports pre-byte silence: this article has
    // moved no bytes, so its copy displaces no payload and the gate
    // must let it through.
    shared.mark_suspect("<s1>");
    let d = shared
        .pick_dup(1, 0b10, 0b10, 0, Pipeline::payload(0), 0)
        .expect("a stalled article must be raced even while the line reads saturated");
    assert_eq!(&*d.id, "<s1>");
    assert!(d.dup);
    // The stale rule caught it, and the ledger recorded that the dup
    // left through a shut gate.
    assert_eq!(shared.hedges_issued.load(Ordering::Relaxed), 1);
    assert_eq!(shared.sat.escapes(), 1);
}

/// TODO 202 §17: `race_escape` off restores the pre-escape suppression
/// exactly - the arm that lets the escape's own payout be priced on ONE
/// binary.
///
/// `race_sat_pct` 0-vs-80 prices the GATE and cannot price the escape:
/// at 0 there is no gate to escape from, so both arms behave
/// identically on a stalled article. The bench round that prices the
/// escape is this knob at `race_sat_pct = 80`, and it only means
/// anything if OFF is genuinely the old behaviour - which is what this
/// pins, against the same rig as
/// `a_stalled_article_escapes_the_shut_line_gate` above.
#[tokio::test]
async fn the_escape_knob_turns_the_escape_off_and_nothing_else() {
    let servers: Vec<(ServerConfig, PoolConfig)> = [
        bound_guard_server("a", false),
        bound_guard_server("b", false),
    ]
    .into_iter()
    .map(|(sc, c)| {
        (
            sc,
            PoolConfig {
                race_escape: false,
                ..c
            },
        )
    })
    .collect();
    let read_timeout = servers[0].1.read_timeout;
    let reqs: Vec<ArticleReq> = (0..(ENDGAME_MAX + 10))
        .map(|i| ArticleReq::fresh(format!("<s{i}>")))
        .collect();
    let (shared, _) = Shared::new(reqs, &servers);
    shared.art_ms.store(TRAINED_ART_MS, Ordering::Relaxed);
    bound_guard_straggler(&shared, "<s1>", 0, read_timeout);
    shut_the_line_gate(&shared).await;

    // Marked stalled, and still suppressed: this is the pre-escape
    // behaviour, reachable without a second build.
    shared.mark_suspect("<s1>");
    assert!(
        shared
            .pick_dup(1, 0b10, 0b10, 0, Pipeline::payload(0), 0)
            .is_none(),
        "the escape fired with race_escape off - the A/B arm is not an arm"
    );
    assert_eq!(shared.sat.escapes(), 0);

    // And the knob touches nothing ELSE. A fresh fleet with the same
    // config and an untrained gauge (no peak, so the gate is open):
    // the ordinary stale rule still races a straggler, escape or no
    // escape. Fresh rather than reusing the pool above, because N6's
    // idle-spin record from that suppressed walk is time-capped at
    // `SCAN_RETRY_MS` and would swallow the next pick - correct in
    // production, where the gate opens by clock and the retry follows
    // inside 100 ms, but it would make this assertion about the wrong
    // thing.
    let (open, _) = Shared::new(
        (0..(ENDGAME_MAX + 10))
            .map(|i| ArticleReq::fresh(format!("<s{i}>")))
            .collect(),
        &servers,
    );
    open.art_ms.store(TRAINED_ART_MS, Ordering::Relaxed);
    bound_guard_straggler(&open, "<s1>", 0, read_timeout);
    assert!(
        !open.line_saturated(open.start.elapsed().as_millis() as u64),
        "rig broken: an untrained gauge must read the gate open"
    );
    let d = open
        .pick_dup(1, 0b10, 0b10, 0, Pipeline::payload(0), 0)
        .expect("the stale rule must still race a straggler on an idle line");
    assert_eq!(&*d.id, "<s1>");
    assert_eq!(open.sat.escapes(), 0, "an open gate issues no escapes");
}

/// TODO 202 §17, the fan-out half: at the endgame the escape also
/// reaches the picker that may race a SIBLING SESSION OF THE SAME
/// SERVER, which is the rescue a wedged TCP session actually needs -
/// the enemy there is one degraded socket, not a slow provider, and
/// the article's own server is usually the fastest answer to it.
///
/// Without the escape this article waits out the 30 s read timeout:
/// the fan-out is the only rule that races same-server, the slow-owner
/// and stale rules both skip `inf.server == me`, and the fleet gauge
/// has stood all three down.
#[tokio::test]
async fn a_stalled_article_reaches_the_same_server_fan_out_through_a_shut_gate() {
    let servers = vec![bound_guard_server("a", true), bound_guard_server("b", true)];
    let reqs: Vec<ArticleReq> = (0..4)
        .map(|i| ArticleReq::fresh(format!("<s{i}>")))
        .collect();
    let (shared, _) = Shared::new(reqs, &servers);
    assert!(
        shared.pending.load(Ordering::Acquire) <= ENDGAME_MAX,
        "rig broken: this leg must be in the endgame"
    );
    // Owned by server 0 and raced BY server 0: an idle sibling session.
    bound_guard_straggler(&shared, "<s1>", 0, TAIL_FANOUT_MIN_AGE * 4);
    shut_the_line_gate(&shared).await;

    assert!(
        shared
            .pick_dup(0, 0b1, 0b1, 0, Pipeline::payload(0), 0)
            .is_none(),
        "the line gate should suppress a healthy fan-out pick"
    );

    shared.mark_suspect("<s1>");
    let d = shared
        .pick_dup(0, 0b1, 0b1, 0, Pipeline::payload(0), 0)
        .expect("a stalled article must reach its own server's idle sibling");
    assert_eq!(&*d.id, "<s1>");
    assert!(d.dup);
    // A fan-out pick, not a hedge: only the fan-out races same-server.
    assert_eq!(shared.hedges_issued.load(Ordering::Relaxed), 0);
    assert_eq!(shared.sat.escapes(), 1);
}

/// TTFB-suspicion hedge (TODO 115, opt-in `PoolConfig::ttfb_hedge`):
/// the suspicion bound's math, and every gate on the suspect dup -
/// off by default, suspect flag required, one dup per article,
/// same-server allowed, each server at most once, fill servers
/// never, the hedge issue-rate cap honoured, and the fast-path flag
/// cleared once nothing suspect is left unraced.
#[tokio::test]
async fn suspect_dup_races_a_pre_byte_stall_at_once() {
    // Bound math: floor 1 s, 2x the EWMA past 500 ms.
    assert_eq!(ttfb_suspect_ms(0), 1000);
    assert_eq!(ttfb_suspect_ms(80), 1000);
    assert_eq!(ttfb_suspect_ms(500), 1000);
    assert_eq!(ttfb_suspect_ms(800), 1600);

    let mk = |host: &str, on: bool| {
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
                ttfb_hedge: on,
                adaptive_timeout: on,
                ..Default::default()
            },
        )
    };
    let mk_work = |id: &str| Work {
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
    };
    let servers = vec![mk("a", true), mk("b", true)];
    let reqs: Vec<ArticleReq> = (0..(ENDGAME_MAX + 10))
        .map(|i| ArticleReq::fresh(format!("<s{i}>")))
        .collect();
    let (shared, _) = Shared::new(reqs, &servers);

    // In flight on server 0, healthy: nobody races it.
    shared.register_inflight(&mk_work("<s0>"), 0);
    assert!(shared.pick_suspect_dup(0b10, 0b10, 0, 0).is_none());

    // Suspicion fires: a SAME-SERVER sibling may race it, the pick
    // counts as a hedge, and the second pick finds nothing (one dup
    // per article) and clears the fast-path flag.
    shared.mark_suspect("<s0>");
    assert!(shared.suspect_pending.load(Ordering::Acquire));
    assert!(
        shared.pick_suspect_dup(0b1, 0b1, 1, 0).is_none(),
        "fill server spent block bytes on a suspicion"
    );
    assert!(
        shared.pick_suspect_dup(0b1, 0b1, 0, 2).is_none(),
        "busy picker displaced queued work with a suspicion dup"
    );
    let d = shared
        .pick_suspect_dup(0b1, 0b1, 0, 0)
        .expect("suspect article should be raced immediately");
    assert_eq!(&*d.id, "<s0>");
    assert!(d.dup);
    // §17c: the TTFB rescue spends its own purse, never the stale one.
    assert_eq!(shared.ttfb_hedges_issued.load(Ordering::Relaxed), 1);
    assert_eq!(shared.hedges_issued.load(Ordering::Relaxed), 0);
    assert!(shared.pick_suspect_dup(0b10, 0b10, 0, 0).is_none());
    assert!(
        !shared.suspect_pending.load(Ordering::Acquire),
        "an empty scan should clear the fast-path flag"
    );

    // A server the article already dupped to never re-races it, and
    // the issue-rate cap gates fresh suspicions.
    shared.mark_suspect("<s0>");
    assert!(shared.pick_suspect_dup(0b1, 0b1, 0, 0).is_none());
    shared.register_inflight(&mk_work("<s1>"), 0);
    shared.mark_suspect("<s1>");
    shared.ttfb_hedges_issued.store(1000, Ordering::Relaxed);
    assert!(
        shared.pick_suspect_dup(0b10, 0b10, 0, 0).is_none(),
        "a capped suspect dup still issued"
    );

    // OFF (the default): a suspect mark goes nowhere.
    let servers_off = vec![mk("a", false), mk("b", false)];
    let reqs: Vec<ArticleReq> = (0..4)
        .map(|i| ArticleReq::fresh(format!("<s{i}>")))
        .collect();
    let (off, _) = Shared::new(reqs, &servers_off);
    assert!(!off.ttfb_hedge, "dark flag leaked into Shared");
    off.register_inflight(&mk_work("<s0>"), 0);
    off.mark_suspect("<s0>");
    assert!(
        off.pick_suspect_dup(0b10, 0b10, 0, 0).is_none(),
        "suspect dup fired while switched off"
    );
}
/// TODO 277: a slot that has NEVER been admitted can still be woken.
///
/// This is the structural claim the whole fleet curve rests on. The
/// seed spawns the curve's CEILING and runs at the curve's own number,
/// so on an anchorless run half the fleet parks before it has ever
/// dialled - and the in-run governor's raise is worth nothing unless
/// those particular slots come up. The sibling rig above moves a target
/// that started at the full spawn count, so every slot it wakes had
/// dialled once already and the pool had a session's worth of state for
/// it; nothing covered the never-admitted case, which is the one this
/// change creates.
///
/// Assertions are on the `connected` gauge, never on rates - socket
/// counts are deterministic on loopback, throughput is not.
#[tokio::test(flavor = "multi_thread")]
async fn a_raise_wakes_slots_that_were_parked_before_they_ever_dialled() {
    let data: Vec<u8> = (0..900_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("t.bin", &data, 20_000, "hr", &mut articles);
    let ids: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    let srv = crate::mock::MockServer::start(
        articles,
        crate::mock::Chaos {
            throttle: crate::mock::Throttle {
                per_conn_bps: 300_000,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    // Four slots SPAWNED, one dialling: the shape `get::fleet` now
    // builds, with the surplus parked as headroom for a raise.
    let target = ConnTarget::new(1);
    let (sc, mut cfg) = payout_server(&srv, 4, PoolConfig::default());
    cfg.live_target = Some(target.clone());
    assert_eq!(cfg.dialled(), 1, "spawned 4, dialling 1");
    let servers = vec![(sc, cfg)];
    let live = LiveStats::for_servers(&servers);
    assert_eq!(
        live.servers[0].budget.load(Ordering::Relaxed),
        1,
        "the dashboard must show the fleet in use, not the slot count"
    );
    let servers: Vec<(ServerConfig, PoolConfig)> = servers
        .into_iter()
        .map(|(s, mut c)| {
            c.live = Some(live.clone());
            (s, c)
        })
        .collect();
    let (tx, mut rx) = mpsc::channel(64);
    let fetch = tokio::spawn(async move { fetch_all_multi(&servers, ids, tx).await });
    let collect = tokio::spawn(async move {
        let mut done = 0usize;
        while let Some(o) = rx.recv().await {
            if matches!(o, FetchOutcome::Done { .. }) {
                done += 1;
            }
        }
        done
    });
    let wait_conns = |want: usize| {
        let live = live.clone();
        async move {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
            loop {
                let got = live.servers[0].connected.load(Ordering::Relaxed);
                if got == want {
                    return;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "connected stuck at {got}, wanted {want}"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    };
    // One dials; the other three park without ever having authenticated,
    // and must STAY parked rather than flap up to the spawn count.
    wait_conns(1).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        live.servers[0].connected.load(Ordering::Relaxed),
        1,
        "a slot above the target dialled unasked"
    );
    // The governor's raise. Every one of these three is a slot the pool
    // has never seen dial.
    target.set(4);
    wait_conns(4).await;
    tokio::time::timeout(Duration::from_secs(60), fetch)
        .await
        .expect("run hung across the raise")
        .unwrap();
    assert_eq!(collect.await.unwrap(), segs.len());
}

/// TODO 112: the live connection target moves BOTH directions
/// mid-run. Lowering it must drain the highest slots to their next
/// response boundary and park them (connected falls to the target,
/// no worker retires); raising it must wake them (connected climbs
/// again); and every article still gets its outcome. Assertions are
/// on the `connected` gauge, never on rates - socket counts are
/// deterministic on loopback, throughput is not.
#[tokio::test(flavor = "multi_thread")]
async fn a_live_target_change_parks_and_wakes_workers() {
    let data: Vec<u8> = (0..3_000_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("t.bin", &data, 20_000, "lt", &mut articles);
    let ids: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    let srv = crate::mock::MockServer::start(
        articles,
        crate::mock::Chaos {
            // Slow enough that the run comfortably outlives three
            // target moves, fast enough to finish inside CI bounds.
            throttle: crate::mock::Throttle {
                per_conn_bps: 150_000,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    let target = ConnTarget::new(4);
    let (sc, mut cfg) = payout_server(&srv, 4, PoolConfig::default());
    cfg.live_target = Some(target.clone());
    let servers = vec![(sc, cfg)];
    let live = LiveStats::for_servers(&servers);
    let servers: Vec<(ServerConfig, PoolConfig)> = servers
        .into_iter()
        .map(|(s, mut c)| {
            c.live = Some(live.clone());
            (s, c)
        })
        .collect();
    let (tx, mut rx) = mpsc::channel(64);
    let fetch = tokio::spawn(async move { fetch_all_multi(&servers, ids, tx).await });
    let collect = tokio::spawn(async move {
        let mut done = 0usize;
        while let Some(o) = rx.recv().await {
            if matches!(o, FetchOutcome::Done { .. }) {
                done += 1;
            }
        }
        done
    });
    let connected = |live: &LiveStats| live.servers[0].connected.load(Ordering::Relaxed);
    let wait_conns = |want: usize| {
        let live = live.clone();
        async move {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
            loop {
                let got = live.servers[0].connected.load(Ordering::Relaxed);
                if got == want {
                    return;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "connected stuck at {got}, wanted {want}"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    };
    // Phase 1: the full fleet authenticates.
    wait_conns(4).await;
    // Phase 2: lower the target - the three highest slots drain
    // (window 3 x 20 KB at 150 KB/s is sub-second) and park.
    target.set(1);
    wait_conns(1).await;
    // Hold a beat: a parked slot must STAY parked, not flap back.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(connected(&live), 1, "a parked slot redialled unasked");
    // Phase 3: raise it again - parked is not retired.
    target.set(3);
    wait_conns(3).await;
    tokio::time::timeout(Duration::from_secs(60), fetch)
        .await
        .expect("run hung across live target changes")
        .unwrap();
    assert_eq!(collect.await.unwrap(), segs.len());
}

/// F-22: admission under the live target is a COUNT, not a slot
/// ordinal. Target 1, fleet 8, and the server answers the first
/// `MAX_SESSION_ATTEMPTS` BODYs with 502 - exactly enough to retire the
/// one admitted worker for good. Under the old `slot < target` rule the
/// seven parked ordinals stayed parked (the target never rises without
/// bytes) and the run hung with pending > 0; now the retiring worker's
/// admission is re-filled by a parked one, which finds a recovered
/// server and finishes the job.
#[tokio::test(start_paused = true)]
async fn a_retired_admitted_worker_is_replaced_from_the_parked_fleet() {
    let _tick = super::inline_tests::Metronome::start();
    let mut articles = std::collections::HashMap::new();
    let payload: Vec<u8> = (0..60_000u32).map(|i| (i * 23) as u8).collect();
    crate::mock::make_file_articles("adm.bin", &payload, 6_000, "adm", &mut articles);
    let n = articles.len();
    let srv = crate::mock::MockServer::start(
        articles.clone(),
        crate::mock::Chaos {
            body_error: Some(MAX_SESSION_ATTEMPTS as u64),
            ..Default::default()
        },
    )
    .await;
    let target = ConnTarget::new(1);
    let (sc, mut cfg) = payout_server(
        &srv,
        8,
        PoolConfig {
            // One BODY in flight: every failure is exactly one session
            // failure, so the first worker walks to the ceiling alone.
            window: 1,
            connect_backoff: Duration::from_secs(2),
            article_retries: 250,
            ..Default::default()
        },
    );
    cfg.live_target = Some(target.clone());
    let reqs: Vec<ArticleReq> = articles
        .keys()
        .map(|k| ArticleReq::fresh(k.clone()))
        .collect();
    let (tx, mut rx) = mpsc::channel(256);
    tokio::time::timeout(
        Duration::from_secs(600),
        fetch_all_multi(&[(sc, cfg)], reqs, tx),
    )
    .await
    .expect("run hung: the retired admission was never re-filled");
    let mut done = 0;
    while let Ok(o) = rx.try_recv() {
        if matches!(o, FetchOutcome::Done { .. }) {
            done += 1;
        }
    }
    assert_eq!(
        done, n,
        "every article must land once a parked worker took over"
    );
    assert!(
        srv.accepted.load(Ordering::Relaxed) > MAX_SESSION_ATTEMPTS as u64,
        "a second worker never dialled"
    );
}

/// §96.5: a prepaid block that runs out MID-RUN releases its server -
/// workers stop topping up, drain what is in flight, and bow out for
/// good - and the shared queue hands everything left to the flatrate
/// server, so every article still gets its outcome. The paid overshoot
/// is bounded to what was in flight at the trip, and exactly one
/// "block spent" event lands on the ring for the graph.
#[tokio::test(flavor = "multi_thread")]
async fn a_spent_block_releases_the_server_mid_run_and_the_other_finishes() {
    let data: Vec<u8> = (0..2_000_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("t.bin", &data, 20_000, "bb", &mut articles);
    let ids: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    // Throttled so the block server cannot swallow the whole corpus in
    // its first pipeline fills - the trip must happen mid-run.
    let chaos = crate::mock::Chaos {
        throttle: crate::mock::Throttle {
            per_conn_bps: 300_000,
            ..Default::default()
        },
        ..Default::default()
    };
    let srv_a = crate::mock::MockServer::start(articles.clone(), chaos.clone()).await;
    let srv_b = crate::mock::MockServer::start(articles, chaos).await;
    const BUDGET: u64 = 400_000;
    let (sa, mut ca) = payout_server(&srv_a, 3, PoolConfig::default());
    ca.budget_bytes = Some(BUDGET);
    let (sb, cb) = payout_server(&srv_b, 3, PoolConfig::default());
    let servers = vec![(sa, ca), (sb, cb)];
    let live = LiveStats::for_servers(&servers);
    let servers: Vec<(ServerConfig, PoolConfig)> = servers
        .into_iter()
        .map(|(s, mut c)| {
            c.live = Some(live.clone());
            (s, c)
        })
        .collect();
    let (tx, mut rx) = mpsc::channel(64);
    let fetch = tokio::spawn(async move { fetch_all_multi(&servers, ids, tx).await });
    let collect = tokio::spawn(async move {
        let mut done = 0usize;
        while let Some(o) = rx.recv().await {
            if matches!(o, FetchOutcome::Done { .. }) {
                done += 1;
            }
        }
        done
    });
    tokio::time::timeout(Duration::from_secs(60), fetch)
        .await
        .expect("run hung after the block tripped")
        .unwrap();
    assert_eq!(
        collect.await.unwrap(),
        segs.len(),
        "articles lost when the block server bowed out"
    );
    let spent = live.servers[0].bytes.load(Ordering::Relaxed);
    assert!(
        spent >= BUDGET,
        "budget never tripped (spent {spent}) - the rig proved nothing"
    );
    // Bounded overshoot: what was in flight at the trip - window (3) x
    // connections (3) encoded articles of ~27 KB, with slack for a
    // response mid-read on each socket. The bug this guards against is
    // a whole-corpus overshoot (2 MB).
    assert!(
        spent < BUDGET + 700_000,
        "block server kept spending after its budget: {spent}"
    );
    assert!(
        live.servers[1].bytes.load(Ordering::Relaxed) > 0,
        "the flatrate server never took over"
    );
    let block_events = live
        .recent_events(200)
        .into_iter()
        .filter(|e| e.kind == "block")
        .count();
    assert_eq!(block_events, 1, "expected exactly one block-spent event");
}

/// PAYOUT (TODO 121.1): a cold-storage article - dead air before the
/// status line on EVERY attempt, then a normal answer - survives with
/// no knobs. The per-server widening alone cannot save it: its ladder
/// caps at the 10 s adaptive ceiling and fast pipelined samples
/// re-floor the EWMA between the slow article's retries, so all four
/// attempts ran under 12 s and the article failed on a healthy
/// provider. The article's own expiry count now escalates its next
/// attempt 10 s -> 20 s -> 30 s, so attempt three answers. Runtime is
/// real waiting (~25 s): the budgets under test are consts.
#[tokio::test(flavor = "multi_thread")]
async fn payout_prebyte_escalation_saves_cold_storage_articles() {
    let data: Vec<u8> = (0..320_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("c.bin", &data, 8_000, "cold", &mut articles);
    // The LAST article is the cold one, so the fast bulk has trained
    // the EWMA to the floor by the time it dispatches.
    let cold_id = format!("<{}>", segs.last().unwrap().0);
    let slow_ttfb: std::collections::HashMap<String, u64> =
        [(cold_id.clone(), 12_000u64)].into_iter().collect();
    let srv = crate::mock::MockServer::start(
        articles,
        crate::mock::Chaos {
            slow_ttfb,
            ..Default::default()
        },
    )
    .await;
    let ids: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    let n = ids.len();
    let cfg = PoolConfig {
        adaptive_timeout: true,
        ..Default::default()
    };
    let (elapsed, done, _) = payout_leg(vec![payout_server(&srv, 3, cfg)], ids).await;
    println!("cold-storage payout: {elapsed:?} for {done}/{n}");
    assert_eq!(
        done, n,
        "the cold-storage article must complete without NZBFAST_READ_TIMEOUT_SECS"
    );
}

/// §129 3g fence-retirement rig: ONE server, no twin, mostly missing
/// and refusing BARE, so the alignment fence arms on its first refusal
/// and every dispatch after that carries a DATE.
///
/// Returns the outcomes, the live-note ring, the server itself and the
/// run's per-server stats. `date_log` (the `served` count at each DATE)
/// against the final `served` is where "is this server still being
/// fenced" is read; `PoolStats::fence_retired` is the CLIENT's own
/// answer to the same question, and it is reported rather than merely
/// observable because a CLI leg reads no live-note ring at all - see
/// that field's doc, and the g25L leg it was added for.
async fn fence_leg(
    n_articles: usize,
    missing_every: usize,
    chaos: crate::mock::Chaos,
) -> (
    Vec<FetchOutcome>,
    Vec<String>,
    crate::mock::MockServer,
    std::collections::HashSet<String>,
    Vec<PoolStats>,
) {
    let data: Vec<u8> = (0..(n_articles as u32) * 4_000).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("f.bin", &data, 4_000, "fence", &mut articles);
    let ids: Vec<String> = segs.iter().map(|(id, _, _)| format!("<{id}>")).collect();
    // Mostly-missing on purpose: a bare refusal is what arms the fence,
    // and a run of them is the only window in which a desync is
    // invisible, so this is the shape both legs need.
    let absent: std::collections::HashSet<String> = ids
        .iter()
        .enumerate()
        .filter(|(i, _)| i % missing_every != 0)
        .map(|(_, id)| id.clone())
        .collect();
    for id in &absent {
        articles.remove(id);
    }
    let absent_out = absent.clone();
    let srv = crate::mock::MockServer::start(
        articles,
        crate::mock::Chaos {
            missing: absent,
            ..chaos
        },
    )
    .await;
    let reqs: Vec<ArticleReq> = ids.iter().map(|id| ArticleReq::fresh(id.clone())).collect();
    let cfg = PoolConfig {
        desync_fence: true,
        adaptive_timeout: true,
        ..Default::default()
    };
    let servers = vec![payout_server(&srv, 2, cfg)];
    let live = LiveStats::for_servers(&servers);
    let servers: Vec<(ServerConfig, PoolConfig)> = servers
        .into_iter()
        .map(|(s, mut c)| {
            c.live = Some(live.clone());
            (s, c)
        })
        .collect();
    let (tx, mut rx) = mpsc::channel(64);
    let fetch = tokio::spawn(async move { fetch_all_multi(&servers, reqs, tx).await });
    let collect = tokio::spawn(async move {
        let mut out = Vec::new();
        while let Some(o) = rx.recv().await {
            out.push(o);
        }
        out
    });
    let stats = tokio::time::timeout(Duration::from_secs(120), fetch)
        .await
        .expect("fence leg hung")
        .unwrap();
    let outcomes = collect.await.unwrap();
    let notes: Vec<String> = live
        .events
        .lock()
        .unwrap()
        .iter()
        .map(|e| format!("{} {}", e.kind, e.detail))
        .collect();
    (outcomes, notes, srv, absent_out, stats)
}

/// §129 3g: a provider that reads DATE and answers nothing must stop
/// being fenced. Every fence it is sent goes unanswered, and the
/// unanswered fence kills the session that sent it, so without
/// retirement this server's sessions die forever on a fault it does
/// not have - the fence's own cost, charged to the innocent.
///
/// Retirement has to LATCH. The first shape of it cleared
/// `bare_refuser`, which `handle_missing` re-arms on the very next bare
/// 430, so fencing came back within one refusal and the live note
/// re-emitted every cycle: that regression is what the "never fenced
/// again" half of this assertion catches.
#[tokio::test(flavor = "multi_thread")]
async fn fence_retires_on_a_date_silent_provider_and_never_comes_back() {
    let (outcomes, notes, srv, _, stats) = fence_leg(
        160,
        4,
        crate::mock::Chaos {
            mute_date: true,
            ..Default::default()
        },
    )
    .await;
    let dates = srv.date_log.lock_ok().clone();
    let last_date = dates.last().copied().unwrap_or(0);
    let served = srv.served.load(Ordering::Relaxed);
    // The rig has to be measuring something: no fence at all means the
    // arming path never ran and the leg proves nothing.
    assert!(
        !dates.is_empty(),
        "the fence never armed - a bare-refusing server must be fenced"
    );
    assert_eq!(
        notes.iter().filter(|n| n.starts_with("fence-off")).count(),
        1,
        "retirement must be announced exactly once, not once per cycle: {notes:?}"
    );
    // The same fact the note carries, REPORTED rather than left on a
    // ring only a daemon reads. A CLI leg has no reader for that ring,
    // so on a bench log the retirement was invisible and its absence
    // proved nothing - which is exactly the ambiguity the 28 Aug 2026
    // g25L question ran into, since a bare-heavy refusal split means
    // one thing under a fence that held and another under one that was
    // gone (research/SLOW-SOCKET-430-CAUSAL-READ-2026-08-28.md).
    assert!(
        stats.iter().any(|st| st.fence_retired),
        "a retired fence must be REPORTED in the run stats, not only noted"
    );
    // Retirement is two duds deep, one per session, so the fences on
    // the wire are bounded by a couple of pipelines' worth. What makes
    // this an assertion about LATCHING rather than about counting is
    // the second half: the run served hundreds of requests after the
    // last DATE, so fencing did not come back.
    assert!(
        served - last_date > served / 2,
        "fencing resumed after retirement: last DATE at {last_date} of {served} served"
    );
    let failed: Vec<&FetchOutcome> = outcomes
        .iter()
        .filter(|o| matches!(o, FetchOutcome::Failed { .. }))
        .collect();
    assert!(
        failed.is_empty(),
        "a DATE-silent provider must not fail articles it holds: {failed:?}"
    );
    let done = outcomes
        .iter()
        .filter(|o| matches!(o, FetchOutcome::Done { .. }))
        .count();
    assert_eq!(done, 40, "every article the server holds must arrive");
}

/// The safety half: a server whose fences DO work, and which really is
/// dropping responses, must keep its fence. `skip_nth_response`
/// withholds every Nth BODY answer, so a later fence read collects a
/// BODY-shaped status - the desync the fence exists to catch - and
/// counting that toward retirement would disarm the check on exactly
/// the provider that needs it. It cannot: this server answers its
/// first fence, `fence_ok` latches, and no dud is ever counted again.
#[tokio::test(flavor = "multi_thread")]
async fn a_desyncing_provider_keeps_its_fence() {
    let (outcomes, notes, srv, absent, stats) = fence_leg(
        160,
        4,
        crate::mock::Chaos {
            skip_nth_response: 12,
            ..Default::default()
        },
    )
    .await;
    let dates = srv.date_log.lock_ok().clone();
    let last_date = dates.last().copied().unwrap_or(0);
    let served = srv.served.load(Ordering::Relaxed);
    assert!(
        notes.iter().all(|n| !n.starts_with("fence-off")),
        "a desyncing server must never retire its fence: {notes:?}"
    );
    assert!(
        served - last_date < served / 4,
        "fencing stopped early on a desyncing server: last DATE at {last_date} of {served} served"
    );
    // The reported half of the same claim, and the direction that
    // matters most: a run whose refusals are all bare AND whose stats
    // say the fence held is one whose Missing verdicts still rest on
    // proven attribution. A `fence_retired` that were true here would
    // read as misattribution on a leg that had none.
    assert!(
        stats.iter().all(|st| !st.fence_retired),
        "a desyncing server's fence must not read as retired in the run stats"
    );
    // And the fence's own job, unchanged: no article the server holds
    // may be declared Missing off a misattributed refusal.
    let held: Vec<&Arc<str>> = outcomes
        .iter()
        .filter_map(|o| match o {
            FetchOutcome::Missing { id, .. } if !absent.contains(&**id) => Some(id),
            _ => None,
        })
        .collect();
    assert!(
        held.is_empty(),
        "present article(s) declared Missing by a desynced session: {held:?}"
    );
}

/// TODO 208.2, the warm-up gap. A starved share looks like this on the
/// wire: half a body, then nothing for longer than the flat 8 s
/// deadline, then the rest - on a connection that is alive the whole
/// time. Under the shipped bound that silence was judged by the floor
/// whenever it began before the run's own line peak had trained (7 s
/// after the FIRST delivered body, which on a 100 Mbit line under 360
/// connections lands 10-27 s in), because the bound was sampled once
/// at read start and nothing that the gauge learned afterwards could
/// reach a wait already armed. Here the gap opens 4 s into the run on
/// the very first article; the fleet's first body lands at 8 s; the
/// floor would fire at 12 s; the gap closes at 14 s (plus the mock's
/// first paced chunk, ~1.3 s).
///
/// The fleet dials on a 1 s ramp in the warm-up pair, as a real one
/// does (150 ms a slot shipped, so a 100-per-server fleet spreads over
/// 15 s), and that was load-bearing when the rig was built: with all
/// eight dialled at once, seven bodies that spent 8 s on the wire land
/// in one clump at t=8 s, and a gauge fed per delivered body - its age
/// starting at the FIRST one - credits them to a window that has
/// barely opened. Measured on this rig before the ramp: a trained peak
/// of 695 KB/s for a 400 KB/s line (+74%), which cut the bound to
/// 9.2 s mid-silence and killed the read the warm-up had just saved.
/// The banked shaped legs carry the same artefact at 10-35% (a `line
/// peak` of 37.3 MB/s through a 248 Mbit pipe; 15.7 to 16.9 MB/s at
/// fleet 360 through 99 Mbit, rising with the fleet), smaller because
/// TCP unfairness spreads a real first wave out. The peak is a run
/// max, so that over-read shortened every stall bound of the run by
/// the same share, loosened the §202 gate and fed the §208.1 cap.
/// Fixed 22 Aug (TODO 208.2 over-read, `PoolConfig::peak_arrivals`):
/// the gauge is fed per arriving chunk, so there is no clump to
/// credit. The `ramp_ms = 0` pair below is that fix's rig: the fleet
/// dialled together, the live bound on, and the read survives only
/// on the arrivals arm - the per-body arm reproduces the kill above.
///
/// Live (the shipped posture): the daemon's link anchor sizes a share
/// from the first delivered body, the wait re-reads the bound during
/// the silence, and the body lands - zero stall kills, zero
/// reconnects. `stall_live` off (the A/B arm, exactly the pre-warm-up
/// code path): the read is killed at 12 s, the half body is thrown
/// away, the worker re-dials and fetches it whole. Both arms finish
/// the job; the difference is the one discarded body and the one
/// reconnect, which is the per-event cost the 311-per-job tally at
/// 100 Mbit was made of.
async fn warm_up_gap_leg(
    stall_live: bool,
    ramp_ms: u64,
    peak_arrivals: bool,
    anchor_bps: u64,
) -> (usize, u64, u64, u64) {
    let data: Vec<u8> = (0..9_600_000u32).map(|i| (i * 13) as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("gap.bin", &data, 400_000, "gap", &mut articles);
    let ids: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    let first = ids[0].id.to_string();
    let srv = crate::mock::MockServer::start(
        articles,
        crate::mock::Chaos {
            gap: [first].into_iter().collect(),
            gap_ms: 10_000,
            throttle: crate::mock::Throttle {
                per_conn_bps: 50_000,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    let (sc, mut cfg) = payout_server(
        &srv,
        8,
        PoolConfig {
            adaptive_timeout: true,
            stall_live,
            peak_arrivals,
            // The daemon's stamp: a 400 KB/s line shared eight ways is
            // 50 KB/s a share, 8 s a body, a 16 s bound. 0 = the CLI
            // shape, where the bound is fed by the gauge's provisional
            // reading instead.
            line_anchor_bps: anchor_bps,
            ..PoolConfig::default()
        },
    );
    cfg.ramp_delay = Duration::from_millis(ramp_ms);
    let servers = vec![(sc, cfg)];
    let live = LiveStats::for_servers(&servers);
    let servers: Vec<(ServerConfig, PoolConfig)> = servers
        .into_iter()
        .map(|(s, mut c)| {
            c.live = Some(live.clone());
            (s, c)
        })
        .collect();
    let (tx, mut rx) = mpsc::channel(64);
    let fetch = tokio::spawn(async move { fetch_all_multi(&servers, ids, tx).await });
    let collect = tokio::spawn(async move {
        let mut done = 0usize;
        while let Some(o) = rx.recv().await {
            if matches!(o, FetchOutcome::Done { .. }) {
                done += 1;
            }
        }
        done
    });
    tokio::time::timeout(Duration::from_secs(120), fetch)
        .await
        .expect("warm-up gap leg hung")
        .unwrap();
    let done = collect.await.unwrap();
    let s = &live.servers[0];
    (
        done,
        s.ends_stall.load(Ordering::Relaxed),
        s.reconnects.load(Ordering::Relaxed),
        live.race.line_peak_bps.load(Ordering::Relaxed),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn the_live_stall_bound_carries_a_starved_body_through_the_warm_up_gap() {
    let (done, stalls, reconnects, _) = warm_up_gap_leg(true, 1000, true, 400_000).await;
    assert_eq!(done, 24, "every article landed");
    assert_eq!(
        (stalls, reconnects),
        (0, 0),
        "live bound: the 10 s silence was judged by the anchor's 16 s share, \
         not the 8 s floor - but it was killed ({stalls} stall kills, \
         {reconnects} reconnects)"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_stall_live_knob_restores_the_flat_floor_until_the_peak_trains() {
    let (done, stalls, reconnects, _) = warm_up_gap_leg(false, 1000, true, 400_000).await;
    assert_eq!(done, 24, "the A/B arm still finishes the job");
    assert!(
        stalls >= 1 && reconnects >= 1,
        "stall_live off: the silence that began before the peak trained must \
         still be killed at the 8 s floor (got {stalls} stall kills, \
         {reconnects} reconnects) - the arm is not an arm"
    );
}

/// TODO 208.2 over-read: the fleet dialled TOGETHER (no ramp) and NO
/// anchor - the CLI shape, where the live bound is fed by the gauge's
/// own reading. Fed per arriving chunk the gauge trains a peak that
/// reads the 400 KB/s line as what it is (within the mock's 64 KB
/// chunk discretisation), the bound is the 16 s share from the first
/// bodies on, and the 10 s silence is carried - no kill, no reconnect.
///
/// THE BAND IS ASYMMETRIC, AND ON PURPOSE. The two edges answer
/// different questions and only one of them is this arm's subject.
///
/// The CEILING is the subject: an over-read is the defect, and the
/// arm below measures the defect at ~1.8x the line. 460_000 is 1.15x
/// nominal, so a gauge that has gone back to crediting clumps cannot
/// pass here. Do not raise it.
///
/// The FLOOR is not a statement about the gauge at all - it is a
/// statement about the BOX, and until 24 Aug 2026 it was an unstated
/// one. The peak is a MEASUREMENT of what crossed the wire, so it
/// tracks what the mock's pacing actually achieved, and the best
/// reading available on this rig is not 400 KB/s to begin with: the
/// fleet runs eight shares for the first half body, SEVEN for the
/// 10 s gap, then eight again, and that trough is still inside the
/// gauge's 10 s-half-life window when the plateau ends. Integrating
/// the profile against the window (T = 8 s an article, plateau
/// [T/2 + 10, 3T]) gives 384.6 KB/s at perfect pacing; the 64 KB
/// chunk sawtooth adds a couple of percent back, and a quiet dev box
/// measures 391-408 KB/s. So the reading scales as
/// `384.6 KB/s x achieved/nominal`, and the floor is really a minimum
/// pacing fraction the runner has to hit for 35 s.
///
/// At 340_000 that fraction was 88%, and nothing said so. It was
/// overrun twice in the 400 main runs between 23 and 24 Aug 2026 -
/// 336_086 B/s and 337_781 B/s, both on `unit-one-process`, where the
/// whole nzbkit binary took 732 s against 72 s on the dev box. Neither
/// was a polluter and no neighbour was involved: the victim
/// reproduces SOLO once the box is loaded enough (measured 24 Aug,
/// ten concurrent copies of this one test at background QoS against
/// 128 spinners: 18 of 20 red, 276_525 to 333_549 B/s, every failure
/// one-sided low). 260_000 is 68% of the 384.6 KB/s best, so a runner
/// now has to lose a THIRD of its paced throughput before this arm can
/// go red - and it still refuses the low-side failure the saturation
/// module doc names, a gauge aged from too early an origin
/// under-reading by the pipeline's fill ("half the line", 200 KB/s
/// here), which stays out by 1.3x. Do not tighten it back toward the
/// line; the gauge reads what the wire achieved, and on a CI runner
/// the wire is the mock's timer.
///
/// One thing the floor cannot cover, so read it before widening
/// further: the `(0, 0)` assertion above carries a wall-clock budget
/// of its OWN - it fired 2 of those same 20 runs, when the gauge was
/// still untrained as the silence opened and the bound sat on its 8 s
/// floor. Widening past ~260_000 buys nothing, because that assertion
/// becomes the limit, and it cannot be loosened without tuning the
/// rig's geometry - which is the one thing the arm below refuses to
/// do.
#[tokio::test(flavor = "multi_thread")]
async fn the_line_peak_reads_the_line_with_the_fleet_dialled_together() {
    let (done, stalls, reconnects, peak) = warm_up_gap_leg(true, 0, true, 0).await;
    assert_eq!(done, 24, "every article landed");
    assert_eq!(
        (stalls, reconnects),
        (0, 0),
        "arrivals on, no ramp: the first wave's clump should not exist, yet the \
         bound it inflates killed the read ({stalls} stall kills, {reconnects} reconnects)"
    );
    assert!(
        (260_000..=460_000).contains(&peak),
        "arrivals on: trained line peak {peak} B/s for a 400 KB/s line"
    );
}

/// The A/B arm reproduces the recorded defect in the figure that
/// carries it: per-body folding, the fleet dialled together, and the
/// clump of seven first bodies at 8 s trains a peak of ~1.7x the line
/// at the second wave (695 KB/s measured for 400 KB/s, the number in
/// TODO 208.2; the arithmetic says 718). That peak is a run max, so it
/// is what every stall bound of the run divides (9.2 s instead of
/// 16 s) - which is what killed the read in the 22 Aug rig. Asserted
/// on the peak rather than on a kill: the rig's one silence (4-14 s)
/// ends before the inflated peak exists, and a rig whose geometry is
/// tuned until the consequence shows would be pinning the geometry.
///
/// Its floor is the same kind of quantity as the arm above's, and it
/// moved on the same day for the same reason: this reading is a
/// measurement too, so it comes off with the box. A quiet dev box
/// measures 717.5-717.9 KB/s (four runs, 0.05% spread - the clump is
/// a byte count, which is why it holds up better under load than the
/// plateau does), and under the load that reddened the arm above 18
/// times in 20 this one still fell to 556_944 once in ten and went
/// red against its old 560_000. 500_000 is 70% of the quiet figure,
/// matching the slip the arm above now tolerates.
///
/// WHAT MAKES THE PAIR AN A/B IS THAT THIS FLOOR SITS ABOVE THAT
/// ARM'S CEILING, and nothing else. 500_000 > 460_000, so a knob that
/// had become inert - both arms reading the same R, whatever R is -
/// fails one of the two for every possible R. Keep that ordering: a
/// ceiling raised to meet this floor, or this floor dropped to meet
/// that ceiling, deletes the A/B and leaves two arms that can both
/// pass on one reading.
#[tokio::test(flavor = "multi_thread")]
async fn the_peak_arrivals_knob_restores_the_first_wave_clump() {
    let (done, _, _, peak) = warm_up_gap_leg(true, 0, false, 0).await;
    assert_eq!(done, 24, "the A/B arm still finishes the job");
    assert!(
        peak >= 500_000,
        "peak_arrivals off, no ramp: the per-body clump should over-read the \
         400 KB/s line by ~1.7x, got a trained peak of {peak} B/s - the arm is not an arm"
    );
}

/// TODO 112, the socket half: what the fleet HANDS BACK when the live
/// target is lowered under it.
///
/// `a_live_target_change_parks_and_wakes_workers` above pins the
/// `connected` gauge - the workers park and wake. It says nothing about
/// where their SESSIONS went, and until 26 Aug 2026 they were quit: the
/// shed was the last exit in this pool that closed a connection it had
/// just proved drained (`inflight.is_empty()` is the guard, which is the
/// reuse point's own safety argument). This pins that they are parked
/// instead, and that the provider still has them.
///
/// The reasoning, and the live-daemon measurement that says this arm's
/// real-world population is empty today, is at the shed in
/// `session_loop`. What makes parking right rather than merely harmless
/// is the raise in phase 3: TODO 277 spawns surplus slots PARKED so a
/// raise lands without a dial, and a shed that quit its socket made the
/// same shed/raise cycle cost a dial, a TLS handshake and an AUTHINFO
/// every time. `accepted` is the assertion that carries that - the
/// fleet re-reaches 3 connections without the far end accepting a
/// fifth.
#[tokio::test(flavor = "multi_thread")]
async fn a_shed_for_a_lowered_target_parks_its_session_rather_than_quitting_it() {
    let data: Vec<u8> = (0..3_000_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("shed.bin", &data, 20_000, "sh", &mut articles);
    let ids: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    let srv = crate::mock::MockServer::start(
        articles,
        crate::mock::Chaos {
            throttle: crate::mock::Throttle {
                per_conn_bps: 150_000,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    let warm = crate::warmpool::WarmPool::new(Duration::from_secs(60), 8);
    let target = ConnTarget::new(4);
    let (sc, mut cfg) = payout_server(&srv, 4, PoolConfig::default());
    cfg.live_target = Some(target.clone());
    cfg.warm = Some(warm.clone());
    let servers = vec![(sc, cfg)];
    let live = LiveStats::for_servers(&servers);
    let servers: Vec<(ServerConfig, PoolConfig)> = servers
        .into_iter()
        .map(|(s, mut c)| {
            c.live = Some(live.clone());
            (s, c)
        })
        .collect();
    let (tx, mut rx) = mpsc::channel(64);
    let fetch = tokio::spawn(async move { fetch_all_multi(&servers, ids, tx).await });
    let collect = tokio::spawn(async move {
        let mut done = 0usize;
        while let Some(o) = rx.recv().await {
            if matches!(o, FetchOutcome::Done { .. }) {
                done += 1;
            }
        }
        done
    });
    let wait_conns = |want: usize| {
        let live = live.clone();
        async move {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
            loop {
                let got = live.servers[0].connected.load(Ordering::Relaxed);
                if got == want {
                    return;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "connected stuck at {got}, wanted {want}"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    };
    wait_conns(4).await;
    let dialled = srv.accepted.load(Ordering::Relaxed);
    assert_eq!(dialled, 4, "the fleet must be up before the target moves");
    // Lower the target: three workers drain their windows and shed.
    target.set(1);
    wait_conns(1).await;
    // The shed hands the socket to the warm pool. Give the three parks a
    // beat to land - `connected` comes down as the guard drops, which is
    // the statement BEFORE the park's own await.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while warm.idle_count().await < 3 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(
        warm.idle_count().await,
        3,
        "a shed connection is drained by its own guard, so it belongs in \
         the warm pool, not on the floor"
    );
    assert_eq!(
        srv.accepted.load(Ordering::Relaxed),
        dialled,
        "and nothing redialled on the way down"
    );
    // Raise it again: the parked sessions are what the fleet comes back
    // on, so the far end accepts nothing new.
    target.set(3);
    wait_conns(3).await;
    assert_eq!(
        srv.accepted.load(Ordering::Relaxed),
        dialled,
        "the raise must land on the parked sessions - that is what TODO \
         277 parks surplus slots for, and what quitting them cost"
    );
    tokio::time::timeout(Duration::from_secs(60), fetch)
        .await
        .expect("run hung across the shed and the raise")
        .unwrap();
    assert_eq!(collect.await.unwrap(), segs.len());
}

/// §96.5, and the other half of the shed's answer: a worker leaving
/// because the prepaid BLOCK is spent quits its session, and must go on
/// quitting it.
///
/// This is the one case where parking a drained connection is wrong, and
/// the module already says so at the loop-top bow-out: the worker leaves
/// "before it can dial (or keep) a session the account can no longer pay
/// for". `over_budget` latches for the whole run, and the daemon's
/// runner rules a host whose block spend has reached its size out of the
/// NEXT job's pool outright - so a session parked here is a provider
/// slot held for a job that will never take it.
///
/// A budget far below the post's size makes every worker shed on this
/// arm rather than on a target (there is no `live_target` here at all),
/// and the run then ends with the server dark.
#[tokio::test(flavor = "multi_thread")]
async fn a_shed_for_a_spent_prepaid_block_quits_its_session() {
    let data: Vec<u8> = (0..2_000_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("blk.bin", &data, 20_000, "bk", &mut articles);
    let ids: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    let srv = crate::mock::MockServer::start(articles, crate::mock::Chaos::default()).await;
    let warm = crate::warmpool::WarmPool::new(Duration::from_secs(60), 8);
    let (sc, mut cfg) = payout_server(&srv, 4, PoolConfig::default());
    cfg.warm = Some(warm.clone());
    // Spent inside the first handful of articles, with the rest of the
    // post still queued - so every worker leaves on the budget arm and
    // none of them reaches the queue-dry park.
    cfg.budget_bytes = Some(100_000);
    let (tx, mut rx) = mpsc::channel(256);
    let collect = tokio::spawn(async move { while rx.recv().await.is_some() {} });
    tokio::time::timeout(
        Duration::from_secs(120),
        fetch_all_multi(&[(sc, cfg)], ids, tx),
    )
    .await
    .expect("a run that spends its block must still return");
    collect.await.unwrap();
    assert_eq!(
        warm.idle_count().await,
        0,
        "a spent block is the one exit that must NOT hand its session \
         on: nothing is coming back for it, and it holds an account slot \
         until max_idle reaps it"
    );
    assert!(
        !segs.is_empty(),
        "the fixture must actually have articles to leave unfetched"
    );
}

/// TODO 315, the late re-ask's own wedge: A LAST BACKBONE THAT ANSWERS
/// AND THEN GOES AWAY.
///
/// [`Shared::take_recheck`] buys one more question of the group whose
/// 430 was the last evidence an article needed, and pays for it by
/// clearing that group's `tried_430` bit so `next_work` cannot call the
/// article live-unanimous while the re-ask waits. That leaves the
/// article retirable ONLY by the group holding it - and dispatchable
/// only by that group as well, because every other server's bit is set
/// and the pickup gate steps them all past it. Nothing bounded how long
/// that took, so a group that answered once and then stopped granting
/// sessions kept the article, and therefore the whole run, alive for
/// ever. `pool/gates.rs` states the shape in writing: "an item nothing
/// can serve rotates in the queue forever and deadlocks the run."
///
/// THE RIG IS THE INCIDENT'S ORDER, which is the part that cannot be
/// skipped: a hold is taken only where the group's OWN refusal was the
/// last evidence, so a backbone that never connects can never produce
/// one - it has to answer first and go away after.
/// [`crate::mock::Chaos::dark_after_refusals`] triggers on the client's
/// own progress rather than a clock, so the ordering needs no poll and
/// no wall-clock race. The fill LEVEL makes B the last refuser by
/// construction: level 1 takes queued work only once every live level-0
/// server has 430'd it, so the article walks A then B and the hold is
/// always B's.
///
/// ONE ARTICLE, and that is a correction rather than a simplification.
/// The first cut ran sixteen and proved something else: a held item is
/// requeued at the queue MIDPOINT, so B spent the back half of its
/// refusal budget on RE-ASKS and seven articles never got B's first
/// refusal at all - they wedged with `tried_430` naming A alone, which
/// is the plain live-mask deadlock `participation_mask`'s own header
/// describes and has nothing to do with this hold. The control arm
/// timed out for the wrong reason and the rig proved nothing. With one
/// article there is no second question: the only thing that can hold
/// the run open is the hold.
///
/// `outage_budget: None` is not decoration either - it is the shipped
/// `server_outage_mins = 0` setting, and it is what keeps B's parked
/// worker ALIVE after it goes dark (`outage_budget_blown` and
/// `ladder_exhausted` are both false for the life of the run, so the
/// elected prober never publishes `CapEpisode::Dead`). B therefore
/// never leaves `live_mask`, which is the one condition that could have
/// retired the hold for free - and under that setting the wedge is
/// PERMANENT rather than merely long.
///
/// BOTH ARMS ARE ASSERTED and the control is the proof of the rig: with
/// the window off the run does not finish, and it can only be the hold
/// holding it, because an unheld article here is live-unanimous the
/// instant B answers.
#[tokio::test(flavor = "multi_thread")]
async fn a_held_re_ask_cannot_outlive_its_window_when_the_backbone_goes_dark() {
    let id = "<dark0@rig>";

    let leg = |hold_ms: u64| async move {
        let absent: std::collections::HashSet<String> = [id.to_string()].into_iter().collect();
        // A: the level-0 primary. Refuses, fast, and is never the last
        // refuser, so it never takes a hold.
        let a = crate::mock::MockServer::start(
            Default::default(),
            crate::mock::Chaos {
                missing: absent.clone(),
                echo_missing_id: true,
                ..Default::default()
            },
        )
        .await;
        // B: the level-1 backbone. Answers exactly one refusal - the
        // one that makes the article live-unanimous and buys the hold -
        // and that refusal takes it dark for good.
        let b = crate::mock::MockServer::start(
            Default::default(),
            crate::mock::Chaos {
                missing: absent,
                echo_missing_id: true,
                dark_after_refusals: 1,
                ..Default::default()
            },
        )
        .await;
        let cfg = |level: u32| {
            let mut sc = if level == 0 {
                a.server_config()
            } else {
                b.server_config()
            };
            sc.connections = 1;
            sc.level = level;
            (
                sc,
                PoolConfig {
                    connections: 1,
                    ramp_delay: Duration::from_millis(0),
                    // Explicit rather than inherited: this rig is ABOUT
                    // the mechanism, so an env kill switch in somebody's
                    // shell must not quietly turn it into a test of
                    // nothing.
                    recheck_430: true,
                    recheck_430_hold: Duration::from_millis(hold_ms),
                    // See the doc comment: this is what keeps B's worker
                    // alive once it stops accepting.
                    outage_budget: None,
                    connect_backoff: Duration::from_millis(20),
                    ..Default::default()
                },
            )
        };
        let servers = vec![cfg(0), cfg(1)];
        let reqs = vec![ArticleReq {
            id: id.into(),
            age_days: 0,
            part: 0,
            file: u32::MAX,
        }];
        let (tx, mut rx) = mpsc::channel(8);
        let fetch = tokio::spawn(async move { fetch_all_multi(&servers, reqs, tx).await });
        let collect = tokio::spawn(async move {
            let mut got = Vec::new();
            while let Some(o) = rx.recv().await {
                got.push(matches!(o, FetchOutcome::Missing { .. }));
            }
            got
        });
        let finished = tokio::time::timeout(Duration::from_secs(15), fetch).await;
        // The mocks must outlive the leg.
        drop((a, b));
        match finished {
            Ok(j) => {
                let _ = j.unwrap();
                Some(collect.await.unwrap())
            }
            Err(_) => None,
        }
    };

    // The bound off: the pre-30-Aug shape. The hold is taken, B is dark,
    // and nothing anywhere can retire it.
    assert!(
        leg(0).await.is_none(),
        "with the window off a held re-ask should keep the run alive for ever - if this \
         leg finished, the rig stopped building the wedge it is the control for (B must \
         be the LAST refuser and must really go dark) and the arm below proves nothing"
    );

    // The bound on. Comfortably above the window, so the assertion is
    // about the mechanism and not about how loaded the box is.
    let got = leg(1_000)
        .await
        .expect("a bounded hold must let the run finish");
    assert_eq!(
        got,
        vec![true],
        "the article owes exactly one outcome once its hold expires, and it is the \
         Missing the two refusals in hand already justified"
    );
}

/// TODO 315: THE WINDOW MUST NOT COST THE MECHANISM ITS VALUE. The
/// rig above proves the hold ends; this one proves it still happens.
///
/// Same fleet and the same shipped window, against the fault the late
/// re-ask exists for - [`crate::mock::Chaos::missing_once`], a refusal
/// that was never true, measured at 231 of 250 refused articles served
/// on the very next pass off the same account nine minutes later. The
/// re-ask is dispatched as soon as the article comes back round, which
/// on a healthy fleet is far inside the window, so the article must
/// come back DONE and not Missing.
///
/// Deliberately run at the SHIPPED [`RECHECK_430_HOLD`] rather than at
/// a rig-sized one: a window shortened below the delay to its own
/// re-ask turns this mechanism off while leaving every other test
/// green, and this is the one assertion that would notice.
#[tokio::test(flavor = "multi_thread")]
async fn a_bounded_hold_still_recovers_the_refusal_that_was_never_true() {
    let data: Vec<u8> = (0..40_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("once.bin", &data, 40_000, "om", &mut articles);
    // Bracketed: `make_file_articles` keys the article map `<id>` and
    // returns the bare id, and every `Chaos` id set is the wire form.
    // The bare form still "works" on a server holding no articles - the
    // not-found arm refuses it - which is exactly how a first cut of
    // this rig read as a permanent absence and never exercised the
    // re-ask at all.
    let real = format!("<{}>", segs[0].0);

    let a = crate::mock::MockServer::start(
        Default::default(),
        crate::mock::Chaos {
            missing: [real.clone()].into_iter().collect(),
            echo_missing_id: true,
            ..Default::default()
        },
    )
    .await;
    // B holds the article and refuses it exactly once - the shape
    // nothing on the wire can tell from a permanent absence.
    let b = crate::mock::MockServer::start(
        articles,
        crate::mock::Chaos {
            missing_once: [real.clone()].into_iter().collect(),
            echo_missing_id: true,
            ..Default::default()
        },
    )
    .await;
    let cfg = |level: u32| {
        let mut sc = if level == 0 {
            a.server_config()
        } else {
            b.server_config()
        };
        sc.connections = 1;
        sc.level = level;
        (
            sc,
            PoolConfig {
                connections: 1,
                ramp_delay: Duration::from_millis(0),
                recheck_430: true,
                ..Default::default()
            },
        )
    };
    let servers = vec![cfg(0), cfg(1)];
    let reqs = vec![ArticleReq {
        id: real.as_str().into(),
        age_days: 0,
        part: 0,
        file: u32::MAX,
    }];
    let (tx, mut rx) = mpsc::channel(8);
    let fetch = tokio::spawn(async move { fetch_all_multi(&servers, reqs, tx).await });
    let collect = tokio::spawn(async move {
        let mut done = 0usize;
        let mut missing = 0usize;
        while let Some(o) = rx.recv().await {
            match o {
                FetchOutcome::Done { .. } => done += 1,
                FetchOutcome::Missing { .. } => missing += 1,
                FetchOutcome::Failed { .. } => {}
            }
        }
        (done, missing)
    });
    tokio::time::timeout(Duration::from_secs(30), fetch)
        .await
        .expect("the healthy-backbone leg hung")
        .unwrap();
    let (done, missing) = collect.await.unwrap();
    assert_eq!(
        (done, missing),
        (1, 0),
        "the shipped window has to leave the late re-ask room to happen - a Missing here \
         means the bound retired the hold before the backbone was asked again, which is \
         the mechanism switched off rather than bounded"
    );
}
