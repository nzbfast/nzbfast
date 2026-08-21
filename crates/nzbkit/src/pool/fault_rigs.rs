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
        ord: 0,
        id: "<q0>".into(),
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
        ord: 0,
        id: "<q0>".into(),
        attempts: 0,
        promoted: false,
        tried_430: 0,
        tried_fail: 0b01, // steered off server a
        dup: false,
        prebyte_expiries: 0,
        soft_430: 0,
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
        ord: 0,
        id: "<s0>".into(),
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
        ord: 0,
        id: "<s1>".into(),
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
        ord: 0,
        id: "<s2>".into(),
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
        ord: 0,
        id: id.into(),
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
    assert_eq!(shared.hedges_issued.load(Ordering::Relaxed), 1);
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
    shared.hedges_issued.store(1000, Ordering::Relaxed);
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
/// Returns the outcomes, the live-note ring, and the server itself -
/// `date_log` (the `served` count at each DATE) against the final
/// `served` is the only place from which "is this server still being
/// fenced" is observable, since a fence leaves no client-side trace a
/// test can reach.
async fn fence_leg(
    n_articles: usize,
    missing_every: usize,
    chaos: crate::mock::Chaos,
) -> (
    Vec<FetchOutcome>,
    Vec<String>,
    crate::mock::MockServer,
    std::collections::HashSet<String>,
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
    tokio::time::timeout(Duration::from_secs(120), fetch)
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
    (outcomes, notes, srv, absent_out)
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
    let (outcomes, notes, srv, _) = fence_leg(
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
    let (outcomes, notes, srv, absent) = fence_leg(
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
