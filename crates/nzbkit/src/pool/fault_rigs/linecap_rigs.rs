//! The fleet-cap rigs (TODO 208 item 1, TODO 277, TODO 275 item 1):
//! the in-run half of the rule that decides how many sockets a run is
//! allowed to hold.
//!
//! Split off `fault_rigs.rs` when that file crossed its size-gate
//! ceiling adding the §275 item 1 rig (27 Aug 2026, GH #62). The cut is
//! where the file's own subject changes: every leg here drives
//! `Shared::line_cap_tick` and asserts on a `ConnTarget`, where its
//! parent's legs are about two faults landing on one article.
//!
//! Imports are spelled out rather than reached through `use super::*`.
//! A `use` is private, so the parent's glob is not re-exported into
//! this child - `super::super` is `pool`, whose internals a descendant
//! may reach, and the rest are named because they came from the
//! parent's own imports.

use super::super::rig_tests::payout_server;
use super::super::*;
use std::time::Duration;
use tokio::sync::mpsc;

/// TODO 208 item 1: the in-run half of the fleet cap. A fleet spawned
/// at sixteen under a cap of ten sheds to it in ONE step, not the
/// walker's one-per-seven-epochs. The cap is a constant (§208 Rounds A
/// and B), so nothing here is divided out of the line - but the shed
/// still needs the install's link anchor to run at all, which is what
/// this rig gives it and the sibling rig below takes away. Assertions:
/// `connected` falls to at most the cap and stays there, nobody retires
/// (the shed parks; `workers_live` is the fleet), and every article
/// still gets its outcome.
#[tokio::test(flavor = "multi_thread")]
async fn the_line_cap_sheds_a_fleet_to_the_constant_in_one_step() {
    let (srv, ids, want) = line_cap_fixture().await;
    let target = ConnTarget::new(16);
    let (sc, mut cfg) = payout_server(&srv, 16, PoolConfig::default());
    cfg.live_target = Some(target.clone());
    cfg.line_cap_fleet = 10;
    cfg.line_anchor_bps = 2_400_000;
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
    let connected = || live.servers[0].connected.load(Ordering::Relaxed);
    // The pool was handed sixteen - the seed lives in the daemon, not
    // here - and the shed's first tick walks the target to the cap in
    // one step. Then the top slots park behind it.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
    while target.get() > 10 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "target stuck at {}",
            target.get()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    while connected() > 10 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "connected stuck at {} (target {})",
            connected(),
            target.get()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let shed_to = target.get();
    assert!((1..=10).contains(&shed_to), "target {shed_to} is not a cap");
    assert_eq!(
        live.servers[0].budget.load(Ordering::Relaxed),
        shed_to,
        "the dashboard's 'using M of N' did not follow the shed"
    );
    // It stays shed: the cap is a constant, so nothing the smaller
    // fleet then measures can raise it, and a parked slot must not
    // flap back.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        target.get() <= 10 && connected() <= 10,
        "the cap loosened on the shed fleet: target {} connected {}",
        target.get(),
        connected()
    );
    tokio::time::timeout(Duration::from_secs(180), fetch)
        .await
        .expect("run hung across the shed")
        .unwrap();
    assert_eq!(collect.await.unwrap(), want);
}

/// TODO 208 item 1, the regression that bought the anchor requirement
/// (22 Aug 2026, when the cap was still divided out of the measured
/// line). The rig above with the anchor taken away and nothing else
/// changed: sixteen sockets throttled to 150 KB/s EACH, so the fleet
/// moves 2.4 MB/s whatever the line underneath it is. Read as a
/// statement about the line, that was "19 Mbit", the rule made it a
/// cap of ten, and the shed took it - costing 37% of a fleet whose
/// throughput is exactly proportional to its connection count, and
/// costing it unrecoverably, because the peak is monotone and the
/// smaller fleet can never argue its way back up. On the daemon the
/// same shape shed a live job 4 -> 1 and doubled its wall clock
/// (`prefetch_borrows_from_the_busy_server_when_no_healthy_idle`).
///
/// A constant cap cannot make that arithmetic mistake, so what the
/// anchor requirement carries now is the narrower rule it left behind:
/// a run with no independent estimate of its line - a CLI run, or a
/// daemon's first job - is dialled once and never resized mid-flight.
/// The cap here would bite (ten against sixteen) if the gate let it.
#[tokio::test(flavor = "multi_thread")]
async fn the_line_cap_never_sheds_a_fleet_that_has_no_anchor() {
    let (srv, ids, want) = line_cap_fixture().await;
    let target = ConnTarget::new(16);
    let (sc, mut cfg) = payout_server(&srv, 16, PoolConfig::default());
    cfg.live_target = Some(target.clone());
    cfg.line_cap_fleet = 10;
    // No `line_anchor_bps`: the CLI shape, and a daemon's first job.
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
    let connected = || live.servers[0].connected.load(Ordering::Relaxed);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while connected() < 16 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "fleet never dialled"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Well past the ~7 s the gauge needs to train a plateau, and past
    // the 8 s at which the daemon job was shed.
    for _ in 0..24 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            target.get(),
            16,
            "a fleet with no line anchor was resized mid-run (connected {})",
            connected()
        );
    }
    assert_eq!(connected(), 16, "connections parked without a line to cap");
    tokio::time::timeout(Duration::from_secs(180), fetch)
        .await
        .expect("run hung")
        .unwrap();
    assert_eq!(collect.await.unwrap(), want);
}

/// The two line-cap rigs' shared fixture: 36 MB in 50 kB articles from
/// a server that throttles every connection to 150 KB/s, so a fleet of
/// sixteen moves 2.4 MB/s - about 19 Mbit - for roughly 15 s. Returns
/// the server, the requests, and how many outcomes to expect.
async fn line_cap_fixture() -> (crate::mock::MockServer, Vec<ArticleReq>, usize) {
    let data: Vec<u8> = (0..36_000_000u32).map(|i| (i * 7) as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("lc.bin", &data, 50_000, "lc", &mut articles);
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
    (srv, ids, segs.len())
}

/// TODO 208 item 1, the other side of the shed: a run whose rate is
/// set by the CONNECTIONS, not by a line, must not be shed at all.
///
/// Eight sockets throttled to 150 KB/s each read as ~1.2 MB/s, about
/// 9.6 Mbit, and the retired per-Mbit rule made that a cap of five - so
/// it took three sockets off a fleet that would have gone FASTER with
/// more, and nothing downstream could undo it: the gauge's peak is
/// monotone, so the survivors could never read a higher number and the
/// raise-back arm was dead for the rest of the run. That is the shape
/// that doubled the daemon suite's borrow test (24.6 s against
/// ~12.5 s) when the cap first landed, and a `LINE_CAP_FLOOR` of eight
/// was bolted under the rule to bound it.
///
/// The SHIPPED constant is what holds it now, which is why this rig
/// runs at the real default rather than at a number chosen for it: a
/// fleet of eight is under the cap outright, so the shed has no
/// surplus to take and no reading of the line can invent one. The
/// anchor is set, so the shed is armed and this is not passing for the
/// sibling rig's reason. The other half of the same defect - the
/// arithmetic the constant removes - is
/// `the_line_cap_never_sheds_a_fleet_that_has_no_anchor`.
#[tokio::test(flavor = "multi_thread")]
async fn the_line_cap_leaves_a_connection_bound_fleet_alone() {
    let data: Vec<u8> = (0..18_000_000u32).map(|i| (i * 7) as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("lcf.bin", &data, 50_000, "lcf", &mut articles);
    drop(data);
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
    let target = ConnTarget::new(8);
    let (sc, mut cfg) = payout_server(&srv, 8, PoolConfig::default());
    cfg.live_target = Some(target.clone());
    cfg.line_cap_fleet = linecap::LINE_CAP_DEFAULT_FLEET;
    // An anchor, so the shed is ARMED and it is the cap and not the
    // gate that this rig measures. Under the old rule 9.6 Mbit at
    // 0.5/Mbit was five, and five would have shed this fleet.
    cfg.line_anchor_bps = 1_200_000;
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
    let connected = || live.servers[0].connected.load(Ordering::Relaxed);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while connected() < 8 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "fleet never dialled"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Well past the gauge's ~7 s training point and several shed ticks
    // in: the shed HAS run by now and had nothing to take.
    tokio::time::sleep(Duration::from_secs(12)).await;
    assert!(
        live.servers[0].bytes.load(Ordering::Relaxed) > 0,
        "nothing was delivered, so the gauge never read a line at all"
    );
    assert!(
        connected() == 8 && target.get() == 8,
        "a connection-bound fleet was shed: target {} connected {}",
        target.get(),
        connected()
    );
    tokio::time::timeout(Duration::from_secs(300), fetch)
        .await
        .expect("run hung")
        .unwrap();
    assert_eq!(collect.await.unwrap(), segs.len());
}

/// TODO 277: the in-run GOVERNOR, which is the half of the fleet curve
/// that runs after the seed has already dialled.
///
/// The seed sizes the fleet from whatever line reading the process had
/// at job build, and on a run that had none - a CLI `get`, a daemon's
/// first job - that is the curve's floor. This rig is the case where
/// the run then learns better: a fleet dialled small against a line the
/// evidence says is multi-gig, with the cap left on `auto` because
/// nobody typed `NZBFAST_LINE_CAP`. The governor must raise the cap and
/// the walk must hand the new share to the target, waking the parked
/// slots.
///
/// It drives the governor from the ANCHOR rather than from the trained
/// peak on purpose: they are the same input to `fleet_step` (the tick
/// takes the larger of the two, both being achieved rates and so lower
/// bounds on the line), and the anchor is available at the first tick
/// where a trained peak needs ~7 s of plateau first - so this rig
/// measures the rule and not the gauge's warm-up, which
/// `the_stall_bound_survives_the_gauges_warm_up` already owns.
///
/// The numbers are synthetic - a real 9 Gbps anchor would have seeded
/// the fleet at the knee and left nothing to raise - because what is
/// under test is the wiring: that `line_cap_auto` reaches the tick,
/// that the raise is not behind the shed's anchor gate, and that a
/// target sitting on the seed's own share is one the governor may move
/// UP. The ceiling still binds: the fleet only ever reaches the eight
/// slots that were spawned, which is the limit the module doc sets out.
#[tokio::test(flavor = "multi_thread")]
async fn the_line_cap_raises_a_fleet_when_the_line_reads_faster_than_it() {
    let data: Vec<u8> = (0..12_000_000u32).map(|i| (i * 11) as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("lcr.bin", &data, 50_000, "lcr", &mut articles);
    drop(data);
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
    // Eight slots spawned, four of them admitted: the shape the seed
    // leaves behind whenever the cap cut the dial.
    let target = ConnTarget::new(4);
    let (sc, mut cfg) = payout_server(&srv, 8, PoolConfig::default());
    cfg.live_target = Some(target.clone());
    cfg.line_cap_fleet = 4;
    cfg.line_cap_auto = true;
    // ~9 Gbps, the line the 24 Aug mummy round measured and the one the
    // curve answers with its ceiling.
    cfg.line_anchor_bps = 1_125_000_000;
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
    // Three agreeing ticks at one a second, plus the dial and the first
    // deliveries that drive the fold at all.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while target.get() < 8 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the governor never raised the fleet: target {}",
            target.get()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(target.get(), 8, "raised past the slots that were spawned");
    tokio::time::timeout(Duration::from_secs(300), fetch)
        .await
        .expect("run hung")
        .unwrap();
    assert_eq!(collect.await.unwrap(), segs.len());
}

/// TODO 275 item 1 (GH #62): the governor's OTHER raise, the one the
/// curve alone could never make. Here the line reading is modest - a
/// 1 Gbit line, which the curve answers with its floor - so
/// `fleet_for_line` asks for nothing at every tick. What is wrong is
/// the SOCKETS: throttled far under the carry the curve plans for, so
/// the fleet sits at its cap moving a fraction of a line it has been
/// told carries a gigabit.
///
/// That is the shape a user reported on 27 Aug 2026 (five servers on a
/// 1 Gbit line against AU-routed providers, 5 connections each of an
/// allowed 50) and the shape §275 watched on a giganews-only box. Its
/// defining property is that the OLD rule was stuck by construction,
/// not by timing: below 3.75 Gbit `fleet_for_line` returns the floor,
/// so `want <= fleet` on every tick for ever, however long the run.
///
/// The rig is the sibling of
/// `the_line_cap_raises_a_fleet_when_the_line_reads_faster_than_it` and
/// differs from it in exactly one way, deliberately: there the ANCHOR
/// is what asks for more sockets, here the anchor asks for nothing and
/// the measured CARRY is what asks. So a regression that removed the
/// supply arm leaves that rig green and reddens this one.
///
/// The cap starts at the curve's own floor rather than at some smaller
/// number, because that is what isolates the arm: at any cap below 25
/// the curve would raise it on its own and the assertion would pass
/// without the new rule existing.
#[tokio::test(flavor = "multi_thread")]
async fn the_line_cap_raises_a_fleet_whose_sockets_cannot_fill_a_modest_line() {
    let data: Vec<u8> = (0..12_000_000u32).map(|i| (i * 7) as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("lcs.bin", &data, 50_000, "lcs", &mut articles);
    drop(data);
    let ids: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    // 40 KB/s a socket: ~0.3 Mbit, which is the far end of the regime
    // this arm is for and keeps the run long enough for three agreeing
    // ticks without a large fixture.
    let srv = crate::mock::MockServer::start(
        articles,
        crate::mock::Chaos {
            throttle: crate::mock::Throttle {
                per_conn_bps: 40_000,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    let cap = crate::pool::linecap::LINE_CAP_DEFAULT_FLEET;
    let spawned = cap + 3;
    let target = ConnTarget::new(cap);
    let (sc, mut cfg) = payout_server(&srv, spawned, PoolConfig::default());
    cfg.live_target = Some(target.clone());
    cfg.line_cap_fleet = cap;
    cfg.line_cap_auto = true;
    // 1 Gbit. The curve returns its floor for this and never moves.
    cfg.line_anchor_bps = 125_000_000;
    assert_eq!(
        crate::pool::linecap::fleet_for_line(cfg.line_anchor_bps),
        cap,
        "the rig is only meaningful while the curve asks for nothing here"
    );
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
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while target.get() <= cap {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the supply arm never raised the fleet: target {} still at the cap {cap}",
            target.get()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        target.get(),
        spawned,
        "raised to the slots that were spawned and no further"
    );
    tokio::time::timeout(Duration::from_secs(300), fetch)
        .await
        .expect("run hung")
        .unwrap();
    assert_eq!(collect.await.unwrap(), segs.len());
}
