//! The fleet-cap rigs (TODO 208 item 1, TODO 277, TODO 275 items 1 and
//! 7): the in-run half of the rule that decides how many sockets a run
//! is allowed to hold.
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

/// TODO 275 item 7: how many connections the one provider in the
/// second-ceiling pair below sells. It is both the account's grant
/// (`PoolConfig::line_cap_uncapped`, what `linecap::supply_ceiling`
/// bounds itself by) and the slots the seed spawns, which is what those
/// two are on a real fleet - `get::fleet::cap_exposed` stamps the grant
/// and `conntune::line_cap_spawn_slots` holds the spawn to it.
///
/// Five past [`linecap::LINE_CAP_MAX_FLEET`] and no further,
/// deliberately. The pair has to put sockets on the wire ABOVE the
/// first ceiling, and every socket past the first one that does buys
/// nothing and costs the fixture both wall clock and memory. This is
/// the smallest fleet that can say what the pair is for.
const SECOND_CEILING_GRANT: usize = linecap::LINE_CAP_MAX_FLEET + 5;

/// The line the second-ceiling pair is told it has: 1 Gbit, the rate
/// GH #62 reported on and the one [`linecap::fleet_for_line`] answers
/// with its FLOOR - so the curve arm asks for nothing at every tick and
/// only the supply arm can move this fleet.
const SECOND_CEILING_ANCHOR_BPS: u64 = 125_000_000;

/// How long the control below watches a fleet that must not grow, and
/// the bound the measured twin's raise has to come in under. One
/// constant rather than two numbers, because the pair only says
/// anything while the window covers the raise: a control that stopped
/// looking before its twin moved would be green for the wrong reason.
///
/// The twin raises at 10.37-10.39 s over three runs, so this is about
/// twice the margin it needs, and the timing is rate-driven rather than
/// CPU-driven - the fixture's throttle sets it - so a loaded box moves
/// it very little. The room above it is the run itself: the control
/// spends about 28 s on this fixture, and a watch past that would be
/// looking at a finished pool.
const SECOND_CEILING_WATCH: Duration = Duration::from_secs(20);

/// TODO 275 item 7: the SECOND fleet ceiling, through a real pool
/// against a real server - CONNECTED sessions past
/// [`linecap::LINE_CAP_MAX_FLEET`], not a governor that decided they
/// should be.
///
/// The distinction is the whole reason this rig exists rather than the
/// arithmetic that already covers the decision
/// (`only_a_measured_anchor_puts_the_extra_sockets_on_the_wire`, which
/// drives `Shared::line_cap_tick` with a synthetic gauge). TODO 277 is
/// the record of what a cap can be worth on its own: a `ConnTarget`
/// raised above the SPAWNED fleet wakes nothing, so a cap that grows
/// buys exactly zero connections while every gauge says it grew. The
/// second ceiling widened the seed's spawn headroom to match
/// (`conntune::line_cap_headroom_fleet` returns
/// `LINE_CAP_SUPPLY_MAX_FLEET` for an automatic cap on a measured
/// anchor), and a rig is the only thing that can catch that widening
/// being wrong.
///
/// The shape is `the_line_cap_raises_a_fleet_whose_sockets_cannot_fill_a_modest_line`
/// one ceiling up, and it differs from that rig in exactly two numbers:
/// the cap starts at the first ceiling rather than at the curve's
/// floor, and the anchor is MEASURED. Neither is decoration - at any
/// cap below 50 this would pass without the second ceiling existing,
/// and with a typed anchor `supply_ceiling` hands back 50 and the
/// clamp holds the fleet exactly where it started, which is what the
/// control asserts.
#[tokio::test(flavor = "multi_thread")]
async fn a_measured_anchor_puts_sockets_past_the_first_ceiling_on_the_wire() {
    // The rig is only meaningful while the second ceiling is what the
    // extra sockets come from: a measured anchor may reach the whole of
    // this account's grant, and everything below asserts on sockets
    // past the first ceiling.
    assert_eq!(
        linecap::supply_ceiling(true, SECOND_CEILING_GRANT),
        SECOND_CEILING_GRANT,
        "a measured anchor must be able to reach the whole grant here"
    );
    let (srv, ids, want) = second_ceiling_fixture().await;
    let (servers, live, target) = second_ceiling_fleet(&srv, true);
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
    let started = tokio::time::Instant::now();
    let deadline = started + Duration::from_secs(90);
    let mut peak = 0usize;
    loop {
        peak = peak.max(connected());
        if peak > linecap::LINE_CAP_MAX_FLEET {
            break;
        }
        // A finished run is a verdict and not a timeout: the fixture is
        // sized so the raise lands with most of the job still to go, so
        // there is nothing to wait for once the last article lands and
        // a rig that spun to its deadline anyway would report a hang.
        assert!(
            !fetch.is_finished(),
            "the run finished with the fleet never past the first ceiling: \
             {peak} sockets connected at most, target {}",
            target.get()
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "the second ceiling never reached the wire: {peak} sockets connected, target {}",
            target.get()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let raised_at = started.elapsed();
    assert_eq!(
        target.get(),
        SECOND_CEILING_GRANT,
        "raised to the slots that were spawned and no further"
    );
    // The pair's own separability, made mechanical rather than argued:
    // the control watches for exactly this long, so a raise that landed
    // after it would leave that rig green with nothing to say.
    assert!(
        raised_at < SECOND_CEILING_WATCH,
        "the raise took {raised_at:?}, which is past the window the control watches"
    );
    tokio::time::timeout(Duration::from_secs(300), fetch)
        .await
        .expect("run hung past the raise")
        .unwrap();
    assert_eq!(collect.await.unwrap(), want);
}

/// TODO 275 item 7, the control: the rig above with the anchor's
/// PROVENANCE taken away and nothing else changed at all - same line,
/// same carry, same grant, same spawned slots, same seed cap. It must
/// stop at [`linecap::LINE_CAP_MAX_FLEET`], which is the ceiling every
/// install a TODO 208 round measured keeps.
///
/// That is the safety case rather than a tidiness one.
/// `fleet_for_supply`'s fourth property - the worst a wrong line
/// reading can do is put the fleet on a rung §208 Round A measured as
/// free at 99 Mbit - is what licenses running the arm on a number
/// somebody typed into Settings, and it stops being true the moment the
/// ceiling moves. So an install that typed 10 Gbps on a 100 Mbit line
/// holds the supply gate open for ever and must still reach only 50.
///
/// The five slots above the cap are spawned here too, on purpose. A
/// control that spawned only what it runs would be green for TODO 277's
/// reason instead of this one - there would be nothing to wake whatever
/// the ceiling said - and the pair would no longer differ in one thing.
#[tokio::test(flavor = "multi_thread")]
async fn a_typed_anchor_stops_at_the_first_ceiling_on_the_wire() {
    // The control's own guard, and the mirror of its twin's: a typed
    // anchor's ceiling is the first one, whatever this account grants.
    assert_eq!(
        linecap::supply_ceiling(false, SECOND_CEILING_GRANT),
        linecap::LINE_CAP_MAX_FLEET,
        "a typed anchor reached past the first ceiling in arithmetic alone"
    );
    let (srv, ids, want) = second_ceiling_fixture().await;
    let (servers, live, target) = second_ceiling_fleet(&srv, false);
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
    let cap = linecap::LINE_CAP_MAX_FLEET;
    let started = tokio::time::Instant::now();
    // Watched for the whole window the twin's raise lands inside, and
    // then some: every poll is an assertion, so a cap that grew for one
    // tick and came back is a failure too.
    while started.elapsed() < SECOND_CEILING_WATCH {
        assert!(
            target.get() <= cap,
            "a typed anchor walked the fleet past the first ceiling: target {}",
            target.get()
        );
        assert!(
            connected() <= cap,
            "a typed anchor put {} sockets on the wire",
            connected()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // And it was a fleet doing work while being watched, not an idle
    // one: a run that delivered nothing has no supply reading to raise
    // on and would pass this whatever the ceiling said.
    assert!(
        live.servers[0].bytes.load(Ordering::Relaxed) > 0,
        "nothing was delivered, so the governor never had a reading at all"
    );
    assert_eq!(
        target.get(),
        cap,
        "the fleet did not hold the first ceiling it was seeded at"
    );
    tokio::time::timeout(Duration::from_secs(300), fetch)
        .await
        .expect("run hung")
        .unwrap();
    assert_eq!(collect.await.unwrap(), want);
}

/// TODO 275 item 7, the stand-down rig's ghost-capacity window, in ms.
///
/// For this long from the mock's start EVERY accept is refused for
/// capacity, so the seed's whole fleet bounces, the pool latches
/// `AuthState::capacity_refused`, and then the account serves normally
/// and the fleet rejoins at full width. Issue #16's restart shape: the
/// provider is still counting a dead process's sessions, and there is
/// nothing the client can shed.
///
/// **A TRANSIENT refusal, and that is the point rather than a
/// convenience.** The latch it sets is not transient - the arm asks
/// whether this account has said no AT ANY POINT, deliberately, so that
/// one granted session cannot let the fleet climb straight back into
/// the refusal it just took - and this is the shape that separates the
/// two. It also leaves the fleet UNIMPEDED afterwards, which a standing
/// account cap does not: written first with `accept_cap` one under the
/// fleet, the account refused a dial for the whole run, the stated-cap
/// dial gate stayed armed on it, and under a parallel sweep of this
/// module the ramp never got past 17 of its 50 sockets. Here the wire
/// carries the full 50, which is a better statement of the same rule.
///
/// Two seconds and not the 1.5 s of
/// `provider_fault_rigs::cap_ghost_window_parks_the_fleet_then_rejoins`:
/// the window is measured from the mock's start and has to cover this
/// rig building a 55-worker fleet and spawning it, which is fast but is
/// not free on a box running the whole module at once.
const REFUSAL_GHOST_MS: u64 = 2_000;

/// TODO 275 item 7, the non-shrink rig's account: it sells 70
/// connections, so the governor's ceiling is the grant and the climb
/// from 50 is twenty sockets wide.
///
/// **Wider than [`SECOND_CEILING_GRANT`] on purpose, and this is the
/// one number in the pair worth reading before changing it.** The
/// ordering that rig needs is the mirror of its sibling's - the fleet
/// must be holding sockets ABOVE the first ceiling at the moment the
/// account refuses one - and the room between the ceiling and the
/// account's cap is what has to survive an ordinary run's reconnect
/// overlap. Written first at the shared grant of 55, it had three
/// sockets of room, and under a parallel sweep of this module that was
/// not enough: a redial landing while an old session was still counted
/// pushed the mock over its accept cap with the fleet still at 50, the
/// stated-cap dial gate armed on that refusal, and the slots above the
/// ceiling were then serialised into an account that had no room for
/// them - so the rig timed out having never put a socket past 50.
/// Twenty sockets of climb and eight of headroom under the cap absorb
/// that.
const REFUSAL_HOLD_GRANT: usize = 70;

/// TODO 275 item 7, the non-shrink rig's second number: the account
/// serves 62 of the 70 it sells before it starts refusing.
///
/// Twelve past the first ceiling, so the fleet is unambiguously above
/// it when the refusal lands, and eight under the grant, so the
/// governor's climb reaches for sockets this account will not give -
/// which is what produces the refusal at all. Both margins are what
/// the constant above exists to buy.
const REFUSAL_AFTER_CLIMB_ACCEPT_CAP: u64 = 62;

/// How long the non-shrink rig watches after the refusal has landed.
///
/// Five ticks of the governor (`LINE_CAP_TICK_MS` is a second), which
/// is past the three agreeing ticks any move of its needs, and a shrink
/// would land on the first of them. It fits the runway: the raise lands
/// at ~10 s, a fleet of 62 clears the rest of this fixture in about
/// 13 s, and five leaves margin at both ends of that.
const REFUSAL_HOLD_WATCH: Duration = Duration::from_secs(5);

/// TODO 275 item 7, the acceptance arm nothing outside one unit test
/// has ever run: a provider that has REFUSED this fleet for capacity
/// takes the second ceiling back off the table, through a real pool
/// against a server saying it in its own words.
///
/// `linecap::tests::a_capacity_refusal_stands_the_second_ceiling_down`
/// is the decision half and it is a good test, but it notes the refusal
/// by calling `AuthState::note` on a fleet whose rate comes from a
/// synthetic gauge - nothing dials, nothing is refused, and no socket
/// exists. This is the arm the residue handoff calls the one most
/// likely to fire in practice and least likely to be right by luck, and
/// the bench leg that ran the second ceiling on a real provider on
/// 2 Sep 2026 produced zero 481s across ten legs, so it did not
/// exercise it either.
///
/// The fleet is the measured twin's, unchanged, with ONE `Chaos` field
/// set: [`REFUSAL_GHOST_MS`] of ghost capacity at the front of the run,
/// so the seed's whole fleet bounces off the account before a byte
/// moves and then the account serves normally. Everything else - the
/// line, the carry, the grant, the spawned slots, the seed cap, the
/// measured anchor - is what
/// `a_measured_anchor_puts_sockets_past_the_first_ceiling_on_the_wire`
/// runs, and that rig IS this one's control: same numbers, no refusal,
/// and it walks to 55 in ~10.4 s. So the watch here is the window that
/// rig bounds its own raise against, and a fleet still at 50 when it
/// ends is a fleet the refusal held.
///
/// **The watch starts when the fleet is UP, not when the run is
/// spawned**, which is what makes it comparable to the twin's. The
/// ghost window and the rejoin behind it are time this fleet spends
/// delivering nothing, and the governor has no reading to raise on
/// until they are over - a watch begun at t=0 would spend its first
/// seconds looking at a pool that could not have raised whatever the
/// ceiling said.
///
/// The wire evidence is what the unit test cannot have. The refusal is
/// a real greeting from a real socket, classified by the shipped
/// `classify_auth_refusal`; the fleet under watch is 50 ESTABLISHED
/// sessions and not a gauge that says 50; and the target it holds is
/// the one workers actually park behind.
#[tokio::test(flavor = "multi_thread")]
async fn a_capacity_refusal_stands_the_second_ceiling_down_on_the_wire() {
    // The rig's own guard, and the reason it is not vacuous: without
    // the refusal this fleet is allowed the whole grant, which is past
    // the ceiling everything below asserts it holds.
    assert_eq!(
        linecap::supply_ceiling(true, SECOND_CEILING_GRANT),
        SECOND_CEILING_GRANT,
        "a measured anchor must be able to reach past the first ceiling here"
    );
    assert!(
        SECOND_CEILING_GRANT > linecap::LINE_CAP_MAX_FLEET,
        "the grant must be past the first ceiling or there is nothing to stand down"
    );
    let (srv, ids, want) = second_ceiling_fixture_refusing(None, REFUSAL_GHOST_MS).await;
    let (servers, live, target) = second_ceiling_fleet(&srv, true);
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
    // The pool's own record of the refusal, in the provider's words.
    // Written by the refusal handler for BOTH kinds, so the arm this
    // rig is about - which reads "has this account said no", not which
    // sentence it said it in - is asked the same question here: a
    // refusal is present and it is not the permanent one.
    //
    // SAMPLED across the window rather than read once at the end, and
    // that is the gauge's design rather than a weakness of the rig:
    // `session` clears this the moment a session is granted, because a
    // provider that is serving must not read as refusing on the
    // Providers card. What the ceiling arm reads is
    // `AuthState::capacity_refused`, a latch that is never cleared and
    // that a rig cannot reach from outside the pool - so this samples
    // the visible half of the same event, which is present for the
    // whole ghost window and therefore for tens of polls.
    let capacity_refusal = || {
        live.servers[0]
            .refusal
            .lock_ok()
            .as_ref()
            .is_some_and(|r| !r.permanent)
    };
    let mut saw_refusal = false;
    let cap = linecap::LINE_CAP_MAX_FLEET;
    // Wait out the ghost window and the rejoin behind it. A finished
    // run is a verdict rather than a timeout, as in the twin.
    let up_deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    while connected() < cap {
        saw_refusal |= capacity_refusal();
        assert!(
            !fetch.is_finished(),
            "the run finished before the fleet rejoined: {} connected, target {}",
            connected(),
            target.get()
        );
        assert!(
            tokio::time::Instant::now() < up_deadline,
            "the fleet never rejoined after the ghost window: {} connected, target {}",
            connected(),
            target.get()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    // The account said no while that was happening, and said it for
    // capacity. Checked BEFORE the watch: a rig whose window closed
    // with nothing ever refused would be the twin with a slow start.
    assert!(
        saw_refusal,
        "the provider never refused this fleet for capacity, so the stand-down never ran"
    );
    // Watched for the whole window the twin's raise lands inside, and
    // every poll is an assertion, so a ceiling that lifted for one tick
    // and came back is a failure too.
    let watch_from = tokio::time::Instant::now();
    while watch_from.elapsed() < SECOND_CEILING_WATCH {
        assert!(
            target.get() <= cap,
            "a refused fleet walked past the first ceiling: target {}",
            target.get()
        );
        assert!(
            connected() <= cap,
            "a refused fleet put {} sockets on the wire",
            connected()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // And it was a fleet doing work for the whole watch, not one that
    // finished under it: a run with nothing left to fetch has no supply
    // reading to raise on and would pass this whatever the ceiling said.
    assert!(
        !fetch.is_finished(),
        "the run finished inside the watch, so the last of it proved nothing"
    );
    assert!(
        live.servers[0].bytes.load(Ordering::Relaxed) > 0,
        "nothing was delivered, so the governor never had a reading at all"
    );
    assert_eq!(
        target.get(),
        cap,
        "the fleet did not hold the first ceiling it was seeded at"
    );
    // TODO 275 item 7, the residue handoff's OWED 4: the stand-down
    // reached a SURFACE, on the shape that leaves no other trace.
    //
    // The refusal this rig arms is `cap_ghost_ms`, which greets with
    // `502 max number of simultaneous IP addresses reached` - the
    // source-address shape. `ServerLive::note_cap` is skipped for it on
    // purpose (Codex sweep 5, M9), `ServerLive::refusal` was cleared the
    // moment the account started serving again, and the latch the
    // ceiling arm reads is private to the pool. So before OWED 4 this
    // fleet spent the rest of its run pinned at the first ceiling with
    // nothing anywhere that a user, a log or `whyslow` could read. The
    // two gauges below are that record, and they are checked here
    // rather than in the unit test because only a real socket can
    // produce this shape at all.
    assert_eq!(
        live.line_cap_ceiling.load(Ordering::Relaxed),
        cap,
        "the gauge whyslow reads still offers a ceiling the governor took away"
    );
    assert!(
        live.line_cap_refused.load(Ordering::Relaxed),
        "a source-address capacity refusal left no durable record of itself"
    );
    tokio::time::timeout(Duration::from_secs(300), fetch)
        .await
        .expect("run hung")
        .unwrap();
    assert_eq!(collect.await.unwrap(), want);
}

/// TODO 275 item 7, the half of the stand-down that NOTHING has ever
/// checked: it stops the climb and it does not take back the fleet it
/// already handed out.
///
/// That distinction is a decision and not an accident. The cap never
/// falls within a run - a reading is an achieved rate and so a lower
/// bound on the line, which makes it evidence for growing and none at
/// all for shrinking - and a ceiling that could shrink a fleet would
/// let one refusal from one server oscillate the whole fleet for the
/// rest of the job. In the code it is one token: `fleet_for_supply`
/// clamps into `ceiling.max(fleet)`, so a fleet already above the
/// ceiling reads as NO OPINION and gets its own number back.
///
/// It is unreachable from the sibling rig above and from the unit test,
/// for the same reason in both: there the refusal lands before the
/// climb, so the ceiling and the fleet are the same number and a
/// stand-down and a shrink do exactly the same thing. Here the order is
/// reversed. The account sells [`REFUSAL_HOLD_GRANT`] connections and
/// serves [`REFUSAL_AFTER_CLIMB_ACCEPT_CAP`] of them, so the seed of 50
/// comes up untouched, the governor walks the whole grant, twelve of
/// the twenty woken slots get onto the wire above the first ceiling,
/// the next is refused, and only THEN does the ceiling stand down - onto
/// a fleet that is already above it.
///
/// The shrink it rules out is a SOCKET one and not a gauge one. Under a
/// stand-down that clawed the cap back to
/// [`linecap::LINE_CAP_MAX_FLEET`] the target falls with it, and every
/// socket past the first ceiling is shed off the wire by the same
/// machinery `the_line_cap_sheds_a_fleet_to_the_constant_in_one_step`
/// measures - which is why this watches `connected` and not only the
/// cap.
#[tokio::test(flavor = "multi_thread")]
async fn a_capacity_refusal_never_shrinks_the_fleet_already_on_the_wire() {
    // This rig's own guard, and deliberately not its sibling's: the
    // fleet has to be able to get ABOVE the first ceiling before the
    // refusal, or there is no fleet above a ceiling to not shrink.
    // Kept here rather than shared, per this file's own rule - a shared
    // guard reddens a rig on a mutation to a rule it does not test.
    assert!(
        REFUSAL_AFTER_CLIMB_ACCEPT_CAP as usize > linecap::LINE_CAP_MAX_FLEET,
        "the account must grant sockets past the first ceiling"
    );
    assert!(
        (REFUSAL_AFTER_CLIMB_ACCEPT_CAP as usize) < REFUSAL_HOLD_GRANT,
        "and it must refuse before the fleet reaches the grant, or nothing is refused"
    );
    assert_eq!(
        linecap::supply_ceiling(true, REFUSAL_HOLD_GRANT),
        REFUSAL_HOLD_GRANT,
        "the climb must be allowed the whole grant, or it never gets above the first ceiling"
    );
    let (srv, ids, want) =
        second_ceiling_fixture_refusing(Some(REFUSAL_AFTER_CLIMB_ACCEPT_CAP), 0).await;
    let (servers, live, target) = second_ceiling_fleet_granting(&srv, true, REFUSAL_HOLD_GRANT);
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
    let refused = || live.servers[0].granted_hi.load(Ordering::Relaxed) > 0;
    let cap = linecap::LINE_CAP_MAX_FLEET;
    let granted = REFUSAL_AFTER_CLIMB_ACCEPT_CAP as usize;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    // Both halves of the precondition, and neither alone is it: sockets
    // past the first ceiling AND the account having refused the next
    // one. Tracked as a peak rather than tested at one instant, because
    // the two do not have to be true in the same 50 ms - the woken
    // slots connect and the refused one bounces within a tick of each
    // other, in an order the scheduler picks. A finished run is a
    // verdict rather than a timeout, exactly as in the twin: the
    // fixture is sized so the raise lands with most of the job to go.
    let mut peak = 0usize;
    while !(peak > cap && refused()) {
        peak = peak.max(connected());
        assert!(
            !fetch.is_finished(),
            "the run finished before the refusal landed on a fleet past the first ceiling: \
             {peak} sockets connected at most, target {}, refused {}",
            target.get(),
            refused()
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "the refusal never landed on a fleet past the first ceiling: \
             {peak} sockets connected at most, target {}, refused {}",
            target.get(),
            refused()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let held = target.get();
    assert_eq!(
        held, REFUSAL_HOLD_GRANT,
        "the governor was not at the grant when the refusal landed, so what follows \
         would be watching a climb rather than a stand-down"
    );
    // The watch. Every poll is an assertion in both directions: the cap
    // the governor already handed out is never taken back, and the
    // sockets it bought never leave the wire.
    let watch_from = tokio::time::Instant::now();
    while watch_from.elapsed() < REFUSAL_HOLD_WATCH {
        assert!(
            target.get() >= held,
            "a capacity refusal shrank a fleet the governor had already handed out: \
             target {} against {held}",
            target.get()
        );
        assert!(
            connected() > cap,
            "a capacity refusal took sockets back off the wire: {} connected",
            connected()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // And the fleet the governor handed out is all still there at the
    // end of the watch, not merely at every poll inside it.
    assert_eq!(
        target.get(),
        REFUSAL_HOLD_GRANT,
        "the governor gave back slots it had already handed out"
    );
    // And the refusal this rig turns on was a CONNECTION-capacity one
    // taken above the first ceiling, which is what makes the ceiling
    // the thing that stood down. `granted_hi` is the provider's own
    // accounting - the sessions held when it refused a dial - so a
    // reading past 50 is the account confirming, on the wire, that it
    // served more than the first ceiling and then said no.
    let seen = live.servers[0].granted_hi.load(Ordering::Relaxed);
    assert!(
        seen > cap && seen <= granted,
        "the pool recorded a ceiling of {seen}, which is not the {granted} this account serves"
    );
    // TODO 275 item 7, the residue handoff's OWED 4, and this is the
    // sharpest place in the suite to say it: the published CEILING fell
    // and the published CAP did not. They are two different quantities
    // and the gauge is the first one, which is what lets a surface ask
    // "can this cap still rise?" of a fleet sitting well above the
    // first ceiling. The sibling rig cannot separate them - there the
    // refusal lands before the climb, so both numbers are 50.
    assert_eq!(
        live.line_cap_ceiling.load(Ordering::Relaxed),
        cap,
        "the ceiling gauge followed the cap instead of the stand-down"
    );
    assert!(
        live.line_cap_refused.load(Ordering::Relaxed),
        "the account refused this fleet and nothing published that it had"
    );
    assert_eq!(
        live.line_cap_fleet.load(Ordering::Relaxed),
        REFUSAL_HOLD_GRANT,
        "the cap gauge moved with the ceiling, which would be the shrink this rig rules out"
    );
    tokio::time::timeout(Duration::from_secs(300), fetch)
        .await
        .expect("run hung past the refusal")
        .unwrap();
    assert_eq!(collect.await.unwrap(), want);
}

/// The second-ceiling pair's shared fixture: 26 MB in 50 kB articles
/// from a server that throttles every connection to 20 KB/s. Returns
/// the server, the requests, and how many outcomes to expect.
///
/// The throttle is what holds the supply gate open for the whole run,
/// and both of its arms want it low: 20 KB/s a socket is far under
/// `LINE_CAP_SOCKET_BPS`, so the plan is provably not holding, and a
/// fleet at the first ceiling moves 1 MB/s against a line it has been
/// told carries 125 - about 1% of it, where the gate shuts at 75%.
/// It also sizes the fixture. A fleet of 50 at this rate spends about
/// 26 s on this much data, which is enough run for the governor's three
/// agreeing ticks several times over and for the control's whole watch,
/// at a fixture the two rigs can afford to build twice.
async fn second_ceiling_fixture() -> (crate::mock::MockServer, Vec<ArticleReq>, usize) {
    second_ceiling_fixture_refusing(None, 0).await
}

/// [`second_ceiling_fixture`] with one of the mock's two capacity
/// refusals armed, which is all that separates the refusal pair below
/// from the measured/typed pair above.
///
/// `(None, 0)` is byte-for-byte the fixture that pair runs on, which is
/// the whole reason these are parameters rather than a second fixture
/// beside it: each refusal rig is that pair's fixture with ONE `Chaos`
/// field set, so the landed twins are usable as controls without an
/// argument about what else differs.
///
/// * `accept_cap` - the provider serves this many CONCURRENT sessions
///   and greets the next accept `502 max connections reached: N`. The
///   refusal is triggered by the fleet's own dialling rather than by a
///   clock, so there is no window for a loaded box to race, and it is
///   permanent for the run: this account will never serve more.
/// * `cap_ghost_ms` - for this long from the server's start EVERY
///   accept is refused for capacity and then the account serves
///   normally. Issue #16's restart shape, where the provider is still
///   counting a dead process's sessions. The refusal is transient, and
///   the pool's own latch is not: `AuthState::capacity_refused` asks
///   whether this account has said no AT ANY POINT, which is the
///   property the stand-down is built on.
///
/// Neither is new and neither is `Chaos::auth_rejected`, which is the
/// lever a reader reaches for first and is the wrong one for all of
/// this: it refuses EVERY authentication, so no fleet ever comes up and
/// the ceiling arm never has a fleet to stand down.
async fn second_ceiling_fixture_refusing(
    accept_cap: Option<u64>,
    cap_ghost_ms: u64,
) -> (crate::mock::MockServer, Vec<ArticleReq>, usize) {
    let data: Vec<u8> = (0..26_000_000u32).map(|i| (i * 13) as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("lc2.bin", &data, 50_000, "lc2", &mut articles);
    drop(data);
    let ids: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    let srv = crate::mock::MockServer::start(
        articles,
        crate::mock::Chaos {
            throttle: crate::mock::Throttle {
                per_conn_bps: 20_000,
                ..Default::default()
            },
            accept_cap,
            cap_ghost_ms,
            ..Default::default()
        },
    )
    .await;
    (srv, ids, segs.len())
}

/// The second-ceiling pair's shared fleet, so that `measured` is
/// provably the only thing between the two rigs. One provider granting
/// [`SECOND_CEILING_GRANT`] connections, all of them spawned, admitted
/// at a seed cap of [`linecap::LINE_CAP_MAX_FLEET`] with the surplus
/// parked - the shape the seed leaves whenever the governor is allowed
/// to walk further than the job opened.
///
/// The one guard it carries is the one both arms need: the curve must
/// have NO opinion at this line, or `fleet_for_line` and not the supply
/// arm is what any raise here would be. Each rig's own guard about the
/// CEILING stays in that rig, deliberately - a shared one would redden
/// the control on a mutation to a rule the control does not test, which
/// is exactly the coupling the pair exists to rule out.
fn second_ceiling_fleet(
    srv: &crate::mock::MockServer,
    measured: bool,
) -> (
    Vec<(ServerConfig, PoolConfig)>,
    std::sync::Arc<LiveStats>,
    std::sync::Arc<ConnTarget>,
) {
    second_ceiling_fleet_granting(srv, measured, SECOND_CEILING_GRANT)
}

/// [`second_ceiling_fleet`] with the account's grant as an argument -
/// both the connections the provider sells and the slots the seed
/// spawns, which is what those two are on a real fleet.
///
/// The parameter exists for the non-shrink rig alone, and its own doc
/// carries why it needs a wider account than
/// [`SECOND_CEILING_GRANT`]. Every other caller passes that constant
/// and gets exactly the fleet it always got.
fn second_ceiling_fleet_granting(
    srv: &crate::mock::MockServer,
    measured: bool,
    grant: usize,
) -> (
    Vec<(ServerConfig, PoolConfig)>,
    std::sync::Arc<LiveStats>,
    std::sync::Arc<ConnTarget>,
) {
    let cap = linecap::LINE_CAP_MAX_FLEET;
    assert_eq!(
        linecap::fleet_for_line(SECOND_CEILING_ANCHOR_BPS),
        linecap::LINE_CAP_DEFAULT_FLEET,
        "the curve must ask for nothing at this line, or it and not the supply arm is the raise"
    );
    let target = ConnTarget::new(cap);
    let (sc, mut cfg) = payout_server(srv, grant, PoolConfig::default());
    cfg.live_target = Some(target.clone());
    cfg.line_cap_fleet = cap;
    cfg.line_cap_auto = true;
    cfg.line_anchor_bps = SECOND_CEILING_ANCHOR_BPS;
    cfg.line_anchor_measured = measured;
    // What this server would dial with the cap taking nothing out,
    // exactly as a fleet build stamps it. `supply_ceiling` bounds
    // itself by the sum of these, so a fleet can never ask a provider
    // for more sockets than it sells.
    cfg.line_cap_uncapped = grant;
    let servers = vec![(sc, cfg)];
    let live = LiveStats::for_servers(&servers);
    let servers: Vec<(ServerConfig, PoolConfig)> = servers
        .into_iter()
        .map(|(s, mut c)| {
            c.live = Some(live.clone());
            (s, c)
        })
        .collect();
    (servers, live, target)
}
