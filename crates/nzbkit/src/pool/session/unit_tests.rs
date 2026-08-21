//! Lib-level unit tests for the session lifecycle (coverage §122).
//!
//! `session_loop` and its `*Step` helpers were the largest single block
//! of product code no `--lib` measurement reached: the daemon and chaos
//! integration suites drive them hard, and `cargo llvm-cov -p nzbkit
//! --lib` cannot see integration coverage. The rigs in
//! `pool/unit_tests.rs` reach the helpers that are `pub(super)`; a CHILD
//! of `session` reaches the rest - `top_up_window`, the two death
//! helpers, and `ReadStep`'s private fields - so the arms that only a
//! whole-fleet chaos run used to walk get pinned directly here.
//!
//! What these pin, in the order the loop meets them: the pre-dial gates
//! (bow-out, live target, the drain-breaks-the-backoff rule), the two
//! done-before-dial exits (park vs close, which is the warm pool's
//! whole argument), the dial's refusal taxonomy (permanent settles the
//! server, capacity paces a keeper, a dead host walks its ladder into
//! the prober), the park/probe machinery's two terminals (a fresh
//! Reopened rejoins, the horizon declares Dead), the window top-up's
//! two "admit nothing" gates, and the duplicate-refusal evidence rules
//! in `handle_missing`.

use super::*;
use crate::mock::{Chaos, MockServer, make_file_articles};
use crate::warmpool::WarmPool;

fn server(host: &str) -> ServerConfig {
    ServerConfig {
        host: host.into(),
        port: 119,
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
    }
}

fn fresh(ids: &[&str]) -> Vec<ArticleReq> {
    ids.iter().map(|id| ArticleReq::fresh(*id)).collect()
}

fn work(id: &str) -> Work {
    Work {
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
    }
}

/// A TCP port with nothing behind it: bind, read the port back, drop the
/// listener. Every dial to it fails at connect, which is the hard-outage
/// shape (`refuse_connect_ms` models the same fault server-side, but a
/// dial ladder test wants no server at all).
fn dead_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    l.local_addr().expect("local addr").port()
}

/// The three gates every pass through `session_loop` clears before it
/// goes near a dial. The ORDER is load-bearing (a worker that is leaving
/// must not sit out a 30 s sleep on the way out) and so is the last
/// one's odd contract: a DRAIN breaks the session backoff and carries
/// the worker on into the loop to retire, where `finished` returns it.
#[tokio::test(start_paused = true)]
async fn the_pre_dial_gates_bow_out_park_and_pace_in_that_order() {
    let servers = vec![(server("s"), PoolConfig::default())];
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    let mut finished = sh.finished.subscribe();
    let cfg = PoolConfig::default();
    // A worker that can only ever fail bows out, and does it BEFORE the
    // backoff: the armed sleep is still there afterwards, unslept.
    let mut armed = Some(Duration::from_secs(30));
    assert!(
        !pre_dial_gates(
            &cfg,
            0,
            MAX_SESSION_ATTEMPTS,
            &mut armed,
            &mut finished,
            &sh
        )
        .await,
        "a worker at the session-attempt ceiling is done"
    );
    assert_eq!(
        armed,
        Some(Duration::from_secs(30)),
        "the bow-out must not pay the backoff on its way out"
    );

    // TODO 112: a slot at or above the live target parks - holding no
    // connection - until the target admits it again.
    let target = ConnTarget::new(1);
    let cfg = PoolConfig {
        live_target: Some(target.clone()),
        ..Default::default()
    };
    let sh2 = sh.clone();
    let mut parked_finished = sh.finished.subscribe();
    let parked = tokio::spawn(async move {
        let mut none = None;
        pre_dial_gates(&cfg, 1, 0, &mut none, &mut parked_finished, &sh2).await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!parked.is_finished(), "slot 1 is over a target of 1");
    target.set(2);
    assert!(
        parked.await.expect("parked worker"),
        "raising the target readmits the slot"
    );

    // The session backoff: a graceful DRAIN breaks the wait and returns
    // TRUE - the worker carries on into the loop and retires through the
    // normal path - where a finished run returns false. That difference
    // is why this is not `backoff_or_finish`.
    let cfg = PoolConfig::default();
    sh.draining.store(true, Ordering::Release);
    let mut armed = Some(Duration::from_secs(30));
    let started = tokio::time::Instant::now();
    assert!(pre_dial_gates(&cfg, 0, 0, &mut armed, &mut finished, &sh).await);
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "a drain must not wait out the whole backoff"
    );
    assert!(armed.is_none(), "the backoff is spent either way");
    sh.draining.store(false, Ordering::Release);
    let _ = sh.finished.send(true);
    let mut armed = Some(Duration::from_secs(30));
    assert!(
        !pre_dial_gates(&cfg, 0, 0, &mut armed, &mut finished, &sh).await,
        "a finished run ends the worker inside its backoff"
    );
}

/// The two exits above the dial, and the difference between them: a
/// worker that finds the queue already drained is holding a validated,
/// idle session and PARKS it (the warm pool exists to keep exactly
/// that), while a user abort closes. Parking on abort would hand a
/// stopped job's sessions to the next one; closing on drain is the
/// measured erosion that shrank a warm pool over six back-to-back jobs.
#[tokio::test]
async fn a_drained_worker_parks_its_unused_session_and_an_abort_closes_it() {
    let srv = MockServer::start(std::collections::HashMap::new(), Chaos::default()).await;
    let sc = srv.server_config();
    let warm = WarmPool::new(Duration::from_secs(60), 4);
    let cfg = PoolConfig {
        warm: Some(warm.clone()),
        ..Default::default()
    };
    // Nothing pending: the queue was emptied while this worker ramped.
    let servers = vec![(server("s"), cfg.clone())];
    let (drained, _) = Shared::new(Vec::new(), &servers);
    let (c, _) = Connection::connect(&sc).await.expect("dial the mock");
    let mut held = Some(c);
    assert!(done_before_dial(&cfg, &sc, &drained, &mut held).await);
    assert!(held.is_none(), "the claimed connection was handed on");
    assert_eq!(
        warm.stats.parked.load(Ordering::Relaxed),
        1,
        "a drained worker's validated session goes back to the pool"
    );

    // Abort: same claimed connection, and it must NOT be parked.
    let (aborted, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    aborted.aborted.store(true, Ordering::Release);
    let (c, _) = Connection::connect(&sc).await.expect("dial the mock");
    let mut held = Some(c);
    assert!(done_before_dial(&cfg, &sc, &aborted, &mut held).await);
    assert!(held.is_none());
    assert_eq!(
        warm.stats.parked.load(Ordering::Relaxed),
        1,
        "an abort closes its session - the user is done with this server"
    );
}

/// §15e: an AUTHINFO refusal is the server's answer to this ACCOUNT, so
/// it is settled ONCE and every later worker reads the verdict instead
/// of re-asking (that storm is what made a wrong password cost every
/// worker its whole backoff ladder). The dashboard gets the server's own
/// words, marked permanent.
#[tokio::test]
async fn a_permanent_auth_refusal_settles_the_account_for_every_worker() {
    let srv = MockServer::start(
        std::collections::HashMap::new(),
        Chaos {
            auth_rejected: true,
            ..Default::default()
        },
    )
    .await;
    let mut sc = srv.server_config();
    sc.username = Some("u".into());
    sc.password = Some("p".into());
    // A declared address allowance makes the refusal ambiguous - 481/502
    // is also what several providers say for "too many addresses" - and
    // the extra advice arm fires on exactly this shape.
    sc.max_source_ips = Some(1);
    let servers = vec![(sc.clone(), PoolConfig::default())];
    let live = LiveStats::for_servers(&servers);
    let cfg = PoolConfig {
        live: Some(live.clone()),
        ..Default::default()
    };
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    let ctx = ctx_for(&servers, 0);
    let mut finished = sh.finished.subscribe();
    let (connects, reconnects) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    let (mut fails, mut flap, mut bounces, mut ever, mut last_end) =
        (0u32, 0u32, 0u32, false, None);
    let step = dial_session(
        &sc,
        &cfg,
        ctx,
        &sh,
        &connects,
        &reconnects,
        &mut finished,
        &mut fails,
        &mut flap,
        &mut bounces,
        &mut ever,
        false,
        &mut last_end,
    )
    .await;
    assert!(
        matches!(step, DialStep::Quit),
        "a credential cannot be retried"
    );
    assert!(
        sh.auth[0].is_rejected(),
        "the verdict is settled per server"
    );
    let refusal = live.servers[0].refusal.lock_ok().clone();
    let refusal = refusal.expect("the dashboard is told which server stopped pulling");
    assert!(refusal.permanent);
    assert!(
        refusal.line.contains("481"),
        "in the server's own words: {}",
        refusal.line
    );
    let asked = srv.accepted.load(Ordering::Relaxed);
    // A second worker reads the settled verdict - it must not re-ask.
    let step = dial_session(
        &sc,
        &cfg,
        ctx,
        &sh,
        &connects,
        &reconnects,
        &mut finished,
        &mut fails,
        &mut flap,
        &mut bounces,
        &mut ever,
        false,
        &mut last_end,
    )
    .await;
    assert!(matches!(step, DialStep::Quit));
    assert_eq!(
        srv.accepted.load(Ordering::Relaxed),
        asked,
        "a settled refusal costs no further dials"
    );
    assert_eq!(connects.load(Ordering::Relaxed), 0);
}

/// TODO 115: the OTHER 481. A capacity refusal says the account is fine
/// and the server will not give us another session right now, so a flap
/// KEEPER paces its retries on its own bounce counter and never walks
/// toward connect exhaustion - the ladder that would retire the one
/// worker holding a slot the provider actually serves. Every bounce
/// reaches the event ring even though only the first reaches the log.
#[tokio::test]
async fn a_keeper_paces_capacity_bounces_instead_of_walking_to_exhaustion() {
    let srv = MockServer::start(
        std::collections::HashMap::new(),
        Chaos {
            auth_rejected: true,
            auth_refusal_text: Some("481 max number of simultaneous IP addresses reached".into()),
            ..Default::default()
        },
    )
    .await;
    let mut sc = srv.server_config();
    sc.username = Some("u".into());
    sc.password = Some("p".into());
    let servers = vec![(sc.clone(), PoolConfig::default())];
    let live = LiveStats::for_servers(&servers);
    let cfg = PoolConfig {
        live: Some(live.clone()),
        flap_cap_keepers: true,
        connect_backoff: Duration::from_millis(1),
        ..Default::default()
    };
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    let ctx = ctx_for(&servers, 0);
    let mut finished = sh.finished.subscribe();
    let (connects, reconnects) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    let (mut fails, mut flap, mut bounces, mut ever, mut last_end) =
        (0u32, 0u32, 0u32, false, None);
    for expect in 1..=2u32 {
        let step = dial_session(
            &sc,
            &cfg,
            ctx,
            &sh,
            &connects,
            &reconnects,
            &mut finished,
            &mut fails,
            &mut flap,
            &mut bounces,
            &mut ever,
            true,
            &mut last_end,
        )
        .await;
        assert!(
            matches!(step, DialStep::Retry),
            "a keeper retries a capacity bounce, paced"
        );
        assert_eq!(flap, expect, "bounces pace on their own counter");
        assert_eq!(
            bounces, 0,
            "and NOT on the capacity-probe ladder's - sharing that counter \
             walked a flapped keeper past the single-prober election"
        );
        assert_eq!(
            fails, 0,
            "a bounce is not a connect failure - the keeper must never \
             reach connect exhaustion on one"
        );
    }
    assert!(
        !sh.auth[0].is_rejected(),
        "the account is fine; only its session count was refused"
    );
    let caps = live
        .recent_events(16)
        .iter()
        .filter(|e| e.kind == "cap")
        .count();
    assert_eq!(
        caps, 2,
        "the ring takes EVERY bounce - the log's `if first` is what \
         made a provider that capped twice look like it capped once"
    );
}

/// A host that is simply not there: the connect ladder counts its own
/// failures, backs off, and at `max_connect_attempts` hands over to the
/// park-or-probe machinery rather than retiring the worker for good
/// (the outage keeper - a wifi drop is as transient as a ghost lease).
/// A lone worker cannot park (there would be nobody left), so it is
/// elected prober and says so on the episode watch.
#[tokio::test]
async fn a_dead_host_walks_its_ladder_then_becomes_the_prober() {
    let mut sc = server("127.0.0.1");
    sc.port = dead_port();
    let servers = vec![(sc.clone(), PoolConfig::default())];
    let cfg = PoolConfig {
        max_connect_attempts: 2,
        connect_backoff: Duration::from_millis(1),
        cap_probe_bounces: 8,
        ..Default::default()
    };
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    sh.alive[0].store(1, Ordering::SeqCst);
    let ctx = ctx_for(&servers, 0);
    let mut finished = sh.finished.subscribe();
    let (connects, reconnects) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    let (mut fails, mut flap, mut bounces, mut ever, mut last_end) =
        (0u32, 0u32, 0u32, false, None);
    let step = dial_session(
        &sc,
        &cfg,
        ctx,
        &sh,
        &connects,
        &reconnects,
        &mut finished,
        &mut fails,
        &mut flap,
        &mut bounces,
        &mut ever,
        false,
        &mut last_end,
    )
    .await;
    assert!(matches!(step, DialStep::Retry));
    assert_eq!(fails, 1, "the first failure is counted and explained once");
    let ticks = sh.deferred.load(Ordering::Relaxed);
    let step = dial_session(
        &sc,
        &cfg,
        ctx,
        &sh,
        &connects,
        &reconnects,
        &mut finished,
        &mut fails,
        &mut flap,
        &mut bounces,
        &mut ever,
        false,
        &mut last_end,
    )
    .await;
    assert!(
        matches!(step, DialStep::Retry),
        "exhausting the ladder hands over to the prober, it does not retire the worker"
    );
    assert_eq!(bounces, 1, "the prober rides its own paced ladder");
    assert!(
        matches!(*sh.auth[0].episode.borrow(), (CapEpisode::Probing, _)),
        "the lone survivor elects itself prober and publishes the episode"
    );
    assert!(
        sh.deferred.load(Ordering::Relaxed) > ticks,
        "each paced bounce is deliberate progress and must tick the \
         watchdog's liveness counter, or a recovering provider is \
         aborted inside the ladder's own horizon"
    );
}

/// The park side of the same machinery, and the generation guard that
/// makes it terminate. The episode watch never returns to Idle, so a
/// PREVIOUS episode's Reopened is still sitting in it: consuming that
/// would skip the prober election for every later episode, and a
/// permanent outage would then never reach Dead and never end the run.
#[tokio::test]
async fn a_parked_worker_waits_for_a_reopened_newer_than_its_park() {
    let servers = vec![(server("s"), PoolConfig::default())];
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    let ctx = ctx_for(&servers, 0);
    // Two workers alive: a yield is only safe while it leaves someone.
    sh.alive[0].store(2, Ordering::SeqCst);
    // The stale value from an earlier episode.
    sh.auth[0].publish_episode(CapEpisode::Reopened);
    let cfg = PoolConfig {
        connect_backoff: Duration::from_millis(1),
        ..Default::default()
    };
    let sh2 = sh.clone();
    let cfg2 = cfg.clone();
    let parker = tokio::spawn(async move {
        let mut finished = sh2.finished.subscribe();
        let (mut bounces, mut fails) = (0u32, 4u32);
        let step = park_or_probe(&cfg2, ctx, &sh2, &mut finished, &mut bounces, &mut fails).await;
        (step, fails)
    });
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(
        !parker.is_finished(),
        "the leftover Reopened is not this park's answer"
    );
    assert_eq!(
        sh.auth[0].yielded.load(Ordering::SeqCst),
        1,
        "the parked worker holds its yield while it waits"
    );
    sh.auth[0].publish_episode(CapEpisode::Reopened);
    let (step, fails) = parker.await.expect("parked worker");
    assert!(matches!(step, DialStep::Retry), "a fresh Reopened rejoins");
    assert_eq!(
        sh.auth[0].yielded.load(Ordering::SeqCst),
        0,
        "the yield is given back on the way in"
    );
    assert_eq!(
        fails, 0,
        "a rejoining worker gets a fresh ladder - the pre-park failures \
         were the episode's, not its own"
    );
}

/// The other terminal: the prober's horizon. A server that is capped or
/// dark for good must not leave the fleet parked forever - at
/// `cap_probe_bounces` the prober publishes Dead, which releases the
/// parked workers to exit so `seal_run` can reach a truthful verdict.
#[tokio::test]
async fn the_probers_horizon_declares_the_server_dead_and_frees_the_parked() {
    let servers = vec![(server("s"), PoolConfig::default())];
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    let ctx = ctx_for(&servers, 0);
    sh.alive[0].store(2, Ordering::SeqCst);
    let cfg = PoolConfig {
        cap_probe_bounces: 3,
        connect_backoff: Duration::from_millis(1),
        ..Default::default()
    };
    // One worker parks on the episode watch...
    let sh2 = sh.clone();
    let cfg2 = cfg.clone();
    let parked = tokio::spawn(async move {
        let mut finished = sh2.finished.subscribe();
        let (mut bounces, mut fails) = (0u32, 0u32);
        park_or_probe(&cfg2, ctx, &sh2, &mut finished, &mut bounces, &mut fails).await
    });
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(
        !parked.is_finished(),
        "the parked worker waits on a verdict"
    );
    // ...and the elected prober rides its ladder to the horizon.
    let mut finished = sh.finished.subscribe();
    let (mut bounces, mut fails) = (0u32, 0u32);
    for _ in 1..cfg.cap_probe_bounces {
        let step = park_or_probe(&cfg, ctx, &sh, &mut finished, &mut bounces, &mut fails).await;
        assert!(matches!(step, DialStep::Retry), "still inside the horizon");
    }
    let step = park_or_probe(&cfg, ctx, &sh, &mut finished, &mut bounces, &mut fails).await;
    assert!(
        matches!(step, DialStep::Quit),
        "the horizon ends the prober's ladder"
    );
    assert!(matches!(
        *sh.auth[0].episode.borrow(),
        (CapEpisode::Dead, _)
    ));
    assert!(
        matches!(parked.await.expect("parked worker"), DialStep::Quit),
        "a Dead verdict releases the parked fleet to exit, so the run \
         can seal instead of idling forever"
    );
}

/// M3 (read-only sweep 2): the THIRD way an episode ends. A capacity
/// episode parks most of the fleet and elects one prober; if that
/// prober's next dial comes back a PERMANENT refusal - a disabled
/// account, or a provider that changed the wording of its cap - the
/// server is settled for good, and nothing published an episode
/// verdict. Active workers read `rejected` at the top of the dial and
/// quit, but the parked ones are not in the dial loop at all: they wake
/// only for a newer Reopened, a Dead, `finished` or `draining`. On a
/// single-server run nothing else can finish the work, so `finished`
/// never fires either - `workers_live` stayed non-zero, the run never
/// reached its terminal seal, and a CLI invocation hung until an
/// external cancellation.
///
/// Both directions, because publishing Dead too eagerly is the opposite
/// bug: the second half drives a CAPACITY refusal through the same
/// parked fleet and requires that the episode stays open and still
/// reopens.
#[tokio::test]
async fn a_permanent_refusal_releases_the_workers_parked_on_a_capacity_episode() {
    // Three of a four-strong fleet yield to the episode and park; the
    // fourth is the prober. Returns the parked handles.
    async fn park_three(
        sh: &Arc<Shared>,
        cfg: &PoolConfig,
        ctx: ServerCtx,
    ) -> Vec<tokio::task::JoinHandle<DialStep>> {
        sh.alive[0].store(4, Ordering::SeqCst);
        let mut parked = Vec::new();
        for _ in 0..3 {
            let sh2 = sh.clone();
            let cfg2 = cfg.clone();
            parked.push(tokio::spawn(async move {
                let mut finished = sh2.finished.subscribe();
                let (mut bounces, mut fails) = (0u32, 0u32);
                park_or_probe(&cfg2, ctx, &sh2, &mut finished, &mut bounces, &mut fails).await
            }));
        }
        // They must REALLY be parked before the refusal lands, or the
        // test proves nothing about waking them.
        for _ in 0..500 {
            if sh.auth[0].yielded.load(Ordering::SeqCst) == 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            sh.auth[0].yielded.load(Ordering::SeqCst),
            3,
            "three workers yielded their slots to the episode"
        );
        assert!(
            parked.iter().all(|h| !h.is_finished()),
            "and each is waiting on the prober's verdict"
        );
        parked
    }

    let cfg = PoolConfig {
        connect_backoff: Duration::from_millis(1),
        ..Default::default()
    };

    // The account is gone for good.
    let srv = MockServer::start(
        std::collections::HashMap::new(),
        Chaos {
            auth_rejected: true,
            ..Default::default()
        },
    )
    .await;
    let mut sc = srv.server_config();
    sc.username = Some("u".into());
    sc.password = Some("p".into());
    let servers = vec![(sc.clone(), PoolConfig::default())];
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    let ctx = ctx_for(&servers, 0);
    let parked = park_three(&sh, &cfg, ctx).await;

    let mut finished = sh.finished.subscribe();
    let (connects, reconnects) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    let (mut fails, mut flap, mut bounces, mut ever, mut last_end) =
        (0u32, 0u32, 0u32, false, None);
    let step = dial_session(
        &sc,
        &cfg,
        ctx,
        &sh,
        &connects,
        &reconnects,
        &mut finished,
        &mut fails,
        &mut flap,
        &mut bounces,
        &mut ever,
        false,
        &mut last_end,
    )
    .await;
    assert!(
        matches!(step, DialStep::Quit),
        "a credential cannot be retried"
    );
    assert!(sh.auth[0].is_rejected(), "the server is settled for good");
    for h in parked {
        let step = tokio::time::timeout(Duration::from_secs(10), h)
            .await
            .expect(
                "a parked worker must be released by the refusal - left waiting, \
                 workers_live never reaches zero and the run never seals",
            )
            .expect("parked worker");
        assert!(matches!(step, DialStep::Quit));
    }
    assert!(
        matches!(*sh.auth[0].episode.borrow(), (CapEpisode::Dead, _)),
        "a permanent refusal is as final as the prober's horizon, so it \
         owes the parked fleet the same verdict"
    );

    // The other direction: the SAME shape with a capacity refusal, which
    // is transient. Nothing may be declared final and the parked fleet
    // must still rejoin when the cap clears.
    let srv = MockServer::start(
        std::collections::HashMap::new(),
        Chaos {
            auth_rejected: true,
            auth_refusal_text: Some("481 max number of simultaneous IP addresses reached".into()),
            ..Default::default()
        },
    )
    .await;
    let mut sc = srv.server_config();
    sc.username = Some("u".into());
    sc.password = Some("p".into());
    let servers = vec![(sc.clone(), PoolConfig::default())];
    let (sh, _) = Shared::new(fresh(&["<b@x>"]), &servers);
    let ctx = ctx_for(&servers, 0);
    let parked = park_three(&sh, &cfg, ctx).await;

    let mut finished = sh.finished.subscribe();
    let (mut fails, mut flap, mut bounces, mut ever, mut last_end) =
        (0u32, 0u32, 0u32, false, None);
    let step = dial_session(
        &sc,
        &cfg,
        ctx,
        &sh,
        &connects,
        &reconnects,
        &mut finished,
        &mut fails,
        &mut flap,
        &mut bounces,
        &mut ever,
        false,
        &mut last_end,
    )
    .await;
    assert!(
        matches!(step, DialStep::Retry),
        "a capacity refusal is transient - the prober paces and goes again"
    );
    assert!(!sh.auth[0].is_rejected());
    assert!(
        !matches!(*sh.auth[0].episode.borrow(), (CapEpisode::Dead, _)),
        "a cap that can still clear is never published as final"
    );
    assert!(
        parked.iter().all(|h| !h.is_finished()),
        "so the fleet stays parked instead of being torn down"
    );
    // The cap clears: a granted session reopens the episode and the
    // parked fleet rejoins at full width.
    sh.auth[0].publish_episode(CapEpisode::Reopened);
    for h in parked {
        let step = tokio::time::timeout(Duration::from_secs(10), h)
            .await
            .expect("a reopened episode must still wake the parked fleet")
            .expect("parked worker");
        assert!(matches!(step, DialStep::Retry));
    }
    assert_eq!(
        sh.auth[0].yielded.load(Ordering::SeqCst),
        0,
        "and each rejoiner gave its slot back"
    );
}

/// The window top-up's two "admit nothing" gates, and the ordinary fill
/// between them. Over the live target the pipeline is left to drain
/// toward the park; over the B3 wire cap it is held at ONE request in
/// flight - never zero, or the response drain that reopens the cap
/// could not happen and the pool would deadlock.
#[tokio::test]
async fn the_top_up_stops_at_the_live_target_and_holds_one_at_the_wire_cap() {
    let mut articles = std::collections::HashMap::new();
    let payload: Vec<u8> = (0..8_000u32).map(|i| i as u8).collect();
    make_file_articles("w.bin", &payload, 2_000, "w", &mut articles);
    let ids: Vec<String> = articles.keys().cloned().collect();
    let srv = MockServer::start(articles, Chaos::default()).await;
    let sc = srv.server_config();
    let servers = vec![(sc.clone(), PoolConfig::default())];
    let live = LiveStats::for_servers(&servers);
    let cfg = PoolConfig {
        live: Some(live.clone()),
        ..Default::default()
    };
    let id_refs: Vec<&str> = ids.iter().map(|s| s.as_str()).collect();
    let (sh, _) = Shared::new(fresh(&id_refs), &servers);
    // This worker is the live fleet: with nobody alive, every queued
    // article is one that "every live server has already refused".
    sh.alive[0].store(1, Ordering::SeqCst);
    let ctx = ctx_for(&servers, 0);
    let (tx, _rx) = mpsc::channel(16);
    let (mut conn, _) = Connection::connect(&sc).await.expect("dial the mock");
    let mut inflight: VecDeque<Work> = VecDeque::new();

    // Over the live target: nothing is admitted at all.
    let step = top_up_window(&mut conn, &cfg, ctx, &sh, &tx, &mut inflight, 4, true, 0, 0).await;
    assert!(matches!(step, TopUp::Filled));
    assert!(
        inflight.is_empty(),
        "a slot over the target admits nothing, so its pipeline drains"
    );
    assert_eq!(sh.queue.lock().await.len(), ids.len());

    // Ordinary fill: the window is topped up, each dispatch charged and
    // registered, and the server's tried counter moves.
    let step = top_up_window(
        &mut conn,
        &cfg,
        ctx,
        &sh,
        &tx,
        &mut inflight,
        3,
        false,
        0,
        0,
    )
    .await;
    assert!(matches!(step, TopUp::Filled));
    assert_eq!(inflight.len(), 3, "the window fills to `win`");
    assert_eq!(
        live.servers[0].articles_tried.load(Ordering::Relaxed),
        3,
        "every dispatch is counted against the server that took it"
    );
    assert_eq!(sh.inflight.lock_ok().len(), 3);

    // Over the wire cap: held where it stands, never topped up further.
    let capped = PoolConfig {
        inflight_cap: 1,
        ..cfg.clone()
    };
    let step = top_up_window(
        &mut conn,
        &capped,
        ctx,
        &sh,
        &tx,
        &mut inflight,
        8,
        false,
        0,
        0,
    )
    .await;
    assert!(matches!(step, TopUp::Filled));
    assert_eq!(
        inflight.len(),
        3,
        "over the byte budget nothing new goes on the wire"
    );
    // ...but a worker holding NOTHING still gets its one request, which
    // is what keeps the drain (and so the cap's own release) moving.
    let mut empty: VecDeque<Work> = VecDeque::new();
    let step = top_up_window(
        &mut conn, &capped, ctx, &sh, &tx, &mut empty, 8, false, 0, 0,
    )
    .await;
    assert!(matches!(step, TopUp::Filled));
    assert_eq!(
        empty.len(),
        1,
        "never below one in flight, or the pool deadlocks against its own cap"
    );

    // A graceful pause admits nothing new either: the in-flight requests
    // below it complete (and journal), and then the worker parks.
    sh.draining.store(true, Ordering::Release);
    let mut none: VecDeque<Work> = VecDeque::new();
    let step = top_up_window(&mut conn, &cfg, ctx, &sh, &tx, &mut none, 4, false, 0, 0).await;
    assert!(matches!(step, TopUp::Filled));
    assert!(none.is_empty(), "a drain takes no new work on the wire");
    conn.quit().await;
}

/// M2c.4 / §129 3g: what a DUPLICATE dispatch's 430 is worth. Un-echoed
/// it is positional evidence off a socket we cannot check, so it is
/// dropped (merging it could push the union to a false unanimous
/// Missing). Echoed, it is the same authoritative answer the original
/// would have got - merged into the article's mask, and terminal the
/// moment the union covers every live server, without waiting for the
/// original to walk the rest of the ladder.
#[tokio::test]
async fn a_duplicates_refusal_counts_only_when_the_socket_can_be_checked() {
    let servers = vec![(server("s"), PoolConfig::default())];
    let cfg = PoolConfig::default();
    let (sh, _) = Shared::new(fresh(&["<d@x>"]), &servers);
    let ctx = ctx_for(&servers, 0);
    sh.alive[0].store(1, Ordering::SeqCst);
    let (tx, mut rx) = mpsc::channel(8);
    // The original is out reading; this is its duplicate.
    let original = work("<d@x>");
    sh.register_inflight(&original, 0);
    let dup = || {
        let mut w = work("<d@x>");
        w.dup = true;
        w
    };
    let mut inflight: VecDeque<Work> = [dup()].into_iter().collect();
    sh.charge_wire();
    let mut bare: VecDeque<Arc<str>> = VecDeque::new();
    handle_missing(
        &cfg,
        ctx,
        &sh,
        &tx,
        &mut inflight,
        Vec::new(),
        false,
        false,
        &mut bare,
    )
    .await;
    assert!(rx.try_recv().is_err(), "a bare dup refusal decides nothing");
    assert_eq!(
        sh.inflight.lock_ok().get("<d@x>").map(|i| i.tried_430),
        Some(0),
        "unproven evidence must not reach the article's mask"
    );
    assert_eq!(sh.pending.load(Ordering::Acquire), 1);

    // The same refusal with the id echoed back: authoritative, merged,
    // and on a single-server run that union is already unanimous.
    let mut inflight: VecDeque<Work> = [dup()].into_iter().collect();
    sh.charge_wire();
    handle_missing(
        &cfg,
        ctx,
        &sh,
        &tx,
        &mut inflight,
        Vec::new(),
        true,
        false,
        &mut bare,
    )
    .await;
    match rx.try_recv() {
        Ok(FetchOutcome::Missing { id, cause }) => {
            assert_eq!(&*id, "<d@x>");
            assert!(matches!(cause, MissingCause::Gone { .. }));
        }
        other => panic!("expected a terminal Missing off the dup's own answer, got {other:?}"),
    }
    assert_eq!(
        sh.pending.load(Ordering::Acquire),
        0,
        "the article went terminal without the original finishing its ladder"
    );
}

/// The takedown hint rides the refusal ladder to the terminal verdict:
/// one backbone naming the removal ("430 ... DMCA", Giganews's 451)
/// flavours the final Missing even when every other backbone answered a
/// plain 430 - and a ladder of plain 430s stays unflavoured. The
/// verdict itself is identical either way: the hint never gates.
#[tokio::test]
async fn a_takedown_flavoured_refusal_flavours_the_terminal_missing() {
    let servers = vec![
        (server("a"), PoolConfig::default()),
        (server("b"), PoolConfig::default()),
    ];
    let cfg = PoolConfig::default();
    let (sh, _) = Shared::new(fresh(&["<t@x>", "<p@x>"]), &servers);
    sh.alive[0].store(1, Ordering::SeqCst);
    sh.alive[1].store(1, Ordering::SeqCst);
    let (tx, mut rx) = mpsc::channel(8);
    let mut bare: VecDeque<Arc<str>> = VecDeque::new();
    let pop_id = |q: &mut VecDeque<Work>, id: &str| {
        let at = q.iter().position(|w| &*w.id == id).expect("queued");
        q.remove(at).expect("present")
    };
    // <t@x>: server a's refusal says removed (takedown = true), server
    // b's is a plain 430. The union is unanimous at b, and a's hint
    // survives to the outcome.
    for (si, takedown) in [(0usize, true), (1usize, false)] {
        let w = pop_id(&mut *sh.queue.lock().await, "<t@x>");
        let mut inflight: VecDeque<Work> = [w].into_iter().collect();
        sh.charge_wire();
        handle_missing(
            &cfg,
            ctx_for(&servers, si),
            &sh,
            &tx,
            &mut inflight,
            Vec::new(),
            true,
            takedown,
            &mut bare,
        )
        .await;
    }
    match rx.try_recv() {
        Ok(FetchOutcome::Missing { id, cause }) => {
            assert_eq!(&*id, "<t@x>");
            assert_eq!(
                cause,
                MissingCause::Gone { takedown: true },
                "the removal notice must survive to the terminal verdict"
            );
        }
        other => panic!("expected a terminal Missing, got {other:?}"),
    }
    // <p@x>: plain 430s all the way down stay unflavoured.
    for si in [0usize, 1] {
        let w = pop_id(&mut *sh.queue.lock().await, "<p@x>");
        let mut inflight: VecDeque<Work> = [w].into_iter().collect();
        sh.charge_wire();
        handle_missing(
            &cfg,
            ctx_for(&servers, si),
            &sh,
            &tx,
            &mut inflight,
            Vec::new(),
            true,
            false,
            &mut bare,
        )
        .await;
    }
    match rx.try_recv() {
        Ok(FetchOutcome::Missing { id, cause }) => {
            assert_eq!(&*id, "<p@x>");
            assert_eq!(cause, MissingCause::Gone { takedown: false });
        }
        other => panic!("expected a terminal Missing, got {other:?}"),
    }
}

/// A promoted (playhead) article that 430s must go back to the FRONT of
/// the queue, behind other promoted work only: at the back it sits
/// behind gigabytes while the player starves, which is the live wedge
/// this rule was written for. It must also re-arm `promoted_pending`,
/// or the promote shed stops seeing work it is supposed to be racing.
#[tokio::test]
async fn a_promoted_articles_refusal_goes_back_to_the_promoted_front() {
    // Two servers, so one server's 430 is not yet the whole ladder.
    let servers = vec![
        (server("a"), PoolConfig::default()),
        (server("b"), PoolConfig::default()),
    ];
    let cfg = PoolConfig::default();
    let (sh, _) = Shared::new(fresh(&["<p@x>", "<q@x>", "<r@x>"]), &servers);
    sh.alive[0].store(1, Ordering::SeqCst);
    sh.alive[1].store(1, Ordering::SeqCst);
    let ctx = ctx_for(&servers, 0);
    let (tx, mut rx) = mpsc::channel(8);
    // A promoted article already at the front, so the insert has to pick
    // the position AFTER it rather than the head of the queue.
    {
        let mut q = sh.queue.lock().await;
        q.retain(|w| &*w.id != "<p@x>");
        let mut ahead = work("<q@x>");
        ahead.promoted = true;
        q.retain(|w| &*w.id != "<q@x>");
        q.push_front(ahead);
    }
    let mut w = work("<p@x>");
    w.promoted = true;
    let mut inflight: VecDeque<Work> = [w].into_iter().collect();
    sh.charge_wire();
    let mut bare: VecDeque<Arc<str>> = VecDeque::new();
    handle_missing(
        &cfg,
        ctx,
        &sh,
        &tx,
        &mut inflight,
        Vec::new(),
        true,
        false,
        &mut bare,
    )
    .await;
    assert!(rx.try_recv().is_err(), "another backbone can still answer");
    let q = sh.queue.lock().await;
    let order: Vec<&str> = q.iter().map(|w| &*w.id).collect();
    assert_eq!(
        order.first().copied(),
        Some("<q@x>"),
        "promoted work already queued keeps its place"
    );
    assert_eq!(
        order.get(1).copied(),
        Some("<p@x>"),
        "the refused playhead article requeues behind it, not at the back: {order:?}"
    );
    assert_eq!(
        sh.promoted_pending.load(Ordering::Acquire),
        1,
        "the promote wave must still count it as outstanding"
    );
}

/// A body's handoff is where a SLOW DISK becomes visible. The channel
/// fills, this await parks, the TCP windows close behind it - that is
/// the designed response, and it is indistinguishable from a network dip
/// on the graph unless somebody measures it. So the wait is timed (only
/// when it actually happened: the healthy path costs no clock read at
/// all), banked per server, and marked once it is long enough for a
/// person to see.
#[tokio::test]
async fn a_body_that_waits_on_the_write_side_is_timed_and_marked() {
    let servers = vec![(server("s"), PoolConfig::default())];
    let live = LiveStats::for_servers(&servers);
    let cfg = PoolConfig {
        live: Some(live.clone()),
        ..Default::default()
    };
    let (sh, _) = Shared::new(fresh(&["<b0@x>", "<b1@x>"]), &servers);
    let ctx = ctx_for(&servers, 0);
    // A channel with no room: the consumer takes the first body only
    // after a wait a person could see (BLOCKED_NOTE_MS).
    let (tx, mut rx) = mpsc::channel(1);
    tx.try_send(FetchOutcome::Missing {
        id: "<filler@x>".into(),
        cause: MissingCause::Gone { takedown: false },
    })
    .expect("prime the channel full");
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(BLOCKED_NOTE_MS + 100)).await;
        let mut got = 0;
        while rx.recv().await.is_some() {
            got += 1;
            if got == 2 {
                break;
            }
        }
        rx
    });
    let mut inflight: VecDeque<Work> = [work("<b0@x>")].into_iter().collect();
    sh.charge_wire();
    let (mut losses, mut bytes) = (0u32, 0u64);
    let step = handle_body(
        &cfg,
        ctx,
        &sh,
        &tx,
        &mut inflight,
        vec![7u8; 4_096],
        &mut losses,
        &mut bytes,
        Instant::now(),
    )
    .await;
    assert!(matches!(step, BodyStep::Proceed));
    assert_eq!(bytes, 4_096, "the session's own byte ledger takes it");
    let waited = live.servers[0].blocked_ms.load(Ordering::Relaxed);
    assert!(
        waited >= BLOCKED_NOTE_MS,
        "the parked handoff must be measured, got {waited} ms"
    );
    assert!(
        live.recent_events(8).iter().any(|e| e.kind == "blocked"),
        "a wait that long earns a mark on the graph"
    );
}

/// The per-article ledgers a served body updates, and what a LOST race
/// does instead. The 222 path is the only feeder of the windowed
/// per-server rate and of the oracle's "this backbone HAS articles of
/// this age" evidence - charged even for a duplicate, because the
/// response is real evidence whoever owns the outcome - while the copy
/// that lost is hygiene spend: charged to the dup budget, and its buffer
/// goes back to the pool instead of being freed.
#[tokio::test]
async fn a_served_body_feeds_the_rate_the_oracle_and_the_buffer_pool() {
    let servers = vec![(server("s"), PoolConfig::default())];
    let live = LiveStats::for_servers(&servers);
    let oracle = Arc::new(crate::oracle::OracleSink::default());
    oracle.set_context(vec!["s".into()], "alt.bin".into());
    let pool = BufPool::new(4);
    let cfg = PoolConfig {
        live: Some(live.clone()),
        oracle: Some(oracle.clone()),
        buf_pool: Some(pool.clone()),
        rate: Some(RateLimit::new(u64::MAX)),
        ..Default::default()
    };
    // Enough queued to stay clear of the endgame, where losing a race
    // is routine and carries no evidence about this session at all.
    let ids: Vec<String> = (0..70).map(|i| format!("<f{i}@x>")).collect();
    let mut id_refs: Vec<&str> = vec!["<w@x>", "<l@x>"];
    id_refs.extend(ids.iter().map(|s| s.as_str()));
    let (sh, _) = Shared::new(fresh(&id_refs), &servers);
    let ctx = ctx_for(&servers, 0);
    let (tx, mut rx) = mpsc::channel(8);
    let mut inflight: VecDeque<Work> = [work("<w@x>")].into_iter().collect();
    sh.charge_wire();
    let (mut losses, mut bytes) = (0u32, 0u64);
    handle_body(
        &cfg,
        ctx,
        &sh,
        &tx,
        &mut inflight,
        vec![1u8; 2_048],
        &mut losses,
        &mut bytes,
        Instant::now(),
    )
    .await;
    assert!(matches!(rx.try_recv(), Ok(FetchOutcome::Done { .. })));
    assert_eq!(live.servers[0].bytes.load(Ordering::Relaxed), 2_048);
    assert_eq!(sh.bytes[0].load(Ordering::Relaxed), 2_048);

    // The same response for an article a duplicate already claimed.
    assert!(sh.claim_done("<l@x>", 1));
    let mut inflight: VecDeque<Work> = [Work {
        ord: 1,
        ..work("<l@x>")
    }]
    .into_iter()
    .collect();
    sh.charge_wire();
    handle_body(
        &cfg,
        ctx,
        &sh,
        &tx,
        &mut inflight,
        vec![2u8; 2_048],
        &mut losses,
        &mut bytes,
        Instant::now(),
    )
    .await;
    assert!(rx.try_recv().is_err(), "a lost race emits no outcome");
    assert_eq!(losses, 1, "the loss is evidence about THIS session's speed");
    // Both responses were real answers from this server: the oracle
    // records the duplicate's too.
    let samples = oracle.drain();
    let hits: u64 = samples.iter().map(|s| s.hits).sum();
    assert_eq!(
        hits, 2,
        "a 222 is evidence the server holds the article, whoever owns the outcome"
    );
    assert!(
        pool.take().capacity() >= 2_048,
        "the losing copy's buffer went back to the pool, not to the allocator"
    );
}
