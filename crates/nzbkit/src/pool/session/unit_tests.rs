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
        address_family: Default::default(),
        tls_hostname: None,
        warm_reserve: None,
    }
}

fn fresh(ids: &[&str]) -> Vec<ArticleReq> {
    ids.iter().map(|id| ArticleReq::fresh(*id)).collect()
}

fn work(id: &str) -> Work {
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

/// A TCP port with nothing behind it: bind, read the port back, drop the
/// listener. Every dial to it fails at connect, which is the hard-outage
/// shape (`refuse_connect_ms` models the same fault server-side, but a
/// dial ladder test wants no server at all).
fn dead_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    l.local_addr().expect("local addr").port()
}

/// TODO 313 item 2, and it is the plumbing the whole mechanism rests
/// on: while a spill episode is live, a HEAD worker parked under a
/// lowered `ConnTarget` gives its account permit back for as long as it
/// is parked, and takes one again on the way out.
///
/// Without it a walk-down frees nothing anybody else can use. The
/// worker parks holding no connection but still holding the permit, so
/// the lease reads the account as fully subscribed and the job spilled
/// behind this one blocks in `acquire` on a slot standing empty - the
/// mechanism looks wired, moves no sockets, and the only symptom is a
/// second job that never starts.
#[tokio::test]
async fn a_spill_head_gives_its_permit_back_while_it_is_parked() {
    use crate::pool::handoff::{ConnBudget, SpillGate, SpillRole, SpillSeat};
    let servers = vec![(server("s"), PoolConfig::default())];
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    let mut finished = sh.finished.subscribe();
    let budget = ConnBudget::new();
    // Cap 3, so a download may hold 2 and one is the post-processing
    // reserve. Two workers, one admission: one runs, one parks.
    let lease = budget.lease("acct", 3);
    let gate = SpillGate::new();
    // The governor has opened an episode: this head is lending.
    gate.open();
    let target = ConnTarget::new(1);
    let cfg = PoolConfig {
        live_target: Some(target.clone()),
        lease: Some(lease.clone()),
        spill: Some(SpillSeat {
            gate: gate.clone(),
            role: SpillRole::Head,
            sockets: 0,
        }),
        ..Default::default()
    };
    // The worker that keeps its slot, holding a permit like any worker
    // with a socket.
    let mut held: Option<Admitted> = None;
    let mut held_permit = Some(lease.acquire().await);
    assert!(
        pre_dial_gates(
            &cfg,
            0,
            &mut held,
            &mut held_permit,
            0,
            &mut None,
            &mut finished,
            &sh
        )
        .await
    );
    assert!(held.is_some() && held_permit.is_some());
    assert_eq!(lease.snapshot(), (1, 3));

    // The second worker: admitted nowhere, and holding a permit it took
    // before the target moved under it.
    let sh2 = sh.clone();
    let cfg2 = cfg.clone();
    let mut parked_finished = sh.finished.subscribe();
    let l2 = lease.clone();
    let parked = tokio::spawn(async move {
        let mut admit = None;
        let mut permit = Some(l2.acquire().await);
        let ok = pre_dial_gates(
            &cfg2,
            0,
            &mut admit,
            &mut permit,
            0,
            &mut None,
            &mut parked_finished,
            &sh2,
        )
        .await;
        // The permit itself, not a bool: dropping it inside the task
        // would put the account back to one held before the assertion
        // below could see the re-take.
        (ok, admit.is_some(), permit)
    });
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(
        lease.snapshot(),
        (1, 3),
        "the parked worker's permit is back on the account - a spilled \
         lane can take it"
    );
    assert!(!parked.is_finished(), "and it is still parked");

    // Reclaim: the target rises, the worker is re-admitted, and it takes
    // a permit again before it may go anywhere near a dial.
    target.set(2);
    let (ok, admitted, permit) = tokio::time::timeout(Duration::from_secs(5), parked)
        .await
        .expect("a raised target re-admits the parked worker")
        .unwrap();
    assert!(ok && admitted, "re-admitted");
    assert!(permit.is_some(), "and holding an account permit again");
    assert_eq!(lease.snapshot(), (2, 3));
    drop(permit);
    let _ = sh.finished.send(true);
}

/// The same park with NO spill episode open keeps the permit, which is
/// the shipped behaviour verbatim. One trigger, one behaviour: outside
/// a spill nothing is waiting on the lease mid-run, so a release would
/// change no outcome and would put a re-acquire in the path of the
/// TODO 112 walker and the line-cap governor.
#[tokio::test]
async fn an_ordinary_parked_worker_keeps_its_permit() {
    use crate::pool::handoff::{ConnBudget, SpillGate, SpillRole, SpillSeat};
    let servers = vec![(server("s"), PoolConfig::default())];
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    let budget = ConnBudget::new();
    let lease = budget.lease("acct", 3);
    let gate = SpillGate::new();
    let target = ConnTarget::new(1);
    let cfg = PoolConfig {
        live_target: Some(target.clone()),
        lease: Some(lease.clone()),
        // Seated, and the gate never opens - the default-off case.
        spill: Some(SpillSeat {
            gate,
            role: SpillRole::Head,
            sockets: 0,
        }),
        ..Default::default()
    };
    let held = lease.acquire().await;
    sh.admitted[0].store(1, Ordering::SeqCst);
    let sh2 = sh.clone();
    let cfg2 = cfg.clone();
    let mut f2 = sh.finished.subscribe();
    let l2 = lease.clone();
    let parked = tokio::spawn(async move {
        let mut admit = None;
        let mut permit = Some(l2.acquire().await);
        pre_dial_gates(
            &cfg2,
            0,
            &mut admit,
            &mut permit,
            0,
            &mut None,
            &mut f2,
            &sh2,
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(
        lease.snapshot(),
        (2, 3),
        "with the gate shut a parked worker holds its permit exactly as \
         it always did"
    );
    let _ = sh.finished.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), parked).await;
    drop(held);
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
            &mut None,
            &mut None,
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

    // TODO 112 / F-22: with the target's one admission already held, a
    // second worker parks - holding no connection - until the target
    // rises or the holder gives its admission back.
    let target = ConnTarget::new(1);
    let cfg = PoolConfig {
        live_target: Some(target.clone()),
        ..Default::default()
    };
    let mut held: Option<Admitted> = None;
    assert!(
        pre_dial_gates(
            &cfg,
            0,
            &mut held,
            &mut None,
            0,
            &mut None,
            &mut finished,
            &sh
        )
        .await
    );
    assert!(held.is_some(), "the first worker takes the admission");
    let sh2 = sh.clone();
    let cfg2 = cfg.clone();
    let mut parked_finished = sh.finished.subscribe();
    let parked = tokio::spawn(async move {
        let mut admit = None;
        let ok = pre_dial_gates(
            &cfg2,
            0,
            &mut admit,
            &mut None,
            0,
            &mut None,
            &mut parked_finished,
            &sh2,
        )
        .await;
        ok && admit.is_some()
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !parked.is_finished(),
        "the second worker is over a target of 1"
    );
    target.set(2);
    assert!(
        parked.await.expect("parked worker"),
        "raising the target readmits the worker"
    );
    // And a retiring holder re-fills its place without the target moving.
    target.set(1);
    let sh3 = sh.clone();
    let cfg3 = cfg.clone();
    let mut f3 = sh.finished.subscribe();
    let parked = tokio::spawn(async move {
        let mut admit = None;
        pre_dial_gates(&cfg3, 0, &mut admit, &mut None, 0, &mut None, &mut f3, &sh3).await
            && admit.is_some()
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !parked.is_finished(),
        "two admissions are out against a target of 1"
    );
    drop(held);
    assert!(
        parked.await.expect("parked worker"),
        "a returned admission promotes a parked worker"
    );

    // The session backoff: a graceful DRAIN breaks the wait and returns
    // TRUE - the worker carries on into the loop and retires through the
    // normal path - where a finished run returns false. That difference
    // is why this is not `backoff_or_finish`.
    let cfg = PoolConfig::default();
    sh.draining.store(true, Ordering::Release);
    let mut armed = Some(Duration::from_secs(30));
    let started = tokio::time::Instant::now();
    assert!(
        pre_dial_gates(
            &cfg,
            0,
            &mut None,
            &mut None,
            0,
            &mut armed,
            &mut finished,
            &sh
        )
        .await
    );
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "a drain must not wait out the whole backoff"
    );
    assert!(armed.is_none(), "the backoff is spent either way");
    sh.draining.store(false, Ordering::Release);
    let _ = sh.finished.send(true);
    let mut armed = Some(Duration::from_secs(30));
    assert!(
        !pre_dial_gates(
            &cfg,
            0,
            &mut None,
            &mut None,
            0,
            &mut armed,
            &mut finished,
            &sh
        )
        .await,
        "a finished run ends the worker inside its backoff"
    );
}

/// The two exits above the dial. Both are holding a validated, idle
/// session - `take` sent its DATE and read the answer - and both hand it
/// to the warm pool, because DRAINED is the only question the pool asks.
///
/// The abort half is the 25-26 Aug 2026 change and reverses what this
/// test used to pin. Closing there was justified as "the user is done
/// with this server", which is what going OFFLINE means and not what
/// stopping a job means: the same flag is the defer watchdog's teeth and
/// the job-switch seam, and quitting on it cost a capped provider 9-13
/// authenticated sessions per defer. Offline and shutdown shut the pool
/// itself, which the second half below pins.
#[tokio::test]
async fn both_exits_above_the_dial_park_their_unused_session() {
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
    assert!(done_before_dial(&cfg, &sc, &drained, 0, &mut held).await);
    assert!(held.is_none(), "the claimed connection was handed on");
    assert_eq!(
        warm.stats.parked.load(Ordering::Relaxed),
        1,
        "a drained worker's validated session goes back to the pool"
    );

    // Abort: same claimed connection, same answer. A defer and a job
    // switch both arrive as this flag, and the session is as reusable
    // here as it was above.
    let (aborted, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    aborted.aborted.store(true, Ordering::Release);
    let (c, _) = Connection::connect(&sc).await.expect("dial the mock");
    let mut held = Some(c);
    assert!(done_before_dial(&cfg, &sc, &aborted, 0, &mut held).await);
    assert!(held.is_none());
    assert_eq!(
        warm.stats.parked.load(Ordering::Relaxed),
        2,
        "an abort keeps its drained session too - stopping a job is not \
         releasing the account"
    );

    // And releasing the account for real still closes, through the
    // switch that means it. This is what makes the arm above safe: the
    // pool refuses the park and QUITs it, so no exit has to guess which
    // kind of abort it is looking at.
    warm.set_accepting(false);
    let (offline, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    offline.aborted.store(true, Ordering::Release);
    let (c, _) = Connection::connect(&sc).await.expect("dial the mock");
    let mut held = Some(c);
    assert!(done_before_dial(&cfg, &sc, &offline, 0, &mut held).await);
    assert_eq!(
        warm.stats.parked.load(Ordering::Relaxed),
        2,
        "a pool that has gone offline takes no more parks"
    );
}

/// §96.5, and the one thing `drained` does not settle: an abort exit
/// must NOT hand its session on when the prepaid block that paid for it
/// is spent.
///
/// The rule is `release_shed_conn`'s, from `9b442b1ce` - `over_budget`
/// latches for the run, and the daemon's runner rules a spent host out
/// of the NEXT job's pool outright, so a session parked there is a
/// provider slot held for a job that will never take it. That commit
/// gave it to the shed and left `stand_down` asking only
/// `inflight.is_empty()`, and the two are not merely inconsistent on
/// paper: the inner loop reads the abort flag BEFORE it reaches the
/// shed, so a worker whose pipeline drains in the same pass a sibling's
/// bytes push the fleet over budget arrives at the abort exit, not the
/// shed, and parked. One slot per racing worker, held against a capped
/// account until the 300 s idle reap (v1.2.4 sweep, finding R3).
///
/// Driven at the exits rather than through a fleet ON PURPOSE. That
/// race is a race - inside the pool the shed handles every worker whose
/// pipeline empties a pass later, so a whole-fleet rig would be pinning
/// its own timing rather than the rule. The three exits below are every
/// door a leaving worker can put a drained session through with the
/// budget latched, and each is asked directly.
///
/// The A/B is what makes it an assertion and not an accident: the SAME
/// call, on a run with no block, must still park - `over_budget` is
/// false for every server without one, which is every server on an
/// unmetered account and every server on a CLI run.
#[tokio::test]
async fn an_abort_exit_does_not_park_a_session_on_a_spent_block() {
    let srv = MockServer::start(std::collections::HashMap::new(), Chaos::default()).await;
    let sc = srv.server_config();
    let warm = WarmPool::new(Duration::from_secs(60), 8);
    let cfg = PoolConfig {
        warm: Some(warm.clone()),
        ..Default::default()
    };
    // A server carrying a prepaid block, and a run that has spent it.
    let spent_cfg = PoolConfig {
        budget_bytes: Some(1_000),
        ..cfg.clone()
    };
    let spent_servers = vec![(server("s"), spent_cfg)];
    let (spent, _) = Shared::new(fresh(&["<a@x>"]), &spent_servers);
    spent.bytes[0].store(1_000, Ordering::Relaxed);
    assert!(
        spent.over_budget(0),
        "the fixture must actually be over its block, or every arm below          passes for the wrong reason"
    );
    // The same run without a block, which is every unmetered server.
    let open_servers = vec![(server("s"), cfg.clone())];
    let (open, _) = Shared::new(fresh(&["<a@x>"]), &open_servers);
    assert!(!open.over_budget(0), "no block configured, no budget");

    let dial = async || Connection::connect(&sc).await.expect("dial the mock").0;

    // 1. The session loop's own abort exit, drained. THE finding.
    stand_down(&cfg, &sc, &spent, 0, dial().await, true).await;
    assert_eq!(
        warm.stats.parked.load(Ordering::Relaxed),
        0,
        "an abort must not park a drained session on a host whose block          is spent - the shed already quits one, and the abort flag is          read first"
    );
    stand_down(&cfg, &sc, &open, 0, dial().await, true).await;
    assert_eq!(
        warm.stats.parked.load(Ordering::Relaxed),
        1,
        "and the 25-26 Aug rule is untouched where there is no block: a          drained session still goes back to the pool"
    );

    // 2. The abort exit ABOVE the dial, holding a preclaimed session.
    let mut held = Some(dial().await);
    spent.aborted.store(true, Ordering::Release);
    assert!(done_before_dial(&cfg, &sc, &spent, 0, &mut held).await);
    assert!(held.is_none(), "the claimed connection was disposed of");
    assert_eq!(
        warm.stats.parked.load(Ordering::Relaxed),
        1,
        "the pre-dial abort exit asks the same question - it is reached          with the budget latched whenever the block runs out inside          `pre_dial_gates`' own awaits"
    );

    // 3. The queue-dry exit above the dial, which is the same door one
    //    flag earlier and must not be the one that leaks the slot.
    let dry_servers = vec![(
        server("s"),
        PoolConfig {
            budget_bytes: Some(1_000),
            ..cfg.clone()
        },
    )];
    let (dry, _) = Shared::new(Vec::new(), &dry_servers);
    dry.bytes[0].store(1_000, Ordering::Relaxed);
    let mut held = Some(dial().await);
    assert!(done_before_dial(&cfg, &sc, &dry, 0, &mut held).await);
    assert_eq!(
        warm.stats.parked.load(Ordering::Relaxed),
        1,
        "a queue that emptied under a spent block is still a spent block"
    );
}

/// The seam the 25-26 Aug 2026 incident is actually about, driven as a
/// whole fleet: a run is aborted mid-flight and the workers that were
/// IDLE at that moment keep their authenticated sessions.
///
/// One article and four connections builds that population on purpose,
/// because it is the population a defer finds: the watchdog fires when a
/// provider has nothing fetchable for the job, so its workers are idle
/// by definition - the same sockets `idle_turn`'s keepalive probe was
/// added for. Before this, every one of them was quit and redialled
/// seconds later, which against a per-account session cap is a dial
/// storm into a wall the storm keeps up.
///
/// The far-end proof is the checkout at the end, and it is a stronger
/// claim than counting sockets: `take` sends a DATE and requires the
/// answer, so a session that comes back out is one the provider still
/// has, still authenticated, and the next job can put a BODY on
/// immediately.
///
/// What the fourth worker pins, and what it does not. It is holding an
/// unread BODY response, so it must close - and it does, but through the
/// READ-side exit rather than the loop-top one: `abort` sends `finished`
/// too, and a worker parked in `read_one` breaks out there and quits
/// with `release_wire`. So the `inflight.is_empty()` guard at the loop
/// top is a belt for the same rule and not what this run walks; removing
/// it leaves this test green. It stays because the rule it enforces is
/// the pool's own - a socket with responses on it is reusable by nobody
/// - and the loop top is reachable with a pipeline still on the wire
/// whenever the flag is read before the next response is.
#[tokio::test(flavor = "multi_thread")]
async fn an_aborted_run_keeps_the_sessions_its_idle_workers_held() {
    const CONNS: usize = 4;
    let mut articles = std::collections::HashMap::new();
    let payload: Vec<u8> = (0..64_000u32).map(|i| i as u8).collect();
    make_file_articles("abort.bin", &payload, 64_000, "ab", &mut articles);
    let ids: Vec<ArticleReq> = articles
        .keys()
        .map(|k| ArticleReq::fresh(k.as_str()))
        .collect();
    let srv = MockServer::start(
        articles,
        Chaos {
            // Long enough that the one fetching worker is still holding
            // its response when the abort lands, so this pins BOTH
            // halves of the rule with one run.
            delay_ms: 60_000,
            ..Default::default()
        },
    )
    .await;
    let warm = WarmPool::new(Duration::from_secs(60), 8);
    let mut sc = srv.server_config();
    sc.connections = CONNS as u32;
    let cfg = PoolConfig {
        connections: CONNS,
        window: 1,
        ramp_delay: Duration::from_millis(0),
        warm: Some(warm.clone()),
        ..Default::default()
    };
    let servers = vec![(sc.clone(), cfg)];
    let ctl = Arc::new(QueueControl::default());
    let (tx, mut rx) = mpsc::channel(16);
    let ctl_fetch = ctl.clone();
    let fetch =
        tokio::spawn(async move { fetch_all_multi_ctl(&servers, ids, tx, Some(&ctl_fetch)).await });
    let drain = tokio::spawn(async move { while rx.recv().await.is_some() {} });

    // Let the fleet dial and settle: one worker takes the article, the
    // other three find the queue dry with work still pending and idle.
    for _ in 0..200 {
        if srv.conns_open() >= CONNS {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(
        srv.conns_open(),
        CONNS,
        "the fleet must be up before the abort, or this proves nothing"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(ctl.abort(), "the run was still live to abort");
    tokio::time::timeout(Duration::from_secs(30), fetch)
        .await
        .expect("an aborted run must return promptly")
        .expect("the fetch task");
    drain.await.expect("the collector");

    assert_eq!(
        warm.idle_count().await,
        CONNS - 1,
        "the {} idle workers parked their sessions; the one holding an \
         unread response could not, and quit",
        CONNS - 1
    );
    assert_eq!(
        srv.accepted.load(Ordering::Relaxed) as usize,
        CONNS,
        "and nothing redialled: the whole point is that the next job \
         starts on these instead of dialling the account again"
    );
    assert_eq!(
        warm.stats.parked.load(Ordering::Relaxed) as usize,
        CONNS - 1,
        "parked, not merely forgotten"
    );
    let reused = warm.take(&sc).await;
    assert!(
        reused.is_some(),
        "a parked session must still be the provider's - `take` validates \
         it with a DATE, so this is the far end agreeing"
    );
    if let Some(c) = reused {
        c.quit().await;
    }
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
/// F-22's SECOND half, and the one that hangs a default-on job: the
/// single-prober election must count the workers that can actually
/// DIAL, not every worker that happens to be alive.
///
/// Under a live target most of a fleet is parked in `wait_for_slot`,
/// upstream of this election, waiting for an admission that only rises
/// when bytes arrive - and every one of them is still counted in
/// `alive`. So the sole ADMITTED worker, the only one that can dial at
/// all, reaches a capacity episode, reads `alive = 8`, and yields:
/// eight alive workers look like plenty to leave someone behind. Nobody
/// is left behind. Nothing publishes `Probing`, no verdict is ever
/// reached, the parked seven never wake, and the run neither recovers
/// nor seals - `pending > 0`, `workers_live > 0`, `finished` silent,
/// which is the hang the audit reported against a DEFAULT-ON line cap.
///
/// Both directions, because refusing every yield is the opposite bug:
/// with no live target every alive worker can dial, the electorate is
/// `alive` again, and a fleet of eight must still be able to park seven
/// of itself behind one prober.
///
/// Draining is set in both halves purely to make the question
/// terminate: the park loop polls `draining` at the top of every pass,
/// BEFORE it can ever publish an episode, so a worker that parks leaves
/// promptly and silently while a worker that probes has already
/// published `Probing` on its way past.
#[tokio::test]
async fn the_prober_election_counts_admitted_workers_not_parked_ones() {
    let servers = vec![(server("s"), PoolConfig::default())];
    let ctx = ctx_for(&servers, 0);

    // Eight workers spawned against a live target that admits one.
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    sh.alive[0].store(8, Ordering::SeqCst);
    sh.admitted[0].store(1, Ordering::SeqCst);
    sh.draining.store(true, Ordering::Release);
    let cfg = PoolConfig {
        live_target: Some(ConnTarget::new(1)),
        connect_backoff: Duration::from_millis(1),
        ..Default::default()
    };
    let mut finished = sh.finished.subscribe();
    let (mut bounces, mut fails) = (0u32, 0u32);
    let _ = park_or_probe(&cfg, ctx, &sh, &mut finished, &mut bounces, &mut fails).await;
    assert_eq!(
        sh.auth[0].yielded.load(Ordering::SeqCst),
        0,
        "the one worker that can dial must not yield - the other seven \
         are parked on an admission and can never take the ladder"
    );
    assert!(
        matches!(*sh.auth[0].episode.borrow(), (CapEpisode::Probing, _)),
        "so it elects itself prober and opens the episode"
    );

    // The bound. Same eight-strong fleet, same single admission on the
    // counter, and NO live target: admission is not gating anyone, so
    // the electorate is `alive` and seven may still park behind one.
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    sh.alive[0].store(8, Ordering::SeqCst);
    sh.admitted[0].store(1, Ordering::SeqCst);
    sh.draining.store(true, Ordering::Release);
    let cfg = PoolConfig {
        connect_backoff: Duration::from_millis(1),
        ..Default::default()
    };
    let mut finished = sh.finished.subscribe();
    let (mut bounces, mut fails) = (0u32, 0u32);
    let step = park_or_probe(&cfg, ctx, &sh, &mut finished, &mut bounces, &mut fails).await;
    assert!(
        matches!(step, DialStep::Quit),
        "the drain releases the parked worker"
    );
    assert_eq!(
        sh.auth[0].yielded.load(Ordering::SeqCst),
        1,
        "with no live target a fleet of eight may still park behind \
         one prober - the admission counter is not the electorate here"
    );
    assert!(
        matches!(*sh.auth[0].episode.borrow(), (CapEpisode::Idle, _)),
        "and a worker that parked published nothing"
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
        PooledBuf::unpooled(Vec::new()),
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
        PooledBuf::unpooled(Vec::new()),
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

/// TODO 315, 29 Aug 2026: a duplicate's authoritative 430 must not
/// stamp its bit back onto a queued article whose LATE RE-ASK is
/// holding that same bit down.
///
/// `handle_missing` clears the re-asked group's bit precisely so the
/// requeued item is not live-unanimous while it waits. The dup fold
/// found the queued copy and OR'd the bit straight back in, which
/// terminalized the article on evidence the hold was bought to doubt -
/// and left the budget slot held by a `Work` nothing would release,
/// because the queued item is then removed by `next_work`'s unservable
/// scan rather than by either verdict arm. The dup is not the delayed
/// ask: it was already in flight when the hold was taken, so its
/// refusal is the very evidence the hold exists to re-test.
#[tokio::test]
async fn a_duplicate_does_not_spend_a_queued_articles_held_re_ask() {
    let servers = vec![(server("s"), PoolConfig::default())];
    let cfg = PoolConfig {
        recheck_430: true,
        ..Default::default()
    };
    let (sh, _) = Shared::new(fresh(&["<h@x>"]), &servers);
    let ctx = ctx_for(&servers, 0);
    sh.alive[0].store(1, Ordering::SeqCst);
    // The shape `handle_missing` leaves behind when it takes the hold:
    // the group's bit remembered in `recheck_430` and cleared out of
    // `tried_430`, the item back in the queue waiting to be re-asked.
    {
        let mut q = sh.queue.lock().await;
        let w = q.front_mut().unwrap();
        assert!(sh.take_recheck(w, &cfg, ctx.group_bits));
        w.tried_430 &= !ctx.group_bits;
    }
    let (tx, mut rx) = mpsc::channel(8);
    let mut dup = work("<h@x>");
    dup.dup = true;
    let mut inflight: VecDeque<Work> = [dup].into_iter().collect();
    sh.charge_wire();
    let mut bare: VecDeque<Arc<str>> = VecDeque::new();
    handle_missing(
        &cfg,
        ctx,
        &sh,
        &tx,
        &mut inflight,
        PooledBuf::unpooled(Vec::new()),
        true,
        false,
        &mut bare,
    )
    .await;
    assert!(
        rx.try_recv().is_err(),
        "the held re-ask has not happened yet - nothing here may end the article"
    );
    assert_eq!(sh.pending.load(Ordering::Acquire), 1);
    assert_eq!(
        sh.queue.lock().await.front().unwrap().tried_430 & ctx.group_bits,
        0,
        "the bit the hold cleared must stay clear until the re-ask is answered"
    );
    assert_eq!(
        sh.recheck_held.load(Ordering::Acquire),
        1,
        "and the slot is still legitimately held by an article still in the queue"
    );
}

/// 27 Aug sweep finding 23: an un-echoed, unfenced dup 430 is dropped
/// as evidence AND gives the article its hedge budget back. It is a dup
/// dying without a verdict, exactly like a shed or a connection death
/// (26 Aug #13), and leaving `dups` charged bars every later stale/TTFB
/// rescue for the rest of the article's life.
#[tokio::test]
async fn an_unproven_dup_refusal_returns_the_hedge_budget() {
    let servers = vec![(server("s"), PoolConfig::default())];
    let cfg = PoolConfig::default();
    let (sh, _) = Shared::new(fresh(&["<u@x>"]), &servers);
    let ctx = ctx_for(&servers, 0);
    sh.alive[0].store(1, Ordering::SeqCst);
    let (tx, mut rx) = mpsc::channel(8);
    let original = work("<u@x>");
    sh.register_inflight(&original, 0);
    // The hedge was spent at pick time.
    sh.inflight
        .lock_ok()
        .get_mut("<u@x>")
        .expect("inflight")
        .dups = 1;
    let mut w = work("<u@x>");
    w.dup = true;
    let mut inflight: VecDeque<Work> = [w].into_iter().collect();
    sh.charge_wire();
    let mut bare: VecDeque<Arc<str>> = VecDeque::new();
    handle_missing(
        &cfg,
        ctx,
        &sh,
        &tx,
        &mut inflight,
        PooledBuf::unpooled(Vec::new()),
        false,
        false,
        &mut bare,
    )
    .await;
    assert!(rx.try_recv().is_err(), "a bare dup refusal decides nothing");
    let inf = sh.inflight.lock_ok();
    let entry = inf.get("<u@x>").expect("original still out reading");
    assert_eq!(entry.dups, 0, "the unspent rescue comes back");
    assert_eq!(
        entry.tried_430, 0,
        "and the do-not-merge half stays: unproven evidence never reaches the mask"
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
    // TODO 315's late re-ask is OFF here: this test is about what a
    // TERMINAL verdict carries, and the re-ask puts one more hop in
    // front of the refusal that becomes terminal. Its own behaviour is
    // pinned in `pool::unit_tests::recheck_tests`.
    let cfg = PoolConfig {
        recheck_430: false,
        ..PoolConfig::default()
    };
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
            PooledBuf::unpooled(Vec::new()),
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
            PooledBuf::unpooled(Vec::new()),
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
        PooledBuf::unpooled(Vec::new()),
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
        PooledBuf::unpooled(vec![7u8; 4_096]),
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
        PooledBuf::unpooled(vec![1u8; 2_048]),
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
    // Taken from the pool, like the session loop's own, so the recycle
    // assertion below is about THIS allocation and not about whatever a
    // fresh take would have produced anyway.
    let mut losing = pool.take();
    losing.extend_from_slice(&[2u8; 2_048]);
    let losing_alloc = losing.as_ptr();
    handle_body(
        &cfg,
        ctx,
        &sh,
        &tx,
        &mut inflight,
        losing,
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
    assert_eq!(
        pool.take().as_ptr(),
        losing_alloc,
        "the losing copy's buffer went back to the pool, not to the allocator"
    );
}

// ---- The idle keepalive probe (25 Aug 2026 incident) ----------------
//
// A worker whose server has nothing fetchable for the job holds its
// connection in `idle_turn`'s 25 ms look-again loop and, before the
// probe, never touched the socket again: the provider's idle reaper
// FIN'd it, the socket sat in CLOSE_WAIT for the life of the job, and
// the conn gauge kept reporting it live (measured: nine such sockets to
// a backbone with 100% of the job's articles missing, whyslow conns 9 /
// reconnects 0). These three pin the probe's verdicts: a FIN'd socket
// and a black-holed one are Dead on the peer tally, a healthy one is
// kept and resets the quiet clock.

/// `server("s")` re-pointed at a real local address, for the tests that
/// dial one of the fake providers below.
fn at(addr: std::net::SocketAddr) -> ServerConfig {
    ServerConfig {
        host: addr.ip().to_string(),
        port: addr.port(),
        ..server("s")
    }
}

/// A provider that greets and immediately hangs up: the accept loop
/// writes the greeting and drops the socket, so the client ends up
/// holding a connection the peer has FIN'd - the state a provider's
/// idle reaper leaves behind, compressed to zero idle time.
fn greet_then_fin_provider() -> std::net::SocketAddr {
    use std::io::Write as _;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    std::thread::spawn(move || {
        while let Ok((mut s, _)) = listener.accept() {
            let _ = s.write_all(b"200 mock ready\r\n");
            let _ = s.flush();
            // Dropped here: FIN. The client keeps the socket.
        }
    });
    addr
}

/// A provider that greets and then never says another word, holding the
/// socket open - the NAT/CGNAT eviction shape the warm pool's validate
/// bound exists for, where the probe's write succeeds locally and the
/// answer never comes. Blocking std sockets on their own thread, so the
/// fake peer keeps working under a paused test clock.
fn greet_then_mute_provider() -> std::net::SocketAddr {
    use std::io::Write as _;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    std::thread::spawn(move || {
        let mut held = Vec::new();
        while let Ok((mut s, _)) = listener.accept() {
            let _ = s.write_all(b"200 mock ready\r\n");
            let _ = s.flush();
            held.push(s); // open forever, mute forever
        }
    });
    addr
}

/// A quiet clock already past the keepalive interval, so the very next
/// idle turn is due to probe.
fn probe_due() -> Instant {
    Instant::now()
        .checked_sub(crate::warmpool::KEEPALIVE_EVERY)
        .expect("the monotonic clock is older than one keepalive interval")
}

/// The probe finds the peer gone: the verdict is Dead, tallied as a
/// `peer` session end, and the caller (not this helper) redials. This is
/// the CLOSE_WAIT shape itself: without the probe this exact call
/// returned `Keep` every 25 ms forever.
#[tokio::test]
async fn an_idle_probe_reaps_a_socket_the_peer_closed() {
    let sc = at(greet_then_fin_provider());
    let servers = vec![(server("s"), PoolConfig::default())];
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    let cfg = PoolConfig::default();
    let ctx = ctx_for(&servers, 0);
    let (conn, _) = Connection::connect(&sc)
        .await
        .expect("dial the fake provider");
    let mut quiet = probe_due();
    match idle_turn(&cfg, &sc, ctx, &sh, conn, &mut quiet).await {
        IdleTurn::Dead => {}
        IdleTurn::Keep(_) => panic!("a FIN'd idle socket was kept as a live connection"),
        IdleTurn::Retire => panic!("a FIN'd idle socket was parked or quit instead of reported"),
    }
    assert_eq!(
        sh.session_ends(0).peer,
        1,
        "the provider hung up on us: that is a peer-flavoured session end"
    );
}

/// A black-holed idle socket (no FIN, no RST, no answer) is condemned at
/// the warm pool's validate bound, not the 60 s command timeout - and
/// certainly not never. Paused clock: the probe parks on IO, so tokio
/// auto-advances straight to the deadline and the test spends no real
/// time waiting.
#[tokio::test]
async fn a_black_holed_idle_socket_is_condemned_at_the_validate_bound() {
    let sc = at(greet_then_mute_provider());
    let servers = vec![(server("s"), PoolConfig::default())];
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    let cfg = PoolConfig::default();
    let ctx = ctx_for(&servers, 0);
    // The connect needs the real clock to complete; only then pause.
    let (conn, _) = Connection::connect(&sc)
        .await
        .expect("dial the fake provider");
    tokio::time::pause();
    let t0 = tokio::time::Instant::now();
    let mut quiet = probe_due();
    match idle_turn(&cfg, &sc, ctx, &sh, conn, &mut quiet).await {
        IdleTurn::Dead => {}
        IdleTurn::Keep(_) => panic!("a black-holed idle socket was kept as a live connection"),
        IdleTurn::Retire => panic!("a black-holed idle socket was parked instead of reported"),
    }
    assert!(
        t0.elapsed() < Duration::from_secs(30),
        "the probe waited {:?}: it must give up at the validate bound, not the \
         command timeout",
        t0.elapsed()
    );
    assert_eq!(sh.session_ends(0).peer, 1);
}

/// A healthy idle socket answers the probe: the worker keeps it, the
/// quiet clock resets (so the next probe is a full interval away, not
/// due again on the next 25 ms turn), and nothing is tallied as a death.
/// DATE also resets the provider's own idle clock, which is what lets a
/// held session survive a job-long wait instead of being reaped and
/// redialled against a per-account connection cap.
#[tokio::test]
async fn an_idle_probe_keeps_a_live_socket_and_resets_the_clock() {
    let srv = MockServer::start(Default::default(), Chaos::default()).await;
    let sc = srv.server_config();
    let servers = vec![(server("s"), PoolConfig::default())];
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    let cfg = PoolConfig::default();
    let ctx = ctx_for(&servers, 0);
    let (conn, _) = Connection::connect(&sc).await.expect("dial the mock");
    let mut quiet = probe_due();
    match idle_turn(&cfg, &sc, ctx, &sh, conn, &mut quiet).await {
        IdleTurn::Keep(c) => c.quit().await,
        IdleTurn::Dead => panic!("a live socket was reported dead"),
        IdleTurn::Retire => panic!("a live socket was parked with work still pending"),
    }
    assert!(
        quiet.elapsed() < crate::warmpool::KEEPALIVE_EVERY,
        "the successful probe resets the quiet clock"
    );
    assert_eq!(
        sh.session_ends(0).peer,
        0,
        "a survived probe is not a death"
    );
}

/// The other half of the seam `an_aborted_run_keeps_the_sessions_its_idle_workers_held`
/// pins, and the half no abort can reach: a BUSY fleet.
///
/// `8cda45132` made the abort exit park a DRAINED connection, and a
/// drained worker is one with an empty pipeline - the whole population
/// of the defer watchdog's capacity arm, whose workers are idle by
/// definition because the server has nothing fetchable. It is none of
/// the population of the `share >= 0.90` arm, whose top server is busy
/// and fast by the arm's own predicate: those workers are mid-BODY when
/// the flag lands, they exit through the read side with an unread
/// response on the wire, and every one of them is CORRECTLY quit - a
/// socket with a response queued on it is reusable by nobody.
///
/// So the only way to keep that fleet is to let the responses land,
/// which is what `drain` is. This drives one rig both ways at the same
/// instant and asserts the contrast rather than either half alone,
/// because the claim is comparative: the abort keeps NONE of a busy
/// fleet and the drain keeps ALL of it.
///
/// 200 articles against 4 connections at a 60 ms body delay puts every
/// worker mid-body with a full window behind it, which is what makes
/// the abort arm's zero a fact about the pipeline and not about timing.
/// Measured 26 Aug 2026 on this rig: the abort returned in 7 ms and the
/// drain in 129 ms - the cost of keeping the fleet is the pipeline's
/// own drain time, and the grace `serve::tasks::stall` bounds it with
/// carries that table.
#[tokio::test(flavor = "multi_thread")]
async fn a_drained_run_keeps_the_sessions_its_busy_workers_held() {
    async fn run(drain_not_abort: bool) -> (usize, usize) {
        const CONNS: usize = 4;
        let mut articles = std::collections::HashMap::new();
        let payload: Vec<u8> = (0..64_000u32).map(|i| i as u8).collect();
        for i in 0..200 {
            make_file_articles(
                &format!("busy{i}.bin"),
                &payload,
                64_000,
                &format!("b{i}"),
                &mut articles,
            );
        }
        let ids: Vec<ArticleReq> = articles
            .keys()
            .map(|k| ArticleReq::fresh(k.as_str()))
            .collect();
        let srv = MockServer::start(
            articles,
            Chaos {
                // Every worker is mid-body when the verb lands, and no
                // read is anywhere near the pre-byte budget.
                delay_ms: 60,
                ..Default::default()
            },
        )
        .await;
        let warm = WarmPool::new(Duration::from_secs(60), 8);
        let mut sc = srv.server_config();
        sc.connections = CONNS as u32;
        let cfg = PoolConfig {
            connections: CONNS,
            window: 3,
            ramp_delay: Duration::from_millis(0),
            warm: Some(warm.clone()),
            // What the daemon runs, and it is the ladder that bounds a
            // drain against a peer that has stopped answering.
            adaptive_timeout: true,
            ..Default::default()
        };
        let servers = vec![(sc.clone(), cfg)];
        let ctl = Arc::new(QueueControl::default());
        let (tx, mut rx) = mpsc::channel(64);
        let ctl_fetch = ctl.clone();
        let fetch =
            tokio::spawn(
                async move { fetch_all_multi_ctl(&servers, ids, tx, Some(&ctl_fetch)).await },
            );
        let collector = tokio::spawn(async move { while rx.recv().await.is_some() {} });
        for _ in 0..400 {
            if srv.conns_open() >= CONNS {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(srv.conns_open(), CONNS, "the fleet must be up first");
        // Long enough that every worker has a full window on the wire -
        // without it the contrast could be about a worker that happened
        // to be between articles rather than about the pipeline.
        tokio::time::sleep(Duration::from_millis(400)).await;

        if drain_not_abort {
            assert!(ctl.drain(), "the run was still live to drain");
        } else {
            assert!(ctl.abort(), "the run was still live to abort");
        }
        tokio::time::timeout(Duration::from_secs(60), fetch)
            .await
            .expect("neither verb may hang the fetch")
            .expect("the fetch task");
        collector.await.expect("the collector");
        (
            warm.idle_count().await,
            srv.accepted.load(Ordering::Relaxed) as usize,
        )
    }

    let (aborted_parks, aborted_dials) = run(false).await;
    let (drained_parks, drained_dials) = run(true).await;
    assert_eq!(
        aborted_parks, 0,
        "an abort of a BUSY fleet keeps nothing: every worker is holding \
         an unread response, and that socket is reusable by nobody"
    );
    assert_eq!(
        drained_parks, 4,
        "a drain lets those responses land, so every worker reaches the \
         pool's own reuse point with an empty pipeline and parks"
    );
    assert_eq!(
        (aborted_dials, drained_dials),
        (4, 4),
        "neither verb may redial: the whole point is that the sessions \
         the fleet already holds are what the next job starts on"
    );
}

// ---- The fetch->decode channel's memory-floor charge -----------------
//
// `PoolConfig::channel_gauge` charges a body's capacity when it enters
// the outcome channel and the CONSUMER's drain releases it, so the pair
// spans a channel and two crates and cannot be one guard. What can be a
// guard is the sender's half, which had three exits and two of them had
// to remember a release by hand: the charge is a `memgauge::Charge`, so
// a send that never lands simply drops it, and only the DELIVERED path
// acts - handing the charge on to the drain that will release it.
//
// Both take `one_gauge_test_at_a_time()` FIRST so it drops LAST:
// `Sub::Channel` is one process-global counter.

// Not `#[tokio::test]`: the serializer is a std `MutexGuard` and has to
// span the whole test, which `clippy::await_holding_lock` refuses inside
// an async fn - rightly, in production. Driving the runtime by hand puts
// the awaits inside `block_on` instead, where the guard is an ordinary
// synchronous hold.
#[test]
fn a_delivered_body_hands_its_channel_charge_to_the_consumer() {
    let _g = crate::memgauge::one_gauge_test_at_a_time();
    crate::memgauge::reset_for_tests();
    use crate::memgauge::{Sub, cur};
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    let servers = vec![(server("s"), PoolConfig::default())];
    let cfg = PoolConfig {
        channel_gauge: Some(Sub::Channel),
        ..Default::default()
    };
    let (sh, _) = Shared::new(fresh(&["<w@x>"]), &servers);
    let ctx = ctx_for(&servers, 0);
    let (tx, mut rx) = mpsc::channel(4);
    let mut inflight: VecDeque<Work> = [work("<w@x>")].into_iter().collect();
    sh.charge_wire();
    let (mut losses, mut bytes) = (0u32, 0u64);
    let body = PooledBuf::unpooled(vec![3u8; 2_048]);
    let charged = body.capacity() as u64;
    rt.block_on(handle_body(
        &cfg,
        ctx,
        &sh,
        &tx,
        &mut inflight,
        body,
        &mut losses,
        &mut bytes,
        Instant::now(),
    ));
    assert!(matches!(rx.try_recv(), Ok(FetchOutcome::Done { .. })));
    assert_eq!(
        cur(Sub::Channel),
        charged,
        "the charge survives the send - the consumer's drain owns it now"
    );
}

#[test]
fn a_body_that_never_entered_the_channel_releases_its_charge() {
    let _g = crate::memgauge::one_gauge_test_at_a_time();
    crate::memgauge::reset_for_tests();
    use crate::memgauge::{Sub, cur};
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    let servers = vec![(server("s"), PoolConfig::default())];
    let cfg = PoolConfig {
        channel_gauge: Some(Sub::Channel),
        ..Default::default()
    };
    let (sh, _) = Shared::new(fresh(&["<w@x>"]), &servers);
    let ctx = ctx_for(&servers, 0);
    let (tx, rx) = mpsc::channel(4);
    drop(rx); // the consumer is gone: try_send answers Closed
    let mut inflight: VecDeque<Work> = [work("<w@x>")].into_iter().collect();
    sh.charge_wire();
    let (mut losses, mut bytes) = (0u32, 0u64);
    rt.block_on(handle_body(
        &cfg,
        ctx,
        &sh,
        &tx,
        &mut inflight,
        PooledBuf::unpooled(vec![3u8; 2_048]),
        &mut losses,
        &mut bytes,
        Instant::now(),
    ));
    assert_eq!(
        cur(Sub::Channel),
        0,
        "an outcome that dropped at teardown must not leave the gauge charged"
    );
}

/// The session's own 430 path takes the same verdict the queue scan
/// does, so it must reach it the same way (27 Aug sweep finding 8).
/// Server b served for part of this run and then went out; server a's
/// refusal is now live-unanimous, which ENDS the article - nobody left
/// can fetch it and rotating it deadlocks the run - but it does not make
/// the article gone, because the server that might have held it was
/// never asked. The report says which of the two happened.
#[tokio::test]
async fn a_refusal_that_only_looks_unanimous_because_a_server_left_says_so() {
    let servers = vec![
        (server("a"), PoolConfig::default()),
        (server("b"), PoolConfig::default()),
    ];
    // TODO 315's late re-ask is OFF here: this test is about what a
    // TERMINAL verdict carries, and the re-ask puts one more hop in
    // front of the refusal that becomes terminal. Its own behaviour is
    // pinned in `pool::unit_tests::recheck_tests`.
    let cfg = PoolConfig {
        recheck_430: false,
        ..PoolConfig::default()
    };
    let (sh, _) = Shared::new(fresh(&["<lost@x>"]), &servers);
    sh.connected[0].store(true, Ordering::SeqCst);
    sh.connected[1].store(true, Ordering::SeqCst);
    sh.alive[0].store(1, Ordering::SeqCst);
    // b's last worker has already left; it never saw this article.
    sh.alive[1].store(0, Ordering::SeqCst);
    let (tx, mut rx) = mpsc::channel(8);
    let mut bare: VecDeque<Arc<str>> = VecDeque::new();
    let w = sh.queue.lock().await.pop_front().expect("queued");
    let mut inflight: VecDeque<Work> = [w].into_iter().collect();
    sh.charge_wire();
    handle_missing(
        &cfg,
        ctx_for(&servers, 0),
        &sh,
        &tx,
        &mut inflight,
        PooledBuf::unpooled(Vec::new()),
        true,
        false,
        &mut bare,
    )
    .await;
    match rx.try_recv() {
        Ok(FetchOutcome::Missing { id, cause }) => {
            assert_eq!(&*id, "<lost@x>");
            assert_eq!(
                cause,
                MissingCause::Unasked {
                    takedown: false,
                    dark: 1
                },
                "one live refusal is not every participant's answer"
            );
        }
        other => panic!("expected a terminal Missing, got {other:?}"),
    }
    assert!(
        sh.queue.lock().await.is_empty(),
        "the article is still terminal - the fleet has nobody who could take it"
    );
}

/// The stated-cap dial gate, wired end to end (measured 29 Aug 2026 on
/// a live daemon; `pool/dialgate.rs`'s header carries the numbers).
/// A provider that names a CONNECTION cap has answered the question the
/// fleet keeps re-asking with eleven sockets at once, so the next dial
/// arms `dialgate::DialGate` and the rest of the fleet queues behind one
/// canary. The arithmetic and the permit itself are pinned in
/// `pool/dialgate/tests.rs`; what is pinned HERE is that the dial path
/// really consults them.
#[tokio::test]
async fn a_stated_connection_cap_arms_the_dial_gate() {
    let srv = MockServer::start(
        std::collections::HashMap::new(),
        Chaos {
            auth_rejected: true,
            // The live line, verbatim.
            auth_refusal_text: Some("502 connection limit (40) reached".into()),
            ..Default::default()
        },
    )
    .await;
    let mut sc = srv.server_config();
    sc.username = Some("u".into());
    sc.password = Some("p".into());
    let servers = vec![(sc.clone(), PoolConfig::default())];
    let cfg = PoolConfig {
        flap_cap_keepers: true,
        connect_backoff: Duration::from_millis(1),
        ..Default::default()
    };
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    sh.alive[0].store(1, Ordering::SeqCst);
    let ctx = ctx_for(&servers, 0);
    let mut finished = sh.finished.subscribe();
    let (connects, reconnects) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    let (mut fails, mut flap, mut bounces, mut ever, mut last_end) =
        (0u32, 0u32, 0u32, false, None);
    assert!(
        !sh.auth[0].dial.is_armed(),
        "nothing is serialised before the provider has said anything"
    );
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
    assert!(matches!(step, DialStep::Retry));
    assert!(
        sh.auth[0].dial.is_armed(),
        "a stated connection cap arms the gate"
    );
    let asked = srv.accepted.load(Ordering::Relaxed);

    // ...and now the fleet queues. Hold the permit the way a worker
    // mid-dial holds it, and send another worker at the same server: it
    // must not reach the wire at all.
    let held = sh.auth[0]
        .dial
        .canary(true)
        .expect("the gate hands out one permit");
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
    assert!(matches!(step, DialStep::Retry), "it waits and asks again");
    assert_eq!(
        srv.accepted.load(Ordering::Relaxed),
        asked,
        "a second socket while the canary is in flight IS the burst - \
         eleven of these landed inside one second on the live daemon"
    );
    assert_eq!(
        (fails, flap),
        (0, 1),
        "standing in the queue is neither a connect failure nor a bounce: \
         counting it would walk a polite worker into the prober election"
    );

    // The canary's dial ends, and the next worker probes for real.
    drop(held);
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
    assert!(matches!(step, DialStep::Retry));
    assert_eq!(
        srv.accepted.load(Ordering::Relaxed),
        asked + 1,
        "one canary at a time, but always one - a gate that let nobody \
         through would abandon a cap that later clears"
    );
}

/// A simultaneous-IP refusal must NOT arm it. That limit is about where
/// the account is used from, not how many sockets it grants, so
/// serialising dials would answer a question it never asked - the same
/// distinction `note_cap` already draws (Codex sweep 5, M9).
#[tokio::test]
async fn a_source_ip_cap_does_not_arm_the_dial_gate() {
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
    let cfg = PoolConfig {
        flap_cap_keepers: true,
        connect_backoff: Duration::from_millis(1),
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
        true,
        &mut last_end,
    )
    .await;
    assert!(matches!(step, DialStep::Retry));
    assert!(
        !sh.auth[0].dial.is_armed(),
        "an address cap counts machines, not sockets - one canary would \
         not make this host look like fewer of them"
    );
}

/// The other end of the latch: a GRANTED session is what stands the gate
/// down, and it has to be wired to the success arm or a cap that later
/// clears leaves the fleet serialised for the rest of the run.
#[tokio::test]
async fn a_granted_session_stands_the_dial_gate_down() {
    let srv = MockServer::start(std::collections::HashMap::new(), Chaos::default()).await;
    let sc = srv.server_config();
    let servers = vec![(sc.clone(), PoolConfig::default())];
    let cfg = PoolConfig {
        connect_backoff: Duration::from_millis(1),
        ..Default::default()
    };
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    let ctx = ctx_for(&servers, 0);
    let mut finished = sh.finished.subscribe();
    let (connects, reconnects) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    let (mut fails, mut flap, mut bounces, mut ever, mut last_end) =
        (0u32, 0u32, 0u32, false, None);
    // An earlier episode left the fleet serialised.
    sh.auth[0].dial.arm();
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
        matches!(step, DialStep::Conn(_)),
        "the mock grants a session"
    );
    assert!(
        !sh.auth[0].dial.is_armed(),
        "the cap has room again, so the fleet ramps back in"
    );
}
