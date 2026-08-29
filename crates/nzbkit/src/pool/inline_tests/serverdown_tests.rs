//! What the fleet does about a server that will NOT serve, split out of
//! `inline_tests` under the size gate (TODO 106).
//!
//! One currency: a server that refuses, dies, backs off, times out or
//! leaves, and the fleet's answer to it - yield connections rather than
//! hammer, pace the reconnects, bow out at the ceiling, and SEAL every
//! article on the way so downstream never reads a silence as "the
//! network said nothing". What stays next door in `inline_tests` is the
//! other half of the same file: how work is DISTRIBUTED across servers
//! that are serving - the retention masks, dedupe, the endgame dup
//! races and fan-out, wire-cap accounting, promotion/shed and drain.
//!
//! A child module of `inline_tests`, so `use super::*` reaches the
//! pool's privates through the parent exactly as it did inline.

use super::*;

/// A corpus's ids, bracketed and interned (R9) the way the fetch plan
/// does it - the pool API takes handles, and building them inline three
/// times cost this file more lines than its size-gate ceiling had.
fn bracketed(segs: &[(String, u64, u32)]) -> Vec<Arc<str>> {
    segs.iter()
        .map(|(id, ..)| Arc::from(format!("<{id}>")))
        .collect()
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
pub(in crate::pool) struct Metronome(tokio::task::JoinHandle<()>);

impl Metronome {
    pub(in crate::pool) fn start() -> Metronome {
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
