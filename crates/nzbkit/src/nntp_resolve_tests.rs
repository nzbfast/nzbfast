//! DNS fault families (TODO §129 3a).
//!
//! Four shapes the §111 campaign could not reach, because every fault
//! it raced happened after a TCP connection already existed:
//!
//! 1. a candidate list whose first address is dead,
//! 2. a resolver that answers slowly,
//! 3. a resolver that starts failing mid-run and later heals,
//! 4. mixed v4/v6 answers.
//!
//! The rig is `crate::mock::dns`: a hostname registry installed as the
//! process resolver once per binary. Every test here takes its own
//! `.invalid` hostname, so they stay independent under the default
//! parallel test runner even though the seam itself is process-wide.
//!
//! Family 1 found the item's real bug: without `NZBFAST_DIAL_RACE` the
//! dialer only ever tried `addrs[0]`, so one dead node in a provider's
//! A-record set failed the dial outright. `dial_in_order` is the fix
//! and `dead_first_candidate_still_connects` is its gate.

use crate::mock::dns;
use crate::nntp::*;
use crate::pool::{ArticleReq, FetchOutcome, PoolConfig, fetch_all_multi};
use std::collections::HashMap;

use std::time::{Duration, Instant};

/// A small corpus and the ids that fetch it.
fn corpus(tag: &str, bytes: u32, art: usize) -> (HashMap<String, Vec<u8>>, Vec<ArticleReq>) {
    let data: Vec<u8> = (0..bytes).map(|i| i as u8).collect();
    let mut articles = HashMap::new();
    let segs =
        crate::mock::make_file_articles(&format!("{tag}.bin"), &data, art, tag, &mut articles);
    let ids = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    (articles, ids)
}

/// A `ServerConfig` for `srv` reached through `host` instead of its
/// literal address - which is the whole point: only a hostname goes
/// through the resolver.
fn via_host(srv: &crate::mock::MockServer, host: &str, conns: u32) -> crate::config::ServerConfig {
    let mut sc = srv.server_config();
    sc.host = host.to_string();
    sc.connections = conns;
    sc
}

/// Test-shaped pool config: no ramp stagger and a short connect backoff
/// so a leg is seconds, not minutes.
fn quick_pool(conns: usize) -> PoolConfig {
    PoolConfig {
        connections: conns,
        ramp_delay: Duration::ZERO,
        connect_backoff: Duration::from_millis(100),
        read_timeout: Duration::from_secs(10),
        ..Default::default()
    }
}

/// Run one fetch and return (wall, articles completed).
async fn leg(
    servers: Vec<(crate::config::ServerConfig, PoolConfig)>,
    ids: Vec<ArticleReq>,
    bound: Duration,
) -> (Duration, usize) {
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let t0 = Instant::now();
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
    tokio::time::timeout(bound, fetch)
        .await
        .expect("leg hung past its bound")
        .unwrap();
    (t0.elapsed(), collect.await.unwrap())
}

// ---------------------------------------------------------------
// Family 1: dead-first candidate list
// ---------------------------------------------------------------

/// A mock on `[::1]` whose name resolves to a REFUSED v4 candidate
/// first and the live v6 one second. The IPv4-first sort guarantees the
/// dead address leads, and both candidates answer instantly on both
/// platforms - see `dns::refused_v4` for why the obvious
/// `127.0.0.2`-then-`127.0.0.1` version is a blackhole test on macOS.
async fn dead_first_mock(
    tag: &str,
    articles: HashMap<String, Vec<u8>>,
) -> (crate::mock::MockServer, String) {
    let srv = crate::mock::MockServer::start_bound(
        "[::1]:0",
        articles,
        HashMap::new(),
        Vec::new(),
        crate::mock::Chaos::default(),
    )
    .await;
    let host = dns::unique_host(tag);
    dns::shared()
        .zone(&host)
        .set_addrs(vec![dns::refused_v4(), dns::loopback_v6()]);
    (srv, host)
}

/// THE REGRESSION GATE for the §129 3a fix. The provider's name
/// resolves to a dead node followed by a live one - the ordinary shape
/// for a provider behind a DNS pool with a node out. Before the
/// candidate walk this failed every dial: the code returned
/// `one(addrs[0]).await` and never looked at `addrs[1]` unless the dark
/// `NZBFAST_DIAL_RACE` was set - a flag §129 3c has since priced out
/// and removed, precisely because this walk covers the shape.
#[tokio::test(flavor = "multi_thread")]
async fn dead_first_candidate_still_connects() {
    let (articles, _) = corpus("df", 1_000, 500);
    let (srv, host) = dead_first_mock("dead-first", articles).await;

    let sc = via_host(&srv, &host, 1);
    let t0 = Instant::now();
    let r = Connection::connect(&sc).await;
    assert!(
        r.is_ok(),
        "a dead first candidate must not fail the dial - the live \
         address behind it was never tried: {:?}",
        r.err()
    );
    assert!(
        t0.elapsed() < Duration::from_secs(5),
        "refused-then-live took {:?} - that is not a connect cost",
        t0.elapsed()
    );
}

/// The same shape at job scale: the download must complete, not merely
/// the first connect. Every worker redials through the same dead-first
/// list, so a fix that only worked once would show up here.
#[tokio::test(flavor = "multi_thread")]
async fn dead_first_candidate_completes_a_download() {
    let (articles, ids) = corpus("dfj", 200_000, 10_000);
    let want = ids.len();
    let (srv, host) = dead_first_mock("dead-first-job", articles).await;

    let servers = vec![(via_host(&srv, &host, 4), quick_pool(4))];
    let (wall, done) = leg(servers, ids, Duration::from_secs(60)).await;
    assert_eq!(done, want, "{done}/{want} articles after {wall:?}");
    assert!(
        wall < Duration::from_secs(20),
        "the dead candidate is being waited on, not walked past: {wall:?}"
    );
}

/// The blackhole variant: the first candidate swallows the SYN with no
/// RST, which is what a firewalled-off provider node actually does. The
/// dial must still reach the live address, and the cost must be a
/// CONNECT budget - each candidate gets an equal slice of
/// `CONNECT_TIMEOUT`, so the whole dial stays inside the same 20 s
/// `Connection::connect` already bounded it to.
///
/// Real time, and it costs the ~10 s it models: a paused clock cannot
/// run this leg. Auto-advance only fires when nothing is runnable, and
/// that is exactly the state the second candidate's loopback connect
/// sits in while its socket readiness is in flight - so the clock jumps
/// past `Connection::connect`'s own 20 s deadline and the dial "times
/// out" in microseconds of real time. The timer and the real socket
/// have to share one clock here.
#[tokio::test(flavor = "multi_thread")]
async fn a_blackholed_first_candidate_is_bounded_not_fatal() {
    let (articles, _) = corpus("bh", 1_000, 500);
    let srv = crate::mock::MockServer::start(articles, crate::mock::Chaos::default()).await;
    let host = dns::unique_host("blackhole-first");
    dns::shared()
        .zone(&host)
        .set_addrs(vec![dns::blackhole_v4(), srv.addr.ip()]);

    let sc = via_host(&srv, &host, 1);
    let t0 = Instant::now();
    let r = Connection::connect(&sc).await;
    assert!(
        r.is_ok(),
        "a blackholed first candidate must not fail the dial after \
         {:?}: {:?}",
        t0.elapsed(),
        r.err()
    );
    // The whole point of the per-candidate slice: the blackhole cannot
    // spend the budget the address behind it needs.
    assert!(
        t0.elapsed() < CONNECT_TIMEOUT,
        "the blackhole ate the whole connect budget: {:?}",
        t0.elapsed()
    );
}

/// The walk is bounded, not a scan: `MAX_DIAL_CANDIDATES` stops it.
///
/// Three refusing candidates followed by a blackhole that never answers
/// at all. If the cap holds, the dial ends on the third refusal and the
/// fourth address is never touched.
///
/// This asserted on the clock until 10 Aug 2026 - three refusals are
/// instant, so "the dial finished inside two seconds" meant "it did not
/// pay the blackhole's slice of CONNECT_TIMEOUT". It measured runner
/// load as much as the cap, and it failed the Windows job at 6.06 s
/// with the cap working perfectly. The dialer's invocation count is the
/// same proof with no clock in it, and it is how the positive case
/// (`dial_race_tests::the_walk_reaches_a_live_third_candidate`) has
/// always been stated. Synthetic addresses for the same reason that
/// file uses them: what is under test is which addresses the walk hands
/// to the dialer, not what a socket does with them.
#[tokio::test(start_paused = true)]
async fn the_candidate_walk_stops_at_the_cap() {
    use std::sync::{Arc, Mutex};

    // TEST-NET-1, one per candidate - the walk must be able to tell
    // them apart, so unlike the old resolver-fed version these are four
    // distinct addresses rather than one repeated.
    let cands: Vec<std::net::SocketAddr> = (1..=4)
        .map(|n| std::net::SocketAddr::from(([192, 0, 2, n], 119)))
        .collect();
    let blackhole = cands[3];

    let dialed = Arc::new(Mutex::new(Vec::new()));
    let seen = dialed.clone();
    let one = move |target: std::net::SocketAddr| {
        let dialed = dialed.clone();
        Box::pin(async move {
            dialed.lock().unwrap().push(target);
            if target == blackhole {
                // A hole swallows the SYN: no RST, no answer, ever.
                std::future::pending::<()>().await;
                unreachable!("the blackhole never answers");
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
            Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
        })
            as std::pin::Pin<
                Box<dyn std::future::Future<Output = std::io::Result<std::net::SocketAddr>> + Send>,
            >
    };

    let r = dial_in_order(&cands, one).await;
    assert!(r.is_err(), "an all-dead candidate list must not connect");
    let walked = seen.lock().unwrap().clone();
    // The literal three, NOT `MAX_DIAL_CANDIDATES` - an expectation
    // written in terms of the constant it is pinning moves with it, and
    // passes just as happily at a cap of four.
    assert_eq!(
        walked.as_slice(),
        &cands[..3],
        "the walk went past the cap and into the blackhole"
    );
}

// ---------------------------------------------------------------
// Family 2: slow resolver
// ---------------------------------------------------------------

/// A one-server fleet behind a resolver that takes seconds still
/// completes. The interesting failure this rules out is a wedge: a
/// resolve that outlives some inner deadline and leaves the worker
/// unable to ever start.
#[tokio::test(flavor = "multi_thread")]
async fn a_slow_resolver_does_not_wedge_a_one_server_fleet() {
    let (articles, ids) = corpus("slow1", 200_000, 10_000);
    let want = ids.len();
    let srv = crate::mock::MockServer::start(articles, crate::mock::Chaos::default()).await;
    let host = dns::unique_host("slow-solo");
    let zone = dns::shared().zone(&host);
    zone.set_addrs(vec![srv.addr.ip()]);
    // Under CONNECT_TIMEOUT (20 s) on purpose: resolution is inside
    // that budget, and a delay past it is a different test (the dial
    // times out, which is correct and already covered).
    zone.set_delay(Duration::from_secs(5));

    let servers = vec![(via_host(&srv, &host, 2), quick_pool(2))];
    let (wall, done) = leg(servers, ids, Duration::from_secs(60)).await;
    assert_eq!(done, want, "{done}/{want} articles after {wall:?}");
    assert!(
        wall >= Duration::from_secs(5),
        "the resolver delay never bit ({wall:?}) - rig broken"
    );
}

/// Two servers, one behind the slow resolver. The healthy server must
/// be serving while the slow one is still resolving - a fleet that
/// stalls behind one server's DNS is the wedge shape this family
/// exists to rule out.
#[tokio::test(flavor = "multi_thread")]
async fn a_slow_resolver_leaves_the_healthy_server_working() {
    let (arts_a, ids) = corpus("slow2", 400_000, 10_000);
    let want = ids.len();
    let arts_b = arts_a.clone();
    let slow = crate::mock::MockServer::start(arts_a, crate::mock::Chaos::default()).await;
    let fast = crate::mock::MockServer::start(arts_b, crate::mock::Chaos::default()).await;
    let host = dns::unique_host("slow-twin");
    let zone = dns::shared().zone(&host);
    zone.set_addrs(vec![slow.addr.ip()]);
    zone.set_delay(Duration::from_secs(5));

    let servers = vec![
        (via_host(&slow, &host, 2), quick_pool(2)),
        (fast.server_config(), quick_pool(2)),
    ];
    let served_early = {
        let fast_served = fast.served.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1_500)).await;
            fast_served.load(std::sync::atomic::Ordering::Relaxed)
        })
    };
    let (wall, done) = leg(servers, ids, Duration::from_secs(60)).await;
    let early = served_early.await.unwrap();
    assert_eq!(done, want, "{done}/{want} articles after {wall:?}");
    assert!(
        early > 0,
        "the healthy server served nothing in the first 1.5 s while its \
         twin was resolving - the fleet is serialized behind one \
         server's DNS"
    );
}

// ---------------------------------------------------------------
// Family 3: resolve failure mid-run
// ---------------------------------------------------------------

/// An established session is not a name: once a worker is connected,
/// DNS going dark must not touch it. The run completes on the sessions
/// it already had.
#[tokio::test(flavor = "multi_thread")]
async fn established_sessions_survive_a_resolver_going_dark() {
    let (articles, ids) = corpus("dark", 400_000, 10_000);
    let want = ids.len();
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
    let host = dns::unique_host("goes-dark");
    let zone = dns::shared().zone(&host);
    zone.set_addrs(vec![srv.addr.ip()]);

    let killer = {
        let zone = zone.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(400)).await;
            zone.set_fail("failed to lookup address information: nodename nor servname provided");
        })
    };
    let servers = vec![(via_host(&srv, &host, 2), quick_pool(2))];
    let (wall, done) = leg(servers, ids, Duration::from_secs(60)).await;
    killer.await.unwrap();
    assert_eq!(
        done, want,
        "{done}/{want} articles after {wall:?} - a resolver failure \
         killed sessions that were already connected"
    );
}

/// A resolver that fails every lookup must not become a hot loop: the
/// connect backoff has to pace the redials. The zone's call counter is
/// the measurement - whatever the client does on the wire, an
/// unbounded retry shows up here.
///
/// The bound is order-of-magnitude, per the §129 3c contract's
/// politeness rule: with a 100 ms backoff over a 2 s window a paced
/// dialer spends tens of lookups per worker, a hot loop spends
/// thousands.
#[tokio::test(flavor = "multi_thread")]
async fn a_failing_resolver_does_not_become_a_hot_loop() {
    let host = dns::unique_host("nxdomain");
    let zone = dns::shared().zone(&host);
    zone.set_fail("failed to lookup address information: nodename nor servname provided");

    let (articles, ids) = corpus("hot", 100_000, 10_000);
    let srv = crate::mock::MockServer::start(articles, crate::mock::Chaos::default()).await;
    let servers = vec![(via_host(&srv, &host, 3), quick_pool(3))];

    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let drain = tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let fetch = tokio::spawn(async move { fetch_all_multi(&servers, ids, tx).await });
    tokio::time::sleep(Duration::from_secs(2)).await;
    let calls = zone.calls();
    // The fleet gives up on a server whose every dial fails; whether it
    // has already done so by now is not what this asserts - so the run
    // is DROPPED here rather than waited out.
    //
    // It was waited out until 1 Sep 2026, and that wait was 28.4 s of
    // this test's 30.4 s (measured, `PROBE drain-wait` around this
    // line). Every measurement this test makes was already taken two
    // lines up: `calls` is sampled BEFORE, and both assertions below
    // read only `calls`. What the wait bought was the dial ladder
    // running its own pacing out against a name that never resolves,
    // with the result discarded - `let _ = timeout(60s, fetch).await`
    // threw away the join result, a panic inside the task included, so
    // it could not fail this test and was not an assertion in
    // disguise. Nothing is loosened by dropping it: the two `calls`
    // bounds are unchanged and the 2 s measurement window above is
    // untouched.
    fetch.abort();
    drain.abort();
    assert!(
        calls > 0,
        "the resolver was never asked - the rig host is not on the dial path"
    );
    assert!(
        calls < 400,
        "{calls} lookups in 2 s against a dead name - the dials are not \
         being paced"
    );
}

/// ...and when the resolver heals, the fleet picks it back up. A
/// backoff that gives up permanently would fail here, which is the
/// other half of "paced, not abandoned".
#[tokio::test(flavor = "multi_thread")]
async fn a_healed_resolver_is_picked_back_up() {
    let (articles, ids) = corpus("heal", 200_000, 10_000);
    let want = ids.len();
    let srv = crate::mock::MockServer::start(articles, crate::mock::Chaos::default()).await;
    let host = dns::unique_host("heals");
    let zone = dns::shared().zone(&host);
    zone.set_fail("failed to lookup address information: nodename nor servname provided");

    let addr = srv.addr.ip();
    let healer = {
        let zone = zone.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            zone.set_addrs(vec![addr]);
        })
    };
    // A longer backoff than `quick_pool`'s and more attempts than the
    // default 5: the point is that the fleet is still trying when the
    // name comes back, not how fast it re-dials.
    let cfg = PoolConfig {
        max_connect_attempts: 50,
        ..quick_pool(2)
    };
    let servers = vec![(via_host(&srv, &host, 2), cfg)];
    let (wall, done) = leg(servers, ids, Duration::from_secs(60)).await;
    healer.await.unwrap();
    assert_eq!(
        done, want,
        "{done}/{want} articles after {wall:?} - the fleet never came \
         back after the resolver healed"
    );
}

// ---------------------------------------------------------------
// Family 4: family mix
// ---------------------------------------------------------------

/// A v6-first answer whose v6 candidate is dead still connects. The
/// IPv4-first ORDER itself is pinned by `resolve::tests::
/// ipv4_sorts_ahead_of_ipv6` - with the candidate walk in place this
/// leg would connect either way, so it pins the outcome, not the sort.
#[tokio::test(flavor = "multi_thread")]
async fn a_v6_first_answer_with_a_dead_v6_still_connects() {
    let (articles, _) = corpus("mix", 1_000, 500);
    let srv = crate::mock::MockServer::start(articles, crate::mock::Chaos::default()).await;
    let host = dns::unique_host("family-mix");
    // ::1 is up on both platforms and nothing is listening on the
    // mock's port there, so the v6 candidate refuses rather than
    // blackholing - a deterministic dead node, same as 127.0.0.2.
    dns::shared()
        .zone(&host)
        .set_addrs(vec![dns::loopback_v6(), srv.addr.ip()]);

    let sc = via_host(&srv, &host, 1);
    let r = Connection::connect(&sc).await;
    assert!(
        r.is_ok(),
        "a mixed-family answer with a dead v6 must connect over v4: {:?}",
        r.err()
    );
}

/// bind_ip pins the family, and a v4-only answer under a v6 bind is a
/// configuration error, not a dial to attempt. Pins the user-facing
/// message end to end (the unit test pins the string; this pins that
/// the dial path is what emits it).
#[tokio::test(flavor = "multi_thread")]
async fn a_v6_bind_against_a_v4_only_answer_says_so() {
    let (articles, _) = corpus("bind6", 1_000, 500);
    let srv = crate::mock::MockServer::start(articles, crate::mock::Chaos::default()).await;
    let host = dns::unique_host("v4-only");
    dns::shared().zone(&host).set_addrs(vec![srv.addr.ip()]);

    let mut sc = via_host(&srv, &host, 1);
    sc.bind_ip = Some("::1".into());
    let err = match Connection::connect(&sc).await {
        Err(e) => e.to_string(),
        Ok(_) => panic!("a v6 bind against a v4-only answer must fail"),
    };
    assert!(
        err.contains("has no IPv6 address to match bind_ip"),
        "wrong message for a family mismatch: {err}"
    );
}

/// The complement: a v6 bind with a v6 answer dials v6, so the message
/// above is a real diagnosis and not just "v6 never works here".
#[tokio::test(flavor = "multi_thread")]
async fn a_v6_bind_against_a_v6_answer_connects() {
    let (articles, _) = corpus("bind6ok", 1_000, 500);
    let srv = crate::mock::MockServer::start_bound(
        "[::1]:0",
        articles,
        HashMap::new(),
        Vec::new(),
        crate::mock::Chaos::default(),
    )
    .await;
    let host = dns::unique_host("v6-only");
    dns::shared()
        .zone(&host)
        .set_addrs(vec![dns::loopback_v6(), dns::refused_v4()]);

    let mut sc = via_host(&srv, &host, 1);
    sc.bind_ip = Some("::1".into());
    let r = Connection::connect(&sc).await;
    assert!(
        r.is_ok(),
        "a v6 bind with a v6 answer must dial: {:?}",
        r.err()
    );
}
