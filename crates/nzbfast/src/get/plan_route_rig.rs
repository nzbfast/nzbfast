//! M29 `oracle_route`: the measured A/B the routing short-circuit
//! shipped without.
//!
//! The M29 milestone parked "oracle-driven routing short-circuit" as
//! hazardous on one argument: a stale oracle that vetoes a live
//! backbone silently loses completions. What unparked it is the guardrail in
//! [`super::demote_predicted_gone`] - the verdict may only REORDER the
//! level ladder, never remove a server, so article-level fallback stays
//! authoritative. That guardrail shipped, with unit tests over the level
//! ASSIGNMENT (`predicted_gone_servers_are_demoted_not_removed` and
//! friends), and nothing ever measured the two things the assignment is
//! a proxy for:
//!
//! 1. that the demotion actually BUYS something - the doomed round trips
//!    move to the end of the ladder instead of the front, and
//! 2. that a WRONG verdict costs only those round trips - the demoted
//!    server is still asked, and still completes the job, when it turns
//!    out to be the only one holding the bytes.
//!
//! (2) is the parked hazard itself, and it is the leg that has to exist
//! before "a wrong verdict costs only latency" is a measurement rather
//! than a claim about code that was read.
//!
//! ## The instrument
//!
//! [`MockServer::serve_counts`] is a per-message-id REQUEST ledger, and
//! its docstring is why it is the right one here: "a 430, a stalled
//! request and a served body are each one request, because each is one
//! round trip the client paid for". A doomed primary attempt IS one
//! entry in that map. `echo_missing_id` makes each 430 terminal on the
//! first ask, so the ledger is a fixed number rather than a race.
//!
//! ## The two-backbone trap, and why the hosts read oddly
//!
//! Verdicts are per BACKBONE, and `oracle::backbone_of` maps a bare
//! address to itself ("an address is its own spool") - so two mocks both
//! reached as `127.0.0.1` are ONE backbone, and writing off the doomed
//! one writes off the healthy one with it. The rig would then measure a
//! flat no-op and pass for the wrong reason. Distinct loopback addresses
//! (127.0.0.2) are not portable - macOS and Windows bind only .1 by
//! default. So the doomed server is addressed as `localhost`, which
//! `backbone_of` keeps as its own label and every platform resolves to
//! the same loopback the mock is on. Both legs assert the two backbones
//! really did come out distinct, because if that ever stops being true
//! the interesting half of this file silently stops running.

use super::*;
use nzbkit::mock::{Chaos, MockServer, Throttle, make_file_articles};
use nzbkit::oracle::{Snapshot, age_bucket, backbone_of};
use nzbkit::pool::{ArticleReq, FetchOutcome, PoolConfig, fetch_all_multi};

/// Enough articles that a per-article ladder decision is visible in the
/// ledger, few enough that the leg is a loopback second.
const ARTICLES: usize = 48;
const PART: usize = 4_096;
/// The release's group family and age. 20 days is bucket 2; the primed
/// cell has to name the SAME bucket or `backbone_gone` reads a blind
/// spot and the whole prior-informed leg quietly becomes the blind one.
const FAMILY: &str = "hdtv";
const AGE_DAYS: u32 = 20;

/// The doomed backbone is reached by name, the live one by address -
/// see the module header. Both are the same loopback interface.
const GONE_HOST: &str = "localhost";

/// One copy of the corpus, plus the request list. Each mock needs its
/// own map, so this is called per server.
fn corpus() -> (std::collections::HashMap<String, Vec<u8>>, Vec<ArticleReq>) {
    let data: Vec<u8> = (0..(ARTICLES * PART) as u32)
        .map(|i| (i >> 4) as u8)
        .collect();
    let mut articles = std::collections::HashMap::new();
    let segs = make_file_articles("rel.mkv", &data, PART, "orc", &mut articles);
    let reqs = segs
        .iter()
        .map(|(id, _, part)| ArticleReq {
            id: format!("<{id}>").into(),
            age_days: AGE_DAYS,
            part: *part,
            file: 0,
        })
        .collect();
    (articles, reqs)
}

/// A ledger that is confident this backbone is GONE for the release's
/// exact (family, bucket) cell - 3 hits in 100, well past MIN_SAMPLES
/// and under RED_HIGH.
fn ledger_writing_off(backbone: &str) -> Snapshot {
    let mut snap = Snapshot::default();
    snap.insert(backbone, FAMILY, age_bucket(AGE_DAYS), 3, 97);
    assert!(
        snap.backbone_gone(backbone, FAMILY, AGE_DAYS),
        "the primed cell must actually read as gone, or the informed leg is the blind one"
    );
    snap
}

/// The healthy server answers at a LINE rate rather than at loopback
/// speed, and that is what makes this rig measure the thing it claims
/// to. A reaped server refuses instantly, so on an unthrottled loopback
/// the healthy peer drains the shared FIFO before the reaped one can
/// claim much of it - the blind leg then pays 9 doomed round trips
/// rather than 48, and the saving reads as noise. That is not the
/// oracle being useless; it is the §109 finding restated (one shared
/// FIFO, workers self-clock, so a provider's share is already
/// proportional to what it delivers). On any real line the healthy
/// server is the slow one and the dead server claims the queue, which
/// is the shape this reproduces.
fn line_rate() -> Chaos {
    Chaos {
        throttle: Throttle {
            per_conn_bps: 200_000,
            ..Default::default()
        },
        ..Default::default()
    }
}

/// The daemon's decision path, verbatim: for each configured server, ask
/// the snapshot about its BACKBONE at this release's family and age, then
/// hand the hosts to the shipped demotion. Kept as one helper so the rig
/// exercises the real join rather than hand-assigned levels.
fn route(servers: &mut [ServerConfig], snap: &Snapshot) -> Vec<String> {
    let gone: Vec<String> = servers
        .iter()
        .filter(|s| snap.backbone_gone(&backbone_of(&s.host), FAMILY, AGE_DAYS))
        .map(|s| s.host.clone())
        .collect();
    super::demote_predicted_gone(servers, &gone, FAMILY, AGE_DAYS);
    gone
}

/// Run one leg through the real pool and return how many articles
/// completed. Per-server round trips are read off each mock's own
/// ledger by the caller.
async fn leg(servers: Vec<(ServerConfig, PoolConfig)>, reqs: Vec<ArticleReq>) -> usize {
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let fetch = tokio::spawn(async move { fetch_all_multi(&servers, reqs, tx).await });
    let collect = tokio::spawn(async move {
        let mut done = 0usize;
        while let Some(o) = rx.recv().await {
            if matches!(o, FetchOutcome::Done { .. }) {
                done += 1;
            }
        }
        done
    });
    tokio::time::timeout(std::time::Duration::from_secs(120), fetch)
        .await
        .expect("oracle-route leg hung")
        .unwrap();
    collect.await.unwrap()
}

/// Pair a mock with a pool config, at a caller-chosen level and host.
fn server_at(srv: &MockServer, host: &str, level: u32) -> (ServerConfig, PoolConfig) {
    let mut sc = srv.server_config();
    sc.host = host.to_string();
    sc.connections = 4;
    sc.level = level;
    (
        sc,
        PoolConfig {
            connections: 4,
            ramp_delay: std::time::Duration::from_millis(0),
            ..Default::default()
        },
    )
}

/// Total round trips this mock was asked to pay.
fn round_trips(srv: &MockServer) -> u64 {
    srv.serve_counts().values().sum()
}

/// **The A/B.** Both legs run the same 48-article release against the
/// same two servers - one backbone that has been reaped (holds nothing,
/// 430s everything) and one that is healthy. The only difference is
/// whether the availability ledger had ever heard of the reaped one.
///
/// Blind: the reaped primary is asked first for every article and refuses
/// every one, so the job pays 48 doomed round trips before the healthy
/// server sees the work. Prior-informed: the ledger's exact
/// (backbone, family, bucket) cell is red, the shipped demotion sinks
/// that server below the healthy one, and `required_mask` withholds it
/// until the healthy server has actually missed - which it never does.
///
/// Both legs must complete all 48. That is not decoration: it is half of
/// what makes the demotion safe to have unparked at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oracle_route_ab_moves_the_doomed_round_trips_off_the_front() {
    assert_ne!(
        backbone_of(GONE_HOST),
        backbone_of("127.0.0.1"),
        "the rig's two servers must be two BACKBONES or there is nothing to demote"
    );
    let (_, reqs) = corpus();

    // BLIND leg: no ledger, both servers primary.
    let (arts_live, _) = corpus();
    let reaped = MockServer::start(
        Default::default(),
        Chaos {
            echo_missing_id: true,
            ..Default::default()
        },
    )
    .await;
    let live = MockServer::start(arts_live, line_rate()).await;
    let mut blind = vec![
        server_at(&reaped, GONE_HOST, 0).0,
        server_at(&live, "127.0.0.1", 0).0,
    ];
    // No snapshot installed is the `oracle_route` off case: nothing is
    // consulted, so the ladder is exactly what the config said.
    assert!(route(&mut blind, &Snapshot::default()).is_empty());
    let blind_done = leg(
        vec![
            (blind[0].clone(), server_at(&reaped, GONE_HOST, 0).1),
            (blind[1].clone(), server_at(&live, "127.0.0.1", 0).1),
        ],
        reqs.clone(),
    )
    .await;
    let blind_wasted = round_trips(&reaped);
    let blind_useful = round_trips(&live);

    // PRIOR-INFORMED leg: same shape, fresh servers, ledger primed.
    let (arts_live2, _) = corpus();
    let reaped2 = MockServer::start(
        Default::default(),
        Chaos {
            echo_missing_id: true,
            ..Default::default()
        },
    )
    .await;
    let live2 = MockServer::start(arts_live2, line_rate()).await;
    let mut informed = vec![
        server_at(&reaped2, GONE_HOST, 0).0,
        server_at(&live2, "127.0.0.1", 0).0,
    ];
    let gone = route(&mut informed, &ledger_writing_off(&backbone_of(GONE_HOST)));
    assert_eq!(
        gone,
        vec![GONE_HOST.to_string()],
        "only the reaped backbone"
    );
    assert_eq!(informed.len(), 2, "no server may leave the pool");
    assert!(
        informed[0].level > informed[1].level,
        "the reaped server must sink BELOW the healthy one: {:?}",
        informed
            .iter()
            .map(|s| (&s.host, s.level))
            .collect::<Vec<_>>()
    );
    let informed_done = leg(
        vec![
            (informed[0].clone(), server_at(&reaped2, GONE_HOST, 0).1),
            (informed[1].clone(), server_at(&live2, "127.0.0.1", 0).1),
        ],
        reqs.clone(),
    )
    .await;
    let informed_wasted = round_trips(&reaped2);
    let informed_useful = round_trips(&live2);

    println!(
        "oracle_route A/B over {ARTICLES} articles ({FAMILY}, {AGE_DAYS}d):\n  \
         blind    : {blind_wasted:>3} doomed round trips to the reaped backbone, \
         {blind_useful:>3} to the live one, {blind_done}/{ARTICLES} complete\n  \
         informed : {informed_wasted:>3} doomed round trips to the reaped backbone, \
         {informed_useful:>3} to the live one, {informed_done}/{ARTICLES} complete"
    );

    assert_eq!(blind_done, ARTICLES, "the blind leg must still complete");
    assert_eq!(
        informed_done, ARTICLES,
        "the informed leg must still complete"
    );
    // The blind leg pays a doomed round trip for most of the release;
    // the informed leg pays none, because the healthy server never
    // misses and so never opens the fill gate.
    //
    // "Most" and not "every": the healthy server claims one pipeline
    // fill (connections x window) off the shared FIFO before the reaped
    // one can take it, so the measured blind cost is ARTICLES minus that
    // fill - 36 of 48 here. The floor is half the corpus rather than the
    // exact figure, so a window or connection-count change moves the
    // number without reddening a rig that is still measuring the effect.
    assert!(
        blind_wasted >= (ARTICLES / 2) as u64,
        "the rig never armed - the reaped server was asked only {blind_wasted} times"
    );
    assert_eq!(
        informed_wasted, 0,
        "a demoted server must not be asked while the primary is answering"
    );
}

/// **The parked hazard, measured.** The verdict is WRONG: the ledger
/// writes off a backbone that is in fact the only one holding a third of
/// the release. The demoted server must still be asked - once the
/// healthy one has refused - and the job must still complete.
///
/// This is the leg that distinguishes the shipped design from the one
/// the milestone refused. A veto here loses 16 articles in silence; a
/// demotion pays 16 extra round trips at the end of the ladder and
/// finishes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrong_verdict_costs_round_trips_and_never_a_completion() {
    let (all_articles, reqs) = corpus();
    // The healthy-looking server is missing the last third; only the
    // written-off one has those.
    let held_back: Vec<String> = all_articles
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .skip(ARTICLES * 2 / 3)
        .collect();
    assert_eq!(held_back.len(), ARTICLES - ARTICLES * 2 / 3);

    let (arts_gone, _) = corpus();
    let only_source = MockServer::start(arts_gone, Chaos::default()).await;
    let (arts_partial, _) = corpus();
    let partial = MockServer::start(
        arts_partial,
        Chaos {
            missing: held_back.iter().cloned().collect(),
            echo_missing_id: true,
            ..Default::default()
        },
    )
    .await;

    let mut servers = vec![
        server_at(&only_source, GONE_HOST, 0).0,
        server_at(&partial, "127.0.0.1", 0).0,
    ];
    let gone = route(&mut servers, &ledger_writing_off(&backbone_of(GONE_HOST)));
    assert_eq!(gone, vec![GONE_HOST.to_string()]);
    assert!(servers[0].level > servers[1].level, "written off, and sunk");

    let done = leg(
        vec![
            (servers[0].clone(), server_at(&only_source, GONE_HOST, 0).1),
            (servers[1].clone(), server_at(&partial, "127.0.0.1", 0).1),
        ],
        reqs,
    )
    .await;

    let rescued = round_trips(&only_source);
    let refused = partial.serve_counts().len();
    println!(
        "wrong-verdict leg: the written-off backbone was still asked {rescued} time(s) \
         and completed {done}/{ARTICLES}; the trusted server was asked for {refused} id(s), \
         {} of which it did not have",
        held_back.len()
    );

    // And what the REFUSED design would have cost, measured rather than
    // asserted in prose: run the same wrong verdict as a VETO - the
    // written-off server simply absent from the pool, which is what
    // "short-circuit the doomed attempts" meant before the guardrail.
    // Every article it alone held is lost, silently, on a job the
    // demotion completes.
    let (arts_partial2, reqs2) = corpus();
    let partial_alone = MockServer::start(
        arts_partial2,
        Chaos {
            missing: held_back.iter().cloned().collect(),
            echo_missing_id: true,
            ..Default::default()
        },
    )
    .await;
    let vetoed = leg(vec![server_at(&partial_alone, "127.0.0.1", 0)], reqs2).await;
    println!(
        "  counterfactual: the same wrong verdict as a VETO completes {vetoed}/{ARTICLES} \
         - {} article(s) lost that the demotion recovered",
        ARTICLES - vetoed
    );

    assert_eq!(
        done, ARTICLES,
        "a demoted server is a LAST resort, never a removed one - this is the parked hazard"
    );
    assert_eq!(
        rescued,
        held_back.len() as u64,
        "the written-off server must be asked for exactly the articles nobody else had"
    );
    assert_eq!(
        vetoed,
        ARTICLES - held_back.len(),
        "the veto must lose exactly the articles only the written-off server had - \
         if this stops being true the rig is no longer pricing the parked hazard"
    );
}
