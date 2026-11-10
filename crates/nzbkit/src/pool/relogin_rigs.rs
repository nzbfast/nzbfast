//! TODO 358 items 2 and 12: the session-state refusals, end to end.
//!
//! A `480 authentication required` or `412 no newsgroup selected` to a
//! BODY is answered on the same socket (`pool::session::relogin`), and
//! these rigs drive the real pool against the mock's
//! [`crate::mock::Chaos::auth_lapse_after`] and
//! [`crate::mock::Chaos::require_group`]. Until they existed nothing in
//! the tree pinned what a 480 does at all (census A9 in
//! `research/PLAN-WEAVER-PARITY-2026-11-08.md`), so the fallback legs
//! below are as much the point as the recovery legs: a refused
//! re-login, or a 480 on a server with no credentials, must still take
//! the redial it always took and still finish the job.
//!
//! What each leg reads is the SERVER's record (`MockServer::accepted`
//! and `MockServer::session`), because the question is what went over
//! the wire: a recovery that quietly redialled instead would pass every
//! outcome assertion and fail only these.

use super::rig_tests::payout_server;
use super::*;

/// One rig run's tallies, from the outcome channel.
struct Tally {
    done: usize,
    failed: usize,
    missing: usize,
}

/// A small single-file corpus: `n` articles of 6,000 bytes.
fn corpus(tag: &str, n: u32) -> (HashMap<String, Vec<u8>>, Vec<ArticleReq>) {
    let mut articles = HashMap::new();
    let payload: Vec<u8> = (0..n * 6_000).map(|i| (i * 31 + 7) as u8).collect();
    crate::mock::make_file_articles(&format!("{tag}.bin"), &payload, 6_000, tag, &mut articles);
    let reqs = articles
        .keys()
        .map(|k| ArticleReq::fresh(k.clone()))
        .collect();
    (articles, reqs)
}

/// Run one fetch to completion against `srv` and tally the outcomes.
/// `creds` gives the server config a login, which the 480 recovery
/// needs and the no-credentials pin must not have.
async fn run(
    srv: &crate::mock::MockServer,
    conns: usize,
    cfg: PoolConfig,
    creds: bool,
    reqs: Vec<ArticleReq>,
) -> Tally {
    let (mut sc, cfg) = payout_server(srv, conns, cfg);
    if creds {
        sc.username = Some("rig-user".into());
        sc.password = Some("rig-pass".into());
    }
    let (tx, mut rx) = mpsc::channel(4096);
    tokio::time::timeout(
        Duration::from_secs(120),
        fetch_all_multi(&[(sc, cfg)], reqs, tx),
    )
    .await
    .expect("relogin rig hung");
    let mut t = Tally {
        done: 0,
        failed: 0,
        missing: 0,
    };
    while let Ok(o) = rx.try_recv() {
        match o {
            FetchOutcome::Done { .. } => t.done += 1,
            FetchOutcome::Failed { .. } => t.failed += 1,
            FetchOutcome::Missing { .. } => t.missing += 1,
        }
    }
    t
}

/// The recovery, mid-batch: every connection's login lapses after its
/// third body, with a four-deep pipeline behind it, so each lapse lands
/// as one 480 at the front and three more already on the wire. Every
/// article must arrive, and the server must see one re-login per
/// connection and NO second dial - the old arm quit and redialled on
/// every lapse, so `accepted` is what tells the two apart.
#[tokio::test(flavor = "multi_thread")]
async fn a_mid_batch_480_logs_in_again_on_the_same_socket() {
    let (articles, reqs) = corpus("rl", 40);
    let n = reqs.len();
    let srv = crate::mock::MockServer::start(
        articles,
        crate::mock::Chaos {
            auth_lapse_after: Some(3),
            ..Default::default()
        },
    )
    .await;
    let t = run(
        &srv,
        2,
        PoolConfig {
            window: 4,
            ..Default::default()
        },
        true,
        reqs,
    )
    .await;
    assert_eq!(
        (t.done, t.failed, t.missing),
        (n, 0, 0),
        "every article lands"
    );
    let accepted = srv.accepted.load(Ordering::Relaxed);
    let relogins = srv.session.relogins.load(Ordering::Relaxed);
    let refusals = srv.session.refusals.load(Ordering::Relaxed);
    assert!(
        accepted <= 2,
        "a 480 must not cost a redial: {accepted} connections for 2 workers"
    );
    assert_eq!(
        relogins, accepted,
        "each connection lapsed once and must have logged in again on itself"
    );
    assert!(
        refusals >= relogins,
        "the rig never sent a 480 ({refusals} refusals) - it proved nothing"
    );
}

/// The budget half of item 2. The login lapses before the FIRST body of
/// every connection (a login that expired while the socket sat parked),
/// so each 480 lands on a session with zero completed responses - the
/// one case where the old death arm CHARGED the front article
/// (`requeue_or_fail`'s `charge_front`). With `article_retries: 0` and a
/// single server, one charge spends an article's whole budget
/// (`note_spent` has no other server to re-arm toward). All of them
/// arriving, on one connection, is therefore the proof that no article
/// paid for the re-login. Measured 9 Nov 2026 with the recovery switched
/// off in `session_loop`: this leg, the mid-batch leg and the 412 leg
/// all fail (the mid-batch one on `accepted`, the other two by not
/// finishing inside the 120 s bound), and the two fallback pins below
/// pass either way, which is what a pin of the old arm should do.
#[tokio::test(flavor = "multi_thread")]
async fn a_480_on_a_fresh_session_charges_the_article_nothing() {
    let (articles, reqs) = corpus("rz", 12);
    let n = reqs.len();
    let srv = crate::mock::MockServer::start(
        articles,
        crate::mock::Chaos {
            auth_lapse_after: Some(0),
            ..Default::default()
        },
    )
    .await;
    let t = run(
        &srv,
        1,
        PoolConfig {
            window: 3,
            article_retries: 0,
            ..Default::default()
        },
        true,
        reqs,
    )
    .await;
    assert_eq!(
        (t.done, t.failed, t.missing),
        (n, 0, 0),
        "a re-login must not spend the retry budget of the article it re-asks"
    );
    assert_eq!(srv.accepted.load(Ordering::Relaxed), 1, "one connection");
    assert_eq!(srv.session.relogins.load(Ordering::Relaxed), 1);
}

/// THE 480 PIN, fallback half: a server that refuses the re-login (481
/// and a hangup) gets exactly the treatment every 480 got before item
/// 2 - the session ends, the pipeline requeues, the worker redials -
/// and the job still finishes. Each connection serves two bodies and
/// then lapses, so finishing at all takes many redials; a recovery that
/// wedged on the refused login, or lost the pipeline it had drained,
/// would show here as a hang or a short count.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_relogin_falls_back_to_the_redial() {
    let (articles, reqs) = corpus("rf", 12);
    let n = reqs.len();
    let srv = crate::mock::MockServer::start(
        articles,
        crate::mock::Chaos {
            auth_lapse_after: Some(2),
            reauth_rejected: true,
            ..Default::default()
        },
    )
    .await;
    let t = run(
        &srv,
        1,
        PoolConfig {
            window: 3,
            connect_backoff: Duration::from_millis(10),
            ..Default::default()
        },
        true,
        reqs,
    )
    .await;
    assert_eq!(
        (t.done, t.failed, t.missing),
        (n, 0, 0),
        "every article lands"
    );
    assert!(
        srv.accepted.load(Ordering::Relaxed) > 1,
        "a refused re-login must end the session and redial"
    );
    assert_eq!(
        srv.session.relogins.load(Ordering::Relaxed),
        0,
        "the mock accepted no re-login, so none can have counted"
    );
}

/// THE 480 PIN, no-credentials half: a 480 from a server the pool holds
/// no login for cannot be answered on the socket, so it must take the
/// old redial and nothing else. Pinned because the gate is the only
/// thing between a credential-less server and an AUTHINFO with nothing
/// to send.
#[tokio::test(flavor = "multi_thread")]
async fn a_480_without_credentials_redials_as_before() {
    let (articles, reqs) = corpus("rn", 12);
    let n = reqs.len();
    let srv = crate::mock::MockServer::start(
        articles,
        crate::mock::Chaos {
            auth_lapse_after: Some(2),
            ..Default::default()
        },
    )
    .await;
    let t = run(
        &srv,
        1,
        PoolConfig {
            window: 3,
            connect_backoff: Duration::from_millis(10),
            ..Default::default()
        },
        false,
        reqs,
    )
    .await;
    assert_eq!(
        (t.done, t.failed, t.missing),
        (n, 0, 0),
        "every article lands"
    );
    assert!(srv.accepted.load(Ordering::Relaxed) > 1, "it redialled");
    assert_eq!(srv.session.relogins.load(Ordering::Relaxed), 0);
}

/// Item 12: a frontend that answers 412 until a group is selected. The
/// pool knows the job's group (`PoolConfig::group`), sends it once per
/// connection on the first 412, and re-asks the pipeline. Every article
/// lands, every connection sends exactly one GROUP, and it is the
/// job's group by name - the server's log is the witness for all three.
#[tokio::test(flavor = "multi_thread")]
async fn a_412_selects_the_jobs_group_once_per_connection() {
    let (articles, reqs) = corpus("rg", 40);
    let n = reqs.len();
    let srv = crate::mock::MockServer::start(
        articles,
        crate::mock::Chaos {
            require_group: true,
            ..Default::default()
        },
    )
    .await;
    let t = run(
        &srv,
        2,
        PoolConfig {
            window: 4,
            group: Some(Arc::from("alt.binaries.rig")),
            ..Default::default()
        },
        false,
        reqs,
    )
    .await;
    assert_eq!(
        (t.done, t.failed, t.missing),
        (n, 0, 0),
        "every article lands"
    );
    let accepted = srv.accepted.load(Ordering::Relaxed);
    let log = srv.session.group_log.lock_ok().clone();
    assert!(accepted <= 2, "a 412 must not cost a redial: {accepted}");
    assert_eq!(
        log.len() as u64,
        accepted,
        "one GROUP per connection, no more: {log:?}"
    );
    let mut conns: Vec<u64> = log.iter().map(|(c, _)| *c).collect();
    conns.sort_unstable();
    conns.dedup();
    assert_eq!(
        conns.len(),
        log.len(),
        "a connection sent GROUP twice: {log:?}"
    );
    assert!(
        log.iter().all(|(_, g)| g == "alt.binaries.rig"),
        "the GROUP must name the job's group: {log:?}"
    );
}
