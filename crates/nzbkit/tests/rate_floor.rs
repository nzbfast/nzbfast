//! A6 (error-detection audit, 20 Aug 2026): the mid-body rate floor,
//! end to end. Before it, the only mid-body bound was the 8 s adaptive
//! stall deadline, which resets on ANY byte - so one connection
//! trickling an article at a few KB/s below everyone's notice held its
//! article, and its connection slot, indefinitely; every rescuer (slope
//! recycle, over-target trim) runs only between articles and never
//! reached a read that never finishes.
//!
//! The rig: one server, two connections, the FIRST accepted connection
//! capped far below the floor (`Chaos::slow_conn`) while its sibling is
//! healthy. The env-shrunk floor (a real deployment runs 64 B/s over
//! 60 s; the test runs 200 KB/s over 1 s so the whole thing fits in
//! seconds) must tear the trickling read down mid-body - the census
//! records it as a mid-flow stall - and the job must still complete
//! whole via the requeue, on a healthy connection.
//!
//! Env is process-global, which is why this test lives alone in its own
//! integration binary: the floor is read once per process, and no other
//! test may run under the shrunk window.

use std::sync::Arc;
use std::time::Duration;

use nzbkit::mock::{Chaos, MockServer, Throttle, make_file_articles};
use nzbkit::pool::{
    ArticleReq, DecodeAck, DecodeReport, FetchOutcome, PoolConfig, QueueControl,
    fetch_all_multi_ctl,
};
use tokio::sync::mpsc;

/// Payload bytes per article: big enough that the slow connection is
/// still mid-body when the shrunk window closes (~309 KB encoded is
/// five 64 KiB pacing chunks, and the floor trips on the second).
const ART: usize = 300_000;
const N_ARTICLES: usize = 3;

#[tokio::test(flavor = "multi_thread")]
async fn a_trickling_body_is_torn_down_at_the_rate_floor_and_the_job_completes() {
    // Must land before the pool's first body read caches the floor.
    unsafe {
        std::env::set_var("NZBFAST_BODY_RATE_FLOOR", "200000");
        std::env::set_var("NZBFAST_BODY_RATE_WINDOW_SECS", "1");
    }

    let data: Vec<u8> = (0..(N_ARTICLES * ART) as u32)
        .map(|i| (i >> 2) as u8)
        .collect();
    let mut articles = std::collections::HashMap::new();
    let segs = make_file_articles("floor.bin", &data, ART, "rf", &mut articles);
    let reqs: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    let n = reqs.len();

    let srv = MockServer::start(
        articles,
        Chaos {
            // The first accepted connection trickles at 60 KB/s - well
            // under the 200 KB/s floor, well over what the 8 s idle
            // bound alone would ever notice (its 64 KiB pacing chunks
            // arrive ~1.1 s apart). Reconnects are healthy.
            slow_conn: Some((1, 60_000)),
            throttle: Throttle {
                per_conn_bps: 500_000,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;

    let mut sc = srv.server_config();
    sc.connections = 2;
    let cfg = PoolConfig {
        connections: 2,
        window: 2,
        ramp_delay: Duration::from_millis(0),
        // The floor rides the adaptive two-phase read; the flat path is
        // whole-response capped and out of scope here.
        adaptive_timeout: true,
        ..Default::default()
    };

    let ctl = Arc::new(QueueControl::default());
    let (tx, mut rx) = mpsc::channel(64);
    let ctl_fetch = ctl.clone();
    let servers = vec![(sc, cfg)];
    let fetch =
        tokio::spawn(
            async move { fetch_all_multi_ctl(&servers, reqs, tx, Some(&ctl_fetch)).await },
        );

    let collect = tokio::spawn(async move {
        let (mut done, mut lost) = (0usize, 0usize);
        while let Some(o) = rx.recv().await {
            match o {
                FetchOutcome::Done { id, .. } => {
                    if ctl.note_decoded(&id, DecodeReport::Clean { part: None })
                        == DecodeAck::Steered
                    {
                        continue;
                    }
                    done += 1;
                }
                FetchOutcome::Missing { .. } | FetchOutcome::Failed { .. } => lost += 1,
            }
        }
        (done, lost)
    });

    // A minute is an eternity for this rig (~3-6 s healthy); past it the
    // floor did not fire and the trickling read is holding the run.
    let stats = tokio::time::timeout(Duration::from_secs(60), fetch)
        .await
        .expect("run wedged: the rate floor never freed the trickling read")
        .expect("fetch task panicked");
    let (done, lost) = collect.await.expect("collector panicked");

    assert_eq!(done, n, "every article must complete despite the trickler");
    assert_eq!(lost, 0, "the teardown must requeue, not fail, the article");
    assert!(
        stats[0].ends.stall >= 1,
        "the floor expiry must be counted as a mid-flow stall in the \
         session census, got {:?}",
        stats[0].ends
    );
}
