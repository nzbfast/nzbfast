//! TODO 315: a refusal that named its own article is still not proof
//! the article is gone. See `Shared::take_recheck` for the measurement
//! that says so and for what the pool now does about it.

use super::super::*;
use crate::mock::{Chaos, MockServer, make_file_articles};
use crate::pool::inline_tests::work;
use std::time::Duration;
use tokio::sync::mpsc;

/// TODO 315: one cold-backend leg, run twice - once with the late
/// re-ask on and once with it off - over articles the server refuses
/// the FIRST time and serves ever after.
///
/// `echo_missing_id` is TRUE here and that is the whole point. The
/// refusals carry the message-id they are about, so `soft_430`'s pass
/// never fires and no amount of alignment evidence helps: this is not
/// the misattribution question, it is whether a refusal that named its
/// own article was TRUE. Measured on the real thing 28 Aug 2026, over a
/// cold-storage backbone on a slow long-haul route: one 17 GB slice
/// losing 250 of 23,103 segments on `430s: 250 id-proven, 3 bare`, and
/// 19 lost when the SAME slice was re-run nine minutes later
/// (research/TODO-315-BARE-VS-TRANSIENT-430-2026-08-28.md).
async fn cold_backend_run(recheck: bool) -> (usize, usize) {
    let mut articles = std::collections::HashMap::new();
    let payload: Vec<u8> = (0..64_000u32).map(|i| (i * 11) as u8).collect();
    let segs = make_file_articles("cold.bin", &payload, 4_000, "cb", &mut articles);
    // Every third article is refused once. Not all of them: a run whose
    // every article takes the hold proves nothing about the ones that
    // did not, and the queue has to have something else in it for the
    // requeue to sit BEHIND - which is where the delay comes from.
    let refused: std::collections::HashSet<String> = segs
        .iter()
        .step_by(3)
        .map(|(id, _, _)| format!("<{id}>"))
        .collect();
    let chaos = Chaos {
        missing_once: refused.clone(),
        echo_missing_id: true,
        ..Default::default()
    };
    let srv = MockServer::start(articles, chaos).await;
    let reqs: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    let cfg = PoolConfig {
        connections: 2,
        ramp_delay: Duration::ZERO,
        recheck_430: recheck,
        ..Default::default()
    };
    let (tx, mut rx) = mpsc::channel(1024);
    tokio::time::timeout(
        Duration::from_secs(30),
        fetch_all(&srv.server_config(), &cfg, reqs, tx),
    )
    .await
    .expect("cold-backend run hung");
    let (mut done, mut missing) = (0, 0);
    while let Ok(o) = rx.try_recv() {
        match o {
            FetchOutcome::Done { .. } => done += 1,
            FetchOutcome::Missing { id, .. } => {
                assert!(
                    refused.contains(&*id),
                    "an article the server never refused was declared Missing: {id}"
                );
                missing += 1;
            }
            _ => {}
        }
    }
    (done, missing)
}

#[tokio::test]
async fn a_transient_430_no_longer_ends_the_article() {
    let (done, missing) = cold_backend_run(true).await;
    assert_eq!(
        missing, 0,
        "every refusal here was false and the server served the article \
         on the very next ask - the late re-ask must collect all of them"
    );
    assert_eq!(done, 16, "and every article must arrive");
}

/// The control, and the half that says the test is measuring the fix
/// rather than the mock. With the re-ask off, the same leg over the
/// same server loses exactly the articles it was refused once - which
/// is the shipped behaviour this round set out to change, and is what
/// a single backbone's one echoed refusal has always meant.
#[tokio::test]
async fn without_the_re_ask_a_transient_430_is_terminal() {
    let (done, missing) = cold_backend_run(false).await;
    assert_eq!(
        missing, 6,
        "with the re-ask off, a refusal that named its own article ends it"
    );
    assert_eq!(done, 10, "and only the never-refused articles arrive");
}

/// TODO 315, 29 Aug 2026: the re-ask's queue POSITION, pinned because
/// getting it wrong is silent. `push_back` reads as "a long delay" and
/// is really "the end of the run" - the queue only shrinks, so the back
/// is the last dispatch and the verdict lands with no download behind
/// it. That cost two e2e tests their whole point (the M2c.5 prefetch
/// never fired; a paged-out chase held its buffers to the holds cap and
/// lost the mapped repair path), and neither is run by any per-push job.
/// The full measurement is at `recheck::recheck_slot`. What is asserted
/// below is the PROPERTY that matters rather than the arithmetic: work
/// is left BEHIND the re-ask, so a consumer still has a window.
#[test]
fn a_late_re_ask_leaves_download_behind_it() {
    let mut q: VecDeque<Work> = (0..10).map(|i| work(&format!("<a{i}>"))).collect();
    let at = recheck::recheck_slot(&q);
    assert!(
        at < q.len(),
        "the re-ask must not go to the back - the back is drain-end, \
         and its verdict lands with no download left to overlap"
    );
    assert!(
        at > 0,
        "and it must still buy time: the FRONT is `soft_430`'s answer \
         to a different question (alignment), not this one (a cold \
         backend needs time, not a round trip)"
    );

    // Never into the promoted prefix: that is other people's playhead
    // work, and inserting ahead of it strands a player exactly as the
    // queue back would.
    for w in q.iter_mut().take(8) {
        w.promoted = true;
    }
    assert_eq!(
        recheck::recheck_slot(&q),
        8,
        "the slot must clear the promoted prefix"
    );

    // Degenerate queues must not panic or produce an out-of-range index
    // - `VecDeque::insert` panics past `len`.
    for n in 0..4usize {
        let q: VecDeque<Work> = (0..n).map(|i| work(&format!("<b{i}>"))).collect();
        assert!(
            recheck::recheck_slot(&q) <= q.len(),
            "slot out of range at len {n}"
        );
    }
}
