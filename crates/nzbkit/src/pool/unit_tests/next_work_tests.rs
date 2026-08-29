//! §122.5 round 2 (6 Aug): the `next_work` scan ladder, driven directly.
//!
//! Every branch here is a queue-shape decision the e2e rigs only reach
//! probabilistically: the all-live-430 terminal report, the tail latch,
//! the futile-scan throttle, the steer-inbox adoption order, the fill
//! gate, the endgame hold-back, the promoted leave-for-faster hop, and
//! the bare-430 deferral with its recheck, its desync-proven re-arm and
//! the cap that keeps the re-arm finite.
//!
//! A child of `unit_tests`, out here for the size gate (TODO 106): the
//! parent sat 15 lines under the 3,000-line file ceiling after the
//! 22 Aug merges. The module is named for its file so size-gate.py's
//! CFG_TEST_MOD resolver still reads it as test code, and `use super::*`
//! brings the parent's `server`, `fresh` and `work` builders along with
//! everything the parent itself pulls from `pool`.

use super::*;

#[tokio::test]
async fn next_work_reports_a_dead_article_and_latches_the_tail() {
    let servers = vec![(server("s"), PoolConfig::default())];
    let (sh, _) = Shared::new(fresh(&["<dead@x>", "<ok@x>"]), &servers);
    let ctx = ctx_for(&servers, 0);
    sh.alive[0].fetch_add(1, Ordering::AcqRel);
    // Every LIVE server has already 430'd the head article: it is
    // terminal, and waiting on it would rotate it forever.
    sh.queue.lock().await.front_mut().unwrap().tried_430 = sh.live_mask();
    let (tx, mut rx) = mpsc::channel(4);
    let w = next_work(&sh, ctx, &tx, Pipeline::payload(0))
        .await
        .expect("the healthy article is picked");
    assert_eq!(&*w.id, "<ok@x>");
    match rx.try_recv() {
        Ok(FetchOutcome::Missing { id, cause }) => {
            assert_eq!(&*id, "<dead@x>");
            assert!(matches!(cause, MissingCause::Gone { .. }), "{cause:?}");
        }
        other => panic!("expected the dead article's Missing report, got {other:?}"),
    }
    // The queue is dry with work still pending: this scan finds nothing,
    // latches the tail phase exactly once, and arms the futile throttle.
    assert!(sh.tail_started.lock_ok().is_none());
    assert!(
        next_work(&sh, ctx, &tx, Pipeline::payload(0))
            .await
            .is_none()
    );
    assert!(
        sh.tail_started.lock_ok().is_some(),
        "a primary finding the queue dry latches the tail"
    );
    assert_ne!(sh.scan_futile[0].load(Ordering::Relaxed), u64::MAX);
    // An immediate rescan takes the throttled path (dup pick only).
    assert!(
        next_work(&sh, ctx, &tx, Pipeline::payload(0))
            .await
            .is_none()
    );
}

#[tokio::test]
async fn steer_inbox_requeues_are_adopted_in_promoted_first_order() {
    let servers = vec![(server("s"), PoolConfig::default())];
    let (sh, _) = Shared::new(fresh(&["<q@x>"]), &servers);
    let ctx = ctx_for(&servers, 0);
    sh.alive[0].fetch_add(1, Ordering::AcqRel);
    {
        let mut inbox = sh.steer_inbox.lock_ok();
        let mut p = work("<p@x>");
        p.promoted = true;
        inbox.push(p);
        inbox.push(work("<n@x>"));
    }
    let (tx, _rx) = mpsc::channel(4);
    let w = next_work(&sh, ctx, &tx, Pipeline::payload(0))
        .await
        .expect("work is available");
    assert_eq!(&*w.id, "<p@x>", "the promoted steer lands at the front");
    assert_eq!(
        sh.promoted_pending.load(Ordering::Acquire),
        0,
        "the adopt charged promoted_pending and the pick spent it"
    );
    let q = sh.queue.lock().await;
    let ids: Vec<&str> = q.iter().map(|w| &*w.id).collect();
    // A plain steer goes to the front BEHIND the promoted run, never
    // the back: the consumer already holds a (rejected) copy and is
    // waiting on exactly this article, and the synthesized-numbering
    // latch needs a steered refetch to REPORT before the ladder runs
    // out (tv4-rot1, 22 Aug 2026).
    assert_eq!(
        ids,
        ["<n@x>", "<q@x>"],
        "the plain steer queued at the front, behind promoted"
    );
}

#[tokio::test]
async fn a_fill_server_waits_for_every_live_primary_miss() {
    let mut fill = server("fill");
    fill.level = 1;
    let servers = vec![
        (server("prime"), PoolConfig::default()),
        (fill, PoolConfig::default()),
    ];
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    let ctx1 = ctx_for(&servers, 1);
    sh.alive[0].fetch_add(1, Ordering::AcqRel);
    sh.alive[1].fetch_add(1, Ordering::AcqRel);
    let (tx, _rx) = mpsc::channel(4);
    // The primary is live and has not missed: the fill server sits out.
    assert!(
        next_work(&sh, ctx1, &tx, Pipeline::payload(0))
            .await
            .is_none()
    );
    sh.scan_futile[1].store(u64::MAX, Ordering::Relaxed);
    // The primary 430'd it: the gate opens.
    sh.queue.lock().await.front_mut().unwrap().tried_430 = server_bit(0);
    let w = next_work(&sh, ctx1, &tx, Pipeline::payload(0))
        .await
        .expect("gate satisfied");
    assert_eq!(&*w.id, "<a@x>");
}

/// M5: the primary resets on one article every time it is dispatched.
/// Nothing ever 430s, so before the `spent` mask the fill server stayed
/// gated for the whole run, the primary kept retaking its own casualty
/// (`other_can_take` saw no eligible elsewhere), and the article was
/// reported lost with a healthy server one level down never asked.
#[tokio::test]
async fn a_primary_that_spends_its_budget_hands_the_article_down() {
    let mut fill = server("fill");
    fill.level = 1;
    let servers = vec![
        (server("prime"), PoolConfig::default()),
        (fill, PoolConfig::default()),
    ];
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    let ctx0 = ctx_for(&servers, 0);
    let ctx1 = ctx_for(&servers, 1);
    sh.alive[0].fetch_add(1, Ordering::AcqRel);
    sh.alive[1].fetch_add(1, Ordering::AcqRel);
    let cfg = PoolConfig::default();
    let (tx, mut rx) = mpsc::channel(4);
    // Every dispatch dies with the article at the front of a session
    // that never answered: the charge the RST-after-AUTH guard makes.
    for attempt in 0..=cfg.article_retries {
        sh.scan_futile[0].store(u64::MAX, Ordering::Relaxed);
        let w = next_work(&sh, ctx0, &tx, Pipeline::payload(0))
            .await
            .unwrap_or_else(|| panic!("the primary picks it on attempt {attempt}"));
        assert_eq!(&*w.id, "<a@x>");
        sh.charge_wire();
        sh.register_inflight(&w, 0);
        let mut inflight: VecDeque<Work> = VecDeque::new();
        inflight.push_back(w);
        requeue_or_fail(
            &sh,
            &tx,
            &cfg,
            ctx0,
            &mut inflight,
            FailCode::Transport,
            "rst",
            true,
        )
        .await;
    }
    assert!(
        rx.try_recv().is_err(),
        "the article must not be declared lost while a server that never saw it is live"
    );
    {
        let q = sh.queue.lock().await;
        let w = q.front().expect("requeued, not failed");
        assert_eq!(w.attempts, 0, "the ladder hands the next tier a budget");
        assert_eq!(
            w.tried_430, 0,
            "a reset answers no question about retention"
        );
        assert_eq!(w.tried_fail, server_bit(0));
    }
    assert_eq!(sh.spent_mask("<a@x>"), server_bit(0));
    // The primary now steps aside: someone else can finally have it.
    sh.scan_futile[0].store(u64::MAX, Ordering::Relaxed);
    assert!(
        next_work(&sh, ctx0, &tx, Pipeline::payload(0))
            .await
            .is_none(),
        "the server that spent its budget must not retake its own casualty"
    );
    sh.scan_futile[1].store(u64::MAX, Ordering::Relaxed);
    let w = next_work(&sh, ctx1, &tx, Pipeline::payload(0))
        .await
        .expect("the fill server takes the article the primary could not fetch");
    assert_eq!(&*w.id, "<a@x>");
}

#[tokio::test]
async fn endgame_ladder_articles_ride_empty_pipelines_only() {
    let servers = vec![
        (server("a"), PoolConfig::default()),
        (server("b"), PoolConfig::default()),
    ];
    let (sh, _) = Shared::new(fresh(&["<l@x>"]), &servers);
    let ctx0 = ctx_for(&servers, 0);
    sh.alive[0].fetch_add(1, Ordering::AcqRel);
    sh.alive[1].fetch_add(1, Ordering::AcqRel);
    // One pending article 430'd by the sibling: an endgame ladder probe.
    sh.queue.lock().await.front_mut().unwrap().tried_430 = server_bit(1);
    let (tx, _rx) = mpsc::channel(4);
    // A busy pipeline holds it back (head-of-line blocking on the last
    // windows was the measured straggler tail).
    assert!(
        next_work(&sh, ctx0, &tx, Pipeline::payload(3))
            .await
            .is_none()
    );
    sh.scan_futile[0].store(u64::MAX, Ordering::Relaxed);
    // An idle worker answers the probe in one RTT.
    let w = next_work(&sh, ctx0, &tx, Pipeline::payload(0))
        .await
        .expect("idle takes the probe");
    assert_eq!(&*w.id, "<l@x>");
}

#[tokio::test]
async fn untried_promoted_work_is_left_for_a_faster_server() {
    let servers = vec![
        (server("slow"), PoolConfig::default()),
        (server("fast"), PoolConfig::default()),
    ];
    let (sh, _) = Shared::new(fresh(&["<s@x>"]), &servers);
    let ctx0 = ctx_for(&servers, 0);
    sh.alive[0].fetch_add(1, Ordering::AcqRel);
    sh.alive[1].fetch_add(1, Ordering::AcqRel);
    // A stream reader is attached and the sibling is measurably faster.
    sh.note_stream();
    sh.bytes[1].store(64_000_000, Ordering::Release);
    {
        let mut q = sh.queue.lock().await;
        q.front_mut().unwrap().promoted = true;
        sh.promoted_pending.fetch_add(1, Ordering::AcqRel);
    }
    let (tx, _rx) = mpsc::channel(4);
    // The slow server steps past it - and puts it back at the FRONT.
    assert!(
        next_work(&sh, ctx0, &tx, Pipeline::payload(0))
            .await
            .is_none()
    );
    {
        let q = sh.queue.lock().await;
        assert_eq!(q.front().map(|w| &*w.id), Some("<s@x>"));
        assert!(q.front().unwrap().promoted);
    }
    assert_eq!(
        sh.promoted_pending.load(Ordering::Acquire),
        1,
        "stepping past is not a pick - the promise stays charged"
    );
    // Once ANY backbone has 430'd it, latency beats speed-matching:
    // whoever can serve it, serves it.
    sh.scan_futile[0].store(u64::MAX, Ordering::Relaxed);
    sh.queue.lock().await.front_mut().unwrap().tried_430 = server_bit(1);
    let w = next_work(&sh, ctx0, &tx, Pipeline::payload(0))
        .await
        .expect("a missed promote goes to whoever is standing");
    assert_eq!(&*w.id, "<s@x>");
    assert_eq!(sh.promoted_pending.load(Ordering::Acquire), 0);
}

/// A bare 430 (no echoed message-id) defers the verdict instead of
/// declaring the article missing, and MUST tick `deferred` on its way
/// out. The caller's stall watchdog reads decoded bytes, outstanding
/// articles and this counter; a deferral moves neither of the first
/// two, so without the tick a wholly dead post - which takes this
/// branch for every one of its articles before any can go terminal -
/// looks exactly like a wedged pool and gets aborted mid-ladder, then
/// blamed on the user's machine. That abort shipped once already
/// (31 Jul) and this branch reopened it; the e2e guard is
/// `dead_post_is_driven_to_missing_not_abandoned_as_a_stall`.
#[tokio::test]
async fn a_bare_430_defers_the_verdict_and_says_so() {
    let servers = vec![(server("s"), PoolConfig::default())];
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    // TODO 315's late re-ask is OFF here, and only here: this test is
    // about `soft_430`, which doubts whether a BARE refusal was about
    // this article, and the re-ask doubts whether a refusal was TRUE.
    // Leaving it on adds a hop that has nothing to do with what is
    // being pinned - the two together are covered in `recheck_tests`.
    let cfg = PoolConfig {
        recheck_430: false,
        ..PoolConfig::default()
    };
    let ctx = ctx_for(&servers, 0);
    let (tx, mut rx) = mpsc::channel(8);
    // Dispatch it the way a worker would, so the queue below counts the
    // requeue and not the seeded entry.
    let dispatched = sh.queue.lock().await.pop_front().expect("the seeded work");
    let mut inflight: VecDeque<Work> = [dispatched].into_iter().collect();
    sh.charge_wire();

    let before = sh.deferred.load(Ordering::Relaxed);
    handle_missing(
        &cfg,
        ctx,
        &sh,
        &tx,
        &mut inflight,
        PooledBuf::unpooled(Vec::new()),
        false,
        false,
        &mut Default::default(),
    )
    .await;
    assert_eq!(
        sh.deferred.load(Ordering::Relaxed),
        before + 1,
        "a deferred verdict is forward progress and must be visible as such"
    );
    assert!(
        rx.try_recv().is_err(),
        "the first bare 430 requeues - it does not resolve the article"
    );
    assert_eq!(sh.queue.lock().await.len(), 1, "requeued for the recheck");

    // The confirming repeat lands on the re-aligned session and is
    // authoritative: the article goes terminally Missing, and THAT
    // resolution is the outstanding-count movement the watchdog sees.
    let w = sh
        .queue
        .lock()
        .await
        .pop_front()
        .expect("the requeued work");
    let mut inflight: VecDeque<Work> = [w].into_iter().collect();
    sh.charge_wire();
    handle_missing(
        &cfg,
        ctx,
        &sh,
        &tx,
        &mut inflight,
        PooledBuf::unpooled(Vec::new()),
        false,
        false,
        &mut Default::default(),
    )
    .await;
    assert!(
        matches!(rx.try_recv(), Ok(FetchOutcome::Missing { id, .. }) if &*id == "<a@x>"),
        "the second bare 430 confirms the first and declares the article"
    );
    assert_eq!(
        sh.deferred.load(Ordering::Relaxed),
        before + 1,
        "a resolving response is not a deferral"
    );
}

/// The soft-430 recheck requeues at the FRONT of the queue, not the
/// back. At the back the confirming repeat only dispatches as the queue
/// empties, so the terminal Missing lands at drain-end - on a long
/// download that defers the verdict by the WHOLE download and starves
/// the M2c.5 speculative prefetch of the trigger it polls for (the
/// 7 Aug nightly red). The fence armed by the first bare refusal proves
/// alignment before any verdict is charged, so the early slot costs
/// nothing on correctness.
#[tokio::test]
async fn the_bare_430_recheck_jumps_the_queue() {
    let servers = vec![(server("s"), PoolConfig::default())];
    let (sh, _) = Shared::new(fresh(&["<a@x>", "<b@x>"]), &servers);
    let cfg = PoolConfig::default();
    let ctx = ctx_for(&servers, 0);
    let (tx, _rx) = mpsc::channel(8);
    let dispatched = sh.queue.lock().await.pop_front().expect("the seeded work");
    assert_eq!(&*dispatched.id, "<a@x>");
    let mut inflight: VecDeque<Work> = [dispatched].into_iter().collect();
    sh.charge_wire();

    handle_missing(
        &cfg,
        ctx,
        &sh,
        &tx,
        &mut inflight,
        PooledBuf::unpooled(Vec::new()),
        false,
        false,
        &mut Default::default(),
    )
    .await;
    let q = sh.queue.lock().await;
    assert_eq!(q.len(), 2, "requeued for the recheck");
    assert_eq!(
        q.front().map(|w| &*w.id),
        Some("<a@x>"),
        "the recheck must dispatch ahead of untouched work, not at drain-end"
    );
}

/// §129 3g: the confirming repeat is a WINDOWED confirmation, not a
/// one-time pass for the whole run. Two bare refusals only confirm each
/// other while both were read off aligned sockets; when the session that
/// took the first one is afterwards shown to have been reading responses
/// off by one, that refusal was never evidence about this article at all
/// and the pass comes back.
///
/// Before this, `soft_430` was set once and carried across every requeue
/// forever, so it defeated exactly ONE desync event per article: a second
/// misattributed refusal - from an unrelated event, on a different
/// session, minutes later - folded straight into `tried_430` and
/// declared an article the server HOLDS terminally Missing. On a
/// single-server run nothing contradicts that verdict, which makes it
/// silent data loss rather than a slowdown.
#[tokio::test]
async fn a_proven_desync_gives_the_bare_430_pass_back() {
    let servers = vec![(server("s"), PoolConfig::default())];
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    // TODO 315's late re-ask is OFF here, and only here: this test is
    // about `soft_430`, which doubts whether a BARE refusal was about
    // this article, and the re-ask doubts whether a refusal was TRUE.
    // Leaving it on adds a hop that has nothing to do with what is
    // being pinned - the two together are covered in `recheck_tests`.
    let cfg = PoolConfig {
        recheck_430: false,
        ..PoolConfig::default()
    };
    let ctx = ctx_for(&servers, 0);
    let (tx, mut rx) = mpsc::channel(8);
    let mut ledger: VecDeque<Arc<str>> = VecDeque::new();

    // A desynced session's refusal: bare, and about the article behind.
    let w = sh.queue.lock().await.pop_front().expect("the seeded work");
    let mut inflight: VecDeque<Work> = [w].into_iter().collect();
    sh.charge_wire();
    handle_missing(
        &cfg,
        ctx,
        &sh,
        &tx,
        &mut inflight,
        PooledBuf::unpooled(Vec::new()),
        false,
        false,
        &mut ledger,
    )
    .await;
    assert_eq!(
        ledger.len(),
        1,
        "a bare refusal goes in the session's ledger - it is the only \
         record of what a later desync proof would have to void"
    );

    // That session then reads an id that is not the one it asked for,
    // proving every refusal since its last checked id was positional
    // evidence off a misaligned socket.
    sh.void_soft_430(&ledger, ctx.group_bits);

    // The next bare refusal is therefore FIRST evidence again.
    let w = sh
        .queue
        .lock()
        .await
        .pop_front()
        .expect("the requeued work");
    let mut inflight: VecDeque<Work> = [w].into_iter().collect();
    sh.charge_wire();
    handle_missing(
        &cfg,
        ctx,
        &sh,
        &tx,
        &mut inflight,
        PooledBuf::unpooled(Vec::new()),
        false,
        false,
        &mut Default::default(),
    )
    .await;
    assert!(
        rx.try_recv().is_err(),
        "the voided refusal cannot confirm anything - declaring the \
         article here is the false Missing this item exists to close"
    );
    assert_eq!(sh.queue.lock().await.len(), 1, "requeued for the recheck");

    // And with no fresh proof, the pair that follows still resolves it:
    // re-arming may not turn a dead post into a loop.
    let w = sh
        .queue
        .lock()
        .await
        .pop_front()
        .expect("the requeued work");
    let mut inflight: VecDeque<Work> = [w].into_iter().collect();
    sh.charge_wire();
    handle_missing(
        &cfg,
        ctx,
        &sh,
        &tx,
        &mut inflight,
        PooledBuf::unpooled(Vec::new()),
        false,
        false,
        &mut Default::default(),
    )
    .await;
    assert!(
        matches!(rx.try_recv(), Ok(FetchOutcome::Missing { id, .. }) if &*id == "<a@x>"),
        "two refusals off aligned sockets are still a confirmation"
    );
}

/// §129 3g, the other half: the re-arm is CAPPED, so a provider that
/// desyncs on every session cannot keep an article out of a terminal
/// verdict for ever. The first cut of the fix had no cap and hung the
/// 1-in-5 desync leg outright - every session's death handed every
/// article it had refused its pass back, and a wholly-absent post then
/// had no way to resolve at all.
#[tokio::test]
async fn the_re_armed_pass_is_capped_so_the_run_still_terminates() {
    let servers = vec![(server("s"), PoolConfig::default())];
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    // TODO 315's late re-ask is OFF here, and only here: this test is
    // about `soft_430`, which doubts whether a BARE refusal was about
    // this article, and the re-ask doubts whether a refusal was TRUE.
    // Leaving it on adds a hop that has nothing to do with what is
    // being pinned - the two together are covered in `recheck_tests`.
    let cfg = PoolConfig {
        recheck_430: false,
        ..PoolConfig::default()
    };
    let ctx = ctx_for(&servers, 0);
    let (tx, mut rx) = mpsc::channel(8);

    // Every single refusal is followed by a proof of desync - the worst
    // case a hostile or badly broken frontend can produce.
    for round in 0..(SOFT_REARM_CAP as usize + 2) {
        let Some(w) = sh.queue.lock().await.pop_front() else {
            break; // resolved: the article left the queue for good
        };
        let mut ledger: VecDeque<Arc<str>> = VecDeque::new();
        let mut inflight: VecDeque<Work> = [w].into_iter().collect();
        sh.charge_wire();
        handle_missing(
            &cfg,
            ctx,
            &sh,
            &tx,
            &mut inflight,
            PooledBuf::unpooled(Vec::new()),
            false,
            false,
            &mut ledger,
        )
        .await;
        sh.void_soft_430(&ledger, ctx.group_bits);
        if let Ok(FetchOutcome::Missing { id, .. }) = rx.try_recv() {
            assert_eq!(&*id, "<a@x>");
            assert!(
                round <= SOFT_REARM_CAP as usize + 1,
                "resolved after {round} rounds"
            );
            return;
        }
    }
    panic!(
        "the article never reached a terminal verdict in \
         {} rounds of refusal-plus-proof - the re-arm is unbounded",
        SOFT_REARM_CAP + 2
    );
}

/// 27 Aug 2026 sweep finding 8. `live_mask` is the set of servers with a
/// worker RUNNING, and the terminal test is `tried_430 & live == live` -
/// so the instant a server's last worker leaves mid-run its bit drops
/// out of `live` and whatever the survivors already refused reads as
/// unanimous. The article is written off as `Gone` - permanently missing
/// from Usenet, the thing the failure summary and the availability
/// oracle both hang a diagnosis on - having never been offered to the
/// server that might have held it.
///
/// The fix is NOT to make the terminal test ask a frozen mask. The
/// comment above that test says why and it is still true: an item
/// nothing can serve rotates in the queue forever and deadlocks the run,
/// and a departed worker never comes back (`note_server_dark`: `alive`
/// crosses 1 -> 0 exactly once per run, workers are not re-spawned after
/// the ramp). So the question is split. Terminality still asks `live`,
/// and this test pins that the article really does LEAVE - a fix that
/// deadlocked the run instead would be worse than the defect. What the
/// participation mask changes is the CLAIM: `Unasked`, which says the
/// fleet shrank past this article, not that the post is gone.
#[tokio::test]
async fn a_fleet_that_shrank_past_an_article_reports_unasked_not_gone() {
    let servers = vec![
        (server("a"), PoolConfig::default()),
        (server("b"), PoolConfig::default()),
    ];
    let (sh, _) = Shared::new(fresh(&["<lost@x>", "<ok@x>"]), &servers);
    // Both servers served for part of this run.
    sh.connected[0].store(true, Ordering::Relaxed);
    sh.connected[1].store(true, Ordering::Relaxed);
    sh.alive[0].store(1, Ordering::Relaxed);
    sh.alive[1].store(1, Ordering::Relaxed);
    // Server a refused the head article. Server b has never seen it.
    sh.queue.lock().await.front_mut().unwrap().tried_430 = server_bit(0);
    // Server b's last worker now leaves mid-run - a spent prepaid block,
    // connect exhaustion, an outage budget: the doors differ, the effect
    // on the mask is the same one.
    sh.alive[1].store(0, Ordering::Relaxed);
    assert_eq!(sh.live_mask(), server_bit(0));
    assert_eq!(
        sh.participation_mask(),
        server_bit(0) | server_bit(1),
        "a server that served and then went out is still a participant"
    );

    let (tx, mut rx) = mpsc::channel(4);
    let w = next_work(&sh, ctx_for(&servers, 0), &tx, Pipeline::payload(0))
        .await
        .expect("the healthy article is still picked");
    assert_eq!(&*w.id, "<ok@x>");
    match rx.try_recv() {
        Ok(FetchOutcome::Missing { id, cause }) => {
            assert_eq!(&*id, "<lost@x>");
            assert_eq!(
                cause,
                MissingCause::Unasked {
                    takedown: false,
                    dark: 1
                },
                "one server that could have answered never saw it"
            );
        }
        other => panic!("expected the article's Missing report, got {other:?}"),
    }
    // The run still ENDS. The article is out of the queue, not rotating
    // in it - which is the half a frozen-mask terminal test would break.
    assert!(
        !sh.queue.lock().await.iter().any(|q| &*q.id == "<lost@x>"),
        "terminality is unchanged - a fix that wedged the run is worse than the defect"
    );
}

/// The control, and the reason `Unasked` is worth telling apart at all:
/// when every server that could have answered DID answer, the verdict is
/// `Gone` exactly as before. A distinction that fired on the ordinary
/// case would be noise, and noise is what gets a distinction ignored.
#[tokio::test]
async fn every_participant_refusing_is_still_gone() {
    let servers = vec![
        (server("a"), PoolConfig::default()),
        (server("b"), PoolConfig::default()),
    ];
    let (sh, _) = Shared::new(fresh(&["<lost@x>", "<ok@x>"]), &servers);
    sh.connected[0].store(true, Ordering::Relaxed);
    sh.connected[1].store(true, Ordering::Relaxed);
    sh.alive[0].store(1, Ordering::Relaxed);
    sh.alive[1].store(1, Ordering::Relaxed);
    sh.queue.lock().await.front_mut().unwrap().tried_430 = server_bit(0) | server_bit(1);
    // b leaves AFTER refusing: its refusal is on the record, so this is
    // not a fleet that shrank past anything.
    sh.alive[1].store(0, Ordering::Relaxed);
    let (tx, mut rx) = mpsc::channel(4);
    let _ = next_work(&sh, ctx_for(&servers, 0), &tx, Pipeline::payload(0)).await;
    match rx.try_recv() {
        Ok(FetchOutcome::Missing { cause, .. }) => {
            assert_eq!(cause, MissingCause::Gone { takedown: false });
        }
        other => panic!("expected a terminal Missing, got {other:?}"),
    }
}

/// A server that NEVER held a usable connection is not a participant,
/// and this is the population decision the mask turns on. A typo'd host
/// or a refused login is not a server that "might have had it" - it was
/// never a candidate for any article of the run, so counting it would
/// downgrade EVERY verdict of every run carrying one bad entry, and a
/// qualifier that is always present says nothing. That server already
/// has its own line in the failure summary, off this same `connected`
/// latch.
#[tokio::test]
async fn a_server_that_never_connected_is_not_a_participant() {
    let servers = vec![
        (server("good"), PoolConfig::default()),
        (server("typo"), PoolConfig::default()),
    ];
    let (sh, _) = Shared::new(fresh(&["<lost@x>"]), &servers);
    sh.connected[0].store(true, Ordering::Relaxed);
    sh.alive[0].store(1, Ordering::Relaxed);
    // The bad server's workers are born, fail every dial and bow out
    // without ever latching `connected`.
    sh.alive[1].store(1, Ordering::Relaxed);
    assert_eq!(
        sh.participation_mask(),
        server_bit(0) | server_bit(1),
        "while its workers are still dialling it could yet answer"
    );
    sh.alive[1].store(0, Ordering::Relaxed);
    assert_eq!(
        sh.participation_mask(),
        server_bit(0),
        "having never held a connection, it was never asked and never could be"
    );
    sh.queue.lock().await.front_mut().unwrap().tried_430 = server_bit(0);
    let (tx, mut rx) = mpsc::channel(4);
    let _ = next_work(&sh, ctx_for(&servers, 0), &tx, Pipeline::payload(0)).await;
    match rx.try_recv() {
        Ok(FetchOutcome::Missing { cause, .. }) => {
            assert_eq!(cause, MissingCause::Gone { takedown: false });
        }
        other => panic!("expected a terminal Missing, got {other:?}"),
    }
}

/// The takedown hint is orthogonal to the participation question and
/// must survive it. A backbone that named a removal said something about
/// the POST, and it is still worth carrying when a different server went
/// dark - the two facts are independent and the report carries both.
#[test]
fn the_takedown_hint_survives_an_unasked_verdict() {
    let servers = vec![
        (server("a"), PoolConfig::default()),
        (server("b"), PoolConfig::default()),
    ];
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    sh.connected[0].store(true, Ordering::Relaxed);
    sh.connected[1].store(true, Ordering::Relaxed);
    sh.alive[0].store(1, Ordering::Relaxed);
    assert_eq!(
        sh.missing_cause(server_bit(0), true),
        MissingCause::Unasked {
            takedown: true,
            dark: 1
        }
    );
    assert_eq!(
        sh.missing_cause(server_bit(0) | server_bit(1), true),
        MissingCause::Gone { takedown: true }
    );
}

/// THE ONE PLACE the unanimous-Missing cause is judged. Three sites
/// reach a live-unanimous verdict - this file's queue scan and both 430
/// paths in `session` - and finding 8 is what a rule spelled out three
/// times costs: the queue scan and both session sites each hardcoded
/// `MissingCause::Gone`, so the claim was made three times and checked
/// nowhere. A source scan rather than a behaviour test because what it
/// refuses is a FOURTH site written by copying one of the three.
///
/// The home file is RESOLVED, not named: `missing_cause` has already
/// moved once (out of pool.rs, to sit beside the other routing masks in
/// gates.rs) and a hardcoded path would have to be a second edit every
/// time - which is how a scan ends up loosened to keep it quiet. Both
/// sites must fall inside the function's own body, so a fifth arm added
/// beside it in the same file is a hit too.
#[test]
fn only_missing_cause_decides_a_terminal_refusals_cause() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/src/");
    let files = [
        "pool.rs",
        "pool/gates.rs",
        "pool/session.rs",
        "pool/runlife.rs",
        "pool/handoff.rs",
        "pool/queue.rs",
        "pool/steer.rs",
        "pool/hedge.rs",
        "pool/park.rs",
        "pool/admit.rs",
    ];
    let mut sites: Vec<(&str, usize)> = Vec::new();
    let mut home: Option<(&str, usize, usize)> = None;
    for rel in files {
        let src = std::fs::read_to_string(format!("{root}{rel}")).unwrap_or_else(|e| {
            panic!("{rel} must be readable - an unread source is not a passing scan: {e}")
        });
        for (n, line) in src.lines().enumerate() {
            // Construction, not the doc-comment cross-references this
            // rule is written up in.
            let code = line.split("//").next().unwrap_or("");
            if code.contains("MissingCause::Gone") || code.contains("MissingCause::Unasked") {
                sites.push((rel, n + 1));
            }
        }
        if let Some(at) = src.find("fn missing_cause(") {
            assert!(home.is_none(), "one definition of `missing_cause`, not two");
            let open = src[at..].find('{').expect("the fn must have a body") + at;
            let mut depth = 0usize;
            let mut close = open;
            for (i, c) in src[open..].char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            close = open + i;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            assert!(close > open, "the body of `missing_cause` must close");
            let line_of = |off: usize| src[..off].lines().count();
            home = Some((rel, line_of(open), line_of(close)));
        }
    }
    let (hrel, hfrom, hto) = home.expect("`Shared::missing_cause` must still exist, by that name");
    assert_eq!(
        sites.len(),
        2,
        "both arms of `Shared::missing_cause` and nothing else may name these causes; \
         found {sites:?} - route the new site through `missing_cause` instead"
    );
    assert!(
        sites
            .iter()
            .all(|&(rel, n)| rel == hrel && n >= hfrom && n <= hto),
        "and they must live inside `missing_cause` ({hrel}:{hfrom}-{hto}): {sites:?}"
    );
}
