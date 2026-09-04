//! TODO 315: a refusal that named its own article is still not proof
//! the article is gone. See `Shared::take_recheck` for the measurement
//! that says so and for what the pool now does about it.

use super::super::*;
use super::{ctx_for, fresh, server};
use crate::mock::{Chaos, MockServer, make_file_articles};
use crate::pool::inline_tests::work;
use crate::pool::session::handle_missing;
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

/// TODO 315, 29 Aug 2026: the FOURTH place a held article leaves flight
/// - `next_work`'s unservable scan - must give the budget slot back.
///
/// `Shared::take_recheck`'s own doc named three release sites and all
/// three are in `session`. The one here is the queue's: a held item sits
/// with its re-asked group's bit CLEARED, so it is not unanimous when it
/// is put back; the fleet shrinking under it is what makes it unanimous
/// later, and the scan used to drop the whole `Work` - budget and all.
/// It fails silently, which is why it is pinned: past `recheck_430_max`
/// leaked slots the late re-ask is retired for the rest of the run with
/// nothing anywhere saying so, and up to that many queued holds can leak
/// together.
#[tokio::test]
async fn a_shrinking_fleet_gives_a_held_re_ask_its_budget_back() {
    let servers = vec![
        (server("a"), PoolConfig::default()),
        (server("b"), PoolConfig::default()),
    ];
    let (sh, _) = Shared::new(fresh(&["<held@x>"]), &servers);
    let cfg = PoolConfig {
        recheck_430: true,
        ..Default::default()
    };
    sh.alive[0].fetch_add(1, Ordering::AcqRel);
    sh.alive[1].fetch_add(1, Ordering::AcqRel);
    // Server b has refused it; server a holds its one late re-ask, which
    // is exactly the shape `handle_missing` leaves in the queue - a's bit
    // cleared from `tried_430` and remembered in `recheck_430`.
    {
        let mut q = sh.queue.lock().await;
        let w = q.front_mut().unwrap();
        w.tried_430 = server_bit(1);
        assert!(sh.take_recheck(w, &cfg, server_bit(0)));
    }
    assert_eq!(sh.recheck_held.load(Ordering::Acquire), 1);
    // Server a's last worker dies. Every server still live has refused
    // the article, so the scan removes it as unservable.
    sh.alive[0].fetch_sub(1, Ordering::AcqRel);
    let (tx, mut rx) = mpsc::channel(4);
    let ctx = ctx_for(&servers, 1);
    assert!(
        next_work(&sh, ctx, &tx, Pipeline::payload(0))
            .await
            .is_none()
    );
    assert!(
        matches!(rx.try_recv(), Ok(FetchOutcome::Missing { id, .. }) if &*id == "<held@x>"),
        "the article is terminal once nobody left can be asked"
    );
    assert_eq!(
        sh.recheck_held.load(Ordering::Acquire),
        0,
        "the removed hold must return its slot - a leak here retires the \
         late re-ask for the rest of the run and says nothing"
    );
}

/// TODO 315, 30 Aug 2026: a fleet that does NOT shrink must retire the
/// hold anyway, once its window is up.
///
/// The sibling above is the case where the group holding the article
/// leaves `live_mask` and the scan can retire it for free. This is the
/// case that wedged a live install: the group stays live - alive is not
/// connected, and a parked prober under `server_outage_mins = 0` keeps
/// it alive for the life of the run - so the article is retirable by
/// nobody and dispatchable by nobody, for ever. `next_work`'s scan is
/// the one thing that ever looks at such an item again, which is why
/// the expiry belongs there and not at the verdict sites in `session`.
///
/// The window is a rig-sized 10 ms; the SHIPPED one is pinned against
/// the measurement it covers in `recheck.rs`'s own tests.
#[tokio::test]
async fn a_live_fleet_still_retires_a_hold_once_its_window_is_up() {
    let short = PoolConfig {
        recheck_430: true,
        recheck_430_hold: Duration::from_millis(10),
        ..Default::default()
    };
    let servers = vec![(server("a"), short.clone()), (server("b"), short.clone())];
    let (sh, _) = Shared::new(fresh(&["<held@x>"]), &servers);
    sh.alive[0].fetch_add(1, Ordering::AcqRel);
    sh.alive[1].fetch_add(1, Ordering::AcqRel);
    {
        let mut q = sh.queue.lock().await;
        let w = q.front_mut().unwrap();
        w.tried_430 = server_bit(1);
        assert!(sh.take_recheck(w, &short, server_bit(0)));
        assert!(
            w.recheck_at > 0 || sh.start.elapsed() < Duration::from_millis(1),
            "the hold must be stamped with the run clock, or nothing can date it"
        );
    }
    let (tx, mut rx) = mpsc::channel(4);
    let ctx = ctx_for(&servers, 1);
    // Inside the window the hold stands: server b may not stamp its way
    // past it, and server a is the only one that could take the item.
    assert!(
        next_work(&sh, ctx, &tx, Pipeline::payload(0))
            .await
            .is_none()
    );
    assert!(
        rx.try_recv().is_err(),
        "a hold inside its window must not produce a verdict - that is the mechanism"
    );
    // Past it, the suppressed refusal is evidence again and the article
    // is live-unanimous on the two 430s already in hand.
    // Past `SCAN_RETRY_MS` as well as past the window, and both are
    // needed: the scan just above found nothing takeable, so this
    // server is throttled out of the queue lock for 100 ms and would
    // otherwise return through `pick_dup` without looking at the item
    // at all.
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        next_work(&sh, ctx, &tx, Pipeline::payload(0))
            .await
            .is_none()
    );
    assert!(
        matches!(rx.try_recv(), Ok(FetchOutcome::Missing { id, .. }) if &*id == "<held@x>"),
        "an expired hold owes the caller the verdict its refusals already justified"
    );
    assert_eq!(
        sh.recheck_held.load(Ordering::Acquire),
        0,
        "and the expiry path releases the budget slot like every other exit"
    );
}

/// TODO 315: the stamp is the run clock and not a constant.
///
/// Pinned on its own because the rigs cannot see it: they finish in
/// seconds, so a `recheck_at` frozen at 0 still dates every hold inside
/// a fifteen-minute window and every one of them passes. What it breaks
/// is the run this bound exists for - a hold taken an hour in would be
/// stamped as an hour old and expire on the spot, which is the
/// mechanism switched off for exactly the long downloads it was
/// measured on.
#[tokio::test]
async fn a_hold_is_stamped_with_the_run_clock() {
    let servers = vec![
        (server("a"), PoolConfig::default()),
        (server("b"), PoolConfig::default()),
    ];
    let (sh, _) = Shared::new(fresh(&["<held@x>"]), &servers);
    let cfg = PoolConfig {
        recheck_430: true,
        ..Default::default()
    };
    tokio::time::sleep(Duration::from_millis(25)).await;
    let mut q = sh.queue.lock().await;
    let w = q.front_mut().unwrap();
    w.tried_430 = server_bit(1);
    assert!(sh.take_recheck(w, &cfg, server_bit(0)));
    assert!(
        w.recheck_at >= 20,
        "a hold taken {:?} into the run was stamped {} ms - the stamp is not tracking \
         the run clock",
        sh.start.elapsed(),
        w.recheck_at
    );
}

/// TODO 315, 30 Aug 2026: the DUPLICATE FOLD is the other arm that
/// decides an article's terminality, and it has to know the hold is
/// bounded or a dup can only ever wait for a queue scan to notice.
///
/// The fold refuses to stamp a bit a live hold is holding open - that
/// refusal is the mechanism, and `next_work`'s own note is the reason
/// ("unanimity simply cannot be reached while the held group's own bit
/// is down, which is the point"). Past the window there is no hold to
/// protect, so the same refusal is just the verdict withheld twice.
///
/// The two halves are driven in one test on purpose: an arm that
/// stamped unconditionally would pass the second assertion and fail the
/// first, and one that never stamps passes the first and fails the
/// second, so neither can be satisfied by loosening the other.
#[tokio::test]
async fn a_duplicates_refusal_folds_once_the_hold_it_waits_on_has_expired() {
    let short = PoolConfig {
        recheck_430: true,
        recheck_430_hold: Duration::from_millis(10),
        ..Default::default()
    };
    let servers = vec![(server("a"), short.clone()), (server("b"), short.clone())];
    let (sh, _) = Shared::new(fresh(&["<dupheld@x>"]), &servers);
    sh.alive[0].fetch_add(1, Ordering::AcqRel);
    sh.alive[1].fetch_add(1, Ordering::AcqRel);
    // The queued copy in exactly the shape `handle_missing` leaves: b
    // has refused, a holds its one late re-ask, so a's bit is down.
    {
        let mut q = sh.queue.lock().await;
        let w = q.front_mut().unwrap();
        w.tried_430 = server_bit(1);
        assert!(sh.take_recheck(w, &short, server_bit(0)));
    }
    let ctx = ctx_for(&servers, 0);
    let (tx, mut rx) = mpsc::channel(8);

    // A duplicate dispatch of the same article on server a comes back
    // refused - and echoed, so it is proven evidence rather than the
    // positional kind the arm above it drops.
    // `Work` is not Clone, so each dispatch builds its own - which is
    // what a second duplicate really is anyway.
    let mk_dup = || {
        let mut d = work("<dupheld@x>");
        d.dup = true;
        d
    };
    let mut inflight: VecDeque<Work> = [mk_dup()].into_iter().collect();
    sh.charge_wire();
    handle_missing(
        &short,
        ctx,
        &sh,
        &tx,
        &mut inflight,
        PooledBuf::unpooled(Vec::new()),
        true,
        false,
        &mut Default::default(),
    )
    .await;
    assert!(
        rx.try_recv().is_err(),
        "inside the window this dup is the same evidence the hold is doubting - folding \
         it reports the Missing the re-ask was bought to test"
    );

    tokio::time::sleep(Duration::from_millis(30)).await;
    let mut inflight: VecDeque<Work> = [mk_dup()].into_iter().collect();
    sh.charge_wire();
    handle_missing(
        &short,
        ctx,
        &sh,
        &tx,
        &mut inflight,
        PooledBuf::unpooled(Vec::new()),
        true,
        false,
        &mut Default::default(),
    )
    .await;
    assert!(
        matches!(rx.try_recv(), Ok(FetchOutcome::Missing { id, .. }) if &*id == "<dupheld@x>"),
        "past the window there is no hold left to protect, so the dup's refusal is \
         ordinary evidence and the article is live-unanimous on it"
    );
}

/// TODO 315: the fleet fold takes the MOST GENEROUS window any server
/// asked for, never the least.
///
/// Pinned because nothing else can see it: every rig here configures
/// one window across the whole fleet, so `max` and `min` are the same
/// number and a fold quietly narrowed to `min` passes every other test
/// in this file. What it would do is let one server's short window
/// shorten a hold somebody deliberately lengthened on another.
#[tokio::test]
async fn the_hold_window_folds_to_the_longest_any_server_asked_for() {
    let mixed = vec![
        (
            server("a"),
            PoolConfig {
                recheck_430_hold: Duration::from_millis(10),
                ..Default::default()
            },
        ),
        (
            server("b"),
            PoolConfig {
                recheck_430_hold: Duration::from_millis(90_000),
                ..Default::default()
            },
        ),
    ];
    let (sh, _) = Shared::new(fresh(&["<w@x>"]), &mixed);
    assert_eq!(sh.recheck_hold_ms, 90_000);
}

/// TODO 315: a cancelled hold gives its budget slot back, and a requeue
/// takes it again.
///
/// The FIFTH release site (see `Shared::take_recheck`). A late re-ask
/// waits in the ordinary queue, so `QueueControl::cancel` can name one:
/// the §146 tail give-up commit cancels every walker it claims, the
/// par-race cancels its stragglers, and the in-stream PAR2 sniff cancels
/// every remaining segment of a covered slot - the same damaged-post
/// population that produces holds in the first place. A cancelled Work
/// is stashed in `cancelled` and nothing ever walks it again: not the
/// expiry scan, which only reads the QUEUE, and not any verdict site. So
/// a missed release here is charged for the life of the run, and once
/// `recheck_430_max` slots are gone the mechanism retires itself in
/// silence - the exact failure the four earlier releases exist to
/// prevent.
///
/// The requeue half is the same bug in the other direction: a queued
/// hold with nothing charged behind it refunds a slot ANOTHER article
/// holds when it finally goes terminal.
#[tokio::test]
async fn a_cancelled_hold_gives_its_budget_back_and_a_requeue_takes_it_again() {
    let servers = vec![
        (server("a"), PoolConfig::default()),
        (server("b"), PoolConfig::default()),
    ];
    let (sh, _) = Shared::new(fresh(&["<held@x>", "<other@x>"]), &servers);
    let cfg = PoolConfig {
        recheck_430: true,
        ..Default::default()
    };
    sh.alive[0].fetch_add(1, Ordering::AcqRel);
    sh.alive[1].fetch_add(1, Ordering::AcqRel);
    let ctl = QueueControl::default();
    ctl.attach(&sh);
    // Exactly the shape `handle_missing` leaves in the queue: server b
    // refused, server a holds the article's one late re-ask.
    {
        let mut q = sh.queue.lock().await;
        let w = q.front_mut().unwrap();
        w.tried_430 = server_bit(1);
        assert!(sh.take_recheck(w, &cfg, server_bit(0)));
    }
    assert_eq!(sh.recheck_held.load(Ordering::Acquire), 1);
    let ids: HashSet<Arc<str>> = ["<held@x>"].iter().map(|s| Arc::from(*s)).collect();
    assert_eq!(ctl.cancel(&ids).len(), 1, "the held article is cancellable");
    assert_eq!(
        sh.recheck_held.load(Ordering::Acquire),
        0,
        "a cancelled hold must return its slot - a leak here retires the \
         late re-ask for the rest of the run and says nothing"
    );
    // And back: the article is in the queue again with its bit still
    // recorded, so the budget has to show it held again.
    let back: Vec<Arc<str>> = ids.iter().cloned().collect();
    assert_eq!(ctl.requeue(&back), 1);
    assert_eq!(
        sh.recheck_held.load(Ordering::Acquire),
        1,
        "a resurrected hold is charged again, or its later terminal \
         release refunds a slot another article is holding"
    );
    let q = sh.queue.lock().await;
    assert!(
        q.iter().any(|w| &*w.id == "<held@x>" && w.recheck_430 != 0),
        "the requeued Work still carries the hold it was cancelled with"
    );
}
