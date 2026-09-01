//! Sweep 8, M2 and M8: the two defects in the consumer steer's
//! provisional BODY ownership, pinned at the seam that carries them.
//!
//! Both live in the window between a delivered body's `claim_done` and
//! the decode verdict that may still send the article back down the
//! ladder. M2 is a lifetime bug (the refetch was publishable before it
//! was unclaimed, so a worker could adopt and complete it into a claim
//! that was still spent, and the article vanished with `pending` still
//! counting it). M8 is an evidence bug (the provisional claim dropped
//! the article's `spent` mask, which is the routing evidence that
//! opened the fill tier the retry has to go to).
//!
//! These drive the production functions - `next_work`,
//! `requeue_or_fail`, `claim_done`, `stash_handed`, `note_decoded` -
//! in the order and with the arguments `pool/session.rs` uses. Only
//! the socket is absent: a full mock-fleet leg cannot pin M8 because
//! WHICH of two same-level fill peers picks the article first is a
//! coin flip, and the leg passes for the wrong reason half the time.

use super::*;
use crate::config::ServerConfig;

fn server(host: &str, level: u32) -> ServerConfig {
    ServerConfig {
        host: host.into(),
        port: 119,
        tls: false,
        username: None,
        password: None,
        connections: 1,
        pin_connections: false,
        rcvbuf: None,
        level,
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
    }
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

/// M2: a steered refetch must never be adoptable while its old done
/// bit is still set.
///
/// The trigger, from the handoff: the verdict thread publishes the
/// retry into `steer_inbox` and is preempted before clearing the bit.
/// A worker drains the inbox, dispatches, and - with a local or cached
/// provider, or across any long enough scheduler pause - the refetch
/// COMES BACK inside that window. `claim_done` finds the bit still
/// spent and discards the only good copy as a duplicate, deregistering
/// it. The verdict thread then clears the bit over an article that is
/// in no queue, no inbox and no inflight map while `pending` still
/// counts it: every worker waits for work that no longer exists and
/// only an outer watchdog ends the job.
///
/// The barrier parks the verdict thread INSIDE that window - the one
/// place the property can be observed - and this thread then plays the
/// worker's adoption against it. The fix holds the inbox guard across
/// the whole window, which is the same mutex `next_work` takes to
/// drain, so the adoption cannot even see the entry. Before the fix
/// the try_lock succeeds, the entry is there, and its bit is still
/// claimed.
#[test]
fn a_steered_refetch_is_not_adoptable_before_it_is_unclaimed() {
    let servers = vec![
        (server("p", 0), PoolConfig::default()),
        (server("q", 0), PoolConfig::default()),
    ];
    let id: Arc<str> = "<m2window@x>".into();
    let (sh, _) = Shared::new(fresh(&[&id]), &servers);
    sh.workers_live.store(1, Ordering::Release);
    sh.alive[0].store(1, Ordering::Relaxed);
    sh.alive[1].store(1, Ordering::Relaxed);
    let ctl = Arc::new(QueueControl::default());
    ctl.attach(&sh);

    // The delivery: exactly pool/session.rs's order for a claimed body.
    let w = work(&id);
    assert!(sh.claim_done(&w.id, w.ord), "the delivering worker claims");
    sh.stash_handed(&w, ctx_for(&servers, 0), 0);

    let barrier = Arc::new(std::sync::Barrier::new(2));
    *queue::STEER_WINDOW.lock_ok() = Some((id.clone(), barrier.clone()));

    let verdict = {
        let ctl = ctl.clone();
        let id = id.clone();
        std::thread::spawn(move || ctl.note_decoded(&id, DecodeReport::Bad { why: "pcrc32" }))
    };

    // Rendezvous: the verdict thread is inside the publish/un-claim
    // window with the refetch already pushed.
    barrier.wait();
    match sh.steer_inbox.try_lock() {
        Err(_) => {
            // The fix: a draining worker parks on the inbox mutex for
            // the rest of the window, so it cannot adopt anything.
            assert!(
                sh.done.lock_ok().contains(w.ord),
                "the article is still owned while the window is open, which is why \
                 the inbox must stay shut"
            );
        }
        Ok(mut inbox) => {
            // Pre-fix shape: the entry is visible. Adopting it here is
            // exactly what a worker's `next_work` drain does, and the
            // refetch that comes back is then thrown away.
            let adopted = inbox.drain(..).next();
            drop(inbox);
            if let Some(a) = adopted {
                assert!(
                    sh.claim_done(&a.id, a.ord),
                    "a worker that can adopt the refetch must be able to complete it - \
                     the article was published while its old done bit was still set, \
                     so the only refetch is discarded as a duplicate and the run wedges"
                );
            }
        }
    }
    barrier.wait();

    assert!(
        matches!(verdict.join().unwrap(), DecodeAck::Steered),
        "a bad body with an eligible elsewhere steers"
    );
    *queue::STEER_WINDOW.lock_ok() = None;

    // The window is closed: now the adoption is legal, and the refetch
    // it completes claims the one outcome the article ever gets.
    let adopted = {
        let mut inbox = sh.steer_inbox.lock_ok();
        assert_eq!(inbox.len(), 1, "the refetch is published exactly once");
        inbox.drain(..).next().unwrap()
    };
    assert!(
        sh.claim_done(&adopted.id, adopted.ord),
        "the refetch completes into an unowned article"
    );
    sh.complete_one();
    assert_eq!(
        sh.pending.load(Ordering::Acquire),
        0,
        "one terminal outcome, and nothing left pending"
    );
}

/// M8: the routing evidence that opened the fill tier must survive the
/// provisional claim.
///
/// A is the level-0 primary and kills this article's connection on
/// every attempt, so it files no 430 and its `spent` bit is the only
/// evidence the fill tier may run. B and C are same-level fill peers.
/// B delivers a corrupt body; `claim_done` drops A's spent entry as it
/// would for any terminal article. Before this fix the bad-body
/// verdict then asked `other_can_take` with that evidence already
/// erased, read "nobody else can have it", and OWNED the damage - the
/// job fell into PAR2 (or died) with C holding a clean copy and never
/// being asked.
///
/// Two halves have to hold, because the steer passes through two
/// separate gates that read the same map: the verdict's eligibility
/// check, and `next_work`'s pickup gate when C actually adopts the
/// requeue.
#[tokio::test]
async fn a_bad_fill_body_keeps_the_spent_evidence_that_opened_its_tier() {
    let servers = vec![
        (server("A-primary", 0), PoolConfig::default()),
        (server("B-fill", 1), PoolConfig::default()),
        (server("C-fill", 1), PoolConfig::default()),
    ];
    let id: Arc<str> = "<m8fill@x>".into();
    let (sh, _) = Shared::new(fresh(&[&id]), &servers);
    sh.workers_live.store(3, Ordering::Release);
    for a in sh.alive.iter() {
        a.store(1, Ordering::Relaxed);
    }
    let ctl = QueueControl::default();
    ctl.attach(&sh);
    let cfg = PoolConfig::default();
    let (tx, mut rx) = mpsc::channel(4);
    let ctx_a = ctx_for(&servers, 0);
    let ctx_b = ctx_for(&servers, 1);
    let ctx_c = ctx_for(&servers, 2);

    // A burns its whole budget in transport - no answer, so no 430.
    for attempt in 0..=cfg.article_retries {
        sh.scan_futile[0].store(u64::MAX, Ordering::Relaxed);
        let w = next_work(&sh, ctx_a, &tx, Pipeline::payload(0))
            .await
            .unwrap_or_else(|| panic!("the primary picks it on attempt {attempt}"));
        sh.charge_wire();
        sh.register_inflight(&w, 0);
        let mut inflight: VecDeque<Work> = VecDeque::new();
        inflight.push_back(w);
        requeue_or_fail(
            &sh,
            &tx,
            &cfg,
            ctx_a,
            &mut inflight,
            FailCode::Transport,
            "rst",
            true,
        )
        .await;
    }
    assert_eq!(
        sh.spent_mask(&id),
        server_bit(0),
        "the spent primary is the only thing that opens the fill tier"
    );

    // B's turn: the gate is satisfied, and it delivers a corrupt body.
    sh.scan_futile[1].store(u64::MAX, Ordering::Relaxed);
    let w = next_work(&sh, ctx_b, &tx, Pipeline::payload(0))
        .await
        .expect("a spent primary lets the fill tier through");
    sh.register_inflight(&w, 1);
    sh.deregister_inflight_done(&w);
    // pool/session.rs's delivery order, verbatim: read the routing
    // evidence, then claim, then stash for the verdict.
    let spent_ev = sh.spent_mask(&w.id);
    assert!(sh.claim_done(&w.id, w.ord), "B's body claims the article");
    assert_eq!(
        sh.spent_mask(&w.id),
        0,
        "and the claim drops the live evidence - which is the bug"
    );
    sh.stash_handed(&w, ctx_b, spent_ev);

    assert!(
        matches!(
            ctl.note_decoded(&id, DecodeReport::Bad { why: "pcrc32" }),
            DecodeAck::Steered
        ),
        "C is a live same-level peer that has not seen this article: the bad body \
         must be refetched, not owned"
    );

    // Second half: C has to be able to PICK it. `next_work`'s fill
    // gate reads the same map the verdict did, so a steer that does
    // not put the evidence back is admitted and then gated out.
    assert_eq!(
        sh.spent_mask(&id),
        server_bit(0),
        "the requeue hands the ladder its evidence back"
    );
    sh.scan_futile[2].store(u64::MAX, Ordering::Relaxed);
    let picked = next_work(&sh, ctx_c, &tx, Pipeline::payload(0))
        .await
        .expect("the clean fill peer picks up the steered refetch");
    assert_eq!(&*picked.id, &*id);
    assert_eq!(
        picked.tried_fail & ctx_b.group_bits,
        ctx_b.group_bits,
        "and it will never be steered back to the backbone that served the damage"
    );

    // C's clean body ends the article: one outcome, no repair.
    assert!(sh.claim_done(&picked.id, picked.ord));
    sh.stash_handed(&picked, ctx_c, sh.spent_mask(&picked.id));
    assert!(matches!(
        ctl.note_decoded(&id, DecodeReport::Clean { part: None }),
        DecodeAck::Owned
    ));
    assert_eq!(sh.pending.load(Ordering::Acquire), 0);
    assert!(
        rx.try_recv().is_err(),
        "the article was never declared lost"
    );
}

/// A peerless fleet must re-ask its own bad body.
///
/// The 31 Aug 2026 finding
/// (`research/CORRUPT-BODY-NO-SECOND-ASK-2026-08-31.md`): the steer was
/// the ONLY retry a corrupt body ever got, so with no eligible peer the
/// article was terminal damage on the first bad copy, while a genuinely
/// MISSING article was requeued and could still complete. On a
/// single-server install that is every corrupt article there is.
///
/// The re-ask needs no routing rule of its own, which is what makes it
/// small: the requeue folds the deliverer's group into `tried_fail`
/// exactly as a peer steer does, and `next_work` already lets a server
/// retake an article it failed when nobody else can have it - the
/// pre-tier behaviour `Work::tried_fail` documents for a transport
/// failure. So the same-server re-ask IS the transport-failure ladder,
/// reached from the decode verdict.
#[tokio::test]
async fn a_peerless_fleet_re_asks_its_own_bad_body() {
    let servers = vec![(server("solo", 0), PoolConfig::default())];
    let id: Arc<str> = "<solo@x>".into();
    let (sh, _) = Shared::new(fresh(&[&id]), &servers);
    sh.workers_live.store(1, Ordering::Release);
    sh.alive[0].store(1, Ordering::Relaxed);
    let ctl = QueueControl::default();
    ctl.attach(&sh);
    let (tx, mut rx) = mpsc::channel(4);
    let ctx = ctx_for(&servers, 0);
    let budget0 = sh.reask_waste.load(Ordering::Acquire);
    assert!(budget0 >= 1, "even a one-article run gets one re-ask");

    let w = deliver(&sh, &servers, 0, &tx).await;
    assert!(
        matches!(
            ctl.note_decoded(&id, DecodeReport::Bad { why: "pcrc32" }),
            DecodeAck::Steered
        ),
        "the only server there is must be asked again rather than owning the damage"
    );
    assert_eq!(
        sh.reask_waste.load(Ordering::Acquire),
        budget0 - 1,
        "the ask is charged while its outcome is unknown"
    );
    assert!(
        !sh.done.lock_ok().contains(w.ord),
        "un-claimed for the retry"
    );

    // The same server picks its own casualty back up.
    sh.scan_futile[0].store(u64::MAX, Ordering::Relaxed);
    let again = next_work(&sh, ctx, &tx, Pipeline::payload(0))
        .await
        .expect("with nobody else to take it, the deliverer retakes its own casualty");
    assert_eq!(&*again.id, &*id);
    assert_eq!(
        again.tried_fail & ctx.group_bits,
        ctx.group_bits,
        "the bad deliverer is still recorded, so a peer that appears is preferred"
    );

    // Second copy is clean: no damage, and the wasted-ask budget comes
    // back because the ask was not wasted.
    sh.register_inflight(&again, 0);
    sh.deregister_inflight_done(&again);
    let spent_ev = sh.spent_mask(&again.id);
    assert!(sh.claim_done(&again.id, again.ord));
    sh.stash_handed(&again, ctx, spent_ev);
    assert!(matches!(
        ctl.note_decoded(&id, DecodeReport::Clean { part: None }),
        DecodeAck::Owned
    ));
    assert_eq!(
        sh.reask_waste.load(Ordering::Acquire),
        budget0,
        "a re-ask that WORKED is not waste and must not shrink the budget"
    );
    assert_eq!(sh.pending.load(Ordering::Acquire), 0);
    assert!(
        rx.try_recv().is_err(),
        "the article was never declared lost"
    );
}

/// The second bad copy from the only server ends it, and keeps the
/// unit: that is the ONLY thing that ever depletes the budget.
///
/// `crc_retried` is one decode-seam requeue per id ever, shared by both
/// destinations, so this arm is reached by the per-id pass and not by
/// the run budget - which is what keeps the same-server re-ask strictly
/// additive to the shipped steer.
#[tokio::test]
async fn a_second_bad_copy_from_the_only_server_is_owned() {
    let servers = vec![(server("solo", 0), PoolConfig::default())];
    let id: Arc<str> = "<twice@x>".into();
    let (sh, _) = Shared::new(fresh(&[&id]), &servers);
    sh.workers_live.store(1, Ordering::Release);
    sh.alive[0].store(1, Ordering::Relaxed);
    let ctl = QueueControl::default();
    ctl.attach(&sh);
    let (tx, _rx) = mpsc::channel(4);
    let ctx = ctx_for(&servers, 0);
    let budget0 = sh.reask_waste.load(Ordering::Acquire);

    deliver(&sh, &servers, 0, &tx).await;
    assert!(matches!(
        ctl.note_decoded(&id, DecodeReport::Bad { why: "pcrc32" }),
        DecodeAck::Steered
    ));
    sh.scan_futile[0].store(u64::MAX, Ordering::Relaxed);
    let again = next_work(&sh, ctx, &tx, Pipeline::payload(0))
        .await
        .unwrap();
    sh.register_inflight(&again, 0);
    sh.deregister_inflight_done(&again);
    let spent_ev = sh.spent_mask(&again.id);
    assert!(sh.claim_done(&again.id, again.ord));
    sh.stash_handed(&again, ctx, spent_ev);
    assert!(
        matches!(
            ctl.note_decoded(&id, DecodeReport::Bad { why: "pcrc32" }),
            DecodeAck::Owned
        ),
        "one ask per article: the second bad copy is damage, as it was before"
    );
    assert_eq!(
        sh.reask_waste.load(Ordering::Acquire),
        budget0 - 1,
        "an ask that came back bad again is exactly what the budget counts"
    );
    assert_eq!(sh.pending.load(Ordering::Acquire), 0);
}

/// A part mismatch is never re-asked from the same server, and this
/// carve-out is what makes the seam safe to leave on for a peerless
/// fleet.
///
/// A mismatch is a disagreement about IDENTITY between the NZB's
/// segment numbering and this backbone, not damage to a body - the body
/// passed its own CRC. The same backbone answers the same way every
/// time, and the `part_latch` stand-down that ends the doubled fetch
/// needs a DIFFERENT group to agree with the first, which one server can
/// never provide. Without this, a poster with synthesized segment
/// numbers would cost a single-server install a second fetch of every
/// article of the file.
#[tokio::test]
async fn a_part_mismatch_is_never_re_asked_from_the_same_server() {
    let servers = vec![(server("solo", 0), PoolConfig::default())];
    let id: Arc<str> = "<partmm@x>".into();
    let mut reqs = fresh(&[&id]);
    reqs[0].part = 7;
    let (sh, _) = Shared::new(reqs, &servers);
    sh.workers_live.store(1, Ordering::Release);
    sh.alive[0].store(1, Ordering::Relaxed);
    let ctl = QueueControl::default();
    ctl.attach(&sh);
    let (tx, _rx) = mpsc::channel(4);
    let budget0 = sh.reask_waste.load(Ordering::Acquire);

    deliver(&sh, &servers, 0, &tx).await;
    assert!(
        matches!(
            ctl.note_decoded(&id, DecodeReport::Clean { part: Some(3) }),
            DecodeAck::Owned
        ),
        "asking the same backbone again just re-states its own numbering"
    );
    assert_eq!(
        sh.reask_waste.load(Ordering::Acquire),
        budget0,
        "and it must not spend the damage budget doing so"
    );
    assert_eq!(sh.pending.load(Ordering::Acquire), 0);
}

/// The budget stops a peerless corrupt storm, and stops nothing else.
///
/// Sized off the run's articles (an eighth, clamped to
/// [`REASK_WASTE_CAP`]), so this nine-article run gets exactly one - and
/// the tenth article of a spool that is damaged outright is owned
/// without an ask, which is the doubled fetch TODO 114 chose the steer
/// to avoid.
#[tokio::test]
async fn the_re_ask_budget_bounds_a_peerless_corrupt_storm() {
    let servers = vec![(server("solo", 0), PoolConfig::default())];
    let ids: Vec<String> = (0..9).map(|i| format!("<storm{i}@x>")).collect();
    let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    let (sh, _) = Shared::new(fresh(&refs), &servers);
    sh.workers_live.store(1, Ordering::Release);
    sh.alive[0].store(1, Ordering::Relaxed);
    let ctl = QueueControl::default();
    ctl.attach(&sh);
    let (tx, _rx) = mpsc::channel(32);
    assert_eq!(
        sh.reask_waste.load(Ordering::Acquire),
        1,
        "nine articles buy one wasted ask, not thirty-two"
    );

    let mut steered = 0;
    for _ in 0..9 {
        let w = deliver(&sh, &servers, 0, &tx).await;
        if matches!(
            ctl.note_decoded(&w.id, DecodeReport::Bad { why: "pcrc32" }),
            DecodeAck::Steered
        ) {
            steered += 1;
            // The retry is also bad: the ask is wasted and stays charged.
            let ctx = ctx_for(&servers, 0);
            sh.scan_futile[0].store(u64::MAX, Ordering::Relaxed);
            let again = next_work(&sh, ctx, &tx, Pipeline::payload(0))
                .await
                .unwrap();
            sh.register_inflight(&again, 0);
            sh.deregister_inflight_done(&again);
            let ev = sh.spent_mask(&again.id);
            assert!(sh.claim_done(&again.id, again.ord));
            sh.stash_handed(&again, ctx, ev);
            assert!(matches!(
                ctl.note_decoded(&again.id, DecodeReport::Bad { why: "pcrc32" }),
                DecodeAck::Owned
            ));
        }
    }
    assert_eq!(
        steered, 1,
        "a server whose copies are all bad is asked twice for ONE article and then believed"
    );
    assert_eq!(sh.pending.load(Ordering::Acquire), 0);
}

/// One delivery, in pool/session.rs's order, from the queue's own next
/// pick. Returns the `Work` the server picked, already stashed for the
/// verdict.
async fn deliver(
    sh: &Arc<Shared>,
    servers: &[(ServerConfig, PoolConfig)],
    si: usize,
    tx: &mpsc::Sender<FetchOutcome>,
) -> Work {
    let ctx = ctx_for(servers, si);
    sh.scan_futile[si].store(u64::MAX, Ordering::Relaxed);
    let w = next_work(sh, ctx, tx, Pipeline::payload(0))
        .await
        .expect("the server has work to take");
    sh.register_inflight(&w, si);
    sh.deregister_inflight_done(&w);
    let spent_ev = sh.spent_mask(&w.id);
    assert!(sh.claim_done(&w.id, w.ord), "the delivering worker claims");
    sh.stash_handed(&w, ctx, spent_ev);
    w
}

fn fresh(ids: &[&str]) -> Vec<ArticleReq> {
    ids.iter().map(|id| ArticleReq::fresh(*id)).collect()
}
