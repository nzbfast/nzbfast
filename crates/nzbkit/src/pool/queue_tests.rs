//! The `QueueControl` seek/steer handle's own tests: promote, cancel,
//! requeue, and the field-scale cost of a cancel against a full queue.
//!
//! The impl came out of pool.rs whole under the size gate (TODO 106,
//! pool/queue.rs) and these came out of inline_tests.rs the same way,
//! for the same reason - that file sat one line under its ceiling, so
//! any lane touching the queue API reddened the gate on arrival. One
//! subject, one file: everything here drives the handle from OUTSIDE
//! the pool, the way the streaming layer and the in-stream PAR2 sniff
//! do.

use super::inline_tests::one_server;
use super::*;

#[tokio::test]
async fn queue_control_promotes_to_front_preserving_order() {
    // M11: promoted ids move to the front in their original relative
    // order; everything else keeps its order behind them.
    let servers: Vec<(ServerConfig, PoolConfig)> = vec![(
        ServerConfig {
            host: "s".into(),
            port: 119,
            tls: false,
            username: None,
            password: None,
            connections: 1,
            pin_connections: false,
            level: 0,
            group: None,
            retention_days: 0,
            rcvbuf: None,
            block_bytes: None,
            block_account: false,
            bind_ip: None,
            socks5: None,
            enabled: true,
            warm_pool: false,
            idle_release_secs: None,
            idle_keep: None,
            max_source_ips: None,
        },
        PoolConfig::default(),
    )];
    let reqs: Vec<ArticleReq> = (0..10)
        .map(|i| ArticleReq::fresh(format!("<a{i}>")))
        .collect();
    let (shared, unservable) = Shared::new(reqs, &servers);
    assert!(unservable.is_empty());
    let ctl = QueueControl::default();
    ctl.attach(&shared);
    // The caller's order (seek-point-first) is the front order - NOT
    // the queue's relative order.
    let ids: Vec<Arc<str>> = ["<a7>", "<a3>", "<a9>"]
        .iter()
        .map(|s| Arc::from(*s))
        .collect();
    assert_eq!(ctl.promote(&ids), 3);
    let q = shared.queue.lock().await;
    let order: Vec<&str> = q.iter().map(|w| &*w.id).collect();
    assert_eq!(
        order,
        [
            "<a7>", "<a3>", "<a9>", "<a0>", "<a1>", "<a2>", "<a4>", "<a5>", "<a6>", "<a8>"
        ]
    );
    drop(q);
    // Unknown ids are a no-op; a dead pool (Weak gone) is a no-op.
    assert_eq!(ctl.promote(&["<zz>".into()]), 0);
    drop(shared);
    assert_eq!(ctl.promote(&ids), 0);
}

#[tokio::test]
async fn queue_control_cancel_removes_pending_and_completes_them() {
    // Issue #14: cancelled articles leave the queue, count as
    // terminal (pending reaches zero without them), and never emit
    // an outcome. In-flight/unknown ids are untouched.
    let servers = one_server();
    let reqs: Vec<ArticleReq> = (0..6)
        .map(|i| ArticleReq::fresh(format!("<c{i}>")))
        .collect();
    let (shared, unservable) = Shared::new(reqs, &servers);
    assert!(unservable.is_empty());
    let ctl = QueueControl::default();
    ctl.attach(&shared);
    let ids: HashSet<Arc<str>> = ["<c1>", "<c4>", "<zz>"]
        .iter()
        .map(|s| Arc::from(*s))
        .collect();
    let mut removed = ctl.cancel(&ids);
    removed.sort();
    assert_eq!(
        removed.iter().map(|s| &**s).collect::<Vec<_>>(),
        ["<c1>", "<c4>"]
    );
    assert_eq!(shared.pending.load(Ordering::Relaxed), 4);
    let q = shared.queue.lock().await;
    let order: Vec<&str> = q.iter().map(|w| &*w.id).collect();
    assert_eq!(order, ["<c0>", "<c2>", "<c3>", "<c5>"]);
    drop(q);
    // A second cancel of the same ids is a no-op (already done).
    assert!(ctl.cancel(&ids).is_empty());
    assert_eq!(shared.pending.load(Ordering::Relaxed), 4);
    // Cancelling the rest drains the run: `finished` fires so the
    // fleet winds down exactly as if the articles had resolved.
    // (Subscribed BEFORE the send - a watch with no receivers drops
    // the value, exactly like a workerless pool would.)
    let fin = shared.finished.subscribe();
    let rest: HashSet<Arc<str>> = ["<c0>", "<c2>", "<c3>", "<c5>"]
        .iter()
        .map(|s| Arc::from(*s))
        .collect();
    assert_eq!(ctl.cancel(&rest).len(), 4);
    assert_eq!(shared.pending.load(Ordering::Relaxed), 0);
    assert!(*fin.borrow());
    // A dead pool (Weak gone) is a no-op.
    drop(shared);
    assert!(ctl.cancel(&rest).is_empty());
}

#[tokio::test]
async fn queue_control_requeue_resurrects_cancelled_work() {
    // Issue #14 reconcile: a cancelled article can come back exactly
    // as it was - pending restored, un-terminal, queued again. Only
    // ids a prior cancel returned qualify, and a finished run
    // refuses.
    let servers = one_server();
    let reqs: Vec<ArticleReq> = (0..4)
        .map(|i| ArticleReq::fresh(format!("<r{i}>")))
        .collect();
    let (shared, _) = Shared::new(reqs, &servers);
    let ctl = QueueControl::default();
    ctl.attach(&shared);
    let ids: HashSet<Arc<str>> = ["<r1>", "<r2>"].iter().map(|s| Arc::from(*s)).collect();
    let cancelled = ctl.cancel(&ids);
    assert_eq!(cancelled.len(), 2);
    assert_eq!(shared.pending.load(Ordering::Relaxed), 2);
    // Never-cancelled ids are ignored; cancelled ones come back.
    let back: Vec<Arc<str>> = ["<r0>", "<r1>", "<r2>"]
        .iter()
        .map(|s| Arc::from(*s))
        .collect();
    assert_eq!(ctl.requeue(&back), 2);
    assert_eq!(shared.pending.load(Ordering::Relaxed), 4);
    {
        let q = shared.queue.lock().await;
        let mut order: Vec<&str> = q.iter().map(|w| &*w.id).collect();
        order.sort();
        assert_eq!(order, ["<r0>", "<r1>", "<r2>", "<r3>"]);
        let done = shared.done.lock().unwrap();
        assert_eq!(done.count(), 0, "requeued ids must be un-terminal");
    }
    // A second requeue finds an empty stash: no-op.
    assert_eq!(ctl.requeue(&back), 0);
    // Once the run has finished, a requeue must refuse and roll back.
    let fin = shared.finished.subscribe();
    let all: HashSet<Arc<str>> = (0..4).map(|i| Arc::from(format!("<r{i}>"))).collect();
    assert_eq!(ctl.cancel(&all).len(), 4);
    assert_eq!(shared.pending.load(Ordering::Relaxed), 0);
    assert!(*fin.borrow());
    assert_eq!(ctl.requeue(&back), 0);
    assert_eq!(shared.pending.load(Ordering::Relaxed), 0);
}

/// Issue #14 sibling - a MEASUREMENT, not a gate (hence ignored).
/// The in-stream deferral cancels every sniffed volume one
/// `defer_sniffed_slot` at a time, and each `cancel` drains and
/// rebuilds the whole pending queue while holding its mutex -
/// O(queue) per volume, on the lock the dispatcher pops from, during
/// every obfuscated download. This times that lock-hold at field
/// scale so the "real dispatcher pressure" claim is a number. Run:
/// `cargo test -p nzbkit --release queue_control_cancel_cost -- --ignored --nocapture`
#[tokio::test]
#[ignore = "hand-run measurement of the cancel lock-hold, not a regression gate"]
async fn queue_control_cancel_cost_at_field_scale() {
    let servers = one_server();
    let n: usize = 100_000;
    let reqs: Vec<ArticleReq> = (0..n)
        .map(|i| ArticleReq::fresh(format!("<m{i}@bench>")))
        .collect();
    let (shared, _) = Shared::new(reqs, &servers);
    let ctl = QueueControl::default();
    ctl.attach(&shared);
    // Eleven volumes of 60 articles each, at the queue tail - the
    // deferral shape: volume bodies are queued after the payload.
    let mut worst = std::time::Duration::ZERO;
    let mut total = std::time::Duration::ZERO;
    for v in 0..11 {
        let ids: HashSet<Arc<str>> = (0..60)
            .map(|k| Arc::from(format!("<m{}@bench>", n - 1 - v * 60 - k)))
            .collect();
        let t = std::time::Instant::now();
        let removed = ctl.cancel(&ids);
        let dt = t.elapsed();
        assert_eq!(removed.len(), 60);
        worst = worst.max(dt);
        total += dt;
        eprintln!("cancel of volume {v:2}: {dt:?}");
    }
    eprintln!("11 volumes vs a {n}-article queue: total {total:?}, worst single hold {worst:?}");
}
