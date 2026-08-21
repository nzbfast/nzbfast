//! R9 interning identity tests: the message-id path holds ONE
//! allocation per article and shares it by handle.
//!
//! Pointer identity is the whole subject, which is why these are not in
//! with the queue tests: every assertion here would still pass on a
//! `String` id, because an id that was re-formatted downstream is EQUAL
//! to the one it was copied from. `Arc::ptr_eq` and `Arc::strong_count`
//! are the only things that can tell a shared handle from an equal
//! string, so a reintroduced `format!("<{}>", ..)` on the plan or queue
//! path fails here and nowhere else. The nzbfast half of the pair (the
//! plan's three holders) lives in get/plan.rs, where the interning is
//! born.
//!
//! Split out of inline_tests.rs, which was at its size-gate ceiling.

use super::inline_tests::one_server;
use super::*;

/// R9: the queue MOVES the request's interned id in - it does not copy
/// it. The caller (the fetch plan) keeps its own handle to the same
/// allocation, so the strong count says two and `ptr_eq` says the same
/// allocation. Pointer identity is the assertion: a `Work` rebuilt with
/// `id.to_string()` would satisfy every equality test in this file and
/// silently restore a per-article heap copy on the queue-build path.
#[tokio::test]
async fn the_queue_shares_the_request_id_rather_than_copying_it() {
    let kept: Arc<str> = Arc::from("<shared@x>");
    let reqs = vec![ArticleReq::fresh(kept.clone())];
    let (shared, unservable) = Shared::new(reqs, &one_server());
    assert!(unservable.is_empty());
    let q = shared.queue.try_lock().unwrap();
    assert!(
        Arc::ptr_eq(&q[0].id, &kept),
        "the queued Work copied the id instead of taking the handle"
    );
    assert_eq!(
        Arc::strong_count(&kept),
        2,
        "exactly the caller's handle and the queue's - no third copy"
    );
}
