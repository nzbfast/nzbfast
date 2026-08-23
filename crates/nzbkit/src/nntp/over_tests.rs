//! OVER / XOVER: the capability latch, the XOVER fallback, empty
//! ranges, the compressed body path, and the desync fence.
//!
//! A child module (the `unit_tests` pattern) so nntp.rs stays inside
//! its size-gate entry; `super::*` spellings keep the private
//! internals reachable.

use super::Connection;
use crate::mock::{Chaos, MockServer, OverRow};
use std::collections::HashMap;

fn rows() -> Vec<OverRow> {
    (1..=5)
        .map(|n| OverRow {
            number: n,
            subject: format!("post {n}"),
            from: "a@b".into(),
            message_id: format!("<m{n}@x>"),
            bytes: 1000,
        })
        .collect()
}

#[tokio::test]
async fn xover_only_server_latches_after_first_rejection() {
    let srv = MockServer::start_full(
        HashMap::new(),
        HashMap::new(),
        rows(),
        Chaos {
            xover_only: true,
            ..Default::default()
        },
    )
    .await;
    let (mut conn, _) = Connection::connect(&srv.server_config())
        .await
        .expect("connect");
    conn.group("mock.group").await.expect("group");
    let es = conn.over(1, 5).await.expect("over via xover fallback");
    assert_eq!(es.len(), 5);
    assert_eq!(
        conn.over_supported,
        Some(false),
        "unknown-command rejection must latch the XOVER-only path"
    );
    // Second call goes straight to XOVER (no doomed OVER round-trip)
    // and still returns rows.
    let es = conn.over(2, 4).await.expect("second over");
    assert_eq!(es.len(), 3);
    conn.quit().await;
}

/// TODO 23: `note_over_progress` must credit the wire on BOTH OVER
/// body paths.
///
/// The header scan's collector deadline re-arms on this counter, so
/// a path that never moves it reads as a dead stream and the scan
/// abandons a range it was halfway through. The plain path was the
/// obvious one to wire up; the compressed path is a separate reader
/// and would have been silently left behind.
#[tokio::test]
async fn note_over_progress_credits_both_body_paths() {
    for gzip in [false, true] {
        let srv = MockServer::start_full(
            HashMap::new(),
            HashMap::new(),
            rows(),
            Chaos {
                gzip_headers: gzip,
                ..Default::default()
            },
        )
        .await;
        let (mut conn, _) = Connection::connect(&srv.server_config())
            .await
            .expect("connect");
        conn.group("mock.group").await.expect("group");
        if gzip {
            assert!(conn.enable_header_gzip().await, "290 must enable");
        }
        let seen = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        conn.note_over_progress(seen.clone());
        let es = conn.over(1, 5).await.expect("over");
        assert_eq!(es.len(), 5);
        assert!(
            seen.load(std::sync::atomic::Ordering::Relaxed) > 0,
            "gzip={gzip}: the OVER body moved no bytes past the watcher"
        );
        conn.quit().await;
    }
}

#[tokio::test]
async fn gzip_headers_roundtrip_and_fallback() {
    // Server accepts XFEATURE: compressed responses parse to the
    // same entries the plain path produces, repeatedly.
    let srv = MockServer::start_full(
        HashMap::new(),
        HashMap::new(),
        rows(),
        Chaos {
            gzip_headers: true,
            ..Default::default()
        },
    )
    .await;
    let (mut conn, _) = Connection::connect(&srv.server_config())
        .await
        .expect("connect");
    conn.group("mock.group").await.expect("group");
    assert!(conn.enable_header_gzip().await, "290 must enable");
    let es = conn.over(1, 5).await.expect("compressed over");
    assert_eq!(es.len(), 5);
    assert_eq!(es[0].subject, "post 1");
    assert_eq!(es[4].message_id, "<m5@x>");
    let es = conn.over(2, 3).await.expect("second compressed over");
    assert_eq!(es.len(), 2);
    conn.quit().await;

    // Server that rejects the feature: enable returns false and the
    // plain path still works untouched.
    let srv =
        MockServer::start_full(HashMap::new(), HashMap::new(), rows(), Chaos::default()).await;
    let (mut conn, _) = Connection::connect(&srv.server_config())
        .await
        .expect("connect");
    conn.group("mock.group").await.expect("group");
    assert!(!conn.enable_header_gzip().await, "no 290 = stay plain");
    let es = conn.over(1, 5).await.expect("plain over");
    assert_eq!(es.len(), 5);
    conn.quit().await;
}

#[tokio::test]
async fn over_capable_server_latches_supported() {
    let srv =
        MockServer::start_full(HashMap::new(), HashMap::new(), rows(), Chaos::default()).await;
    let (mut conn, _) = Connection::connect(&srv.server_config())
        .await
        .expect("connect");
    conn.group("mock.group").await.expect("group");
    let es = conn.over(1, 5).await.expect("over");
    assert_eq!(es.len(), 5);
    assert_eq!(conn.over_supported, Some(true));
    conn.quit().await;
}

#[tokio::test]
async fn empty_range_reads_as_no_articles_not_a_failed_pass() {
    // A resuming scan asks for everything above its high-water mark.
    // When nothing new has arrived, that range is valid and empty and
    // the server answers 423. Reading that as a failure stalled the
    // whole pass: the caller bailed out, never advanced its mark, and
    // asked for the identical empty range on every retry, forever.
    let srv =
        MockServer::start_full(HashMap::new(), HashMap::new(), rows(), Chaos::default()).await;
    let (mut conn, _) = Connection::connect(&srv.server_config())
        .await
        .expect("connect");
    let g = conn.group("mock.group").await.expect("group");
    let es = conn
        .over(g.high + 1, g.high + 1000)
        .await
        .expect("an empty range is not a failure");
    assert!(es.is_empty(), "an empty range yields no rows");
    // And the session survives it - nothing was left half-read on the
    // wire, so the next chunk of the same pass still returns its rows.
    let es = conn.over(1, 5).await.expect("over after an empty range");
    assert_eq!(es.len(), 5);
    conn.quit().await;
}

#[tokio::test]
async fn a_rejected_over_is_still_an_error() {
    // The empty-range arm stays narrow: 411 no-such-group (like every
    // 5xx) means we learned NOTHING about the range, so it must not
    // read as "nothing here" and let a caller skip past those articles.
    let srv = MockServer::start_full(
        HashMap::new(),
        HashMap::new(),
        rows(),
        Chaos {
            over_rejected: true,
            ..Default::default()
        },
    )
    .await;
    let (mut conn, _) = Connection::connect(&srv.server_config())
        .await
        .expect("connect");
    conn.group("mock.group").await.expect("group");
    assert!(
        conn.over(1, 5).await.is_err(),
        "411 must not be mistaken for an empty range"
    );
    conn.quit().await;
}
