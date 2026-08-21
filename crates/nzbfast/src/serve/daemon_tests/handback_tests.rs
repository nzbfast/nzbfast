//! B4: a pass hands its own connection back instead of re-running the
//! `Index::open` migration ladder and flushing the read pool after
//! every pass. These pin the three claims the change rests on: an
//! existing shared connection is KEPT (WAL makes the pass's commits
//! visible through it without a reopen), the first hand-back still
//! installs a connection and sets `index_migrated` (the 28 Jul / 2 Aug
//! wedge seam), and a stale-era hand-back is dropped rather than
//! resurrecting a wiped or switched-off index. `use super::*` carries
//! `with_daemon` and daemon.rs's test scope.

use super::*;

/// Three-article OVER batch for one release stem, the same shape the
/// scan lane ingests.
#[cfg(feature = "indexer")]
fn over_rows(stem: &str, tag: &str) -> Vec<nzbkit::nntp::OverEntry> {
    (1..=3u64)
        .map(|n| nzbkit::nntp::OverEntry {
            number: n,
            subject: format!(r#""{stem}.part1.rar" yEnc ({n}/3)"#),
            from: "p@x".into(),
            message_id: format!("<{tag}{n}@test>"),
            bytes: 1000,
            date: 1_700_000_000,
        })
        .collect()
}

/// The hand-back keeps an existing shared connection - proven by a
/// piece of connection-local state (an installed arrival watch)
/// surviving it - while the handing pass's commits are visible through
/// that kept connection with no reopen at all (the open counter stands
/// still across the hand-back).
#[cfg(feature = "indexer")]
#[test]
fn a_handback_keeps_the_shared_connection_and_its_commits_are_visible() {
    with_daemon("handback", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        let era = d.index_era();
        let fresh = nzbkit::index::Index::open(&d.index_db).expect("open index");
        d.publish_index(era, fresh);
        // Connection-local marker on the SHARED connection: replaced,
        // it would be gone (the hand-back clears the offered
        // connection's watch); kept, it survives.
        d.with_index_mut(|ix| {
            ix.set_watch_names(Some(Box::new(|_| true)));
            Some(())
        })
        .expect("install watch");

        // The pass's own scratch connection ingests and hands over. The
        // open counter is per-thread and the hand-back is synchronous
        // on this thread, so the delta below is exactly this sequence's
        // opens - sibling tests opening indexes on other threads (plain
        // `cargo test` runs everything in one process) cannot move it.
        let opens = nzbkit::index::Index::open_count();
        let mut scratch = nzbkit::index::Index::open(&d.index_db).expect("open scratch");
        scratch
            .ingest(
                "a.b.test",
                &over_rows("Pass.Release.2026-GRP", "hb"),
                1_700_000_001,
            )
            .expect("scratch ingest");
        d.publish_index(era, scratch);
        assert_eq!(
            nzbkit::index::Index::open_count(),
            opens + 1,
            "the hand-back itself must open nothing - only the scratch open counts"
        );

        // WAL visibility: the KEPT connection sees the scratch's commit.
        let found = d
            .with_index(|ix| ix.search("pass release", 10).ok())
            .expect("search");
        assert_eq!(
            found.len(),
            1,
            "the pass's rows are visible without a reopen"
        );

        // The watch installed above still fires - the connection was
        // kept, not swapped for the scratch (whose watch is cleared).
        let (hits, _) = d
            .with_index_mut(|ix| {
                ix.ingest(
                    "a.b.test",
                    &over_rows("Watched.Release.2026-GRP", "hw"),
                    1_700_000_002,
                )
                .ok()?;
                Some(ix.take_watch_hits())
            })
            .expect("ingest on the shared connection");
        assert!(
            !hits.is_empty(),
            "connection-local state (the arrival watch) must survive a hand-back"
        );
    });
}

/// The first hand-back installs the offered connection, sets
/// `index_migrated` (the seam whose absence was the 28 Jul and 2 Aug
/// wedges), and clears the offered connection's arrival watch so a
/// stale scan predicate cannot journal hits nobody drains.
#[cfg(feature = "indexer")]
#[test]
fn the_first_handback_installs_and_sets_index_migrated() {
    with_daemon("handback1st", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        assert!(!d.index_migrated.load(Ordering::Acquire));
        let era = d.index_era();
        let mut scratch = nzbkit::index::Index::open(&d.index_db).expect("open scratch");
        scratch.set_watch_names(Some(Box::new(|_| true)));
        d.publish_index(era, scratch);
        assert!(d.index.lock_ok().is_some(), "installed");
        assert!(
            d.index_migrated.load(Ordering::Acquire),
            "first publication must set index_migrated - the read pool is dead code otherwise"
        );
        let (hits, _) = d
            .with_index_mut(|ix| {
                ix.ingest(
                    "a.b.test",
                    &over_rows("Quiet.Release.2026-GRP", "q"),
                    1_700_000_003,
                )
                .ok()?;
                Some(ix.take_watch_hits())
            })
            .expect("ingest");
        assert!(
            hits.is_empty(),
            "the offered connection's watch must be cleared on hand-over"
        );
    });
}

/// A wipe or source-off mid-pass bumps the era; the pass's hand-back
/// must then be dropped on the floor - not installed, not migrated -
/// or a wiped database gets resurrected by whichever pass was in
/// flight.
#[cfg(feature = "indexer")]
#[test]
fn a_stale_era_handback_is_dropped_not_installed() {
    with_daemon("handbackstale", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        let era = d.index_era();
        let scratch = nzbkit::index::Index::open(&d.index_db).expect("open scratch");
        d.index_generation.fetch_add(1, Ordering::SeqCst);
        d.publish_index(era, scratch);
        assert!(
            d.index.lock_ok().is_none(),
            "a pass from before the wipe must not publish its connection"
        );
        assert!(!d.index_migrated.load(Ordering::Acquire));
    });
}

/// The read pool retires exactly when the schema changes: the feed
/// batch that BUILDS the named-count index bumps the pool generation
/// once, and the next batch leaves the warmed readers alone.
#[cfg(feature = "indexer")]
#[test]
fn the_read_pool_retires_on_the_named_index_build_and_only_then() {
    with_daemon("handbackddl", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        let pre = |title: &str, filename: &str| nzbkit::predb::PreLine {
            kind: nzbkit::predb::PreKind::New,
            title: title.into(),
            filename: filename.into(),
            source: "PRE".into(),
            ..Default::default()
        };
        let generation = || d.index_read.inner.lock_ok().generation;
        let g0 = generation();
        d.with_index_mut_retiring_ddl(|ix| {
            ix.predb_store(&[pre("Some.Release.2026-GRP", "some.release.r00")], 1000)
                .ok()
        })
        .expect("first store");
        assert_eq!(
            generation(),
            g0 + 1,
            "the batch that built the named index must retire the pooled readers"
        );
        d.with_index_mut_retiring_ddl(|ix| {
            ix.predb_store(&[pre("Other.Release.2026-GRP", "other.release.r00")], 1001)
                .ok()
        })
        .expect("second store");
        assert_eq!(
            generation(),
            g0 + 1,
            "a steady-state batch is not a schema change and keeps the warm pool"
        );
    });
}
