//! A4: the index_stats TTL cache. What makes it a cache rather than a
//! busy-fallback: fresh figures are served without touching any index
//! lock even when the writer mutex is FREE, expiry recomputes, an era
//! bump (wipe, source-off) orphans the figures instantly, and the
//! singleflight flag keeps a second poller from queueing another full
//! table scan. Out here for the size-gate ceiling, with
//! daemon_tests.rs's #[path] requirement.

use super::*;

/// Ingest `n` one-part releases so the exact stats move.
fn seed_releases(d: &Arc<Daemon>, n: u64, tag: &str) {
    let now = 1_753_000_000i64;
    let entries: Vec<nzbkit::nntp::OverEntry> = (0..n)
        .map(|i| nzbkit::nntp::OverEntry {
            number: i + 1,
            subject: format!("\"Cache.{tag}.S01E{i:02}.1080p-GRP.rar\" yEnc (1/1)"),
            from: "p@x".into(),
            date: now - (i as i64) * 3_600,
            message_id: format!("<{tag}{i}@x>"),
            bytes: 4096,
        })
        .collect();
    d.with_index_mut(|ix| ix.ingest("a.b.cache", &entries, now).ok())
        .expect("ingest");
}

/// The headline A4 fix: a fresh snapshot is served from the cache even
/// though the writer mutex is free and the database has moved on - the
/// old shape recomputed the full `SCAN releases` on every poll the
/// moment try_lock succeeded. Forcing expiry (what the post-scan-pass
/// refresh does) picks the new figures up.
#[cfg(feature = "indexer")]
#[test]
fn index_stats_fresh_cache_is_served_without_recompute_and_expiry_recomputes() {
    with_daemon("statsttl", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        seed_releases(d, 3, "cold");
        let first = d.index_stats_snapshot().expect("cold compute");
        assert_eq!(first.0, 3, "cold cache computes exact figures");

        // Dirty write: the database grows, the cache does not know.
        seed_releases(d, 2, "dirty");
        assert_eq!(
            d.index_stats_snapshot().expect("cached"),
            first,
            "within the TTL the cached figures are served - no recompute \
             even though the writer mutex is free and the count moved"
        );

        // Expiry: at=None is exactly what refresh_index_stats installs.
        d.index_stats_cache.lock_ok().at = None;
        let after = d.index_stats_snapshot().expect("recompute");
        assert_eq!(after.0, 5, "an expired cache recomputes exact figures");
    });
}

/// A wipe or source-off bumps the index era; figures stamped with the
/// old era must never be served again, fresh TTL or not.
#[cfg(feature = "indexer")]
#[test]
fn index_stats_era_bump_orphans_the_cached_figures() {
    with_daemon("statsera", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        seed_releases(d, 2, "era");
        let real = d.index_stats_snapshot().expect("seed");
        {
            // A stale-era sentinel with a fresh timestamp: only the
            // era check can reject it.
            let mut c = d.index_stats_cache.lock_ok();
            c.snap = Some((999, 999, 9, 9));
            c.at = Some(std::time::Instant::now());
            c.era = d.index_era();
        }
        d.index_generation.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            d.index_stats_snapshot(),
            Some(real),
            "an era bump must force a recompute, not serve the orphan"
        );
        assert_eq!(
            d.index_stats_cache.lock_ok().era,
            d.index_era(),
            "the recompute restamps the cache with the new era"
        );
    });
}

/// Singleflight: while one caller recomputes, a second poll serves the
/// same-era stale figures instead of starting a second table scan -
/// and a cross-era snapshot answers cold, never the orphan.
#[cfg(feature = "indexer")]
#[test]
fn index_stats_singleflight_serves_stale_same_era_and_cold_across_eras() {
    with_daemon("statssf", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        seed_releases(d, 4, "sf");
        let real = d.index_stats_snapshot().expect("seed");
        let sentinel = (777, 7, 7, 7);
        {
            let mut c = d.index_stats_cache.lock_ok();
            c.snap = Some(sentinel);
            c.at = None; // expired, so only `refreshing` short-circuits
            c.refreshing = true;
        }
        assert_eq!(
            d.index_stats_snapshot(),
            Some(sentinel),
            "a poll during a recompute serves the stale same-era figures"
        );
        d.index_generation.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            d.index_stats_snapshot(),
            None,
            "during a recompute a cross-era snapshot answers cold"
        );
        d.index_stats_cache.lock_ok().refreshing = false;
        assert_eq!(
            d.index_stats_snapshot(),
            Some(real),
            "once the flight lands the next poll recomputes normally"
        );
    });
}

/// `refresh_index_stats` (the once-per-scan-pass exact recompute) both
/// forces the compute and leaves the cache warm at the new figures.
#[cfg(feature = "indexer")]
#[test]
fn refresh_index_stats_installs_fresh_figures() {
    with_daemon("statsrf", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        seed_releases(d, 1, "rf");
        let first = d.index_stats_snapshot().expect("seed");
        seed_releases(d, 2, "rf2");
        d.refresh_index_stats();
        let c = d.index_stats_cache.lock_ok();
        let snap = c.snap.expect("warm after refresh");
        assert!(c.at.is_some(), "refresh leaves a fresh timestamp");
        assert_eq!(snap.0, first.0 + 2, "refresh computed the new figures");
    });
}

/// Sweep 8, L8: a flight that started BEFORE an explicit refresh may
/// not publish itself as fresh.
///
/// The interleaving: a dashboard poll begins its SQLite reads; the scan
/// pass commits and calls `refresh_index_stats`, which clears `at`,
/// sees `refreshing` already set and returns; the older flight then
/// finishes and stamps `Instant::now()`. Its pre-commit snapshot is
/// then served as current for the whole 45 s TTL - the one call whose
/// entire job is "the cache must reflect what I just wrote" defeated by
/// the singleflight that exists to save work.
///
/// The old flight is simulated exactly as the sibling test above
/// simulates the singleflight, because the real race needs a reader
/// parked mid-statement across a committing writer.
#[cfg(feature = "indexer")]
#[test]
fn an_old_flight_cannot_publish_over_an_explicit_refresh() {
    with_daemon("statsgen", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        seed_releases(d, 1, "gen");
        let before = d.index_stats_snapshot().expect("seed");

        // A flight is in the air, holding `before` as its answer.
        let started_gen = {
            let mut c = d.index_stats_cache.lock_ok();
            c.refreshing = true;
            c.generation
        };

        // The pass commits and asks for the exact recompute. It finds
        // the flight and returns - but it bumps the generation.
        seed_releases(d, 3, "gen2");
        d.refresh_index_stats();
        {
            let c = d.index_stats_cache.lock_ok();
            assert_ne!(
                c.generation, started_gen,
                "an explicit refresh must invalidate the flights it could not run"
            );
        }

        // The old flight lands. Its figures predate the commit, so it
        // must NOT stamp them fresh.
        {
            let mut c = d.index_stats_cache.lock_ok();
            c.refreshing = false;
            c.snap = Some(before);
            c.at = if c.generation == started_gen {
                Some(std::time::Instant::now())
            } else {
                None
            };
        }
        assert!(
            d.index_stats_cache.lock_ok().at.is_none(),
            "the cache is left expired, not warm at a pre-commit snapshot"
        );

        // So the next reader gets the truth rather than waiting out the
        // TTL on figures the pass already contradicted.
        let after = d.index_stats_snapshot().expect("recompute");
        assert_eq!(
            after.0,
            before.0 + 3,
            "the first read after the refresh sees the pass's own result"
        );
    });
}

/// Bug sweep 22 Aug 2026, F-18: the eviction / shrink / scan-park sites
/// used to clear `at` alone, which an in-flight snapshot overrides with
/// a fresh stamp unless the generation fence moved. `expire_index_stats`
/// does both, so those sites are the same invalidation as a refresh.
#[cfg(feature = "indexer")]
#[test]
fn expire_index_stats_clears_at_and_advances_the_generation() {
    with_daemon("statsexp", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        seed_releases(d, 1, "exp");
        let _ = d.index_stats_snapshot().expect("seed");
        let gen_before = {
            let c = d.index_stats_cache.lock_ok();
            assert!(c.at.is_some(), "warm before expiry");
            c.generation
        };
        d.expire_index_stats();
        let c = d.index_stats_cache.lock_ok();
        assert!(c.at.is_none(), "expired");
        assert_eq!(c.generation, gen_before.wrapping_add(1), "fenced");
    });
}
