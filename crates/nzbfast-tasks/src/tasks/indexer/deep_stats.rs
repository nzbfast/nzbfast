//! TODO 198 tail: the maintenance leg that turns the query planner's
//! SAMPLED statistics into measured ones, one index per pass.
//!
//! `Index::optimize` runs `PRAGMA analysis_limit=1000`, which caps the
//! per-value estimates in `sqlite_stat1` near the sample size and - the
//! half that is not in the pragma's documentation - suppresses
//! `sqlite_stat4` entirely. On the 33.4M-release index measured 22 Aug
//! 2026 that writes 1001 rows per `kind` against a true 5,559,939, and
//! the planner answers an \*arr's `kind = ? AND complete AND
//! first_posted >= ?` count out of `idx_rel_kind` instead of the
//! covering `idx_rel_complete_kind` §198 built for it: 219 ms against
//! 15 ms, the one shape §198 could not win.
//!
//! The shape here is `picker_index_backfill`'s, deliberately: one unit
//! of whole-index work per pass, on a blocking thread, under a
//! `MaintenanceArm` with a watcher that aborts the statement the moment
//! a download starts. Same reason, too - `ANALYZE main.<index>` reads
//! the whole index holding the index write lock, 74.4 s for the worst
//! one on that database, and a maintenance leg that can stall a
//! starting download is the thing §95 removed from compaction.
//!
//! There is no stamp. `Index::shallow_stat_index` reads the state out
//! of the stat tables themselves, so a `PRAGMA optimize` that resets
//! them (which is what the B1 picker backfill provokes, by landing an
//! index with no `sqlite_stat1` row) is simply measured again on later
//! passes rather than silently believed.

use super::*;

/// Measure one still-sampled index's statistics, or return at once when
/// there are none left. See the module comment for why this is one
/// index per pass rather than one `ANALYZE`.
#[cfg(feature = "indexer")]
pub(crate) async fn deep_stats_pass(daemon2: &Arc<Daemon>) {
    let Some(name) = daemon2.with_index(|ix| ix.shallow_stat_index()) else {
        return;
    };
    // The SHARED-DATABASE predicate, for sweep 8 L12's reason: a
    // Spot-only install has `index_enabled` false, and gating on the
    // indexing predicate would leave the statistics permanently sampled
    // on exactly the databases whose browse and newznab reads still go
    // through this planner.
    if !daemon2.db_maintenance_ok() {
        return;
    }
    let started = std::time::Instant::now();
    let arm = Arc::new(super::super::daemon::MaintenanceArm::default());
    let done = Arc::new(AtomicBool::new(false));
    let watch = {
        let jobs = daemon2.index_jobs_active.clone();
        let done = done.clone();
        let arm = arm.clone();
        tokio::spawn(abort_compact_when_job_starts(jobs, done, move || {
            arm.abort();
        }))
    };
    let d3 = daemon2.clone();
    let done2 = done.clone();
    let arm2 = arm.clone();
    let deep = name.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        d3.with_index(|ix| {
            if !arm2.arm(ix.interrupt_handle()) {
                // A download started before we got the guard.
                done2.store(true, Ordering::Release);
                return None;
            }
            let r = ix.analyze_index_deep(&deep);
            arm2.disarm();
            // Inside the closure, same as the ANALYZE and picker-build
            // legs: the watcher must never see "running" on a
            // connection somebody else has already started using.
            done2.store(true, Ordering::Release);
            Some(r)
        })
    })
    .await;
    done.store(true, Ordering::Release);
    let aborted = matches!(watch.await, Ok(true));
    match outcome {
        _ if aborted => {}
        Ok(Some(Ok(()))) => {
            // The whole point of the leg, and it is invisible without
            // this line. New statistics are NOT seen by a connection
            // that is already open: measured on the 2M-row fixture, a
            // reader held across the ANALYZE keeps planning the old way
            // while a freshly opened one takes the new index. Browse,
            // the wall and the newznab facade all run on the pooled
            // read-only connections, so retiring the pool is what makes
            // the measurement reach them.
            daemon2.drop_index_read();
            // Only worth a line when it cost something - most of the
            // 52 indexes on a real database are milliseconds, and a
            // daemon that narrated each one would say nothing useful
            // fifty times.
            if started.elapsed() >= std::time::Duration::from_secs(1) {
                info!(
                    target: "index",
                    "measured planner statistics for {name} in {:.1}s",
                    started.elapsed().as_secs_f64()
                );
            }
        }
        Ok(Some(Err(e))) => warn!(target: "index", "statistics for {name}: {e}"),
        Ok(None) | Err(_) => {}
    }
}
