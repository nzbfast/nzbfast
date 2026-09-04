//! TODO 26c A5: the maintenance leg that rebuilds `files` into its
//! compact layout - segment lists as `segcodec` bytes and `nsegs` ahead
//! of the blob - a slice per scan pass, beside a daemon that keeps
//! ingesting into that table the whole time. The mechanism (staging
//! table, mirror triggers, rowid cursor, swap, reclaim) is
//! `nzbkit::index::segmig`; this file is the clock it runs on and the
//! gates it runs behind.

use super::super::*;
use super::abort_compact_when_job_starts;

/// How long one hold of the index write mutex may last in the §26c A5
/// rebuild, and how much of one scan pass the rebuild may take. The
/// slice is the reap's: a download that starts mid-slice waits one
/// slice. The pass is twice the reap's, sized from the measurement: the
/// copy ran at 39 s per million rows on a real clone (22 Aug 2026), so
/// a 48 M-row live index is ~32 minutes of slices - 32 passes at this
/// budget, about 8 hours of a 15-minute scan loop, plus a third of that
/// again for the reclaim. It yields to the scan it shares the loop with
/// and resumes next pass.
#[cfg(feature = "indexer")]
const SEGMIG_SLICE: std::time::Duration = std::time::Duration::from_secs(1);
#[cfg(feature = "indexer")]
const SEGMIG_PASS: std::time::Duration = std::time::Duration::from_secs(60);
/// Free space the rebuild insists on beyond its own estimate, so it
/// never makes a tight volume tighter than the download path's own
/// guard would allow.
#[cfg(feature = "indexer")]
const SEGMIG_FREE_MARGIN: u64 = 1 << 30;

/// §26c A5: one budgeted slice of the `files` rebuild per scan pass -
/// segment lists to the compact form and `nsegs` ahead of the blob.
/// See `nzbkit::index::segmig` for the shape; this is the clock it
/// runs on. Four stages, each resumable, each advancing at most one
/// pass's budget at a time:
///
/// 1. copy, in 1 s slices of the write mutex, behind a free-space gate
///    (the staging table grows the file before the old table is freed);
/// 2. swap, one instant transaction plus a row count on each table,
///    under the same interrupt arm as a deferred index build so a
///    download that starts during the count stands it down;
/// 3. reclaim, deleting the old table in slices, then dropping it;
/// 4. done - a sub-millisecond catalogue read, every pass, forever.
///
/// The swap is the one schema change a pooled reader's prepared
/// statement can predate, which is why stages 2 and 3 go through
/// `with_index_mut_retiring_ddl`.
#[cfg(feature = "indexer")]
pub(crate) async fn segments_rebuild_pass(daemon2: &Arc<Daemon>) {
    use nzbkit::index::SegMigState;
    let Some(state) = daemon2.with_index(|ix| Some(ix.segmig_state())) else {
        return;
    };
    let started = std::time::Instant::now();
    let pass_end = started + SEGMIG_PASS;
    match state {
        SegMigState::Done => {}
        SegMigState::Copying { copied, total } => {
            let need = daemon2
                .with_index(|ix| ix.segmig_estimate_bytes().ok())
                .unwrap_or(0);
            let dir = daemon2
                .index_db
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| daemon2.index_db.clone());
            if let Some(free) = super::disk::free_bytes(&dir)
                && free < need.saturating_add(SEGMIG_FREE_MARGIN)
            {
                // Once an hour, not once a pass: the condition persists
                // until somebody frees disk, and a log line every 15
                // minutes is how a warning becomes wallpaper.
                static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|t| t.as_secs())
                    .unwrap_or(0);
                if now.saturating_sub(LAST.load(Ordering::Relaxed)) >= 3_600 {
                    LAST.store(now, Ordering::Relaxed);
                    warn!(
                        target: "index",
                        "compact segments: standing down - needs about {} MB free beside the \
                         index for the rebuild, {} MB available",
                        (need + SEGMIG_FREE_MARGIN) / 1_000_000,
                        free / 1_000_000
                    );
                }
                return;
            }
            let mut rows = 0u64;
            let mut finished = false;
            while !finished {
                if std::time::Instant::now() >= pass_end || !daemon2.db_maintenance_ok() {
                    break;
                }
                let slice = std::time::Instant::now() + SEGMIG_SLICE;
                // Retiring: the first slice installs the staging table's
                // mirror triggers, which is DDL, and the stamp it leaves
                // must be drained here rather than by whichever pre-feed
                // write happens to come next.
                let Some(r) =
                    daemon2.with_index_mut_retiring_ddl(|ix| match ix.segmig_copy_slice(slice) {
                        Ok(r) => Some(r),
                        Err(e) => {
                            warn!(target: "index", "compact segments: {e}");
                            None
                        }
                    })
                else {
                    break;
                };
                rows += r.rows;
                finished = r.finished;
                tokio::task::yield_now().await;
            }
            if rows > 0 || finished {
                let done = copied + rows as i64;
                info!(
                    target: "index",
                    "compact segments: {done} of ~{total} file rows rewritten ({:.1}%) - \
                     {rows} this pass in {:.1}s{}",
                    100.0 * done as f64 / total.max(1) as f64,
                    started.elapsed().as_secs_f64(),
                    if finished { "; swapping next pass" } else { "" }
                );
            }
        }
        SegMigState::Swappable => {
            let arm = Arc::new(super::daemon::MaintenanceArm::default());
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
            let outcome = tokio::task::spawn_blocking(move || {
                d3.with_index_mut_retiring_ddl(|ix| {
                    if !arm2.arm(ix.interrupt_handle()) {
                        done2.store(true, Ordering::Release);
                        return None;
                    }
                    let r = ix.segmig_swap();
                    arm2.disarm();
                    done2.store(true, Ordering::Release);
                    Some(r)
                })
            })
            .await;
            done.store(true, Ordering::Release);
            let aborted = matches!(watch.await, Ok(true));
            match outcome {
                _ if aborted => info!(
                    target: "index",
                    "compact segments: swap stood down for a download - next pass"
                ),
                Ok(Some(Ok(Some(n)))) => info!(
                    target: "index",
                    "compact segments: files table swapped to the compact layout ({n} rows) \
                     in {:.1}s; reclaiming the old table from next pass",
                    started.elapsed().as_secs_f64()
                ),
                Ok(Some(Err(e))) => warn!(target: "index", "compact segments: {e}"),
                _ => {}
            }
        }
        SegMigState::Reclaiming => {
            let mut rows = 0u64;
            let mut finished = false;
            while !finished {
                if std::time::Instant::now() >= pass_end || !daemon2.db_maintenance_ok() {
                    break;
                }
                let slice = std::time::Instant::now() + SEGMIG_SLICE;
                let Some((n, f)) = daemon2.with_index_mut_retiring_ddl(|ix| {
                    match ix.segmig_reclaim_slice(slice) {
                        Ok(r) => Some(r),
                        Err(e) => {
                            warn!(target: "index", "compact segments: reclaim: {e}");
                            None
                        }
                    }
                }) else {
                    break;
                };
                rows += n;
                finished = f;
                tokio::task::yield_now().await;
            }
            if finished {
                // The rebuild frees the whole old table, and on the
                // live index that was 10,164,683 pages / 41.6 GB of
                // freelist. Nothing here used to raise this, so the
                // line below promised a compaction that could never
                // start: `spawn_index_compact` short-circuits on
                // `compact_pending` before it reaches any of its other
                // gates, and the ONLY other writer of the flag is
                // `Daemon::evict_to` on a prune reporting
                // `needs_compact` - which never fires on an index with
                // no cap and eviction off, the default. Measured on
                // :6789 on 23 Aug 2026: fifteen minutes after this
                // branch ran, `page_count` had not moved by one page
                // and the file was byte-identical at 98.75 GB, with
                // live bytes of 57.1 GB. The falling `freelist_count`
                // was pages being REUSED by the tip scan, not
                // reclaimed - read `page_count`, not the freelist, to
                // tell those two apart.
                //
                // Sticky by design, so raising it here cannot lose the
                // request to a busy moment: the compactor defers while
                // a download or scan is in flight and comes back a
                // minute later. It takes the chunked path (this
                // database has been in incremental auto-vacuum since
                // the migration), which checks for a job between
                // 8 MB chunks, so the reclaim is abortable and every
                // chunk it does run is already committed and
                // truncated.
                daemon2.compact_pending.store(true, Ordering::Relaxed);
            }
            if rows > 0 || finished {
                info!(
                    target: "index",
                    "compact segments: {rows} old rows reclaimed in {:.1}s{}",
                    started.elapsed().as_secs_f64(),
                    if finished {
                        " - rebuild complete; freed pages return through compaction"
                    } else {
                        ""
                    }
                );
            }
        }
    }
}

#[cfg(all(test, feature = "indexer"))]
mod tests {
    use super::*;

    /// The rebuild frees the whole old `files` table, and on :6789 that
    /// was 41.6 GB of freelist that never came back: `spawn_index_compact`
    /// short-circuits on `compact_pending` before any of its other gates,
    /// and nothing here raised it. Fifteen minutes after the live reclaim
    /// finished, `page_count` had not moved by one page.
    ///
    /// Drives the whole rebuild on a tiny legacy-layout index rather than
    /// poking the flag: the raise has to sit on the branch that actually
    /// ends the reclaim, and only running the stages proves which branch
    /// that is.
    #[tokio::test]
    async fn a_finished_rebuild_asks_for_the_compaction_that_hands_its_pages_back() {
        let dir = std::env::temp_dir().join(format!(
            "nzbfast-segmig-pending-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let d = crate::testutil::test_daemon(&dir);
        d.index_enabled.store(true, Ordering::Relaxed);

        // Put the index back in the pre-A5 shape so the rebuild has
        // something to do, and confirm it - a fixture that is already
        // Done would pass every assertion below while proving nothing.
        assert!(
            d.with_index(|ix| ix.segmig_debug_install_legacy_layout().ok())
                .is_some(),
            "fixture could not open the index"
        );
        assert_ne!(
            d.with_index(|ix| Some(ix.segmig_state())),
            Some(nzbkit::index::SegMigState::Done),
            "fixture is already rebuilt - the passes below would be no-ops"
        );
        assert!(
            !d.compact_pending.load(Ordering::Relaxed),
            "fixture starts with the flag already raised"
        );

        // One pass per stage, plus slack. Bounded so a stage that stops
        // advancing fails here rather than hanging the suite.
        for _ in 0..16 {
            if d.with_index(|ix| Some(ix.segmig_state())) == Some(nzbkit::index::SegMigState::Done)
            {
                break;
            }
            segments_rebuild_pass(&d).await;
        }
        assert_eq!(
            d.with_index(|ix| Some(ix.segmig_state())),
            Some(nzbkit::index::SegMigState::Done),
            "the rebuild did not finish"
        );
        assert!(
            d.compact_pending.load(Ordering::Relaxed),
            "the rebuild finished without asking for a compaction, so the freed pages \
             would sit on the freelist forever - the 23 Aug 2026 :6789 defect"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
