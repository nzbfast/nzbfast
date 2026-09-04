//! The passes the scan loop runs BETWEEN group scans, and the one it
//! runs before them.
//!
//! Nine of them: the Spotnet pass, the reclassify sweep, the
//! maintenance slice, the enrich unstamp, the two folds, retention and
//! statistics, the deferred picker-index build, and the cache evict.
//! They share the discipline the parent module's doc states - none of
//! them may cost the user a download - and they share nothing else with
//! the compactor and the samplers next door, which is why they are a
//! file of their own.
//!
//! Split out of `tasks/indexer.rs` whole for the 4,000-line file
//! ceiling: the code is verbatim, nothing changed but which file it
//! sits in. The parent re-exports every name, so `indexer::spot_pass`
//! and friends still resolve for `tasks.rs` and for the two
//! `#[path]` test children that read them through `super::*`.

use super::*;

/// Spotnet: one scan pass per configured spot group, then the promotion
/// of what it found.
///
/// Run before the group scans because it is short (a 20k-article OVER
/// walk is ~20 s against a live server) and a spots-only install should
/// not sit behind a group pass that is not even running. Same gate,
/// same preemption contract as the scans: dropped promptly when a
/// download starts, with the high-water mark left on the last whole
/// chunk.
#[cfg(feature = "indexer")]
pub(crate) async fn spot_pass(
    daemon2: &Arc<Daemon>,
    config: &std::path::Path,
    db: &std::path::Path,
) {
    let spot_groups = daemon2.spot_groups.lock_ok().clone();
    let backfill = daemon2.spot_backfill.load(Ordering::Relaxed);
    let deepen = daemon2.spot_deepen.load(Ordering::Relaxed);
    for g in &spot_groups {
        if daemon2.spot_pause_reason().is_some() {
            break;
        }
        // The generation this pass runs under: if the
        // database is switched off or wiped while the
        // scan is in flight, its connection must be
        // dropped rather than handed back (which would
        // reopen, and after a wipe RECREATE, the file).
        let era = daemon2.index_era();
        let mut scratch = match nzbkit::index::Index::open_scratch(db) {
            Ok(ix) => ix,
            Err(e) => {
                warn!(target: "spots", "open {}: {e}", db.display());
                break;
            }
        };
        let scan = crate::spot_scan_pass(config, &mut scratch, g, backfill, deepen);
        // The reason rides out with the preemption - see
        // `Daemon::pause_phrase`. The deepening leg lives on this arm,
        // so a wrongly-named stand-down here is why 4.3 M articles of
        // free.pt history sat unread with nothing to point at.
        let pause = async {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                if let Some(reason) = daemon2.spot_pause_reason() {
                    break reason;
                }
            }
        };
        match tokio::select! {
            result = scan => Ok(result),
            reason = pause => Err(reason),
        } {
            Ok(Ok(sum)) if sum.new > 0 => info!(
                target: "spots",
                "{g}: {} new spots ({} scanned, {} verified){}",
                sum.new, sum.scanned, sum.valid,
                // The deepening leg's own numbers, so "the catalogue is
                // growing" and "history is still arriving" never have to
                // be inferred from one total.
                if sum.deepened > 0 {
                    format!(
                        ", {} of history read, {} articles left",
                        sum.deepened, sum.depth_left
                    )
                } else {
                    String::new()
                },
            ),
            Ok(Ok(_)) => {}
            Ok(Err(e)) => warn!(target: "spots", "{g}: {e}"),
            Err(reason) => info!(
                target: "spots",
                "{g} stood down: {}",
                Daemon::pause_phrase(reason)
            ),
        }
        // Hand the connection back (B4): kept-or-installed under the
        // era check, no reopen, no reader retirement - WAL gives every
        // other connection this pass's commits on their next statement.
        daemon2.publish_index(era, scratch);
    }
    // E3 / TODO 131: promote scanned spots to first-class
    // release rows (fetch NZB, dedup against the index,
    // insert + name through the sanctioned seam). Budgeted
    // per pass - each spot is one HEAD plus a few BODYs on
    // the scan server - with the same preemption contract
    // as the scan above.
    let resolve_budget = daemon2.spot_resolve.load(Ordering::Relaxed) as u32;
    if daemon2.spot_pause_reason().is_none() && resolve_budget > 0 {
        let era = daemon2.index_era();
        match nzbkit::index::Index::open_scratch(db) {
            Ok(mut scratch) => {
                let d3 = daemon2.clone();
                // The pass's own wall clock. It used to be reconstructible
                // only from the gap between two of these log lines, which
                // is the whole lap and not this leg - and reading a
                // throughput off that gap is what hid how much of the lap
                // the resolver was (measured 1 Sep 2026,
                // research/SPOT-RESOLVER-IS-THROTTLED-2026-09-01.md).
                let t0 = Instant::now();
                let resolve = crate::spot_resolve_pass(config, &mut scratch, resolve_budget, {
                    move || d3.spot_pause_reason().is_some()
                });
                let pause = async {
                    loop {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        if let Some(reason) = daemon2.spot_pause_reason() {
                            break reason;
                        }
                    }
                };
                let outcome = tokio::select! {
                    result = resolve => Ok(result),
                    reason = pause => Err(reason),
                };
                // Same B4 hand-back as the scan above.
                daemon2.publish_index(era, scratch);
                match outcome {
                    Ok(Ok(sum)) => {
                        if sum.fetched + sum.failed > 0 {
                            info!(
                                target: "spots",
                                "resolved {} spot NZBs in {:.1?}: {} new cards, {} upgraded \
                                 existing releases, {} unusable, {} failed; \
                                 {} head articles checked, {} already gone",
                                sum.fetched,
                                t0.elapsed(),
                                sum.promoted,
                                sum.upgraded,
                                sum.unusable,
                                sum.failed,
                                sum.checked,
                                sum.gone
                            );
                        }
                        // Fresh cards want titles rows so
                        // enrichment reaches them without
                        // waiting for a wall page view -
                        // same seeding the group pass does.
                        if sum.promoted > 0 {
                            let _ = daemon2.with_index(|ix| ix.seed_missing_titles(14, 500).ok());
                        }
                    }
                    Ok(Err(e)) => warn!(target: "spots", "spot resolve: {e}"),
                    Err(reason) => {
                        info!(
                            target: "spots",
                            "spot resolve stood down: {}",
                            Daemon::pause_phrase(reason)
                        )
                    }
                }
            }
            Err(e) => warn!(target: "spots", "open {}: {e}", db.display()),
        }
    }
}

/// 24D: the category config changed (or this is the first run since
/// start) - reconcile stored rows BEFORE the pass, so a pass's own
/// re-ingest touches never fight the sweep. Chunked and
/// fingerprint-stamped, so this is a no-op when nothing actually
/// changed.
#[cfg(feature = "indexer")]
pub(crate) async fn reclassify_pending_rows(
    daemon2: &Arc<Daemon>,
    db: &std::path::Path,
    cats: &[nzbkit::categories::CustomCategory],
) {
    if daemon2.reclassify_pending.swap(false, Ordering::Relaxed) {
        let cats2 = cats.to_vec();
        let db2 = db.to_path_buf();
        let outcome = tokio::task::spawn_blocking(move || {
            let mut ix = nzbkit::index::Index::open(&db2)
                .map_err(|e| format!("open {}: {e}", db2.display()))?;
            ix.set_custom(cats2);
            ix.reclassify_custom().map_err(|e| e.to_string())
        })
        .await;
        let changed = match outcome {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                warn!(target: "cats", "reclassify failed: {e} - will retry");
                daemon2.reclassify_pending.store(true, Ordering::Relaxed);
                0
            }
            Err(e) => {
                warn!(target: "cats", "reclassify task failed: {e} - will retry");
                daemon2.reclassify_pending.store(true, Ordering::Relaxed);
                0
            }
        };
        if changed > 0 {
            info!(target: "cats", "reclassified {changed} releases under the new category rules");
            // Freshly re-keyed cards need titles rows for the
            // wall; the seeder below only covers recent posts, so
            // seed now. No republish (B4): the sweep's own
            // connection committed, and WAL makes that visible to
            // the shared connection and the pooled readers alike.
            let _ = daemon2.with_index(|ix| ix.seed_missing_titles(3650, 2000).ok());
        }
    }
}

/// The between-scan maintenance slice of one index pass: retention
/// prune + planner statistics, one deferred picker index, one
/// shatter-fold budget. Returns false when the pass must stand down
/// (a job started), which the caller answers by handing back the pass
/// gate.
///
/// Lifted out of `spawn_index_scan` under the size gate, alongside the
/// four blocks of the same pass that already live here.
///
/// All three legs share ONE gate, and which gate that is was sweep 8's
/// L12. Spot ingestion runs with a deliberately EMPTY group vector, so
/// `has_groups` is false on a Spot-only install and every pass used to
/// skip all three - including the deferred index build, which past the
/// one-million-row inline threshold `schema.rs` does not create at open
/// either. Complete-browse therefore kept its whole-table plan
/// indefinitely rather than merely across a migration, and no amount of
/// waiting could fix it.
///
/// The gate is `db_maintenance_ok` - either scan source live, database
/// wanted, nothing downloading - and NOT `index_maintenance_ok`, which
/// answers `Some("off")` in precisely this configuration and would
/// leave every leg exactly as unreachable as it found them. Read that
/// predicate's doc comment before touching any of this.
///
/// Retention, statistics and folding joined the picker build here on
/// 22 Aug 2026 (TODO 199 item 5's policy half). The question was never
/// whether a Spot-only database CAN be maintained but whether it
/// should be, and the answer is that these are properties of the ROWS:
/// `promote_spot` writes first-class release rows into the same
/// `releases` table, clamping their posted date specifically so they
/// cannot "dodge the retention prunes", and the wall, newznab and
/// browse read them through the same planner. The size cap
/// (`evict_between_passes`) has never been group-gated at all, so an
/// age cap that was is the odd one out rather than the careful one.
/// A Spot-only install that sets a retention window and gets nothing
/// is a bug, and an index with no statistics plans `wall2` as a full
/// table scan whichever source filled it - which is the 45 GB / 85 s
/// card query of 2 Aug, and would be a strange thing to fix by
/// building the picker indexes and then never analysing them.
///
/// The fold is the weakest of the three and is here for uniformity
/// rather than for a Spot workload of its own: its members must be
/// dark (`junk>=70`, unnamed, single-file), which a promoted spot card
/// never is, so on a pure Spot install it costs one `MAX(id)` a pass
/// and folds nothing. It earns its place on the install this
/// configuration ACTUALLY describes - one that scanned groups and then
/// switched the indexer off - where the dark rows are already there
/// and nothing else will ever come back for them.
#[cfg(feature = "indexer")]
pub(crate) async fn maintenance_slice(
    daemon2: &Arc<Daemon>,
    has_groups: bool,
    scan_spots: bool,
    waiting: &(dyn Fn() -> bool + Sync),
) -> bool {
    // Re-asked between legs rather than once at the top: the reap runs
    // to a 30 s pass budget, and a job that starts inside it must stop
    // the two that follow. `waiting()` cannot carry that here - it is
    // `scan_groups && ...`, so on a Spot-only install it is always
    // false and the gate is the only stand-down there is.
    let ok = || (has_groups || scan_spots) && daemon2.db_maintenance_ok();
    if ok() {
        retention_and_statistics(daemon2).await;
        if waiting() {
            return false;
        }
    }
    if ok() {
        picker_index_backfill(daemon2).await;
        if waiting() {
            return false;
        }
    }
    // After the build, never before: a picker index that has just
    // landed carries no `sqlite_stat1` row, which makes the next
    // `PRAGMA optimize` re-sample its whole table and discard the deep
    // samples. Measuring first would be work thrown away.
    if ok() {
        deep_stats_pass(daemon2).await;
        if waiting() {
            return false;
        }
    }
    if ok() {
        segments_rebuild_pass(daemon2).await;
        if waiting() {
            return false;
        }
    }
    // The message-id map backfill, same shape as the folds below: a
    // bounded loop of one-second slices, the write mutex released
    // between them. It used to run only at daemon open for two seconds,
    // which on this index left 19.4M releases without a map entry and
    // the seed-join lane blind to every NZB that pointed at them
    // (research/LIVE-INDEX-CENSUS-2026-09-02.md). Before the folds on
    // purpose: a row the fold is about to merge is still keyed by the
    // ids it carries, and INSERT OR IGNORE makes a repeat harmless.
    const MSGID_MAP_SLICES_PER_LAP: u32 = 16;
    for _ in 0..MSGID_MAP_SLICES_PER_LAP {
        if !ok() {
            break;
        }
        let done = msgid_map_backfill_pass(daemon2);
        if waiting() {
            return false;
        }
        if done {
            break;
        }
    }
    // ...and the same for the quality re-classification backfill, which
    // is dormant until a version bump - one kv read a lap - and then has
    // the whole table to walk once. Same 1 s slices, same `waiting()`
    // abort between them, same caught-up break.
    //
    // EIGHT slices, fewer than the msgid map's sixteen and far fewer
    // than the folds' forty, and the arithmetic is worth stating because
    // it reads slow: at the 42-77 s per million rows the pass measures
    // (see `schema::quality_backfill`), a 67M-row index is 2,800-5,200 s
    // of work, so 8 s a lap on ~18-minute laps is four to eight days to
    // heal.
    // That is the right trade rather than a concession. This is a fixed
    // job that ENDS, so it is not losing ground the way the folds are
    // against an arrival rate, and every slice it takes is one the folds
    // do not get while they are still clearing a backlog. And the
    // population it heals is inversely sized: an index reaches 67M rows
    // by scanning the big binary groups, which are not media groups, so
    // almost nothing in it moves lane - while an index that IS full of
    // books, music and anime is orders of magnitude smaller and
    // finishes in minutes.
    const QUALITY_SLICES_PER_LAP: u32 = 8;
    for _ in 0..QUALITY_SLICES_PER_LAP {
        if !ok() {
            break;
        }
        let done = quality_backfill_pass(daemon2);
        if waiting() {
            return false;
        }
        if done {
            break;
        }
    }
    // The folds get a bounded LOOP of one-second slices, not one slice:
    // one slice per ~18-minute lap is 80 seconds of fold work a day,
    // which research/SHATTER-FOLD-STARVATION-2026-09-01.md measured
    // LOSING to ingest 11.9 to 1 with the whole 21M-row dark band
    // arriving in a week. More CALLS, never a longer hold - each slice
    // keeps its own `index_fold_secs` budget (see `fold_budget`) inside
    // its own `with_index_mut`, so the write mutex is released between
    // slices and a queued HTTP worker (or `index_write_checked`'s 5 s
    // bounded waiter) gets its window; a single 12 s hold would be the
    // http_wedge class TODO 166 exists to refuse. Sized past the memo's
    // ~12x break-even so the backlog shrinks instead of treading water;
    // `waiting()` still aborts the lap for a starting download between
    // every slice.
    //
    // 40 slices, not 16, since 2 Sep 2026: research/FOLD-BUDGET-DIAL-
    // 2026-09-02.md measured the fold's per-second yield FLAT from a 4 s
    // slice to a 10 s one (5.5k rows/s either way, against 4k at 1 s),
    // so what the fold gets per lap is slices times seconds and the
    // hold length buys nothing but refused HTTP writers past the 5 s
    // `HTTP_INDEX_WAIT`. 16 slices of 4 s (64 s a lap) only tread water
    // against ~6.3M new ids a day; 40 slices of 4 s is the 160 s a lap
    // that 16 x 10 s measured clearing the 66M-id backlog at ~17M ids
    // a day, with every hold still under the HTTP waiter's bound.
    const FOLD_SLICES_PER_LAP: u32 = 40;
    for _ in 0..FOLD_SLICES_PER_LAP {
        if !ok() {
            break;
        }
        let done = shatter_fold_pass(daemon2);
        if waiting() {
            return false;
        }
        if done {
            break;
        }
    }
    // After the shatter fold, never before: a file the shatter fold has
    // just made whole is exactly the complete single-file row the
    // session fold's population wants next.
    for _ in 0..FOLD_SLICES_PER_LAP {
        if !ok() {
            break;
        }
        let done = session_fold_pass(daemon2);
        if waiting() {
            return false;
        }
        if done {
            break;
        }
    }
    // And after the session fold, for the mirror of that fold's reason:
    // this one's population is complete single-FILE rows, which is what
    // both folds above leave behind.
    for _ in 0..FOLD_SLICES_PER_LAP {
        if !ok() {
            break;
        }
        let done = album_fold_pass(daemon2);
        if waiting() {
            return false;
        }
        if done {
            break;
        }
    }
    // And after all three folds, the durable seed replay - the lane
    // that turns a saved NZB into an exact release name. Last on
    // purpose: an exact hit needs COMPLETE local file rows with a
    // matching full manifest, which is what the folds above leave
    // behind, so a set that could not name a release before the folds
    // ran may name one after.
    //
    // It gets a reserved slice at all because until 2 Sep 2026 it had
    // none: its background task reaches the replay only by winning
    // `index_pass_gate`, and THIS loop holds that gate for the whole of
    // its work. Measured live that day, the lane had reconciled nothing
    // for 91 minutes across three restarts with 343 sets pending -
    // research/SEED-REPLAY-STARVATION-2026-09-02.md and the header on
    // `seed_replay_pass`.
    //
    // Sized from that same window, which is the only measurement of
    // this lane at live scale there is: the harvest cleared sets 3..328
    // between 15:10:56Z and 15:24:20Z, in bursts of ~4 sets a second
    // whose spacing was its own 250 ms inter-pass sleep - so a typical
    // set costs single-digit to low-tens of MILLISECONDS, not seconds.
    // Four sets a slice therefore holds the write mutex for about as
    // long as one of the harvest's own calls (its `REPLAY_PER_PASS` is
    // 1) and nothing like the folds' 4 s budget; 128 slices is 512 sets
    // a lap, which walks this index's 906 sets in two laps. Deliberately
    // MORE CALLS rather than a longer hold, for the http_wedge reason
    // the fold sizing above states at length.
    const SEED_REPLAY_SLICES_PER_LAP: u32 = 128;
    for _ in 0..SEED_REPLAY_SLICES_PER_LAP {
        if !ok() {
            break;
        }
        let done = seed_replay_pass(daemon2);
        if waiting() {
            return false;
        }
        if done {
            break;
        }
    }
    if ok() {
        enrich_unstamp_pass(daemon2);
    }
    true
}

/// TODO 26c: the one-off that puts back the titles a transient provider
/// failure blanked, on installs that collected them before the enricher
/// could tell a 429 from a "no such film".
///
/// Here rather than in the enrichment lane on purpose. It is DATABASE
/// upkeep - one bounded walk of `titles` under the index write mutex,
/// stamped done and never repeated - and the lanes are network workers
/// that must not take that mutex for a walk. It also means it inherits
/// the gate every other maintenance leg has: `db_maintenance_ok`, so it
/// stands down for a download exactly as the retention reap does.
///
/// Cheap once finished: [`nzbkit::index::Index::titles_unstamp_blanked`]
/// reads one kv key and returns.
#[cfg(feature = "indexer")]
pub(crate) fn enrich_unstamp_pass(daemon2: &Arc<Daemon>) {
    // The same slice budget the shatter fold takes, and for the same
    // reason: this holds the index writer, and a download that starts
    // mid-walk should be waiting a second, not a table scan.
    const BUDGET: std::time::Duration = std::time::Duration::from_secs(1);
    let Some((n, done)) = daemon2.with_index(|ix| ix.titles_unstamp_blanked(BUDGET).ok()) else {
        return;
    };
    if n > 0 {
        info!(
            target: "wall",
            "re-queued {n} title{} blanked by a past provider failure{}",
            if n == 1 { "" } else { "s" },
            if done { "" } else { " (more next pass)" }
        );
    }
}

/// The one budget both folds slice by: the live `index_fold_secs`
/// setting as a Duration. Read per slice, so a dashboard change takes
/// effect on the next slice rather than the next lap.
fn fold_budget(daemon2: &Arc<Daemon>) -> std::time::Duration {
    std::time::Duration::from_secs(daemon2.index_fold_secs.load(Ordering::Relaxed))
}

/// One budgeted slice of the shatter fold per scan pass: merge dark
/// rows shattered by per-article poster randomization (and group
/// rotation) back into whole per-file releases. See
/// `Index::shatter_fold` for the census that sized this (97% of dark
/// rows) and the gates that keep it narrow. Runs whenever indexing
/// does - the artifact hurts every consumer (correlation, probes,
/// msgid joins, completeness), not just predb installs.
/// Returns true when the fold is caught up (or errored - hammering a
/// failing index with more slices is noise), false while backlog
/// remains, so the caller's slice loop knows when to stop early.
pub(crate) fn shatter_fold_pass(daemon2: &Arc<Daemon>) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs() as i64)
        .unwrap_or(0);
    let budget = fold_budget(daemon2);
    let Some((g, n, done)) = daemon2.with_index_mut(|ix| {
        // An error here must be SAID: a silent Err loops forever
        // looking exactly like "nothing to do".
        match ix.shatter_fold(now, budget) {
            Ok(t) => Some(t),
            Err(e) => {
                warn!(target: "index", "shatter fold error: {e}");
                None
            }
        }
    }) else {
        return true;
    };
    if g > 0 {
        info!(
            target: "index",
            "shatter fold: {n} scattered row(s) folded into {g} posting(s)"
        );
    }
    done
}

/// One budgeted slice of the retroactive `msgid_map` fill per call.
/// Same caught-up contract as [`shatter_fold_pass`]: true when the fill
/// is complete, so the caller's slice loop stops early. Logs progress
/// once per lap (on the first slice that did work) so the fill's
/// advance is visible in the log rather than only in `kv`.
pub(crate) fn msgid_map_backfill_pass(daemon2: &Arc<Daemon>) -> bool {
    const BUDGET: std::time::Duration = std::time::Duration::from_secs(1);
    let Some((done, before, after)) = daemon2.with_index_mut(|ix| {
        let before = ix.msgid_map_progress();
        let done = ix.msgid_map_backfill_slice(BUDGET);
        Some((done, before, ix.msgid_map_progress()))
    }) else {
        return true;
    };
    if after.1 > before.1 {
        info!(
            target: "index",
            "msgid map fill: +{} key(s) this slice, cursor at files row {}, {} keys total{}",
            after.1 - before.1,
            after.0,
            after.1,
            if done { " - complete" } else { "" }
        );
    }
    done
}

/// One budgeted slice of the quality re-classification backfill per
/// call. Same caught-up contract as [`shatter_fold_pass`]: true when
/// the pass is complete, so the caller's slice loop stops early.
///
/// Why the lap and not only `Index::open`: the pass re-parses every row
/// in the table once per version bump, and it runs INSIDE the open, so
/// an unbounded loop there is blocked daemon startup proportional to the
/// index. It gets 2 s at open (enough that a small index finishes at
/// once) and the rest here, which is the shape
/// `msgid_map_backfill_pass` above arrived at for the same reason.
pub(crate) fn quality_backfill_pass(daemon2: &Arc<Daemon>) -> bool {
    const BUDGET: std::time::Duration = std::time::Duration::from_secs(1);
    let Some((done, before, after)) = daemon2.with_index_mut(|ix| {
        let before = ix.quality_backfill_cursor();
        let done = ix.quality_backfill_slice(BUDGET);
        Some((done, before, ix.quality_backfill_cursor()))
    }) else {
        return true;
    };
    if before != after {
        match after {
            Some(at) => info!(target: "index", "quality backfill: cursor at release {at}"),
            None => info!(target: "index", "quality backfill: complete"),
        }
    }
    done
}

/// One budgeted slice of the session fold per scan pass: merge each
/// proven dark upload session (one stable poster, N complete
/// single-file rows at one volume size, every member covering 1..P
/// exactly once) into one release with a true total size. See
/// `Index::session_fold` for the proof that licenses a merge and the
/// frozen-index measurement that sized the band (289 sessions, 26k
/// rows, 1.9 TB). Runs after the shatter fold on purpose - a file that
/// fold has just made whole is this fold's population.
/// Same caught-up contract as [`shatter_fold_pass`].
pub(crate) fn session_fold_pass(daemon2: &Arc<Daemon>) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs() as i64)
        .unwrap_or(0);
    let budget = fold_budget(daemon2);
    let Some((s, n, done)) = daemon2.with_index_mut(|ix| {
        // An error here must be SAID: a silent Err loops forever
        // looking exactly like "nothing to do".
        match ix.session_fold(now, budget) {
            Ok(t) => Some(t),
            Err(e) => {
                warn!(target: "index", "session fold error: {e}");
                None
            }
        }
    }) else {
        return true;
    };
    if s > 0 {
        info!(
            target: "index",
            "session fold: {n} lone file(s) folded into {s} session release(s)"
        );
    }
    done
}

/// One budgeted slice of the album fold per scan pass: merge a
/// poster's per-track music or audiobook post into the one album it
/// was posted as, named by the `00-artist-album-...` furniture beside
/// it or, failing that, by what the track stems agree on. See
/// `Index::album_fold` for which of those two names is load-bearing
/// and why, and for the measurement that sized the band (2 Sep 2026,
/// `music` preset: 1,939 Music-tab "titles", the first two rows of
/// cards fourteen tracks of one album).
///
/// It takes the same per-slice budget and the same slice count as the
/// two folds before it, deliberately: it holds the same index write
/// mutex, so what keeps a queued HTTP writer inside the 5 s
/// `HTTP_INDEX_WAIT` bound is that no single hold is longer, not that
/// there are fewer of them. Same caught-up contract as
/// [`shatter_fold_pass`].
pub(crate) fn album_fold_pass(daemon2: &Arc<Daemon>) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs() as i64)
        .unwrap_or(0);
    let budget = fold_budget(daemon2);
    let started = std::time::Instant::now();
    let Some((a, n, done)) = daemon2.with_index_mut(|ix| {
        // An error here must be SAID: a silent Err loops forever
        // looking exactly like "nothing to do".
        match ix.album_fold(now, budget) {
            Ok(t) => Some(t),
            Err(e) => {
                warn!(target: "index", "album fold error: {e}");
                None
            }
        }
    }) else {
        return true;
    };
    if a > 0 {
        // The hold time is in the line on purpose: this slice holds the
        // index write mutex, and the number an operator (or the next
        // lane sizing the fold) needs is how long for, not just what it
        // achieved.
        info!(
            target: "index",
            "album fold: {n} track row(s) folded into {a} album release(s) in {:.1?}",
            started.elapsed()
        );
    }
    done
}

/// M31a retention prune and the query-planner statistics refresh - the
/// two pieces of index upkeep that run between passes on their own
/// clocks.
///
/// Throttled to once an hour (a kv timestamp) and skipped while a
/// download is active, so it never fights for the write lock during a
/// job. The stale-partial reaper runs whenever a scan source is on; the
/// age prune only when retention is enabled AND a max-age window is set.
///
/// The caller owns the entry guard (`maintenance_slice`), and it is
/// `db_maintenance_ok`. The reap's own per-slice stand-down below has to
/// ask the SAME question: with the indexing predicate there, a Spot-only
/// install is admitted at the door and then breaks out before its first
/// slice, which reaps nothing and never stamps the hourly clock.
pub(crate) async fn retention_and_statistics(daemon2: &Arc<Daemon>) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs() as i64)
        .unwrap_or(0);
    let last: i64 = daemon2
        .with_index(|ix| ix.kv_get("retention_at").and_then(|v| v.parse().ok()))
        .unwrap_or(0);
    if now - last >= 3_600 {
        let max_age = daemon2.index_max_age_secs.load(Ordering::Relaxed) as i64;
        let retention = daemon2.index_retention.load(Ordering::Relaxed);
        let (mut aged, mut stale) = (0usize, 0usize);
        // One slice = one hold of the index write mutex. The reap used
        // to run to exhaustion inside a single `with_index`, which on a
        // large index is hours with every other index consumer - the
        // download runner's oracle ingest included - parked on the
        // mutex behind it. Slicing is the whole fix: the work is the
        // same, the LOCK is handed back between batches.
        const PRUNE_SLICE: std::time::Duration = std::time::Duration::from_secs(1);
        // ...and the pass gives up its turn well before the scan
        // interval, so a reap with millions of rows to go never starves
        // the scan it shares this loop with. It resumes next pass.
        const PRUNE_PASS: std::time::Duration = std::time::Duration::from_secs(30);
        let pass_started = std::time::Instant::now();
        let pass_end = pass_started + PRUNE_PASS;
        let mut caught_up = false;
        while !caught_up {
            // The same stand-down every other maintenance slice takes:
            // a download that starts mid-reap gets the mutex at the
            // next slice boundary rather than at the end of the reap.
            // `db_maintenance_ok`, not `index_maintenance_ok` - the
            // same correction as the entry gate, and the same trap.
            // With the indexing predicate here, a Spot-only install
            // entered the reap and broke out of it before the first
            // slice: nothing pruned, `caught_up` false forever, and an
            // hourly clock that never stamps. A gate that admits work
            // and then refuses it is worse than one that never admits
            // it, because the log says the pass ran.
            if std::time::Instant::now() >= pass_end || !daemon2.db_maintenance_ok() {
                break;
            }
            let slice = std::time::Instant::now() + PRUNE_SLICE;
            let Some((a, s, done)) = daemon2.with_index(|ix| {
                // Age prune (wall-visible content) is
                // opt-in via the retention setting + a
                // window; the stale-partial junk reaper
                // is always on (touches only junk-hidden
                // dead fragments).
                let (a, a_done) = if retention && max_age > 0 {
                    ix.prune_age(max_age, now, slice).unwrap_or((0, true))
                } else {
                    (0, true)
                };
                // Only if the age prune left budget: both share the one
                // slice, and starting the second reap past the deadline
                // would double this hold of the mutex.
                //
                // `a_done` alone did NOT say that. It says "the age
                // prune was not cut off", and a prune reports itself
                // caught up the moment its selection comes back empty -
                // even when that one statement burned the whole slice
                // and more. So the clock has to be read as well, or two
                // unbounded walks land in one hold of the write mutex
                // and the slice means half what it says (read-only
                // sweep 3, 16 Aug 2026, M9).
                let (s, s_done) = if a_done && std::time::Instant::now() < slice {
                    ix.prune_stale_partials(7 * 86_400, now, slice)
                        .unwrap_or((0, true))
                } else {
                    (0, false)
                };
                Some((a, s, a_done && s_done))
            }) else {
                break;
            };
            aged += a;
            stale += s;
            caught_up = done;
            // Yield the runtime as well as the mutex. A waiting index
            // caller has to be RUNNABLE to take the lock we just
            // dropped, and this task would otherwise re-acquire it
            // without ever going back to the scheduler.
            tokio::task::yield_now().await;
        }
        daemon2.with_index(|ix| {
            // §131 D3 search-miss log, both caps. Not counted in
            // the pruned totals below: these are derived rows
            // about queries, not catalogue content, and folding
            // them into "retention pruned N old rows" would make
            // that line lie about what left the index.
            let _ =
                ix.search_log_prune(crate::SEARCH_LOG_DAYS * 86_400, crate::SEARCH_LOG_ROWS, now);
            // The hourly clock is stamped only by a reap that ran out
            // of rows. A pass that spent its budget has more to take
            // and must come back on the NEXT scan pass - an hour's wait
            // per slice is how a bounded reap turns into one that never
            // finishes.
            if caught_up {
                let _ = ix.kv_set("retention_at", &now.to_string());
            }
            Some(())
        });
        if aged + stale > 0 {
            // The elapsed is the diagnostic, not decoration. The pass is
            // bounded at PRUNE_PASS, so anything much past 30 s is by
            // definition a single statement that ran long with the index
            // write mutex held - which is what every consumer waiting on
            // that mutex experiences as a stall, the download runner's
            // tail included. Gary's 20 Aug report had to be inferred from
            // an 8m46s GAP between two log lines, because this one did
            // not say. Now it says.
            info!(
                target: "index",
                "retention pruned {aged} old + {stale} stale-partial rows in {:.1}s{}",
                pass_started.elapsed().as_secs_f64(),
                if caught_up { "" } else { " (more to reap next pass)" }
            );
            // No republish (B4): the reap ran on the shared connection
            // itself, and the pooled readers see its commits through
            // WAL on their next query.
        }
    }
    // Query-planner statistics, on the same gate and a
    // slower clock. Daily rather than hourly because the
    // shape of the data - a few thousand titles against
    // tens of millions of releases - is what the planner
    // needs, and that ratio moves over weeks, not hours.
    //
    // Not optional maintenance: an index with no statistics
    // plans `wall2` as a full scan of every release, which
    // is how a 45 GB index came to spend 85s answering one
    // card query (2 Aug). See `Index::optimize`.
    let last_opt: i64 = daemon2
        .with_index(|ix| ix.kv_get("analyze_at").and_then(|v| v.parse().ok()))
        .unwrap_or(0);
    if now - last_opt >= 86_400 {
        let started = std::time::Instant::now();
        // The first run on a big never-analyzed database is
        // minutes of synchronous work holding the write
        // connection, under the same pass gate a starting
        // download rendezvouses on - the exact stall §95
        // removed from compaction. Same cure: a blocking
        // thread, an interrupt handle, and a watcher that
        // aborts the statement the moment a job appears. An
        // aborted refresh is NOT stamped, so it retries at
        // the next idle hour.
        // The handle is taken INSIDE the blocking closure,
        // under the guard that runs the statement - see
        // MaintenanceArm. Taken out here (an earlier, since
        // released with_index) it belonged to a connection
        // some other writer could be using by the time the
        // watcher fired.
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
            d3.with_index(|ix| {
                if !arm2.arm(ix.interrupt_handle()) {
                    // A download started before we got the
                    // guard: do not begin at all.
                    done2.store(true, Ordering::Release);
                    return None;
                }
                let r = ix.optimize();
                arm2.disarm();
                // Inside the closure for the same reason as
                // the VACUUM path: the watcher must never
                // see "running" on a connection somebody
                // else has already started using.
                done2.store(true, Ordering::Release);
                Some(r)
            })
        })
        .await;
        done.store(true, Ordering::Release);
        let aborted = matches!(watch.await, Ok(true));
        match outcome {
            _ if aborted => {
                info!(
                    target: "index",
                    "statistics refresh stood down for a download - \
                     it will run again at the next idle hour"
                );
            }
            Ok(Some(Ok(()))) => {
                let _ = daemon2.with_index(|ix| ix.kv_set("analyze_at", &now.to_string()).ok());
                // Only worth a line when it actually took
                // time - the daily no-op pass is silent.
                if started.elapsed() >= std::time::Duration::from_secs(1) {
                    info!(
                        target: "index",
                        "query planner statistics refreshed in {:.1}s",
                        started.elapsed().as_secs_f64()
                    );
                }
            }
            Ok(Some(Err(e))) => {
                // Stamped even on error: a database that
                // cannot be analyzed must not retry it
                // every hour forever.
                let _ = daemon2.with_index(|ix| ix.kv_set("analyze_at", &now.to_string()).ok());
                warn!(target: "index", "ANALYZE: {e}");
            }
            Ok(None) | Err(_) => {}
        }
    }
}

/// B1: backfill the deferred partial indexes on an index too big for
/// `Index::open` to build them inline - the three background-picker
/// ones and, since §198, the two `complete` browse ones. One index per
/// pass, so one pass each carries the whole migration; each build is a
/// CREATE INDEX that reads the whole `releases` table once holding the
/// write lock, so it runs exactly like the daily ANALYZE - a blocking
/// thread, a `MaintenanceArm`, and a watcher that aborts the statement
/// the moment a download starts. An aborted build rolls back cleanly
/// and the next pass retries; sqlite_master is the only state, so
/// there is no stamp to get wrong. Once they all exist the probe is a
/// sub-millisecond catalog read and this returns immediately.
#[cfg(feature = "indexer")]
pub(crate) async fn picker_index_backfill(daemon2: &Arc<Daemon>) {
    let Some(name) = daemon2.with_index(|ix| ix.missing_picker_index()) else {
        return;
    };
    // Sweep 8, L12: the SHARED-DATABASE predicate, not the indexing
    // one - a Spot-only install has `index_enabled` false, which makes
    // `index_maintenance_ok` permanently false and would leave this
    // build unreachable forever on exactly the databases that need it.
    if !daemon2.db_maintenance_ok() {
        return;
    }
    info!(
        target: "index",
        "building deferred index {name} (one-time, holds the index writer; \
         stands down if a download starts)"
    );
    let started = std::time::Instant::now();
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
        d3.with_index(|ix| {
            if !arm2.arm(ix.interrupt_handle()) {
                // A download started before we got the guard: do
                // not begin at all.
                done2.store(true, Ordering::Release);
                return None;
            }
            let r = ix.build_picker_index(name);
            arm2.disarm();
            // Inside the closure, same as ANALYZE: the watcher must
            // never see "running" on a connection somebody else has
            // already started using.
            done2.store(true, Ordering::Release);
            Some(r)
        })
    })
    .await;
    done.store(true, Ordering::Release);
    let aborted = matches!(watch.await, Ok(true));
    match outcome {
        _ if aborted => {
            info!(
                target: "index",
                "deferred index {name} stood down for a download - \
                 it will be built on a later pass"
            );
        }
        Ok(Some(Ok(()))) => {
            info!(
                target: "index",
                "deferred index {name} built in {:.1}s",
                started.elapsed().as_secs_f64()
            );
        }
        Ok(Some(Err(e))) => warn!(target: "index", "deferred index {name}: {e}"),
        Ok(None) | Err(_) => {}
    }
}

/// M34: hold the database under its size cap. BETWEEN passes, never
/// inside one - the scan JoinSet is fully drained by the time this
/// runs, so no scan task is holding the write lock or about to
/// re-insert what was just deleted.
///
/// `evict_pass` is a no-op (two atomic loads) unless the user turned
/// eviction on AND set a cap, so the common install pays nothing for
/// this. It never compacts: reclaiming the freed pages is a VACUUM, and
/// that waits for the idle window in `spawn_index_compact`.
#[cfg(feature = "indexer")]
pub(crate) async fn evict_between_passes(daemon2: &Arc<Daemon>) {
    {
        let d3 = daemon2.clone();
        // The prune is synchronous SQLite work on a shared
        // connection - off the async worker.
        let outcome = tokio::task::spawn_blocking(move || d3.evict_pass()).await;
        // Record a trim that actually removed something, so the
        // DB card can say what happened to the releases that
        // disappeared. `Nothing`/`Unavailable` removed nothing
        // and must not overwrite the last real answer.
        if let Ok(crate::daemon::EvictOutcome::Ran(rep, _)) = &outcome
            && rep.removed > 0
        {
            *daemon2.last_auto_trim.lock_ok() = Some((
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
                rep.removed as u64,
            ));
        }
        // No republish (B4): eviction ran on the shared connection
        // through `with_index`, and WAL hands its commits to the pooled
        // readers on their next query. The rows are gone even though
        // the file is still big - the pages are free, not returned,
        // until the deferred compact runs.
    }
}

// `seed_replay_pass` and its per-slice constant moved DOWN into
// `nzbfast_daemon::seed_harvest` when the daemon layer became its own
// crate: the function is the reconcile ENGINE over a `&Arc<Daemon>`
// with no lane machinery of its own, and `seed_harvest` runs the same
// work opportunistically while this lap is the floor under it - lane
// 1b's ENGINE DOWN, LANE UP rule. The lap calls it under its old bare
// name through serve's root glob; nothing about the lap moved.
pub(crate) use nzbfast_daemon::seed_harvest::seed_replay_pass;
