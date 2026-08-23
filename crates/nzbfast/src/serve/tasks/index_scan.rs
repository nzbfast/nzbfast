//! The two leaf blocks of `spawn_index_scan`'s pass loop: the per-group
//! scan task and the A8 gap-fill leg. Hoisted out of `tasks.rs` verbatim
//! on 22 Aug 2026 because `fn spawn_index_scan` sat five lines under the
//! size gate's 500-line function ceiling, so the next line anyone added
//! would have reddened main (TODO 106 pattern, as `check_sweep.rs` and
//! `get/fleet_knobs.rs`). Behaviour unchanged: this is `spawn_index_scan`'s
//! own child module, glob-imported back, and both bodies keep their
//! ordering, their preemption contract and their comment blocks exactly
//! as they were - only the pass-wide scalars became `PassKnobs` fields.

use super::*;

/// The pass-wide scalars every group task of one pass shares, in the
/// order `spawn_index_scan` binds them. Field names match the local
/// bindings the inline code used, so `scan_group` destructures this and
/// the `index_scan_into` call reads as it always did.
#[derive(Clone, Copy)]
pub(super) struct PassKnobs {
    pub(super) backfill: u64,
    pub(super) max_age: u64,
    pub(super) deep: Option<u64>,
    pub(super) deepen: u64,
    pub(super) par: usize,
    pub(super) turbo: bool,
    pub(super) coverage: bool,
}

/// One group's scan task: the body `spawn_index_scan` puts on its
/// JoinSet per group. Owns its arguments because the task outlives the
/// loop iteration that spawned it.
#[expect(clippy::too_many_arguments)]
pub(super) async fn scan_group(
    g: String,
    sem: Arc<tokio::sync::Semaphore>,
    config: std::path::PathBuf,
    db: std::path::PathBuf,
    daemon3: Arc<Daemon>,
    gates: Option<crate::gates::Gates>,
    cats: Vec<nzbkit::categories::CustomCategory>,
    preempted2: Arc<AtomicBool>,
    knobs: PassKnobs,
) {
    let PassKnobs {
        backfill,
        max_age,
        deep,
        deepen,
        par,
        turbo,
        coverage,
    } = knobs;
    let _permit = sem.acquire_owned().await.expect("scan semaphore");
    // The generation this pass belongs to. A pass runs
    // for minutes; the switch and the wipe are one
    // click. Publishing without checking this is how a
    // switched-off indexer got a live connection back
    // and a wiped database got recreated.
    let era = daemon3.index_era();
    // Scan into a dedicated connection, then republish
    // - keeps the OVER round-trips off the lock that
    // query handlers need.
    let mut scratch = match nzbkit::index::Index::open_scratch(&db) {
        Ok(ix) => ix,
        Err(e) => {
            warn!(target: "index", "open {}: {e}", db.display());
            return;
        }
    };
    let done = Arc::new(AtomicU64::new(0));
    daemon3.scan_progress.lock_ok().push(ScanProgress {
        group: g.clone(),
        done: done.clone(),
    });
    // Backfill, max-age and gates are all live settings
    // now (M12 volume control), sampled per pass.
    // A download can begin during a long scan. Drop
    // the scan future promptly; its owned JoinSet
    // aborts every OVER worker, while the contiguous
    // high-water invariant leaves the unfinished
    // range for the next pass.
    let scan = crate::index_scan_into(
        &config,
        &g,
        backfill,
        max_age,
        gates.as_ref(),
        cats,
        &mut scratch,
        deep,
        deepen,
        Some(done),
        par,
        turbo,
        coverage,
        // §74: sampled per group, like the gates above -
        // an item added while a long pass runs is armed
        // for the groups still to come.
        daemon3.instant_matcher(),
    );
    // Carries the reason out, not just the fact: this
    // future fires for every stand-down cause, and the
    // fixed "paused for foreground job" it used to print
    // sent a 14-hour offline standstill (11 Aug 2026)
    // looking for a download that was never there.
    let pause = async {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            if let Some(reason) = daemon3.indexing_pause_reason() {
                break reason;
            }
        }
    };
    match tokio::select! {
        result = scan => Ok(result),
        reason = pause => Err(reason),
    } {
        Ok(Err(e)) => warn!(target: "index", "scan {g}: {e}"),
        Err(reason) => {
            preempted2.store(true, Ordering::Relaxed);
            info!(
                target: "index",
                "scan {g} stood down: {}",
                Daemon::pause_phrase(reason)
            );
        }
        Ok(Ok(())) => {}
    }
    daemon3.scan_progress.lock_ok().retain(|p| p.group != g);
    // §74: what this pass's FORWARD legs read. TAKEN
    // here because the journal lives on `scratch` - the
    // dedicated connection this task scanned into - and
    // this is the last point it is still in hand.
    // Unconditional on the outcome above: a pass stood
    // down halfway still INGESTED what it read, and
    // dropping those on the floor would be the very
    // silence this exists to end.
    let (hits, dropped) = scratch.take_watch_hits();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // Arrivals triaged first, staged WITH the republish
    // below, announced after. The staging shares the
    // republish's hold of `index` so the two cannot be
    // observed apart: between them the release is
    // visible while `instant_hint` is still empty, and a
    // pass already in flight grabs it and never records
    // it as an instant grab.
    //
    // The hint is still never staged BEFORE the
    // republish, but do NOT trust the reason §74
    // originally gave for that - "the shared handle
    // cannot see a word `scratch` wrote until the
    // republish". Read `Index::ingest`: it commits each
    // of its passes internally and journals the watch
    // hits AFTER the commit (hence its
    // `debug_assert!(hits.is_empty())`), so the rows are
    // visible to every connection before
    // `take_watch_hits` is even called. A pass can grab
    // the release before anything here has staged a
    // thing. This ordering is cheap and defensively
    // right; it is not what makes the arrival visible,
    // and it does not close the race on its own. See
    // `nzbfast-scan-leg-swallows-arrivals`.
    let ready = instant_ready(&daemon3, hits, dropped, now);
    let names = ready.join(", ");
    // Hand this task's own connection back (B4). When a
    // shared connection already exists it is kept - WAL
    // means it sees this task's committed writes on its
    // next statement - and when none does, `scratch`
    // becomes it, sparing the full `Index::open`
    // migration ladder this used to re-run per group
    // per pass. The era check lives inside: a wipe or
    // source-off mid-pass drops the connection and
    // stages only the hint (deciding what to do with it
    // is the pass's job either way). The pooled readers
    // are NOT retired here any more - a WAL reader
    // picks up commits on its next query, and the
    // identity events retire the pool themselves.
    let staged = daemon3.publish_index_with_arrivals(era, scratch, &ready, now);
    // Last, so the woken pass finds both invalidations
    // done. `notify_one` parks a permit when nobody is
    // waiting, so nothing is lost by waking late.
    if staged {
        info!(
            target: "watch",
            "arrived: {names} - checking the watchlist now"
        );
        daemon3.watch_now.notify_one();
    }
}

/// A8 gap-fill leg, run under the pass gate after the group scans when
/// `index_gapfill` is set and coverage is on. The caller has already
/// asked the pause reason; this re-asks it between chunks and selects
/// against it, same as the scan tasks.
pub(super) async fn gapfill_leg(
    daemon2: &Arc<Daemon>,
    config: &std::path::Path,
    db: &std::path::Path,
    gapfill: u32,
) {
    let gates2 = daemon2.index_gates.lock_ok().1.clone();
    let cats2 = daemon2.custom_categories.read_ok().clone();
    // Same contract as the scan tasks above: this owns a
    // dedicated connection for the length of the pass, so
    // it may only publish if the index it belongs to is
    // still the current one.
    let era = daemon2.index_era();
    match nzbkit::index::Index::open_scratch(db) {
        Ok(mut scratch) => {
            install_live_ingest_policy(&mut scratch, gates2, cats2);
            let d3 = daemon2.clone();
            // Same preemption contract as the scan tasks:
            // a starting job raises its guard then waits
            // on the pass gate this section holds, so
            // dropping the future promptly (never
            // mid-transaction - ingest holds no await
            // point) is what keeps job start snappy. The
            // stop() closure is the cheap between-chunks
            // early-out; the select is the hard bound.
            let gap = crate::index_gapfill_pass(config, &mut scratch, gapfill, || {
                d3.indexing_pause_reason().is_some()
            });
            let pause = async {
                loop {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    if let Some(reason) = daemon2.indexing_pause_reason() {
                        break reason;
                    }
                }
            };
            match tokio::select! {
                r = gap => Ok(r),
                reason = pause => Err(reason),
            } {
                Ok(Ok((tried, done))) if tried > 0 => {
                    info!(
                        target: "gapfill",
                        "{tried} incomplete releases re-hunted, {done} completed"
                    );
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) => warn!(target: "gapfill", "{e}"),
                Err(reason) => {
                    info!(
                        target: "gapfill",
                        "stood down: {}",
                        Daemon::pause_phrase(reason)
                    )
                }
            }
            // Hand the connection back rather than reopening
            // (B4) - kept-or-installed under the era check,
            // same as the scan tasks. No reader retirement:
            // WAL covers the freshness.
            daemon2.publish_index(era, scratch);
        }
        Err(e) => warn!(target: "gapfill", "open {}: {e}", db.display()),
    }
}
