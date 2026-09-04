//! Index upkeep, either side of the scan loop itself (which stays in
//! `tasks.rs` with the download worker): deferred VACUUM
//! compaction, the instant-watch hook that offers fresh arrivals to the
//! watchlist, the tip watcher, and the oracle sampler.
//!
//! The common discipline here is that none of it may cost the user a
//! download - the compactor waits for a genuinely idle moment, and the
//! samplers sit out entirely while anything is fetching.
//!
//! Split out of `tasks.rs` whole (TODO 106) - the code is verbatim,
//! only visibility changed (and one `super::daemon::` path, which now
//! sits one module deeper, spelled from the crate root).
//!
//! The nine passes the scan loop runs BETWEEN group scans are NOT here -
//! they are the `passes` child, split off for the same 4,000-line
//! ceiling and re-exported flat, so `indexer::spot_pass` still resolves.

use super::*;

/// M34: deferred compaction. Deleting rows does not shrink a SQLite
/// file - the pages go on the free list and the file stays the size
/// it grew to - so reclaiming the disk the size cap just promised
/// needs a VACUUM. VACUUM exclusive-locks and rewrites the WHOLE
/// database, which is exactly the thing that must never interrupt a
/// scan pass or a download, so it is not run where the prune raises
/// the flag. This loop waits for a genuinely idle moment instead:
/// nothing downloading, nothing scanning, and room on the volume for
/// the rebuild. If any of that fails it stays deferred and tries
/// again a minute later - a compact that never happens costs disk,
/// a compact that runs at the wrong time costs the user their
/// download.
#[cfg(feature = "indexer")]
pub fn spawn_index_compact(daemon: &Arc<Daemon>, index_pass_gate: &Arc<tokio::sync::Mutex<()>>) {
    let d = daemon.clone();
    let index_pass_gate = index_pass_gate.clone();
    // Not `index_db` - the scan-loop task above owns that binding now.
    let db = daemon.index_db.clone();
    tokio::spawn(async move {
        // Seed the space ledger BEFORE the first sleep. The loop below
        // reconciles it every minute, which is soon enough for a write
        // and far too late for a READ: until the stored figures are
        // back, `last_compact` is None, and None is what the dashboard
        // renders as "it has not been compacted yet" - a false sentence
        // about a database that was compacted last night, on the one
        // card whose whole job is not to say things like that. A
        // failure here is not retried on the spot; the loop takes it.
        {
            let dl = d.clone();
            let _ = tokio::task::spawn_blocking(move || dl.sync_index_ledger()).await;
        }
        // One-shot and offline, also before the first sleep: releases
        // whose applied name is exactly its own text twice get the
        // single half back. It rides this task rather than a naming one
        // because every naming task is behind the wire-spend gate
        // (`may_call_out`) and this repair never touches a server -
        // and because the rows cannot heal themselves: the doubled name
        // and its correct half grade EQUAL in `applied_strength`, so
        // the correct claim loses the tie every time. kv-guarded, so
        // this is a no-op on every start after the first.
        {
            let dl = d.clone();
            let done = tokio::task::spawn_blocking(move || {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|t| t.as_secs() as i64)
                    .unwrap_or(0);
                dl.with_index_mut(|ix| Some(ix.repair_doubled_pre_titles(now)))
            })
            .await;
            match done {
                Ok(Some(Ok(n))) if n > 0 => {
                    info!(target: "claims", "repaired {n} release name(s) written twice")
                }
                Ok(Some(Err(e))) => warn!(target: "claims", "doubled-name repair: {e}"),
                _ => {}
            }
        }
        // Rate-limit the "no room" line: this ticks every minute and
        // a small NAS volume can stay full for days.
        let mut last_moan = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(7200))
            .unwrap_or_else(std::time::Instant::now);
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            // Reconcile the space ledger with the database before the
            // early returns below. This is the index's background tick
            // and the ledger's only trip to disk: the stats poll reads
            // its in-memory mirror, because a poll may never take the
            // index mutex (TODO 166). A no-op when nothing has changed,
            // and when the database is not open it simply comes back.
            {
                let dl = d.clone();
                let _ = tokio::task::spawn_blocking(move || dl.sync_index_ledger()).await;
            }
            // `compact_pending` is sticky, so a prune that raised it
            // just before the indexer was switched off would still
            // rewrite a multi-GB file - the loudest disk work there
            // is, on behalf of a feature that is now off. It stays
            // raised and runs if the indexer comes back; to get the
            // space back instead, the off state offers to delete the
            // database outright.
            if !d.compact_pending.load(Ordering::Relaxed) || d.indexer_off() {
                continue;
            }
            let Ok(_index_pass) = index_pass_gate.try_lock() else {
                continue;
            };
            let _busy = d.busy.hold("maintenance");
            // A stat, but on whatever volume holds the index - demote
            // the worker like every other sync fs touch on a tokio task.
            let db_bytes = crate::persist::blocking_db(|| {
                std::fs::metadata(&db).map(|m| m.len()).unwrap_or(0)
            });
            // §95: which of the two paths this database can take, read
            // BEFORE the verdict because it decides whether the volume
            // needs room for a second copy. A fresh install has been
            // incremental since `Index::open` created it; an existing
            // one is still in SQLite's default mode and needs one full
            // rewrite to get there.
            let style = d
                .with_index(|ix| ix.compact_style().ok())
                .unwrap_or(nzbkit::index::CompactStyle::FullRewrite);
            let verdict = compact_verdict(
                true,
                !d.scan_progress.lock_ok().is_empty(),
                // This argument is `downloading`, and a true answer
                // yields Busy("a download is running"). The pause
                // PREDICATE is not that question and gets it wrong in
                // both directions: with pause-on-download switched off
                // it reads false during a job, so a multi-GB VACUUM
                // could start mid-download on the same volume; and with
                // the indexer manually paused it reads true forever, so
                // compaction never runs at exactly the moment it is
                // safest. compact_pending is sticky, so that second one
                // defers silently and permanently.
                //
                // Count jobs in flight rather than reading started_at,
                // which goes None between queued jobs while the
                // pipeline is still busy.
                d.index_jobs_active.load(Ordering::Acquire) > 0,
                db_bytes,
                crate::persist::blocking_db(|| {
                    free_bytes(db.parent().unwrap_or(std::path::Path::new(".")))
                }),
                style == nzbkit::index::CompactStyle::FullRewrite,
            );
            match verdict {
                CompactVerdict::NotNeeded | CompactVerdict::Busy(_) => continue,
                CompactVerdict::NoRoom { need, free } => {
                    if last_moan.elapsed() >= std::time::Duration::from_secs(3600) {
                        last_moan = std::time::Instant::now();
                        info!(
                            target: "index",
                            "compact deferred: rebuilding the {:.0} MB index needs \
                             ~{:.0} MB free and the volume has {:.0} MB - the pruned rows \
                             are gone, the file just hasn't shrunk yet",
                            db_bytes as f64 / (1u64 << 20) as f64,
                            need as f64 / (1u64 << 20) as f64,
                            free as f64 / (1u64 << 20) as f64,
                        );
                    }
                    continue;
                }
                CompactVerdict::Go => {}
            }
            // Clear the flag BEFORE the rewrite: if a prune lands
            // while this runs it re-raises it and we come back,
            // whereas clearing afterwards would swallow that request.
            d.compact_pending.store(false, Ordering::Relaxed);
            let d2 = d.clone();
            let path = db.clone();
            // The verdict above answers "is a download running?" a
            // moment BEFORE the rewrite starts, and the rewrite then
            // holds `index_pass_gate` - which is exactly what a
            // starting download waits on - for its whole duration.
            // A job that arrives in between sits in `Downloading`
            // making no progress and logging nothing until the
            // VACUUM ends: measured, a 175 MB index blocks a waiter
            // for ~0.5 s, so the multi-GB indexes this feature exists
            // for block it for minutes.
            //
            // So take an interrupt handle before handing the
            // connection to the blocking thread, and abort the
            // rewrite the moment a job appears. VACUUM is one
            // transaction: aborting leaves the file exactly as it
            // was, and `compact_pending` brings us back a minute
            // later. The user's rule is that compaction never
            // interrupts a download - the same rule has to hold when
            // the download turns up second.
            if style == nzbkit::index::CompactStyle::Chunked {
                chunked_compact(&d, &db).await;
                continue;
            }
            info!(
                target: "index",
                "compacting the {:.0} MB index in one pass to enable incremental \
                 reclaim - this one cannot be cut short for a download, later ones can",
                db_bytes as f64 / (1u64 << 20) as f64,
            );
            // Armed inside the blocking closure, under the guard that
            // runs the VACUUM - see MaintenanceArm. A handle taken here
            // and used later belongs to a connection an unrelated
            // writer may hold by then.
            let arm = Arc::new(crate::daemon::MaintenanceArm::default());
            let done = Arc::new(AtomicBool::new(false));
            let watch = {
                let jobs = d.index_jobs_active.clone();
                let done = done.clone();
                let arm = arm.clone();
                tokio::spawn(abort_compact_when_job_starts(jobs, done, move || {
                    arm.abort();
                }))
            };
            // VACUUM is a long synchronous rewrite - it belongs on a
            // blocking thread, not on an async worker.
            let done2 = done.clone();
            let arm2 = arm.clone();
            let outcome = tokio::task::spawn_blocking(move || {
                let before = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                let ok = d2
                    .with_index(|ix| {
                        if !arm2.arm(ix.interrupt_handle()) {
                            // A download started before we got the
                            // guard: do not begin the rewrite at all.
                            done2.store(true, Ordering::Release);
                            return None;
                        }
                        let r = ix.compact();
                        arm2.disarm();
                        // Inside the closure, so the flag is set
                        // while this thread still holds the index
                        // lock: the watcher can never see "running"
                        // for a connection somebody else has already
                        // started using.
                        done2.store(true, Ordering::Release);
                        r.ok()
                    })
                    .is_some();
                let after = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                if ok {
                    // Charged outside the `with_index` closure above:
                    // the ledger mutex is taken before the index mutex
                    // everywhere, never after it.
                    d2.note_compact(before.saturating_sub(after));
                    info!(
                        target: "index",
                        "compacted at idle - {:.0} MB reclaimed",
                        before.saturating_sub(after) as f64 / (1u64 << 20) as f64
                    );
                } else {
                    d2.compact_pending.store(true, Ordering::Relaxed);
                }
                ok
            })
            .await;
            done.store(true, Ordering::Release);
            // Distinguish the two failures in the log. "Compact
            // failed" for a rewrite we deliberately aborted would
            // send the user looking for a broken database.
            if matches!(watch.await, Ok(true)) {
                info!(
                    target: "index",
                    "compact stood down for a download - the index will \
                     shrink at the next idle moment"
                );
            } else if matches!(outcome, Ok(false)) {
                warn!(target: "index", "compact failed - will retry when idle");
            }
        }
    });
}

/// §95: reclaim the freed pages in bounded chunks, stopping the moment
/// a download appears.
///
/// This is the whole point of the incremental mode. The VACUUM path
/// above can only ASK to stop - `sqlite3_interrupt` is read from the
/// VDBE, so it never reaches the rewrite's `sqlite3BtreeCopyFile` tail -
/// and measured on a 1.16 GB index, a job that arrived as the rewrite
/// started waited the full 4.8 s and every abort that did land threw
/// away all 580 MB of reclaim. Here the check is between chunks, where
/// nothing is running, so standing down is immediate and everything
/// reclaimed so far is already committed and truncated.
///
/// It stays on one blocking thread for the whole loop, but takes the
/// shared index connection PER CHUNK: scan passes are already excluded
/// for the whole iteration by `index_pass_gate` (they use scratch
/// connections and rendezvous on the gate, never this mutex), so the
/// only threads the mutex holds off are the write-side HTTP handlers -
/// wall admin edits, pre_assign, kv writes - and parking those for a
/// multi-minute pass is the 2 Aug wedge shape all over again. Between
/// chunks the mutex is free, so an admin edit waits one chunk (~100 ms),
/// not the whole compaction.
#[cfg(feature = "indexer")]
async fn chunked_compact(d: &Arc<Daemon>, db: &std::path::Path) {
    let d2 = d.clone();
    let jobs = d.index_jobs_active.clone();
    let path = db.to_path_buf();
    let outcome = tokio::task::spawn_blocking(move || {
        let before = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let mut chunks = 0u64;
        let mut stood_down = false;
        let ran = (|| {
            let mut left = d2.with_index(|ix| ix.freelist_pages().ok())?;
            while left > 0 {
                // Between chunks: nothing is running, so this
                // needs no interrupt and cannot be ignored.
                if jobs.load(Ordering::Acquire) > 0 {
                    stood_down = true;
                    break;
                }
                let now_left = d2.with_index(|ix| ix.compact_chunk(COMPACT_CHUNK_PAGES).ok())?;
                chunks += 1;
                // A chunk that reclaimed nothing means the freelist
                // is not shrinking - pages pinned by something we
                // cannot move. Without this the loop would spin on
                // them forever, holding the gate it is meant to
                // release.
                if now_left >= left {
                    break;
                }
                left = now_left;
            }
            Some(())
        })()
        .is_some();
        let after = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        (ran, stood_down, chunks, before.saturating_sub(after))
    })
    .await;
    let Ok((ran, stood_down, chunks, freed)) = outcome else {
        d.compact_pending.store(true, Ordering::Relaxed);
        return;
    };
    if !ran {
        // Re-raise the sticky flag or "will retry" is a lie: nothing
        // else raises it until some future eviction happens to, and an
        // index that stays under its cap never evicts again.
        d.compact_pending.store(true, Ordering::Relaxed);
        warn!(target: "index", "compact failed - will retry when idle");
        return;
    }
    let mb = freed as f64 / (1u64 << 20) as f64;
    // Both arms below reclaimed and COMMITTED `freed` bytes - standing
    // down is not "nothing happened" here (see the note in the message
    // itself), so both count as a compaction.
    d.note_compact(freed);
    if stood_down {
        // Unlike the VACUUM path, this is not "nothing happened": the
        // chunks that did run are committed and the file is already
        // shorter. Say so, or the next line the user reads implies the
        // work was wasted.
        d.compact_pending.store(true, Ordering::Relaxed);
        info!(
            target: "index",
            "compact stood down for a download after {chunks} chunks - {mb:.0} MB \
             reclaimed and kept, the rest at the next idle moment"
        );
    } else {
        info!(target: "index", "compacted at idle - {mb:.0} MB reclaimed");
    }
}

/// §74: install (or clear) the arrival watch on an index handle. Kept
/// beside `install_live_ingest_policy` and called from the same places
/// for the same reason: the shared handle is republished after every
/// full scan pass, so neither closure survives one.
///
/// `None` clears it, which is what an install with no watchlist - or the
/// setting switched off - must do, or a handle would keep journalling
/// hits nobody will ever drain.
#[cfg(feature = "indexer")]
pub(crate) fn install_instant_watch(
    ix: &mut nzbkit::index::Index,
    matcher: Option<crate::watchlist::InstantMatcher>,
) {
    ix.set_watch_names(
        matcher
            .map(|m| Box::new(move |name: &str| m.wants(name)) as Box<dyn Fn(&str) -> bool + Send>),
    );
}

/// §74: react to what the arrival watch caught in one batch.
///
/// Complete releases wake the watchlist pass immediately. Incomplete ones
/// are held for a short re-check instead: a post seen seconds after it
/// went up is usually still going up, and the watchlist only ever
/// considers complete releases. Nothing here decides anything about a
/// release - the pass does that, with the whole ladder - so the worst a
/// wrong call costs is a wasted look or a minute of latency.
#[cfg(feature = "indexer")]
pub(crate) fn instant_arrivals(
    d: &Arc<Daemon>,
    hits: Vec<nzbkit::index::WatchHit>,
    dropped: u32,
    now: i64,
) {
    let ready = instant_ready(d, hits, dropped, now);
    if !ready.is_empty() {
        let names = ready.join(", ");
        if d.instant_kick(&ready, now) {
            info!(target: "watch", "arrived: {names} - checking the watchlist now");
        }
    }
}

/// §74: the triage half of [`instant_arrivals`] - which of this batch's
/// hits are complete enough to be worth a look right now.
///
/// Split out for the scan leg, which cannot kick here: its arrivals have
/// to be staged under the same `index` mutex hold that republishes the
/// connection they live on, or a pass slipping between the two sees the
/// release without the hint (see `publish_index_with_arrivals`). Every
/// other caller drains hits from the ALREADY-shared handle, where there
/// is no republish to be atomic with, and uses `instant_arrivals`.
#[cfg(feature = "indexer")]
pub(crate) fn instant_ready(
    d: &Arc<Daemon>,
    hits: Vec<nzbkit::index::WatchHit>,
    dropped: u32,
    now: i64,
) -> Vec<String> {
    if dropped > 0 {
        // Said out loud rather than swallowed: this is the one place
        // instant coverage is knowingly given up, and it must not look
        // like "nothing arrived".
        info!(
            target: "watch",
            "{dropped} arrival(s) past the instant journal's cap - \
             they wait for the next regular check"
        );
    }
    if hits.is_empty() {
        return Vec::new();
    }
    let mut ready: Vec<String> = Vec::new();
    {
        let mut pending = d.instant_pending.lock_ok();
        for h in hits {
            if h.complete {
                pending.remove(&h.id);
                ready.push(h.name);
            } else {
                // First sighting wins: the clock this starts is what
                // expires the entry back to the periodic pass, and
                // re-stamping it on every batch of a large post would
                // keep it alive for as long as the post kept growing.
                pending.entry(h.id).or_insert(now);
            }
        }
    }
    ready
}

/// TODO 110: how long a background sampler stands down from a host
/// whose connect was refused because the account's slots are full.
///
/// The samplers redial on their own tick - the tip watcher's default is
/// 20 s - so without this a provider at its cap was asked again three
/// times a minute, all night. The slots in question clear on another
/// machine's schedule (a laptop shutting down, a seedbox finishing, a
/// multi-WAN route settling), never on the next tick. Fifteen minutes
/// matches the full scan interval, whose passes cover the same groups
/// the cooled-down watcher is skipping, so the cost is latency only.
#[cfg(feature = "indexer")]
const SAMPLER_CAP_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(900);

/// Should a background sampler stop redialling this server for a while
/// after this connect error, and if so for how long?
///
/// Two refusal shapes qualify:
///
/// * a Capacity-classified AUTHINFO refusal ("too many connections",
///   "max simultaneous IP addresses") on ANY server - the account is
///   fine, its slots are simply full, and a retry every tick is
///   exactly the hammering providers punish;
/// * a Permanent-classified refusal against a server whose source
///   addresses are declared (or known) tight - the shape where an
///   address cap answers with the same 502 wording as a bad password
///   (`max_source_ips` set low, or the [`caps_source_ips`] hostname
///   list). On a lax server that stays a credential error and keeps
///   the loud per-tick warn, because cooling it down would hide a
///   typo for fifteen minutes at a time.
///
/// Everything else (unreachable, TLS, timeout) keeps the existing
/// retry-next-tick behavior: those are what a flaky network produces,
/// and the next tick genuinely may succeed.
///
/// [`caps_source_ips`]: nzbkit::config::caps_source_ips
#[cfg(feature = "indexer")]
pub(crate) fn sampler_cap_cooldown(
    err: &nzbkit::nntp::NntpError,
    server: &nzbkit::config::ServerConfig,
) -> Option<std::time::Duration> {
    use nzbkit::nntp::{AuthRefusal, NntpError};
    match err {
        NntpError::AuthFailed {
            kind: AuthRefusal::Capacity,
            ..
        } => Some(SAMPLER_CAP_COOLDOWN),
        NntpError::AuthFailed {
            kind: AuthRefusal::Permanent,
            ..
        } if server.source_ips_are_tight() => Some(SAMPLER_CAP_COOLDOWN),
        _ => None,
    }
}

/// Tip watcher: the short loop that tracks only what is NEW at the
/// head of each group.
///
/// A full scan pass is two legs - the forward tip (~20k articles) and
/// a 200,000-article backward history deepen - and the interval
/// (default 900 s) does not start until BOTH have finished. So the
/// part that matters for "something just arrived" was riding on the
/// schedule of the part that does not: measured on the live daemon,
/// ~90% of every pass is backfill, and a new post waited up to a
/// quarter of an hour to become visible.
///
/// This loop does the forward leg alone, on its own short interval,
/// over ONE connection reused across ticks. That matters more than it
/// looks: a full pass builds and tears down a connection per worker
/// per group (~33 TLS handshakes at turbo fan-out), which is fine
/// every 15 minutes and ruinous every 20 seconds. When nothing has
/// arrived a whole tick costs one GROUP command per group.
///
/// It never competes with the full pass: a group the scan loop is
/// currently working is skipped, so only one of the two ever advances
/// a given group's high-water mark. Anything the watcher does not
/// reach (a group far behind, or a tick that runs out of budget) is
/// simply picked up by the next pass, exactly as before - the mark
/// only ever advances over a contiguous prefix, so falling behind
/// costs latency, never coverage.
#[cfg(feature = "indexer")]
pub fn spawn_tip_watcher(
    daemon: &Arc<Daemon>,
    config: &std::path::Path,
    index_pass_gate: &Arc<tokio::sync::Mutex<()>>,
) {
    let config = config.to_path_buf();
    let daemon2 = daemon.clone();
    let index_pass_gate = index_pass_gate.clone();
    tokio::spawn(async move {
        // A lone connection wants big OVER ranges - per-request
        // server latency, not bandwidth, is what costs (the full
        // scanner measures 82-95k hdr/s on 100k ranges against
        // 31-54k/s on 10k ones).
        const TIP_CHUNK: u64 = 20_000;
        // Further behind than this and catching up is the full
        // pass's job, not ours: it fans out over ~10 connections and
        // will cover the gap far faster than one connection can.
        const TIP_HANDOFF: u64 = 500_000;
        // A8: one connection per PRIMARY host - groups can have
        // different chosen primaries, and a mark is only valid
        // against the server whose numbering built it. With one
        // provider this degenerates to the single connection it
        // always was.
        let mut conns: std::collections::HashMap<String, nzbkit::nntp::Connection> =
            Default::default();
        // TODO 110: hosts cooling down after a slots-full refusal -
        // see `sampler_cap_cooldown`. Keyed like `conns`.
        let mut cooldown: std::collections::HashMap<String, Instant> = Default::default();
        let mut group_cursor = 0usize;
        loop {
            let every = daemon2.index_tip_secs.load(Ordering::Relaxed);
            let groups = daemon2.index_groups.lock_ok().clone();
            if every == 0 || groups.is_empty() {
                // Off, or nothing to watch - drop the connections
                // rather than hold them open for nothing.
                for (_, c) in conns.drain() {
                    c.quit().await;
                }
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                continue;
            }
            // Stand down entirely while a full pass is in flight.
            // Skipping just the group being scanned is not enough:
            // both write the same SQLite file, and a 200k-article
            // deepen leg plus this loop's ingest overran the 10 s
            // busy timeout and failed a whole group's scan with
            // "database is locked". The full pass is the faster
            // catch-up anyway, so there is nothing to add here while
            // it runs.
            if daemon2.indexing_pause_reason().is_some() {
                for (_, c) in conns.drain() {
                    c.quit().await;
                }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
            if daemon2.scan_active.load(Ordering::Relaxed) {
                tokio::time::sleep(std::time::Duration::from_secs(every.min(5))).await;
                continue;
            }
            let index_pass = index_pass_gate.lock().await;
            if daemon2.indexing_pause_reason().is_some() {
                drop(index_pass);
                for (_, c) in conns.drain() {
                    c.quit().await;
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
            let gates = daemon2.index_gates.lock_ok().1.clone();
            let cats = daemon2.custom_categories.read_ok().clone();
            // §74: the watchlist, compiled into the cheap name test the
            // ingest below runs over each arriving release. Rebuilt every
            // tick rather than cached behind a generation counter: it is
            // a handful of string normalisations against a list a person
            // typed, once per tick, and a stale matcher would silently
            // stop reacting to an item the user just added.
            let matcher = daemon2.instant_matcher();
            let mut fresh = 0u32;
            // Set when a group still had articles waiting as the
            // tick ended - see the nap below.
            let mut behind = false;
            // The tick bounds itself by TIME, not by an article
            // count. A fixed count cannot work: measured live,
            // alt.binaries.boneless alone posts ~900 articles/s, so
            // a 20k-per-tick cap pinned the watcher at 100% duty
            // cycle and permanently ~20k behind - it never caught
            // up, and had no headroom for a slow tick. A deadline
            // tracks whatever the group actually does and still
            // guarantees the loop keeps to its own interval.
            let deadline = Instant::now() + std::time::Duration::from_secs(every.min(30));
            // The walk below runs under the pass gate a starting
            // download rendezvouses on, and its NNTP awaits answer to
            // a REMOTE peer's clock: each connect/GROUP/OVER carries
            // its own wire bound, but a tick over many groups against
            // a mute provider stacks those bounds into minutes - all
            // of them spent holding the gate while a job the user just
            // added sits in Downloading doing nothing. So the walk
            // gets the same 100 ms preemption select as the scan and
            // spot legs: dropping the future cancels whatever await is
            // stuck, however wedged its peer is.
            let walk = async {
                for offset in 0..groups.len() {
                    let g = &groups[(group_cursor + offset) % groups.len()];
                    // A8: follow the group's chosen primary - the full
                    // pass persists its marks key. Absent = the group was
                    // never scanned; seeding needs the backfill count and
                    // max-age bisection only the full pass knows, so
                    // leave it alone.
                    let Some(pkey) =
                        daemon2.with_index(|ix| ix.kv_get(&format!("scan_primary:{g}")))
                    else {
                        continue;
                    };
                    let mark = daemon2
                        .with_index(|ix| Some(ix.high_water(g, &pkey)))
                        .unwrap_or(0);
                    if mark == 0 {
                        continue;
                    }
                    if !conns.contains_key(&pkey) {
                        // TODO 110: still cooling down from a slots-full
                        // refusal - skip quietly, the full pass covers it.
                        if cooldown.get(&pkey).is_some_and(|&t| Instant::now() < t) {
                            continue;
                        }
                        // The key names a server the config may have
                        // dropped since the pass; skip until the next
                        // pass re-chooses.
                        let Some(server) = crate::find_scan_server(&config, &pkey) else {
                            continue;
                        };
                        match nzbkit::nntp::Connection::connect(&server).await {
                            Ok((c, _)) => {
                                cooldown.remove(&pkey);
                                conns.insert(pkey.clone(), c);
                            }
                            Err(e) => match sampler_cap_cooldown(&e, &server) {
                                Some(cd) => {
                                    cooldown.insert(pkey.clone(), Instant::now() + cd);
                                    warn!(
                                        target: "tip",
                                        "{}: {e} - the account's slots are in use \
                                         elsewhere; tip watch resumes in {} min \
                                         (full scan passes still cover the group)",
                                        server.host,
                                        cd.as_secs() / 60
                                    );
                                    continue;
                                }
                                None => {
                                    warn!(target: "tip", "{}: connect: {e}", server.host);
                                    continue;
                                }
                            },
                        }
                    }
                    let c = conns.get_mut(&pkey).expect("connected above");
                    let high = match c.group(g).await {
                        Ok(info) => info.high,
                        // A dropped idle connection looks exactly like
                        // this; reconnect on the next tick.
                        Err(_) => {
                            conns.remove(&pkey);
                            continue;
                        }
                    };
                    if high <= mark || high - mark > TIP_HANDOFF {
                        continue;
                    }
                    let mut lo = mark.saturating_add(1);
                    // No inline pause check here: the preemption select
                    // wrapping this walk stands the whole tick down within
                    // 100 ms of any reason, mid-await included.
                    while lo <= high && Instant::now() < deadline {
                        let hi = lo.saturating_add(TIP_CHUNK - 1).min(high);
                        let Some(c) = conns.get_mut(&pkey) else { break };
                        let entries = match c.over(lo, hi).await {
                            Ok(es) => es,
                            Err(_) => {
                                conns.remove(&pkey);
                                break;
                            }
                        };
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(0);
                        let gates = gates.clone();
                        let cats = cats.clone();
                        let matcher = matcher.clone();
                        let done = daemon2.with_index_mut(|ix| {
                            // Gates are a live setting, so they are
                            // re-installed each time rather than once at
                            // startup. No gates configured = a closure
                            // that admits everything, which is what the
                            // absence of a gate means anyway.
                            install_live_ingest_policy(ix, gates, cats);
                            // §74: same re-install discipline for the
                            // arrival watch, and for the same reason - a
                            // scan pass can hand the shared handle over
                            // (and the hand-back clears the watch).
                            install_instant_watch(ix, matcher);
                            let n = ix.ingest(g, &entries, now).ok()?;
                            // The mark moves only with the rows: an
                            // ingest that failed must not claim the
                            // range.
                            ix.set_high_water(g, &pkey, hi).ok()?;
                            // Drained inside the same lock hold: these are
                            // this batch's arrivals, and leaving them for
                            // later would mix them with the next one's.
                            Some((n, ix.take_watch_hits()))
                        });
                        let Some((_, (hits, dropped))) = done else {
                            break;
                        };
                        instant_arrivals(&daemon2, hits, dropped, now);
                        fresh += (hi - lo + 1) as u32;
                        lo = hi.saturating_add(1);
                    }
                    if lo <= high {
                        behind = true;
                    }
                }
            };
            let pause = async {
                loop {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    if let Some(reason) = daemon2.indexing_pause_reason() {
                        break reason;
                    }
                }
            };
            let stood_down = tokio::select! {
                _ = walk => None,
                reason = pause => Some(reason),
            };
            // Every group leads one tick in turn. A sustained backlog
            // in groups[0] can consume the global deadline, but it can
            // no longer starve every quiet group behind it forever.
            group_cursor = (group_cursor + 1) % groups.len();
            if let Some(reason) = stood_down {
                // A cancelled OVER leaves unread bytes on the sockets,
                // so the sessions can be neither reused nor politely
                // QUIT - dropping them is the hang-up.
                conns.clear();
                drop(index_pass);
                info!(
                    target: "tip",
                    "tip watch stood down: {}",
                    Daemon::pause_phrase(reason)
                );
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
            if fresh > 0 && daemon2.index_maintenance_ok() {
                // Fresh posts need `titles` rows before the enricher
                // will look at them, and the wall sorts newest-first
                // - so this is what makes an arriving card get its
                // poster in seconds rather than at the next pass.
                let seeded = daemon2
                    .with_index(|ix| ix.seed_missing_titles(2, 200).ok())
                    .unwrap_or(0);
                info!(
                    target: "tip",
                    "{fresh} new headers{}",
                    if seeded > 0 {
                        format!(", {seeded} titles queued for artwork")
                    } else {
                        String::new()
                    }
                );
            }
            // The interval is how often to CHECK for arrivals, not
            // a throttle on ingesting them. Sleeping it out while a
            // group still had a backlog halved the loop's capacity -
            // measured against alt.binaries.boneless (~900
            // articles/s) that left it permanently ~47k articles
            // behind. Catching up gets a short nap instead, so busy
            // groups get continuous service and quiet ones stay
            // cheap.
            let nap = if behind { 1 } else { every };
            drop(index_pass);
            // Same stand-down as the oracle sampler: once the daemon
            // has been download-idle past the release timeout, hold
            // a session only for the pass that uses it. The steady
            // state here is one GROUP and one empty OVER per tick,
            // so the socket is idle for essentially the whole
            // interval while occupying an account slot - and against
            // a provider capping source IPs, the account.
            //
            // Skipped while `behind`, where the nap is 1 s and the
            // loop is genuinely working: reconnecting between
            // one-second catch-up passes would be churn, and a
            // backlog means the account is in use by this host
            // anyway.
            if !behind && !conns.is_empty() {
                // Config once, not once per held session: the map is
                // keyed by the index's server key, and resolving
                // each key through `find_scan_server` would re-read
                // the file every time.
                let cfg_now = nzbkit::config::Config::load(&config).ok();
                let release: Vec<String> = conns
                    .keys()
                    .filter(|k| {
                        cfg_now.as_ref().is_some_and(|c| {
                            c.servers
                                .iter()
                                .find(|s| nzbkit::index::Index::server_key(&s.host) == **k)
                                .is_some_and(|s| !daemon2.sampler_may_hold(s))
                        })
                    })
                    .cloned()
                    .collect();
                for k in release {
                    if let Some(c) = conns.remove(&k) {
                        c.quit().await;
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(nap)).await;
        }
    });
}

/// M29: idle STAT sampler - probes indexed releases' articles on one
/// spare connection per enabled server and feeds the availability
/// ledger, stalest-verdict release first. Throttled: `oracle_sample`
/// = STATs/hour/server (live setting, default 300; 0 disables). Sits
/// out whole ticks while a download is active so it never competes
/// for account connection slots.
#[cfg(feature = "indexer")]
pub fn spawn_oracle_sampler(daemon: &Arc<Daemon>, config: &std::path::Path) {
    let config = config.to_path_buf();
    let d = daemon.clone();
    tokio::spawn(async move {
        let mut conns: std::collections::HashMap<String, nzbkit::nntp::Connection> =
            Default::default();
        // TODO 110: same stand-down as the tip watcher's, same reason.
        let mut cooldown: std::collections::HashMap<String, Instant> = Default::default();
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            let rate = d.oracle_sample.load(Ordering::Relaxed);
            // The ledger it feeds is a table in the index database
            // and the releases it probes are indexed ones, so the
            // master switch takes this with it. Same `conns.clear()`
            // as the other stand-down arms: an idle session held
            // open against a provider is the account's slot, not
            // ours.
            if rate == 0
                || d.offline.load(Ordering::Relaxed)
                || d.indexer_off()
                || d.started_at.lock_ok().is_some()
            {
                // Offline joins the existing stand-down arms, which
                // already drop the map rather than hold sessions
                // open - dropping a Connection closes its socket, so
                // this is the hang-up, not just a bookkeeping reset.
                conns.clear();
                continue;
            }
            // Per-tick budget: ceil(rate/60) STATs per server - the
            // default 300/h probes 5 articles of one release a minute.
            let budget = (rate as usize).div_ceil(60);
            let servers: Vec<nzbkit::config::ServerConfig> =
                match nzbkit::config::Config::load(&config) {
                    Ok(c) => c.servers.into_iter().filter(|s| s.enabled).collect(),
                    Err(_) => continue,
                };
            if servers.is_empty() {
                continue;
            }
            conns.retain(|h, _| servers.iter().any(|s| &s.host == h));
            // On the READ pool, not the write handle. Both questions are
            // reads, and `with_index` would hold the index write mutex
            // for as long as they take - which is how a sampler tick
            // froze the whole daemon on 16 Aug (see `Index::oracle_pick`
            // for the statement and the damage). The pick is bounded
            // now, but the discipline is what keeps it harmless: a read
            // that turns expensive again costs this tick, never the
            // queue. The `oracle_mark` below is a keyed UPDATE and
            // stays on the write handle, because it has to.
            let picked = d.with_index_read(|ix| {
                let (id, grp, posted) = ix.oracle_pick(1).ok()?.into_iter().next()?;
                let ids = ix.oracle_msgids(id, budget).ok()?;
                Some((id, grp, posted, ids))
            });
            let Some((rid, grp, posted, ids)) = picked else {
                continue;
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|t| t.as_secs() as i64)
                .unwrap_or(0);
            // Stamp first: even a failed probe rotates the pick, so
            // one bad release can't pin the sampler forever.
            d.with_index(|ix| ix.oracle_mark(rid, now).ok());
            if ids.is_empty() {
                continue;
            }
            let family = nzbkit::oracle::group_family(&grp);
            let bucket = nzbkit::oracle::age_bucket(((now - posted).max(0) / 86_400) as u32);
            let mut samples: Vec<nzbkit::oracle::Sample> = Vec::new();
            for s in &servers {
                if !conns.contains_key(&s.host) {
                    if cooldown.get(&s.host).is_some_and(|&t| Instant::now() < t) {
                        continue;
                    }
                    match nzbkit::nntp::Connection::connect(s).await {
                        Ok((c, _)) => {
                            cooldown.remove(&s.host);
                            conns.insert(s.host.clone(), c);
                        }
                        Err(e) => {
                            match sampler_cap_cooldown(&e, s) {
                                Some(cd) => {
                                    cooldown.insert(s.host.clone(), Instant::now() + cd);
                                    warn!(
                                        target: "oracle",
                                        "{}: {e} - the account's slots are in \
                                         use elsewhere; sampling this server \
                                         resumes in {} min",
                                        s.host,
                                        cd.as_secs() / 60
                                    );
                                }
                                None => warn!(target: "oracle", "{}: connect: {e}", s.host),
                            }
                            continue;
                        }
                    }
                }
                let conn = conns.get_mut(&s.host).expect("just inserted");
                let probe = async {
                    for id in &ids {
                        conn.send_stat(id).await?;
                    }
                    conn.flush().await?;
                    let (mut hits, mut misses) = (0u64, 0u64);
                    // `read_stat_checked` and not the bare `read_stat`
                    // this used until 28 Aug 2026: every STAT went out
                    // before the first reply was read, so replies are
                    // attributed POSITIONALLY. One reply lost upstream
                    // and every later one is filed against the id behind
                    // it, which silently turns a hit into a miss in the
                    // availability sample this oracle is built from. A
                    // mismatch errors, and the arm below already drops
                    // the connection and reconnects next tick on any
                    // error, which is exactly the right answer for a
                    // desynced socket - the whole sample is discarded
                    // rather than banked half-shifted. A server that
                    // echoes no id at all still passes.
                    for id in &ids {
                        match conn.read_stat_checked(Some(id.as_str())).await? {
                            true => hits += 1,
                            false => misses += 1,
                        }
                    }
                    Ok::<(u64, u64), nzbkit::nntp::NntpError>((hits, misses))
                };
                match tokio::time::timeout(std::time::Duration::from_secs(20), probe).await {
                    Ok(Ok((hits, misses))) => samples.push(nzbkit::oracle::Sample {
                        host: s.host.clone(),
                        family: family.clone(),
                        bucket,
                        hits,
                        misses,
                    }),
                    other => {
                        if let Ok(Err(e)) = other {
                            warn!(target: "oracle", "{}: STAT: {e}", s.host);
                        }
                        // Desynced or mute - reconnect next tick.
                        conns.remove(&s.host);
                    }
                }
            }
            // One release, probed once per enabled server, is ONE
            // observation of that release - not one per server. Eweka,
            // UsenetServer and Newshosting are all Omicron, so without
            // this fold a single missing posting arrived as three
            // independent (0,5) samples that summed to (0,15), crossed
            // MIN_SAMPLES, and marked the whole backbone gone off one
            // posting. The fold also caps the per-tick budget at
            // JOB_SAMPLE_WEIGHT, which matters once oracle_sample is
            // raised above the 300/h default that made the two equal.
            let samples =
                nzbkit::oracle::fold_by_backbone(&samples, nzbkit::oracle::JOB_SAMPLE_WEIGHT);
            if !samples.is_empty() {
                d.with_index(|ix| ix.oracle_ingest(&samples, now).ok());
            }
            // Give the slots back between ticks, per server, once
            // the daemon has been download-idle past that server's
            // release timeout. This sampler probes ~5 articles a
            // minute: holding the socket for the other 59-odd
            // seconds occupies one of the account's connections -
            // and on a provider limiting source addresses, one of
            // its one or two address slots - permanently, for a few
            // hundred milliseconds of work. Reconnecting costs five
            // round-trips a minute, which is nothing against a
            // sampler already throttled to 300 STATs an hour.
            //
            // Per server so a strict provider cannot make this churn
            // reconnects against a lax one sharing nothing with it.
            for s in &servers {
                if !d.sampler_may_hold(s)
                    && let Some(c) = conns.remove(&s.host)
                {
                    c.quit().await;
                }
            }
        }
    });
}

// ---- TODO 131 B3: the byte-probe naming lane -------------------------
//
// The whole lane lives in indexer/probe7z.rs now (TODO 106): 582 lines
// of one subject, and this file had crossed the size-gate ceiling.
#[cfg(feature = "indexer")]
mod probe7z;
#[cfg(feature = "indexer")]
use crate::rarprobe::probe_fetch;
#[cfg(feature = "indexer")]
pub use probe7z::spawn_probe7z;

// ---- TODO 198 tail: measured planner statistics ----------------------
//
// Its own file for probe7z's reason - this one is near the ceiling -
// and because the leg is one subject with a long why. See
// indexer/deep_stats.rs.
#[cfg(feature = "indexer")]
mod deep_stats;
#[cfg(feature = "indexer")]
pub(crate) use deep_stats::deep_stats_pass;

// ---- TODO 26c A5: the compact segment storage rebuild ---------------
//
// Its own file for the same reason as deep_stats: this one is at the
// ceiling, and the leg is one subject with a long why. See
// indexer/segmig.rs.
#[cfg(feature = "indexer")]
mod segmig;
#[cfg(feature = "indexer")]
pub(crate) use segmig::segments_rebuild_pass;

// ---- TODO 131 #6: the posted-NZB ingestion rung ----------------------

/// Objects walked per tick. The measured census (research
/// NZB-IMPORT-RUNG-2026-08-10) found today's candidate population
/// mostly corroborative - uploaders posting the .nzb beside
/// identically-named content - so the rung's standing value is covering
/// every FUTURE posted .nzb, not bulk naming. A few objects a minute
/// keeps pace with arrivals indefinitely (the live index accrued ~300
/// candidates in ten days) and clears a fresh install's backlog in
/// hours, without ever costing enough wire to notice.
#[cfg(feature = "indexer")]
const NZBIMPORT_PER_TICK: usize = 3;

/// Ceiling on one posted object's fetch against one server. Most
/// candidates are a single article; the cap (32 MiB) bounds the rest.
#[cfg(feature = "indexer")]
const NZBIMPORT_FETCH_SECS: u64 = 60;

/// Ceiling on what one candidate charges the token bucket, and the
/// floor of the bucket's cap: the 32 MiB decode cap works out to ~48
/// full-size articles, so a bucket that can hold 48 tokens can always
/// eventually afford the largest candidate - a bucket capped below the
/// dearest object would pin the cursor on it forever.
#[cfg(feature = "indexer")]
const NZBIMPORT_ARTICLES_MAX: usize = 48;

/// Ticks a candidate may answer all-servers-Transient before the walk
/// gives it up as Gone (see the Transient arm in the tick loop).
#[cfg(feature = "indexer")]
const NZBIMPORT_TRANSIENT_TRIES: u32 = 5;

/// What one candidate's fleet fetch concluded.
#[cfg(feature = "indexer")]
enum ImportFetch {
    Ok(Vec<u8>),
    /// Every server we could reach says gone or damaged - and we
    /// reached at least one. Retrying cannot change the bytes
    /// (propagation gap or takedown), so the cursor walks on for good:
    /// give-up, not chase.
    Gone,
    /// Connection-level trouble only - no server actually answered for
    /// the object. The next tick may do better, so the cursor must NOT
    /// move past it.
    Transient,
}

enum ImportDecision {
    Store(Vec<u8>),
    Terminal { unreachable_ticks: Option<u32> },
    Retry,
}

fn classify_import_fetch(
    fetched: ImportFetch,
    selection_era: u64,
    arrival_seq: i64,
    transient: &mut (u64, i64, u32),
) -> ImportDecision {
    match fetched {
        ImportFetch::Ok(bytes) => {
            *transient = (0, 0, 0);
            ImportDecision::Store(bytes)
        }
        ImportFetch::Gone => {
            *transient = (0, 0, 0);
            ImportDecision::Terminal {
                unreachable_ticks: None,
            }
        }
        ImportFetch::Transient => {
            if transient.0 == selection_era && transient.1 == arrival_seq {
                transient.2 += 1;
            } else {
                *transient = (selection_era, arrival_seq, 1);
            }
            if transient.2 < NZBIMPORT_TRANSIENT_TRIES {
                ImportDecision::Retry
            } else {
                ImportDecision::Terminal {
                    unreachable_ticks: Some(transient.2),
                }
            }
        }
    }
}

/// Fetch one posted `.nzb` object over the scan fleet, per-server
/// fallback in fleet order (retention and propagation differ per
/// backbone - the CLI census measured misses recovered by the second
/// server). Mutates the shared connection map exactly like the tip
/// watcher: a dead session is dropped and remade on a later attempt.
#[cfg(feature = "indexer")]
async fn fetch_import_candidate(
    servers: &[nzbkit::config::ServerConfig],
    conns: &mut std::collections::HashMap<String, nzbkit::nntp::Connection>,
    cooldown: &mut std::collections::HashMap<String, Instant>,
    segs: &[(u32, String)],
) -> ImportFetch {
    let mut reached = 0u32;
    for s in servers {
        if !conns.contains_key(&s.host) {
            if cooldown.get(&s.host).is_some_and(|&t| Instant::now() < t) {
                continue;
            }
            match nzbkit::nntp::Connection::connect(s).await {
                Ok((c, _)) => {
                    cooldown.remove(&s.host);
                    conns.insert(s.host.clone(), c);
                }
                Err(e) => {
                    let cd =
                        sampler_cap_cooldown(&e, s).unwrap_or(std::time::Duration::from_secs(600));
                    cooldown.insert(s.host.clone(), Instant::now() + cd);
                    warn!(target: "nzbimport", "{}: connect: {e}", s.host);
                    continue;
                }
            }
        }
        let conn = conns.get_mut(&s.host).expect("connected above");
        let attempt = tokio::time::timeout(
            std::time::Duration::from_secs(NZBIMPORT_FETCH_SECS),
            nzbkit::nzbimport::fetch_posted_nzb(conn, segs),
        )
        .await;
        match attempt {
            Ok(Ok(bytes)) => return ImportFetch::Ok(bytes),
            Ok(Err(nzbkit::nzbimport::NzbImportError::Missing(_))) => {
                // This server answered and does not hold it - the next
                // backbone may.
                reached += 1;
            }
            Ok(Err(nzbkit::nzbimport::NzbImportError::Nntp(e))) => {
                // Connection-level: drop the session, try the next
                // server (this one reconnects on a later attempt).
                warn!(target: "nzbimport", "{}: {e}", s.host);
                conns.remove(&s.host);
            }
            Ok(Err(_)) => {
                // A content property (yEnc damage, the size cap,
                // holes): the bytes are identical on every server, so
                // trying another cannot help.
                return ImportFetch::Gone;
            }
            Err(_) => {
                // Timed out mid-object: the session's state is
                // unknown, so it cannot be reused.
                warn!(target: "nzbimport", "{}: posted-NZB fetch timeout", s.host);
                conns.remove(&s.host);
            }
        }
    }
    if reached > 0 {
        ImportFetch::Gone
    } else {
        ImportFetch::Transient
    }
}

/// The posted-NZB ingestion rung (§131 build-order #6), run
/// continuously: walk NEW one-file `*.nzb` index rows behind a
/// persisted cursor, fetch each posted object over the scan fleet,
/// parse it, and durably store its complete file-aware membership before
/// advancing the cursor. Public filenames remain shadow membership evidence;
/// only an independent trusted assertion can supply a title. Exact seed replay
/// then applies that title only after every local data file and every required
/// external file passes its coverage gate. A split pack therefore stays
/// evidence, never several misnamed rows.
///
/// Modelled on the oracle sampler: 60 s tick, stand-down arms (the
/// index_nzbimport kill switch, a zero index_nzbimport_budget, offline,
/// indexer off, anything downloading), connect cooldowns, slots handed
/// back between ticks, and a token bucket over fetched articles so a
/// group flooded with large .nzb-named posts cannot hold the walk at
/// its 3-objects-a-minute ceiling indefinitely. Provenance is fixed to
/// `posted-nzb` plus a SHA-256 digest of the fetched XML. It never stores
/// the source group, outer Message-ID, provider, URL, or credentials.
#[cfg(feature = "indexer")]
pub fn spawn_nzb_import(daemon: &Arc<Daemon>, config: &std::path::Path) {
    let config = config.to_path_buf();
    let d = daemon.clone();
    tokio::spawn(async move {
        let mut conns: std::collections::HashMap<String, nzbkit::nntp::Connection> =
            Default::default();
        let mut cooldown: std::collections::HashMap<String, Instant> = Default::default();
        // Token bucket over fetched articles, the probe7z lane's shape:
        // refills at the hourly budget, caps at ten minutes' worth (but
        // never below one full-size candidate's cost) so an idle
        // stretch cannot bank an afternoon of burst.
        let mut tokens: f64 = 0.0;
        // The candidate the cursor is currently parked on (by arrival
        // ordinal, the one identity a deleted row cannot hand to its
        // successor) and how many ticks it has answered Transient - the
        // walk-on exit for an object that can never finish inside the
        // fetch window (see the Transient arm below).
        let mut transient: (u64, i64, u32) = (0, 0, 0);
        // One replay per daemon start, before the first tick: claims
        // recorded but never applied (a gate bug since fixed, a writer
        // that died mid-decision) have no other re-fire - the byte
        // prober's first seven production names sat stranded in the
        // ledger exactly this way. Offline, bounded, idempotent.
        if let Some(n) = d.with_index_mut(|ix| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|t| t.as_secs() as i64)
                .unwrap_or(0);
            ix.claims_replay(now, 2000).ok()
        }) && n > 0
        {
            info!(target: "claims", "replay: {n} stranded ledger name(s) applied");
        }
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            let rate = d.index_nzbimport_budget.load(Ordering::Relaxed);
            if !d.index_nzbimport.load(Ordering::Relaxed)
                || rate == 0
                || d.offline.load(Ordering::Relaxed)
                || d.indexer_off()
                || d.started_at.lock_ok().is_some()
            {
                // Same stand-down shape as the sampler: dropping a
                // connection is the hang-up, and an idle session held
                // against a provider is the account's slot, not ours.
                for (_, c) in conns.drain() {
                    c.quit().await;
                }
                tokens = 0.0;
                continue;
            }
            tokens = (tokens + rate as f64 / 60.0)
                .min((rate as f64 / 6.0).max(NZBIMPORT_ARTICLES_MAX as f64));
            // An arrival_seq, not a release id - ids are recycled after
            // a delete and a posted NZB landing on one below the cursor
            // was skipped forever (see `posted_nzb_candidates`).
            let Some((selection_era, cands)) = d.with_index(|ix| {
                let selection_era = d.index_era();
                let cursor = ix.nzbimport_cursor();
                ix.posted_nzb_candidates(cursor, NZBIMPORT_PER_TICK)
                    .ok()
                    .map(|cands| (selection_era, cands))
            }) else {
                continue;
            };
            if cands.is_empty() {
                // Caught up - the steady state. The connections (if
                // any) are released below on the sampler's terms.
                for (_, c) in conns.drain() {
                    c.quit().await;
                }
                continue;
            }
            let servers = match nzbkit::config::Config::load(&config) {
                Ok(c) => crate::servers::scan_servers(&c),
                Err(_) => continue,
            };
            if servers.is_empty() {
                continue;
            }
            for cand in cands {
                // A download that started mid-tick takes the wire; the
                // unwalked remainder waits for the next tick.
                if d.started_at.lock_ok().is_some() {
                    break;
                }
                // The bucket must cover this candidate's worst case
                // BEFORE the fetch - candidates are cursor-ordered, so
                // an unaffordable one ends the tick rather than being
                // skipped past (the cursor may only advance through a
                // settled object).
                let Some(cost) = posted_candidate_cost(cand.segs.len()) else {
                    warn!(
                        target: "nzbimport",
                        "posted NZB #{} has {} article(s), outside the 1..={} admission cap - walking on",
                        cand.release_id,
                        cand.segs.len(),
                        NZBIMPORT_ARTICLES_MAX
                    );
                    if !settle_posted_candidate(
                        &d,
                        selection_era,
                        cand.arrival_seq,
                        cand.stem,
                        None,
                    )
                    .await
                    {
                        break;
                    }
                    continue;
                };
                if tokens < cost {
                    break;
                }
                // Charge the attempted BODY budget before touching the
                // network. Connection failures otherwise make repeated
                // transient attempts free and let a bad candidate exceed the
                // configured hourly request ceiling.
                tokens -= cost;
                // The cursor must not move past an object nobody answered
                // for, but retry-next-tick needs an exit. A few consecutive
                // transients are tolerated, then the item is settled as
                // terminal. Any actual answer resets that history even when
                // the later local store has to retry.
                let bytes = match classify_import_fetch(
                    fetch_import_candidate(&servers, &mut conns, &mut cooldown, &cand.segs).await,
                    selection_era,
                    cand.arrival_seq,
                    &mut transient,
                ) {
                    ImportDecision::Store(bytes) => Some(bytes),
                    ImportDecision::Terminal { unreachable_ticks } => {
                        if let Some(ticks) = unreachable_ticks {
                            warn!(
                                target: "nzbimport",
                                "posted NZB #{} unreachable {ticks} ticks running - walking on",
                                cand.release_id
                            );
                        }
                        None
                    }
                    ImportDecision::Retry => break,
                };
                // The settle helper owns the store-before-cursor ordering.
                // It carries only the small stem onto the blocking worker,
                // never this candidate's potentially large segment vector.
                if !settle_posted_candidate(&d, selection_era, cand.arrival_seq, cand.stem, bytes)
                    .await
                {
                    break;
                }
            }
            // Give the slots back between ticks, per server, once the
            // daemon has been download-idle past that server's release
            // timeout - the sampler's rule, for the sampler's reasons.
            for s in &servers {
                if !d.sampler_may_hold(s)
                    && let Some(c) = conns.remove(&s.host)
                {
                    c.quit().await;
                }
            }
        }
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PostedSeedDisposition {
    Durable,
    Terminal,
    Retry,
}

fn posted_candidate_cost(segment_count: usize) -> Option<f64> {
    (1..=NZBIMPORT_ARTICLES_MAX)
        .contains(&segment_count)
        .then_some(segment_count as f64)
}

fn advance_posted_cursor(d: &Arc<Daemon>, selection_era: u64, arrival_seq: i64) -> bool {
    d.with_index(|index| {
        (d.index_era() == selection_era && d.index_db_wanted())
            .then(|| index.nzbimport_cursor_set(arrival_seq).ok())
            .flatten()
    })
    .is_some()
}

/// Settle exactly one cursor item. Durable evidence is committed before the
/// cursor advances; terminal content advances without a store; retryable
/// failures leave the cursor parked. Keeping those three transitions here
/// makes their crash ordering testable and prevents a later loop refactor from
/// accidentally publishing the cursor first.
async fn settle_posted_candidate(
    d: &Arc<Daemon>,
    selection_era: u64,
    arrival_seq: i64,
    posted_stem: String,
    xml: Option<Vec<u8>>,
) -> bool {
    let disposition = match xml {
        None => PostedSeedDisposition::Terminal,
        Some(xml) => {
            let d2 = d.clone();
            match tokio::task::spawn_blocking(move || {
                persist_posted_seed(&d2, selection_era, &posted_stem, xml)
            })
            .await
            {
                Ok(disposition) => disposition,
                Err(_) => PostedSeedDisposition::Retry,
            }
        }
    };
    if disposition == PostedSeedDisposition::Retry {
        return false;
    }
    if disposition == PostedSeedDisposition::Durable {
        d.seed_harvest_wake.notify_one();
    }
    // If this write fails after a durable store, the next tick refetches and
    // idempotently finds the same assertion. That is the intended at-least-once
    // side of the ordering.
    advance_posted_cursor(d, selection_era, arrival_seq)
}

fn posted_seed_name(posted_stem: &str, nzb: &nzbkit::nzb::Nzb) -> Option<String> {
    let posted = nzbkit::nzbimport::strip_nzb_suffix(posted_stem);
    if nzbkit::release::stem_is_a_name(posted) {
        // Return the raw stem. The seed store owns canonical normalization
        // and strips exactly one suffix. Returning `posted` here would strip
        // twice for a legitimate `Show.nzb.nzb` filename.
        return Some(posted_stem.to_string());
    }
    if let Some(title) = nzb
        .meta
        .iter()
        .find(|(kind, value)| {
            (kind == "title" || kind == "name") && nzbkit::release::stem_is_a_name(value)
        })
        .map(|(_, value)| value.clone())
    {
        return Some(title);
    }
    let mut stems: std::collections::BTreeMap<String, usize> = Default::default();
    for file in &nzb.files {
        if let Some(filename) = file.filename_hint() {
            let stem = nzbkit::extract::release_stem(filename);
            if !stem.is_empty() {
                *stems.entry(stem).or_default() += 1;
            }
        }
    }
    stems
        .into_iter()
        .filter(|(stem, _)| nzbkit::release::stem_is_a_name(stem))
        .max_by(|left, right| left.1.cmp(&right.1).then_with(|| right.0.cmp(&left.0)))
        .map(|(stem, _)| stem)
}

/// Settle a fetched posted NZB into the same exact, file-aware evidence store
/// as accepted user NZBs. No group, outer Message-ID, URL, or account detail
/// enters provenance. The old three-ID direct join was removed because one
/// pack title could otherwise be stamped onto several dark per-file rows.
fn persist_posted_seed(
    d: &Arc<Daemon>,
    selection_era: u64,
    posted_stem: &str,
    xml: Vec<u8>,
) -> PostedSeedDisposition {
    if d.offline.load(Ordering::Relaxed)
        || d.indexer_off()
        || d.index_jobs_active.load(Ordering::Acquire) > 0
        || d.started_at.lock_ok().is_some()
    {
        return PostedSeedDisposition::Retry;
    }
    let guid = nzb_sha(&xml);
    let nzb = match nzbkit::nzb::Nzb::parse(&xml) {
        Ok(nzb) => nzb,
        Err(_) => return PostedSeedDisposition::Terminal,
    };
    drop(xml);
    let posted = nzb
        .files
        .iter()
        .map(|file| file.date)
        .filter(|date| *date > 0)
        .min()
        .unwrap_or(0);
    let bytes = nzb.total_bytes();
    let prepared = match nzbkit::index::NzbSeedPrepared::from_nzb(&nzb) {
        Ok(prepared) => prepared,
        Err(
            nzbkit::index::NzbSeedError::Invalid(_)
            | nzbkit::index::NzbSeedError::Nzb(_)
            | nzbkit::index::NzbSeedError::Corrupt(_),
        ) => {
            return PostedSeedDisposition::Terminal;
        }
        Err(nzbkit::index::NzbSeedError::Capacity(_)) => {
            return PostedSeedDisposition::Terminal;
        }
        Err(nzbkit::index::NzbSeedError::Sqlite(_)) => return PostedSeedDisposition::Retry,
    };
    let Some(name) = posted_seed_name(posted_stem, &nzb) else {
        return PostedSeedDisposition::Terminal;
    };
    if d.offline.load(Ordering::Relaxed)
        || d.indexer_off()
        || d.index_jobs_active.load(Ordering::Acquire) > 0
        || d.started_at.lock_ok().is_some()
    {
        return PostedSeedDisposition::Retry;
    }
    let now = epoch_secs() as i64;
    match d.try_with_index_mut_retiring_ddl(|index| {
        if d.index_era() != selection_era || !d.index_db_wanted() {
            return None;
        }
        Some(index.nzb_seed_store_prepared(
            nzbkit::index::NzbSeedSpec {
                source: nzbkit::index::NZB_SEED_POSTED_SOURCE,
                source_guid: &guid,
                name: &name,
                category: "",
                posted,
                bytes,
            },
            &prepared,
            now,
        ))
    }) {
        Some(Ok(_)) => PostedSeedDisposition::Durable,
        Some(Err(
            nzbkit::index::NzbSeedError::Invalid(_)
            | nzbkit::index::NzbSeedError::Nzb(_)
            | nzbkit::index::NzbSeedError::Capacity(_),
        )) => PostedSeedDisposition::Terminal,
        Some(Err(
            nzbkit::index::NzbSeedError::Corrupt(_) | nzbkit::index::NzbSeedError::Sqlite(_),
        ))
        | None => PostedSeedDisposition::Retry,
    }
}

#[cfg(test)]
#[path = "indexer/posted_seed_tests.rs"]
mod posted_seed_tests;

// ---- Indexer-confirm lane: correlation suggestions -> proven names ----

// ---- the seed pick: sampling the reference indexer directly ---------
//
// research/SEEDJOIN-PROBE-2026-09-01.md's build item 1. The confirm
// lane's grab-and-join tail is proof-grade (a message-id match IS the
// post), but its pick source was correlation suggestions, which
// research/NAMECORR-PRECISION-2026-09-01.md measured at 0% precision -
// a proven pipeline fed by a refuted one. The seed pick samples the
// reference indexer's own newest listings instead: every listed title
// is a NAME the indexer was handed with an uploaded NZB, and grabbing
// that NZB joins those names onto the wire posts we already hold. Same
// dial, same daily budget, same quota discipline as the corr picks it
// stands in for when none exist.

/// Titles harvested from the reference's newest listings, waiting for
/// a grab attempt (index kv, JSON array).
#[cfg(feature = "indexer")]
const SEED_QUEUE_KEY: &str = "seed_queue_v1";
/// match_keys this lane already attempted, ring-capped - a listing
/// whose NZB joined nothing must not be re-grabbed every sweep.
#[cfg(feature = "indexer")]
const SEED_RECENT_KEY: &str = "seed_recent_v1";
/// When the last listing sweep ran (index kv, unix seconds).
#[cfg(feature = "indexer")]
const SEED_LISTING_AT_KEY: &str = "seed_listing_at";

/// One newest-listing sweep per hour at most: a sweep is one API hit
/// buying up to [`SEED_QUEUE_CAP`] candidates, and the queue drains at
/// the confirm lane's own budgeted pace anyway.
#[cfg(feature = "indexer")]
const SEED_LISTING_EVERY: i64 = 3_600;
#[cfg(feature = "indexer")]
const SEED_QUEUE_CAP: usize = 40;
#[cfg(feature = "indexer")]
const SEED_RECENT_CAP: usize = 500;

/// Ring of titles the confirm lane settled recently, whatever the
/// pick source (index kv, JSON array of match_keys). The corr stamp
/// already makes each suggestion once-ever, but SEVERAL rows can
/// suggest one title, and each would buy the identical search and the
/// identical NZB minutes apart - measured live on beta 4's first hour:
/// one title, three grabs, three minutes. A ring hit is stamped
/// without a lookup, because the exact lookup just ran.
const CONFIRM_RECENT_KEY: &str = "confirm_recent_v1";
const CONFIRM_RECENT_CAP: usize = 200;

/// Pop the next queued seed title, recording it in the attempted ring
/// so a joinless grab is never repeated.
#[cfg(feature = "indexer")]
#[cfg(test)]
fn seed_pop(d: &Arc<Daemon>) -> Option<String> {
    seed_pop_at(d, d.index_era())
}

#[cfg(feature = "indexer")]
fn seed_pop_at(d: &Arc<Daemon>, selection_era: u64) -> Option<String> {
    d.with_index(|ix| {
        if d.index_era() != selection_era {
            return None;
        }
        seed_pop_from_index(ix)
    })
}

#[cfg(feature = "indexer")]
fn seed_pop_from_index(ix: &nzbkit::index::Index) -> Option<String> {
    let mut queue: Vec<String> = ix
        .kv_get(SEED_QUEUE_KEY)
        .and_then(|v| serde_json::from_str(&v).ok())
        .unwrap_or_default();
    if queue.is_empty() {
        return None;
    }
    let title = queue.remove(0);
    let mut recent: Vec<String> = ix
        .kv_get(SEED_RECENT_KEY)
        .and_then(|v| serde_json::from_str(&v).ok())
        .unwrap_or_default();
    recent.push(nzbkit::predb::match_key(&title));
    if recent.len() > SEED_RECENT_CAP {
        let cut = recent.len() - SEED_RECENT_CAP;
        recent.drain(..cut);
    }
    // Record suppression before removing the queue entry. A crash between
    // these autocommit writes can repeat one pick, but cannot lose it.
    if ix
        .kv_set(
            SEED_RECENT_KEY,
            &serde_json::to_string(&recent).unwrap_or_default(),
        )
        .is_err()
    {
        return None;
    }
    let _ = ix.kv_set(
        SEED_QUEUE_KEY,
        &serde_json::to_string(&queue).unwrap_or_default(),
    );
    Some(title)
}

#[cfg(feature = "indexer")]
fn seed_retry_at(d: &Arc<Daemon>, selection_era: u64, title: &str) -> Option<bool> {
    d.with_index(|ix| {
        if d.index_era() != selection_era {
            return Some(false);
        }
        seed_retry_on_index(ix, title, false)
    })
}

#[cfg(feature = "indexer")]
fn seed_retry_legacy(d: &Arc<Daemon>, title: &str) -> Option<bool> {
    d.with_index(|ix| seed_retry_on_index(ix, title, true))
}

#[cfg(feature = "indexer")]
fn seed_retry_on_index(
    ix: &nzbkit::index::Index,
    title: &str,
    require_witness: bool,
) -> Option<bool> {
    let key = nzbkit::predb::match_key(title);
    let mut queue: Vec<String> = ix
        .kv_get(SEED_QUEUE_KEY)
        .and_then(|value| serde_json::from_str(&value).ok())
        .unwrap_or_default();
    let mut recent: Vec<String> = ix
        .kv_get(SEED_RECENT_KEY)
        .and_then(|value| serde_json::from_str(&value).ok())
        .unwrap_or_default();
    let queued = queue
        .iter()
        .any(|candidate| nzbkit::predb::match_key(candidate) == key);
    if require_witness && !queued && !recent.iter().any(|old| old == &key) {
        return Some(false);
    }
    if !queued {
        queue.insert(0, title.to_string());
    }
    recent.retain(|old| old != &key);
    let queue = serde_json::to_string(&queue).ok()?;
    let recent = serde_json::to_string(&recent).ok()?;
    ix.retry_kv_set_durable(&[
        (SEED_QUEUE_KEY, queue.as_str()),
        (SEED_RECENT_KEY, recent.as_str()),
    ])
    .ok()?;
    Some(true)
}

#[cfg(feature = "indexer")]
const CONFIRM_RETRY_FILE: &str = "confirm-retry-v1.json";
#[cfg(feature = "indexer")]
const CONFIRM_RETRY_CATALOG_KEY: &str = "confirm_retry_catalog_v1";

#[cfg(feature = "indexer")]
#[derive(serde::Serialize, serde::Deserialize)]
enum ConfirmRetry {
    Expected {
        catalog_id: String,
        pick: super::expected::ExpectedPick,
    },
    Seed {
        catalog_id: String,
        title: String,
    },
}

#[cfg(feature = "indexer")]
#[derive(serde::Deserialize)]
enum LegacyConfirmRetry {
    Expected {
        era: u64,
        pick: super::expected::ExpectedPick,
    },
    Seed {
        era: u64,
        title: String,
    },
}

#[cfg(feature = "indexer")]
#[derive(serde::Deserialize)]
#[serde(untagged)]
enum ConfirmRetryRecord {
    Current(ConfirmRetry),
    Legacy(LegacyConfirmRetry),
}

#[cfg(feature = "indexer")]
impl LegacyConfirmRetry {
    fn era(&self) -> u64 {
        match self {
            Self::Expected { era, .. } | Self::Seed { era, .. } => *era,
        }
    }
}

#[cfg(feature = "indexer")]
impl ConfirmRetry {
    fn catalog_id(&self) -> &str {
        match self {
            Self::Expected { catalog_id, .. } | Self::Seed { catalog_id, .. } => catalog_id,
        }
    }
}

#[cfg(feature = "indexer")]
fn confirm_catalog_fence(d: &Arc<Daemon>) -> Option<(u64, String)> {
    let era = d.index_era();
    d.with_index(|index| {
        if d.index_era() != era {
            return None;
        }
        let catalog_id = match index.kv_get(CONFIRM_RETRY_CATALOG_KEY) {
            Some(value)
                if value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) =>
            {
                value
            }
            _ => {
                let mut random = [0u8; 32];
                getrandom::fill(&mut random).ok()?;
                let value = hex::encode(random);
                index
                    .retry_kv_set_durable(&[(CONFIRM_RETRY_CATALOG_KEY, value.as_str())])
                    .ok()?;
                value
            }
        };
        Some((era, catalog_id))
    })
}

#[cfg(feature = "indexer")]
fn confirm_retry_path(d: &Daemon) -> PathBuf {
    d.spool.join(CONFIRM_RETRY_FILE)
}

#[cfg(feature = "indexer")]
fn clear_confirm_retry(d: &Daemon) -> std::io::Result<()> {
    let path = confirm_retry_path(d);
    match std::fs::remove_file(&path) {
        Ok(()) => crate::smart::sync_dir(&d.spool),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(feature = "indexer")]
fn save_confirm_retry(d: &Daemon, retry: &ConfirmRetry) -> std::io::Result<()> {
    let encoded = serde_json::to_vec(retry)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    if encoded.len() > 64 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "confirm retry record exceeds 64 KiB",
        ));
    }
    crate::persist::write_atomic(&confirm_retry_path(d), &encoded)?;
    crate::smart::sync_dir(&d.spool)
}

#[cfg(feature = "indexer")]
fn flush_confirm_retry(d: &Arc<Daemon>) -> bool {
    let path = confirm_retry_path(d);
    let encoded = match std::fs::read(&path) {
        Ok(encoded) if encoded.len() <= 64 * 1024 => encoded,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return true,
        Ok(_) | Err(_) => {
            let hold = path.with_extension("hold");
            let _ = std::fs::rename(&path, &hold);
            let _ = crate::smart::sync_dir(&d.spool);
            warn!(target: "confirm", "quarantined unreadable confirm retry record");
            return true;
        }
    };
    let retry: ConfirmRetryRecord = match serde_json::from_slice(&encoded) {
        Ok(retry) => retry,
        Err(_) => {
            let hold = path.with_extension("hold");
            let _ = std::fs::rename(&path, &hold);
            let _ = crate::smart::sync_dir(&d.spool);
            warn!(target: "confirm", "quarantined invalid confirm retry record");
            return true;
        }
    };
    let ConfirmRetryRecord::Current(retry) = retry else {
        let ConfirmRetryRecord::Legacy(retry) = retry else {
            unreachable!();
        };
        let legacy_era = retry.era();
        let restored = match &retry {
            LegacyConfirmRetry::Expected { pick, .. } => {
                super::expected::expected_retry_legacy(d, pick)
            }
            LegacyConfirmRetry::Seed { title, .. } => seed_retry_legacy(d, title),
        };
        return match restored {
            Some(true) => clear_confirm_retry(d).is_ok(),
            Some(false) => {
                warn!(
                    target: "confirm",
                    "retired legacy confirm retry from era {legacy_era}: catalogue ownership witness is absent"
                );
                clear_confirm_retry(d).is_ok()
            }
            None => false,
        };
    };
    // `index_era` fences one open connection and changes on both a harmless
    // source-off close and a destructive wipe. The durable catalog identity
    // survives the former and changes with a recreated database, preserving
    // the one-shot retry without injecting old work after a wipe.
    for _ in 0..2 {
        let Some((era, catalog_id)) = confirm_catalog_fence(d) else {
            return false;
        };
        if catalog_id != retry.catalog_id() {
            return clear_confirm_retry(d).is_ok();
        }
        let restored = match &retry {
            ConfirmRetry::Expected { pick, .. } => super::expected::expected_retry_at(d, era, pick),
            ConfirmRetry::Seed { title, .. } => seed_retry_at(d, era, title),
        };
        match restored {
            Some(true) => return clear_confirm_retry(d).is_ok(),
            Some(false) => continue,
            None => return false,
        }
    }
    false
}

#[cfg(feature = "indexer")]
fn retry_confirm_pick(
    d: &Arc<Daemon>,
    selection_era: u64,
    catalog_id: &str,
    seeded: bool,
    expected: Option<&super::expected::ExpectedPick>,
    title: &str,
) {
    let retry = if let Some(expected) = expected {
        ConfirmRetry::Expected {
            catalog_id: catalog_id.to_string(),
            pick: expected.clone(),
        }
    } else if seeded {
        ConfirmRetry::Seed {
            catalog_id: catalog_id.to_string(),
            title: title.to_string(),
        }
    } else {
        return;
    };
    // Take durable custody before touching the SQLite queue. This closes the
    // power-loss cut before the FULL-synchronous transaction begins.
    let journaled = match save_confirm_retry(d, &retry) {
        Ok(()) => true,
        Err(error) => {
            warn!(target: "confirm", "could not preserve one-shot retry: {error}");
            false
        }
    };
    let restored = match &retry {
        ConfirmRetry::Expected { pick, .. } => {
            super::expected::expected_retry_at(d, selection_era, pick)
        }
        ConfirmRetry::Seed { title, .. } => seed_retry_at(d, selection_era, title),
    };
    match restored {
        Some(true) => {
            if journaled {
                let _ = clear_confirm_retry(d);
            }
        }
        Some(false) | None => {
            if !journaled {
                warn!(
                    target: "confirm",
                    "one-shot retry has neither journal nor SQLite custody"
                );
            }
        }
    }
}

/// Which of the three pickers bought this attempt, for the log. Both
/// flags already reach every retire/retry call here; this spells them.
#[cfg(feature = "indexer")]
fn pick_kind(seeded: bool, expected: bool) -> &'static str {
    match (expected, seeded) {
        (true, _) => "expected",
        (_, true) => "seeded",
        _ => "suggestion",
    }
}

#[cfg(feature = "indexer")]
fn retire_confirm_pick(
    d: &Arc<Daemon>,
    selection_era: u64,
    seeded: bool,
    expected: bool,
    rid: i64,
    pid: i64,
    title: &str,
    now: i64,
) {
    d.with_index(|ix| {
        if d.index_era() != selection_era {
            return None;
        }
        let mut recent: Vec<String> = ix
            .kv_get(CONFIRM_RECENT_KEY)
            .and_then(|value| serde_json::from_str(&value).ok())
            .unwrap_or_default();
        recent.push(nzbkit::predb::match_key(title));
        if recent.len() > CONFIRM_RECENT_CAP {
            let cut = recent.len() - CONFIRM_RECENT_CAP;
            recent.drain(..cut);
        }
        let _ = ix.kv_set(
            CONFIRM_RECENT_KEY,
            &serde_json::to_string(&recent).unwrap_or_default(),
        );
        if !seeded && !expected {
            ix.corr_confirm_stamp(rid, pid, now).ok()
        } else {
            Some(())
        }
    });
}

/// The seed pick: pop a queued title, refilling the queue from one
/// newest-listing sweep when it is empty and the hourly throttle
/// allows. The sweep is an ordinary API hit and is counted against the
/// same per-account quota and daily budget as everything else this
/// lane does; `spent` is bumped here and persisted by the caller.
#[cfg(feature = "indexer")]
fn seed_next(
    d: &Arc<Daemon>,
    cfg: &crate::newznab::IndexerConfig,
    selection_era: u64,
    now: i64,
    spent: &mut u32,
) -> Option<String> {
    if let Some(t) = seed_pop_at(d, selection_era) {
        return Some(t);
    }
    // Only a newznab-kind reference can list "newest" with no free-text
    // query - the nzbindex client refuses an empty `q` by design, and
    // `indexer_search_one` turns that into an error rather than a
    // firehose.
    if !matches!(cfg.kind, crate::newznab::SourceKind::Newznab) {
        return None;
    }
    // And being newznab-kind is not enough. A site may refuse the
    // request shape outright, and this one is on an hourly timer that
    // charges a quota hit BEFORE it asks - so an unlatched refusal is a
    // standing daily cost with nothing on the other side of it. Checked
    // before the throttle and before the charge, so a stood-down source
    // costs the tick nothing at all.
    if d.indexer_rt.lock_ok().no_listing.contains(&cfg.identity()) {
        return None;
    }
    let last: i64 = d
        .with_index(|ix| ix.kv_get(SEED_LISTING_AT_KEY).and_then(|v| v.parse().ok()))
        .unwrap_or(0);
    if now - last < SEED_LISTING_EVERY || *spent >= confirm_budget(cfg) {
        return None;
    }
    {
        let mut rt = d.indexer_rt.lock_ok();
        rt.usage.roll(now);
        // TWO hits, not one (F25, 1 Sep 2026). The sweep below is one
        // API hit and its whole product is a POPPED title - `seed_pop`
        // takes it out of the queue and rings its key in
        // `SEED_RECENT_KEY` so the hourly sweep will not offer it
        // again - and the confirm search the caller then runs for that
        // title needs a hit of its own. With exactly one left, the old
        // single-hit test let this spend it, pop a title, and hand it
        // to a caller whose authoritative wall then refused: the title
        // was consumed with no search behind it and never came back.
        // Asking for both up front costs a tick that could not have
        // finished anyway.
        if !rt.usage.hits_left(cfg, 2) {
            return None;
        }
        rt.usage.count_hit(&cfg.name);
    }
    crate::save_indexer_usage(d);
    *spent += 1;
    // Stamped before the request, not after: a sweep that errors must
    // still wait out the throttle, or a broken account is hammered
    // once a minute forever.
    d.with_index(|ix| ix.kv_set(SEED_LISTING_AT_KEY, &now.to_string()).ok());
    // Screen the sweep by the user's own stated interests (6c and
    // 6c-BUILT of research/SEED-LANE-LIVE-2026-09-02.md). Part of an
    // unscreened newest-listing feed is category 6000, and this index
    // holds 123 `adult` rows in 67 million because it scans none of the
    // groups that content is posted to - so those grabs cannot join,
    // ever, by construction. The two measurements of how big that part
    // is disagree wildly (48% across a 247-grab day, 7% in one live
    // snapshot) and the disagreement does not matter: the request costs
    // the same single hit either way, and every listing the screen
    // drops is one the join could never have answered.
    //
    // `newznab_cats` walks the built-in table and keeps what the
    // setting names, so no stored value can WIDEN this. An unanswered
    // or unrecognised setting leaves it empty, which sends no `cat=` at
    // all and is exactly the request that shipped before: a user who
    // never chose is not narrowed on their behalf.
    let cats = crate::interests::newznab_cats(&crate::interests::parse(
        &d.index_interests.lock_ok().clone(),
    ));
    let q = crate::newznab::SearchQuery {
        q: String::new(),
        cats,
        limit: 100,
        ..Default::default()
    };
    let (results, _origin) = match crate::indexer_search_one(cfg, &q) {
        Ok(pair) => pair,
        // A refusal of the request SHAPE is a verdict, not weather: the
        // same ask gets the same answer next hour and the hour after,
        // so latch it and say so ONCE. Everything else - auth, quota,
        // transport - recovers on its own and keeps its hourly retry.
        Err(e) if e.is_unsupported_request() => {
            // The lock is dropped before the log line: `warn!` reaches a
            // file writer, and the indexer lock is on the pull-search
            // path every dashboard keystroke takes.
            let first = d.indexer_rt.lock_ok().no_listing.insert(cfg.identity());
            if first {
                warn!(
                    target: "confirm",
                    "{} cannot list newest ({e}) - standing the seed sweep down for it \
                     until restart; the confirm lane keeps its other pick sources",
                    cfg.name
                );
            }
            return None;
        }
        Err(e) => {
            warn!(target: "confirm", "seed sweep against {} failed: {e}", cfg.name);
            return None;
        }
    };
    let total = results.len();
    // Scoped to the groups the SCAN covers, which is the only place a
    // message-id join can ever fire. Over the whole table this number
    // was 2009-07-30 on the live index - one stray repost in a group
    // nothing scans - and the screen below therefore rejected nothing at
    // all. See `oldest_first_posted` for what the scoped number is worth
    // and why it is an exact minimum rather than a percentile.
    let groups = d.index_groups.lock_ok().clone();
    let min_fp: i64 = d
        .with_index(|ix| ix.oldest_first_posted(&groups).ok())
        .unwrap_or(0);
    let recent: Vec<String> = d
        .with_index(|ix| {
            ix.kv_get(SEED_RECENT_KEY)
                .and_then(|v| serde_json::from_str(&v).ok())
        })
        .unwrap_or_default();
    let mut queue: Vec<String> = Vec::new();
    let mut mix: Vec<(u32, u32)> = Vec::new();
    for r in results {
        if queue.len() >= SEED_QUEUE_CAP {
            break;
        }
        // Older than anything we hold IN A SCANNED GROUP: the join has
        // nothing to hit and the grab is quota spent on nothing (the
        // live probe lost one of its two grabs exactly this way).
        if r.posted > 0 && min_fp > 0 && r.posted < min_fp {
            continue;
        }
        let key = nzbkit::predb::match_key(&r.title);
        if key.is_empty() || recent.contains(&key) {
            continue;
        }
        // Already posted READABLY under this very name: the index has
        // it and needs no grab. One probe of idx_rel_stem.
        if d.with_index(|ix| ix.stem_exists(&r.title).ok())
            .unwrap_or(false)
        {
            continue;
        }
        match mix.iter_mut().find(|(c, _)| *c == r.cat) {
            Some((_, n)) => *n += 1,
            None => mix.push((r.cat, 1)),
        }
        queue.push(r.title);
    }
    if !queue.is_empty() {
        // The screen's own before/after instrument, counted AFTER the
        // queue filters so it is the mix actually queued for the join.
        // Without it in the log, a change to the screen can only be
        // asserted, never measured.
        mix.sort_unstable();
        let mix: Vec<String> = mix.iter().map(|(c, n)| format!("{c}x{n}")).collect();
        let cats: Vec<String> = q.cats.iter().map(u32::to_string).collect();
        let screen = if cats.is_empty() {
            String::new()
        } else {
            format!(" (cat={})", cats.join(","))
        };
        info!(
            target: "confirm",
            "seed sweep{screen}: {total} listing(s), {} queued for the join [{}]",
            queue.len(),
            mix.join(" ")
        );
    }
    d.with_index(|ix| {
        if d.index_era() != selection_era {
            return None;
        }
        ix.kv_set(
            SEED_QUEUE_KEY,
            &serde_json::to_string(&queue).unwrap_or_default(),
        )
        .ok()?;
        seed_pop_from_index(ix)
    })
}

/// Checks `indexer_inbox_room` and logs why not, distinguishing three
/// causes that used to read as one "full or unavailable" sentence. Split out
/// of `corr_confirm_once` to stay clear of its 500-line size-gate ceiling
/// (indexer.rs runs the narrowest headroom in the tree).
#[cfg(feature = "indexer")]
fn confirm_inbox_room_or_log(d: &Arc<Daemon>) -> bool {
    match crate::seed_harvest::indexer_inbox_room(d) {
        crate::seed_harvest::IndexerInboxRoom::Available => true,
        crate::seed_harvest::IndexerInboxRoom::Busy => {
            // Self-clearing: the advisory `.lock` file contends within one
            // process too (each `OpenOptions::open` is its own file
            // description), so this daemon's own harvest worker draining the
            // inbox is the usual holder, not a second daemon. A skipped tick
            // spends nothing from the daily budget and the next confirm tick
            // (a minute away) retries for free, so stand down quietly rather
            // than at WARN, which would misread a routine handoff as a fault.
            tracing::debug!(
                target: "confirm",
                "commercial NZB seed inbox lock is busy (most likely this daemon's own harvest worker draining it) - standing down this tick, retrying next minute"
            );
            false
        }
        crate::seed_harvest::IndexerInboxRoom::AtCapacity(detail) => {
            warn!(
                target: "confirm",
                "commercial NZB seed inbox is at capacity ({detail}) - standing down before spending quota"
            );
            false
        }
        crate::seed_harvest::IndexerInboxRoom::Unreadable(error) => {
            // Fails closed deliberately (better to skip a tick than spend
            // quota into an inbox we cannot even inspect), but that used to
            // collapse into the same "full" wording as a real capacity hold.
            // Name the io error so a broken spool reads as broken, not full.
            warn!(
                target: "confirm",
                "commercial NZB seed inbox could not be read ({error}) - standing down before spending quota"
            );
            false
        }
    }
}

/// One confirm attempt: pick the best unchecked STRONG suggestion,
/// search the user's chosen indexer for its pre title, fetch the
/// matching NZB and save its complete, file-aware identity. Exact seed
/// reconciliation names only a local row that covers the full external data
/// manifest; a split pack becomes a named collection edge instead of several
/// rows wearing the pack title. The ordinary proof seam still settles any
/// matching pre_corr row and back-feeds the predb filename. Returns whether
/// budget was spent.
///
/// Blocking (ureq + index writes) - call from `spawn_blocking`. The
/// A definitive miss, invalid body, or durably staged proof retires the pick.
/// Transient search, fetch, or staging failures leave it eligible for retry;
/// quota is still counted at attempt time.
#[cfg(feature = "indexer")]
pub fn corr_confirm_once(d: &Arc<Daemon>) -> bool {
    if !d.corr_confirm_on() {
        return false;
    }
    if !flush_confirm_retry(d) {
        return false;
    }
    if !confirm_inbox_room_or_log(d) {
        return false;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs() as i64)
        .unwrap_or(0);
    let Some((selection_era, catalog_id)) = confirm_catalog_fence(d) else {
        return false;
    };
    let today = now.div_euclid(86_400);
    let spent: u32 = d
        .with_index(|ix| {
            let day: i64 = ix
                .kv_get("corr_confirm_day")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            if day != today {
                let _ = ix.kv_set("corr_confirm_day", &today.to_string());
                let _ = ix.kv_set("corr_confirm_spent", "0");
                Some(0)
            } else {
                ix.kv_get("corr_confirm_spent").and_then(|v| v.parse().ok())
            }
        })
        .unwrap_or(0);
    // The reference account resolves BEFORE the budget gate as well as
    // before the pick: the budget is 80% of THIS account's configured
    // quota (`confirm_budget`), so there is no number to compare
    // against until the account is known - and a broken setting should
    // stop both pick sources, not just one.
    let cfg = match d.corr_confirm_reference() {
        Ok(c) => c,
        Err(e) => {
            // Once per daemon run, not per tick: the setting is wrong,
            // and 1,440 identical lines a day would bury the one that
            // matters.
            static WARNED: std::sync::atomic::AtomicBool =
                std::sync::atomic::AtomicBool::new(false);
            if !WARNED.swap(true, Ordering::Relaxed) {
                warn!(target: "confirm", "{e}");
            }
            return false;
        }
    };
    let budget = confirm_budget(&cfg);
    if spent >= budget {
        return false;
    }
    let spent_before_pick = spent;
    let mut spent = spent;
    // The per-account quotas are asked BEFORE the pick as well as
    // after it, because every pick source CONSUMES its candidate as it
    // picks: the seed queue pops and rings the title, the expected
    // queue pops and rings its key, both before a byte leaves. A tick
    // refused by the authoritative wall below would therefore burn one
    // queued title a minute with no search behind it - a 40-title seed
    // queue destroyed in 40 minutes, and its keys left in the recent
    // ring so the hourly sweep will not re-queue them once the quota
    // resets. This is not an exotic state: `confirm_budget`'s
    // CONFIRM_PER_DAY floor sits above a small `grabs_per_day` by
    // design, so `spent < budget` while `grab_allowed` is false is
    // routine, and `Usage` is daemon-wide, so a watchlist or *arr
    // burst can spend the quota while this lane's own `spent` is
    // still 0. Read-only: the block after the pick stays the
    // authoritative wall and the only place that counts a hit.
    // The usage charge itself lands immediately before the actual request.
    {
        let mut rt = d.indexer_rt.lock_ok();
        rt.usage.roll(now);
        if !rt.usage.hit_allowed(&cfg) || !rt.usage.grab_allowed(&cfg) {
            return false;
        }
    }
    // BELOW the read-only quota check above on purpose: a hunt spends a
    // hit and a grab like every other attempt, and it consumes its
    // candidate into a recent ring as it picks, so a tick the account
    // cannot serve must stand the hunts down too rather than burn picks
    // with no search behind them.
    if let Some(after) = super::namehunt::spend_hunt_share(d, now, budget, spent) {
        spent = after;
        d.with_index(|ix| ix.kv_set("corr_confirm_spent", &spent.to_string()).ok());
        return true;
    }
    // The pick, in priority order: an EXPECTED title from the release
    // calendar first, then a correlation suggestion, then a title
    // seeded from the reference's own newest listings. Expected goes
    // FIRST because its queue is BOUNDED - a day of TV plus web is a
    // few hundred titles, so it cannot starve what stands behind it -
    // while the corr backlog is unbounded and its premise measured 0%
    // precision (research/NAMECORR-PRECISION-2026-09-01.md): the
    // original corr-first order let it spend every attempt of beta 4's
    // raised budget disproving correlations one grab at a time, and
    // the oracle never ran once (live log, 1 Sep 2026 15:07-15:57Z).
    // `seeded` and `expected` keep each source's own steps - the corr
    // stamp, the score in the log, the token match - out of the other
    // paths.
    let mut expected: Option<super::expected::ExpectedPick> = None;
    let (seeded, rid, title, score, pid) =
        match super::expected::expected_next_at(d, now, selection_era) {
            Some(p) => {
                // Free-text with the episode token or the year folded in -
                // the exact fallback `plan_query` itself uses, so it works
                // against every newznab with no caps round-trip.
                let q = p.query();
                expected = Some(p);
                (false, 0, q, 0, 0)
            }
            None => {
                // The corr pick, deduped by attempted TITLE: a suggestion
                // whose title is in the recent ring is stamped without a
                // lookup - the identical search and grab just ran for a
                // sibling row, and buying it again is quota for nothing.
                let fresh = d.with_index(|ix| {
                    if d.index_era() != selection_era {
                        return None;
                    }
                    let recent: Vec<String> = ix
                        .kv_get(CONFIRM_RECENT_KEY)
                        .and_then(|v| serde_json::from_str(&v).ok())
                        .unwrap_or_default();
                    let picks = ix.corr_confirm_pick(10).ok()?;
                    let mut fresh = None;
                    for (rid, title, score, pid) in picks {
                        if recent.contains(&nzbkit::predb::match_key(&title)) {
                            let _ = ix.corr_confirm_stamp(rid, pid, now);
                        } else {
                            fresh = Some((rid, title, score, pid));
                            break;
                        }
                    }
                    Some(fresh)
                });
                let Some(fresh) = fresh else {
                    return false;
                };
                match fresh {
                    Some((rid, title, score, pid)) => (false, rid, title, score, pid),
                    None => match seed_next(d, &cfg, selection_era, now, &mut spent) {
                        Some(title) => (true, 0, title, 0, 0),
                        None => {
                            // Persist whatever a listing sweep spent even
                            // when it queued nothing grabbable.
                            d.with_index(|ix| {
                                ix.kv_set("corr_confirm_spent", &spent.to_string()).ok()
                            });
                            return spent > spent_before_pick;
                        }
                    },
                }
            }
        };
    // A seed queue refill spends one listing hit before it yields this pick.
    // Re-check both ledgers after selection so a refill that used the final
    // unit cannot be followed by an over-budget title search. Put one-shot
    // picks back before standing down; correlation rows were never stamped.
    let search_reserved = if spent >= confirm_budget(&cfg) {
        false
    } else {
        let mut rt = d.indexer_rt.lock_ok();
        rt.usage.roll(now);
        if rt.usage.hit_allowed(&cfg) && rt.usage.grab_allowed(&cfg) {
            // Admission and reservation share one lock acquisition. Other
            // indexer lanes cannot consume the last hit between our check and
            // charge.
            rt.usage.count_hit(&cfg.name);
            true
        } else {
            false
        }
    };
    if !search_reserved {
        retry_confirm_pick(
            d,
            selection_era,
            &catalog_id,
            seeded,
            expected.as_ref(),
            &title,
        );
        d.with_index(|ix| ix.kv_set("corr_confirm_spent", &spent.to_string()).ok());
        return spent > spent_before_pick;
    }
    // The user's own per-account quotas gate BOTH halves up front: a
    // search whose grab could never follow is quota spent on nothing.
    crate::save_indexer_usage(d);
    let spend = |n: u32| {
        d.with_index(|ix| {
            ix.kv_set("corr_confirm_spent", &(spent + n).to_string())
                .ok()
        });
    };
    let q = crate::newznab::SearchQuery {
        q: title.clone(),
        limit: 50,
        ..Default::default()
    };
    // The origin is kept, not dropped: the NZB link below comes out of
    // THIS response, so the fetch that follows it is bound to where
    // this search actually answered from (M12 / TODO 135).
    let (results, origin) = match crate::indexer_search_one(&cfg, &q) {
        Ok(pair) => pair,
        Err(e) => {
            // Budget is spent on the failure too, so a broken account
            // warns at most CONFIRM_PER_DAY times a day, not every
            // tick forever. A CORR candidate is NOT stamped - it gets
            // its lookup once the account answers again. A seeded or
            // expected candidate has already left its queue at pick
            // time and does not come back; that leak is bounded by the
            // daily budget this arm spends.
            warn!(target: "confirm", "search against {} failed: {e}", cfg.name);
            spend(1);
            retry_confirm_pick(
                d,
                selection_era,
                &catalog_id,
                seeded,
                expected.as_ref(),
                &title,
            );
            return true;
        }
    };
    // Corr and seed picks: the listing must BE the release, not merely
    // contain its words - match_key is the same normalization the
    // predb exact legs join on. An EXPECTED pick cannot know the full
    // release title in advance (codec and group are the poster's), so
    // its rule is the show plus the SxxEyy token, both inside the
    // listing's match_key.
    let hit = if let Some(p) = &expected {
        results
            .iter()
            .find(|r| p.matches(&nzbkit::predb::match_key(&r.title)))
    } else {
        let want = nzbkit::predb::match_key(&title);
        results
            .iter()
            .find(|r| nzbkit::predb::match_key(&r.title) == want)
    };
    spend(1);
    let Some(hit) = hit else {
        if let Some(p) = &expected {
            info!(
                target: "confirm",
                "{} (expected): {} listings, none carrying the episode - not posted or not listed",
                p.label(),
                results.len()
            );
        } else if seeded {
            info!(
                target: "confirm",
                "\"{title}\" (seeded): {} listings, none exact - unresolved",
                results.len()
            );
        } else {
            info!(
                target: "confirm",
                "\"{title}\" (suggestion score {score}): {} listings, none exact - unresolved",
                results.len()
            );
        }
        retire_confirm_pick(
            d,
            selection_era,
            seeded,
            expected.is_some(),
            rid,
            pid,
            &title,
            now,
        );
        return true;
    };
    let grab_reserved = {
        let mut rt = d.indexer_rt.lock_ok();
        rt.usage.roll(now);
        if rt.usage.grab_allowed(&cfg) {
            // Search and enclosure fetch are separated by parsing and result
            // selection. Re-check and reserve under the same mutex so another
            // lane taking the final grab cannot make this request exceed the
            // configured account limit.
            rt.usage.count_grab(&cfg.name);
            true
        } else {
            false
        }
    };
    if !grab_reserved {
        retry_confirm_pick(
            d,
            selection_era,
            &catalog_id,
            seeded,
            expected.as_ref(),
            &title,
        );
        return true;
    }
    crate::save_indexer_usage(d);
    // fetch_url_from, not the plain indexer fetch: hit.link is an
    // `<enclosure url>` the far end CHOSE, and the plain SSRF guard
    // deliberately permits loopback and the LAN so a self-hosted
    // indexer stays reachable. Unbound, a hostile or compromised
    // account could point this lane's grab at any other service on the
    // user's own box - the same pivot every other link-following lane
    // here closed (indexer grabs, the RSS poller, the watchlist, the
    // scoreboard's calibration). One line, same fix, same reason.
    let xml = match crate::fetch_url_from(&hit.link, &origin) {
        Ok(f) => f.bytes,
        Err(e) => {
            // redact_url_creds, for the reason every other grab lane
            // already states: fetch_url names the URL it failed on, and
            // hit.link is the indexer's own enclosure link, which
            // carries the account credential - spelled `apikey`, `r`,
            // `i`, or simply built into the path, so blanking one
            // parameter name would be a guess. logtee mirrors this into
            // the dashboard log and support bundles. The watchlist,
            // scoreboard, nzblnk and manual-grab lanes all scrub here;
            // this one was missed (14 Aug sweep).
            warn!(
                target: "confirm",
                "NZB fetch from {} failed: {}",
                cfg.name,
                crate::redact_url_creds(&e.to_string())
            );
            retry_confirm_pick(
                d,
                selection_era,
                &catalog_id,
                seeded,
                expected.as_ref(),
                &title,
            );
            return true;
        }
    };
    // Validate the complete manifest before publishing the acquisition. The
    // durable inbox stores the raw bytes and uses their SHA-256 as provenance,
    // so an enclosure URL that contains an API key never reaches disk, even as
    // a reversible or credential-derived identifier.
    let parsed = match nzbkit::nzb::Nzb::parse(&xml) {
        Ok(parsed) => parsed,
        Err(error) => {
            warn!(target: "confirm", "\"{title}\": fetched NZB did not parse: {error:?}");
            retire_confirm_pick(
                d,
                selection_era,
                seeded,
                expected.is_some(),
                rid,
                pid,
                &title,
                now,
            );
            return true;
        }
    };
    let prepared = match nzbkit::index::NzbSeedPrepared::from_nzb(&parsed) {
        Ok(prepared) => prepared,
        Err(error) => {
            warn!(target: "confirm", "\"{title}\": fetched NZB is not safe seed evidence: {error}");
            retire_confirm_pick(
                d,
                selection_era,
                seeded,
                expected.is_some(),
                rid,
                pid,
                &title,
                now,
            );
            return true;
        }
    };
    drop(prepared);
    drop(parsed);
    let category = hit.cat.to_string();
    // An expected pick searched by show+episode; the NAME is the
    // listing's own full release title, which the indexer was handed
    // with the upload. Corr and seed picks already searched by the
    // full title.
    let claim_name = if expected.is_some() {
        hit.title.clone()
    } else {
        title.clone()
    };
    match crate::seed_harvest::stage_indexer_seed(
        d,
        &xml,
        &claim_name,
        &category,
        hit.posted,
        hit.size,
    ) {
        Ok(_) => {
            retire_confirm_pick(
                d,
                selection_era,
                seeded,
                expected.is_some(),
                rid,
                pid,
                &title,
                now,
            );
            d.seed_harvest_wake.notify_one();
            // Named by PICK SOURCE: this is the line a paid grab ends
            // on, and without it no log says which of the three pickers
            // spent the money - the gap that stopped
            // research/SEED-LANE-LIVE-2026-09-02.md attributing them.
            info!(
                target: "confirm",
                "\"{title}\" ({}): commercial NZB proof saved for exact local replay",
                pick_kind(seeded, expected.is_some())
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
            // Metadata, body size, or an existing quarantine makes this exact
            // acquisition permanently unsuitable. Requeueing would buy the
            // same rejected proof on every tick.
            retire_confirm_pick(
                d,
                selection_era,
                seeded,
                expected.is_some(),
                rid,
                pid,
                &title,
                now,
            );
            warn!(
                target: "confirm",
                "\"{title}\": rejected commercial NZB proof: {error}"
            );
        }
        Err(error) => {
            retry_confirm_pick(
                d,
                selection_era,
                &catalog_id,
                seeded,
                expected.as_ref(),
                &title,
            );
            warn!(
                target: "confirm",
                "\"{title}\": could not durably stage fetched NZB proof: {error}"
            );
        }
    }
    true
}

/// The confirm lane's clock: one budgeted attempt per tick, standing
/// down whenever index maintenance would (offline, an active job).
#[cfg(feature = "indexer")]
pub fn spawn_corr_confirm(daemon: &Arc<Daemon>) {
    // Checked once - the env cannot change under a running process,
    // and the tests drive `corr_confirm_once` directly.
    if !crate::identity::may_call_out() {
        return;
    }
    let d = daemon.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            if !d.corr_confirm_on() || !d.index_maintenance_ok() {
                continue;
            }
            let d2 = d.clone();
            let _ = tokio::task::spawn_blocking(move || corr_confirm_once(&d2)).await;
        }
    });
}

// ---- TODO 131 red-team 5a: the pesto tiny-PAR2 naming rung -----------

/// Payload candidates one set may hash-check per hunt. The census's
/// collision resolved among 4 claimants; past that the link is noise.
#[cfg(feature = "indexer")]
const PESTO_CAND_MAX: usize = 4;

/// One decoded BODY fetch with fill-server fallthrough: every scan
/// server in turn until one has the article. The census lost 2.8% of
/// sidecars to single-backbone retention holes; a real rung recovers
/// most of those from the fills. `None` = gone (or undecodable)
/// everywhere reachable this tick.
#[cfg(feature = "indexer")]
async fn pesto_fetch_any(
    conns: &mut std::collections::HashMap<
        String,
        (nzbkit::config::ServerConfig, nzbkit::nntp::Connection),
    >,
    cooldown: &mut std::collections::HashMap<String, Instant>,
    servers: &[nzbkit::config::ServerConfig],
    msgid: &str,
    spent: &mut (u64, u64),
) -> Option<nzbkit::yenc::Decoded> {
    for s in servers {
        if cooldown.get(&s.host).is_some_and(|&t| Instant::now() < t) {
            continue;
        }
        if !conns.contains_key(&s.host) {
            match nzbkit::nntp::Connection::connect(s).await {
                Ok((c, _)) => {
                    cooldown.remove(&s.host);
                    conns.insert(s.host.clone(), (s.clone(), c));
                }
                Err(e) => {
                    let cd =
                        sampler_cap_cooldown(&e, s).unwrap_or(std::time::Duration::from_secs(600));
                    cooldown.insert(s.host.clone(), Instant::now() + cd);
                    warn!(target: "pesto", "{}: connect: {e}", s.host);
                    continue;
                }
            }
        }
        let Some((_, c)) = conns.get_mut(&s.host) else {
            continue;
        };
        match probe_fetch(c, msgid, spent).await {
            Ok(Some(dec)) => return Some(dec),
            // Missing on this server: fall through to the next one.
            Ok(None) => continue,
            Err(e) => {
                // Connection trouble: cool the host off, keep going -
                // the whole point of the fallthrough is that one dead
                // server must not sink the fetch.
                warn!(target: "pesto", "{}: {e}", s.host);
                if let Some((_, c)) = conns.remove(&s.host) {
                    c.quit().await;
                }
                cooldown.insert(
                    s.host.clone(),
                    Instant::now() + std::time::Duration::from_secs(600),
                );
            }
        }
    }
    None
}

/// The token line phase A must stop at, so the linking half of the
/// pesto lane cannot be starved by the fetching half. Half the bucket:
/// the two phases cost about the same per unit of work (one article to
/// read a sidecar, one to hash-confirm a payload), and whatever the
/// reserved half goes unused carries into the next tick.
#[cfg(feature = "indexer")]
fn pesto_link_floor(tokens: f64) -> f64 {
    tokens / 2.0
}

/// The pesto tiny-PAR2 naming worker (TODO 131, red-team 5a): a 60 s
/// loop that fetches the family's tiny sidecar objects, parses them
/// into recovery sets (deduped by set id), links each set backward to
/// its payload by message-id counter + length ratio, and - only after
/// the payload's own first article hash-matches a FileDesc - writes a
/// PAR2-grade name claim. The hash gate is load-bearing: skipping it
/// ships >=2.4% wrong names on the confident tier (census section 4),
/// so it runs for the clean tier too until 40/40 is re-earned at scale.
///
/// Modelled on the byte prober: stamp-first rotation, token-bucket
/// article budget, hard stand-down while anything downloads. Scope
/// honesty: this band is ~5% of dark bytes, one poster tool, moovee +
/// teevee - the daily tallies (`mode=pesto_stats`) are the early
/// warning when that tool changes its message-id grammar, and the
/// `index_pesto` switch is the kill for the whole lane.
#[cfg(feature = "indexer")]
pub fn spawn_pesto(daemon: &Arc<Daemon>, config: &std::path::Path) {
    use nzbkit::index::PESTO_GIVE_UP;
    let config = config.to_path_buf();
    let d = daemon.clone();
    tokio::spawn(async move {
        let mut conns: std::collections::HashMap<
            String,
            (nzbkit::config::ServerConfig, nzbkit::nntp::Connection),
        > = Default::default();
        let mut cooldown: std::collections::HashMap<String, Instant> = Default::default();
        // Token bucket over articles, the probe7z shape: refills at
        // the hourly budget, caps at ten minutes' worth.
        let mut tokens: f64 = 0.0;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            let rate = d.index_pesto_budget.load(Ordering::Relaxed);
            if !d.index_pesto.load(Ordering::Relaxed)
                || rate == 0
                || d.offline.load(Ordering::Relaxed)
                || d.indexer_off()
                || d.started_at.lock_ok().is_some()
            {
                for (_, (_, c)) in conns.drain() {
                    c.quit().await;
                }
                tokens = 0.0;
                continue;
            }
            // Floor the cap at one action's worth, same reason as the
            // 7z lane: a budget under 6/hr capped the bucket below 1.0
            // and the whole lane silently idled.
            tokens = (tokens + rate as f64 / 60.0).min((rate as f64 / 6.0).max(1.0));
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|t| t.as_secs() as i64)
                .unwrap_or(0);
            let servers = match nzbkit::config::Config::load(&config) {
                Ok(c) => crate::servers::scan_servers(&c),
                Err(_) => continue,
            };
            if servers.is_empty() {
                continue;
            }
            // The bucket is SPLIT between the two phases, not handed to
            // whoever asks first. Phase A has a pick for as long as the
            // census backlog lasts (749 rows on the live index the day
            // this shipped), so a bare `while tokens >= 1.0` here spent
            // every token before phase B - the half that actually turns
            // sidecars into names - was ever tested: 78 sidecars parsed,
            // 69 sets pending, 0 named. Phase A now stops at the floor
            // and leaves the rest for linking; when either phase has no
            // work the other still gets the whole bucket, because the
            // floor is recomputed from what is left each tick.
            let link_floor = pesto_link_floor(tokens);
            // Phase A: fetch and parse tiny sidecar objects.
            while tokens - link_floor >= 1.0 {
                let Some(cand) = d.with_index(|ix| ix.pesto_pick(now, 1).ok()?.into_iter().next())
                else {
                    break;
                };
                // Stamp first (the sampler's rule): a fetch that dies
                // mid-wire still rotates the pick.
                d.with_index(|ix| ix.probe7z_mark(cand.id, now).ok());
                let seg = d
                    .with_index(|ix| ix.probe7z_files(cand.id).ok())
                    .unwrap_or_default()
                    .into_iter()
                    .find_map(|f| f.segments.first().map(|(_, id, _)| id.clone()));
                let Some(msgid) = seg else {
                    d.with_index(|ix| {
                        ix.probe7z_give_up(cand.id, now).ok();
                        ix.pesto_note(now, "fetchmiss", 0, 0).ok()
                    });
                    continue;
                };
                let Some(ctr) = nzbkit::pesto::parse_msgid(&msgid).map(|p| p.counter as i64) else {
                    // The pick's SQL said pesto but the stored id does
                    // not parse - marked off, never chased.
                    d.with_index(|ix| {
                        ix.probe7z_give_up(cand.id, now).ok();
                        ix.pesto_note(now, "other", 0, 0).ok()
                    });
                    continue;
                };
                let mut spent = (0u64, 0u64);
                let dec =
                    pesto_fetch_any(&mut conns, &mut cooldown, &servers, &msgid, &mut spent).await;
                tokens -= (spent.0.max(1)) as f64;
                let Some(dec) = dec else {
                    if spent.0 == 0 {
                        // No server even answered: nothing this tick
                        // can do, and looping would only burn picks.
                        d.with_index(|ix| ix.pesto_note(now, "fetchfail", 0, 0).ok());
                        break;
                    }
                    // Fetched at, missing everywhere: retry on the
                    // rotation (retention may still fill in), give up
                    // for good once the tries cap it.
                    d.with_index(|ix| ix.pesto_note(now, "fetchmiss", spent.0, spent.1).ok());
                    continue;
                };
                if !dec.data.starts_with(nzbkit::par2::MAGIC) {
                    // A real ~80 KB payload file, not a sidecar (the
                    // census saw 3/620). Structural: leave the row.
                    d.with_index(|ix| {
                        ix.probe7z_give_up(cand.id, now).ok();
                        ix.pesto_note(now, "notpar2", spent.0, spent.1).ok()
                    });
                    continue;
                }
                let grp = d
                    .with_index(|ix| ix.release_grp(cand.id).ok().flatten())
                    .unwrap_or_default();
                let stored = nzbkit::par2::Par2Set::parse(&[&dec.data])
                    .ok()
                    .and_then(|set| {
                        d.with_index(|ix| ix.pesto_set_store(&grp, ctr, &set, now).ok())
                    })
                    .unwrap_or(false);
                let outcome = if stored {
                    "par2ok"
                } else {
                    // PAR2 magic present but unparseable (or fileless):
                    // the lane's own canary, distinct from notpar2 -
                    // this is what a pesto tool update looks like.
                    "parsefail"
                };
                d.with_index(|ix| {
                    ix.probe7z_give_up(cand.id, now).ok();
                    ix.pesto_note(now, outcome, spent.0, spent.1).ok()
                });
            }
            // Phase B: link pending sets backward and hash-confirm.
            while tokens >= 1.0 {
                let Some(set) =
                    d.with_index(|ix| ix.pesto_pending(now, 1).ok()?.into_iter().next())
                else {
                    break;
                };
                d.with_index(|ix| ix.pesto_set_touch(&set.set_id, now).ok());
                let last_try = set.tries + 1 >= PESTO_GIVE_UP;
                let cands = d
                    .with_index(|ix| ix.pesto_candidates(&set).ok())
                    .unwrap_or_default();
                if cands.is_empty() {
                    // No payload passes containment + the ratio band -
                    // out of retention, still posting, or another
                    // session's counters. Retries on rotation.
                    d.with_index(|ix| {
                        if last_try {
                            ix.pesto_set_resolve(&set.set_id, "nopayload", 0, now).ok();
                            ix.pesto_note(now, "nopayload", 0, 0).ok()
                        } else {
                            ix.pesto_note(now, "nolink", 0, 0).ok()
                        }
                    });
                    continue;
                }
                let mut spent = (0u64, 0u64);
                let (mut hashed, mut noheads) = (0u32, 0u32);
                let mut verdict: Option<&'static str> = None;
                for cand in cands.iter().take(PESTO_CAND_MAX) {
                    if tokens - (spent.0 as f64) < 1.0 {
                        break;
                    }
                    // The payload's FIRST-POSTED file: smallest
                    // counter on its first segment. Its part 1 is the
                    // span every FileDesc's 16k hash covers.
                    let files = d
                        .with_index(|ix| ix.probe7z_files(cand.id).ok())
                        .unwrap_or_default();
                    let first = files
                        .iter()
                        .filter(|f| !f.segments.is_empty())
                        .min_by_key(|f| {
                            f.segments
                                .first()
                                .and_then(|(_, id, _)| nzbkit::pesto::parse_msgid(id))
                                .map(|p| p.counter)
                                .unwrap_or(u32::MAX)
                        });
                    let Some((_, msgid, _)) = first.and_then(|f| f.segments.first()) else {
                        continue;
                    };
                    let Some(dec) =
                        pesto_fetch_any(&mut conns, &mut cooldown, &servers, msgid, &mut spent)
                            .await
                    else {
                        continue;
                    };
                    if dec.offset() != 0 {
                        noheads += 1;
                        continue;
                    }
                    hashed += 1;
                    // THE gate. None = these are not the set's bytes,
                    // whatever the counters said - next candidate.
                    let confirmed = d
                        .with_index_mut(|ix| ix.pesto_confirm(&set, cand.id, &dec.data, now).ok())
                        .flatten();
                    if let Some(outcome) = confirmed {
                        if outcome == "named" {
                            info!(
                                target: "pesto",
                                "release {} named from its PAR2 sidecar (set {})",
                                cand.id, set.set_id
                            );
                        }
                        verdict = Some(outcome);
                        break;
                    }
                }
                tokens -= spent.0 as f64;
                let outcome = match verdict {
                    Some(o) => o,
                    // Candidates existed but none confirmed. hashreject
                    // is the mislink canary: the pre-filters said yes
                    // and the bytes said no - exactly the shape that
                    // would have shipped a wrong name without the gate.
                    None if hashed > 0 => {
                        if last_try {
                            d.with_index(|ix| {
                                ix.pesto_set_resolve(&set.set_id, "unresolved", 0, now).ok()
                            });
                        }
                        "hashreject"
                    }
                    None if noheads > 0 => "nohead",
                    None => "fetchfail",
                };
                d.with_index(|ix| ix.pesto_note(now, outcome, spent.0, spent.1).ok());
                if spent.0 == 0 && verdict.is_none() && hashed == 0 && noheads == 0 {
                    // Nothing reachable on the wire - stop the phase
                    // rather than churning stamps.
                    break;
                }
            }
            // Give slots back between ticks once downloads are idle
            // past each server's release timeout - the sampler's rule.
            let held: Vec<String> = conns.keys().cloned().collect();
            for host in held {
                let may = conns.get(&host).is_some_and(|(s, _)| d.sampler_may_hold(s));
                if !may && let Some((_, c)) = conns.remove(&host) {
                    c.quit().await;
                }
            }
        }
    });
}

#[cfg(all(test, feature = "indexer"))]
mod tests {
    use super::*;
    // Only the tests still reach into the byte-probe lane for this one.
    use crate::rarprobe::rar_probe_volumes;

    /// The background recipe now sees RAR sets: a hash release whose
    /// data is `.partNN.rar` volumes gets the RarHead arm, a `.7z` one
    /// keeps the SevenzTail arm, and a release carrying both is the 7z
    /// shape (the cheaper certain read).
    #[test]
    fn recipe_routes_rar_sets_to_the_rar_arm_and_7z_first() {
        use super::probe7z::{ProbeRecipe, probe_recipe};
        let rar = [
            pf("blob.part01.rar", &[1]),
            pf("blob.part02.rar", &[1]),
            pf("blob.par2", &[1]),
        ];
        assert!(matches!(probe_recipe(&rar), Some(ProbeRecipe::RarHead)));
        let sevenz = [pf("blob.7z", &[1]), pf("blob.par2", &[1])];
        assert!(matches!(
            probe_recipe(&sevenz),
            Some(ProbeRecipe::SevenzTail(_))
        ));
        let both = [pf("blob.7z", &[1]), pf("stray.rar", &[1])];
        assert!(matches!(
            probe_recipe(&both),
            Some(ProbeRecipe::SevenzTail(_))
        ));
        assert!(probe_recipe(&[pf("blob.par2", &[1])]).is_none());
    }

    fn pf(filename: &str, parts: &[u32]) -> nzbkit::index::ProbeFile {
        nzbkit::index::ProbeFile {
            filename: filename.into(),
            bytes: 500_000_000,
            segments: parts
                .iter()
                .map(|p| (*p, format!("<{filename}.{p}@x>"), 700_000))
                .collect(),
        }
    }

    /// The pilot's correction to the bundle, pinned. The old "779-fetch
    /// dead end" searched for physical volume 1 BY FILENAME, which in
    /// this band is not where the archive starts. The probe order is
    /// middle-first because a CONTINUATION volume repeats the inner
    /// file header - that is where 11 of 14 RAR4 names actually came
    /// from (part43, part51, part19, part22), never from part01.
    #[test]
    fn rar_volumes_are_probed_middle_first_and_capped_at_three() {
        let files: Vec<_> = (1..=9)
            .map(|n| pf(&format!("blob.part{n:02}.rar"), &[1, 2]))
            .chain([pf("blob.par2", &[1])])
            .collect();
        let order: Vec<&str> = rar_probe_volumes(&files)
            .iter()
            .map(|f| Box::leak(f.filename.clone().into_boxed_str()) as &str)
            .collect();
        assert_eq!(
            order,
            vec!["blob.part05.rar", "blob.part01.rar", "blob.part09.rar"],
            "middle, then first, then last - and the .par2 is not a volume"
        );
    }

    /// A single-volume set must not be probed three times for the same
    /// article: middle == first == last collapses to one fetch.
    #[test]
    fn a_single_volume_is_one_article_not_three() {
        let v = rar_probe_volumes(&[pf("blob.rar", &[1, 2]), pf("blob.par2", &[1])]);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].filename, "blob.rar");
        // Old-style continuation naming is a volume too.
        let v = rar_probe_volumes(&[pf("blob.rar", &[1]), pf("blob.r00", &[1])]);
        assert_eq!(v.len(), 2);
        // And a set with no RAR at all names nothing rather than
        // fetching on spec.
        assert!(rar_probe_volumes(&[pf("blob.7z", &[1])]).is_empty());
    }

    /// Phase A always has a pick while the sidecar census drains, so
    /// the split is the only thing standing between "sidecars parsed"
    /// and "releases named". One minute of the default 120/hr budget
    /// must leave phase B a whole article to spend.
    #[test]
    fn pesto_phase_a_cannot_drain_the_bucket() {
        let mut tokens = 120.0 / 60.0;
        let floor = pesto_link_floor(tokens);
        let mut fetched = 0;
        while tokens - floor >= 1.0 {
            tokens -= 1.0;
            fetched += 1;
        }
        assert_eq!(fetched, 1, "phase A takes its half, not the bucket");
        assert!(
            tokens >= 1.0,
            "phase B must be able to hash-confirm: {tokens} left"
        );
    }

    /// An idle phase B must not throttle phase A: the floor is taken
    /// from what is left each tick, so unspent linking budget rolls
    /// forward and fetching still averages the full refill rate.
    #[test]
    fn pesto_unused_link_budget_rolls_forward() {
        let (refill, cap) = (120.0 / 60.0, 120.0 / 6.0);
        let mut tokens: f64 = 0.0;
        let mut fetched = 0;
        for _ in 0..10 {
            tokens = (tokens + refill).min(cap);
            let floor = pesto_link_floor(tokens);
            while tokens - floor >= 1.0 {
                tokens -= 1.0;
                fetched += 1;
            }
            // Phase B finds nothing pending this tick and spends none.
        }
        assert!(
            fetched >= 16,
            "ten ticks of a 2/min refill should still fetch ~20, got {fetched}"
        );
    }
}

mod passes;
// Re-exported flat, because every caller predates the split:
// `tasks.rs` calls these as `indexer::spot_pass`, and the two
// `#[path]` test children below reach them through `super::*`.
//
// A GLOB where the two module re-exports above name their items, and
// deliberately: four of the nine are called only by `maintenance_slice`
// beside them and a fifth only under `cfg(test)`, so a named list would
// have to be cfg-dependent to stay warning-free - and the alternative,
// an `#[allow(unused_imports)]`, mutes a real signal for the rest.
pub(crate) use passes::*;

// Sweep 8's L12 regression: the deferred picker-index build on a
// Spot-only database, and the gate that decides it. A #[path] child so
// this file stays inside its ceiling.
#[cfg(all(test, feature = "indexer"))]
#[path = "picker_index_tests.rs"]
mod picker_index_tests;

// The quality_v10 lap leg: that the lap reaches it, that it heals and
// stamps, and that it stands down for a download. A #[path] child for
// the same reason as the one above.
#[cfg(all(test, feature = "indexer"))]
#[path = "quality_lap_tests.rs"]
mod quality_lap_tests;

// Sweep 8's L7 gate: where the pass takes its one exact stats
// recompute. Hooked here rather than from tasks.rs, which has no lines
// to spare under the size gate.
#[cfg(test)]
#[path = "pass_order_tests.rs"]
mod pass_order_tests;
