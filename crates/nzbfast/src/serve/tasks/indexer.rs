//! Index upkeep, either side of the scan loop itself (which stays in
//! `serve/tasks.rs` with the download worker): deferred VACUUM
//! compaction, the instant-watch hook that offers fresh arrivals to the
//! watchlist, the tip watcher, and the oracle sampler.
//!
//! The common discipline here is that none of it may cost the user a
//! download - the compactor waits for a genuinely idle moment, and the
//! samplers sit out entirely while anything is fetching.
//!
//! Split out of `serve/tasks.rs` whole (TODO 106) - the code is verbatim,
//! only visibility changed (and one `super::daemon::` path, which now
//! sits one module deeper, spelled from the crate root).

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
pub(in crate::serve) fn spawn_index_compact(
    daemon: &Arc<Daemon>,
    index_pass_gate: &Arc<tokio::sync::Mutex<()>>,
) {
    let d = daemon.clone();
    let index_pass_gate = index_pass_gate.clone();
    // Not `index_db` - the scan-loop task above owns that binding now.
    let db = daemon.index_db.clone();
    tokio::spawn(async move {
        // Rate-limit the "no room" line: this ticks every minute and
        // a small NAS volume can stay full for days.
        let mut last_moan = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(7200))
            .unwrap_or_else(std::time::Instant::now);
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
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
            let arm = Arc::new(crate::serve::daemon::MaintenanceArm::default());
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
pub(in crate::serve) fn install_instant_watch(
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
pub(in crate::serve) fn instant_arrivals(
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
pub(in crate::serve) fn instant_ready(
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
pub(in crate::serve) fn sampler_cap_cooldown(
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
pub(in crate::serve) fn spawn_tip_watcher(
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
pub(in crate::serve) fn spawn_oracle_sampler(daemon: &Arc<Daemon>, config: &std::path::Path) {
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
                    for _ in &ids {
                        match conn.read_stat().await? {
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
use probe7z::probe_fetch;
#[cfg(feature = "indexer")]
pub(in crate::serve) use probe7z::{run_rar_probe, spawn_probe7z};

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
/// parse it, join its payload message-ids against the identity
/// substrate's reverse map, and feed quorum joins to
/// `apply_proven_name` as MsgidSet claims - message-id identity only,
/// never time/size.
///
/// Modelled on the oracle sampler: 60 s tick, stand-down arms (the
/// index_nzbimport kill switch, a zero index_nzbimport_budget, offline,
/// indexer off, anything downloading), connect cooldowns, slots handed
/// back between ticks, and a token bucket over fetched articles so a
/// group flooded with large .nzb-named posts cannot hold the walk at
/// its 3-objects-a-minute ceiling indefinitely. The join is
/// `find_releases_by_msgids` - indexed `msgid_map` probes - and
/// deliberately NOT the interim `msgid_lookup` exact join, which is a
/// full `json_each` pass (~45 min on the live index) that exists as a
/// census instrument only.
///
/// The displacement gate lives in `apply_proven_name` itself (a
/// readable stem is a name the claims layer respects): a name lands
/// only on a row whose stem `looks_obfuscated`, or which already
/// carries the same name by `match_key` - a season-pack NZB
/// quorum-joining its per-episode rows comes back Conflict, recorded
/// and never applied. Same quorum, same gate, same canonical
/// matched-set key as `Daemon::record_nzb_pairing`, so the two lanes
/// corroborate instead of reading as independent evidence.
#[cfg(feature = "indexer")]
pub(in crate::serve) fn spawn_nzb_import(daemon: &Arc<Daemon>, config: &std::path::Path) {
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
        let mut transient: (i64, u32) = (0, 0);
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
            let cursor: i64 = d.with_index(|ix| Some(ix.nzbimport_cursor())).unwrap_or(0);
            let cands = d
                .with_index(|ix| ix.posted_nzb_candidates(cursor, NZBIMPORT_PER_TICK).ok())
                .unwrap_or_default();
            if cands.is_empty() {
                // Caught up - the steady state. The connections (if
                // any) are released below on the sampler's terms.
                for (_, c) in conns.drain() {
                    c.quit().await;
                }
                continue;
            }
            let servers = match nzbkit::config::Config::load(&config) {
                Ok(c) => crate::nettools::scan_servers(&c),
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
                let cost = cand.segs.len().clamp(1, NZBIMPORT_ARTICLES_MAX) as f64;
                if tokens < cost {
                    break;
                }
                let bytes =
                    match fetch_import_candidate(&servers, &mut conns, &mut cooldown, &cand.segs)
                        .await
                    {
                        // A reached server delivered or refused
                        // articles either way - both outcomes spend
                        // the candidate's charge.
                        ImportFetch::Ok(b) => {
                            tokens -= cost;
                            Some(b)
                        }
                        ImportFetch::Gone => {
                            tokens -= cost;
                            None
                        }
                        // The cursor must not move past an object nobody
                        // answered for - but "retry next tick" needs an
                        // exit. A near-cap object on a slow link can time
                        // out on EVERY server EVERY tick: without a
                        // counter the cursor pins here forever, every
                        // posted NZB after it is never ingested, and each
                        // tick re-burns the full fetch window per server -
                        // the chase the give-up rule forbids. A few ticks
                        // of grace for real transients (a reconnecting
                        // provider), then walk on as if Gone.
                        ImportFetch::Transient => {
                            if transient.0 == cand.arrival_seq {
                                transient.1 += 1;
                            } else {
                                transient = (cand.arrival_seq, 1);
                            }
                            if transient.1 < NZBIMPORT_TRANSIENT_TRIES {
                                break;
                            }
                            warn!(
                                target: "nzbimport",
                                "posted NZB #{} unreachable {} ticks running - walking on",
                                cand.release_id, transient.1
                            );
                            None
                        }
                    };
                if let Some(bytes) = bytes
                    // A fetch that will not parse was never an NZB
                    // (the census measured 1 in 757) - walk on.
                    && let Ok(ident) = nzbkit::nzbimport::nzb_identity(&bytes)
                {
                    self::import_join_apply(&d, &cand, &ident);
                }
                // Every non-transient disposition advances the cursor
                // - fetched-and-joined, gone, or unparseable alike.
                // Persisted per object so a restart mid-tick never
                // re-fetches what this one already settled.
                d.with_index(|ix| ix.nzbimport_cursor_set(cand.arrival_seq).ok());
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

/// Join one parsed posted NZB against the substrate's reverse map and
/// apply the quorum joins. Split from the loop for the name ladder and
/// the lock scope: everything index-side happens under one
/// `with_index_mut` hold, the logging outside it.
#[cfg(feature = "indexer")]
fn import_join_apply(
    d: &Arc<Daemon>,
    cand: &nzbkit::index::PostedNzbCandidate,
    ident: &nzbkit::nzbimport::NzbIdentity,
) {
    use nzbkit::index::msgid_set_key;
    use nzbkit::nzbimport::MIN_MSGID_QUORUM;
    if ident.lead_ids.is_empty() {
        return;
    }
    // The name ladder (census-shaped): the stem the .nzb was POSTED
    // under is the uploader speaking, so it leads; an obfuscated post
    // name falls back to the NZB's own meta title, then the dominant
    // inner filename stem. All three junk = nothing worth claiming,
    // however exact the join (the claims layer would reject it anyway;
    // skipping saves the probe pass nothing but keeps the logs honest).
    let posted = nzbkit::nzbimport::strip_nzb_suffix(&cand.stem).to_string();
    // `stem_is_a_name` is THE shared verdict for a whole stem: the raw
    // function judges tokens, so a blob carrying a trailing `.7z` reads
    // as readable to it and outranks the NZB's own meta title (M7,
    // 10 Aug sweep).
    let name = if nzbkit::release::stem_is_a_name(&posted) {
        Some(posted)
    } else if let Some(t) = ident
        .meta_title
        .as_ref()
        .filter(|t| nzbkit::release::stem_is_a_name(t))
    {
        Some(t.clone())
    } else {
        ident
            .inner_stem
            .as_ref()
            .filter(|s| nzbkit::release::stem_is_a_name(s))
            .cloned()
    };
    let Some(name) = name else { return };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs() as i64)
        .unwrap_or(0);
    let applied = d.with_index_mut(|ix| {
        // Probed one id at a time (the batch form loops internally
        // anyway) so each release's MATCHED id set is known: the
        // canonical MsgidSet key digests the matched set per join,
        // and any other lane proving the same join then produces the
        // same key and the claims dedupe.
        let mut per: std::collections::HashMap<i64, Vec<&str>> = Default::default();
        for id in &ident.lead_ids {
            for (rid, _) in ix
                .find_releases_by_msgids(std::iter::once(id.as_str()))
                .unwrap_or_default()
            {
                // A self-join carries no information: the posted .nzb
                // cannot name itself.
                if rid != cand.release_id {
                    per.entry(rid).or_default().push(id);
                }
            }
        }
        let mut out = Vec::new();
        for (rid, mids) in per {
            // The floor alone, not the census's majority-coverage arm:
            // the map keys a bounded per-file sample, so coverage of
            // the row is structurally unreachable here - the same bar
            // record_nzb_pairing holds its probes to.
            if mids.len() < MIN_MSGID_QUORUM {
                continue;
            }
            let claim = nzbkit::index::NameClaim {
                name: name.clone(),
                evidence: nzbkit::index::NameEvidence::MsgidSet,
                key: msgid_set_key(&mids),
                source: "posted-nzb".into(),
            };
            if let Ok(o) = ix.apply_proven_name(rid, &claim, now) {
                out.push((rid, mids.len(), o));
            }
        }
        Some(out)
    });
    for (rid, matched, outcome) in applied.into_iter().flatten() {
        use nzbkit::index::ProvenOutcome;
        // Quiet by design: conflicts and refusals are the claims
        // layer's to log (it already does, with the specifics); this
        // lane speaks only when a row actually gained a name.
        if matches!(outcome, ProvenOutcome::Applied | ProvenOutcome::Replaced) {
            info!(
                target: "claims",
                "release {rid}: msgid-set pairing ({matched} ids) from posted-nzb \
                 names it {name:?} -> {outcome:?}"
            );
        }
    }
}

// ---- Indexer-confirm lane: correlation suggestions -> proven names ----

/// One confirm attempt: pick the best unchecked STRONG suggestion,
/// search the user's chosen indexer for its pre title, fetch the
/// matching NZB and message-id-join it against the index. A quorum
/// join applies the title through `apply_proven_name` at msgid-set
/// tier (source `nzb-indexer`), which also settles the pre_corr row
/// confirmed/rejected and back-feeds the predb filename - the same
/// seam every other proof uses. Returns whether budget was spent.
///
/// Blocking (ureq + index writes) - call from `spawn_blocking`. The
/// suggestion is stamped `checked_at` after the search attempt, hit
/// or miss, so one suggestion can never cost quota twice.
#[cfg(feature = "indexer")]
pub(in crate::serve) fn corr_confirm_once(d: &Arc<Daemon>) -> bool {
    use nzbkit::index::msgid_set_key;
    use nzbkit::nzbimport::MIN_MSGID_QUORUM;
    if !d.corr_confirm_on() {
        return false;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs() as i64)
        .unwrap_or(0);
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
    if spent >= CONFIRM_PER_DAY {
        return false;
    }
    let Some((rid, title, score, pid)) = d.with_index(|ix| {
        ix.corr_confirm_pick(1)
            .ok()
            .and_then(|v| v.into_iter().next())
    }) else {
        return false;
    };
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
    // The user's own per-account quotas gate BOTH halves up front: a
    // search whose grab could never follow is quota spent on nothing.
    {
        let mut rt = d.indexer_rt.lock_ok();
        rt.usage.roll(now);
        if !rt.usage.hit_allowed(&cfg) || !rt.usage.grab_allowed(&cfg) {
            return false;
        }
        rt.usage.count_hit(&cfg.name);
    }
    crate::serve::save_indexer_usage(d);
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
    let (results, origin) = match crate::serve::indexer_search_one(&cfg, &q) {
        Ok(pair) => pair,
        Err(e) => {
            // Budget is spent on the failure too, so a broken account
            // warns at most CONFIRM_PER_DAY times a day, not every
            // tick forever. The candidate is NOT stamped - it gets its
            // lookup once the account answers again.
            warn!(target: "confirm", "search against {} failed: {e}", cfg.name);
            spend(1);
            return true;
        }
    };
    // The listing must BE the suggested release, not merely contain
    // its words - match_key is the same normalization the predb exact
    // legs join on.
    let want = nzbkit::predb::match_key(&title);
    let hit = results
        .iter()
        .find(|r| nzbkit::predb::match_key(&r.title) == want);
    d.with_index(|ix| ix.corr_confirm_stamp(rid, pid, now).ok());
    spend(1);
    let Some(hit) = hit else {
        info!(
            target: "confirm",
            "\"{title}\" (suggestion score {score}): {} listings, none exact - unresolved",
            results.len()
        );
        return true;
    };
    {
        let mut rt = d.indexer_rt.lock_ok();
        rt.usage.count_grab(&cfg.name);
    }
    crate::serve::save_indexer_usage(d);
    // fetch_url_from, not the plain indexer fetch: hit.link is an
    // `<enclosure url>` the far end CHOSE, and the plain SSRF guard
    // deliberately permits loopback and the LAN so a self-hosted
    // indexer stays reachable. Unbound, a hostile or compromised
    // account could point this lane's grab at any other service on the
    // user's own box - the same pivot every other link-following lane
    // here closed (indexer grabs, the RSS poller, the watchlist, the
    // scoreboard's calibration). One line, same fix, same reason.
    let xml = match crate::serve::fetch_url_from(&hit.link, &origin) {
        Ok(f) => String::from_utf8_lossy(&f.bytes).into_owned(),
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
                crate::serve::redact_url_creds(&e.to_string())
            );
            return true;
        }
    };
    let ident = match nzbkit::nzbimport::nzb_identity(xml.as_bytes()) {
        Ok(i) => i,
        Err(e) => {
            warn!(target: "confirm", "\"{title}\": fetched NZB did not parse: {e:?}");
            return true;
        }
    };
    if ident.lead_ids.is_empty() {
        return true;
    }
    let applied = d.with_index_mut(|ix| {
        // One id per probe so each release's MATCHED set is known -
        // the canonical msgid-set key digests exactly what joined
        // (same discipline as the posted-NZB lane).
        let mut per: std::collections::HashMap<i64, Vec<&str>> = Default::default();
        for id in &ident.lead_ids {
            for (jrid, _) in ix
                .find_releases_by_msgids(std::iter::once(id.as_str()))
                .unwrap_or_default()
            {
                per.entry(jrid).or_default().push(id);
            }
        }
        let mut out = Vec::new();
        for (jrid, mids) in per {
            if mids.len() < MIN_MSGID_QUORUM {
                continue;
            }
            let claim = nzbkit::index::NameClaim {
                name: title.clone(),
                evidence: nzbkit::index::NameEvidence::MsgidSet,
                key: msgid_set_key(&mids),
                source: "nzb-indexer".into(),
            };
            if let Ok(o) = ix.apply_proven_name(jrid, &claim, now) {
                out.push((jrid, mids.len(), o));
            }
        }
        Some(out)
    });
    let mut named_any = false;
    for (jrid, matched, outcome) in applied.into_iter().flatten() {
        use nzbkit::index::ProvenOutcome;
        if matches!(outcome, ProvenOutcome::Applied | ProvenOutcome::Replaced) {
            named_any = true;
            let aimed = if jrid == rid {
                "the suggested row"
            } else {
                "a sibling row"
            };
            info!(
                target: "confirm",
                "release {jrid}: indexer NZB joined ({matched} ids, {aimed}) - named \"{title}\""
            );
        }
    }
    if !named_any {
        info!(
            target: "confirm",
            "\"{title}\": listing found but its NZB joined no release at quorum - unresolved"
        );
    }
    true
}

/// The confirm lane's clock: one budgeted attempt per tick, standing
/// down whenever index maintenance would (offline, an active job).
#[cfg(feature = "indexer")]
pub(in crate::serve) fn spawn_corr_confirm(daemon: &Arc<Daemon>) {
    // Checked once - the env cannot change under a running process,
    // and the tests drive `corr_confirm_once` directly.
    if std::env::var("NZBFAST_NO_ENRICH").is_ok_and(|v| v == "1") {
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
/// The token line phase A must stop at, so the linking half of the
/// pesto lane cannot be starved by the fetching half. Half the bucket:
/// the two phases cost about the same per unit of work (one article to
/// read a sidecar, one to hash-confirm a payload), and whatever the
/// reserved half goes unused carries into the next tick.
#[cfg(feature = "indexer")]
fn pesto_link_floor(tokens: f64) -> f64 {
    tokens / 2.0
}

#[cfg(feature = "indexer")]
pub(in crate::serve) fn spawn_pesto(daemon: &Arc<Daemon>, config: &std::path::Path) {
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
                Ok(c) => crate::nettools::scan_servers(&c),
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
    use super::probe7z::rar_probe_volumes;

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
pub(in crate::serve) async fn spot_pass(
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
                                "resolved {} spot NZBs: {} new cards, {} upgraded \
                                 existing releases, {} unusable, {} failed; \
                                 {} head articles checked, {} already gone",
                                sum.fetched,
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
pub(in crate::serve) async fn reclassify_pending_rows(
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

/// M31a retention prune and the query-planner statistics refresh - the
/// two pieces of index upkeep that run between passes on their own
/// clocks.
///
/// Throttled to once an hour (a kv timestamp) and skipped while a
/// download is active, so it never fights for the write lock during a
/// job. The stale-partial reaper runs whenever indexing is on; the age
/// prune only when retention is enabled AND a max-age window is set.
/// The caller owns the "indexing is on and maintenance is allowed"
/// guard.
#[cfg(feature = "indexer")]
/// One budgeted slice of the shatter fold per scan pass: merge dark
/// rows shattered by per-article poster randomization (and group
/// rotation) back into whole per-file releases. See
/// `Index::shatter_fold` for the census that sized this (97% of dark
/// rows) and the gates that keep it narrow. Runs whenever indexing
/// does - the artifact hurts every consumer (correlation, probes,
/// msgid joins, completeness), not just predb installs.
pub(in crate::serve) fn shatter_fold_pass(daemon2: &Arc<Daemon>) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs() as i64)
        .unwrap_or(0);
    const FOLD_BUDGET: std::time::Duration = std::time::Duration::from_secs(1);
    if let Some((g, n, _)) = daemon2.with_index_mut(|ix| {
        // An error here must be SAID: a silent Err loops forever
        // looking exactly like "nothing to do".
        match ix.shatter_fold(now, FOLD_BUDGET) {
            Ok(t) => Some(t),
            Err(e) => {
                warn!(target: "index", "shatter fold error: {e}");
                None
            }
        }
    }) && g > 0
    {
        info!(
            target: "index",
            "shatter fold: {n} scattered row(s) folded into {g} posting(s)"
        );
    }
}

pub(in crate::serve) async fn retention_and_statistics(daemon2: &Arc<Daemon>) {
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
            if std::time::Instant::now() >= pass_end || !daemon2.index_maintenance_ok() {
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
            let _ = ix.search_log_prune(
                crate::serve::SEARCH_LOG_DAYS * 86_400,
                crate::serve::SEARCH_LOG_ROWS,
                now,
            );
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
pub(in crate::serve) async fn picker_index_backfill(daemon2: &Arc<Daemon>) {
    let Some(name) = daemon2.with_index(|ix| ix.missing_picker_index()) else {
        return;
    };
    if !daemon2.index_maintenance_ok() {
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
pub(in crate::serve) async fn evict_between_passes(daemon2: &Arc<Daemon>) {
    {
        let d3 = daemon2.clone();
        // The prune is synchronous SQLite work on a shared
        // connection - off the async worker.
        let outcome = tokio::task::spawn_blocking(move || d3.evict_pass()).await;
        // Record a trim that actually removed something, so the
        // DB card can say what happened to the releases that
        // disappeared. `Nothing`/`Unavailable` removed nothing
        // and must not overwrite the last real answer.
        if let Ok(crate::serve::daemon::EvictOutcome::Ran(rep, _)) = &outcome
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
