use super::*;

// The background tasks that came out whole under TODO 106. Each child is
// `use super::*;` over this module, and everything it exposes is
// re-exported below, so `tasks::spawn_x(..)` still names the same thing
// it did when all of it lived in one file.
// enrich and indexer are gated whole: every item in them already carried
// `#[cfg(feature = "indexer")]`, so without the feature they are empty
// modules and both the module and its glob read as unused imports.
#[cfg(feature = "indexer")]
mod enrich;
#[cfg(feature = "indexer")]
pub(in crate::serve) mod indexer;
#[cfg(feature = "indexer")]
mod scoreboard;
// The §77 post-health preflight, whole: the probe loop, its stand-down
// predicates and its sampler. `download_idle` and `busy_tail` are read
// back here by `spawn_memory_trim`, so the glob comes back in.
mod health;
// The §76 queue-row media prober, whole: both passes and the latch.
mod media;
// The download runner's guard ladder, hub hand-over and tail accounting,
// moved out of `spawn_download_worker` under the fn ceiling (TODO 106).
mod runner;
mod worker;
use runner::*;
pub(super) use worker::spawn_download_worker;
mod stall;
mod tuner;
mod watchfolder;
// The two leaf blocks of `spawn_index_scan`'s pass loop, moved out under
// the fn ceiling (TODO 106); gated like enrich because every item in it
// already was.
#[cfg(feature = "indexer")]
mod index_scan;
#[cfg(feature = "indexer")]
use index_scan::*;

#[cfg(feature = "indexer")]
pub(super) use enrich::*;
pub(super) use health::*;
#[cfg(feature = "indexer")]
pub(super) use indexer::*;
pub(super) use media::*;
#[cfg(feature = "indexer")]
pub(super) use scoreboard::*;
pub(crate) use stall::*;
pub(super) use tuner::*;
pub(crate) use watchfolder::*;

/// Daily ceiling on indexer-confirm suggestion lookups. Each candidate
/// costs one API hit and (on a listing match) one grab against the
/// user's own account, so the ceiling is deliberately modest - the
/// STRONG-first pick order means the budget spends itself on the
/// likeliest pairs. It lives out here rather than in `indexer` because
/// the settings setter quotes it in the switch-on line, and that setter
/// is compiled with or without the `indexer` feature.
pub(in crate::serve) const CONFIRM_PER_DAY: u32 = 24;

/// M14g scheduler: JSON list of {days, time, action, value} entries,
/// evaluated once per minute in the machine's LOCAL timezone. On
/// startup the whole week is re-evaluated so a restart lands in the
/// state the schedule implies. Entries live in the daemon (settings
/// UI can replace them); a UI-saved schedule wins over --schedule.
pub(super) fn spawn_scheduler(
    daemon: &Arc<Daemon>,
    settings_path: &std::path::Path,
    schedule: &Option<PathBuf>,
) -> Result<()> {
    let saved_text = load_settings(settings_path)
        .get("schedule")
        .and_then(Value::as_str)
        .map(str::to_string);
    let text = match (saved_text, &schedule) {
        // Empty saved text = "no schedule" chosen in the UI.
        (Some(t), _) => (!t.is_empty()).then_some(t),
        (None, Some(path)) => Some(
            std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("--schedule {}: {e}", path.display()))?,
        ),
        (None, None) => None,
    };
    if let Some(text) = text {
        let entries = parse_schedule(&text).map_err(|e| anyhow::anyhow!("schedule: {e}"))?;
        let (paused, limit) = effective_state(&entries, local_minute_of_week());
        // Through the one mutator, so a timed pause restored from the
        // spool just above cannot outlive the schedule's own verdict
        // on the current hour. No running job here for the wind-down
        // to touch, so this is otherwise unchanged.
        if let Some(p) = paused {
            apply_action(
                daemon,
                if p {
                    SchedAction::Pause
                } else {
                    SchedAction::Resume
                },
            );
            info!(
                target: "schedule",
                "startup: {}",
                if p { "paused" } else { "resumed" }
            );
        }
        if let Some(l) = limit {
            daemon.set_speed_ceiling_from(l, "schedule");
            info!(target: "schedule", "startup: speedlimit {:.1} KB/s", l as f64 / 1e3);
        }
        *daemon.schedule.lock_ok() = entries;
        *daemon.schedule_text.lock_ok() = text;
    }
    let d = daemon.clone();
    tokio::spawn(async move {
        let mut last = local_minute_of_week();
        loop {
            // Half-minute tick so every minute boundary is seen promptly.
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            let now = local_minute_of_week();
            // DST fall-back (or a clock step) moves local time
            // BACKWARDS: the forward distance around the week would be
            // huge - resync silently instead of replaying the week.
            let forward = (now + WEEK_MINUTES - last) % WEEK_MINUTES;
            if forward > 8 * 60 {
                last = now;
                continue;
            }
            let entries = d.schedule.lock_ok().clone();
            while last != now {
                last = (last + 1) % WEEK_MINUTES;
                for e in entries.iter().filter(|e| e.fires_at(last)) {
                    info!(target: "schedule", "{:?}", e.action);
                    apply_action(&d, e.action.clone());
                }
            }
        }
    });
    Ok(())
}

/// §131 D3: write out what people searched for.
///
/// The whole point of the buffer this drains is that a search handler
/// never touches the index write connection (see serve/searchlog.rs),
/// so somebody off the query path has to do the writing. It is this
/// task rather than the index scan loop because that loop's interval
/// is a user setting - 15 minutes by default - and an hour of merged
/// counters would collapse genuinely separate searches into one
/// as-you-type prefix run.
///
/// A minute is short enough that the prefix collapse only ever eats
/// one person's typing, and cheap enough to be invisible: an idle
/// daemon takes one uncontended mutex and returns.
#[cfg(feature = "indexer")]
pub(super) fn spawn_search_log_writer(daemon: &Arc<Daemon>) {
    let d = daemon.clone();
    // The e2e that pins the four call sites has to see a flush land, and
    // a minute is a minute. Same shape as the other test seams: a debug
    // env override, clamped, documented in docs/ENVIRONMENT.md.
    let every = std::env::var("NZBFAST_SEARCH_LOG_FLUSH_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(60)
        .clamp(1, 3_600);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(every)).await;
            let d2 = d.clone();
            // The flush is synchronous SQLite (with_index_mut runs it
            // on blocking_db), so hand the whole thing to a blocking
            // thread rather than holding a tokio worker across it.
            // search_log_tick, not flush_search_log: TODO 166's
            // deferred clear is retried here, and it has to run even on
            // a tick whose buffer is empty - which, with recording
            // switched off, is every tick.
            let _ = tokio::task::spawn_blocking(move || d2.search_log_tick()).await;
        }
    });
}

/// §282 section C: the worker behind `Daemon::hunt_request`.
///
/// Notify-driven rather than periodic, because a terminal verdict is a
/// rare event and a poll that finds an empty queue every tick for weeks
/// is pure cost. `notify_one` stores a permit, so a request that lands
/// while the tick is already running is not lost: the loop comes
/// straight back around and drains it.
///
/// `spawn_blocking`: the search, the NZB fetch and the enqueue are all
/// synchronous, and each indexer call carries a 15 s ceiling, so this is
/// not tokio-worker work.
pub(super) fn spawn_hunt_worker(daemon: &Arc<Daemon>) {
    let d = daemon.clone();
    tokio::spawn(async move {
        loop {
            d.hunt.wake.notified().await;
            let d2 = d.clone();
            let _ = tokio::task::spawn_blocking(move || d2.hunt_tick()).await;
        }
    });
}

/// §96.5: bill the running download's per-server bytes into the usage
/// ledger every 30 s, instead of only at net-drain. The whole point is
/// crash safety for PAID bytes: block accounts span years, and the old
/// end-of-job-only billing forgot an entire run's spend if the daemon
/// died mid-job - the block then read fuller than it was. Delta-billed
/// through `flush_run_usage`, so the net-drain call bills only what the
/// last tick had not; a tick with no download (pool_live is None) costs
/// two lock peeks and no disk write.
pub(super) fn spawn_usage_flush(daemon: &Arc<Daemon>) {
    let d = daemon.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            d.flush_run_usage();
        }
    });
}

/// Issue #38 follow-up: the debounced queue saver behind
/// `save_queue_soon`. Waits for a dirty mark, sits out a short debounce
/// window so a completion's burst of saves (postproc submit, park, the
/// finalize tail) coalesces into one, then writes on the blocking pool -
/// `save_queue` serializes every job and fsyncs twice, which is not
/// tokio-worker work at 14,500 jobs.
///
/// A mark that lands mid-write is not lost: `notify_one` stores a permit,
/// so the loop comes straight back around and writes again. Wind-down's
/// own synchronous `save_queue` flushes whatever a kill would have caught
/// pending.
pub(super) fn spawn_queue_saver(daemon: &Arc<Daemon>) {
    let d = daemon.clone();
    d.saver_armed.store(true, Ordering::Relaxed);
    tokio::spawn(async move {
        loop {
            d.save_wake.notified().await;
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            if d.save_soon.swap(false, Ordering::AcqRel) {
                let d2 = d.clone();
                let _ = tokio::task::spawn_blocking(move || d2.save_queue()).await;
            }
        }
    });
}

/// Post-job memory trim. A finished job frees its pipeline buffers,
/// but the allocator keeps those pages resident for reuse - which
/// reads as a leak on the dashboard's RAM line. Once the daemon has
/// been idle for a full minute after a download, hand the retained
/// pages back to the OS; the next download simply faults fresh ones
/// in. One trim per idle period, none at startup.
pub(super) fn spawn_memory_trim(daemon: &Arc<Daemon>) {
    let d = daemon.clone();
    tokio::spawn(async move {
        // The download-end stamp the last trim covered. Arming on the
        // stamp rather than on catching `started_at` mid-flight matters:
        // the old 15 s sampler never SAW a job shorter than a tick, so a
        // fast job's retained buffers were never trimmed. Boot's initial
        // stamp counts as covered - nothing worth trimming before the
        // first job.
        let mut covered = *d.last_download_end.lock_ok();
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
            // `download_idle`, not `started_at` alone: the stamp lands
            // when the NETWORK drains, and repair/extract/move run on
            // the post-processing lane after it (a short download with a
            // long repair is the shape where the tail outlasts the
            // download by minutes). The sidecar prefetch is the other
            // half of the house idle test. Nothing is lost by waiting -
            // `covered` only advances when the trim actually fires, so
            // the next tick past the tail still collects.
            if !download_idle(&d) || busy_tail(&d) {
                continue;
            }
            let end = *d.last_download_end.lock_ok();
            if end != covered && end.elapsed() >= std::time::Duration::from_secs(60) {
                covered = end;
                let before = nzbkit::mem::dashboard_rss().unwrap_or(0);
                // mimalloc (macOS + Linux): force a collection - the
                // call that actually offers the pages back. On macOS the
                // system allocator's pressure_relief is a measured no-op;
                // on Linux mimalloc owns the heap so glibc malloc_trim
                // below no longer sees the pipeline arenas.
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                unsafe {
                    libmimalloc_sys::mi_collect(true)
                };
                nzbkit::mem::trim(); // glibc malloc_trim; no-op under mimalloc
                let after = nzbkit::mem::dashboard_rss().unwrap_or(0);
                let freed = before.saturating_sub(after);
                // Always visible under NZBFAST_LOG=mem=debug: the trim
                // that measured nothing is the interesting one when a
                // big footprint fails to come down (live memory, not
                // allocator retention - the collector cannot help).
                tracing::debug!(
                    target: "mem",
                    "idle trim: footprint {} -> {} MB",
                    before >> 20,
                    after >> 20
                );
                if freed >= 64 << 20 {
                    info!(
                        target: "mem",
                        "idle after download - returned {:.0} MB of retained buffers to the OS",
                        freed as f64 / 1e6
                    );
                }
            }
        }
    });
}

/// M14g3 auto-speed governor: a dedicated probe connection measures
/// DATE round-trips to the first ENABLED server at 1 Hz. Base RTT = 10-minute
/// sliding minimum; queueing delay = smoothed − base. While a download
/// runs (and the toggle is on) each sample drives one AIMD step of the
/// shared RateLimit, under the user/schedule ceiling. One extra NNTP
/// connection is the entire cost.
pub(super) fn spawn_auto_speed(daemon: &Arc<Daemon>, config: &std::path::Path) {
    let d = daemon.clone();
    let config = config.to_path_buf();
    tokio::spawn(async move {
        use nzbkit::nntp::Connection;
        let mut window: VecDeque<(Instant, u64)> = VecDeque::new();
        let mut smoothed: f64 = 0.0;
        loop {
            if !d.auto_speed.load(Ordering::Relaxed) {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
            // `enabled`, not `first`: this probe holds a connection for
            // the life of the daemon, so picking the raw `servers[0]`
            // parked a permanent socket on an account the user had
            // switched off whenever the disabled entry sorted first -
            // the same hole `load_server` carried into the 23 Aug 2026
            // incident, on a lane that never lets go.
            let server = match nzbkit::config::Config::load(&config) {
                Ok(c) => c.servers.into_iter().find(|s| s.enabled),
                Err(_) => None,
            };
            let Some(server) = server else {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                continue;
            };
            let Ok((mut conn, _)) = Connection::connect(&server).await else {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            };
            loop {
                if !d.auto_speed.load(Ordering::Relaxed) {
                    conn.quit().await;
                    break;
                }
                let t0 = Instant::now();
                let ok = tokio::time::timeout(std::time::Duration::from_secs(5), conn.exec("DATE"))
                    .await;
                let rtt = t0.elapsed().as_millis().max(1) as u64;
                match ok {
                    Ok(Ok(_)) => {
                        let now = Instant::now();
                        window.push_back((now, rtt));
                        while window
                            .front()
                            .is_some_and(|(t, _)| now.duration_since(*t).as_secs() > 600)
                        {
                            window.pop_front();
                        }
                        let base = window.iter().map(|(_, r)| *r).min().unwrap_or(rtt);
                        smoothed = if smoothed == 0.0 {
                            rtt as f64
                        } else {
                            smoothed * 0.7 + rtt as f64 * 0.3
                        };
                        let downloading = d.started_at.lock_ok().is_some();
                        if downloading {
                            let delay = (smoothed as u64).saturating_sub(base);
                            let cap = auto_speed_step(
                                delay,
                                AUTO_SPEED_TARGET_MS,
                                d.hub.rate.get(),
                                d.speed_ceiling.load(Ordering::Relaxed),
                            );
                            d.hub.rate.set(cap);
                        }
                    }
                    _ => {
                        // Timeout under our own load IS the congestion
                        // signal at its loudest - back off before
                        // reconnecting the probe.
                        let downloading = d.started_at.lock_ok().is_some();
                        if downloading {
                            let cap = auto_speed_step(
                                u64::MAX,
                                AUTO_SPEED_TARGET_MS,
                                d.hub.rate.get(),
                                d.speed_ceiling.load(Ordering::Relaxed),
                            );
                            d.hub.rate.set(cap);
                        }
                        break;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    });
}

/// Newsgroup discovery catalogue: load the on-disk cache off the hot
/// path so mode=groups answers instantly after a restart (parsing
/// ~100k TSV lines is tens of ms, but not worth blocking startup on).
/// Then keep it fresh unattended: no cache on first run = fetch now;
/// after that, a refetch once a day picks up newly created groups
/// (the browser's "Newly added" chip and saved-search notices feed
/// off the first_seen stamps that diff produces).
#[cfg(feature = "indexer")]
pub(super) fn spawn_group_catalog(daemon: &Arc<Daemon>, config: &std::path::Path) {
    let d = daemon.clone();
    let config = config.to_path_buf();
    tokio::spawn(async move {
        let d2 = d.clone();
        let _ = tokio::task::spawn_blocking(move || {
            if let Some(cat) = crate::groups::Catalog::load(&d2.groups_cache_path()) {
                info!(target: "groups", "catalogue cache: {} groups", cat.groups.len());
                *d2.group_catalog.lock_ok() = Some(Arc::new(cat));
            }
            if let Some(st) = crate::groupstats::StatsCache::load(&d2.groupstats_cache_path()) {
                info!(target: "groups", "sampled profiles: {} groups", st.map.len());
                *d2.group_stats.lock_ok() = Arc::new(st);
            }
        })
        .await;
        // A cached catalogue is all the interests picked in the setup
        // wizard need, so resolve them before the 20 s settle: a user
        // who just chose "sport" should find it scanning, not waiting.
        // With no cache the fetch below finishes the job. Nothing to
        // resolve while the indexer is off - the switch re-runs this
        // when it is turned on.
        if !d.indexer_off() {
            apply_interests(&d);
        }
        // Let startup settle before the first-run fetch.
        tokio::time::sleep(std::time::Duration::from_secs(20)).await;
        // Burst state, deliberately local: it lives exactly as long as
        // this task, so "one burst window per process" needs no field
        // on Daemon and no way to be reset from outside.
        let burst_started = std::time::Instant::now();
        let mut burst_samples = 0usize;
        loop {
            // The catalogue and the group profiles exist to answer
            // "what could I index?", so the master switch takes both
            // - together they are a 111k-group LIST over NNTP plus a
            // rolling sample of the busiest groups, which is real
            // provider traffic on behalf of a browser nobody can
            // open while the indexer is off.
            //
            // The orphan sweep below is NOT indexer work (it tidies
            // the download spool), so it keeps its hourly tick and
            // this stands down around it rather than instead of it.
            // ...and offline takes both for the same reason the master
            // switch does, one step further out: a 111k-group LIST and a
            // rolling OVER sample are provider traffic, and offline says
            // there is none. Measured on the live daemon 11 Aug 2026:
            // "[groups] catalogue fetched: 111332 groups" at 15:51,
            // twelve hours into an offline the operator had set to hand
            // the account to another machine. The explicit refresh in
            // the settings UI is left alone - `kick_group_fetch`'s API
            // callers are a click, not a clock.
            let indexing = !d.indexer_off() && !d.offline.load(Ordering::Relaxed);
            let age = {
                let cat = d.group_catalog.lock_ok();
                cat.as_ref().map(|c| epoch_secs() as i64 - c.fetched_at)
            };
            if indexing && age.is_none_or(|a| a >= 24 * 3600) {
                kick_group_fetch(&d, config.clone());
            }
            let profiled = d.group_stats.lock_ok().map.len();
            let burst = indexing
                && should_burst_profiles(
                    profiled,
                    burst_samples,
                    burst_started.elapsed().as_secs(),
                );
            let started = if indexing {
                sample_top_groups(&d, &config, burst).await
            } else {
                0
            };
            if burst {
                burst_samples += started;
            } else {
                // Hourly cadence only: an orphan sweep is a directory
                // walk, and there is nothing for it to find during the
                // first hour of an install anyway.
                sweep_orphan_spool_nzbs(&d);
                // Same tick, same reasoning, and the same grace period.
                // Not a startup-only sweep: an upload staging file is
                // orphaned by a partial write as readily as by a crash
                // (an ENOSPC write leaves one behind on a daemon that
                // never restarts), and not one of TODO 166's admin legs
                // either - those block the caller on the index write
                // mutex to do their work, and this one wants neither the
                // index nor a person pressing anything.
                sweep_abandoned_art_staging(&d);
            }
            let nap = if burst { BURST_TICK_SECS } else { 3600 };
            tokio::time::sleep(std::time::Duration::from_secs(nap)).await;
        }
    });
}

/// M12: continuous OVER scanning - incremental per group (high-water
/// marks in the index db make re-scans cheap). Always spawned: the
/// group list / interval / backfill are live settings read each cycle,
/// so indexing can be switched on from the dashboard.
#[cfg(feature = "indexer")]
pub(super) fn spawn_index_scan(
    daemon: &Arc<Daemon>,
    config: &std::path::Path,
    index_db: &std::path::Path,
    index_pass_gate: &Arc<tokio::sync::Mutex<()>>,
) {
    // Owned: the scan task outlives this call and reopens the db by path.
    let index_db = index_db.to_path_buf();
    let config = config.to_path_buf();
    let db = index_db.to_path_buf();
    let daemon2 = daemon.clone();
    let index_pass_gate = index_pass_gate.clone();
    tokio::spawn(async move {
        // What this loop last said it was standing down for, and when.
        // Deliberately local: it lives exactly as long as the task, and
        // nothing outside may reset it.
        //
        // The 11 Aug 2026 case this exists for: the loop went quiet at
        // 03:25 and was still quiet fourteen hours later, with nothing
        // in the log after the per-group lines and nothing in it ever
        // again. `[predb]` writes every minute, so the file looked
        // alive; the only honest check was the index's own newest row.
        // A stand-down that lasts hours has to keep saying so.
        let mut standdown: Option<(&'static str, std::time::Instant)> = None;
        const STANDDOWN_RESTATE_SECS: u64 = 3600;
        loop {
            // A pass takes min(connections/par, 5) NNTP connections
            // PER concurrent group - 15 of a 20-connection account at
            // the default parallelism - plus SQLite writes on the same
            // box the download is using. Re-check every 5 s so
            // indexing resumes promptly when the queue drains.
            //
            // The two sources are switched independently, so this
            // waits only while BOTH are stopped, and each leg below
            // re-asks for itself. A spots-only install runs this
            // loop with an empty group list.
            let idx_reason = daemon2.indexing_pause_reason();
            let scan_groups = idx_reason.is_none();
            // The index reason is the one named: the two differ only in
            // their own master switch, and this loop is the index scan.
            if let Some(reason) = idx_reason.filter(|_| daemon2.spot_pause_reason().is_some()) {
                // Say it on the transition, then restate it hourly. One
                // line an hour is nothing next to the alternative:
                // fourteen hours in which the only truthful signal was a
                // SQL query against `releases.first_seen` that nobody
                // thinks to run, because the log looks fine.
                let say = match standdown {
                    Some((was, since)) => {
                        was != reason || since.elapsed().as_secs() >= STANDDOWN_RESTATE_SECS
                    }
                    None => true,
                };
                if say {
                    let held = standdown
                        .filter(|(was, _)| *was == reason)
                        .map(|(_, since)| {
                            format!(", {} min so far", since.elapsed().as_secs() / 60)
                        })
                        .unwrap_or_default();
                    info!(
                        target: "index",
                        "indexing and spots both standing down: {}{held}",
                        Daemon::pause_phrase(reason)
                    );
                    // Keep the ORIGINAL instant across a restatement of
                    // the same reason - the elapsed time is the whole
                    // point of the restatement, and resetting it here
                    // would print "60 min so far" forever.
                    let since = standdown
                        .filter(|(was, _)| *was == reason)
                        .map_or_else(std::time::Instant::now, |(_, since)| since);
                    standdown = Some((reason, since));
                }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
            if let Some((was, since)) = standdown.take() {
                info!(
                    target: "index",
                    "indexing resumed after {} min ({})",
                    since.elapsed().as_secs() / 60,
                    Daemon::pause_phrase(was)
                );
            }
            let groups = if scan_groups {
                daemon2.index_groups.lock_ok().clone()
            } else {
                Vec::new()
            };
            let backfill = daemon2.index_backfill.load(Ordering::Relaxed);
            let deepen = daemon2.index_deepen.load(Ordering::Relaxed);
            let coverage = daemon2.index_coverage.load(Ordering::Relaxed);
            let max_age = daemon2.index_max_age_secs.load(Ordering::Relaxed);
            let gates = daemon2.index_gates.lock_ok().1.clone();
            // 24D: custom categories, sampled per pass like gates so
            // a settings change applies from the next pass on.
            let cats = daemon2.custom_categories.read_ok().clone();
            let index_pass = index_pass_gate.lock().await;
            // A job may have started while this task waited behind
            // the tip watcher or VACUUM. The foreground worker raises
            // its guard before waiting for this same gate, so this
            // recheck hands the gate over without starting a pass.
            // Both legs are re-asked: whatever started applies to
            // both, and a pass with nothing left to do should give
            // the gate straight back.
            let scan_groups = scan_groups && daemon2.indexing_pause_reason().is_none();
            let scan_spots = daemon2.spot_pause_reason().is_none();
            if !scan_groups && !scan_spots {
                drop(index_pass);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
            let groups = if scan_groups { groups } else { Vec::new() };

            // Spotnet first - see `spot_pass` for why it leads.
            if scan_spots {
                spot_pass(&daemon2, &config, &db).await;
            }
            reclassify_pending_rows(&daemon2, &db, &cats).await;
            // One-off deep-backfill override (index_scan_now&value=N).
            // Taking it with a swap consumes it, so a pass preempted
            // by a download that starts seconds after the user clicks
            // dropped the request on the floor: the deep leg never
            // ran, nothing said so, and the next passes went back to
            // normal depth. Remember it and put it back if this pass
            // does not get to finish.
            let deep_taken = daemon2.scan_deep.swap(0, Ordering::Relaxed);
            let deep = (deep_taken > 0).then_some(deep_taken);
            let preempted = Arc::new(AtomicBool::new(false));
            // M30 turbo: an idle line belongs to the scanner - passes
            // that start with no download active fan out deeper
            // (per-group conn clamp 10 vs 5; the account-limit ÷
            // parallelism budget still applies).
            let turbo = daemon2.started_at.lock_ok().is_none();
            // M28: groups scan CONCURRENTLY (they were strictly
            // sequential - wall-clock scaled with group count). Each
            // task gets its own connection into the shared WAL db;
            // ingest transactions are per-chunk so writer-lock waits
            // stay inside the 10s busy timeout. The per-scan NNTP
            // connection budget divides the account limit by the
            // parallelism (`share`), so N groups never exceed it.
            let par = (daemon2.index_scan_par.load(Ordering::Relaxed) as usize)
                .clamp(1, 8)
                .min(groups.len().max(1));
            let sem = Arc::new(tokio::sync::Semaphore::new(par));
            daemon2.scan_active.store(true, Ordering::Relaxed);
            let _busy = daemon2.busy.hold("indexing");
            let mut set = tokio::task::JoinSet::new();
            let knobs = PassKnobs {
                backfill,
                max_age,
                deep,
                deepen,
                par,
                turbo,
                coverage,
            };
            for g in groups.clone() {
                let sem = sem.clone();
                let config = config.clone();
                let db = db.clone();
                let daemon3 = daemon2.clone();
                let gates = gates.clone();
                let cats = cats.clone();
                let preempted2 = preempted.clone();
                set.spawn(scan_group(
                    g, sem, config, db, daemon3, gates, cats, preempted2, knobs,
                ));
            }
            while set.join_next().await.is_some() {}
            daemon2.scan_active.store(false, Ordering::Relaxed);
            // Hand the one-off deep request back if this pass was cut
            // short before it could honour it. fetch_max so a newer
            // (or deeper) request made meanwhile is never clobbered.
            if deep_taken > 0 && preempted.load(Ordering::Relaxed) {
                daemon2.scan_deep.fetch_max(deep_taken, Ordering::Relaxed);
                info!(
                    target: "index",
                    "deep backfill of {deep_taken} was interrupted - \
                     it stays queued for the next pass"
                );
            }
            // A job that interrupted this pass is waiting for the
            // gate. Skip every post-pass SQLite task and release it
            // immediately; indexing resumes from its marks later.
            //
            // Asked BETWEEN the stages below, not just once ahead of
            // them, because the gate is held for the whole section and
            // the section is where the time goes. Every stage already
            // hands back the write MUTEX promptly - the reap slices at
            // one second, the fold is budgeted at one - but none of
            // them hands back the GATE, and the runner rendezvouses on
            // the gate. So a reap working through its 30 s pass budget
            // was, correctly and by design, holding a job the user had
            // just added: measured 16 Aug 2026, a watch-folder drop
            // landing in this section waited out the runner's whole
            // bound with nothing actually blocked. One check cannot
            // cover a section that runs for tens of seconds.
            //
            // Safe at every one of these points because each stage is
            // resumable by construction: the reap only stamps its
            // hourly clock when it runs out of rows, the fold and the
            // gapfill carry cursors, the title seeding is idempotent,
            // and eviction is a no-op unless it is switched on.
            //
            // `scan_groups &&` matters on a spots-only install: with
            // the indexer switched off this reason is permanently
            // "off", and short-circuiting on it would skip the
            // interval sleep at the bottom of the loop and re-scan
            // free.pt as fast as the server would answer. Every
            // post-pass task below is already a no-op with no groups.
            // Sweep 8, L7: a stand-down leaves the pass's writers
            // half-applied, so whatever the stats cache holds is stale
            // in the same way a completed pass's early snapshot was.
            // Expire it rather than recompute - the machine is standing
            // down for a download and owes it no table scan; the next
            // reader pays for a fresh answer.
            let waiting = || {
                let park = scan_groups && daemon2.indexing_pause_reason().is_some();
                if park {
                    daemon2.expire_index_stats();
                }
                park
            };
            if waiting() {
                drop(index_pass);
                continue;
            }
            // M30: fresh posts get titles rows (→ enrichment) right
            // after the pass that indexed them - a wall page view
            // used to be the only seeder.
            if !groups.is_empty() {
                let seeded = daemon2
                    .with_index(|ix| ix.seed_missing_titles(14, 500).ok())
                    .unwrap_or(0);
                if seeded > 0 {
                    info!(target: "wall", "seeded {seeded} new titles for enrichment");
                }
            }
            if waiting() {
                drop(index_pass);
                continue;
            }
            // A8: targeted gap-fill - re-hunt a few incomplete
            // releases' posting windows on the OTHER backbones.
            // Runs under the pass gate (the tip watcher stands
            // down), aborts between chunks the moment a download
            // starts, and skips entirely while one is active.
            let gapfill = daemon2.index_gapfill.load(Ordering::Relaxed) as u32;
            if gapfill > 0
                && coverage
                && !groups.is_empty()
                && daemon2.indexing_pause_reason().is_none()
            {
                gapfill_leg(&daemon2, &config, &db, gapfill).await;
            }
            if waiting() {
                drop(index_pass);
                continue;
            }
            // M31a retention prune + the planner-statistics refresh,
            // both on their own clocks inside.
            if !maintenance_slice(&daemon2, !groups.is_empty(), scan_spots, &waiting).await {
                drop(index_pass);
                continue;
            }
            if waiting() {
                drop(index_pass);
                continue;
            }
            evict_between_passes(&daemon2).await;
            // A4: the one exact stats recompute for the whole pass.
            //
            // Sweep 8, L7: this used to run immediately after group
            // ingest, which is BEFORE the pass's own remaining writers
            // - gap-fill adds rows, retention prunes them, the fold
            // rewrites shards, and the size cap evicts whole releases.
            // A pass that removed a known set left the dashboard and
            // the status endpoint reporting counts the just-finished
            // pass had already contradicted, and nothing invalidated
            // them until the 45 s TTL expired. The manual shrink/evict
            // endpoints have always invalidated explicitly; the pass's
            // own recompute simply ran too early. Last, so it describes
            // the database the pass leaves behind.
            crate::persist::blocking_db(|| daemon2.refresh_index_stats());
            drop(index_pass);
            // The chip covers the whole pass (scan + gapfill + prune),
            // never the interval sleep below.
            drop(_busy);
            let interval = daemon2.index_interval_secs.load(Ordering::Relaxed).max(30);
            // Interval sleep, cut short by mode=index_scan_now (a
            // notify during a pass leaves a permit - the next wait
            // returns at once, so a mid-pass click still lands).
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(
                    // Idle (nothing scanned): just re-check the
                    // setting soon. A spot pass IS work, so it waits
                    // out the real interval - the 15 s re-check would
                    // otherwise walk free.pt four times a minute.
                    if groups.is_empty() && !scan_spots { 15 } else { interval },
                )) => {}
                _ = daemon2.scan_now.notified() => {}
            }
        }
    });
}

/// M14k RSS poller. Feeds are a LIVE setting: initial list comes from
/// --feeds (file) with a UI-saved settings.json "feeds" key winning
/// over it; the single poller task re-reads daemon.feeds each pass,
/// so dashboard edits apply without a restart. New items that pass the
/// rules are fetched and enqueued (dupe detection then holds
/// ALTERNATIVEs). Seen-guids persist in the spool so restarts don't
/// re-grab history.
pub(super) fn spawn_rss_poller(
    daemon: &Arc<Daemon>,
    settings_path: &std::path::Path,
    feeds: &Option<PathBuf>,
) -> Result<()> {
    let mut feed_list: Vec<crate::rss::FeedConfig> = Vec::new();
    if let Some(feeds_path) = &feeds {
        feed_list = serde_json::from_slice(&std::fs::read(feeds_path)?)
            .map_err(|e| anyhow::anyhow!("parsing {}: {e}", feeds_path.display()))?;
    }
    let mut from_settings = false;
    if let Some(v) = load_settings(settings_path).get("feeds") {
        match serde_json::from_value(v.clone()) {
            Ok(l) => {
                feed_list = l;
                from_settings = true;
            }
            Err(e) => warn!(target: "rss", "ignoring saved feeds setting: {e}"),
        }
    }
    // TODO §20c: the id is the merge key a masked url is restored by, so
    // every feed needs one before the first `get_config` can ship a mask
    // - including every feed written before the field existed, which is
    // all of them. Minting is silent and changes nothing else about the
    // entry; persisting it is what makes the id STABLE, so the row the
    // browser saves against tomorrow is the row it saw today.
    //
    // Only when the list came from settings.json. A `--feeds` file is
    // the user's own, and settings.json WINS over it at every later
    // load - so writing the migrated list there would quietly promote a
    // one-off copy of that file into the authority and leave the user
    // editing a file nothing reads. Those feeds get ids in memory (the
    // masking round-trip works for the session either way) and persist
    // the first time the dashboard saves, which is the point at which
    // settings.json takes over anyway.
    if crate::rss::assign_feed_ids(&mut feed_list) && from_settings {
        save_settings(
            settings_path,
            &[(
                "feeds",
                serde_json::to_value(&feed_list).unwrap_or(json!([])),
            )],
        );
    }
    *daemon.feeds.lock_ok() = feed_list;
    // M35 pull-search indexers ride the same settings file, and the
    // daily usage counters survive a restart via the spool.
    if let Some(v) = load_settings(settings_path).get("indexers") {
        match serde_json::from_value(v.clone()) {
            Ok(l) => *daemon.indexers.lock_ok() = l,
            Err(e) => warn!(target: "indexer", "ignoring saved indexers setting: {e}"),
        }
    }
    if let Ok(b) = std::fs::read(daemon.spool.join("indexer-usage.json"))
        && let Ok(mut u) = serde_json::from_slice::<crate::newznab::Usage>(&b)
    {
        u.roll(unix_now());
        daemon.indexer_rt.lock_ok().usage = u;
    }
    let d = daemon.clone();
    tokio::spawn(async move {
        /// The RSS dedupe set: which guids have already been judged.
        ///
        /// Insertion-ordered alongside the set, and capped. It used to
        /// be a bare HashSet that never shrank under any
        /// configuration, and every single marked item re-serialised
        /// the WHOLE set and durably wrote it - `write_atomic` is
        /// write_all + sync_all + a directory fsync - so one poll cost
        /// O(items x every-guid-ever) of durable I/O. A feed producing
        /// a few hundred guids a day reaches a multi-MB file within a
        /// year, and from then on each new item costs a multi-MB
        /// rewrite plus two fsyncs: real flash wear on a NAS or Pi
        /// spool. Now it evicts the oldest and writes once per pass,
        /// the same accumulate-then-write shape the watchlist watcher
        /// in this file already uses.
        ///
        /// Evicting the oldest, never clearing: a cleared set lets old
        /// items back through the dedupe and re-grabs history, which
        /// is the one thing this file exists to prevent. The cap is
        /// far wider than any rolling feed window.
        /// Keys are `<feed scope>\u{1}<guid>`, not the bare guid.
        ///
        /// An RSS `guid` and an Atom `id` are publisher-local arbitrary
        /// strings, and one global set meant two feeds publishing
        /// different items under guid `123` suppressed each other -
        /// including across restarts, so a rule-rejected item in feed A
        /// permanently hid an accepted item in feed B (Codex sweep 12 Aug
        /// F12).
        ///
        /// Reads still fall back to the bare guid, because every entry
        /// written before this change is unscoped and re-evaluating them
        /// would re-grab whatever is still inside each feed's rolling
        /// window. Legacy entries therefore keep suppressing (the old
        /// behaviour, cross-feed collisions and all) and age out of the
        /// LRU, while every new decision is per feed.
        struct SeenGuids {
            set: std::collections::HashSet<String>,
            order: std::collections::VecDeque<String>,
            dirty: bool,
        }
        impl SeenGuids {
            const MAX: usize = 20_000;
            fn key(scope: &str, guid: &str) -> String {
                format!("{scope}\u{1}{guid}")
            }
            fn contains(&self, scope: &str, guid: &str) -> bool {
                self.set.contains(&Self::key(scope, guid)) || self.set.contains(guid)
            }
            fn insert(&mut self, scope: &str, guid: &str) {
                let guid = &Self::key(scope, guid);
                if !self.set.insert(guid.to_string()) {
                    return;
                }
                self.order.push_back(guid.to_string());
                while self.order.len() > Self::MAX {
                    if let Some(old) = self.order.pop_front() {
                        self.set.remove(&old);
                    }
                }
                self.dirty = true;
            }
            /// The on-disk form: a JSON array, byte-compatible with
            /// what the bare HashSet wrote, so an existing
            /// rss-seen.json loads unchanged - it just gains an order.
            fn take_dirty(&mut self) -> Option<Vec<u8>> {
                if !std::mem::take(&mut self.dirty) {
                    return None;
                }
                serde_json::to_vec(&self.order).ok()
            }
        }
        let seen_path = d.spool.join("rss-seen.json");
        let loaded: Vec<String> = std::fs::read(&seen_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let seen = Arc::new(Mutex::new(SeenGuids {
            set: loaded.iter().cloned().collect(),
            order: loaded.into(),
            dirty: false,
        }));
        // Per-feed next-poll deadlines, keyed by url (a removed feed's
        // entry just goes stale; a re-added one polls immediately).
        let mut due: std::collections::HashMap<String, Instant> = std::collections::HashMap::new();
        loop {
            let feed_list = d.feeds.lock_ok().clone();
            // §G: forget the health of feeds that are no longer
            // configured, so a removed-and-re-added url starts clean and
            // the map cannot grow across a long-running daemon.
            {
                let live: std::collections::HashSet<&str> =
                    feed_list.iter().map(|f| f.url.as_str()).collect();
                d.feed_health
                    .lock_ok()
                    .retain(|u, _| live.contains(u.as_str()));
            }
            for feed in feed_list {
                let now = Instant::now();
                if due.get(&feed.url).is_some_and(|t| *t > now) {
                    continue;
                }
                due.insert(
                    feed.url.clone(),
                    now + std::time::Duration::from_secs(feed.interval_secs.max(60)),
                );
                let polled = tokio::task::spawn_blocking({
                    let url = feed.url.clone();
                    move || {
                        // parse_feed_checked, not parse_feed: an HTTP
                        // 200 that is not a feed (the login page a
                        // revoked apikey gets) has to reach the failure
                        // arm below, not be recorded as a healthy feed
                        // with nothing new (Codex sweep 2, 3 Aug ML1).
                        let body = fetch_url(&url)?;
                        // The addresses the FEED answered from travel
                        // with its items: an item link is bound to the
                        // feed as an origin, and a name that resolved
                        // publicly here may resolve to the LAN by the
                        // time the grab runs (M9).
                        let origin = SourceOrigin::witnessed(&url, body.addrs);
                        crate::rss::parse_feed_checked(&String::from_utf8_lossy(&body.bytes))
                            .map(|items| (items, origin))
                            .map_err(|e| anyhow::anyhow!("{url}: {e}"))
                    }
                })
                .await;
                // §G: what this poll did, recorded per feed. Every one of
                // these arms used to collapse to an empty list, so a
                // revoked apikey, a 403, a dead host and a feed with
                // genuinely nothing new were the same event to everyone
                // downstream - including the user, whose settings row
                // said nothing either way.
                let mut feed_origin = SourceOrigin::default();
                let items = match polled {
                    Ok(Ok((items, origin))) => {
                        d.feed_health.lock_ok().insert(
                            feed.url.clone(),
                            crate::rss::FeedHealth::ok(unix_now(), items.len()),
                        );
                        feed_origin = origin;
                        items
                    }
                    Ok(Err(e)) => {
                        // redact_url_creds, always: a feed url essentially
                        // always embeds the indexer's apikey, and both
                        // ureq's Display and fetch_url's own bails lead
                        // with the url they were handed. This string goes
                        // to the log ring AND to the settings row.
                        let h = crate::rss::FeedHealth::failed(
                            unix_now(),
                            &e.to_string(),
                            redact_url_creds,
                        );
                        warn!(target: "rss", "feed poll failed: {}", h.last_error);
                        d.feed_health.lock_ok().insert(feed.url.clone(), h);
                        Vec::new()
                    }
                    Err(e) => {
                        // The blocking task itself died (panic, or a
                        // runtime shutting down). Nothing about the feed
                        // is known; say that rather than "no items".
                        let h = crate::rss::FeedHealth::failed(
                            unix_now(),
                            &format!("the poll did not finish: {e}"),
                            redact_url_creds,
                        );
                        warn!(target: "rss", "feed poll task failed: {}", h.last_error);
                        d.feed_health.lock_ok().insert(feed.url.clone(), h);
                        Vec::new()
                    }
                };
                // Is this feed still the one we were told to poll?
                //
                // The snapshot above predates a network fetch that can take
                // most of a minute, and everything below acts on that
                // snapshot's authority: its rules decide, its category is
                // stamped, its enclosure is fetched with the user's
                // credentials and the result is enqueued. Deleting the feed
                // or tightening its rules in that window used to change
                // none of it (Codex sweep 12 Aug F6b).
                //
                // Re-read rather than trusted, and re-read AGAIN after the
                // enclosure fetch below, because that is a second await.
                let fp = feed.fetch_fingerprint();
                let authorized = || {
                    d.feeds
                        .lock_ok()
                        .iter()
                        .any(|f| f.fetch_fingerprint() == fp)
                };
                if !items.is_empty() && !authorized() {
                    info!(
                        target: "rss",
                        "a feed was removed or changed while it was being polled - \
                         discarding that poll's {} item(s)",
                        items.len()
                    );
                    continue;
                }
                let scope = feed.scope_key();
                for it in items {
                    if seen.lock_ok().contains(&scope, &it.guid) {
                        continue;
                    }
                    // In memory only; the pass flushes once at the end.
                    let mark_seen = |guid: &str| seen.lock_ok().insert(&scope, guid);
                    let judged = crate::rss::rules_judge(&feed.rules, &it);
                    if !judged.accept {
                        // A rules reject is final for this guid.
                        mark_seen(&it.guid);
                        continue;
                    }
                    // §129 2d: the deciding Accept rule's own filing
                    // wins over the feed's; -100 stays "the default".
                    let category = judged
                        .opts
                        .category
                        .clone()
                        .unwrap_or_else(|| feed.category.clone());
                    let priority = judged.opts.priority.unwrap_or(-100);
                    info!(
                        target: "rss",
                        "grabbing {} ({:.2} GB)",
                        it.title,
                        it.size as f64 / 1e9
                    );
                    let link = it.link.clone();
                    // fetch_url_from, not fetch_url: the item link is
                    // whatever the FEED's body said, and the feed is the
                    // origin it is allowed to point into. Same rule the
                    // newznab enclosure grabs follow (M12) - a feed may
                    // redirect a grab to a public sibling host, but
                    // never to a private address it does not own, nor to
                    // one its own name only started answering from after
                    // the poll (M9).
                    let origin = feed_origin.clone();
                    let nzb =
                        tokio::task::spawn_blocking(move || fetch_url_from(&link, &origin)).await;
                    // The second await, so the second recheck: a feed
                    // revoked while its enclosure was downloading must not
                    // enqueue, and must not leave a seen marker either -
                    // the item was never judged by the rules in force.
                    if !authorized() {
                        info!(
                            target: "rss",
                            "a feed was removed or changed while {} was being fetched - \
                             not enqueuing it",
                            it.title
                        );
                        break;
                    }
                    // The guid is marked seen only AFTER the grab
                    // sticks: marking before the fetch meant one
                    // transient 503 permanently dropped the release
                    // (it scrolls off the rolling feed unretried).
                    match nzb {
                        Ok(Ok(fetched)) => {
                            match d.enqueue_fetched(
                                &fetched,
                                &format!("{}.nzb", it.title),
                                &category,
                                priority,
                                None,
                                None,
                                0,
                                // The feed's own name, so history says
                                // WHICH feed grabbed this.
                                // REDACTED at the store: an RSS feed URL
                                // is `https://indexer/rss?apikey=…`, and
                                // `origin` is emitted verbatim by
                                // `job_json`, the SAB queue and history
                                // endpoints (which every *arr polls, and
                                // logs) and persisted to the history file.
                                // The dashboard already reduces an `rss:`
                                // origin to its hostname; the API never
                                // got the same treatment.
                                &format!("rss:{}", redact_url_creds(&feed.url)),
                                false,
                            ) {
                                // Enqueue failures are content errors
                                // (bad NZB) - retrying can't help.
                                Err(e) => {
                                    warn!(target: "rss", "enqueue {}: {e}", it.title);
                                    mark_seen(&it.guid);
                                }
                                Ok(_) => mark_seen(&it.guid),
                            }
                        }
                        _ => warn!(
                            target: "rss",
                            // Strip the query string: Newznab enclosure URLs
                            // carry the indexer apikey, and this line fires on
                            // every flaky-indexer retry (secret into the logs).
                            "fetch failed (will retry next poll): {}",
                            it.link.split('?').next().unwrap_or("")
                        ),
                    }
                }
                // One durable write per feed pass, not one per item.
                // Still before the next feed is polled, so a crash
                // can lose at most the pass in flight - the same
                // exposure the per-item write had between items.
                if let Some(body) = seen.lock_ok().take_dirty() {
                    let _ = crate::persist::write_atomic(&seen_path, &body);
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
    });
    Ok(())
}

/// M23 watchlist watcher. The list is a live setting ("watchlist" in
/// settings.json); grab state persists in the spool so restarts don't
/// re-download what's already on disk. Each pass matches items
/// against the index the scan loop keeps fresh, so "as soon as it
/// appears in a watched group" means one scan interval + one watcher
/// tick at worst - and edits/check-now skip even that.
pub(super) fn spawn_watchlist_watcher(daemon: &Arc<Daemon>, settings_path: &std::path::Path) {
    if let Some(v) = load_settings(settings_path).get("watchlist") {
        match serde_json::from_value(v.clone()) {
            Ok(l) => *daemon.watchlist.lock_ok() = l,
            Err(e) => warn!(target: "watch", "ignoring saved watchlist setting: {e}"),
        }
    }
    let state_path = daemon.spool.join("watchlist-state.json");
    if let Some(v) = crate::persist::load_json_with_backup(&state_path) {
        match serde_json::from_value(v) {
            Ok(s) => *daemon.watch_state.lock_ok() = s,
            Err(e) => warn!(target: "watch", "ignoring {}: {e}", state_path.display()),
        }
    }
    let d = daemon.clone();
    tokio::spawn(async move {
        loop {
            // Sleep first: the initial index scan gets a head start.
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
                _ = d.watch_now.notified() => {}
            }
            // The watchlist has TWO legs since M35 phase 2: the
            // local index, and the user's third-party indexer
            // accounts. The built-in indexer's master switch closes
            // the first, so the pass only stands down when it would
            // have nothing left to ask - otherwise a watchlist that
            // runs entirely on external indexers would silently stop
            // because a feature it does not use was switched off.
            // watchlist_external_on(), never the raw bool: the stored
            // flag only counts once the user has answered, and until
            // then the answer is "yes if you have indexer accounts".
            // Reading the bool here stood the whole pass down for the
            // commonest indexer-off setup - accounts configured, the
            // checkbox never touched - while get_config told the
            // dashboard it was ticked, so the card looked armed and
            // "Check now" reported a check that never ran.
            let local = !d.indexer_off();
            if !local && !d.watchlist_external_on() {
                continue;
            }
            let d2 = d.clone();
            // SQLite matching + enqueue (and the calendar's TVmaze
            // refresh) are blocking work.
            let _ = tokio::task::spawn_blocking(move || {
                let _busy = d2.busy.hold("watchlist");
                // The calendar caches its episode lists in the index
                // database, so with no database every lookup looks
                // stale and it would re-fetch the same shows from
                // TVmaze every minute. Skip it rather than let it
                // run uncached; the pass itself does not need it.
                #[cfg(feature = "indexer")]
                if local {
                    watch_calendar_refresh(&d2);
                }
                watchlist_pass(&d2);
            })
            .await;
        }
    });
    #[cfg(feature = "indexer")]
    spawn_instant_recheck(daemon);
}

/// §74: the short re-check behind the instant path's completeness gate.
///
/// A watched release usually arrives before it has finished going up, and
/// the watchlist only grabs complete releases - so a match on an
/// incomplete post is parked here and asked again every
/// [`INSTANT_RECHECK_SECS`] until it completes or ages out to the
/// periodic pass. Nothing is ever concluded from a post staying
/// incomplete: missing articles mean "not yet", never "dead".
///
/// Cheap by construction: one indexed lookup per parked release, and the
/// loop does nothing at all while the map is empty, which is almost
/// always.
#[cfg(feature = "indexer")]
fn spawn_instant_recheck(daemon: &Arc<Daemon>) {
    let d = daemon.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(INSTANT_RECHECK_SECS)).await;
            let parked: Vec<(i64, i64)> = d
                .instant_pending
                .lock_ok()
                .iter()
                .map(|(id, at)| (*id, *at))
                .collect();
            if parked.is_empty() {
                continue;
            }
            let now = unix_now();
            let d2 = d.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let mut ready: Vec<String> = Vec::new();
                let mut done: Vec<i64> = Vec::new();
                for (id, first) in parked {
                    if now - first >= INSTANT_PENDING_SECS {
                        done.push(id);
                        continue;
                    }
                    // One read per parked release; `is_complete` is a
                    // primary-key lookup.
                    let complete = d2
                        .with_index_read(|ix| Some(ix.is_complete(id)))
                        .unwrap_or(false);
                    if complete {
                        done.push(id);
                        if let Some(name) = d2.with_index_read(|ix| ix.stem_by_id(id).ok()?) {
                            ready.push(name);
                        }
                    }
                }
                {
                    let mut pending = d2.instant_pending.lock_ok();
                    for id in done {
                        pending.remove(&id);
                    }
                }
                if !ready.is_empty() {
                    let names = ready.join(", ");
                    if d2.instant_kick(&ready, now) {
                        info!(target: "watch", "finished posting: {names} - checking the watchlist now");
                    }
                }
            })
            .await;
        }
    });
}

/// TODO §154: what the runner's no-servers guard learned about the
/// config this pass.
///
/// Three answers rather than two, because §156 item 7 found the guard
/// publishing "no server is configured" for a config it had never
/// managed to read. "Nothing to dial" and "no idea" both stand the guard
/// down, but only one of them may take a live hold back down again - see
/// `ServerProbe`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
enum ServerVerdict {
    /// At least one enabled server: there is something to dial.
    Dialable,
    /// The config was read and parsed, and lists no enabled server.
    /// The hold's condition, and the only one of the three.
    NoneEnabled,
    /// No answer: the config could not be read or parsed, or no probe
    /// has come back yet.
    #[default]
    Unknown,
}

/// TODO §154: has this box nothing at all to dial right now?
///
/// Strictly "zero ENABLED servers", which arrives in two shapes: a
/// config that loads and has every server disabled, and `servers: []`,
/// which the loader reports as the `NoServers` ERROR rather than an
/// empty list - that is this condition under another name, and it is the
/// exact error a download with no servers used to die on.
///
/// Every OTHER load failure is a different condition with different
/// reporting - a missing file, a torn write, a path typo - and the
/// runner already `continue`s past load errors elsewhere, so the two are
/// deliberately not folded together: an unreadable config leaves this
/// guard standing down and the download reports the real error instead
/// of a hold that blames a server list nobody could read.
///
/// §156 item 7: keeping that promise needs `load_no_fallback`. Plain
/// `Config::load` answers a missing file by going and finding the host's
/// SABnzbd ini, so a typo'd `--config` path came back as that other
/// application's server list - `NoServers` when SAB has none enabled,
/// which is this guard's own condition wearing the wrong face. Reading
/// only the operator's own file is also what keeps the guard off an
/// unrelated application's file it was otherwise re-parsing twice a
/// second, forever.
///
/// Blocking, and called only from the blocking pool - see `ServerProbe`.
///
/// Also returns the parsed config, because this is the one place the
/// runner's config is read OFF the runner. `reset_hub_for_job` needs
/// the server list for §96.5 block-account budgets and used to take it
/// with a synchronous `Config::load` on the runner itself, immediately
/// after this bounded probe had just protected the same read - so a
/// config path that stopped answering held the runner in that read with
/// a job already marked Downloading and no fetch task yet to cancel
/// (Codex sweep H, 13 Aug 2026). The healthy path costs nothing extra:
/// the parse this probe already did IS the snapshot, and only the
/// operator-file-missing case (where the loader searches for a SABnzbd
/// ini, which this probe deliberately does not) reads a second time.
fn server_verdict(config: &std::path::Path) -> (ServerVerdict, Option<nzbkit::config::Config>) {
    match nzbkit::config::Config::load_no_fallback(config) {
        Ok(c) if c.servers.iter().any(|s| s.enabled) => (ServerVerdict::Dialable, Some(c)),
        Ok(c) => (ServerVerdict::NoneEnabled, Some(c)),
        Err(nzbkit::config::ConfigError::NoServers) => (ServerVerdict::NoneEnabled, None),
        Err(_) => (
            ServerVerdict::Unknown,
            nzbkit::config::Config::load(config).ok(),
        ),
    }
}

/// How long the download runner waits for `index_pass_gate` before
/// starting the job anyway. The gate is a rendezvous, not a resource:
/// every holder (scan legs, spot legs, gapfill, tip watcher, VACUUM)
/// stands down on its own once the runner's `begin_index_job` guard is
/// visible, so a wait past a few seconds means one of them is stuck in
/// I/O against a peer that has gone mute. Waiting that out forever is
/// issue #38's silent-wedge shape wearing the runner's face: the job
/// sits in Downloading, HTTP answers, nothing is logged.
///
/// FIVE seconds, not the sixty this shipped with. The bound was set on
/// the reasoning that a lane stands down inside its 100 ms preemption
/// poll, so only a wedged one could ever reach it and the wait would
/// therefore never be paid in practice. Measured on a live daemon on 16
/// Aug 2026, it was paid in full on the very first add of a batch: a
/// sampler tick holding the index write mutex (`Index::oracle_pick`)
/// stalled the scan pass, which could not hand the gate back, and the
/// user's download sat for a silent minute before starting. A lane
/// that has not answered in five seconds is not about to - the gate is
/// confirmation, not permission, and every holder also stands down on
/// its own once the guard is visible - so the whole cost of being
/// wrong here is brief SQLite/bandwidth contention with a lane that is
/// already leaving. That is a far smaller price than a minute of a
/// user's time, paid on every add.
/// `NZBFAST_INDEX_GATE_WAIT_SECS` overrides for the tests.
fn index_gate_bound() -> std::time::Duration {
    static SECS: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    std::time::Duration::from_secs(*SECS.get_or_init(|| {
        std::env::var("NZBFAST_INDEX_GATE_WAIT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|&s| s > 0)
            .unwrap_or(5)
    }))
}

/// Rendezvous on the index pass gate with [`index_gate_bound`] as the
/// deadline. True = the gate was acquired (and released) cleanly;
/// false = the bound expired and the caller proceeds without it. The
/// guard is never held past this function either way - the acquisition
/// itself is the proof that no index lane still runs.
async fn index_gate_rendezvous(gate: &tokio::sync::Mutex<()>, bound: std::time::Duration) -> bool {
    tokio::time::timeout(bound, gate.lock()).await.is_ok()
}

/// M14i background re-verify: library entries are only pointers, so the
/// content can rot out from under them. Periodically re-sample parked
/// (never-fetched) Completed library jobs; a vanished post flips to
/// Failed and the *arrs' failed-download handling re-grabs elsewhere.
pub(super) fn spawn_library_recheck(daemon: &Arc<Daemon>, config: &std::path::Path) {
    let d = daemon.clone();
    let config = config.to_path_buf();
    tokio::spawn(async move {
        loop {
            let every = d.library_recheck_secs.load(Ordering::Relaxed).max(1);
            tokio::time::sleep(std::time::Duration::from_secs(every)).await;
            let jobs: Vec<_> = {
                let h = d.history.lock_ok();
                h.iter()
                    .filter(|job| {
                        let j = job.lock_ok();
                        j.library && !j.fetched && j.state == JobState::Completed
                    })
                    .cloned()
                    .collect()
            };
            for job in jobs {
                let nzb_path = job.lock_ok().nzb_path.clone();
                if let Ok(crate::Verdict::Impossible { .. }) =
                    crate::check(&config, &nzb_path, 10, 4, 50, true).await
                {
                    {
                        let mut j = job.lock_ok();
                        j.state = JobState::Failed;
                        j.fail_message = "content no longer retrievable".into();
                        info!(target: "library", "{} vanished - marked Failed", j.nzo_id);
                    }
                    // Log and carry on, deliberately: this verdict is
                    // the one thing here that re-derives itself. A row
                    // whose Failed flip never reached the store comes
                    // back Completed at the next start, and this same
                    // loop re-samples it and reaches the same answer -
                    // so a refusal costs one more sampling round, not
                    // the verdict.
                    d.history_publish_change(&job, "the vanished-content verdict");
                    d.save_queue();
                }
            }
        }
    });
}

/// NZBFAST_NO_ENRICH=1 disables the metadata workers entirely - set by
/// the test suite (they hit the real internet: the IMDb refresher pulls
/// a ~25 MB dataset and ingests 425k rows on every fresh db, whose
/// write transaction also locked the first index scan out - the
/// long-standing scan_loop test "flake").
#[cfg(feature = "indexer")]
pub(super) fn spawn_enrichment_workers(daemon: &Arc<Daemon>) {
    if std::env::var_os("NZBFAST_NO_ENRICH").is_none() {
        {
            let d = daemon.clone();
            // §193 d: the line below reports what the key situation is
            // AT STARTUP. The lanes themselves re-read `d.tmdb_key` per
            // title, so a key added later is used without a restart -
            // only this one sentence is a snapshot.
            let key = d.tmdb_key.lock_ok().is_some();
            let omdb = d.omdb_key.lock_ok().is_some();
            info!(
                target: "wall",
                "enrichment on via {} (posters cache to .spool/art)",
                if key {
                    "TMDB"
                } else if omdb {
                    "TVmaze + OMDb + Wikidata/Wikipedia + AniList"
                } else {
                    "TVmaze + Wikidata/Wikipedia + AniList (keyless)"
                }
            );
            let stop = super::RunStop::current();
            super::spawn_aux("wall-enrich", move || wall_enricher(d, stop));
        }
        {
            let d = daemon.clone();
            let stop = super::RunStop::current();
            super::spawn_aux("imdb-ratings", move || imdb_ratings_refresher(d, stop));
        }
        {
            let d = daemon.clone();
            let stop = super::RunStop::current();
            super::spawn_aux("person-photos", move || person_photo_fetcher(d, stop));
        }
    }
}

/// Update checker: 90 s after start, then every 6 h. NOTIFY-ONLY:
/// finding a newer version sets the banner state and logs a line,
/// nothing more - the daemon never downloads or replaces its own
/// binary. Turn checks off entirely with the update_checks setting
/// (or an empty update_url).
///
/// Weak, not `Arc`: the six-hour sleep is far longer than an embedded
/// host's whole start/stop cycle, so a strong handle here pinned the
/// entire daemon graph of every generation. Upgraded per pass, dropped
/// before the next sleep.
pub(super) fn spawn_update_checker(daemon: &Arc<Daemon>) {
    let d = Arc::downgrade(daemon);
    let stop = super::RunStop::current();
    super::spawn_aux("update-check", move || {
        if !stop.sleep(std::time::Duration::from_secs(90)) {
            return;
        }
        loop {
            let Some(d) = d.upgrade() else { return };
            if d.update_checks.load(Ordering::Relaxed) {
                match check_update(&d) {
                    Ok(Some(m)) => {
                        let ver = m.get("version").and_then(Value::as_str).unwrap_or("?");
                        info!(
                            target: "update",
                            "v{ver} is available (running v{}) - see {DOWNLOAD_URL}",
                            env!("CARGO_PKG_VERSION")
                        );
                    }
                    Ok(None) => {}
                    Err(e) => info!(target: "update", "{e}"),
                }
            }
            drop(d);
            if !stop.sleep(std::time::Duration::from_secs(6 * 3600)) {
                return;
            }
        }
    });
}

/// Scheduled system benchmark (live setting bench_interval, hours;
/// 0 = off). Runs only while the queue is idle - a benchmark that
/// comes due mid-download waits and re-checks each minute. Every run
/// appends to .spool/bench_history.json (mode=bench_history).
///
/// Weak like the update checker, and for the same reason - plus one of
/// its own: `rt` is THIS run's runtime handle, and `measure_system`
/// block_on's it. A generation that outlived its stop would be calling
/// into a runtime that had already been shut down.
pub(super) fn spawn_scheduled_bench(daemon: &Arc<Daemon>, config: &std::path::Path) {
    let dw = Arc::downgrade(daemon);
    let cfg_path = config.to_path_buf();
    let rt = tokio::runtime::Handle::current();
    let stop = super::RunStop::current();
    super::spawn_aux("sched-bench", move || {
        // Seed last-run from history so a restart doesn't re-run early.
        {
            let Some(d) = dw.upgrade() else { return };
            if let Some(ts) = d
                .bench_history()
                .last()
                .and_then(|e| e.get("ts").and_then(Value::as_u64))
            {
                d.bench_last.store(ts, Ordering::Relaxed);
            }
        }
        loop {
            if !stop.sleep(std::time::Duration::from_secs(60)) {
                return;
            }
            let Some(d) = dw.upgrade() else { return };
            let hrs = d.bench_interval.load(Ordering::Relaxed);
            if hrs == 0 {
                continue;
            }
            let now = epoch_secs();
            if now.saturating_sub(d.bench_last.load(Ordering::Relaxed)) < hrs * 3600 {
                continue;
            }
            let busy = d.queue.lock_ok().iter().any(|j| {
                matches!(
                    j.lock_ok().state,
                    JobState::Downloading | JobState::Finishing
                )
            });
            if busy {
                continue; // never disturb a download; re-check in a minute
            }
            // Last look before a minute of network and disk work on a
            // runtime this run may be about to lose. Before the permit,
            // so a run that is going away does not take one on its way
            // out.
            if stop.stopping() {
                return;
            }
            // Single-flight with the manual mode=sysbench run (Codex
            // sweep 10 Aug M14): if one is in flight, re-check in a
            // minute rather than running a second workload beside it.
            let Some(_running) = d.bench_begin() else {
                continue;
            };
            info!(target: "bench", "scheduled system benchmark (every {hrs} h)");
            d.bench_last.store(now, Ordering::Relaxed);
            match measure_system(&d, &cfg_path, &rt) {
                Ok(v) => d.bench_append(json!({
                    "ts": now, "source": "scheduled",
                    // Which servers and how many connections the network
                    // figure came from. A tester compared a row measured
                    // on the old fixed-8, first-server probe against one
                    // measured on the whole set and read the method change
                    // as a 30% line regression - rows are only comparable
                    // when this matches.
                    "network_host": v.network_host,
                    "network_conns": v.network_conns,
                    "network_gbps": v.network_gbps,
                    "compute_gbps": v.compute_gbps,
                    "disk_gbps": v.disk_gbps,
                    "expected_gbps": v.expected_gbps,
                    "bottleneck": v.bottleneck,
                })),
                Err(e) => {
                    info!(target: "bench", "scheduled benchmark failed: {e}");
                    d.bench_append(json!({"ts": now, "source": "scheduled", "error": e}));
                }
            }
        }
    });
}

#[cfg(test)]
#[path = "tasks_stall_tests.rs"]
mod tasks_stall_tests;

#[cfg(test)]
#[path = "tasks_tests.rs"]
mod tasks_tests;

// TODO 161 items 2 and 3: the scoreboard and corr-confirm lanes driven
// end to end against a loopback newznab fixture. Its own file, not an
// extension of either lane's module, because it exercises BOTH and
// because indexer.rs is already 2.4k lines against the 3k size gate.
#[cfg(all(test, feature = "indexer"))]
#[path = "tasks/lane_proof_tests.rs"]
mod lane_proof_tests;
