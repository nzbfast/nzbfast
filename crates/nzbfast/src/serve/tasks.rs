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
mod indexer;
#[cfg(feature = "indexer")]
mod scoreboard;
// The download runner's guard ladder, hub hand-over and tail accounting,
// moved out of `spawn_download_worker` under the fn ceiling (TODO 106).
mod runner;
use runner::*;
mod stall;
mod tuner;
mod watchfolder;

#[cfg(feature = "indexer")]
pub(super) use enrich::*;
#[cfg(feature = "indexer")]
pub(super) use indexer::*;
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

/// Post-job memory trim. A finished job frees its pipeline buffers,
/// but the allocator keeps those pages resident for reuse - which
/// reads as a leak on the dashboard's RAM line. Once the daemon has
/// been idle for a full minute after a download, hand the retained
/// pages back to the OS; the next download simply faults fresh ones
/// in. One trim per idle period, none at startup.
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
            let _ = tokio::task::spawn_blocking(move || d2.flush_search_log()).await;
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
/// DATE round-trips to the first server at 1 Hz. Base RTT = 10-minute
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
            let server = match nzbkit::config::Config::load(&config) {
                Ok(c) => c.servers.first().cloned(),
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
            for g in groups.clone() {
                let sem = sem.clone();
                let config = config.clone();
                let db = db.clone();
                let daemon3 = daemon2.clone();
                let gates = gates.clone();
                let cats = cats.clone();
                let preempted2 = preempted.clone();
                set.spawn(async move {
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
                    daemon3
                        .scan_progress
                        .lock()
                        .unwrap()
                        .retain(|p| p.group != g);
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
                });
            }
            while set.join_next().await.is_some() {}
            daemon2.scan_active.store(false, Ordering::Relaxed);
            // A4: the one exact stats recompute for the whole pass, now
            // that every group's ingest is committed. The per-group
            // scans and progress lines serve a TTL memo; this seeds the
            // dashboard cache so the pill shows the pass's result
            // without waiting out the TTL.
            crate::persist::blocking_db(|| daemon2.refresh_index_stats());
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
            let waiting = || scan_groups && daemon2.indexing_pause_reason().is_some();
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
                let gates2 = daemon2.index_gates.lock_ok().1.clone();
                let cats2 = daemon2.custom_categories.read_ok().clone();
                // Same contract as the scan tasks above: this owns a
                // dedicated connection for the length of the pass, so
                // it may only publish if the index it belongs to is
                // still the current one.
                let era = daemon2.index_era();
                match nzbkit::index::Index::open_scratch(&db) {
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
                        let gap = crate::index_gapfill_pass(&config, &mut scratch, gapfill, || {
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
            if waiting() {
                drop(index_pass);
                continue;
            }
            // M31a retention prune + the planner-statistics refresh,
            // both on their own clocks inside.
            if !groups.is_empty() && daemon2.index_maintenance_ok() {
                retention_and_statistics(&daemon2).await;
                if waiting() {
                    drop(index_pass);
                    continue;
                }
                // B1: one background-picker partial index per pass,
                // until the three exist. Same stand-down contract as
                // the statistics refresh it follows.
                picker_index_backfill(&daemon2).await;
                if waiting() {
                    drop(index_pass);
                    continue;
                }
                // One budgeted shatter-fold slice per pass, same
                // stand-down gate: it takes the write lock, so it
                // yields to anything the user is actually doing.
                shatter_fold_pass(&daemon2);
            }
            if waiting() {
                drop(index_pass);
                continue;
            }
            evict_between_passes(&daemon2).await;
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

/// TODO §77 post-health prober: STAT a handful of a queued job's
/// articles across every configured server and hang the verdict on the
/// job, so the queue row can say "posted four days ago, on none of your
/// three servers (8 sampled)" before the bandwidth is spent rather than
/// at 97%. The scoring, and the reasons it is only ever advisory, live
/// in [`crate::health`].
///
/// Discipline copied from `spawn_oracle_sampler` above, and for the same
/// reasons (memory `nzbfast-idle-connection-holders`):
///
/// * it sits out entirely while any download is active, and abandons a
///   probe mid-flight the moment one starts - the account's connection
///   slots, and on a source-IP-capped provider its address slots, belong
///   to the job the user is waiting on;
/// * one connection per host, opened for the probe and closed after it,
///   never borrowed from an active download's pool;
/// * one job per tick, and at most [`crate::health::MAX_PROBES`] probes
///   per job ever, so a queue full of held duplicates cannot turn into a
///   STAT generator.
pub(super) fn spawn_health_prober(daemon: &Arc<Daemon>, config: &std::path::Path) {
    let config = config.to_path_buf();
    let d = daemon.clone();
    tokio::spawn(async move {
        // Jobs whose NZB could not be sampled at all (unreadable, or no
        // articles outside the PAR2 volumes). In memory rather than on
        // the record: it is a property of this file on this disk, not a
        // verdict about the post, and one retry after a restart is the
        // right amount of forgiveness for a share that was offline.
        let mut unsampleable: std::collections::HashSet<String> = Default::default();
        // Jobs whose last probe learned NOTHING (every server refused
        // the login, or none was reachable), and the unix time before
        // which they must not be tried again.
        //
        // Without this, a fruitless probe leaves `health` at None, the
        // pick treats the job as never-sampled, and the next tick
        // connects to the same dead provider - a connect storm against
        // a host that is already having a bad day, once per queued job
        // per tick. A short backoff instead of a permanent give-up: a
        // provider that was down for two minutes should get the job
        // badged when it comes back.
        let mut blind_until: std::collections::HashMap<String, i64> = Default::default();
        // Env-tunable so the daemon suite can compress the timeline, the
        // same way the slow-job watchdog's window is.
        let secs = |k: &str, def: u64| {
            std::env::var(k)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(def)
                .max(1)
        };
        let tick = secs("NZBFAST_HEALTH_TICK_SECS", 15);
        let recheck = secs(
            "NZBFAST_HEALTH_RECHECK_SECS",
            crate::health::RECHECK_AFTER_SECS as u64,
        ) as i64;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(tick)).await;
            if !d.post_health.load(Ordering::Relaxed)
                || d.offline.load(Ordering::Relaxed)
                || !download_idle(&d)
            {
                continue;
            }
            let now = unix_now();
            // An expired backoff is not a memory: forget it, and let the
            // job be picked again on its merits.
            blind_until.retain(|_, t| *t > now);
            // One job per tick: the next queued item that has never been
            // sampled, or that has sat here long enough to be worth
            // asking about a second time (a post that was still
            // propagating at add time has usually landed by then).
            let picked = {
                let q = d.queue.lock_ok();
                // Neither side-table may outlive the queue it describes.
                // A daemon that runs for months would otherwise
                // accumulate one entry per job it ever failed to sample,
                // and nothing would ever drop them. Guarded because the
                // set is empty on every healthy install, and the sweep
                // locks every job in the queue.
                if !unsampleable.is_empty() {
                    unsampleable.retain(|id| q.iter().any(|j| j.lock_ok().nzo_id == *id));
                }
                q.iter()
                    .find(|j| {
                        let g = j.lock_ok();
                        g.state == JobState::Queued
                            && !g.tombstone
                            // A paused job (including a held duplicate)
                            // is not going to start, so it is not worth
                            // a provider round trip until it is resumed.
                            && !g.paused
                            && !unsampleable.contains(&g.nzo_id)
                            && blind_until.get(&g.nzo_id).is_none_or(|t| now >= *t)
                            && match &g.health {
                                None => true,
                                Some(h) => {
                                    h.probes < crate::health::MAX_PROBES
                                        && now - h.checked_at >= recheck
                                }
                            }
                    })
                    .cloned()
            };
            let Some(job) = picked else { continue };
            let (nzo_id, nzb_path, total_bytes, probes) = {
                let g = job.lock_ok();
                (
                    g.nzo_id.clone(),
                    g.nzb_path.clone(),
                    g.total_bytes,
                    g.health.as_ref().map_or(0, |h| h.probes),
                )
            };
            let servers: Vec<nzbkit::config::ServerConfig> =
                match nzbkit::config::Config::load(&config) {
                    Ok(c) => c.servers.into_iter().filter(|s| s.enabled).collect(),
                    Err(_) => continue,
                };
            if servers.is_empty() {
                continue;
            }
            // Parsing an NZB is a file read plus an XML pass, and a big
            // one is tens of MB - off the runtime's workers.
            let k = crate::health::sample_size(total_bytes);
            let Ok(Some((ids, age_days))) =
                tokio::task::spawn_blocking(move || sample_ids(&nzb_path, k)).await
            else {
                // An unreadable or article-less NZB is not an error
                // worth logging on every tick: the job simply gets no
                // badge, and the download decides for itself.
                unsampleable.insert(nzo_id.clone());
                continue;
            };
            let mut answers: Vec<crate::health::ServerAnswer> = Vec::new();
            for s in &servers {
                // Re-checked per server, not just once at the top: a job
                // can start between two hosts, and when it does the rest
                // of the probe is abandoned with whatever it has.
                if !download_idle(&d) {
                    break;
                }
                answers.push(probe_server(s, &ids, &d).await);
            }
            let verdict = crate::health::score(&answers, age_days, now, probes + 1);
            {
                let mut g = job.lock_ok();
                // Never overwrite a real verdict with nothing: a probe
                // that ran into a dead network says less than the one
                // that answered an hour ago, and blanking the badge
                // would read as "we stopped worrying about this".
                if let Some(mut v) = verdict {
                    // A waiver is the user's decision about SCHEDULING, not
                    // a fact about the post, so a fresh probe replaces the
                    // evidence and never the decision. `score` always builds
                    // `waived: false`, so without carrying it forward the
                    // hourly re-check silently re-sinks a job the user had
                    // already pulled back up - which is the one thing the
                    // flag exists to prevent.
                    v.waived = g.health.as_ref().is_some_and(|h| h.waived);
                    info!(target: "health", "{nzo_id} {}: {}", v.bucket.as_str(), v.reason);
                    g.health = Some(v);
                    blind_until.remove(&nzo_id);
                } else {
                    // Nothing answered. Back off before asking again,
                    // and burn a probe against any verdict already on
                    // the record so a permanently mute fleet cannot
                    // keep re-asking on an hourly re-check either.
                    blind_until.insert(nzo_id.clone(), now + (tick * 20) as i64);
                    if let Some(h) = g.health.as_mut() {
                        h.probes += 1;
                        h.checked_at = now;
                    }
                }
            }
            d.save_queue();
        }
    });
}

/// Is nothing downloading right now? The prober's whole stand-down rule.
///
/// Both pipelines, not just the primary runner: the idle-server prefetch
/// sidecar holds live NNTP connections of its own (and in the borrow
/// case it deliberately shares a BUSY server's headroom), and the runner
/// clears `started_at` before it awaits the previous job's tail and
/// winds the sidecar down - a span that has run minutes in the field.
/// Probing through that window pipelines STATs onto servers the sidecar
/// is downloading on, which is exactly what §77 stands down to avoid.
fn download_idle(d: &Arc<Daemon>) -> bool {
    d.started_at.lock_ok().is_none() && d.sidecar.lock_ok().is_none()
}

/// Is a post-processing tail still running? `download_idle` answers for
/// the WIRE only - the download-end stamp lands when the network drains
/// and the repair/extract/move tail is handed to the lane after it, so a
/// job can be well past its last article and still be working the disk
/// hard. Same predicate the §129 1b poll calls "active".
fn busy_tail(d: &Arc<Daemon>) -> bool {
    d.queue.lock_ok().iter().any(|j| {
        let g = j.lock_ok();
        g.state == JobState::Finishing || g.finalizing
    })
}

/// The sampled message-ids for one job, and the age in days of the
/// youngest article in the post.
///
/// Stratified over the whole post - first, last and evenly spread -
/// using the same [`nzbkit::preflight::stratified_sample`] the `check`
/// command's sweep uses, over the same file set: PAR2 recovery volumes
/// are excluded because nothing fetches them unless a repair needs them,
/// so their absence says nothing about whether the job can complete.
///
/// The age is the MINIMUM over the files, matching what the failure
/// diagnosis computes (`get.rs`) - a fill or a repost tops an old NZB up
/// with fresh articles, and it is the newest posting that decides
/// whether propagation is still a live explanation.
fn sample_ids(nzb_path: &std::path::Path, k: usize) -> Option<(Vec<String>, u32)> {
    let bytes = std::fs::read(nzb_path).ok()?;
    let nzb = nzbkit::nzb::Nzb::parse(&bytes).ok()?;
    let mut ids: Vec<String> = Vec::new();
    let mut age = u32::MAX;
    for f in &nzb.files {
        if f.kind() == nzbkit::nzb::FileKind::Par2Volume {
            continue;
        }
        age = age.min(crate::nzb_age_days(f.date));
        ids.extend(f.segments.iter().map(|s| format!("<{}>", s.message_id)));
    }
    if ids.is_empty() {
        return None;
    }
    let picked = nzbkit::preflight::stratified_sample(ids.len(), k)
        .into_iter()
        .map(|i| ids[i].clone())
        .collect();
    Some((picked, if age == u32::MAX { 0 } else { age }))
}

/// STAT every sampled id on one server over a single pipelined burst.
///
/// Every failure path - refused login, a dead socket, a peer that goes
/// mute mid-batch - leaves the cells it never reached `Unknown`, which
/// [`crate::health::score`] treats as "this server did not vote" rather
/// than as evidence in either direction. Nothing here can produce a
/// miss that a server did not actually report.
async fn probe_server(
    s: &nzbkit::config::ServerConfig,
    ids: &[String],
    d: &Arc<Daemon>,
) -> crate::health::ServerAnswer {
    use crate::health::Avail;
    let mut cells = vec![Avail::Unknown; ids.len()];
    let host = s.host.clone();
    let Ok((mut conn, _)) = nzbkit::nntp::Connection::connect(s).await else {
        return crate::health::ServerAnswer { host, cells };
    };
    let probe = async {
        for id in ids {
            conn.send_stat(id).await?;
        }
        conn.flush().await?;
        for cell in cells.iter_mut() {
            // `read_stat` is the normalizer both this and the M29
            // sampler share: 223 have, 423/430 missing, and Giganews's
            // nonstandard "451 0 <msgid>" for a takedown counted as a
            // miss rather than thrown away as a protocol error. Do not
            // re-derive it here.
            *cell = match conn.read_stat().await? {
                true => Avail::Have,
                false => Avail::Missing,
            };
        }
        Ok::<(), nzbkit::nntp::NntpError>(())
    };
    // Two ways out, and both end the session immediately: the ordinary
    // 20 s ceiling, and a download starting under us. Dropping the
    // future cancels the probe outright (nothing is spawned), and
    // dropping the Connection closes the socket - so "yield the slot"
    // is not a request the provider has to wait on.
    let clean = tokio::select! {
        r = tokio::time::timeout(std::time::Duration::from_secs(20), probe) => {
            if let Ok(Err(e)) = &r {
                warn!(target: "health", "{host}: STAT: {e}");
            }
            matches!(r, Ok(Ok(())))
        }
        () = async {
            while download_idle(d) {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        } => false,
    };
    // A polite QUIT only on a session that read every reply it asked
    // for. An abandoned or timed-out probe has unread STAT statuses in
    // the socket, so the "goodbye" it would read is somebody else's
    // answer - the same reason the M29 sampler drops a desynced
    // connection rather than tidying it up. Dropping closes it.
    if clean {
        conn.quit().await;
    }
    crate::health::ServerAnswer { host, cells }
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
    if let Some(v) = load_settings(settings_path).get("feeds") {
        match serde_json::from_value(v.clone()) {
            Ok(l) => feed_list = l,
            Err(e) => warn!(target: "rss", "ignoring saved feeds setting: {e}"),
        }
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

/// Download worker: one download at a time at full pipeline speed,
/// but job N's TAIL (settle/repair/extract) overlaps job N+1's
/// download - the network never idles across queue boundaries.
pub(super) fn spawn_download_worker(
    daemon: &Arc<Daemon>,
    config: &std::path::Path,
    index_pass_gate: &Arc<tokio::sync::Mutex<()>>,
    mem_budget: nzbkit::mem::MemBudget,
) {
    let d = daemon.clone();
    let config = config.to_path_buf();
    let index_pass_gate = index_pass_gate.clone();
    // Opened lazily on the first pass with a quota set - the quota
    // (and its period) are live settings now.
    let mut ledger: Option<QuotaLedger> = None;
    tokio::spawn(async move {
        let mut guard_reason: Option<String> = None;
        // §129: the post-processing lane the tails hand off to. The
        // worker never blocks on a tail again - it blocks (below) only
        // on the lane's honest backpressure bound.
        let lane = PostprocLane::new(d.clone());
        // In-flight statfs probe for the min-free guard (≤1 outstanding).
        let mut disk_probe: Option<tokio::task::JoinHandle<Option<u64>>> = None;
        // §156 item 7: the no-servers guard's config read, on the
        // blocking pool under the same one-outstanding rule.
        let mut server_probe = ServerProbe::default();
        loop {
            let Some(only_force) = download_guards(
                &d,
                &config,
                &lane,
                &mut guard_reason,
                &mut ledger,
                &mut disk_probe,
                &mut server_probe,
            )
            .await
            else {
                continue;
            };
            d.run_due_auto_retries();
            let Some(job) = d.pick_job(only_force) else {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                continue;
            };
            // Never start a primary while this job's prefetch sidecar
            // still runs (possible when a library pick bypassed the
            // job-end stop below).
            {
                let picked = job.lock_ok().nzo_id.clone();
                let holds = d
                    .sidecar
                    .lock()
                    .unwrap()
                    .as_ref()
                    .is_some_and(|s| s.nzo_id == picked);
                if holds {
                    stop_sidecar(&d).await;
                    // The sidecar may have FINISHED this job while we
                    // waited. Its success arm marks the job Completed
                    // and hands the post-processing tail to a task of
                    // its own, so that tail can be unlocking, renaming
                    // or moving `out_dir` right now. Starting the
                    // pipeline would point a fresh download at the
                    // directory being moved out from under it, so
                    // re-read what we picked on and let the job go if
                    // it is no longer waiting to run.
                    let j = job.lock_ok();
                    if j.paused || j.state != JobState::Queued {
                        continue;
                    }
                }
            }
            let (
                nzb_path,
                out_dir,
                total,
                library,
                nzo_id,
                name,
                prio,
                job_password,
                eat_ok,
                failure_host,
            ) = {
                let mut j = job.lock_ok();
                j.state = JobState::Downloading;
                // §129 4a: the pick is the "started" moment. A job that
                // re-enters the runner after a demotion, disk hold or
                // retry starts again - `resumed` carries the difference.
                d.queue_idle_latch.store(false, Ordering::Relaxed);
                d.life_emit(
                    "job.started",
                    json!({
                        "nzo_id": j.nzo_id,
                        "name": j.name,
                        "category": j.category,
                        "total_bytes": j.total_bytes,
                        "resumed": j.downloaded_bytes > 0,
                    }),
                );
                // Late-pick marker: the runner was free when this job
                // arrived, yet took over 2 s to start it - the signature
                // of the fixed runner-starvation bug, named so any
                // recurrence attributes itself. Taken, not read, so a
                // job that requeues can never replay a stale stamp.
                if let Some(waited) = j
                    .queued_at
                    .take()
                    .filter(|_| j.idle_at_add)
                    .map(|t| t.elapsed())
                    .filter(|w| *w > std::time::Duration::from_secs(2))
                {
                    d.note_event(
                        "late",
                        format!(
                            "{} started {:.1} s after it was added with nothing \
                             ahead of it - the runner was slow to pick it up",
                            j.name,
                            waited.as_secs_f64()
                        ),
                    );
                }
                (
                    j.nzb_path.clone(),
                    j.out_dir.clone(),
                    j.total_bytes,
                    j.library,
                    j.nzo_id.clone(),
                    j.name.clone(),
                    j.priority,
                    j.password.clone(),
                    j.eat_volumes_ok,
                    // §99 try-order key for the in-stream password
                    // probe: which site supplied the NZB.
                    j.failure_host.clone(),
                )
            };
            let index_job_guard = d.begin_index_job();
            // Raise the guard first so an active scan observes it and
            // cancels, then rendezvous on the shared gate. Once this
            // lock is acquired no scan, tip ingest, eviction or
            // VACUUM can still be running beside the foreground job.
            //
            // Bounded (issue #38's second wedge shape): a lane wedged
            // mid-I/O against a mute peer would otherwise park this
            // runner forever with the job stuck in Downloading and
            // nothing logged. Past the bound, say so and start - every
            // lane also stands down on its own once the guard above is
            // visible, so the gate is confirmation, not permission.
            if d.index_pause_on_download.load(Ordering::Relaxed)
                && !index_gate_rendezvous(&index_pass_gate, index_gate_bound()).await
            {
                let detail = format!(
                    "{name} started without the index-pass rendezvous - an index \
                     lane held the gate past {} s (stuck mid-I/O against an \
                     unresponsive server); it stands down on its own",
                    index_gate_bound().as_secs()
                );
                warn!(target: "queue", "{detail}");
                d.note_event("indexer", detail);
            }
            // Claim the shared progress counters for THIS job, in one
            // lock section with the zeroing they describe. A queue
            // payload that reads the owner can then never pair it with
            // the next job's zeroes: it either gets the lock first and
            // sees the previous owner with the previous counters, or
            // gets it after and sees this job with this job's.
            {
                let mut owner = d.active_dl.lock_ok();
                d.progress.store(0, Ordering::Relaxed);
                d.active_total.store(total, Ordering::Relaxed);
                // The UX §15 fetch-plan pair goes with them, and the plan
                // is zeroed FIRST: a reader that catches the gap sees "no
                // plan" and falls back to the counters above, never a
                // fresh plan paired with the previous job's finished
                // count.
                d.hub.fetch_plan.store(0, Ordering::Relaxed);
                d.hub.fetch_done.store(0, Ordering::Relaxed);
                // §129 4b's post date goes with them, and for the same
                // reason: a whyslow tick between the transition and the
                // plan publish must not read the PREVIOUS job's post age
                // against this job's article misses. 0 is "unknown",
                // which asserts nothing.
                d.hub.post_unix.store(0, Ordering::Relaxed);
                *owner = Some(nzo_id.clone());
            }
            let t_start = Instant::now();
            *d.started_at.lock_ok() = Some(t_start);

            // A /stream trigger re-queues a library entry at Force
            // priority - that's the "actually download now" signal.
            if library && prio < 2 {
                // M14i metadata-only: STAT-sample availability instead of
                // downloading. Pass → Completed + .strm pointer; the real
                // fetch happens on first /stream/<id> playback.
                d.hub.activity.lock_ok().insert(nzo_id.clone(), "preflight");
                let verdict = crate::check(&config, &nzb_path, 10, 4, 50, true).await;
                {
                    let mut j = job.lock_ok();
                    match verdict {
                        Ok(crate::Verdict::Impossible {
                            est_missing,
                            recovery,
                            measured,
                            ..
                        }) => {
                            j.state = JobState::Failed;
                            // The counts make the verdict checkable;
                            // append-only, the prefix is classified on.
                            j.fail_message = crate::with_build(format!(
                                "pre-flight: articles missing beyond repair - {}",
                                crate::check::impossible_reason(est_missing, recovery, &measured)
                            ));
                        }
                        Ok(_) => {
                            j.state = JobState::Completed;
                            if let Err(e) = write_strm(
                                &out_dir,
                                &name,
                                d.scheme(),
                                d.port,
                                &nzo_id,
                                &d.stream_token(&nzo_id),
                            ) {
                                warn!(target: "strm", "write for {nzo_id}: {e}");
                            }
                        }
                        Err(e) => {
                            j.state = JobState::Failed;
                            j.fail_message = e.to_string();
                        }
                    }
                    j.finished_at = Some(Instant::now());
                    j.finished_unix = Some(unix_now());
                }
                *d.started_at.lock_ok() = None;
                *d.last_download_end.lock_ok() = Instant::now();
                // The hooks and the park go to the post-processing
                // lane, not to the next two statements. This arm
                // reaches `Completed` without downloading a byte, and
                // Completed is the word Sonarr imports on - so the
                // pp-script, which may be moving or renaming the .strm
                // this arm just wrote, has to be finished before the
                // history row exists. Awaiting that here would stall
                // the picker for the script's whole run; the lane is
                // where the wait is affordable. See
                // `PostprocLane::submit_hooks_only`.
                lane.submit_hooks_only(job).await;
                continue;
            }

            // Bracket this job's console output. Everything the
            // failure diagnosis needs - the per-file segment tally,
            // the per-server table, the first transport error - is
            // PRINTED and then lost: the log ring is memory-only and
            // 2000 lines deep, so a daemon restart (or a busy hour)
            // takes it with it, and the one-line fail_message is all
            // that reaches history. Marked before any of this job's
            // work so the snapshots below are its lines, nobody else's.
            let log_mark = nzbkit::logtee::mark();
            // Onto the RECORD as well, so `mode=report` can slice this
            // job's lines later. The ticket's copy dies with the tail;
            // a user asks for a report minutes or hours afterwards.
            if let Some(j) = d
                .queue
                .lock_ok()
                .iter()
                .find(|j| j.lock_ok().nzo_id == nzo_id)
            {
                j.lock_ok().log_mark = log_mark;
            }

            // TODO §138 (issue #29), opt-in `post_health_fail`: the §77
            // sample already asked every configured server about this
            // post while the queue was idle. If every one of them said
            // every sampled article was missing, and the post is old
            // enough that propagation is no longer an explanation, end
            // it here - the *arr gets a FAILURE/HEALTH it can blocklist
            // and re-search on within seconds of the job coming up,
            // instead of after however long it takes a doomed download
            // to prove the same thing at full retry ladder.
            //
            // Free: no probe runs here, the evidence is the verdict on
            // the record. The bar is `no_server_can_supply`, which is
            // deliberately much narrower than the red bucket the
            // reorder acts on - see its doc for each clause.
            //
            // WHY HERE and not in the prober that gathered the evidence:
            // the runner picks a job and only then marks it Downloading,
            // so a prober failing a queued job races that window and can
            // park a job the runner has already started - one record in
            // history and a live download with no queue row. The runner
            // is single and owns the transition, so deciding here cannot
            // race anything, and it is the same seam the opt-in
            // `preflight` sweep below already fails jobs on.
            //
            // Sentence, class and consequences arrive together:
            // `giveup_reason` opens with `post is gone`, so `fail_kind`
            // reads Gone - no automatic retry, FAILURE/HEALTH to the
            // *arr, "find another release" as the suggested move.
            let giveup: Option<String> = if d.post_health_fail.load(Ordering::Relaxed) {
                let j = job.lock_ok();
                j.health
                    .as_ref()
                    .filter(|h| h.no_server_can_supply())
                    .map(crate::health::giveup_reason)
            } else {
                None
            };
            if let Some(reason) = giveup {
                {
                    let mut j = job.lock_ok();
                    j.state = JobState::Failed;
                    j.fail_message = crate::with_build(reason);
                    j.finished_at = Some(Instant::now());
                    j.finished_unix = Some(unix_now());
                    info!(target: "health", "{nzo_id}: {}", j.fail_message);
                }
                *d.started_at.lock_ok() = None;
                // The idle clock starts at every job exit, not only the
                // completion path below - the idle memory trim arms on
                // this stamp, and a give-up as the last pick of the day
                // otherwise left it unarmed for good (§156 item 8a).
                *d.last_download_end.lock_ok() = Instant::now();
                // Off the picker's loop and into the lane, same as the
                // metadata-only arm above. `Failed` is a word an *arr
                // acts on too - it blocklists this release and
                // re-searches - and a user's failure script runs on
                // this path exactly as it does on a download that
                // failed the long way round, where the lane already
                // finishes it before the row is filed. One ordering
                // for every ending, not one per arm.
                //
                // The give-up's own selling point survives it: what
                // this feature buys is not having to spend a doomed
                // download to reach the verdict, and none of that is
                // given back by the script taking the time the user
                // configured it to take. The failure REPORT still
                // lands after the park by construction - only the
                // script is awaited - so a re-grab can never enter the
                // queue while the row it replaces is still in it.
                lane.submit_hooks_only(job).await;
                continue;
            }

            // Opt-in pre-flight (settings.json `preflight`): sample
            // this post's articles before spending the bandwidth. A
            // post nothing carries any more is otherwise discovered
            // the slow way - every article asked of every server, at
            // full retry ladder, for a verdict a 10% STAT sample
            // reaches in seconds. Only `Impossible` stops the job:
            // "repairable" is what PAR2 is for, and an errored sweep
            // (a provider hiccup mid-probe) must never fail a job the
            // download itself might well complete.
            if d.preflight.load(Ordering::Relaxed) {
                d.hub.activity.lock_ok().insert(nzo_id.clone(), "preflight");
                match crate::check(&config, &nzb_path, 10, 4, 50, true).await {
                    Ok(crate::Verdict::Impossible {
                        est_missing,
                        recovery,
                        measured,
                        ..
                    }) => {
                        {
                            let mut j = job.lock_ok();
                            j.state = JobState::Failed;
                            j.fail_message = crate::with_build(format!(
                                "pre-flight: articles missing beyond repair - {}",
                                crate::check::impossible_reason(est_missing, recovery, &measured)
                            ));
                            j.fail_detail = crate::fail_detail_snapshot(log_mark);
                            j.finished_at = Some(Instant::now());
                            j.finished_unix = Some(unix_now());
                        }
                        *d.started_at.lock_ok() = None;
                        // Same idle-clock stamp as every other job
                        // exit; the STAT sample above is the network
                        // phase this job had (§156 item 8a).
                        *d.last_download_end.lock_ok() = Instant::now();
                        // Third of the three runner arms that end a job
                        // before the pipeline starts, and the lane
                        // takes its tail for the same reason as the
                        // other two.
                        lane.submit_hooks_only(job).await;
                        continue;
                    }
                    Ok(_) => {}
                    Err(e) => info!(target: "preflight", "sweep failed, downloading anyway: {e}"),
                }
            }

            reset_hub_for_job(&d, server_probe.config(), &nzo_id, failure_host);
            let (net_tx, net_rx) = tokio::sync::oneshot::channel::<()>();
            let fetch = {
                let config = config.clone();
                let nzb_path = nzb_path.clone();
                let out_dir = out_dir.clone();
                let progress = d.progress.clone();
                let hub = d.hub.clone();
                let stream_owner = nzo_id.clone();
                // Live settings, sampled once per job: a dashboard
                // change applies from the NEXT download.
                let connections = d.connections.load(Ordering::Relaxed).max(1);
                let window = d.window.load(Ordering::Relaxed).max(1);
                let decoders = d.decoders.load(Ordering::Relaxed).max(1);
                let fast_verify = d.fast_verify.load(Ordering::Relaxed);
                let verify_lean = d.verify_lean.load(Ordering::Relaxed);
                let par_cleanup = d.par_cleanup.load(Ordering::Relaxed);
                let skip_samples = d.skip_samples.load(Ordering::Relaxed);
                tokio::spawn(async move {
                    crate::get_with_progress(
                        &config,
                        &nzb_path,
                        &out_dir,
                        connections,
                        window,
                        decoders,
                        fast_verify,
                        verify_lean,
                        false,
                        par_cleanup,
                        skip_samples,
                        job_password,
                        eat_ok,
                        Some(progress),
                        Some(hub),
                        &stream_owner,
                        Some(net_tx),
                        mem_budget,
                    )
                    .await
                })
            };
            // This download runs WHILE the previous job's tail
            // finishes on disk/CPU. net_rx resolves at network-drain
            // (or is dropped by an early error - same meaning: no
            // more network work for this job).
            let _ = net_rx.await;
            // Network wall time stops HERE, not after the prev-tail
            // wait below: bytes÷seconds is the history's average speed,
            // and a stalled tail once inflated a 72 s download to a
            // recorded 121 s.
            let dl_secs = t_start.elapsed().as_secs_f64();
            // Stand the watchdog down BEFORE waiting on the previous
            // tail, not after: `started_at` means "this job's network
            // phase is live", and the wait below can be long (job N-1's
            // tail once sat minutes in a Finder-trash stall). This job
            // is still Downloading in the queue for all of it, and the
            // watchdog reading a drained pool as "one host at ~0 MB/s
            // while others wait" demoted a job that had already
            // finished - park then re-queued it after post-processing
            // had renamed its directory, and the whole release
            // downloaded a second time (31 Jul queue soak).
            *d.started_at.lock_ok() = None;
            // Phase marker: the pipeline (download AND checks) is over.
            // This is what closes the chart's "checking files" shading -
            // without it the tint would run on into the idle time after
            // the job, dressing ordinary quiet as an endless check.
            d.note_event(
                "finished",
                "job finished - the line is idle until the next download",
            );
            // Release the progress counters at the same instant and for
            // the same reason: from here this job reads 100% and its
            // phase word, and the next job is free to zero them without
            // its bar appearing on this one's row.
            *d.active_dl.lock_ok() = None;
            // The network phase is what occupies the account, so the
            // idle clock starts here rather than after the tail: the
            // post-processing that follows touches no provider.
            *d.last_download_end.lock_ok() = Instant::now();
            // §129: the previous tail is the LANE's business now; only
            // the backpressure gate at the loop top can hold the line.
            // Wind down any idle-server prefetch before the next pick:
            // the next primary may be the very job the sidecar holds,
            // and two pipelines must never share an out_dir or a
            // server's connection budget. Its journal keeps the bytes.
            stop_sidecar(&d).await;
            let JobTail {
                dl_bytes,
                on_disk_bytes,
                verifier,
                shaper,
                #[cfg(feature = "indexer")]
                oracle_samples,
            } = settle_job_tail(&d, &nzo_id, &mut ledger);
            lane.submit(PostprocTicket {
                job,
                fetch,
                verifier,
                shaper,
                log_mark,
                dl_bytes,
                dl_secs,
                on_disk_bytes,
                index_job_guard,
                #[cfg(feature = "indexer")]
                oracle_samples,
            })
            .await;
        }
    });
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

// ---------------------------------------------------------------------------
// TODO §76: the queue-row media prober
// ---------------------------------------------------------------------------

/// How often the prober looks at the running job. Env-tunable so the
/// daemon suite can compress the timeline, like the defer watchdog's.
fn media_tick() -> std::time::Duration {
    std::time::Duration::from_millis(
        std::env::var("NZBFAST_MEDIA_TICK_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5_000)
            .max(50),
    )
}
/// Attempts at the fast cadence before backing off. A container header
/// is usually readable within one or two ticks; past a minute of trying,
/// the missing region is a trailing index that arrives with the download
/// and there is nothing to gain from asking twice a minute.
const MEDIA_FAST_TRIES: u32 = 12;
const MEDIA_SLOW: std::time::Duration = std::time::Duration::from_secs(30);
/// How long a finished job stays on the final-pass list. Post-processing
/// on a large release is minutes (unpack, repair, rename, a move to a
/// NAS); half an hour covers that and stops a job that never reaches
/// history from being retried forever.
const MEDIA_FINAL_WINDOW: std::time::Duration = std::time::Duration::from_secs(1800);
/// How many times an I/O fault on the final pass is worth retrying. A
/// sleeping NAS wakes within a tick or two; a volume that is simply gone
/// answers the same way every time, and the log line below has already
/// said so once.
const MEDIA_IO_RETRIES: u32 = 3;

/// What the final pass read, in one line for the log. The same fields
/// the chip shows, in the same order, so the log and the row agree.
///
/// Never empty: an `any()`-false answer is the interesting case here
/// (the file parsed, no track came out of it) and must not print as a
/// bare nzo_id with a colon after it.
fn media_line(f: &nzbkit::mediaprobe::MediaFacts) -> String {
    let parts: Vec<&str> = [
        f.res.as_deref(),
        f.vcodec.as_deref(),
        f.audio.as_deref(),
        f.hdr.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect();
    if parts.is_empty() {
        match f.container.as_deref() {
            Some(c) => format!("{c}, but no track could be read from it"),
            None => "nothing could be read from the file".to_string(),
        }
    } else {
        parts.join(" · ")
    }
}

/// A job owed the final on-disk pass, with what it has cost so far.
struct FinalPass {
    id: String,
    /// When it was admitted - `MEDIA_FINAL_WINDOW` runs from here, so an
    /// I/O retry cannot extend its own deadline.
    at: std::time::Instant,
    io_faults: u32,
}

/// The name a mismatch is judged against: what an identity oracle
/// concluded, when one answered, and the posted name otherwise.
///
/// This matters most on exactly the posts the feature is for. An
/// obfuscated stem claims nothing - `parse_release` finds no resolution
/// and no codec in "a4f9c2e1", so nothing can contradict it - while the
/// canonical name srrdb or xREL handed back claims everything. Judging
/// the bytes against that is free here and impossible anywhere else.
fn media_claim_name(j: &Job) -> String {
    if j.identity_name.is_empty() {
        j.name.clone()
    } else {
        j.identity_name.clone()
    }
}

/// Has this job's chip stopped changing? A partial answer is worth
/// showing - the resolution lands before the audio - but it is not worth
/// keeping. A chip owed a re-judge (the identity oracle answered after
/// pass 1 settled) is not settled either: the facts are complete but the
/// NAME they were judged against has changed.
fn media_settled(j: &Job) -> bool {
    !j.media_rejudge && j.media.as_ref().is_some_and(|m| m.complete && m.any())
}

/// Latch a probe result, never downgrading. Same rule as
/// [`Job::archive_shape`] and for the same reason: a later pass that
/// could read less (a renamed file the on-disk walk no longer finds, a
/// resumed job whose writer maps nothing) must not replace an answer
/// that was right.
fn latch_media(job: &Arc<Mutex<Job>>, facts: nzbkit::mediaprobe::MediaFacts) -> bool {
    let mut j = job.lock_ok();
    if !facts.any() && j.media.is_some() {
        return false;
    }
    if j.media.as_ref() == Some(&facts) {
        return false;
    }
    if !facts.mismatch.is_empty() {
        let list: Vec<String> = facts
            .mismatch
            .iter()
            .map(|m| format!("{} claimed, {} found", m.claimed, m.actual))
            .collect();
        info!(
            target: "media",
            "{}: the file contradicts its name - {}",
            j.nzo_id,
            list.join("; ")
        );
    }
    j.media = Some(facts);
    true
}

/// §76: read the main video's own header while it downloads, so the
/// queue row can say what the file actually IS - "2160p HEVC · DDP 5.1"
/// - and say so when that contradicts the name the post carries.
///
/// The probe itself is [`nzbkit::mediaprobe`], which §73 phase 1 built
/// for the preview panel: this task exists because the panel's answer is
/// per-open-drawer and per-request, and a queue row needs one that is
/// already computed, already durable, and shared by every client polling
/// the queue. It reads container headers only (a few hundred KB, skipping
/// every payload region by arithmetic) off an ordinary blocking thread.
///
/// Two passes, deliberately:
///
/// 1. While a job runs, over the live writer. Bytes that have not landed
///    read as a gap, never as a wait, and this pass NEVER promotes
///    articles - the preview endpoint may reorder a download because a
///    user is watching that file, but a background badge has no business
///    perturbing fetch order for every job on the queue.
/// 2. Once, on disk, after the job leaves the queue. Archive shapes that
///    unpack after the download write no media file until post-processing
///    finishes, so pass 1 sees nothing at all for them; and a shape that
///    does write one may still have been reading a trailing index that
///    only completes at the end.
pub(super) fn spawn_media_prober(daemon: &Arc<Daemon>) {
    let d = daemon.clone();
    tokio::spawn(async move {
        // The job pass 1 is watching, its attempt count, and when it is
        // next due. All task-local: nothing else needs to know, and a
        // restart correctly starts over.
        let mut watching: Option<String> = None;
        let mut tries: u32 = 0;
        let mut due = std::time::Instant::now();
        // Jobs that left the queue owing a final on-disk pass.
        let mut finals: Vec<FinalPass> = Vec::new();
        let tick = media_tick();
        loop {
            tokio::time::sleep(tick).await;
            // The job actually on the wire. `active_stream` alone will
            // not do: it is deliberately left pointing at the last job
            // that ran so post-completion streaming keeps working, so
            // the queue is what says whether that job is still fetching.
            //
            // Two statements ON PURPOSE (issue #38): chained as
            // `.lock_ok().clone().filter(..)` the guard is a statement
            // temporary that stays held while the closure takes the
            // queue lock - the exact reverse of queue_json's
            // queue -> active_stream order. With a huge queue the
            // completion path holds the queue lock for seconds, this
            // task parked inside that convoy still holding
            // active_stream, a mode=queue poll won the queue mutex and
            // then blocked on active_stream: both sides frozen forever,
            // and with them every HTTP worker and the runner. The clone
            // must be bound (and the guard dropped) before any other
            // lock is touched.
            let cur = d.active_stream.lock_ok().clone();
            let live = cur.filter(|id| {
                d.queue_job(id)
                    .is_some_and(|job| job.lock_ok().state == JobState::Downloading)
            });
            // A different job (or none) is fetching: whatever we were
            // watching is owed its final pass.
            if watching != live
                && let Some(prev) = watching.take()
                && !finals.iter().any(|f| f.id == prev)
            {
                finals.push(FinalPass {
                    id: prev,
                    at: std::time::Instant::now(),
                    io_faults: 0,
                });
            }
            if let Some(id) = &live {
                if watching.is_none() {
                    watching = Some(id.clone());
                    tries = 0;
                    due = std::time::Instant::now();
                }
                let job = d.queue_job(id);
                let ask = job.as_ref().is_some_and(|job| {
                    let j = job.lock_ok();
                    !media_settled(&j)
                });
                if ask && std::time::Instant::now() >= due {
                    tries += 1;
                    due = std::time::Instant::now()
                        + if tries < MEDIA_FAST_TRIES {
                            tick
                        } else {
                            MEDIA_SLOW
                        };
                    let (d2, id2) = (d.clone(), id.clone());
                    // Blocking file reads, off the runtime's worker
                    // threads - the same rule the endpoint follows.
                    if let Ok(Some(facts)) =
                        tokio::task::spawn_blocking(move || probe_live_facts(&d2, &id2)).await
                        && let Some(job) = job
                        && latch_media(&job, facts)
                    {
                        // A DOWNLOADING job: `Absent` is the normal
                        // answer and `save_queue` below is what makes
                        // the chip durable. The call is here for the
                        // job that parked between the probe and this
                        // line, and only THAT one can be refused - so
                        // the reporting hangs off the outcome rather
                        // than off "nothing was written".
                        d.history_publish_change(&job, "the media chip");
                        d.save_queue();
                    }
                }
            }
            // The two events that owe a final pass: a record reaching
            // history, and an identity oracle answering after the chip
            // had already settled (a settled job has left `finals`, so
            // it has to be re-admitted here). Neither is something this
            // task can see for itself - see `Daemon::media_final_owed`.
            for id in d.media_final_owed.lock_ok().drain(..) {
                if !finals.iter().any(|f| f.id == id) {
                    finals.push(FinalPass {
                        id,
                        at: std::time::Instant::now(),
                        io_faults: 0,
                    });
                }
            }
            // Pass 2. One job per tick, and only once post-processing
            // has published the payload: `finalizing` is set for the
            // whole of unpack/rename/move, during which out_dir names a
            // directory whose contents are still arriving.
            finals.retain(|f| f.at.elapsed() < MEDIA_FINAL_WINDOW);
            let ready = finals.iter().position(|f| {
                d.history_job(&f.id).is_some_and(|job| {
                    let j = job.lock_ok();
                    // A failed job has no settled payload to read. The
                    // retain arm below already treats it that way; this
                    // stops it costing a directory walk and a "no media
                    // file" line first.
                    !j.finalizing && !media_settled(&j) && j.state != JobState::Failed
                })
            });
            match ready {
                Some(i) => {
                    let entry = finals.remove(i);
                    let Some(job) = d.history_job(&entry.id) else {
                        continue;
                    };
                    // This attempt IS the re-judge, whatever it reads:
                    // cleared before the probe so a failed read leaves
                    // the chip settled-as-judged, not owed forever.
                    job.lock_ok().media_rejudge = false;
                    let (d2, job2) = (d.clone(), job.clone());
                    // `_checked`, not the lossy wrapper: the three
                    // outcomes are three different things to say, and a
                    // row with no chip used to look exactly like a row
                    // nobody had probed. Every arm leaves a line.
                    let read =
                        tokio::task::spawn_blocking(move || probe_disk_facts_checked(&d2, &job2))
                            .await;
                    match read {
                        Ok(Ok(Some(facts))) => {
                            let shown = media_line(&facts);
                            if latch_media(&job, facts) {
                                info!(target: "media", "{}: {shown}", entry.id);
                                // Cosmetic, and self-healing on a build
                                // bump: the §188 re-derivation pass walks
                                // every row and writes the facts again.
                                d.history_publish_change(&job, "the media chip");
                                d.save_queue();
                            }
                        }
                        // A settled miss: the output holds no media file
                        // of ours, or its bytes are not a container we
                        // read. Both answer the same way forever, so this
                        // is the end of it and the row keeps no chip.
                        Ok(Ok(None)) => info!(
                            target: "media",
                            "{}: no media file to read in the output - the row keeps no chip",
                            entry.id
                        ),
                        // A failure to LOOK: an absent volume, a sleeping
                        // mount, a folder the OS declined. Worth another
                        // try, and worth saying once.
                        Ok(Err(e)) => {
                            if entry.io_faults == 0 {
                                warn!(
                                    target: "media",
                                    "{}: could not read the payload for the media chip - {e}",
                                    entry.id
                                );
                            }
                            if entry.io_faults + 1 < MEDIA_IO_RETRIES {
                                finals.push(FinalPass {
                                    io_faults: entry.io_faults + 1,
                                    ..entry
                                });
                            }
                        }
                        // The blocking thread itself died. Nothing was
                        // read and nothing can be said about the file.
                        Err(e) => warn!(
                            target: "media",
                            "{}: the media probe did not finish - {e}",
                            entry.id
                        ),
                    }
                }
                // Nothing ready, but drop any entry that has already
                // settled (pass 1 finished the job off) or that failed
                // outright and has no payload to read.
                None => finals.retain(|f| {
                    d.history_job(&f.id).is_none_or(|job| {
                        let j = job.lock_ok();
                        !media_settled(&j) && j.state != JobState::Failed
                    })
                }),
            }
        }
    });
}

/// Pass 1: the running job's main video, from the bytes on disk so far.
fn probe_live_facts(d: &Daemon, id: &str) -> Option<nzbkit::mediaprobe::MediaFacts> {
    let name = media_claim_name(&d.queue_job(id)?.lock_ok());
    let (file, w, mut r) = super::stream::open_live_probe(d, id)?;
    let info = nzbkit::mediaprobe::probe(
        &mut r,
        nzbkit::mediaprobe::ProbeHint {
            filename: Some(file),
            known_size: Some(w.size),
        },
    )
    .ok()?;
    Some(nzbkit::mediaprobe::facts::check(&info, &name))
}

/// Pass 2: the finished payload, whatever post-processing left behind,
/// keeping the difference between "there is nothing to read" and "I
/// could not read it".
///
/// `Ok(None)` is a settled answer: no media file of ours in the output
/// directory, or a file whose bytes are not a container we understand.
/// `Err` is a failure to look, and only ever an I/O one - the volume,
/// the permission, the network mount. Every caller needs that
/// distinction (Codex sweep 7, M6): the re-derivation pass must not
/// record "no payload" for a disk it never managed to read, and the
/// prober says a different thing in the log for each - a lossy wrapper
/// that erased both into `None` is what made a chipless row and an
/// unprobed row look identical.
pub(super) fn probe_disk_facts_checked(
    d: &Daemon,
    job: &Arc<Mutex<Job>>,
) -> std::io::Result<Option<nzbkit::mediaprobe::MediaFacts>> {
    let Some(path) = super::stream::finished_media_path_checked(d, job)? else {
        return Ok(None);
    };
    let name = media_claim_name(&job.lock_ok());
    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    let mut f = match std::fs::File::open(&path) {
        Ok(f) => f,
        // The walk named it a moment ago, so a NotFound here is a file
        // that has just been moved or deleted - an answer, not a fault.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let info = match nzbkit::mediaprobe::probe(
        &mut f,
        nzbkit::mediaprobe::ProbeHint {
            filename: path.file_name().map(|n| n.to_string_lossy().to_string()),
            known_size: Some(size),
        },
    ) {
        Ok(i) => i,
        // A container we cannot parse is a property of the FILE and will
        // read the same way forever; only the I/O arm is worth retrying.
        Err(nzbkit::mediaprobe::ProbeError::Io(e)) => return Err(e),
        Err(_) => return Ok(None),
    };
    Ok(Some(nzbkit::mediaprobe::facts::check(&info, &name)))
}

/// NZBFAST_NO_ENRICH=1 disables the metadata workers entirely - set by
/// the test suite (they hit the real internet: the IMDb refresher pulls
/// a ~25 MB dataset and ingests 425k rows on every fresh db, whose
/// write transaction also locked the first index scan out - the
/// long-standing scan_loop test "flake").
#[cfg(feature = "indexer")]
pub(super) fn spawn_enrichment_workers(daemon: &Arc<Daemon>, tmdb_key: &Option<String>) {
    if std::env::var_os("NZBFAST_NO_ENRICH").is_none() {
        {
            let d = daemon.clone();
            let key = tmdb_key.clone();
            let omdb = d.omdb_key.lock_ok().is_some();
            info!(
                target: "wall",
                "enrichment on via {} (posters cache to .spool/art)",
                if key.is_some() {
                    "TMDB"
                } else if omdb {
                    "TVmaze + OMDb + Wikidata/Wikipedia + AniList"
                } else {
                    "TVmaze + Wikidata/Wikipedia + AniList (keyless)"
                }
            );
            let stop = super::RunStop::current();
            super::spawn_aux("wall-enrich", move || wall_enricher(d, key, stop));
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
