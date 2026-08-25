//! Connection tuning: the live tuner's per-host controller, the
//! auto-connections ladder that measures what a server will actually
//! give, and [`update_tune_hint`], which judges total provider
//! capability against the user's stated line speed.
//!
//! Nothing here ever writes a connection count back to settings - the
//! target is state, and the dashboard's "using M of N" gauge follows it
//! through `ServerLive::budget`. What IS persisted is the bucketed seed
//! store in conntune.json, so the next daemon run starts warm.
//!
//! Split out of `serve/tasks.rs` whole (TODO 106) - the code is verbatim,
//! only visibility changed.

use super::*;

struct HostState {
    tuner: nzbkit::livetune::ServerTuner,
    shape: nzbkit::shaping::ShapeDetector,
    /// Rolling clean-epoch samples for the CURRENT bucket.
    per_conn: Vec<f64>,
    rates: Vec<f64>,
    /// Clean epochs observed since the last write-back.
    clean_epochs: u64,
    /// The kept target the store last saw, so unchanged
    /// targets cost no writes.
    persisted_target: usize,
    last_save: Option<std::time::Instant>,
}
fn median(xs: &[f64]) -> f64 {
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.total_cmp(b));
    if v.is_empty() { 0.0 } else { v[v.len() / 2] }
}

/// Hand the fleet back to the typed number in the same epoch the live-tune
/// toggle flips off, and leave the cold state a re-enable wants - the seed
/// store is exactly what makes that cheap.
///
/// Hand the fleet back to the typed number in the same
/// epoch the toggle flips. The handles the pool build
/// attached keep whatever the walk last wrote, and a
/// running job reads them live, so without this a fleet
/// walked down to 6 stays at 6 for the rest of the job
/// with nothing tuning it and the setting saying 24.
///
/// Split out of `spawn_live_tuner` (TODO 106), body verbatim.
fn stand_down(
    d: &Arc<Daemon>,
    config: &std::path::Path,
    announced: &mut bool,
    hosts: &mut std::collections::HashMap<String, HostState>,
) {
    if *announced {
        info!("live-tune: epoch controller off");
        *announced = false;
    }
    // Hand the fleet back to the typed number in the same
    // epoch the toggle flips. The handles the pool build
    // attached keep whatever the walk last wrote, and a
    // running job reads them live, so without this a fleet
    // walked down to 6 stays at 6 for the rest of the job
    // with nothing tuning it and the setting saying 24.
    if !hosts.is_empty() {
        let global = d.connections.load(Ordering::Relaxed).max(1);
        if let Ok(cfg) = nzbkit::config::Config::load(config) {
            let targets = d.hub.live_targets.lock_ok();
            for s in &cfg.servers {
                if let Some(t) = targets.get(&s.host) {
                    t.set(crate::conntune::effective_limit(global, s.connections));
                }
            }
        }
    }
    // Cold state on re-enable: the seed store is exactly
    // what makes that cheap.
    hosts.clear();
}

/// A bucket boundary mid-download must NOT jump the fleet
/// (design §5.1): the walk already tracks the live knee,
/// which outranks any stored seed as evidence, so crossing
/// only flushes the old bucket's samples and re-aims the
/// write-back. The new bucket's stored target is adopted
/// where it belongs - as the seed of the next cold start.
///
/// The caller adopts the new bucket after this returns. Split out of
/// `spawn_live_tuner` (TODO 106), body verbatim.
fn flush_bucket(
    d: &Arc<Daemon>,
    config: &std::path::Path,
    hosts: &mut std::collections::HashMap<String, HostState>,
    cur_bucket: u8,
    now_s: u64,
) {
    let global = d.connections.load(Ordering::Relaxed).max(1);
    let cfg_servers = nzbkit::config::Config::load(config)
        .map(|c| c.servers)
        .unwrap_or_default();
    for (host, st) in hosts.iter_mut() {
        if st.clean_epochs > 0 {
            let limit = cfg_servers
                .iter()
                .find(|s| s.host == *host)
                .map(|s| crate::conntune::effective_limit(global, s.connections))
                .unwrap_or_else(|| st.tuner.ceiling());
            crate::conntune::update_bucket(
                config,
                host,
                cur_bucket,
                crate::conntune::BucketUpdate {
                    target: st.tuner.target(),
                    per_conn_bps: median(&st.per_conn),
                    rate_bps: median(&st.rates),
                    epochs_add: st.clean_epochs,
                    limit,
                    now: now_s,
                },
            );
        }
        st.per_conn.clear();
        st.rates.clear();
        st.clean_epochs = 0;
        st.persisted_target = st.tuner.target();
        st.last_save = Some(std::time::Instant::now());
    }
}

/// TODO 112: the live connection tuner's epoch loop - one `EpochObs`
/// per server per epoch off the live gauges, fed to the pure
/// controller in `nzbkit::livetune`, whose verdict moves the per-host
/// `ConnTarget` the pool build attached. Gated by the `live_tune`
/// setting (default OFF; NZBFAST_LIVE_TUNE=1 is the dev override),
/// checked every epoch so the toggle takes effect without a restart.
///
/// Everything noisy stays in `livetune` behind pinned rules; this loop
/// only OBSERVES:
/// - rate: per-host byte delta over the epoch, from `pool_live`,
/// - busy: the same pool spanned the whole epoch, bytes moved, and the
///   article queue has not latched its tail (a drying queue measures
///   the queue, not the line),
/// - rate_limited: the global limiter is set and the aggregate sat
///   near it - socket-count verdicts are meaningless at a byte cap.
///   The index scan is OR'd in here (design §5.3): a deepening pull
///   competes for the same link, so socket-count verdicts taken
///   during one are meaningless too. Note the asymmetry with the
///   offline prober: a contaminated epoch merely aborts a cycle and
///   the controller keeps holding, so scan-heavy installs degrade to
///   "seed + hold" instead of starving,
/// - capacity_pressure: a "cap" ring event for this host inside the
///   epoch (481/502 refusals and the flap-keeper clamp both emit it),
/// - fleet_met: the fleet actually reached the target it was asked
///   to run.
///
/// The controller's belief lives here (per host, daemon lifetime); the
/// ceiling is re-read from config each epoch so a settings change
/// clamps within one epoch. Nothing is ever written to settings - the
/// target is state, and the dashboard's "using M of N" gauge follows
/// it through `ServerLive::budget`. What IS persisted (design §5.2) is
/// the bucketed seed store in conntune.json: kept targets and
/// clean-epoch medians, throttled, so the next daemon run starts warm.
/// The same samples feed the shaping decay detector (design §6).
pub(in crate::serve) fn spawn_live_tuner(daemon: &Arc<Daemon>, config: &std::path::Path) {
    let d = daemon.clone();
    let config = config.to_path_buf();
    // Mirror persisted decay flags for the queue payload before the
    // first epoch - and regardless of the toggle, so a flag raised
    // while the tuner was on stays visible after it is switched off.
    *d.shaped_hosts.lock_ok() = crate::conntune::load(&config)
        .into_iter()
        .filter_map(|(h, t)| t.shaped.map(|s| (h, s)))
        .collect();
    tokio::spawn(async move {
        let epoch_secs: u64 = std::env::var("NZBFAST_LIVE_TUNE_EPOCH_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60)
            .max(2);
        let epoch = std::time::Duration::from_secs(epoch_secs);
        /// Bucket writes per host are throttled to one per this window
        /// (plus the bucket-boundary flush) - linkpeak's SAVE_MIN_SECS
        /// idea, sized for a whole-file rewrite.
        const SAVE_MIN_SECS: u64 = 300;
        /// A bucket older than this is refreshed even when the kept
        /// target has not moved, so `checked` keeps tracking evidence.
        const BUCKET_REFRESH_SECS: u64 = 3600;
        /// Rolling clean-epoch samples kept per host for the medians.
        const SAMPLE_WINDOW: usize = 30;
        let mut announced = false;
        // The shared probe metronome (livetune::EpochObs::cycle_gate):
        // every server may START a cycle only on the same epochs, so
        // multi-server down-probes shrink together and stay
        // share-neutral on a saturated link. 6 = exactly one full
        // cycle (PAIRS*2 epochs): a kept verdict lands on the epoch
        // before the next gate, so momentum chains run back-to-back
        // and every server's pairs stay in lockstep.
        const CYCLE_SYNC_EPOCHS: u64 = 6;
        let mut epoch_idx: u64 = 0;
        let mut announced_saturated = false;
        let mut hosts: std::collections::HashMap<String, HostState> = Default::default();
        // (pool identity, per-host cumulative bytes) at epoch start.
        let mut prev: Option<(Arc<nzbkit::pool::LiveStats>, Vec<(String, u64)>)> = None;
        // Download-stretch id for the decay quorum: bumped whenever
        // the pool identity changes, so "across >= 2 stretches" means
        // what the design means (one bad evening is one bad evening).
        let mut stretch: u64 = 0;
        let mut cur_bucket = crate::conntune::bucket_of(crate::conntune::local_hour());
        loop {
            tokio::time::sleep(epoch).await;
            if !(d.live_tune.load(Ordering::Relaxed) || crate::conntune::live_tune_on()) {
                stand_down(&d, &config, &mut announced, &mut hosts);
                prev = None;
                continue;
            }
            if !announced {
                info!("live-tune: epoch controller on ({epoch_secs}s epochs)");
                announced = true;
            }
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|t| t.as_millis() as u64)
                .unwrap_or(0);
            let now_s = now_ms / 1000;
            let b_now = crate::conntune::bucket_of(crate::conntune::local_hour());
            if b_now != cur_bucket {
                flush_bucket(&d, &config, &mut hosts, cur_bucket, now_s);
                cur_bucket = b_now;
            }
            let live = d.hub.pool_live.lock_ok().clone();
            let Some(live) = live else {
                if prev.take().is_some() {
                    stretch += 1;
                }
                continue;
            };
            let bytes_now: Vec<(String, u64)> = live
                .servers
                .iter()
                .map(|s| (s.host.clone(), s.bytes.load(Ordering::Relaxed)))
                .collect();
            // The epoch is only a measurement if the SAME run spanned
            // it end to end.
            let Some((plive, pbytes)) = prev.replace((live.clone(), bytes_now.clone())) else {
                stretch += 1;
                continue;
            };
            if !Arc::ptr_eq(&plive, &live) {
                stretch += 1;
                continue;
            }
            let tail_latched = d
                .hub
                .queue_ctl
                .lock_ok()
                .as_ref()
                .and_then(|q| q.tail_pending())
                .is_some();
            let deltas: Vec<(String, u64)> = bytes_now
                .iter()
                .zip(pbytes.iter())
                .filter(|((h1, _), (h2, _))| h1 == h2)
                .map(|((h, b1), (_, b0))| (h.clone(), b1.saturating_sub(*b0)))
                .collect();
            let total: u64 = deltas.iter().map(|(_, b)| *b).sum();
            let cap = d.hub.rate.get();
            let total_rate = total as f64 / epoch.as_secs_f64();
            let rate_limited = cap > 0 && total_rate >= cap as f64 * 0.85;
            epoch_idx += 1;
            let cycle_gate = epoch_idx.is_multiple_of(CYCLE_SYNC_EPOCHS);
            // The link anchor: the linkpeak learner when it has one,
            // else the typed line speed, else 0 = unknown. With the
            // aggregate at ~the anchor the LINK is the binding
            // constraint, and per-server up-probes can only share-grab
            // (livetune::EpochObs::line_saturated). Unknown anchor
            // reads as never-saturated - the James-safe direction: a
            // wrongly-suppressed up-walk is a lasting cap, a wrongly
            // permitted one is walked back by the next down cycles.
            let (anchor, _) = d.link_peak.effective(d.line_speed.load(Ordering::Relaxed));
            let line_saturated = anchor > 0 && total_rate >= anchor as f64 * 0.85;
            // TODO 208 item 1: the walker walks WITHIN the fleet cap,
            // never owns it - it is per-server and sheds one socket per
            // ~7 epochs by design, and the cap is a fleet quantity.
            // Clamped on `desired` below rather than folded into the
            // controller's ceiling, so a cap that moves between jobs
            // does not read as a settings change. TODO 277: the same
            // `anchor` the saturation test above reads is what sizes
            // the cap, so the walker's clamp grows with the line
            // exactly as the job's own seed does.
            let line_share = crate::conntune::line_cap_share(live.servers.len(), anchor);
            if line_saturated != announced_saturated {
                info!(
                    "live-tune: link {} (fleet {:.0} Mbps vs anchor {:.0} Mbps)",
                    if line_saturated {
                        "saturated - up-probes parked"
                    } else {
                        "below its anchor - up-probes free"
                    },
                    total_rate * 8.0 / 1e6,
                    anchor as f64 * 8.0 / 1e6
                );
                announced_saturated = line_saturated;
            }
            // The index scan contaminates every server's epoch alike -
            // same shape as the limiter, so it rides the same flag.
            let scan_active = d.scan_active.load(Ordering::Relaxed);
            // Capacity events inside this epoch, by host.
            let epoch_start_ms = now_ms.saturating_sub(epoch.as_millis() as u64);
            // The WHOLE ring, not a count: the filter below is by TIME,
            // and `recent_events` trims by count first, so a storm of
            // more than the limit inside one epoch throws away the cap
            // events before the time filter can see them. Capacity
            // pressure is the one signal that outranks measurement, and
            // a storm is exactly when it is true.
            let cap_events: std::collections::HashSet<String> = live
                .recent_events(nzbkit::pool::EVENT_RING)
                .into_iter()
                .filter(|e| e.kind == "cap" && e.at_ms >= epoch_start_ms)
                .map(|e| e.host)
                .collect();
            // Whether the config could be READ this epoch, kept apart
            // from its contents: on a failed load a server has no
            // configured ceiling, and that must never be mistaken for
            // the user having changed the number (see the rebuild
            // below).
            let cfg_loaded = nzbkit::config::Config::load(&config);
            let cfg_read = cfg_loaded.is_ok();
            let cfg_servers = cfg_loaded.map(|c| c.servers).unwrap_or_default();
            let global = d.connections.load(Ordering::Relaxed).max(1);
            let store = crate::conntune::load(&config);
            for (i, sl) in live.servers.iter().enumerate() {
                let srv_cfg = cfg_servers.iter().find(|s| s.host == sl.host);
                // A pin set MID-SESSION leaves the handle the job build
                // attached in place, so "no handle" only catches servers
                // pinned before the build. The setting is the pin, and
                // it is checked here: walking a pinned server writes
                // `sl.budget` too, which is where the dashboard's
                // "using M of N" comes from - a number the user pinned
                // away from and nothing was allowed to move.
                if srv_cfg.is_some_and(|s| s.pin_connections) {
                    continue;
                }
                let target = {
                    let g = d.hub.live_targets.lock_ok();
                    g.get(&sl.host).cloned()
                };
                // No handle = pinned server, sidecar hub, or the
                // feature raced a config change: nothing to move.
                let Some(target) = target else { continue };
                // No server config this epoch (a failed load, or a host
                // the user removed while it is still live): fall back to
                // the GLOBAL limit, which is a bound we actually know -
                // `effective_limit` never returns more than it either.
                //
                // It used to fall back to `target.get()`, the value the
                // just-finished epoch ran at, and that is read BEFORE
                // `on_epoch` below and then used to clamp `desired`. A
                // ceiling equal to the current target is a one-way
                // ratchet: the controller can still walk down and can
                // never walk back up, so an up-probe leaves the live
                // target untouched, measures no gain, and confirms
                // itself. Down-only was invisible because each single
                // epoch looked like an ordinary decision.
                let ceiling = srv_cfg
                    .map(|s| crate::conntune::effective_limit(global, s.connections))
                    .unwrap_or(global);
                // The ceiling a `ServerTuner` is built with is immutable
                // and the per-epoch re-read only ever NARROWS (`.min`),
                // so a raised connections setting could not reach the
                // live controller at all: the James case, one layer up
                // from the knee it was found in. A configured ceiling
                // that no longer matches the controller's rebuilds the
                // host - the typed number takes effect on this epoch,
                // and the fresh controller seeds from it and re-learns.
                // Only ever off a config that actually LOADED, and only
                // for a server the config still lists: the fallback
                // above is the current target, which would otherwise
                // read as a ceiling change every epoch.
                if cfg_read
                    && srv_cfg.is_some()
                    && hosts
                        .get(&sl.host)
                        .is_some_and(|st: &HostState| !st.tuner.ceiling_matches(ceiling))
                {
                    info!(
                        "live-tune: {} connections setting changed - re-seating at {ceiling}",
                        sl.host
                    );
                    hosts.remove(&sl.host);
                    target.set(ceiling);
                }
                // Block-account rule (design §7.7): the live tuner may
                // hold or walk DOWN on a block fill, never probe up -
                // not because a probe epoch costs bytes (it does not),
                // but because in a multi-server fleet a faster block
                // server takes a larger SHARE of the articles, so
                // up-walking one shifts paid bytes onto it.
                // The explicit `block_account` server flag is the
                // user's own statement; a configured block quota
                // stays as the inference for accounts where they
                // never told us the size (M7b.2 §5.7).
                let block = srv_cfg.is_some_and(|s| s.block_account || s.block_bytes.is_some());
                let st = hosts.entry(sl.host.clone()).or_insert_with(|| HostState {
                    tuner: nzbkit::livetune::ServerTuner::new(target.get(), ceiling, 3),
                    shape: nzbkit::shaping::ShapeDetector::new(
                        store.get(&sl.host).is_some_and(|t| t.shaped.is_some()),
                    ),
                    per_conn: Vec::new(),
                    rates: Vec::new(),
                    clean_epochs: 0,
                    persisted_target: store
                        .get(&sl.host)
                        .and_then(|t| t.buckets.iter().find(|b| b.b == cur_bucket))
                        .map(|b| b.target)
                        .unwrap_or(0),
                    last_save: None,
                });
                let delta = deltas.get(i).map(|(_, b)| *b).unwrap_or(0);
                let connected = sl.connected.load(Ordering::Relaxed);
                let rate_bps = delta as f64 / epoch.as_secs_f64();
                // M7b.2 contract (steering doc §4.3): while this
                // server is depth-clamped or frontier-passed its byte
                // gauge measures the steering, not the line, so the
                // `steered` bit is per-server contamination - same
                // shape as scan_active. False until NZBFAST_STEER_DEPTH
                // arms, so this is inert on unarmed builds.
                let steered = sl.steered.load(Ordering::Relaxed);
                let obs = nzbkit::livetune::EpochObs {
                    rate_bps,
                    busy: delta > 0 && !tail_latched,
                    rate_limited: rate_limited || scan_active || steered,
                    capacity_pressure: cap_events.contains(&sl.host),
                    // A band, not a floor: an epoch measures its rung
                    // only if the fleet ENDED the epoch near the count
                    // it was asked to run. Below = the ramp; above =
                    // park drain still in flight from a down-step, so
                    // the bytes belong to a bigger fleet than the rung
                    // claims (rig 7 caught the walk trusting those and
                    // trimming through the knee). The slack covers the
                    // hot spare and prober extras.
                    fleet_met: {
                        let tgt = target.get();
                        connected >= tgt && connected <= tgt + (tgt / 32).max(2)
                    },
                    cycle_gate,
                    line_saturated,
                };
                let clean =
                    obs.busy && !obs.rate_limited && !obs.capacity_pressure && obs.fleet_met;
                let before = st.tuner.target();
                st.tuner.on_epoch(obs);
                let mut desired = st.tuner.desired().min(ceiling);
                if let Some(share) = line_share {
                    desired = desired.min(share);
                }
                if block {
                    desired = desired.min(st.tuner.target());
                }
                target.set(desired);
                sl.budget.store(target.get(), Ordering::Relaxed);
                if st.tuner.target() != before {
                    info!(
                        "live-tune: {} using {} of {ceiling} (was {before})",
                        sl.host,
                        st.tuner.target()
                    );
                }
                if !clean || connected == 0 {
                    continue;
                }
                // ---- clean epoch: evidence for the store + decay ----
                let per_conn = rate_bps / connected as f64;
                st.per_conn.push(per_conn);
                st.rates.push(rate_bps);
                if st.per_conn.len() > SAMPLE_WINDOW {
                    st.per_conn.remove(0);
                    st.rates.remove(0);
                }
                st.clean_epochs += 1;
                // Decay reference (design §6): while flagged, the rate
                // the host fell FROM is the recovery bar; while
                // healthy, the current bucket's evidenced median.
                let tref = store.get(&sl.host);
                let reference = tref
                    .and_then(|t| t.shaped.as_ref().map(|s| s.ref_per_conn_bps))
                    .or_else(|| {
                        tref.and_then(|t| {
                            t.buckets
                                .iter()
                                .find(|b| {
                                    b.b == cur_bucket
                                        && crate::conntune::bucket_fresh(b, now_s)
                                        && b.epochs >= crate::conntune::BUCKET_MIN_EPOCHS
                                        && b.per_conn_bps > 0.0
                                })
                                .map(|b| b.per_conn_bps)
                        })
                    });
                if tref.is_some_and(|t| t.shaped.is_some()) != st.shape.shaped() {
                    // The store and the detector disagree - a fresh
                    // ladder cleared the flag (reconcile's fresh-
                    // reference rule), or another writer raised it.
                    // The store is the authority; the mirror follows.
                    st.shape.reset_reference();
                    if tref.is_none_or(|t| t.shaped.is_none()) {
                        d.shaped_hosts.lock_ok().remove(&sl.host);
                    }
                }
                if let Some(refv) = reference {
                    match st.shape.on_epoch(per_conn, refv, stretch, true) {
                        nzbkit::shaping::ShapeVerdict::Raised => {
                            let sh = crate::conntune::Shaped {
                                since: now_s,
                                ref_per_conn_bps: refv,
                            };
                            // One confirmation ladder at the next idle
                            // window (checked goes to 0) - unless this
                            // is a block fill, where an unasked-for
                            // ladder would spend the user's own bytes.
                            crate::conntune::set_shaped(
                                &config,
                                &sl.host,
                                Some(sh.clone()),
                                !block,
                            );
                            d.shaped_hosts.lock_ok().insert(sl.host.clone(), sh);
                            info!(
                                "live-tune: {} flagged as shaped - delivering ~{:.0} Mbps \
                                 per connection against a usual ~{:.0} Mbps",
                                sl.host,
                                per_conn / 1e6,
                                refv / 1e6
                            );
                        }
                        nzbkit::shaping::ShapeVerdict::Cleared => {
                            crate::conntune::set_shaped(&config, &sl.host, None, false);
                            d.shaped_hosts.lock_ok().remove(&sl.host);
                            info!(
                                "live-tune: {} recovered to ~{:.0} Mbps per connection - \
                                 shaped flag cleared",
                                sl.host,
                                per_conn / 1e6
                            );
                        }
                        nzbkit::shaping::ShapeVerdict::Hold => {}
                    }
                }
                // ---- throttled write-back (design §5.2) ----
                let due = st
                    .last_save
                    .is_none_or(|t| t.elapsed().as_secs() >= SAVE_MIN_SECS);
                let bucket_stale = tref
                    .and_then(|t| t.buckets.iter().find(|b| b.b == cur_bucket))
                    .is_none_or(|b| now_s.saturating_sub(b.checked) > BUCKET_REFRESH_SECS);
                if due && (st.tuner.target() != st.persisted_target || bucket_stale) {
                    crate::conntune::update_bucket(
                        &config,
                        &sl.host,
                        cur_bucket,
                        crate::conntune::BucketUpdate {
                            target: st.tuner.target(),
                            per_conn_bps: median(&st.per_conn),
                            rate_bps: median(&st.rates),
                            epochs_add: st.clean_epochs,
                            limit: ceiling,
                            now: now_s,
                        },
                    );
                    st.persisted_target = st.tuner.target();
                    st.clean_epochs = 0;
                    st.last_save = Some(std::time::Instant::now());
                }
            }
        }
    });
}

/// Re-point the dashboard's shaped mirror at what the store now says
/// for one host, after a ladder result has been recorded.
///
/// The store is the authority (`reconcile`: a trusted ladder is a fresh
/// reference and clears the flag), but `d.shaped_hosts` is a separate
/// in-memory map, and the only place it was reconciled with the store
/// is the live tuner's clean-epoch branch. With live tuning off, or
/// between downloads, nothing ran it - so a host whose flag a ladder
/// had just cleared kept telling the queue payload it was shaped, for
/// the life of the daemon. Called from BOTH ladder paths, the manual
/// Test and the idle auto probe.
pub(in crate::serve) fn mirror_shaped(d: &Daemon, config: &std::path::Path, host: &str) {
    let stored = crate::conntune::load(config)
        .get(host)
        .and_then(|t| t.shaped.clone());
    let mut m = d.shaped_hosts.lock_ok();
    match stored {
        Some(s) => {
            m.insert(host.to_string(), s);
        }
        None => {
            m.remove(host);
        }
    }
}

/// Judge measured provider capability against the user's stated line
/// speed (`line_speed`, the Settings hint of what the connection can
/// do) and store the verdict in `tune_hint` for the dashboard. Called
/// after every ladder - auto probe or manual run.
///
/// Only judges with a FULL picture: line speed set, and every enabled
/// server probed. A missing probe reads as capability the daemon
/// can't see yet, and a false "your setup is short" is worse than
/// saying nothing.
///
/// Two ways to be wrong, so two bands: well under the line (providers
/// are the lever) and well OVER it (the setting is the lever - the
/// ladder never stops measuring at the line speed, so a stale 300M on a
/// gigabit link shows up here rather than silently capping the reading).
/// In between, the setup covers the line and the hint clears.
pub(in crate::serve) fn update_tune_hint(
    d: &Daemon,
    servers: &[nzbkit::config::ServerConfig],
    tuned: &std::collections::HashMap<String, crate::conntune::Tuned>,
) {
    let expected_bps = d.line_speed.load(Ordering::Relaxed);
    // §210: the local link comes first, because it is the yardstick.
    // A Wi-Fi link or a port negotiated under the line caps what ANY
    // provider can show, so the provider verdict below is scored
    // against the lower of the two - otherwise a 710 Mbit line over a
    // 1200 Mbps Wi-Fi link reads "providers are short" forever, and
    // the lever it names (a faster provider) cannot help.
    let link = d.local_link.lock_ok().clone();
    let link_verdict = link
        .as_ref()
        .map(|l| l.verdict(expected_bps))
        .unwrap_or_default();
    let yardstick = link
        .as_ref()
        .and_then(|l| l.ceiling_bps())
        .filter(|c| *c < expected_bps)
        .unwrap_or(expected_bps);
    let mut hint = String::new();
    let enabled: Vec<_> = servers.iter().filter(|s| s.enabled).collect();
    // Only the servers the prober will ever measure. It skips metered
    // accounts on purpose (a ladder would spend the user's own money),
    // so requiring EVERY enabled server to carry an entry meant one
    // enabled block account suppressed the line-speed verdict for the
    // whole install, permanently and with nothing in the log saying
    // why. Same predicate as the prober's, deliberately - see
    // `may_spend_on_measurement`.
    let measured: Vec<_> = enabled
        .iter()
        .copied()
        .filter(|s| s.may_spend_on_measurement())
        .collect();
    // Key presence is NOT proof of measurement. `note_capped` creates an
    // entry for a host that has never run a ladder - the whole point is
    // to remember a cap on a provider that never got a clean probe - and
    // it carries `connections: 0`, which every knee consumer already
    // reads as "nothing measured". Treating it as measured summed its
    // zero Gbps, so the hint could claim the fleet covers half the line
    // and recommend a faster provider on the strength of a host nobody
    // had timed (Codex sweep 5, M8).
    let is_measured = |h: &str| tuned.get(h).is_some_and(|t| t.connections > 0);
    if expected_bps > 0 && !measured.is_empty() && measured.iter().all(|s| is_measured(&s.host)) {
        let cap_bytes: f64 = measured.iter().map(|s| tuned[&s.host].gbps).sum::<f64>() * 1e9 / 8.0;
        let pct = (100.0 * cap_bytes / yardstick as f64).round() as u64;
        if cap_bytes > expected_bps as f64 * 1.1 {
            // The ladder deliberately measures PAST the line speed, so a
            // reading well above it is not an error - it means the number
            // in Settings is stale (an unchanged 300M after a gigabit
            // upgrade). Say so: percentage speed limits are computed from
            // it, so a low setting silently throttles them too.
            hint = format!(
                "providers measured ~{:.0} Mbps together, {pct}% of the ~{:.0} Mbps \
                 Line speed set in Settings - the setting looks low, raise it so \
                 percentage speed limits and these readings are right",
                cap_bytes * 8.0 / 1e6,
                expected_bps as f64 * 8.0 / 1e6
            );
        } else if cap_bytes < yardstick as f64 * 0.8 {
            let meas = cap_bytes * 8.0 / 1e6;
            let want = yardstick as f64 * 8.0 / 1e6;
            let mut tips: Vec<String> = Vec::new();
            for s in &measured {
                let t = &tuned[&s.host];
                // Against what the ladder ASKED for, not what the server
                // is configured for. The ladder stops at the knee, so on
                // a server set to 20 whose knee is 8 it may never ask
                // beyond 16 - and comparing against 20 then told the
                // user their account tier was capping them, using a
                // number nothing had requested. `asked == 0` is an entry
                // from before the field existed: unknown, so say
                // nothing.
                // The knee rung against what it was actually granted -
                // "32 asked, 21 granted" - not against the CONFIGURED
                // count. The ladder stops at the knee, so on a server set
                // to 20 whose knee is 8 it may never ask beyond 16, and
                // comparing against 20 told the user their account tier
                // was capping them using a number nothing had requested.
                // `connections` is already clamped to the granted count
                // at that rung, so the pair is exact. `asked == 0` is an
                // entry from before the field existed: unknown, so say
                // nothing.
                if t.asked > 0 && t.asked > t.connections {
                    tips.push(format!(
                        "{} granted only {} of the {} connections asked for - the \
                         account tier may cap it",
                        s.host, t.connections, t.asked
                    ));
                }
            }
            if measured.len() == 1 {
                tips.push("a second provider adds parallel headroom".into());
            } else if tips.is_empty() {
                tips.push("a faster provider (or one more) is the likely lever".into());
            }
            // Name what the figure was scored against: the line the
            // user typed, or the local link when that is lower.
            let what = if yardstick < expected_bps {
                "this machine's link can carry"
            } else {
                "line"
            };
            hint = format!(
                "providers measured ~{meas:.0} Mbps together, {pct}% of the \
                 ~{want:.0} Mbps {what} - well short. {}",
                tips.join("; ")
            );
        }
    }
    let hint = match (link_verdict.is_empty(), hint.is_empty()) {
        (true, _) => hint,
        (false, true) => link_verdict,
        (false, false) => format!("{link_verdict}. Also: {hint}"),
    };
    let mut cur = d.tune_hint.lock_ok();
    if *cur != hint {
        if hint.is_empty() {
            info!(target: "tune", "provider capability now covers the stated line speed");
        } else {
            info!(target: "tune", "{hint}");
        }
        *cur = hint;
    }
}

/// M7b.1: connection auto-tune (live setting auto_connections,
/// default ON). While the queue is idle, probe one provider whose
/// ladder result is missing or older than a week and store the knee
/// in conntune.json next to the config - every job build then caps
/// that server at min(configured, knee); over-asking measured 3-4×
/// slower than the knee (connect-flood defense). Block accounts are
/// never probed (a ladder run would eat the paid block). Probe
/// traffic is billed to the data-usage ledger like any other bytes.
pub(in crate::serve) fn spawn_auto_connections(daemon: &Arc<Daemon>, config: &std::path::Path) {
    let d = daemon.clone();
    let cfg_path = config.to_path_buf();
    let rt = tokio::runtime::Handle::current();
    // Before anything else, and synchronously: sweep knees the user's
    // current settings have outgrown. This runs at boot rather than in
    // the probe thread below because a job can start inside the 120 s
    // settling sleep, and a job that starts capped by a knee the user
    // already disowned is the whole complaint (v1.0.14 field report:
    // 6 sockets of 24 asked for, ~25 MB/s on a 900 Mbps line, across
    // every download in his history). Pre-guard files on disk are only
    // ever reachable from here - a record-time guard cannot revisit
    // them.
    crate::conntune::reopen_for_install(config, d.connections.load(Ordering::Relaxed));
    // Weak from here on: the probe lane outlives nothing but itself, and
    // an embedded host that stops mid-settle must not be left holding a
    // whole daemon generation (nor a thread that would go on dialling
    // the user's provider afterwards). `rt` is this run's runtime too.
    let dw = Arc::downgrade(&d);
    drop(d);
    let stop = crate::serve::RunStop::current();
    crate::serve::spawn_aux("auto-conn", move || {
        // In-memory failure backoff so an unreachable server is
        // retried in hours, not every minute.
        let mut attempted: std::collections::HashMap<String, u64> = Default::default();
        // Let startup settle before the first probe.
        if !stop.sleep(std::time::Duration::from_secs(120)) {
            return;
        }
        loop {
            if !stop.sleep(std::time::Duration::from_secs(60)) {
                return;
            }
            let Some(d) = dw.upgrade() else { return };
            if !d.auto_connections.load(Ordering::Relaxed) {
                continue;
            }
            // Offline is a promise that this machine is touching no
            // provider - the whole point of the switch is freeing the
            // account for another box - and a ladder is the single
            // heaviest thing this daemon does unasked: up to 64
            // concurrent connections pulling real article bodies for as
            // long as four minutes. Measured on a live daemon 11 Aug
            // 2026: two full ladders against the user's provider (07:41
            // and 13:41) while `offline` had been true since 03:25, the
            // second of which APPLIED its knee. A number measured in
            // a state the operator declared provider-free is not one to
            // trust either. The manual Test button is unaffected - that
            // one is asked for.
            if d.offline.load(Ordering::Relaxed) {
                continue;
            }
            let busy = d.queue.lock_ok().iter().any(|j| {
                matches!(
                    j.lock_ok().state,
                    JobState::Downloading | JobState::Finishing
                )
            });
            // An index scan or deepening pass pulls headers over the SAME
            // provider the ladder measures (field case: a 90k headers/s
            // deepening pull mid-probe reads every rung flat and fakes a
            // knee at a fraction of the true one). "Idle" must mean the
            // LINK is idle, not just the job queue.
            if busy || d.scan_active.load(Ordering::Relaxed) {
                continue;
            }
            let Ok(cfg) = nzbkit::config::Config::load(&cfg_path) else {
                continue;
            };
            let tuned = crate::conntune::load(&cfg_path);
            let now = epoch_secs();
            let Some(srv) = cfg
                .servers
                .iter()
                .find(|srv| {
                    // A disabled server must not be probed: jobs will
                    // never use its knee, and an unreachable one puts
                    // "[tune] ... connect timed out" in the log every
                    // few hours forever.
                    //
                    // Nor may a metered one (M7b.2 §5.7, and the
                    // conn-tuning design's rule 7a - two designs, one
                    // rule): every rung of this ladder is tens of
                    // seconds of real article bodies, and on a per-byte
                    // account that is the user's money spent on a
                    // number they never asked for. `block_account` is
                    // the user's own statement; a configured
                    // `block_bytes` implies the same thing for those
                    // who told us the size instead, and
                    // `may_spend_on_measurement` is both. The MANUAL
                    // Test button stays open to them - choosing to
                    // spend is theirs to make - and it says so before
                    // it runs.
                    srv.enabled
                        && srv.may_spend_on_measurement()
                        && attempted
                            .get(&srv.host)
                            .is_none_or(|&t| now.saturating_sub(t) > 6 * 3600)
                        && tuned.get(&srv.host).is_none_or(|t| {
                            // A knee that caps the server below HALF its
                            // configured connections halves the user's
                            // line if it is wrong, so it does not get a
                            // week of trust: re-probe within hours - far
                            // enough apart that the corroborating sample
                            // sees a different time of day. A genuine
                            // connect-flood knee will reproduce; a
                            // transient (congestion, a busy Mac during
                            // the 5 s samples) will not. Field case: a
                            // gigabit user tuned to 6 and ran at half the
                            // speed of a 16-connection client for days.
                            // (`suspect` flags entries written by this
                            // build; the half-check also catches knees
                            // recorded before the flag existed.)
                            // Judged against the ceiling a job would
                            // REALLY hand this server, which is what
                            // `record` used when it decided `suspect` -
                            // the global setting caps the per-server
                            // number too. Against `srv.connections`
                            // alone, a knee that is perfectly healthy
                            // under a lower global reads as
                            // "suspiciously low" forever: a default
                            // global of 8 with a server configured at 50
                            // calls a knee of 20 suspect, every probe
                            // rewrites `checked`, and the 6-hourly clock
                            // therefore never settles into the 7-day
                            // one. That is roughly 5 GB of probe traffic
                            // four times a day, billed to the user's
                            // account and metered quota, for a verdict
                            // that cannot change.
                            let ceiling = crate::conntune::effective_limit(
                                d.connections.load(Ordering::Relaxed),
                                srv.connections,
                            );
                            // The half-check applies ONLY to entries
                            // written before `suspect` existed. Left
                            // unscoped it never lets a genuinely low
                            // knee settle: global 20, server 20, true
                            // knee 8 - probe one flags it, probe two
                            // corroborates it, `suspect` clears and it
                            // is applied and correct, and then every
                            // later pass still reads 8*2 <= 20 and puts
                            // it back on the 6-hourly clock. A full
                            // ladder every six hours forever, for a
                            // verdict that has already settled and
                            // cannot change - the same cost this
                            // comment was written to prevent, arrived at
                            // from the other direction. The term
                            // conflates "unproven" with "low"; after
                            // corroboration only the first should still
                            // buy a short clock.
                            // A PARKED reading is an outstanding question
                            // and belongs on the short clock. `reconcile`
                            // deliberately leaves `suspect` false on these
                            // - the point is that the old knee stays IN
                            // FORCE while the new one waits - so reading
                            // only `suspect` here made the second opinion
                            // the whole mechanism exists to collect wait
                            // seven days instead of six hours, defeating
                            // the fix it is part of.
                            let suspicious = t.suspect
                                || t.pending.is_some()
                                || (t.v < crate::conntune::SCHEMA && t.connections * 2 <= ceiling);
                            let ttl = if suspicious {
                                crate::conntune::SUSPECT_STALE_SECS
                            } else {
                                crate::conntune::STALE_SECS
                            };
                            now.saturating_sub(t.checked) > ttl
                        })
                })
                .cloned()
            else {
                continue;
            };
            // Never probe over a manual test the user is watching (or
            // over another provider's auto probe): skip this cycle and
            // come back, rather than making two measurements wrong.
            let Some(_permit) = crate::serve::daemon::LadderPermit::try_take(&d) else {
                continue;
            };
            // Last look before up to four minutes of real provider
            // traffic on a runtime this run may be about to lose. A
            // ladder that outlives its own daemon is billed to the
            // user's account for a knee nothing will ever read.
            if stop.stopping() {
                return;
            }
            attempted.insert(srv.host.clone(), now);
            let _busy = d.busy.hold("measuring");
            // Real-content articles from the install's own downloads,
            // STAT-verified on THIS provider (design doc 12.1) - the
            // synthetic probe group undermeasured a provider 17x and
            // none of the knee guards can catch a deterministic error.
            // Nothing usable = no ladder: leave the provider untuned
            // (the live tuner learns from the first real download)
            // rather than record a structurally wrong knee. The 6 h
            // attempt backoff above already paces the retry.
            let Some(ids) = rt.block_on(crate::serve::probeids::real_ladder_ids(&d, &srv)) else {
                info!(
                    target: "tune",
                    "{}: no verified articles from recent downloads to measure with - \
                     leaving connections untuned until a download provides some",
                    srv.host
                );
                continue;
            };
            let cap = (srv.connections.max(1) as usize * 2).clamp(30, 100);
            // What a job would really hand this server, which is what a
            // knee has to be plausible against - not the probe cap.
            let ceiling = crate::conntune::effective_limit(
                d.connections.load(Ordering::Relaxed),
                srv.connections,
            );
            info!(target: "tune", "probing {} connection ladder (queue idle)", srv.host);
            let res = rt.block_on(async {
                tokio::time::timeout(
                    std::time::Duration::from_secs(240),
                    // The background probe publishes too: it is the one
                    // a user never asked for, so seeing WHY the number
                    // moved matters even more than on a manual run.
                    nzbkit::sysbench::conn_ladder(&srv, ids.clone(), cap, ceiling, 5, {
                        let dd = d.clone();
                        let host = srv.host.clone();
                        move |phase, at, steps| {
                            *dd.ladder_live.lock_ok() = Some(crate::serve::daemon::LadderLive {
                                host: host.clone(),
                                phase: phase.into(),
                                at,
                                steps: steps.to_vec(),
                                started: now,
                                done: false,
                            });
                            // Cancel stops whichever ladder is running,
                            // and the permit means that is exactly one.
                            !dd.ladder_cancel.load(Ordering::Acquire)
                        }
                    }),
                )
                .await
            });
            if let Some(l) = d.ladder_live.lock_ok().as_mut() {
                l.done = true;
            }
            match res {
                Ok(Ok(steps)) if !steps.is_empty() => {
                    // A jagged ladder gets its contested rungs re-measured
                    // once before anything is read off it. Costs a probe
                    // per disagreeing rung (~5 s each) and only fires when
                    // the rungs actually contradict each other - a clean
                    // curve is its own corroboration, since every rung
                    // agrees with its neighbours.
                    let contested = crate::conntune::knee_of(&steps)
                        .map(|k| (k.contested, k.gbps))
                        .filter(|(c, _)| !c.is_empty());
                    let steps = match contested {
                        None => steps,
                        Some((rungs, peak)) => {
                            info!(
                                target: "tune",
                                "{}: ladder disagrees with itself - re-measuring {:?}",
                                srv.host, rungs
                            );
                            // The same verified supply; remeasure
                            // rotates through it just as the climb did
                            // (the old path re-discovered the same
                            // newest-headers ids, so the overlap
                            // behavior is unchanged).
                            let again = rt.block_on(async {
                                tokio::time::timeout(
                                    std::time::Duration::from_secs(120),
                                    nzbkit::sysbench::remeasure(&srv, ids.clone(), &rungs, peak, 5),
                                )
                                .await
                            });
                            match again {
                                // Not billed here: merge_samples SUMS the
                                // two samples' bytes into the merged rung,
                                // and the ledger write below bills the
                                // merged ladder. Billing `extra` as well
                                // would charge the re-measure twice.
                                Ok(Ok(extra)) => crate::conntune::merge_samples(&steps, &extra),
                                // A failed re-measure leaves the ladder as
                                // it was: still jagged, so still suspect.
                                _ => {
                                    warn!(
                                        target: "tune",
                                        "{}: re-measure failed - keeping the jagged ladder",
                                        srv.host
                                    );
                                    steps
                                }
                            }
                        }
                    };
                    d.add_usage(&[(srv.host.clone(), steps.iter().map(|s| s.bytes).sum())]);
                    // The per-rung rates in the log are the ONLY record
                    // of WHY a knee was chosen - a bare verdict left a
                    // user report ("it picked 6") undiagnosable.
                    let rungs: Vec<String> = steps
                        .iter()
                        .map(|s| {
                            format!(
                                "{}c {:.2} Gbps (granted {})",
                                s.connections, s.gbps, s.granted
                            )
                        })
                        .collect();
                    info!(target: "tune", "{} ladder: {}", srv.host, rungs.join(", "));
                    // The idle gate at the top of this loop is a ONE-SHOT
                    // pre-check, and the ladder runs for up to 180 s
                    // after it passed. A job the scheduler picked up in
                    // the meantime, or an index scan or deepening pass
                    // waking, pulls headers over this very provider and
                    // reads every rung flat - which is exactly the
                    // faked-low-knee shape the corroboration rule exists
                    // for, arriving this time from our own side. Nothing
                    // tells the ladder that happened, so ask afterwards:
                    // if the link is no longer idle the measurement
                    // cannot be trusted, and an unrecorded provider is
                    // simply re-probed where a wrongly-recorded one gets
                    // applied.
                    let still_idle = !d.scan_active.load(Ordering::Relaxed)
                        && !d.queue.lock_ok().iter().any(|j| {
                            matches!(
                                j.lock_ok().state,
                                JobState::Downloading | JobState::Finishing
                            )
                        });
                    if !still_idle {
                        info!(
                            target: "tune",
                            "{}: a download or index scan started while the ladder ran - \
                             discarding the measurement rather than recording a knee \
                             taken against a busy link",
                            srv.host
                        );
                        continue;
                    }
                    // A ladder that moved nothing is not a knee of 2 - it is
                    // no measurement at all, and recording it would cap this
                    // provider at 2 connections permanently once the next
                    // probe reproduced it and called that corroboration.
                    let Some(knee) = crate::conntune::knee_of(&steps) else {
                        warn!(
                            target: "tune",
                            "{}: ladder moved no data at any rung - the provider \
                             served no bodies, so no knee was recorded",
                            srv.host
                        );
                        continue;
                    };
                    let (best, peak) = (knee.connections, knee.gbps);
                    let granted = steps.iter().map(|s| s.granted).max().unwrap_or(0);
                    // The ceiling a job would really hand this server:
                    // the global setting caps it too, and judging the
                    // knee against the server's own number alone called
                    // a knee "low" on an install whose global setting
                    // WAS that number.
                    let limit = crate::conntune::effective_limit(
                        d.connections.load(Ordering::Relaxed),
                        srv.connections,
                    );
                    // Re-read the store rather than trust the snapshot
                    // taken before the ladder. `record` replaces the
                    // host's entry wholesale, and 180 s is long enough
                    // for the user to have run the settings-page Test
                    // and had it finish: their explicit run, documented
                    // as "their call, applied as-is", was then silently
                    // overwritten by a measurement that started before
                    // it. The fresher answer wins, and it also feeds the
                    // corroboration below - judging that against the
                    // stale snapshot meant a newer sample could not even
                    // influence the flag.
                    let fresh = crate::conntune::load(&cfg_path);
                    if fresh
                        .get(&srv.host)
                        .is_some_and(|p| p.source == "manual" && p.checked >= now)
                    {
                        info!(
                            target: "tune",
                            "{}: a manual test landed while this probe ran - keeping the \
                             user's own result",
                            srv.host
                        );
                        continue;
                    }
                    // One rule, shared with the dashboard's Test button.
                    // `is_suspect` carries the same "unproven unless a
                    // second probe agrees" logic and corroborates through
                    // `corroborates`, so a parked reading is compared
                    // against the parked value - see conntune.
                    let suspect =
                        crate::conntune::is_suspect(best, limit, knee.jagged, fresh.get(&srv.host));
                    if knee.jagged {
                        warn!(
                            target: "tune",
                            "{}: ladder is JAGGED - the rate drops below {:.0}% of \
                             peak between {}c and the {}c peak, so the link was not \
                             quiet enough to measure a knee",
                            srv.host,
                            crate::conntune::LADDER_BAR * 100.0,
                            best,
                            knee.peak_at
                        );
                    }
                    crate::conntune::record(
                        &cfg_path,
                        &srv.host,
                        crate::conntune::Tuned {
                            connections: best,
                            granted,
                            asked: knee.asked,
                            gbps: peak,
                            checked: now,
                            source: "auto".into(),
                            suspect,
                            limit,
                            v: crate::conntune::SCHEMA,
                            pending: None,
                            buckets: Vec::new(),
                            shaped: None,
                            capped: None,
                        },
                    );
                    mirror_shaped(&d, &cfg_path, &srv.host);
                    if suspect {
                        info!(
                            target: "tune",
                            "{}: knee {best} of {limit} configured looks LOW - \
                             not applied yet; a re-probe in ~6 h must agree first \
                             ({peak:.2} Gbps peak)",
                            srv.host
                        );
                    } else if best < limit {
                        info!(
                            target: "tune",
                            "{}: knee is {best} of {limit} configured - jobs \
                             will use {best} ({peak:.2} Gbps peak)",
                            srv.host
                        );
                    } else if best > limit {
                        info!(
                            target: "tune",
                            "{}: knee {best} is ABOVE the configured {limit} - \
                             raise the server's connections to use it ({peak:.2} Gbps peak)",
                            srv.host
                        );
                    } else {
                        info!(
                            target: "tune",
                            "{}: configured {limit} sits at the knee \
                             ({peak:.2} Gbps peak)",
                            srv.host
                        );
                    }
                    // With this probe recorded, re-judge total provider
                    // capability against the user's stated line speed.
                    update_tune_hint(&d, &cfg.servers, &crate::conntune::load(&cfg_path));
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) => info!(target: "tune", "{} ladder failed: {e}", srv.host),
                Err(_) => info!(target: "tune", "{} ladder timed out", srv.host),
            }
        }
    });
}
