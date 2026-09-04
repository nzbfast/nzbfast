//! TODO §77 post-health preflight: STAT a sample of a queued job's
//! articles across every configured server, so the queue row can say
//! what a post looks like out there BEFORE the bandwidth is spent
//! rather than at 97%.
//!
//! THE LANE ONLY: the tick loop that picks a job, probes it and hangs
//! the verdict on it. Everything it is built out of - the stand-down
//! predicates, the stratified sampler, the STAT burst, the escalation
//! and the §303 add-time preview - is `crate::postprobe`, one
//! layer down, because `api::queue::preview` runs the preview on a POST
//! and an API handler must not reach into a background lane. The
//! SCORING, and the reasons the verdict is only ever advisory, stay in
//! [`crate::health`] - nothing in either concludes anything.
//!
//! Split out of `tasks.rs` whole under the size gate (TODO 106);
//! the code is verbatim, only visibility changed.

use super::*;

/// TODO §77 post-health prober: STAT a handful of a queued job's
/// articles across every configured server and hang the verdict on the
/// job, so the queue row can say "posted four days ago, on none of your
/// three servers (8 sampled)" before the bandwidth is spent rather than
/// at 97%. The scoring, and the reasons it is only ever advisory, live
/// in [`crate::health`].
///
/// Discipline copied from `spawn_oracle_sampler` (in `tasks/indexer.rs`),
/// and for the same reasons (memory `nzbfast-idle-connection-holders`):
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
pub fn spawn_health_prober(daemon: &Arc<Daemon>, config: &std::path::Path) {
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
                            // A paused job is not going to start, so it
                            // is not worth a provider round trip until
                            // it is resumed - EXCEPT a held alternative
                            // (§295): promotion picks among held rows
                            // the moment their primary fails, and a
                            // pick made blind can spend a full download
                            // discovering a spare is as dead as the job
                            // it replaced. Held rows are exactly the
                            // paused jobs whose health is consulted
                            // WHILE they are paused.
                            && (!g.paused
                                || (g.priority == DUPE_PRIORITY && !g.held_for.is_empty()))
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
            let path = nzb_path.clone();
            let Ok(Some(sample)) = tokio::task::spawn_blocking(move || sample_job(&path, k)).await
            else {
                // An unreadable or article-less NZB is not an error
                // worth logging on every tick: the job simply gets no
                // badge, and the download decides for itself.
                unsampleable.insert(nzo_id.clone());
                continue;
            };
            let verdict =
                probe_sample(&d, &servers, sample, Resample::Path(nzb_path), probes + 1).await;
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
                    if let Some(c) = v
                        .completable
                        .filter(|c| *c != crate::health::Completable::Yes)
                    {
                        info!(target: "health", "{nzo_id} completable: {}", c.as_str());
                    }
                    // Logged on its own line, and only when it has
                    // something to say: a green recovery set is the
                    // overwhelmingly common case and a second line per
                    // job is how a log stops being read.
                    if let Some(r) = v.recovery.as_ref().filter(|r| r.doubtful()) {
                        info!(target: "health", "{nzo_id} recovery {}: {}", r.bucket.as_str(), r.reason);
                    }
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
