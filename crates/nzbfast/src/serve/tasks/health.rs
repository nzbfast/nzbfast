//! TODO §77 post-health preflight: STAT a sample of a queued job's
//! articles across every configured server, so the queue row can say
//! what a post looks like out there BEFORE the bandwidth is spent
//! rather than at 97%.
//!
//! The whole subject in one file: the tick loop that picks a job, probes
//! it and hangs the verdict on it; the two stand-down predicates that
//! keep it off an account somebody is waiting on (`download_idle` for
//! the wire, `busy_tail` for the post-processing tail); the stratified
//! sampler that chooses which ids to ask about; and the single-server
//! STAT burst itself. The SCORING, and the reasons the verdict is only
//! ever advisory, stay in [`crate::health`] - nothing here concludes
//! anything.
//!
//! Split out of `serve/tasks.rs` whole under the size gate (TODO 106);
//! the code is verbatim, only visibility changed. `use super::*` brings
//! the daemon and the parent module's own items back into scope, and
//! `pub(super)` here means "pub in tasks" - which is what
//! `spawn_memory_trim` and the `tasks_tests` child need for the two
//! stand-down predicates.

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
pub(in crate::serve) fn spawn_health_prober(daemon: &Arc<Daemon>, config: &std::path::Path) {
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
pub(super) fn download_idle(d: &Arc<Daemon>) -> bool {
    d.started_at.lock_ok().is_none() && d.sidecar.lock_ok().is_none()
}

/// Is a post-processing tail still running? `download_idle` answers for
/// the WIRE only - the download-end stamp lands when the network drains
/// and the repair/extract/move tail is handed to the lane after it, so a
/// job can be well past its last article and still be working the disk
/// hard. Same predicate the §129 1b poll calls "active".
pub(super) fn busy_tail(d: &Arc<Daemon>) -> bool {
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
/// diagnosis computes (`post_age_days`, in `get/census.rs`) - a fill or
/// a repost tops an old NZB up with fresh articles, and it is the newest
/// posting that decides whether propagation is still a live explanation.
pub(super) fn sample_ids(nzb_path: &std::path::Path, k: usize) -> Option<(Vec<String>, u32)> {
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
