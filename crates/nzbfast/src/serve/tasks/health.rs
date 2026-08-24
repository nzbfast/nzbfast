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
            let Ok(Some(sample)) =
                tokio::task::spawn_blocking(move || sample_job(&nzb_path, k)).await
            else {
                // An unreadable or article-less NZB is not an error
                // worth logging on every tick: the job simply gets no
                // badge, and the download decides for itself.
                unsampleable.insert(nzo_id.clone());
                continue;
            };
            // §282 item 2: one pipelined burst per server carrying BOTH
            // samples, split back apart afterwards. A second burst would
            // be a second connection to every host per probe, for
            // evidence that costs the same handful of STATs riding along
            // behind the first.
            let split = sample.ids.len();
            let rec_ids = sample
                .recovery
                .as_ref()
                .map(|r| r.ids.clone())
                .unwrap_or_default();
            let all: Vec<String> = sample.ids.iter().chain(rec_ids.iter()).cloned().collect();
            let mut answers: Vec<crate::health::ServerAnswer> = Vec::new();
            let mut rec_answers: Vec<crate::health::ServerAnswer> = Vec::new();
            for s in &servers {
                // Re-checked per server, not just once at the top: a job
                // can start between two hosts, and when it does the rest
                // of the probe is abandoned with whatever it has.
                if !download_idle(&d) {
                    break;
                }
                let mut a = probe_server(s, &all, &d).await;
                let tail = a.cells.split_off(split.min(a.cells.len()));
                rec_answers.push(crate::health::ServerAnswer {
                    host: a.host.clone(),
                    cells: tail,
                });
                answers.push(a);
            }
            let verdict = crate::health::score(&answers, sample.age_days, now, probes + 1);
            // §282 item 1: and the recovery set's own verdict, scored
            // apart from the payload's and never folded into it.
            //
            // The BODY probe runs only on servers that ANSWERED and that
            // may fund a measurement, and both halves matter. Answered,
            // because a host we never reached is not evidence about the
            // set - the rule `score` already applies to the STAT sweep,
            // and the reason `health.rs` unions for itself rather than
            // reusing `preflight::SweepResult::union_missing`. Fundable,
            // because this is nzbfast's own curiosity running against
            // every queued job, which is exactly what
            // `may_spend_on_measurement` is the install-wide answer to;
            // `check` falls back to a metered account because a person
            // asked it to, and a background prober has nobody asking.
            // With none qualifying the fetch is skipped, the verdict
            // rests on the STAT sample, and the reason says so.
            let recovery = match sample.recovery.as_ref() {
                Some(rec) if !rec.seed.is_empty() => {
                    let payers: Vec<nzbkit::config::ServerConfig> = servers
                        .iter()
                        .zip(rec_answers.iter())
                        .filter(|(s, a)| a.answered() && s.may_spend_on_measurement())
                        .map(|(s, _)| s.clone())
                        .collect();
                    let fetched = if payers.is_empty() || !download_idle(&d) {
                        None
                    } else {
                        probe_recovery(&payers, &rec.seed, &d).await
                    };
                    crate::health::score_recovery(&rec_answers, rec.age_days, rec.volumes, fetched)
                }
                _ => None,
            };
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
                    // Logged on its own line, and only when it has
                    // something to say: a green recovery set is the
                    // overwhelmingly common case and a second line per
                    // job is how a log stops being read.
                    if let Some(r) = recovery.as_ref().filter(|r| r.doubtful()) {
                        info!(target: "health", "{nzo_id} recovery {}: {}", r.bucket.as_str(), r.reason);
                    }
                    v.recovery = recovery;
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

/// What one job's NZB offers the prober: the payload sample, the post's
/// age, and - since TODO §282 - the recovery set's own sample beside
/// them rather than folded into them.
pub(super) struct JobSample {
    /// Payload message-ids, bracketed.
    pub ids: Vec<String>,
    /// Age in days of the youngest PAYLOAD article.
    pub age_days: u32,
    /// `None` on a post that declares no PAR2 at all.
    pub recovery: Option<RecoverySample>,
}

/// TODO §282 items 1 and 2: the recovery half of one job's NZB.
pub(super) struct RecoverySample {
    /// Recovery-volume message-ids, bracketed - the ids the payload
    /// sample deliberately skips.
    pub ids: Vec<String>,
    /// Age in days of the youngest article in the recovery set. Its
    /// own, not the post's: a fill can re-post par2 long after the
    /// payload, and it is this figure the propagation guard has to run
    /// on for this verdict.
    pub age_days: u32,
    /// PAR2 files the NZB declares, index and volumes together.
    pub volumes: u32,
    /// Head and tail of the cheapest PAR2 file, for the BODY probe -
    /// the same two draws `check`'s `block_size_probe` makes, off the
    /// same [`nzbkit::nzb::Nzb::par2_seed_file`] pick.
    pub seed: Vec<String>,
}

/// The sampled message-ids for one job.
///
/// Stratified over the whole post - first, last and evenly spread -
/// using the same [`nzbkit::preflight::stratified_sample`] the `check`
/// command's sweep uses. PAR2 recovery volumes are excluded from the
/// PAYLOAD sample and always were, because a recovery volume's absence
/// is not payload absence; §282 item 2 keeps that skip exactly as it is
/// and samples the recovery set SEPARATELY, into
/// [`JobSample::recovery`], so the two verdicts never share a bucket.
///
/// The age is the MINIMUM over the files, matching what the failure
/// diagnosis computes (`post_age_days`, in `get/census.rs`) - a fill or
/// a repost tops an old NZB up with fresh articles, and it is the newest
/// posting that decides whether propagation is still a live explanation.
pub(super) fn sample_job(nzb_path: &std::path::Path, k: usize) -> Option<JobSample> {
    let bytes = std::fs::read(nzb_path).ok()?;
    let nzb = nzbkit::nzb::Nzb::parse(&bytes).ok()?;
    let mut ids: Vec<String> = Vec::new();
    let mut age = u32::MAX;
    let mut rec_ids: Vec<String> = Vec::new();
    let mut rec_age = u32::MAX;
    let mut volumes = 0u32;
    for f in &nzb.files {
        let kind = f.kind();
        if kind != nzbkit::nzb::FileKind::Data {
            volumes += 1;
        }
        if kind == nzbkit::nzb::FileKind::Par2Volume {
            rec_age = rec_age.min(crate::nzb_age_days(f.date));
            rec_ids.extend(f.segments.iter().map(|s| format!("<{}>", s.message_id)));
            continue;
        }
        age = age.min(crate::nzb_age_days(f.date));
        ids.extend(f.segments.iter().map(|s| format!("<{}>", s.message_id)));
    }
    if ids.is_empty() {
        return None;
    }
    let pick = |from: &[String], n: usize| -> Vec<String> {
        nzbkit::preflight::stratified_sample(from.len(), n)
            .into_iter()
            .map(|i| from[i].clone())
            .collect()
    };
    // The seed is the `.par2` index where there is one and the smallest
    // volume where there is not - the download path's own pick for
    // bootstrapping a set, so the probe draws the cheapest article that
    // can carry a Main packet rather than whatever the NZB listed
    // first. Head then tail: an index carries its Main packet in the
    // first bytes, a volume interleaves criticals between slices and
    // puts a copy near the end. Two articles, ~1.5 MB at worst.
    let seed = nzb
        .par2_seed_file()
        .map(|fi| {
            let segs = &nzb.files[fi].segments;
            let mut out = vec![format!("<{}>", segs[0].message_id)];
            if segs.len() > 1 {
                out.push(format!("<{}>", segs[segs.len() - 1].message_id));
            }
            out
        })
        .unwrap_or_default();
    let recovery = (!rec_ids.is_empty()).then(|| RecoverySample {
        ids: pick(&rec_ids, k),
        age_days: if rec_age == u32::MAX { 0 } else { rec_age },
        volumes,
        seed,
    });
    Some(JobSample {
        ids: pick(&ids, k),
        age_days: if age == u32::MAX { 0 } else { age },
        recovery,
    })
}

/// TODO §282 item 1: pull a couple of articles of the recovery set and
/// see whether they arrive and parse as a PAR2 set.
///
/// The half a STAT sweep cannot reach. In the 24 Aug incident the
/// provider ANSWERED for the recovery volumes and then delivered 68.9 MB
/// of a 1024 MB ask; only asking for the bytes finds that out. The
/// function itself is `nzbkit::preflight::probe_recovery_set`, written
/// and tested for `check` long before this and called from nowhere in
/// the daemon until now.
///
/// `None` means the probe was abandoned, not that it failed: a download
/// starting under us takes the account's connection slots back, exactly
/// as `probe_server` yields them, and an abandoned probe must not be
/// recorded as an answer.
///
/// Callers pass only servers that ANSWERED the STAT sweep and that
/// `may_spend_on_measurement()` - see the call site for why both.
async fn probe_recovery(
    servers: &[nzbkit::config::ServerConfig],
    ids: &[String],
    d: &Arc<Daemon>,
) -> Option<bool> {
    tokio::select! {
        got = nzbkit::preflight::probe_recovery_set(servers, ids) => Some(got.is_some()),
        () = async {
            while download_idle(d) {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        } => None,
    }
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
