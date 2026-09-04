//! The §77 post-health PROBE ENGINE: pick a sample of a post's articles,
//! STAT them across every configured server, escalate once, and answer
//! what the post looks like out there.
//!
//! Two roads run it and they are in different layers, which is why it is
//! below both. `tasks::health`'s prober tick reads a queued job's
//! spooled NZB and hangs the verdict on the queue row;
//! `api::queue::preview` runs the §303 add-time preview over POSTed
//! bytes with nothing enqueued and answers the request. Leaving the
//! engine in the lane made the API handler depend on the background-task
//! layer, which is the last edge `tools/modgraph.py --serve` had.
//!
//! The two roads differ in where the NZB comes from and in what happens
//! to the answer, and MUST NOT differ in how it is measured - which is
//! the argument for one engine, and is `probe_sample`'s own doc. The
//! LANE - the rotation, the blind list, the per-job probe budget, the
//! queue save - stays in `tasks::health`.
//!
//! The two stand-down predicates come with it because they are
//! preconditions of a probe rather than of the tick: `download_idle` for
//! the wire and `busy_tail` for the post-processing tail. The lane and
//! `tasks::spawn_memory_trim` both still read them, reaching down.
//!
//! Verbatim from `tasks/health.rs`, `pub(super)` widened to
//! `pub(crate)` because `super` is a different module now.

use super::*;

/// Where [`probe_sample`]'s one escalation re-draws its bigger sample
/// from. The prober re-reads the job's spooled file (a big NZB is tens
/// of MB, deliberately not held across a network burst); the §303
/// preview already has the POSTed bytes in hand and re-parses those.
pub enum Resample {
    Path(std::path::PathBuf),
    Bytes(std::sync::Arc<Vec<u8>>),
}

/// One full probe over an already-parsed sample: the STAT burst, the
/// §294 escalation, the §282 recovery verdict with its BODY probe, and
/// the joint completable verdict - returned ON the payload verdict, as
/// the prober stores it. Shared by the queue prober's tick and the §303
/// add-time preview: the two roads differ in where the NZB comes from
/// (a spooled file vs POSTed bytes) and in what happens to the answer
/// (a queue row vs a reply), and must not differ in how it is measured.
///
/// `probes` is what [`crate::health::PostHealth::probes`] will carry -
/// the prober passes its running count, the preview always 1 (its
/// re-ask budget is the cache in `api/queue/preview.rs`, not
/// `MAX_PROBES`, because there is no queue row for that to hang on).
pub async fn probe_sample(
    d: &Arc<Daemon>,
    servers: &[nzbkit::config::ServerConfig],
    mut sample: JobSample,
    resample: Resample,
    probes: u32,
) -> Option<crate::health::PostHealth> {
    let now = unix_now();
    let (mut answers, mut rec_answers) = stat_burst(d, servers, &sample).await;
    let mut verdict = crate::health::score(&answers, sample.age_days, now, probes);
    // §294: one escalation, same pass. The first sample is a takedown
    // detector (health.rs says so of SAMPLE_K in as many words) and the
    // completable arithmetic below needs a LOSS RATE - so when the
    // first burst shows trouble on EITHER half, the burst is re-run
    // once at ESCALATE_K, which narrows the Wilson interval enough for
    // the joint verdict to separate "repairable" from "short". Either
    // half, because the recovery side is §282's founding incident: a
    // payload that samples clean over a doubtful recovery set is
    // exactly where a lucky 8-STAT green needs tightening before
    // "completes without repair" is worth saying. The recovery
    // pre-score runs WITHOUT the BODY probe (fetched: None) - it is an
    // escalation trigger, and the real scoring below still runs exactly
    // once, after it. Green on both halves escalates nothing: the
    // everyday healthy case pays the old eight STATs and not one more.
    let troubled = verdict
        .as_ref()
        .is_some_and(|v| v.bucket != crate::health::Bucket::Green)
        || sample.recovery.as_ref().is_some_and(|rec| {
            crate::health::score_recovery(&rec_answers, rec.age_days, rec.volumes, None)
                .is_some_and(|r| r.doubtful())
        });
    if troubled && sample.ids.len() < crate::health::ESCALATE_K && download_idle(d) {
        let s2 = match resample {
            Resample::Path(p) => {
                tokio::task::spawn_blocking(move || sample_job(&p, crate::health::ESCALATE_K)).await
            }
            Resample::Bytes(b) => {
                tokio::task::spawn_blocking(move || sample_bytes(&b, crate::health::ESCALATE_K))
                    .await
            }
        };
        if let Ok(Some(s2)) = s2 {
            let (a2, r2) = stat_burst(d, servers, &s2).await;
            // An escalation that learned nothing (a fleet that went
            // quiet mid-pass) keeps the first burst's evidence rather
            // than blanking it.
            if a2.iter().any(crate::health::ServerAnswer::answered) {
                sample = s2;
                answers = a2;
                rec_answers = r2;
                verdict = crate::health::score(&answers, sample.age_days, now, probes);
            }
        }
    }
    // §282 item 1: and the recovery set's own verdict, scored apart
    // from the payload's and never folded into it.
    //
    // The BODY probe runs only on servers that ANSWERED and that may
    // fund a measurement, and both halves matter. Answered, because a
    // host we never reached is not evidence about the set - the rule
    // `score` already applies to the STAT sweep, and the reason
    // `health.rs` unions for itself rather than reusing
    // `preflight::SweepResult::union_missing`. Fundable, because this
    // is nzbfast's own curiosity (against every queued job, or against
    // a post nobody has even added yet), which is exactly what
    // `may_spend_on_measurement` is the install-wide answer to; `check`
    // falls back to a metered account because a person asked it to, and
    // neither road here has anybody asking for a billed fetch. With
    // none qualifying the fetch is skipped, the verdict rests on the
    // STAT sample, and the reason says so.
    let recovery = match sample.recovery.as_ref() {
        Some(rec) if !rec.seed.is_empty() => {
            let payers: Vec<nzbkit::config::ServerConfig> = servers
                .iter()
                .zip(rec_answers.iter())
                .filter(|(s, a)| a.answered() && s.may_spend_on_measurement())
                .map(|(s, _)| s.clone())
                .collect();
            let fetched = if payers.is_empty() || !download_idle(d) {
                None
            } else {
                probe_recovery(&payers, &rec.seed, d).await
            };
            crate::health::score_recovery(&rec_answers, rec.age_days, rec.volumes, fetched)
        }
        _ => None,
    };
    // §294: the joint verdict, off whichever sample (initial or
    // escalated) the buckets themselves rest on.
    verdict.map(|mut v| {
        v.completable = Some(crate::health::score_completable(
            &v,
            recovery.as_ref(),
            sample.payload_bytes,
            sample.recovery.as_ref().map_or(0, |r| r.bytes),
        ));
        v.recovery = recovery;
        v
    })
}

/// §303: the add-time preview - the same verdict the prober hangs on a
/// queue row, computed over POSTed NZB bytes with nothing enqueued.
/// `Err` is a reason token for the UI ("downloading", "offline",
/// "no_servers", "unsampleable", "no_answer"): every one means "not
/// checked", never "unhealthy" - degrade-to-unknown is the design
/// constraint, because at add time downloading is the NORMAL state and
/// §77's rule stands: the account's connection slots belong to the job
/// the user is waiting on. The same stand-down discipline as the
/// prober, and the same abandon-on-contention inside `stat_burst`.
pub async fn nzb_preview_probe(
    d: &Arc<Daemon>,
    config: &std::path::Path,
    bytes: std::sync::Arc<Vec<u8>>,
) -> Result<crate::health::PostHealth, &'static str> {
    if d.offline.load(Ordering::Relaxed) {
        return Err("offline");
    }
    if !download_idle(d) {
        return Err("downloading");
    }
    let servers: Vec<nzbkit::config::ServerConfig> = match nzbkit::config::Config::load(config) {
        Ok(c) => c.servers.into_iter().filter(|s| s.enabled).collect(),
        Err(_) => Vec::new(),
    };
    if servers.is_empty() {
        return Err("no_servers");
    }
    // SAMPLE_K flat, where the prober picks 8-or-16 by job size: the
    // size split buys a slightly better takedown detector on a big job,
    // and the verdict this road exists for comes from the ESCALATE_K
    // pass either way. Off the runtime's workers, same as the prober -
    // a big NZB is tens of MB of XML.
    let b = bytes.clone();
    let Ok(Some(sample)) =
        tokio::task::spawn_blocking(move || sample_bytes(&b, crate::health::SAMPLE_K)).await
    else {
        return Err("unsampleable");
    };
    probe_sample(d, &servers, sample, Resample::Bytes(bytes), 1)
        .await
        .ok_or("no_answer")
}

/// §282 item 2: one pipelined STAT burst per server carrying BOTH
/// samples, split back apart afterwards. A second burst per sample
/// would be a second connection to every host per probe, for evidence
/// that costs the same handful of STATs riding along behind the first.
/// Re-checked per server, not just once at the top: a job can start
/// between two hosts, and when it does the rest of the probe is
/// abandoned with whatever it has. Hoisted out of the loop for §294,
/// whose escalation runs it a second time at a bigger k.
async fn stat_burst(
    d: &Arc<Daemon>,
    servers: &[nzbkit::config::ServerConfig],
    sample: &JobSample,
) -> (
    Vec<crate::health::ServerAnswer>,
    Vec<crate::health::ServerAnswer>,
) {
    let split = sample.ids.len();
    let rec_ids = sample
        .recovery
        .as_ref()
        .map(|r| r.ids.clone())
        .unwrap_or_default();
    let all: Vec<String> = sample.ids.iter().chain(rec_ids.iter()).cloned().collect();
    let mut answers: Vec<crate::health::ServerAnswer> = Vec::new();
    let mut rec_answers: Vec<crate::health::ServerAnswer> = Vec::new();
    for s in servers {
        if !download_idle(d) {
            break;
        }
        let mut a = probe_server(s, &all, d).await;
        let tail = a.cells.split_off(split.min(a.cells.len()));
        rec_answers.push(crate::health::ServerAnswer {
            host: a.host.clone(),
            cells: tail,
        });
        answers.push(a);
    }
    (answers, rec_answers)
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
pub fn download_idle(d: &Arc<Daemon>) -> bool {
    d.started_at.lock_ok().is_none() && d.sidecar.lock_ok().is_none()
}

/// Is a post-processing tail still running? `download_idle` answers for
/// the WIRE only - the download-end stamp lands when the network drains
/// and the repair/extract/move tail is handed to the lane after it, so a
/// job can be well past its last article and still be working the disk
/// hard. Same predicate the §129 1b poll calls "active".
pub fn busy_tail(d: &Arc<Daemon>) -> bool {
    d.queue.lock_ok().iter().any(|j| {
        let g = j.lock_ok();
        g.state == JobState::Finishing || g.finalizing
    })
}

/// What one job's NZB offers the prober: the payload sample, the post's
/// age, and - since TODO §282 - the recovery set's own sample beside
/// them rather than folded into them.
pub struct JobSample {
    /// Payload message-ids, bracketed.
    pub ids: Vec<String>,
    /// Age in days of the youngest PAYLOAD article.
    pub age_days: u32,
    /// §294: declared bytes of everything the payload sample draws
    /// from - the denominator the completable arithmetic projects the
    /// sampled loss rate over.
    pub payload_bytes: u64,
    /// `None` on a post that declares no PAR2 at all.
    pub recovery: Option<RecoverySample>,
}

/// TODO §282 items 1 and 2: the recovery half of one job's NZB.
pub struct RecoverySample {
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
    /// §294: declared bytes of the RECOVERY volumes alone (the index
    /// carries no slices) - what the set can spend on repair, before
    /// the availability and overhead haircuts `score_completable`
    /// applies.
    pub bytes: u64,
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
pub fn sample_job(nzb_path: &std::path::Path, k: usize) -> Option<JobSample> {
    let bytes = std::fs::read(nzb_path).ok()?;
    sample_bytes(&bytes, k)
}

/// The same sample off NZB bytes that never touched the spool - the
/// §303 preview's road in. Split from [`sample_job`] rather than
/// copied, so the two roads cannot drift on what "the payload sample"
/// means.
pub(super) fn sample_bytes(bytes: &[u8], k: usize) -> Option<JobSample> {
    let nzb = nzbkit::nzb::Nzb::parse(bytes).ok()?;
    let mut ids: Vec<String> = Vec::new();
    let mut age = u32::MAX;
    let mut payload_bytes = 0u64;
    let mut rec_ids: Vec<String> = Vec::new();
    let mut rec_age = u32::MAX;
    let mut rec_bytes = 0u64;
    let mut volumes = 0u32;
    for f in &nzb.files {
        let kind = f.kind();
        if kind != nzbkit::nzb::FileKind::Data {
            volumes += 1;
        }
        let bytes: u64 = f.segments.iter().map(|s| s.bytes).sum();
        if kind == nzbkit::nzb::FileKind::Par2Volume {
            rec_age = rec_age.min(crate::nzb_age_days(f.date));
            rec_ids.extend(f.segments.iter().map(|s| format!("<{}>", s.message_id)));
            rec_bytes += bytes;
            continue;
        }
        age = age.min(crate::nzb_age_days(f.date));
        ids.extend(f.segments.iter().map(|s| format!("<{}>", s.message_id)));
        payload_bytes += bytes;
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
        bytes: rec_bytes,
        seed,
    });
    Some(JobSample {
        ids: pick(&ids, k),
        age_days: if age == u32::MAX { 0 } else { age },
        payload_bytes,
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
        for (cell, id) in cells.iter_mut().zip(ids) {
            // `read_stat_checked` is the normalizer both this and the
            // M29 sampler share: 223 have, 423/430 missing, and
            // Giganews's nonstandard "451 0 <msgid>" for a takedown
            // counted as a miss rather than thrown away as a protocol
            // error. Do not re-derive it here.
            //
            // CHECKED and not the bare `read_stat` this used until
            // 28 Aug 2026: every STAT went out before the first reply
            // was read, so cells are filled POSITIONALLY - one reply
            // lost upstream and every later refusal is filed against
            // the article behind it, which is a healthy server voting
            // Missing on articles it holds. An id mismatch errors, and
            // the error path here already leaves every cell it never
            // reached Unknown, which `crate::health::score` reads as
            // "did not vote" rather than as evidence. A server that
            // echoes no id at all still passes - that is most of them
            // on a 430.
            *cell = match conn.read_stat_checked(Some(id.as_str())).await? {
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
