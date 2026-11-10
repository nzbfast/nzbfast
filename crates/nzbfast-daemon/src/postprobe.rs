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
    let (mut answers, mut rec_answers) = stat_burst(d, servers, &sample, Spread::FIRST).await;
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
            // TODO 358 item 1: split over connections, or a slow-430
            // provider leaves most of the 64 Unknown at the deadline and
            // the escalated verdict can never be unanimous (the 4.2
            // defect, on `Spread`).
            let (a2, r2) = stat_burst(d, servers, &s2, Spread::ESCALATED).await;
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

/// What [`start_sample`] decided about a job about to start.
#[derive(Debug)]
pub enum StartSample {
    /// Not run. The token says why, for the log: "offline",
    /// "no_servers", "unsampleable", or "young" (the post is below
    /// [`crate::diag::GONE_MIN_AGE_DAYS`], where no verdict can reach
    /// red, so a probe could not fail it and is not worth a dial).
    Skipped(&'static str),
    /// Run, and the bar was not met: the job downloads as normal. The
    /// verdict rides along for the log; `None` when nothing answered.
    Pass(Option<crate::health::PostHealth>),
    /// Run, and the verdict clears [`crate::health::PostHealth::fails_job`]:
    /// every configured server said every sampled article was missing,
    /// at full width, past the age gate.
    Gone(crate::health::PostHealth),
}

/// TODO 358 item 1 (decision D1, shape A'): the PARALLEL START SAMPLE.
/// Run at prestart by the opt-in give-up, when the job's own record has
/// no verdict wide and unanimous enough to act on - which is the usual
/// case, since an *arr grab to an idle daemon starts long before the
/// idle prober's next tick (`research/DEAD-POST-GIVEUP-NEVER-SEES-A-VERDICT-2026-10-12.md`
/// section 1).
///
/// Two steps, both across every server at once:
///
/// 1. **A k=8 burst, one id per connection** ([`Spread::START_FIRST`]).
///    The everyday healthy post ends here: a present article answers
///    STAT in 2-15 ms, so the cost is one connect per server, well under
///    a second. Anything short of unanimous - one article present on one
///    server, one server silent - ends here too, as `Pass`: a post with
///    even one sampled article still on the fleet is not wholly dead,
///    and a silent server has not voted.
/// 2. **Only when step 1 was already unanimous missing, the 64-wide
///    sample** ([`Spread::START_WIDE`]), re-drawn across the whole post
///    and split over up to twenty connections per server. Never the k=8
///    shortcut: eight unanimous misses on a 90%-dead, repairable post
///    happen 43% of the time, 64 of them about 0.1% (see
///    [`crate::health::PostHealth::fails_job`]). A post of 64 articles
///    or fewer was already sampled whole in step 1 and skips this.
///
/// The bar is the one the give-up always had, unchanged in every
/// clause; this only makes it reachable. Below the age gate the probe
/// is not run at all.
///
/// Connections: never past an account's configured number
/// ([`probe_width`]). At prestart the job about to start owns the
/// account's slots, so the probe borrows them for its few seconds and
/// returns them before the pipeline dials. When something else is
/// already on the wire (a predecessor draining in a hand-over, a
/// prefetch sidecar), `probe_width` leaves the probe only what that run
/// is not holding, and a server with no headroom does not vote, so the
/// verdict can only get thinner, never harsher. The stand-down fires if
/// a download STARTS during the probe that was not running when it
/// began.
pub async fn start_sample(
    d: &Arc<Daemon>,
    servers: &[nzbkit::config::ServerConfig],
    nzb_path: &std::path::Path,
) -> StartSample {
    if d.offline.load(Ordering::Relaxed) {
        return StartSample::Skipped("offline");
    }
    if servers.is_empty() {
        return StartSample::Skipped("no_servers");
    }
    let draw = |k: usize| {
        let p = nzb_path.to_path_buf();
        tokio::task::spawn_blocking(move || sample_job(&p, k))
    };
    let Ok(Some(s1)) = draw(crate::health::SAMPLE_K).await else {
        return StartSample::Skipped("unsampleable");
    };
    if s1.age_days < crate::diag::GONE_MIN_AGE_DAYS {
        return StartSample::Skipped("young");
    }
    let was_idle = download_idle(d);
    let dd = d.clone();
    let stop: Stop = Arc::new(move || was_idle && !download_idle(&dd));
    let now = unix_now();
    let a1 = split_burst(d, servers, &s1.ids, Spread::START_FIRST, stop.clone()).await;
    let Some(v1) = crate::health::score(&a1, s1.age_days, now, 1) else {
        return StartSample::Pass(None);
    };
    if !v1.no_server_can_supply() {
        return StartSample::Pass(Some(v1));
    }
    if v1.fails_job(s1.population) {
        return StartSample::Gone(v1);
    }
    let Ok(Some(s2)) = draw(crate::health::ESCALATE_K).await else {
        return StartSample::Pass(Some(v1));
    };
    let a2 = split_burst(d, servers, &s2.ids, Spread::START_WIDE, stop).await;
    match crate::health::score(&a2, s2.age_days, now, 1) {
        Some(v2) if v2.fails_job(s2.population) => StartSample::Gone(v2),
        Some(v2) => StartSample::Pass(Some(v2)),
        // Nothing answered the wide pass: the narrow verdict is all the
        // evidence there is, and it is too narrow to fail on.
        None => StartSample::Pass(Some(v1)),
    }
}

/// §282 item 2: one pipelined STAT burst per server carrying BOTH
/// samples, split back apart afterwards. A second burst per sample
/// would be a second connection to every host per probe, for evidence
/// that costs the same handful of STATs riding along behind the first.
/// The payload ids go first, so a deadline that cuts a slow server
/// short takes recovery cells before payload ones (see [`split_burst`]).
///
/// Every server at once since TODO 358 item 1, not one after another,
/// and the stand-down is the burst's `stop`: a job starting under it
/// drops every session, where the old loop abandoned the hosts it had
/// not reached yet. A server the burst never reached is now in the
/// answer list as all-Unknown, which `tally` drops from the vote exactly
/// as it drops any other silent host, and which `servers` then counts.
/// Hoisted out of the loop for §294, whose escalation runs it a second
/// time at a bigger k.
async fn stat_burst(
    d: &Arc<Daemon>,
    servers: &[nzbkit::config::ServerConfig],
    sample: &JobSample,
    spread: Spread,
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
    let dd = d.clone();
    let stop: Stop = Arc::new(move || !download_idle(&dd));
    let mut answers = split_burst(d, servers, &all, spread, stop).await;
    let rec_answers = answers
        .iter_mut()
        .map(|a| crate::health::ServerAnswer {
            host: a.host.clone(),
            cells: a.cells.split_off(split.min(a.cells.len())),
        })
        .collect();
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
    /// TODO 358 item 1: payload articles the NZB declares, the population
    /// `ids` was drawn from. What tells a 64-wide verdict on a small post
    /// (which is the whole post) from a k=8 shortcut on a big one - see
    /// [`crate::health::wide_enough`].
    pub population: usize,
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
        population: ids.len(),
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
/// as `probe_conn` yields them, and an abandoned probe must not be
/// recorded as an answer.
///
/// Callers pass only servers that ANSWERED the STAT sweep and that
/// `may_spend_on_measurement()` - see the call site for why both.
async fn probe_recovery(
    servers: &[nzbkit::config::ServerConfig],
    ids: &[String],
    d: &Arc<Daemon>,
) -> Option<bool> {
    // A seat per server it may dial, held for the whole probe, like any
    // STAT burst's (`Daemon::probe_sessions`); a server with no room left
    // beside the other bursts sits this one out.
    let mut seats = Vec::with_capacity(servers.len());
    let mut room = Vec::with_capacity(servers.len());
    for s in servers {
        let seat = reserve_probe_width(d, s, 1).await;
        if seat.n > 0 {
            room.push(s.clone());
        }
        seats.push(seat);
    }
    if room.is_empty() {
        return None;
    }
    tokio::select! {
        got = nzbkit::preflight::probe_recovery_set(&room, ids) => Some(got.is_some()),
        () = async {
            while download_idle(d) {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        } => None,
    }
}

/// How one burst spreads over the wire: at most `conns_max` connections
/// to each server, all servers at once, every server's sessions cut at
/// one shared `deadline` measured from the start of the burst.
///
/// TODO 358 item 1 (decision D1), and the defect it fixes first
/// (`research/DEAD-POST-GIVEUP-NEVER-SEES-A-VERDICT-2026-10-12.md`
/// section 4.2). This used to be one connection per server, servers in
/// sequence, under a fixed 20 s ceiling each. A provider answers a
/// not-found STAT one at a time per session, at 0.47-2.2 s an article on
/// four of the five measured accounts, and pipelining does not hide it,
/// so the escalated 64-article pass could not finish inside 20 s on any
/// of them (xsnews answered about 9 of 64). `tally` counts an article
/// absent only when every voting server said Missing, and an Unknown
/// cell never is, so the verdict could never be "no server can supply"
/// and the opt-in give-up was a silent no-op on that fleet. The same 64
/// ids split over N connections cost near-linearly less (section 4.3:
/// xsnews 142 s on one, 19.9 s on 8, 9.4 s on 20), which is what
/// `conns_max` buys. A PRESENT article answers in 2-15 ms at any width
/// (measured 9 Nov 2026 on the same five accounts, ids from a live
/// post), so the width only ever costs a dead or damaged post anything.
///
/// The width is a CEILING, never a demand: [`probe_width`] takes it down
/// to the headroom the account has left, so a probe never dials past a
/// server's configured connections.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Spread {
    pub conns_max: usize,
    pub deadline: std::time::Duration,
}

impl Spread {
    /// The §77 prober's first k=8 burst, and the §303 preview's: one
    /// connection per server and the old 20 s ceiling, exactly the
    /// shape it always had. The takedown detector answers a healthy
    /// post in milliseconds, and the idle prober is in no hurry.
    pub const FIRST: Spread = Spread {
        conns_max: 1,
        deadline: std::time::Duration::from_secs(20),
    };
    /// The §294 escalated pass (k=64 payload plus the recovery sample)
    /// on the idle prober and the preview. Eight connections and a 30 s
    /// deadline: xsnews, the slowest measured account, answered 64 dead
    /// ids in 19.9 s over 8 (section 4.3), and [`split_burst`] hands
    /// every connection its share of the PAYLOAD ids before any recovery
    /// id, so the payload half is answered first whatever the recovery
    /// half costs. Eight rather than the start sample's twenty because
    /// this is background curiosity on an idle daemon, not a job about
    /// to start: it keeps the dial burst small.
    pub const ESCALATED: Spread = Spread {
        conns_max: 8,
        deadline: std::time::Duration::from_secs(30),
    };
    /// The start sample's first k=8 burst: one id per connection, so a
    /// dead post's first answer costs ONE per-article refusal time (2.2 s
    /// on xsnews) rather than eight of them in series (17.6 s), and a
    /// healthy post's costs one connect plus milliseconds.
    pub const START_FIRST: Spread = Spread {
        conns_max: 8,
        deadline: std::time::Duration::from_secs(30),
    };
    /// The start sample's 64-wide pass, run only when the k=8 burst was
    /// already unanimous missing. Twenty connections is the widest the
    /// 13 Oct round measured (9.4 s for 64 dead ids on xsnews), and 30 s
    /// covers that account at eight (19.9 s) for an install configured
    /// below twenty.
    pub const START_WIDE: Spread = Spread {
        conns_max: 20,
        deadline: std::time::Duration::from_secs(30),
    };
}

/// How many connections a burst may open to `s` right now, at most
/// `want`: the account's configured connections less what is already
/// in use on it.
///
/// The §77 rule ("the account's connection slots belong to the
/// download") in arithmetic. In use is the download permits the hub's
/// connection budget has handed out on this account, plus the larger of
/// the warm reserve's held slots and the sessions parked in the warm
/// pool (the two overlap, so the larger is taken rather than the sum;
/// the error is on the safe side either way). One more is left for the
/// background samplers that hold a session per server whatever the pool
/// does (the M29 oracle, the tip watcher), except on an account with a
/// single free slot, which keeps the one connection the prober has
/// always opened. Zero when the account is full: that server then does
/// not vote, which can only ever make a verdict thinner, never
/// manufacture a miss.
///
/// And in use includes the sessions every OTHER post-health burst holds
/// on the account right now (`Daemon::probe_sessions`), since 9 Nov 2026:
/// the job-start sample runs before `started_at` is set, so the idle
/// prober and the add-time preview can burst the same servers at the
/// same moment, and the download's permits see none of the three. This
/// is the answer a burst would get; [`split_burst`] takes it through
/// [`reserve_probe_width`], which holds what it was given.
pub async fn probe_width(d: &Arc<Daemon>, s: &nzbkit::config::ServerConfig, want: usize) -> usize {
    let (configured, in_use) = account_in_use(d, s).await;
    let probing = d
        .probe_sessions
        .lock_ok()
        .get(&nzbkit::pool::handoff::ConnBudget::key(s))
        .copied()
        .unwrap_or(0);
    width_of(configured, in_use + probing, want)
}

/// The account's configured connections, and what the download side has
/// in use on it - the async half of [`probe_width`].
async fn account_in_use(d: &Arc<Daemon>, s: &nzbkit::config::ServerConfig) -> (usize, usize) {
    let configured = (s.connections as usize).max(1);
    let (held, spares) = d
        .hub
        .conn_budget
        .get()
        .and_then(|b| b.lease_borrowed(&nzbkit::pool::handoff::ConnBudget::key(s)))
        .map_or((0, 0), |l| (l.snapshot().0, l.spares()));
    let parked = match d.hub.warm.get() {
        Some(w) => w.parked_for(s).await,
        None => 0,
    };
    (configured, held + spares.max(parked))
}

/// [`probe_width`]'s arithmetic, given everything in use.
fn width_of(configured: usize, in_use: usize, want: usize) -> usize {
    let free = configured.saturating_sub(in_use);
    let usable = free.saturating_sub(1).max(free.min(1));
    usable.min(want)
}

/// A burst's hold on the sessions it was sized for, returned on drop -
/// which covers a burst that is itself cancelled mid-flight.
pub struct ProbeSeats {
    d: Arc<Daemon>,
    key: String,
    /// How many sessions the burst may open.
    pub n: usize,
}

impl Drop for ProbeSeats {
    fn drop(&mut self) {
        if self.n == 0 {
            return;
        }
        let mut m = self.d.probe_sessions.lock_ok();
        if let Some(c) = m.get_mut(&self.key) {
            *c = c.saturating_sub(self.n);
            if *c == 0 {
                m.remove(&self.key);
            }
        }
    }
}

/// [`probe_width`], and the width it answers RESERVED until the returned
/// seats drop. The read of the other bursts' sessions and the reservation
/// are one critical section, so two bursts sizing themselves together
/// cannot both count the same free slots.
pub async fn reserve_probe_width(
    d: &Arc<Daemon>,
    s: &nzbkit::config::ServerConfig,
    want: usize,
) -> ProbeSeats {
    let (configured, in_use) = account_in_use(d, s).await;
    let key = nzbkit::pool::handoff::ConnBudget::key(s);
    let n = {
        let mut m = d.probe_sessions.lock_ok();
        let probing = m.get(&key).copied().unwrap_or(0);
        let n = width_of(configured, in_use + probing, want);
        if n > 0 {
            *m.entry(key.clone()).or_default() += n;
        }
        n
    };
    ProbeSeats {
        d: d.clone(),
        key,
        n,
    }
}

/// The stand-down a burst polls. True means "drop every session now".
pub type Stop = Arc<dyn Fn() -> bool + Send + Sync>;

/// STAT `ids` on every server at once, each server's share split over up
/// to `spread.conns_max` connections (see [`Spread`]). One answer per
/// server, in `servers` order, every cell in `ids` order.
///
/// `stop` is the stand-down: polled every 100 ms, and the moment it
/// says true every session in the burst is dropped where it stands. The
/// prober passes "a download started"; the start sample passes "a
/// download started that was not already running when I began".
///
/// The ids are dealt ROUND-ROBIN onto the connections, not cut into
/// contiguous runs, and each connection asks for its share in index
/// order. Callers put the payload ids first, so when a deadline cuts a
/// slow server short it is the recovery tail that goes unanswered and
/// not the payload sample the give-up bar reads.
///
/// Every failure path a single connection can take - refused login, a
/// dead socket, a peer that goes mute mid-batch, the deadline, the
/// stand-down - leaves the cells that connection never reached
/// `Unknown`, which [`crate::health::score`] treats as "this server did
/// not vote" rather than as evidence in either direction. Nothing here
/// can produce a miss that a server did not actually report. Each
/// connection keeps the single-connection discipline `probe_conn`
/// documents (checked positional reads, no QUIT on an unclean session).
pub async fn split_burst(
    d: &Arc<Daemon>,
    servers: &[nzbkit::config::ServerConfig],
    ids: &[String],
    spread: Spread,
    stop: Stop,
) -> Vec<crate::health::ServerAnswer> {
    use crate::health::Avail;
    let mut cells: Vec<Vec<Avail>> = vec![vec![Avail::Unknown; ids.len()]; servers.len()];
    if ids.is_empty() || stop() {
        return answers_of(servers, cells);
    }
    let deadline = tokio::time::Instant::now() + spread.deadline;
    // A JoinSet rather than a join over borrowed futures: dropping it
    // aborts every task in it, so a caller that is itself cancelled
    // still closes every socket, exactly as dropping the old single
    // probe future did.
    // Held until every session below has ended (declared before the set,
    // so they drop after it): another burst on the same account sizes
    // itself around them.
    let mut seats: Vec<ProbeSeats> = Vec::with_capacity(servers.len());
    let mut set = tokio::task::JoinSet::new();
    for (si, s) in servers.iter().enumerate() {
        let seat = reserve_probe_width(d, s, spread.conns_max.min(ids.len())).await;
        let n = seat.n;
        seats.push(seat);
        for c in 0..n {
            let share: Vec<(usize, String)> = (c..ids.len())
                .step_by(n)
                .map(|i| (i, ids[i].clone()))
                .collect();
            let s = s.clone();
            let stop = stop.clone();
            set.spawn(async move { (si, probe_conn(&s, &share, deadline, stop).await) });
        }
    }
    while let Some(r) = set.join_next().await {
        if let Ok((si, got)) = r {
            for (i, a) in got {
                cells[si][i] = a;
            }
        }
    }
    answers_of(servers, cells)
}

fn answers_of(
    servers: &[nzbkit::config::ServerConfig],
    cells: Vec<Vec<crate::health::Avail>>,
) -> Vec<crate::health::ServerAnswer> {
    servers
        .iter()
        .zip(cells)
        .map(|(s, cells)| crate::health::ServerAnswer {
            host: s.host.clone(),
            cells,
        })
        .collect()
}

/// STAT one connection's share of a burst over a single pipelined
/// session, returning only the cells it actually got an answer for.
///
/// The connect counts against the deadline too: a server that cannot
/// be reached in time has not voted.
async fn probe_conn(
    s: &nzbkit::config::ServerConfig,
    share: &[(usize, String)],
    deadline: tokio::time::Instant,
    stop: Stop,
) -> Vec<(usize, crate::health::Avail)> {
    use crate::health::Avail;
    let host = &s.host;
    let mut got: Vec<(usize, Avail)> = Vec::with_capacity(share.len());
    let Ok(Ok((mut conn, _))) =
        tokio::time::timeout_at(deadline, nzbkit::nntp::Connection::connect(s)).await
    else {
        return got;
    };
    let probe = async {
        for (_, id) in share {
            conn.send_stat(id).await?;
        }
        conn.flush().await?;
        for (i, id) in share {
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
            // the error path here leaves every cell it never reached
            // Unknown, which `crate::health::score` reads as "did not
            // vote" rather than as evidence. A server that echoes no id
            // at all still passes - that is most of them on a 430.
            let a = match conn.read_stat_checked(Some(id.as_str())).await? {
                true => Avail::Have,
                false => Avail::Missing,
            };
            got.push((*i, a));
        }
        Ok::<(), nzbkit::nntp::NntpError>(())
    };
    // Two ways out, and both end the session immediately: the burst's
    // deadline, and the stand-down. Dropping the future cancels the
    // probe outright, and dropping the Connection closes the socket - so
    // "yield the slot" is not a request the provider has to wait on.
    let clean = tokio::select! {
        r = tokio::time::timeout_at(deadline, probe) => {
            if let Ok(Err(e)) = &r {
                warn!(target: "health", "{host}: STAT: {e}");
            }
            matches!(r, Ok(Ok(())))
        }
        () = async {
            while !stop() {
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
    got
}

#[cfg(test)]
#[path = "postprobe_tests.rs"]
mod tests;
