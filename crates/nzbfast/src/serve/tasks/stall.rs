//! Two things that watch a download from outside it: [`StallTracker`],
//! the pure state machine that reports transfer-stall episodes, and the
//! slow-job watchdog that defers a job monopolised by one slow server and
//! puts otherwise-idle servers onto the next queued job.
//!
//! The tracker is observation ONLY - it produces log lines and the queue
//! row's "no data for Ns" sub-line and never touches the job. The stall
//! watchdog that once aborted a healthy run is why action stays out of
//! its scope.
//!
//! Split out of `serve/tasks.rs` whole (TODO 106) - the code is verbatim,
//! only visibility changed, plus the watchdog's own doc comment reunited
//! with it (an earlier move had stranded it above `StallTracker`).

use super::*;

/// Transfer-stall episode tracker (Gary, 2 Aug: a mid-download 30-40 s
/// flatline resumed on its own and nothing anywhere said why). A pure
/// state machine over per-tick pool-byte totals, so the timing logic is
/// unit-testable with synthetic clocks. Observation ONLY: it produces
/// log lines and the queue row's "no data for Ns" sub-line, and never
/// touches the job - the stall watchdog that once aborted a healthy run
/// is why action stays out of scope here. Zero throughput is not zero
/// progress (a wholly-dead post moves no bytes while the pool drives
/// its refusal ladder perfectly), so an episode is a fact to report,
/// never a verdict.
pub(crate) struct StallTracker {
    threshold: std::time::Duration,
    /// (nzo_id, display name) of the fetch being observed.
    job: Option<(String, String)>,
    last_total: u64,
    /// When the pool-byte total last moved (or the job was first seen).
    last_change: Instant,
    open: bool,
}

pub(crate) enum StallEvent {
    /// Bytes have not moved for the threshold: episode starts.
    Opened { idle_secs: u64, since: Instant },
    /// Bytes moved again after an open episode.
    Cleared { idle_secs: u64 },
    /// The job went away (finished, aborted, paused) mid-episode.
    Ended { idle_secs: u64, name: String },
}

impl StallTracker {
    pub(crate) fn new(threshold: std::time::Duration) -> Self {
        Self {
            threshold,
            job: None,
            last_total: 0,
            last_change: Instant::now(),
            open: false,
        }
    }

    /// One sample: the active fetch (if any) and its pool's cumulative
    /// byte total across all servers. At most one event per call.
    pub(crate) fn observe(
        &mut self,
        now: Instant,
        job: Option<(&str, &str)>,
        total_bytes: u64,
    ) -> Option<StallEvent> {
        let ended = |s: &Self| {
            s.open.then(|| StallEvent::Ended {
                idle_secs: now.duration_since(s.last_change).as_secs(),
                name: s.job.as_ref().map(|(_, n)| n.clone()).unwrap_or_default(),
            })
        };
        let Some((id, name)) = job else {
            let ev = ended(self);
            self.job = None;
            self.open = false;
            return ev;
        };
        if self.job.as_ref().map(|(i, _)| i.as_str()) != Some(id) {
            let ev = ended(self);
            self.job = Some((id.to_string(), name.to_string()));
            self.last_total = total_bytes;
            self.last_change = now;
            self.open = false;
            return ev;
        }
        if total_bytes != self.last_total {
            self.last_total = total_bytes;
            let idle = now.duration_since(self.last_change).as_secs();
            self.last_change = now;
            if self.open {
                self.open = false;
                return Some(StallEvent::Cleared { idle_secs: idle });
            }
            return None;
        }
        if !self.open && now.duration_since(self.last_change) >= self.threshold {
            self.open = true;
            return Some(StallEvent::Opened {
                idle_secs: now.duration_since(self.last_change).as_secs(),
                since: self.last_change,
            });
        }
        None
    }
}

/// Copy this job's observed connection ceilings somewhere that outlives
/// the pool, and bank them in the lifetime ledger.
///
/// The same reasoning as the refusal copy above, one number further on:
/// the Providers row reads the ceiling from the live pool, which is gone
/// the moment the queue drains, and the whole point of the number is
/// that it survives to be read. Sampled here rather than in the stats
/// handler because a headless run has no dashboard polling it - and the
/// Giganews day this feature exists for was headless for most of its
/// length.
///
/// Only ever off a gauge a CAPACITY refusal wrote (`capped_since` is
/// the pool's own gate): nothing here compares `connected` against
/// `budget`, because every idle provider is under its budget and idle
/// must never be shown as refused.
///
/// The session map is max-merged, so it can be folded at any cadence
/// and from more than one caller; `note_capped` writes the disk ledger
/// only when the day or the ceiling actually moves, so a tick a second
/// for the length of a download is not a disk write a second.
///
/// Returns what the CALLER must bank on disk - (host, ceiling) per
/// capped provider. Nothing here touches the filesystem, so no pool
/// mutex is held across one.
#[cfg(test)]
pub(in crate::serve) fn fold_caps_for_test(d: &Arc<Daemon>) -> Vec<(String, usize)> {
    fold_caps(d)
}

/// §G: copy any provider refusal somewhere that outlives the pool.
///
/// The Providers card reads it from the live pool, which is gone the
/// moment the queue drains - so the one sentence explaining why a
/// paid-for provider did nothing disappeared exactly when the user went
/// looking for it. Sampled from the daemon rather than in the stats
/// handler because a headless run has no dashboard polling it.
///
/// The clear arm is deliberately "moved bytes or holds a connection",
/// not "has no refusal right now": every server starts each job with an
/// empty refusal slot, so clearing on that alone would wipe the record a
/// second after the next job began and refill it a second later. Bytes
/// or a live connection are proof it authenticated.
///
/// Called from the runner's tail as well as the watchdog tick, for the
/// reason `fold_and_bank_caps` below is: the tick sleeps 1-5 s first, so
/// a refusal seen only inside a shorter job whose pool a later job
/// replaces was never copied at all, and neither was one on the last job
/// before a queue-finished shutdown action ended the process (Codex
/// sweep 7, L2). Idempotent - the record is keyed by host and rewritten
/// wholesale, so both callers reaching it costs one map insert.
pub(in crate::serve) fn bank_refusals(d: &Arc<Daemon>) {
    let live = d.hub.pool_live.lock_ok();
    let Some(l) = live.as_ref() else { return };
    let mut keep = d.last_refusals.lock_ok();
    for s in &l.servers {
        if let Some(r) = s.refusal.lock_ok().as_ref() {
            keep.insert(
                s.host.clone(),
                ServerRefusal {
                    permanent: r.permanent,
                    source_ips: r.source_ips,
                    line: r.line.clone(),
                    at: unix_now(),
                },
            );
        } else if s.connected.load(Ordering::Relaxed) > 0 || s.bytes.load(Ordering::Relaxed) > 0 {
            keep.remove(&s.host);
        }
    }
}

/// Fold this job's ceilings and bank what the fold hands back.
///
/// The watchdog's own tick does exactly this, and it was the ONLY
/// caller - so a job shorter than one tick (1-5 s) could be refused,
/// finish, and have the next job replace `pool_live` before anything
/// ever looked. The lifetime ledger, whose whole job is to be the
/// record a user sends their provider, silently missed the day (Codex
/// sweep 6, N8). Called from the runner's tail as well, where
/// `pool_live` still points at the job that has just ended.
///
/// Idempotent: `fold_caps` banks one EPISODE once, keyed on the
/// refusal's own stamp, so the tail call and the next tick cannot
/// double-count.
pub(in crate::serve) fn fold_and_bank_caps(d: &Arc<Daemon>) {
    for (host, granted) in fold_caps(d) {
        crate::conntune::note_capped(&d.cfg_path, &host, granted, unix_now().max(0) as u64);
    }
}

fn fold_caps(d: &Arc<Daemon>) -> Vec<(String, usize)> {
    let live = d.hub.pool_live.lock_ok().clone();
    let Some(l) = live else { return Vec::new() };
    let mut seen = d.capped_hosts.lock_ok();
    let mut out = Vec::new();
    for s in &l.servers {
        // A fleet HOLDING more than a recorded ceiling has disproven it.
        // Done here as well as in the payload builder because the idle
        // `planned_servers` row has no live gauge to consult at all: it
        // reads this map alone, so a ceiling only the payload builder
        // retired came back the moment the queue drained (Codex sweep 6,
        // N4).
        let held = s.connected.load(Ordering::Relaxed);
        if seen.get(&s.host).is_some_and(|c| c.disproven_by(held)) {
            seen.remove(&s.host);
        }
        let since = s.capped_since.load(Ordering::Relaxed);
        if since == 0 {
            continue;
        }
        let granted = s.granted_hi.load(Ordering::Relaxed);
        let e = seen.entry(s.host.clone()).or_default();
        // First refusal of the SESSION wins, not of the job: the row's
        // "since" is how long this daemon has been capped, and a second
        // job restarting the clock would say the cap was minutes old
        // when it had been hours.
        if e.since == 0 {
            e.since = since;
        }
        e.granted_hi = e.granted_hi.max(granted);
        e.capped_at = e.capped_at.max(s.capped_at.load(Ordering::Relaxed));
        // Bank the EPISODE, not the level. This gauge is sticky and the
        // watchdog re-reads it every tick, so emitting on every read
        // stamped today's date on a refusal that happened days ago - an
        // idle daemon could turn one Monday event into "capped on 30 of
        // the last 30 days", which is exactly the sentence meant to be
        // evidence for a provider (Codex sweep 5, M7). `since` is
        // first-write-wins per episode, so it identifies one.
        if e.banked == since {
            continue;
        }
        e.banked = since;
        out.push((s.host.clone(), granted));
    }
    out
}

/// The job one watchdog tick judges, with the gauges and stop handles
/// that are ITS rather than whatever the hub holds right now.
struct Watched {
    id: String,
    t0: Instant,
    pool_live: Arc<nzbkit::pool::LiveStats>,
    abort: Option<Arc<std::sync::atomic::AtomicBool>>,
    queue_ctl: Option<Arc<nzbkit::pool::QueueControl>>,
    /// True when this is a predecessor draining behind the hub owner.
    draining: bool,
}

impl Watched {
    /// Abort the judged run - the defer verdict's teeth.
    fn stop(&self) {
        if let Some(f) = &self.abort {
            f.store(true, Ordering::Relaxed);
        }
        if let Some(c) = &self.queue_ctl {
            c.abort();
        }
    }
}

/// Which job the defer watchdog judges this tick. A predecessor still
/// draining behind the active job comes first - the queue waits on it
/// (the runner files it before it looks at its successor), so it is the
/// job whose slowness holds everyone up - and it is judged off the
/// gauges and handles the runner detached for it, since the hub's are
/// the successor's by now. Otherwise the hub owner, as ever. None while
/// nothing is on the wire.
fn watched(d: &Daemon) -> Option<Watched> {
    if let Some(s) = d.drain_dl.lock_ok().as_ref()
        && let Some(pl) = &s.pool_live
    {
        return Some(Watched {
            id: s.nzo_id.clone(),
            t0: s.t_start,
            pool_live: pl.clone(),
            abort: s.abort.clone(),
            queue_ctl: s.queue_ctl.clone(),
            draining: true,
        });
    }
    let t0 = (*d.started_at.lock_ok())?;
    let id = d.active_stream.lock_ok().clone()?;
    let pool_live = d.hub.pool_live.lock_ok().clone()?;
    Some(Watched {
        id,
        t0,
        pool_live,
        abort: d.hub.abort.lock_ok().clone(),
        queue_ctl: d.hub.queue_ctl.lock_ok().clone(),
        draining: false,
    })
}

/// One watchdog tick's OBSERVATION half: copy any provider refusal
/// somewhere that outlives the pool, warn once per server-outage
/// episode, and open/clear the transfer-stall episode for the active
/// fetch. Split out of `spawn_slow_job_watchdog` (size gate) - it is
/// the half that runs unconditionally, BEFORE the auto-defer and
/// prefetch gates, and nothing in it escapes the caller's loop.
///
/// `stall` and `outage_noted` carry episode state across ticks, so
/// they are borrowed rather than rebuilt: both exist precisely to
/// fire on the EDGE, and a fresh one every tick would log forever.
fn observe_transfer_and_outages(
    d: &Arc<Daemon>,
    stall: &mut StallTracker,
    outage_noted: &mut std::collections::HashMap<String, u64>,
) {
    // The fetch being observed: hub owner, Downloading, not
    // pause-suspended (a pause legitimately stops bytes).
    let fetching = d
        .started_at
        .lock_ok()
        .is_some()
        .then(|| d.active_stream.lock_ok().clone())
        .flatten();
    let job_info = fetching.and_then(|id| {
        d.queue.lock_ok().iter().find_map(|j| {
            let g = j.lock_ok();
            (g.nzo_id == id && g.state == JobState::Downloading && !g.suspended)
                .then(|| (id.clone(), g.name.clone()))
        })
    });
    // Per-server (host, connections, bytes, refused) - the
    // states the episode lines report.
    let servers: Vec<(String, usize, u64, bool)> = d
        .hub
        .pool_live
        .lock_ok()
        .as_ref()
        .map(|l| {
            l.servers
                .iter()
                .map(|s| {
                    (
                        s.host.clone(),
                        s.connected.load(Ordering::Relaxed),
                        s.bytes.load(Ordering::Relaxed),
                        s.refusal.lock_ok().is_some(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    bank_refusals(d);
    // Deliberately NOT inside the block above, and `fold_caps` clones
    // the Arc out before it merges: banking a ceiling in the lifetime
    // ledger is a read-modify-write of conntune.json, and holding
    // `pool_live` - which the fetch path and every stats poll take -
    // across a disk write is how a mutex becomes a wedge. This runs on
    // the watchdog's 1-5 s tick and writes only when the day or the
    // ceiling has actually moved.
    fold_and_bank_caps(d);
    // Servers granting nothing right now. The `warn!` below
    // is the first thing anywhere that says a provider is
    // dead WHILE the job that needs it is still running -
    // the census line that named one only ever printed in
    // the diagnostics block of a job that FINISHED, which a
    // job wedged behind that provider never reaches.
    let outages = server_outages(d);
    {
        let win = server_down_secs();
        for o in &outages {
            if o.secs < win {
                continue;
            }
            // Keyed by when the episode STARTED, so a
            // server that recovers and dies again is warned
            // about twice and one that stays down once.
            if outage_noted.get(&o.host) == Some(&o.since_ms) {
                continue;
            }
            outage_noted.insert(o.host.clone(), o.since_ms);
            let what = match o.kind {
                "refused" => "it rejected the sign-in",
                "capacity" => "it is at a connection or IP cap",
                _ => "unreachable",
            };
            warn!(
                target: "pool",
                "{}: no usable connection for {}s ({what}: {}) - \
                 any article only this server carries is waiting on it",
                o.host, o.secs, o.detail
            );
        }
        // Servers that came back drop out of the map, so the
        // next outage is a fresh episode and the map cannot
        // grow past the configured server count.
        outage_noted.retain(|h, _| outages.iter().any(|o| &o.host == h));
    }
    let states = || -> String {
        if servers.is_empty() {
            return "pool not up yet".into();
        }
        servers
            .iter()
            .map(|(h, c, _, r)| {
                // A named outage outranks both: "0 conn"
                // reads like a worker mid-redial, which is
                // exactly what a dead provider is not.
                if let Some(o) = outages.iter().find(|o| &o.host == h) {
                    format!("{h} down {}s ({})", o.secs, o.kind)
                } else if *r {
                    format!("{h} refused")
                } else {
                    format!("{h} {c} conn")
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let total: u64 = servers.iter().map(|(_, _, b, _)| *b).sum();
    let name = job_info
        .as_ref()
        .map(|(_, n)| n.clone())
        .unwrap_or_default();
    match stall.observe(
        Instant::now(),
        job_info.as_ref().map(|(i, n)| (i.as_str(), n.as_str())),
        total,
    ) {
        Some(StallEvent::Opened { idle_secs, since }) => {
            info!(
                target: "stall",
                "no data for {idle_secs}s on {name}; servers: {}",
                states()
            );
            *d.stall_since.lock_ok() = job_info.as_ref().map(|(i, _)| (i.clone(), since));
        }
        Some(StallEvent::Cleared { idle_secs }) => {
            info!(
                target: "stall",
                "data flowing again on {name} after {idle_secs}s; servers: {}",
                states()
            );
            *d.stall_since.lock_ok() = None;
        }
        Some(StallEvent::Ended { idle_secs, name }) => {
            info!(
                target: "stall",
                "stall on {name} not resolved after {idle_secs}s (job ended)"
            );
            *d.stall_since.lock_ok() = None;
        }
        None => {}
    }
}

/// Slow-job watchdog (auto-defer + idle-server prefetch): a queue
/// shouldn't sit behind one job whose articles live only on one slow
/// server. Over a rolling window of per-server byte deltas:
/// - PREFETCH: servers idle for the whole window (their copies of
///   this job's articles keep 430ing, or they're down) start the next
///   queued job in a restricted sidecar pipeline instead of idling -
///   the journal makes the handover free however it ends.
/// - DEFER: a job taking ≥90% of its bytes from one host at <40% of
///   the session-best rate while others wait is aborted (journal
///   keeps all landed articles) and requeued deferred at the back -
///   pick_job then runs it only when nothing faster is available.
///   Suppressed while a sidecar is progressing: with the idle
///   capacity already downloading the next job, every server is busy
///   and demoting the slow job would only idle its lone server.
/// Thresholds are env-tunable so tests can compress the timeline.
pub(in crate::serve) fn spawn_slow_job_watchdog(
    daemon: &Arc<Daemon>,
    config: &std::path::Path,
    mem_budget: nzbkit::mem::MemBudget,
) {
    let d = daemon.clone();
    let config = config.to_path_buf();
    tokio::spawn(async move {
        let secs = |k: &str, def: u64| {
            std::env::var(k)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(def)
                .max(1)
        };
        let warmup = secs("NZBFAST_DEFER_WARMUP_SECS", 45);
        let window = secs("NZBFAST_DEFER_WINDOW_SECS", 30);
        // Refusals in one window that make "this post is gone" a
        // verdict rather than noise. A dead post answers 430 as fast as
        // the pool can ask - the 14 Aug releases were accruing thousands
        // per window - so the floor only has to clear a handful of
        // stragglers 430ing at the tail of an otherwise healthy job,
        // which the zero-byte test has almost always excluded already.
        let gone_min_misses = secs("NZBFAST_DEFER_GONE_MIN_MISSES", 64);
        // Tail-prefetch experiment (dark): when the active job's article
        // queue runs dry (the pool's network tail), the flat byte window
        // below would skip the whole prefetch block - which is exactly
        // backwards, because the tail is when idle line capacity peaks.
        // With the knob on, a latched tail overrides the flat-window and
        // single-server gates; every other gate (warmup, quota, pause,
        // one-sidecar) still applies, and the fleet the byte test then
        // yields at a dry tail is the bounded BORROW fleet (all healthy
        // hosts at 1-2 connections each), never a full-budget one.
        let tail_prefetch = std::env::var("NZBFAST_TAIL_PREFETCH").is_ok_and(|v| v == "1");
        let tick = (window / 6).clamp(1, 5);
        // Rolling (time, per-host cumulative bytes) samples of the
        // ACTIVE job's pool; reset on job change. `attempted` = jobs
        // already sidecar-tried during the current active job (so a
        // job whose articles the idle servers don't hold either
        // isn't retried every tick).
        // Per sample: (taken at, per-host raw bytes, articles tried,
        // articles 430'd) - the last two summed across servers, because
        // "is this post gone" is a job-wide question, not a per-host one.
        let mut win: VecDeque<(Instant, Vec<(String, u64)>, u64, u64)> = VecDeque::new();
        let mut cur: Option<String> = None;
        let mut attempted: std::collections::HashSet<String> = Default::default();
        // Once per active job: "every idle server has refused auth".
        let mut refusal_noted = false;
        // Transfer-stall episodes: one log line when the active fetch
        // moves no bytes for NZBFAST_STALL_LOG_SECS (default 10), one
        // when it clears - so "send me the log" captures a flatline
        // after the fact. Observation only, and always on: it runs
        // BEFORE the auto-defer/prefetch gates below.
        let mut stall = StallTracker::new(std::time::Duration::from_secs(secs(
            "NZBFAST_STALL_LOG_SECS",
            10,
        )));
        // Server-outage episodes already warned about, host -> the
        // `down_since` stamp that was warned. A stamp is per episode by
        // construction (the gauge clears on the first granted session),
        // so this warns once per outage per server rather than once per
        // tick - and warns AGAIN if the server comes back and dies
        // again, which is a different fact worth a line.
        let mut outage_noted: std::collections::HashMap<String, u64> = Default::default();
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(tick)).await;
            observe_transfer_and_outages(&d, &mut stall, &mut outage_noted);
            if !d.auto_defer.load(Ordering::Relaxed) && !d.auto_prefetch.load(Ordering::Relaxed) {
                win.clear();
                continue;
            }
            // The job that OWNS the hub, never merely the first
            // Downloading one in the queue: job N's tail overlaps
            // job N+1's download, so N stays Downloading (and ahead
            // in the queue) while pool_live/abort/queue_ctl below
            // are already N+1's. Picking by position measured N+1's
            // pool, wrote the demote onto N and fired the abort at
            // N+1 - killing a healthy download.
            //
            // Except while a predecessor is still DRAINING behind the
            // owner (the cross-job hand-over): the runner holds the
            // queue on that job, not on the owner, so it is the one
            // whose slowness costs everyone - and the owner's own rate
            // says nothing yet, its fleet still being handed to it
            // one connection at a time. `watched` carries the
            // drainer's own gauges and stop handles for exactly this.
            let Some(w) = watched(&d) else {
                win.clear();
                cur = None;
                continue;
            };
            let (t0, active, handing_over) = (w.t0, w.id.clone(), w.draining);
            let Some(job) = d
                .queue
                .lock_ok()
                .iter()
                .find(|j| {
                    let g = j.lock_ok();
                    g.nzo_id == active && g.state == JobState::Downloading
                })
                .cloned()
            else {
                win.clear();
                continue;
            };
            let (id, defer_count, demote) = {
                let g = job.lock_ok();
                (g.nzo_id.clone(), g.defer_count, g.demote)
            };
            if demote {
                continue; // abort already in flight
            }
            if cur.as_deref() != Some(id.as_str()) {
                win.clear();
                attempted.clear();
                refusal_noted = false;
                cur = Some(id.clone());
            }
            let (snap, tried_now, missing_now) = {
                let l = &w.pool_live;
                let mut hosts: Vec<(String, u64)> = Vec::with_capacity(l.servers.len());
                let (mut tried, mut missing) = (0u64, 0u64);
                for s in l.servers.iter() {
                    hosts.push((s.host.clone(), s.bytes.load(Ordering::Relaxed)));
                    tried += s.articles_tried.load(Ordering::Relaxed);
                    missing += s.articles_missing.load(Ordering::Relaxed);
                }
                (hosts, tried, missing)
            };
            if snap.is_empty() {
                continue;
            }
            let now = Instant::now();
            win.push_back((now, snap, tried_now, missing_now));
            while win
                .front()
                .is_some_and(|(t, ..)| now.duration_since(*t).as_secs() > window)
            {
                win.pop_front();
            }
            let Some((t_first, first, tried_base, missing_base)) = win.front().cloned() else {
                continue;
            };
            // Answers this window, not this run: a job that fetched
            // half a release and only then hit a dead patch still holds
            // the queue, and cumulative totals would let its early
            // successes mask that forever.
            let tried_delta = tried_now.saturating_sub(tried_base);
            let missing_delta = missing_now.saturating_sub(missing_base);
            let span = now.duration_since(t_first).as_secs_f64();
            if span < window as f64 * 0.8 {
                continue;
            }
            let base: std::collections::HashMap<&str, u64> =
                first.iter().map(|(h, b)| (h.as_str(), *b)).collect();
            let deltas: Vec<(String, u64)> = win
                .back()
                .unwrap()
                .1
                .iter()
                .map(|(h, b)| {
                    (
                        h.clone(),
                        b.saturating_sub(base.get(h.as_str()).copied().unwrap_or(0)),
                    )
                })
                .collect();
            let total: u64 = deltas.iter().map(|(_, b)| b).sum();
            let rate = total as f64 / span;
            // Every sustained window is also a reference sample.
            d.best_rate_bps.fetch_max(rate as u64, Ordering::Relaxed);
            // Tail-prefetch experiment: a latched network tail with
            // work still in flight. Read fresh each tick - the latch
            // only ever appears once per run, and `Some(0)` (tail
            // finished) must not trigger.
            let tail_now = tail_prefetch
                && w.queue_ctl
                    .as_ref()
                    .and_then(|c| c.tail_pending())
                    .is_some_and(|p| p > 0);
            // ---- Wedged behind a dead server: defer and move on.
            //
            // "A wholly stalled job is the pool's retry logic's problem"
            // (below) is true of a job whose articles are 430ing their
            // way through a refusal ladder - that is real progress with
            // no bytes to show for it. It is NOT true when a configured
            // server has been granting no connection at all for the
            // whole window: the pool is waiting on a socket, the retry
            // logic has nothing to retry, and the whole QUEUE sits
            // behind one job that cannot move. That case reached the
            // `total == 0` bail below and stopped there, which is how
            // two soak jobs held the queue for 25 minutes (11->12 Aug).
            //
            // Deferring is cheap and reversible: the journal keeps every
            // landed article, `pick_job` runs a deferred job whenever
            // nothing else is available, and if the whole queue is
            // deferred it comes straight back. `others_waiting` is the
            // point - with nothing else to run, sitting here is right.
            if total == 0
                && d.auto_defer.load(Ordering::Relaxed)
                && now.duration_since(t0).as_secs() >= warmup
                && defer_count < 3
                && d.sidecar.lock_ok().as_ref().is_none_or(|s| s.borrowed)
                && let Some(o) = server_outages(&d)
                    .into_iter()
                    .find(|o| o.secs >= span as u64 && o.secs >= server_down_secs())
            {
                let others_waiting = d.queue.lock_ok().iter().any(|j| {
                    let g = j.lock_ok();
                    g.state == JobState::Queued && !g.paused && !g.deferred
                });
                if others_waiting {
                    let reason = format!(
                        "{} has had no usable connection for {}s ({}) and nothing \
                         has arrived for {:.0}s - the articles this job still needs \
                         are only on that server",
                        o.host, o.secs, o.kind, span
                    );
                    {
                        let mut g = job.lock_ok();
                        g.demote = true;
                        g.defer_reason = reason.clone();
                    }
                    info!(target: "defer", "{id}: {reason} - moving to the back of the queue");
                    w.stop();
                    win.clear();
                    continue;
                }
            }
            // ---- The post is gone: servers healthy, every answer a 430.
            //
            // The sibling arm above covers a server that grants no
            // CONNECTION. This is the other shape of a zero-byte window,
            // and the `total == 0` bail below sends it to the pool's
            // retry logic on the reasoning that articles "430ing their
            // way through a refusal ladder" are real progress. They are,
            // right up until every one of them is a refusal - then the
            // ladder has nothing left to climb and the queue sits behind
            // a post no configured server carries.
            //
            // Measured 14 Aug 2026: two 21-day-old teevee releases whose
            // articles are all taken down held the queue for 10+ minutes
            // each, at 0.0 MB/s, while other jobs waited. The engine had
            // already PROVED it - the prefetch lane logged "post is
            // gone: not one of the 14087 article(s) is on any server" -
            // but that verdict died with the sidecar and the main job
            // started over from scratch.
            //
            // Separating the two shapes is the miss counter, not the
            // clock: a wedged server answers nothing, so `missing_delta`
            // stays 0 and this arm cannot fire on it. Zero bytes plus
            // refusals means the answers arrived and every one was "no
            // such article".
            //
            // Deferring, not failing: this says "unservable right now",
            // which a provider outage or a still-propagating post also
            // looks like. `pick_job` runs a deferred job when nothing
            // else is available, the journal keeps every landed article,
            // and the give-up breaker and post-download health verdict
            // remain the things that decide a job is finally dead.
            if total == 0
                && missing_delta >= gone_min_misses
                && tried_delta > 0
                && d.auto_defer.load(Ordering::Relaxed)
                && now.duration_since(t0).as_secs() >= warmup
                && defer_count < 3
                && d.sidecar.lock_ok().as_ref().is_none_or(|s| s.borrowed)
            {
                let others_waiting = d.queue.lock_ok().iter().any(|j| {
                    let g = j.lock_ok();
                    g.state == JobState::Queued && !g.paused && !g.deferred
                });
                if others_waiting {
                    let reason = format!(
                        "every one of the {missing_delta} article(s) answered in the \
                         last {span:.0}s came back missing and not a byte arrived - \
                         no configured server carries this post right now"
                    );
                    {
                        let mut g = job.lock_ok();
                        g.demote = true;
                        g.defer_reason = reason.clone();
                    }
                    info!(target: "defer", "{id}: {reason} - moving to the back of the queue");
                    w.stop();
                    win.clear();
                    continue;
                }
            }
            // A wholly stalled job is the pool's retry logic's
            // problem, and a single-server setup has nothing to
            // route around. (Unless the tail override is live: a dry
            // tail IS a flat window, and borrowing 1-2 connections is
            // meaningful even from a single server.)
            if (total == 0 || deltas.len() < 2) && !tail_now {
                continue;
            }
            if now.duration_since(t0).as_secs() < warmup {
                continue;
            }

            // ---- Idle-server prefetch: any host that contributed
            // <1% of the window while the job moved is idle - its
            // copies of this job's articles keep 430ing (or it's
            // down). Start the next queued job on JUST those hosts.
            // Skipped when a period quota is configured: the quota
            // ledger is the runner's, and opportunistic fetches
            // shouldn't race a metered budget.
            //
            // Not while a hand-over is in progress: the next job is
            // already running on the real hub, and a server that is
            // idle for the DRAINING job is busy for it - a sidecar
            // built on that reading would be a second full fleet on
            // the server the successor is filling.
            if d.auto_prefetch.load(Ordering::Relaxed)
                && !d.paused.load(Ordering::Relaxed)
                && d.quota.load(Ordering::Relaxed) == 0
                && d.sidecar.lock_ok().is_none()
                && !handing_over
            {
                // A server that refused to authenticate (bad
                // credential, or at its connection/IP cap) moved no
                // bytes, so by the byte test alone it reads as idle
                // capacity - and a sidecar whose whole fleet is
                // refused servers prefetches nothing while the
                // queued job it claimed sits blocked behind it.
                let refused: std::collections::HashSet<String> = w
                    .pool_live
                    .servers
                    .iter()
                    .filter(|s| s.refusal.lock_ok().is_some())
                    .map(|s| s.host.clone())
                    .collect();
                let mut any_idle = false;
                let idle: Vec<String> = deltas
                    .iter()
                    .filter(|(_, b)| (*b as f64) < total as f64 * 0.01)
                    .inspect(|_| any_idle = true)
                    .filter(|(h, _)| !refused.contains(h))
                    .map(|(h, _)| h.clone())
                    .collect();
                // No healthy idle server (they all refused auth, or
                // every server is busy on the active job): borrow a
                // bounded 1-2 connection slice of the healthy BUSY
                // servers instead, so the next job's tail-overlap
                // still engages (the 31 Jul soak measured
                // 49 s line-idle of a 144 s queue without it). The
                // per-host cap lives on the sidecar hub - see
                // spawn_sidecar for the budget accounting.
                let (fleet, borrow) = if idle.is_empty() {
                    let busy: Vec<String> = deltas
                        .iter()
                        .filter(|(_, b)| (*b as f64) >= total as f64 * 0.01)
                        .filter(|(h, _)| !refused.contains(h))
                        .map(|(h, _)| h.clone())
                        .collect();
                    (busy, true)
                } else {
                    (idle, false)
                };
                if borrow && any_idle && !refusal_noted {
                    refusal_noted = true;
                    info!(
                        target: "prefetch",
                        "every idle server refused to authenticate ({}) - borrowing from the busy server(s) instead",
                        refused.iter().cloned().collect::<Vec<_>>().join(", ")
                    );
                }
                if !fleet.is_empty() {
                    // Same ordering as pick_job, minus: deferred jobs
                    // (their articles live on the BUSY server - the
                    // idle set has already rejected them), library
                    // entries, and jobs already tried this cycle.
                    let mut best: Option<(i32, Arc<Mutex<Job>>)> = None;
                    for j in d.queue.lock_ok().iter() {
                        let g = j.lock_ok();
                        if g.state != JobState::Queued
                            || g.paused
                            || g.deferred
                            || g.library
                            || attempted.contains(&g.nzo_id)
                        {
                            continue;
                        }
                        if best.as_ref().is_none_or(|(bp, _)| g.priority > *bp) {
                            best = Some((g.priority, j.clone()));
                        }
                    }
                    if let Some((_, nj)) = best {
                        spawn_sidecar(&d, &config, &nj, &fleet, &deltas, mem_budget, borrow);
                        attempted.insert(nj.lock_ok().nzo_id.clone());
                    }
                }
            }

            // The tail override above unlocks ONLY the prefetch block.
            // The defer verdict below must never see the tail shapes:
            // `share = top/total` is NaN at total == 0 and NaN slips
            // the `share < 0.90` demote gate (a healthy job would be
            // aborted at its own tail), and a single-server job has
            // nothing to route around.
            if total == 0 || deltas.len() < 2 {
                continue;
            }

            // ---- Defer verdict. Suppressed while an IDLE-server
            // sidecar runs: the idle capacity is already downloading
            // the next job, so every server is busy - demoting the
            // slow job would only idle its lone server. A BORROWED
            // sidecar claims no idle capacity (it runs on a 1-2
            // connection slice of the busy servers), so it must not
            // disarm the watchdog: with borrowing, a sidecar exists
            // almost whenever a queue does, and suppressing on it
            // would retire the defer verdict outright.
            let idle_sidecar = d.sidecar.lock_ok().as_ref().is_some_and(|s| !s.borrowed);
            if defer_count >= 3 || idle_sidecar {
                continue;
            }
            let others_waiting = d.queue.lock_ok().iter().any(|j| {
                let g = j.lock_ok();
                g.state == JobState::Queued && !g.paused && !g.deferred
            });
            if !others_waiting {
                continue;
            }
            let (top_host, top_bytes) = deltas.iter().max_by_key(|(_, b)| *b).cloned().unwrap();
            let share = top_bytes as f64 / total as f64;
            let best = d.best_rate_bps.load(Ordering::Relaxed);
            if share < 0.90 || best < 1_000_000 || rate >= 0.4 * best as f64 {
                continue;
            }
            let reason = format!(
                "{:.0}% of the last {:.0}s came from {top_host} at {:.1} MB/s \
                 (session best {:.1} MB/s) - the other servers had nothing \
                 for this job",
                share * 100.0,
                span,
                rate / 1e6,
                best as f64 / 1e6
            );
            {
                let mut g = job.lock_ok();
                g.demote = true;
                g.defer_reason = reason.clone();
            }
            info!(target: "defer", "{id}: {reason} - moving to the back of the queue");
            w.stop();
            win.clear();
        }
    });
}
