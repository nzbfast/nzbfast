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

/// How long a defer lets the fleet wind itself down before it takes the
/// line back by force. One watchdog tick (`window / 6`, clamped, default
/// 5 s) - the same beat the loop already judges on, so the escalation
/// has always landed by the time the next verdict is formed.
///
/// It is a constant rather than a read of the live tick because the tick
/// shrinks to 1 s under a short `NZBFAST_DEFER_WINDOW_SECS`, and a 1 s
/// grace cuts off a fleet that is winding down perfectly well (the
/// 400 ms/article row below).
///
/// **The number, measured 26 Aug 2026** (mock fleet, 4 connections,
/// window 3, the daemon's adaptive timeouts; `abort()` against `drain()`
/// at the same instant; "kept" is sessions still the provider's
/// afterwards, out of 4):
///
/// | the fleet the verdict finds       | abort  | drain    | kept abort -> drain |
/// |-----------------------------------|--------|----------|---------------------|
/// | fast, deep pipelines (60 ms/art)  | 7 ms   |   129 ms | 0 -> 4              |
/// | every answer a 430 (post is gone) | 8 ms   |   131 ms | 0 -> 4              |
/// | slow but answering (400 ms/art)   | 151 ms | 1,185 ms | 0 -> 4              |
/// | slow but answering (1.5 s/art)    | 152 ms | 4,084 ms | 0 -> 4              |
/// | idle but for one wedged body      | 151 ms | 9,577 ms | 3 -> 3              |
/// | wholly wedged, all mid-body       | 151 ms | 9,575 ms | 0 -> 0              |
///
/// Two facts decide the shape. A drain keeps the WHOLE fleet whenever
/// the server is answering - and an abort keeps none of it, because
/// those workers are mid-body and a socket with an unread response is
/// reusable by nobody. And a drain buys exactly NOTHING against a peer
/// that has stopped answering, while costing the pre-byte budget's
/// ceiling (10 s) to find that out. So the verb is a drain and the
/// grace is what stops the second row of that pair from holding the
/// queue: 5 s clears every measured fleet that was answering and halves
/// the wedge.
const DEFER_DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

impl Watched {
    /// Wind the judged run down - the defer verdict's teeth.
    fn stop(&self) {
        self.stop_within(DEFER_DRAIN_GRACE);
    }

    /// [`Watched::stop`] with the grace named, so a test can drive the
    /// escalation without sitting out [`DEFER_DRAIN_GRACE`].
    ///
    /// **Why a defer drains rather than aborts.** A defer means "move
    /// this job to the back of the queue and come back to it", which is
    /// a pause/resume and not a stop - and `8cda45132` could only reach
    /// half of the fleet it strands. That commit made an abort PARK a
    /// drained session, which is the whole population of the capacity
    /// arm below (its workers are idle by definition: the server has
    /// nothing fetchable). It is NONE of the population of the
    /// `share >= 0.90` arm, whose top server is busy and fast by the
    /// arm's own predicate, so its workers are mid-body and exit through
    /// the read side with an unread response on the wire - correctly
    /// quit, and nothing inside the pool can change that. This is every
    /// arm's verb, and the two post-is-gone arms are on the same side of
    /// it as the busy one rather than with the capacity arm: a dead post
    /// answers 430 as fast as the pool can ask, so those pipelines drain
    /// in about the time one refusal takes (the second row below). The
    /// only way
    /// to keep those sessions is to let the responses LAND, which is
    /// what `drain()` is: admit no new articles, finish and journal what
    /// is in flight, and every worker then reaches the pool's own reuse
    /// point and parks. The in-flight bodies are journaled instead of
    /// discarded and re-fetched when the job comes round again.
    ///
    /// **Why it is bounded.** A drain deliberately sends no `finished`,
    /// so a fleet whose peer has stopped answering waits out the
    /// per-article pre-byte ladder before it can retire - measured at
    /// 9.6 s, for zero sessions kept. `DEFER_DRAIN_GRACE` carries that
    /// measurement; past it this escalates to the abort, which is
    /// exactly what a defer did before.
    ///
    /// **What the escalation may and may not touch.** `abort()` answers
    /// false once the pool has dropped its `Shared`, and that is
    /// precisely "the drain finished" - so a fleet that wound down
    /// inside the grace is never touched. It also cannot reach a
    /// SUCCESSOR: both handles are clones of the judged run's own (the
    /// hub slots hold an `Arc` per run and `install_seek` replaces them),
    /// so a late escalation is inert rather than aimed at the next job.
    ///
    /// The engine's abort flag is set only WITH the escalation. On the
    /// ordinary path the run ends on the drain's own bail instead
    /// ("paused (drained in-flight; queue kept for resume)"), which is
    /// the same `Err` the demote arm keys on - `postproc` asks
    /// `res.is_err() && j.demote`, and `park` clears the message when it
    /// re-queues - so the defer lands exactly as it did before.
    fn stop_within(&self, grace: std::time::Duration) {
        let Some(ctl) = self.queue_ctl.clone() else {
            // No pool handle for this run: the flag is the only teeth
            // there are, and it is what a defer has always set.
            if let Some(f) = &self.abort {
                f.store(true, Ordering::Relaxed);
            }
            return;
        };
        if ctl.is_draining() {
            // Already winding down - a second verdict on the same run
            // (or the user's own graceful pause) must not arm a second
            // escalation behind the first.
            return;
        }
        if !ctl.drain() {
            // The run beat the verdict to the line. Set the flag anyway:
            // `park` is what decides a demotion actually happened, and
            // it already knows how to drop a stale one.
            if let Some(f) = &self.abort {
                f.store(true, Ordering::Relaxed);
            }
            return;
        }
        let abort = self.abort.clone();
        tokio::spawn(async move {
            tokio::time::sleep(grace).await;
            if ctl.abort()
                && let Some(f) = &abort
            {
                f.store(true, Ordering::Relaxed);
            }
        });
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

/// Is there another job this queue could be running instead?
///
/// The whole justification for every demotion below: setting a job
/// aside costs the queue nothing when something else can run, and costs
/// it a restart when nothing can. Deliberately the same test in all
/// four arms - a Queued job that is neither paused nor already
/// deferred - so no arm can be more or less willing to demote than its
/// siblings for a reason nobody wrote down.
fn others_waiting(d: &Daemon) -> bool {
    d.queue.lock_ok().iter().any(|j| {
        let g = j.lock_ok();
        g.state == JobState::Queued && !g.paused && !g.deferred
    })
}

/// What the EARLY post-is-gone arm (TODO 306) has to see before it will
/// speak: the same verdict as its windowed sibling, read over the job's
/// WHOLE RUN instead of over one rolling window.
struct GoneEvidence {
    /// Articles answered "no such article" since this job started,
    /// summed across every server.
    misses: u64,
    /// Servers that have themselves answered at least one of them.
    probed: usize,
}

/// Run-cumulative evidence that no configured server carries this post.
///
/// # Why this exists beside a windowed arm that already works
///
/// The windowed post-is-gone arm below is correct and measured, and it
/// cannot fire inside about 69 seconds: `warmup` (45 s) plus a rolling
/// window at least 80% full (24 s of a 30 s window). The 14 Aug 2026
/// incident it was written for was ten minutes long and clears that
/// comfortably. **Everything shorter it cannot help at all** - and a
/// dead post of a few thousand articles on a normal line grinds itself
/// out in tens of seconds while holding the entire queue for all of
/// them. Measured 26 Aug 2026 (`research/QUEUE-PROGRESS-UNDER-FAULT-2026-08-26.md`
/// finding F4): a 1200-article post refused at a transatlantic refusal
/// cost held three healthy jobs for its whole 16.7 s run, `set aside
/// never`, against a 1.0 s control - sixteen times, with the mechanism
/// present, correct and simply not yet armed. The same row at
/// compressed thresholds is released at 5.4 s by the windowed arm.
///
/// # Why the answer is evidence and not a smaller clock
///
/// Lowering `warmup` would move every arm, and the warmup earns its
/// keep for the other two: a job whose fleet is still dialling, or
/// whose first megabyte is slow, must not be benched for it. What is
/// different about THIS arm is that its evidence does not improve with
/// time. A job that has answered nothing but refusals for its entire
/// life is not a job that needs warming up, and waiting another 45
/// seconds only buys more of the same answer.
///
/// So the gates here are all statements about the RUN, and each one is
/// strictly stronger than what the windowed arm asks:
///
/// 1. **Not one byte, ever.** The windowed arm allows a job that
///    fetched half a release and only then hit a dead patch; this one
///    does not. Every server's cumulative `bytes` must be zero, which
///    is the single condition that rules out "the tail of an otherwise
///    healthy job" outright - the case the 64-refusal floor was written
///    to clear.
/// 2. **Nothing unprobed.** Every server must either have answered a
///    refusal ITSELF, or be granting no connection at all right now
///    (`down_since`), which is the outage arm's territory and cannot
///    supply anything either way. A server that is up and simply has
///    not been asked yet might be the one that has the post, so its
///    silence stands the verdict down rather than being counted as
///    agreement.
/// 3. **A floor of authoritative answers** (the caller's
///    `gone_min_misses`), so a handful of 430s is never a verdict.
///
/// # What it cannot see, stated rather than papered over
///
/// There is no live in-flight gauge: `articles_tried` is bumped at
/// dispatch and `articles_missing` at the response, so on a pipelined
/// fleet the two differ by whatever is on the wire and "nothing is in
/// flight" is not a question these counters can answer. The caller
/// answers it the way `slowstore.rs` answers its own - by CONFIRMING
/// before acting. It arms on one tick and fires on a later one, and an
/// in-flight body landing in between moves `bytes` off zero and stands
/// the whole thing down. That bounds the exposure to one tick rather
/// than pretending to a certainty the gauges do not carry.
///
/// Two shapes degrade rather than misfiring, and both fall back to the
/// windowed arm at its old 69 seconds, which is the safe direction:
///
/// * A server the pool never dials at all and that never records itself
///   down keeps condition 2 unsatisfied forever.
/// * A PARTIAL takedown - some of the post arrives and the rest is
///   refused - fails condition 1 by construction, and that is the price
///   of firing with no warmup. Measured 26 Aug 2026 on round A's S6
///   row: unchanged at both threshold sets, still holding the queue for
///   its whole 11.6 s run at the shipped ones. Covering it means
///   shortening the FLATLINE window rather than removing a warmup,
///   which is a different risk decision and is TODO 306's own remaining
///   box. Do NOT reach for [`StallTracker`] to shorten it: this
///   module's header says why action stays out of that scope.
fn gone_evidence(live: &nzbkit::pool::LiveStats) -> Option<GoneEvidence> {
    let (mut misses, mut probed) = (0u64, 0usize);
    for s in live.servers.iter() {
        if s.bytes.load(Ordering::Relaxed) > 0 {
            return None;
        }
        let m = s.articles_missing.load(Ordering::Relaxed);
        if m > 0 {
            misses += m;
            probed += 1;
        } else if s.down_since.load(Ordering::Relaxed) == 0 {
            return None;
        }
    }
    (probed > 0).then_some(GoneEvidence { misses, probed })
}

/// TODO 306's early post-is-gone arm: the same verdict as the windowed
/// twin in [`spawn_slow_job_watchdog`], reached off the RUN rather than
/// off a rolling window, so it is bounded by its own confirmation
/// rather than by a 69-second clock. Returns the defer reason when it
/// fires, having already consumed its arming latch.
///
/// [`gone_evidence`] carries the whole argument for why reading the run
/// is sound HERE and would not be for the other two arms - do not lift
/// the elapsed-time gate off them on the strength of this one.
///
/// Everything past the evidence is the windowed arm's own list,
/// unchanged: the feature on, the demotion budget, a sidecar that is
/// only borrowing, and somewhere for the queue to go next.
///
/// **Arm on one tick, fire on the next.** `armed` holds the refusal
/// count at the arming instant and the fire requires MORE to have
/// landed since, so what is confirmed is that the fleet is still
/// actively being told "no such article" - a pool that has gone quiet
/// instead is the outage arm's shape, or a job about to end on its own,
/// and neither is this arm's to judge. A tick whose evidence fails
/// clears the latch, so the confirmation is always over an unbroken
/// stretch.
fn early_gone_defer(
    d: &Arc<Daemon>,
    live: &nzbkit::pool::LiveStats,
    armed: &mut Option<u64>,
    gone_min_misses: u64,
    defer_count: u32,
) -> Option<String> {
    let Some(e) = gone_evidence(live).filter(|e| e.misses >= gone_min_misses) else {
        *armed = None;
        return None;
    };
    let Some(armed_at) = *armed else {
        *armed = Some(e.misses);
        return None;
    };
    if e.misses <= armed_at
        || !d.auto_defer.load(Ordering::Relaxed)
        || defer_count >= 3
        || !d.sidecar.lock_ok().as_ref().is_none_or(|s| s.borrowed)
        || !others_waiting(d)
    {
        return None;
    }
    *armed = None;
    Some(format!(
        "not a byte has arrived since this job started and every one of the {} \
         article(s) answered so far came back missing, on all {} server(s) that \
         could be asked - no configured server carries this post right now",
        e.misses, e.probed
    ))
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
        // TODO 306's early post-is-gone arm, armed on one tick and
        // fired on a later one: the run-cumulative refusal count as it
        // stood when the evidence first held. `None` = not armed, and
        // any tick whose evidence fails clears it, so the confirmation
        // is always over an unbroken stretch. See [`gone_evidence`] for
        // why confirming is the honest substitute for an in-flight
        // gauge the pool does not publish.
        let mut gone_armed: Option<u64> = None;
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
            // Retention insurance: an in-flight background fetch stands
            // down the moment a real job becomes runnable. Before the
            // auto_defer/auto_prefetch gate below on purpose - yielding
            // is part of the insurance feature's own not-hinder
            // contract, not of either tuner's - and one atomic load
            // when the feature is off.
            crate::serve::insurance::insurance_yields_to_arrivals(&d);
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
                gone_armed = None;
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

            // ---- The post is gone, before any window can say so
            // (TODO 306). Deliberately BEFORE the window bookkeeping
            // and the `span < window * 0.8` bail below, which is the
            // gate that makes the shipped regime unreachable for a
            // short job. See [`early_gone_defer`].
            if let Some(reason) = early_gone_defer(
                &d,
                &w.pool_live,
                &mut gone_armed,
                gone_min_misses,
                defer_count,
            ) {
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
                && others_waiting(&d)
                && let Some(o) = server_outages(&d)
                    .into_iter()
                    .find(|o| o.secs >= span as u64 && o.secs >= server_down_secs())
            {
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
                && others_waiting(&d)
            {
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
            if !others_waiting(&d) {
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

#[cfg(test)]
mod stop_verb_tests {
    use super::*;
    use nzbkit::mock::{Chaos, MockServer, make_file_articles};
    use nzbkit::pool::{ArticleReq, PoolConfig, QueueControl, fetch_all_multi_ctl};
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    /// A `Watched` with only the two handles `stop_within` touches -
    /// everything else on it belongs to the JUDGEMENT, and these tests
    /// are about the verdict's teeth rather than about reaching it.
    fn watched_over(
        abort: Option<Arc<AtomicBool>>,
        queue_ctl: Option<Arc<QueueControl>>,
    ) -> Watched {
        Watched {
            id: "SABnzbd_nzo_stopverb".into(),
            t0: Instant::now(),
            pool_live: nzbkit::pool::LiveStats::for_servers(&[]),
            abort,
            queue_ctl,
            draining: false,
        }
    }

    /// A run with no pool handle - and a run whose pool has already gone
    /// - keep the teeth a defer has always had. Both are the fall-back
    /// arms of `stop_within`, and both must still set the engine flag,
    /// because it is the only thing left that can end the run.
    #[test]
    fn a_defer_with_no_live_pool_still_sets_the_engine_flag() {
        let flag = Arc::new(AtomicBool::new(false));
        watched_over(Some(flag.clone()), None).stop_within(Duration::from_millis(10));
        assert!(
            flag.load(Ordering::Relaxed),
            "with no queue handle the flag is the only teeth there are"
        );

        let flag = Arc::new(AtomicBool::new(false));
        // A default `QueueControl` holds a dead `Weak`, which is exactly
        // the shape of a run that beat the verdict to the line.
        let gone = Arc::new(QueueControl::default());
        assert!(!gone.drain(), "the fixture must be a run that is over");
        watched_over(Some(flag.clone()), Some(gone)).stop_within(Duration::from_millis(10));
        assert!(
            flag.load(Ordering::Relaxed),
            "a run that has already ended still gets the flag - `park` is \
             what decides whether the demotion happened"
        );
    }

    /// The verdict's verb, driven against a REAL fleet: a defer winds the
    /// pool down rather than killing it, and escalates at the grace.
    ///
    /// Two phases on one rig, because the claim is that the escalation
    /// is a BOUND and not the verb. Phase 1 is a fleet whose server has
    /// stopped answering - the shape a drain cannot finish, measured at
    /// 9.6 s of pre-byte ladder for zero sessions kept - and the grace
    /// is what takes the line back. Phase 2 is a fleet that is
    /// answering, where the drain completes well inside the grace and
    /// the escalation must find nothing left to abort: `QueueControl`
    /// answers false once the pool has dropped its `Shared`, and that is
    /// the whole of what stops a late escalation reaching a successor.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_defer_drains_the_fleet_and_escalates_only_at_the_grace() {
        async fn rig(delay_ms: u64) -> (Arc<QueueControl>, tokio::task::JoinHandle<()>) {
            let mut articles = std::collections::HashMap::new();
            let payload: Vec<u8> = (0..64_000u32).map(|i| i as u8).collect();
            for i in 0..40 {
                make_file_articles(
                    &format!("d{i}.bin"),
                    &payload,
                    64_000,
                    &format!("d{i}"),
                    &mut articles,
                );
            }
            let ids: Vec<ArticleReq> = articles
                .keys()
                .map(|k| ArticleReq::fresh(k.as_str()))
                .collect();
            let srv = MockServer::start(
                articles,
                Chaos {
                    delay_ms,
                    ..Default::default()
                },
            )
            .await;
            let mut sc = srv.server_config();
            sc.connections = 2;
            let cfg = PoolConfig {
                connections: 2,
                window: 2,
                ramp_delay: Duration::from_millis(0),
                adaptive_timeout: true,
                ..Default::default()
            };
            let ctl = Arc::new(QueueControl::default());
            let (tx, mut rx) = tokio::sync::mpsc::channel(64);
            let ctl_fetch = ctl.clone();
            let run = tokio::spawn(async move {
                let servers = vec![(sc, cfg)];
                let collect = tokio::spawn(async move { while rx.recv().await.is_some() {} });
                let _ = fetch_all_multi_ctl(&servers, ids, tx, Some(&ctl_fetch)).await;
                let _ = collect.await;
                // Hold the mock until the run is over, or its listener
                // dies under the fleet and the rig measures a dead peer
                // instead of the verb.
                drop(srv);
            });
            // Let the fleet dial and fill its pipelines.
            tokio::time::sleep(Duration::from_millis(500)).await;
            (ctl, run)
        }

        // Phase 1: the server has stopped answering. The drain cannot
        // finish, so the grace is what ends the run.
        let (ctl, run) = rig(60_000).await;
        let flag = Arc::new(AtomicBool::new(false));
        watched_over(Some(flag.clone()), Some(ctl.clone())).stop_within(Duration::from_millis(300));
        assert!(
            ctl.is_draining(),
            "a defer's verb is the drain - the abort is only its bound"
        );
        assert!(
            !flag.load(Ordering::Relaxed),
            "and the engine flag belongs to the escalation, not to the verdict"
        );
        tokio::time::timeout(Duration::from_secs(30), run)
            .await
            .expect("the grace must take the line back from a wedged fleet")
            .expect("the run task");
        assert!(
            flag.load(Ordering::Relaxed),
            "the escalation sets the flag on the way past, exactly as a \
             defer did before it drained first"
        );

        // Phase 2: the server is answering. The drain finishes long
        // before the grace, so the escalation must be inert.
        let (ctl, run) = rig(30).await;
        let flag = Arc::new(AtomicBool::new(false));
        watched_over(Some(flag.clone()), Some(ctl.clone())).stop_within(Duration::from_secs(3));
        tokio::time::timeout(Duration::from_secs(30), run)
            .await
            .expect("a drained fleet must wind down on its own")
            .expect("the run task");
        // Past the grace, with the run long gone.
        tokio::time::sleep(Duration::from_secs(4)).await;
        assert!(
            !flag.load(Ordering::Relaxed),
            "a fleet that wound down inside the grace is never aborted - \
             that is what keeps a late escalation off a successor's run"
        );
    }
}

#[cfg(test)]
#[path = "stall_gone_tests.rs"]
mod stall_gone_tests;
