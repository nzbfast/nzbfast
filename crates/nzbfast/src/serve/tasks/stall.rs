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
    /// **A run that is ALREADY draining still gets the bound.** The verb
    /// is idempotent and the bound is not: a drain the verdict did not
    /// start - the user's own graceful pause is the live case - carries
    /// no escalation behind it, so skipping the arming left the wedge
    /// held by the read ladder alone. The reasoning, and why a duplicate
    /// escalation is harmless if one were ever possible, is at the site.
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
        // Wind the fleet down - unless something already has, in which
        // case the verb is done and only the BOUND is still owed. Until
        // 27 Aug 2026 an already-draining run took an early return here,
        // on the reasoning that "a second verdict on the same run (or
        // the user's own graceful pause) must not arm a second
        // escalation behind the first". Half of that never happened and
        // the other half cost the verdict its teeth:
        //
        // * A SECOND VERDICT CANNOT REACH THIS. `fire_defer` sets
        //   `job.demote` before it calls `stop`, and the watchdog loop's
        //   own `if demote { continue }` gate skips every later tick for
        //   that job. A re-run of the same job clears `demote` (in
        //   `park`) and gets a fresh `QueueControl` besides. (This said
        //   "`fire_defer` and the two arms that still spell it out" when
        //   it was written, hours before TODO 309(d) folded the last
        //   three sites into `fire_defer`. Same argument, one door now.)
        // * THE USER'S OWN GRACEFUL PAUSE HAS NO FIRST ESCALATION.
        //   `fire_pause(false)` calls `drain()` and arms nothing, so
        //   returning here left a defer against a wedged fleet a
        //   complete no-op: the drain was already set, the flag was
        //   never set, and the wedge was bounded only by the pre-byte
        //   read ladder - the 9.6 s rows in the table above, which is
        //   the exact measurement `DEFER_DRAIN_GRACE` exists to replace.
        //   (v1.2.4 sweep, finding R4.)
        //
        // And arming one is safe even if a second ever did arrive:
        // `abort()` is idempotent, and it answers false once the pool
        // has dropped its `Shared`, so the worst a duplicate can do is
        // sleep out its own grace and find nothing.
        //
        // What a defer costs a paused run is nothing it was keeping: the
        // four ZERO-BYTE arms that get here all require that no byte
        // moved (or that every article answered came back missing), so
        // there is no in-flight body whose journaling the escalation
        // discards. The FIFTH, the single-server-bound arm, is the one
        // exception and is bounded rather than free - it fires precisely
        // because bytes ARE moving, so it can have bodies in flight, and
        // what protects them is the drain: the escalation lands only at
        // `DEFER_DRAIN_GRACE`, and everything that finished before it is
        // journaled. TODO 309(d) is that arm's other half - it weighs
        // what the requeue will cost before it ever reaches here.
        if !ctl.is_draining() && !ctl.drain() {
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
/// arms - a Queued job that is neither paused nor already
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
///   of firing with no warmup. That shape is [`partial_gone_defer`]'s,
///   which is a THIRD arm and not a loosening of this one, because what
///   has to shorten for it is the FLATLINE and that is a different risk
///   decision. The two are disjoint on purpose: bytes arriving is
///   exactly what stands this one down and exactly what the other one
///   assumes.
fn gone_evidence(live: &nzbkit::pool::LiveStats) -> Option<GoneEvidence> {
    let mut misses = 0u64;
    for s in live.servers.iter() {
        if s.bytes.load(Ordering::Relaxed) > 0 {
            return None;
        }
        misses += s.articles_missing.load(Ordering::Relaxed);
    }
    let probed = fleet_answered(live)?;
    Some(GoneEvidence { misses, probed })
}

/// How many servers have themselves answered "no such article", or
/// `None` when any server is up and simply has not been asked yet.
///
/// Condition 2 of [`gone_evidence`], lifted out because both
/// post-is-gone arms ask it and only one of them can also ask for a
/// zero byte count. "No configured server carries this post" is a claim
/// about EVERY server, so a server that is up and unprobed stands the
/// verdict down - it might be the one that has it. A server granting no
/// connection at all (`down_since`) cannot supply anything either way
/// and is the outage arm's business, so it neither blocks the verdict
/// nor is counted as agreeing with it.
///
/// # It is the WHOLE of what keeps the windowed arm alive
///
/// This is the one condition the windowed post-is-gone arm in
/// [`spawn_slow_job_watchdog`] does not ask, and therefore the only
/// thing it can still be reached by - so read this before tidying the
/// three arms into two. A fleet carrying a server that is up and has
/// simply never been asked returns `None` here, both twins stand down
/// forever, and the windowed arm is the only one left that can speak.
/// A `retention_days` shorter than the post's age is how a real
/// install produces such a server ([`nzbkit::pool::retention_mask`]
/// seeds it into every article's `tried_430` at queue-build time), and
/// `e2e_qprog::an_unprobed_server_leaves_the_windowed_arm_to_speak` is
/// that fleet driven end to end.
///
/// **There is no second such condition**, and the arm's own comment
/// claimed one until 27 Aug 2026 - "a refusal rate slow enough that no
/// single flatline stretch clears the floor a whole window does".
/// There is no such rate, and the argument is kept here so nobody
/// re-derives it as grounds for leaving that arm untested. Per-host
/// byte counters are monotonic inside a run (the watchdog clears its
/// window on job change), so `total == 0` over the window means EVERY
/// sample in it carries the same byte sum - which is exactly the
/// trailing run [`flat_gone`] walks back over. Its `first` is then the
/// window's own front, so the flatline's seconds are `span`, its
/// misses ARE `missing_delta` and its tries ARE `tried_delta`: the
/// same three numbers, never a smaller count over a shorter stretch.
/// `span >= window * 0.8` also implies the flatline minimum
/// (`2 * (window / 6).clamp(1, 5)`) for every window of 3 s or more,
/// covering the shipped 30 s and both compressed sets in the tests.
/// Add that [`partial_gone_defer`] is evaluated earlier in the tick
/// and takes no warmup, and it reaches the verdict FIRST wherever this
/// function says yes - always.
fn fleet_answered(live: &nzbkit::pool::LiveStats) -> Option<usize> {
    let mut probed = 0usize;
    for s in live.servers.iter() {
        if s.articles_missing.load(Ordering::Relaxed) > 0 {
            probed += 1;
        } else if s.down_since.load(Ordering::Relaxed) == 0 {
            return None;
        }
    }
    (probed > 0).then_some(probed)
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
    // `misses` counts per-server refusal TRANSACTIONS (the ladder asks
    // each missing article on every server), so the article count shown
    // is the floor `ceil(misses / probed)` - each distinct article can
    // be refused at most once per answering server - never the raw sum,
    // which overstates by the fleet multiple.
    Some(format!(
        "not a byte has arrived since this job started and every article \
         answered so far came back missing - at least {} of them, on all {} \
         server(s) that could be asked - no configured server carries this \
         post right now",
        e.misses.div_ceil(e.probed as u64),
        e.probed
    ))
}

/// Land a demotion verdict on the job this tick judged: mark it, say
/// what it will cost, and wind the judged run down.
///
/// Shared by all five arms. It was shared by the two post-is-gone arms
/// TODO 306 added, while the outage, windowed post-is-gone and
/// single-server-bound arms each spelled the same five lines out - which
/// that change called "a fine tidy-up" deliberately not taken. TODO
/// 309(d) took it, because the cost clause below is one sentence that
/// has to be true at every one of those sites, and a sentence copied to
/// five hand-maintained siblings is this repo's most documented defect
/// class.
///
/// **The clause is appended to `defer_reason`, not merely logged.** That
/// field is what the dashboard's queue drawer prints, so a user who is
/// wondering why a job went to the back of the queue reads what the trip
/// back cost it in the same breath. Before this, the only trace anywhere
/// that a job had taken the 2.53x route was one `info!` on the `resume`
/// target of the rerun, hours later, with nothing tying it to the
/// demotion that caused it.
fn fire_defer(
    job: &Arc<Mutex<Job>>,
    reason: &str,
    cost: Option<RequeueCost>,
    w: &Watched,
    win: &mut VecDeque<Sample>,
) {
    // `w.id` and not a second parameter: the caller found `job` by
    // `g.nzo_id == w.id`, so they are the same string by construction,
    // and one of the two would only ever be the one that went stale.
    let id = &w.id;
    let reason = match cost {
        Some(RequeueCost::Disk { restored, cap }) => format!(
            "{reason}; the {:.1} GB already downloaded is over the {:.1} GB budget \
             that keeps a resume to one pass, so when this job runs again it will \
             unpack from volumes on disk instead",
            restored as f64 / 1e9,
            cap as f64 / 1e9
        ),
        Some(RequeueCost::Refetch { refetch }) => format!(
            "{reason}; the {:.1} GB already downloaded unpacked as it arrived and \
             left nothing on disk for a resume to pick up, so when this job runs \
             again it will download those bytes a second time",
            refetch as f64 / 1e9
        ),
        None => reason.to_string(),
    };
    {
        let mut g = job.lock_ok();
        g.demote = true;
        g.defer_reason = reason.clone();
    }
    info!(target: "defer", "{id}: {reason} - moving to the back of the queue");
    w.stop();
    win.clear();
}

/// TODO 309(d): does what the requeue would cost VETO the
/// single-server-bound demotion?
///
/// **This is the one arm where the trade is real, and that falls out of
/// the code rather than being asserted.** All four arms above it require
/// a stretch in which not one byte arrived - `gone_evidence` refuses a
/// server that has moved any, `flat_gone` reads a flatline, and the
/// outage and windowed post-is-gone arms both gate on `total == 0`. A
/// job moving nothing cannot be made cheaper by keeping its slot,
/// because keeping it buys the queue nothing at all and the alternative
/// is that the whole queue sits behind a post no reachable server
/// carries. So their answer is "defer, whatever it costs" - which is
/// what `the_defer_line_says_what_the_requeue_will_cost` asserts at the
/// landing site they all share, and what their own signatures pin, since
/// neither `early_gone_defer` nor `partial_gone_defer` takes a cost at
/// all. This arm is different in kind: the job IS making progress. It is
/// merely bound to one server and slower than the session's best, so
/// deferring it trades the queue's throughput against a rerun that has
/// to extract from volumes on disk - or, for a compressed set, fetch
/// every byte it already downloaded a second time
/// ([`RequeueCost::Refetch`]; the inequality per arm is
/// [`cost_outweighs_the_wait`]'s).
///
/// **The inequality, and why it is not a magic number.** TODO 94 A
/// prices the disk route at 2.53x payload of device I/O against 1.02x
/// mapped, so a requeue's EXTRA work is about one and a half passes over
/// everything already restored. What deferring buys is that the bytes
/// still to fetch leave the critical path. So the job keeps its slot
/// while `left < 1.5 * restored` - past that crossing the extra disk
/// work is the bigger number. Both sides are measured quantities; the
/// 1.5 is TODO 94 A's own two figures subtracted.
///
/// **What stops it keeping the slot forever.** Two things, and the first
/// is the load-bearing one. The arm only reaches this test when bytes
/// ARE moving (its caller has already bailed on `total == 0`), so `left`
/// strictly shrinks every window while the veto holds, and the veto's
/// own condition therefore only ever gets easier to satisfy - the job
/// finishes. The second is the belt for the pathological case that
/// argument does not cover, a job trickling a few bytes a window: the
/// veto also requires the job to still be moving at a tenth of the
/// session best. Under that it is closer to the stalled shapes the arms
/// above own than to a working download, and the queue's claim wins. The
/// arm's own gate is 0.4 of best, so a job between 0.1 and 0.4 is the
/// band this speaks for.
///
/// Kill switch: `NZBFAST_DEFER_IGNORE_RESUME_COST=1` (read in
/// [`requeue_cost`], so it disarms the clause and the veto together).
fn slow_keeps_its_slot(d: &Daemon, id: &str, rate: f64, best: u64, st: &mut SlowCost) -> bool {
    let Some(c) = st.seen.as_ref() else {
        return false;
    };
    let Some((_, _, left)) = d.wire_counters(id) else {
        return false;
    };
    if !cost_outweighs_the_wait(c, left, rate, best) {
        return false;
    }
    if !st.noted {
        st.noted = true;
        match *c {
            RequeueCost::Disk { restored, cap } => info!(
                target: "defer",
                "{id}: slow, but {:.1} GB restored is over the {:.1} GB one-pass resume budget \
                 and only {:.1} GB is left - keeping its slot rather than paying to unpack from \
                 volumes on disk when it runs again",
                restored as f64 / 1e9,
                cap as f64 / 1e9,
                left as f64 / 1e9
            ),
            RequeueCost::Refetch { refetch } => info!(
                target: "defer",
                "{id}: slow, but a rerun would download the {:.1} GB already fetched all over \
                 again and only {:.1} GB is left - keeping its slot rather than paying for the \
                 same bytes twice",
                refetch as f64 / 1e9,
                left as f64 / 1e9
            ),
        }
    }
    true
}

/// The single-server-bound arm's per-active-job state, reset on every job
/// change: what the requeue was last measured to cost, and whether the
/// veto has already said so.
///
/// **It exists because a veto REPEATS and a demotion does not.** Every
/// other arm reads the cost once and fires; this one re-reaches its
/// verdict every window for as long as it keeps the slot, which for a
/// large slow job is hours. Re-parsing a 60 GB job's journal every 30 s
/// to be told what it said last time is exactly the kind of cost nobody
/// finds until it is a support question.
///
/// **Latching is sound because both figures only GROW.** Once the placed
/// bytes are over the held-span budget they stay over, so a `Disk` never
/// becomes a `None`; and the `restored` figure going stale can only make
/// it SMALLER than the truth, which under-vetoes rather than over-vetoes.
/// The same argument carries the `Refetch` arm: a compressed set's
/// placements never grow, the wire counter only climbs, so a stale
/// `refetch` is smaller than the truth and under-vetoes the same way.
/// A `None` is deliberately not latched - a job under the budget is
/// demoted on the spot, so there is no second tick to save, and a job
/// that has not yet crossed must be free to.
#[derive(Default)]
struct SlowCost {
    seen: Option<RequeueCost>,
    noted: bool,
}

/// The inequality [`slow_keeps_its_slot`] is built on, split out so it
/// can be driven directly, one arm per [`RequeueCost`] variant and the
/// rate belt shared:
///
/// * **Disk**: TODO 94 A's 2.53x-against-1.02x is about one and a half
///   extra passes over what is restored, against the bytes a deferral
///   would take off the critical path.
/// * **Refetch**: the rerun's extra wire work is exactly the bytes it
///   downloads a second time, so the factor is 1.0 - the job keeps its
///   slot while what is left to fetch is smaller than what a deferral
///   would make it fetch twice. Both sides are wire bytes, so unlike
///   the disk arm no cross-medium exchange rate is being asserted.
fn cost_outweighs_the_wait(cost: &RequeueCost, left: u64, rate: f64, best: u64) -> bool {
    const EXTRA_PASSES: f64 = 1.5;
    if rate < 0.10 * best as f64 {
        return false;
    }
    match *cost {
        RequeueCost::Disk { restored, .. } => (left as f64) < restored as f64 * EXTRA_PASSES,
        RequeueCost::Refetch { refetch } => left < refetch,
    }
}

/// One watchdog sample of the judged job's pool: when it was taken, the
/// per-host cumulative byte totals, and the fleet's cumulative article
/// dispatches and refusals. Named so the two readers of the rolling
/// window can be given a signature rather than a four-tuple.
type Sample = (Instant, Vec<(String, u64)>, u64, u64);

/// The newest unbroken run of watchdog samples over which not one byte
/// moved anywhere in the fleet: TODO 306's FLATLINE.
struct FlatGone {
    /// Wall seconds from the oldest sample of the stretch to the newest.
    secs: f64,
    /// Articles the fleet answered "no such article" inside it.
    misses: u64,
    /// Article dispatches it answered at all inside it.
    tried: u64,
}

/// How far back the byte total has been flat, and what the fleet was
/// doing while it was.
///
/// Read off the rolling window the watchdog already keeps, so the
/// resolution is one tick and the reach is one `window`. Every per-host
/// total is cumulative, so a fleet sum that has not moved between two
/// samples is "not a byte arrived anywhere between them" exactly.
///
/// `None` while there is no second sample to compare against, which is
/// the first tick of every job.
fn flat_gone(win: &VecDeque<Sample>) -> Option<FlatGone> {
    let bytes = |s: &Sample| -> u64 { s.1.iter().map(|(_, b)| *b).sum() };
    let last = win.back()?;
    let flat = bytes(last);
    let first = win
        .iter()
        .rev()
        .skip(1)
        .take_while(|s| bytes(s) == flat)
        .last()?;
    Some(FlatGone {
        secs: last.0.duration_since(first.0).as_secs_f64(),
        misses: last.3.saturating_sub(first.3),
        tried: last.2.saturating_sub(first.2),
    })
}

/// TODO 306's PARTIAL post-is-gone arm: the windowed twin's verdict off
/// a FLATLINE rather than off the whole rolling window.
///
/// # The case neither sibling can reach
///
/// [`early_gone_defer`] fires with no warmup because it asks for "not a
/// byte since this job started", and that is exactly what a partial
/// takedown is not: the first third of the post arrives and the rest is
/// refused, so the strongest condition the early arm has is false by
/// construction and it correctly stands down. The windowed arm in
/// [`spawn_slow_job_watchdog`] is then the only thing that can speak
/// for it, and it cannot do so inside about 69 seconds - `warmup`
/// (45 s) plus a window at least 80% full. Measured 26 Aug 2026 on
/// round A's S6 row: a partial takedown held three healthy jobs for its
/// whole run at the shipped thresholds, `set aside never`.
///
/// So what has to shorten here is the FLATLINE, and that is a different
/// risk decision from the early arm's, which is why this is a third arm
/// and not a loosened second one. The 30 s window is what tells a dead
/// patch from a job that paused five seconds on a disk hiccup with a
/// few 430s still in flight.
///
/// # What each condition rules out
///
/// 1. **A flatline of at least `flat_min`** (two watchdog ticks, so
///    10 s at the shipped thresholds). One tick is the shortest
///    interval over which "not a byte moved" is expressible at all, and
///    it is deliberately not enough: five seconds is the length of the
///    hiccup this arm has to be able to tell itself apart from. Two is
///    also one confirmation interval MORE than [`early_gone_defer`]
///    takes, which is the right way round - this arm's evidence is
///    weaker than its early twin's by exactly one condition (bytes did
///    arrive, once), so it pays for that with one more interval of
///    nothing arriving.
/// 2. **Refusals still landing inside it** (the caller's
///    `gone_min_misses` floor, unchanged at 64). This is the condition
///    that does the real work, and it is the windowed arm's own: a
///    worker that is wedged - on a peer that has stopped answering, on
///    a full downstream channel, on anything - completes no
///    transactions at all, so it contributes neither bytes NOR
///    refusals. Every refusal banked inside a flatline is a completed
///    transaction that proves the article asked for is not there. A dry
///    network tail and a stalled provider both fail this outright.
/// 3. **Nothing unprobed** ([`fleet_answered`]): every server has
///    itself answered a refusal, or is granting no connection at all
///    and is the outage arm's business. A server that is up and has
///    simply not been asked yet might be the one holding what is left.
/// 4. The windowed arm's own remaining list, unchanged: the feature on,
///    the demotion budget, a sidecar that is only borrowing, and
///    somewhere for the queue to go next.
///
/// # Measured and rejected: `ServerLive::blocked_ms`
///
/// The obvious extra guard is to stand down when the write side was
/// what stopped the bytes, and the gauge for it exists. It was read and
/// left out, in both directions: it is charged on the send that
/// COMPLETES, so it stays flat during the very wedge it would be meant
/// to catch, and brief parks are NORMAL on a fast line ("the channel is
/// meant to fill"), so a job whose channel filled once in the last ten
/// seconds would never reach a real takedown verdict. Condition 2 is
/// the discriminator that actually works, and it is the one the
/// windowed arm already rests on.
///
/// # What it does not do
///
/// It does not take the elapsed-time gate. That gate is the OUTAGE and
/// single-server-bound arms' - a job whose fleet is still dialling, or
/// whose first megabyte is slow, must not be benched for it - and TODO
/// 306 already settled that the post-is-gone verdict does not improve
/// by waiting. Do not lift it off the other two on the strength of
/// this one. And it does not reach for [`StallTracker`] to find the
/// flatline: this module's header says why action stays out of that
/// scope, and the rolling window the watchdog already keeps answers the
/// same question with no new detector in it.
fn partial_gone_defer(
    d: &Arc<Daemon>,
    live: &nzbkit::pool::LiveStats,
    win: &VecDeque<Sample>,
    gone_min_misses: u64,
    flat_min: u64,
    defer_count: u32,
) -> Option<String> {
    let f = flat_gone(win)?;
    if f.secs < flat_min as f64 || f.misses < gone_min_misses || f.tried == 0 {
        return None;
    }
    let probed = fleet_answered(live)?;
    if !d.auto_defer.load(Ordering::Relaxed)
        || defer_count >= 3
        || !d.sidecar.lock_ok().as_ref().is_none_or(|s| s.borrowed)
        || !others_waiting(d)
    {
        return None;
    }
    // Same per-server-transaction arithmetic as the early arm: the
    // count shown is the distinct-article floor, never the raw sum.
    Some(format!(
        "not a byte has arrived for {:.0}s and every article answered in that \
         time came back missing - at least {} of them, on all {probed} \
         server(s) that could be asked - no configured server carries what is \
         left of this post right now",
        f.secs,
        f.misses.div_ceil(probed as u64)
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
        // TODO 306: how long the fleet must go without a byte before
        // the PARTIAL takedown arm will speak - two watchdog ticks, so
        // 10 s at the shipped thresholds against the windowed arm's
        // 69. Why two and not one, and why the length is not the part
        // that makes it safe, is in `partial_gone_defer`.
        let gone_flat = tick * 2;
        // Rolling (time, per-host cumulative bytes) samples of the
        // ACTIVE job's pool; reset on job change. `attempted` = jobs
        // already sidecar-tried during the current active job (so a
        // job whose articles the idle servers don't hold either
        // isn't retried every tick).
        // Per sample: (taken at, per-host raw bytes, articles tried,
        // articles 430'd) - the last two summed across servers, because
        // "is this post gone" is a job-wide question, not a per-host one.
        let mut win: VecDeque<Sample> = VecDeque::new();
        let mut cur: Option<String> = None;
        let mut attempted: std::collections::HashSet<String> = Default::default();
        // Once per active job: "every idle server has refused auth".
        let mut refusal_noted = false;
        // TODO 309(d): the single-server-bound arm's cost latch. Both
        // halves are latched for the same reason - that arm's verdict is
        // re-reached every window for as long as it keeps the slot - and
        // [`SlowCost`] argues why that is sound.
        let mut slow_cost = SlowCost::default();
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
            let (id, defer_count, demote, out_dir) = {
                let g = job.lock_ok();
                (g.nzo_id.clone(), g.defer_count, g.demote, g.out_dir.clone())
            };
            if demote {
                continue; // abort already in flight
            }
            // TODO 309(d), read at a VERDICT rather than every tick: it
            // parses the journal, and the four demoting arms below reach
            // it only on a tick they are about to fire on. The fifth
            // reader is the single-server-bound arm's veto, which
            // re-reaches its verdict every window - `SlowCost` is the
            // latch that keeps that from re-parsing, and says why it is
            // sound to.
            let cost = || requeue_cost(&d, &id, &out_dir, mem_budget);
            if cur.as_deref() != Some(id.as_str()) {
                win.clear();
                attempted.clear();
                refusal_noted = false;
                slow_cost = SlowCost::default();
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
                fire_defer(&job, &reason, cost(), &w, &mut win);
                continue;
            }

            win.push_back((now, snap, tried_now, missing_now));
            while win
                .front()
                .is_some_and(|(t, ..)| now.duration_since(*t).as_secs() > window)
            {
                win.pop_front();
            }
            // ---- What is LEFT of the post is gone (TODO 306).
            // AFTER the window bookkeeping, which is where the
            // flatline is read from, and BEFORE the `span < window *
            // 0.8` bail. See [`partial_gone_defer`].
            if let Some(reason) = partial_gone_defer(
                &d,
                &w.pool_live,
                &win,
                gone_min_misses,
                gone_flat,
                defer_count,
            ) {
                fire_defer(&job, &reason, cost(), &w, &mut win);
                continue;
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
                // TODO 308: THIS job's gauges, never the hub's.
                && let Some(o) = outages_in(&w.pool_live)
                    .into_iter()
                    .find(|o| o.secs >= span as u64 && o.secs >= server_down_secs())
            {
                let reason = format!(
                    "{} has had no usable connection for {}s ({}) and nothing \
                     has arrived for {:.0}s - the articles this job still needs \
                     are only on that server",
                    o.host, o.secs, o.kind, span
                );
                fire_defer(&job, &reason, cost(), &w, &mut win);
                continue;
            }
            // ---- The post is gone: servers healthy, every answer a 430.
            //
            // The outage arm above covers a server that grants no
            // CONNECTION. This is the other shape of a zero-byte window,
            // and since TODO 306 it is the SLOWEST of the three arms
            // that reach it: `early_gone_defer` takes the same verdict
            // off the run and `partial_gone_defer` off a flatline
            // inside the window, both with no warmup. It is not
            // redundant, because both twins ask for something this one
            // does not - every server having ANSWERED a refusal itself
            // ([`fleet_answered`]). A fleet with a server that is up
            // and has simply never been asked stands both of them down
            // forever, and that fleet is this arm's territory ALONE -
            // the whole of it, which `fleet_answered`'s own doc
            // comment now argues at length after this comment claimed
            // a second shape for nine days and had none.
            // `e2e_qprog::an_unprobed_server_leaves_the_windowed_arm_to_speak`
            // drives it end to end.
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
                fire_defer(&job, &reason, cost(), &w, &mut win);
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
            slow_cost.seen = slow_cost.seen.take().or_else(&cost);
            if slow_keeps_its_slot(&d, &id, rate, best, &mut slow_cost) {
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
            fire_defer(&job, &reason, slow_cost.seen.take(), &w, &mut win);
        }
    });
}

/// TODO 309(d): the demotion watchdog now asks what the requeue it is
/// about to cause will COST, and one arm lets the answer veto it.
///
/// What each of these pins, and why the split is the way it is, is in
/// [`slow_keeps_its_slot`]'s own comment: the three zero-byte arms defer
/// whatever it costs, because a job moving nothing cannot be made
/// cheaper by keeping its slot, and the single-server-bound arm is the
/// only one where the job is still making progress.
#[cfg(test)]
mod requeue_cost_tests {
    use super::*;
    use nzbkit::extract::Frag;
    use std::sync::atomic::AtomicBool;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-defercost-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A journal holding `n` placed articles of `len` bytes each, which
    /// is what `resume_map_admitted` will weigh against the budget when
    /// this job reruns.
    fn journal_of(dir: &std::path::Path, n: usize, len: u64) {
        let (j, _) = nzbkit::journal::Journal::open(dir, b"<nzb/>").unwrap();
        for i in 0..n {
            j.record_placed(
                0,
                &format!("<a{i}@x>"),
                None,
                "vol.part01.rar",
                n as u64 * len,
                &[Frag::identity("vol.part01.rar", i as u64 * len, len)],
            );
        }
        j.flush();
    }

    /// The same total spread over `n` slots of `len` bytes EACH - the
    /// small-volume shape TODO 309(a)'s widened gate maps however large
    /// the total, where [`journal_of`]'s single wide slot never can.
    fn journal_of_slots(dir: &std::path::Path, n: usize, len: u64) {
        let (j, _) = nzbkit::journal::Journal::open(dir, b"<nzb/>").unwrap();
        for i in 0..n {
            let name = format!("vol.part{i:03}.rar");
            j.record_placed(
                i,
                &format!("<a{i}@x>"),
                None,
                &name,
                len,
                &[Frag::identity(&name, 0, len)],
            );
        }
        j.flush();
    }

    /// The judged job, spelled the way a restart spells one.
    fn job_at(out_dir: &std::path::Path) -> Arc<Mutex<Job>> {
        Arc::new(Mutex::new(
            crate::serve::job_from_json(&serde_json::json!({
                "nzo_id": "SABnzbd_nzo_nzbfast1",
                "name": "Judged",
                "nzb_path": out_dir.join("j.nzb"),
                "out_dir": out_dir,
                "state": "Downloading",
            }))
            .expect("job_from_json"),
        ))
    }

    fn watched_for(id: &str) -> Watched {
        Watched {
            id: id.into(),
            t0: Instant::now(),
            pool_live: nzbkit::pool::LiveStats::for_servers(&[]),
            abort: Some(Arc::new(AtomicBool::new(false))),
            queue_ctl: None,
            draining: false,
        }
    }

    /// PART 1, and the whole of what this change owes the person reading
    /// the queue: when the requeue will be expensive, the defer line
    /// SAYS SO - in `defer_reason`, which is the string the dashboard's
    /// queue drawer prints, not merely in a log line nobody correlates.
    ///
    /// Before this, `stall.rs` and `daemon_park.rs` between them named
    /// neither `holds_cap` nor `placement_bytes` nor `resume_map`
    /// anywhere (verified 27 Aug 2026), so a job could be demoted onto
    /// the 2.53x route with the only trace being one `info!` on the
    /// `resume` target of a rerun hours later.
    #[test]
    fn the_defer_line_says_what_the_requeue_will_cost() {
        let dir = scratch("expensive");
        // 60 MB placed against the smallest budget the process will
        // take (64 MiB, so a ~30 MB replay budget): over, and
        // unambiguously so. The FRAGMENT LENGTHS are what the gate
        // weighs, so the fixture claims 60 MB in a file of a few KB.
        journal_of(&dir, 60, 1_000_000);
        let budget = nzbkit::mem::MemBudget::with_total(nzbkit::mem::MemBudget::MIN);
        assert!(budget.holds_cap() < 60_000_000, "the fixture must be over");
        let d = crate::serve::testutil::test_daemon(&dir);
        let cost = requeue_cost(&d, "SABnzbd_nzo_nzbfast1", &dir, budget)
            .expect("60 MB placed is over a ~30 MB replay budget");
        let RequeueCost::Disk { restored, .. } = cost else {
            panic!("a single 60 MB volume cannot map under a ~30 MB budget");
        };
        assert_eq!(restored, 60_000_000);

        let job = job_at(&dir);
        let w = watched_for("SABnzbd_nzo_nzbfast1");
        let mut win: VecDeque<Sample> = VecDeque::new();
        fire_defer(
            &job,
            "the other servers had nothing for this job",
            Some(cost),
            &w,
            &mut win,
        );
        let g = job.lock_ok();
        assert!(g.demote, "the clause is a CLAUSE - it never vetoes here");
        assert!(
            g.defer_reason.contains("the other servers had nothing"),
            "the arm's own verdict survives: {}",
            g.defer_reason
        );
        assert!(
            g.defer_reason.contains("unpack from volumes on disk"),
            "and the cost is spelled out beside it: {}",
            g.defer_reason
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// PART 2, the per-arm decision, at the one site every arm lands
    /// through: an expensive requeue does NOT stop a demotion. The three
    /// zero-byte arms reach `fire_defer` unconditionally once their
    /// evidence holds - `early_gone_defer` and `partial_gone_defer` do
    /// not take a cost at all, which is the type system pinning it - so
    /// this is where "defer whatever it costs" is decided for them, and
    /// the assertion above that `demote` is set with `Some(cost)` in
    /// hand is that decision.
    ///
    /// The mirror: an ordinary job under the budget says nothing extra,
    /// so the common case is exactly the sentence it was before.
    #[test]
    fn a_requeue_inside_the_budget_adds_nothing_to_the_line() {
        let dir = scratch("cheap");
        journal_of(&dir, 4, 1_000_000);
        // 45% of this is 450 MB, comfortably over the 4 MB placed.
        let budget = nzbkit::mem::MemBudget::with_total(1_000_000_000);
        let d = crate::serve::testutil::test_daemon(&dir);
        assert!(
            requeue_cost(&d, "SABnzbd_nzo_nzbfast1", &dir, budget).is_none(),
            "under the budget, with no wire counters to price a refetch, \
             there is no cost to report"
        );

        let job = job_at(&dir);
        let w = watched_for("SABnzbd_nzo_nzbfast1");
        let mut win: VecDeque<Sample> = VecDeque::new();
        fire_defer(&job, "no bytes moved", None, &w, &mut win);
        let g = job.lock_ok();
        assert!(g.demote);
        assert_eq!(
            g.defer_reason, "no bytes moved",
            "the cheap case must read exactly as it did before this change"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A directory with no journal, and one whose file is not a journal,
    /// both answer "no cost to report" rather than inventing one - with
    /// no wire counters either (the job is not the active download),
    /// neither arm has anything to price. The second fixture is what
    /// stops a stray file in an out_dir being parsed as an empty
    /// journal - `Journal::peek` requires the v1 header.
    #[test]
    fn a_job_with_nothing_to_read_reports_no_cost() {
        let dir = scratch("bare");
        let budget = nzbkit::mem::MemBudget::with_total(nzbkit::mem::MemBudget::MIN);
        let d = crate::serve::testutil::test_daemon(&dir);
        let id = "SABnzbd_nzo_nzbfast1";
        assert!(
            requeue_cost(&d, id, &dir, budget).is_none(),
            "no journal at all"
        );
        std::fs::write(dir.join(".nzbfast.journal"), b"not a journal\nR 0 x\n").unwrap();
        assert!(
            requeue_cost(&d, id, &dir, budget).is_none(),
            "not a journal"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The inequality itself, driven directly at both sides of its
    /// crossing and at its rate floor.
    ///
    /// TODO 94 A prices the disk route at 2.53x payload of device I/O
    /// against 1.02x mapped, so the requeue's extra work is about one
    /// and a half passes over what is restored - and the job keeps its
    /// slot exactly while what is LEFT is smaller than that.
    #[test]
    fn the_crossing_is_one_and_a_half_passes_over_what_is_restored() {
        let cost = RequeueCost::Disk {
            restored: 2_000_000_000,
            cap: 1_000_000_000,
        };
        let (rate, best) = (40e6, 100_000_000u64);
        // 2.9 GB left against 3.0 GB of extra disk work: keep the slot.
        assert!(cost_outweighs_the_wait(&cost, 2_900_000_000, rate, best));
        // 3.1 GB left: past the crossing, the wait is the bigger number.
        assert!(!cost_outweighs_the_wait(&cost, 3_100_000_000, rate, best));
        // And the belt: a job trickling under a tenth of the session
        // best is closer to the stalled shapes the other arms own than
        // to a working download, so it is deferred however much is
        // already on disk.
        assert!(!cost_outweighs_the_wait(&cost, 1_000_000_000, 9e6, best));
        assert!(cost_outweighs_the_wait(&cost, 1_000_000_000, 11e6, best));
    }

    /// The veto is armed by the COST and by nothing else: with the
    /// requeue on the cheap route there is nothing to weigh, so the
    /// single-server-bound arm demotes exactly as it always has.
    ///
    /// Deliberately not tested here: the `NZBFAST_DEFER_IGNORE_RESUME_COST`
    /// kill switch. Reading it would mean setting a process-global
    /// environment variable in a suite that shares one process with
    /// ~1,750 other tests - the hazard `nzbkit::mem`'s own
    /// `holds_cap_override_parses_decimal_sizes` declines for the same
    /// reason.
    #[test]
    fn nothing_to_weigh_means_nothing_to_veto() {
        let dir = scratch("noveto");
        let d = crate::serve::testutil::test_daemon(&dir);
        let mut st = SlowCost::default();
        assert!(
            !slow_keeps_its_slot(&d, "SABnzbd_nzo_nzbfast1", 40e6, 100_000_000, &mut st),
            "an affordable requeue never keeps a slow job's slot"
        );
        assert!(!st.noted, "and says nothing about it");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The veto end to end, on a job the arm would otherwise have sent
    /// to the back of the queue: 2 GB restored over a 1 GB budget with
    /// 2 GB left is inside one and a half passes, so the job keeps its
    /// slot - and says so exactly ONCE however many windows the verdict
    /// is re-reached over. That latch is not tidiness: without it a
    /// large slow job prints the same line every 30 s for hours.
    ///
    /// Then the crossing, driven through the same door: with 4 GB still
    /// to fetch the wait is the bigger number and the arm demotes as it
    /// always has.
    #[test]
    fn the_veto_keeps_the_slot_once_and_lets_go_at_the_crossing() {
        let dir = scratch("veto");
        let d = crate::serve::testutil::test_daemon(&dir);
        let id = "SABnzbd_nzo_nzbfast1";
        *d.active_dl.lock_ok() = Some(id.into());
        let f = d.hub.fetch_counters();
        f.plan.store(10_000_000_000, Ordering::Relaxed);
        f.done.store(8_000_000_000, Ordering::Relaxed);

        let mut st = SlowCost {
            seen: Some(RequeueCost::Disk {
                restored: 2_000_000_000,
                cap: 1_000_000_000,
            }),
            noted: false,
        };
        assert!(
            slow_keeps_its_slot(&d, id, 40e6, 100_000_000, &mut st),
            "2 GB left is inside 1.5 passes over 2 GB restored"
        );
        assert!(st.noted, "and it said so");
        assert!(
            slow_keeps_its_slot(&d, id, 40e6, 100_000_000, &mut st),
            "the verdict is re-reached every window for as long as it holds"
        );

        // 4 GB left: past the crossing, so the slot is not kept and the
        // demotion the arm was about to land goes ahead.
        f.done.store(6_000_000_000, Ordering::Relaxed);
        assert!(!slow_keeps_its_slot(&d, id, 40e6, 100_000_000, &mut st));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The disk arm is held to the rule the rerun applies, not to a copy
    /// of its old self: the same 60 MB total that is a `Disk` cost as a
    /// single volume is NO cost spread over sixty 1 MB volumes, because
    /// TODO 309(a)'s volume arm maps that rerun in-stream at ~1.02x.
    /// Before this, the drawer warned about a 2.53x route the rerun was
    /// never going to take, and `slow_keeps_its_slot` vetoed demotions
    /// on the strength of a cost that would never be paid.
    #[test]
    fn a_set_the_rerun_will_map_is_not_priced_as_a_disk_cost() {
        let dir = scratch("mapped");
        journal_of_slots(&dir, 60, 1_000_000);
        let budget = nzbkit::mem::MemBudget::with_total(nzbkit::mem::MemBudget::MIN);
        assert!(budget.holds_cap() < 60_000_000, "the total must be over");
        assert!(
            2_000_000 < budget.holds_cap() as u64,
            "and the widest volume must fit the margin"
        );
        let d = crate::serve::testutil::test_daemon(&dir);
        assert!(
            requeue_cost(&d, "SABnzbd_nzo_nzbfast1", &dir, budget).is_none(),
            "a rerun that maps in-stream has no disk cost to report"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// TODO 309(b)'s warning half, end to end: the compressed shape is a
    /// journal shielding nothing while the wire counters have moved
    /// gigabytes, its price is the refetch, the defer line says so, and
    /// the same figure vetoes the single-server-bound demotion while
    /// what is left is the smaller number.
    #[test]
    fn a_compressed_set_prices_the_refetch_and_the_line_says_so() {
        let dir = scratch("refetch");
        // The measured shape (RESUME-ONEPASS-EDGES section 7.5): the
        // journal exists and holds no placements - a compressed set's
        // output bytes are decoded bytes, so nothing is ever placed.
        let (j, _) = nzbkit::journal::Journal::open(&dir, b"<nzb/>").unwrap();
        j.flush();
        drop(j);
        let budget = nzbkit::mem::MemBudget::with_total(nzbkit::mem::MemBudget::MIN);
        let d = crate::serve::testutil::test_daemon(&dir);
        let id = "SABnzbd_nzo_nzbfast1";
        *d.active_dl.lock_ok() = Some(id.into());
        let f = d.hub.fetch_counters();
        f.plan.store(10_000_000_000, Ordering::Relaxed);
        f.done.store(8_000_000_000, Ordering::Relaxed);

        let cost = requeue_cost(&d, id, &dir, budget)
            .expect("8 GB fetched with nothing shielded is a refetch cost");
        let RequeueCost::Refetch { refetch } = cost else {
            panic!("an empty journal cannot be a disk cost");
        };
        assert_eq!(refetch, 8_000_000_000);

        let job = job_at(&dir);
        let w = watched_for(id);
        let mut win: VecDeque<Sample> = VecDeque::new();
        fire_defer(&job, "no usable connection", Some(cost), &w, &mut win);
        let g = job.lock_ok();
        assert!(
            g.defer_reason
                .contains("download those bytes a second time"),
            "the drawer says what the rerun refetches: {}",
            g.defer_reason
        );
        drop(g);

        // The veto, on the latched figure: 2 GB left against 8 GB
        // fetched twice keeps the slot (and says so once); with the
        // refetch the smaller number the demotion goes ahead.
        let mut st = SlowCost {
            seen: Some(RequeueCost::Refetch {
                refetch: 8_000_000_000,
            }),
            noted: false,
        };
        assert!(
            slow_keeps_its_slot(&d, id, 40e6, 100_000_000, &mut st),
            "2 GB left is smaller than the 8 GB a rerun would fetch again"
        );
        assert!(st.noted);
        f.done.store(1_000_000_000, Ordering::Relaxed);
        assert!(
            !slow_keeps_its_slot(&d, id, 40e6, 100_000_000, &mut st),
            "9 GB left outweighs the 8 GB refetch - the wait is the bigger number"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The two guards on the bandwidth arm, each driven at the shape it
    /// exists for. A store set's placements legitimately trail the wire
    /// (held spans, in-flight, par2-main), so a 400 MB shield against
    /// 2.5 GB moved is bookkeeping lag and not a compressed set - the
    /// ratio guard holds even though the raw gap tops the floor. And a
    /// genuinely unshielded set under the floor is seconds of wire time,
    /// not worth alarming over.
    #[test]
    fn the_refetch_arm_reads_lag_and_small_change_as_no_cost() {
        let dir = scratch("guards");
        journal_of(&dir, 400, 1_000_000);
        let budget = nzbkit::mem::MemBudget::with_total(1_000_000_000);
        assert!(400_000_000 < budget.holds_cap() as u64, "under the cap");
        let d = crate::serve::testutil::test_daemon(&dir);
        let id = "SABnzbd_nzo_nzbfast1";
        *d.active_dl.lock_ok() = Some(id.into());
        let f = d.hub.fetch_counters();
        f.plan.store(4_000_000_000, Ordering::Relaxed);
        f.done.store(2_500_000_000, Ordering::Relaxed);
        assert!(
            requeue_cost(&d, id, &dir, budget).is_none(),
            "400 MB shielded of 2.5 GB moved is lag, not a compressed set"
        );

        // Nothing shielded at all, but only 900 MB moved: under the
        // floor, so still nothing worth a line.
        let bare = scratch("floor");
        let d2 = crate::serve::testutil::test_daemon(&bare);
        *d2.active_dl.lock_ok() = Some(id.into());
        let f2 = d2.hub.fetch_counters();
        f2.plan.store(2_000_000_000, Ordering::Relaxed);
        f2.done.store(900_000_000, Ordering::Relaxed);
        assert!(
            requeue_cost(&d2, id, &bare, budget).is_none(),
            "a refetch under the floor is not worth alarming over"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&bare);
    }
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

    /// A live two-connection fleet against a mock whose bodies take
    /// `delay_ms`, with its pipelines already full: 60_000 is the fleet
    /// a drain cannot finish (the wedged rows of the table on
    /// `DEFER_DRAIN_GRACE`), a small number is one that winds down well
    /// inside any grace. Hands back the run's own `QueueControl` - the
    /// handle a verdict's teeth go through - and the task to join.
    async fn fleet_rig(delay_ms: u64) -> (Arc<QueueControl>, tokio::task::JoinHandle<()>) {
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
        // Phase 1: the server has stopped answering. The drain cannot
        // finish, so the grace is what ends the run.
        let (ctl, run) = fleet_rig(60_000).await;
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
        let (ctl, run) = fleet_rig(30).await;
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

    /// The bound against a drain THE VERDICT DID NOT START, which until
    /// 27 Aug 2026 was no bound at all (v1.2.4 sweep, finding R4).
    ///
    /// `stop_within` early-returned on `is_draining()`, so a defer
    /// landing on a run the user had already paused gracefully did
    /// nothing whatsoever: the drain was set, so the verb was a no-op;
    /// the escalation was skipped, so no grace was armed; and the engine
    /// flag belongs to the escalation, so it was never set either. The
    /// wedge was then bounded only by the pre-byte read ladder - the
    /// 9.6 s wedged rows of the table on `DEFER_DRAIN_GRACE`, which is
    /// the measurement that constant exists to replace.
    ///
    /// The pause is spelled as `QueueControl::drain`, because that IS
    /// the user's pause: `Daemon::fire_pause(false)` is exactly this
    /// call on exactly this handle, and it arms nothing behind it.
    ///
    /// The FLAG is the assertion and the join is only hygiene. Under the
    /// old code the flag could never be set, on any box at any load, so
    /// this kills the mutation deterministically rather than by racing a
    /// wedged fleet's ladder against a timeout.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_defer_bounds_a_wedge_the_users_own_pause_left_draining() {
        let (ctl, run) = fleet_rig(60_000).await;
        // The user's graceful pause, ahead of the verdict.
        assert!(ctl.drain(), "the pause must reach a live run");
        assert!(ctl.is_draining(), "and leave it draining, with no bound");

        let flag = Arc::new(AtomicBool::new(false));
        watched_over(Some(flag.clone()), Some(ctl.clone())).stop_within(Duration::from_millis(300));
        // Comfortably past the grace, and a small fraction of the
        // ladder the old code left this wedge to.
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(
            flag.load(Ordering::Relaxed),
            "a defer against a fleet that has stopped answering must be \
             bounded by DEFER_DRAIN_GRACE whoever started the drain - a \
             verdict that finds the run already draining still owes the \
             escalation, because the user's pause armed none"
        );
        tokio::time::timeout(Duration::from_secs(30), run)
            .await
            .expect("the escalation must take the line back")
            .expect("the run task");
    }
}

#[cfg(test)]
#[path = "stall_gone_tests.rs"]
mod stall_gone_tests;
