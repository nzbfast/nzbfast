//! §129 3e (§108 decision 4): the CHRONIC slow-storage pause.
//!
//! The acute sibling is done: a write that fails outright (ENOSPC, a
//! read-only share) halts the job fast with "out of disk space", journal
//! kept, Retry resumes (c069ab3e). This module is the other half - the
//! writes SUCCEED, but they block for pathological spans. A USB
//! enclosure going bad, an SMB share whose server is thrashing, a
//! spun-down NAS disk: the fleet sawtooths, the throughput graph looks
//! like a bad provider, and the user blames the network.
//!
//! The rule this module implements: PAUSE with a reason, never fail.
//! So the action here is the ordinary pause path - the job parks back in
//! the queue with its journal intact, exactly as if a person had hit
//! Pause - attributed to `"storage"` so the header and the row say why,
//! and auto-resumed when the volume recovers.
//!
//! # Why this is built the way it is
//!
//! The cautionary tale is the stall watchdog, which once aborted a
//! perfectly HEALTHY run off a misread rate window (memory
//! `nzbfast-stall-watchdog-decode-only`). A detector that acts on the
//! user's download has to earn it, so the evidence here is deliberately
//! slow and doubly-sourced:
//!
//! 1. **Windowed, never a spike.** The judge accumulates over MINUTES
//!    from telemetry the pipeline already keeps (`ServerLive::blocked_ms`
//!    - worker time parked because the fetch->decode channel was full,
//!    i.e. waiting on everything downstream of the network). A single
//!    park, or a busy disk absorbing a burst, cannot trip it: the trip
//!    needs stalled samples covering most of a whole window.
//! 2. **Blocked AND starved.** A fast, healthy download parks its
//!    workers constantly - the channel is MEANT to fill when the network
//!    outruns decode. So high blocked time on its own is not evidence;
//!    it only counts while goodput has also collapsed against the best
//!    rate this run has actually shown.
//! 3. **Only while there is something to write.** Ticks with no bytes
//!    and no parking are network-idle, not storage-slow; they are not
//!    stalled evidence, and because the trip is measured against the
//!    whole window rather than against the active part of it, idle time
//!    dilutes the evidence instead of concentrating it.
//! 4. **Confirmed by a probe before acting.** `blocked_ms` cannot tell
//!    a slow disk from a wedged decoder - it is one counter over
//!    everything downstream of the socket. So the window's verdict is
//!    only a nomination: before the pause fires, a real write+fsync goes
//!    to the affected volume and has to come back SLOW. That is the same
//!    probe the resume side uses, so trip and recovery are judged by the
//!    same instrument.
//!
//! The probe is the only new I/O in the design, and it is deliberately
//! not the trip detector: nothing here polls a volume on a healthy
//! daemon. It runs at the trip edge and then once per probe interval for
//! as long as the pause holds.
//!
//! # What this must never disturb
//!
//! A storage pause is a PAUSE. It never files a failure, so the give-up
//! breaker (§96.3) and the auto-retry ladder never see it - both are fed
//! from final failures on the history path, and a suspended job returns
//! to the queue without going near it. §100 resume semantics are
//! likewise untouched: this uses the same wind-down the user's own pause
//! uses, so the article journal is preserved by construction and the
//! resume refetches exactly what a manual pause/resume would.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use serde_json::{Value, json};
use tracing::{info, warn};

use super::daemon::Daemon;
use crate::tools::MutexExt;

/// How often the watcher samples the pool. Fine enough that a burst is
/// several samples wide (so "self-clears in seconds" is visible as
/// such), coarse enough to be free.
const TICK: Duration = Duration::from_secs(2);

/// Everything the judge and the probe are tuned by. settings.json only,
/// under `slow_storage` - the ON/OFF switch (`slow_storage_pause`) is
/// the one knob in the UI, per the §129 rule that a setting is three
/// places and these numbers are not ones a person should be choosing.
#[derive(Debug, Clone, PartialEq)]
pub struct Tune {
    /// Y: the evidence window. Minutes, because "chronic" is the whole
    /// point - the acute case is already handled elsewhere.
    pub window_secs: u64,
    /// X: a tick counts as stalled only if at least this fraction of
    /// live worker time went into write-side parking.
    pub blocked_pct: f64,
    /// Z: ...and only if goodput also fell to this fraction or less of
    /// the best rate seen recently (see `norm_secs`).
    pub goodput_pct: f64,
    /// How much of the window has to be stalled before the judge
    /// nominates a pause. Measured against the WHOLE window, so idle
    /// stretches count against the evidence rather than being skipped.
    pub trip_pct: f64,
    /// Floor on evidence quantity: a window that somehow holds only a
    /// couple of samples is not minutes of anything.
    pub min_samples: usize,
    /// How far back the "best recent rate" reference looks. Longer than
    /// the window, so a stall that lasts longer than the window is still
    /// compared against the healthy rate that preceded it.
    pub norm_secs: u64,
    /// Probe payload. Big enough that a dying enclosure cannot absorb it
    /// into a cache and answer instantly, small enough to be nothing on
    /// a healthy volume.
    pub probe_bytes: u64,
    /// A probe write+fsync at or over this is SLOW - it confirms a
    /// nomination, and while paused it is not a healthy probe.
    pub probe_slow_ms: u64,
    /// Probe cadence while the pause holds.
    pub probe_secs: u64,
    /// Probe cadence while merely ANSWERING THE DIAGNOSTIC (§108 option
    /// 2): the queue is running and nothing has tripped, so this is
    /// deliberately slower than `probe_secs` - four times slower at the
    /// defaults. It only runs at all while the whyslow core is stuck at
    /// its disk-vs-client fork, which needs an established shortfall
    /// AND heavy write-side parking, so a healthy daemon never reaches
    /// it. See `DIAG_SLOW_RUNS`.
    pub diag_secs: u64,
    /// N: consecutive healthy probes before the queue resumes. The
    /// hysteresis - one good answer from a flapping enclosure is not
    /// recovery.
    pub probe_healthy: u32,
}

impl Default for Tune {
    fn default() -> Self {
        Tune {
            window_secs: 180,
            blocked_pct: 0.60,
            goodput_pct: 0.20,
            trip_pct: 0.75,
            min_samples: 20,
            norm_secs: 900,
            probe_bytes: 4 << 20,
            probe_slow_ms: 1_500,
            probe_secs: 15,
            diag_secs: 60,
            probe_healthy: 3,
        }
    }
}

/// Consecutive SLOW diagnostic probes before the whyslow verdict is
/// allowed to name the disk.
///
/// One is not enough, for the same reason one clean probe is not a
/// recovery: this verdict is shown to a user as a fact about their
/// hardware, and the cheapest way to be wrong about it is to believe a
/// single sample. Two at the default cadence means about two minutes of
/// a genuinely struggling volume - still days earlier than the breaker,
/// which needs three quarters of a three-minute window.
const DIAG_SLOW_RUNS: u32 = 2;

impl Tune {
    /// Read the `slow_storage` object out of settings.json. Every field
    /// is optional and every one is clamped: this is a hand-edited file,
    /// and a typo must not be able to turn the detector into a hair
    /// trigger (or into a no-op that silently never fires).
    pub fn from_settings(v: &Value) -> Tune {
        let mut t = Tune::default();
        let num = |k: &str| v.get(k).and_then(Value::as_f64);
        if let Some(n) = num("window_secs") {
            t.window_secs = (n as u64).clamp(30, 3600);
        }
        if let Some(n) = num("blocked_pct") {
            t.blocked_pct = n.clamp(0.1, 1.0);
        }
        if let Some(n) = num("goodput_pct") {
            t.goodput_pct = n.clamp(0.0, 0.9);
        }
        if let Some(n) = num("trip_pct") {
            t.trip_pct = n.clamp(0.25, 1.0);
        }
        if let Some(n) = num("min_samples") {
            t.min_samples = (n as usize).clamp(2, 10_000);
        }
        if let Some(n) = num("norm_secs") {
            t.norm_secs = (n as u64).clamp(t.window_secs, 24 * 3600);
        }
        if let Some(n) = num("probe_bytes") {
            t.probe_bytes = (n as u64).clamp(4 << 10, 256 << 20);
        }
        if let Some(n) = num("probe_slow_ms") {
            t.probe_slow_ms = (n as u64).clamp(50, 600_000);
        }
        if let Some(n) = num("probe_secs") {
            t.probe_secs = (n as u64).clamp(1, 3600);
        }
        if let Some(n) = num("diag_secs") {
            // Never faster than the paused cadence: the diagnostic runs
            // while the queue is still working, so it must be the
            // lighter of the two, not the heavier.
            t.diag_secs = (n as u64).clamp(t.probe_secs, 24 * 3600);
        }
        if let Some(n) = num("probe_healthy") {
            t.probe_healthy = (n as u32).clamp(1, 100);
        }
        // norm_secs shorter than the window would compare a stall
        // against itself. Enforced after both are read so field order in
        // the file does not change the meaning.
        t.norm_secs = t.norm_secs.max(t.window_secs);
        t
    }
}

/// One stats tick, as the watcher reads it off the live pool. Deltas,
/// not totals - the judge never sees a cumulative counter, so it cannot
/// be confused by a new job resetting one.
#[derive(Debug, Clone, Copy)]
pub struct Sample {
    /// Monotonic-ish milliseconds (the daemon's `now_ms`). Only
    /// differences are used.
    pub at_ms: u64,
    /// Wall milliseconds this tick covers.
    pub span_ms: u64,
    /// Worker-milliseconds AVAILABLE in the tick: `span_ms` times the
    /// number of live connections. The denominator that turns a sum
    /// over workers into a fraction of the fleet.
    pub worker_ms: u64,
    /// Worker-milliseconds spent parked on the write side in the tick.
    pub blocked_ms: u64,
    /// Payload bytes that arrived in the tick.
    pub bytes: u64,
}

/// What the judge saw, in the words the UI and the log use.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Evidence {
    /// Seconds of the window that were stalled.
    pub stalled_secs: f64,
    /// Seconds the window covers.
    pub window_secs: f64,
    /// Goodput over the stalled part, bytes/s.
    pub goodput_bps: f64,
    /// The reference it collapsed against, bytes/s.
    pub norm_bps: f64,
}

impl Evidence {
    /// The sentence the drawer, the log and the notification all use.
    /// Deliberately numeric: "output storage is not keeping up" is the
    /// claim, and this is what makes it checkable.
    pub(crate) fn sentence(&self, path: &Path) -> String {
        format!(
            "write stalls: {:.0} s of {:.0} s over the last {:.0} min on {}",
            self.stalled_secs,
            self.window_secs,
            (self.window_secs / 60.0).max(1.0),
            path.display()
        )
    }
}

/// One retained tick.
#[derive(Debug, Clone, Copy)]
struct Obs {
    at_ms: u64,
    span_ms: u64,
    rate: f64,
    stalled: bool,
}

/// The windowed judge. Pure: it owns no clock, no filesystem and no
/// daemon - it is fed samples and answers. Everything that decides
/// whether a real download pauses is in here, which is what makes the
/// no-false-positive cases testable at all.
#[derive(Debug)]
pub(crate) struct Judge {
    tune: Tune,
    hist: VecDeque<Obs>,
    /// Ticks at or before this instant do not count toward a trip. Moved
    /// forward by [`Judge::rearm`], which is how "a re-trip needs a whole
    /// fresh window" is enforced without flushing the history.
    ///
    /// The history behind the floor is deliberately KEPT, because it
    /// holds the goodput reference. Dropping it was a real hole: a
    /// nomination that the probe declined would take the healthy rate
    /// with it, and a volume that then genuinely died would have nothing
    /// but its own stalled rate to compare against - so it could never
    /// nominate again. Evidence resets; the reference ages out on its
    /// own clock (`norm_secs`).
    floor_ms: u64,
    /// Latched after a nomination so one bad stretch nominates once.
    latched: bool,
}

impl Judge {
    pub fn new(tune: Tune) -> Judge {
        Judge {
            tune,
            hist: VecDeque::new(),
            floor_ms: 0,
            latched: false,
        }
    }

    /// Discard the accumulated EVIDENCE (not the goodput reference) and
    /// un-latch. Called when the pause is released, when the pool
    /// changes identity (a new job's counters are not comparable across
    /// the boundary), and whenever a nomination is not confirmed by the
    /// probe - in every one of those cases the next verdict has to be
    /// built from a full fresh window.
    pub fn rearm(&mut self, at_ms: u64) {
        self.floor_ms = at_ms;
        self.latched = false;
    }

    /// The best per-tick rate seen inside the reference window. Taken
    /// over ALL retained ticks, including stalled ones: comparing a
    /// stall only against other stalls is how a detector convinces
    /// itself that a slow line is a slow disk.
    pub fn norm_bps(&self) -> f64 {
        self.hist.iter().map(|o| o.rate).fold(0.0, f64::max)
    }

    /// Feed one tick. `Some(evidence)` means the window says this volume
    /// is chronically stalled - a NOMINATION, not a decision: the caller
    /// confirms with a real probe before anything pauses.
    pub fn observe(&mut self, s: Sample) -> Option<Evidence> {
        if s.span_ms == 0 {
            return None;
        }
        self.hist
            .retain(|o| s.at_ms.saturating_sub(o.at_ms) <= self.tune.norm_secs * 1000);
        // Nothing to write and nothing parked: the pipeline is idle or
        // between jobs. Not evidence either way, and deliberately not
        // retained - but note that the trip below measures stalled time
        // against the WHOLE window, so the gap this leaves still counts
        // against a nomination.
        if s.worker_ms == 0 || (s.bytes == 0 && s.blocked_ms == 0) {
            return None;
        }
        let rate = s.bytes as f64 / (s.span_ms as f64 / 1000.0);
        let blocked_frac = (s.blocked_ms as f64 / s.worker_ms as f64).min(1.0);
        // The reference includes this tick, so the fastest tick in the
        // window can never be "starved" against itself.
        let norm = self.norm_bps().max(rate);
        let starved = rate <= self.tune.goodput_pct * norm;
        let stalled = blocked_frac >= self.tune.blocked_pct && starved;
        self.hist.push_back(Obs {
            at_ms: s.at_ms,
            span_ms: s.span_ms,
            rate,
            stalled,
        });
        if self.latched {
            return None;
        }
        let window_ms = self.tune.window_secs * 1000;
        let start = s.at_ms.saturating_sub(window_ms);
        let in_window = || self.hist.iter().filter(move |o| o.at_ms > start);
        // A window we have not been watching for long enough is not a
        // window - whichever came later, the first retained tick or the
        // last rearm. If the pipeline only started a minute ago there is
        // no three-minute verdict to give, whatever that minute looked
        // like; and the same holds a minute after a stand-down.
        let oldest = self
            .hist
            .front()
            .map(|o| o.at_ms)
            .unwrap_or(s.at_ms)
            .max(self.floor_ms);
        if s.at_ms.saturating_sub(oldest) < window_ms {
            return None;
        }
        if in_window().count() < self.tune.min_samples {
            return None;
        }
        let stalled_ms: u64 = in_window().filter(|o| o.stalled).map(|o| o.span_ms).sum();
        if (stalled_ms as f64) < self.tune.trip_pct * window_ms as f64 {
            return None;
        }
        self.latched = true;
        let stalled_rate = {
            let (sum, n) = in_window()
                .filter(|o| o.stalled)
                .fold((0.0, 0u32), |(a, n), o| (a + o.rate, n + 1));
            if n == 0 { 0.0 } else { sum / n as f64 }
        };
        Some(Evidence {
            stalled_secs: stalled_ms as f64 / 1000.0,
            window_secs: self.tune.window_secs as f64,
            goodput_bps: stalled_rate,
            norm_bps: self.norm_bps(),
        })
    }
}

/// What one write+fsync of the probe payload did.
#[derive(Debug, Clone, PartialEq)]
pub enum Probe {
    /// Completed inside `probe_slow_ms`.
    Fast(u64),
    /// Completed, but took at least `probe_slow_ms`.
    Slow(u64),
    /// The write itself failed. NOT slowness: a volume that errors is
    /// the ACUTE case, and it belongs to the fast-halt path (out of
    /// disk space / read-only share), which produces a verdict a person
    /// can act on. Here it means "do not claim to know", so it neither
    /// confirms a nomination nor counts as recovery.
    Failed(String),
}

impl Probe {
    pub fn ms(&self) -> u64 {
        match self {
            Probe::Fast(ms) | Probe::Slow(ms) => *ms,
            Probe::Failed(_) => 0,
        }
    }
}

/// Write `bytes` to a probe file on the volume holding `dir`, fsync it,
/// delete it, and report how long the write+fsync took.
///
/// Blocking by design - it is the measurement. The caller runs it on the
/// blocking pool and keeps ONE outstanding probe rather than stacking a
/// new thread per tick, because a wedged volume is exactly the case
/// where this call does not return promptly (the same discipline the
/// min-free guard's `statfs` probe already uses).
///
/// The directory may not exist yet (a per-category folder made at job
/// time, a share that is not mounted); we walk up to the nearest
/// existing ancestor, which is the same filesystem the writes will land
/// on - and the same walk `free_bytes` does for the min-free guard.
pub(crate) fn probe_write(dir: &Path, bytes: u64, slow_ms: u64) -> Probe {
    use std::io::Write;
    let Some(base) = nearest_existing(dir) else {
        return Probe::Failed(format!("{} has no existing ancestor", dir.display()));
    };
    // Unique per probe, not just per process. The caller abandons a
    // probe that overruns its budget rather than waiting forever on a
    // wedged volume, so the write from a previous attempt can still be
    // in flight on its own thread when the next one starts - and two
    // threads writing one path would measure each other.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let path = base.join(format!(
        ".nzbfast-storage-probe-{}-{seq}",
        std::process::id()
    ));
    let payload = probe_payload(bytes as usize, seq);
    let t0 = std::time::Instant::now();
    let res = (|| -> std::io::Result<()> {
        let mut f = std::fs::File::create(&path)?;
        f.write_all(&payload)?;
        // The fsync is the point: a buffered write to a dying enclosure
        // returns instantly and tells us nothing.
        f.sync_all()
    })();
    let ms = t0.elapsed().as_millis() as u64;
    // Always try to clean up, including after a failure - a partial
    // probe file left in the user's output folder would be its own bug.
    let _ = std::fs::remove_file(&path);
    match res {
        Err(e) => Probe::Failed(e.to_string()),
        Ok(()) if ms >= slow_ms => Probe::Slow(ms),
        Ok(()) => Probe::Fast(ms),
    }
}

/// The probe's payload. NOT zeroes, and that is the whole point of it
/// being a function: a block of zeroes is exactly what a compressing or
/// deduping filesystem - ZFS with lz4, btrfs, an SMB share in front of
/// either - turns into a hole, so a zero-filled probe would come back
/// instantly on the very NAS setups this feature exists for and the
/// pause could never fire. A xorshift stream costs nothing to generate,
/// does not compress, and differs per probe so nothing can dedupe the
/// second write against the first.
fn probe_payload(bytes: usize, seq: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(bytes + 8);
    let mut x = 0x2545_F491_4F6C_DD1Du64 ^ seq.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    while v.len() < bytes {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.extend_from_slice(&x.to_le_bytes());
    }
    v.truncate(bytes);
    v
}

fn nearest_existing(dir: &Path) -> Option<PathBuf> {
    let mut p = dir;
    loop {
        if p.is_dir() {
            return Some(p.to_path_buf());
        }
        p = match p.parent() {
            Some(q) if q.as_os_str().is_empty() => return Some(PathBuf::from(".")),
            Some(q) => q,
            None => return None,
        };
    }
}

/// The live state of a storage pause, for the queue payload and the
/// resume side. `None` on the daemon whenever no storage pause holds.
#[derive(Debug, Clone)]
pub struct Held {
    /// The volume the evidence is about (the job's output directory, or
    /// the daemon's output root when no job was running).
    pub path: PathBuf,
    /// [`Evidence::sentence`] - what the log said, and the tooltip of
    /// last resort. The dashboard composes its OWN sentence from the
    /// two numbers below, because this one is built here in English
    /// and a formatted sentence cannot be translated at the display
    /// edge the way a bare status word can.
    pub evidence: String,
    /// The same measurement as numbers, for the localised sentence:
    /// seconds of the window that were stalled, out of the seconds the
    /// window covers.
    pub stalled_secs: f64,
    pub window_secs: f64,
    /// The job that was downloading when the pause fired, so the queue
    /// row that gets the sub-line is the one this happened to.
    pub nzo_id: Option<String>,
    pub since_unix: i64,
    /// Milliseconds the confirming probe took, and the last probe since.
    pub probe_ms: u64,
    /// Consecutive healthy probes so far, against `Tune::probe_healthy`.
    pub healthy: u32,
}

/// Everything this feature owns, as ONE field on the Daemon (the
/// `link_peak` shape). Not three: the Daemon literal is spelled out in
/// `serve()` and in the test fixture, both of which are size-gated, and
/// a feature whose state is cohesive should cost one line there rather
/// than one per member.
pub struct Governor {
    /// The switch (settings `slow_storage_pause`). Atomic because
    /// `apply_setting` writes it from an API thread while the watcher
    /// reads it every tick.
    pub on: std::sync::atomic::AtomicBool,
    /// Thresholds (settings.json `slow_storage`), read at startup.
    /// Behind a lock rather than atomics because the judge takes them
    /// as one coherent set.
    pub tune: std::sync::Mutex<Tune>,
    /// The pause now in force, or None. Written only by the watcher,
    /// and only while `pause_source` is "storage" - a user pause landing
    /// on top takes ownership and this clears.
    pub held: std::sync::Mutex<Option<Held>>,
    /// §108 option 2: the whyslow core is at its disk-vs-client fork
    /// and wants the volume tested. Set by the whyslow tick, read by
    /// the watcher - an atomic because they are different threads at
    /// different cadences and neither should wait on the other.
    pub want_diag: std::sync::atomic::AtomicBool,
    /// What the diagnostic probes have said so far.
    pub diag: std::sync::Mutex<Diag>,
}

/// The diagnostic latch: what the pre-pause probes have found, and when.
///
/// Kept apart from `held` on purpose. `held` is an ACTION in force;
/// this is only an opinion offered to the "why is this slow?" panel,
/// and it must never be mistaken for one - nothing here pauses
/// anything, and the breaker's own evidence is untouched by it.
#[derive(Debug, Default, Clone)]
pub struct Diag {
    /// Consecutive slow probes, against [`DIAG_SLOW_RUNS`].
    slow_runs: u32,
    /// Milliseconds the last diagnostic probe took.
    last_ms: u64,
    /// When that probe answered. A verdict about hardware goes stale:
    /// once the fork stops being reached the probes stop, and an
    /// opinion nobody is refreshing must not keep condemning a volume.
    at_ms: u64,
}

impl Default for Governor {
    fn default() -> Self {
        Governor {
            on: std::sync::atomic::AtomicBool::new(super::SLOW_STORAGE_PAUSE_DEFAULT),
            tune: std::sync::Mutex::new(Tune::default()),
            held: std::sync::Mutex::new(None),
            want_diag: std::sync::atomic::AtomicBool::new(false),
            diag: std::sync::Mutex::new(Diag::default()),
        }
    }
}

impl Governor {
    pub(crate) fn enabled(&self) -> bool {
        self.on.load(Ordering::Relaxed)
    }

    pub(crate) fn set_enabled(&self, on: bool) {
        self.on.store(on, Ordering::Relaxed);
    }

    pub(crate) fn tune(&self) -> Tune {
        self.tune.lock_ok().clone()
    }

    pub(crate) fn set_tune(&self, t: Tune) {
        *self.tune.lock_ok() = t;
    }

    pub(crate) fn paused(&self) -> bool {
        self.held.lock_ok().is_some()
    }

    /// The whyslow core, telling us whether it is stuck at the fork.
    pub(crate) fn set_want_diag(&self, want: bool) {
        // Asking the question again after it lapsed must not inherit an
        // old answer: the probes stopped because the fork stopped being
        // reached, and whatever the volume was doing then is not
        // evidence about now.
        if want && !self.want_diag.swap(true, Ordering::Relaxed) {
            *self.diag.lock_ok() = Diag::default();
        } else if !want {
            self.want_diag.store(false, Ordering::Relaxed);
        }
    }

    fn wants_diag(&self) -> bool {
        self.want_diag.load(Ordering::Relaxed)
    }

    /// Does the diagnostic currently condemn the volume?
    ///
    /// Three conditions, all of them narrowing: enough consecutive slow
    /// probes, an answer recent enough to still be about now, and the
    /// question still being asked. The freshness bound is three
    /// cadences, so one missed probe does not drop a standing verdict.
    pub(crate) fn suspect(&self, now_ms: u64) -> bool {
        if !self.wants_diag() {
            return false;
        }
        let fresh_ms = self.tune().diag_secs.saturating_mul(3_000);
        let d = self.diag.lock_ok();
        d.slow_runs >= DIAG_SLOW_RUNS && now_ms.saturating_sub(d.at_ms) <= fresh_ms
    }

    /// The last diagnostic probe's duration, for the panel's numbers.
    pub(crate) fn diag_ms(&self) -> u64 {
        self.diag.lock_ok().last_ms
    }
}

/// Fold one diagnostic probe into the latch. Returns whether the
/// volume is now condemned.
///
/// Only SLOW accumulates. A fast probe clears the run outright, and so
/// does an errored one: an error is not evidence of slowness - a write
/// that fails outright is the ACUTE path's business, and it has its own
/// verdict.
fn note_diag(d: &Daemon, probe: &Probe, now_ms: u64) -> bool {
    let mut g = d.slow_storage.diag.lock_ok();
    g.last_ms = probe.ms();
    g.at_ms = now_ms;
    g.slow_runs = match probe {
        Probe::Slow(_) => g.slow_runs.saturating_add(1),
        _ => 0,
    };
    g.slow_runs >= DIAG_SLOW_RUNS
}

/// Tell the dashboard its queue payload moved.
///
/// Everything this module changes - `paused`, `pause_source` and the
/// `storage_pause` block below - rides the §129 1b revisioned queue
/// payload, and the poll answers `"queue": null` for a client whose
/// revision matches unless something is actively transferring. A
/// storage pause is precisely the case where nothing is: the wind-down
/// takes the one running job off the wire, so from the moment the pause
/// lands until it lifts, `any_active` is false and the revision is the
/// ONLY thing that can move the payload.
///
/// Without this the header pill, the row sub-line and the drawer all
/// freeze at whatever they last applied - the recovery tally sits at
/// "0 so far" for the whole pause, and a release with an empty queue
/// behind it leaves "paused - output storage is not keeping up" on
/// screen indefinitely. This is the same staleness `persist_pause`
/// documents, from a path that deliberately does not persist.
pub fn bump(d: &Daemon) {
    d.queue_rev.fetch_add(1, Ordering::Relaxed);
}

/// The queue payload's `storage_pause` block: null unless a storage
/// pause is holding right now. Carries the affected path, the evidence
/// sentence, the job it happened to and the recovery-probe tally - the
/// header pill, the queue row sub-line and the drawer all render from
/// this one object, because the pause belongs to the QUEUE and only
/// names the job it interrupted.
pub fn payload(d: &Daemon) -> Value {
    match d.slow_storage.held.lock_ok().as_ref() {
        None => Value::Null,
        Some(h) => json!({
            "path": h.path.to_string_lossy(),
            "evidence": h.evidence,
            "stalled_secs": h.stalled_secs.round(),
            "window_secs": h.window_secs.round(),
            "nzo_id": h.nzo_id,
            "since_unix": h.since_unix,
            "probe_ms": h.probe_ms,
            "healthy_probes": h.healthy,
            "probes_needed": d.slow_storage.tune().probe_healthy,
        }),
    }
}

/// The user-facing reason, in one clause. English only for now; the
/// locale pass picks the new keys up with the rest of §129 phase 3.
pub(crate) const REASON: &str = "output storage is not keeping up";

/// Engage the pause, having been nominated by the judge and confirmed by
/// a probe. Returns whether it fired.
///
/// The pause itself is the ORDINARY one: `paused` plus the graceful
/// `suspend_active` wind-down, which is what the user's own Pause does.
/// That is load-bearing for three separate contracts - the article
/// journal is preserved because pausing already preserves it (§100), the
/// job returns to the queue instead of to history so no failure is
/// filed (the give-up breaker and the auto-retry ladder never see it),
/// and the resume is an ordinary resume rather than a retry.
pub(super) fn engage(d: &Arc<Daemon>, ev: &Evidence, path: &Path, probe: &Probe) -> bool {
    let Probe::Slow(ms) = probe else {
        // The window said "storage", the volume says otherwise. That is
        // the case this confirmation exists for: `blocked_ms` counts
        // waiting on EVERYTHING downstream of the socket, so a wedged
        // decoder and a dying disk look identical in it. Stand down and
        // rebuild the evidence from scratch.
        info!(
            target: "storage",
            "write stalls looked chronic but a {:.0} MB probe write on {} came back {} - not pausing",
            d.slow_storage.tune().probe_bytes as f64 / 1e6,
            path.display(),
            match probe {
                Probe::Fast(ms) => format!("in {ms} ms"),
                Probe::Failed(e) => format!("with an error ({e})"),
                Probe::Slow(_) => unreachable!(),
            }
        );
        return false;
    };
    let sentence = ev.sentence(path);
    let nzo_id = d.active_dl.lock_ok().clone();
    *d.slow_storage.held.lock_ok() = Some(Held {
        path: path.to_path_buf(),
        evidence: sentence.clone(),
        stalled_secs: ev.stalled_secs,
        window_secs: ev.window_secs,
        nzo_id,
        since_unix: super::job::unix_now(),
        probe_ms: *ms,
        healthy: 0,
    });
    // A storage pause cancels any pending timed auto-resume: coming back
    // is the probe's call now, not a clock's.
    crate::set_paused_cancel_timer(d, true);
    *d.pause_source.lock_ok() = "storage";
    bump(d);
    // Graceful: in-flight articles finish and journal, so the resume
    // refetches only what was never started.
    d.suspend_active(true);
    warn!(
        target: "storage",
        "downloads paused - {REASON} ({sentence}); a {:.0} MB probe write took {ms} ms",
        d.slow_storage.tune().probe_bytes as f64 / 1e6
    );
    let msg = format!("downloads paused - {REASON} ({sentence})");
    // §129 2e: the existing "disk" event token, distinct message. The
    // min-free guard's message is about SPACE; this one is about speed,
    // and a target routed onto "disk" wants both.
    crate::hooks::notify_event(d, "disk", &msg);
    // §129 4a: on the schema this speed pause is its own kind -
    // storage.slow, not disk.low - because a machine consumer must not
    // have to parse the message to tell space from speed.
    // event-arm-gate: a STATE, not a moment - the header's pause pill
    // and the drawer's storagePauseBlock draw it from the queue payload
    // (`pause_source === 'storage'` plus `q.storage_pause`), with the
    // write stalls behind the verdict. §129 1b finding (b) is the rule.
    d.life_emit(
        "storage.slow",
        json!({
            "message": msg,
            "path": path.to_string_lossy(),
            "probe_ms": *ms,
        }),
    );
    d.note_event("disk", msg);
    // Deliberately NOT persisted: `persist_pause` writes `paused` into
    // settings.json so a user's pause survives a restart, and a machine
    // rebooted to fix its enclosure must not come back paused with no
    // one having chosen that.
    true
}

/// Drop our pause state, lifting the queue pause only if it is still
/// OURS. `why` goes in the log and the marker ring.
///
/// The ownership test is the whole point. A person (or a schedule, or
/// going offline) pausing on top of a storage pause has said something,
/// and a healed probe does not get to overrule it - lifting a pause we
/// no longer own would put a fleet back on the wire that an operator had
/// deliberately taken off it.
pub fn release(d: &Arc<Daemon>, why: &str) {
    let ours = still_ours(d);
    if d.slow_storage.held.lock_ok().take().is_none() {
        return;
    }
    if ours {
        d.paused.store(false, Ordering::Relaxed);
        // Back to the neutral default, so a later pause taken by a path
        // that sets no source (the offline transition, the shutdown
        // wind-down) cannot inherit "storage" and be mistaken for ours.
        *d.pause_source.lock_ok() = "user";
        // Direct write, so the edge is owed by hand. AFTER the source
        // is reset and with the lock dropped: the announce reads it.
        crate::announce_pause(d);
    }
    // Unconditional: the handover case does not lift anything, but it
    // still drops the `storage_pause` block off the payload.
    bump(d);
    info!(target: "storage", "{why}");
    d.note_event("clear", why.to_string());
}

/// One probe result while the pause holds. Returns true when it resumed.
///
/// Hysteresis: `probe_healthy` CONSECUTIVE fast probes. Anything else -
/// a slow probe, or a probe that errored - puts the counter back to
/// zero, so a flapping enclosure that answers well once in a while never
/// releases the queue.
pub fn heal(d: &Arc<Daemon>, probe: &Probe) -> bool {
    let need = d.slow_storage.tune().probe_healthy;
    let (healthy, path) = {
        let mut g = d.slow_storage.held.lock_ok();
        let Some(h) = g.as_mut() else { return false };
        h.probe_ms = probe.ms();
        h.healthy = match probe {
            Probe::Fast(_) => h.healthy + 1,
            _ => 0,
        };
        (h.healthy, h.path.clone())
    };
    // Every probe moves the payload, whether or not it resumes: the
    // tally and the last-probe duration are what the drawer's recovery
    // line is made of, and a probe that resets the count to zero after a
    // flap is exactly the moment the user should see change.
    bump(d);
    if healthy < need {
        return false;
    }
    release(
        d,
        &format!(
            "output storage recovered ({healthy} clean write checks on {}) - downloads resume",
            path.display()
        ),
    );
    true
}

/// Is a storage pause in force AND still ours to manage? A user pause
/// or a schedule pause landing on top of one takes ownership; the
/// watcher then drops its state rather than fighting for it.
///
/// `paused_by_offline` is belt and braces. The watch loop stands down
/// entirely while `offline` is set, so this cannot normally see an
/// offline pause - but going offline pauses the queue WITHOUT touching
/// `pause_source`, so if that early return ever moves, the source alone
/// would read as ours and a healed probe would put the fleet back on an
/// account the operator had deliberately vacated.
fn still_ours(d: &Daemon) -> bool {
    d.paused.load(Ordering::Relaxed)
        && !d.paused_by_offline.load(Ordering::Relaxed)
        && *d.pause_source.lock_ok() == "storage"
}

/// The affected volume: the running job's own output directory when
/// there is one (categories can put jobs on different volumes), else the
/// daemon's output root.
fn affected_path(d: &Daemon) -> PathBuf {
    let active = d.active_dl.lock_ok().clone();
    if let Some(id) = active {
        for j in d.queue.lock_ok().iter() {
            let g = j.lock_ok();
            if g.nzo_id == id {
                return g.out_dir.clone();
            }
        }
    }
    crate::naming::out_dir(d)
}

/// What the watcher does with a tick, decided before it touches any I/O.
/// Split out so the gating - and in particular the offline stand-down -
/// is testable without a runtime.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Step {
    /// Nothing to do: switched off with no pause held, or offline.
    Idle,
    /// Sample the pool and feed the judge.
    Watch,
    /// Our pause is holding: probe the volume for recovery.
    Probe,
    /// Drop our state, with this reason.
    Release(&'static str),
}

pub fn step(d: &Daemon) -> Step {
    // Switched off. Releasing is not optional: leaving the pause in
    // place would strand the user with a paused queue and the one
    // mechanism that would have resumed it disarmed.
    if !d.slow_storage.enabled() {
        return match d.slow_storage.paused() {
            true => Step::Release("the slow-storage pause was switched off - downloads resume"),
            false => Step::Idle,
        };
    }
    // Offline stands the whole feature down, BEFORE the ownership test
    // below. Nothing is on the wire, so there is nothing to judge, and
    // probing a volume we are not writing to would be work for its own
    // sake. State is KEPT and the pause is not lifted: a failing
    // enclosure does not heal because the operator took the account
    // offline, and going offline while a storage pause is already in
    // force leaves `pause_source` reading "storage" - so a probe allowed
    // to run here would find a healthy volume, resume, and put the whole
    // fleet back on an account that was deliberately vacated.
    if d.offline.load(Ordering::Relaxed) {
        return Step::Idle;
    }
    if d.slow_storage.paused() {
        // Someone else now owns the pause - a person, or a schedule
        // entry. Drop our state, without lifting THEIR pause.
        return match still_ours(d) {
            true => Step::Probe,
            false => {
                Step::Release("storage pause handed over - the queue is paused by something else")
            }
        };
    }
    Step::Watch
}

/// The watcher: one task for the daemon's life, inert unless a job is
/// downloading (or a storage pause is holding).
pub fn spawn(daemon: &Arc<Daemon>) {
    let d = daemon.clone();
    tokio::spawn(async move { watch(d).await });
}

pub async fn watch(d: Arc<Daemon>) {
    let mut judge = Judge::new(d.slow_storage.tune());
    // (pool identity, blocked_ms total, bytes total) at the last tick.
    let mut prev: Option<(Arc<nzbkit::pool::LiveStats>, u64, u64, u64)> = None;
    let mut last_probe_ms = 0u64;
    let mut last_diag_ms = 0u64;
    loop {
        tokio::time::sleep(TICK).await;
        let todo = step(&d);
        if todo != Step::Watch {
            prev = None;
        }
        if let Step::Release(why) = todo {
            release(&d, why);
            judge.rearm(nzbkit::pool::now_ms());
        }
        if matches!(todo, Step::Idle | Step::Release(_)) {
            continue;
        }
        // Paused by us: probe for recovery on the probe cadence.
        if todo == Step::Probe {
            let now = nzbkit::pool::now_ms();
            let (secs, bytes, slow) = {
                let t = d.slow_storage.tune();
                (t.probe_secs, t.probe_bytes, t.probe_slow_ms)
            };
            if now.saturating_sub(last_probe_ms) < secs * 1000 {
                continue;
            }
            last_probe_ms = now;
            let path = d
                .slow_storage
                .held
                .lock_ok()
                .as_ref()
                .map(|h| h.path.clone())
                .unwrap_or_else(|| crate::naming::out_dir(&d));
            let probe = run_probe(path, bytes, slow).await;
            if heal(&d, &probe) {
                judge.rearm(nzbkit::pool::now_ms());
            }
            continue;
        }
        // Watching. The judge holds the tunables it was built with: they
        // are settings.json-only and read at startup, so a hand edit
        // takes effect on the next launch, never mid-verdict.
        let live = d.hub.pool_live.lock_ok().clone();
        let Some(live) = live else {
            prev = None;
            continue;
        };
        let (blocked, bytes, conns) = totals(&live);
        let now = nzbkit::pool::now_ms();
        let Some((plive, pblocked, pbytes, pat)) =
            prev.replace((live.clone(), blocked, bytes, now))
        else {
            continue;
        };
        // A different pool is a different job: its counters restart, so
        // a delta across the boundary is meaningless.
        if !Arc::ptr_eq(&plive, &live) {
            judge.rearm(now);
            continue;
        }
        let span_ms = now.saturating_sub(pat);
        let sample = Sample {
            at_ms: now,
            span_ms,
            worker_ms: span_ms.saturating_mul(conns),
            blocked_ms: blocked.saturating_sub(pblocked),
            bytes: bytes.saturating_sub(pbytes),
        };
        let Some(ev) = judge.observe(sample) else {
            // No nomination. This is where the vast majority of ticks
            // land, and it is also the only place the §108 option 2
            // diagnostic can run: the breaker has NOT tripped, so if
            // the whyslow core is stuck at its disk-vs-client fork,
            // the volume is the open question and nothing else is
            // going to answer it. Same instrument, slower cadence.
            if d.slow_storage.wants_diag()
                && now.saturating_sub(last_diag_ms) >= diag_secs_now(&d) * 1000
            {
                last_diag_ms = now;
                let (bytes, slow) = {
                    let t = d.slow_storage.tune();
                    (t.probe_bytes, t.probe_slow_ms)
                };
                let probe = run_probe(affected_path(&d), bytes, slow).await;
                if note_diag(&d, &probe, nzbkit::pool::now_ms()) {
                    // Opinion only - the queue keeps running. The panel
                    // reads this; nothing else does.
                    info!(
                        target: "storage",
                        "the output volume is answering slowly ({} ms for a {:.0} MB write) \
                         while downloads run short of the line - naming it in the slowdown panel",
                        probe.ms(),
                        bytes as f64 / 1e6
                    );
                }
            }
            continue;
        };
        let path = affected_path(&d);
        let (bytes, slow) = {
            let t = d.slow_storage.tune();
            (t.probe_bytes, t.probe_slow_ms)
        };
        let probe = run_probe(path.clone(), bytes, slow).await;
        if !engage(&d, &ev, &path, &probe) {
            // Not confirmed: build the next verdict from a whole fresh
            // window rather than re-nominating on the same evidence.
            judge.rearm(nzbkit::pool::now_ms());
            prev = None;
        } else {
            last_probe_ms = nzbkit::pool::now_ms();
        }
    }
}

/// Live totals across the fleet: parked worker-ms, payload bytes, and
/// how many connections are up (the worker-time denominator).
fn totals(live: &nzbkit::pool::LiveStats) -> (u64, u64, u64) {
    live.servers.iter().fold((0, 0, 0), |(b, y, c), s| {
        (
            b + s.blocked_ms.load(Ordering::Relaxed),
            y + s.bytes.load(Ordering::Relaxed),
            c + s.connected.load(Ordering::Relaxed) as u64,
        )
    })
}

/// Run one probe on the blocking pool. A wedged volume is precisely the
/// case where this does not return, so the await is bounded and a
/// timeout reports as slow-by-observation rather than hanging the
/// watcher - the write is still outstanding on its own thread, and the
/// next tick's probe simply starts a new one.
fn diag_secs_now(d: &Daemon) -> u64 {
    d.slow_storage.tune().diag_secs
}

async fn run_probe(path: PathBuf, bytes: u64, slow_ms: u64) -> Probe {
    let budget = Duration::from_millis(slow_ms.saturating_mul(4).max(5_000));
    let job = tokio::task::spawn_blocking(move || probe_write(&path, bytes, slow_ms));
    match tokio::time::timeout(budget, job).await {
        Ok(Ok(p)) => p,
        // The task itself died (panic / runtime shutdown): no verdict.
        Ok(Err(e)) => Probe::Failed(e.to_string()),
        Err(_) => Probe::Slow(budget.as_millis() as u64),
    }
}

#[cfg(test)]
mod tests;
