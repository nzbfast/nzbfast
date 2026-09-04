//! Where a chase worker's wall actually goes: decoding, or parked.
//!
//! Every chase and frontier threshold in this module tree - the holds
//! cap, the drop-behind pace ratio, the bounded gate park - was tuned in
//! Aug 2026, when the RAR decoder was the slower half of the pair and
//! the chase could be assumed to be the thing arrivals waited FOR. The
//! 2-3 Sep 2026 rounds made the decoder ~1.5x faster on `-m3` and the
//! encrypted store path ~1.8x (`research/RAR-PERF-AUDIT-2026-09-02.md`),
//! which moves the boundary: a chase that used to be decode-bound can
//! now be arrival-bound, and a threshold that reads a rate is reading a
//! different rate than the one it was set against.
//!
//! Nothing in the tree could answer that. `[mem]`'s holds peak says how
//! much RAM the chase held and `chase trimmed` says what the trim gave
//! back, but neither separates "the decode was busy" from "the decode
//! was parked at a hole", and the two call for opposite fixes. These
//! counters do, in the four places a chase worker can lose time:
//!
//! - a HOLE in the frontier (arrivals have not reached the decode)
//! - the §94 B verify gate (the bytes are here, the PAR2 vouching is
//!   not). Its 100 ms is a BOUND and not a poll period at the root -
//!   `VerifyGate::advance` notifies, and the round that added these
//!   counters measured 0 or 1 gate parks of 11-15 ms per one-pass job.
//!   For a routed CHILD it is closer to a poll: `ChildGate::wait_past`
//!   waits on the root gate's condvar, and a child watermark that moved
//!   because the parent's ROUTING map resolved has nothing to notify it.
//! - a repair PAUSE (a mapped repair is rewriting this volume)
//! - a VOLUME the router has not registered yet (the chase asked for
//!   volume N+1 before any article of it classified)
//!
//! OFF BY DEFAULT and gated on one cached bool, because the timing is
//! two `Instant::now()` calls per park and the report is a bench
//! instrument, not a user-facing line. `NZBFAST_CHASE_STAT=1` turns it
//! on; `nzbfast`'s `[mem]` summary prints the line only when it is.
//!
//! Process-global rather than per-chain, deliberately: the rigs that
//! read it run one job per process, and a per-chain home would have to
//! thread an Arc through every FrontierBuffer, the ChildGate and the
//! worker for a number no production path reads.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::time::Instant;

/// Is the instrument on? One cached bool; every call site below is a
/// relaxed load away from doing nothing at all.
pub(crate) fn on() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("NZBFAST_CHASE_STAT").is_ok_and(|v| v == "1"))
}

/// Start timing a park, or `None` when the instrument is off.
pub(crate) fn mark() -> Option<Instant> {
    on().then(Instant::now)
}

macro_rules! counters {
    ($($name:ident),* $(,)?) => {
        $(static $name: AtomicU64 = AtomicU64::new(0);)*
    };
}

counters!(
    READ_CALLS,
    HOLE_PARKS,
    HOLE_NS,
    GATE_PARKS,
    GATE_NS,
    PAUSE_PARKS,
    PAUSE_NS,
    VOL_PARKS,
    VOL_NS,
    WORKER_NS,
    WORKERS,
    TRIM_PASSES,
    TRIM_DROPS,
    TRIM_PARKED,
    TRIM_VETO_LOSS,
    TRIM_VETO_PACE,
    TRIM_VETO_SIZE,
    TRIM_VOUCH_SPILL,
    NO_PARITY,
);
/// High-water RAM retained by any ONE frontier buffer. The chain-wide
/// figure is the holds budget's own peak (`Extractor::holds_peak`);
/// this says how much of it one volume's buffer accounted for.
static BUF_PEAK: AtomicUsize = AtomicUsize::new(0);

/// One blocking read entered (both readers - the RAR forward one and
/// the 7z random-access one). Counted even when it serves without
/// parking: parks per read is the ratio that says whether the decode is
/// starving or merely being fed.
pub(crate) fn read_call() {
    if on() {
        READ_CALLS.fetch_add(1, Relaxed);
    }
}

fn park(count: &AtomicU64, ns: &AtomicU64, since: Option<Instant>) {
    if let Some(t) = since {
        count.fetch_add(1, Relaxed);
        ns.fetch_add(t.elapsed().as_nanos() as u64, Relaxed);
    }
}

/// A read parked at a hole in the frontier and has just woken.
pub(crate) fn hole_park(since: Option<Instant>) {
    park(&HOLE_PARKS, &HOLE_NS, since);
}

/// A read parked on the §94 B verify gate and has just woken.
pub(crate) fn gate_park(since: Option<Instant>) {
    park(&GATE_PARKS, &GATE_NS, since);
}

/// A read parked on a repair pause and has just woken.
pub(crate) fn pause_park(since: Option<Instant>) {
    park(&PAUSE_PARKS, &PAUSE_NS, since);
}

/// The worker parked waiting for a volume to be registered by routing.
pub(crate) fn vol_park(since: Option<Instant>) {
    park(&VOL_PARKS, &VOL_NS, since);
}

/// One chase worker ran for this long, engine call to engine return -
/// the denominator every park total above is a fraction of.
pub(crate) fn worker_ran(since: Option<Instant>) {
    if let Some(t) = since {
        WORKERS.fetch_add(1, Relaxed);
        WORKER_NS.fetch_add(t.elapsed().as_nanos() as u64, Relaxed);
    }
}

/// Retained RAM for one frontier buffer, after a span landed.
pub(crate) fn buf_retained(bytes: usize) {
    if on() {
        BUF_PEAK.fetch_max(bytes, Relaxed);
    }
}

/// Why a drop-eligible drop-behind trim SPILLED instead of dropping.
///
/// The `[mem]` line reports what the trim released (`chase trimmed N MB
/// (M dropped)`) but never which of the gates in `rar_trim_set` said no,
/// and they call for opposite fixes: a LOSS veto is the job's own damage
/// and correct; a PACE veto is a rate test, and a rate test set against
/// the old decoder is exactly what this round exists to re-read; a SIZE
/// veto is the set being too big for the cap, which no threshold change
/// can help.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TrimVeto {
    /// Dropped - no veto.
    None,
    /// A lost article, or doubt about one (and the nested and
    /// drop-switched-off arms, which are configuration, not a verdict).
    Loss,
    /// Not parked, and the engine is not keeping pace with arrivals.
    Pace,
    /// Not parked, keeping pace, but the set cannot finish inside the cap.
    Size,
}

/// One drop-eligible trim pass and what it decided. `parked` is the
/// held-bytes backpressure disjunct as the pass saw it, recorded
/// separately because it is the one gate that makes the other two moot.
pub(crate) fn trim_pass(veto: TrimVeto, parked: bool) {
    if !on() {
        return;
    }
    TRIM_PASSES.fetch_add(1, Relaxed);
    if parked {
        TRIM_PARKED.fetch_add(1, Relaxed);
    }
    match veto {
        TrimVeto::None => TRIM_DROPS.fetch_add(1, Relaxed),
        TrimVeto::Loss => TRIM_VETO_LOSS.fetch_add(1, Relaxed),
        TrimVeto::Pace => TRIM_VETO_PACE.fetch_add(1, Relaxed),
        TrimVeto::Size => TRIM_VETO_SIZE.fetch_add(1, Relaxed),
    };
}

/// One volume-level trim pass that the DROP-BEHIND decided to drop and
/// the §94 B vouch turned into a spill. The pass counters above are per
/// SET and say what the drop-behind decided; this is per VOLUME and says
/// how often that decision was then overruled by "the PAR2 verifier has
/// not vouched for these bytes". On a job with no parity at all that was
/// every single one of them before `parity_ruled_out` (3 Sep 2026:
/// 48,149 of 48,151 passes decided DROP and `[mem]` reported 0 dropped).
pub(crate) fn trim_vouch_spill() {
    if on() {
        TRIM_VOUCH_SPILL.fetch_add(1, Relaxed);
    }
}

/// The run proved no PAR2 set can ever claim a slot of this job, so the
/// trim drops unvouched bytes from here on (`parity_ruled_out`). Latched
/// once per run by its caller. Behind the instrument's own gate like
/// every other counter here: the only reader is the `[mem]` line, which
/// prints nothing at all when the instrument is off.
pub(crate) fn note_no_parity() {
    if on() {
        NO_PARITY.store(1, Relaxed);
    }
}

/// What the run measured. All zero (and `on` false) unless the
/// instrument was switched on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChaseStat {
    pub workers: u64,
    pub worker_ns: u64,
    pub read_calls: u64,
    pub hole_parks: u64,
    pub hole_ns: u64,
    pub gate_parks: u64,
    pub gate_ns: u64,
    pub pause_parks: u64,
    pub pause_ns: u64,
    pub vol_parks: u64,
    pub vol_ns: u64,
    pub buf_peak: usize,
    /// Drop-eligible drop-behind trim passes, and how they went.
    pub trim_passes: u64,
    pub trim_drops: u64,
    /// Passes that saw the held-bytes backpressure engaged.
    pub trim_parked: u64,
    pub trim_veto_loss: u64,
    pub trim_veto_pace: u64,
    pub trim_veto_size: u64,
    /// Per-VOLUME drops the §94 B vouch turned into spills.
    pub trim_vouch_spills: u64,
    /// The run ruled parity out and stopped asking for a vouch.
    pub no_parity: bool,
}

impl ChaseStat {
    /// Every nanosecond a chase worker spent parked rather than
    /// decoding. Summed over workers, so it can exceed the wall of any
    /// one of them when a nested chain runs two at once - as can
    /// `worker_ns`, which is the matching denominator.
    pub fn parked_ns(&self) -> u64 {
        self.hole_ns + self.gate_ns + self.pause_ns + self.vol_ns
    }

    /// Did anything at all get measured? A run with the instrument off
    /// reads false, and so does one where no chase ever attached - both
    /// are "nothing to print" for the caller.
    pub fn engaged(&self) -> bool {
        self.workers > 0 || self.read_calls > 0
    }
}

/// Read the counters. A snapshot, not a reset: the rigs run one job per
/// process and read this once, at the `[mem]` summary.
pub fn chase_stat() -> ChaseStat {
    ChaseStat {
        workers: WORKERS.load(Relaxed),
        worker_ns: WORKER_NS.load(Relaxed),
        read_calls: READ_CALLS.load(Relaxed),
        hole_parks: HOLE_PARKS.load(Relaxed),
        hole_ns: HOLE_NS.load(Relaxed),
        gate_parks: GATE_PARKS.load(Relaxed),
        gate_ns: GATE_NS.load(Relaxed),
        pause_parks: PAUSE_PARKS.load(Relaxed),
        pause_ns: PAUSE_NS.load(Relaxed),
        vol_parks: VOL_PARKS.load(Relaxed),
        vol_ns: VOL_NS.load(Relaxed),
        buf_peak: BUF_PEAK.load(Relaxed),
        trim_passes: TRIM_PASSES.load(Relaxed),
        trim_drops: TRIM_DROPS.load(Relaxed),
        trim_vouch_spills: TRIM_VOUCH_SPILL.load(Relaxed),
        no_parity: NO_PARITY.load(Relaxed) != 0,
        trim_parked: TRIM_PARKED.load(Relaxed),
        trim_veto_loss: TRIM_VETO_LOSS.load(Relaxed),
        trim_veto_pace: TRIM_VETO_PACE.load(Relaxed),
        trim_veto_size: TRIM_VETO_SIZE.load(Relaxed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The instrument is OFF in a unit-test build (no `NZBFAST_CHASE_STAT`
    /// in the environment), and every call site is a no-op when it is.
    ///
    /// Order-independent on purpose. These counters are process-global,
    /// which normally makes a test of them depend on what ran first
    /// (memory topic `nzbfast-test-suite-index`: a process-global counter
    /// test must be PINNED); this one asserts the opposite property - that
    /// nothing in the process can move them while the gate is shut - so
    /// every other test in the binary is free to run a chase before it.
    #[test]
    fn off_by_default_and_free() {
        assert!(!on(), "NZBFAST_CHASE_STAT leaked into the test environment");
        let before = chase_stat();
        read_call();
        hole_park(mark());
        gate_park(mark());
        pause_park(mark());
        vol_park(mark());
        worker_ran(mark());
        buf_retained(1 << 30);
        trim_pass(TrimVeto::Pace, true);
        assert_eq!(
            before,
            chase_stat(),
            "a call site moved a counter with the instrument off"
        );
        assert_eq!(chase_stat(), ChaseStat::default());
        assert!(!chase_stat().engaged());
    }

    /// `mark()` hands back nothing while the gate is shut, which is what
    /// makes a park site cost one relaxed load and no clock read.
    #[test]
    fn mark_is_none_when_off() {
        assert!(mark().is_none());
    }

    #[test]
    fn parked_is_the_sum_of_the_four_parks() {
        let s = ChaseStat {
            hole_ns: 1,
            gate_ns: 20,
            pause_ns: 300,
            vol_ns: 4000,
            worker_ns: 9_000_000,
            ..ChaseStat::default()
        };
        assert_eq!(s.parked_ns(), 4321);
    }

    /// A run where a chase attached but never parked still has something
    /// to report; a run where none ever did has not.
    #[test]
    fn engaged_tracks_whether_a_chase_ran() {
        assert!(!ChaseStat::default().engaged());
        assert!(
            ChaseStat {
                workers: 1,
                ..ChaseStat::default()
            }
            .engaged()
        );
        assert!(
            ChaseStat {
                read_calls: 1,
                ..ChaseStat::default()
            }
            .engaged()
        );
    }
}
