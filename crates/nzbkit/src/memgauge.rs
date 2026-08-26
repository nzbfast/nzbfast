//! Instrument-first: per-subsystem live/peak byte gauges for the memory
//! floor (TODO: the unexplained ~450-700 MB the 21 Aug --mem-limit ladder
//! could not attribute - `holds peak` and `partials peak` read 0 while
//! peak RSS sat near 700 MB, insensitive to a 66x budget change).
//!
//! Counters only - nothing reads these to make a decision. Same house
//! pattern as `live::CRC_REUSE_GEOMETRY`: relaxed atomics, a plain
//! snapshot struct, `reset_for_tests` gated to tests. Process-global on
//! purpose (the daemon runs one job at a time on the paths these cover;
//! concurrent jobs sum, which is still the process's honest floor), and
//! like every counter in this pattern it cannot be asserted exactly under
//! plain `cargo test` where lib tests share a process - serialize or
//! assert monotone properties only.
//!
//! The gauges deliberately separate quantities that overlap:
//! - `RawFree`/`RawOut` and `OutFree`/`OutOut` are the two `BufPool`s'
//!   free-list bytes and outstanding (taken, not yet returned) bytes.
//!   Together they are every live article buffer in the process.
//! - `Channel` is the subset of `RawOut` currently queued in the
//!   fetch->decode channel - a split of RawOut, NOT an addition to it.
//! - `WireEst` mirrors the B3 wire cap's charge: 800 KB per pipelined
//!   item. It counts requests in flight, most of whose bytes exist only
//!   on the wire or in kernel buffers, so it OVERSTATES resident memory
//!   by roughly the pipeline window and is reported for comparison, not
//!   summed into the attribution.

use crate::sync::MutexExt;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, Weak};

/// Subsystem index. Keep `COUNT` and `name()` in step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sub {
    /// Network-side body BufPool: free-list bytes (retained, reusable).
    RawFree,
    /// Network-side body BufPool: outstanding bytes (in read loops, the
    /// fetch->decode channel, and decoder hands).
    RawOut,
    /// Decoded-payload BufPool: free-list bytes.
    OutFree,
    /// Decoded-payload BufPool: outstanding bytes.
    OutOut,
    /// Raw bodies queued in the fetch->decode channel (subset of RawOut).
    Channel,
    /// B3 wire-cap charge: 800 KB x pipelined items (estimate, overlaps
    /// RawOut; excluded from the attribution sum).
    WireEst,
    /// PAR2 main/bootstrap capture mirrors (slot.capture).
    Par2Capture,
    /// One-shot: plan/job metadata estimate (ids, queue items, maps).
    JobMeta,
    /// One-shot: verifier per-block tables once a PAR2 set activates.
    VerifierMeta,
    /// Extractor holds (mirror of HoldsBudget, which spills at its cap).
    Holds,
    /// Repair-path transient whole-file reads (par2repair catalog scan:
    /// one recovery volume at a time, up to MAX_PACKET_FILE_BYTES).
    /// Budget-independent and connection-independent - the suspected
    /// owner of the damaged-fixture ladder floor.
    RepairScan,
    /// PAR2 reconstruction working set: syndrome rows (recovery blocks x
    /// block_size, live for the whole repair), feed-batch arenas in
    /// flight and NTT-retained, the NTT tail-pad arena, and the rebuilt
    /// output blocks at finish. The term the first damaged-leg run left
    /// as a 632 MB unattributed remainder.
    RepairWork,
}

pub const SUB_COUNT: usize = 12;

impl Sub {
    pub fn name(self) -> &'static str {
        match self {
            Sub::RawFree => "raw_free",
            Sub::RawOut => "raw_out",
            Sub::OutFree => "out_free",
            Sub::OutOut => "out_out",
            Sub::Channel => "channel",
            Sub::WireEst => "wire_est",
            Sub::Par2Capture => "par2_capture",
            Sub::JobMeta => "job_meta",
            Sub::VerifierMeta => "verifier_meta",
            Sub::Holds => "holds",
            Sub::RepairScan => "repair_scan",
            Sub::RepairWork => "repair_work",
        }
    }
}

static CUR: [AtomicU64; SUB_COUNT] = [const { AtomicU64::new(0) }; SUB_COUNT];
static PEAK: [AtomicU64; SUB_COUNT] = [const { AtomicU64::new(0) }; SUB_COUNT];

/// Charge `n` bytes to a subsystem and roll its peak forward.
pub fn add(s: Sub, n: u64) {
    if n == 0 {
        return;
    }
    let i = s as usize;
    let now = CUR[i].fetch_add(n, Relaxed) + n;
    PEAK[i].fetch_max(now, Relaxed);
}

/// Release `n` bytes. Saturating, not wrapping: buffer capacities can
/// grow while outstanding (a large article grows a pooled Vec), so a
/// release can honestly exceed its charge - a floor that drifts a little
/// low beats a gauge that wraps to u64::MAX and reads as 16 EB forever.
pub fn sub(s: Sub, n: u64) {
    if n == 0 {
        return;
    }
    let _ = CUR[s as usize].fetch_update(Relaxed, Relaxed, |v| Some(v.saturating_sub(n)));
}

/// One-shot setter for computed sizes (plan metadata, verifier tables).
/// `fetch_max`, not `store`: nested jobs and re-activations keep the
/// biggest figure rather than the latest.
pub fn set_at_least(s: Sub, n: u64) {
    let i = s as usize;
    CUR[i].fetch_max(n, Relaxed);
    PEAK[i].fetch_max(n, Relaxed);
}

/// RAII charge against one gauge: adds on construction, releases what
/// remains on drop - so a charge threaded through moves, thread
/// boundaries, and early-error paths can never leak the gauge upward.
/// `grow` charges more onto the same guard; `release_all` returns the
/// whole charge early (for a drop the code wants to account at a precise
/// line rather than at scope end).
pub struct Charge {
    sub_of: Sub,
    n: u64,
}

impl Charge {
    pub fn new(s: Sub, n: u64) -> Charge {
        add(s, n);
        Charge { sub_of: s, n }
    }

    pub fn grow(&mut self, n: u64) {
        add(self.sub_of, n);
        self.n += n;
    }

    pub fn release_all(&mut self) {
        sub(self.sub_of, self.n);
        self.n = 0;
    }

    /// The charged bytes have gone somewhere this scope cannot follow -
    /// down a channel, into another thread's hands - and whoever holds
    /// them now owns the release. Stops guarding WITHOUT releasing, so
    /// the charge survives the guard.
    ///
    /// Consuming, and the only way out that is not a release: every
    /// other path off a `Charge` (an early return, a `?`, an unwind)
    /// releases, which is the safe direction. Forgetting to call this
    /// makes the gauge read a little LOW - the far end releases a charge
    /// this scope already gave back, and `sub` saturates - which is the
    /// error this module's `sub` doc says to prefer over a gauge that
    /// climbs and never comes down.
    pub fn hand_off(mut self) {
        self.n = 0;
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        sub(self.sub_of, self.n);
    }
}

/// Point-in-time snapshot of every gauge (current and peak).
#[derive(Clone, Copy, Debug, Default)]
pub struct MemGauges {
    pub cur: [u64; SUB_COUNT],
    pub peak: [u64; SUB_COUNT],
}

impl MemGauges {
    pub fn cur_of(&self, s: Sub) -> u64 {
        self.cur[s as usize]
    }
    pub fn peak_of(&self, s: Sub) -> u64 {
        self.peak[s as usize]
    }
}

/// One gauge's current charge - the single-sub read for a hot path
/// that wants one number, not the whole snapshot.
pub fn cur(s: Sub) -> u64 {
    CUR[s as usize].load(Relaxed)
}

pub fn snapshot() -> MemGauges {
    let mut g = MemGauges::default();
    for i in 0..SUB_COUNT {
        g.cur[i] = CUR[i].load(Relaxed);
        g.peak[i] = PEAK[i].load(Relaxed);
    }
    g
}

/// The gauge snapshot taken the moment the sampled RSS high-water moved.
#[derive(Clone, Copy, Debug)]
pub struct PeakAttribution {
    /// Resident set size at the sample (mach resident_size / statm),
    /// the same basis as the bench column.
    pub rss: u64,
    /// phys_footprint at the same instant - the kernel's live charge,
    /// EXCLUDING pages the allocator already offered back. rss minus
    /// this is allocator retention at the high-water.
    pub footprint: u64,
    pub gauges: MemGauges,
}

/// One job's sampled RSS high-water and the gauge snapshot taken there.
/// Owned by the job (its memory sampler holds the `Arc`), NOT by the
/// process: the daemon overlaps job B's download with job A's
/// post-processing tail, and when this was a single global pair of
/// statics B's spawn wiped A's record before A's summary printed it and
/// A's repair high-water was credited to B (bug sweep 22 Aug 2026,
/// F-19, the half left open when the stop token was fixed).
#[derive(Debug, Default)]
pub struct PeakRecord {
    rss_seen: AtomicU64,
    at: Mutex<Option<PeakAttribution>>,
}

impl PeakRecord {
    pub const fn new() -> PeakRecord {
        PeakRecord {
            rss_seen: AtomicU64::new(0),
            at: Mutex::new(None),
        }
    }

    /// Sample RSS + footprint now; when RSS makes a new sampled high for
    /// THIS record, store a coincident snapshot of every gauge. Called
    /// from the job's sampler tick, so the stored attribution is "at the
    /// highest RSS any sample saw" - close to, but not exactly,
    /// `ru_maxrss` (which the summary prints beside it so the shortfall
    /// is visible). The gauges are process-wide, so a sample taken while
    /// another job's tail is live attributes that job's charges too:
    /// that is the truth of the process at the instant, named as such.
    pub fn note_rss_sample(&self) {
        let Some(rss) = crate::mem::current_rss() else {
            return;
        };
        if rss <= self.rss_seen.fetch_max(rss, Relaxed) {
            return;
        }
        let footprint = crate::mem::dashboard_rss().unwrap_or(0);
        let attr = PeakAttribution {
            rss,
            footprint,
            gauges: snapshot(),
        };
        // Poisoning ignored on purpose (lock_ok idiom): a panicked
        // sampler tick must not take the attribution down with it.
        let mut slot = self.at.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_none_or(|p| rss > p.rss) {
            *slot = Some(attr);
        }
    }

    pub fn peak_attribution(&self) -> Option<PeakAttribution> {
        *self.at.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The record of the most recently started job, for readers that have
/// no job in hand (the daemon's instrument endpoint). Installed when a
/// job's sampler spawns and kept after the job ends, so a poll between
/// jobs still answers with the last one's high-water. When two jobs
/// overlap this names the NEWER job's record; the older job's is only
/// printed by its own summary.
static LATEST: Mutex<Option<Arc<PeakRecord>>> = Mutex::new(None);

pub fn install_latest_peak_record(record: Arc<PeakRecord>) {
    *LATEST.lock().unwrap_or_else(|e| e.into_inner()) = Some(record);
}

/// The latest-started job's peak attribution (see [`LATEST`]).
pub fn peak_attribution() -> Option<PeakAttribution> {
    let latest = LATEST.lock().unwrap_or_else(|e| e.into_inner()).clone();
    latest.and_then(|r| r.peak_attribution())
}

/// One live job's entry in the registry [`LIVE`]: the sampler generation
/// token it was born with, a label for the reader (the daemon's nzo_id
/// when there is one), and a WEAK handle to its record.
///
/// Weak on purpose. The strong references are the job's sampler guard
/// and the sampler task, both of which die with the job even on an
/// error return that never reaches the summary; a strong entry here
/// would keep every job that ever ran resident instead, and would keep
/// answering for jobs that ended.
struct LiveRecord {
    run: u64,
    label: String,
    record: Weak<PeakRecord>,
}

/// Every job whose memory sampler is still alive, oldest start first.
/// [`LATEST`] answers "the newest job" for readers with no job in hand;
/// this answers "every job running right now", which is the case the
/// daemon actually produces - job B's download overlaps job A's
/// post-processing tail, and A's repair high-water is the interesting
/// one exactly then.
static LIVE: Mutex<Vec<LiveRecord>> = Mutex::new(Vec::new());

/// Add a job's record to [`LIVE`] (called where its sampler spawns).
/// Dropped records are pruned on the way past, so a job that ended
/// without unregistering leaves nothing behind.
pub fn register_peak_record(run: u64, label: &str, record: &Arc<PeakRecord>) {
    let mut live = LIVE.lock_ok();
    live.retain(|r| r.record.strong_count() > 0);
    live.push(LiveRecord {
        run,
        label: label.to_string(),
        record: Arc::downgrade(record),
    });
}

/// Drop a job's registry entry (called where its sampler guard drops),
/// and keep its high-water in [`RECENT`] on the way out.
///
/// The guard still holds the `Arc` while its `Drop` runs, so the record
/// is readable here - this is the one instant at which a job's final
/// attribution is both complete and still reachable.
pub fn unregister_peak_record(run: u64) {
    let finished = {
        let mut live = LIVE.lock_ok();
        let finished = live.iter().find(|r| r.run == run).and_then(|r| {
            let at_peak = r.record.upgrade()?.peak_attribution()?;
            Some(JobPeak {
                label: r.label.clone(),
                at_peak: Some(at_peak),
            })
        });
        live.retain(|r| r.run != run && r.record.strong_count() > 0);
        finished
    };
    // Nested locks avoided on purpose: LIVE is released above before
    // RECENT is taken, so the two can never be held in both orders.
    if let Some(job) = finished {
        let mut recent = RECENT.lock_ok();
        if recent.len() >= RECENT_CAP {
            recent.pop_front();
        }
        recent.push_back(job);
    }
}

/// One live job: its label and its own sampled high-water, `None` until
/// that job's sampler has ticked once.
#[derive(Clone, Debug)]
pub struct JobPeak {
    pub label: String,
    pub at_peak: Option<PeakAttribution>,
}

/// Every live job's peak attribution, oldest start first. See [`LIVE`].
pub fn live_peak_attributions() -> Vec<JobPeak> {
    let mut live = LIVE.lock_ok();
    live.retain(|r| r.record.strong_count() > 0);
    live.iter()
        .map(|r| JobPeak {
            label: r.label.clone(),
            at_peak: r.record.upgrade().and_then(|rec| rec.peak_attribution()),
        })
        .collect()
}

/// How many finished jobs [`RECENT`] remembers. Small on purpose: this
/// is a tail readable after the fact, not a history - the history store
/// is where a per-job figure would belong if one is ever wanted for
/// every job the daemon has run.
const RECENT_CAP: usize = 8;

/// The last [`RECENT_CAP`] FINISHED jobs' high-waters, oldest first
/// (TODO 224). [`LIVE`] answers "every job running right now", which
/// says nothing once a job's sampler retires: a repair that peaked at
/// 900 MB and finished four seconds before the poll used to exist only
/// in that job's own mem-floor log lines, because [`LATEST`] by then
/// names the NEXT job. This is that figure, kept long enough for a poll
/// to arrive.
///
/// A VALUE, not the `Arc`. Holding a strong reference to a finished
/// job's record would keep it alive, and [`LIVE`] prunes by
/// `strong_count`, so a job that ended without unregistering would
/// still read as running. A [`PeakAttribution`] is `Copy` - two `u64`s
/// and a 12-entry [`MemGauges`] - so the whole ring is under 2 KB.
///
/// Only a job that sampled at least once is kept: a record with no
/// attribution reports nothing, so keeping it would spend a slot to say
/// "no data" and push out a slot that had some.
static RECENT: Mutex<VecDeque<JobPeak>> = Mutex::new(VecDeque::new());

/// The last few finished jobs' peak attributions, oldest first. See
/// [`RECENT`]. Every row's `at_peak` is `Some` by construction.
pub fn recent_peak_attributions() -> Vec<JobPeak> {
    RECENT.lock_ok().iter().cloned().collect()
}

/// Test-only serializer for the process-global gauges. `CUR`/`PEAK` are
/// one array for the whole process, so two tests that move a gauge and
/// then assert on it read each other's writes the moment they land on
/// different threads of one process - which nextest hides by giving
/// every test its own process, so only `cargo test` (and the
/// `unit-one-process` job) would ever flake. Exported rather than
/// module-private because the gauge has callers outside this file that
/// tests drive: `pool::bufpool` charges `RawOut`/`RawFree` on every
/// take and give, and its characterization tests take THIS lock, not
/// one of their own - a lock of their own would serialize them against
/// nobody. Take it as the test's FIRST statement so it drops LAST.
#[cfg(test)]
pub(crate) fn one_gauge_test_at_a_time() -> std::sync::MutexGuard<'static, ()> {
    static CENSUS: Mutex<()> = Mutex::new(());
    CENSUS.lock().unwrap_or_else(|e| e.into_inner())
}

/// Test-only: zero every gauge and forget the peak attribution.
#[cfg(test)]
pub fn reset_for_tests() {
    for i in 0..SUB_COUNT {
        CUR[i].store(0, Relaxed);
        PEAK[i].store(0, Relaxed);
    }
    *LATEST.lock().unwrap_or_else(|e| e.into_inner()) = None;
    LIVE.lock_ok().clear();
    RECENT.lock_ok().clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_sub_tracks_current_and_peak() {
        let _g = one_gauge_test_at_a_time();
        reset_for_tests();
        add(Sub::RawFree, 800);
        add(Sub::RawFree, 800);
        sub(Sub::RawFree, 800);
        add(Sub::RawFree, 100);
        let g = snapshot();
        assert_eq!(g.cur_of(Sub::RawFree), 900);
        assert_eq!(g.peak_of(Sub::RawFree), 1600);
        // Other gauges untouched.
        assert_eq!(g.cur_of(Sub::OutFree), 0);
    }

    #[test]
    fn over_release_saturates_instead_of_wrapping() {
        let _g = one_gauge_test_at_a_time();
        reset_for_tests();
        add(Sub::OutOut, 100);
        // A pooled buffer that grew while outstanding releases more than
        // its charge; the floor holds at zero.
        sub(Sub::OutOut, 4_000_000);
        assert_eq!(snapshot().cur_of(Sub::OutOut), 0);
        assert_eq!(snapshot().peak_of(Sub::OutOut), 100);
    }

    #[test]
    fn set_at_least_keeps_the_biggest_figure() {
        let _g = one_gauge_test_at_a_time();
        reset_for_tests();
        set_at_least(Sub::JobMeta, 500);
        set_at_least(Sub::JobMeta, 200);
        assert_eq!(snapshot().cur_of(Sub::JobMeta), 500);
        assert_eq!(snapshot().peak_of(Sub::JobMeta), 500);
    }

    /// Bug sweep 22 Aug 2026, F-19: one job's sample lands in ITS record
    /// only - a second job's record (the overlapping tail) is untouched,
    /// and the process-wide reader follows whichever was installed last.
    #[test]
    fn peak_records_are_per_job() {
        let _g = one_gauge_test_at_a_time();
        reset_for_tests();
        let a = Arc::new(PeakRecord::new());
        let b = Arc::new(PeakRecord::new());
        install_latest_peak_record(a.clone());
        a.note_rss_sample();
        assert!(a.peak_attribution().is_some(), "one sample is a peak");
        assert!(b.peak_attribution().is_none(), "b never sampled");
        assert_eq!(
            peak_attribution().map(|p| p.rss),
            a.peak_attribution().map(|p| p.rss)
        );
        install_latest_peak_record(b.clone());
        assert!(
            peak_attribution().is_none(),
            "the reader follows the newest job"
        );
        assert!(
            a.peak_attribution().is_some(),
            "a's record survives b's start"
        );
        reset_for_tests();
    }

    /// The live registry is what the daemon's instrument endpoint reads
    /// to see BOTH overlapping jobs: the newer job's download and the
    /// older job's post-processing tail, in start order.
    #[test]
    fn live_registry_holds_every_overlapping_job() {
        let _g = one_gauge_test_at_a_time();
        reset_for_tests();
        let a = Arc::new(PeakRecord::new());
        let b = Arc::new(PeakRecord::new());
        register_peak_record(1, "nzo_a", &a);
        register_peak_record(2, "nzo_b", &b);
        a.note_rss_sample();
        let live = live_peak_attributions();
        assert_eq!(
            live.iter().map(|j| j.label.as_str()).collect::<Vec<_>>(),
            ["nzo_a", "nzo_b"],
            "oldest start first"
        );
        assert!(live[0].at_peak.is_some(), "a sampled");
        assert!(live[1].at_peak.is_none(), "b never sampled");
        // The older job finishing leaves the younger one answering.
        unregister_peak_record(1);
        let live = live_peak_attributions();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].label, "nzo_b");
        reset_for_tests();
    }

    /// A job that ends without unregistering (an early error return that
    /// never reaches its summary) must not linger: the entry is weak, so
    /// dropping the record retires the row.
    #[test]
    fn a_dropped_record_falls_out_of_the_registry() {
        let _g = one_gauge_test_at_a_time();
        reset_for_tests();
        let gone = Arc::new(PeakRecord::new());
        register_peak_record(7, "nzo_gone", &gone);
        assert_eq!(live_peak_attributions().len(), 1);
        drop(gone);
        assert!(
            live_peak_attributions().is_empty(),
            "the weak entry retires with its record"
        );
        reset_for_tests();
    }

    /// TODO 224: a finished job's high-water outlives its sampler in the
    /// recent ring, which is what a poll arriving after the tail reads.
    /// Bounded, oldest evicted first, and a job that never sampled is
    /// not kept (it would spend a slot to report nothing).
    #[test]
    fn recent_ring_keeps_the_last_finished_jobs() {
        let _g = one_gauge_test_at_a_time();
        reset_for_tests();
        assert!(recent_peak_attributions().is_empty(), "nothing has run");

        let a = Arc::new(PeakRecord::new());
        register_peak_record(1, "nzo_a", &a);
        a.note_rss_sample();
        unregister_peak_record(1);
        drop(a);
        let recent = recent_peak_attributions();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].label, "nzo_a");
        assert!(
            recent[0].at_peak.is_some(),
            "the finished job's attribution survives its sampler"
        );
        assert!(
            live_peak_attributions().is_empty(),
            "and it is NOT reported as still running"
        );

        // Never sampled: nothing to report, so no slot spent.
        let b = Arc::new(PeakRecord::new());
        register_peak_record(2, "nzo_b", &b);
        unregister_peak_record(2);
        assert_eq!(recent_peak_attributions().len(), 1, "b reported nothing");

        // An early error return that drops the record without
        // unregistering leaves nothing behind here either.
        let c = Arc::new(PeakRecord::new());
        register_peak_record(3, "nzo_c", &c);
        c.note_rss_sample();
        drop(c);
        assert_eq!(recent_peak_attributions().len(), 1, "c never retired");

        // Bounded: the ring holds the newest RECENT_CAP, oldest first.
        for run in 10..10 + RECENT_CAP as u64 + 2 {
            let r = Arc::new(PeakRecord::new());
            register_peak_record(run, &format!("nzo_{run}"), &r);
            r.note_rss_sample();
            unregister_peak_record(run);
        }
        let recent = recent_peak_attributions();
        assert_eq!(recent.len(), RECENT_CAP, "the ring is capped");
        assert_eq!(
            recent[0].label, "nzo_12",
            "nzo_a and the first two aged out"
        );
        assert_eq!(recent[RECENT_CAP - 1].label, "nzo_19", "newest last");
        reset_for_tests();
        assert!(recent_peak_attributions().is_empty());
    }
}
