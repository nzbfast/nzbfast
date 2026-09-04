//! The one-pass writer's per-file write-coalescing window.
//!
//! Round 23 of `research/RAR-PERF-AUDIT-2026-09-02.md` priced the
//! small-article regime and found the write CALL, not our code: at 50 KB
//! articles **98.3% of every decode thread's samples are in `pwrite`**,
//! and a standalone fit over the same box says a positioned write costs
//! about the same for 50 KB as for 700 KB (a per-call term of 41-50 us
//! against a per-byte term of 0.067-0.108 s/GiB). So a 100 KB-article
//! post pays roughly 0.4 s of extra kernel time per GiB in the syscall
//! alone, and round 23's own conclusion was that "nothing in nzbkit can
//! make that call cheaper; the only lever is issuing fewer of them".
//!
//! That is this module: contiguous article spans are held until they can
//! be issued as ONE positioned write.
//!
//! **WHY THE WINDOW HOLDS SEVERAL RUNS AND NOT ONE.** The first cut held
//! exactly one open run per file, on the reading that "articles arrive
//! roughly in order". Measured on round 23's own ladder it coalesced
//! NOTHING - `writes` was identical to the control at every article size
//! from 1.4 MB down to 50 KB, all six rungs. Sixteen connections fetch
//! sixteen consecutive articles AT ONCE, so the next arrival is one of
//! sixteen candidates and only one of them continues the run; a
//! single-run window is displaced by the other fifteen. The window
//! therefore holds up to [`MAX_RUNS`] disjoint runs, an arriving span
//! extends whichever run it continues, and two runs that MEET are merged
//! into one - which is how a gap filled late still becomes one write.
//!
//! **What a staged byte is NOT.** It is not covered, not written, and not
//! readable. Nothing in [`FileWriter`](super::FileWriter) publishes
//! coverage for a byte until its `pwrite` has returned, exactly as
//! before, so every reader of the coverage map (the live verifier, the
//! streaming frontier, `materialized_span_on_disk`, §296's early
//! publish) can only ever be told LESS than the truth, never more, and
//! only for as long as the run is open. Every door that reads BYTES back
//! - `read_at`, `open_read`, `try_open_read` - flushes first, and so do
//! the durability doors (`sync`, `park`) and `Drop`. The readers OUTSIDE
//! this module - settle's read-back, the native repair's PAR2 scan, the
//! unpack step, which all open the output BY PATH - are served by
//! `FileWriter::flush_staged`, which the engine calls over every writer
//! the moment the decode threads join.
//!
//! **The window is bounded twice**, because an unbounded one is a memory
//! leak with a nice name: per file by [`coalesce_cap`], and across the
//! process by [`coalesce_total_cap`], with the outstanding bytes charged
//! to `memgauge::Sub::WriteStage` so they appear in the mem-floor
//! attribution rather than as the unattributed remainder round 14 spent
//! a whole lane chasing.

use crate::memgauge;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// Per-file window, in bytes across every open run.
/// `NZBFAST_WRITE_COALESCE_KB` sets it; 0 disables coalescing entirely
/// and every article takes the unchanged one-article-one-`pwrite` path,
/// which is what the control arm of every measurement below is.
///
/// **THE DEFAULT IS 4 MiB - THE WINDOW SHIPS ON SINCE ROUND 42, AND
/// ROUND 41 IS WHY IT DID NOT BEFORE.** Round 41 built the window,
/// measured a real and large lever, and shipped it OFF at 0 because the
/// only version that kept `Extractor::write`'s postcondition captured
/// about a third of that lever at 100 KB articles and almost none at
/// 50 KB. The whole of that gap was `articles_in_flight` INFERRING
/// quiescence from a counter a fast decoder drives to zero between
/// arrivals, and round 44 replaced the inference with the engine's own
/// signal (`FileWriter`'s `feeding` field, `Extractor::set_feeding`).
/// The postcondition is not traded for it: the signal is an `Arc` a
/// caller has to hand the writer, so every caller that does not - every
/// library user, every test, and the three tests under `extract/` that
/// write one article and `std::fs::read` the output by path - keeps
/// round 41's rule exactly, which
/// `disk::tests::an_unfed_writer_still_answers_a_by_path_read_after_one_article`
/// executes as a sentence.
///
/// 4 MiB per file, [`COALESCE_TOTAL_DEFAULT`] across the process, and
/// [`STAGE_MAX_AGE_DEFAULT`] in time - and it is that third bound that
/// makes turning this on by default safe rather than merely profitable,
/// because it degenerates the window to the old write path in exactly
/// the regime (a real line, one article per file per bound) where round
/// 23 found the write call nowhere near the critical path.
pub const COALESCE_CAP_DEFAULT: usize = 4 << 20;

/// How large ONE run grows before it is written. The win is entirely in
/// the CALL COUNT - round 23's fit is flat in bytes to about 700 KB - so
/// this is sized as "several articles of the regime that hurts" rather
/// than as a device transfer size, and a bigger one would buy only
/// latency.
pub const RUN_CAP_DEFAULT: usize = 1 << 20;

/// The largest article the window will HOLD. Above it the article takes
/// its own positioned write, exactly as it did before this existed.
///
/// This is not the same bound as [`RUN_CAP_DEFAULT`] and it is the one
/// the measurement asked for. Staging costs a copy of every byte, and
/// round 41's ladder on the dev Mac prices that copy against the calls
/// it saves: at 50 KB articles the window takes 21,484 writes to 4,979
/// and retired instructions FALL 8.8%; at 100 KB, 10,752 to 2,085 and
/// instructions are flat; at 200 KB, 5,386 to 1,232 for +2.2%; at
/// 350 KB, 3,072 to 1,247 for **+9.0%**, with system seconds flat
/// (0.64 -> 0.65) - the calls saved stop paying for the copy well before
/// the calls run out. 256 KiB is the round number between the last rung
/// that wins and the first that does not.
pub const STAGE_MAX_ARTICLE_DEFAULT: usize = 256 << 10;

/// How many disjoint runs one file may hold. Sixteen because sixteen is
/// the connection count a default fleet fetches with, and the shape this
/// bounds is exactly "one run per in-flight article" - see the module
/// header on why one was not enough.
pub const MAX_RUNS: usize = 16;

/// Ceiling on the bytes every open run in the process holds AT ONCE. A
/// job with thousands of members has thousands of writers, and one
/// window each is a budget item; past this ceiling a run is written out
/// rather than extended, which is exactly the old behaviour and never a
/// failure.
pub const COALESCE_TOTAL_DEFAULT: u64 = 64 << 20;

/// The longest a staged byte may sit in RAM, and it is 100 ms because
/// that is `journal::BATCH_AGE` - the SAME constant, chosen for the same
/// reason, and the two must not drift apart.
///
/// **WHY THIS BOUND EXISTS AT ALL (round 44).** The window's other
/// bounds are all about memory; this one is about a fact the journal
/// states about itself: "a kill loses at most `BATCH_AGE` of placements,
/// refetched on resume, **never corrupting anything**". A placement
/// record is queued when the article completes and lands within
/// `BATCH_AGE`; if that article's bytes are still in a run, a kill
/// leaves a LANDED record naming bytes that are not on disk, and a
/// resume replays a hole as payload. Bounding the run's age by the same
/// constant makes the two windows the same window: an article's bytes
/// are on disk within `BATCH_AGE` of the article, exactly as its record
/// is, so the kill that loses one loses the other.
///
/// It also makes the window SELF-LIMITING to the regime it wins in,
/// which is why turning it on by default is safe. Coalescing needs
/// several articles of one file inside one bound: at loopback rates
/// (round 23's ladder, 500+ articles/s to a single file) a 1 MiB run
/// fills in about 40 ms and the bound never binds; on a 100 Mbit line
/// one file receives about one article per 100 ms, the bound fires on
/// every run, and the write path degenerates to exactly what it was
/// before this module existed - which is correct, because that is also
/// the regime where round 23 found the write call nowhere near the
/// critical path.
pub const STAGE_MAX_AGE_DEFAULT: std::time::Duration = std::time::Duration::from_millis(100);

fn env_bytes(key: &str, unit: u64, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(|n| n.saturating_mul(unit))
        .unwrap_or(default)
}

/// The per-file window, latched on first use like every other knob in
/// `disk.rs` - a benchmark arm sets it in the environment and a mid-run
/// change would make the two halves of one leg incomparable.
pub fn coalesce_cap() -> usize {
    static V: OnceLock<usize> = OnceLock::new();
    *V.get_or_init(|| {
        env_bytes(
            "NZBFAST_WRITE_COALESCE_KB",
            1024,
            COALESCE_CAP_DEFAULT as u64,
        )
        .min(usize::MAX as u64) as usize
    })
}

/// The per-run flush size ([`RUN_CAP_DEFAULT`]). Clamped against the
/// per-file window by [`Caps::sized`], not here.
pub fn run_cap() -> usize {
    static V: OnceLock<usize> = OnceLock::new();
    *V.get_or_init(|| {
        env_bytes(
            "NZBFAST_WRITE_COALESCE_RUN_KB",
            1024,
            RUN_CAP_DEFAULT as u64,
        )
        .min(usize::MAX as u64) as usize
    })
}

/// The largest article the window holds ([`STAGE_MAX_ARTICLE_DEFAULT`]).
/// Clamped against the run cap by [`Caps::sized`], not here.
pub fn stage_max_article() -> usize {
    static V: OnceLock<usize> = OnceLock::new();
    *V.get_or_init(|| {
        env_bytes(
            "NZBFAST_WRITE_COALESCE_MAX_ART_KB",
            1024,
            STAGE_MAX_ARTICLE_DEFAULT as u64,
        )
        .min(usize::MAX as u64) as usize
    })
}

/// The longest a staged byte may sit in RAM ([`STAGE_MAX_AGE_DEFAULT`]).
/// `NZBFAST_WRITE_COALESCE_MAX_AGE_MS` sets it; 0 means no age bound at
/// all, which is a benchmark arm and not a shippable configuration -
/// see [`STAGE_MAX_AGE_DEFAULT`] for the invariant it would give up.
pub fn max_age() -> std::time::Duration {
    static V: OnceLock<std::time::Duration> = OnceLock::new();
    *V.get_or_init(|| {
        std::time::Duration::from_millis(env_bytes(
            "NZBFAST_WRITE_COALESCE_MAX_AGE_MS",
            1,
            STAGE_MAX_AGE_DEFAULT.as_millis() as u64,
        ))
    })
}

/// The process-wide ceiling ([`COALESCE_TOTAL_DEFAULT`]).
pub fn coalesce_total_cap() -> u64 {
    static V: OnceLock<u64> = OnceLock::new();
    *V.get_or_init(|| {
        env_bytes(
            "NZBFAST_WRITE_COALESCE_TOTAL_MB",
            1 << 20,
            COALESCE_TOTAL_DEFAULT,
        )
    })
}

/// Bytes held by every open run in this process, right now. The gauge
/// (`memgauge::Sub::WriteStage`) carries the same figure for the
/// mem-floor report; this one exists so the admission test is a relaxed
/// load rather than a gauge lookup.
static OUTSTANDING: AtomicU64 = AtomicU64::new(0);

pub fn outstanding() -> u64 {
    OUTSTANDING.load(Ordering::Relaxed)
}

fn charge(n: u64) {
    OUTSTANDING.fetch_add(n, Ordering::Relaxed);
    memgauge::add(memgauge::Sub::WriteStage, n);
}

fn release(n: u64) {
    let _ = OUTSTANDING.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_sub(n))
    });
    memgauge::sub(memgauge::Sub::WriteStage, n);
}

/// One contiguous span of held bytes.
struct Run {
    start: u64,
    buf: Vec<u8>,
    /// Arrival order, so eviction can take the run least likely to grow.
    born: u64,
    /// When the run's FIRST byte was staged - the quantity
    /// [`max_age`] bounds. Taken once and never advanced by an
    /// extension, because what the bound protects is the age of the
    /// OLDEST byte still in RAM.
    born_at: std::time::Instant,
    /// This run absorbed another - a hole closed from below. See
    /// [`StagedRun::merged`] for why that is not just bookkeeping.
    merged: bool,
}

impl Run {
    fn end(&self) -> u64 {
        self.start + self.buf.len() as u64
    }
}

/// A run taken out of a [`WriteStage`], on its way to one `pwrite`.
pub struct StagedRun {
    pub start: u64,
    pub buf: Vec<u8>,
    /// The run was built by JOINING two runs across a hole, so its bytes
    /// did not arrive in the order they sit in.
    ///
    /// It is the writer's rolling prefix checksum that cares
    /// (`disk::PrefixHash`, TODO 217). That hash advances only on a
    /// write landing exactly at its hashed end, so a hole FREEZES it and
    /// the resume ledger records the shorter checksummed length - which
    /// is the whole point: bytes past the hash may be contiguous on disk
    /// and no later pass could tell them from a stale copy. A merged run
    /// lands at the hashed end and is contiguous, so observing it would
    /// extend the mark over bytes that arrived out of order - exactly
    /// the defect §217's hard-parts list names, and exactly what
    /// `chase_tests::a_backfilled_hole_is_contiguous_but_never_extends_the_mark`
    /// caught. So a merged run freezes the hash instead of advancing it.
    pub merged: bool,
}

impl StagedRun {
    pub fn end(&self) -> u64 {
        self.start + self.buf.len() as u64
    }
}

impl Drop for StagedRun {
    fn drop(&mut self) {
        // The charge follows the bytes: a run in flight is still held,
        // and it is released exactly when the Vec that holds it dies.
        release(self.buf.len() as u64);
    }
}

/// **THE WINDOW STARTS OFF ON EVERY FILE AND ARMS ITSELF ONLY ON
/// EVIDENCE, AND THIS IS WHAT LETS IT SHIP ON BY DEFAULT (round 44).**
///
/// Coalescing wins exactly when a file receives a RUN'S WORTH OF BYTES
/// INSIDE ONE [`max_age`] BOUND, because that is the condition under
/// which a run reaches [`Caps::run`] instead of being written by the
/// clock with whatever happened to be in it. Measured on round 23's
/// ladder: at loopback article rates a 1 MiB run fills in about 25 ms
/// against a 100 ms bound and the window takes 21,484 positioned writes
/// to 1,043; drop the bound to 20 ms, or run the same leg on a box busy
/// enough to take it from 0.83 s to 3.3 s, and every run is written by
/// age with one article in it and the window's effect is **exactly
/// zero** - it has copied every byte and issued the same writes.
///
/// That is not merely a wasted copy, which is why this is a gate and not
/// a tuning note. A staged byte is in RAM, and a SIGKILL takes it: an
/// article whose placement record LANDED but whose bytes were still in a
/// run refetches on resume. It cannot corrupt anything (`restore`
/// re-reads every replayed article and checks it against the article's
/// crc - that is what `fault_contract`'s slack clause is for), but it is
/// a real cost, and an always-armed window ran that test 1 to 4 articles
/// over a refetch budget whose own comment refuses to be widened by a
/// constant. It is right to refuse: the fix is not to pay the cost more
/// cheaply, it is not to pay it where there is nothing to buy.
///
/// So a file's window stays off until the file has actually delivered
/// [`Caps::run`] bytes inside one bound, and latches on when it has. On
/// a real line - one file receiving of the order of one article per
/// bound - it never arms, and the write path is byte-for-byte the one
/// round 41 shipped. At the rates where the win is real it arms within a
/// single bound and stays armed.
///
/// Arming is LATCHED rather than re-evaluated: a writer lives for one
/// output file, so a job whose rate collapses mid-file keeps a window
/// that its own age bound already reduces to the old behaviour, and a
/// job whose rate picks up gets fresh writers for the files it opens
/// next.
/// One file's open runs.
#[derive(Default)]
pub struct WriteStage {
    runs: Vec<Run>,
    /// Start of the current arming probe, and the bytes this file has
    /// taken since - see the module rule above. `None` until the first
    /// article.
    probe_start: Option<std::time::Instant>,
    probe_bytes: usize,
    /// This file has proved it is fed fast enough for a run to FILL, so
    /// the window is on for it. Latched.
    armed: bool,
    /// Runs TAKEN out of this window and not yet on disk. A run's
    /// `pwrite` deliberately runs with no lock held, so between the take
    /// and the write there is an interval in which those bytes are in
    /// neither place - and an observer that missed them there would read
    /// under a run exactly the way this design exists to prevent. They
    /// stay visible to [`Self::overlaps`] until the write returns, and
    /// `FileWriter`'s flush lock is what makes waiting for one possible.
    inflight: Vec<(u64, u64)>,
    seq: u64,
}

impl WriteStage {
    /// Does an open run, or a run still on its way to disk, share a byte
    /// with `[off, end)`?
    pub fn overlaps(&self, off: u64, end: u64) -> bool {
        self.runs.iter().any(|r| r.start < end && off < r.end())
            || self.inflight.iter().any(|&(s, e)| s < end && off < e)
    }

    /// Bytes this window is holding: every open run plus every run whose
    /// write has not returned. `FileWriter` mirrors it into an atomic so
    /// the "is anything staged?" test costs a load.
    pub fn held(&self) -> u64 {
        self.runs.iter().map(|r| r.buf.len() as u64).sum::<u64>()
            + self.inflight.iter().map(|&(s, e)| e - s).sum::<u64>()
    }

    /// Bytes in OPEN runs alone - what the per-file cap bounds.
    fn open_bytes(&self) -> usize {
        self.runs.iter().map(|r| r.buf.len()).sum()
    }

    /// Take one run out by index; it becomes in-flight until
    /// [`Self::landed`] retires it.
    fn take_at(&mut self, i: usize) -> StagedRun {
        let r = self.runs.remove(i);
        let run = StagedRun {
            start: r.start,
            buf: r.buf,
            merged: r.merged,
        };
        self.inflight.push((run.start, run.end()));
        run
    }

    /// Take out every run whose oldest byte is older than `bound` -
    /// the age rule [`max_age`] documents, evaluated on arrival at this
    /// file rather than by a timer thread.
    ///
    /// A file that stops receiving articles is caught by the completion
    /// rule, by every door, by `flush_staged` and by `Drop`; this is the
    /// bound on a file that keeps receiving them SLOWLY, which is the
    /// only shape in which a run can sit in RAM while the journal lands
    /// a placement record naming its bytes.
    pub fn take_expired(&mut self, bound: std::time::Duration) -> Vec<StagedRun> {
        let now = std::time::Instant::now();
        let mut out = Vec::new();
        loop {
            let Some(i) = self
                .runs
                .iter()
                .position(|r| now.duration_since(r.born_at) >= bound)
            else {
                return out;
            };
            out.push(self.take_at(i));
        }
    }

    /// Arm this window without the probe - the door a test takes.
    ///
    /// A staging test delivers a handful of small articles, which is by
    /// construction below the run cap the arming probe waits for, so
    /// every one of them would otherwise measure the UNARMED path and
    /// the window would have no coverage at all. `FileWriter::coalescing`
    /// calls this, which is what makes "this test means to exercise the
    /// window" one statement rather than a rate simulation.
    #[cfg(test)]
    pub(crate) fn arm_for_test(&mut self) {
        self.armed = true;
    }

    /// Has this file proved fast enough to be worth coalescing? See the
    /// arming rule in this module's header.
    pub fn armed(&self) -> bool {
        self.armed
    }

    /// Take EVERY open run out, in ASCENDING OFFSET order.
    ///
    /// Offset order and not birth order (round 44), and the difference
    /// is the §217 resume mark. `PrefixHash` advances only on a write
    /// landing exactly at its hashed end and FREEZES on one landing
    /// ahead of it, so a flush that writes a file's open runs
    /// oldest-first hands the hash a hole and stops it at the first run
    /// out of sequence - which is how
    /// `e2e_chaseresume::a_forfeited_7z_chase_resumes_its_member_on_disk`
    /// lost its ledger entirely. Ascending, the runs land in the order
    /// the hash wants them and it advances across every one that is
    /// genuinely contiguous with what came before.
    ///
    /// Nothing else cared which order they went in, and ascending is if
    /// anything the friendlier order for the device.
    pub fn take_all(&mut self) -> Vec<StagedRun> {
        self.runs.sort_by_key(|r| r.start);
        let mut out = Vec::with_capacity(self.runs.len());
        while !self.runs.is_empty() {
            out.push(self.take_at(0));
        }
        out
    }

    /// Retire a run whose `pwrite` has returned - success or failure.
    /// A failed write must retire too: the bytes are not coming, and
    /// leaving the span in flight would make every later observer of
    /// that range wait for a write nobody will issue.
    pub fn landed(&mut self, start: u64, end: u64) {
        if let Some(i) = self
            .inflight
            .iter()
            .position(|&(s, e)| s == start && e == end)
        {
            self.inflight.swap_remove(i);
        }
    }

    /// Offer `[offset, offset+data.len())` to the window.
    ///
    /// The caller has already established (under the article gate) that
    /// this span overlaps nothing in flight and nothing staged, so the
    /// only question here is whether the bytes can WAIT.
    ///
    /// Returns `(runs_to_write, staged_incoming)`. Whatever comes back is
    /// written by the caller with no lock held; when `staged_incoming` is
    /// false the caller must ALSO write `data` itself, because there was
    /// no room to hold it. Between the two, every byte offered is always
    /// accounted for - this method never drops one and never merges two
    /// spans that are not adjacent.
    pub fn offer(&mut self, offset: u64, data: &[u8], caps: Caps) -> (Vec<StagedRun>, bool) {
        let (cap, run_cap, max_art) = (caps.file, caps.run, caps.max_article);
        let mut out = Vec::new();
        // THE ARMING PROBE. Until this file has delivered a run's worth
        // of bytes inside one age bound it is not fast enough for a run
        // to fill, so nothing is staged and the article takes the write
        // it would have taken anyway - see the rule above the
        // `probe_start` field for the measurement that chose this.
        if !self.armed {
            let now = std::time::Instant::now();
            match self.probe_start {
                Some(t) if caps.age.is_zero() || now.duration_since(t) < caps.age => {
                    self.probe_bytes += data.len();
                }
                _ => {
                    self.probe_start = Some(now);
                    self.probe_bytes = data.len();
                }
            }
            if self.probe_bytes < run_cap {
                return (out, false);
            }
            self.armed = true;
        }
        // Too big to be worth a copy - see `stage_max_article`, which is
        // where the measurement that chose the bound lives.
        if data.len() >= max_art {
            return (out, false);
        }
        // Room in the process budget, or nothing new may be held at all.
        if outstanding() + data.len() as u64 > coalesce_total_cap() {
            return (out, false);
        }
        // Make room inside this file: evict the oldest run until the
        // incoming span fits under the per-file cap and there is a run
        // slot free for it.
        while self.open_bytes() + data.len() > cap
            || (self.runs.len() >= MAX_RUNS && !self.runs.iter().any(|r| r.end() == offset))
        {
            let Some(oldest) = self
                .runs
                .iter()
                .enumerate()
                .min_by_key(|(_, r)| r.born)
                .map(|(i, _)| i)
            else {
                return (out, false);
            };
            out.push(self.take_at(oldest));
        }
        match self.runs.iter().position(|r| r.end() == offset) {
            Some(mut i) => {
                self.runs[i].buf.extend_from_slice(data);
                charge(data.len() as u64);
                // A gap filled late makes two runs one write. `remove`
                // SHIFTS every later index down, so `i` is corrected
                // rather than shadowed: getting that wrong took the
                // wrong run out below, and off the end of the Vec it
                // panicked the decode worker that was holding the
                // window - which reads as a wedged pool with articles
                // outstanding and no error, not as a crash.
                let end = self.runs[i].end();
                if let Some(j) = self.runs.iter().position(|r| r.start == end) {
                    let tail = self.runs.remove(j);
                    if j < i {
                        i -= 1;
                    }
                    self.runs[i].buf.extend_from_slice(&tail.buf);
                    self.runs[i].born_at = self.runs[i].born_at.min(tail.born_at);
                    self.runs[i].merged = true;
                }
                if self.runs[i].buf.len() >= run_cap {
                    out.push(self.take_at(i));
                }
            }
            None => {
                self.seq += 1;
                let mut run = Run {
                    start: offset,
                    buf: Vec::with_capacity(run_cap.min(data.len() * 4)),
                    born: self.seq,
                    born_at: std::time::Instant::now(),
                    merged: false,
                };
                run.buf.extend_from_slice(data);
                charge(data.len() as u64);
                // The incoming span may itself close a gap from the
                // front, which is the other half of the merge above.
                let end = run.end();
                if let Some(j) = self.runs.iter().position(|r| r.start == end) {
                    let tail = self.runs.remove(j);
                    run.buf.extend_from_slice(&tail.buf);
                    run.born_at = run.born_at.min(tail.born_at);
                    run.merged = true;
                }
                self.runs.push(run);
                let i = self.runs.len() - 1;
                if self.runs[i].buf.len() >= run_cap {
                    out.push(self.take_at(i));
                }
            }
        }
        (out, true)
    }

    #[cfg(test)]
    pub(crate) fn spans(&self) -> Vec<(u64, u64)> {
        let mut v: Vec<(u64, u64)> = self.runs.iter().map(|r| (r.start, r.end())).collect();
        v.sort_unstable();
        v
    }
}

/// One writer's three bounds, resolved once at construction so the
/// clamps between them ("a run cannot exceed the window, an article
/// cannot fill a run") are stated in one place rather than at each use.
#[derive(Clone, Copy)]
pub struct Caps {
    /// Bytes this file may hold across every open run. 0 = the window
    /// is off for this writer and nothing below it runs.
    pub file: usize,
    /// Bytes one run grows to before it is written.
    pub run: usize,
    /// The largest article the window will hold at all.
    pub max_article: usize,
    /// The longest a run may sit in RAM - see [`STAGE_MAX_AGE_DEFAULT`],
    /// which is the journal's own `BATCH_AGE` and is the reason this is
    /// a bound at all. Zero means unbounded, which is a benchmark arm.
    pub age: std::time::Duration,
}

impl Caps {
    /// The knobs, clamped into a consistent set.
    pub fn from_env() -> Caps {
        Caps::sized(coalesce_cap())
    }

    /// [`Caps::from_env`] with the run clamped to the FILE's declared
    /// size (round 44). A run can never be larger than the file it is
    /// in, and saying so here is not tidiness - it is what lets a small
    /// member ARM.
    ///
    /// The arming probe waits for a run's worth of bytes inside one age
    /// bound. Left at the flat 1 MiB run cap, a 512 KB member could
    /// never satisfy that however fast it arrived, so a 2,048-member
    /// shape never armed and the window read 0% where it had been
    /// worth -37%. Clamped, the same shape asks for 512 KB in a bound,
    /// which is a question about its RATE rather than about its size.
    ///
    /// `size` of 0 means undeclared and clamps nothing.
    pub fn for_file(size: u64) -> Caps {
        let mut c = Caps::sized(coalesce_cap());
        if size > 0 {
            c.run = c.run.min(size.min(usize::MAX as u64) as usize).max(1);
            c.max_article = c.max_article.min(c.run);
        }
        c
    }

    /// [`Caps::from_env`] with the per-file window named directly - the
    /// door a test (or a caller that has already decided) takes.
    pub fn sized(file: usize) -> Caps {
        let run = run_cap().min(file.max(1));
        Caps {
            file,
            run,
            max_article: stage_max_article().min(run),
            age: max_age(),
        }
    }

    /// Is the window on for a writer with these bounds?
    pub fn on(&self) -> bool {
        self.file > 0
    }
}
