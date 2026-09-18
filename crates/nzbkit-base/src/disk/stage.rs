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
//!
//! **RUN BUFFERS COME FROM A FREE LIST ([`RunPool`]), AND THAT IS WHAT
//! LETS A RUN RESERVE ITS WHOLE SIZE UP FRONT.**
//! `research/SMALL-ARTICLE-MEMCPY-2026-09-16.md` profiled a 128 KB-article
//! download and found this module twice in the mem-op stacks: 3.78% of
//! on-CPU samples in the staging copy itself, which is what the window
//! IS, and a further **2.03%** in `offer -> RawVec::finish_grow ->
//! realloc -> memmove`, which is not. The second one was the opening
//! capacity: a run used to open at `run_cap.min(data.len() * 4)`, so a
//! 128 KB article opened a 512 KiB run, grew past it and copied half of
//! every run's bytes a second time for nothing. Isolated on the x86 rig
//! it was worth **28% of the window's mem-op cycles**, and the
//! allocation churn underneath it (one `malloc` and one `free` per run,
//! each first touch a page fault) showed up as an **87% swing in minor
//! faults**.
//!
//! Reserving [`Caps::run`] at the open would have fixed the realloc and
//! broken the accounting, which is why the note filed a pool rather than
//! a one-line change: [`charge`] accounts the STAGED BYTES and not the
//! capacity, so runs opened at their full size would have under-reported
//! the memory floor by up to 4x. The pool answers both halves at once.
//! A buffer is minted at [`Caps::run`] + [`Caps::max_article`] - the
//! largest a run can reach before [`WriteStage::offer`] takes it out, so
//! the normal path never reallocs at all - and it is minted against a
//! ceiling of its own ([`run_pool_cap`]), which is the bound the
//! reserved bytes now have and did not have before. The slack is
//! reported rather than hidden: `memgauge::Sub::WriteStage` still
//! carries the staged bytes, exactly as the two caps bound them, and
//! `memgauge::Sub::WriteStageReserve` carries `capacity - len` over
//! every buffer the pool owns, the same split `HoldsReserve` makes for
//! the extractor's holds and for the same reason.
//!
//! At the ceiling the pool hands back nothing and [`WriteStage::offer`]
//! declines to open a run, so the article takes its own positioned write
//! - the same answer as the three bounds above it, and never a failure.

use crate::memgauge;
use crate::sync::MutexExt;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// Per-file window, in bytes across every open run.
/// `NZBFAST_WRITE_COALESCE_KB` sets it; 0 disables coalescing entirely
/// and every article takes the unchanged one-article-one-`pwrite` path,
/// which is what the control arm of every measurement below is.
///
/// **THE DEFAULT IS 0 AGAIN SINCE 17 SEP 2026 - THE WINDOW SHIPS OFF,
/// AND THE FORTNIGHT IT SHIPPED ON IS THE HISTORY BELOW.** It shipped
/// off at 0 from round 41, ON at 4 MiB from round 44, and off again
/// once the measurement reached a filesystem that is not RAM. Round 41
/// built the window,
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
/// When it is armed at all it is bounded three ways - the per-file
/// window here, [`COALESCE_TOTAL_DEFAULT`] across the process, and
/// [`STAGE_MAX_AGE_DEFAULT`] in time - and it was that third bound,
/// plus round 44's arming rule, that made ON look safe rather than
/// merely profitable: both degenerate the window to the old write path
/// in exactly the regime (a real line, one article per file per bound)
/// where round 23 found the write call nowhere near the critical path.
///
/// **WHY IT IS 0 AGAIN.** Round 44 shipped it on against a CALL COUNT
/// and a CONTENTION result and said so in terms - "wall and system time
/// did not move ... must not be reported as a wall win" - and round 45
/// called the feature CPU-only on the wall clock. Neither could see
/// otherwise: their ladders were 1 GiB into a box with tens of GB of
/// RAM, so the writes never reached a device inside the leg. Round 43
/// (`research/WSTAGE-REAL-FILESYSTEM-2026-09-17.md`) put the bytes on
/// ext4 on a device and found a wall LOSS at every article size from
/// 20 KB to 360 KB; the round after it
/// (`research/WSTAGE-WINDOW-DEFAULT-2026-09-17.md`) re-ran that on a
/// binary carrying [`RunPool`] and on a SECOND filesystem - twelve
/// spinning disks under btrfs - and the loss holds on both:
/// `unstaged/staged` wall 0.712 and 0.807 on the SSD at 128 KB and
/// 250 KB articles (the pool is worth 22-28% of the staged arm and
/// none of the sign), 0.940 and 0.933 on the rotational array, against
/// A/A floors of 1.013, 1.091, 1.007 and 0.978. **No configuration
/// anybody has measured is a win**, which is why this is 0 rather than
/// a smaller number or a rule keyed on the medium: the medium-adaptive
/// escape points the window at `Storage::Rotational`, which is the box
/// it was just measured losing on. What the call count buys is real and
/// unchanged - 64,000 positioned writes become 14,861 at 128 KB, worth
/// 18% of cycles on ext4 - so a CPU-bound box may still want
/// `NZBFAST_WRITE_COALESCE_KB=4096`, which restores this exactly.
pub const COALESCE_CAP_DEFAULT: usize = 0;

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
///
/// **THAT LADDER IS RETIRED INSTRUCTIONS ON A RAM DISK, AND BOTH HALVES
/// OF THAT ARE NOW KNOWN TO BE THE WRONG INSTRUMENT FOR IT.** Round 42
/// (`research/SMALL-ARTICLE-MEMCPY-2026-09-16.md`) measured the staging
/// copy costing 15 G cycles while moving instructions 1.3%, so the
/// column this ladder is quoted in cannot see the copy; and its "system
/// seconds flat" is flat because a `pwrite` to tmpfs is nearly free, so
/// the rig priced the copy honestly and the CALLS IT SAVES at
/// approximately zero. Round 43
/// (`research/WSTAGE-REAL-FILESYSTEM-2026-09-17.md`) put the bytes on
/// ext4 on a device and walked the bound in both directions on one
/// binary: unstaged/staged WALL reads 0.791, 0.642, 0.520, 0.526,
/// 0.545, 0.550, 0.539 at 20, 50, 80, 110, 128, 190 and 250 KB, and
/// staging a 360 KB article by RAISING this bound costs 1.827x - the
/// same contrast from the other side. **It does not cross anywhere in
/// the population**, so no value of this constant is the right one, and
/// 256 KiB is kept only because the value that expresses that finding
/// is 0, which is a decision about [`COALESCE_CAP_DEFAULT`] and not
/// about a bound - **and that decision was taken on 17 Sep 2026, in the
/// direction this paragraph pointed**
/// (`research/WSTAGE-WINDOW-DEFAULT-2026-09-17.md`): the window ships
/// off, so this bound now sizes an arm somebody turns on deliberately
/// rather than the shipped write path. That round also rules out the two explanations a
/// reader reaches for first: an arm with 2.8x MORE writes and 22% fewer
/// cycles than the shipped one reads the same wall, so the cost is
/// neither the call count nor the copy's cycles - it is that a staged
/// article's write is DEFERRED, under the per-file `flush_lock`, with
/// the article's gate entry still held. Its binary PREDATES the run
/// buffer pool below, and it argued from that arm that the pool could
/// not move it - an arm that already removes the churn buys no wall.
/// **Measured on the pool, that argument is wrong on magnitude and
/// right on sign**: the same two cells re-run on a post-pool binary
/// read 0.712 and 0.807 rather than 0.545 and 0.539, all of the
/// movement being the staged arm getting 22-28% cheaper. Do not re-tune
/// this number against either ladder without a rig where the write can
/// block.
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

/// Ceiling on the run-buffer CAPACITY [`RunPool`] may own at once,
/// across the free list and every buffer out on loan.
///
/// The same 64 MiB as [`COALESCE_TOTAL_DEFAULT`], and deliberately the
/// same number: this is the process's write-window budget said in the
/// bytes that are actually resident instead of in the bytes that happen
/// to be staged. It is not an increase. Before the pool a run's buffer
/// was as large as the run had grown and nothing bounded the SUM of
/// them - [`COALESCE_TOTAL_DEFAULT`] bounds staged bytes, and sixteen
/// nearly-empty runs on each of a job's thousands of writers is a large
/// number of buffers holding almost nothing - so the worst case was
/// several times this and was reported nowhere.
///
/// `NZBFAST_WRITE_COALESCE_POOL_MB` sets it. 0 disables the pool, which
/// disables staging with it (no buffer, no run), and is therefore a
/// second spelling of the `NZBFAST_WRITE_COALESCE_KB=0` control arm
/// rather than a configuration worth shipping.
pub const RUN_POOL_DEFAULT: u64 = COALESCE_TOTAL_DEFAULT;

/// How many buffers the free list retains. Past it a returned buffer is
/// freed rather than kept, so a job that briefly opened many runs does
/// not pin their memory for the rest of the process.
///
/// 64 because [`RUN_POOL_DEFAULT`] over a default-sized buffer
/// ([`RUN_CAP_DEFAULT`] + [`STAGE_MAX_ARTICLE_DEFAULT`] = 1.25 MiB) is
/// 51, so the slot count is not the binding constraint at the shipped
/// sizes - the byte ceiling is, which is the bound worth stating - while
/// it still bounds a pool of very small buffers (a many-member job whose
/// [`Caps::for_file`] clamps every run down) to something countable.
const RUN_POOL_SLOTS: usize = 64;

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
    // env-default-gate: the 100 ms the doc row states is
    // [`STAGE_MAX_AGE_DEFAULT`], reached as `.as_millis() as u64` - a
    // METHOD CALL on a `Duration` const, which is not an expression the
    // const folder evaluates. The sibling `NZBFAST_WRITE_COALESCE_TOTAL_MB`
    // pairs because its const is a plain integer expression.
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

/// The run pool's own ceiling ([`RUN_POOL_DEFAULT`]). Latched on first
/// use like every other knob here, for the same reason.
pub fn run_pool_cap() -> u64 {
    // env-default-gate: the 64 the doc row states is [`RUN_POOL_DEFAULT`],
    // which is [`COALESCE_TOTAL_DEFAULT`] (`64 << 20`) divided by this
    // call's own `1 << 20` unit - the same arithmetic that pairs the
    // TOTAL_MB row twelve lines up. What defeats the resolver here is
    // only the SPELLING: that one is a multi-line `env_bytes(..)` call
    // and this one sits on one line inside the `get_or_init` closure,
    // which the chain walk does not step into.
    static V: OnceLock<u64> = OnceLock::new();
    *V.get_or_init(|| env_bytes("NZBFAST_WRITE_COALESCE_POOL_MB", 1 << 20, RUN_POOL_DEFAULT))
}

/// Bytes held by every open run in this process, right now. The gauge
/// (`memgauge::Sub::WriteStage`) carries the same figure for the
/// mem-floor report; this one exists so the admission test is a relaxed
/// load rather than a gauge lookup.
///
/// STAGED BYTES and not buffer capacity, which is the whole of the
/// accounting decision the pool forced. This is the quantity
/// [`coalesce_cap`] and [`coalesce_total_cap`] bound, the quantity a
/// SIGKILL loses, and the quantity whose caps round 41 and round 44
/// calibrated; making it a capacity would silently retune all three. The
/// capacity those caps do NOT see is
/// `memgauge::Sub::WriteStageReserve`'s, bounded by [`run_pool_cap`].
static OUTSTANDING: AtomicU64 = AtomicU64::new(0);

pub fn outstanding() -> u64 {
    OUTSTANDING.load(Ordering::Relaxed)
}

/// Say ONCE, on the first file in this process whose window arms, that
/// the window is doing something.
///
/// **A SUMMARY AT THE END OF A RUN CANNOT ANSWER THIS FOR A RUN THAT IS
/// SIGKILLED**, and a SIGKILL with bytes in the window is precisely the
/// case round 44 found a defect in - a staged byte is in RAM while the
/// journal has already landed a record naming it, which is what the
/// per-file arming rule exists to bound. A test that kills run 1 and
/// then grades the resume has no end-of-run line to read, so without
/// this it can only infer that run 1 armed, and an inference is exactly
/// what `e2e_wstage`'s header refuses. This line is IN the killed run's
/// own log.
///
/// One relaxed compare-and-swap on the first arming of the process and a
/// relaxed load on every one after, and only ever reached when the
/// window is configured on at all.
fn announce_first_arming(run_cap: usize) {
    static SAID: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if SAID.swap(true, Ordering::Relaxed) {
        return;
    }
    tracing::info!(
        target: "write-window",
        "write window ARMED on a file: it took a run's worth of bytes ({} KB) inside one age bound",
        run_cap / 1024,
    );
}

/// Spans ever staged, runs ever taken out, and bytes ever staged - the
/// CUMULATIVE counters, which is what separates them from
/// [`outstanding`] and from `memgauge::Sub::WriteStage`.
///
/// **THESE EXIST TO MAKE "THE WINDOW ARMED" OBSERVABLE FROM OUTSIDE THE
/// PROCESS**, and that is a correctness need rather than an instrument.
/// The window ships OFF ([`COALESCE_CAP_DEFAULT`] = 0) and arms itself
/// per file only on a file proved fast enough, so a test that sets
/// `NZBFAST_WRITE_COALESCE_KB` and downloads a handful of articles can
/// run the UNSTAGED path from end to end and pass - a green line over
/// nothing, which is CLAUDE.md's "failing to find is failing". Every
/// other reading of the window is a LEVEL that returns to zero the
/// moment the last run lands ([`outstanding`], the gauge) or is
/// `#[cfg(test)]` and so unreachable from an integration test
/// (`FileWriter::staged_bytes`, [`pool_mints`]). A monotone count of
/// spans that took the staged path is the one figure a test can read
/// AFTER the job and still tell the two paths apart.
///
/// Three relaxed adds on the staged path only; the unstaged path - the
/// shipped one - touches none of them.
static EVER_SPANS: AtomicU64 = AtomicU64::new(0);
static EVER_RUNS: AtomicU64 = AtomicU64::new(0);
static EVER_BYTES: AtomicU64 = AtomicU64::new(0);

/// Spans staged, runs written out of the window, and bytes staged since
/// the process started. `(0, 0, 0)` is the exact statement "this process
/// never coalesced a byte" - see [`EVER_SPANS`] for why a level cannot
/// say that.
pub fn staged_totals() -> (u64, u64, u64) {
    (
        EVER_SPANS.load(Ordering::Relaxed),
        EVER_RUNS.load(Ordering::Relaxed),
        EVER_BYTES.load(Ordering::Relaxed),
    )
}

/// `n` bytes are now STAGED in a pool-owned buffer: they come out of
/// that buffer's slack and into the window's charge.
fn charge(n: u64) {
    OUTSTANDING.fetch_add(n, Ordering::Relaxed);
    EVER_SPANS.fetch_add(1, Ordering::Relaxed);
    EVER_BYTES.fetch_add(n, Ordering::Relaxed);
    memgauge::add(memgauge::Sub::WriteStage, n);
    memgauge::sub(memgauge::Sub::WriteStageReserve, n);
}

/// The reverse, and the PRECONDITION of [`RunPool::give`]: after this
/// the buffer's whole capacity is accounted as slack, whatever
/// `buf.len()` still says, so `give` has one thing to do rather than two.
fn release(n: u64) {
    let _ = OUTSTANDING.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_sub(n))
    });
    memgauge::sub(memgauge::Sub::WriteStage, n);
    memgauge::add(memgauge::Sub::WriteStageReserve, n);
}

/// The process's run buffers: a free list, a byte ceiling, and nothing
/// else. See the module header for why it exists.
///
/// The gauge invariant, which every method here keeps and which is the
/// reason the arithmetic is worth reading: **`WriteStageReserve` is the
/// sum of `capacity - len` over every buffer this pool owns** - the ones
/// on the free list (cleared, so all slack), the ones in open runs, and
/// the ones in runs whose `pwrite` has not returned. `WriteStage` is the
/// `len` half. The two together are the window's resident bytes, exactly.
struct RunPool {
    free: std::sync::Mutex<Vec<Vec<u8>>>,
    /// Capacity bytes this pool owns: free list plus everything on loan.
    /// Kept beside the gauge rather than read out of it because the
    /// ceiling test is on the hot path and the gauge is a report.
    owned: AtomicU64,
    /// How many buffers have been ALLOCATED, ever. The reuse this module
    /// exists for is a statement about this counter and about nothing
    /// else: `owned` is a net figure and reads the same whether a run
    /// took a buffer off the free list or minted one and freed the last.
    mints: AtomicU64,
}

static RUN_POOL: RunPool = RunPool {
    free: std::sync::Mutex::new(Vec::new()),
    owned: AtomicU64::new(0),
    mints: AtomicU64::new(0),
};

impl RunPool {
    /// A cleared buffer of at least `want` capacity, or `None` at the
    /// ceiling - which is not an error: the caller declines to stage and
    /// the article takes the positioned write it would have taken
    /// anyway.
    fn take(&self, want: usize) -> Option<Vec<u8>> {
        {
            // First fit rather than the last slot, because
            // [`Caps::for_file`] clamps a small member's run cap and the
            // free list can therefore hold a mix of sizes. The list is
            // bounded by [`RUN_POOL_SLOTS`] and this runs once per run -
            // once per ~1 MiB of download at the shipped caps.
            let mut free = self.free.lock_ok();
            if let Some(i) = free.iter().position(|b| b.capacity() >= want) {
                return Some(free.swap_remove(i));
            }
        }
        let cap = run_pool_cap();
        // Minting is the only place the ceiling is tested, because it is
        // the only place the pool's owned bytes go up.
        self.owned
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                (v + want as u64 <= cap).then_some(v + want as u64)
            })
            .ok()?;
        self.mints.fetch_add(1, Ordering::Relaxed);
        let buf = Vec::<u8>::with_capacity(want);
        // `with_capacity` may hand back more than was asked for, and the
        // pool owns every byte of what it actually got.
        let extra = buf.capacity() as u64 - want as u64;
        self.owned.fetch_add(extra, Ordering::Relaxed);
        memgauge::add(memgauge::Sub::WriteStageReserve, buf.capacity() as u64);
        Some(buf)
    }

    /// Hand a buffer back. `charged` is the capacity it left the pool
    /// with; the caller has already [`release`]d its bytes, so the whole
    /// of `charged` is currently accounted as slack.
    ///
    /// A buffer whose capacity has MOVED since it was taken is not the
    /// buffer the pool minted - only a merge across a hole can do that,
    /// and [`WriteStage::extend`] resyncs the charge when it does - so
    /// the equality below is a consistency check as much as a policy.
    fn give(&self, mut buf: Vec<u8>, charged: usize) {
        buf.clear();
        if buf.capacity() == charged {
            let mut free = self.free.lock_ok();
            if free.len() < RUN_POOL_SLOTS {
                free.push(buf);
                return;
            }
        }
        self.retire(charged as u64);
    }

    /// Stop owning `n` bytes of capacity: the buffer is being freed
    /// rather than kept.
    fn retire(&self, n: u64) {
        let _ = self
            .owned
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(n))
            });
        memgauge::sub(memgauge::Sub::WriteStageReserve, n);
    }

    /// A buffer on loan reallocated under a merge. The extra capacity is
    /// extra slack, and it is NOT tested against the ceiling: growing a
    /// run the pool has already admitted is not a new admission, and
    /// refusing it here would mean losing bytes that are already staged.
    fn regrew(&self, old: usize, new: usize) {
        let d = new.saturating_sub(old) as u64;
        self.owned.fetch_add(d, Ordering::Relaxed);
        memgauge::add(memgauge::Sub::WriteStageReserve, d);
    }
}

/// Capacity bytes the run pool owns right now - the free list plus every
/// buffer on loan. The tests' door onto [`RUN_POOL`]; production reads
/// the same figure out of `memgauge::Sub::WriteStageReserve` plus
/// [`outstanding`].
pub fn pool_owned() -> u64 {
    RUN_POOL.owned.load(Ordering::Relaxed)
}

/// Run buffers allocated since the process started. See [`RunPool::mints`].
#[cfg(test)]
pub(crate) fn pool_mints() -> u64 {
    RUN_POOL.mints.load(Ordering::Relaxed)
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
    /// The capacity `buf` left [`RUN_POOL`] with, which is what the
    /// pool is owed back. Equal to `buf.capacity()` at all times -
    /// [`WriteStage::extend`] is what keeps it so across the one
    /// realloc a merge can still cause.
    charged: usize,
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
    /// The capacity [`RUN_POOL`] is owed back when this run dies. See
    /// [`Run::charged`].
    charged: usize,
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
        // The BUFFER, though, does not die - it goes back on the free
        // list, which is the whole point of the pool: a run costs one
        // `malloc` on the first ~1 MiB of a job and none afterwards.
        release(self.buf.len() as u64);
        RUN_POOL.give(std::mem::take(&mut self.buf), self.charged);
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

    /// Append to a run's buffer, keeping [`Run::charged`] and the
    /// reserve gauge exact across the one realloc a merge can still
    /// cause. The normal path never reallocs - a pooled buffer is minted
    /// at the largest a run can reach before [`Self::offer`] takes it
    /// out - which is the 2.03% of on-CPU samples the pool exists to
    /// remove.
    fn extend(run: &mut Run, data: &[u8]) {
        let before = run.buf.capacity();
        run.buf.extend_from_slice(data);
        if run.buf.capacity() != before {
            RUN_POOL.regrew(before, run.buf.capacity());
            run.charged = run.buf.capacity();
        }
    }

    /// Absorb `tail` into `run` - a hole closed - and give its buffer
    /// back.
    ///
    /// The bytes stay STAGED, so neither [`charge`] nor [`release`] runs
    /// here: the slack `run` loses is exactly the slack the emptied
    /// `tail` gains, so [`RunPool::give`]'s precondition holds with no
    /// arithmetic at all.
    fn absorb(run: &mut Run, tail: Run) {
        Self::extend(run, &tail.buf);
        run.born_at = run.born_at.min(tail.born_at);
        run.merged = true;
        RUN_POOL.give(tail.buf, tail.charged);
    }

    /// Take one run out by index; it becomes in-flight until
    /// [`Self::landed`] retires it.
    fn take_at(&mut self, i: usize) -> StagedRun {
        let r = self.runs.remove(i);
        EVER_RUNS.fetch_add(1, Ordering::Relaxed);
        let run = StagedRun {
            start: r.start,
            buf: r.buf,
            merged: r.merged,
            charged: r.charged,
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
    ///
    /// **NOTHING ABOVE THE UNIT LEVEL REDS IF YOU DELETE THIS SORT, and
    /// that is measured, not a licence** (17 Sep 2026,
    /// `research/WSTAGE-TAKEALL-ORDER-INTEGRATION-2026-09-17.md`): with
    /// it reverted to birth order the whole e2e suite passes 457/457
    /// with the window forced ON, and so do this crate's 1,629 lib
    /// tests. The reason is that the only reader of a prefix hash is
    /// `extract::resume::settle_resume_ledger`, whose writers are all
    /// `ChaseSink`s driven by `io::copy` - strictly ascending, so one
    /// open run and no order to get wrong. The e2e suite DOES build
    /// windows of out-of-order runs on prefix-hashed writers (mapped and
    /// routed members, three fixtures), and not one of them is ever
    /// asked for its mark. The sort is insurance for the day one is.
    /// The single test that separates the two orders is
    /// `disk::tests::a_window_of_disjoint_runs_is_flushed_low_first_so_the_mark_survives`.
    ///
    /// The 7z attribution above is narrower than it reads: that leg's
    /// sink is sequential, so it holds one run and both orders are the
    /// same order on it - what took it red was the other half of the
    /// same fix, `prefix_hash` not flushing. The RULE is unchanged.
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
            announce_first_arming(run_cap);
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
        //
        // OLDEST-BORN IS A VICTIM RULE, NOT A WRITE ORDER, and the two
        // were conflated once. `born` picks the run least likely to
        // grow, which is what makes the window coalesce at all; the
        // age BOUND is `take_expired`'s and not this loop's. What order
        // these reach disk in is settled downstream, where the whole
        // batch is one list: `FileWriter::flush_runs` sorts it ascending
        // for `PrefixHash`'s sake, which it must, because the run this
        // method appends AFTER the loop (the one the incoming article
        // closed) is frequently lower than everything the loop
        // displaced. Do not re-derive an offset-ordered victim here -
        // it would cost the coalescing this loop exists to protect and
        // still leave the composite batch unsorted.
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
                Self::extend(&mut self.runs[i], data);
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
                    Self::absorb(&mut self.runs[i], tail);
                }
                if self.runs[i].buf.len() >= run_cap {
                    out.push(self.take_at(i));
                }
            }
            None => {
                // A run buffer is minted at the largest a run can REACH,
                // not at the size it is taken out at: `offer` takes a run
                // once it is at or past `run_cap`, and the article that
                // pushes it there can be `max_art - 1` bytes, so this is
                // the capacity at which the normal path never reallocs.
                // Before the pool the opening capacity was
                // `run_cap.min(data.len() * 4)` and a 128 KB article
                // therefore copied half of every run's bytes a second
                // time - see the module header.
                let want = run_cap.saturating_add(max_art).max(data.len());
                // Nothing left in the pool's budget: decline, exactly as
                // the three bounds above do, and the article takes its
                // own positioned write.
                let Some(buf) = RUN_POOL.take(want) else {
                    return (out, false);
                };
                self.seq += 1;
                let charged = buf.capacity();
                let mut run = Run {
                    start: offset,
                    buf,
                    born: self.seq,
                    born_at: std::time::Instant::now(),
                    merged: false,
                    charged,
                };
                Self::extend(&mut run, data);
                charge(data.len() as u64);
                // The incoming span may itself close a gap from the
                // front, which is the other half of the merge above.
                let end = run.end();
                if let Some(j) = self.runs.iter().position(|r| r.start == end) {
                    let tail = self.runs.remove(j);
                    Self::absorb(&mut run, tail);
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

impl Drop for WriteStage {
    fn drop(&mut self) {
        // A window dropped with runs still open is not a shipped path -
        // `FileWriter` writes them out at every door and on its own
        // `Drop` - but a caller driving `offer` directly can do it, and
        // both of the window's process-wide counters would otherwise
        // carry those bytes for the rest of the run. Returning them here
        // makes the leak impossible rather than merely unusual; the
        // BYTES are still lost, which is the caller's business and not
        // this module's.
        for r in self.runs.drain(..) {
            release(r.buf.len() as u64);
            RUN_POOL.give(r.buf, r.charged);
        }
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
