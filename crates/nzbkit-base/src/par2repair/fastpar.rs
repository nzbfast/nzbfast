//! Fast PAR mode: the user-facing NTT control, the dispatch gates that
//! decide whether a repair shape gets the transform, and the
//! trip-breaker plus fold retry that make a misbehaving NTT unable to
//! surface a failed repair the fold would have completed. Its own file
//! for the reason `par2repair/linalg.rs` and `par2repair/volshape.rs`
//! are: one subject per file (TODO 106, the code-quality refactor).
//!
//! One subject at three moments, which is why it is one module: before
//! a repair starts ([`resolve_syndrome_path`], the gates and the
//! budget), while it runs ([`NttProbe`], filled by the repair drivers),
//! and after it has failed ([`run_with_ntt_fallback`], the retry, and
//! [`record_ntt_divergence`], the telemetry that trips the breaker).
//! The parent keeps [`SyndromePath`] and the reconstruction types
//! beside their own docs.

use super::{RepairError, SyndromePath};
use crate::sync::MutexExt;
use tracing::warn;

// --- fast PAR mode (user-facing NTT control) -------------------------------
//
// The daemon's "fast par mode" setting lands here as a process-global
// flag; the repair drivers below pair it with a verify-failure fold
// retry and a trip-breaker so a misbehaving NTT can never surface a
// failed repair the fold would have completed.

/// Default for "fast par mode" across EVERY entry point - the daemon's
/// `fast_par` setting AND non-daemon paths (the CLI's `get` repair, or
/// any other embedder that never calls [`set_fast_par_enabled`]). ON
/// since 2026-07-31: the verify-failure fold retry makes
/// wrong output impossible to ship, the trip-breaker covers live
/// disable, and the RAM/cgroup-scaled retention budget gates small
/// machines onto the fold up front. Lives here (not in the daemon)
/// precisely so the CLI cannot drift from the daemon default.
pub const FAST_PAR_DEFAULT: bool = true;

/// The "fast par mode" flag ([`FAST_PAR_DEFAULT`] until an embedder
/// overrides it; the daemon mirrors its saved setting in at startup).
/// `NZBFAST_NTT` in the environment overrides this in both directions.
static FAST_PAR_ENABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(FAST_PAR_DEFAULT);
/// Trip-breaker: set when a repair that used the NTT path failed
/// whole-file verification (or panicked) and the fold retry ran. Once
/// tripped, setting-driven dispatch prefers the fold for the rest of
/// the process; the explicit env override still works.
pub(super) static FAST_PAR_TRIPPED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static NTT_DIVERGENCES: std::sync::Mutex<Vec<NttDivergence>> = std::sync::Mutex::new(Vec::new());

/// Set the process-wide "fast par mode" flag (the daemon's setting).
pub fn set_fast_par_enabled(on: bool) {
    FAST_PAR_ENABLED.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// Whether a verified NTT divergence has tripped the breaker this
/// process (see [`NttDivergence`]).
pub fn fast_par_tripped() -> bool {
    FAST_PAR_TRIPPED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Field telemetry for one NTT divergence: a repair that ran the NTT
/// syndrome path and then failed whole-file verification (or panicked)
/// where the fold retry was invoked. Both paths are bit-identical by
/// construction, so every one of these is an NTT bug; the geometry here
/// is what a reproduction needs.
#[derive(Debug, Clone)]
pub struct NttDivergence {
    /// True when the NTT attempt panicked rather than producing output
    /// that failed verification.
    pub panicked: bool,
    /// Missing-block count (syndrome rows).
    pub(crate) m: usize,
    /// Present source slices fed to the transform (0 when unknown, e.g.
    /// a panic before the transform ran).
    pub(crate) n_present: usize,
    pub(crate) block_size: usize,
    /// Largest recovery exponent used.
    pub(crate) max_exp: u32,
    /// What was being repaired (set directory or first file name).
    pub(crate) context: String,
}

/// Drain the recorded divergence events (the daemon appends them to the
/// job log / history).
pub fn take_ntt_divergences() -> Vec<NttDivergence> {
    // Poison-proof: this log must never turn a caught panic elsewhere
    // into a new one (the push/take critical sections cannot panic).
    std::mem::take(&mut NTT_DIVERGENCES.lock_ok())
}

/// Per-attempt observation of the NTT dispatch, filled by the repair
/// drivers so the retry wrapper can tell an NTT failure from an
/// ordinary one.
#[derive(Default)]
pub(super) struct NttProbe {
    /// The dispatcher selected retention at construction (the NTT was
    /// live when the attempt ended, even if it ended in a panic).
    pub(super) selected: bool,
    /// The transform actually computed the syndromes (no mid-flight
    /// fold fallback).
    pub(super) used: bool,
    pub(super) m: usize,
    pub(super) n_present: usize,
    pub(super) block_size: usize,
    pub(super) max_exp: u32,
    pub(super) context: String,
}

fn record_ntt_divergence(probe: &NttProbe, panicked: bool) {
    FAST_PAR_TRIPPED.store(true, std::sync::atomic::Ordering::Relaxed);
    let d = NttDivergence {
        panicked,
        m: probe.m,
        n_present: probe.n_present,
        block_size: probe.block_size,
        max_exp: probe.max_exp,
        context: probe.context.clone(),
    };
    // Warning level on purpose: the fold and the NTT are bit-identical
    // by construction, so this is an NTT bug by definition, not noise.
    warn!(
        target: "par2",
        "WARNING: NTT syndrome path diverged ({}) - retrying with the fold path \
         (m={}, n_present={}, block_size={}, max_exp={}, context={})",
        if panicked {
            "panic"
        } else {
            "repaired output failed verification"
        },
        d.m,
        d.n_present,
        d.block_size,
        d.max_exp,
        d.context,
    );
    NTT_DIVERGENCES.lock_ok().push(d);
}

// Armed by `force_one_retry`: the next `run_with_ntt_fallback` ON
// THE ARMING THREAD runs its attempt twice.
//
// Thread-local, and that is the whole point. It was a process-wide
// `AtomicBool` until 9 Sep 2026, on the stated ground that "callers
// serialize themselves (the census tests hold the recorder's
// process-wide lock)". They do not: that lock serializes the census
// tests against each other, not against every OTHER repair test in the
// binary, and `run_with_ntt_fallback` is on the path of most of them.
// So any concurrent repair could reach the `swap` first and eat a flag
// it never armed - the owner then saw ONE attempt where it asserted
// two, and the thief silently ran a second one. Reproduced on
// `cargo test -p nzbkit-base --release --lib --features test-support
// par2` at 618ca2042: two failures, `a_fallback_retry_has_two_attempt_ids`
// (the robbed owner, every time) plus whichever unrelated repair
// happened to steal it that run - a DIFFERENT innocent test in each of
// two independent runs, which is the signature. Both pass serially, so
// the gate read green under `--test-threads=1` and under nextest, which
// gives every test its own PROCESS and cannot see this class at all.
//
// `run_with_ntt_fallback` runs its attempt closure on the calling
// thread - it is a plain wrapper, not a spawn - so the arming thread
// IS the consuming thread for every caller, and the seam keeps working
// unchanged while becoming unstealable.
#[cfg(any(test, feature = "test-support"))]
thread_local! {
    /// Armed by [`force_one_retry`] for THIS thread; see above.
    static FORCED_RETRY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Make the next repair attempt ON THIS THREAD run twice, as an NTT
/// verify-failure retry would. A test seam and nothing else: no
/// divergence is recorded and no warning is printed, because nothing
/// diverged.
#[cfg(any(test, feature = "test-support"))]
pub fn force_one_retry() {
    FORCED_RETRY.with(|f| f.set(true));
}

/// Run a repair attempt, retrying once on the fold path when the NTT
/// was live and the attempt ended in a whole-file verification failure
/// or a panic. A non-NTT attempt's panic is re-raised untouched; every
/// other error passes through.
pub(super) fn run_with_ntt_fallback<T>(
    initial: SyndromePath,
    mut attempt: impl FnMut(SyndromePath, &mut NttProbe) -> Result<T, RepairError>,
) -> Result<T, RepairError> {
    let mut probe = NttProbe::default();
    // catch_unwind is the only boundary that lets the fold retry run
    // after an NTT panic: the transform's scoped workers propagate a
    // panic through finish(), and without the catch it would abort the
    // whole repair the fold could have completed. AssertUnwindSafe is
    // sound here because the retry rebuilds every missing block from
    // scratch and re-verifies every file, so no state the panicking
    // attempt half-wrote is ever trusted.
    let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        attempt(initial, &mut probe)
    }));
    let (diverged, panicked) = match &first {
        Ok(Err(RepairError::VerifyFailed(_))) => (probe.used, false),
        Err(_) => (probe.selected, true),
        _ => (false, false),
    };
    if !diverged {
        // A TEST-ONLY second attempt, armed by `force_one_retry`
        // above. It runs the retry without recording a divergence,
        // which is what lets the retention admission census's
        // validation case "a fallback retry has two attempt IDs" be a
        // real repair rather than a hand-driven pair of ids. Only over
        // an `Ok` first attempt: discarding a caught PANIC here would
        // swallow it, and a seam is never worth that.
        #[cfg(any(test, feature = "test-support"))]
        if first.is_ok() && FORCED_RETRY.with(|f| f.replace(false)) {
            return attempt(SyndromePath::Fold, &mut NttProbe::default());
        }
        return match first {
            Ok(r) => r,
            Err(p) => std::panic::resume_unwind(p),
        };
    }
    record_ntt_divergence(&probe, panicked);
    attempt(SyndromePath::Fold, &mut NttProbe::default())
}

/// Conservative static gates. The Stage 0/1 hot-loop sweeps
/// (research/NTT-STAGE0-crossover-2026-07-30.md) put the crossover
/// near m~260-420 on the measured ARM boxes and asked for an
/// end-to-end revisit; that revisit ran twice, on both machine
/// classes, and it did NOT push the crossover up the way the original
/// margin assumed:
///
/// - 32-core Mac15,14 (research/NTT-CROSSOVER-E2E-2026-08-11.md):
///   end-to-end `repair_dir`, crossover m~256-300.
/// - 20-core Mac13,2 / M1 Ultra, the class the Stage 0 comment cites
///   (research/NTT-CROSSOVER-E2E-20CORE-2026-08-11.md): 126 byte-gated
///   legs, three reps, crossover m~288 in both CPU and wall, with the
///   fold linear at 0.150 CPU-s per missing block against a nearly
///   flat NTT.
///
/// So `NTT_MIN_MISSING` became 384, not the original 512: ~1.3x above
/// the measured crossover on both ARM boxes, while no longer folding
/// the 384-511 band, which cost up to 1.4 s wall / 25 CPU-s per repair
/// on the 20-core box.
///
/// Then the x86 sweep, 2 Sep 2026 (research/PAR2-PERF-AUDIT-2026-09-02.md
/// section 7): the same 64 KiB / 16,384-block corpus damaged at m =
/// 96..512, transform forced on and off, best of two, four boxes -
///
/// - M3 Ultra 32c (NEON):            crossover ~290 (fold 0.76 vs NTT 0.69 s at 320)
/// - Zen 4 EPYC 8 vCPU (AVX-512):     crossover ~200 (2.35 vs 1.81 at 320)
/// - i5-10600KF 6c (AVX2, no GFNI):   crossover ~330 (5.95 vs 6.06 at 320)
/// - Core Ultra 9 16t (GFNI laptop):  crossover ~400 (10.9 vs 12.3 at 320)
///
/// A uniform 320 is inside noise of the fold on the AVX2 desktop,
/// takes back 10-30% of the 320-383 band on the M3 and the Zen 4
/// server, and costs the laptop up to 12% at m=320 (its whole leg is
/// storage-bound, which lifts the transform's flat time with it);
/// 256 would cost the AVX2 desktop 27% and the M3 12% at that count,
/// so it stays. One constant is right everywhere only to ~10%. The
/// budget is an OOM guard, not a speed one; the present-count gate is
/// [`NTT_MIN_PRESENT`], swept on its own 7 Sep 2026.
///
/// **Re-measured 15 Sep 2026 with the conjugate-paired leaf in, on both
/// x86 GFNI classes it still covers, and NOT split**
/// (`research/NTT-ROW-GATE-GFNI-AVX512-2026-09-15.md`). NEON and nibble
/// had moved to their own constants on 5 Sep; GFNI-256 (fan-in 6) and
/// AVX-512 GFNI (fan-in 12) had not been measured since. Corpus resident
/// (no `-m`), forced transform against fold, whole-process CPU-seconds,
/// two reps each run as an ABBA quartet with an A/A copy of both arms:
///
/// | class, part, pool | 64 KiB, n = 16,384 | 1 MiB, n = 4,096 |
/// |---|---:|---:|
/// | GFNI-256, Core Ultra 9 386H, `-t4` | ~286-309 | ~361-376 |
/// | GFNI-256, Core Ultra 9 386H, `-t16` | ~256-273 | ~354-360 |
/// | AVX-512, EPYC 9354P 8 vCPU guest, `-t4` | ~234 | - |
/// | AVX-512, EPYC 9354P 8 vCPU guest, `-t8` | ~202 | ~323 |
///
/// **The shape moves the crossover further than the class does**, so a
/// per-class constant would key on the smaller difference. At 64 KiB the
/// AVX-512 part wants ~256 (the transform wins all four readings from
/// there, by 6-11%) and GFNI-256 sits on 320 (a tie on four threads, a
/// 12-13% transform win on sixteen). At 1 MiB both want 320 or more: on
/// AVX-512 the fold wins by ~11% at 256 and ties at 320, and on GFNI-256
/// the fold still wins by 4-8% at 320. Lowering the AVX-512 arm to 256
/// would buy 5-17% over m = 256..319 on the small-block shape and pay
/// about the same over the same band on the large-block one, which is the
/// nearer of the two to a real posting's recovery set; 320 is the
/// compromise between them, within the ~10% this constant was already
/// said to hold to. Two traps for the next calibration: the ~400 above
/// was the storage-bound WALL reading it was flagged as (wall on the
/// 64 KiB sweep is 321-333), and 14 Sep's leaves-over-fold ratio of
/// 355-375 overstated the crossover because it leaves out the fold's own
/// fixed per-leg costs. The rise with block size is the same direction
/// the 15 Sep work-floor grid found on the x86 nibble arm (up 1.31x from
/// 128 KiB to 1 MiB at m = 1,024, written at [`NTT_MIN_WORK`]), where
/// NEON's had only ever moved down. **It is the block size, not `n`**:
/// on the Core Ultra at `-t4`, quartering `n` at a fixed 64 KiB block
/// moves the crossover ~10-25 rows (to ~312), quadrupling the block at a
/// fixed n = 16,384 moves it ~50 (to ~344, where 320 already costs
/// 4-5%). That rise is followed by a block-size clause on the GFNI-256 arm,
/// [`NTT_MIN_MISSING_GFNI256_LARGE_BLOCK`], not by a per-class constant;
/// the 4-5% at 256 KiB did not survive a quiet re-read and that clause's
/// docstring says why it starts at 1 MiB.
pub(crate) const NTT_MIN_MISSING: usize = 320;

/// The row gate on the GFNI-256 arm (fan-in 6) at blocks of 1 MiB and up,
/// keyed on the block size the way [`default_stripe_words`] keys the
/// nibble stripe. Measured 15 Sep 2026 on the Core Ultra 9 386H, one
/// binary (origin/main `71d930ee0`), corpus resident, forced transform
/// against fold, whole-process CPU, two reps of an ABBA quartet with an
/// A/A copy of each arm, every leg SHA-256 gated
/// (`research/NTT-ROW-GATE-GFNI-AVX512-2026-09-15.md`, section "The
/// block-size clause"). CPU crossover at n = 16,384:
///
/// | block | `-t4` | `-t16` | F/T at m = 320, `-t4` / `-t16` |
/// |---|---:|---:|---|
/// | 64 KiB | ~293 | ~272 | 1.05 / 1.13 (transform) |
/// | 256 KiB | ~325-338 | ~308 | 0.98-1.00 / 1.02 (tie) |
/// | 1 MiB | ~408 | ~342 | 0.88 / 0.96 (fold, both past A/A) |
///
/// **Why 1 MiB and not 256 KiB.** The first read of the 256 KiB shape
/// (~344, 320 costing 4-5%) came off a single `-t4` round; re-read back
/// to back on the old and the current binary on a quiet box it crosses at
/// ~325 and ~338, a 0-2% band that clears no floor, so the rise below
/// 1 MiB is inside the ~10% this family holds to and 320 keeps it.
/// **Why 352 and not 384.** At 1 MiB the fold wins m = 320 by 12% on
/// four threads and 4% on sixteen, but sixteen threads cross at ~342 and
/// the transform wins m = 384 there by 8%; 352 sits 1.03x past that
/// crossover and 0.86x of the four-thread one, so neither pool is handed
/// a band where the other arm wins by more than its noise.
///
/// **Not on AVX-512 GFNI (fan-in 12)**: its only 1 MiB reading, a KVM
/// guest at `-t8`, crosses at ~323, so the clause would cost it the band
/// this buys GFNI-256; a bare-metal part is owed before that arm moves.
/// **Not on NEON - and the REASON below no longer reads as settled.** The
/// 15 Sep work-floor grid put NEON's 1 MiB crossover BELOW its 128 KiB one
/// (0.63-0.80x, [`NTT_MIN_WORK`]), and the 11 Sep large-block row round
/// left [`NTT_MIN_MISSING_NEON`] unchanged, which was read at the time as
/// NEON's block-size effect pointing the other way. **Two forced-arm 2x2s
/// on 17 Sep 2026 measured it pointing the SAME way as this clause, on
/// both NEON parts they ran on**: between 64 KiB and 4,429,188-byte
/// blocks a Snapdragon X2's crossover rises 130 -> 218 on the repair and
/// 171 -> 225 on the create
/// (`research/NTT-NEON-ROW-GATE-SNAPDRAGON-2026-09-17.md`), and an M3
/// Ultra's rises 133 -> 158 and 133 -> 176 over the same span
/// (`research/NTT-NEON-LARGE-BLOCK-APPLE-2026-09-17.md`), both on one
/// binary with an A/A copy of each arm at every rung. So NEON is not the
/// exception that sentence made it, and a reader must not take it as one.
///
/// **It still buys NEON no clause, and now for a measured reason rather
/// than an absent measurement**: the two parts' MAGNITUDES differ far
/// more than their signs. At 4,429,188 bytes the M3 wants a gate at or
/// below 176 and the Snapdragon one at or above 218, so 192 is on the
/// right side for the Apple part and the wrong side for the Qualcomm one
/// and no single number is on both. A shared 224 from 512 KiB up - the
/// clause this shape asks for - would buy the Snapdragon 6-11% over a
/// 13-to-33-row band and cost the M3 16-31% over a 48-to-74-row one.
/// [`NTT_MIN_MISSING_NEON`] therefore stays at 192 on the strength of
/// this, not in spite of it.
///
/// Blocks past 1 MiB are unmeasured ON THIS CLASS; the rise is in the
/// direction that makes 352 conservative there. The rule that a fold
/// change moves it is at [`NTT_MIN_PRESENT`].
pub(crate) const NTT_MIN_MISSING_GFNI256_LARGE_BLOCK: usize = 352;

/// The row gate on aarch64 (NEON), re-measured 5 Sep 2026 with the
/// conjugate-paired leaf in: the M3 Ultra's crossover moved from ~290
/// rows to ~160 on both the repair (heavy 64 KiB set, m blocks zeroed:
/// forced transform 0.56-0.57 s vs fold 0.64-0.65 at m = 192, 0.61-0.63
/// vs 0.92-0.93 at 256; the fold still wins at 128, 0.52 vs 0.56-0.57)
/// and the create (512 KiB / ~2,150 inputs: 0.57 vs 0.63-0.65 at 192
/// rows, 0.66 vs 0.84 at 256). 192 is 1.2x past the crossover.
///
/// **Re-measured 11 Sep 2026 on the large-block shape and UNCHANGED**
/// (`research/NTT-NEON-ROW-GATE-LARGE-BLOCK-2026-09-11.md`, 264 legs,
/// every one SHA-256 gated). A 10 GiB / 768,000-byte / 13,990-block
/// repair had read a wall crossover near 265 against a CPU crossover
/// near 158, which made this constant look 1.4x early. It was the box:
/// that reading came from a host carrying 352 orphaned CPU spinners.
/// Idle, wall and whole-process CPU agree to within one rung on all
/// three aarch64 parts in the fleet - **155/153 on a 20-thread M1
/// Ultra, 176/164 on a 32-thread M3 Ultra, 212/210 on an 18-thread M5
/// Max** - so 192 sits INSIDE the spread, 1.24x and 1.09x past two of
/// them and 0.91x of the third. It is wrong only in a 16-to-37-row
/// band worth 4-13% of a 4-6 s repair, and every part agrees past
/// ~250 rows. Moving it to 1.2x the worst part (256) would hand the
/// other two bands where the fold is up to 39% and 23% slower.
///
/// Two things that round pins for whoever calibrates this next.
/// **Thread count does not order the crossovers** - 20, 32 and 18
/// threads give 155, 176 and 212 - because more threads cheapen the
/// fold as well as the transform, so the ratio that sets the crossover
/// barely moves. And **the transform phase is FLAT in `m` by
/// construction**, so a transform column that is not flat is measuring
/// the host, not the shape, and its MINIMUM is the best estimate of
/// the idle cost: 2.10-2.18 s across 30 idle legs on the 32-thread
/// part, against 2.21-4.85 s for the same legs on the same box under
/// other work.
pub(crate) const NTT_MIN_MISSING_NEON: usize = 192;

/// The row gate on the x86 nibble arms (AVX2 without GFNI), same day,
/// same sweep on an i5-10600KF (6c/12t, the transform on its then
/// six-thread pool): repair (heavy 64 KiB set) forced transform
/// 1.99-2.08 s vs fold 2.47-2.52 at m = 192, 2.09-2.14 vs 3.18 at 256,
/// the fold still ahead at 128 (1.90 vs 2.08-2.11); create at 512 KiB /
/// ~2,150 inputs 2.65-2.73 vs 2.49-2.52 at 192 rows (a 6% loss) and
/// 2.79-2.83 vs 3.43-3.49 at 256, at 64 KiB / ~17,000 inputs 2.03-2.04
/// vs 2.44-2.57 already at 192. 256 clears every measured shape. The
/// GFNI-256 and AVX-512 arms were re-measured with the paired leaf on
/// 15 Sep 2026 and keep [`NTT_MIN_MISSING`]; its docstring says why.
pub(crate) const NTT_MIN_MISSING_NIBBLE: usize = 256;

/// The row gate this build runs under for `block_size`:
/// [`NTT_MIN_MISSING_NEON`] on aarch64, and on x86 whatever
/// [`ntt_min_missing_for`] answers for the selected kernel's fan-in (as
/// the back-substitution gate keys on it).
///
/// This is the VERTICAL asymptote `a/c` of the one crossover
/// [`NTT_MIN_PRESENT`] carries the horizontal end of, so the fold's
/// cost is its denominator too and a fold change moves it the same
/// way. The rule and what it costs to forget it are written out once,
/// at [`NTT_MIN_PRESENT`]; do not re-derive it here.
pub(crate) fn ntt_min_missing(block_size: usize) -> usize {
    if cfg!(target_arch = "aarch64") {
        NTT_MIN_MISSING_NEON
    } else {
        ntt_min_missing_for(crate::gf16::multi_fold_width(), block_size)
    }
}

/// The x86 row gate as a pure function of the fold kernel's fan-in and the
/// block size, so the tests pin every arm without the host's CPU:
/// [`NTT_MIN_MISSING_NIBBLE`] at fan-in 4,
/// [`NTT_MIN_MISSING_GFNI256_LARGE_BLOCK`] at fan-in 6 from 1 MiB blocks,
/// [`NTT_MIN_MISSING`] for everything else (GFNI-256 under 1 MiB, AVX-512
/// GFNI at fan-in 12, and the single-source path at 0).
pub(crate) fn ntt_min_missing_for(fan_in: usize, block_size: usize) -> usize {
    match fan_in {
        4 => NTT_MIN_MISSING_NIBBLE,
        6 if block_size >= 1 << 20 => NTT_MIN_MISSING_GFNI256_LARGE_BLOCK,
        _ => NTT_MIN_MISSING,
    }
}
/// How far the recovery exponents may SPREAD, as work per row the
/// transform actually EVALUATES: `exp_span * NTT_MIN_WORK_PER_ROW <
/// n_present * n_missing`, with a floor at `exp_span < n_missing` so a
/// set posted whole is always admitted.
///
/// **Why a span gate exists at all.** A PAR2 set posted whole carries
/// consecutive exponents, so `exp_span + 1 == n_missing` and only the
/// floor arm is ever reached. It fires when recovery volumes are
/// MISSING - the ordinary Usenet case, where what survives is a union
/// of ranges. The transform then evaluates every row in the range it is
/// handed (`plan_count = exp_span + 1` for a set that does not compact,
/// reconstruct.rs), while the fold only ever computes the `n_missing`
/// rows anyone wants. The span is therefore the one axis on which the
/// transform pays for rows nobody asked for and the fold's cost does
/// not move at all.
///
/// **It has a second role since 5 Sep 2026**, when
/// `ntt_worker_arenas(block_size, exp_span + 1)` started pricing the
/// per-worker arenas off the same number, so this gate caps the memory
/// as well as the shape. Measured on the M3 (peak RSS, 2,048 present at
/// 64 KiB): 750 MB at `k = 1` and 1,444 MB at `k = 8`, i.e. the arena
/// roughly quadruples across the band, and that growth is subtracted
/// from the corpus budget before the retention clause sees it. So a
/// span this gate admits can still be refused by
/// [`ntt_retention_admits`], which folds - never OOMs.
///
/// **This was a flat `NTT_MAX_EXP_FACTOR = 3` until 8 Sep 2026** - a
/// bare `const` from `f40bcf99e` (30 Jul) that got its first
/// measurement on 7 Sep (`a11136216`) and kept its value, because a
/// flat constant had nothing better available to it. That round found
/// the crossover MOVES with the present count and could not say how: it
/// had three present points at one `m`. This is the present axis swept
/// at fixed `m` on both boxes, which is what it takes.
///
/// **The shape, and it predicts rather than fits.** The fold costs
/// `c . n_present . m`; the transform costs `a . n_present` for the
/// leaves plus `b . exp_span` for the rows it evaluates. Setting them
/// equal and dividing by `exp_span`, the crossover sits at a constant
/// `n_present . n_missing / exp_span` - work per EVALUATED row, which
/// is [`NTT_MIN_WORK`]'s quantity with the span in the denominator
/// instead of the row count. That is one constant, not a fitted curve,
/// and the sweep is what it is read from rather than what it is fitted
/// to.
///
/// **Swept 8 Sep 2026 on both boxes** through `par2_ntt_bench`'s
/// `NZBFAST_NTT_EXP_SPAN`, which spreads the exponents IRREGULARLY (an
/// arithmetic progression relabels to a consecutive set in
/// [`exponent_span`], so a stride would have measured nothing), 5-9
/// repetitions a point, every leg's outputs byte-compared between the
/// paths and its `needed=` read off the `ntt syndromes` line so a
/// declined plan is never read as a loss. `k` is `exp_span / n_missing`
/// at the crossover and `W/row` is `n_present / k` - the quantity the
/// gate is set from:
///
/// | box | m | n_present | k | W/row |
/// |---|---:|---:|---:|---:|
/// | i5-10600KF | 400 | 1,312 | **2.20** | **596** |
/// | i5-10600KF | 400 | 2,048 | 3.59 | 571 |
/// | i5-10600KF | 400 | 3,072 | 6.41 | 479 |
/// | i5-10600KF | 400 | 4,096 | 9.24 | 443 |
/// | i5-10600KF | 400 | 6,144 | 27.9 | 220 |
/// | M3 Ultra | 400 | 1,312 | 3.15 | 416 |
/// | M3 Ultra | 400 | 1,600 | 3.85 | 416 |
/// | M3 Ultra | 400 | 2,048 | 5.62 | 364 |
/// | M3 Ultra | 400 | 2,816 | 9.02 | 312 |
/// | M3 Ultra | 400 | 4,096..15,984 | 54..over 64 | under 100 |
/// | M3 Ultra | 2,048 | 320 | 1.4-1.9 | 168-230 |
/// | M3 Ultra | 2,048 | 768 | 1.77 | 434 |
/// | M3 Ultra | 2,048 | 1,536 | 21.5 | 71 |
///
/// The whole round, its two rigs, the raw legs, the three noisy points
/// and the discriminator that separates a present-keyed rule from a
/// work-keyed one is
/// `research/NTT-EXP-SPAN-PRESENT-AXIS-2026-09-08.md`.
///
/// **768 is 1.29x past the worst measured**, the i5's 596 at the lowest
/// present count [`NTT_MIN_PRESENT`] and [`NTT_MIN_WORK`] admit at
/// m = 400, which is the margin the rest of this family carries; it is
/// 1.77x past the M3's worst. One constant and not a per-arch pair for
/// the reason written out at [`NTT_MIN_PRESENT`]: the margin already
/// covers the gap. Since 15 Sep 2026 the x86 nibble work floor
/// ([`NTT_MIN_WORK_NIBBLE`]) refuses that 1,312-present point itself -
/// it asks for 1,475 present at m = 400 - so on that arm the worst span
/// point the gate can still reach is 2,048 present's 571, 1.34x under
/// 768. The value is unchanged.
///
/// **What it fixes.** The flat 3 was above the crossover at BOTH
/// corners the present gate admits, which is to say it had negative
/// margin exactly where a gate has to be right: at 1,312 present /
/// m = 400 the i5 lost 11% (ratio 0.90 at `k = 3`), and at the
/// [`NTT_MIN_PRESENT`] floor the M3 lost 5-8% at 320 present /
/// m = 2,048 (0.92-0.95) and 13% at 320 / m = 4,096 (0.87) - corners
/// the 7 Sep round never reached, and on the FAST box, which is why
/// "the i5 is the worst case" did not catch them. All three are now
/// refused into the fold.
///
/// **What it takes back.** Above 2,304 present the rule is strictly
/// more permissive than 3, and it keeps widening: 3.7x the row count at
/// 2,816 present, 8x at 6,144, 20.8x at 15,984 - where the M3 is still
/// 1.75x ahead of the fold at `k = 64` and had not crossed at the
/// widest span the transform can represent. That is the "~2x wins at
/// large present counts" the 7 Sep round measured and could not act on.
///
/// The cost is a narrow band between the new bound and the old 3 for
/// 768..2,304 present, where both boxes do still win: at 2,048 present
/// / m = 400 the M3 wins 1.26x at `k = 3` and the rule stops at 2.67.
/// That is the 1.29x margin being paid for, and it is the trade the
/// present gate makes too.
pub(crate) const NTT_MIN_WORK_PER_ROW: usize = 768;

/// The present-count gate, and the reason it is now TWO clauses.
///
/// `NTT_MIN_PRESENT` was minted at 8,192 by `f40bcf99e` (30 Jul 2026)
/// alongside [`NTT_MIN_MISSING`] and the span gate as an
/// explicitly conservative placeholder - *"Thresholds sit comfortably
/// above the crossover because Stage 2 integration overhead only pushes
/// it up; revisit with end-to-end numbers"*. The row gate was revisited
/// three times (512 -> 384 -> 320 -> a per-arch pair); this one never
/// was, and the one sentence its neighbour's essay offered for it
/// measured the OTHER gate - `m` is the MISSING count everywhere in
/// that essay, so "forcing it at m=64 costs 2.6x the fold's CPU" was
/// evidence about the row gate wearing this gate's name.
///
/// Swept end to end 7 Sep 2026 on both machine classes
/// (`research/NTT-MIN-PRESENT-CROSSOVER-2026-09-07.md`). One
/// damaged member carrying exactly `m` blocks and eight intact peers
/// carrying exactly `n_present`, so the two counts move independently;
/// `NZBFAST_NTT=force` against `NZBFAST_NTT=0`, mirrored, every leg
/// SHA-identical to the pristine corpus and its syndrome path ASSERTED
/// from the timing line rather than inferred. Present count at which
/// the transform stops losing, 128 KiB blocks:
///
/// | m (missing) | M3 Ultra (NEON) | i5-10600KF (AVX2) | n_present x m |
/// |---:|---:|---:|---:|
/// | 192 (NEON row gate) | ~1,490 | - | 285k |
/// | 256 (x86 row gate) | ~890 | ~1,610 | 228k / 413k |
/// | 400 | ~580 | ~1,010 | 232k / 406k |
/// | 1,024 | ~280 | ~330 | 285k / 336k |
/// | 2,048 | ~215 | ~240 | 440k / 492k |
/// | 4,096 | ~165 | <192 | 676k |
///
/// **The two gates are not separable.** Over the band the row gate
/// actually admits (m = 192..1,024) the present count falls 5x on both
/// boxes while the product spans 228k to 413k, a factor of 1.8 that
/// includes the whole gap BETWEEN the boxes. The shape underneath is arithmetic
/// rather than coincidence: the fold costs `c.n_present.m` and the
/// transform `a.n_present + b.m + d`, so the crossover is
/// `(b.m + d)/(c.m - a)` - a hyperbola whose vertical asymptote is the
/// `m` below which no present count wins, which is what
/// [`ntt_min_missing`] already gates, and whose horizontal asymptote is
/// a floor no amount of damage gets under. The two constants below are
/// the two ends of that one curve, and the gate is
/// `n_present >= max(NTT_MIN_PRESENT, NTT_MIN_WORK / m)`.
///
/// Both were set past the WORST measured crossover, which is the i5's:
/// the work floor by 1.27x (524,288 against its 413k at m=256, 128 KiB)
/// and the present floor by 1.33x (320 against its ~240 at m=2,048), the
/// way the row gate is set 1.2x past its own. That left them 1.5-2.7x
/// past every NEON point, which is why this was **one pair for every
/// arch rather than the per-arch pair [`NTT_MIN_MISSING`] needs**: the
/// gap between the boxes fit inside the margin, and a split would have
/// rested on four legs a point.
///
/// **The work end was split on 15 Sep 2026**, once both boxes had a
/// same-binary grid at two block sizes: the i5's worst crossover had
/// risen to 459k at 1 MiB, past the margin, so the x86 nibble arms read
/// [`NTT_MIN_WORK_NIBBLE`] through [`ntt_min_work`]. The present end is
/// still one constant. The table and the decision are at
/// [`NTT_MIN_WORK`].
///
/// The floor was 512 for the first day (`fda1e39a5`), which was the
/// value the m = 1,024 row alone supported. Swept past that row on both
/// boxes it came down to 320: at m = 2,048 the crossover is ~215 on the
/// M3 and ~240 here, at m = 4,096 ~165 and under 192, and the band 320
/// takes back is worth 11-15% of the whole repair at m = 2,048 / 384
/// present on both boxes.
///
/// Block size moved the crossover far less than `m` did and, on NEON,
/// always downward (m = 400: ~650 at 64 KiB, ~580 at 128 KiB, ~460 at
/// 512 KiB), so it was not made a third clause - the 128 KiB column
/// above is the conservative one there. The 15 Sep grid found it NOT
/// always downward on x86 (up 1.31x from 128 KiB to 1 MiB at m = 1,024
/// on the i5) and kept it out of the gate for a different reason,
/// written at [`NTT_MIN_WORK`].
///
/// **Read on wall, not on whole-process CPU, where the two disagree -
/// but only on an IDLE host, because on a busy one the disagreement is
/// a measurement of the other work.** Contention costs the transform's
/// phase about 1.75x what it costs the fold's (1.74/1.74/1.81 on three
/// aarch64 parts): the transform runs after the corpus is retained and
/// has no reads to hide behind, where the fold's arithmetic overlaps
/// them. So loading a host leaves the CPU crossover where it was and
/// pushes the WALL one out by half again - measured on three boxes at
/// two loads each, 176 -> 307, 212 -> 330 and 155 -> 255 on wall
/// against 164 -> 149, 210 -> 209 and 153 -> 150 on CPU
/// (`research/NTT-NEON-ROW-GATE-LARGE-BLOCK-2026-09-11.md`). Two lanes
/// have now read a busy host's wall figure as a property of the block
/// size. **Check the host was idle before believing a wall crossover;
/// where the two criteria disagree, suspect the host first.**
///
/// They agree everywhere on the M3 and at m = 256/400 on the i5; at
/// m = 1,024 the i5's whole-process CPU puts the crossover at ~560
/// against the stage's ~330, because the transform spreads over 12
/// threads on 6 cores and buys wall with CPU. At the admitted boundary
/// there (512 present) that shape is 14% faster in wall for 6% more
/// CPU, which is the trade a downloader wants. At 1 MiB blocks
/// (15 Sep) the same row reads 448 on wall and 776 on CPU, and the
/// transform's CPU premium at 512 present is 18%; the nibble boundary
/// there is 576 present since.
///
/// What this admits that 8,192 refused, measured on the M3: a
/// 1 GiB posting at 256 KiB with 400 rows missing (3,696 present) at
/// 1.88x, the same set at 128 KiB (7,792 present) at 1.95x, and a
/// 640 KiB / 768-row repair with 872 present at 1.34x on the phase and
/// -26% whole-process CPU (29.0 s against 39.0, eleven mirrored legs).
///
/// **THE DENOMINATOR OF EVERY CONSTANT IN THIS FAMILY IS THE FOLD'S
/// COST, so a fold that gets faster RAISES the crossover and every one
/// of them has to be re-derived.** `c` in `(b.m + d)/(c.m - a)` is the
/// fold's cost per (present block x row); shrink it and `c.m - a`
/// shrinks with it, which lifts `P_cross` - the transform then needs
/// MORE present blocks to be worth admitting than it did when these
/// numbers were measured. That direction is easy to get backwards: a
/// faster fold makes the gate STRICTER, not looser. The four numbers
/// it moves are this constant, [`ntt_min_work`], [`ntt_min_missing`]
/// and the create's own pair in
/// `crates/nzbkit-base/src/par2gen/ntt_range.rs`, and the fold itself
/// (`crates/nzbkit-base/src/par2repair/linalg.rs`) carries the pointer
/// back to here.
///
/// **Nothing asserts any of it, which is why the rule has to be
/// written down rather than noticed.** The two hits for
/// `NTT_MIN_PRESENT` in
/// `crates/nzbkit-base/src/par2repair/inline_tests.rs` READ these
/// values to build a shape the gate admits; they do not check that the
/// values are right, and no cheap test can - a crossover is a timing
/// measurement on a quiet box. So a stale calibration reddens nothing
/// anywhere. It admits the transform on a band the faster fold would
/// win and is paid in wall, silently, on the fold path, which is the
/// path memory-constrained hosts are forced onto.
///
/// Re-checked 8 Sep 2026 against the two fold changes landed since the
/// sweep and NOT changed: `71413391bd`'s SMT row floor is Windows-x86
/// only and binds under 64 rows, where every gate here already demands
/// 192 or more, and `093d9222ae`'s work-unit fix removes a per-call
/// setup of about 2 KiB a row against `window x block_size` bytes a row
/// of arithmetic - measured at 220 mirrored legs over 14 shapes with
/// the ratio scattered 0.91-1.03 around 1.00 inside a 12-34% per-arm
/// spread. `research/NTT-GATE-FOLD-COST-RECHECK-2026-09-08.md` has the
/// derivation, the legs and the bound.
pub(crate) const NTT_MIN_PRESENT: usize = 320;

/// The other end of the same curve: the syndrome-work floor,
/// `n_present * n_missing`, which binds wherever it asks for more than
/// [`NTT_MIN_PRESENT`] does - below m = 1,638 at this value. See
/// [`NTT_MIN_PRESENT`] for the 7 Sep sweep it was set from - and for the
/// rule that the fold's cost is this constant's denominator too, so a
/// fold change requires re-deriving it. The gate reads
/// [`ntt_min_work`], which since 15 Sep 2026 answers
/// [`NTT_MIN_WORK_NIBBLE`] on the x86 nibble arms; this value is every
/// other arch's, NEON included.
///
/// **Swept again 14-15 Sep 2026 on both boxes, on one binary
/// (`87ee76638`), at 1 MiB and 128 KiB blocks**
/// (`research/NTT-MIN-WORK-SMALL-SETS-2026-09-14.md`: 448 legs on the
/// M3 Ultra, 406 on the i5-10600KF, every one SHA-gated with its path
/// asserted). Crossover as work, `n_present x m`, read on CPU on the M3
/// (a loaded desktop) and on wall on the i5 (idle; its feed+fold+solve
/// stage agrees within 11% on every row, and within 4.3% at the two
/// points in bold that set the x86 floor):
///
/// | m | M3 1 MiB | M3 128 KiB | i5 1 MiB | i5 128 KiB |
/// |---:|---:|---:|---:|---:|
/// | 192 | 205k | 324k | - | - |
/// | 256 | 176k | 279k | 376k | **442k** |
/// | 320 | 178k | 264k | 369k | 382k |
/// | 448 | 189k | 259k | 328k | 360k |
/// | 640 | 200k | 268k | 346k | 348k |
/// | 1,024 | 268k | **334k** | **459k** | 351k |
///
/// **On NEON this value is 1.57x past the worst point, and it stays.**
/// A NEON floor of `416 << 10` (1.27x past 334k) is what the M3's grid
/// alone supports, and it is NOT taken, because lowering the floor
/// moves its hand-off to [`NTT_MIN_PRESENT`] from m = 1,638 down to
/// m = 1,331, and crossover work RISES with m past 1,024 on that part
/// (7 Sep: ~440k at m = 2,048). Interpolated between those two rows the
/// NEON crossover at m = 1,331 is ~280 present, which the 320 present
/// floor would clear by only ~1.15x. That band - m = 1,024..2,048 at
/// 128 KiB, present ~250-450 - has no leg in this family, and a NEON
/// floor needs it first.
///
/// **On the x86 nibble arms it did not hold.** 524,288 sat 1.14x past
/// the i5's 459k (448 present at m = 1,024, 1 MiB) and 1.19x past its
/// 442k (m = 256, 128 KiB), both under the 1.27x it was set with against
/// the 7 Sep figure of 413k. Every shape it admitted still won on wall;
/// the margin is what had gone. That arm has its own constant now.
///
/// **Block size is still not a third clause, and the reason changed.**
/// The 1 MiB crossover over the 128 KiB one at the same `m` is
/// 0.63-0.80 on the M3 (down 1.25-1.6x) but 0.85, 0.97, 0.91, 1.00 and
/// 1.31 on the i5 at m = 256..1,024: inside the margin at four rows of
/// five and UPWARD at the fifth, the opposite direction to NEON. A
/// clause needs the same move past the margin on both boxes; instead
/// each floor is set against its own box's worse block size.
pub(crate) const NTT_MIN_WORK: usize = 512 << 10;

/// The work floor on the x86 nibble arms (AVX2 without GFNI), 15 Sep
/// 2026: 1.29x past the i5-10600KF's worst crossover on this gate, 459k
/// at m = 1,024 / 1 MiB on wall (the stage reads 453k), and 1.33x past
/// its 442k at m = 256 / 128 KiB. The table is at [`NTT_MIN_WORK`].
///
/// **What it gives back, measured.** The shapes between 524,288 and
/// this value were transform wins on wall: (m = 256, 2,048 present) by
/// 14% at 1 MiB and 9% at 128 KiB, (1,024, 512) by 2.5% and 10%. That
/// is the margin being paid for, as at every constant in this family.
/// At 1 MiB it is a cheap trade on this box - the transform bought
/// those two wall wins with 31% and 18% MORE whole-process CPU than the
/// fold, running 12 threads on 6 cores - but at 128 KiB (256, 2,048)
/// won on CPU too (15%), and that is the real cost.
///
/// The GFNI and AVX-512 x86 arms are unmeasured on this gate and keep
/// [`NTT_MIN_WORK`], as they keep [`NTT_MIN_MISSING`] for the row gate.
/// **It was expected to move with the transform's x86 CPU at 1 MiB, and
/// on 15 Sep 2026 it did not need to.** That A/B
/// (research/NTT-X86-TRANSFORM-CPU-1MIB-2026-09-15.md) left the pool at
/// every logical CPU - six threads cuts the CPU 15-36% but pays up to
/// 10% wall at the shapes this floor admits, a policy call - and moved
/// the REPAIR's stripe to 512 ([`repair_stripe_words`]), which at
/// (m = 1,024, 512 present) bought 0.8% of wall, at the A/A floor. The
/// 459k point was measured at the old 1,024 stripe, so it can only have
/// come DOWN, by an estimated ~20 present at that depth (to roughly
/// 440k); the 128 KiB 442k point ran at 512 before and after. This
/// value therefore sits ~1.30x past the worst point, inside the 1.27x
/// rule, and is not re-derived: tightening it could buy ~2.5% and would
/// rest on an interpolated crossover rather than a measured one.
pub(crate) const NTT_MIN_WORK_NIBBLE: usize = 576 << 10;

/// The work floor this build runs under: [`NTT_MIN_WORK_NIBBLE`] on the
/// x86 nibble arms (keyed on the selected kernel's fan-in, as
/// [`ntt_min_missing`] is), [`NTT_MIN_WORK`] everywhere else, aarch64
/// included. The rule that a fold change moves it is at
/// [`NTT_MIN_PRESENT`].
pub(crate) fn ntt_min_work() -> usize {
    if !cfg!(target_arch = "aarch64") && crate::gf16::multi_fold_width() == 4 {
        NTT_MIN_WORK_NIBBLE
    } else {
        NTT_MIN_WORK
    }
}

/// Flat ceiling on the default resident-corpus budget. The NTT is a
/// big-machine feature; low-memory hosts stay on the streaming fold
/// (amendment 2) - and that is the RAM/4 and cgroup/4 rules' job below,
/// not this constant's. It was 4 GiB until 5 Sep 2026, which removed the
/// transform from every big corpus on every box: a 10 GiB / 1 MiB
/// repair (900 rows) on the 512 GB M3 Ultra streamed the fold in 25.3 s,
/// level with turbo, and transformed in 8.36 s with the budget lifted
/// (byte-identical, 12.5 GB resident). 64 GiB keeps RAM/4 as the
/// binding guard on anything under 256 GB.
const NTT_BUDGET_CEIL: u64 = 64 << 30;

/// Default retention budget, scaled to the machine: an OOM kill is the
/// one failure the verify-retry cannot rescue, so beyond the flat
/// ceiling the budget is capped at a quarter of physical RAM and, in a
/// container, a quarter of the cgroup limit (the process's hard
/// OOM-kill line; the pipeline's own MemBudget::auto uses half, and
/// repair retention must not claim that much on top). A small box
/// thereby refuses the NTT up front - the budget is a dispatch gate,
/// not a runtime failure. `NZBFAST_NTT_BUDGET` overrides absolutely.
pub(super) fn ntt_default_budget(ram: Option<u64>, cgroup_limit: Option<u64>) -> usize {
    let mut b = NTT_BUDGET_CEIL;
    if let Some(r) = ram {
        b = b.min(r / 4);
    }
    if let Some(l) = cgroup_limit {
        b = b.min(l / 4);
    }
    // `b as usize` WRAPPED TO ZERO on 32-bit hosts (armv7 Raspberry Pi
    // OS) whenever neither probe answered: NTT_BUDGET_CEIL is 64 GiB,
    // well past what a 32-bit `usize` holds. A zero budget fails `n_present * block_size <= budget` for
    // every corpus, so the NTT path was silently unreachable there -
    // fail-safe, but for a reason nothing in the code said out loud.
    // Saturating is only half the answer: a 32-bit process has ~3 GiB
    // of user address space TOTAL, so the retention arenas this gate
    // prices cannot approach the flat ceiling anyway. Hold it where it
    // is actually spendable.
    #[cfg(target_pointer_width = "32")]
    let b = b.min(1 << 30);
    usize::try_from(b).unwrap_or(usize::MAX)
}

/// Present blocks one retention WINDOW must hold before the streaming
/// transform is considered over it at all. Since 14 Sep 2026 this is a
/// SANITY floor under [`ntt_window_row_gate`], which is the gate that
/// decides whether a corpus bigger than the budget takes the transform
/// in windows or streams the fold instead.
///
/// The fold worker has transformed the corpus in budget-sized windows
/// since 2 Sep 2026 (the transform is linear, so windows XOR into the
/// same syndrome rows), but nothing DISPATCHED to it that way: the
/// admission clause below demanded the whole corpus fit, so a 10 GiB
/// repair on any box budgeting less than that folded. What a window
/// costs on top of the single-plan transform is the upper tree, which
/// every window rebuilds and re-evaluates: measured on an M3 Ultra with
/// `NZBFAST_NTT_PROFILE=1`, the 1 GiB / 64 KiB / 1,500-row heavy set
/// spends 9.50 of 10.32 inclusive thread-seconds in the leaves at one
/// window and 1.72 of 2.58 at four, i.e. ~0.8 thread-seconds of combine
/// per window whatever the window holds. The leaves, which are the
/// other 92-95%, are linear in the sources a window carries, so the
/// window count is the only thing streaming costs.
///
/// That charge is thread-parallel, so THE CROSSOVER IS A FUNCTION OF
/// THE BOX and not of the corpus. Same 10 GiB / 900-row / 1 MiB repair,
/// forced arms, SHA 10/10 every leg:
///
/// | sources/window | M3 Ultra (32 threads) | i5-10600KF (12 threads) |
/// |---|---|---|
/// | 9,340 (one window) | 7.92 s | 26.5 / 26.7 s |
/// | ~4,100 | 9.15 | 37.3 / 37.8 |
/// | ~3,110 | - | 41.7 / 42.1 |
/// | ~2,050 | 8.80 | 50.8 / 50.9 |
/// | ~1,540 | - | 59.4 / 62.4 |
/// | ~1,030 | 11.14 | 79.8 / 80.3 |
/// | the fold | 19.83 | 87.3 / 89.5 |
///
/// Fitted, the per-window charge is 0.52 s on the 32-thread box and
/// 5.5 s on the 12-thread one, which puts break-even against the fold
/// at ~265 sources per window on the first and **~785 on the second**.
///
/// **It was 2,048 from 5 Sep to 14 Sep 2026**, set from the WORSE arm
/// and from the measured points on either side of it rather than the
/// fit: a 1,030-source window is 1.1x the fold there and a 1,540-source
/// one 1.45x, where 2,048 buys 1.73x (50.8 against 88.4) and 2.3x on the
/// M3. It was also two full eight-source groups of the fused kernel per
/// live leaf (base logs are coprime to 65,535, so only 128 of the 255
/// leaves carry sources). It was one flat constant rather than a
/// per-arch pair on the argument that the thread count, not the kernel,
/// separates the two boxes; and it admitted the transform for blocks up
/// to 512 KiB on a 4 GB box, 1 MiB on 8 GB, 2 MiB on 16 GB and 4 MiB on
/// 32 GB.
///
/// **That was the right reading of ONE shape and the wrong constant for
/// the rest**, because the charge is not a fixed number of seconds a
/// window. It is about `c_w * min(m, 4369)` per 64 KiB of width - it
/// grows with the ROWS, BENDS at the depth-2 tile, and does not move
/// with the sources the window holds - so "sources per window" was a
/// proxy that only held at 900 rows and 1 MiB. ("Bends" was "plateaus"
/// until 17 Sep 2026, and the block below is why it is not.) On a
/// 512 MB box (a 128 MiB budget)
/// at 64 KiB blocks a window holds ~1,650 sources once the worker arenas
/// are paid, so 2,048 refused the transform at EVERY `m`, while the
/// forced transform beat the fold from m = 256 (by 18%) to m = 4,096
/// (7x in CPU, 10x in wall), 120 SHA-gated legs
/// (`research/PARFAST-SMALL-BUDGET-TRANSFORM-CROSSOVER-2026-09-14.md`).
/// The curve in window size that replaced it, per kernel class, is
/// [`ntt_window_row_gate`].
///
/// **THE TILE IS MEASURED SINCE 17 SEP 2026, AND THE PLATEAU IS NOT
/// FLAT.** This block said "plateaus" from 14 Sep on the strength of
/// the allocation shape alone - [`crate::par2ntt`] decimates
/// 65,535 = 3 x 5 x 17 x 257, so `FlatPlan::new_scratch` and
/// `scratch_bytes` hold `min(needed, 4369)` rows at depth 2 - with no
/// timing behind it on any box. Five `m` ladders have now put a knee on
/// it, and not one of them had 4,369 in its rung set
/// (`research/PARFAST-BARE-RAISE-TIMING-2026-09-16.md`, sections 8.12,
/// 8.14, 8.15, 8.21 and - on a guest, and read as such - 8.18):
///
/// | round | class, box, block | knee | slope below | slope above |
/// |---|---|---:|---:|---:|
/// | 8.12, 64 legs | x86 nibble, Xeon D-1531, 1 MiB | **4,383** | 4.5792 ms/row | **15.9%** |
/// | 8.14, 104 legs | NEON, M3 Ultra, 1 MiB | **4,396** | 0.6859 ms/row | **12.47%** |
/// | 8.14.8, 72 legs | NEON, M3 Ultra, 64 KiB | 4,382 / 4,539 | 0.0400 / 0.0436 | 18.8% / 7.4% |
/// | 8.15, 240 legs | NEON, M3 Ultra, 512 KiB | **4,334** | 0.3419 ms/row | **14.9%** |
/// | 8.21, 68 legs | x86 nibble, i5-10600KF, 512 KiB | **4,231** | 1.0595 ms/row | **18.3%** |
/// | 8.18, 45 legs, GUEST | AVX-512 GFNI, EPYC 9354P 8-vCPU guest, 1 MiB | 4,275 | 0.9440 ms/row | not measured |
///
/// **THE LAST ROW IS A CONSISTENCY CHECK AND NOT A MEASUREMENT**, in
/// 8.18.1's own headline: a leg-resampling bootstrap puts that knee at
/// 4,000-4,600 at 68%, where the bare-metal cells agree to a few per
/// cent, and a median hypervisor steal of 3.41% moved the same fit by
/// 20% on the unfiltered legs. Read it as the third class showing a
/// knee at all; do not average it into the rows above it.
///
/// **The tile is a property of the PLAN and not of the kernel** - the
/// two bare-metal classes' below-tile slopes differ by 6.7x at 1 MiB
/// and 3.10x at 512 KiB, and a cache effect sitting near 4,369 by
/// coincidence could not do that five times over. **But it is no longer
/// tight to 1.1%, and the honest statement is a RANGE**: the five
/// bare-metal readings span **-3.15% (8.21) to +0.63% (8.14)** of the
/// structural 4,369, four of them inside 1.1% and 8.21's the loose one.
/// 8.21.7 reports its own rather than smoothing it and does not explain
/// it: that cell's below-tile residuals are convex at about 1% of the
/// charge against an A/A floor of 0.41%, and four extra legs run for
/// exactly this moved the knee from -3.48% to -3.15%, so rung sparsity
/// alone is not the cause.
///
/// What is wrong is the word "plateaus": **a seventh to a sixth of the
/// slope survives above the tile**, so
/// `c_w * min(m, 4369)` UNDERSTATES the tree by **4.6% and 4.9% at
/// m = 5,900** and by more further out. That is the non-conservative
/// direction for anything pricing the transform against the fold, and
/// it is the direction a reader of this block would not expect. Which
/// way it cuts for the shipped DECISION is worked out at
/// [`ntt_window_row_gate`], and it is the other way.
///
/// **DO NOT TAKE ONE RESIDUAL FIGURE FROM THAT COLUMN.** The four
/// 1 MiB-and-wider cells read 12.47% (NEON, 1 MiB), 14.9% (NEON,
/// 512 KiB), 15.9% (nibble, 1 MiB) and 18.3% (nibble, 512 KiB) - **a
/// 47% spread** around a structural 12.33%, where 8.15 reported 27%
/// over three (8.21.6). So the 1.1% agreement 8.14 found was partly
/// luck of the cell, and every cell added since has WIDENED the
/// interval rather than narrowing it: the residual is not pinned the
/// way the knee is. Quote the range, not a number.
///
/// **The mechanism, offered as one and not as a fit.** Only the depth-2
/// level saturates: the root holds `min(m, 65535)` rows over its live
/// depth-1 children and each depth-1 node `min(m, 21845)` over its
/// depth-2 children, and neither stops growing at 4,369. Taking the
/// per-row cost as equal at each level, the surviving fraction is
/// `(3 + 15) / (3 + 15 + L)` for `L` live leaves, which at **L = 128** -
/// the leaf count the 2,048 paragraph above already gives, because the
/// base logs are coprime to 65,535 - is **12.33%**. NEON measured
/// 12.47%, 1.1% out; the nibble class measured 15.9%, 29% out.
///
/// **That equal-cost assumption was TESTED on 17 Sep 2026 and it is
/// FALSE on BOTH classes that can test it, by the same factor** (8.15.5
/// and 8.21.6 - the two cells with three regimes to solve with, so the
/// system is determined in each). Per fold-row: NEON's root
/// **0.00940 ms** against depth-1's 0.00153 and depth-2's 0.00227; the
/// nibble class's **0.02881** against 0.00718 and 0.00676. **The root
/// is 4.1x a depth-2 fold-row on NEON and 4.26x on nibble** - an
/// agreement to 4% between kernels whose below-tile slopes differ by
/// 3.10x. So this is a property of the PLAN and no longer a candidate
/// artefact of one kernel's memory behaviour, which is the one thing
/// 8.15 could not say. The mechanism is still offered rather than
/// measured - the root's folds combine the widest spans in the plan,
/// 65,535 rows against 4,369, so they have the least locality per row -
/// and it survived a class change that should have broken a
/// memory-behaviour story. A root that is dear per row makes BOTH knees
/// shallower than the node counts say, which is the measured pattern on
/// both cells: the first drop reads 0.1494 (NEON, +21%) and 0.1832
/// (nibble, +49%) against a structural 18/146, the second 0.5526
/// (**+232%**) and 0.4452 (**+167%**) against 3/18. Same direction,
/// same order, wider spread - **so anyone pricing the transform past a
/// tile from `(3 + 15) / (3 + 15 + L)` will UNDER-price it**, on any
/// class, by roughly the same amount. The second cell strengthens that
/// conclusion rather than changing it. Keep the arithmetic as the
/// family and sign it gets right; do not use it as a number.
///
/// **The MEMORY estimate's tile is exact, and its CONSTANT is PER-CELL
/// rather than per-class.** `scratch_bytes` prices `5 + 3 + 1` rows per
/// row below the tile and `3 + 1` above, and THAT half transfers
/// wherever it has been checked: 8.14.9 backs 9,216 and 4,096 B/row out
/// of the NEON arenas to the byte at `W = 512`, and 8.21.3 reads
/// **7,549.7 B/row** across the depth-2 tile against a structural
/// 7,545.9 - 0.05% out. **The ADDITIVE term is three values on three
/// cells, and NONE of them is "the x86 figure".** 2,304,000 B is the
/// constant 8.12 FITTED on its own Xeon D-1531 cell; 8.14.9 puts NEON
/// at 76-207 KB per worker; and 8.21.3 puts a DIFFERENT x86 part in the
/// SAME nibble class at **under 78.6 KB per worker**, over four probe
/// legs at m = 1,000 / 6,000 / 15,000 / 26,500 - about thirty times
/// smaller than the figure fitted on the other x86 box. **So never
/// quote 2,304,000 B as an x86-CLASS figure; name the box it was fitted
/// on.** Carrying it costs real budget in either direction: 17% over at
/// m = 600 on NEON (8.14.9), and 18 MB of over-budgeted arena on 8.21's
/// cell, which would have put every window 35 sources wide of where it
/// was asked to be. 8.14.9's rule stands and is now paid for twice -
/// carry the `m` half between classes, measure the constant with one
/// probe leg.
///
/// **AND IT BENDS A SECOND TIME, AT THE DEPTH-1 TILE** (8.15, 240 legs
/// at 512 KiB, landed hours after the paragraphs above were written).
/// The charge does not stay on the residual line either: it breaks
/// again at **m = 22,074 against `min(m, 21845)`, 1.05% out**, to
/// **2.8%** of the below-tile slope. Three regimes, three straight
/// lines, r2 = 0.99998 / 0.99978 / 0.99289. So the honest shape of the
/// tree charge is piecewise with a knee at EACH tile the plan carries,
/// and 4,369 is only the first of them.
///
/// **AND THAT SECOND TILE HAS A SECOND CLASS SINCE 8.21** (68 legs,
/// nibble x86 at 512 KiB), which reads it TIGHTER than the class that
/// found it: **m = 21,939, +0.43% out**, against NEON's +1.05%, on a
/// ladder that never had 21,845 in its rung set. Three regimes again,
/// r2 = 0.99928 / 0.99842 / 0.99215. The residual ABOVE that tile is no
/// more a single figure than the one above 4,369 is: **2.8% of the
/// below-tile slope on NEON against 8.2% here.**
///
/// **Still open.** The AVX-512 GFNI class's `m` axis is measured only
/// on a GUEST and only at the DEPTH-2 tile - 8.18, whose own headline
/// calls it a consistency check rather than a measurement, for the
/// reason the table row above gives. **The DEPTH-1 tile on that class
/// is untouched, on a guest or on metal**, and is claimed as
/// `ntt-depth1-tile-gfni-bare-metal-17sep`; a bare-metal round there
/// needs a PowerShell port of `research/harness/nttladder.py` before it
/// can be scheduled at all, because the fleet's only metal GFNI parts
/// are Windows and the driver is POSIX-only (8.18.2). And
/// a ladder's reach above the depth-1 tile is capped by
/// [`ntt_admit_within`]'s narrowing rule rather than by RAM (m = 26,700
/// at 256 KiB), because the arena grows with `m` while
/// `MAX_INPUT_SLICES` holds the corpus - any future lane on this axis
/// needs 8.15.2's table before it sizes a cell.
///
/// **320 is [`NTT_MIN_PRESENT`]**: a window holding fewer sources than
/// the present gate asks of a whole corpus would be a transform over a
/// shape that gate refuses on its own. The curve already refuses every
/// window at or under its combine ratio whatever `m` is (163 sources on
/// NEON, 312 on x86 since that constant was measured), so on both it is a
/// guard and not a calibration: on x86 it binds alone only for windows of
/// 313 to 319 sources, where the curve would ask thousands of rows anyway.
pub(crate) const NTT_MIN_WINDOW_PRESENT: usize = 320;

/// The windowed crossover's one per-class constant on aarch64 (NEON):
/// `k = c_w / c_f`, the per-window combine over the fold, in SOURCES.
///
/// Measured 14 Sep 2026 on the M3 Ultra at `-t4` with
/// `NZBFAST_NTT_PROFILE=1` over a 1 GiB / 64 KiB / 16,384-block repair,
/// in CPU-seconds per 64 KiB of width: fold `c_f` = 1.9e-6 per
/// source-row (10.7 -> 131 CPU-s over m = 192..4,096, linear), combine
/// `c_w` = 3.1e-4 per row per window (0.08 thread-s a window at m = 256,
/// 0.34 at 1,024, 0.35 at 4,096 on 16 KiB slabs, identical at 2,304 and
/// 16,128 sources a window). 3.1e-4 / 1.9e-6 = 163
/// (`research/PARFAST-SMALL-BUDGET-TRANSFORM-CROSSOVER-2026-09-14.md`,
/// section 3a). No margin on it: the margin is the row gate's own, which
/// [`ntt_window_row_gate`] scales.
///
/// **THOSE THREE POINTS DO NOT REPRODUCE, AND THE MEDIAN IS WHY 163
/// SURVIVED THEM** (17 Sep 2026,
/// `research/PARFAST-BARE-RAISE-TIMING-2026-09-16.md` section 8.14.8).
/// Read as a curve they say the combine has already saturated by
/// m = 1,024: 4.25x from m = 256 to 1,024, then 1.03x to 4,096. A
/// 72-leg `m` ladder on the SAME class at the SAME block size and the
/// same three `m` values measures **2.27x and 2.97x** - still on a
/// straight line through 4,096, bending at about 4,400 like every other
/// cell anyone has measured. So the saturation is not the class and it
/// is not the 64 KiB block. What that round did NOT hold fixed against
/// this measurement is the thread count (`-t4` here, `-t8` there), the
/// retention budget (`-m128` here, giving ~1,650-source windows against
/// 4,400-10,000 there) and the instrument (`NZBFAST_NTT_PROFILE`'s
/// depth0-minus-leaves per window here, a k = 1 against k = 2 syndrome
/// difference there). One of those three is the explanation and neither
/// round can say which; do not assert one.
///
/// **163 is not damaged by it, and the reason is the MEDIAN.**
/// Charge-over-rows on the three rungs above reads 3.13e-4 / 3.32e-4 /
/// 8.5e-5, so the median is 3.13e-4 and the anomalous third point is
/// exactly the one the median discards. Had two of the three sat where
/// that one does, or had `c_w` been a mean, 163 would be a different
/// number today - which is worth knowing before reading those three
/// figures as evidence of anything. The numerator also reproduces
/// independently: the NEON `m` ladder's 0.6859 ms/row of wall at 1 MiB
/// on eight threads is `0.6859e-3 * 8 / 16` = **3.43e-4** in this
/// block's own units, **11% from 3.1e-4** across both a thread count
/// and a 16x block. Nothing follows for 163 itself, because `k` is
/// `c_w / c_f` and neither round measured the fold's `c_f` at that cell.
///
/// **And the charge this constant prices does not plateau above the
/// depth-2 tile**, whatever [`NTT_MIN_WINDOW_PRESENT`] used to say:
/// 12.47% of the slope survives on this class at 1 MiB, and 14.9% on
/// the same class at 512 KiB, so take the range and not either figure.
/// See there for the measurements and [`ntt_window_row_gate`] for which
/// way they cut.
pub(crate) const NTT_WINDOW_COMBINE_NEON: usize = 163;

/// The same constant on x86, measured 14 Sep 2026 on BOTH x86 kernel
/// classes the fleet has, and set to the largest of the four cells.
///
/// Same fixture and definitions as the NEON constant (1 GiB / 64 KiB /
/// 16,384 blocks, CPU-seconds per 64 KiB of width, `c_f` the slope of
/// whole-process CPU over no-`-m` fold legs at m = 192..4,096 divided by
/// n, `c_w` the median over m = 256 / 1,024 / 4,096 with the corpus
/// resident and under `-m128` of each window's depth0 - leaves over its
/// rows), release parfast on Windows, two reps, minimum of the two:
///
/// | box, kernel class, pool | `c_f` | `c_w` | `k` |
/// |---|---:|---:|---:|
/// | i5-10600KF, nibble (AVX2), `-t4` | 3.37e-6 | 7.56e-4 | 225 |
/// | i5-10600KF, nibble (AVX2), `-t12` | 4.25e-6 | 1.33e-3 | **312** |
/// | Core Ultra 9 386H, GFNI-256, `-t4` | 8.93e-7 | 2.22e-4 | 249 |
/// | Core Ultra 9 386H, GFNI-256, `-t16` | 1.61e-6 | 4.44e-4 | 276 |
/// | EPYC 9354P, AVX-512 GFNI, `-t4` (15 Sep) | 1.58e-6 | 3.62e-4 | 229 |
/// | EPYC 9354P, AVX-512 GFNI, `-t8` (15 Sep) | 1.67e-6 | 4.21e-4 | 251 |
///
/// **One constant, not a split on [`crate::gf16::multi_fold_width`]**:
/// the GFNI class sits inside the nibble class's own thread-count spread,
/// so a per-class pair would key on a difference the measurement does not
/// show. 312 is the worst cell with no margin on it, for the reason the
/// NEON constant gives - the margin is the row gate's, which
/// [`ntt_window_row_gate`] scales - and a larger `k` refuses more
/// windows, so the worst cell is the conservative end. The AVX-512 GFNI
/// arm inherited it unmeasured and was measured on 15 Sep 2026 (the last
/// two rows: an 8 vCPU KVM guest, same fixture and definitions, Linux,
/// `research/harness/rowgate.py`'s `k` phase, two reps, minimum of the
/// two) at 229 / 251, inside the same family and under 312, so it keeps
/// the one constant (`research/NTT-ROW-GATE-GFNI-AVX512-2026-09-15.md`).
///
/// **It was 702 until this measurement, inferred** from the WALL figures
/// in [`NTT_MIN_WINDOW_PRESENT`]'s table times a 1.2 margin, and the
/// inference was wrong in the fold, not the combine: 88 s of wall over
/// 9,340 x 900 on twelve threads read as `c_f` ~ 6.5e-7, five times
/// under the i5's measured CPU slope. On a 128 MiB budget at 64 KiB
/// (a 1,630-source window) 702 asked 449 rows and 312 asks 316.
///
/// Validated at `-t4 -m128`, both builds interleaved per rung: on the i5
/// the transform is now taken from m = 384 (19.16 CPU-s against the
/// fold's 22.44, where 702 folded), and on the Core Ultra at m = 512 at
/// the full stripe (10.89 against 702's 14.75, which was over the fold).
/// One rung below the GFNI edge [`ntt_admit_within`] then re-admitted a
/// row-refused window at a narrowed stripe that lost to the fold (m = 384,
/// 14.16 CPU-s against 10.50); that was the narrowing rule's, not this
/// constant's, it moved with it, and since 15 Sep 2026 that window folds
/// (step 5 of the rule;
/// `research/PARFAST-SMALL-BUDGET-TRANSFORM-CROSSOVER-2026-09-14.md`,
/// sections 6 and 8; driver `research/harness/wcomb.ps1`, reducer
/// `research/harness/wcombsum.py`).
///
/// **Measured again at 1 MiB BLOCKS on 16 Sep 2026, because nothing made
/// it scale-free by construction**: the combine it prices is per WINDOW,
/// while the transform's saving inside a window grows with the block. On
/// the GFNI-256 part, with a 64 KiB control in the same sitting on the
/// same binary (`research/NTT-ROW-GATE-GFNI-AVX512-2026-09-15.md`,
/// "`k` at 1 MiB"):
///
/// | block, pool | `c_f` | `c_w` | `k` |
/// |---|---:|---:|---:|
/// | 64 KiB, `-t4` (control; 249 on 14 Sep) | 8.82e-7 | 2.21e-4 | 251 |
/// | 64 KiB, `-t16` (control; 276 on 14 Sep) | 1.63e-6 | 4.42e-4 | 272 |
/// | 1 MiB, `-t4` | 1.02e-6 | 2.30e-4 | 225 |
/// | 1 MiB, `-t16` | 2.26e-6 | 4.56e-4 | 202 |
///
/// **`c_w` is what does NOT move: +4.0% and +3.2% across a 16x block**,
/// which is what [`crate::par2ntt`]'s `Node::Combine` arm says must
/// happen - the combine is a `fold_into` over the stripe's words, once
/// per stripe, so a window's combine is linear in the block exactly as
/// the fold is. All of `k`'s movement is the FOLD getting dearer per byte
/// at 1 MiB (+15.8% / +38.9%), which is the direction
/// [`NTT_MIN_MISSING_GFNI256_LARGE_BLOCK`] moved on.
///
/// **312 STAYS, and the rungs are why rather than the spread.** The 1 MiB
/// cells do sit inside the 225-312 the six 64 KiB cells span, but the
/// windowed ladders settle it: at 1 MiB the measured crossover excess over
/// a resident ladder in the same sitting is 13 rows at 2,064-source
/// windows (where 312 asks 62) and ~123 rows at 1,040-source windows
/// (where 312 asks 150, and 225 and 202 ask 97 and 84). **312 is the only
/// candidate conservative at BOTH**, so re-deriving `k` here would buy a
/// fifth of the overcharge at large windows and pay 26-39 rows for it at
/// small ones. No single `k` fits both cells either (73 fitted to one, 246
/// to the other), so the overcharge belongs to
/// [`ntt_window_row_gate`]'s one-parameter SHAPE and not to this number.
///
/// **312 CARRIES AN UNCERTAINTY, and that clause above is more confident
/// than the evidence** (16 Sep 2026, the same note's "`k` at 1 MiB on
/// the NIBBLE class" and the estimator section under it). Two things a
/// reader of the tables above cannot see:
///
/// - **The NIBBLE class measures ABOVE 312 at 1 MiB**, where the
///   GFNI-256 rows above measure below it: `k` = 395 at `-t12` on the i5,
///   380 with both halves rung-matched, 21-27% over this constant. A `k`
///   set below the truth UNDER-asks, which is the non-conservative
///   direction, and it is the class that SET this number. Nothing moved
///   on it, because `k` without a measured ask is the half that did not
///   decide 312 the first time and a nibble-class windowed ladder at
///   1 MiB is still owed.
/// - **`c_f` is a least-squares SLOPE in `m`, so its RUNG SET is a free
///   parameter, and nobody recorded the choice.** The fold is not linear
///   in `m` on this part, and refitting the 14 Sep i5 `-t12` legs over
///   m = 192..2048 instead of 192..4096 - same legs, same log, same
///   night - moves `c_f` 18% and reads `k` = 264. Refitted on the one
///   rung set every fixture shares, the ten 64 KiB cells span 197-264
///   rather than 183-312, and the selection rule that set this constant
///   (one number, the largest cell, no margin) gives 264. **312 is a
///   value the common rung set does not produce in any cell**, and its
///   own fit is the worst conditioned of the ten (worst residual 14.88
///   and intercept 18.18, both the largest; 2.15 and 8.31 without the
///   m = 4,096 rung). `research/harness/wcombsum.py` and `rowgate.py`
///   both take `--rungs` and print the rung set beside every `c_f` and
///   `k` since that date, so a figure copied out of either carries its
///   own provenance.
///
/// **THE SECOND BULLET'S UNCERTAINTY IS A FLOOR, NOT A MEASUREMENT DEBT**
/// (16 Sep 2026, the same note's two-binary control section). The
/// two-binary control ran the 14 Sep tree `87ee76638` and an
/// origin/main tip interleaved in ONE quiet sitting on the i5 at
/// `-t4 -t6 -t12`, 132 legs: **`c_f` agrees to 2.3% between them at
/// every pool on both rung sets**, against the 28-35% that separated the
/// 14 and 16 Sep SITTINGS. So the spread above is not a code difference
/// waiting to be resolved by a better round - the three sittings order
/// by their box load exactly as they order by `c_f`, and a constant
/// cannot be conditioned on a sitting. A future re-measure will not
/// tighten this; do not commission one expecting it to. The highest
/// 64 KiB cell now measured anywhere is 288, so the conservatism
/// argument below is unchanged and slightly wider than it was.
///
/// **It STAYS anyway, and the reason is rows rather than inertia.** 312
/// is conservative against every 64 KiB cell on either rung set, and what
/// [`ntt_window_row_gate`] does with the whole 197-395 spread is worth 34
/// rows of excess at 2,048-source windows and 15 at 4,096; below about
/// 1,000 sources `reconstruct`'s `plan_slabs` limit decides instead of
/// this number, whatever it is. Re-deriving it on a shared rung set would
/// move it DOWN 15% while the one cell above it stayed put, which is the
/// wrong direction to move first.
///
/// **The nibble class's `m` axis was measured on 16 Sep 2026, and the
/// charge this constant prices BENDS rather than plateaus above the
/// depth-2 tile**: 15.9% of the slope survives, against 12.47% on NEON
/// (`research/PARFAST-BARE-RAISE-TIMING-2026-09-16.md`, sections 8.12
/// and 8.14). It moves nothing here, and for a reason worth stating -
/// the `c_w` in the tables is a median over m = 256 / 1,024 / 4,096 and
/// **4,096 is UNDER 4,369**, so all three rungs sit on the linear part;
/// a rung above the tile would have read `c_w` low. (That argument does
/// NOT carry to [`NTT_WINDOW_COMBINE_NEON`], whose own three points
/// behave differently and whose constant survives on the median
/// instead.) What the bend does touch is
/// [`NTT_MIN_WINDOW_PRESENT`]'s statement of the charge and the
/// DIRECTION of the row gate's error; both are written up at those two
/// sites.
pub(crate) const NTT_WINDOW_COMBINE_X86: usize = 312;

/// [`NTT_WINDOW_COMBINE_NEON`] on aarch64, [`NTT_WINDOW_COMBINE_X86`]
/// everywhere else - keyed on the target the way [`ntt_min_missing`] is,
/// with the nibble and GFNI arms sharing one measured figure because
/// they measured inside each other's spread.
pub(crate) fn ntt_window_combine() -> usize {
    if cfg!(target_arch = "aarch64") {
        NTT_WINDOW_COMBINE_NEON
    } else {
        NTT_WINDOW_COMBINE_X86
    }
}

/// The windowed row gate: the fewest missing rows at which a corpus taken
/// `sources` blocks per window beats the fold, or `None` when no row
/// count does. `gate` is the single-window row gate ([`ntt_min_missing`])
/// and `k` the class's combine ratio ([`ntt_window_combine`]).
///
/// Per window of `S` sources and `m` rows the fold costs `c_f * S * m`;
/// the transform costs `c_l * S` for the leaves plus `c_w * m` for the
/// upper tree every window rebuilds. All three are linear in the block
/// width, so the width cancels and the crossover is
///
/// ```text
///     m*(S) = (c_l / c_f) * S / (S - k)        k = c_w / c_f
/// ```
///
/// a hyperbola with no solution at `S <= k`. `c_l / c_f` is the
/// single-window crossover, which the row gate already carries with its
/// margin, so the gate is that constant scaled by `S / (S - k)` and `k`
/// is the one number this adds. Only WHOLE rows of the excess are
/// charged (`gate + gate * k / (S - k)`, integer division), so a big
/// window keeps exactly the row gate it had: on NEON the excess is zero
/// from S = 31,460 and at most one row from S = 15,812.
///
/// **It must stay a curve in S, not a flat row margin.** Wherever the
/// arenas leave a window its whole budget, `S >= 2m` - `plan_slabs`
/// holds `2 * m * w` inside it - so the excess is at most `k / 2` rows
/// (81 on NEON). A flat 81 would refuse the transform at m = 192..272
/// on every big-window shape where it wins today, and the curve adds
/// 16 rows at S = 2,048 falling to nothing past S = 31,459, which is
/// what leaves a big box's dispatch as it was.
///
/// **The one parameter does not describe 1 MiB, measured 16 Sep 2026**,
/// and it is the SHAPE rather than `k` (see [`NTT_WINDOW_COMBINE_X86`],
/// which was re-measured that day and kept). Three ladders on one fixture
/// in one sitting on the GFNI-256 part put the crossover's excess over a
/// resident ladder at 13 rows for 2,064-source windows and ~123 for 1,040,
/// where this curve grows 2.2x between them and the measurement grows 8x:
/// no `k` fits both (73 fitted to one, 246 to the other). It errs
/// CONSERVATIVE at both with the shipped 312 - it over-asks, so a window
/// it refuses folds - which is why nothing was changed on two points
/// (`research/NTT-ROW-GATE-GFNI-AVX512-2026-09-15.md`, "`k` at 1 MiB").
///
/// **ANSWERED the same day, and the one parameter STAYS** - five window
/// sizes on that fixture, in that note's "The windowed ask's FORM"
/// section. The small-window end is not a curve-shape problem at all:
/// [`crate::par2repair::reconstruct`]'s `plan_slabs` keeps `2 * m * w`
/// inside the budget, so a window of `S` sources only survives to
/// m ~ S/2, and a 784-source probe walks into that limit with the fold
/// winning by 32%. So the protection down there is ARITHMETIC, and a
/// second parameter fitted to recover the large-window band would lower
/// the ask across the range and give it up where the fold is measured
/// winning - with a fitted pole too unstable to ship anyway (~921 across
/// one sitting, ~226 across another). What today's conservatism costs is
/// ~40 rows of `m` at 1,500-2,000-source windows, worth nothing to ~7% of
/// repair CPU. A rung up, at 4 MiB, the window term's cost in rows is the
/// SAME and it is [`ntt_min_missing`]'s block-size clause that stops
/// carrying (that note's "The 4 MiB windowed ladder").
///
/// **THE TREE TERM ABOVE IS UNCAPPED, AND THAT IS WHY THE DEPTH-2 TILE
/// COSTS THIS GATE NOTHING** (17 Sep 2026,
/// `research/PARFAST-BARE-RAISE-TIMING-2026-09-16.md`, sections 8.12.10
/// and 8.14.12). The model this hyperbola is solved out of charges
/// `c_w * m` for the upper tree with no cap on `m`, where
/// [`NTT_MIN_WINDOW_PRESENT`] states the same charge as
/// `c_w * min(m, 4369)`. Above the tile BOTH are wrong and they are
/// wrong in OPPOSITE directions: the measured charge bends there to
/// 12.47% of its slope on NEON and 15.9% on the nibble class, so the
/// capped form under-charges the transform and this one over-charges
/// it. **The truth sits between the file's two statements, and the
/// executable one is on the safe side** - over-charging the transform
/// raises the ask, so the gate refuses a window it could have admitted
/// and that window folds.
///
/// **On NEON the tile is not reachable by this gate at all.** The ask
/// is `gate + gate * k / (S - k)` over a budget holding `S` sources, so
/// it reaches 4,369 only for:
///
/// | class arm | `gate` | `k` | ask >= 4,369 at | admitted? |
/// |---|---:|---:|---|---|
/// | NEON | 192 | 163 | `S <= 170` | **no** |
/// | x86 nibble (fan-in 4) | 256 | 312 | `S <= 331` | S = 320..331 |
/// | x86 fan-in 12, and GFNI-256 under 1 MiB | 320 | 312 | `S <= 336` | S = 320..336 |
/// | x86 GFNI-256 from 1 MiB | 352 | 312 | `S <= 339` | S = 320..339 |
///
/// [`NTT_MIN_WINDOW_PRESENT`] refuses every window under 320 sources
/// before the curve is consulted, so on NEON the two bounds are 170 and
/// 320 and do not overlap. On the x86 arms they do - by twelve,
/// seventeen and twenty budgets. 8.12.10 rounded the first band away
/// ("about 332 - a window `NTT_MIN_WINDOW_PRESENT` refuses at 320
/// anyway") and 8.14.12 corrected it on the nibble arm; **the other two
/// rows are this block's own arithmetic**, because
/// [`ntt_min_missing_for`] answers three different gates on x86 and
/// both rounds priced x86 as one class.
///
/// **In every one of those bands the error is the conservative one**,
/// and it is not small at the bottom: at S = 320 the nibble arm asks
/// 10,240 rows where the bent charge wants about 4,540, falling to 2%
/// over by S = 331. It is also a band the slab arithmetic three
/// paragraphs up already protects - `plan_slabs` keeps `2 * m * w`
/// inside the budget, so 4,369 rows against at most 331 blocks puts
/// `2 * m` at 26 times the whole window. **Nothing to move, on any
/// arm**: the understatement is a defect of the MODEL as
/// [`NTT_MIN_WINDOW_PRESENT`] states it, not of a decision this gate
/// makes.
///
/// **THE OTHER TERM IS NOT A CONSTANT EITHER** (17 Sep 2026, sections
/// 8.15.1 and 8.15.9 item 3). The `c_l * S` above treats the leaf cost
/// as flat in the window's sources, and across 8.11, 8.12 and 8.14 it
/// measured flat - but those ladders all sat well under 16,000 sources
/// a window. Past that it collapses by about a factor of ten.
/// **No constant in this family is damaged**, because every one of them
/// was measured inside the flat band. The error direction is the
/// conservative one again - over-pricing the leaves raises the ask, so
/// the gate prefers the fold where it need not - and it only arises on
/// a big box with a budget wide enough for a window that wide.
///
/// **AND IT IS A LEAF-KERNEL SWITCH, AT A THRESHOLD WITH A NAME**
/// (section 8.17, which closed 8.15.8's first stated limit; 162 legs on
/// NEON at 256 KiB plus an untimed leaf-fill census). `par2ntt` admits
/// each leaf to a kernel BY FILL: the fixed-cost 512-point additive FFT
/// at or above `par2ntt::additive::MIN_SOURCES` = 128 sources, else the
/// O(fill) paired leaf. Base logs are coprime to 65,535 so 128 of the
/// 255 Rader-257 leaves are live, a window of `S` sources has mean leaf
/// fill `S / 128`, and the mean leaf crosses the gate at
/// `128 * MIN_SOURCES` = **16,384 sources**. Measured there: `df/dS` is
/// 0.16337 ms/source below and 0.01671 above at 256 KiB, and with
/// `NZBFAST_NTT_ADDITIVE=0` it is 0.16331 below and **0.17482 above** -
/// the collapse is that one kernel and nothing else.
///
/// **WRITE THE THRESHOLD AS `128 * additive::MIN_SOURCES`, NEVER AS
/// 16,384**: it moves with that gate, which is measured at 64 and 192
/// as well as at the shipped 128. **And it is a KNEE, not a band** -
/// the leaves go 0 additive at S = 16,000 to all 128 at 16,896, about
/// 900 sources - so 8.15's "14,000 to 22,000" was that round's secant
/// spacing and not the shape. Do not re-derive the leaf-OCCUPANCY
/// account (`128 x 257 = 32,896`): the same coprimality excludes one of
/// a leaf's 257 slots, so `128 x 256` is `par2gen::MAX_INPUT_SLICES`
/// exactly and 32,896 is off the end of the axis.
pub(crate) fn ntt_window_row_gate(sources: usize, gate: usize, k: usize) -> Option<usize> {
    let spare = sources.checked_sub(k).filter(|&s| s > 0)?;
    Some(gate.saturating_add(gate.saturating_mul(k) / spare))
}

/// The conservative shape gates, as a pure function so the tests pin
/// them without touching the process environment - `stream_windows` is
/// the caller's `NZBFAST_NTT_STREAM` reading, passed in for that reason.
pub(crate) fn ntt_gates_pass(
    block_size: usize,
    n_present: usize,
    n_missing: usize,
    exp_span: usize,
    budget: usize,
    stream_windows: bool,
) -> bool {
    n_missing >= ntt_min_missing(block_size)
        && n_present >= NTT_MIN_PRESENT
        // The present gate's low-m branch. `saturating_mul` is not
        // decoration: both counts reach the PAR2 ceiling of 65,535, and
        // 65,535^2 does not fit a 32-bit `usize` (armv7), where the
        // wrapped product would refuse a shape the gate means to admit.
        && n_present.saturating_mul(n_missing) >= ntt_min_work()
        // The span gate. A set posted whole spans `n_missing - 1` and
        // takes the floor arm unconditionally; everything wider has to
        // carry [`NTT_MIN_WORK_PER_ROW`] of work for each row the
        // transform will EVALUATE, not just for each row anyone wants.
        // `saturating_mul` on both sides for the reason the work clause
        // above gives - and the two saturate the same way, so a 32-bit
        // host does not answer differently: 65,535 x 768 is well inside
        // a u32, and a product that does saturate is already far past
        // any span the PAR2 ceiling allows.
        && (exp_span < n_missing
            || exp_span.saturating_mul(NTT_MIN_WORK_PER_ROW)
                < n_present.saturating_mul(n_missing))
        && ntt_retention_admits(block_size, n_present, n_missing, budget, stream_windows)
}

/// The retention arm of [`ntt_gates_pass`]: the corpus fits the budget
/// (one window - the retained path, unchanged), or the budget holds a
/// window worth transforming at this row count and the worker takes the
/// corpus a window at a time. The budget itself is untouched either
/// way, so the peak resident set is what it always was - this admits
/// shapes the flat "corpus must fit" clause refused, it never raises
/// what one of them holds.
pub(crate) fn ntt_retention_admits(
    block_size: usize,
    n_present: usize,
    n_missing: usize,
    budget: usize,
    stream_windows: bool,
) -> bool {
    if n_present.saturating_mul(block_size) <= budget {
        return true;
    }
    stream_windows && ntt_window_row_ask(block_size, budget).is_some_and(|rows| n_missing >= rows)
}

/// The fewest missing rows a window of `corpus_budget` bytes admits the
/// transform at ([`ntt_window_row_gate`] under this build's row gate and
/// combine ratio), or `None` when the window is too small for ANY row
/// count - under [`NTT_MIN_WINDOW_PRESENT`], or at or under `k` sources.
///
/// One function for two readers, because they must agree:
/// [`ntt_retention_admits`] admits a windowed corpus on it, and
/// [`ntt_admit_within`] reads its `None` as "refused on the ARENAS" - the
/// one refusal a narrower stripe can honestly answer.
///
/// A window of full-length slices, which is what this divides. The
/// worker charges a short tail its zero-padded block as well as its fed
/// bytes (the pad arena the transform builds), so a set that is ALL
/// tails fills a window at about half this count - which the curve then
/// prices as the smaller window it is not, in the fold's favour. Stated
/// in whole blocks for that reason.
pub(crate) fn ntt_window_row_ask(block_size: usize, corpus_budget: usize) -> Option<usize> {
    let sources = corpus_budget / block_size.max(1);
    if sources < NTT_MIN_WINDOW_PRESENT {
        return None;
    }
    ntt_window_row_gate(sources, ntt_min_missing(block_size), ntt_window_combine())
}

/// Whether an over-budget corpus may take the transform one window at a
/// time. `NZBFAST_NTT_STREAM=0` is the A/B arm: it restores the flat
/// "the whole corpus must fit the budget" admission the dispatcher used
/// until 5 Sep 2026.
pub(crate) fn ntt_stream_windows() -> bool {
    !std::env::var_os("NZBFAST_NTT_STREAM").is_some_and(|v| v == "0")
}

/// The resident-corpus budget the CREATE transform may spend.
///
/// The repair's `ntt_budget_env` prices against the MACHINE (RAM/4,
/// cgroup/4, a flat 64 GiB ceiling), so `--mem-limit 512M` on a 64 GB
/// box left this reading ~16 GiB and the copied fallback below
/// allocating `ntt_window * block_size` off the back of it, several
/// GiB, none of it charged to CreateAdmission. `par2gen::accum_budget` was
/// moved onto the process budget for exactly this reason (a 2.247 GB
/// peak against a 512 MB published budget); the transform was left
/// behind.
///
/// Only a PUBLISHED budget binds: `process_budget` substitutes
/// host-derived `MemBudget::auto` when nothing set one, and taking that
/// would re-cap every library caller and bench box - auto's 16 GiB
/// ceiling is under the M3 Ultra's measured 10 GiB corpus's headroom.
/// `NZBFAST_NTT_BUDGET` still overrides absolutely, either direction.
///
/// A published limit a PERSON set binds in either direction too, since
/// 15 Sep 2026, raising only to cgroup / 4 under a cgroup limit; a
/// published `auto` only lowers - [`clamp_to_published`] says why.
///
/// Used by BOTH the creator and the repair since 8 Sep 2026. The
/// creator honoured the published budget and the repair did not, so a
/// `--mem-limit` that held creation to 2 GiB let a repair on the same
/// binary retain against host RAM instead - the limit bound one
/// direction of the same job, which is the outcome
/// [`crate::mem::set_process_budget`] documents itself as existing to
/// stop. One function rather than a create/repair pair, because it is
/// one rule and a pair invites the two halves to drift back apart.
pub(crate) fn ntt_budget_within_published() -> usize {
    // The override is resolved ONCE, here, and only a host-derived
    // default is clamped. Asking `var_os` inside the clamp instead
    // meant an UNUSABLE value (`NZBFAST_NTT_BUDGET=banana`, or one that
    // is not valid UTF-8) counted as an override: `ntt_budget_env`
    // would fall back to the host default and the clamp would then wave
    // that default through as if the user had chosen it, so a typo
    // silently bought back the whole host budget. Same shape in
    // `solve_window_budget`'s own fallback. Taking the parsed
    // `Option` makes the state unrepresentable rather than guarded.
    match ntt_budget_override() {
        Some(explicit) => explicit,
        None => clamp_to_published(host_ntt_budget()),
    }
}

/// The published-budget clamp, in ONE place and PURE: no environment,
/// no host probe, so a test can drive both sides of it without touching
/// process-global state that cannot be un-published.
///
/// **Which direction a published budget binds in (15 Sep 2026).** A
/// limit a PERSON set - `parfast -m`, `--mem-limit`, the daemon's
/// `mem_limit` setting, an embedded host's limit, all of which arrive
/// through [`crate::mem::MemBudget::from_user_limit`] - REPLACES the host
/// default in both directions, up to [`NTT_BUDGET_CEIL`] and the address
/// space. Until then it only ever lowered it, so `parfast r -m256` on a
/// 512 MB box still solved and retained against RAM/4 = 128 MB, and only
/// the two raw env overrides could go higher. The design: the
/// automatic default stays RAM/4, because the window is the one
/// allocation an OOM kill cannot be rescued from (a 512 MB Linux box
/// floors at 160-180 MB and RAM/4 already lands near 340 MB peak,
/// `research/PARFAST-REPAIR-RSS-FLOOR-2026-09-14.md`), and the room above
/// it comes from the knob the user already owns.
///
/// **A published budget that is NOT a person's figure still only
/// lowers**, and that half is load-bearing rather than caution: the
/// nzbfast CLI, the daemon and the embedded host publish
/// `MemBudget::auto` when nobody set a limit, and auto is RAM/4 FLOORED at
/// 256 MiB and cgroup/2 rather than cgroup/4. Letting that raise would
/// double the repair window on every sub-1 GiB box and in every
/// memory-limited container with nothing set at all - the automatic
/// default moving, which is exactly what the decision rules out.
/// [`crate::mem::published_user_limit`] is what tells the two apart.
///
/// **Under a cgroup limit a person's figure raises only to cgroup / 4
/// (decided 15 Sep 2026).** Built uncapped, the raise let `-m256` inside
/// `MemoryMax=512M` hand both budgets 256 MiB where the container's
/// quarter held 128, and 9 of 36 legs were OOM-killed inside the first
/// slab on cells main completed every time, with a fixed glibc mmap
/// threshold still leaving a kill
/// (`research/PARFAST-512MB-CGROUP-REPAIR-2026-09-15.md`, the addendum).
/// So the chosen arm is `min(user, cgroup / 4)`: inside a container that
/// is the shipped lowering-only dispatch exactly, and a container user
/// widens the window by giving the container more memory; on a bare box
/// (no cgroup limit) the raise stands as built. A figure below the
/// quarter still lowers.
pub(crate) fn clamp_to_published(base: usize) -> usize {
    clamp_to(
        base,
        crate::mem::published_budget().map(|b| b.total),
        crate::mem::published_user_limit().is_some(),
        crate::mem::cgroup_mem_limit(),
    )
}

/// [`clamp_to_published`] with its three process-global reads handed in:
/// `published` is the published total, `chosen` whether a person set it,
/// `cgroup_limit` the container's hard limit when there is one.
/// Pure, so `published_clamp_tests` drives every arm without publishing.
fn clamp_to(base: usize, published: Option<u64>, chosen: bool, cgroup_limit: Option<u64>) -> usize {
    match published {
        // A person's figure binds both ways. The ceiling is the same flat
        // one the host default has, and the address-space clamp keeps a
        // figure written for a bigger machine from asking a 32-bit process
        // for more than it can hold (`reconstruct::fit_addressable`'s
        // reasoning; the same `max_total` it asks). The cgroup quarter is
        // the same one `ntt_default_budget` takes, and caps the raise in a
        // container (`clamp_to_published` says why).
        Some(total) if chosen => usize::try_from(
            total
                .min(NTT_BUDGET_CEIL)
                .min(crate::mem::MemBudget::max_total())
                .min(cgroup_limit.map_or(u64::MAX, |l| l / 4)),
        )
        .unwrap_or(usize::MAX),
        Some(total) => base.min(usize::try_from(total).unwrap_or(usize::MAX)),
        None => base,
    }
}

/// The explicit `NZBFAST_NTT_BUDGET`, or `None` when it is unset, not
/// valid UTF-8, or not a number. Unset and unusable answer alike ON
/// PURPOSE: a value nothing can read is not a choice to honour.
fn ntt_budget_override() -> Option<usize> {
    std::env::var("NZBFAST_NTT_BUDGET")
        .ok()
        .and_then(|v| v.parse().ok())
}

fn host_ntt_budget() -> usize {
    ntt_default_budget(crate::mem::physical_ram(), crate::mem::cgroup_mem_limit())
}

/// The host budget with the published one NOT applied - the dispatcher
/// tests' control arm, which drives both sides of `clamp_to_published`
/// without publishing anything. Production has no caller: retention and
/// the transform both go through [`ntt_budget_within_published`], and a
/// second door onto the same number is how the two halves of one rule
/// drift apart (`retain.rs` sat on this one until 9 Sep 2026).
#[cfg(test)]
pub(crate) fn ntt_budget_env() -> usize {
    ntt_budget_override().unwrap_or_else(host_ntt_budget)
}

/// The exponent span the transform will produce for this recovery set:
/// `len - 1` when the exponents are a unit-stride progression the
/// repair relabels to a consecutive set (the same test
/// `reconstruct::progression_parameters` applies, with its
/// offset-in-range filter), else `max - min` for the range plan. What
/// the exponent-gap gate and the arena pricing measure.
pub(crate) fn exponent_span(exponents: &[u32]) -> usize {
    let max = exponents.iter().copied().max().unwrap_or(0) as usize;
    // The A/B arms price what they will run: with the range plan off the
    // transform produces the whole prefix, and with the relabel off a
    // progression is just its range.
    if std::env::var("NZBFAST_REPAIR_NTT_RANGE").ok().as_deref() == Some("0") {
        return max;
    }
    if std::env::var("NZBFAST_REPAIR_NTT_PROGRESSION")
        .ok()
        .as_deref()
        != Some("0")
    {
        let progression =
            super::reconstruct::progression_parameters(&[], exponents).filter(|(_, e)| {
                (*e as usize)
                    .checked_add(exponents.len())
                    .is_some_and(|end| end <= crate::par2ntt::N)
            });
        if progression.is_some() {
            return exponents.len().saturating_sub(1);
        }
    }
    let min = exponents.iter().copied().min().unwrap_or(0) as usize;
    max - min
}

/// The stripe width the CREATE's transform runs at when `NZBFAST_NTT_W`
/// does not pin it (the repair's own since 15 Sep 2026, when it measured
/// 512 better at 1 and 4 MiB: [`repair_stripe_words`]): 512 words, except
/// 1,024 on the x86 nibble-shuffle arms (AVX2
/// or SSSE3 without GFNI, `gf16::multi_fold_width() == 4`) at blocks of
/// 1 MiB and up. Measured 6 Sep 2026 on the i5-10600KF, same binary,
/// mirrored, outputs identical (lane parfast-optimisation-search-2,
/// rounds Z and AC): the 10 GiB / 1 MiB create 17.22 / 17.91 s at 1,024
/// against 17.84 / 18.57 at 512 (CPU 177-179 against 183-189), the
/// 10 GiB / 4 MiB / 256-row create 21.54 / 21.69 against 22.01 / 22.37
/// (CPU 222-225 against 230-232), the 10 GiB / 1 MiB / 900-missing
/// repair flat (25.08 / 25.32 against 24.97 / 25.83); 2,048 loses at
/// 4 MiB (23.58 / 23.65) and 1,024 lost on the 64 KiB shapes on 5 Sep
/// (the physical-core round, `heavy repair 3.28-3.35 s`), which is why
/// the rule keys on the block size. The M3 Ultra at the same shapes is
/// flat to worse at 1,024 (transform 2.54-2.66 s against 2.30-2.57 on
/// the repair), so aarch64 and the GFNI arms keep 512.
///
/// RE-MEASURED 16 Sep 2026 on the same i5, one binary, 45 gated legs
/// (`research/CREATE-STRIPE-WIDTH-X86-2026-09-16.md`). The 6 Sep result
/// reproduces at the fill it was set on: 1,024 wins the 10 GiB creates on
/// both wall and CPU, disjoint, at 1 MiB (2.3% / 3.3%) and 4 MiB (1.9% /
/// 2.3%), against an A/A floor of 0.4-0.7%. So this rule stays and the
/// per-pass split is measured rather than inherited.
///
/// BUT THE SIGN REVERSES AT A HIGH LEAF FILL, WHICH THE BLOCK SIZE CANNOT
/// SEE, AND SINCE 16 Sep 2026 THIS FUNCTION READS THE LEAF KERNEL TOO.
/// The 6 Sep control shapes fill leaves to 19-81 and run the PAIRED leaf;
/// near PAR2's 32,768-block ceiling the fill is 256 and the ADDITIVE leaf
/// takes over (its gate is 128 sources), and there 512 wins by 8.7% /
/// 8.1% at 1 MiB and 11.9% / 14.7% at 4 MiB, also disjoint. Across both
/// block sizes the block size predicted nothing and the fill predicted
/// the sign every time.
///
/// THE LADDER THAT LOCATED IT (`research/CREATE-WIDTH-FILL-LADDER-I5-2026-09-16.md`,
/// 123 legs on the same i5, one binary, 1 MiB blocks throughout so only
/// the fill moves): the preference does not slide with the fill, it STEPS
/// at `par2ntt::additive`'s 128-source gate. `w512` against `w1024` reads
/// +3.3% wall / +3.8% CPU at median fill 126, the last all-paired plan,
/// and -19.8% / -21.4% at 129, the first all-additive one - one source of
/// fill, 23 points of wall, both cells disjoint against A/A floors of
/// 0.3-2.0%. It is the majority of leaves and not the fraction: 31 of 128
/// leaves additive still behaves like the paired regime (+3.1%) and 96 of
/// 128 like the additive one (-8.3%), which is why the key is the MEDIAN
/// leaf's kernel (`par2ntt::FlatPlan::median_leaf_kernel`). Above the gate
/// 512's win decays and is largest at the gate: -19.8% at fill 129, -12.9%
/// at 160, -12.9% at 192, -3.8% at 256. THE DECAY IS MEASURED AND
/// UNEXPLAINED; "512 above the gate" is right at every point on that
/// ladder, so it does not block this rule, but nobody should write a
/// width that varies WITHIN the additive regime without explaining it.
///
/// THE ARM TEST IS NOT WIDENED, AND THAT IS MEASURED RATHER THAN CAUTIOUS
/// (`research/CREATE-WIDTH-ADDITIVE-KERNEL-GFNI-2026-09-16.md`, 63 legs on
/// the fleet's one GFNI-256 part at the same cell shapes). Forcing W 1,024
/// above the gate there does not reproduce the penalty, it REVERSES the
/// sign on both columns: `w512` against `w1024` is +3.4% / +2.9% at fill
/// 129 and +6.6% / +7.3% at 160. So a kernel-keyed width applied to every
/// arch would cost that box 3-7% of its transform at exactly the fills it
/// aimed at.
///
/// AARCH64 IS THE THIRD ARM AND IT REFUSES THE PENALTY TOO
/// (`research/CREATE-WIDTH-AARCH64-2026-09-16.md`, the same cells through
/// `research/harness/cstripe-mac.py`; read its CPU column, it discards its
/// own wall as noise). Forcing W 1,024 above the gate reads +0.4% CPU at
/// fill 129, +1.8% at 160, +0.9% at 192 and +2.1% at 256 - a small BENEFIT
/// there too, with no trace of a 10-20% penalty at any above-gate cell. So
/// both arms that run 512 refuse it and THE NIBBLE ARM IS ALONE, which is
/// what makes this arm test the right place for the clause rather than a
/// coincidence of where the arm test already sat.
///
/// The step at the gate is real on all three arms, and its SIZE and its
/// DIRECTION are both the arm's: -25.2 points of CPU here, -9.7 on
/// GFNI-256, and **+6.0 on NEON**, which shifts toward 1,024 rather than
/// away from it. The kernel modulates; the ARM decides - and it does not
/// modulate the same way everywhere, so no rule may assume it does.
/// aarch64 and GFNI keep 512 at every fill, which is what they already
/// ran; on NEON that is measured RIGHT below the gate (512 wins there by
/// 5.6-10.1% of CPU) and mildly wrong above it, by about 2%, which is a
/// separate item and not this clause's.
///
/// THIS CLAUSE SHIPPED WITHOUT EVER BEING OBSERVED ON THE ARM IT
/// AFFECTS, AND THAT IS A DELIBERATE, REVERSIBLE DECISION RATHER THAN AN
/// OVERSIGHT. The rule above rests on 186 legs across three arms. What
/// has never been watched is this IMPLEMENTATION of it selecting a width
/// on an x86 nibble part: the one such part on the test fleet was
/// occupied for the whole of 16 Sep 2026 and the verifying round never
/// got a slot, so the change shipped with that round scheduled rather
/// than held back.
///
/// **So this constant is PROVISIONAL until that round runs**, and its
/// failure mode is the invisible one - a clause that never fires looks
/// exactly like a clause that fired and bought nothing. Two readings are
/// REVERT proposals and not tuning exercises: a plan at median leaf fill
/// 126 whose timing MOVES at all means the clause is firing below the
/// gate where the ladder says it must not, and one at fill 129 whose
/// unpinned arm still runs W 1,024 means the wiring never fired.
/// **Whoever runs that round deletes these two paragraphs**, in either
/// direction. While they stand, nobody should cite this rule as
/// measured.
///
/// `median_leaf` is `None` where the caller has no plan to ask, and that
/// resolves to the pre-16-Sep behaviour rather than to 512: an absent
/// plan is not evidence of a full leaf.
///
/// THE REPAIR IS A SEPARATE RULE AND IS NOT TOUCHED BY ANY OF THIS -
/// [`repair_stripe_words`] is 512 at every block size on every arm, and
/// the two passes were measured apart.
pub(crate) fn default_stripe_words(
    block_size: usize,
    median_leaf: Option<crate::par2ntt::LeafKernel>,
) -> usize {
    if cfg!(target_arch = "x86_64") && crate::gf16::multi_fold_width() == 4 && block_size >= 1 << 20
    {
        if median_leaf == Some(crate::par2ntt::LeafKernel::Additive) {
            512
        } else {
            1024
        }
    } else {
        512
    }
}

/// The stripe width the REPAIR's transform runs at when `NZBFAST_NTT_W`
/// does not pin it: 512 words at every block size on every arm. Until
/// 15 Sep 2026 the repair took [`default_stripe_words`], whose 1,024 on
/// the x86 nibble arms at 1 MiB and up was won on the CREATE (6 Sep) with
/// the one repair it was checked on flat. Measured apart on the
/// i5-10600KF, one binary per round, forced transform on twelve threads,
/// four mirrored reps, SHA-gated with the width read back from the trace
/// (research/NTT-X86-TRANSFORM-CPU-1MIB-2026-09-15.md), 512 beat 1,024
/// on BOTH wall and whole-process CPU at every cell: at 1 MiB, (256
/// missing, 512 present) 4.72 s / 41.2 CPU-s against 4.89 / 42.2, (256,
/// 2,048) 5.83 / 51.7 against 6.02 / 53.6, (320, 1,536) 6.11 / 53.7
/// against 6.23 / 54.9, (1,024, 512) 16.68 / 144.6 against 16.82 / 146.1;
/// at 4 MiB, (256, 512) 19.72 / 164.4 against 20.43 / 169.8 and (256,
/// 1,024) 20.88 / 177.6 against 21.57 / 183.5 - against an A/A floor of
/// +1.1% wall. The 6 Sep 10 GiB / 1 MiB / 900-missing repair was flat
/// between the two, so no measured repair loses; aarch64 and the GFNI
/// arms were at 512 already.
pub(crate) fn repair_stripe_words() -> usize {
    512
}

/// Stripe width and worker count the REPAIR's syndrome pass will use for
/// this block size. Factored out of `Reconstructor::ntt_syndromes` so the
/// admission gate prices the arenas with the SAME geometry the transform
/// actually runs - an estimate derived independently would drift.
pub(crate) fn ntt_stripe_geometry(block_size: usize) -> (usize, usize) {
    ntt_stripe_geometry_capped(block_size, usize::MAX)
}

/// Stripe width and worker count the CREATE's transform runs at: the same
/// pool rule and pin as the repair, over [`default_stripe_words`], the
/// width the create was measured at. The two passes share every other
/// part of the geometry.
///
/// `median_leaf` is the plan's [`crate::par2ntt::FlatPlan::median_leaf_kernel`],
/// which the width has read on the x86 nibble arm since 16 Sep 2026, and
/// `None` from a site with no plan in hand. Every caller that HAS a plan
/// passes it: the width is a property of the transform about to run, not
/// of the block size alone.
pub(crate) fn ntt_create_stripe_geometry(
    block_size: usize,
    median_leaf: Option<crate::par2ntt::LeafKernel>,
) -> (usize, usize) {
    stripe_geometry_at(
        block_size,
        default_stripe_words(block_size, median_leaf),
        usize::MAX,
    )
}

/// An explicit `NZBFAST_NTT_W` (16 words or more), or `None`.
fn ntt_stripe_pin() -> Option<usize> {
    std::env::var("NZBFAST_NTT_W")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&v: &usize| v >= 16)
}

/// [`ntt_stripe_geometry`] with the stripe held at or under `cap` words -
/// the width [`ntt_admit_within`] narrowed to so the worker arenas fit
/// the budget, or `usize::MAX` for the geometry's own. The admission
/// price and the transform both run through this, so a narrowed stripe
/// is priced at exactly the width it then runs at.
pub(crate) fn ntt_stripe_geometry_capped(block_size: usize, cap: usize) -> (usize, usize) {
    stripe_geometry_at(block_size, repair_stripe_words(), cap)
}

/// The geometry both passes share: `default_w` unless `NZBFAST_NTT_W`
/// pins it, held under `cap` and the block, and the transform's pool.
fn stripe_geometry_at(block_size: usize, default_w: usize, cap: usize) -> (usize, usize) {
    let words = block_size / 2;
    let w: usize = ntt_stripe_pin()
        .unwrap_or(default_w)
        .min(cap)
        .min(words.max(16));
    let stripes = words.div_ceil(w);
    // Every logical CPU, on purpose: the transform's leaf is table-lookup
    // bound and an SMT sibling fills its stalls, where the fold is
    // bandwidth bound and a sibling only thrashes its tiles. Until 5 Sep
    // 2026 this took fold_parallel's physical-core rule on Windows x86,
    // which halved the pool on SMT parts: an i5-10600KF (6c/12t), quiet,
    // two mirrored rounds - heavy repair 3.28-3.35 s on six threads vs
    // 2.85-2.93 on twelve, the 64 KiB create 2.37-2.53 vs 2.06-2.14
    // (-13% both); a 1,024-word stripe lost on either count. Hybrid parts
    // without SMT (Core Ultra 9 386H) report physical == logical and
    // never saw the rule. `NZBFAST_NTT_THREADS` still pins it.
    //
    // Re-asked 15 Sep 2026 at 1 MiB blocks, where the i5's forced repair
    // transform cost 1.2-2.6x the fold's CPU: six threads cuts that CPU
    // 15-36% and takes it UNDER the fold's at every shape the gates admit,
    // but it pays in wall exactly there - (256 missing, 2,048 present)
    // 6.61 s against 6.02 on twelve, which is the fold's 6.58, so the win
    // the transform was admitted for is gone - and the 64 KiB heavy shape
    // still reads +17% wall for -14% CPU on six. The pool stays every
    // logical CPU; trading wall for CPU is a policy call, not a
    // measurement (research/NTT-X86-TRANSFORM-CPU-1MIB-2026-09-15.md).
    let cores = crate::mem::cpu_workers();
    let threads = std::env::var("NZBFAST_NTT_THREADS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(cores)
        .clamp(1, stripes.max(1));
    (w, threads)
}

/// Everything the NTT allocates OUTSIDE the resident corpus: the
/// per-worker arenas times the worker count.
///
/// This estimate counts ONLY the NTT's INCREMENTAL footprint - the
/// retained corpus (priced by the caller), these per-worker Scratch
/// pools and output rows, and the short-tail pad arena (charged at
/// runtime by the fold worker, which is the first place the tail count
/// is known). It deliberately does NOT count the syndrome rows, the
/// inverse matrix or the reconstructed output: the streaming fold
/// allocates every one of them identically, so they belong to the
/// repair baseline that the quarter-of-the-OOM-line budget exists to
/// leave room for. Charging them here would refuse the fast path for
/// memory the process spends either way.
pub(crate) fn ntt_worker_arenas(block_size: usize, needed: usize) -> usize {
    ntt_worker_arenas_capped(block_size, needed, usize::MAX)
}

/// [`ntt_worker_arenas`] at a capped stripe
/// ([`ntt_stripe_geometry_capped`]).
pub(crate) fn ntt_worker_arenas_capped(block_size: usize, needed: usize, cap: usize) -> usize {
    let (w, threads) = ntt_stripe_geometry_capped(block_size, cap);
    crate::par2ntt::FlatPlan::scratch_bytes(needed, w).saturating_mul(threads)
}

/// What [`resolve_syndrome_path`] hands the Reconstructor when it selects
/// the transform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NttAdmission {
    /// The RETENTION budget the worker's runtime backstop compares
    /// retained bytes against: the corpus budget, arenas already paid.
    pub(crate) budget: usize,
    /// The widest stripe the transform may run at, in words - a cap on
    /// [`ntt_stripe_geometry_capped`], `usize::MAX` for the geometry's
    /// own width.
    pub(crate) stripe_cap: usize,
}

/// The narrowest stripe, in u16 words, the dispatcher will narrow the
/// transform to so its worker arenas fit the budget. Below it, a shape
/// the arenas do not fit folds.
///
/// 32 words is 64 bytes, the widest granule any shipped fused kernel
/// takes (`gf16::xor_mul_multi_gfni512` works in 64-byte chunks; NEON
/// and AVX2 take 32) - the floor `forney::STRIPE_GRAN` holds for the same
/// reason - and every halving from the 512- or 1,024-word default is a
/// power of two, so every narrowed stripe stays on it. It sits above the
/// 16-word minimum [`ntt_stripe_geometry_capped`] allows a PIN, because a
/// pin is an experiment and this is a default.
///
/// What a narrower stripe costs, measured 14 Sep 2026 on the M3 Ultra at
/// `-t4`: the 1 GiB / 64 KiB repair at m = 4,096, forced, the whole
/// corpus in one window, whole-process CPU best of two SHA-gated legs -
/// 13.62 CPU-s at 512 words, 13.86 at 256 (+1.8%), 14.53 at 128
/// (+6.7%), 15.43 at 64 (+13%), 17.92 at 32 (+32%). Even the floor is
/// 7x under the 131 CPU-s the fold costs at that depth, which is what a
/// refusal hands back; and [`ntt_admit_within`] stops at the first
/// width whose arenas no longer outweigh the corpus, so the floor binds
/// only where the rows are deep and the budget tiny.
pub(crate) const NTT_STRIPE_W_FLOOR: usize = 32;

/// Choose the stripe the transform runs at under `budget`, and admit or
/// refuse the shape there. `admit_at(cap)` is the dispatcher's gate
/// priced at a stripe cap; `needed` is the rows the arenas are priced
/// on and `n_present` the corpus.
///
/// **Why narrow rather than refuse.** The arenas are
/// `FlatPlan::scratch_bytes(needed, W)` per worker and grow with the
/// rows with nothing tying them to the budget. At m = 4,096 on four
/// threads they are 161 MB at W = 512 - over a 512 MB box's whole
/// 128 MiB budget - so the corpus budget saturated to zero and the
/// dispatcher took the fold at its worst: 32.95 s / 131 CPU-s, against
/// 4.98 s / 19.0 forced. Forced at `NZBFAST_NTT_W=128` the arenas are a
/// quarter and the same repair cost 4% more (5.17 s / 19.8); halving
/// `NZBFAST_NTT_THREADS` instead cost 34% of wall (6.68 s), which is why
/// the lever is the width and never the pool
/// (`research/PARFAST-SMALL-BUDGET-TRANSFORM-CROSSOVER-2026-09-14.md`,
/// section 3d).
///
/// **The rule, in order.**
///
/// 1. A pinned `NZBFAST_NTT_W` is a pin: priced and admitted at that
///    width, never narrowed. It is the A/B arm.
/// 2. A corpus that fits ONE window at the geometry's own width is
///    admitted or refused there, exactly as before - narrowing could buy
///    it nothing but a slower stripe. This is the arm a big box takes,
///    and why its dispatch is unchanged.
/// 3. Otherwise the stripe halves while the arenas outweigh the corpus
///    budget they leave (`arenas > budget - arenas`): past that point a
///    window is smaller than the arenas beside it, and the per-window
///    combine ([`ntt_window_row_gate`]) costs more than a halving's few
///    percent. At m = 2,048 under 128 MiB (32 KiB slabs) W = 512 leaves
///    1,244 sources a window, 13 windows a slab; W = 256 leaves ~2,670,
///    6.1 a slab.
/// 4. The gates are asked at that width. A refusal narrows further only
///    while the window the width leaves is too small for ANY row count
///    ([`ntt_window_row_ask`] answers `None`) - a refusal on the ARENAS,
///    which is the one thing a narrower stripe answers - down to
///    [`NTT_STRIPE_W_FLOOR`], where a refusal folds.
/// 5. **A window refused on its ROWS folds at the width it was refused
///    at.** Narrowing it would shrink the arenas, hand the window more
///    sources and lower [`ntt_window_row_gate`]'s ask until the rows
///    cleared it - admitting the shape at a stripe the curve never
///    priced, because the curve prices the window and not the stripe.
///    Step 4 did exactly that until 15 Sep 2026: `-t4 -m128`, the
///    1 GiB / 64 KiB set, m = 384 on the Core Ultra 9 386H (GFNI-256),
///    refused at W = 512, narrowed to W = 128, admitted eight 1,920-source
///    windows and paid 14.16 CPU-s against the fold's 10.50 and the
///    full-width forced arm's 10.28; on the inferred combine ratio the
///    same penalty sat one rung up (14.75 against 12.81), so it moved with
///    `k` and never went away. In both x86 validate rounds every other
///    narrowed width was chosen by step 3, so this refuses the band the
///    defect lived in and nothing else. Charging the narrower stripe's
///    cost into the curve instead was weighed and not taken: it needs a
///    per-class stripe-cost constant no x86 box has measured, to rescue a
///    band whose one measured x86 cell lost
///    (`research/PARFAST-SMALL-BUDGET-TRANSFORM-CROSSOVER-2026-09-14.md`,
///    section 8).
pub(crate) fn ntt_admit_within(
    block_size: usize,
    needed: usize,
    n_present: usize,
    budget: usize,
    admit_at: impl Fn(usize) -> Option<NttAdmission>,
) -> Option<NttAdmission> {
    let (w0, _) = ntt_stripe_geometry(block_size);
    let arenas = |cap: usize| ntt_worker_arenas_capped(block_size, needed, cap);
    let whole_corpus = n_present.saturating_mul(block_size);
    if ntt_stripe_pin().is_some() || whole_corpus <= budget.saturating_sub(arenas(usize::MAX)) {
        return admit_at(usize::MAX);
    }
    // Halving to the next power of two below, so a width the block
    // clamped off the granule (a block narrower than the default stripe)
    // lands back on it at the first step.
    let narrower = |w: usize| {
        let p = w.next_power_of_two();
        if p == w { w / 2 } else { p / 2 }
    };
    let cap_of = |w: usize| if w == w0 { usize::MAX } else { w };
    // Refused on the ARENAS (step 4): the corpus does not fit what this
    // width leaves, and that window is too small for any row count to take
    // it a window at a time. The retained-only A/B arm has no windows, so
    // there the corpus not fitting is the whole of it.
    let starved = |cap: usize| {
        let corpus = budget.saturating_sub(arenas(cap));
        whole_corpus > corpus
            && (!ntt_stream_windows() || ntt_window_row_ask(block_size, corpus).is_none())
    };
    let mut w = w0;
    while w > NTT_STRIPE_W_FLOOR && arenas(cap_of(w)) > budget.saturating_sub(arenas(cap_of(w))) {
        w = narrower(w).max(NTT_STRIPE_W_FLOOR);
    }
    loop {
        if let Some(admitted) = admit_at(cap_of(w)) {
            return Some(admitted);
        }
        // Step 5: a refusal the window could answer on its rows folds here.
        if w <= NTT_STRIPE_W_FLOOR || !starved(cap_of(w)) {
            return None;
        }
        w = narrower(w).max(NTT_STRIPE_W_FLOOR);
    }
}

/// Resolve the syndrome path for this repair shape. Returns the
/// retention budget and the stripe cap when the NTT path is selected.
pub(super) fn resolve_syndrome_path(
    path: SyndromePath,
    block_size: usize,
    n_inputs: usize,
    n_missing: usize,
    exponents: &[u32],
) -> Option<NttAdmission> {
    let max_exp = exponents.iter().copied().max().unwrap_or(0) as usize;
    // Hard requirements in every mode: syndromes to compute, sources to
    // transform, and a transform prefix that exists (max exponent
    // within the group order).
    if exponents.is_empty() || max_exp >= crate::par2ntt::N || n_inputs <= n_missing {
        return None;
    }
    // The gate and the arena pricing see the SPAN the plan will actually
    // produce, not the prefix: the range plan starts at the smallest
    // selected exponent, and a unit-stride progression relabels to a
    // consecutive set (reconstruct.rs, the same two rules the transform
    // then applies). Until 5 Sep 2026 a set starting at 8,192 was priced
    // as 8,192 rows and refused into the fold by the exponent-gap gate
    // whatever its real size.
    let exp_span = exponent_span(exponents);
    match path {
        SyndromePath::Fold => None,
        SyndromePath::NttForce(budget)
        | SyndromePath::NttForceCorrupt(budget)
        | SyndromePath::NttForcePanic(budget) => Some(NttAdmission {
            budget,
            stripe_cap: usize::MAX,
        }),
        SyndromePath::Auto => {
            let mode = std::env::var("NZBFAST_NTT").unwrap_or_default();
            let budget = ntt_budget_within_published();
            // The budget has to cover the WHOLE footprint, not just the
            // resident corpus. Every worker allocates a Scratch plus
            // `needed * W` output rows, and the worker count is visible
            // parallelism with no memory cap of its own - so a many-core
            // memory-capped host (a container with --memory and no
            // --cpus) could clear a corpus-only gate and then be
            // OOM-killed mid-repair, which is the one failure the
            // verify-and-retry cannot rescue: catch_unwind does not catch
            // an aborting allocator. Priced up front instead, so an
            // over-footprint shape quietly FOLDS. The fold is
            // bit-identical, is already the unconditional fallback, and
            // was the default until fast par mode landed - this can make
            // a repair slower, never wrong and never refused.
            //
            // What this prices is the NTT's INCREMENTAL footprint only;
            // see [`ntt_worker_arenas`] for what is deliberately left
            // out and why. Priced per candidate stripe width, because a
            // footprint that does not fit at the default width is
            // narrowed before it is refused - see [`ntt_admit_within`].
            let n_present = n_inputs - n_missing;
            let gated = || {
                ntt_admit_within(block_size, exp_span + 1, n_present, budget, |cap| {
                    let corpus_budget = budget.saturating_sub(ntt_worker_arenas_capped(
                        block_size,
                        exp_span + 1,
                        cap,
                    ));
                    ntt_gates_pass(
                        block_size,
                        n_present,
                        n_missing,
                        exp_span,
                        corpus_budget,
                        ntt_stream_windows(),
                    )
                    // The corpus budget, not the whole budget: what comes
                    // back is the RETENTION headroom the worker's runtime
                    // backstop compares against, and the arenas are
                    // already spoken for. Returning `budget` here let a
                    // shape whose actual retention landed between the two
                    // keep retaining past what was priced.
                    .then_some(NttAdmission {
                        budget: corpus_budget,
                        stripe_cap: cap,
                    })
                })
            };
            match mode.as_str() {
                // The environment is the bench/test/ops escape hatch: it
                // overrides the daemon setting in both directions and
                // ignores the trip-breaker.
                //
                // NOTE THE WHOLE `budget` HERE, WHERE `gated()` ABOVE
                // HANDS ON `budget - arenas`: forcing retains the whole
                // budget for the corpus and allocates the worker arenas
                // ON TOP, unpriced. So `force` is a CPU CEILING AND NEVER
                // A MEMORY REFERENCE, and the difference is not small - at
                // 64 KiB blocks, `-m128`, w = 512 and four threads it is
                // 27.95 MiB at m = 224, which buys forcing a 2,112-slice
                // window against the gated path's 1,664 and 7 transform
                // windows against 9. MEASURED 17 Sep 2026: that is the
                // WHOLE of the 4.45% (m = 224) and 6.39% (m = 256) by
                // which `auto` costs more than `force` at rungs where both
                // take this path - 99% of the gap is inside `transform_s`
                // and the admission arithmetic itself differences to zero,
                // and `auto_window = floor_64(force_window - arenas/64KiB)`
                // reproduces both measured widths EXACTLY. Do not read
                // that gap as a dispatcher defect or "fix" it by widening
                // the gated path's retention: it is the price of the
                // budget, `auto` still beats the fold by 3.1% and 9.3%
                // there, and the arenas are priced out of the budget to
                // stop an OOM-kill `catch_unwind` cannot rescue (see the
                // comment on `gated()` above).
                // research/PARFAST-AUTO-VS-FORCED-TRANSFORM-GAP-2026-09-17.md
                "force" => Some(NttAdmission {
                    budget,
                    stripe_cap: usize::MAX,
                }),
                "1" => gated(),
                "0" | "off" => None,
                // Unset: the daemon's "fast par mode" setting decides,
                // unless a divergence tripped the breaker this process.
                _ => {
                    if FAST_PAR_ENABLED.load(std::sync::atomic::Ordering::Relaxed)
                        && !fast_par_tripped()
                    {
                        gated()
                    } else {
                        None
                    }
                }
            }
        }
    }
}

/// The forced-retry seam's OWNERSHIP, which is the half a serial run
/// cannot check.
#[cfg(test)]
mod retry_seam_tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    /// An unrelated repair running concurrently must not consume a
    /// retry it never armed.
    ///
    /// Deterministic rather than probabilistic: the owner is held INSIDE
    /// its first attempt until the unrelated caller has been all the way
    /// through the consume point, which is the exact interleaving the
    /// process-wide `AtomicBool` lost. Against that version this fails
    /// as `(owner 1, unrelated 2)`; the ordinary parallel suite showed
    /// the same theft as `a_fallback_retry_has_two_attempt_ids` failing
    /// beside a different innocent repair in each run.
    ///
    /// `recv_timeout` and not `recv`: a regression here must fail the
    /// gate, never wedge it into nextest's retry-a-timeout path, where a
    /// deadlock can still report `passed (1 flaky)`.
    #[test]
    fn a_concurrent_repair_cannot_steal_a_forced_retry() {
        let (start_tx, start_rx) = mpsc::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let unrelated = std::thread::spawn(move || {
            start_rx.recv().expect("the owner releases us");
            let mut calls = 0usize;
            run_with_ntt_fallback(SyndromePath::Fold, |_, _| {
                calls += 1;
                Ok::<(), RepairError>(())
            })
            .expect("the seam never fails an attempt");
            done_tx.send(()).ok();
            calls
        });

        force_one_retry();
        let mut owner_calls = 0usize;
        run_with_ntt_fallback(SyndromePath::Fold, |_, _| {
            owner_calls += 1;
            if owner_calls == 1 {
                start_tx.send(()).expect("the other thread is waiting");
                done_rx
                    .recv_timeout(Duration::from_secs(30))
                    .expect("the unrelated repair finishes");
            }
            Ok::<(), RepairError>(())
        })
        .expect("the seam never fails an attempt");

        let stolen = unrelated.join().expect("the unrelated thread");
        assert_eq!(owner_calls, 2, "the arming thread still gets its retry");
        assert_eq!(stolen, 1, "and nobody else does");
    }
}

#[cfg(test)]
mod published_clamp_tests {
    use super::{NTT_BUDGET_CEIL, clamp_to};

    /// The clamp itself, driven from both sides without publishing a
    /// budget process-wide - `set_process_budget` cannot be
    /// un-published, so a test that used it would leak into every other
    /// test sharing the process (the `cargo test` one-process run, which
    /// is the only place that class of pollution is visible at all).
    /// That is why `clamp_to` takes the budget rather than reading it.
    #[test]
    fn a_published_budget_binds_and_its_absence_does_not() {
        // MiB, and that is LOAD-BEARING rather than taste. This block
        // was written in GiB (`const GB: usize = 1 << 30`, driven with
        // `8 * GB`), and on a 32-bit target `usize` tops out just under
        // 4 GiB - so `8 * GB` is not a large number there, it is an
        // UNREPRESENTABLE one. rustc const-evaluates it and
        // `arithmetic_overflow` is deny-by-default, so it was a COMPILE
        // error that took the whole `nzbkit-base` lib test target - and
        // with it nightly's armv7-cross job, the repo's only 32-bit
        // coverage - down. Nothing below reads an absolute magnitude:
        // every arm asserts an ORDERING between the host figure and the
        // published one, so the unit is free and the smaller one is the
        // one both widths can spell. Do not restore the GiB spelling.
        const MB: usize = 1 << 20;
        const BIG: usize = 8 * MB;
        const SMALL: usize = 2 * MB;
        // Nothing published: the host-derived budget stands untouched,
        // and `chosen` cannot conjure a budget out of an absence.
        assert_eq!(clamp_to(BIG, None, false, None), BIG);
        assert_eq!(clamp_to(BIG, None, true, None), BIG);
        // Published and SMALLER: it binds, whoever chose it. This is the
        // whole point - a repair on a `--mem-limit`ed process must not
        // solve or retain against host RAM.
        assert_eq!(clamp_to(BIG, Some(SMALL as u64), false, None), SMALL);
        assert_eq!(clamp_to(BIG, Some(SMALL as u64), true, None), SMALL);
        // Published and LARGER, and NOT a person's figure: it only lowers.
        // That published figure is `MemBudget::auto`, which the CLI and
        // the daemon publish when nobody set a limit - RAM/4 floored at
        // 256 MiB, cgroup/2 - so raising to meet it would move the
        // automatic default on every small box and container
        // (`clamp_to_published`).
        assert_eq!(clamp_to(SMALL, Some(BIG as u64), false, None), SMALL);
        // Published and LARGER, and a person's figure: it RAISES the host
        // default (15 Sep 2026) - `parfast r -m256` on a 512 MB box gets
        // the 256 MiB it asked for rather than RAM/4.
        assert_eq!(clamp_to(SMALL, Some(BIG as u64), true, None), BIG);
        // ...capped at the flat ceiling the host default has, and at what
        // this target can address, so the one absolute cap stays absolute.
        let cap = usize::try_from(NTT_BUDGET_CEIL.min(crate::mem::MemBudget::max_total()))
            .expect("the ceiling fits the target");
        assert_eq!(clamp_to(SMALL, Some(NTT_BUDGET_CEIL * 4), true, None), cap);
        assert_eq!(clamp_to(SMALL, Some(u64::MAX), true, None), cap);
        // Equal: admitted, not refused by an off-by-one.
        assert_eq!(clamp_to(SMALL, Some(SMALL as u64), false, None), SMALL);
        assert_eq!(clamp_to(SMALL, Some(SMALL as u64), true, None), SMALL);
        // A budget past `usize` saturates instead of truncating. On a
        // 64-bit host both spellings agree and neither arm can fail, so
        // these two only ever discriminate on a 32-bit build (armv7).
        // 2^32 is the one that BITES: `as usize` truncates it to
        // exactly 0 there, which would clamp every budget to nothing,
        // while `try_from(..).unwrap_or(MAX)` saturates and leaves the
        // host figure standing.
        assert_eq!(clamp_to(SMALL, Some(1u64 << 32), false, None), SMALL);
        // `u64::MAX` is the weaker of the pair and is kept as
        // DOCUMENTATION, not as cover: its low 32 bits are all ones, so
        // the broken `as` spelling happens to land on `usize::MAX` and
        // this arm passes either way, at every width. The arm above is
        // the control; this one only records the intent.
        assert_eq!(clamp_to(SMALL, Some(u64::MAX), false, None), SMALL);
    }

    /// A person's raise under a cgroup limit stops at the container's
    /// quarter (decided 15 Sep 2026): uncapped, `-m256` inside
    /// `MemoryMax=512M` gave both budgets 256 MiB and 9 of 36 legs were
    /// OOM-killed (`research/PARFAST-512MB-CGROUP-REPAIR-2026-09-15.md`).
    /// Magnitudes in MiB for the 32-bit reason the test above records.
    #[test]
    fn a_persons_raise_stops_at_the_cgroup_quarter() {
        const MB: usize = 1 << 20;
        // The 512 MB container: RAM/4 is far above, the quarter is 128.
        let cgroup = Some(512 * MB as u64);
        let quarter = 128 * MB;
        let host_in_cgroup = quarter; // what `ntt_default_budget` gave
        // Bare box (no cgroup limit), a person's limit above RAM/4: it
        // raises, as the uncapped branch did.
        let ram_quarter = 128 * MB; // a 512 MB bare box
        assert_eq!(
            clamp_to(ram_quarter, Some(256 * MB as u64), true, None),
            256 * MB
        );
        // A cgroup limit and a person's limit above the quarter: capped at
        // the quarter, which is the shipped dispatch exactly.
        assert_eq!(
            clamp_to(host_in_cgroup, Some(256 * MB as u64), true, cgroup),
            quarter
        );
        assert_eq!(
            clamp_to(host_in_cgroup, Some(192 * MB as u64), true, cgroup),
            quarter
        );
        // The cap is a ceiling on the RAISE only: a box whose RAM/4 (64)
        // is under its cgroup's quarter still rises to the quarter.
        assert_eq!(
            clamp_to(64 * MB, Some(256 * MB as u64), true, cgroup),
            quarter
        );
        // A person's limit BELOW the quarter still lowers, in or out of a
        // container.
        assert_eq!(
            clamp_to(host_in_cgroup, Some(64 * MB as u64), true, cgroup),
            64 * MB
        );
        assert_eq!(
            clamp_to(ram_quarter, Some(64 * MB as u64), true, None),
            64 * MB
        );
        // No person's limit: the cgroup changes nothing in the clamp (the
        // host figure already carries the quarter), published or not.
        assert_eq!(
            clamp_to(host_in_cgroup, None, false, cgroup),
            host_in_cgroup
        );
        assert_eq!(
            clamp_to(host_in_cgroup, Some(256 * MB as u64), false, cgroup),
            host_in_cgroup
        );
        assert_eq!(clamp_to(ram_quarter, None, false, None), ram_quarter);
    }
}
