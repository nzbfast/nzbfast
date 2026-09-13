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
pub(crate) const NTT_MIN_MISSING: usize = 320;

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
/// vs 2.44-2.57 already at 192. 256 clears every measured shape; the
/// GFNI and AVX-512 arms are unmeasured with the paired leaf and keep
/// [`NTT_MIN_MISSING`].
pub(crate) const NTT_MIN_MISSING_NIBBLE: usize = 256;

/// The row gate this build runs under: [`NTT_MIN_MISSING_NEON`] on
/// aarch64, [`NTT_MIN_MISSING_NIBBLE`] on the x86 nibble arms (keyed on
/// the selected kernel's fan-in, as the back-substitution gate is),
/// [`NTT_MIN_MISSING`] everywhere else.
///
/// This is the VERTICAL asymptote `a/c` of the one crossover
/// [`NTT_MIN_PRESENT`] carries the horizontal end of, so the fold's
/// cost is its denominator too and a fold change moves it the same
/// way. The rule and what it costs to forget it are written out once,
/// at [`NTT_MIN_PRESENT`]; do not re-derive it here.
pub(crate) fn ntt_min_missing() -> usize {
    if cfg!(target_arch = "aarch64") {
        NTT_MIN_MISSING_NEON
    } else if crate::gf16::multi_fold_width() == 4 {
        NTT_MIN_MISSING_NIBBLE
    } else {
        NTT_MIN_MISSING
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
/// covers the gap.
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
/// Both are set past the WORST measured crossover, which is the i5's:
/// the work floor by 1.27x (524,288 against its 413k at m=256) and the
/// present floor by 1.33x (320 against its ~240 at m=2,048), the way the
/// row gate is set 1.2x past its own. That leaves them 1.5-2.7x past
/// every NEON point, which is why this is **one pair for every arch
/// rather than the per-arch pair [`NTT_MIN_MISSING`] needs**: the gap
/// between the boxes fits inside the margin, and a split would rest on
/// four legs a point.
///
/// The floor was 512 for the first day (`fda1e39a5`), which was the
/// value the m = 1,024 row alone supported. Swept past that row on both
/// boxes it came down to 320: at m = 2,048 the crossover is ~215 on the
/// M3 and ~240 here, at m = 4,096 ~165 and under 192, and the band 320
/// takes back is worth 11-15% of the whole repair at m = 2,048 / 384
/// present on both boxes.
///
/// Block size moves the crossover far less than `m` does and always
/// downward (NEON, m = 400: ~650 at 64 KiB, ~580 at 128 KiB, ~460 at
/// 512 KiB), so it is not a third clause - the 128 KiB column above is
/// the conservative one.
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
/// CPU, which is the trade a downloader wants.
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
/// it moves are this constant, [`NTT_MIN_WORK`], [`ntt_min_missing`]
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
/// `n_present * n_missing`, which is what binds below m = 1,024. See
/// [`NTT_MIN_PRESENT`] for the sweep both come from - and for the rule
/// that the fold's cost is this constant's denominator too, so a fold
/// change requires re-deriving it.
pub(crate) const NTT_MIN_WORK: usize = 512 << 10;

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
/// transform is worth running over it - the gate that decides whether a
/// corpus bigger than the budget takes the transform in windows or
/// streams the fold instead.
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
/// The floor is therefore set from the WORSE arm, and from the measured
/// points on either side of it rather than the fit: a 1,030-source
/// window is 1.1x the fold there and a 1,540-source one 1.45x - a whole
/// window of RAM for very little - where 2,048 buys 1.73x (50.8 against
/// 88.4) and 2.3x on the M3. It is also two full eight-source groups of
/// the fused kernel per live leaf (base logs are coprime to 65,535, so
/// only 128 of the 255 leaves carry sources), which is where the leaf
/// stops running under-filled.
///
/// One flat constant rather than a per-arch pair like
/// [`NTT_MIN_MISSING_NIBBLE`]: what separates the two boxes here is the
/// thread count the combine is spread over, not the kernel, so an
/// eight-core Apple part would sit nearer the i5 and an arch-keyed
/// constant would tell it the wrong thing.
///
/// At 2,048 the transform is admitted for blocks up to 512 KiB on a
/// 4 GB box, 1 MiB on 8 GB, 2 MiB on 16 GB and 4 MiB on 32 GB.
pub(crate) const NTT_MIN_WINDOW_PRESENT: usize = 2048;

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
    n_missing >= ntt_min_missing()
        && n_present >= NTT_MIN_PRESENT
        // The present gate's low-m branch. `saturating_mul` is not
        // decoration: both counts reach the PAR2 ceiling of 65,535, and
        // 65,535^2 does not fit a 32-bit `usize` (armv7), where the
        // wrapped product would refuse a shape the gate means to admit.
        && n_present.saturating_mul(n_missing) >= NTT_MIN_WORK
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
        && ntt_retention_admits(block_size, n_present, budget, stream_windows)
}

/// The retention arm of [`ntt_gates_pass`]: the corpus fits the budget
/// (one window - the retained path, unchanged), or the budget holds a
/// window worth transforming and the worker takes the corpus a window
/// at a time. The budget itself is untouched either way, so the peak
/// resident set is what it always was - this admits shapes the flat
/// "corpus must fit" clause refused, it never raises what one of them
/// holds.
pub(crate) fn ntt_retention_admits(
    block_size: usize,
    n_present: usize,
    budget: usize,
    stream_windows: bool,
) -> bool {
    if n_present.saturating_mul(block_size) <= budget {
        return true;
    }
    stream_windows && budget / block_size.max(1) >= NTT_MIN_WINDOW_PRESENT
    // A window of full-length slices, which is what this divides. The
    // worker charges a short tail its zero-padded block as well as its
    // fed bytes (the pad arena the transform builds), so a set that is
    // ALL tails fills a window at about half this count - still twice
    // the measured crossover, which is why the floor is stated in whole
    // blocks and not in charged bytes.
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
pub(crate) fn clamp_to_published(base: usize) -> usize {
    clamp_to(base, crate::mem::published_budget().map(|b| b.total))
}

fn clamp_to(base: usize, published: Option<u64>) -> usize {
    match published {
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

/// The stripe width the transform runs at when `NZBFAST_NTT_W` does not
/// pin it: 512 words, except 1,024 on the x86 nibble-shuffle arms (AVX2
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
pub(crate) fn default_stripe_words(block_size: usize) -> usize {
    if cfg!(target_arch = "x86_64") && crate::gf16::multi_fold_width() == 4 && block_size >= 1 << 20
    {
        1024
    } else {
        512
    }
}

/// Stripe width and worker count the syndrome pass will use for this
/// block size. Factored out of `Reconstructor::ntt_syndromes` so the
/// admission gate prices the arenas with the SAME geometry the transform
/// actually runs - an estimate derived independently would drift.
pub(crate) fn ntt_stripe_geometry(block_size: usize) -> (usize, usize) {
    let words = block_size / 2;
    let w: usize = std::env::var("NZBFAST_NTT_W")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&v: &usize| v >= 16)
        .unwrap_or_else(|| default_stripe_words(block_size))
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
    let (w, threads) = ntt_stripe_geometry(block_size);
    crate::par2ntt::FlatPlan::scratch_bytes(needed, w).saturating_mul(threads)
}

/// Resolve the syndrome path for this repair shape. Returns the
/// retention budget when the NTT path is selected.
pub(super) fn resolve_syndrome_path(
    path: SyndromePath,
    block_size: usize,
    n_inputs: usize,
    n_missing: usize,
    exponents: &[u32],
) -> Option<usize> {
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
        | SyndromePath::NttForcePanic(budget) => Some(budget),
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
            // out and why.
            let corpus_budget = budget.saturating_sub(ntt_worker_arenas(block_size, exp_span + 1));
            let gated = || {
                ntt_gates_pass(
                    block_size,
                    n_inputs - n_missing,
                    n_missing,
                    exp_span,
                    corpus_budget,
                    ntt_stream_windows(),
                )
                // The corpus budget, not the whole budget: what comes
                // back is the RETENTION headroom the worker's runtime
                // backstop compares against, and the arenas are already
                // spoken for. Returning `budget` here let a shape whose
                // actual retention landed between the two keep retaining
                // past what was priced.
                .then_some(corpus_budget)
            };
            match mode.as_str() {
                // The environment is the bench/test/ops escape hatch: it
                // overrides the daemon setting in both directions and
                // ignores the trip-breaker.
                "force" => Some(budget),
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
    use super::clamp_to;

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
        // Nothing published: the host-derived budget stands untouched.
        assert_eq!(clamp_to(BIG, None), BIG);
        // Published and SMALLER: it binds. This is the whole point - a
        // repair on a `--mem-limit`ed process must not solve or retain
        // against host RAM.
        assert_eq!(clamp_to(BIG, Some(SMALL as u64)), SMALL);
        // Published and LARGER: the clamp only ever lowers. A published
        // budget is a ceiling, never a grant - raising the host figure
        // to meet it would hand out memory the host probe said was not
        // there.
        assert_eq!(clamp_to(SMALL, Some(BIG as u64)), SMALL);
        // Equal: admitted, not refused by an off-by-one.
        assert_eq!(clamp_to(SMALL, Some(SMALL as u64)), SMALL);
        // A budget past `usize` saturates instead of truncating. On a
        // 64-bit host both spellings agree and neither arm can fail, so
        // these two only ever discriminate on a 32-bit build (armv7).
        // 2^32 is the one that BITES: `as usize` truncates it to
        // exactly 0 there, which would clamp every budget to nothing,
        // while `try_from(..).unwrap_or(MAX)` saturates and leaves the
        // host figure standing.
        assert_eq!(clamp_to(SMALL, Some(1u64 << 32)), SMALL);
        // `u64::MAX` is the weaker of the pair and is kept as
        // DOCUMENTATION, not as cover: its low 32 bits are all ones, so
        // the broken `as` spelling happens to land on `usize::MAX` and
        // this arm passes either way, at every width. The arm above is
        // the control; this one only records the intent.
        assert_eq!(clamp_to(SMALL, Some(u64::MAX)), SMALL);
    }
}
