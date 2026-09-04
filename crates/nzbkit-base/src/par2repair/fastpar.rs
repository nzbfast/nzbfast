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

// Its only call site carries the same cfg - it is a Windows core
// census, and off Windows nothing asks the question.
#[cfg(all(target_arch = "x86_64", windows))]
use super::linalg::physical_cores;

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
/// so it stays. One constant is right everywhere only to ~10%. The other two gates are unchanged - at low present
/// counts the transform's structural loss stands (forcing it at m=64
/// costs 2.6x the fold's CPU), and the budget is an OOM guard, not a
/// speed one.
pub(crate) const NTT_MIN_MISSING: usize = 320;
pub(crate) const NTT_MIN_PRESENT: usize = 8192;
const NTT_MAX_EXP_FACTOR: usize = 3;
/// Flat ceiling on the default resident-corpus budget. The NTT is a
/// big-machine feature; low-memory hosts stay on the streaming fold
/// (amendment 2).
const NTT_BUDGET_CEIL: u64 = 4 << 30;

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
    // OS) whenever neither probe answered: NTT_BUDGET_CEIL is exactly
    // 2^32. A zero budget fails `n_present * block_size <= budget` for
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

/// The conservative shape gates, as a pure function so the tests pin
/// them without touching the process environment.
pub(crate) fn ntt_gates_pass(
    block_size: usize,
    n_present: usize,
    n_missing: usize,
    max_exp: usize,
    budget: usize,
) -> bool {
    n_missing >= NTT_MIN_MISSING
        && n_present >= NTT_MIN_PRESENT
        && max_exp < NTT_MAX_EXP_FACTOR.saturating_mul(n_missing.max(1))
        && n_present.saturating_mul(block_size) <= budget
}

pub(crate) fn ntt_budget_env() -> usize {
    std::env::var("NZBFAST_NTT_BUDGET")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| {
            ntt_default_budget(crate::mem::physical_ram(), crate::mem::cgroup_mem_limit())
        })
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
        .unwrap_or(512)
        .min(words.max(16));
    let stripes = words.div_ceil(w);
    let cores = crate::mem::cpu_workers();
    // Same physical-core rule as fold_parallel on hybrid x86.
    #[cfg(all(target_arch = "x86_64", windows))]
    let cores = physical_cores().map_or(cores, |p| p.min(cores));
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
    match path {
        SyndromePath::Fold => None,
        SyndromePath::NttForce(budget)
        | SyndromePath::NttForceCorrupt(budget)
        | SyndromePath::NttForcePanic(budget) => Some(budget),
        SyndromePath::Auto => {
            let mode = std::env::var("NZBFAST_NTT").unwrap_or_default();
            let budget = ntt_budget_env();
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
            let corpus_budget = budget.saturating_sub(ntt_worker_arenas(block_size, max_exp + 1));
            let gated = || {
                ntt_gates_pass(
                    block_size,
                    n_inputs - n_missing,
                    n_missing,
                    max_exp,
                    corpus_budget,
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
