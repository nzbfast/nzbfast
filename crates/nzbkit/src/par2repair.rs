//! In-process PAR2 Reed-Solomon repair over GF(2^16) - M2's "open
//! research" item, now real. `par2.rs` stays parsing/verification-only;
//! this module reconstructs missing or corrupt input blocks from
//! recovery slices and patches the damaged files IN PLACE (no whole-file
//! rewrite, no external par2cmdline).
//!
//! ## The math (PAR2 spec, recovery-slice section)
//!
//! Input slice `i` (files in Main-packet order, slices in file order) is
//! assigned the constant g_i = 2^{k_i}, where k_i is the i-th natural
//! number coprime to 65535 (not divisible by 3, 5, 17 or 257; 32768
//! exist, which is the spec's input-slice cap). A recovery slice with
//! exponent `e` holds, over GF(2^16) with slices read as little-endian
//! u16 words (odd tail byte = low half of a zero-padded final word):
//!
//! ```text
//!     R_e = Σ_i g_i^e · D_i
//! ```
//!
//! With missing-slice set M and present set P this rearranges to
//!
//! ```text
//!     Σ_{j∈M} g_j^e · D_j  =  R_e ⊕ Σ_{i∈P} g_i^e · D_i  =:  S_e
//! ```
//!
//! - |M| unknowns solved from |M| recovery slices by inverting the
//! matrix A[r][c] = g_{j_c}^{e_r} (every entry a power of two:
//! 2^{k_{j_c}·e_r mod 65535}). [`Reconstructor`] streams the present
//! slices through the syndrome accumulation so the whole data set is
//! never in memory: peak RAM is |M| syndromes + |M| recovery slices +
//! one small batch of input blocks.
//!
//! Correctness is self-proving: after patching, every touched file must
//! match its FileDesc whole-file MD5, or [`repair_dir`] fails and the
//! caller falls back to par2cmdline.
//!
//! Obfuscated and shifted sets are covered by the extra-file adoption
//! scan (par2cmdline's "sliding scan", natively): when a file fails
//! identification outright - missing, renamed, or byte-shifted - the
//! IFSC block checksums (rolling CRC32 prefilter, MD5 confirm) are slid
//! over every candidate file in the directory to locate block content
//! living under other names or offsets, and those blocks are adopted as
//! data sources. The scan reads whole files, so it is gated: it only
//! runs when some file failed identification or the damage exceeds the
//! recovery slices on disk - never on the everyday a-few-blocks-bad
//! repair, whose verified files already pin every block in place. Two
//! extensions go past par2cmdline: recovery volumes hidden under junk
//! names are found by packet-magic sniffing (par2cmdline only loads
//! packets from files with ".par2" in the name), and when damage still
//! exceeds recovery after the extras scan, identified-but-damaged
//! targets are scanned too (mid-file insertions leave a half-verified
//! file whose remaining content is byte-shifted inside itself).

use crate::disk::case_fold_key as fold_key;
use crate::gf16;
use crate::par2::{self, BlockCheck, Par2File};
use crate::sync::MutexExt;
use md5::{Digest, Md5};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// PAR2 hard limit: number of naturals below 65535 coprime to it.
/// Public so pre-repair planners (the mapped path's parity-as-a-source
/// slot allocation) can refuse a set that could never repair anyway
/// BEFORE committing any state to it.
pub const MAX_INPUT_SLICES: usize = 32768;
/// A dense missing x missing GF(2^16) inverse costs ~4*m^2 bytes (the
/// matrix plus its inverse) and O(m^3) single-threaded field ops. The
/// PAR2 spec slice cap (32768) is far too loose a bound for that: a
/// crafted set declaring tens of thousands of missing blocks would pin
/// multiple GB and run for hours (a repair-time DoS). Refuse a matrix
/// larger than a real recovery set ever is; 8192 caps peak matrix memory
/// near 256 MB. An extreme legitimate repair can still use par2cmdline.
/// Public for the same pre-repair planners as [`MAX_INPUT_SLICES`].
pub const MAX_REPAIR_DIM: usize = 8192;

/// Present-slice bytes buffered between threaded syndrome flushes.
const BATCH_BYTES: usize = 64 << 20;

#[derive(Debug, thiserror::Error)]
pub enum RepairError {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("no valid PAR2 Main packet found in the .par2 files")]
    NoMainPacket,
    #[error("recovery set malformed: {0}")]
    Malformed(String),
    /// Not enough recovery slices could be VALIDATED to cover the
    /// missing blocks. Deliberately distinct from [`Self::Malformed`]:
    /// this is the everyday shortfall, and reporting it as a malformed
    /// set sends the reader after a corrupt PAR2 set when the set is
    /// usually fine and the RECOVERY DATA is simply not all there.
    ///
    /// Live on a real daemon 24 Aug 2026 00:36Z (TODO §282 item 15): a
    /// 1024 MB recovery fetch returned 68.9 MB with 1206 article
    /// failures, and the decline read "recovery set malformed: 0
    /// recovery slice(s) for 163 missing block(s)" over a set whose
    /// only problem was that the provider would not serve it. `have`
    /// counts slices that are BOTH present and MD5-valid, so a
    /// partially fetched volume's intact slices are already in it - a
    /// torn one contributes nothing because a recovery slice is
    /// atomic, not because it was skipped.
    #[error("recovery data short: {have} usable recovery slice(s) for {need} missing block(s)")]
    RecoveryShort { have: usize, need: usize },
    #[error("recovery matrix is singular for this slice combination")]
    SingularMatrix,
    #[error("repaired file failed MD5 verification: {0}")]
    VerifyFailed(String),
}

/// The log₂ of the RS constant for each of the first `n` input slices:
/// the n smallest naturals coprime to 65535. (Sequence of constants:
/// 2, 4, 16, 128, 256, 2048, …)
pub fn input_base_logs(n: usize) -> Result<Vec<u32>, RepairError> {
    if n > MAX_INPUT_SLICES {
        return Err(RepairError::Malformed(format!(
            "{n} input slices exceeds the PAR2 limit of {MAX_INPUT_SLICES}"
        )));
    }
    let mut logs = Vec::with_capacity(n);
    let mut k = 0u32;
    while logs.len() < n {
        k += 1;
        if !k.is_multiple_of(3)
            && !k.is_multiple_of(5)
            && !k.is_multiple_of(17)
            && !k.is_multiple_of(257)
        {
            logs.push(k);
        }
    }
    Ok(logs)
}

// The two recovery-slice finders live in par2repair/slices.rs (TODO
// 106 size-gate split); the public paths are unchanged.
// The GF(2^16) arithmetic - fold present slices into syndromes, invert
// the repair matrix - is a child module (TODO 106 size-gate split), and
// `pub(crate)` because `par2gen` folds its RECOVERY slices with the very
// same routine. The benchmark doors keep their `par2repair::` re-exports.
pub(crate) mod linalg;
use linalg::{FeedBatch, fold_parallel, invert};
pub use linalg::{bench_fold, bench_invert};
// Its only two call sites carry the same cfg - it is a Windows core
// census, and off Windows nothing asks the question.
#[cfg(all(target_arch = "x86_64", windows))]
use linalg::physical_cores;

mod slices;
pub use slices::{recovery_slice_census, recovery_slice_locators, slice_fits_block};

/// Streaming Reed-Solomon reconstruction. Build with the missing input
/// slice indices and exactly as many recovery slices, [`feed`] every
/// present input slice exactly once (any order, short tail data fine),
/// then [`finish`] returns the reconstructed slices in `missing` order.
///
/// [`feed`]: Reconstructor::feed
/// [`finish`]: Reconstructor::finish
pub struct Reconstructor {
    block_size: usize,
    /// k_i per global input index (shared with [`Feeder`] handles).
    base_logs: std::sync::Arc<Vec<u32>>,
    missing: Vec<usize>,
    /// Recovery exponents, in syndrome-row order (needed again at
    /// finish() by the NTT path and its fold fallback).
    exponents: Vec<u32>,
    /// A⁻¹, row-major: missing[c] = Σ_r inverse[c][r] · S_r.
    inverse: Vec<Vec<u16>>,
    /// Batches travel to a worker thread that owns the syndrome rows, so
    /// the caller's disk reads overlap the GF math (bounded channel:
    /// one batch queued while one folds).
    tx: Option<std::sync::mpsc::SyncSender<FeedBatch>>,
    /// Worker returns (syndromes, retained batches) - retained is empty
    /// on the streaming path, and holds the resident source corpus when
    /// the experimental NTT dispatch selected retention.
    worker: Option<std::thread::JoinHandle<(Vec<Vec<u16>>, Vec<FeedBatch>)>>,
    /// Pending present slices, packed into the next batch's arena.
    batch: FeedBatch,
    batch_capacity: usize,
    /// The dispatcher selected NTT retention at construction (the
    /// mid-flight budget/plan fallbacks can still land on the fold).
    ntt_selected: bool,
    /// Memory-floor gauge charge for the syndrome rows (recovery blocks
    /// x block_size, live from construction to back-substitution).
    /// Released explicitly where finish drops the rows; the RAII drop
    /// covers an abandoned Reconstructor.
    syn_charge: crate::memgauge::Charge,
    /// TEST ONLY fault injection, from the `NttForce*` test paths.
    ntt_fault: NttFault,
}

/// TEST ONLY fault injected after the NTT transform (see
/// [`SyndromePath::NttForceCorrupt`] / [`SyndromePath::NttForcePanic`]).
#[derive(Clone, Copy, PartialEq)]
enum NttFault {
    None,
    Corrupt,
    Panic,
}

/// What [`Reconstructor::finish_reported`] observed about the syndrome
/// pass. Not part of the supported API surface.
#[doc(hidden)]
pub struct SyndromeReport {
    /// The NTT transform computed the syndromes (false on the fold path
    /// and on every mid-flight fallback).
    pub(crate) ntt_used: bool,
    /// Present slices fed to the transform (0 when it did not run).
    pub(crate) n_present: usize,
}

/// One thread's share of a multi-accumulate: `dsts[j] ^= Σ_i
/// coeff(j, i) · srcs[i]` over GF(2^16), column-tiled for cache reuse.
///
/// The naive loop (rows outer, sources inner) streams every source
/// past every row: with a 32 MiB batch and ~100 syndrome rows that is
/// ~100x the batch in RAM reads, which is exactly where the repair leg
/// falls behind on parts with laptop-class caches (an L3 smaller than
/// the batch re-reads it from memory each sweep; Apple-class bandwidth
/// hides the same traffic). Tiling columns keeps this thread's slice
/// of every destination row L2-resident across one pass over the
/// sources, so each source tile is read once per thread and the
/// destination tiles never leave cache.
///
/// Sources may be shorter than the rows (zero-padded tails) and the
/// split tables are built once per (row, source-group) - `group` caps
/// their memory, degrading toward the untiled loop only when a single
/// group's tables would not fit the budget.
/// How the syndrome pass runs. EXPERIMENTAL dispatch for the NTT path
/// (merged NTT plan Stage 2); not part of the supported API surface.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub enum SyndromePath {
    /// Setting- and environment-gated. `NZBFAST_NTT` set in the
    /// environment takes precedence over the daemon's "fast par mode"
    /// setting (the bench/test/ops escape hatch): `1` enables the NTT
    /// behind the conservative dispatch gates from the Stage 0/1
    /// measurements, `force` skips the shape gates (memory budget still
    /// applies), `0`/`off` disables it outright. With the variable
    /// unset, [`set_fast_par_enabled`] decides, behind the same shape
    /// gates, unless a divergence has tripped the breaker
    /// ([`fast_par_tripped`]). Default.
    Auto,
    /// The streaming fold, unconditionally (today's behavior).
    Fold,
    /// Resident-source NTT with this retention budget in bytes; falls
    /// back to the fold if retention overflows the budget or the plan
    /// is unbuildable. Test/bench hook.
    NttForce(usize),
    /// TEST ONLY: [`SyndromePath::NttForce`], then flip one syndrome
    /// word after the transform - simulates an NTT correctness bug so
    /// the verify-failure fold retry can be exercised end to end.
    NttForceCorrupt(usize),
    /// TEST ONLY: [`SyndromePath::NttForce`], then panic after the
    /// transform - proves the fold retry survives an NTT panic.
    NttForcePanic(usize),
}

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
static FAST_PAR_TRIPPED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
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
struct NttProbe {
    /// The dispatcher selected retention at construction (the NTT was
    /// live when the attempt ended, even if it ended in a panic).
    selected: bool,
    /// The transform actually computed the syndromes (no mid-flight
    /// fold fallback).
    used: bool,
    m: usize,
    n_present: usize,
    block_size: usize,
    max_exp: u32,
    context: String,
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
fn run_with_ntt_fallback<T>(
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
/// So `NTT_MIN_MISSING` is 384, not the original 512: still ~1.3x
/// above the measured crossover on both boxes (the margin the
/// small-n structural loss and any host we have not measured are
/// owed), while no longer folding the 384-511 band, which cost up to
/// 1.4 s wall / 25 CPU-s per repair on the 20-core box. The other two
/// gates are unchanged - at low present counts the transform's
/// structural loss stands (forcing it at m=64 costs 2.6x the fold's
/// CPU), and the budget is an OOM guard, not a speed one.
const NTT_MIN_MISSING: usize = 384;
const NTT_MIN_PRESENT: usize = 8192;
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
fn ntt_default_budget(ram: Option<u64>, cgroup_limit: Option<u64>) -> usize {
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
fn ntt_gates_pass(
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

fn ntt_budget_env() -> usize {
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
fn ntt_stripe_geometry(block_size: usize) -> (usize, usize) {
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
fn ntt_worker_arenas(block_size: usize, needed: usize) -> usize {
    let (w, threads) = ntt_stripe_geometry(block_size);
    crate::par2ntt::FlatPlan::scratch_bytes(needed, w).saturating_mul(threads)
}

/// Resolve the syndrome path for this repair shape. Returns the
/// retention budget when the NTT path is selected.
fn resolve_syndrome_path(
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

// `impl Reconstructor` lives in par2repair/reconstruct.rs (TODO 106
// size-gate split).
mod catalog;
mod nested;
mod reconstruct;

pub use catalog::PacketCatalog;
use catalog::{Crit, RecLoc, SetReplay, load_selected_recovery};
pub use nested::{PacketScope, nested_subdirs, source_candidate_files};

/// One producer's handle into a [`Reconstructor`]'s fold worker (M2c.2
/// parallel feed reads). Same batching as the built-in feed path, but
/// clonable across reader threads; flushes its tail batch on drop.
pub struct Feeder {
    tx: std::sync::mpsc::SyncSender<FeedBatch>,
    base_logs: std::sync::Arc<Vec<u32>>,
    batch: FeedBatch,
    max_batch: usize,
}

impl Feeder {
    /// Same contract as [`Reconstructor::feed`].
    pub fn feed(&mut self, input_index: usize, data: &[u8]) {
        if self.batch.arena.len() + data.len() > self.max_batch {
            self.flush();
        }
        self.batch.push(self.base_logs[input_index], data);
        if self.batch.arena.len() >= self.max_batch {
            self.flush();
        }
    }

    fn flush(&mut self) {
        if self.batch.slices.is_empty() {
            return;
        }
        let batch = std::mem::replace(&mut self.batch, FeedBatch::with_capacity(self.max_batch));
        // The worker outlives every sender; send can't fail.
        let _ = self.tx.send(batch);
    }
}

impl Drop for Feeder {
    fn drop(&mut self) {
        self.flush();
    }
}

// ---------------------------------------------------------------------------
// Mapped-target repair driver (M2c.1) - repair INTO the extracted file
// ---------------------------------------------------------------------------

/// Byte access to the recovery-set files by their Main-packet index,
/// however they are actually stored - the daemon implements this over
/// the extractor's volume view (header stash + block→payload mapping
/// into the extracted output), so damaged store-mode sets repair with
/// no materialized volume files at all.
pub trait VolumeIo: Sync {
    fn read(&self, file: usize, off: u64, buf: &mut [u8]) -> std::io::Result<()>;
    fn write(&self, file: usize, off: u64, data: &[u8]) -> std::io::Result<()>;
}

/// Reed-Solomon repair over [`VolumeIo`]: `files` must be EVERY file of
/// the recovery set in Main-packet order (the global slice numbering
/// assigns the RS constants - a reordered or partial list computes
/// garbage), each with a caller-supplied per-block present vector (the
/// daemon's in-stream + read-back verification ledger). `recovery`
/// holds candidate recovery slices (exponent, exactly block_size
/// bytes); duplicates by exponent are fine, the smallest exponents win.
///
/// Present slices are streamed through the syndromes via `io.read`,
/// missing ones are reconstructed and written back via `io.write`
/// (tails trimmed to the file length), and then - the self-proving
/// contract - the set is re-read via `io.read` and must check out, or
/// the whole call fails with [`RepairError::VerifyFailed`] and the
/// caller falls back to the materialize + `repair_dir` path. Returns the
/// number of blocks rebuilt. No adoption here: misnamed/shifted sets
/// take the directory path.
///
/// EVERY file is re-read, not only the ones that received a rebuilt
/// block. The blocks this function trusts were verified as they ARRIVED,
/// off the wire, never off disk, so a covered file whose bytes went bad
/// after they were written - a failed pwrite, a bad sector, anything
/// between - passed straight through a "successful" repair and out into
/// a Completed job. The directory path never had this hole, because
/// par2 verifies the whole set from disk before and after.
///
/// The digest differs by what the file has been through, which is what
/// keeps the added cost near a plain read:
///
/// - a file that received rebuilt blocks is re-hashed WHOLE against its
///   PAR2 MD5, exactly as before: those bytes are new, and MD5 is what
///   proves them;
/// - an untouched file is checked per block against the IFSC CRC32s,
///   ~5-10x cheaper than MD5 and the same answer for the corruption this
///   is looking for. `full_verify` (the operator asking for full rather
///   than fast verification) puts it on MD5 too, as does a set that
///   carries no per-block checksums to use.
pub fn repair_mapped(
    files: &[(Par2File, Vec<bool>)],
    block_size: usize,
    recovery: &[(u32, Vec<u8>)],
    io: &dyn VolumeIo,
    full_verify: bool,
) -> Result<usize, RepairError> {
    repair_mapped_with_path(
        files,
        block_size,
        recovery,
        io,
        full_verify,
        SyndromePath::Auto,
    )
}

/// [`repair_mapped`] fed from a [`PacketCatalog`] instead of a
/// harvested-in-memory recovery corpus (B3 stage 2 on the B2 catalog):
/// the smallest exponents actually needed are selected from the
/// catalog's validated locators, pread one block each, and re-proven
/// against their packet MD5s as they load. Peak recovery memory is
/// missing x block_size instead of every slice on disk, and the NTT
/// fallback retry reloads from disk rather than pinning the corpus.
/// Selection, dedupe, error arithmetic and fallback semantics are
/// [`repair_mapped`]'s own - the loaded set IS the set it would have
/// chosen out of the full harvest.
pub fn repair_mapped_catalog(
    files: &[(Par2File, Vec<bool>)],
    block_size: usize,
    cat: &mut PacketCatalog,
    set_id: &[u8; 16],
    io: &dyn VolumeIo,
    full_verify: bool,
) -> Result<usize, RepairError> {
    run_with_ntt_fallback(SyndromePath::Auto, |path, probe| {
        let recovery = catalog::load_mapped_recovery(cat, set_id, files, block_size)?;
        repair_mapped_inner(files, block_size, &recovery, io, full_verify, path, probe)
    })
}

/// [`repair_mapped`] with an explicit initial syndrome path (test hook
/// for the NTT fallback machinery). Not part of the supported API
/// surface. The verify-failure fold retry applies here too: a rerun on
/// the fold path re-reads only PRESENT slices (the failed attempt only
/// wrote MISSING ones, so its output never contaminates the retry's
/// syndromes) and rewrites every missing block, so partially-written
/// output from the failed attempt is fully overwritten.
#[doc(hidden)]
pub fn repair_mapped_with_path(
    files: &[(Par2File, Vec<bool>)],
    block_size: usize,
    recovery: &[(u32, Vec<u8>)],
    io: &dyn VolumeIo,
    full_verify: bool,
    path: SyndromePath,
) -> Result<usize, RepairError> {
    run_with_ntt_fallback(path, |path, probe| {
        repair_mapped_inner(files, block_size, recovery, io, full_verify, path, probe)
    })
}

fn repair_mapped_inner(
    files: &[(Par2File, Vec<bool>)],
    block_size: usize,
    recovery: &[(u32, Vec<u8>)],
    io: &dyn VolumeIo,
    full_verify: bool,
    path: SyndromePath,
    probe: &mut NttProbe,
) -> Result<usize, RepairError> {
    if block_size == 0 || !block_size.is_multiple_of(2) {
        return Err(RepairError::Malformed(format!(
            "block size {block_size} not a positive multiple of 2"
        )));
    }
    let bs = block_size as u64;
    // Lay files onto the global slice index space; collect the missing.
    let mut first_slice = Vec::with_capacity(files.len());
    // owner[g] = file index of global slice g (zero-length files make
    // first_slice non-unique, so a binary search can't be trusted).
    let mut owner: Vec<usize> = Vec::new();
    let mut missing: Vec<usize> = Vec::new();
    let mut next = 0usize;
    for (fi, (f, present)) in files.iter().enumerate() {
        let n = f.length.div_ceil(bs) as usize;
        if present.len() != n {
            return Err(RepairError::Malformed(format!(
                "{}: present vector has {} entries, length implies {n}",
                f.name,
                present.len()
            )));
        }
        first_slice.push(next);
        owner.extend(std::iter::repeat_n(fi, n));
        for (i, &p) in present.iter().enumerate() {
            if !p {
                missing.push(next + i);
            }
        }
        next += n;
    }
    let n_inputs = next;
    if n_inputs > MAX_INPUT_SLICES {
        return Err(RepairError::Malformed(format!(
            "{n_inputs} input slices exceeds the PAR2 limit of {MAX_INPUT_SLICES}"
        )));
    }
    if missing.is_empty() {
        return Ok(0);
    }

    // Smallest exponents win, deduped; exactly one per missing slice.
    let mut by_exp: HashMap<u32, &[u8]> = HashMap::new();
    for (e, data) in recovery {
        if data.len() == block_size {
            by_exp.entry(*e).or_insert(data.as_slice());
        }
    }
    if by_exp.len() < missing.len() {
        return Err(RepairError::RecoveryShort {
            have: by_exp.len(),
            need: missing.len(),
        });
    }
    let mut exps: Vec<u32> = by_exp.keys().copied().collect();
    exps.sort_unstable();
    exps.truncate(missing.len());
    // Borrowed payloads, not clones: the caller's corpus outlives the
    // whole attempt (it is pinned across the NTT-fallback retry), and
    // `Reconstructor::new_with_path` widens these into its own u16
    // syndrome rows before its fold worker spawns, so nothing borrowed
    // crosses a thread. The old per-selection clone was ~m x block_size
    // (512 MiB at 128 missing x 4 MiB) of dead weight.
    let chosen: Vec<(u32, &[u8])> = exps.iter().map(|e| (*e, by_exp[e])).collect();

    // Syndrome pass: stream every present slice once via io.read.
    // M2c.2: the reads were the measured hot spot (4.0 s of a 4.96 s
    // repair, single-threaded 1 MB reads) - fan them out. The flattened
    // present-slice list is split into CONTIGUOUS chunks (sequential
    // read patterns per thread), each reader owns a Feeder into the one
    // fold worker; XOR accumulation makes arrival order irrelevant.
    let timing = std::env::var_os("NZBFAST_REPAIR_TIMING").is_some();
    let t0 = std::time::Instant::now();
    let rec = Reconstructor::new_with_path(block_size, n_inputs, &missing, &chosen, path)?;
    probe.selected = rec.ntt_selected();
    probe.m = missing.len();
    probe.block_size = block_size;
    probe.max_exp = chosen.last().map_or(0, |&(e, _)| e);
    probe.context = files
        .first()
        .map(|(f, _)| f.name.clone())
        .unwrap_or_default();
    let work: Vec<(usize, usize, u64, usize)> = files
        .iter()
        .enumerate()
        .flat_map(|(fi, (f, present))| {
            let base = first_slice[fi];
            present
                .iter()
                .enumerate()
                .filter(|&(_, &p)| p)
                .map(move |(i, _)| {
                    let off = i as u64 * bs;
                    (base + i, fi, off, (f.length - off).min(bs) as usize)
                })
        })
        .collect();
    // A par-only / whole-set-missing rebuild has NO present slices to
    // stream: every input's contribution to the syndromes is zero, so
    // the recovery slices already ARE the syndromes and the solve runs
    // on them directly (parity as a source). Skip the reader fan-out -
    // `work.chunks(0)` would panic on the empty list.
    if !work.is_empty() {
        let readers = crate::mem::cpu_workers().min(8).min(work.len()).max(1);
        // Split the shared batch budget across handles so total in-flight
        // memory matches the old single-feeder design.
        let per_reader_batch = (BATCH_BYTES / readers).max(1 << 20);
        let chunk = work.len().div_ceil(readers);
        let mut read_results: Vec<Result<(), RepairError>> = (0..readers).map(|_| Ok(())).collect();
        std::thread::scope(|s| {
            for (wchunk, res) in work.chunks(chunk).zip(read_results.iter_mut()) {
                let mut feeder = rec.feeder(per_reader_batch);
                s.spawn(move || {
                    *res = (|| {
                        // One reusable read buffer per reader: slices are
                        // packed into the feeder's arena, so per-slice
                        // allocations are gone (see FeedBatch).
                        let mut buf = vec![0u8; block_size];
                        for &(g, fi, off, take) in wchunk {
                            io.read(fi, off, &mut buf[..take])?;
                            feeder.feed(g, &buf[..take]);
                        }
                        Ok(())
                    })();
                    // feeder drops here → tail batch flushes.
                });
            }
        });
        for r in read_results {
            r?;
        }
    }
    if timing {
        info!(target: "repair-timing", "feed reads queued in {:.2?}", t0.elapsed());
    }
    let (rebuilt, syn_report) = rec.finish_reported();
    probe.used = syn_report.ntt_used;
    probe.n_present = syn_report.n_present;
    if timing {
        info!(target: "repair-timing", "fold+solve done at {:.2?}", t0.elapsed());
    }

    // Write rebuilt blocks back, tails trimmed.
    for (mi, &g) in missing.iter().enumerate() {
        let fi = owner[g];
        let (f, _) = &files[fi];
        let off = (g - first_slice[fi]) as u64 * bs;
        let take = (f.length - off).min(bs) as usize;
        io.write(fi, off, &rebuilt[mi][..take])?;
    }

    // Self-prove: re-read the WHOLE SET via io.read - files are
    // independent, so verify across threads.
    let rebuilt_files: HashSet<usize> = missing.iter().map(|&g| owner[g]).collect();
    // Sorted, because the results below are collected in this order and
    // `for r in results { r?; }` reports the FIRST error: HashSet order
    // meant a repair leaving two files failing their MD5 named a
    // different one on each run from identical inputs. repair_dir_set
    // sorts for the same reason. Also makes the chunk split
    // size-independent of hash order.
    let touched: Vec<usize> = (0..files.len()).collect();
    let machine = crate::mem::cpu_workers();
    let threads = machine.min(touched.len()).max(1);
    let chunk = touched.len().div_ceil(threads);
    let mut results: Vec<Option<Result<(), RepairError>>> =
        (0..touched.len()).map(|_| None).collect();
    std::thread::scope(|s| {
        for (tchunk, rchunk) in touched.chunks(chunk).zip(results.chunks_mut(chunk)) {
            let rebuilt_files = &rebuilt_files;
            s.spawn(move || {
                let mut buf = vec![0u8; 1 << 20];
                for (&fi, r) in tchunk.iter().zip(rchunk) {
                    let (f, _) = &files[fi];
                    // MD5 for the bytes this call just wrote, for a set
                    // with no IFSC to check against, and for a grid
                    // holding any UNPROVEN slice - a short IFSC, fitted
                    // rather than dropped (`par2::fit_ifsc`), leaves
                    // blocks with no CRC to close against, and the
                    // per-block path would refuse a file the whole-file
                    // MD5 proves. CRC32 per block for the rest. See the
                    // function docs.
                    let md5_this = full_verify
                        || rebuilt_files.contains(&fi)
                        || f.blocks.len() as u64 != f.length.div_ceil(bs)
                        || f.blocks.iter().any(|b| !b.is_proven());
                    let one = (|| {
                        let mut hasher = Md5::new();
                        let mut crc = crc32fast::Hasher::new();
                        let mut filled = 0usize; // bytes of the current block
                        let mut bidx = 0usize;
                        let mut off = 0u64;
                        while off < f.length {
                            let take = (f.length - off).min(buf.len() as u64) as usize;
                            io.read(fi, off, &mut buf[..take])?;
                            if md5_this {
                                hasher.update(&buf[..take]);
                            } else {
                                // Blocks straddle reads freely; the CRC
                                // accumulates across them and closes at each
                                // boundary. The tail block is zero-padded to
                                // the block size per spec, which
                                // `crc32_zeros` does without allocating.
                                let mut p = 0usize;
                                while p < take {
                                    let seg = (block_size - filled).min(take - p);
                                    crc.update(&buf[p..p + seg]);
                                    filled += seg;
                                    p += seg;
                                    if filled == block_size {
                                        let done =
                                            std::mem::replace(&mut crc, crc32fast::Hasher::new());
                                        if !f
                                            .blocks
                                            .get(bidx)
                                            .is_some_and(|b| b.crc_matches(done.finalize()))
                                        {
                                            return Err(RepairError::VerifyFailed(f.name.clone()));
                                        }
                                        filled = 0;
                                        bidx += 1;
                                    }
                                }
                            }
                            off += take as u64;
                        }
                        if md5_this {
                            let md5: [u8; 16] = hasher.finalize().into();
                            if md5 != f.md5 {
                                return Err(RepairError::VerifyFailed(f.name.clone()));
                            }
                            return Ok(());
                        }
                        if filled > 0 {
                            let padded = crate::yenc_simd::crc32_zeros(
                                crc.finalize(),
                                (block_size - filled) as u64,
                            );
                            if !f.blocks.get(bidx).is_some_and(|b| b.crc_matches(padded)) {
                                return Err(RepairError::VerifyFailed(f.name.clone()));
                            }
                        }
                        Ok(())
                    })();
                    *r = Some(one);
                }
            });
        }
    });
    for r in results {
        r.expect("verify worker filled every slot")?;
    }
    if timing {
        info!(target: "repair-timing", "patch+verify done at {:.2?}", t0.elapsed());
    }
    Ok(missing.len())
}

// ---------------------------------------------------------------------------
// Extra-file block adoption - par2cmdline's "sliding scan", natively
// ---------------------------------------------------------------------------

/// Where an adopted block's bytes live: candidate index + byte offset.
/// Bytes past the candidate's end are zeros (a tail block matched at
/// end-of-file - its checksum covers the zero padding).
#[derive(Debug, Clone, Copy)]
struct AdoptSrc {
    cand: usize,
    offset: u64,
}

/// 32×32 GF(2) matrix over u32 columns: column `j` is the image of bit
/// `1 << j`.
type Mat32 = [u32; 32];

fn mat_apply(m: &Mat32, mut x: u32) -> u32 {
    let mut r = 0u32;
    let mut i = 0usize;
    while x != 0 {
        if x & 1 != 0 {
            r ^= m[i];
        }
        x >>= 1;
        i += 1;
    }
    r
}

fn mat_mul(a: &Mat32, b: &Mat32) -> Mat32 {
    std::array::from_fn(|j| mat_apply(a, b[j]))
}

/// CRC32 (IEEE-reflected, the IFSC flavor) over a fixed-length window
/// that slides one byte in O(1). The CRC register update is GF(2)-linear
/// in (register, byte), so the difference between "window shifted by
/// one" and "window plus one byte" is a linear function of the expiring
/// byte pushed through `window` zero-byte updates - precomputed here as
/// `expire`, built in O(log window) by matrix exponentiation (windows
/// are PAR2 block sizes, up to 256 MB).
struct RollingCrc {
    table: [u32; 256],
    /// expire[c]: contribution to remove when byte value `c` leaves.
    expire: [u32; 256],
}

impl RollingCrc {
    fn new(window: usize) -> RollingCrc {
        let mut table = [0u32; 256];
        for (i, e) in table.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    (c >> 1) ^ 0xEDB8_8320
                } else {
                    c >> 1
                };
            }
            *e = c;
        }
        // One-zero-byte register operator, raised to the window length.
        let one: Mat32 = std::array::from_fn(|j| {
            let r = 1u32 << j;
            (r >> 8) ^ table[(r & 0xFF) as usize]
        });
        let mut zn: Mat32 = std::array::from_fn(|j| 1u32 << j);
        let mut base = one;
        let mut e = window;
        while e != 0 {
            if e & 1 != 0 {
                zn = mat_mul(&base, &zn);
            }
            e >>= 1;
            if e != 0 {
                base = mat_mul(&base, &base);
            }
        }
        const INIT: u32 = 0xFFFF_FFFF;
        let expire = std::array::from_fn(|c| {
            let after_first = (INIT >> 8) ^ table[((INIT ^ c as u32) & 0xFF) as usize];
            mat_apply(&zn, after_first ^ INIT)
        });
        RollingCrc { table, expire }
    }

    /// Register update for one appended byte.
    #[inline]
    fn push(&self, reg: u32, byte: u8) -> u32 {
        (reg >> 8) ^ self.table[((reg ^ byte as u32) & 0xFF) as usize]
    }

    /// Slide a full window one byte: append `new`, expire `old` (the
    /// byte that entered `window` updates ago).
    #[inline]
    fn roll(&self, reg: u32, old: u8, new: u8) -> u32 {
        self.push(reg, new) ^ self.expire[old as usize]
    }
}

/// Identity key for a destination path. On a case-insensitive volume
/// `README.txt` and `readme.txt` name ONE object, so comparing raw paths
/// counts two aliases of the same file as two distinct destinations -
/// which is how a "distinct" target ends up sharing (and destroying)
/// another's bytes. `fold` comes from probing the output volume
/// (`disk::case_insensitive_dir`), not from the build target: the answer
/// belongs to the destination filesystem, not to the binary. `fold_key`
/// is `disk::case_fold_key`, NOT `to_lowercase`, which is weaker than the
/// volume: read that header, which prices both directions here (M4-44).
fn path_identity_key(fold: bool, p: &Path) -> PathBuf {
    if fold {
        PathBuf::from(fold_key(&p.to_string_lossy()))
    } else {
        p.to_path_buf()
    }
}

/// [`path_identity_key`] for a declared file NAME, sanitized the way the
/// repair lands it. Same folding rule and the same reason.
fn name_identity_key(fold: bool, name: &str) -> String {
    let s = crate::disk::sanitize_out_name(name);
    if fold { fold_key(&s) } else { s }
}

/// What the OTHER recovery sets sharing this directory declare.
///
/// A repair runs one set at a time - packets carrying any other set id
/// are dropped before a target is ever built - so on its own a set
/// cannot see that a neighbour claims the same destination, nor that a
/// file it is about to write off as spare bytes is a neighbour's
/// payload. Both cost data, so the multi-set entry points read every
/// packet file once up front and hand the answer down. `repair_dir`,
/// which is single-set by definition, passes the default and behaves
/// exactly as it always has.
#[derive(Default, Clone)]
struct DirContext {
    /// Destination names that two DIFFERENT sets in this directory
    /// claim for different content. Targets with these names are
    /// disambiguated in EVERY set, so no two sets can land on one path.
    /// Two sets describing the SAME file (identical descriptor) are not
    /// contested - sharing that destination is correct, and neither is
    /// a collision INSIDE one set, which the claim loop sees for itself
    /// (see `PacketCatalog::declared_and_contested`).
    contested: HashSet<String>,
    /// Every name any set in the directory declares. Payload, whoever
    /// owns it, and so never a spent adoption donor to sweep.
    declared: HashSet<String>,
    /// May a SHORTFALL publish patch a member that already EXISTS? Only
    /// a caller can answer it, only the surveying entry point may grant
    /// it, and [`status::publishable`] carries the argument.
    patch_existing: bool,
    /// §293: directories OUTSIDE the repair dir whose files are offered
    /// to the adoption scan - a failed predecessor's output, handed to
    /// the successor so blocks the wire will not serve again can still
    /// be found on disk. Rides the context rather than every signature
    /// between the entry points and the adopt call. Files under these
    /// directories are candidates only: they are never patched, never
    /// recreated, and never reported as spent donors (the sweep is
    /// scoped to the repair dir - a donor is somebody else's payload).
    donors: Vec<PathBuf>,
}

// Extra-file adoption - the candidate walk (repair dir plus §293 donor
// directories), the whole-file fast path and the rolling-CRC sliding
// scan - lives in par2repair/adopt.rs, a child module (size gate,
// TODO 106), and fans out across candidates (R2 / N11).
mod adopt;
pub use adopt::is_recovery_by_name_and_content;
mod donate;
pub use donate::{Donation, donate_whole_files, donor_candidates, placed_names};

// ---------------------------------------------------------------------------
// Directory-level driver
// ---------------------------------------------------------------------------

// The two values a directory repair hands back - see
// par2repair/status.rs, a child module under the size gate (TODO 106),
// the same shape `adopt` and `donate` already use.
mod status;
pub use status::{FileRepair, RepairReport, RepairStatus, adopted_from_clause, published_clause};

// Which files in a directory are packet files - the ceiling, the
// by-name rule and the content sniff. Its own file under the size gate
// (TODO 106); the sniff PREDICATE it shares with the catalog's relist
// lives in `par2::head_is_packet_file`, not here.
#[path = "par2repair/collect.rs"]
mod collect;
pub use collect::{MAX_PACKET_FILE_BYTES, sniffed_packet_files};
// Reached by name from `par2repair/unit_tests.rs`, which drives the
// ceiling and the sniff through the bounded form rather than writing a
// gigabyte; nothing in production takes it.
#[cfg(test)]
use collect::collect_packet_files_bounded;

/// One recovery-set file mapped onto the global slice index space.
struct Target {
    file: Par2File,
    path: PathBuf,
    first_slice: usize,
    n_slices: usize,
    /// Per-slice verification result (present ⇔ both IFSC hashes match).
    present: Vec<bool>,
    /// Whole-file MD5 over the first `length` bytes matched AND the disk
    /// length is exactly `length`.
    intact: bool,
    exists: bool,
    /// Verify-pass MD5 state for the in-place self-prove to resume
    /// from (see [`Md5Resume`]); None keeps the full reread.
    resume: Option<Md5Resume>,
}

/// Repair the PAR2 recovery set found in `dir`: parse every `*.par2`
/// file (packets only - data files are located by their FileDesc names),
/// verify each recovery-set file block-by-block from disk, reconstruct
/// missing/corrupt blocks from recovery slices, and patch them in place.
/// Files longer than declared are truncated; absent files are recreated.
/// Success requires every touched file to pass its whole-file MD5.
/// When the dir carries packets from more than one recovery set, the
/// first set seen (sorted packet-file order) is the one repaired.
pub fn repair_dir(dir: &Path) -> Result<RepairStatus, RepairError> {
    // Lazy build keeps the historical shape: criticals from the first
    // file(s), the recovery-volume tail scanned in the background under
    // the target-verify pass.
    let mut cat = PacketCatalog::build_lazy(dir)?;
    repair_dir_set(&mut cat, None, &DirContext::default(), true)
}

/// [`repair_dir`] with DONOR directories (§293): each donor's files
/// join the extra-file adoption scan as candidates, so a block the
/// recovery set cannot rebuild and the wire will not serve again can
/// still be found in a failed predecessor's output. Donor files are
/// read-only to the repair - never patched, never recreated, never
/// reported in `consumed_sources` - and an unreadable donor directory
/// degrades to "no donation" rather than failing the repair. Adoption
/// still runs only when its gate fires (a file unidentified outright,
/// or damage past the recovery on disk); donors widen what the scan
/// can find, not when it runs.
pub fn repair_dir_with_donors(dir: &Path, donors: &[PathBuf]) -> Result<RepairStatus, RepairError> {
    let mut cat = PacketCatalog::build_lazy(dir)?;
    let ctx = DirContext {
        donors: donors.to_vec(),
        ..DirContext::default()
    };
    repair_dir_set(&mut cat, None, &ctx, true)
}

/// [`repair_dir_with_donors`] scoped to ONE recovery set, named by id
/// rather than left to "whichever set the sorted packet walk saw first".
///
/// A directory-scoped verdict is a verdict about ONE set, and on a
/// multi-set post that set is not the caller's. Not theory:
/// `fetch_and_repair` runs once per set the mapped route declined, and
/// on the directory-scoped entry every one of those passes repaired the
/// FIRST set - passes two and three then found it verifying, answered
/// [`RepairStatus::NoDamage`], and the job printed `repair complete ✔`
/// and exited 0 over two payload files holed with 49,805 zero bytes.
/// Measured on origin/main `b5e8f0717`; the private notes for 29 Aug
/// 2026 on directory-scoped multi-set repair carry the mechanism and
/// name what it deliberately does NOT change.
///
/// A wanted set with no Main packet on disk is
/// [`RepairError::NoMainPacket`] - the honest answer, which lets the
/// caller reach its own backstop instead of accepting a green about
/// somebody else's files. The donors are [`repair_dir_with_donors`]'s
/// exactly; the catalog and the two [`DirContext`] name sets are not,
/// and deliberately - see [`repair_dir_set_with_donors_scoped`], which
/// this forwards to, for why a set picked out of a shared directory has
/// to be told what its neighbours declare.
pub fn repair_dir_set_with_donors(
    dir: &Path,
    set_id: &[u8; 16],
    donors: &[PathBuf],
) -> Result<RepairStatus, RepairError> {
    repair_dir_set_with_donors_scoped(dir, set_id, donors, PacketScope::Flat, false)
}

/// [`repair_dir_set_with_donors`] with packet DISCOVERY scope named.
///
/// Only the packet walk widens: the data files this set speaks for are
/// still resolved against `dir` through
/// [`crate::disk::join_out_name`], because a FileDesc name is relative
/// to the JOB, never to wherever its packets happen to have landed.
/// That is what makes `META/inner.par2` naming a root payload work, and
/// it is the same rule the flat walk always applied.
///
/// This is "one set out of a directory that may hold SEVERAL" by
/// construction - `get::latesets` applies every non-activated set in
/// turn through it - so it owes its caller both of [`DirContext`]'s
/// protections, and neither survives a lazy catalog: a name is declared
/// by a critical packet, and which files carry which set's criticals is
/// not known until they have been read. The bytes are read either way
/// (the volume scan always finishes before the repair does), so the
/// price of building COMPLETE is the overlap with the verify pass and
/// not the I/O. What the default cost is measured, not reasoned, and
/// pinned in `crates/nzbkit/tests/integration/par2repair_namepath.rs`.
pub fn repair_dir_set_with_donors_scoped(
    dir: &Path,
    set_id: &[u8; 16],
    donors: &[PathBuf],
    scope: PacketScope,
    patch_existing: bool,
) -> Result<RepairStatus, RepairError> {
    let mut cat = PacketCatalog::build_scoped(dir, scope)?;
    let (declared, contested) = cat.declared_and_contested(crate::disk::case_insensitive_dir(dir));
    let ctx = DirContext {
        contested,
        declared,
        donors: donors.to_vec(),
        patch_existing,
    };
    repair_dir_set(&mut cat, Some(*set_id), &ctx, true)
}

/// Every recovery-set id the PAR2 packets in `dir` carry, in
/// first-seen (sorted packet-file) order. Finding F12's door: a set
/// can LAND on disk through another set's naming (par2-of-par2 - the
/// outer set names the obfuscated inner par2 files) without ever
/// activating in-stream, and the caller needs the ids to ask
/// [`repair_dir_set_with_donors`] about the ones it has not applied.
pub fn disk_set_ids(dir: &Path) -> Result<Vec<[u8; 16]>, RepairError> {
    disk_set_ids_scoped(dir, PacketScope::Flat)
}

/// [`disk_set_ids`] with the discovery scope named. W4-06's door: the
/// outer set of a par2-of-par2 chain may legitimately publish the inner
/// packet files under a safe subdirectory, so the walk that looks for
/// the set nobody activated has to be able to see one.
pub fn disk_set_ids_scoped(dir: &Path, scope: PacketScope) -> Result<Vec<[u8; 16]>, RepairError> {
    Ok(disk_sets_scoped(dir, scope)?
        .into_iter()
        .map(|(id, _)| id)
        .collect())
}

/// [`disk_set_ids_scoped`], each id paired with the packet files that
/// carry it, in the same first-seen order.
///
/// The paths are what a NESTED caller needs and a flat one never did:
/// discovering a set below the job root widens WHERE a set may be, so
/// the caller has to be able to ask whether anything actually published
/// it there. An extracted archive can carry a recovery set of its own,
/// and repairing that against the job ROOT - where its files are not -
/// is at best noise and at worst files recreated from slices in a
/// directory that never wanted them, which is the resurrection
/// [`repair_present_sets`] keeps its own name gate to avoid.
pub fn disk_sets_scoped(
    dir: &Path,
    scope: PacketScope,
) -> Result<Vec<([u8; 16], Vec<PathBuf>)>, RepairError> {
    let cat = PacketCatalog::build_scoped(dir, scope)?;
    let mut out: Vec<([u8; 16], Vec<PathBuf>)> = Vec::new();
    let mut at: HashMap<[u8; 16], usize> = HashMap::new();
    for (file, occ) in cat.walk() {
        let i = match at.get(&occ.set_id) {
            Some(i) => *i,
            None => {
                out.push((occ.set_id, Vec::new()));
                at.insert(occ.set_id, out.len() - 1);
                out.len() - 1
            }
        };
        let p = cat.path_of(file);
        // A packet FILE can carry two sets interleaved, so dedupe by
        // membership rather than against the previous push.
        if !out[i].1.iter().any(|q| q == p) {
            out[i].1.push(p.to_path_buf());
        }
    }
    Ok(out)
}

/// Every file name the PAR2 packets in `dir` describe, across EVERY
/// recovery set present (obfuscated volumes included - the same
/// magic-sniff `repair_dir` uses finds them).
///
/// A repair verdict is a verdict about one recovery set and nothing
/// else, so a caller that wants to turn "the set is fine" into "the
/// download is fine" has to know which files the set was ever speaking
/// for. That is this list. Names come back exactly as the FileDesc
/// packets spell them; compare on-disk names through
/// [`crate::disk::sanitize_filename`], as the repair itself does.
pub fn covered_names(dir: &Path) -> Result<Vec<String>, RepairError> {
    Ok(covered_names_catalog(&PacketCatalog::build(dir)?))
}

/// [`covered_names`] replayed over an already-built catalog: same
/// dedupe-by-name over FileDesc packets in sorted-file order, no reread.
fn covered_names_catalog(cat: &PacketCatalog) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for (_, occ) in cat.walk() {
        if let Some(Crit::FileDesc(_, d)) = cat.crit(&occ.md5)
            && seen.insert(d.name.clone())
        {
            out.push(d.name.clone());
        }
    }
    out
}

/// Repair every recovery set in `dir` whose data files are actually
/// there. A nested layer can land beside packets that describe files
/// which never touched this dir (the downloaded set's own index next to
/// an in-stream-extracted payload: its volumes exist only as the
/// extracted output) - repairing such a set would at best re-derive
/// "everything missing" noise and at worst resurrect volume files, so a
/// set only qualifies when at least one of its FileDesc names exists on
/// disk. Sets are repaired in first-seen (sorted packet-file) order;
/// per-set failures don't stop later sets. `Ok(vec![])` = nothing
/// relevant here at all.
pub fn repair_present_sets(dir: &Path) -> Result<Vec<SetOutcome>, RepairError> {
    repair_sets_inner(dir, false)
}

/// [`repair_present_sets`], plus a content fallback for the wholly
/// renamed obfuscated post: when not a single FileDesc name is on disk,
/// the sets are attempted anyway and the verdicts speak (issue #9's
/// single-file shape, where not even a companion .nfo keeps its name).
///
/// A separate entry point because the fallback is WRONG for the other
/// caller. The nested disk post-pass leans on the name gate to skip an
/// outer index whose volumes never touched disk - attempted anyway,
/// `repair_dir_set` would RECREATE those volumes on disk from recovery
/// slices and adoption, materializing files the one-pass pipeline just
/// proved it never needed to write. Only the no-set obfuscated arm,
/// which owns a directory where everything already landed, wants this.
pub fn repair_present_or_renamed_sets(dir: &Path) -> Result<Vec<SetOutcome>, RepairError> {
    repair_sets_inner(dir, true)
}

/// One recovery set's verdict, with the file names that set declares.
///
/// The names travel WITH the verdict because a caller turning "the sets
/// are fine" into "the download is fine" may only count coverage from a
/// set that actually reported one. A set with no data file on disk is
/// skipped, and folding its declared names into a directory-wide
/// coverage union is how a wholly missing file - the everyday
/// one-file-takedown shape - reached Completed with its journal
/// deleted. [`covered_names`] is still the right answer for "whose
/// payload is this file", which is a question about the packets, not
/// about any repair.
#[derive(Debug)]
pub struct SetOutcome {
    /// The recovery set id these packets share - the same 16 bytes
    /// `Par2Set::recovery_set_id` carries, so a caller can name the set
    /// the way every `[par2]`/`[verify]` console line already does
    /// (first 8 of `par2::hex16`). It travels WITH the verdict because
    /// an arithmetic shortfall is a statement about ONE set, and a
    /// caller reporting it over a post that carries several has nothing
    /// else to say which one it measured (31 Aug 2026).
    pub set_id: [u8; 16],
    /// Every file name this set's FileDesc packets declare.
    pub names: Vec<String>,
    /// What repairing it produced. `Ok` means every one of `names` is
    /// verified on disk; anything else means the set speaks for none of
    /// them.
    pub status: Result<RepairStatus, RepairError>,
}

fn repair_sets_inner(dir: &Path, renamed_fallback: bool) -> Result<Vec<SetOutcome>, RepairError> {
    let mut cat = PacketCatalog::build(dir)?;
    repair_sets_catalog(&mut cat, renamed_fallback)
}

/// [`repair_sets_inner`] over a shared catalog: the discovery walk (set
/// order, declared names, contested-name claims) replays occurrences,
/// and each qualifying set's repair consults the same catalog instead
/// of rescanning the corpus.
fn repair_sets_catalog(
    cat: &mut PacketCatalog,
    renamed_fallback: bool,
) -> Result<Vec<SetOutcome>, RepairError> {
    let dir = cat.dir().to_path_buf();
    let dir = dir.as_path();
    if cat.is_empty() {
        return Ok(Vec::new());
    }
    let fold = crate::disk::case_insensitive_dir(dir);
    let mut order: Vec<[u8; 16]> = Vec::new();
    let mut names: HashMap<[u8; 16], Vec<String>> = HashMap::new();
    for (_, occ) in cat.walk() {
        names.entry(occ.set_id).or_insert_with(|| {
            order.push(occ.set_id);
            Vec::new()
        });
        if let Some(Crit::FileDesc(_, d)) = cat.crit(&occ.md5) {
            names.get_mut(&occ.set_id).unwrap().push(d.name.clone());
        }
    }
    // Which descriptors claim each destination name, directory-wide -
    // `PacketCatalog::declared_and_contested`, shared with the
    // single-set-out-of-a-shared-directory entry point so the two
    // cannot disagree about what this directory declares.
    let (declared, contested) = cat.declared_and_contested(fold);
    let ctx = DirContext {
        contested,
        declared,
        donors: Vec::new(),
        patch_existing: false,
    };
    let mut out = Vec::new();
    for id in &order {
        let present = names[id]
            .iter()
            .any(|n| crate::disk::join_out_name(dir, &crate::disk::sanitize_out_name(n)).is_file());
        if present {
            out.push(SetOutcome {
                set_id: *id,
                names: names[id].clone(),
                status: repair_dir_set(cat, Some(*id), &ctx, false),
            });
        }
    }
    // No set matched by NAME - which on a wholly renamed obfuscated post
    // is the expected state, not proof of absence: every data file is on
    // disk under a hash, and only the adoption scan's content match can
    // tie one to a FileDesc. Skipping here failed exactly those posts.
    //
    // So when the caller asked for the renamed fallback and the name test
    // found NOTHING, attempt the sets anyway and let the verdicts speak -
    // but only if the directory holds at least one non-packet file that
    // could serve as an adoption source; packets alone can only rebuild
    // what `files_created` recreates from slices, and a caller wanting
    // that shape drives `repair_dir` directly.
    //
    // Deliberately all-or-nothing: when even ONE set matched by name, an
    // unmatched set stays skipped exactly as before. The fallback can
    // therefore only run where the name gate returned an empty Vec - a
    // job that was already failing - so a foreign junk set going
    // Unrepairable here fails nothing that used to succeed.
    if renamed_fallback && out.is_empty() {
        let packet_set: HashSet<&Path> = cat.packet_paths().collect();
        if adopt::any_adoption_source(dir, &packet_set)? {
            for id in &order {
                out.push(SetOutcome {
                    set_id: *id,
                    names: names[id].clone(),
                    status: repair_dir_set(cat, Some(*id), &ctx, false),
                });
            }
        }
    }
    Ok(out)
}

/// The repair engine behind [`repair_dir`] / [`repair_present_sets`]:
/// `want` pins the recovery set to operate on (packets from other sets
/// are ignored, exactly as foreign-set packets always were); `None`
/// keeps the historical first-seen binding.
/// `fresh`: the catalog was listed inside THIS repair call and nothing
/// has consulted it before, so its lazy prefix scan happens here and
/// selected recovery slices need no re-proof - the exact trust the
/// historical scan-then-pread had. A reused catalog (`false`) is a
/// snapshot: the inner pass rechecks file identity/size/mtime first and
/// re-proves each selected recovery packet against its MD5 at pread.
fn repair_dir_set(
    cat: &mut PacketCatalog,
    want: Option<[u8; 16]>,
    ctx: &DirContext,
    fresh: bool,
) -> Result<RepairStatus, RepairError> {
    // The NTT verify-failure retry is safe to run as a full re-attempt
    // here: the rerun re-verifies every target from disk, so any block
    // the failed attempt patched in place with wrong bytes fails its
    // checksum again, lands back in `missing`, and is rebuilt by the
    // fold; temp-file rebuilds were already cleaned up before the
    // VerifyFailed returned. The retry drops `fresh`: the first attempt
    // wrote to the directory, so the rerun rechecks and re-proves.
    let mut fresh = fresh;
    run_with_ntt_fallback(SyndromePath::Auto, |path, probe| {
        let f = std::mem::replace(&mut fresh, false);
        repair_dir_set_inner(cat, want, ctx, f, path, probe)
    })
}

fn repair_dir_set_inner(
    cat: &mut PacketCatalog,
    want: Option<[u8; 16]>,
    ctx: &DirContext,
    fresh: bool,
    path: SyndromePath,
    probe: &mut NttProbe,
) -> Result<RepairStatus, RepairError> {
    let dir = cat.dir().to_path_buf();
    let dir = dir.as_path();
    let timing = std::env::var_os("NZBFAST_REPAIR_TIMING").is_some();
    let t0 = std::time::Instant::now();
    let mut mark = {
        let mut last = t0;
        move |label: &str| {
            if timing {
                let now = std::time::Instant::now();
                info!(
                    target: "repair-timing",
                    "{label}: +{:.2?} (total {:.2?})",
                    now - last,
                    now - t0
                );
                last = now;
            }
        }
    };
    if !fresh {
        // Reused catalog: recheck every file's identity/size/mtime and
        // selectively rescan whatever moved before trusting a byte of it
        // (the previous set's repair may have patched, recreated, or
        // disambiguated files in this directory).
        cat.refresh()?;
    }
    if cat.is_empty() {
        return Err(RepairError::NoMainPacket);
    }

    // --- incremental packet scan (one file's bytes in memory at a time) ---
    // Critical packets (Main + every FileDesc + IFSC) are duplicated in
    // every volume, so they normally all come out of the FIRST (index)
    // file. On a lazily-built catalog the loop stops reading files as
    // soon as the critical set is complete; the remaining files - the
    // recovery volumes, i.e. almost all the bytes - carry only RecvSlic
    // locations we still need, and that scan runs in the background
    // UNDER the target-verify pass below (disjoint files: .par2 volumes
    // here, data files there). A prebuilt catalog replays the same walk
    // from memory and reads nothing.
    let mut replay = SetReplay::new(want);
    let mut fed = replay.feed_files(cat, 0, SetReplay::criticals_complete);
    while !replay.criticals_complete() && cat.scan_next()? {
        fed = replay.feed_files(cat, fed, SetReplay::criticals_complete);
    }
    mark("packet scan (critical)");
    let (block_size, file_ids) = replay.main.take().ok_or(RepairError::NoMainPacket)?;
    let bs = block_size as usize;
    // Whether two destination paths that differ only in case name ONE file is
    // a property of this volume, so probe it rather than guessing from the
    // build target (see `disk::case_insensitive_dir`).
    let fold = crate::disk::case_insensitive_dir(dir);

    // --- lay the recovery-set files onto the global slice index space ---
    let mut targets: Vec<Target> = Vec::with_capacity(file_ids.len());
    let mut next_slice = 0usize;
    for fid in &file_ids {
        let Some(d) = replay.descs.remove(fid) else {
            // Without the FileDesc we know neither name nor length, and
            // the global constant assignment shifts - unrecoverable here.
            return Err(RepairError::Malformed(format!(
                "FileDesc missing for file id {fid:02x?}"
            )));
        };
        // d.length is attacker-controlled; a huge value makes n_slices
        // enormous. Reject per-file before it can (a) wrap the running
        // sum in `next_slice += n_slices` (release builds have no overflow
        // checks), slipping past the aggregate guard below, or (b) drive a
        // multi-exabyte `vec![false; n_slices]` in verify_target.
        let n_slices_u64 = d.length.div_ceil(block_size);
        if n_slices_u64 > MAX_INPUT_SLICES as u64 {
            return Err(RepairError::Malformed(format!(
                "{}: {n_slices_u64} slices exceeds the PAR2 limit of {MAX_INPUT_SLICES}",
                d.name
            )));
        }
        let n_slices = n_slices_u64 as usize;
        // A disagreeing IFSC packet is FITTED to the declared grid, not
        // fatal and not discarded - `par2.rs::fit_ifsc` is the same
        // reconciliation for the same reason, and this is its second
        // reader, so the two move together or a set parses one way here
        // and another there. Failing the call instead abandoned every
        // other file in the set (19 repairable files lost to one
        // malformed packet) when the recovery blocks to fix them were
        // sitting right there.
        let blocks = replay
            .ifscs
            .remove(fid)
            .map(|b| par2::fit_ifsc(b, d.length, bs as u64))
            .unwrap_or_default();
        // Wire-supplied names never touch the filesystem raw.
        // Tree-preserving: a provably safe FileDesc path keeps its
        // directory structure (VIDEO_TS trees have to stay trees to
        // play); anything else flattens exactly as before.
        let path = crate::disk::join_out_name(dir, &crate::disk::sanitize_out_name(&d.name));
        targets.push(Target {
            file: Par2File {
                file_id: *fid,
                name: d.name,
                length: d.length,
                md5: d.md5,
                md5_16k: d.md5_16k,
                blocks,
            },
            path,
            first_slice: next_slice,
            n_slices,
            present: Vec::new(),
            intact: false,
            exists: false,
            resume: None,
        });
        next_slice = next_slice.saturating_add(n_slices);
    }
    let n_inputs = next_slice;
    if n_inputs > MAX_INPUT_SLICES {
        return Err(RepairError::Malformed(format!(
            "{n_inputs} input slices exceeds the PAR2 limit of {MAX_INPUT_SLICES}"
        )));
    }

    // Two distinct FileDescs can sanitize to the SAME path (e.g. "a/b.bin"
    // and "a_b.bin" both land at "a_b.bin"). Sharing a destination is silent
    // data loss: verifying, repairing, or landing the second removes the
    // first's (possibly intact) bytes and renames over them, yet the set can
    // still report `Repaired`. Give every colliding target a distinct path,
    // disambiguated by its unique file_id, so a destination is never shared
    // and each descriptor is verified/landed against its own file.
    {
        // Claims are keyed by filesystem identity: on macOS/Windows two
        // descriptors that differ only in case name ONE object, so an exact
        // path compare would leave both undisambiguated and let the second
        // land over the first - the very loss this block exists to prevent.
        let mut claimed: HashSet<PathBuf> = HashSet::new();
        for t in &mut targets {
            // A name some OTHER set in this directory claims for
            // DIFFERENT content is disambiguated on its first appearance
            // here, not just on a repeat. The loop below only ever sees
            // one set - `want` dropped every foreign packet long before
            // this - so two sets each declaring a file that sanitizes to
            // `a_b.bin` both chose that path, the second renamed its
            // verified rebuild over the first's verified bytes, and both
            // verdicts still came back green. Keyed by file_id, so the
            // two sets independently agree on who gets which path and a
            // retried attempt picks the same one again.
            let contested = ctx
                .contested
                .contains(&name_identity_key(fold, &t.file.name));
            if !contested && claimed.insert(path_identity_key(fold, &t.path)) {
                continue;
            }
            // Composed onto the out-RELATIVE name and re-capped, not
            // pushed onto the joined path: `t.path`'s leaf is a
            // `sanitize_out_name` result and is routinely AT the
            // 255-byte component cap - capping is what produced it - so
            // a raw 17-byte `.dup-<fid>` yields a 272-byte component no
            // filesystem here will create, and the repaired file has
            // nowhere to land. The cap goes on the COMPOSED name
            // because this path is also the claim key (`claimed` is
            // keyed on it and the verify pass reads it back); shortening
            // it at the write would split the two. Distinctness across
            // `suffix` rests on `cap_component`'s hash tag, which is
            // exactly what that function's tag is for - the tail is what
            // truncation removes here, where a prefix survives it.
            let base = crate::disk::out_name_of(dir, &t.path);
            let mut suffix = 0u32;
            loop {
                let fid: String = t
                    .file
                    .file_id
                    .iter()
                    .take(6)
                    .map(|b| format!("{b:02x}"))
                    .collect();
                let tag = if suffix == 0 {
                    format!(".dup-{fid}")
                } else {
                    format!(".dup-{fid}-{suffix}")
                };
                let alt = crate::disk::join_out_name(
                    dir,
                    &crate::disk::sanitize_out_name(&format!("{base}{tag}")),
                );
                if claimed.insert(path_identity_key(fold, &alt)) {
                    t.path = alt;
                    break;
                }
                suffix += 1;
            }
        }
    }

    // A sniffed packet file that is also a recovery-set target is data
    // first - keep it eligible for the adoption scan. Compared through
    // `path_identity_key` like every other destination compare in this file:
    // on a case-insensitive volume `Movie.R00` and `movie.r00` name one
    // object, and an exact compare left the file in `exclude`, so the
    // adoption scan never looked at the one file holding the missing blocks
    // and the set reported Unrepairable when it was repairable.
    let mut sniffed = cat.sniffed_paths();
    sniffed.retain(|p| {
        !targets
            .iter()
            .any(|t| path_identity_key(fold, &t.path) == path_identity_key(fold, p))
    });

    // --- verify every target from disk, overlapped with the recovery-
    //     volume scan (they touch disjoint files: data files here, .par2
    //     volumes there). A prebuilt catalog has no tail left to scan,
    //     so verify runs alone and the replay just finishes from memory.
    if cat.complete() {
        verify_all_targets(&mut targets, bs)?;
    } else {
        let mut verify_res: Result<(), RepairError> = Ok(());
        let mut bg_res: Result<(), RepairError> = Ok(());
        std::thread::scope(|s| {
            let h = s.spawn(|| cat.scan_rest());
            verify_res = verify_all_targets(&mut targets, bs);
            bg_res = h.join().expect("volume scan worker panicked");
        });
        verify_res?;
        bg_res?;
    }
    replay.feed_files(cat, fed, |_| false);
    let rec_locs = std::mem::take(&mut replay.rec_locs);
    mark("verify targets + volume scan");
    let mut missing: Vec<usize> = Vec::new();
    for t in &targets {
        for (i, ok) in t.present.iter().enumerate() {
            if !ok {
                missing.push(t.first_slice + i);
            }
        }
    }
    let needs_resize: Vec<usize> = targets
        .iter()
        .enumerate()
        .filter(|(_, t)| !t.intact)
        .map(|(i, _)| i)
        .collect();
    if missing.is_empty() && needs_resize.is_empty() {
        return Ok(RepairStatus::NoDamage);
    }

    // --- pick recovery slices: smallest exponents, deduped ---
    let mut by_exp: HashMap<u32, RecLoc> = HashMap::new();
    let (mut refused, mut shortest) = (0usize, u32::MAX);
    for loc in &rec_locs {
        // M4-56, and the same rule the mapped selection applies: a
        // packet longer than one block is the block plus padding and is
        // cut on load; a short one cannot be extended without inventing
        // bytes, so it is refused - out loud, which is the half that was
        // missing. See [`slices::slice_fits_block`].
        if slices::slice_fits_block(loc.len as usize, bs) {
            by_exp.entry(loc.exp).or_insert(*loc);
        } else {
            refused += 1;
            shortest = shortest.min(loc.len);
        }
    }
    catalog::warn_short_slices(refused, shortest, bs);

    // --- extra-file adoption ---
    // Only when a file failed identification outright (missing, renamed,
    // shifted - nothing on disk verifies) or the damage exceeds the
    // recovery slices on disk. The scan reads whole candidate files, so
    // it must never run on the everyday a-few-blocks-bad repair.
    let any_unidentified = targets
        .iter()
        .any(|t| t.n_slices > 0 && !(t.exists && (t.intact || t.present.iter().any(|&p| p))));
    let (mut cands, donor_from, mut adopted) =
        if !missing.is_empty() && (any_unidentified || missing.len() > by_exp.len()) {
            adopt::adopt_blocks(dir, &ctx.donors, &targets, &missing, bs, &sniffed)?
        } else {
            (Vec::new(), 0, HashMap::new())
        };
    // §293 donors are the walk's tail; fixed before the escalation appends.
    let donor_cands = donor_from..cands.len();
    // Adopted slices are found, not missing - only the rest needs RS.
    let mut missing: Vec<usize> = missing
        .into_iter()
        .filter(|g| !adopted.contains_key(g))
        .collect();
    // Sweep S3's residue: the solve and the patch reread donor bytes, so
    // a donor deleted after the decision failed the repair from the lazy
    // open. Pin them now; one already gone degrades to dropped adoptions.
    let pinned = adopt::pin_donor_sources(&cands, &donor_cands, &mut adopted, &mut missing);

    // In-set harvest: a slice this set already proved present on disk is
    // this set's own copy of any missing slice declaring the same block
    // checksums, wherever the two files sit. Free to decide and
    // unconditional - see [`adopt::harvest_in_set`] for why it may not
    // wait for a shortfall the way the escalation below does.
    adopt::harvest_in_set(&targets, &missing, bs, &mut cands, &mut adopted)?;
    missing.retain(|g| !adopted.contains_key(g));

    // Last-resort escalation: still more damage than recovery on disk -
    // scan identified damaged targets too, which the normal pass skips.
    // A mid-file insertion leaves a file half-verified with the rest of
    // its content byte-shifted inside itself; only a scan of that file
    // can find it. Any target whose bytes end up serving as an adoption
    // source is later rebuilt via temp+rename, never patched in place.
    if !missing.is_empty() && missing.len() > by_exp.len() {
        let start = cands.len();
        for t in &targets {
            let identified = t.exists && (t.intact || t.present.iter().any(|&p| p));
            if identified && t.present.iter().any(|&p| !p) {
                let len = std::fs::metadata(&t.path)?.len();
                if len > 0 {
                    cands.push((t.path.clone(), len));
                }
            }
        }
        if cands.len() > start {
            let missing_set: HashSet<usize> = missing.iter().copied().collect();
            let indices: Vec<usize> = (start..cands.len()).collect();
            // Empty donor range: every slot this scan reads is one of the
            // identified damaged targets appended just above - the
            // repair's OWN files, whose I/O errors must stay fatal.
            adopt::sliding_scan(
                &cands,
                &indices,
                0..0,
                &targets,
                &missing_set,
                bs,
                &mut adopted,
            )?;
            missing.retain(|g| !adopted.contains_key(g));
        }
    }
    mark("adoption");
    let cands = cands;
    // `adopted` is final: THREE writers above fill this one map -
    // `adopt::adopt_blocks` (outside the set), `adopt::harvest_in_set`
    // and the escalation's `adopt::sliding_scan` (both inside it) - and
    // `RepairStatus::Unrepairable` reports only its LENGTH. A fourth
    // writer needs nothing here, which is the point: the shortfall
    // surface deliberately says how many blocks adoption found and not
    // where they came from, because a location claim has to be
    // re-derived for every path and the old one ("in files outside the
    // recovery set") was false on two of these three for five weeks.
    // See `nzbfast::repair::adopted_clause`, which carries the whole
    // argument and the reason the donor NAMES were not plumbed here.
    let adopted = adopted;
    let missing = missing;
    let mut cand_reader = adopt::CandReader {
        cands: &cands,
        open: pinned,
    };

    let needed = missing.len();
    // `missing` is final here - adoption has already subtracted every
    // block it found, and a set that adoption brings back UNDER the cap
    // is a legitimate repair, which is why this cannot move any earlier.
    // The shortfall verdict stays first: "you do not have enough
    // recovery data" is the more useful answer when both are true, and
    // it is the order `Reconstructor::new_with_path` would have reached
    // on its own. What this buys over that backstop is the load below.
    //
    // A SHORTFALL NO LONGER RETURNS HERE: the write path below still
    // runs, over `status::publishable` targets only, so a member already
    // proven byte-exact is not thrown away with the set. Verdict and
    // arithmetic are unchanged. See `status::finish`.
    let mut shortfall = (by_exp.len() < needed).then_some(by_exp.len());
    let recovery = if shortfall.is_none() && needed > 0 {
        reconstruct::check_repair_dim(needed)?;
        match load_selected_recovery(cat, &mut by_exp, needed, bs, !fresh)? {
            Some(loaded) => loaded,
            // Re-proof at pread dropped enough mutated packets to fall
            // short - the same verdict a fresh scan of the changed file
            // would have reached.
            None => {
                shortfall = Some(by_exp.len());
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    mark("load recovery");

    // --- syndrome pass: stream every present slice once ---
    let blocks_rebuilt = missing.len();
    let rebuilt: Vec<Vec<u8>> = if blocks_rebuilt > 0 && shortfall.is_none() {
        let mut rec = Reconstructor::new_with_path(bs, n_inputs, &missing, &recovery, path)?;
        probe.selected = rec.ntt_selected();
        probe.m = missing.len();
        probe.block_size = bs;
        probe.max_exp = recovery.last().map_or(0, |&(e, _)| e);
        probe.context = dir.display().to_string();
        // `Reconstructor::new` has copied every recovery slice into its own
        // u16 syndrome buffers, so this second payload-sized copy (missing x
        // block_size - 537 MB on a 128-block/4 MiB repair) is dead weight for
        // the rest of the solve. Peak RSS on that repair measured ~2 GB
        // against a 268 MB resolved budget; this is one of the four live
        // buffers and the only one that is redundant.
        drop(recovery);
        // Present-slice reads fan out exactly as in `repair_mapped`
        // (M2c.2): contiguous chunks of the flattened work list per
        // reader (sequential read patterns), each with its own Feeder
        // into the one fold worker. This loop used to run single-file,
        // single-threaded - the only serial data pass left in the
        // disk repair path.
        let work: Vec<(usize, usize, u64, usize)> = targets
            .iter()
            .enumerate()
            .filter(|(_, t)| t.exists)
            .flat_map(|(ti, t)| {
                t.present
                    .iter()
                    .enumerate()
                    .filter(|&(_, &p)| p)
                    .map(move |(i, _)| {
                        let off = i as u64 * block_size;
                        (
                            t.first_slice + i,
                            ti,
                            off,
                            (t.file.length - off).min(block_size) as usize,
                        )
                    })
            })
            .collect();
        if !work.is_empty() {
            let readers = crate::mem::cpu_workers().min(8).min(work.len()).max(1);
            let per_reader_batch = (BATCH_BYTES / readers).max(1 << 20);
            let chunk = work.len().div_ceil(readers);
            let targets_ref = &targets;
            let mut read_results: Vec<Result<(), RepairError>> =
                (0..readers).map(|_| Ok(())).collect();
            std::thread::scope(|s| {
                for (wchunk, res) in work.chunks(chunk).zip(read_results.iter_mut()) {
                    let mut feeder = rec.feeder(per_reader_batch);
                    s.spawn(move || {
                        *res = (|| {
                            let mut open: Option<(usize, File)> = None;
                            // One reusable read buffer per reader (see
                            // FeedBatch - per-slice allocs are the trap).
                            let mut buf = vec![0u8; bs];
                            for &(g, ti, off, take) in wchunk {
                                if open.as_ref().is_none_or(|(oi, _)| *oi != ti) {
                                    open = Some((ti, File::open(&targets_ref[ti].path)?));
                                }
                                let f = &open.as_ref().expect("just opened").1;
                                crate::disk::read_exact_at(f, &mut buf[..take], off)?;
                                feeder.feed(g, &buf[..take]);
                            }
                            Ok(())
                        })();
                        // feeder drops here → tail batch flushes.
                    });
                }
            });
            for r in read_results {
                r?;
            }
        }
        // Adopted blocks are present data too - fed from their source.
        let mut by_cand: HashMap<usize, Vec<(usize, u64)>> = HashMap::new();
        for (&g, s) in &adopted {
            by_cand.entry(s.cand).or_default().push((g, s.offset));
        }
        for (ci, mut list) in by_cand {
            list.sort_unstable_by_key(|&(_, off)| off);
            for (g, off) in list {
                let take = crate::disk::chunk_len(cands[ci].1.saturating_sub(off), bs);
                let data = cand_reader.read(
                    AdoptSrc {
                        cand: ci,
                        offset: off,
                    },
                    take,
                )?;
                rec.feed(g, &data);
            }
        }
        let (r, syn_report) = rec.finish_reported();
        probe.used = syn_report.ntt_used;
        probe.n_present = syn_report.n_present;
        mark("feed+fold+solve");
        r
    } else {
        Vec::new()
    };

    // --- patch ---
    // X6-02c: [`adopt::adopted_from_names`] owns the rule and its argument.
    let adopted_from = adopt::adopted_from_names(dir, &cands, &donor_cands, &adopted);
    // Which candidates donated anything. Turning these into whole paths
    // the CALLER may delete needs a proof about every byte of the file,
    // not just the window that matched, so it waits until after the
    // final verify (see `spent_donors` below).
    let donors: HashSet<usize> = adopted.values().map(|s| s.cand).collect();
    let mut report = RepairReport {
        blocks_rebuilt: rebuilt.len(),
        blocks_adopted: adopted.len(),
        adopted_from,
        files_patched: Vec::new(),
        files_created: Vec::new(),
        consumed_sources: Vec::new(),
        // Built HERE and not in the patch loop below: that loop walks
        // `damaged` only, and the census is over every target.
        per_file: status::per_file_census(&targets, &adopted, &missing),
    };
    // Bounded by `rebuilt` so it cannot outrun it: a shortfall
    // reconstructs nothing, and an empty map cannot be indexed.
    let rebuilt_of: HashMap<usize, usize> = missing[..rebuilt.len()]
        .iter()
        .enumerate()
        .map(|(m, &g)| (g, m))
        .collect();
    // Global slice ids the repair rebuilt from recovery data - ALL of
    // `missing`, correct only while the spend loop is gated on
    // `shortfall.is_none()`. Read `adopt::proven_spent` before lifting it.
    let rebuilt_set: HashSet<usize> = missing.iter().copied().collect();
    let mut damaged: Vec<usize> = needs_resize;
    for (ti, t) in targets.iter().enumerate() {
        if !t.present.iter().all(|&p| p) && !damaged.contains(&ti) {
            damaged.push(ti);
        }
    }
    damaged.sort_unstable();
    if shortfall.is_some() {
        damaged.retain(|&ti| status::publishable(&report.per_file[ti], &targets[ti], ctx));
    }

    // Identified targets (≥1 verified block or an intact MD5) are patched
    // in place - unless their bytes serve as an adoption source. Those,
    // and unidentified targets, are rebuilt to a temp file and renamed in
    // LAST, so no source is overwritten until every adopted read and
    // every whole-file verify has happened.
    // Identity-keyed for the same reason as `adoption_candidates`: the source
    // was found by `read_dir` and the target names itself from the PAR2
    // packet, so a case difference between the two would defeat this check
    // and patch a file in place while it is still being read as a source.
    let used_sources: HashSet<PathBuf> = adopted
        .values()
        .map(|s| path_identity_key(fold, &cands[s.cand].0))
        .collect();
    let mut renames: Vec<(PathBuf, usize)> = Vec::new();
    // Publishable members that did NOT land - `status::publish_failed`.
    let mut unpublished: Vec<usize> = Vec::new();
    let cleanup = |renames: &[(PathBuf, usize)], extra: Option<&PathBuf>| {
        for (tmp, _) in renames {
            let _ = std::fs::remove_file(tmp);
        }
        if let Some(tmp) = extra {
            let _ = std::fs::remove_file(tmp);
        }
    };
    // (path to verify, target index, patched in place) - temps verify
    // before their rename, and only in-place patches may resume the
    // proof from the verify pass's MD5 snapshot (see [`Md5Resume`]).
    let mut checks: Vec<(PathBuf, usize, bool)> = Vec::new();
    for &ti in &damaged {
        let t = &targets[ti];
        // A tree-preserved target writes into a subdirectory that may
        // not exist yet (missing-file recreate); the temp file lands in
        // the same parent, so both arms need it. Symlink-refusing, same
        // containment rule as every other tree write.
        crate::disk::create_out_dirs(dir, &crate::disk::out_name_of(dir, &t.path))?;
        let identified = t.exists && (t.intact || t.present.iter().any(|&p| p));
        // Shortfall publishes stage - `status::publishable`'s argument.
        let via_temp = !identified
            || shortfall.is_some()
            || used_sources.contains(&path_identity_key(fold, &t.path));
        // In temp mode verified blocks are copied over from the old
        // file; in place they're already where they belong.
        let write_blocks = |f: &File,
                            cand_reader: &mut adopt::CandReader,
                            copy_present: bool|
         -> Result<(), RepairError> {
            f.set_len(t.file.length)?;
            let src = if copy_present && t.exists && t.present.iter().any(|&p| p) {
                Some(File::open(&t.path)?)
            } else {
                None
            };
            for (i, &present) in t.present.iter().enumerate() {
                let g = t.first_slice + i;
                let off = i as u64 * block_size;
                let take = (t.file.length - off).min(block_size) as usize;
                if present {
                    if let Some(src) = &src {
                        let mut v = vec![0u8; take];
                        crate::disk::read_exact_at(src, &mut v, off)?;
                        crate::disk::write_all_at(f, &v, off)?;
                    }
                    continue;
                }
                if let Some(&mi) = rebuilt_of.get(&g) {
                    crate::disk::write_all_at(f, &rebuilt[mi][..take], off)?;
                } else if let Some(&s) = adopted.get(&g) {
                    let data = cand_reader.read(s, take)?;
                    crate::disk::write_all_at(f, &data, off)?;
                }
            }
            Ok(())
        };
        if !via_temp {
            let f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&t.path)?;
            let res = write_blocks(&f, &mut cand_reader, false);
            drop(f);
            if let Err(e) = res {
                cleanup(&renames, None);
                return Err(e);
            }
            checks.push((t.path.clone(), ti, true));
        } else {
            // A temp this call provably created. The name used to be fully
            // predictable and opened with `File::create`, which truncates and
            // follows symlinks: a pre-existing `.<name>.nzbfast-repair.tmp`
            // was clobbered and then removed by cleanup, and a symlink there
            // put the truncation on its target. `create_new` cannot do either.
            let base = t
                .path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "file".into());
            // That leaf is a `sanitize_out_name` result and is routinely
            // AT the 255-byte component cap - capping is what produced
            // it - so decorating it raw gives a temp name no filesystem
            // will create, and the rebuild has nowhere to be staged.
            //
            // Held back at the STEM rather than capped on the composed
            // name, unlike the `.dup-` destination above: this name is
            // nobody's identity key (it is created with `create_new`,
            // renamed away, and swept by its infix), so what matters is
            // that it stays RECOGNISABLE as a repair temp - and capping
            // the composed name truncates the `.nzbfast-repair.` marker
            // off exactly the names that needed shortening.
            //
            // ONE closure spells the decoration and the reserve is that
            // same closure over an empty stem, so the two cannot drift:
            // `cap_shared_stem` reserves its LONGEST tail rather than a
            // sum, and the leading `.` costs a byte on the same
            // component as the tail does.
            let decorate = |stem: &str, n: usize| format!(".{stem}.nzbfast-repair.{n}.tmp");
            let base = crate::disk::cap_shared_stem(&base, [decorate("", 1023).as_str()]);
            let mut made = None;
            for n in 0..1024 {
                let candidate = t.path.with_file_name(decorate(&base, n));
                match std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&candidate)
                {
                    Ok(f) => {
                        made = Some((candidate, f));
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(e) => {
                        cleanup(&renames, None);
                        return Err(e.into());
                    }
                }
            }
            let Some((tmp, tmp_file)) = made else {
                cleanup(&renames, None);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "no free repair temp name",
                )
                .into());
            };
            if let Err(e) = write_blocks(&tmp_file, &mut cand_reader, true) {
                let _ = std::fs::remove_file(&tmp);
                status::publish_failed(shortfall, &t.file.name, e)
                    .inspect_err(|_| cleanup(&renames, None))?;
                unpublished.push(ti);
                continue;
            }
            checks.push((tmp.clone(), ti, false));
            renames.push((tmp, ti));
        }
    }
    mark("patch");
    // Whole-file MD5 for everything written - files are independent, so
    // verify across threads.
    if !checks.is_empty() {
        let machine = crate::mem::cpu_workers();
        let threads = machine.min(checks.len()).max(1);
        let chunk = checks.len().div_ceil(threads);
        let mut results: Vec<Option<Result<bool, RepairError>>> =
            (0..checks.len()).map(|_| None).collect();
        let targets_ref = &targets;
        std::thread::scope(|s| {
            for (cchunk, rchunk) in checks.chunks(chunk).zip(results.chunks_mut(chunk)) {
                s.spawn(move || {
                    for ((path, ti, in_place), r) in cchunk.iter().zip(rchunk) {
                        let t = &targets_ref[*ti];
                        *r = Some(match &t.resume {
                            Some(res) if *in_place => md5_matches_resumed(path, &t.file, res),
                            _ => md5_matches(path, &t.file),
                        });
                    }
                });
            }
        });
        unpublished.extend(
            status::verify_results(&checks, results, &targets, shortfall)
                .inspect_err(|_| cleanup(&renames, None))?,
        );
    }
    mark("final verify");
    // --- which donors are provably spent ---
    //
    // One adopted block authenticates ONE window of the donor - a legal
    // PAR2 block can be four bytes - and says nothing whatever about the
    // donor's other bytes. Handing the caller every path that donated
    // anything, which it deletes outright, therefore destroyed complete
    // files over a shared block: zero padding, a common container
    // header, or a neighbouring recovery set's payload (foreign targets
    // are unidentified here, so they are ordinary adoption candidates).
    //
    // The case this cleanup exists for - issue #9, the obfuscated post -
    // is the one where the hash-named donor IS the payload byte for
    // byte, and the repair has just landed those same bytes under the
    // FileDesc name. So require exactly that: the donor must match a
    // target of this set in declared length AND in declared whole-file
    // MD5. That is a proof about every byte, which is what deletion
    // needs, and it is cheap to reach because the length test rejects
    // almost everything before a hash is computed.
    //
    // A name any set in the directory declares is somebody's payload and
    // is never swept, whatever it hashes to.
    let declared_names: HashSet<String> = ctx
        .declared
        .iter()
        .cloned()
        .chain(
            targets
                .iter()
                .map(|t| name_identity_key(fold, &t.file.name)),
        )
        .collect();
    let target_keys: HashSet<PathBuf> = targets
        .iter()
        .map(|t| path_identity_key(fold, &t.path))
        .collect();
    let mut spent_donors: Vec<PathBuf> = Vec::new();
    // A shortfall publishes files and spends NOTHING: see the
    // `consumed_sources` note on `status::RepairStatus::Unrepairable`.
    for ci in donors.into_iter().filter(|_| shortfall.is_none()) {
        let (p, len) = &cands[ci];
        // §293: a candidate from a DONOR directory is a predecessor
        // job's payload, not this directory's junk - byte-identical to
        // a target is exactly the good case there, and sweeping it
        // would delete another job's files. Only the repair dir's own
        // files can ever be spent.
        if !p.starts_with(dir) {
            continue;
        }
        if adopt::is_somebodys_payload(dir, fold, p, &target_keys, &declared_names) {
            continue;
        }
        let want: Vec<[u8; 16]> = targets
            .iter()
            .filter(|t| t.file.length == *len)
            .map(|t| t.file.md5)
            .collect();
        // A hash that cannot be read decides nothing: keep the file.
        if !want.is_empty() && adopt::md5_of_file(p, None).is_ok_and(|h| want.contains(&h)) {
            spent_donors.push(p.clone());
            continue;
        }
        // The damaged-twin and fully-donated arms - the per-byte proofs
        // for a source the exact-MD5 test can never clear. See
        // [`adopt::proven_spent`].
        if adopt::proven_spent(p, *len, ci, &targets, &adopted, &rebuilt_set, &cands, bs) {
            spent_donors.push(p.clone());
        }
    }
    spent_donors.sort();
    report.consumed_sources = spent_donors;
    // Every adopted read and every verify is done - land the rebuilds.
    status::drop_unpublished(&unpublished, &mut damaged, &mut renames);
    let temp_set: HashSet<usize> = renames.iter().map(|&(_, ti)| ti).collect();
    for &ti in &damaged {
        if !temp_set.contains(&ti) {
            report.files_patched.push(targets[ti].file.name.clone());
        }
    }
    for (tmp, ti) in renames {
        let t = &targets[ti];
        // Rename straight over the target - no remove first.
        //
        // `fs::rename` replaces atomically on unix AND windows
        // (MOVEFILE_REPLACE_EXISTING), so the file is never absent. Removing
        // it first opened a window where a crash, or any rename failure, left
        // NO canonical file at all: the original had been deleted and the
        // rebuilt copy was still sitting under its temp name.
        if let Err(e) = std::fs::rename(&tmp, &t.path) {
            let _ = std::fs::remove_file(&tmp);
            status::publish_failed(shortfall, &t.file.name, e.into())?;
            continue;
        }
        report.files_patched.push(t.file.name.clone());
        if !t.exists {
            report.files_created.push(t.file.name.clone());
        }
    }
    Ok(status::finish(shortfall, needed, adopted.len(), report))
}

/// Per-worker read-chunk size for the parallel block-hash pass. Blocks
/// larger than this are streamed through the chunk incrementally, so
/// the buffer bound holds whatever the wire-supplied block size is
/// (`bs` goes up to MAX_BLOCK_SIZE, 256 MiB).
const HASH_CHUNK: usize = 4 << 20;
/// Ceiling on total chunk-buffer bytes across hash workers - the same
/// role the partials budget plays for the download path: parallelism
/// must never buy unbounded reader memory. 16 workers x 4 MiB.
const HASH_POOL_BYTES: usize = 64 << 20;
/// Below this many readable bytes the thread fan-out is not worth its
/// setup; the serial single-pass scanner keeps the small-file path.
#[cfg(not(fuzzing))]
const HASH_PAR_MIN_BYTES: u64 = 8 << 20;
/// Under cargo-fuzz the gate drops to 8 KiB. `par2_verify_diff` exists to
/// prove the two verify paths cannot disagree, and a gate it can only
/// cross by writing 8 MiB per case would cost ~30 executions a second -
/// the parallel branch would be fuzzed at a rate that finds nothing. The
/// threshold is a performance choice, not part of the verdict rule, so
/// lowering it changes which path answers and never what it answers.
#[cfg(fuzzing)]
const HASH_PAR_MIN_BYTES: u64 = 8 << 10;

/// The pool gate, readable from outside the crate so `par2_verify_diff`
/// can assert it is small enough for the files that target writes. The
/// failure this guards is silent: if `--cfg fuzzing` ever stops reaching
/// this crate, the gate goes back to 8 MiB, every generated case takes
/// the serial path, and the differential keeps passing while proving
/// nothing about the parallel one.
#[doc(hidden)]
pub fn hash_par_min_bytes() -> u64 {
    HASH_PAR_MIN_BYTES
}

/// Per-block CRC32 presence for one file, across a worker pool.
///
/// `crc_ok[i]` reproduces the serial scanner's presence decision
/// exactly: full blocks close at `bs`, the tail extends through its
/// zero padding via `crc32_zeros`, and a block whose declared bytes are
/// not all on disk is damage by definition and stays false.
///
/// PRESENCE only. This pool used to also check the per-block IFSC MD5s
/// and hand back "every block matched" as a whole-file verdict (§129),
/// which is a claim about the IFSC list, not about the FileDesc MD5 the
/// contract names - see [`verify_pass1`] and [`md5_matches`] for why
/// that stopped being a verdict (H7). Presence needs no such premise:
/// it is defined by the IFSC CRC32s, so it is the pool's to answer.
///
/// `limit` is how many bytes are readable (min of declared length and
/// disk length); `threads` is this file's share of the machine, decided
/// by the caller so nested file-level and block-level pools do not
/// multiply.
fn hash_blocks_par(
    read_at: &(dyn Fn(u64, &mut [u8]) -> std::io::Result<()> + Sync),
    limit: u64,
    length: u64,
    blocks: &[BlockCheck],
    bs: usize,
    threads: usize,
) -> Result<Vec<bool>, RepairError> {
    let n_slices = length.div_ceil(bs as u64) as usize;
    if n_slices == 0 {
        return Ok(Vec::new());
    }
    let mut crc_ok = vec![false; n_slices];
    let chunk_buf = bs.min(HASH_CHUNK);
    let workers = threads
        .min(n_slices)
        .min((HASH_POOL_BYTES / chunk_buf.max(1)).max(1))
        .max(1);
    // Contiguous block ranges per worker: N sequential read streams,
    // not a random-access shuffle.
    let per = n_slices.div_ceil(workers);
    let mut worker_out: Vec<Result<(), RepairError>> = (0..workers).map(|_| Ok(())).collect();
    std::thread::scope(|s| {
        for (wi, (oks, res)) in crc_ok
            .chunks_mut(per)
            .zip(worker_out.iter_mut())
            .enumerate()
        {
            s.spawn(move || {
                *res = (|| {
                    let mut buf = vec![0u8; chunk_buf];
                    for (j, ok) in oks.iter_mut().enumerate() {
                        let bidx = wi * per + j;
                        let off = bidx as u64 * bs as u64;
                        let declared = (length - off).min(bs as u64);
                        let avail = limit.saturating_sub(off).min(bs as u64);
                        if avail < declared {
                            // Truncation: the serial pass never closes
                            // this block's CRC either.
                            continue;
                        }
                        let mut crc = crc32fast::Hasher::new();
                        let mut p = 0u64;
                        while p < avail {
                            let take = crate::disk::chunk_len(avail - p, buf.len());
                            read_at(off + p, &mut buf[..take])?;
                            crc.update(&buf[..take]);
                            p += take as u64;
                        }
                        // Tail zero padding in O(log n), exactly as the
                        // serial scanner does it.
                        let crc_val = if avail == bs as u64 {
                            crc.finalize()
                        } else {
                            crate::yenc_simd::crc32_zeros(crc.finalize(), bs as u64 - avail)
                        };
                        *ok = blocks.get(bidx).is_some_and(|c| c.crc_matches(crc_val));
                    }
                    Ok(())
                })();
            });
        }
    });
    for r in worker_out {
        r?;
    }
    Ok(crc_ok)
}

/// What the verify pass learned about one target file.
///
/// `#[doc(hidden)] pub` for the same reason [`SyndromeReport`] is: the
/// `par2_verify_diff` fuzz target lives outside this crate and has to
/// compare the verdicts of both verify paths against each other and
/// against bytes it generated. Not part of the supported API surface.
#[doc(hidden)]
pub struct Pass1Out {
    pub exists: bool,
    pub intact: bool,
    /// Whole-file MD5 matched over the declared length: every block is
    /// present even if trailing junk keeps `intact` false.
    pub clean: bool,
    /// Per-block presence from the in-stream block CRC32s, for a
    /// damaged file with IFSC data (None when clean, absent, or the
    /// set has no IFSC packets - those fall back to all-false).
    pub present: Option<Vec<bool>>,
    /// Where the post-repair self-prove may pick the whole-file MD5
    /// back up (TODO 133.1 cost work) - see [`Md5Resume`].
    pub resume: Option<Md5Resume>,
}

/// The whole-file MD5 state this verify pass had reached at the byte
/// boundary of the first block it could not prove present - the point
/// up to which the file's bytes have been read (and hashed) once
/// already, and before which an IN-PLACE patch writes nothing: every
/// block the patch touches is a not-present block, and those all start
/// at or after this boundary (so do `set_len`'s zero-extension bytes).
/// Hashing `[offset..length]` of the patched file from `state` is
/// therefore the same FileDesc-MD5 proof over the same final bytes as
/// a full reread; the only thing it stops re-checking is that nothing
/// OUTSIDE the repair rewrote the already-verified prefix in the
/// window between verify and patch, which the full reread only caught
/// by accident. Temp-file rebuilds do NOT get this: their prefix is a
/// fresh copy whose bytes nobody has hashed, so they keep the full
/// reread ([`md5_matches`]).
///
/// The self-prove itself stays a separate read-back-from-disk step
/// after the patch - fusing it into the syndrome feed is the shape the
/// mapped driver's safety contract forbids
/// (`mapped_driver_rereads_files_it_did_not_rebuild`), and this
/// mirrors that: prove what landed, never what was about to be fed.
///
/// `#[doc(hidden)] pub` for `par2_verify_diff`, which asserts the
/// resumed verdict can never disagree with the full one.
#[doc(hidden)]
#[derive(Clone)]
pub struct Md5Resume {
    offset: u64,
    state: Md5,
}

/// Blocks below this stop the resume snapshotting: one `Md5` clone per
/// block start is noise against hashing 64 KiB, but a wire-supplied
/// 4-byte block size would turn it into the dominant term of the scan.
#[cfg(not(fuzzing))]
const RESUME_MIN_BLOCK: usize = 64 << 10;
/// Under cargo-fuzz the gate drops to 16 bytes for the same reason
/// `HASH_PAR_MIN_BYTES` does: `par2_verify_diff` asserts the resumed
/// self-prove verdict against the full one, and a gate the generated
/// block sizes never cross would leave that assertion passing while
/// proving nothing. The threshold is a performance choice; the snapshot
/// it gates is either taken or not, never different.
#[cfg(fuzzing)]
const RESUME_MIN_BLOCK: usize = 16;

/// The resume gate, readable from outside the crate so
/// `par2_verify_diff` can assert it is small enough for the block sizes
/// that target generates - the same silent-coverage guard as
/// [`hash_par_min_bytes`].
#[doc(hidden)]
pub fn resume_min_block() -> usize {
    RESUME_MIN_BLOCK
}

/// Target verification in ONE streaming pass: the whole-file MD5 and
/// the per-block IFSC CRC32s are computed from the same buffered read.
/// The old shape hashed every damaged file twice (whole-file MD5, then
/// a second full pass of per-block MD5+CRC); the CRC costs a few
/// percent on top of the MD5 and deletes that second pass outright.
///
/// Presence is decided by the block CRC32 ALONE. The block MD5s are
/// deliberately not consulted: a corrupt block that collides CRC32
/// (2⁻³² per damaged block, and damage is honest randomness) would
/// poison the syndromes and make the repair produce wrong bytes for
/// OTHER blocks - and that is exactly what the mandatory whole-file
/// self-prove after patching catches, so the failure mode is a FAILED
/// repair, never a wrong "Repaired". Same trade par2cmdline's own
/// scanning makes, with a stronger backstop.
///
/// The CLEAN verdict is the FileDesc whole-file MD5 and only that.
/// "Every padded block MD5 matched" is a statement about the IFSC list,
/// which is a SEPARATE claim in the same set - nothing binds the two,
/// so a PAR2 pairing one file's FileDesc with another's IFSC under one
/// file id passed the block proof and failed the MD5 (H7, 08-08 sweep;
/// `ifsc_contradicting_the_filedesc_md5_is_rejected_by_both_paths`).
/// Recomputing the spec's file id does not bind them either - it hashes
/// hash16k, length and name, not the whole-file MD5 beside them.
///
/// `threads` is this file's share of the machine (see
/// [`verify_all_targets`]). It buys parallelism for one shape only: a
/// file SHORT of its declared length cannot be clean whatever any hash
/// says, so [`hash_blocks_par`]'s block-CRC32 presence scan is the
/// whole answer there and runs across lanes. Everything else takes the
/// serial pass below, which gets the whole-file MD5 and the per-block
/// CRC32s out of one read.
///
/// `#[doc(hidden)] pub` for `par2_verify_diff` (see [`Pass1Out`]), which
/// calls it at both thread counts over the same file.
#[doc(hidden)]
pub fn verify_pass1(
    path: &Path,
    file: &Par2File,
    bs: usize,
    threads: usize,
) -> Result<Pass1Out, RepairError> {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Pass1Out {
                exists: false,
                intact: false,
                clean: false,
                present: None,
                resume: None,
            });
        }
        Err(e) => return Err(e.into()),
    };
    let disk_len = f.metadata()?.len();
    let n_slices = file.length.div_ceil(bs as u64) as usize;
    let track = !file.blocks.is_empty();
    if threads > 1
        && n_slices >= 2
        && file.blocks.len() >= n_slices
        && disk_len < file.length
        && disk_len >= HASH_PAR_MIN_BYTES
    {
        let fref = &f;
        let crc_ok = hash_blocks_par(
            &|off, buf| crate::disk::read_exact_at(fref, buf, off),
            disk_len,
            file.length,
            &file.blocks,
            bs,
            threads,
        )?;
        return Ok(Pass1Out {
            exists: true,
            intact: false,
            clean: false,
            present: Some(crc_ok),
            // The pool branch never computes the whole-file MD5, so
            // there is no state to resume from - such targets keep the
            // full-reread self-prove.
            resume: None,
        });
    }
    let mut whole = Md5::new();
    let mut blocks_ok = track.then(|| vec![false; n_slices]);
    let mut crc = crc32fast::Hasher::new();
    let mut bfill = 0usize;
    let mut bidx = 0usize;
    // Resume snapshotting (TODO 133.1): `pending` is the whole-file
    // MD5 state at the START of the block currently being scanned;
    // when a block fails its CRC, that clone becomes the frozen
    // `snap` the self-prove resumes from. Cloning stops the moment a
    // failure is frozen - after that only the hash itself keeps going.
    let snapping = track && bs >= RESUME_MIN_BLOCK;
    let mut snap: Option<Md5Resume> = None;
    let mut pending: Option<Md5Resume> = None;
    // The buffer is bounded regardless of the slice size - `bs` is
    // wire-supplied up to MAX_BLOCK_SIZE (256 MiB), and this allocates
    // once per parallel worker. The in-stream block CRC accumulates
    // across reads (`bfill`), so blocks may straddle buffers freely.
    let mut buf = vec![0u8; bs.clamp(1 << 20, 8 << 20)];
    let limit = file.length.min(disk_len);
    let mut pos = 0u64;
    while pos < limit {
        let take = crate::disk::chunk_len(limit - pos, buf.len());
        read_full(&mut f, &mut buf[..take])?;
        if !snapping {
            whole.update(&buf[..take]);
        }
        if let Some(ok) = blocks_ok.as_mut() {
            let mut p = 0usize;
            while p < take {
                if snapping && bfill == 0 && snap.is_none() {
                    pending = Some(Md5Resume {
                        offset: pos + p as u64,
                        state: whole.clone(),
                    });
                }
                let seg = (bs - bfill).min(take - p);
                if snapping {
                    // Fed per block segment instead of per read so the
                    // state at each block boundary exists to clone;
                    // segments are >= RESUME_MIN_BLOCK except at
                    // buffer straddles, so the per-call overhead stays
                    // noise.
                    whole.update(&buf[p..p + seg]);
                }
                crc.update(&buf[p..p + seg]);
                bfill += seg;
                p += seg;
                if bfill == bs {
                    let done = std::mem::replace(&mut crc, crc32fast::Hasher::new());
                    let matched = file
                        .blocks
                        .get(bidx)
                        .is_some_and(|check| check.crc_matches(done.finalize()));
                    if let Some(slot) = ok.get_mut(bidx) {
                        *slot = matched;
                    }
                    if !matched && snap.is_none() {
                        snap = pending.take();
                    }
                    bfill = 0;
                    bidx += 1;
                }
            }
        }
        pos += take as u64;
    }
    if bfill > 0
        && let Some(ok) = blocks_ok.as_mut()
    {
        // Tail block, zero-padded to the block size per spec - but
        // only when the declared bytes were all on disk (a tail cut
        // short by a truncated file is damage by definition).
        let off = bidx as u64 * bs as u64;
        let expect = (file.length - off).min(bs as u64);
        if limit - off >= expect {
            // Extended through the padding in O(log n) rather than by
            // hashing a zero buffer: `bs` is wire-supplied up to 256 MiB,
            // and a set of many one-byte targets made every parallel
            // worker allocate one of those at its tail block - a
            // metadata-driven `targets x block_size` memory spike on a
            // file that could be a few KB. The read buffer above is
            // already clamped for exactly this reason.
            let padded = crate::yenc_simd::crc32_zeros(crc.clone().finalize(), (bs - bfill) as u64);
            if let Some(check) = file.blocks.get(bidx) {
                ok[bidx] = check.crc_matches(padded);
            }
        }
        if !ok.get(bidx).copied().unwrap_or(true) && snap.is_none() {
            // Tail block unproven (bad padded CRC, cut short, or no
            // IFSC entry): the resume boundary is its start.
            snap = pending.take();
        }
    }
    // No block failed IN the streamed bytes: any remaining damage
    // (blocks wholly past a boundary-truncated EOF, or nothing but a
    // length mismatch `set_len` fixes) starts at or after `limit`, so
    // the state right here resumes it. A partial tail that FAILED set
    // `snap` above, so reaching here with `bfill > 0` means the tail
    // proved out - the only in-place mutation left is `set_len`, which
    // never touches a byte below `limit`. Cloned before `finalize`
    // consumes the hasher.
    if snapping && snap.is_none() {
        snap = Some(Md5Resume {
            offset: limit,
            state: whole.clone(),
        });
    }
    let md5: [u8; 16] = whole.finalize().into();
    let md5_ok = disk_len >= file.length && md5 == file.md5;
    Ok(Pass1Out {
        exists: true,
        intact: md5_ok && disk_len == file.length,
        clean: md5_ok,
        present: if md5_ok { None } else { blocks_ok },
        // Kept even when the MD5 matched: a clean-but-oversized target
        // (`needs_resize`) is patched by a bare `set_len` truncation,
        // and its resume boundary is `limit` - the whole proof is the
        // already-computed state, no reread at all.
        resume: snap,
    })
}

/// Verify every target from a size-descending work queue (biggest file
/// first, so no fixed-chunk straggler). One streaming pass per file
/// does everything - see [`verify_pass1`].
fn verify_all_targets(targets: &mut [Target], bs: usize) -> Result<(), RepairError> {
    if targets.is_empty() {
        return Ok(());
    }
    let mut order: Vec<usize> = (0..targets.len()).collect();
    order.sort_by_key(|&ti| targets[ti].file.length); // pop() takes the largest
    let queue = std::sync::Mutex::new(order);
    let machine = crate::mem::cpu_workers();
    let cores = machine.min(targets.len());
    // Each file-level worker hands its big files a fair share of the
    // remaining cores for block-parallel hashing - one 8 GB target on a
    // 24-core box gets all 24 lanes instead of one.
    let inner = (machine / cores).max(1);
    let targets_ref: &[Target] = targets;
    let mut results: Vec<Result<Vec<(usize, Pass1Out)>, RepairError>> = Vec::new();
    std::thread::scope(|s| {
        let handles: Vec<_> = (0..cores)
            .map(|_| {
                s.spawn(|| {
                    let mut out: Vec<(usize, Pass1Out)> = Vec::new();
                    loop {
                        let Some(ti) = queue.lock_ok().pop() else {
                            return Ok(out);
                        };
                        let t = &targets_ref[ti];
                        out.push((ti, verify_pass1(&t.path, &t.file, bs, inner)?));
                    }
                })
            })
            .collect();
        results = handles
            .into_iter()
            .map(|h| h.join().expect("verify worker panicked"))
            .collect();
    });
    let mut p1s: Vec<(usize, Pass1Out)> = Vec::with_capacity(targets.len());
    for r in results {
        p1s.extend(r?);
    }
    for (ti, out) in p1s {
        let t = &mut targets[ti];
        t.exists = out.exists;
        t.intact = out.intact;
        t.present = match out.present {
            Some(p) => p,
            None => vec![out.clean; t.n_slices],
        };
        t.resume = out.resume;
    }
    Ok(())
}

fn read_full(f: &mut File, mut buf: &mut [u8]) -> std::io::Result<()> {
    while !buf.is_empty() {
        match f.read(buf) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "file shorter than its metadata length",
                ));
            }
            Ok(n) => buf = &mut buf[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Whole-file proof for a patched target: the FileDesc MD5 over the
/// bytes as they will actually be read afterwards - M2c's self-proving
/// contract, and nothing else stands in for it (H7).
///
/// `#[doc(hidden)] pub` for `par2_verify_diff` (see [`Pass1Out`]): the
/// third verdict in the differential, and the one the other two must
/// not contradict.
#[doc(hidden)]
pub fn md5_matches(path: &Path, file: &Par2File) -> Result<bool, RepairError> {
    let mut f = File::open(path)?;
    if f.metadata()?.len() != file.length {
        return Ok(false);
    }
    let mut hasher = Md5::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let md5: [u8; 16] = hasher.finalize().into();
    Ok(md5 == file.md5)
}

/// [`md5_matches`] resumed from the verify pass's snapshot: the same
/// FileDesc whole-file proof, minus a reread of the prefix the verify
/// pass already hashed and an in-place patch cannot have touched (see
/// [`Md5Resume`] for why that equivalence holds, and for why temp-file
/// rebuilds never take this path).
///
/// `#[doc(hidden)] pub` for `par2_verify_diff`: the fourth verdict in
/// the differential - on an unpatched file it must equal
/// [`md5_matches`] exactly.
#[doc(hidden)]
pub fn md5_matches_resumed(
    path: &Path,
    file: &Par2File,
    resume: &Md5Resume,
) -> Result<bool, RepairError> {
    use std::io::Seek;
    let mut f = File::open(path)?;
    if f.metadata()?.len() != file.length {
        return Ok(false);
    }
    let mut hasher = resume.state.clone();
    f.seek(std::io::SeekFrom::Start(resume.offset))?;
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let md5: [u8; 16] = hasher.finalize().into();
    Ok(md5 == file.md5)
}

// Wave-4 row M4-53: the recovery-volume SHAPE test the sniffed-leftover
// sweeps gate their deletes on. Its own file for the size gate.
mod volshape;
pub use volshape::is_recovery_volume_shape;

// The repair math and the mapped driver - moved out bodily (TODO 106),
// same child-module shape as `unit_tests` below.
#[cfg(test)]
mod inline_tests;

// Directory-path unit tests (coverage §122.5) - a child module, the
// pool/unit_tests.rs pattern, so par2repair.rs stays inside its
// size-gate entry while `super::*` keeps the private internals
// reachable.
#[cfg(test)]
mod unit_tests;
