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
use crate::md5fast::{Digest, Md5};
use crate::par2::{self, BlockCheck, Par2File};
use crate::sync::MutexExt;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering::Relaxed;
use tracing::{debug, info, warn};

/// PAR2 hard limit: number of naturals below 65535 coprime to it.
/// Public so pre-repair planners (the mapped path's parity-as-a-source
/// slot allocation) can refuse a set that could never repair anyway
/// BEFORE committing any state to it.
pub const MAX_INPUT_SLICES: usize = 32768;
/// The dense arm's matrix scale, and NO LONGER A REFUSAL: `~4*m^2` bytes
/// of matrix and inverse, ~256 MB at this m. A hard cap until 8 Sep 2026;
/// the arm is bounded by MEMORY now (`reconstruct::check_repair_dim_dense`),
/// as Forney's was. Kept because `forney` and `catalog` anchor cost
/// arguments on its scale. Nothing refuses on it: timed from ABOVE it at
/// last on a 20-core arm64 desktop, the arm takes 67.8 s at m = 10,000
/// where this doc predicted hours, and par2cmdline-turbo 1.5.0 - the
/// fallback it named - takes 84.9 s on the same set.
pub const MAX_REPAIR_DIM: usize = 8192;

/// Present-slice bytes buffered between threaded syndrome flushes.
const BATCH_BYTES: usize = 64 << 20;

/// Reader threads feeding present slices to the fold worker: the
/// machine's workers capped at eight, or at FOUR on Windows.
/// `NZBFAST_FEED_READERS` (1..=64) overrides either.
///
/// The Windows cap is measured (i5-10600KF, 6c/12t, 5 Sep 2026, the
/// next-dial handoff section 5): `ReadFile` out of the page cache is a
/// kernel memcpy at ~2.9 GB/s per thread there, so the 3-block leg's
/// 1 GiB feed is 374 / 372 / 352 ms on one reader, 228 / 251 / 233 on
/// two, **209 / 208 / 196 on four**, 223 / 242 / 243 on eight and
/// 241 / 237 / 232 on twelve - past four the readers and the six fold
/// workers fight over six physical cores. The 101-block leg is flat
/// across 2 / 4 / 8 (0.99-1.12 s, noise). macOS copies the same GiB in
/// ~30 ms across eight readers and is not the box the cap is for.
fn feed_readers() -> usize {
    static N: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *N.get_or_init(|| {
        std::env::var("NZBFAST_FEED_READERS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&n| (1..=64).contains(&n))
            .unwrap_or_else(|| {
                let cap = if cfg!(windows) { 4 } else { 8 };
                crate::mem::cpu_workers().min(cap)
            })
    })
}

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
    /// The recovery set is fine; the SOLVE just does not fit this
    /// machine's memory budget. Deliberately distinct from
    /// [`Self::Malformed`] for the same reason [`Self::RecoveryShort`]
    /// is: `check_repair_dim_within`'s window-over-budget refusal used
    /// to report this as a malformed set, which sent the reader after a
    /// corrupt PAR2 download when the download is fine and the box
    /// simply is not big enough for the solve RIGHT NOW. It is
    /// retryable where `Malformed` is not - a bigger machine, or a
    /// raised `NZBFAST_REPAIR_SOLVE_BUDGET`, repairs the SAME set.
    /// Measured 8 Sep 2026: an identical set refused here at a 16 GiB
    /// budget repairs in 18.16 s on a 256 GiB box, all 21 files
    /// sha-verified - only the budget differed.
    #[error(
        "recovery set needs {needed_mb} MB for the solve ({m} missing blocks at {block_size} B \
         each) - over this machine's {budget_mb} MB solve-window budget \
         (NZBFAST_REPAIR_SOLVE_BUDGET). The set itself is fine: retry on a machine with more \
         memory, or raise the budget"
    )]
    SolveBudget {
        m: usize,
        block_size: usize,
        needed_mb: u64,
        budget_mb: u64,
    },
    #[error("recovery matrix is singular for this slice combination")]
    SingularMatrix,
    #[error("repaired file failed MD5 verification: {0}")]
    VerifyFailed(String),
    /// A caller raised its [`control::PauseGate`]'s cancel while the
    /// repair was running. Deliberately distinct from every other arm
    /// here: nothing is WRONG - not the set, not the machine, not the
    /// recovery data - and a caller that reports this as a failed repair
    /// tells its user their set is broken when they simply pressed
    /// Cancel.
    ///
    /// WHAT IS LEFT ON DISK, which is the half a caller has to know.
    /// Cancelled before the patch (the verify pass, the fold, the
    /// solve): nothing at all was written, exactly as an
    /// [`AfterSurvey::Stop`] leaves it. Cancelled DURING the patch:
    /// every temp-staged member is removed and none is renamed in, and
    /// an in-place patched member has some subset of its MISSING blocks
    /// filled - the patch only ever writes blocks the verify pass found
    /// missing, so it is monotone and the member is no worse than it
    /// was. Nothing is purged and no backup is consumed, because both
    /// happen after a repair that finished. A re-run re-verifies from
    /// disk and repairs from the same recovery data.
    #[error("repair cancelled")]
    Cancelled,
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
use linalg::{FeedBatch, fold_parallel_controlled, invert_controlled};
pub use linalg::{bench_backsub, bench_fold, bench_invert, set_unattended_unstructured_ceiling};

// The Forney-style back-substitution and its gate: the LAST phase of a
// repair, and its own subject, the way `linalg` is the fold's and
// `fastpar` is the syndrome dispatch's.
pub(crate) mod forney;

use forney::ForneyPlan;
/// Arm or disarm the joint solve for this process, overriding
/// `NZBFAST_FORNEY_JOINT` in BOTH directions.
///
/// The default is ON on aarch64 and OFF on every x86 class since 11 Sep
/// 2026 - see `forney::joint_default_on`, which carries the measurement
/// and the reason the split is provenance rather than preference. So
/// this is no longer only a way to turn the arm on: passing `false` is
/// how a caller takes the shipped solve on a part where the arm is the
/// default, which is what a measurement round needs.
///
/// This is the door `parfast --fast` comes through. It is a process
/// setting rather than a per-repair argument because the solver is
/// chosen inside plan construction, several layers below any repair
/// entry point, and threading a flag down that stack would put an
/// experimental switch in every signature between here and there.
pub use forney::{
    JointDecline, JointReach, joint_armed, joint_reach, reset_joint_reach, set_joint_arm,
};

/// Which back-substitution a repair runs. Both produce the same words
/// (the differential harness in `inline_tests` holds them to it); the
/// dense product is the one that cannot be gated away, because gapped
/// exponents have no factorization for the transform route to use.
enum BackSub {
    /// A⁻¹, row-major: missing[c] = Σ_r inverse[c][r] · S_r.
    Dense(Vec<Vec<u16>>),
    Forney(ForneyPlan),
}

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
    /// What the SOLVE reports to and is cancelled through - taken at
    /// [`Reconstructor::new_controlled`] and inert for every other
    /// constructor. See `par2repair::control`.
    control: control::RepairControl,
    block_size: usize,
    /// k_i per global input index (shared with [`Feeder`] handles).
    base_logs: std::sync::Arc<Vec<u32>>,
    missing: Vec<usize>,
    /// Recovery exponents, in syndrome-row order (needed again at
    /// finish() by the NTT path and its fold fallback).
    exponents: Vec<u32>,
    /// How the back-substitution runs: the explicit inverse, or the
    /// transform solve (see [`forney`]). Chosen at construction, before
    /// any syndrome exists, because the explicit inverse is exactly what
    /// the transform route does not build.
    solve: BackSub,
    /// Batches travel to a worker thread that owns the syndrome rows, so
    /// the caller's disk reads overlap the GF math (bounded channel:
    /// one batch queued while one folds).
    tx: Option<std::sync::mpsc::SyncSender<FeedBatch>>,
    /// Worker returns (syndromes, retained batches, windows closed,
    /// any window transformed, slices transformed) - retained is empty
    /// on the streaming path, and holds the LAST window of the resident
    /// source corpus when the experimental NTT dispatch selected
    /// retention (the whole corpus when it fitted the budget).
    worker: Option<std::thread::JoinHandle<(Vec<Vec<u16>>, Vec<FeedBatch>, usize, bool, usize)>>,
    /// Pending present slices, packed into the next batch's arena.
    batch: FeedBatch,
    batch_capacity: usize,
    /// How the feed pipeline is sized for this construction - see
    /// `reconstruct::FeedShape`. The drivers split its batch across
    /// their readers with [`Reconstructor::per_reader_batch`].
    feed: reconstruct::FeedShape,
    /// Recycled batch arenas, shared with every [`Feeder`] and the fold
    /// worker (see [`linalg::ArenaPool`]).
    pool: std::sync::Arc<linalg::ArenaPool>,
    /// See [`Reconstructor::backsub_arm`].
    backsub_arm: &'static str,
    /// The dispatcher selected NTT retention at construction (the
    /// mid-flight budget/plan fallbacks can still land on the fold).
    ntt_selected: bool,
    /// The stripe cap the dispatcher admitted the transform at
    /// (`fastpar::NttAdmission::stripe_cap`; `usize::MAX` when nothing
    /// was narrowed or the fold was selected).
    ntt_stripe_cap: usize,
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
    /// Present slices fed to the transform, summed over every window
    /// (0 when it did not run). Summed rather than "the last window's",
    /// which is what it was until the streaming admission of 5 Sep 2026
    /// made a multi-window repair the ordinary case: this number is the
    /// geometry a divergence report is reproduced from, and a tail-only
    /// count understates it by the window count.
    pub(crate) n_present: usize,
    /// Retention windows the corpus was taken in - 1 when the whole
    /// corpus was retained and computed at once, more when the budget
    /// admitted it a window at a time, 0 on the fold path, where
    /// nothing is retained at all. A window that the plan could not
    /// represent and that folded still counts: this is how the corpus
    /// was DIVIDED, not how many transforms ran (`ntt_used` answers
    /// that).
    pub(crate) windows: usize,
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
    /// Resident-source NTT with this WINDOW budget in bytes: the worker
    /// retains fed batches up to it, transforms and releases them, and
    /// starts over, so a corpus larger than the budget is taken a
    /// window at a time rather than folded. A window whose plan is
    /// unbuildable (a duplicate feed, an out-of-range log) folds
    /// instead. Test/bench hook - it skips every shape gate.
    NttForce(usize),
    /// TEST ONLY: [`SyndromePath::NttForce`], then flip one syndrome
    /// word after the transform - simulates an NTT correctness bug so
    /// the verify-failure fold retry can be exercised end to end.
    NttForceCorrupt(usize),
    /// TEST ONLY: [`SyndromePath::NttForce`], then panic after the
    /// transform - proves the fold retry survives an NTT panic.
    NttForcePanic(usize),
}

// Fast PAR mode - the process-global "fast par mode" flag, the NTT
// dispatch gates and budget, the trip-breaker and the verify-failure
// fold retry - is a child module of its own (TODO 106). The
// [`SyndromePath`] vocabulary it resolves stays here beside the
// reconstruction types that consume it.
mod fastpar;
pub use fastpar::{
    FAST_PAR_DEFAULT, NttDivergence, fast_par_tripped, set_fast_par_enabled, take_ntt_divergences,
};
use fastpar::{NttProbe, resolve_syndrome_path, run_with_ntt_fallback};
// The creator reads the same shape gates the repair dispatcher prices, so
// the two engines admit the NTT on one rule; the stripe WIDTH is per pass
// (`ntt_create_stripe_geometry`), measured apart since 15 Sep 2026.
pub(crate) use fastpar::{
    ntt_budget_within_published, ntt_create_stripe_geometry, ntt_min_missing, ntt_worker_arenas,
};
// Pinned by `inline_tests` (a descendant, so `use super::*` names them)
// and by nothing else in this module - importing them unconditionally
// would be an unused import at `-D warnings` in every non-test build.
#[cfg(test)]
use fastpar::{
    FAST_PAR_TRIPPED, NTT_MIN_MISSING, NTT_MIN_MISSING_GFNI256_LARGE_BLOCK, NTT_MIN_MISSING_NEON,
    NTT_MIN_MISSING_NIBBLE, NTT_MIN_PRESENT, NTT_MIN_WINDOW_PRESENT, NTT_MIN_WORK_PER_ROW,
    NTT_STRIPE_W_FLOOR, NTT_WINDOW_COMBINE_NEON, NTT_WINDOW_COMBINE_X86, NttAdmission,
    exponent_span, ntt_admit_within, ntt_budget_env, ntt_default_budget, ntt_gates_pass,
    ntt_min_missing_for, ntt_min_work, ntt_stripe_geometry, ntt_window_combine, ntt_window_row_ask,
    ntt_window_row_gate, ntt_worker_arenas_capped,
};

// `impl Reconstructor` lives in par2repair/reconstruct.rs (TODO 106
// size-gate split).
mod catalog;
mod nested;
mod rebuilt;
mod reconstruct;
mod retain;
// The retention ADMISSION census (TODO 331 item 1) and the caller-
// labelled entry points that feed it. Off by default; see census.rs.
mod census;
mod entry;
pub use census::{CallerSite, CallerStage, RetentionCaller, close_retention_census};
/// The census's TEST SEAMS, reachable the way `renameclaim` is: a
/// `pub` path under the `test-support` feature. Three of them, and each
/// exists because a process-global cannot be varied from a test any
/// other way - the census sink, the retention budget's `OnceLock`, and
/// the NTT verify-failure retry.
#[cfg(any(test, feature = "test-support"))]
pub mod census_testing {
    pub use super::census::testing::{Recorder, record, record_to_file};
    pub use super::fastpar::force_one_retry;
    pub use super::retain::{ForcedPolicy, force_policy};
}
pub use entry::{
    repair_dir, repair_dir_as, repair_dir_set_with_donors, repair_dir_set_with_donors_as,
    repair_dir_set_with_donors_controlled_as, repair_dir_set_with_donors_scoped,
    repair_dir_set_with_donors_scoped_as, repair_dir_set_with_donors_scoped_controlled_as,
    repair_dir_with_donors, repair_present_or_renamed_sets, repair_present_sets,
    repair_present_sets_as, repair_present_sets_controlled_as,
};

pub use catalog::PacketCatalog;
use catalog::{Crit, RecLoc, SetReplay, SlicePool, load_selected_recovery_span};
pub use nested::{PacketScope, nested_subdirs, source_candidate_files};
use rebuilt::RebuiltStore;

/// One producer's handle into a [`Reconstructor`]'s fold worker (M2c.2
/// parallel feed reads). Same batching as the built-in feed path, but
/// clonable across reader threads; flushes its tail batch on drop.
pub struct Feeder {
    tx: std::sync::mpsc::SyncSender<FeedBatch>,
    base_logs: std::sync::Arc<Vec<u32>>,
    batch: FeedBatch,
    pool: std::sync::Arc<linalg::ArenaPool>,
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

    /// Read one slice directly into this feeder's packed arena. The arena is
    /// initialized before `fill` runs so arbitrary safe I/O implementations
    /// can use an ordinary `&mut [u8]`; a failed read rolls the reservation
    /// back and feeds no partial slice.
    fn feed_with<E>(
        &mut self,
        input_index: usize,
        len: usize,
        fill: impl FnOnce(&mut [u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        if self.batch.arena.len() + len > self.max_batch {
            self.flush();
        }
        self.batch
            .push_with(self.base_logs[input_index], len, fill)?;
        if self.batch.arena.len() >= self.max_batch {
            self.flush();
        }
        Ok(())
    }

    fn flush(&mut self) {
        if self.batch.slices.is_empty() {
            return;
        }
        let batch = std::mem::replace(&mut self.batch, self.pool.take(self.max_batch));
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
/// Which digest each file gets, and why that keeps the added cost near
/// a plain read, is [`self_prove_set`] - including the prefix arm
/// [`repair_mapped_catalog_resumed`] feeds.
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
    repair_mapped_catalog_resumed(files, block_size, cat, set_id, io, full_verify, &[])
}

/// [`repair_mapped_catalog`] handed the per-file whole-file MD5 states
/// the live verifier accumulated OFF DISK during the download, one per
/// entry of `files` (a shorter slice, or a `None`, simply means "no
/// prefix for this file" and costs nothing).
///
/// This is the daemon's tail lever: the self-prove's whole-file MD5 is
/// the `postproc_secs` term for a big member with a few bad articles -
/// 0.74 GB/s on one core, ~31 s on a 23 GB member - and MD5 is a serial
/// chain, so the only place that work can be moved to is a window
/// EARLIER in the job. `Md5Resume` names how far the verifier got;
/// everything under it was hashed from the same disk this call rereads,
/// and the self-prove closes it against the IFSC CRC32s anyway. See
/// `research/DESIGN-2026-09-02-mapped-selfprove-prefix.md` for why the
/// two alternatives (hash the wire bytes on every download; overlap the
/// prefix with the syndrome feed) were priced and rejected.
pub fn repair_mapped_catalog_resumed(
    files: &[(Par2File, Vec<bool>)],
    block_size: usize,
    cat: &mut PacketCatalog,
    set_id: &[u8; 16],
    io: &dyn VolumeIo,
    full_verify: bool,
    prefixes: &[Option<Md5Resume>],
) -> Result<usize, RepairError> {
    repair_mapped_catalog_resumed_controlled(
        files,
        block_size,
        cat,
        set_id,
        io,
        full_verify,
        prefixes,
        &control::RepairControl::default(),
    )
}

/// [`repair_mapped_catalog_resumed`] under a
/// [`RepairControl`](control::RepairControl) - progress out of the
/// repair, a cancel its loops poll - for the MAPPED in-stream driver's
/// daemon caller (`nzbfast-unpack`'s `repair::try_mapped_repair`),
/// which was the last daemon repair path handing this engine a default
/// control.
///
/// # What the mapped driver reports, and why `Verify` runs LAST here
///
/// All four of the disk driver's phases arrive, in the same units, so
/// one sink can weigh them the same way - but not in the disk driver's
/// order:
///
/// - `Fold` is the syndrome feed, in bytes read off disk.
/// - `Solve` comes from [`Reconstructor::new_controlled`] and its
///   back-substitution, exactly as on the disk driver.
/// - `Write` is the patch, in bytes written back.
/// - `Verify` is the SELF-PROVE, AFTER the patch rather than before it.
///   This driver has no pre-fold verify pass - its present-block ledger
///   was earned off the WIRE during the download - so its only proof is
///   this reread, and it is the last thing the call does.
///
/// [`control::RepairRoute::Mapped`], announced once before the first
/// phase, is what lets a band table place this `Verify` at the tail
/// instead of the head: published at the disk driver's `[0.0, 0.45)` it
/// would arrive behind a `Write` that already reached 1,000, and a
/// monotone bar (`fetch_max`) would simply discard it - the argument is
/// at the `self_prove_set` call below. The disk driver's own post-write
/// whole-file MD5 is silent in exactly the same way and for the same
/// reason, and stays that way: see that call for why generalising this
/// fix to the disk route is a separate trade.
///
/// [`control::ProgressSink::slab`] is announced once per sweep, before
/// that sweep's phases, for the same reason the disk driver announces
/// it: a caller weighing four phases into one bar cannot infer the
/// sweep COUNT from the re-entries.
///
/// Everything else is [`repair_mapped_catalog_resumed`] BY
/// CONSTRUCTION - both are one call to `repair_mapped_inner` differing
/// in the control argument alone - and a default control is the
/// uncontrolled call exactly, branch for branch.
#[expect(clippy::too_many_arguments)]
pub fn repair_mapped_catalog_resumed_controlled(
    files: &[(Par2File, Vec<bool>)],
    block_size: usize,
    cat: &mut PacketCatalog,
    set_id: &[u8; 16],
    io: &dyn VolumeIo,
    full_verify: bool,
    prefixes: &[Option<Md5Resume>],
    control: &control::RepairControl,
) -> Result<usize, RepairError> {
    let policy = SelfProvePolicy {
        full_verify,
        prefixes,
    };
    run_with_ntt_fallback(SyndromePath::Auto, |path, probe| {
        // BEFORE THE CATALOG LOAD, not after: `load_mapped_recovery`
        // preads and re-proves one block per missing slice, which on a
        // big set is itself seconds of work, and the NTT fallback runs
        // this closure a second time. A cancel that landed during the
        // first attempt must not buy the corpus again.
        control.check()?;
        let recovery = catalog::load_mapped_recovery(cat, set_id, files, block_size)?;
        repair_mapped_inner(
            files, block_size, &recovery, io, policy, path, probe, control,
        )
    })
}

/// [`repair_mapped`] with an explicit initial syndrome path (test hook
/// for the NTT fallback machinery). Not part of the supported API
/// surface. The verify-failure fold retry applies here too: a rerun on
/// the fold path re-reads only PRESENT slices (the failed attempt only
/// wrote MISSING ones, so its output never contaminates the retry's
/// syndromes) and rewrites every missing block, so partially-written
/// output from the failed attempt is fully overwritten.
/// [`repair_mapped`] with caller-supplied per-file prefix digests - the
/// in-memory-corpus twin of [`repair_mapped_catalog_resumed`], for the
/// bench and the unit rigs. Not part of the supported API surface.
#[doc(hidden)]
pub fn repair_mapped_prefixed(
    files: &[(Par2File, Vec<bool>)],
    block_size: usize,
    recovery: &[(u32, Vec<u8>)],
    io: &dyn VolumeIo,
    full_verify: bool,
    prefixes: &[Option<Md5Resume>],
) -> Result<usize, RepairError> {
    let policy = SelfProvePolicy {
        full_verify,
        prefixes,
    };
    run_with_ntt_fallback(SyndromePath::Auto, |path, probe| {
        repair_mapped_inner(
            files,
            block_size,
            recovery,
            io,
            policy,
            path,
            probe,
            &control::RepairControl::default(),
        )
    })
}

#[doc(hidden)]
pub fn repair_mapped_with_path(
    files: &[(Par2File, Vec<bool>)],
    block_size: usize,
    recovery: &[(u32, Vec<u8>)],
    io: &dyn VolumeIo,
    full_verify: bool,
    path: SyndromePath,
) -> Result<usize, RepairError> {
    let policy = SelfProvePolicy {
        full_verify,
        prefixes: &[],
    };
    run_with_ntt_fallback(path, |path, probe| {
        repair_mapped_inner(
            files,
            block_size,
            recovery,
            io,
            policy,
            path,
            probe,
            &control::RepairControl::default(),
        )
    })
}

#[expect(clippy::too_many_arguments)]
fn repair_mapped_inner(
    files: &[(Par2File, Vec<bool>)],
    block_size: usize,
    recovery: &[(u32, Vec<u8>)],
    io: &dyn VolumeIo,
    policy: SelfProvePolicy<'_>,
    path: SyndromePath,
    probe: &mut NttProbe,
    // The caller's channel, or an inert control for every entry of this
    // driver that reports nothing - see
    // [`repair_mapped_catalog_resumed_controlled`].
    control: &control::RepairControl,
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

    // Lowest consecutive RUN wins, deduped, one per missing slice - NOT
    // the `m` smallest, which this driver took until 8 Sep 2026 while
    // the disk driver had selected this way since 6 Sep. One gap costs
    // 3.9-9.3x over the whole reconstructor; the argument is in
    // `catalog::select_consecutive_run` and the round in
    // research/SPARSE-EXPONENT-BACKSUB-2026-09-08.md.
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
    let exps = catalog::selected_exponents(&by_exp, missing.len());
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
    // The same bracket the disk driver takes, on the path a DOWNLOAD
    // waits on rather than the CLI one (`forney::PlanPrepCounters`).
    let _prep = forney::PrepSpan::start("mapped repair");
    // MEMORY SETS THE PASS COUNT, NEVER A VERDICT. A window too big for
    // the budget is cut along the block's byte axis and swept once per
    // slab instead of being refused - `reconstruct::plan_slabs` carries
    // the argument and the incident. `slabs == 1` is the ordinary case
    // and reproduces the pre-slab code exactly: one construction, one
    // pass over the payload, one write per missing block.
    // Priced AFTER selection: an unstructured selection is the dense arm
    // whatever the gate says (`reconstruct::solve_buffers`, TODO 348 C).
    let plan = reconstruct::plan_slabs_for(
        missing.len(),
        block_size,
        reconstruct::selection_structured(n_inputs, &missing, &exps),
    );
    if plan.slabs > 1 {
        info!(
            target: "repair-timing",
            "solve window over budget: {} block(s) at {block_size} B in {} slab(s) of {} B \
             - the payload is swept once per slab",
            missing.len(),
            plan.slabs,
            plan.width
        );
    }
    // WHICH ROUTE THIS IS, before anything reports. Once: this driver
    // never falls back to the disk route mid-call, so there is no later
    // boundary to re-announce it at the way `slab` re-announces per
    // sweep. See `control::RepairRoute` for why the band table needs it.
    control.route(control::RepairRoute::Mapped);
    for si in 0..plan.slabs {
        // WHICH SWEEP THIS IS, before anything in it reports. The disk
        // driver says the same thing in the same place and for the same
        // reason: a caller weighing the phases into ONE bar cannot infer
        // the sweep COUNT from the re-entries, so it has to be told
        // before sweep 1 spends the room. See
        // `control::ProgressSink::slab`.
        control.slab(si, plan.slabs);
        // A SLAB BOUNDARY IS A UNIT BOUNDARY: the previous slab's thread
        // scopes have joined and the next one's have not been opened, so
        // this is where a slabbed mapped repair honours a pause, and the
        // one place in this driver where a park is legal. See
        // `control::PauseGate`.
        control.gate()?;
        let span = plan.range(si, block_size);
        let (c0, w) = (span.start, span.len());
        // Borrowed again per slab, never copied: each recovery payload is
        // the caller's, and a slab is a sub-slice of it.
        let chosen_slab: Vec<(u32, &[u8])> =
            chosen.iter().map(|&(e, d)| (e, &d[c0..c0 + w])).collect();
        // Every present slice's contribution to THIS slab: the same work
        // list, shifted into the slab and clipped to it. A block whose
        // file ends before the slab starts contributes nothing and is
        // dropped here rather than read as a zero-length request.
        //
        // BUILT BEFORE THE RECONSTRUCTOR SINCE 16 Sep 2026, and only so
        // the fold's total can be announced ahead of a construction that
        // is itself a reported phase (the Gauss-Jordan inverse reports
        // Solve). Nothing in it reads `rec`; the disk driver sizes its
        // fold in the same place for the same reason.
        let work: Vec<(usize, usize, u64, usize)> = files
            .iter()
            .enumerate()
            .flat_map(|(fi, (f, present))| {
                let base = first_slice[fi];
                present
                    .iter()
                    .enumerate()
                    .filter(|&(_, &p)| p)
                    .filter_map(move |(i, _)| {
                        let off = i as u64 * bs;
                        let whole = (f.length - off).min(bs) as usize;
                        let take = whole.saturating_sub(c0).min(w);
                        (take > 0).then_some((base + i, fi, off + c0 as u64, take))
                    })
            })
            .collect();
        // THE FOLD'S OWN PHASE, in bytes read off disk. Unlike the disk
        // driver there is no retained corpus to add: this driver feeds
        // nothing it did not read here, so the work list IS the total.
        control.begin(
            control::RepairPhase::Fold,
            work.iter().map(|&(_, _, _, take)| take as u64).sum(),
        );
        let rec =
            Reconstructor::new_controlled(w, n_inputs, &missing, &chosen_slab, path, control)?;
        if si == 0 {
            probe.selected = rec.ntt_selected();
            probe.m = missing.len();
            probe.block_size = block_size;
            probe.max_exp = chosen.last().map_or(0, |&(e, _)| e);
            probe.context = files
                .first()
                .map(|(f, _)| f.name.clone())
                .unwrap_or_default();
        }
        // A par-only / whole-set-missing rebuild has NO present slices to
        // stream: every input's contribution to the syndromes is zero, so
        // the recovery slices already ARE the syndromes and the solve runs
        // on them directly (parity as a source). Skip the reader fan-out -
        // `work.chunks(0)` would panic on the empty list.
        if !work.is_empty() {
            let readers = feed_readers().min(work.len()).max(1);
            // Split the shared batch budget across handles so total in-flight
            // memory matches the old single-feeder design.
            let per_reader_batch = rec.per_reader_batch(readers);
            let chunk = work.len().div_ceil(readers);
            let mut read_results: Vec<Result<(), RepairError>> =
                (0..readers).map(|_| Ok(())).collect();
            std::thread::scope(|s| {
                for (wchunk, res) in work.chunks(chunk).zip(read_results.iter_mut()) {
                    let mut feeder = rec.feeder(per_reader_batch);
                    s.spawn(move || {
                        *res = (|| {
                            for &(g, fi, off, take) in wchunk {
                                // Per BLOCK, which is where a cancelled
                                // mapped repair actually stops: this is
                                // the driver's longest stretch on an
                                // ordinary set and every reader is
                                // inside it. `gate_if_held` is one
                                // relaxed load unless somebody is
                                // holding the repair.
                                control.gate_if_held()?;
                                feeder.feed_with(g, take, |buf| io.read(fi, off, buf))?;
                                control.step(control::RepairPhase::Fold, take as u64);
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
        control.finish(control::RepairPhase::Fold);
        if timing {
            info!(
                target: "repair-timing",
                "slab {}/{}: feed reads queued in {:.2?}", si + 1, plan.slabs, t0.elapsed()
            );
        }
        // BEFORE THE SOLVE, the other multi-minute stretch and the one a
        // cancelled repair must not sit through - the same check the
        // disk driver takes at this boundary. On a par-only rebuild the
        // feed above is empty and this is where the cancel first lands.
        control.check()?;
        let (rebuilt, syn_report) = rec.finish_owned_reported();
        if si == 0 {
            probe.used = syn_report.ntt_used;
            probe.n_present = syn_report.n_present;
        }
        if timing {
            info!(
                target: "repair-timing",
                "slab {}/{}: fold+solve done at {:.2?}", si + 1, plan.slabs, t0.elapsed()
            );
        }

        // Write rebuilt blocks back, tails trimmed - across threads, the same
        // fan-out the disk driver's patch uses: `VolumeIo` is `Sync`, each
        // block is one positional write to its own offset, and serially this
        // was the last data pass in the call still running on one core.
        let threads = crate::mem::cpu_workers().min(missing.len()).max(1);
        let chunk = missing.len().div_ceil(threads);
        let mut results: Vec<std::io::Result<()>> = (0..threads).map(|_| Ok(())).collect();
        let rebuilt = &rebuilt;
        let owner = &owner;
        let first_slice = &first_slice;
        // THE PATCH, in bytes written back, sized over exactly the
        // clipped spans the loop below writes. This driver patches
        // MISSING blocks only - it never rewrites a member whole the
        // way the disk driver's temp-staged arm does - so the two
        // measure the same unit over different work, which is what a
        // caller weighing one bar needs them to.
        control.begin(
            control::RepairPhase::Write,
            missing
                .iter()
                .map(|&g| {
                    let fi = owner[g];
                    let off = (g - first_slice[fi]) as u64 * bs;
                    let whole = (files[fi].0.length - off).min(bs) as usize;
                    whole.saturating_sub(c0).min(w) as u64
                })
                .sum(),
        );
        std::thread::scope(|s| {
            for (wi, (mchunk, res)) in missing.chunks(chunk).zip(results.iter_mut()).enumerate() {
                s.spawn(move || {
                    *res = (|| {
                        for (k, &g) in mchunk.iter().enumerate() {
                            let mi = wi * chunk + k;
                            let fi = owner[g];
                            let (f, _) = &files[fi];
                            let off = (g - first_slice[fi]) as u64 * bs;
                            let whole = (f.length - off).min(bs) as usize;
                            let take = whole.saturating_sub(c0).min(w);
                            if take > 0 {
                                io.write(fi, off + c0 as u64, &rebuilt[mi][..take])?;
                                control.step(control::RepairPhase::Write, take as u64);
                            }
                        }
                        Ok(())
                    })();
                });
            }
        });
        for r in results {
            r?;
        }
        control.finish(control::RepairPhase::Write);
        // NO CANCEL POLL INSIDE THE PATCH LOOP, deliberately, and this
        // is the one place in this driver where that is a decision
        // rather than an omission. A mapped write goes through
        // `VolumeIo` into a LIVE extractor slot - a chase buffer or an
        // in-place volume span - and a half-applied slab has no
        // caller-visible rollback the way the disk driver's temp-staged
        // rename does. The patch is also the shortest of the four
        // phases by a wide margin (`forney`'s measurements: seconds
        // against minutes), so stopping inside it buys nothing a check
        // at the next slab boundary does not. The checks that matter -
        // before the fold, before the solve, between slabs - are all
        // ahead of it.
    }
    if timing {
        info!(target: "repair-timing", "patch done at {:.2?}", t0.elapsed());
    }

    // Self-prove: re-read the WHOLE SET via io.read.
    let rebuilt_files: HashSet<usize> = missing.iter().map(|&g| owner[g]).collect();
    // Where each file's FIRST rebuilt block starts. A supplied prefix
    // digest is only usable BELOW this: everything the patch wrote is
    // at or after it, so the bytes under it are the same bytes the
    // prefix was hashed over. `u64::MAX` for a file nothing rebuilt
    // (which takes the untouched-file path anyway).
    let mut first_hole = vec![u64::MAX; files.len()];
    for &g in &missing {
        let fi = owner[g];
        let off = (g - first_slice[fi]) as u64 * bs;
        first_hole[fi] = first_hole[fi].min(off);
    }
    // THE SELF-PROVE REPORTS, as `RepairPhase::Verify` - the same code
    // the disk driver's pre-fold hash uses, because it is the same kind
    // of claim ("these bytes check out"), made at the opposite end of
    // the call. Until 16 Sep 2026 this was silent by decision rather
    // than omission: the first cut of this work published it as Verify
    // straight into `nzbfast_core::repairprog::band`'s disk-shaped
    // `[0.0, 0.45)`, which arrives at ~400 per-mille behind a Write that
    // has already reached 1,000 - and the queue row's bar is monotone by
    // `fetch_max`, so the reading was simply discarded and the row sat
    // at `write, 100%` for the whole of a full-set reread. That is the
    // "Repairing, 100%, timeleft 0:00:00" stall this entire mechanism
    // exists to remove, reintroduced on the route a downloading job
    // actually takes (research/REPAIR-SLABBED-BAR-2026-09-16.md is the
    // measured record of the same shape at a slab boundary).
    //
    // `control.route(RepairRoute::Mapped)`, announced above, is what
    // fixes that: the band table places THIS route's `Verify` after
    // `Write` instead of before `Fold` (`nzbfast_core::repairprog::band`),
    // so the self-prove's rising fraction lands where it is actually
    // read - the tail of the bar, not underneath a phase that already
    // finished. The disk driver's own post-write whole-file MD5 is
    // silent in exactly the same way and for the same reason, and stays
    // that way here: wiring it would move the DISK route's own bands and
    // risk exactly the regression `a_daemon_repair_moves_a_bar_through_
    // four_phases` pins against, for a driver that already has an honest
    // pre-fold Verify. Left for a change that prices that trade on its
    // own.
    self_prove_set(
        files,
        block_size,
        io,
        &rebuilt_files,
        &first_hole,
        policy,
        control,
    )?;
    if timing {
        info!(target: "repair-timing", "patch+verify done at {:.2?}", t0.elapsed());
    }
    Ok(missing.len())
}

/// What the self-prove is allowed to lean on, bundled so
/// [`repair_mapped_inner`] keeps its argument count.
#[derive(Clone, Copy)]
struct SelfProvePolicy<'a> {
    /// The operator asked for FULL verification rather than fast: every
    /// file goes on MD5, and no prefix digest is taken (the point of
    /// the flag is to hash bytes, not to check them cheaply).
    full_verify: bool,
    /// Per-file whole-file MD5 state carried in from OUTSIDE the repair
    /// - the live verifier hashed the file's proven prefix off DISK
    /// while the download ran (see
    /// `research/DESIGN-2026-09-02-mapped-selfprove-prefix.md`). Empty,
    /// or `None` per file, is the ordinary case and costs nothing.
    prefixes: &'a [Option<Md5Resume>],
}

/// Re-read the whole set through `io` and prove it, after the patch.
///
/// THE CONTRACT THIS FUNCTION IS: every file of the recovery set is
/// read back FROM DISK here, not just the ones that received a rebuilt
/// block, because the present-block ledger the driver trusted was
/// earned off the WIRE and cannot see a byte that went bad after it was
/// written (`mapped_driver_rereads_files_it_did_not_rebuild`). The
/// digest differs by what the file has been through:
///
/// - a rebuilt file is proven by its FileDesc MD5 - those bytes are new
///   and MD5 is what proves them;
/// - an untouched file is proven per block against the IFSC CRC32s,
///   ~37x cheaper (measured 27.8 vs 0.74 GB/s on the M3) and the same
///   answer for the corruption this is looking for;
/// - a rebuilt file whose caller supplied a PREFIX digest is proven by
///   both: per-block CRC32 from disk below the prefix boundary, and the
///   FileDesc MD5 resumed at that boundary and finished from disk. Every
///   byte is still read back after the patch and the verdict is still
///   the whole-file MD5 - which makes this arm strictly stronger than
///   the disk driver's [`md5_matches_resumed`], where the prefix is not
///   reread at all.
///
/// `full_verify`, or a set with no per-block checksums to close
/// against, puts everything on MD5 and takes no prefix.
fn self_prove_set(
    files: &[(Par2File, Vec<bool>)],
    block_size: usize,
    io: &dyn VolumeIo,
    rebuilt_files: &HashSet<usize>,
    first_hole: &[u64],
    policy: SelfProvePolicy<'_>,
    control: &control::RepairControl,
) -> Result<(), RepairError> {
    let bs = block_size as u64;
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
    // ONE STEP PER FILE, not per block: this pass has no natural batch
    // unit the way the fold does (`control::ProgressSink`'s cost
    // argument is about a hot loop, and a whole-file MD5 chain is
    // already the coarsest thing here), and `total` is every touched
    // file's declared length - the same reading the disk driver's own
    // Verify total uses. A file whose actual work was cheaper (an IFSC
    // close, or a prefix-shortened MD5) still counts its full length
    // when it lands, exactly as the disk driver's retained-block Verify
    // does: the total is what the pass COULD have read, not what it did.
    control.begin(
        control::RepairPhase::Verify,
        touched.iter().map(|&fi| files[fi].0.length).sum(),
    );
    let timing = std::env::var_os("NZBFAST_REPAIR_TIMING").is_some();
    let crc_bytes = std::sync::atomic::AtomicU64::new(0);
    let md5_bytes = std::sync::atomic::AtomicU64::new(0);
    let crc_ns = std::sync::atomic::AtomicU64::new(0);
    let md5_ns = std::sync::atomic::AtomicU64::new(0);
    let acc = (&crc_bytes, &md5_bytes, &crc_ns, &md5_ns);
    // Unconditional (the two above are behind NZBFAST_REPAIR_TIMING):
    // the bytes the MD5 chain walked, and which files carried how much
    // in from a prefix. Both feed the one report line at the bottom.
    let md5_bytes_total = std::sync::atomic::AtomicU64::new(0);
    let carried: std::sync::Mutex<Vec<(String, u64)>> = std::sync::Mutex::new(Vec::new());
    let tally = (&md5_bytes_total, &carried);
    std::thread::scope(|s| {
        for (tchunk, rchunk) in touched.chunks(chunk).zip(results.chunks_mut(chunk)) {
            s.spawn(move || {
                let mut buf = vec![0u8; 1 << 20];
                for (&fi, r) in tchunk.iter().zip(rchunk) {
                    let (f, _) = &files[fi];
                    // A short IFSC, fitted rather than dropped
                    // (`par2::fit_ifsc`), leaves blocks with no CRC to
                    // close against, and the per-block path would refuse
                    // a file the whole-file MD5 proves.
                    let ifsc = f.blocks.len() as u64 == f.length.div_ceil(bs)
                        && f.blocks.iter().all(|b| b.is_proven());
                    let md5_this = policy.full_verify || rebuilt_files.contains(&fi) || !ifsc;
                    let prefix = if md5_this && ifsc && !policy.full_verify {
                        policy
                            .prefixes
                            .get(fi)
                            .and_then(|p| p.as_ref())
                            .filter(|p| usable_prefix(p, f, block_size, first_hole[fi]))
                    } else {
                        None
                    };
                    let t0 = std::time::Instant::now();
                    let one = if let Some(p) = prefix {
                        // The two halves are timed INSIDE, not around
                        // the call: the whole point of this arm is the
                        // ratio between them, and a single elapsed()
                        // over both reports the sum and calls it the
                        // cheap half (it did, in the first cut).
                        match prove_with_prefix(io, fi, f, block_size, p, &mut buf) {
                            Ok((crc_ns, md5_ns)) => {
                                tally.0.fetch_add(f.length - p.offset, Relaxed);
                                tally.1.lock_ok().push((f.name.clone(), p.offset));
                                if timing {
                                    acc.0.fetch_add(p.offset, Relaxed);
                                    acc.2.fetch_add(crc_ns, Relaxed);
                                    acc.1.fetch_add(f.length - p.offset, Relaxed);
                                    acc.3.fetch_add(md5_ns, Relaxed);
                                }
                                Ok(())
                            }
                            Err(e) => Err(e),
                        }
                    } else if md5_this {
                        let out = prove_md5(io, fi, f, &mut buf);
                        tally.0.fetch_add(f.length, Relaxed);
                        if timing && out.is_ok() {
                            acc.1.fetch_add(f.length, Relaxed);
                            acc.3.fetch_add(t0.elapsed().as_nanos() as u64, Relaxed);
                        }
                        out
                    } else {
                        let out = prove_crc(io, fi, f, block_size, 0, f.length, &mut buf);
                        if timing && out.is_ok() {
                            acc.0.fetch_add(f.length, Relaxed);
                            acc.2.fetch_add(t0.elapsed().as_nanos() as u64, Relaxed);
                        }
                        out
                    };
                    if one.is_ok() {
                        control.step(control::RepairPhase::Verify, f.length);
                    }
                    *r = Some(one);
                }
            });
        }
    });
    for r in results {
        r.expect("verify worker filled every slot")?;
    }
    control.finish(control::RepairPhase::Verify);
    let mut carried = carried.into_inner().unwrap_or_else(|e| e.into_inner());
    carried.sort();
    if timing {
        let mib = |b: u64| b as f64 / (1u64 << 20) as f64;
        let ms = |n: u64| n as f64 / 1e6;
        info!(
            target: "repair-timing",
            "self-prove: crc32 {:.1} MiB in {:.1} ms, md5 {:.1} MiB in {:.1} ms (thread time)",
            mib(crc_bytes.load(Relaxed)),
            ms(crc_ns.load(Relaxed)),
            mib(md5_bytes.load(Relaxed)),
            ms(md5_ns.load(Relaxed)),
        );
    }
    // ONE line, unconditionally, naming how many bytes the tail's MD5
    // chain actually had to walk. This is the deterministic statement of
    // what the prefix bought - a wall-clock number on a shared runner is
    // not - and it is what the e2e row bounds. `carried` is 0 on every
    // repair with no prefix, which is exactly what it read before.
    if !carried.is_empty() {
        let mib = |b: u64| b as f64 / (1u64 << 20) as f64;
        info!(
            target: "repair",
            "self-prove: {:.1} MiB hashed, {:.1} MiB carried in from the \
             download's prefix digest ({})",
            mib(md5_bytes_total.load(Relaxed)),
            mib(carried.iter().map(|(_, b)| b).sum::<u64>()),
            carried
                .iter()
                .map(|(n, b)| format!("{n} at {b}"))
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    Ok(())
}

/// Whether a caller-supplied prefix digest may stand in for rereading
/// `[0, offset)` with MD5.
///
/// Every arm is a soundness condition, not a heuristic:
/// - **block-aligned and non-empty**, so the CRC32 recheck below it
///   closes on whole IFSC blocks and there is something to save;
/// - **at or below the first rebuilt block**, so the patch wrote
///   nothing under it (the same argument [`Md5Resume`] makes);
/// - **within the file**, because a state past EOF describes a
///   different file than the one on disk.
///
/// A prefix that fails any of these is dropped and the file takes the
/// full reread - never a weaker check.
fn usable_prefix(p: &Md5Resume, f: &Par2File, block_size: usize, first_hole: u64) -> bool {
    p.offset > 0
        && p.offset.is_multiple_of(block_size as u64)
        && p.offset <= first_hole
        && p.offset <= f.length
}

/// Whole-file FileDesc MD5, read back from disk.
fn prove_md5(
    io: &dyn VolumeIo,
    fi: usize,
    f: &Par2File,
    buf: &mut [u8],
) -> Result<(), RepairError> {
    let mut hasher = Md5::new();
    read_span(io, fi, 0, f.length, buf, |c| hasher.update(c))?;
    if <[u8; 16]>::from(hasher.finalize()) != f.md5 {
        return Err(RepairError::VerifyFailed(f.name.clone()));
    }
    Ok(())
}

/// [`prove_md5`] resumed at the prefix boundary, with the bytes below
/// the boundary reread from disk and closed against their IFSC CRC32s.
/// Returns the nanoseconds each half cost, for the bench's phase split.
fn prove_with_prefix(
    io: &dyn VolumeIo,
    fi: usize,
    f: &Par2File,
    block_size: usize,
    p: &Md5Resume,
    buf: &mut [u8],
) -> Result<(u64, u64), RepairError> {
    let t0 = std::time::Instant::now();
    prove_crc(io, fi, f, block_size, 0, p.offset, buf)?;
    let crc_ns = t0.elapsed().as_nanos() as u64;
    let t1 = std::time::Instant::now();
    let mut hasher = p.state.clone();
    read_span(io, fi, p.offset, f.length, buf, |c| hasher.update(c))?;
    if <[u8; 16]>::from(hasher.finalize()) != f.md5 {
        return Err(RepairError::VerifyFailed(f.name.clone()));
    }
    Ok((crc_ns, t1.elapsed().as_nanos() as u64))
}

/// Per-block IFSC CRC32 over `[from, to)`, read back from disk. `from`
/// and `to` are block-aligned or `to` is the file length (the tail
/// block is zero-padded to the block size per spec, which `crc32_zeros`
/// does without allocating).
fn prove_crc(
    io: &dyn VolumeIo,
    fi: usize,
    f: &Par2File,
    block_size: usize,
    from: u64,
    to: u64,
    buf: &mut [u8],
) -> Result<(), RepairError> {
    if to <= from {
        return Ok(());
    }
    let mut crc = crc32fast::Hasher::new();
    let mut filled = 0usize; // bytes of the current block
    let mut bidx = (from / block_size as u64) as usize;
    let mut bad = false;
    // Blocks straddle reads freely; the CRC accumulates across them and
    // closes at each boundary.
    read_span(io, fi, from, to, buf, |chunk| {
        let mut q = 0usize;
        while q < chunk.len() {
            let seg = (block_size - filled).min(chunk.len() - q);
            crc.update(&chunk[q..q + seg]);
            filled += seg;
            q += seg;
            if filled == block_size {
                let done = std::mem::replace(&mut crc, crc32fast::Hasher::new());
                bad |= !f
                    .blocks
                    .get(bidx)
                    .is_some_and(|b| b.crc_matches(done.finalize()));
                filled = 0;
                bidx += 1;
            }
        }
    })?;
    if filled > 0 {
        let padded = crate::yenc_simd::crc32_zeros(crc.finalize(), (block_size - filled) as u64);
        bad |= !f.blocks.get(bidx).is_some_and(|b| b.crc_matches(padded));
    }
    if bad {
        return Err(RepairError::VerifyFailed(f.name.clone()));
    }
    Ok(())
}

/// Read `[from, to)` of file `fi` through `io` in buffer-sized chunks.
fn read_span(
    io: &dyn VolumeIo,
    fi: usize,
    from: u64,
    to: u64,
    buf: &mut [u8],
    mut sink: impl FnMut(&[u8]),
) -> Result<(), RepairError> {
    let mut off = from;
    while off < to {
        let take = (to - off).min(buf.len() as u64) as usize;
        io.read(fi, off, &mut buf[..take])?;
        sink(&buf[..take]);
        off += take as u64;
    }
    Ok(())
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
    /// Which outer call site opened this repair, for the retention
    /// admission census. Rides the context for the same reason `donors`
    /// does - it would otherwise be a parameter on every signature
    /// between the entry points and `RetainedCorpus`. `Unknown` by
    /// default, which is an explicit bucket and never folded into a
    /// named one.
    caller: RetentionCaller,
    /// The surveying entry point's door (10 Sep 2026): `contested` and
    /// `declared` are EMPTY here and derived by the inner pass once its
    /// scan completes, under a provisional verify; a contested name then
    /// reruns the pass with the settled context - see
    /// `survey::repair_dir_set_surveyed_as`. Every other door settles
    /// both before the call and leaves this false.
    settle_names_after_scan: bool,
}

// Extra-file adoption - the candidate walk (repair dir plus §293 donor
// directories), the whole-file fast path and the rolling-CRC sliding
// scan - lives in par2repair/adopt.rs, a child module (size gate,
// TODO 106), and fans out across candidates (R2 / N11).
mod adopt;
pub use adopt::{is_recovery_by_name_and_content, scan_members_for_blocks};
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
    /// The verify pass cut the whole-file MD5 short at the first block
    /// it could not prove present (see [`verify_pass1`]), so `intact`
    /// and `present` here rest on the IFSC alone. The shortfall
    /// arbitration in `repair_dir_set_inner` finishes the hash when
    /// that distinction can change the verdict.
    md5_unfinished: bool,
}

mod survey;
pub use survey::{
    AfterSurvey, MemberSurvey, PacketFileScan, PacketSeen, RecoverySeen, RepairForecast,
    ScanReport, SolveKind, SurveyObserver, repair_dir_set_surveyed, repair_dir_set_surveyed_as,
};

// What a repair says WHILE it runs, and how a caller stops it - the
// half of the observer contract that begins where `survey`'s ends.
// Its own module for the same reason `survey` is: one subject, and the
// argument about where a pause may park is long enough to need room.
pub mod control;
pub use control::{PauseGate, ProgressSink, RepairControl, RepairPhase, RepairRoute};
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

/// [`repair_sets_inner`] over a shared catalog: the discovery walk (set
/// order, declared names, contested-name claims) replays occurrences,
/// and each qualifying set's repair consults the same catalog instead
/// of rescanning the corpus.
fn repair_sets_catalog(
    cat: &mut PacketCatalog,
    renamed_fallback: bool,
    caller: RetentionCaller,
    // The control-carrying observer of
    // [`entry::repair_present_sets_controlled_as`], or `None` for every
    // entry of this family that reports nothing. Re-borrowed per set, so
    // its `control()` is asked once per set - which is the set boundary
    // that door's doc rests on.
    mut observe: Option<&mut (dyn SurveyObserver + '_)>,
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
    // `None`: every set this walk found is a ROOT set, and this pass
    // would attempt any of them whose files are on disk, so there is no
    // phantom competitor to narrow away (F6's applicability whitelist is
    // the Nested entry point's, and its argument is at
    // `PacketCatalog::declared_and_contested`).
    let (declared, contested) = cat.declared_and_contested(fold, None);
    let ctx = DirContext {
        contested,
        declared,
        donors: Vec::new(),
        patch_existing: false,
        caller,
        settle_names_after_scan: false,
    };
    let mut out = Vec::new();
    for id in &order {
        let present = names[id]
            .iter()
            .any(|n| crate::disk::join_out_name(dir, &crate::disk::sanitize_out_name(n)).is_file());
        if present {
            let status = repair_dir_set(cat, Some(*id), &ctx, false, observe.as_deref_mut());
            let cancelled = matches!(status, Err(RepairError::Cancelled));
            out.push(SetOutcome {
                set_id: *id,
                names: names[id].clone(),
                status,
            });
            // THE SET EDGE, and the same one `get::latesets` breaks on.
            // The gate is sticky, so every set after this one would come
            // straight back `Cancelled` too - a run of verdicts that
            // reads like N unreadable sets over a directory where the
            // user simply pressed Cancel. Unreachable for the entries
            // that pass no observer: an inert control can never answer
            // this error.
            if cancelled {
                break;
            }
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
                // A SET THAT NAMES NOTHING IS NO SET, and this loop is
                // the one place that has to say so out loud. The name
                // gate above tests `names[id].iter().any(is_file)`, so
                // an id with no FileDesc packet at all never reaches it;
                // here every id in the walk is attempted, and one whose
                // Main packet lists file ids no FileDesc describes comes
                // straight back `Malformed("FileDesc missing for file
                // id ...")` - an ERROR, which fails `every_set_ok` for
                // the whole directory and takes the real set's verdict
                // down with it.
                //
                // That is not hypothetical: it is P10, the `.par2`-named
                // decoy (catalog row `n2-p2-p10-par2-named-decoy`). A
                // post names one file `.par2` whose bytes carry a
                // genuine Main packet, a genuine Creator packet and no
                // FileDesc, the real set rides under tokens, and this
                // fallback is the pass that would otherwise adopt the
                // token payload back under its FileDesc name. Attempting
                // the decoy's set turned that rescue into a failed job.
                //
                // Narrow on purpose: this skips only a set with ZERO
                // declared names. A set with SOME descriptors missing -
                // a genuinely damaged index - still reaches
                // `repair_dir_set` and still reports its error, which is
                // a statement about a set this post really has.
                if names[id].is_empty() {
                    continue;
                }
                let status = repair_dir_set(cat, Some(*id), &ctx, false, observe.as_deref_mut());
                let cancelled = matches!(status, Err(RepairError::Cancelled));
                out.push(SetOutcome {
                    set_id: *id,
                    names: names[id].clone(),
                    status,
                });
                // The set edge again - see the walk above.
                if cancelled {
                    break;
                }
            }
        }
    }
    Ok(out)
}

/// The repair engine behind [`repair_dir`] / [`repair_present_sets`]:
/// `want` pins the recovery set to operate on (packets from other sets
/// are ignored, exactly as foreign-set packets always were); `None`
/// keeps the historical first-seen binding.
///
/// `fresh`: the catalog was listed inside THIS repair call and nothing
/// has consulted it before, so its lazy prefix scan happens here and
/// selected recovery slices need no re-proof - the exact trust the
/// historical scan-then-pread had. A reused catalog (`false`) is a
/// snapshot: the inner pass rechecks file identity/size/mtime first and
/// re-proves each selected recovery packet against its MD5 at pread.
///
/// `observe`, when given, is shown the verify pass before the fold and
/// may call the repair off - see [`repair_dir_set_surveyed`]. It is
/// taken on the FIRST attempt and gone on the retry: the rerun
/// re-verifies from disk, and an observer that prints would print
/// twice.
fn repair_dir_set(
    cat: &mut PacketCatalog,
    want: Option<[u8; 16]>,
    ctx: &DirContext,
    fresh: bool,
    mut observe: Option<&mut (dyn SurveyObserver + '_)>,
) -> Result<RepairStatus, RepairError> {
    // The NTT verify-failure retry is safe to run as a full re-attempt
    // here: the rerun re-verifies every target from disk, so any block
    // the failed attempt patched in place with wrong bytes fails its
    // checksum again, lands back in `missing`, and is rebuilt by the
    // fold; temp-file rebuilds were already cleaned up before the
    // VerifyFailed returned. The retry drops `fresh`: the first attempt
    // wrote to the directory, so the rerun rechecks and re-proves.
    let mut fresh = fresh;
    // The retention admission census's invocation boundary. The NTT
    // retry below is a second ATTEMPT of THIS invocation: it pays for a
    // second corpus under one final verdict, which is failure 4 of
    // `research/PAR2-RETENTION-CALLER-CENSUS-2026-09-08.md` and the
    // reason the two ids are separate.
    let inv = census::Invocation::start(ctx.caller);
    let out = run_with_ntt_fallback(SyndromePath::Auto, |path, probe| {
        let f = std::mem::replace(&mut fresh, false);
        let att = inv.attempt();
        let r = repair_dir_set_inner(cat, want, ctx, f, path, probe, observe.take(), &att);
        // `probe.used` on a `VerifyFailed` is exactly what makes the
        // fallback rerun, so the attempt can say whether it is the
        // verdict without the census guessing from a later record.
        let continuing = probe.used && matches!(r, Err(RepairError::VerifyFailed(_)));
        att.finish(&r, continuing);
        r
    });
    inv.finish(&out);
    out
}

fn repair_dir_set_inner(
    cat: &mut PacketCatalog,
    want: Option<[u8; 16]>,
    ctx: &DirContext,
    fresh: bool,
    path: SyndromePath,
    probe: &mut NttProbe,
    mut observe: Option<&mut (dyn SurveyObserver + '_)>,
    att: &census::Attempt,
) -> Result<RepairStatus, RepairError> {
    let dir = cat.dir().to_path_buf();
    let dir = dir.as_path();
    // Progress out, cancel in, pause parked - asked ONCE, here, so a
    // hook site downstream is a cheap branch on an owned value and not a
    // virtual call through an observer another thread cannot borrow.
    // An inert control is what every caller that passes no observer
    // gets, and every site below short-circuits on it. See
    // `par2repair::control`.
    let control = observe.as_deref().map(|o| o.control()).unwrap_or_default();
    let timing = std::env::var_os("NZBFAST_REPAIR_TIMING").is_some();
    let t0 = std::time::Instant::now();
    // Plan preparation is not a phase of its own - it happens inside
    // `Reconstructor::new_with_path`, mid-way through what `mark` calls
    // "feed+fold+solve" - so it is BRACKETED rather than marked, and the
    // denominator it reports is the whole of this function. Measured
    // 8 Sep 2026 over 65 repairs: 0.11-0.76% of a repair on the shapes
    // real sets have, which is why the plan's own arithmetic is not
    // worth optimising (`forney::PrepSpan`).
    let _prep = forney::PrepSpan::start("repair");
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
            md5_unfinished: false,
        });
        next_slice = next_slice.saturating_add(n_slices);
    }
    let n_inputs = next_slice;
    if n_inputs > MAX_INPUT_SLICES {
        return Err(RepairError::Malformed(format!(
            "{n_inputs} input slices exceeds the PAR2 limit of {MAX_INPUT_SLICES}"
        )));
    }

    // Two distinct FileDescs can sanitize to the SAME path, and sharing a
    // destination is silent data loss. Hoisted whole to
    // `par2repair/dupclaim.rs` (M4-99/M4-80, 31 Aug 2026), which is also
    // where the report that a declared name could not be honoured lives -
    // this file had eight lines free at the time.
    dupclaim::disambiguate_colliding_targets(&mut targets, &ctx.contested, fold, dir);

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
    // The verify pass keeps the blocks it proves (up to the retention
    // budget) so the syndrome pass below folds them from memory rather
    // than reading the set a second time - see `retain`.
    // Recorded BEFORE the pass it pays for, so an attempt that is
    // interrupted - or that returns clean and logs nothing at all - is
    // still visible as a corpus somebody bought.
    let mut retained = att.admit(n_inputs, bs);
    // The hashing loop's own phase. Its `total` is the declared length
    // of every member, which is what the pass reads when nothing is
    // missing; a member that is absent or short costs less and the bar
    // simply arrives early. A cancel raised here unwinds before a byte
    // is written, exactly as an `AfterSurvey::Stop` would.
    control.begin(
        control::RepairPhase::Verify,
        targets.iter().map(|t| t.file.length).sum(),
    );
    if cat.complete() {
        verify_all_targets(&mut targets, bs, retained.as_ref(), &control)?;
    } else {
        let mut verify_res: Result<(), RepairError> = Ok(());
        let mut bg_res: Result<(), RepairError> = Ok(());
        std::thread::scope(|s| {
            let h = s.spawn(|| cat.scan_rest());
            verify_res = verify_all_targets(&mut targets, bs, retained.as_ref(), &control);
            bg_res = h.join().expect("volume scan worker panicked");
        });
        verify_res?;
        bg_res?;
    }
    control.finish(control::RepairPhase::Verify);
    // The surveying door's PROVISIONAL pass settles here (see
    // `DirContext::settle_names_after_scan`): the catalog is complete,
    // so the name sets can be derived. A contested name means the
    // disambiguation above ran without its one input, so this pass is
    // thrown away (retained corpus included, before the rerun admits
    // its own) and rerun with the settled context - the path every
    // other entry point takes, before the observer saw anything or a
    // byte was written. `fresh` stays true: nothing wrote to the
    // directory since the listing.
    let settled: Option<DirContext> = if ctx.settle_names_after_scan {
        debug_assert!(cat.complete(), "the scan above completes the catalog");
        let (declared, contested) = cat.declared_and_contested(fold, None);
        let resolved = DirContext {
            contested,
            declared,
            settle_names_after_scan: false,
            ..ctx.clone()
        };
        if !resolved.contested.is_empty() {
            att.provisional_discarded(resolved.contested.len());
            drop(retained);
            mark("provisional verify discarded (contested names)");
            return repair_dir_set_inner(cat, want, &resolved, true, path, probe, observe, att);
        }
        Some(resolved)
    } else {
        None
    };
    let ctx: &DirContext = settled.as_ref().unwrap_or(ctx);
    replay.feed_files(cat, fed, |_| false);
    let rec_locs = std::mem::take(&mut replay.rec_locs);
    mark("verify targets + volume scan");
    att.verify_done();
    // What the scan validated, for a caller that prints it (see
    // `SurveyObserver::packets_scanned`). Built only when somebody is
    // listening: it is a copy of every packet identity in the set.
    if let Some(observe) = observe.as_mut() {
        observe.packets_scanned(&cat.scan_report());
    }
    // The verify pass is done and NOTHING has been written yet, so this
    // is the one point where an observer can both see the whole set and
    // still refuse the repair. Names are the FileDesc's own, in Main
    // packet order; a caller that prints in its own order matches on
    // them (see [`repair_dir_set_surveyed`]).
    // THE FORECAST, and it is announced to EVERY caller rather than only
    // to the ones that survey.
    //
    // "Repairing" on its own is not information: the same word covers a
    // second and half an hour, and a user watching a long one cannot tell
    // it from a wedged one. This is the last moment before a byte is
    // written and the first at which the answer is known, so it is said
    // here - on the `repair` target, which the daemon's log viewer
    // already shows and every caller already reads - instead of through
    // the observer alone. Twelve call sites reach this function and only
    // parfast passes an observer; a fact this cheap should not be
    // available to one of them.
    //
    // The observer still gets it structurally below, because a caller
    // that wants to ACT on it (defer the job, ask first) needs the fields
    // and not a log line.
    let missing_now: usize = targets
        .iter()
        .map(|t| t.present.iter().filter(|&&ok| !ok).count())
        .sum();
    let forecast = (missing_now > 0).then(|| survey::forecast(&rec_locs, missing_now, bs));
    if let Some(f) = forecast.as_ref() {
        if f.is_long() {
            // THE LAST CLAUSE IS CONDITIONAL, and it was not until
            // 12 Sep 2026. It used to end flatly "and nothing reports
            // progress while it runs", which was true of every caller
            // there was: there was no counter and no token anywhere
            // past the survey handshake. Since `par2repair::control`
            // there is, so the sentence is now about THIS caller - a
            // caller that passed a `RepairControl` is told a phase and
            // a fraction from inside the fold for the whole of that
            // half hour, and telling it otherwise would be the more
            // alarming of the two lies. An uncontrolled caller still
            // hears exactly what it heard before. The clause is
            // KEPT rather than deleted because the thing it warns
            // about is still real for the twelve call sites that pass
            // nothing (CLAUDE.md's comment-gate rule).
            warn!(
                target: "repair",
                "large repair ahead: {} block(s) to rebuild ({} MB), and the recovery set \
                 is itself damaged so there is no fast solve for it - expect roughly {} \
                 minute(s){}",
                f.missing_blocks,
                (f.missing_blocks as u64).saturating_mul(f.block_size as u64) / (1 << 20),
                f.est_secs.unwrap_or(0).div_ceil(60),
                if control.is_active() {
                    ", and it reports its progress as it goes"
                } else {
                    ", and nothing reports progress while it runs"
                }
            );
        } else {
            info!(
                target: "repair",
                "repair ahead: {} block(s) to rebuild, {} solve",
                f.missing_blocks,
                match f.solve {
                    survey::SolveKind::Structured => "structured",
                    survey::SolveKind::Unstructured => "unstructured",
                }
            );
        }
    }
    let observed = observe.is_some();
    let mut stopped = false;
    if let Some(observe) = observe.as_mut() {
        if let Some(f) = forecast.as_ref() {
            observe.forecast(f);
        }
        let members: Vec<MemberSurvey> = targets
            .iter()
            .map(|t| MemberSurvey {
                name: t.file.name.clone(),
                exists: t.exists,
                intact: t.intact,
                blocks_present: t.present.iter().filter(|&&ok| ok).count().min(t.n_slices),
                blocks_total: t.n_slices,
            })
            .collect();
        stopped = observe.after_survey(&members) == AfterSurvey::Stop;
    }
    // The census's survey record, taken here because this is where the
    // observer's answer exists and BEFORE the stop returns `NoDamage`:
    // a stop is not a clean set, and the two are one value below.
    att.survey(&targets, retained.as_ref(), observed, stopped);
    if stopped {
        // The caller's own verdict stands in for the engine's; the
        // surveying entry point turns this into `Ok(None)` and no
        // other entry point can reach it.
        return Ok(RepairStatus::NoDamage);
    }
    // THE FIRST PAUSE POINT, and it is on the driver thread between two
    // units of work - the verify pass is joined and the fold has not
    // started. Every `gate()` in this function is placed to that rule;
    // see `control::PauseGate` for why a worker may never park.
    control.gate()?;
    let mut missing: Vec<usize> = Vec::new();
    for t in &targets {
        for (i, ok) in t.present.iter().enumerate() {
            if !ok {
                missing.push(t.first_slice + i);
            }
        }
    }
    let mut needs_resize: Vec<usize> = targets
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

    // --- arbitration: finish any digest the verify pass cut short ---
    // `verify_pass1` stops the whole-file MD5 at the first failed block
    // (see EARLY STOP there). The one verdict that can turn on the
    // finished digest is a shortfall: a byte-exact file whose IFSC lies
    // about a block counts that block as missing, and if the recovery
    // set cannot cover the count, the honest answer is still "no damage
    // here". So when the missing count already exceeds what the volumes
    // carry, finish those digests now - the cost is the pass this
    // optimisation skipped, paid only on the shortfall path - and let a
    // matching file back out of `missing` before adoption or the verdict
    // ever see it.
    if missing.len() > by_exp.len() && targets.iter().any(|t| t.md5_unfinished) {
        let to_finish: Vec<usize> = targets
            .iter()
            .enumerate()
            .filter(|(_, t)| t.md5_unfinished)
            .map(|(ti, _)| ti)
            .collect();
        let machine = crate::mem::cpu_workers();
        let threads = machine.min(to_finish.len()).max(1);
        let chunk = to_finish.len().div_ceil(threads);
        let mut results: Vec<Option<Result<bool, RepairError>>> =
            (0..to_finish.len()).map(|_| None).collect();
        let targets_ref: &[Target] = &targets;
        std::thread::scope(|s| {
            for (tchunk, rchunk) in to_finish.chunks(chunk).zip(results.chunks_mut(chunk)) {
                s.spawn(move || {
                    for (&ti, r) in tchunk.iter().zip(rchunk) {
                        let t = &targets_ref[ti];
                        *r = Some(md5_matches(&t.path, &t.file));
                    }
                });
            }
        });
        let mut flipped = 0usize;
        for (&ti, r) in to_finish.iter().zip(results) {
            let clean = r.expect("arbitration worker filled every slot")?;
            let t = &mut targets[ti];
            t.md5_unfinished = false;
            if clean {
                // `md5_matches` is true only at exactly `length` bytes.
                t.intact = true;
                t.present = vec![true; t.n_slices];
                t.resume = None;
                flipped += 1;
            }
        }
        att.arbitrated(flipped);
        if flipped > 0 {
            info!(
                target: "repair",
                "arbitration: {flipped} member(s) the IFSC called damaged hash byte-exact by \
                 FileDesc and are not missing anything"
            );
            missing = targets
                .iter()
                .flat_map(|t| {
                    t.present
                        .iter()
                        .enumerate()
                        .filter(|&(_, &ok)| !ok)
                        .map(move |(i, _)| t.first_slice + i)
                })
                .collect();
            needs_resize.retain(|&ti| !targets[ti].intact);
            if missing.is_empty() && needs_resize.is_empty() {
                return Ok(RepairStatus::NoDamage);
            }
        }
    }

    // --- extra-file adoption ---
    // Only when a file failed identification outright (missing, renamed,
    // shifted - nothing on disk verifies) or the damage exceeds the
    // recovery slices on disk. The scan reads whole candidate files, so
    // it must never run on the everyday a-few-blocks-bad repair.
    let any_unidentified = targets
        .iter()
        .any(|t| t.n_slices > 0 && !(t.exists && (t.intact || t.present.iter().any(|&p| p))));
    let (mut cands, donor_from, mut adopted) = if adopt::disabled_for_screen() {
        // The deterministic trap screen: no writer of `adopted` runs,
        // so a repair here can only come out of the recovery set. All
        // THREE writers are gated, not just this one - see
        // `adopt::disabled_for_screen`.
        (Vec::new(), 0, HashMap::new())
    } else if !missing.is_empty() && (any_unidentified || missing.len() > by_exp.len()) {
        let mut excluded = sniffed.clone();
        if let Some(observer) = observe.as_ref() {
            excluded.extend(observer.adoption_exclusions().iter().cloned());
        }
        adopt::adopt_blocks(dir, &ctx.donors, &targets, &missing, bs, &excluded)?
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
    if !adopt::disabled_for_screen() {
        adopt::harvest_in_set(&targets, &missing, bs, &mut cands, &mut adopted)?;
    }
    missing.retain(|g| !adopted.contains_key(g));

    // Last-resort escalation: still more damage than recovery on disk -
    // scan identified damaged targets too, which the normal pass skips.
    // A mid-file insertion leaves a file half-verified with the rest of
    // its content byte-shifted inside itself; only a scan of that file
    // can find it. Any target whose bytes end up serving as an adoption
    // source is later rebuilt via temp+rename, never patched in place.
    if !missing.is_empty() && missing.len() > by_exp.len() && !adopt::disabled_for_screen() {
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
    // DONOR PARITY (claim `donor-parity-catalog-harvest`, 1 Sep 2026):
    // SHORT OF PARITY, AND A DONOR MAY HOLD MORE OF OURS. A donor
    // directory's own recovery volumes are the last thing on disk this
    // engine has never looked at: the adoption walk excludes them (and
    // correctly - it collects files that might BE a member's bytes, and
    // a recovery volume is not a payload member), so a predecessor's
    // par2 has always been dead weight here.
    //
    // It is only worth reading when the id matches, and
    // `catalog::harvest_donor_recovery` carries that argument and the
    // honest size of the prize. Gated on the SHORTFALL and placed
    // HERE - after adoption, where `needed` is final - deliberately:
    // every decision above it (whether to run the adoption scan, the
    // escalation, what `RepairReport` says about donors) reads
    // `by_exp`, and none of them moves. The only outcome that changes
    // is a repair that used to report Unrepairable and can now finish.
    let donor_vols = match replay.set_id {
        Some(id) if needed > by_exp.len() && !ctx.donors.is_empty() => {
            catalog::harvest_donor_recovery(&ctx.donors, dir, &id, bs, &mut by_exp)
        }
        _ => Vec::new(),
    };
    if !donor_vols.is_empty() {
        info!(
            target: "repair",
            "donor parity: {} recovery volume file(s) carry this set's id, \
             {} slice(s) available after the fold",
            donor_vols.len(),
            by_exp.len()
        );
    }
    let pool = SlicePool {
        cat,
        donor: &donor_vols,
    };
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
    // MEMORY SETS THE PASS COUNT, NEVER A VERDICT. `check_repair_dim`
    // used to refuse here when the solve's window was over budget, which
    // repaired NOTHING on a set that was perfectly good; the plan below
    // cuts the solve along the block's byte axis instead and sweeps the
    // payload once per slab. `reconstruct::plan_solve` carries the
    // argument, the tiers and the incident.
    //
    // PRICED AFTER SELECTION (TODO 348 C): whether the selected exponents
    // have structure decides the arm, and the arm decides the window - an
    // unstructured set is Gauss-Jordan's two buffers and matrix, never the
    // joint arm's one. `reconstruct::solve_buffers` carries the incident.
    let structured = reconstruct::selection_structured(
        n_inputs,
        &missing,
        &catalog::selected_exponents(&by_exp, needed),
    );
    let mut solve = if shortfall.is_none() && needed > 0 {
        reconstruct::plan_solve_for(needed, bs, structured)
    } else {
        reconstruct::plan_solve_for(0, bs, true)
    };
    // Only the FIRST slab's bytes of each recovery slice: at one slab
    // that is the whole slice and this is the pre-slab load exactly.
    let recovery = if shortfall.is_none() && needed > 0 {
        let mut loaded = load_selected_recovery_span(
            &pool,
            &mut by_exp,
            needed,
            bs,
            solve.slabs.range(0, bs),
            !fresh,
        )?;
        // The load re-proves each slice and RE-SELECTS past one that no
        // longer proves, so the selection planned above can lose its
        // structure here. Priced again at its real arm, and loaded again
        // when that moves the slab.
        if let Some(rec) = &loaded
            && structured
        {
            let exps: Vec<u32> = rec.iter().map(|(e, _)| *e).collect();
            let replanned = reconstruct::plan_solve_for(
                needed,
                bs,
                reconstruct::selection_structured(n_inputs, &missing, &exps),
            );
            if replanned != solve {
                solve = replanned;
                loaded = load_selected_recovery_span(
                    &pool,
                    &mut by_exp,
                    needed,
                    bs,
                    solve.slabs.range(0, bs),
                    !fresh,
                )?;
            }
        }
        match loaded {
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
    if solve.slabs.slabs > 1 {
        info!(
            "solve window over budget: {needed} block(s) at {bs} B in {} slab(s) of {} B,              output {:?} - the payload is swept once per slab",
            solve.slabs.slabs, solve.slabs.width, solve.staging
        );
    }
    let solve = solve;
    mark("load recovery");

    // --- syndrome pass: stream every present slice once ---
    let blocks_rebuilt = missing.len();
    let rebuilt: RebuiltStore = if blocks_rebuilt > 0 && shortfall.is_none() {
        let plan = solve.slabs;
        // Where the output goes. `Whole` takes the solve's own buffers
        // by move and is the pre-slab driver exactly.
        let mut store = match solve.staging {
            reconstruct::Staging::Whole => RebuiltStore::Whole(Vec::new()),
            reconstruct::Staging::Assembled => {
                RebuiltStore::Assembled(vec![vec![0u8; bs]; blocks_rebuilt])
            }
            reconstruct::Staging::Spill => RebuiltStore::spill(dir, blocks_rebuilt, bs as u64)?,
        };
        // The exponents slab 0 selected. Every later slab MUST solve
        // against the same ones: the recovery matrix is a function of
        // this set, so a slab that silently re-selected (a slice going
        // bad between sweeps drops it from the pool and `by_exp` picks
        // again) would solve a DIFFERENT system and write bytes that
        // look repaired and are not. Re-selection is refused below
        // rather than followed.
        let pinned: Vec<u32> = recovery.iter().map(|(e, _)| *e).collect();
        let mut recovery = recovery;
        for si in 0..plan.slabs {
            // WHICH SWEEP THIS IS, before anything in it reports.
            // Fold and Solve are entered once per slab, and a caller
            // that weighs the four phases into ONE bar cannot infer the
            // COUNT from the re-entries - it has to reserve the room
            // for sweeps 2..N before sweep 1 spends it. Said here, on
            // the driver thread, rather than left to be guessed:
            // `control::ProgressSink::slab` carries the argument and
            // the incident.
            control.slab(si, plan.slabs);
            // A SLAB BOUNDARY IS A UNIT BOUNDARY: the previous slab's
            // scope has joined and the next one's has not been opened,
            // so this is where a slabbed repair honours a pause. See
            // `control::PauseGate` - a worker may never park, so on a
            // one-slab repair the pause lands at the fold/solve
            // boundary instead and the capability says so.
            control.gate()?;
            let span = plan.range(si, bs);
            let (c0, w) = (span.start, span.len());
            // THE FOLD'S OWN PHASE, and the one this whole module was
            // built for: on an ordinary repair the feed is most of the
            // wall, and until 12 Sep 2026 a progress bar stopped dead
            // here for all of it.
            //
            // SIZED HERE, before the retained corpus is taken, and over
            // EVERY present block of the slab rather than over the work
            // list below. The verify pass keeps what it proved (see
            // `retain`), so on a set that fitted the retention budget
            // the work list is EMPTY and the whole fold arrives from
            // memory - a total taken from `work` would read 0 there,
            // which is a bar that is full before it starts. Adopted
            // blocks are added because they are fed too.
            control.begin(
                control::RepairPhase::Fold,
                targets
                    .iter()
                    .filter(|t| t.exists)
                    .flat_map(|t| {
                        t.present
                            .iter()
                            .enumerate()
                            .filter(|&(_, &p)| p)
                            .map(|(i, _)| {
                                let off = i as u64 * block_size;
                                let whole = (t.file.length - off).min(block_size) as usize;
                                whole.saturating_sub(c0).min(w) as u64
                            })
                    })
                    .sum::<u64>()
                    + adopted.len() as u64 * w as u64,
            );
            if si > 0 {
                recovery =
                    load_selected_recovery_span(&pool, &mut by_exp, needed, bs, span, !fresh)?
                        .ok_or_else(|| {
                            RepairError::Malformed(format!(
                                "recovery slices became unreadable between slab {si} and the one \
                         before it - the set changed under a repair already in progress"
                            ))
                        })?;
                if recovery.iter().map(|(e, _)| *e).ne(pinned.iter().copied()) {
                    return Err(RepairError::Malformed(format!(
                        "recovery selection changed at slab {si} of {} - a slabbed solve \
                         must use one recovery set throughout, and re-selecting mid-repair \
                         would rebuild against a different system",
                        plan.slabs
                    )));
                }
            }
            // The recovery payloads are widened into the syndrome rows
            // by the constructor and are dead weight afterwards, so they
            // go before the output is allocated - the same reason the
            // pre-slab driver dropped them here.
            let feed_from = std::mem::take(&mut recovery);
            let max_exp = feed_from.last().map_or(0, |&(e, _)| e);
            let mut rec = if reconstruct::in_place_output() {
                // A window priced at one buffer cannot afford the
                // borrowed door's two (`new_controlled_owned`).
                Reconstructor::new_controlled_owned(
                    w, n_inputs, &missing, feed_from, path, &control,
                )?
            } else {
                let rec = Reconstructor::new_controlled(
                    w, n_inputs, &missing, &feed_from, path, &control,
                )?;
                drop(feed_from);
                rec
            };
            if si == 0 {
                probe.selected = rec.ntt_selected();
                probe.m = missing.len();
                probe.block_size = bs;
                probe.max_exp = max_exp;
                probe.context = dir.display().to_string();
            }
            // What the verify pass held goes to the fold worker first,
            // from memory; only the present blocks it did not hold are
            // read below. A SLABBED solve cannot use it - those batches
            // are whole blocks and this pass wants one slab of each - so
            // it is dropped instead, which is also the right thing to do
            // with `m x block_size` of cache on the one path that is
            // short of memory by definition.
            let held: Vec<bool> = match retained.take() {
                Some(r) if plan.slabs == 1 => {
                    let (batches, held) = r.take();
                    let (n, bytes) = batches.iter().fold((0usize, 0usize), |(n, b), batch| {
                        (n + batch.slices.len(), b + batch.len())
                    });
                    if std::env::var_os("NZBFAST_REPAIR_TIMING").is_some() {
                        info!(
                            target: "repair-timing",
                            "retained from the verify pass: {n} block(s), {:.1} MB",
                            bytes as f64 / 1e6
                        );
                    }
                    // The line above is CONSUMPTION and is gated on a timing
                    // env var, which is failure 2 of the caller census. This
                    // is the same fact told to the census, which already
                    // recorded the admission that paid for it.
                    att.consumed(n, bytes);
                    for b in batches {
                        // Retained blocks are fold input that never
                        // touched the disk on this pass, and they are
                        // counted in the phase's total above - a bar
                        // that ignored them would sit at zero through
                        // the whole of a set that fitted the retention
                        // budget, which is most small repairs.
                        control.step(control::RepairPhase::Fold, b.len() as u64);
                        rec.send_batch(b);
                    }
                    // Handing over is instant; the FOLDING of what was
                    // just handed over is not, and it happens on the
                    // syndrome worker - which polls the same cancel and
                    // discards instead of folding (see
                    // `Reconstructor::new_controlled`). This check is
                    // what stops the hand-over itself on a corpus large
                    // enough to be several batches.
                    if control.cancelled() {
                        return Err(RepairError::Cancelled);
                    }
                    held
                }
                _ => Vec::new(),
            };
            let held = &held;
            // Present-slice reads fan out exactly as in `repair_mapped`
            // (M2c.2): contiguous chunks of the flattened work list per
            // reader (sequential read patterns), each with its own Feeder
            // into the one fold worker. This loop used to run single-file,
            // single-threaded - the only serial data pass left in the
            // disk repair path.
            //
            // Shifted into the slab and clipped to it: a block whose file
            // ends before this slab starts contributes nothing and is
            // dropped here rather than read as a zero-length request.
            let work: Vec<(usize, usize, u64, usize)> = targets
                .iter()
                .enumerate()
                .filter(|(_, t)| t.exists)
                .flat_map(|(ti, t)| {
                    t.present
                        .iter()
                        .enumerate()
                        .filter(move |&(i, &p)| {
                            p && !held.get(t.first_slice + i).copied().unwrap_or(false)
                        })
                        .filter_map(move |(i, _)| {
                            let off = i as u64 * block_size;
                            let whole = (t.file.length - off).min(block_size) as usize;
                            let take = whole.saturating_sub(c0).min(w);
                            (take > 0).then_some((t.first_slice + i, ti, off + c0 as u64, take))
                        })
                })
                .collect();
            if !work.is_empty() {
                let readers = feed_readers().min(work.len()).max(1);
                let per_reader_batch = rec.per_reader_batch(readers);
                let chunk = work.len().div_ceil(readers);
                let targets_ref = &targets;
                // By reference into every reader: `RepairControl` is
                // clonable, but a clone per reader is an Arc bump for
                // nothing - the scope cannot outlive this frame.
                let control = &control;
                let mut read_results: Vec<Result<(), RepairError>> =
                    (0..readers).map(|_| Ok(())).collect();
                std::thread::scope(|s| {
                    for (wchunk, res) in work.chunks(chunk).zip(read_results.iter_mut()) {
                        let mut feeder = rec.feeder(per_reader_batch);
                        s.spawn(move || {
                            *res = (|| {
                                let mut open: Option<(usize, File)> = None;
                                for &(g, ti, off, take) in wchunk {
                                    // PER BLOCK, which is the batch this
                                    // loop deals in - one relaxed load
                                    // and one relaxed add against a
                                    // block-sized read. A reader that
                                    // sees the cancel stops feeding; the
                                    // fold worker then drains what it
                                    // has and `finish` returns blocks
                                    // nobody will write, because the
                                    // check before the patch refuses
                                    // first.
                                    //
                                    // IT PARKS HERE TOO, which is the
                                    // one place in the fold a pause can
                                    // be honoured: this reader owns a
                                    // static, disjoint chunk of `work`,
                                    // so no other thread is waiting for
                                    // the block it holds; its Feeder is
                                    // its own; it holds no lock; and the
                                    // fold worker keeps draining while
                                    // it sleeps. `control::PauseGate`
                                    // carries the rule and why the
                                    // solve's shared unit queue is
                                    // excluded from it.
                                    control.gate_if_held()?;
                                    if open.as_ref().is_none_or(|(oi, _)| *oi != ti) {
                                        open = Some((ti, File::open(&targets_ref[ti].path)?));
                                    }
                                    let f = &open.as_ref().expect("just opened").1;
                                    feeder.feed_with(g, take, |buf| {
                                        crate::disk::read_exact_at(f, buf, off)
                                    })?;
                                    control.step(control::RepairPhase::Fold, take as u64);
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
                    // The slab's bytes of an adopted block, on the same
                    // clip as a present one.
                    let from = c0.min(data.len());
                    let to = (c0 + w).min(data.len());
                    rec.feed(g, &data[from..to]);
                    control.step(control::RepairPhase::Fold, (to - from) as u64);
                }
            }
            control.finish(control::RepairPhase::Fold);
            // BEFORE THE SOLVE, which is the other multi-minute stretch
            // and the one a cancelled repair must not sit through. On a
            // set whose whole corpus was retained the fold is one
            // hand-over and this is where the cancel lands; on any set
            // big enough to read from disk the readers have already
            // carried it out.
            control.check()?;
            let (r, syn_report) = rec.finish_owned_reported();
            if si == 0 {
                probe.used = syn_report.ntt_used;
                probe.n_present = syn_report.n_present;
            }
            match &mut store {
                // One slab: the solve's buffers ARE the output.
                RebuiltStore::Whole(v) => *v = r,
                store => store.put_slab(&r, c0, w)?,
            }
            mark("feed+fold+solve");
        }
        store
    } else {
        RebuiltStore::Whole(Vec::new())
    };

    // --- patch ---
    // Every write to a target is below this line; the observer's
    // `before_write` contract (see [`SurveyObserver`]) is that nothing
    // above it touched one. Adoption and the feed only read.
    //
    // THE LAST PAUSE POINT, and the cancel that matters most. A cancel
    // raised during the fold or the solve unwinds here, before
    // `before_write` and before any destination is opened, so the
    // directory is exactly as the survey found it - and a solve that
    // was abandoned mid-fold produced blocks that are NOT a repair,
    // which is why this check may never be moved below the patch.
    control.gate()?;
    if let Some(observe) = observe.as_mut() {
        observe.before_write();
    }
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
    // The patch runs in three passes. Pass one, serial and in `damaged`
    // order, decides in-place versus temp and OPENS every destination -
    // temp names are probed with `create_new`, so their allocation has to
    // stay ordered. Pass two writes every target's blocks in parallel:
    // targets are independent files, and the write loop was the last
    // serial data pass in this driver - 1,500 rebuilt 64 KiB blocks
    // spread over 21 files took 101 ms one `pwrite` at a time on an
    // otherwise saturated 32-core repair, a tenth of the whole heavy
    // leg, where the same writes fanned out per file take a few ms.
    // Pass three folds the outcomes back into `checks` / `renames` /
    // `unpublished` in the original order, so the verify and rename
    // that follow see exactly the sequence they always did.
    //
    // What moves: an in-place write error used to abort before later
    // targets were touched; now every target's write has run by the time
    // it is reported. That changes nothing a caller can observe - an
    // in-place patch lands rebuilt bytes onto blocks the verify pass
    // already found damaged, and a failed repair is reported as failed
    // either way - and temps are cleaned up on the same error paths.
    struct PatchJob {
        ti: usize,
        file: File,
        tmp: Option<PathBuf>,
    }
    // Shared by every writer thread. Adopted blocks come off the PINNED
    // donor handles (`pin_donor_sources`) through one mutex - adoption
    // is a handful of blocks per repair, and reopening donors by path
    // per thread would hand back the identity guarantee pinning bought.
    let cand_reader = std::sync::Mutex::new(cand_reader);
    let write_blocks = |f: &File, t: &Target, copy_present: bool| -> Result<(), RepairError> {
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
            // PER BLOCK, and this is the cancel with the consequences -
            // see `RepairError::Cancelled`, which states exactly what a
            // cancelled patch leaves behind. The guarantee that makes it
            // safe lives in this loop: a MISSING block is the only thing
            // written in place (`copy_present` is false for every
            // in-place job, so the `present` arm above is a temp-file
            // arm only), so a half-written in-place patch has strictly
            // more correct blocks than it started with and strictly none
            // fewer. Temps are removed by `cleanup` and nothing is
            // renamed in, so a cancel is re-runnable either way.
            //
            // It parks here too: a patch worker owns a static, disjoint
            // chunk of the job list and holds only its own destination
            // handle. A paused repair therefore stops with a target
            // part-written, which is the same state a cancel leaves and
            // the same state a re-run recovers from.
            control.gate_if_held()?;
            if present {
                if let Some(src) = &src {
                    let mut v = vec![0u8; take];
                    crate::disk::read_exact_at(src, &mut v, off)?;
                    crate::disk::write_all_at(f, &v, off)?;
                    control.step(control::RepairPhase::Write, take as u64);
                }
                continue;
            }
            if let Some(&mi) = rebuilt_of.get(&g) {
                rebuilt.write_block_to(mi, take, f, off)?;
                control.step(control::RepairPhase::Write, take as u64);
            } else if let Some(&s) = adopted.get(&g) {
                let data = cand_reader.lock_ok().read(s, take)?;
                crate::disk::write_all_at(f, &data, off)?;
                control.step(control::RepairPhase::Write, take as u64);
            }
        }
        Ok(())
    };
    let mut jobs: Vec<PatchJob> = Vec::new();
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
        if !via_temp {
            let f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&t.path)?;
            jobs.push(PatchJob {
                ti,
                file: f,
                tmp: None,
            });
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
            // Registered before its bytes land so an error on ANY job
            // cleans it up; a failed write drops it from the list again.
            renames.push((tmp.clone(), ti));
            jobs.push(PatchJob {
                ti,
                file: tmp_file,
                tmp: Some(tmp),
            });
        }
    }
    // The patch's THREE passes are marked separately, because on the
    // single-large-member shape the phase as a whole is the largest
    // fixed cost on x86 and a single `patch` mark cannot say which pass
    // holds it: 3.07 s of a 5.94 s one-block repair on a Core Ultra 9
    // against 9 ms on an M5 Max, and LOWER at m=100 than at m=1, which
    // is the shape a per-block write cannot make
    // (research/PARFAST-SINGLE-MEMBER-REPAIR-FIXED-COST-2026-09-16.md).
    mark("patch: destinations opened");
    // Pass two: every target's blocks, across threads.
    // Sized from the JOBS and not from the set: a temp-staged member is
    // rewritten whole and an in-place one only where it was damaged, so
    // the two cost wildly different amounts and a bar over declared
    // lengths would crawl through one and jump through the other.
    control.begin(
        control::RepairPhase::Write,
        jobs.iter()
            .map(|j| {
                let t = &targets[j.ti];
                if j.tmp.is_some() {
                    t.file.length
                } else {
                    t.present.iter().filter(|&&p| !p).count() as u64 * block_size
                }
            })
            .sum(),
    );
    let write_results: Vec<Result<(), RepairError>> = if jobs.is_empty() {
        Vec::new()
    } else {
        let threads = crate::mem::cpu_workers().min(jobs.len()).max(1);
        let chunk = jobs.len().div_ceil(threads);
        let mut results: Vec<Option<Result<(), RepairError>>> =
            (0..jobs.len()).map(|_| None).collect();
        let targets_ref = &targets;
        let write_blocks = &write_blocks;
        std::thread::scope(|s| {
            for (jchunk, rchunk) in jobs.chunks(chunk).zip(results.chunks_mut(chunk)) {
                s.spawn(move || {
                    for (job, r) in jchunk.iter().zip(rchunk) {
                        let t = &targets_ref[job.ti];
                        *r = Some(write_blocks(&job.file, t, job.tmp.is_some()));
                    }
                });
            }
        });
        results
            .into_iter()
            .map(|r| r.expect("patch worker filled every slot"))
            .collect()
    };
    mark("patch: blocks written");
    // Pass three: outcomes in `damaged` order. Handles close here, before
    // anything re-reads or renames what they wrote.
    for (job, res) in jobs.into_iter().zip(write_results) {
        let t = &targets[job.ti];
        match (res, job.tmp) {
            (Ok(()), None) => checks.push((t.path.clone(), job.ti, true)),
            (Ok(()), Some(tmp)) => checks.push((tmp, job.ti, false)),
            (Err(e), None) => {
                cleanup(&renames, None);
                return Err(e);
            }
            (Err(e), Some(tmp)) => {
                let _ = std::fs::remove_file(&tmp);
                renames.retain(|(p, _)| *p != tmp);
                status::publish_failed(shortfall, &t.file.name, e)
                    .inspect_err(|_| cleanup(&renames, None))?;
                unpublished.push(job.ti);
            }
        }
    }
    control.finish(control::RepairPhase::Write);
    mark("patch");
    // Whole-file MD5 for everything written - files are independent, so
    // verify across threads. Under the fast-check tier (see
    // `verify_pass1_tiered`) the proof is per block instead: the scan
    // ran no chain, so there is no `resume` state, and a full reread
    // chain here would be the whole wall of a single large member.
    let fast_check = crate::par2::fast_check_enabled();
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
                        *r = Some(if fast_check {
                            blocks_match_fast(path, &t.file, bs)
                        } else {
                            match &t.resume {
                                Some(res) if *in_place => md5_matches_resumed(path, &t.file, res),
                                _ => md5_matches(path, &t.file),
                            }
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

// The verify half of the repair - the block-hash pass, the pass-1
// verdict and its resume snapshot, and the final whole-file proof.
// Its own file since 10 Sep 2026: this file stood at 3,999 of the size
// gate's 4,000-line ceiling and the next edit would have redded it.
mod verify;
// A glob rather than a list, and `pub use` rather than `use`, so the
// module surface is exactly what it was before the lift: this is a
// contiguous 1,082-line block out of this file, every name in it kept
// the unqualified spelling its call sites already used (here, in the
// sibling modules, and in `unit_tests.rs`), and re-exporting at each
// item's own visibility keeps the `pub` ones public and the
// `pub(super)` ones reachable from this module and its children.
pub use verify::*;

// Wave-4 rows M4-99/M4-80: the colliding-destination claim, and the
// report that says which declared name it could not honour. Its own
// file for the size gate.
mod dupclaim;

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
