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
pub use linalg::{bench_backsub, bench_fold, bench_invert};

// The Forney-style back-substitution and its gate: the LAST phase of a
// repair, and its own subject, the way `linalg` is the fold's and
// `fastpar` is the syndrome dispatch's.
pub(crate) mod forney;
use forney::ForneyPlan;

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
    /// Worker returns (syndromes, retained batches) - retained is empty
    /// on the streaming path, and holds the resident source corpus when
    /// the experimental NTT dispatch selected retention.
    worker: Option<std::thread::JoinHandle<(Vec<Vec<u16>>, Vec<FeedBatch>, usize, bool)>>,
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
// The creator reads the same shape gates and stripe geometry the repair
// dispatcher prices, so the two engines admit the NTT on one rule.
pub(crate) use fastpar::{
    NTT_MIN_MISSING, NTT_MIN_PRESENT, ntt_budget_env, ntt_stripe_geometry, ntt_worker_arenas,
};
// Pinned by `inline_tests` (a descendant, so `use super::*` names them)
// and by nothing else in this module - importing them unconditionally
// would be an unused import at `-D warnings` in every non-test build.
#[cfg(test)]
use fastpar::{FAST_PAR_TRIPPED, ntt_default_budget, ntt_gates_pass};

// `impl Reconstructor` lives in par2repair/reconstruct.rs (TODO 106
// size-gate split).
mod catalog;
mod nested;
mod reconstruct;

pub use catalog::PacketCatalog;
use catalog::{Crit, RecLoc, SetReplay, SlicePool, load_selected_recovery};
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
    let policy = SelfProvePolicy {
        full_verify,
        prefixes,
    };
    run_with_ntt_fallback(SyndromePath::Auto, |path, probe| {
        let recovery = catalog::load_mapped_recovery(cat, set_id, files, block_size)?;
        repair_mapped_inner(files, block_size, &recovery, io, policy, path, probe)
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
        repair_mapped_inner(files, block_size, recovery, io, policy, path, probe)
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
        repair_mapped_inner(files, block_size, recovery, io, policy, path, probe)
    })
}

fn repair_mapped_inner(
    files: &[(Par2File, Vec<bool>)],
    block_size: usize,
    recovery: &[(u32, Vec<u8>)],
    io: &dyn VolumeIo,
    policy: SelfProvePolicy<'_>,
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
                        for &(g, fi, off, take) in wchunk {
                            feeder.feed_with(g, take, |buf| io.read(fi, off, buf))?;
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

    // Write rebuilt blocks back, tails trimmed - across threads, the same
    // fan-out the disk driver's patch uses: `VolumeIo` is `Sync`, each
    // block is one positional write to its own offset, and serially this
    // was the last data pass in the call still running on one core.
    if !missing.is_empty() {
        let threads = crate::mem::cpu_workers().min(missing.len()).max(1);
        let chunk = missing.len().div_ceil(threads);
        let mut results: Vec<std::io::Result<()>> = (0..threads).map(|_| Ok(())).collect();
        let rebuilt = &rebuilt;
        let owner = &owner;
        let first_slice = &first_slice;
        std::thread::scope(|s| {
            for (wi, (mchunk, res)) in missing.chunks(chunk).zip(results.iter_mut()).enumerate() {
                s.spawn(move || {
                    *res = (|| {
                        for (k, &g) in mchunk.iter().enumerate() {
                            let mi = wi * chunk + k;
                            let fi = owner[g];
                            let (f, _) = &files[fi];
                            let off = (g - first_slice[fi]) as u64 * bs;
                            let take = (f.length - off).min(bs) as usize;
                            io.write(fi, off, &rebuilt[mi][..take])?;
                        }
                        Ok(())
                    })();
                });
            }
        });
        for r in results {
            r?;
        }
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
    self_prove_set(files, block_size, io, &rebuilt_files, &first_hole, policy)?;
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
                    *r = Some(one);
                }
            });
        }
    });
    for r in results {
        r.expect("verify worker filled every slot")?;
    }
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
    /// The verify pass cut the whole-file MD5 short at the first block
    /// it could not prove present (see [`verify_pass1`]), so `intact`
    /// and `present` here rest on the IFSC alone. The shortfall
    /// arbitration in `repair_dir_set_inner` finishes the hash when
    /// that distinction can change the verdict.
    md5_unfinished: bool,
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
    repair_dir_set(&mut cat, None, &DirContext::default(), true, None)
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
    repair_dir_set(&mut cat, None, &ctx, true, None)
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
    repair_dir_set_with_donors_scoped(dir, set_id, donors, PacketScope::Flat, false, None)
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
///
/// `applicable` is the OTHER half of that answer, and only a caller
/// applying sets in turn can give it: the ids it will actually attempt.
/// A Nested walk discovers sets a caller may permanently refuse (an
/// extracted subdirectory carrying its own recovery set, which
/// `get::latesets`' `published_here` will not let run), and a set that
/// can never land a file must not disambiguate a running set's target
/// away from its declared name - F6, 1 Sep 2026. `None` keeps the
/// directory-wide reading; see `PacketCatalog::declared_and_contested`
/// for why only the CONTESTED half narrows.
pub fn repair_dir_set_with_donors_scoped(
    dir: &Path,
    set_id: &[u8; 16],
    donors: &[PathBuf],
    scope: PacketScope,
    patch_existing: bool,
    applicable: Option<&HashSet<[u8; 16]>>,
) -> Result<RepairStatus, RepairError> {
    let mut cat = PacketCatalog::build_scoped(dir, scope)?;
    let (declared, contested) =
        cat.declared_and_contested(crate::disk::case_insensitive_dir(dir), applicable);
    let ctx = DirContext {
        contested,
        declared,
        donors: donors.to_vec(),
        patch_existing,
    };
    repair_dir_set(&mut cat, Some(*set_id), &ctx, true, None)
}

/// What the verify pass found about ONE member, before a byte is
/// repaired - the half of a repair a command-line tool has to PRINT.
///
/// Every field is the pass's own finding, not a re-derivation: `intact`
/// is the FileDesc whole-file MD5 over an exactly-sized file, and
/// `blocks_present` counts the IFSC block CRC32s that proved out. See
/// [`repair_dir_set_surveyed`] for why this exists at all.
#[derive(Clone, Debug)]
pub struct MemberSurvey {
    /// The FileDesc name, exactly as the packet spells it - NOT the
    /// on-disk path, which sanitizing and collision disambiguation may
    /// both have moved.
    pub name: String,
    /// Something is at the member's destination path.
    pub exists: bool,
    /// The whole-file FileDesc MD5 matched AND the length is exact.
    /// `verify_pass1`'s verdict verbatim, so false under its EARLY STOP
    /// is the tri-state's "not proven" - see
    /// [`repair_dir_set_surveyed`] for why an observer takes it as
    /// damaged rather than deciding it.
    pub intact: bool,
    /// Blocks the pass proved present, at most `blocks_total`.
    pub blocks_present: usize,
    /// Blocks the set declares for this member.
    pub blocks_total: usize,
}

/// What an observer wants done once it has seen the survey.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AfterSurvey {
    /// Go on and repair, exactly as the unobserved entry points do.
    Repair,
    /// Stop here. Nothing has been written yet - the verify pass and
    /// the packet walk only READ - so the directory is untouched.
    Stop,
}

/// [`repair_dir_set_with_donors`] that shows its caller the verify pass
/// and lets the caller call the repair off.
///
/// THE PROBLEM THIS SOLVES, because it is not obvious from the
/// signature. A par2cmdline-compatible CLI has to print an `Opening:`
/// and a `Target:` line for every member BEFORE it decides anything,
/// and those lines are a per-member verify verdict. Getting them out of
/// [`repair_dir_set_with_donors`] was impossible, so `parfast` surveyed
/// the whole set itself and then called that entry, which surveys the
/// whole set AGAIN: two complete passes over every payload byte on
/// every damaged repair. Measured on the 1 GiB / 21-member rig corpus,
/// retired instructions, 4 Sep 2026: the duplicate pass was 26.0G of
/// the 3-block leg's 40.4G and 29.2G of the 101-block leg's 106.3G,
/// against the engine harness's 14.4G and 77.0G for the same work.
///
/// The observer runs after the verify pass and before the fold, so it
/// sees what the repair is about to act on and may still refuse it
/// ([`AfterSurvey::Stop`] - the answer for "the reference prints
/// `Repair is not possible.` here", and for a rename-only run).
/// `Ok(None)` is that refusal; `Ok(Some(_))` is an ordinary verdict.
///
/// It fires ONCE. The NTT verify-failure retry re-runs the whole
/// attempt, verify pass included, and a caller that PRINTS would print
/// its table twice.
///
/// `intact` in the report is `verify_pass1`'s, EARLY STOP included, so
/// it is the tri-state's withheld-positive and not a decided verdict -
/// see `Pass1Out::md5_unfinished`. That is deliberate and it is the
/// same reading `parfast`'s own `verify::survey` settled on in
/// `89b2f4c0a`: on the M4-69 shape (a byte-exact member whose IFSC
/// contradicts its own FileDesc MD5) both call it damaged, the repair
/// rebuilds the disputed block to the bytes it already had, and the
/// file comes out identical. An observer that decided it here instead
/// would make one tool print two answers for one set.
pub fn repair_dir_set_surveyed(
    dir: &Path,
    set_id: &[u8; 16],
    donors: &[PathBuf],
    observe: &mut dyn FnMut(&[MemberSurvey]) -> AfterSurvey,
) -> Result<Option<RepairStatus>, RepairError> {
    let mut cat = PacketCatalog::build_scoped(dir, PacketScope::Flat)?;
    let (declared, contested) =
        cat.declared_and_contested(crate::disk::case_insensitive_dir(dir), None);
    let ctx = DirContext {
        contested,
        declared,
        donors: donors.to_vec(),
        patch_existing: false,
    };
    // The caller's answer, remembered here rather than smuggled through
    // `RepairStatus`: a new variant would have to be handled by every
    // match on it in the workspace, to describe a state only this entry
    // point can reach.
    let mut stopped = false;
    // Scoped so `watch`'s borrow of `stopped` ends before it is read -
    // the block IS the drop, and an explicit `drop` of a closure is a
    // clippy error.
    let status = {
        let mut watch = |members: &[MemberSurvey]| {
            let action = observe(members);
            stopped = action == AfterSurvey::Stop;
            action
        };
        repair_dir_set(&mut cat, Some(*set_id), &ctx, true, Some(&mut watch))?
    };
    Ok((!stopped).then_some(status))
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
                status: repair_dir_set(cat, Some(*id), &ctx, false, None),
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
                    status: repair_dir_set(cat, Some(*id), &ctx, false, None),
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
    mut observe: Option<&mut dyn FnMut(&[MemberSurvey]) -> AfterSurvey>,
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
        repair_dir_set_inner(cat, want, ctx, f, path, probe, observe.take())
    })
}

fn repair_dir_set_inner(
    cat: &mut PacketCatalog,
    want: Option<[u8; 16]>,
    ctx: &DirContext,
    fresh: bool,
    path: SyndromePath,
    probe: &mut NttProbe,
    observe: Option<&mut dyn FnMut(&[MemberSurvey]) -> AfterSurvey>,
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
    // The verify pass is done and NOTHING has been written yet, so this
    // is the one point where an observer can both see the whole set and
    // still refuse the repair. Names are the FileDesc's own, in Main
    // packet order; a caller that prints in its own order matches on
    // them (see [`repair_dir_set_surveyed`]).
    if let Some(observe) = observe {
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
        if observe(&members) == AfterSurvey::Stop {
            // The caller's own verdict stands in for the engine's; the
            // surveying entry point turns this into `Ok(None)` and no
            // other entry point can reach it.
            return Ok(RepairStatus::NoDamage);
        }
    }
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
    let recovery = if shortfall.is_none() && needed > 0 {
        reconstruct::check_repair_dim(needed)?;
        match load_selected_recovery(&pool, &mut by_exp, needed, bs, !fresh)? {
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
                            for &(g, ti, off, take) in wchunk {
                                if open.as_ref().is_none_or(|(oi, _)| *oi != ti) {
                                    open = Some((ti, File::open(&targets_ref[ti].path)?));
                                }
                                let f = &open.as_ref().expect("just opened").1;
                                feeder.feed_with(g, take, |buf| {
                                    crate::disk::read_exact_at(f, buf, off)
                                })?;
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
                let data = cand_reader.lock_ok().read(s, take)?;
                crate::disk::write_all_at(f, &data, off)?;
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
    // Pass two: every target's blocks, across threads.
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
/// (`bs` goes up to [`crate::par2::MAX_BLOCK_SIZE`], 256 MiB).
const HASH_CHUNK: usize = 4 << 20;
/// Small proved slices can share one positioned read. Keep the window below
/// the normal streaming chunk: this is large enough to amortize syscall and
/// `FileExt` overhead without charging sparse IFSC grids for dense buffers.
const HASH_POSITIONED_WINDOW: usize = 512 << 10;
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
/// disk length); `threads` is this file's share of the machine. The calling
/// file-level worker hashes range zero and only the remaining ranges become
/// child threads, so nested file-level and block-level pools stay inside that
/// share. On Windows each child owns a separate handle because its positioned
/// read compatibility primitive moves the handle cursor.
fn hash_blocks_par(
    _path: &Path,
    _source: &File,
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
    let diagnostic_slices = hash_diagnostic_slice_count(&blocks[..blocks.len().min(n_slices)]);
    if diagnostic_slices == 0 {
        return Ok(crc_ok);
    }
    let chunk_buf = hash_positioned_buffer_len(&blocks[..diagnostic_slices], bs);
    let proven_slices = blocks[..diagnostic_slices]
        .iter()
        .filter(|check| check.is_proven())
        .count();
    let workers = bounded_hash_workers(threads, proven_slices, chunk_buf);
    // Contiguous block ranges per worker: N sequential read streams,
    // not a random-access shuffle.
    let (per, ranges) = hash_range_geometry(diagnostic_slices, workers);
    let (caller_blocks, child_blocks) = crc_ok[..diagnostic_slices].split_at_mut(per);
    let mut child_out: Vec<Result<(), RepairError>> = (1..ranges).map(|_| Ok(())).collect();
    let hash_range = |first_block: usize,
                      oks: &mut [bool],
                      _independent_handle: bool|
     -> Result<(), RepairError> {
        #[cfg(unix)]
        let src = _source;
        // The caller is the only user of the original handle on this branch;
        // every concurrent Windows child needs its own cursor.
        #[cfg(windows)]
        let owned = if _independent_handle {
            Some(File::open(_path)?)
        } else {
            None
        };
        #[cfg(windows)]
        let src = owned.as_ref().unwrap_or(_source);
        let mut buf = Vec::new();
        let mut crc = crc32fast::Hasher::new();
        let mut j = 0usize;
        while j < oks.len() {
            let bidx = first_block + j;
            let Some(check) = blocks.get(bidx).filter(|check| check.is_proven()) else {
                j += 1;
                continue;
            };
            let off = bidx as u64 * bs as u64;
            let declared = (length - off).min(bs as u64);
            let avail = limit.saturating_sub(off).min(bs as u64);
            if avail < declared {
                // Truncation: the serial pass never closes this block's CRC
                // either.
                j += 1;
                continue;
            }
            if buf.is_empty() {
                buf = vec![0u8; chunk_buf];
            }

            // A lane owns a contiguous range of slice slots. Adjacent proved
            // full slices share a positioned read, but an UNPROVEN cell or a
            // short physical/declaration tail ends the run. In particular,
            // this never reads a fixed-false IFSC gap as incidental read-ahead.
            if avail == bs as u64 && declared == bs as u64 && bs <= buf.len() {
                let max_run = hash_full_run_limit(
                    (buf.len() / bs).min(oks.len() - j),
                    limit - off,
                    length - off,
                    bs as u64,
                );
                let run = hash_proven_run_len(&blocks[bidx..], max_run);
                debug_assert!(run > 0);
                let bytes = run * bs;
                crate::disk::read_exact_at(src, &mut buf[..bytes], off)?;
                for k in 0..run {
                    crc.update(&buf[k * bs..(k + 1) * bs]);
                    let crc_val = crc.clone().finalize();
                    crc.reset();
                    oks[j + k] = blocks[bidx + k].crc_matches(crc_val);
                }
                j += run;
                continue;
            }

            let mut p = 0u64;
            while p < avail {
                let take = crate::disk::chunk_len(avail - p, buf.len());
                crate::disk::read_exact_at(src, &mut buf[..take], off + p)?;
                crc.update(&buf[..take]);
                p += take as u64;
            }
            // Tail zero padding in O(log n), exactly as the serial scanner
            // does it.
            let crc_val = if avail == bs as u64 {
                crc.clone().finalize()
            } else {
                crate::yenc_simd::crc32_zeros(crc.clone().finalize(), bs as u64 - avail)
            };
            crc.reset();
            oks[j] = check.crc_matches(crc_val);
            j += 1;
        }
        Ok(())
    };
    let caller_out = std::thread::scope(|s| {
        for (child_index, (oks, res)) in child_blocks
            .chunks_mut(per)
            .zip(child_out.iter_mut())
            .enumerate()
        {
            let hash_range = &hash_range;
            s.spawn(move || {
                *res = hash_range((child_index + 1) * per, oks, true);
            });
        }
        hash_range(0, caller_blocks, false)
    });
    caller_out?;
    for r in child_out {
        r?;
    }
    Ok(crc_ok)
}

/// Number of consecutive proved cells a coalesced read may cross. Keeping the
/// UNPROVEN stop in a small pure helper makes the no-incidental-read boundary
/// directly testable rather than merely inferred from a checksum result.
fn hash_proven_run_len(blocks: &[BlockCheck], max_run: usize) -> usize {
    blocks
        .iter()
        .take(max_run)
        .take_while(|check| check.is_proven())
        .count()
}

/// Clamp full-slice availability before narrowing to pointer width. The lane
/// cap is already tiny, while `readable` and `declared` are wire/file `u64`s;
/// narrowing either quotient first can wrap to zero on a 32-bit target.
fn hash_full_run_limit(lane_slots: usize, readable: u64, declared: u64, block_size: u64) -> usize {
    (readable / block_size)
        .min(declared / block_size)
        .min(lane_slots as u64) as usize
}

/// Buffer size for one block-hash lane. The longest consecutive proved run
/// controls allocation so an isolated sparse grid retains the old one-slice
/// buffer, while dense small-slice grids receive a bounded coalescing window.
fn hash_positioned_buffer_len(blocks: &[BlockCheck], bs: usize) -> usize {
    if bs >= HASH_POSITIONED_WINDOW {
        return bs.min(HASH_CHUNK);
    }
    let max_run = HASH_POSITIONED_WINDOW / bs;
    let mut run = 0usize;
    let mut longest = 0usize;
    for check in blocks {
        if check.is_proven() {
            run += 1;
            longest = longest.max(run);
            if longest == max_run {
                break;
            }
        } else {
            run = 0;
        }
    }
    longest.max(1) * bs
}

/// Resolve the block-hash pool width from work that can still become true.
/// Geometry continues to span the diagnostic prefix so offsets stay exact,
/// but UNPROVEN holes must not buy empty child threads.
fn bounded_hash_workers(requested: usize, proven_slices: usize, chunk_buf: usize) -> usize {
    if proven_slices == 0 {
        return 0;
    }
    requested
        .min(proven_slices)
        .min((HASH_POOL_BYTES / chunk_buf.max(1)).max(1))
        .max(1)
}

fn hash_range_geometry(blocks: usize, workers: usize) -> (usize, usize) {
    if blocks == 0 || workers == 0 {
        return (0, 0);
    }
    let per = blocks.div_ceil(workers);
    (per, blocks.div_ceil(per))
}

/// Last slice for which IFSC evidence can possibly produce `true`. Missing
/// entries and a fitted UNPROVEN suffix have fixed-false verdicts and require
/// neither positioned reads nor worker ranges.
fn hash_diagnostic_slice_count(blocks: &[BlockCheck]) -> usize {
    blocks
        .iter()
        .rposition(BlockCheck::is_proven)
        .map_or(0, |index| index + 1)
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
    /// `clean` AND the disk length is exactly the declared one. Read it
    /// beside `md5_unfinished`: these three verdicts are a TRI-state,
    /// and false under that flag is "not proven", not "disproven".
    pub intact: bool,
    /// Whole-file MD5 matched over the declared length: every block is
    /// present even if trailing junk keeps `intact` false. Same
    /// tri-state as `intact` - see `md5_unfinished`.
    pub clean: bool,
    /// Per-block presence from the in-stream block CRC32s, for a
    /// damaged file with IFSC data (None when clean, absent, or the
    /// set has no IFSC packets - those fall back to all-false).
    pub present: Option<Vec<bool>>,
    /// Where the post-repair self-prove may pick the whole-file MD5
    /// back up (TODO 133.1 cost work) - see [`Md5Resume`].
    pub resume: Option<Md5Resume>,
    /// The whole-file MD5 stopped at the first failed block, so `clean`
    /// is false on IFSC evidence alone and the digest was never
    /// finished - see [`verify_pass1`]. Always false when `resume` is
    /// None.
    ///
    /// This is the flag that makes the two above a tri-state, and a
    /// caller that reads them without it reads an IFSC verdict as a
    /// FileDesc one. In-tree the only reader is [`verify_all_targets`],
    /// which carries the flag through to `Target`, and the one verdict
    /// it can change is arbitrated in `repair_dir_set_inner`. What the
    /// early stop can NOT do is manufacture a positive: `md5_ok` is
    /// gated on it, so a false "clean" - the H7 direction - stays
    /// unreachable
    /// (`filedesc_md5_over_bytes_the_ifsc_denies_is_unproven_not_damaged`).
    pub md5_unfinished: bool,
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
#[derive(Clone, Debug)]
pub struct Md5Resume {
    offset: u64,
    state: Md5,
}

impl Md5Resume {
    /// A resume point built OUTSIDE a verify pass: the live verifier's
    /// prefix hasher (`live::prefix`), which hashes a slot's
    /// PAR2-vouched prefix off disk while the download runs. Same
    /// meaning, same obligations - `offset` must be a point below which
    /// the patch writes nothing, and `state` must be the digest of the
    /// bytes on disk under it - which is why the mapped self-prove
    /// rechecks that span against the IFSC CRC32s anyway before it
    /// trusts the resume (`self_prove_set`).
    /// A RESUME POINT CAN ONLY FAIL, NEVER PASS. The verdict is still
    /// `digest == f.md5` over the whole file, so a state that does not
    /// describe the bytes under `offset` produces a digest that does
    /// not match and the repair reports `VerifyFailed`. That is what
    /// makes this constructor safe to expose to the bench and the
    /// verifier alike: the worst a wrong prefix can do is throw the
    /// mapped route away and fall back to the directory path.
    pub(crate) fn from_prefix(offset: u64, state: Md5) -> Md5Resume {
        Md5Resume { offset, state }
    }

    /// How far this resume point reaches, and the digest it would
    /// finalize to. Test-only: `live/prefix_tests.rs` asserts the
    /// hasher's output IS the FileDesc MD5 of the proven prefix, which
    /// is the whole of what it promises the repair.
    #[cfg(test)]
    pub(crate) fn offset_for_test(&self) -> u64 {
        self.offset
    }

    #[cfg(test)]
    pub(crate) fn finish_for_test(&self) -> [u8; 16] {
        self.state.clone().finalize().into()
    }

    /// [`Md5Resume::from_prefix`] for `par2_mapped_repair_bench`, which
    /// stands in for the live verifier's download-time hasher and lives
    /// outside this crate. Not part of the supported API surface.
    #[doc(hidden)]
    pub fn bench_prefix(offset: u64, state: Md5) -> Md5Resume {
        Md5Resume::from_prefix(offset, state)
    }
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
                md5_unfinished: false,
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
        let crc_ok = hash_blocks_par(path, &f, disk_len, file.length, &file.blocks, bs, threads)?;
        return Ok(Pass1Out {
            exists: true,
            intact: false,
            clean: false,
            present: Some(crc_ok),
            // The pool branch never computes the whole-file MD5, so
            // there is no state to resume from - such targets keep the
            // full-reread self-prove.
            resume: None,
            md5_unfinished: false,
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
    // EARLY STOP (2 Sep 2026): once a block has failed its CRC the
    // whole-file digest can no longer prove the file clean, and the
    // self-prove after the patch resumes from `snap` - the state at
    // that block's start - and hashes everything past it anyway. So the
    // bytes past the first failure were hashed TWICE, once here to a
    // digest nobody reads and once after the patch; on a 1 GiB single
    // member damaged at block 2 that was 1.4 s of a 3.1 s repair
    // (measured, M3 Ultra, md5 at 0.75 GB/s). The per-block CRCs keep
    // going - presence is still decided here - and only the digest
    // stops. What that gives up is the one case where an unfinished
    // digest WOULD have mattered: an IFSC entry disagreeing with a
    // byte-exact file (the whole-file MD5 arbitrates, M4-69). For that
    // shape the repair rebuilds the disputed block to the bytes it
    // already had and the resumed self-prove passes, so the file comes
    // out identical; the only verdict it can change is a SHORTFALL,
    // which is why `repair_dir_set_inner` finishes the digest before
    // declaring one - see its arbitration step. Never on the pool
    // branch above (no snapshot to resume from) and never below
    // RESUME_MIN_BLOCK, where no snapshot is taken.
    let mut md5_stopped = false;
    // The buffer is bounded regardless of the slice size - `bs` is
    // wire-supplied up to `par2::MAX_BLOCK_SIZE` (256 MiB), and this allocates
    // once per parallel worker. The in-stream block CRC accumulates
    // across reads (`bfill`), so blocks may straddle buffers freely.
    let mut buf = vec![0u8; bs.clamp(1 << 20, 8 << 20)];
    let limit = file.length.min(disk_len);
    // The read-side cache policy (disk::readpolicy). This loop is a
    // single front-to-back pass over the target, and for the common
    // outcome - the file is clean - nothing reads those bytes again.
    // Measured on a 23.4 GB member: -11.4% cold, flat warm, and the
    // unrelated working set on the box goes from 17-19% evicted to zero
    // (`DROP_BEHIND_DEFAULT`). It gives back only what THIS read
    // faulted in, so a payload somebody else cached is left alone.
    //
    // THE TRADE, STATED HERE because this is where it lands: a member
    // past the policy's floor (a quarter of RAM, so 8 GiB on a 32 GB
    // host) that turns out to be DAMAGED is re-read by the repair, and
    // the bytes this pass brought in are now cold. Every RAR volume
    // shape is far below that floor and is untouched either way; a
    // member that large was never going to be held in cache whole.
    let scan = crate::disk::ScanCache::attach(&f, path, disk_len);
    let mut pos = 0u64;
    while pos < limit {
        let take = crate::disk::chunk_len(limit - pos, buf.len());
        read_full(&mut f, &mut buf[..take])?;
        scan.consumed(&f, pos + take as u64);
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
                if snapping && !md5_stopped {
                    // Fed per block segment instead of per read so the
                    // state at each block boundary exists to clone;
                    // segments are >= RESUME_MIN_BLOCK except at
                    // buffer straddles, so the per-call overhead stays
                    // noise.
                    whole.update(&buf[p..p + seg]);
                }
                let crc_proven = file.blocks.get(bidx).is_some_and(BlockCheck::is_proven);
                // An all-zero IFSC MD5 is the reserved UNPROVEN marker.
                // `crc_matches` can therefore never accept this cell, so its
                // CRC state has a fixed false answer before touching bytes.
                // The FileDesc MD5 above still sees the payload whenever its
                // proof remains live, and later proved blocks retain their
                // independent CRC state.
                if crc_proven {
                    crc.update(&buf[p..p + seg]);
                }
                bfill += seg;
                p += seg;
                if bfill == bs {
                    let matched = if crc_proven {
                        let done = std::mem::replace(&mut crc, crc32fast::Hasher::new());
                        file.blocks[bidx].crc_matches(done.finalize())
                    } else {
                        false
                    };
                    if let Some(slot) = ok.get_mut(bidx) {
                        *slot = matched;
                    }
                    if !matched && snap.is_none() {
                        snap = pending.take();
                        // Only with a snapshot in hand: the self-prove
                        // must be able to resume from it.
                        md5_stopped = snap.is_some();
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
        if limit - off >= expect
            && let Some(check) = file.blocks.get(bidx)
            && check.is_proven()
        {
            // Extended through the padding in O(log n) rather than by
            // hashing a zero buffer: `bs` is wire-supplied up to 256 MiB,
            // and a set of many one-byte targets made every parallel
            // worker allocate one of those at its tail block - a
            // metadata-driven `targets x block_size` memory spike on a
            // file that could be a few KB. The read buffer above is
            // already clamped for exactly this reason.
            let padded = crate::yenc_simd::crc32_zeros(crc.clone().finalize(), (bs - bfill) as u64);
            ok[bidx] = check.crc_matches(padded);
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
    let md5_ok = !md5_stopped && disk_len >= file.length && md5 == file.md5;
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
        md5_unfinished: md5_stopped,
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
        t.md5_unfinished = out.md5_unfinished;
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
