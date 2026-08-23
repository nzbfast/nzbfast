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

use crate::gf16::{self, FoldTable, MulTable};
use crate::par2::{self, BlockCheck, Par2File};
use crate::sync::{MutexExt, RwLockExt};
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

/// Locate every valid recovery slice for `set_id` in a buffer of PAR2
/// packets: (exponent, offset of slice data, data length). Packets
/// failing their MD5 are already dropped by the scanner; duplicates are
/// NOT deduped here - callers dedupe by exponent across files.
pub fn recovery_slice_locators(bytes: &[u8], set_id: &[u8; 16]) -> Vec<(u32, usize, usize)> {
    let mut out = Vec::new();
    par2::scan_packets(bytes, |pkt| {
        if &pkt.ptype == par2::TYPE_RECVSLIC && &pkt.set_id == set_id && pkt.body.len() >= 4 {
            let e = u32::from_le_bytes(pkt.body[0..4].try_into().unwrap());
            out.push((e, pkt.body_offset + 4, pkt.body.len() - 4));
        }
    });
    out
}

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
fn fold_chunk_tiled(
    dsts: &mut [&mut [u16]],
    srcs: &[&[u8]],
    coeff: &(dyn Fn(usize, usize) -> u16 + Sync),
    row_base: usize,
    tile_words: usize,
    table_budget: usize,
) {
    if dsts.is_empty() || srcs.is_empty() {
        return;
    }
    if gf16::multi_fold_width() > 0 {
        return fold_chunk_multi(dsts, srcs, coeff, row_base, tile_words);
    }
    let words = dsts[0].len();
    debug_assert!(dsts.iter().all(|d| d.len() == words));
    let per_src = std::mem::size_of::<FoldTable>() * dsts.len();
    let group = (table_budget / per_src.max(1)).clamp(1, srcs.len());
    // One column tile is walked across EVERY row this thread owns before
    // moving on, so the resident set is tile x rows, not tile. A fixed
    // tile therefore only stays L2-resident while the row count is small;
    // scale it down as rows grow so the intent holds either way.
    // The caller's tile is the ceiling, so the floor must never exceed
    // it (callers - and the tests - may ask for a deliberately tiny
    // tile). A zero tile would not advance the loop below.
    let ceiling = tile_words.max(1);
    let tile_words = (L2_TARGET_WORDS / dsts.len()).clamp(MIN_TILE_WORDS.min(ceiling), ceiling);
    let mut tables: Vec<FoldTable> = Vec::with_capacity(group * dsts.len());
    // Coefficients hoisted out of the tile loop: the zero test used to
    // recompute one per (tile, source, row), and for the syndrome fold
    // that is a u64 multiply plus a `% 65535` division.
    let mut coeffs: Vec<u16> = Vec::with_capacity(group * dsts.len());
    let mut g0 = 0usize;
    while g0 < srcs.len() {
        let g1 = (g0 + group).min(srcs.len());
        tables.clear();
        coeffs.clear();
        for j in 0..dsts.len() {
            for i in g0..g1 {
                let c = coeff(row_base + j, i);
                coeffs.push(c);
                tables.push(FoldTable::new(c));
            }
        }
        let mut w0 = 0usize;
        while w0 < words {
            let w1 = (w0 + tile_words).min(words);
            for (gi, src) in srcs[g0..g1].iter().enumerate() {
                let sb = (w0 * 2).min(src.len());
                let eb = (w1 * 2).min(src.len());
                if sb == eb {
                    continue;
                }
                for (j, d) in dsts.iter_mut().enumerate() {
                    let t = j * (g1 - g0) + gi;
                    if coeffs[t] == 0 {
                        continue;
                    }
                    tables[t].xor_mul_into(&mut d[w0..w1], &src[sb..eb]);
                }
            }
            w0 = w1;
        }
        g0 = g1;
    }
}

/// The multi-source twin of [`fold_chunk_tiled`], used when the
/// platform has a fused kernel ([`gf16::multi_fold_width`] > 0): per
/// destination tile, per row, sources are folded in fused groups - each
/// dst chunk is loaded/stored once per GROUP instead of once per source,
/// and no split tables are built at all (the old path built one 1.2 KB
/// table per (row, source): 23M of them on a heavy repair, all fighting
/// the destination tiles for L2). Sources that don't cover a full tile
/// (zero-padded tails) and sub-chunk tile remainders take the scalar
/// single-source path; both are rare edges of a fold that is otherwise
/// whole blocks.
fn fold_chunk_multi(
    dsts: &mut [&mut [u16]],
    srcs: &[&[u8]],
    coeff: &(dyn Fn(usize, usize) -> u16 + Sync),
    row_base: usize,
    tile_words: usize,
) {
    let width = gf16::multi_fold_width().min(16);
    let words = dsts[0].len();
    debug_assert!(dsts.iter().all(|d| d.len() == words));
    // Same residency math as the table path (a tile is walked across
    // every row this thread owns), with one extra constraint: a multiple
    // of 16 words, so the fused kernel covers whole tiles and the
    // per-source remainder path stays out of the steady state.
    let ceiling = tile_words.max(16);
    let tile_words =
        ((L2_TARGET_WORDS / dsts.len()).clamp(MIN_TILE_WORDS.min(ceiling), ceiling)) & !15;
    let tile_words = tile_words.max(16);
    // Coefficients hoisted per (row, group) sweep, exactly as the table
    // path hoists them. Zero coefficients ride along (a pmull by zero
    // contributes nothing and they are far too rare to branch on).
    let mut coeffs: Vec<u16> = Vec::with_capacity(dsts.len() * width);
    let mut g0 = 0usize;
    while g0 < srcs.len() {
        let g1 = (g0 + width).min(srcs.len());
        coeffs.clear();
        for j in 0..dsts.len() {
            for i in g0..g1 {
                coeffs.push(coeff(row_base + j, i));
            }
        }
        let mut w0 = 0usize;
        while w0 < words {
            let w1 = (w0 + tile_words).min(words);
            let tile_bytes = (w1 - w0) * 2;
            // Window this group's sources to the tile. Full-coverage
            // sources take the fused kernel; short ones (zero-padded
            // tails) are folded singly afterwards.
            let mut full: [&[u8]; 16] = [&[]; 16];
            let mut full_idx: [usize; 16] = [0; 16];
            let mut n = 0usize;
            let mut partial: [(usize, &[u8]); 16] = [(0, &[]); 16];
            let mut np = 0usize;
            for (gi, src) in srcs[g0..g1].iter().enumerate() {
                let sb = (w0 * 2).min(src.len());
                let eb = (w1 * 2).min(src.len());
                if sb == eb {
                    continue;
                }
                if eb - sb == tile_bytes {
                    full[n] = &src[sb..eb];
                    full_idx[n] = gi;
                    n += 1;
                } else {
                    partial[np] = (gi, &src[sb..eb]);
                    np += 1;
                }
            }
            for (j, d) in dsts.iter_mut().enumerate() {
                let dtile = &mut d[w0..w1];
                if n > 0 {
                    let mut gc: [u16; 16] = [0; 16];
                    for (k, &gi) in full_idx[..n].iter().enumerate() {
                        gc[k] = coeffs[j * (g1 - g0) + gi];
                    }
                    let done = gf16::xor_mul_multi_into(dtile, &full[..n], &gc[..n]);
                    if done < dtile.len() {
                        // Only a non-32-byte-aligned FINAL tile lands here.
                        for (s, c) in full[..n].iter().zip(&gc[..n]) {
                            if *c != 0 {
                                FoldTable::new(*c).xor_mul_into(&mut dtile[done..], &s[done * 2..]);
                            }
                        }
                    }
                }
                for &(gi, s) in &partial[..np] {
                    let c = coeffs[j * (g1 - g0) + gi];
                    if c != 0 {
                        FoldTable::new(c).xor_mul_into(&mut dtile[..s.len().div_ceil(2)], s);
                    }
                }
            }
            w0 = w1;
        }
        g0 = g1;
    }
}

/// Destination tile size for [`fold_chunk_tiled`]: the ceiling, used
/// when a thread owns few enough rows that 64 KiB each still fits.
const TILE_WORDS: usize = 32 << 10;
/// Destination-cache target a thread aims to stay inside across all the
/// rows it owns. 512 KiB is a conservative L2 share (leaving room for
/// the source tile and the split tables beside it).
const L2_TARGET_WORDS: usize = (512 << 10) / 2;
/// Never tile finer than this - past here the per-call overheads and the
/// source re-reads cost more than the residency buys.
const MIN_TILE_WORDS: usize = 2 << 10;
/// Per-thread split-table memory cap for [`fold_chunk_tiled`].
const TABLE_BUDGET: usize = 2 << 20;
/// Do not split a column range finer than this: below it the thread and
/// table-build overheads dominate the fold itself.
const MIN_COL_WORDS: usize = 2 << 10;

/// Run `dsts[j] ^= Σ_i coeff(j, i) · srcs[i]` across the whole machine.
///
/// Splitting by rows alone caps parallelism at the ROW COUNT, which for
/// both callers is the number of missing blocks. Light damage is the
/// common case (a few failed articles), so that repeatedly left a
/// many-core machine folding on one or two threads: measured, fold
/// throughput scaled linearly with missing-block count and only
/// saturated once it reached the core count.
///
/// Rows stay the outer split (they need no sub-slicing and keep whole
/// rows on one thread), and whatever parallelism they leave unused goes
/// to the column range: the grid is rows x columns. Column slices of a
/// row are disjoint, so each thread still owns its destination bytes
/// outright and nothing is shared but the read-only sources.
/// Bench hook: the fold in isolation, so a harness can time the GF work
/// without the surrounding allocation and batching. Not part of the
/// supported API.
#[doc(hidden)]
pub fn bench_fold(
    dsts: &mut [Vec<u16>],
    srcs: &[&[u8]],
    coeff: &(dyn Fn(usize, usize) -> u16 + Sync),
) {
    fold_parallel(dsts, srcs, coeff);
}

/// Bench hook: the scalar matrix work (Vandermonde inverse and
/// Gauss-Jordan) in isolation, so fold-table A/Bs can prove the scalar
/// solve path untouched. Returns a checksum over both inverses so the
/// work cannot be optimized away. Not part of the supported API.
#[doc(hidden)]
pub fn bench_invert(m: usize) -> u16 {
    let ks: Vec<u32> = (0..m as u32).map(|k| 2 * k + 1).collect();
    let v = invert_vandermonde(&ks, 7).expect("distinct bases");
    let a: Vec<Vec<u16>> = (0..m)
        .map(|r| {
            ks.iter()
                .map(|&k| gf16::pow2(k as u64 * (7 + r as u64)))
                .collect()
        })
        .collect();
    let g = invert(a).expect("nonsingular");
    // Rotate between words: v and g are inverses of the SAME matrix, so
    // a plain XOR would structurally cancel to zero and discriminate
    // nothing.
    let mut sum = 0u16;
    for row in v.iter().chain(g.iter()) {
        for &x in row {
            sum = sum.rotate_left(1) ^ x;
        }
    }
    sum
}

/// Physical core count on Windows (P and E cores, SMT siblings
/// excluded), counted the way par2j counts fold workers: one
/// `RelationProcessorCore` record per core. `None` on failure, and off
/// Windows (Apple Silicon has no SMT, so `available_parallelism` IS the
/// physical count there).
#[cfg(all(target_arch = "x86_64", windows))]
fn physical_cores() -> Option<usize> {
    // SAFETY: declaration matches the documented kernel32 ABI
    // (LOGICAL_PROCESSOR_RELATIONSHIP as u32, byte buffer, in/out
    // DWORD length, BOOL return).
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetLogicalProcessorInformationEx(rel: u32, buf: *mut u8, len: *mut u32) -> i32;
    }
    const RELATION_PROCESSOR_CORE: u32 = 0;
    // SAFETY: the documented two-call protocol: the first call (null
    // buffer, len 0) reports the required byte count, the second gets
    // a buffer of exactly that many bytes, and record parsing stays
    // inside `len` via the `off + 8 <= len` loop bound and the
    // `size < 8` rejection.
    unsafe {
        let mut len: u32 = 0;
        GetLogicalProcessorInformationEx(RELATION_PROCESSOR_CORE, std::ptr::null_mut(), &mut len);
        if len < 8 {
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        if GetLogicalProcessorInformationEx(RELATION_PROCESSOR_CORE, buf.as_mut_ptr(), &mut len)
            == 0
        {
            return None;
        }
        // Variable-size SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX records:
        // u32 relationship, u32 size, then the union. Every record here
        // is a core (the call filtered on the relation).
        let mut off = 0usize;
        let mut cores = 0usize;
        while off + 8 <= len as usize {
            let size = u32::from_le_bytes(buf[off + 4..off + 8].try_into().unwrap()) as usize;
            if size < 8 {
                return None;
            }
            cores += 1;
            off += size;
        }
        (cores > 0).then_some(cores)
    }
}

fn fold_parallel(
    dsts: &mut [Vec<u16>],
    srcs: &[&[u8]],
    coeff: &(dyn Fn(usize, usize) -> u16 + Sync),
) {
    let rows = dsts.len();
    if rows == 0 || srcs.is_empty() {
        return;
    }
    let words = dsts[0].len();
    debug_assert!(dsts.iter().all(|d| d.len() == words));
    if words == 0 {
        return;
    }
    let cores = std::thread::available_parallelism()
        .map_or(4, |n| n.get())
        .max(1);
    // Hybrid x86: fold on PHYSICAL cores only, SMT siblings idle (par2j
    // runs 14 threads on the i7-1280P, never 20). Measured on that box:
    // HT added nothing to the old kernel and REGRESSED the affine2x one
    // (two siblings thrash the shuffle ports and 16 hoisted ymm each).
    // min() keeps a process affinity mask authoritative when it is the
    // smaller number (the pinned bench rows depend on that).
    #[cfg(all(target_arch = "x86_64", windows))]
    let cores = physical_cores().map_or(cores, |p| p.min(cores));
    let row_threads = cores.min(rows);
    let row_chunk = rows.div_ceil(row_threads);
    // Columns split past the leftover-core count on purpose: units are
    // WORK-STOLEN, not statically owned. A static grid handed each
    // thread one fixed cell, so on hybrid parts every fold waited for
    // the slowest E-core to finish a P-core-sized share (measured: the
    // straggler set the wall on both the i7 and the M3 at high m).
    // Oversplitting columns a few times per thread gives fast cores
    // more units and the tail shrinks to one small unit's length.
    let col_splits = if rows >= cores {
        #[cfg(target_arch = "x86_64")]
        {
            // TODO 58 item B rung 2: size units from cache geometry
            // instead of a fixed 8-way split. A unit's dst slab
            // (row_chunk x col_chunk words) must stay L2-resident per
            // worker: 512 KiB = min(P-core L2 / 2, E-cluster L2 / 4) on
            // the hybrid-x86 reference (i7-1280P). And the column
            // stripe's source window (every source's slice of one
            // column range, L3-shared by all workers via the
            // column-major LIFO drain below) is capped at a
            // conservative half-L3. The fixed 8-way split left 600 KiB
            // units at m = 1500 - 20 workers' worth blew past both the
            // E-cluster L2 and the L3, and the fold measurably fell off
            // (267 -> 141 GB/s all-core) exactly there.
            const UNIT_DST_BUDGET: usize = 512 << 10;
            const STRIPE_SRC_BUDGET: usize = 8 << 20;
            let by_dst = (UNIT_DST_BUDGET / 2 / row_chunk.max(1)).max(MIN_COL_WORDS);
            let by_src = (STRIPE_SRC_BUDGET / 2 / srcs.len().max(1)).max(MIN_COL_WORDS);
            words
                .div_ceil(by_dst.min(by_src))
                .clamp(1, words.div_ceil(MIN_COL_WORDS).max(1))
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            (8usize).min(words.div_ceil(MIN_COL_WORDS).max(1))
        }
    } else {
        // Few rows: columns are the only parallelism, so they carry
        // both the fan-out AND the oversplit.
        (cores / row_threads * 4)
            .max(1)
            .min(words.div_ceil(MIN_COL_WORDS).max(1))
    };
    // A column boundary that is not a multiple of 16 words leaves every
    // unit's tiles with a sub-32-byte-chunk remainder, and the remainder
    // path builds a fold table per (row, group, source) - measured as
    // a 7-25x fold COLLAPSE the first time a cache-derived col_chunk
    // landed off-alignment (the old fixed 8-way split only survived
    // because 32768/8 happened to be aligned). Align up: whole blocks
    // are word-power-of-two sized, so every column - including the last
    // - stays a multiple of 16 words.
    let col_chunk = words.div_ceil(col_splits).next_multiple_of(16);

    // A view of every row restricted to each column range, built by
    // repeated split_at_mut so the borrows are provably disjoint.
    let mut cols: Vec<Vec<&mut [u16]>> =
        (0..col_splits).map(|_| Vec::with_capacity(rows)).collect();
    for row in dsts.iter_mut() {
        let mut rest: &mut [u16] = row.as_mut_slice();
        for col in cols.iter_mut() {
            let take = rest.len().min(col_chunk);
            let (head, tail) = rest.split_at_mut(take);
            col.push(head);
            rest = tail;
        }
    }

    // The unit grid: (row range x column range) cells, each owning its
    // destination region outright, pulled off one atomic counter.
    //
    // LOAD-BEARING ORDER: units are built column-major and drained LIFO
    // (`Vec::pop`), so all workers co-schedule on ONE column stripe at a
    // time and the stripe's source window stays L3-shared instead of
    // each worker streaming a different slice of every source. The
    // STRIPE_SRC_BUDGET cap above sizes that window; changing the drain
    // order breaks the cap's premise.
    struct Unit<'a> {
        rows: Vec<&'a mut [u16]>,
        row_base: usize,
        col_off: usize,
    }
    let mut units: Vec<Unit> = Vec::with_capacity(col_splits * row_threads);
    for (ci, col) in cols.into_iter().enumerate() {
        let mut row_base = 0usize;
        let mut col = col;
        while !col.is_empty() {
            let take = col.len().min(row_chunk);
            let rest = col.split_off(take);
            units.push(Unit {
                rows: col,
                row_base,
                col_off: ci * col_chunk,
            });
            row_base += take;
            col = rest;
        }
    }
    let units = std::sync::Mutex::new(units);
    let workers = cores.min(row_threads * col_splits);
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| {
                loop {
                    let unit = units.lock_ok().pop();
                    let Some(unit) = unit else { return };
                    // Each unit sees only its own bytes of every source;
                    // a source that ends before this range contributes
                    // nothing (PAR2 tail slices are zero-padded).
                    let sub: Vec<&[u8]> = srcs
                        .iter()
                        .map(|src| {
                            let b0 = (unit.col_off * 2).min(src.len());
                            let b1 = ((unit.col_off + col_chunk) * 2).min(src.len());
                            &src[b0..b1]
                        })
                        .collect();
                    let mut rows = unit.rows;
                    fold_chunk_tiled(
                        &mut rows,
                        &sub,
                        coeff,
                        unit.row_base,
                        TILE_WORDS,
                        TABLE_BUDGET,
                    );
                }
            });
        }
    });
}

/// One feeder's assembled batch: slices PACKED into a single arena
/// instead of one heap allocation each. The per-slice `Vec<u8>` design
/// allocated and freed tens of thousands of block-sized buffers across
/// threads per heavy repair; on Windows every 64 KiB+ allocation is a
/// direct VirtualAlloc, and the cross-thread VirtualFree storm (TLB
/// shootdowns interrupt every core) collapsed the fold from 105 GB/s to
/// 13 GB/s a few seconds into the run (measured, i7-1280P, m=1500). An
/// arena per batch is ~two allocations per 32 MiB instead of ~512.
struct FeedBatch {
    arena: Vec<u8>,
    /// (base log k, arena offset, len) per slice.
    slices: Vec<(u32, usize, usize)>,
    /// Memory-floor gauge (memgauge::Sub::RepairWork), grown as bytes
    /// land in the arena and released when the batch drops - so batches
    /// queued in the channel, merged for a fold, and NTT-retained all
    /// stay attributed wherever they travel. Charged by LEN, not
    /// capacity: a fresh 64 MB arena's untouched pages are not resident,
    /// and the ram cost tracks the bytes actually written.
    charge: crate::memgauge::Charge,
}

impl FeedBatch {
    fn with_capacity(bytes: usize) -> FeedBatch {
        FeedBatch {
            arena: Vec::with_capacity(bytes),
            slices: Vec::new(),
            charge: crate::memgauge::Charge::new(crate::memgauge::Sub::RepairWork, 0),
        }
    }

    fn push(&mut self, k: u32, data: &[u8]) {
        let off = self.arena.len();
        self.arena.extend_from_slice(data);
        self.slices.push((k, off, data.len()));
        self.charge.grow(data.len() as u64);
    }
}

/// Fold queued batches of present slices into every syndrome row - one
/// row sweep for the whole set, however many feeder batches it arrived
/// as.
fn fold_batches(exponents: &[u32], syndromes: &mut [Vec<u16>], batches: &[FeedBatch]) {
    if syndromes.is_empty() {
        return;
    }
    let mut srcs: Vec<&[u8]> = Vec::new();
    let mut logs: Vec<u32> = Vec::new();
    for b in batches {
        for &(k, off, len) in &b.slices {
            srcs.push(&b.arena[off..off + len]);
            logs.push(k);
        }
    }
    if srcs.is_empty() {
        return;
    }
    fold_parallel(syndromes, &srcs, &|j, i| {
        gf16::pow2(logs[i] as u64 * exponents[j] as u64)
    });
}

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
    let cores = std::thread::available_parallelism().map_or(4, |n| n.get());
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
mod reconstruct;

pub use catalog::PacketCatalog;
use catalog::{Crit, RecLoc, SetReplay, load_selected_recovery};

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

/// Explicit inverse of the CONSECUTIVE-exponent repair matrix in O(m²),
/// via Lagrange basis polynomials - Gauss-Jordan is O(m³) and was the
/// true ceiling at extreme damage (0.55 s at m = 1400 even fanned out;
/// ~two minutes extrapolated at the m = 8192 repair cap).
///
/// With exponents e0..e0+m-1 the matrix factors: A[r][c] = g_c^{e0+r} =
/// g_c^{e0} · g_c^r, so A = V · diag(g_c^{e0}) with V[r][c] = g_c^r a
/// classic Vandermonde in the bases g_c = 2^{k_c}. V is the transpose of
/// the evaluation matrix whose inverse rows are the Lagrange basis
/// polynomials of the nodes, so
///
/// ```text
///     A⁻¹[c][r] = g_c^{-e0} · [z^r] L_c(z),
///     L_c(z) = Π_{k≠c}(z + g_k) / Π_{k≠c}(g_c + g_k)
/// ```
///
/// (char 2: subtraction is XOR). Build the master polynomial P(z) =
/// Π(z + g_c) once in O(m²); each column is then one synthetic division
/// P/(z + g_c), one Horner evaluation for the denominator, and one
/// scalar-vector scale - O(m) each, columns independent, so the whole
/// inverse is O(m²), which is optimal (it HAS m² entries). Everything is
/// exact field arithmetic: no conditioning concerns. `ks` are the base
/// logs k_c; distinct ks (guaranteed - they are distinct naturals
/// coprime to 65535) make V nonsingular ALWAYS, so this path cannot
/// fail; `None` is returned only on the theoretically-impossible
/// duplicate base, and the caller falls back to Gauss-Jordan.
fn invert_vandermonde(ks: &[u32], e0: u32) -> Option<Vec<Vec<u16>>> {
    let m = ks.len();
    let bases: Vec<u16> = ks.iter().map(|&k| gf16::pow2(k as u64)).collect();
    // P(z) = Π (z + g_c), degree m: p[i] is the z^i coefficient.
    let mut p = vec![0u16; m + 1];
    p[0] = 1;
    for (deg, &g) in bases.iter().enumerate() {
        // p ← p·(z + g): new[i] = old[i-1] + g·old[i], walked downward
        // so it runs in place.
        let t = MulTable::new(g);
        p[deg + 1] = p[deg];
        for i in (1..=deg).rev() {
            p[i] = p[i - 1] ^ t.mul(p[i]);
        }
        p[0] = t.mul(p[0]);
    }
    // Columns are independent - fan out for the big heavy-damage case.
    let threads = std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .min(m / 64)
        .max(1);
    let mut rows: Vec<Option<Vec<u16>>> = vec![None; m];
    let build_row = |c: usize| -> Option<Vec<u16>> {
        let g = bases[c];
        let t = MulTable::new(g);
        // Synthetic division: Q_c = P / (z + g), degree m-1.
        let mut q = vec![0u16; m];
        q[m - 1] = p[m];
        for i in (1..m).rev() {
            q[i - 1] = p[i] ^ t.mul(q[i]);
        }
        // Denominator d_c = Q_c(g) = Π_{k≠c}(g + g_k), by Horner.
        let mut d = 0u16;
        for &coef in q.iter().rev() {
            d = t.mul(d) ^ coef;
        }
        if d == 0 {
            return None; // duplicate base - cannot happen for valid ks
        }
        // Row c of A⁻¹: (g^{-e0} / d_c) · Q_c, one SIMD scalar-vector
        // product (xor into zeros = plain multiply).
        let neg_e0 = gf16::ORDER as u64 - (ks[c] as u64 * e0 as u64) % gf16::ORDER as u64;
        let scale = gf16::mul(gf16::inv(d), gf16::pow2(neg_e0));
        let mut row = vec![0u16; m];
        MulTable::new(scale).xor_mul_words(&mut row, &q);
        Some(row)
    };
    if threads < 2 {
        for (c, slot) in rows.iter_mut().enumerate() {
            *slot = build_row(c);
        }
    } else {
        let chunk = m.div_ceil(threads);
        std::thread::scope(|s| {
            for (w, slice) in rows.chunks_mut(chunk).enumerate() {
                let build_row = &build_row;
                s.spawn(move || {
                    for (i, slot) in slice.iter_mut().enumerate() {
                        *slot = build_row(w * chunk + i);
                    }
                });
            }
        });
    }
    rows.into_iter().collect()
}

/// Gauss-Jordan inversion over GF(2^16) (addition = XOR, so no sign
/// bookkeeping). Distinct bases and exponents make singularity
/// essentially theoretical, but a generalized Vandermonde over a finite
/// field carries no guarantee - the caller treats it as unrepairable
/// with this slice set.
///
/// Past [`PAR_INVERT_MIN`] rows the elimination fans out: the serial
/// loop is O(m²) split-table builds plus O(m³) field work on ONE thread,
/// and at heavy damage that was the single largest piece of the solve
/// (measured 1.9 s of a 6.3 s repair at m = 1400).
fn invert(a: Vec<Vec<u16>>) -> Result<Vec<Vec<u16>>, RepairError> {
    let m = a.len();
    // Each worker should own enough rows that a column's elimination
    // outweighs its two barrier crossings.
    let threads = std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .min(m / 32)
        .max(1);
    if m < PAR_INVERT_MIN || threads < 2 {
        return invert_serial(a);
    }
    invert_parallel(a, threads)
}

/// Below this the barrier choreography costs more than the elimination.
const PAR_INVERT_MIN: usize = 128;

/// The fan-out behind [`invert`]. Rows are dealt to workers round-robin
/// and NEVER move - pivoting is tracked as a permutation instead of the
/// serial path's row swaps, so every worker keeps `&mut` to its own rows
/// for the whole solve. Each column runs two barrier-separated phases:
/// scan (every worker offers its lowest eligible pivot row; atomic min
/// picks the winner), publish (the owner normalizes the pivot row and
/// copies it into a shared buffer), then every worker eliminates its own
/// rows against the copy. The published inverse is reassembled through
/// the pivot permutation at the end.
fn invert_parallel(mut a: Vec<Vec<u16>>, threads: usize) -> Result<Vec<Vec<u16>>, RepairError> {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let m = a.len();
    let mut inv: Vec<Vec<u16>> = (0..m)
        .map(|i| {
            let mut row = vec![0u16; m];
            row[i] = 1;
            row
        })
        .collect();
    // piv[col] = row index chosen as that column's pivot (usize::MAX =
    // none found = singular).
    let piv: Vec<AtomicUsize> = (0..m).map(|_| AtomicUsize::new(usize::MAX)).collect();
    let used: Vec<AtomicBool> = (0..m).map(|_| AtomicBool::new(false)).collect();
    let singular = AtomicBool::new(false);
    let pivot_rows = std::sync::RwLock::new((vec![0u16; m], vec![0u16; m]));
    let barrier = std::sync::Barrier::new(threads);
    let mut shards: Vec<Vec<(usize, &mut [u16], &mut [u16])>> =
        (0..threads).map(|_| Vec::new()).collect();
    for (r, (ar, ir)) in a.iter_mut().zip(inv.iter_mut()).enumerate() {
        shards[r % threads].push((r, ar.as_mut_slice(), ir.as_mut_slice()));
    }
    std::thread::scope(|s| {
        for shard in shards {
            let (piv, used, singular, pivot_rows, barrier) =
                (&piv, &used, &singular, &pivot_rows, &barrier);
            s.spawn(move || {
                let mut shard = shard;
                for col in 0..m {
                    // Scan: offer this shard's lowest unused row with a
                    // nonzero in the pivot column. Rows were dealt in
                    // ascending order, so the first hit is the lowest.
                    for (r, ar, _) in shard.iter() {
                        if !used[*r].load(Ordering::Relaxed) && ar[col] != 0 {
                            piv[col].fetch_min(*r, Ordering::AcqRel);
                            break;
                        }
                    }
                    barrier.wait();
                    let p = piv[col].load(Ordering::Acquire);
                    if p == usize::MAX {
                        // Every worker reads the same verdict right
                        // after the same barrier, so all of them leave
                        // on this column together.
                        singular.store(true, Ordering::Relaxed);
                        return;
                    }
                    if p % threads == shard[0].0 % threads {
                        // This shard owns the pivot row: normalize it
                        // and publish a copy for everyone to fold with.
                        used[p].store(true, Ordering::Relaxed);
                        let (_, ar, ir) = shard
                            .iter_mut()
                            .find(|(r, _, _)| *r == p)
                            .expect("owner shard holds the pivot row");
                        let f = gf16::inv(ar[col]);
                        if f != 1 {
                            for x in ar.iter_mut().chain(ir.iter_mut()) {
                                *x = gf16::mul(*x, f);
                            }
                        }
                        let mut g = pivot_rows.write_ok();
                        g.0.copy_from_slice(ar);
                        g.1.copy_from_slice(ir);
                    }
                    barrier.wait();
                    let g = pivot_rows.read_ok();
                    for (r, ar, ir) in shard.iter_mut() {
                        if *r == p {
                            continue;
                        }
                        let f = ar[col];
                        if f == 0 {
                            continue;
                        }
                        let t = MulTable::new(f);
                        t.xor_mul_words(ar, &g.0);
                        t.xor_mul_words(ir, &g.1);
                    }
                    // No third barrier: the next scan touches only this
                    // shard's rows and a fresh piv slot, and the next
                    // publisher's write lock can't be granted until every
                    // reader has dropped `g` at its next barrier.
                }
            });
        }
    });
    if singular.load(Ordering::Relaxed) {
        return Err(RepairError::SingularMatrix);
    }
    // inv[piv[col]] is column `col`'s row of A⁻¹.
    Ok(piv
        .into_iter()
        .map(|p| std::mem::take(&mut inv[p.into_inner()]))
        .collect())
}

fn invert_serial(mut a: Vec<Vec<u16>>) -> Result<Vec<Vec<u16>>, RepairError> {
    let m = a.len();
    let mut inv: Vec<Vec<u16>> = (0..m)
        .map(|i| {
            let mut row = vec![0u16; m];
            row[i] = 1;
            row
        })
        .collect();
    for col in 0..m {
        let piv = (col..m)
            .find(|&r| a[r][col] != 0)
            .ok_or(RepairError::SingularMatrix)?;
        a.swap(col, piv);
        inv.swap(col, piv);
        let f = gf16::inv(a[col][col]);
        if f != 1 {
            for x in a[col].iter_mut().chain(inv[col].iter_mut()) {
                *x = gf16::mul(*x, f);
            }
        }
        for r in 0..m {
            if r == col || a[r][col] == 0 {
                continue;
            }
            let f = a[r][col];
            let t = MulTable::new(f);
            let (arow, acol) = two_rows(&mut a, r, col);
            t.xor_mul_words(arow, acol);
            let (irow, icol) = two_rows(&mut inv, r, col);
            t.xor_mul_words(irow, icol);
        }
    }
    Ok(inv)
}

/// Disjoint (&mut rows[r], &rows[c]) - r ≠ c.
fn two_rows(rows: &mut [Vec<u16>], r: usize, c: usize) -> (&mut [u16], &[u16]) {
    debug_assert_ne!(r, c);
    if r < c {
        let (lo, hi) = rows.split_at_mut(c);
        (&mut lo[r], &hi[0])
    } else {
        let (lo, hi) = rows.split_at_mut(r);
        (&mut hi[0], &lo[c])
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
        return Err(RepairError::Malformed(format!(
            "{} recovery slice(s) for {} missing block(s)",
            by_exp.len(),
            missing.len()
        )));
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
        let readers = std::thread::available_parallelism()
            .map_or(4, |n| n.get())
            .min(8)
            .min(work.len())
            .max(1);
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
    let machine = std::thread::available_parallelism().map_or(4, |n| n.get());
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
                    // MD5 for the bytes this call just wrote, and for a set
                    // with no IFSC to check against; CRC32 per block for the
                    // rest. See the function docs.
                    let md5_this = full_verify
                        || rebuilt_files.contains(&fi)
                        || f.blocks.len() as u64 != f.length.div_ceil(bs);
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
                                        if f.blocks.get(bidx).map(|b| b.crc32)
                                            != Some(done.finalize())
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
                            if f.blocks.get(bidx).map(|b| b.crc32) != Some(padded) {
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
/// belongs to the destination filesystem, not to the binary.
fn path_identity_key(fold: bool, p: &Path) -> PathBuf {
    if fold {
        PathBuf::from(p.to_string_lossy().to_lowercase())
    } else {
        p.to_path_buf()
    }
}

/// [`path_identity_key`] for a declared file NAME, sanitized the way the
/// repair lands it. Same folding rule and the same reason.
fn name_identity_key(fold: bool, name: &str) -> String {
    let s = crate::disk::sanitize_filename(name);
    if fold { s.to_lowercase() } else { s }
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
    /// Destination names that more than one DISTINCT file descriptor
    /// claims across the whole directory. Targets with these names are
    /// disambiguated in EVERY set, so no two sets can land on one path.
    /// Two sets describing the SAME file (identical descriptor) are not
    /// contested - sharing that destination is correct.
    contested: HashSet<String>,
    /// Every name any set in the directory declares. Payload, whoever
    /// owns it, and so never a spent adoption donor to sweep.
    declared: HashSet<String>,
}

/// Files eligible as adoption sources: every regular non-.par2 file in
/// `dir` that is not an identified target (identified files' bytes are
/// already pinned block-by-block - scanning them again is the perf trap
/// this gate exists to avoid).
fn adoption_candidates(
    dir: &Path,
    targets: &[Target],
    exclude: &HashSet<PathBuf>,
) -> Result<Vec<(PathBuf, u64)>, RepairError> {
    // Keyed by filesystem identity, not by spelling: the PAR2-declared name
    // and the on-disk name routinely differ in case, and on a case-insensitive
    // volume an exact compare would hand an identified target's OWN file to
    // the sliding scan as an adoption source.
    let fold = crate::disk::case_insensitive_dir(dir);
    let identified: HashSet<PathBuf> = targets
        .iter()
        .filter(|t| t.exists && (t.intact || t.present.iter().any(|&p| p)))
        .map(|t| path_identity_key(fold, &t.path))
        .collect();
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let p = e.path();
        if !e.file_type()?.is_file()
            || p.extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("par2"))
            || identified.contains(&path_identity_key(fold, &p))
            || exclude.contains(&p)
        {
            continue;
        }
        let len = e.metadata()?.len();
        if len > 0 {
            out.push((p, len));
        }
    }
    out.sort();
    Ok(out)
}

// Extra-file adoption - the candidate walk, the whole-file fast path
// and the rolling-CRC sliding scan - lives in par2repair/adopt.rs, a
// child module (size gate, TODO 106), and fans out across candidates
// (R2 / N11).
mod adopt;

/// Reads adopted block bytes from candidate files, keeping each source
/// open across calls. Bytes past a candidate's end are the zero padding
/// the block checksum was verified against.
struct CandReader<'a> {
    cands: &'a [(PathBuf, u64)],
    open: HashMap<usize, File>,
}

impl CandReader<'_> {
    fn read(&mut self, s: AdoptSrc, take: usize) -> Result<Vec<u8>, RepairError> {
        let (path, len) = &self.cands[s.cand];
        let f = match self.open.entry(s.cand) {
            std::collections::hash_map::Entry::Occupied(o) => o.into_mut(),
            std::collections::hash_map::Entry::Vacant(v) => v.insert(File::open(path)?),
        };
        let avail = take.min(len.saturating_sub(s.offset) as usize);
        let mut v = vec![0u8; take];
        crate::disk::read_exact_at(f, &mut v[..avail], s.offset)?;
        Ok(v)
    }
}

// ---------------------------------------------------------------------------
// Directory-level driver
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct RepairReport {
    /// Input blocks reconstructed via Reed-Solomon.
    pub blocks_rebuilt: usize,
    /// Input blocks whose content was found intact under another name or
    /// offset by the extra-file adoption scan.
    pub blocks_adopted: usize,
    /// File names (as found on disk) that adopted blocks came from.
    pub adopted_from: Vec<String>,
    /// Files whose bytes were patched (includes created ones).
    pub files_patched: Vec<String>,
    /// Subset of `files_patched` that were missing entirely.
    pub files_created: Vec<String>,
    /// Full paths of the extra files this repair CONSUMED as adoption
    /// sources - obfuscated copies whose bytes now also exist under the
    /// name the PAR2 set gives them. The engine never deletes them (it
    /// does not own the directory), so a caller that DOES own it is told
    /// which files are now redundant; on an obfuscated post this is the
    /// difference between a finished folder and two copies of it.
    ///
    /// Recovery-set targets are excluded: a candidate can share a path
    /// with a target (exactly what `used_sources` forces through the
    /// temp+rename path below), and there the "source" IS the restored
    /// payload. Deleting it would undo the repair.
    pub consumed_sources: Vec<PathBuf>,
}

#[derive(Debug)]
pub enum RepairStatus {
    /// Every recovery-set file already verifies - nothing written.
    NoDamage,
    /// Damage found and repaired; every patched file re-verified by MD5.
    Repaired(RepairReport),
    /// Not enough recovery slices on disk for the damage found.
    Unrepairable { needed: usize, have: usize },
}

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

/// Ceiling on one packet file. Every consumer below reads a packet file
/// WHOLE (`std::fs::read`, because `scan_packets` walks a slice and
/// recovery slices are copied straight out of it), so this is the bound
/// on how much attacker-chosen input one directory entry can turn into
/// resident memory.
///
/// It applies by SIZE, never by name: the extension is chosen by the
/// poster, so letting `*.par2` past a bound that extensionless volumes
/// have to clear would make the bound optional - rename the file and it
/// is gone (Codex sweep 10 Aug, M4). A real recovery volume is orders of
/// magnitude under this; a file over it is either not a volume at all or
/// one no repair could afford to load.
pub const MAX_PACKET_FILE_BYTES: u64 = 1 << 30;

/// Gather the PAR2 packet files in `dir`: `*.par2` by name, plus
/// magic-sniffed files (obfuscated posts rename recovery volumes too, and
/// par2cmdline - handed extra files - loads packets from them, so do we).
/// Sniffing costs one 8-byte read per file. Oversized candidates are
/// skipped rather than slurped, by name and by sniff alike - see
/// [`MAX_PACKET_FILE_BYTES`]. Returns (sorted packet files, the subset
/// found by sniff rather than name).
fn collect_packet_files(dir: &Path) -> Result<(Vec<PathBuf>, HashSet<PathBuf>), RepairError> {
    collect_packet_files_bounded(dir, MAX_PACKET_FILE_BYTES)
}

/// [`collect_packet_files`] with the ceiling spelled out, so a test can
/// exercise the bound without writing a gigabyte.
fn collect_packet_files_bounded(
    dir: &Path,
    max_bytes: u64,
) -> Result<(Vec<PathBuf>, HashSet<PathBuf>), RepairError> {
    let mut packet_files: Vec<PathBuf> = Vec::new();
    let mut sniffed: HashSet<PathBuf> = HashSet::new();
    for e in std::fs::read_dir(dir)? {
        let Ok(e) = e else { continue };
        if !e.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        let p = e.path();
        let len = e.metadata().map(|m| m.len()).unwrap_or(u64::MAX);
        if p.extension()
            .is_some_and(|x| x.eq_ignore_ascii_case("par2"))
        {
            if len > max_bytes {
                warn!(
                    file = %p.display(),
                    bytes = len,
                    "skipping oversized .par2 - past the packet-file ceiling"
                );
                continue;
            }
            packet_files.push(p);
        } else if (64..=max_bytes).contains(&len) {
            let mut head = [0u8; 8];
            let ok = File::open(&p)
                .and_then(|mut f| f.read_exact(&mut head))
                .is_ok();
            if ok && &head == par2::MAGIC {
                sniffed.insert(p.clone());
                packet_files.push(p);
            }
        }
    }
    packet_files.sort();
    Ok((packet_files, sniffed))
}

/// The PAR2 packet files in `dir` that only a content sniff could find:
/// recovery volumes an obfuscated post shipped under an extensionless
/// hash name.
///
/// Deliberately NOT the whole packet set. Files named `*.par2` are
/// already swept by extension wherever that matters; these are the ones
/// no extension rule can ever match, which is why a finished obfuscated
/// download kept its spent recovery set forever (issue #9).
///
/// Directory-wide, so it says nothing about which recovery SET a volume
/// served. A caller holding more than one set must not act on this until
/// every set it cares about has verified.
pub fn sniffed_packet_files(dir: &Path) -> Result<Vec<PathBuf>, RepairError> {
    let (_, sniffed) = collect_packet_files(dir)?;
    let mut out: Vec<PathBuf> = sniffed.into_iter().collect();
    out.sort();
    Ok(out)
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
    // Which descriptors claim each destination name, directory-wide.
    // A name claimed by two DIFFERENT descriptors is one destination
    // holding two different files; a name claimed by one descriptor in
    // two sets is the same file described twice, which is fine.
    let mut claims: HashMap<String, HashSet<([u8; 16], u64, [u8; 16])>> = HashMap::new();
    for (_, occ) in cat.walk() {
        names.entry(occ.set_id).or_insert_with(|| {
            order.push(occ.set_id);
            Vec::new()
        });
        if let Some(Crit::FileDesc(fid, d)) = cat.crit(&occ.md5) {
            claims
                .entry(name_identity_key(fold, &d.name))
                .or_default()
                .insert((*fid, d.length, d.md5));
            names.get_mut(&occ.set_id).unwrap().push(d.name.clone());
        }
    }
    let ctx = DirContext {
        contested: claims
            .iter()
            .filter(|(_, who)| who.len() > 1)
            .map(|(k, _)| k.clone())
            .collect(),
        declared: claims.into_keys().collect(),
    };
    let mut out = Vec::new();
    for id in &order {
        let present = names[id]
            .iter()
            .any(|n| dir.join(crate::disk::sanitize_filename(n)).is_file());
        if present {
            out.push(SetOutcome {
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
        let has_candidates = std::fs::read_dir(dir)?.flatten().any(|e| {
            e.file_type().is_ok_and(|t| t.is_file()) && !packet_set.contains(e.path().as_path())
        });
        if has_candidates {
            for id in &order {
                out.push(SetOutcome {
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
        // A disagreeing IFSC packet is DROPPED, not fatal - `par2.rs` handles
        // the identical case the same way, for the same reason: an empty
        // `blocks` routes the file to the whole-file MD5, which covers every
        // byte. Failing the call instead abandoned every other file in the
        // set (19 repairable files lost to one malformed packet) when the
        // recovery blocks to fix them were sitting right there.
        let blocks = replay
            .ifscs
            .remove(fid)
            .filter(|b| b.len() == n_slices)
            .unwrap_or_default();
        // Wire-supplied names never touch the filesystem raw.
        let path = dir.join(crate::disk::sanitize_filename(&d.name));
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
                let mut alt = t.path.clone().into_os_string();
                alt.push(tag);
                let alt = PathBuf::from(alt);
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
    for loc in &rec_locs {
        if loc.len as usize == bs {
            by_exp.entry(loc.exp).or_insert(*loc);
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
    let (mut cands, mut adopted) =
        if !missing.is_empty() && (any_unidentified || missing.len() > by_exp.len()) {
            adopt::adopt_blocks(dir, &targets, &missing, bs, &sniffed)?
        } else {
            (Vec::new(), HashMap::new())
        };
    // Adopted slices are found, not missing - only the rest needs RS.
    let mut missing: Vec<usize> = missing
        .into_iter()
        .filter(|g| !adopted.contains_key(g))
        .collect();

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
            adopt::sliding_scan(&cands, &indices, &targets, &missing_set, bs, &mut adopted)?;
            missing.retain(|g| !adopted.contains_key(g));
        }
    }
    mark("adoption");
    let cands = cands;
    let adopted = adopted;
    let missing = missing;
    let mut cand_reader = CandReader {
        cands: &cands,
        open: HashMap::new(),
    };

    let needed = missing.len();
    if by_exp.len() < needed {
        return Ok(RepairStatus::Unrepairable {
            needed,
            have: by_exp.len(),
        });
    }
    let recovery = if needed > 0 {
        match load_selected_recovery(cat, &mut by_exp, needed, bs, !fresh)? {
            Some(loaded) => loaded,
            // Re-proof at pread dropped enough mutated packets to fall
            // short - the same verdict a fresh scan of the changed file
            // would have reached.
            None => {
                return Ok(RepairStatus::Unrepairable {
                    needed,
                    have: by_exp.len(),
                });
            }
        }
    } else {
        Vec::new()
    };
    mark("load recovery");

    // --- syndrome pass: stream every present slice once ---
    let blocks_rebuilt = missing.len();
    let rebuilt: Vec<Vec<u8>> = if blocks_rebuilt > 0 {
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
            let readers = std::thread::available_parallelism()
                .map_or(4, |n| n.get())
                .min(8)
                .min(work.len())
                .max(1);
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
                let take = bs.min(cands[ci].1.saturating_sub(off) as usize);
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
    let mut adopted_from: Vec<String> = adopted
        .values()
        .map(|s| {
            cands[s.cand]
                .0
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        })
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    adopted_from.sort();
    // Which candidates donated anything. Turning these into whole paths
    // the CALLER may delete needs a proof about every byte of the file,
    // not just the window that matched, so it waits until after the
    // final verify (see `spent_donors` below).
    let donors: HashSet<usize> = adopted.values().map(|s| s.cand).collect();
    let mut report = RepairReport {
        blocks_rebuilt,
        blocks_adopted: adopted.len(),
        adopted_from,
        files_patched: Vec::new(),
        files_created: Vec::new(),
        consumed_sources: Vec::new(),
    };
    let rebuilt_of: HashMap<usize, usize> =
        missing.iter().enumerate().map(|(mi, &g)| (g, mi)).collect();
    let mut damaged: Vec<usize> = needs_resize;
    for (ti, t) in targets.iter().enumerate() {
        if !t.present.iter().all(|&p| p) && !damaged.contains(&ti) {
            damaged.push(ti);
        }
    }
    damaged.sort_unstable();

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
        let identified = t.exists && (t.intact || t.present.iter().any(|&p| p));
        let via_temp = !identified || used_sources.contains(&path_identity_key(fold, &t.path));
        // In temp mode verified blocks are copied over from the old
        // file; in place they're already where they belong.
        let write_blocks = |f: &File,
                            cand_reader: &mut CandReader,
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
            let mut made = None;
            for n in 0..1024 {
                let candidate = t
                    .path
                    .with_file_name(format!(".{base}.nzbfast-repair.{n}.tmp"));
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
            let res = write_blocks(&tmp_file, &mut cand_reader, true);
            if let Err(e) = res {
                cleanup(&renames, Some(&tmp));
                return Err(e);
            }
            checks.push((tmp.clone(), ti, false));
            renames.push((tmp, ti));
        }
    }
    mark("patch");
    // Whole-file MD5 for everything written - files are independent, so
    // verify across threads.
    if !checks.is_empty() {
        let machine = std::thread::available_parallelism().map_or(4, |n| n.get());
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
        for ((_, ti, _), r) in checks.iter().zip(results) {
            match r.expect("verify worker filled every slot") {
                Ok(true) => {}
                Ok(false) => {
                    cleanup(&renames, None);
                    return Err(RepairError::VerifyFailed(targets[*ti].file.name.clone()));
                }
                Err(e) => {
                    cleanup(&renames, None);
                    return Err(e);
                }
            }
        }
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
    for ci in donors {
        let (p, len) = &cands[ci];
        if target_keys.contains(&path_identity_key(fold, p))
            || p.file_name()
                .map(|n| name_identity_key(fold, &n.to_string_lossy()))
                .is_some_and(|n| declared_names.contains(&n))
        {
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
        }
    }
    spent_donors.sort();
    report.consumed_sources = spent_donors;
    // Every adopted read and every verify is done - land the rebuilds.
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
        std::fs::rename(&tmp, &t.path)?;
        report.files_patched.push(t.file.name.clone());
        if !t.exists {
            report.files_created.push(t.file.name.clone());
        }
    }
    Ok(RepairStatus::Repaired(report))
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
                            let take = ((avail - p) as usize).min(buf.len());
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
                        *ok = blocks.get(bidx).is_some_and(|c| c.crc32 == crc_val);
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
        let take = ((limit - pos) as usize).min(buf.len());
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
                        .is_some_and(|check| done.finalize() == check.crc32);
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
                ok[bidx] = padded == check.crc32;
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
    let machine = std::thread::available_parallelism().map_or(4, |n| n.get());
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
