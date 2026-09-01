//! The GF(2^16) linear algebra the repair runs on: folding present
//! slices into syndromes, and inverting the repair matrix.
//!
//! One subject, and the pairing is already in the tree - [`bench_fold`]
//! and [`bench_invert`] are the two benchmark doors this crate exposes,
//! one per half, and `examples/par2_fold_bench.rs` drives both. Neither
//! half opens a file, parses a packet or knows what a recovery set is:
//! they take buffers and exponents and return words.
//!
//! What is NOT here, deliberately: WHICH engine computes the syndromes
//! (the NTT gates, the divergence probe and the fallback) stays in the
//! parent. That is a policy question about budgets, environment and
//! trust, answered before any arithmetic runs, and it reads the fold
//! below as one of its two outcomes.
//!
//! Split out of par2repair.rs for the size gate (TODO 106);
//! `par2repair::bench_fold` and `bench_invert` are re-exported, so the
//! three examples that drive them spell no new path.

use crate::gf16::{self, FoldTable, MulTable};
use crate::sync::{MutexExt, RwLockExt};

use super::RepairError;

pub(super) fn fold_chunk_tiled(
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
pub(super) const TABLE_BUDGET: usize = 2 << 20;
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
pub(super) fn physical_cores() -> Option<usize> {
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

/// `pub(crate)` for `par2gen`: building a RECOVERY slice is the same
/// linear algebra as building a syndrome - `R_e = Σ_i g_i^e · D_i`
/// against `S_j = Σ_i g_i^{e_j} · D_i` - so the creator folds through
/// this routine rather than growing a second spelling of it beside
/// `par2gen::recovery_slices`. Two implementations of one fold is how a
/// creator and a repairer part company over a coefficient.
pub(crate) fn fold_parallel(
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
    let cores = crate::mem::cpu_workers().max(1);
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
pub(super) struct FeedBatch {
    pub(super) arena: Vec<u8>,
    /// (base log k, arena offset, len) per slice.
    pub(super) slices: Vec<(u32, usize, usize)>,
    /// Memory-floor gauge (memgauge::Sub::RepairWork), grown as bytes
    /// land in the arena and released when the batch drops - so batches
    /// queued in the channel, merged for a fold, and NTT-retained all
    /// stay attributed wherever they travel. Charged by LEN, not
    /// capacity: a fresh 64 MB arena's untouched pages are not resident,
    /// and the ram cost tracks the bytes actually written.
    charge: crate::memgauge::Charge,
}

impl FeedBatch {
    pub(super) fn with_capacity(bytes: usize) -> FeedBatch {
        FeedBatch {
            arena: Vec::with_capacity(bytes),
            slices: Vec::new(),
            charge: crate::memgauge::Charge::new(crate::memgauge::Sub::RepairWork, 0),
        }
    }

    pub(super) fn push(&mut self, k: u32, data: &[u8]) {
        let off = self.arena.len();
        self.arena.extend_from_slice(data);
        self.slices.push((k, off, data.len()));
        self.charge.grow(data.len() as u64);
    }
}

/// Fold queued batches of present slices into every syndrome row - one
/// row sweep for the whole set, however many feeder batches it arrived
/// as.
pub(super) fn fold_batches(exponents: &[u32], syndromes: &mut [Vec<u16>], batches: &[FeedBatch]) {
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
pub(super) fn invert_vandermonde(ks: &[u32], e0: u32) -> Option<Vec<Vec<u16>>> {
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
    let threads = crate::mem::cpu_workers().min(m / 64).max(1);
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
pub(super) fn invert(a: Vec<Vec<u16>>) -> Result<Vec<Vec<u16>>, RepairError> {
    let m = a.len();
    // Each worker should own enough rows that a column's elimination
    // outweighs its two barrier crossings.
    let threads = crate::mem::cpu_workers().min(m / 32).max(1);
    if m < PAR_INVERT_MIN || threads < 2 {
        return invert_serial(a);
    }
    invert_parallel(a, threads)
}

/// Below this the barrier choreography costs more than the elimination.
pub(super) const PAR_INVERT_MIN: usize = 128;

/// The fan-out behind [`invert`]. Rows are dealt to workers round-robin
/// and NEVER move - pivoting is tracked as a permutation instead of the
/// serial path's row swaps, so every worker keeps `&mut` to its own rows
/// for the whole solve. Each column runs two barrier-separated phases:
/// scan (every worker offers its lowest eligible pivot row; atomic min
/// picks the winner), publish (the owner normalizes the pivot row and
/// copies it into a shared buffer), then every worker eliminates its own
/// rows against the copy. The published inverse is reassembled through
/// the pivot permutation at the end.
pub(super) fn invert_parallel(
    mut a: Vec<Vec<u16>>,
    threads: usize,
) -> Result<Vec<Vec<u16>>, RepairError> {
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

pub(super) fn invert_serial(mut a: Vec<Vec<u16>>) -> Result<Vec<Vec<u16>>, RepairError> {
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
