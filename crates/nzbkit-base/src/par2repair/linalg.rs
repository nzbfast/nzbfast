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

#[cfg(test)]
pub(super) fn fold_chunk_tiled(
    dsts: &mut [&mut [u16]],
    srcs: &[&[u8]],
    coeff: &(dyn Fn(usize, usize) -> u16 + Sync),
    row_base: usize,
    tile_words: usize,
    table_budget: usize,
) {
    fold_chunk_tiled_prepared(
        dsts,
        srcs,
        coeff,
        row_base,
        tile_words,
        table_budget,
        false,
        None,
    )
}

/// The coefficient tables of one fold call, `rows x sources` in row-major
/// order, built ONCE per call and shared by every column unit. Without it
/// each unit rebuilt the tables for its rows x sources: with 16 sources
/// per window and 256 rows of 4 MiB the column split made 2,000 units per
/// window, 230 million table builds per 10 GiB create (~11 CPU-seconds).
struct CoeffTable<'a> {
    table: &'a [gf16::FoldCoeff],
    stride: usize,
}

#[allow(clippy::too_many_arguments)]
fn fold_chunk_tiled_prepared(
    dsts: &mut [&mut [u16]],
    srcs: &[&[u8]],
    coeff: &(dyn Fn(usize, usize) -> u16 + Sync),
    row_base: usize,
    tile_words: usize,
    table_budget: usize,
    prepacked: bool,
    prepared: Option<CoeffTable<'_>>,
) {
    if dsts.is_empty() || srcs.is_empty() {
        return;
    }
    if gf16::multi_fold_width() > 0 {
        return fold_chunk_multi(dsts, srcs, coeff, row_base, tile_words, prepacked, prepared);
    }
    assert!(!prepacked, "prepacked sources need the fused kernel");
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
    let tile_words = (l2_target_words() / dsts.len()).clamp(MIN_TILE_WORDS.min(ceiling), ceiling);
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
    prepacked: bool,
    prepared: Option<CoeffTable<'_>>,
) {
    let fan_in = gf16::multi_fold_width();
    let width = fan_in.min(16);
    let words = dsts[0].len();
    debug_assert!(dsts.iter().all(|d| d.len() == words));
    // Same residency math as the table path (a tile is walked across
    // every row this thread owns), with one extra constraint: a multiple
    // of the SELECTED kernel's destination granule, so the fused kernel
    // covers whole tiles and the per-source remainder path stays out of
    // the steady state. That is 16 words everywhere except the 512-bit
    // GFNI arm, which eats 32 - see the granule table on
    // `gf16::multi_fold_schedule_granule_words`; flooring to 16 there
    // left every tile one half-chunk short.
    //
    // A caller whose explicit ceiling is BELOW the granule keeps the
    // 16-word schedule and the kernel's own reported tail, because
    // rounding a ceiling up would widen the L2 footprint the ceiling
    // exists to bound. Only the tests pass such a tile; production passes
    // TILE_WORDS and floors at MIN_TILE_WORDS, so it cannot reach it.
    let granule = gf16::multi_fold_schedule_granule_words(fan_in);
    let granule = if tile_words >= granule { granule } else { 16 };
    let ceiling = tile_words.max(granule);
    let tile_words = ((l2_target_words() / dsts.len()).clamp(MIN_TILE_WORDS.min(ceiling), ceiling))
        & !(granule - 1);
    let tile_words = tile_words.max(granule);
    // Packed sources are planar per 64 bytes, so every tile edge must
    // sit on one: 32-word tiles, and a fan-in of at most four.
    let tile_words = if prepacked {
        tile_words & !31
    } else {
        tile_words
    };
    let width = if prepacked { width.min(4) } else { width };
    debug_assert!(!prepacked || (tile_words >= 32 && srcs.iter().all(|s| s.len() == words * 2)));
    // Coefficients hoisted per (row, group) sweep, exactly as the table
    // path hoists them - and PREPARED here, once per sweep, so the x86
    // nibble kernels do not rebuild their tables per (row, tile) call:
    // at the 4 KiB tiles a dense m x m back-substitution walks, that
    // build was about a fifth of every call (`gf16::FoldCoeff`). Zero
    // coefficients ride along (a pmull by zero contributes nothing and
    // they are far too rare to branch on).
    let mut coeffs: Vec<gf16::FoldCoeff> = Vec::with_capacity(dsts.len() * width);
    // Eight rows or more: the split pays back over rows (see
    // `gf16::PreparedSources`); under that the interleaved kernel wins.
    let use_planar = dsts.len() >= 8 && gf16::PreparedSources::enabled();
    let mut packed_sources = gf16::PreparedSources::default();
    let mut g0 = 0usize;
    while g0 < srcs.len() {
        let g1 = (g0 + width).min(srcs.len());
        coeffs.clear();
        if prepared.is_none() {
            for j in 0..dsts.len() {
                for i in g0..g1 {
                    coeffs.push(gf16::FoldCoeff::new(coeff(row_base + j, i)));
                }
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
            let packed = !prepacked && use_planar && n > 0 && packed_sources.prepare(&full[..n]);
            debug_assert!(!prepacked || np == 0, "a packed source is always whole");
            for (j, d) in dsts.iter_mut().enumerate() {
                let dtile = &mut d[w0..w1];
                let row: &[gf16::FoldCoeff] = match &prepared {
                    Some(t) => {
                        &t.table[(row_base + j) * t.stride + g0..(row_base + j) * t.stride + g1]
                    }
                    None => &coeffs[j * (g1 - g0)..(j + 1) * (g1 - g0)],
                };
                if n > 0 {
                    let mut gc: [&gf16::FoldCoeff; 16] = [&row[0]; 16];
                    for (k, &gi) in full_idx[..n].iter().enumerate() {
                        gc[k] = &row[gi];
                    }
                    let done = if prepacked {
                        gf16::xor_mul_multi_planar_prepacked(dtile, &full[..n], &gc[..n])
                    } else if packed && !gc[..n].iter().all(|c| c.coeff() == 1) {
                        packed_sources.fold(dtile, &gc[..n])
                    } else {
                        gf16::xor_mul_multi_prepared(dtile, &full[..n], &gc[..n])
                    };
                    debug_assert!(!prepacked || done == dtile.len(), "packed tiles are whole");
                    if done < dtile.len() {
                        // Only a non-32-byte-aligned FINAL tile lands here.
                        for (s, c) in full[..n].iter().zip(&gc[..n]) {
                            if c.coeff() != 0 {
                                FoldTable::new(c.coeff())
                                    .xor_mul_into(&mut dtile[done..], &s[done * 2..]);
                            }
                        }
                    }
                }
                for &(gi, s) in &partial[..np] {
                    let c = row[gi].coeff();
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
/// the source tile and the split tables beside it) ON THE PART IT WAS
/// SIZED ON (an i7-1280P, 1.25 MB of L2 per P-core); a Skylake-class
/// desktop has 256 KB, and there a 3-row fold at 1 MiB blocks holds
/// 300-600 KB of destination plus source tile per group and streams it
/// from L3 - 14 GB/s all-core against 60-90 in the fold bench
/// (i5-10600KF, 4 Sep 2026). `NZBFAST_FOLD_L2` (bytes) sweeps it.
///
/// THE SWEEP, `feed+fold+solve` on the 1 GiB rig, one binary and four
/// settings, 4 Sep 2026: the i5 (256 KB L2) wants a SMALL budget - at
/// 32 KiB its 3-block fold 239 -> 221-224 ms and its 101-block fold
/// 1,420-1,460 -> 1,320-1,340 (the leg that tied turbo becomes a 5-8%
/// win) - while the Zen 4 EPYC (1 MB L2) reads flat natively and
/// ~10% WORSE below 512 KiB on its forced-AVX2 arm, and the M3 Ultra
/// (16 MB shared) is flat at every setting. So the budget follows the
/// part's L2: [`L2_TARGET_WORDS_SMALL_L2`] on a core with 512 KB or less
/// (Skylake through Comet Lake, Zen 1-2), this constant everywhere else
/// and wherever the probe cannot answer.
///
/// **AND IT IS NOT `L2 / ASSOCIATIVITY`, WHICH WAS MEASURED AND LOST.**
/// par2j sizes its chunk to one way-slice of L2
/// (`cache2_size / cache2_associativity`, floor 64 KB) and exposes it as
/// `/lcb`, so the obvious move is to copy the rule and read
/// associativity from the OS - Windows hands it to us in the buffer
/// `l2_per_core_bytes` already walks. Do not: the rule LOSES on both
/// parts where this budget bites, and the arm is already in the sweep
/// above rather than needing a new round.
///
/// - **The denominator does not match.** par2j's `chunk_size` bounds ONE
///   (row, chunk) destination tile - its work grid is chunk x lost-block
///   and a worker holds a single row. This constant is a budget shared
///   across ALL the rows a thread owns: the tile is
///   `l2_target_words / dsts.len()`. Applying a per-tile rule to a
///   per-thread aggregate over-constrains it by the row count, so the
///   two numbers are not the same quantity and copying one into the
///   other is a category error before it is a performance question.
/// - **i5-10600KF: 256 KB L2, 4-way, so the rule asks for 64 KiB - and
///   64 KiB IS AN ARM OF THE SWEEP ABOVE.** It read 250 / 235 ms on the
///   3-block leg and 1,340 / 1,370 on the 101-block, against 32 KiB's
///   221 / 224 and 1,320 / 1,340. It loses on both legs, and on the
///   3-block leg it is no better than the 512 KiB it would replace.
///   par2j's own 64 KB floor means its rule cannot even reach the 32 KiB
///   that actually won this part.
/// - **Zen 4 EPYC: 1 MB L2, 8-way, so the rule asks for 128 KiB**, and
///   the sweep reads ~10% WORSE anywhere below 512 KiB on its
///   forced-AVX2 arm.
/// - **M3 Ultra: flat at every setting**, and macOS exposes no L2
///   associativity OID at all, so the rule is unavailable as well as
///   unmotivated there.
///
/// So on every part in the fleet the rule either loses or cannot be
/// evaluated, and NO associativity query is added - which also avoids a
/// third repeat of the musl gap documented in `l2_per_core_bytes`.
/// Full verdict, and the same treatment of par2j's `src_max`:
/// `research/FOLD-CACHE-GEOMETRY-2026-09-10.md`.
const L2_TARGET_WORDS: usize = (512 << 10) / 2;
/// The budget on a part with at most [`SMALL_L2_BYTES`] of L2 per core.
const L2_TARGET_WORDS_SMALL_L2: usize = (32 << 10) / 2;
/// A per-core L2 at or under this takes the small budget.
const SMALL_L2_BYTES: usize = 512 << 10;

/// The tile budget this process runs under: `NZBFAST_FOLD_L2` (bytes) if
/// set, else the constant the part's L2 selects. Read once.
fn l2_target_words() -> usize {
    static W: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *W.get_or_init(|| {
        if let Some(b) = std::env::var("NZBFAST_FOLD_L2")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&b| b >= 8 << 10)
        {
            return b / 2;
        }
        let l2 = l2_per_core_bytes();
        let words = match l2 {
            Some(l2) if l2 <= SMALL_L2_BYTES => L2_TARGET_WORDS_SMALL_L2,
            _ => L2_TARGET_WORDS,
        };
        // Once per process, on the timing channel: which geometry the
        // fold decided on, so a round's log carries it.
        tracing::info!(
            target: "repair-timing",
            "fold tile budget {} KiB (L2 per core {})",
            words * 2 / 1024,
            l2.map_or("unknown".to_string(), |b| format!("{} KiB", b / 1024))
        );
        words
    })
}

/// The work unit's destination slab budget on x86 (`fold_parallel`'s
/// row grid): 512 KiB on the part it was sized on (the i7-1280P,
/// 1.25 MB of L2 per P-core) and everywhere the probe cannot answer,
/// HALF THE L2 on a part with [`SMALL_L2_BYTES`] or less - 128 KiB on
/// the i5-10600KF's 256 KB. The inner tile already followed the L2 (the
/// `l2_target_words` sweep, 4 Sep 2026); the outer unit did not, and
/// the review's cache-geometry pass on the i5 (5 Sep 2026, fresh-hotpaths
/// worktree, `NZBFAST_FOLD_UNIT_DST=131072` against the same binary's
/// default, four scored calls per arm) read the 1 GiB / 21-member
/// create -4.0% at 1 MiB, -9.7% at 2 MiB and -7.5% at 4 MiB, the
/// 101-block repair -3.0%, with CPU down 4-8%: at 103 rows the default
/// unit is a ~498 KiB slab on a 256 KB L2, so every worker streamed
/// its destination from L3. 256 KiB was a -2% arm there, so the rule is
/// half the L2 rather than a second constant, and the row grid's
/// worker count is untouched (the units only get smaller). Read once.
#[cfg(target_arch = "x86_64")]
fn unit_dst_budget() -> usize {
    const UNIT_DST_BUDGET: usize = 512 << 10;
    const UNIT_DST_FLOOR: usize = 64 << 10;
    static B: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *B.get_or_init(|| {
        let l2 = l2_per_core_bytes();
        let bytes = match l2 {
            Some(l2) if l2 <= SMALL_L2_BYTES => (l2 / 2).max(UNIT_DST_FLOOR),
            _ => UNIT_DST_BUDGET,
        };
        tracing::info!(
            target: "repair-timing",
            "fold unit dst budget {} KiB (L2 per core {})",
            bytes / 1024,
            l2.map_or("unknown".to_string(), |b| format!("{} KiB", b / 1024))
        );
        bytes
    })
}

/// The largest level-2 data cache one core owns, in bytes; `None` where
/// the platform cannot say (the default budget then applies). On a
/// hybrid part the P-core's L2 is the answer - the fold runs on physical
/// cores and the E-cluster's shared L2 is the smaller of the two only
/// per core, not per cluster.
///
/// `pub(crate)` so a bench can print what the fold decided on.
pub(crate) fn l2_per_core_bytes() -> Option<usize> {
    #[cfg(windows)]
    {
        // SAFETY: declaration matches the documented kernel32 ABI, as
        // `physical_cores` declares it.
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetLogicalProcessorInformationEx(rel: u32, buf: *mut u8, len: *mut u32) -> i32;
        }
        const RELATION_CACHE: u32 = 2;
        // SAFETY: the documented two-call protocol; record parsing stays
        // inside `len` via the `off + 20 <= len` bound (a cache record's
        // Level/Associativity/LineSize/CacheSize/Type all sit within the
        // first 20 bytes of the union) and the `size < 8` rejection.
        unsafe {
            let mut len: u32 = 0;
            GetLogicalProcessorInformationEx(RELATION_CACHE, std::ptr::null_mut(), &mut len);
            if len < 8 {
                return None;
            }
            let mut buf = vec![0u8; len as usize];
            if GetLogicalProcessorInformationEx(RELATION_CACHE, buf.as_mut_ptr(), &mut len) == 0 {
                return None;
            }
            let mut best: Option<usize> = None;
            let mut off = 0usize;
            while off + 20 <= len as usize {
                let size = u32::from_le_bytes(buf[off + 4..off + 8].try_into().unwrap()) as usize;
                if size < 8 {
                    return None;
                }
                let level = buf[off + 8];
                let cache =
                    u32::from_le_bytes(buf[off + 12..off + 16].try_into().unwrap()) as usize;
                // Type 0 = unified, 1 = instruction, 2 = data, 3 = trace.
                let ty = u32::from_le_bytes(buf[off + 16..off + 20].try_into().unwrap());
                if level == 2 && (ty == 0 || ty == 2) && cache > 0 {
                    best = Some(best.map_or(cache, |b| b.max(cache)));
                }
                off += size;
            }
            best
        }
    }
    // GNU ONLY, and the axis is the C library rather than the
    // architecture: `libc` declares `_SC_LEVEL2_CACHE_SIZE` in its
    // linux-gnu and android modules and nowhere else, so a musl target
    // does not compile against it at all. That took nightly's
    // `armv7-cross` job red from the moment the L2-derived unit budget
    // landed (5 Sep 2026) - it builds
    // `armv7-unknown-linux-musleabihf`, and nothing else in the fleet
    // compiles a non-gnu Linux target, so no per-push gate could see it.
    // musl is not merely missing the constant either: it does not
    // implement the `_SC_LEVEL*_CACHE_*` queries, so `None` (the default
    // budget) is the honest answer there rather than a number to go
    // hunting for through /sys.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        // SAFETY: sysconf takes a name and returns a long; no memory is
        // shared with it.
        let v = unsafe { libc::sysconf(libc::_SC_LEVEL2_CACHE_SIZE) };
        (v > 0).then_some(v as usize)
    }
    #[cfg(all(target_os = "linux", not(target_env = "gnu")))]
    {
        None
    }
    #[cfg(target_os = "macos")]
    {
        /// One integer sysctl by name, `None` when the OID does not
        /// exist on this part (which is how the Apple-silicon probe
        /// below detects an Intel Mac).
        ///
        /// THE WIDTH IS NOT UNIFORM ACROSS THESE OIDs and the caller
        /// must not assume it: measured on an M3 Ultra, `hw.l2cachesize`
        /// answers 8 bytes while `hw.perflevel0.l2cachesize` and
        /// `hw.perflevel0.physicalcpu` answer 4. Passing 8 for a 4-byte
        /// OID happens to read correctly on a little-endian host with a
        /// zeroed buffer - the kernel writes the low half and updates
        /// `n` - which is precisely the kind of accident that holds
        /// until it does not, so decode off the length the kernel
        /// reports instead of relying on it.
        fn sysctl_uint(name: &std::ffi::CStr) -> Option<u64> {
            let mut buf = [0u8; 8];
            let mut n = buf.len();
            // SAFETY: the documented sysctlbyname ABI - `n` carries the
            // buffer size in and the written length out, and the buffer
            // is 8 bytes, the widest of these OIDs.
            let r = unsafe {
                libc::sysctlbyname(
                    name.as_ptr(),
                    buf.as_mut_ptr().cast(),
                    &mut n,
                    std::ptr::null_mut(),
                    0,
                )
            };
            if r != 0 {
                return None;
            }
            let v = match n {
                4 => u32::from_ne_bytes(buf[..4].try_into().ok()?) as u64,
                8 => u64::from_ne_bytes(buf),
                _ => return None,
            };
            (v > 0).then_some(v)
        }
        // APPLE SILICON REPORTS THE WRONG CLUSTER THROUGH
        // `hw.l2cachesize`, AND THIS FUNCTION WANTS THE OTHER ONE.
        // L2 there is shared per CLUSTER, and the flat OID answers with
        // the EFFICIENCY cluster: on an M3 Ultra `hw.l2cachesize` is
        // 4 MiB (the E-cluster, 8 cores) while `hw.perflevel0.*` is
        // 16 MiB over 24 P-cores. The doc comment above asks for the
        // P-core's, because the fold runs on physical performance
        // cores - so read the perflevel OIDs and divide by the cores
        // that actually share the cache (699 KiB per P-core on an
        // M3 Ultra, against the 4 MiB cluster figure this replaces).
        //
        // SHIPPED BEHAVIOUR IS UNCHANGED, and the bound is exact rather
        // than hopeful: both consumers (`l2_target_words`,
        // `unit_dst_budget`) use this value ONLY through the
        // `<= SMALL_L2_BYTES` comparison, so the two readings can only
        // diverge on a part where one is at or under 512 KiB and the
        // other is over. Verified equal on the M3 Ultra (4 MiB and
        // 699 KiB are both over). The correction is landed for the next
        // lane rather than this one: any geometry-DERIVED arithmetic -
        // which is exactly what the par2j cache-hierarchy study
        // proposes - would compute off a figure that is out by 4x and
        // names the wrong core type.
        //
        // Intel Macs have no perflevel OIDs (no hybrid topology and an
        // unshared per-core L2), so they fall through to the flat
        // `hw.l2cachesize`, which is already per-core there.
        let apple = sysctl_uint(c"hw.perflevel0.l2cachesize").and_then(|l2| {
            sysctl_uint(c"hw.perflevel0.physicalcpu").map(|n| (l2 / n.max(1)) as usize)
        });
        apple.or_else(|| sysctl_uint(c"hw.l2cachesize").map(|v| v as usize))
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        None
    }
}
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
    fold_parallel(dsts, srcs, coeff, None);
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

/// Bench hook: ONE back-substitution at the caller's shape, either
/// solve, with setup and solve timed apart - the door
/// `examples/par2_fold_bench.rs` races the dense `m x m` product against
/// the transform route through (audit section 20). `ks` are the missing
/// columns' base logs and `e0` the first recovery exponent, exactly as
/// [`super::Reconstructor`] passes them; `syn` is one row per recovery
/// slice. Returns `(setup seconds, solve seconds, checksum)`; the
/// checksum touches every rebuilt row so nothing folds away. Not part of
/// the supported API.
///
/// Setup is timed separately because it is not the same work on the two
/// paths and the difference is not small: the dense route builds the m²
/// explicit inverse (134 MB and 62 ms at the repair cap), the transform
/// route builds only the master polynomial and its coefficient tables.
#[doc(hidden)]
pub fn bench_backsub(ks: &[u32], e0: u32, syn: &[Vec<u16>], forney: bool) -> (f64, f64, u16) {
    let m = ks.len();
    let words = syn.first().map_or(0, |r| r.len());
    let t0 = std::time::Instant::now();
    let plan = forney.then(|| super::forney::ForneyPlan::prepare(ks, e0).expect("distinct bases"));
    let inverse =
        (!forney).then(|| invert_vandermonde(ks, e0).expect("distinct bases cannot fail"));
    let setup = t0.elapsed().as_secs_f64();
    let t1 = std::time::Instant::now();
    let out = match (&plan, &inverse) {
        (Some(plan), _) => plan.solve(syn, words),
        (_, Some(inv)) => {
            let mut out: Vec<Vec<u16>> = vec![vec![0u16; words]; m];
            let bytes: Vec<&[u8]> = syn.iter().map(|s| gf16::words_as_bytes(s)).collect();
            fold_parallel(&mut out, &bytes, &|j, i| inv[j][i], None);
            out
        }
        _ => unreachable!("one of the two arms is always built"),
    };
    let solve = t1.elapsed().as_secs_f64();
    let mut sum = 0u16;
    for row in &out {
        sum = sum.rotate_left(1) ^ row[0] ^ row[row.len() / 2] ^ row[row.len() - 1];
    }
    (setup, solve, sum)
}

/// Rows below which a fold keeps the Windows physical-core clamp even
/// when it has at least as many sources (see the clamp in
/// [`fold_parallel`]): 12 rows measured losing with the sibling, 101
/// winning, nothing between; the floor sits on the measured winning
/// side's half.
#[cfg(all(target_arch = "x86_64", windows))]
const SMT_LIFT_MIN_ROWS: usize = 64;

/// Physical core count on Windows (P and E cores, SMT siblings
/// excluded), counted the way par2j counts fold workers: one
/// `RelationProcessorCore` record per core. `None` on failure, and off
/// Windows (Apple Silicon has no SMT, so `available_parallelism` IS the
/// physical count there).
#[cfg(all(target_arch = "x86_64", windows))]
pub(crate) fn physical_cores() -> Option<usize> {
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
///
/// `gauge` names the subsystem the prepared coefficient table's bytes
/// belong to, and every caller states its answer rather than inheriting
/// a default: this helper is shared between the repairer and the
/// creator, so it cannot pick one itself, and an ungauged term is
/// exactly what [`crate::memgauge`] exists to stop. `None` where there
/// is no honest `Sub` (the creator's folds) or nothing to attribute (a
/// bench hook, a test).
///
/// **A CHANGE TO WHAT THIS COSTS MOVES FIVE GATE CONSTANTS, AND
/// NOTHING WILL TELL YOU.** This fold is the losing arm the NTT's
/// admission gates are calibrated against, and its cost per (source x
/// row) is the DENOMINATOR of every one of them: `NTT_MIN_PRESENT`,
/// `ntt_min_work` and `ntt_min_missing` in
/// `crates/nzbkit-base/src/par2repair/fastpar.rs`, and
/// `CREATE_NTT_MIN_PRESENT_NEON` / `_X86` in
/// `crates/nzbkit-base/src/par2gen/ntt_range.rs`. A faster fold RAISES
/// the crossover, so each of them should go UP; a slower one lowers
/// them. None is asserted anywhere - a stale one admits the transform
/// on a band this fold would win and is paid in silent wall - so a
/// speed change here owes them a re-derivation, by the sweep the first
/// of those constants names. The two sites are edited by different
/// lanes on different boxes, which is how the calibration went two
/// commits stale unnoticed
/// (`research/NTT-GATE-FOLD-COST-RECHECK-2026-09-08.md`).
pub(crate) fn fold_parallel(
    dsts: &mut [Vec<u16>],
    srcs: &[&[u8]],
    coeff: &(dyn Fn(usize, usize) -> u16 + Sync),
    gauge: Option<crate::memgauge::Sub>,
) {
    fold_parallel_opts(
        dsts,
        srcs,
        coeff,
        false,
        gauge,
        &crate::par2repair::control::RepairControl::default(),
        GridReport::SolveUnits,
    )
}

/// WHICH PHASE A TILED FOLD'S UNIT GRID IS A PIECE OF.
///
/// The same scheduler runs two unrelated stretches of a repair, and a
/// bar cannot be told which from inside: the dense back-substitution,
/// where the grid IS the solve, and the syndrome fold, where the grid
/// is one merged batch of a `Fold` phase the DRIVER already sized in
/// bytes. Passing the phase in is what lets the syndrome pass report
/// without re-sizing the host's solve bar every time it folds.
#[derive(Clone, Copy, Debug)]
pub(crate) enum GridReport {
    /// The dense back-substitution: re-size
    /// [`RepairPhase::Solve`](crate::par2repair::control::RepairPhase::Solve)
    /// to this grid - which is finer than the `m` the caller opened it
    /// with - and count one unit each.
    SolveUnits,
    /// The syndrome fold: this call folds that many BYTES of a
    /// [`RepairPhase::Fold`](crate::par2repair::control::RepairPhase::Fold)
    /// phase somebody else opened, so it re-sizes nothing and
    /// apportions those bytes across its own units.
    FoldBytes(u64),
}

/// [`fold_parallel`] that reports its unit grid's progress and can be
/// called off inside it.
///
/// TWO CALLERS, AND BOTH REPORT - into different phases, which is what
/// [`GridReport`] carries. The dense back-substitution passes the
/// repair's control and counts units into `Solve`. The syndrome pass
/// ([`fold_batches`]) passes `RepairControl::reporting_only(Fold)` and
/// apportions the bytes it is folding across the same grid. Until
/// 15 Sep 2026 the syndrome pass went through [`fold_parallel`] with an
/// inert control, on the reasoning that nobody may cancel it half-done
/// - and a half-done syndrome pass is exactly as harmless as a
/// half-done back-substitution, because the driver refuses both before
/// the patch. What that rule bought was a cancel waiting out a whole
/// merged fold. It then took the cancel alone until 17 Sep 2026, which
/// left the `Fold` bar to be filled by the hand-over that FEEDS this
/// call rather than by this call. The creator's folds still go through
/// [`fold_parallel`] inert.
///
/// The grain is the UNIT - one cache-sized cell of the destination grid,
/// which is what the drain below already deals in - and never the row.
/// A relaxed add per row at `m` rows times `words` columns is the
/// instrumentation that shows up as a benchmark regression; per unit it
/// is one add against a `MIN_COL_WORDS`-wide fold, measured as noise.
/// It is also the CEILING on how finely the fold can be reported: a
/// grid of one unit - few enough rows to share a chunk and a column
/// narrower than `MIN_COL_WORDS`, which means small blocks - says its
/// bytes once, at the end. That is a set whose whole fold is
/// milliseconds.
pub(crate) fn fold_parallel_controlled(
    dsts: &mut [Vec<u16>],
    srcs: &[&[u8]],
    coeff: &(dyn Fn(usize, usize) -> u16 + Sync),
    gauge: Option<crate::memgauge::Sub>,
    control: &crate::par2repair::control::RepairControl,
) {
    fold_parallel_opts(
        dsts,
        srcs,
        coeff,
        false,
        gauge,
        control,
        GridReport::SolveUnits,
    )
}

/// Whether [`fold_parallel_opts`] prepares its coefficients once for the
/// whole call: a flat allowance on the entry count, and nothing else.
///
/// A SECOND, PROPORTIONAL ARM WAS TRIED AND MEASURED A REGRESSION
/// (`44cc0375e`, reverted 6 Sep 2026 - keep this note, it is the reason
/// the obvious improvement is not here). Past the flat allowance it
/// admitted any table staying under an eighth of the destination bytes
/// it served, capped at 192 MB, on the reasoning that what preparing
/// buys is the per-(row, source) table build that each of the
/// `col_splits` column ranges would otherwise repeat - ~1,200 of them
/// for a 10 GiB / 1 MiB set at m = 900 - so the arm could spend memory
/// but not time.
///
/// It spends time. i5-10600KF, that exact shape, same binary, three
/// mirrored pairs: the 10 GiB / 900-row repair went 24.40 -> 25.54 s
/// wall and 196.3 -> 200.4 CPU-s with the arm on, +4.6% and +2.1%, both
/// ranges DISJOINT, while the two control legs (m = 101, admitted by
/// both arms; m = 1,500 over 64 KiB, refused by both) stayed in noise
/// and drifted the other way.
///
/// The self-bounding argument counted the table BUILDS it saves and
/// never counted the table's own traffic. At m = 900 the prepared table
/// is 105 MB on x86, and the fold walks it once per tile - so those
/// ~1,200 column ranges that made the build multiplier look enormous
/// are the same ~1,200 passes over 105 MB, through a 12 MB L3 shared by
/// twelve threads. Rebuilding eight 16-byte tables in L1 is cheaper
/// than streaming 105 MB past them. Same lesson as the NTT leaf's cost
/// split: price the TRAFFIC a hoist creates, not just the arithmetic it
/// removes.
fn coeff_table_admitted(rows: usize, srcs: usize) -> bool {
    const MAX_ENTRIES: usize = 256 << 10;
    rows.saturating_mul(srcs) <= MAX_ENTRIES
}

/// The planar column alignment above, on unless `NZBFAST_FOLD_PLANAR_ALIGN=0`.
/// Read once.
fn planar_align_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("NZBFAST_FOLD_PLANAR_ALIGN").as_deref() != Ok("0"))
}

/// Whether a caller may pack its sources with
/// `gf16::prepack_planar_in_place` and fold them through
/// [`fold_parallel_prepacked`]: the planar kernel must be the selected
/// one, the fused path on, every source a whole `words * 2` bytes, a
/// multiple of 64, and enough rows for the split to pay back.
pub(crate) fn prepacked_fold_admissible(words: usize, rows: usize) -> bool {
    gf16::PreparedSources::enabled()
        && gf16::multi_fold_width() > 0
        && rows >= 8
        && words >= 32
        && (words * 2).is_multiple_of(64)
}

/// [`fold_parallel`] over sources ALREADY in the planar layout (every
/// one whole, `words * 2` bytes). The caller checked
/// [`prepacked_fold_admissible`] before packing; this asserts it.
pub(crate) fn fold_parallel_prepacked(
    dsts: &mut [Vec<u16>],
    srcs: &[&[u8]],
    coeff: &(dyn Fn(usize, usize) -> u16 + Sync),
    gauge: Option<crate::memgauge::Sub>,
) {
    let words = dsts.first().map_or(0, |d| d.len());
    assert!(prepacked_fold_admissible(words, dsts.len()));
    assert!(srcs.iter().all(|s| s.len() == words * 2));
    fold_parallel_opts(
        dsts,
        srcs,
        coeff,
        true,
        gauge,
        &crate::par2repair::control::RepairControl::default(),
        GridReport::SolveUnits,
    )
}

fn fold_parallel_opts(
    dsts: &mut [Vec<u16>],
    srcs: &[&[u8]],
    coeff: &(dyn Fn(usize, usize) -> u16 + Sync),
    prepacked: bool,
    gauge: Option<crate::memgauge::Sub>,
    control: &crate::par2repair::control::RepairControl,
    report: GridReport,
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
    // The coefficient tables once per call (see `CoeffTable`).
    //
    // WHY THERE IS A CEILING. [`gf16::FoldCoeff`] is 130 bytes on x86
    // (two bytes off it), so an m x m back-substitution's table is
    // m^2 * 130 - 105 MB at m = 900, 292 MB at m = 1,500. What it BUYS
    // is the nibble kernels' per-call table build, which the tiled fold
    // otherwise pays once per (row, source, TILE): hoisting it measured
    // the dense back-substitution -17% on an i5-10600KF and on a Zen 4
    // part (see `gf16::FoldCoeff`). The flat entry allowance is where
    // that trade stops paying; sizing it to the destination instead was
    // tried and measured a regression on the very shape it was aimed at
    // (see `coeff_table_admitted`).
    //
    // The table is CHARGED to the `Sub` the caller named, for the length
    // of the call - 105 MB at m = 900 over 1 MiB blocks, which is real
    // memory and belonged in no gauge at all until this argument
    // existed. The charge is taken BEFORE the allocation, so the gauge
    // never reads low across the build, and `Charge`'s drop returns it
    // down every path out of here including an unwind. A caller with no
    // honest `Sub` passes `None` and the term stays where it was, in the
    // unattributed remainder - visibly, at the call site.
    let table_entries = (gf16::multi_fold_width() > 0 && coeff_table_admitted(rows, srcs.len()))
        .then(|| rows * srcs.len());
    let _table_charge = table_entries.zip(gauge).map(|(n, s)| {
        crate::memgauge::Charge::new(
            s,
            (n.saturating_mul(std::mem::size_of::<gf16::FoldCoeff>())) as u64,
        )
    });
    let prepared_table: Option<Vec<gf16::FoldCoeff>> = table_entries.map(|n| {
        let mut t = Vec::with_capacity(n);
        for j in 0..rows {
            for i in 0..srcs.len() {
                t.push(gf16::FoldCoeff::new(coeff(j, i)));
            }
        }
        t
    });
    let prepared_table = prepared_table.as_deref();
    let stride = srcs.len();
    // `fold_workers`, not `cpu_workers`: the same number unless a create
    // has measured its fold outrunning its whole-file MD5 chain and
    // published a lower ceiling (`mem::FoldWidthCap`) - the one case
    // where fewer fold threads make the WALL shorter.
    let cores = crate::mem::fold_workers().max(1);
    // Hybrid x86: fold on PHYSICAL cores only, SMT siblings idle (par2j
    // runs 14 threads on the i7-1280P, never 20). Measured on that box:
    // HT added nothing to the old kernel and REGRESSED the affine2x one
    // (two siblings thrash the shuffle ports and 16 hoisted ymm each).
    // min() keeps a process affinity mask authoritative when it is the
    // smaller number (the pinned bench rows depend on that).
    // ...except where the fold is compute-bound rather than
    // bandwidth-bound, which the shape tells apart: a square-ish fold
    // (sources >= rows - the dense back-substitution's m x m, the
    // 101-block repair's 101 x 101) absorbs many sources per pass over
    // its destination and an SMT sibling fills the kernel's stalls,
    // where a window fold of few sources into many rows (the creator's
    // 64 sources into 256 rows, the syndrome window) is destination
    // traffic and a sibling only thrashes it. Measured 6 Sep 2026 on an
    // i5-10600KF (6c/12t, nibble arm), same binary, mirrored, identical
    // outputs: twelve threads on the 10 GiB / 1 MiB / 900-missing repair
    // 23.46 / 23.48 s against 24.64 / 24.64 on six (the dense solve is
    // the difference), the 101-block repair 1.36-1.40 against
    // 1.53-1.57, the heavy (Forney) repair flat, and the 10 GiB / 4 MiB
    // fold-path create 22.94-23.59 against 22.46-22.65 at 255 CPU-s
    // against 155. And a FEW-row fold is the window kind whatever its
    // source count: the 12-hole 10 GiB repair (64-source syndrome windows
    // into 12 rows) read 9.42-11.59 s with the sibling against 7.80-7.84
    // clamped (the standings refresh that caught it, 6 Sep), because with
    // rows < cores the split is by column and every thread streams every
    // source. So the lift needs `SMT_LIFT_MIN_ROWS` rows as well - 101 is
    // measured winning, 12 losing, nothing between. `NZBFAST_FOLD_SMT=1`
    // lifts the clamp for every fold, `0` keeps it for every fold (the
    // A/B arms).
    #[cfg(all(target_arch = "x86_64", windows))]
    let cores = {
        let lift = match std::env::var("NZBFAST_FOLD_SMT").ok().as_deref() {
            Some("1") => true,
            Some("0") => false,
            _ => srcs.len() >= rows && rows >= SMT_LIFT_MIN_ROWS,
        };
        if lift {
            cores
        } else {
            physical_cores().map_or(cores, |p| p.min(cores))
        }
    };
    // FEWER ROWS THAN CORES: keep every row in ONE unit and split columns
    // only. Splitting three rows across three workers had each of them
    // stream the whole source set for its own row - the same bytes off
    // DRAM once per row - and the fold ran at 14 GB/s all-core on the
    // 3-block leg of an i5-10600KF desktop (232 ms for 3 rows over
    // 1 GiB, fold trace 4 Sep 2026) where the same box folds 60-90 GB/s
    // once the rows share a source pass. With all rows in a unit a source byte is read once
    // per COLUMN unit and used for every row; the destination slab is
    // rows x col_chunk, small by construction here. The column oversplit
    // below (`cores / row_threads * 4`) keeps the fan-out.
    // `NZBFAST_FOLD_ROW_THREADS` (bench knob, 5 Sep 2026): pin the row
    // split, `1` being the column-region split the few-rows arm below
    // already takes - every worker then reads each source byte once
    // instead of once per row chunk, which is the L3 traffic round M
    // measured on an i5-10600KF (linear to 2 workers, ~75% of linear from
    // 3 up, the same at 64 KiB and 4 MiB blocks).
    let row_threads = match std::env::var("NZBFAST_FOLD_ROW_THREADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
    {
        Some(n) => n.clamp(1, rows),
        None if rows < cores => 1,
        None => cores.min(rows),
    };
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
            //
            // THIS IS ALREADY par2j's `src_max`, IN BETTER UNITS - do
            // not "add" it a second time. par2j caps the number of
            // sources streamed through a resident destination tile at a
            // cache-geometry COUNT (roughly L3 / L2, about 19 on the
            // i7-1280P) so the source window stays inside L3. The cap
            // below plus the column-major LIFO drain is the same
            // mechanism expressed as a BYTE budget on that window, which
            // is strictly the more robust form: par2j's count is only
            // equivalent to it when a source's chunk slice happens to be
            // L2-sized, whereas `by_src` divides the window budget by
            // the actual source count and gets the column width
            // directly. Deriving this constant from a queried L3 is the
            // one open question left by the 2026-09-10 cache-hierarchy
            // pass; it is NOT free, because Apple silicon has no
            // conventional L3 at all (`hw.l3cachesize` is empty on an
            // M3 Ultra) and musl answers no `_SC_LEVEL*` query, so two
            // of the three platforms would keep this constant anyway.
            // See `research/FOLD-CACHE-GEOMETRY-2026-09-10.md`.
            const STRIPE_SRC_BUDGET: usize = 8 << 20;
            // `NZBFAST_FOLD_UNIT_DST` (bench knob): the unit's destination
            // slab budget in bytes, for the same round-M sweep; the
            // default follows the part's L2 (`unit_dst_budget`).
            let unit_dst = std::env::var("NZBFAST_FOLD_UNIT_DST")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or_else(unit_dst_budget);
            let by_dst = (unit_dst / 2 / row_chunk.max(1)).max(MIN_COL_WORDS);
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
    // A column boundary that is not a multiple of the fused kernel's
    // granule leaves every unit's tiles with a sub-chunk remainder, and
    // the remainder path builds a fold table per (row, group, source) -
    // measured as a 7-25x fold COLLAPSE the first time a cache-derived
    // col_chunk landed off-alignment (the old fixed 8-way split only
    // survived because 32768/8 happened to be aligned). Align up: whole
    // blocks are word-power-of-two sized, so every column - including the
    // last - stays a whole number of chunks.
    //
    // The granule is the SELECTED kernel's, not a constant 16: the
    // 512-bit GFNI arm consumes 32 words a chunk, so a 16-aligned column
    // ended half a chunk short there and every unit paid the remainder
    // path. Rounding up can only grow the soft cache target by 16 words
    // past the 16-word rounding it replaces, and the unit count is
    // unchanged.
    let granule = gf16::multi_fold_schedule_granule_words(gf16::multi_fold_width());
    // Planar-packed sources are laid out per 64 bytes: column edges on
    // 32-word boundaries or a unit's tile straddles a chunk. And where
    // the planar kernel is the selected one with enough rows per unit to
    // admit it, the SAME alignment for unpacked sources (the review's
    // large-job pass, 5 Sep 2026): the tiled fold packs a tile planar
    // only when the tile is a whole number of 64-byte chunks, so a
    // column split off the 16-word granule left every unit's LAST tile
    // ineligible and on the nibble kernel - at 10 x 1 GiB / 8 MiB /
    // 128 rows on the i5-10600KF the column was 2,992 words with a
    // 944-word final tile, 3,008 / 960 aligned, and the create read
    // 13.06-13.22 s against 14.05-14.18 (-6.7%, CPU -6%). The unit count
    // is unchanged; a column grows by at most 16 words.
    // `NZBFAST_FOLD_PLANAR_ALIGN=0` is the A/B arm.
    let align_planar = row_chunk >= 8 && gf16::PreparedSources::enabled() && planar_align_enabled();
    let granule = if prepacked || align_planar {
        granule.max(32)
    } else {
        granule
    };
    let col_chunk = words.div_ceil(col_splits).next_multiple_of(granule);

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
    // `Unit`s are pushed here and popped by the workers below, so the
    // order they are BUILT in is the only place a per-unit share of a
    // `FoldBytes` call can be handed out exactly once.
    let mut unit_bytes: Vec<u64> = Vec::with_capacity(col_splits * row_threads);
    for (ci, col) in cols.into_iter().enumerate() {
        let mut row_base = 0usize;
        // ONE LINEAR PASS, and it has to stay one. `split_off(take)` read
        // as "hand the unit its rows and keep the rest", but it allocated
        // a fresh Vec for the SUFFIX and copied it, then left the whole
        // original capacity attached to the tiny prefix the unit kept. So
        // a column of r rows in groups of `row_chunk` copied ~r^2/(2 *
        // row_chunk) references and retained about as many unused slots,
        // per column, on every platform. The waste GROWS as row groups
        // shrink, which is the direction cache-sized grouping pushes it.
        // Moving each reference once into an exactly sized group is the
        // same order as reading the column and holds nothing spare.
        let mut col = col.into_iter();
        loop {
            let take = col.len().min(row_chunk);
            if take == 0 {
                break;
            }
            let mut rows = Vec::with_capacity(take);
            rows.extend(col.by_ref().take(take));
            units.push(Unit {
                rows,
                row_base,
                col_off: ci * col_chunk,
            });
            unit_bytes.push(0);
            row_base += take;
        }
    }
    // WHAT THE DRAIN REPORTS, and it is not the same phase in both
    // callers - see `GridReport`.
    let phase = match report {
        GridReport::SolveUnits => {
            // The grid is the denominator: it is known exactly here, it
            // is the same thing the drain counts down, and it costs
            // nothing to say. Re-sizing the phase the caller opened is
            // deliberate - the dense back-substitution's `Solve` bar is
            // this grid, and the `m` the caller sized it with was the
            // best it had before the grid existed.
            control.begin(
                crate::par2repair::control::RepairPhase::Solve,
                units.len() as u64,
            );
            unit_bytes.fill(1);
            crate::par2repair::control::RepairPhase::Solve
        }
        GridReport::FoldBytes(bytes) => {
            // NO `begin`: the `Fold` phase is the whole feed and this
            // call is one merged batch of it, opened and sized by the
            // driver before the first block was read. The shares below
            // sum to `bytes` EXACTLY whatever the unit count, so the
            // phase's counter tracks bytes folded and not a rounding of
            // them - and each unit is popped exactly once, so no share
            // is spent twice.
            let n = (unit_bytes.len() as u64).max(1);
            for (i, b) in unit_bytes.iter_mut().enumerate() {
                let i = i as u64;
                *b = bytes * (i + 1) / n - bytes * i / n;
            }
            crate::par2repair::control::RepairPhase::Fold
        }
    };
    let units = std::sync::Mutex::new(units.into_iter().zip(unit_bytes).collect::<Vec<_>>());
    let workers = cores.min(row_threads * col_splits);
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| {
                loop {
                    // A CANCELLED FOLD LEAVES ITS DESTINATION HALF
                    // FOLDED, and that is safe here for one reason only:
                    // the repair checks the cancel again before the
                    // patch opens a destination, so blocks this grid did
                    // not finish are never written. A future caller of
                    // this entry that does NOT re-check before acting on
                    // `dsts` would be writing rubbish - and that is not
                    // hypothetical: `repair_mapped_inner` was such a
                    // caller until 17 Sep 2026 and wrote this grid's
                    // zeros into a live extractor slot. BOTH production
                    // drivers hold the rule now, each with a `gate` at
                    // the head of its patch: `repair_dir_set_inner`'s
                    // before `before_write`, and the mapped driver's
                    // between `finish_owned_reported` and its write
                    // loop.
                    if control.cancelled() {
                        return;
                    }
                    let unit = units.lock_ok().pop();
                    let Some((unit, add)) = unit else { return };
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
                    fold_chunk_tiled_prepared(
                        &mut rows,
                        &sub,
                        coeff,
                        unit.row_base,
                        TILE_WORDS,
                        TABLE_BUDGET,
                        prepacked,
                        prepared_table.map(|table| CoeffTable { table, stride }),
                    );
                    control.step(phase, add);
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
/// arena per batch is ~two allocations per 32 MiB instead of ~512, and
/// [`ArenaPool`] recycles those so a streaming repair allocates and
/// frees a handful of arenas rather than one per batch.
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

    /// Reserve an initialized slice in the arena and let the caller fill it
    /// in place. This keeps positional reads from landing in a per-reader
    /// scratch block only to be copied into the batch immediately after.
    pub(super) fn push_with<E>(
        &mut self,
        k: u32,
        len: usize,
        fill: impl FnOnce(&mut [u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        let off = self.arena.len();
        self.arena.resize(off + len, 0);
        if let Err(error) = fill(&mut self.arena[off..]) {
            self.arena.truncate(off);
            return Err(error);
        }
        self.slices.push((k, off, len));
        self.charge.grow(len as u64);
        Ok(())
    }

    /// Bytes in the arena, sealed or not.
    pub(super) fn len(&self) -> usize {
        self.arena.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.arena.is_empty()
    }

    /// Append bytes of a slice being assembled at the arena's tail
    /// (see `retain::RetainSink`); `seal` records it, `truncate_to`
    /// drops it.
    pub(super) fn extend(&mut self, bytes: &[u8]) {
        self.arena.extend_from_slice(bytes);
    }

    /// Record the slice assembled from `off` to the arena's tail.
    pub(super) fn seal(&mut self, k: u32, off: usize) {
        let len = self.arena.len() - off;
        self.slices.push((k, off, len));
        self.charge.grow(len as u64);
    }

    /// Drop the unsealed tail past `off`.
    pub(super) fn truncate_to(&mut self, off: usize) {
        debug_assert!(self.slices.last().is_none_or(|&(_, o, l)| o + l <= off));
        self.arena.truncate(off);
    }

    #[cfg(test)]
    pub(super) fn charged_bytes(&self) -> u64 {
        self.charge.bytes_for_tests()
    }
}

/// Recycled feed arenas, one pool per [`super::Reconstructor`]: a batch
/// the fold worker has finished with hands its arena back here and the
/// next feeder batch takes it, so the arena's pages stay mapped and
/// resident for the whole repair instead of being faulted in fresh by a
/// reader thread and unmapped again after every fold.
///
/// Why it matters: with an arena PER batch a 1 GiB streaming repair
/// still walked ~128 VirtualAlloc/VirtualFree pairs of 8 MiB (eight
/// readers, `BATCH_BYTES` split across them), each free a TLB shootdown
/// across every core the fold workers were on, each fresh arena 2,048
/// page faults on a reader thread. `par2_fold_bench` at the repair's
/// own shape (1 MiB blocks, 112 sources per call, 3 rows) folds a
/// 117 MB call in 4.4 ms on an i5-10600KF; the repair's fold worker
/// took 21-27 ms for the same call with the same kernel (`fold-trace`,
/// 4 Sep 2026) - the difference is the environment the readers put it
/// in, and the pool was built as the half of that this code owns.
///
/// MEASURED: a win on Windows only, so it ships ON there and OFF
/// elsewhere (`NZBFAST_FEED_POOL=1` / `0` overrides either way). One
/// binary, arms mirrored, `feed+fold+solve` in ms, 5 Sep 2026 (section
/// 4 of the next-dial handoff). i5-10600KF, Windows: 3-block leg pool
/// 234 / 193 / 193 / 191 vs off 221 / 223 / 238 / 224 (the tip beside
/// them 227 / 230 / 218 / 221) - about 13% of the phase in three
/// samples of four; 101-block within noise (1.02-1.14 vs 1.04-1.09).
/// M3 Ultra: 3-block 32-35 vs 32-34, 101-block 265-328 vs 261-267 -
/// flat, mmap and munmap of an 8 MiB arena cost nothing there. It is
/// not the whole 3-row story: the fold bench does the repair's own
/// 117 MB, 3-row call in 4.4 ms and the repair's worker takes 21-27,
/// and 30 ms is a fraction of that gap (the reader sweep in the same
/// handoff is the next half).
///
/// Memory: a pooled arena is fully resident (it was written up to its
/// old length), so it is charged to the gauge at CAPACITY while pooled,
/// where a live batch is charged by length. The pool holds at most
/// `cap` arenas - sized to what is in circulation at steady state
/// (feeders + channel depth), so at the shape above nothing is freed
/// until the repair ends - and drops the rest, which is the old
/// behaviour. Batches the NTT path retains never come back here.
/// `NZBFAST_FEED_POOL=0` makes `take` allocate and `put` free, which is
/// the A/B arm.
pub(super) struct ArenaPool {
    free: std::sync::Mutex<Vec<(Vec<u8>, crate::memgauge::Charge)>>,
    cap: usize,
}

impl ArenaPool {
    /// `cap` arenas kept; 0 is a pool that only allocates and frees.
    /// The caller applies [`Self::enabled`] (the tests do not).
    pub(super) fn new(cap: usize) -> std::sync::Arc<ArenaPool> {
        std::sync::Arc::new(ArenaPool {
            free: std::sync::Mutex::new(Vec::with_capacity(cap)),
            cap,
        })
    }

    pub(super) fn enabled() -> bool {
        static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *ON.get_or_init(|| match std::env::var_os("NZBFAST_FEED_POOL") {
            Some(v) => v == "1",
            None => cfg!(windows),
        })
    }

    /// A batch whose arena can hold `bytes`: a recycled one when the
    /// pool has one that large, else fresh.
    pub(super) fn take(&self, bytes: usize) -> FeedBatch {
        let recycled = {
            let mut free = self.free.lock().unwrap_or_else(|e| e.into_inner());
            free.iter()
                .rposition(|(a, _)| a.capacity() >= bytes)
                .map(|i| free.swap_remove(i))
        };
        match recycled {
            Some((arena, charge)) => {
                drop(charge);
                debug_assert!(arena.is_empty());
                FeedBatch {
                    arena,
                    slices: Vec::new(),
                    charge: crate::memgauge::Charge::new(crate::memgauge::Sub::RepairWork, 0),
                }
            }
            None => FeedBatch::with_capacity(bytes),
        }
    }

    /// Hand a folded batch's arena back. Past `cap` it is freed.
    pub(super) fn put(&self, batch: FeedBatch) {
        let FeedBatch {
            mut arena, charge, ..
        } = batch;
        drop(charge);
        if arena.capacity() == 0 {
            return;
        }
        let mut free = self.free.lock().unwrap_or_else(|e| e.into_inner());
        if free.len() >= self.cap {
            return;
        }
        arena.clear();
        let held =
            crate::memgauge::Charge::new(crate::memgauge::Sub::RepairWork, arena.capacity() as u64);
        free.push((arena, held));
    }

    #[cfg(test)]
    pub(super) fn pooled(&self) -> usize {
        self.free.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// Fold queued batches of present slices into every syndrome row - one
/// row sweep for the whole set, however many feeder batches it arrived
/// as.
/// Fold `batches` into the syndrome rows. `control` is the repair's
/// [`reporting_only`](crate::par2repair::control::RepairControl::reporting_only)
/// view of [`RepairPhase::Fold`](crate::par2repair::control::RepairPhase::Fold)
/// (or the inert default): polled per unit, so a cancel stops the call
/// instead of waiting for every row of a merged batch, and STEPPED per
/// unit, so the phase counts the bytes this call actually folds.
///
/// The figure is derived here rather than passed in because this
/// function IS the syndrome fold - there is no caller of it that folds
/// anything else - and because the fed bytes are what the drivers sized
/// the phase with, so the two agree by construction: every byte handed
/// to the worker lands in exactly one batch arena, and every batch is
/// folded exactly once.
pub(super) fn fold_batches(
    exponents: &[u32],
    syndromes: &mut [Vec<u16>],
    batches: &[FeedBatch],
    control: &crate::par2repair::control::RepairControl,
) {
    if syndromes.is_empty() {
        return;
    }
    let mut srcs: Vec<&[u8]> = Vec::new();
    let mut logs: Vec<u32> = Vec::new();
    let mut bytes = 0u64;
    for b in batches {
        for &(k, off, len) in &b.slices {
            srcs.push(&b.arena[off..off + len]);
            logs.push(k);
            bytes += len as u64;
        }
    }
    if srcs.is_empty() {
        return;
    }
    fold_parallel_opts(
        syndromes,
        &srcs,
        &|j, i| gf16::pow2(logs[i] as u64 * exponents[j] as u64),
        false,
        Some(crate::memgauge::Sub::RepairWork),
        control,
        GridReport::FoldBytes(bytes),
    );
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
/// The UNCONTROLLED door, kept for the callers that have nothing to
/// report to and nobody to answer: `bench_invert` and the tests. Every
/// production repair route reaches [`invert_controlled`] instead, because
/// a repair that cannot be called off in its `O(m^3)` stretch is the
/// defect that pair exists to remove.
pub(super) fn invert(a: Vec<Vec<u16>>) -> Result<Vec<Vec<u16>>, RepairError> {
    invert_controlled(a, &crate::par2repair::control::RepairControl::default())
}

/// [`invert`] that reports a COLUMN at a time and can be called off
/// between columns.
///
/// This is the unstructured arm's first long stretch - `O(m^3)`, 1.9 s
/// of a 6.3 s repair at m = 1400 and the dominant term well before the
/// sizes `RepairForecast::is_long` warns about - and until 12 Sep 2026
/// a user watching it had no way to know it had started, let alone to
/// stop it.
///
/// A column is the grain for both halves, and for the parallel arm it is
/// the ONLY safe one: the workers are barrier-synchronised, so a cancel
/// that let one of them leave early would park every other on a barrier
/// nothing will complete. The flag is therefore LATCHED before a barrier
/// and read after it, exactly as the singular verdict already is, so all
/// workers leave on the same column together.
pub(super) fn invert_controlled(
    a: Vec<Vec<u16>>,
    control: &crate::par2repair::control::RepairControl,
) -> Result<Vec<Vec<u16>>, RepairError> {
    let m = a.len();
    // Each worker should own enough rows that a column's elimination
    // outweighs its two barrier crossings.
    let threads = crate::mem::cpu_workers().min(m / 32).max(1);
    if m < PAR_INVERT_MIN || threads < 2 {
        return invert_serial_controlled(a, control);
    }
    invert_parallel_controlled(a, threads, control)
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
/// The fan-out under a control - see [`invert_controlled`].
pub(super) fn invert_parallel_controlled(
    mut a: Vec<Vec<u16>>,
    threads: usize,
    control: &crate::par2repair::control::RepairControl,
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
    // Latched before a barrier, read after it - see
    // [`invert_controlled`] for why it may not be read directly.
    let cancelled = AtomicBool::new(false);
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
            let cancelled = &cancelled;
            s.spawn(move || {
                let mut shard = shard;
                // One worker reports, or every column would be counted
                // `threads` times. Shard 0 holds row 0 by the deal above
                // and is never empty at this `m`.
                let reporting = shard.first().is_some_and(|(r, _, _)| *r == 0);
                for col in 0..m {
                    // LATCHED here, BEFORE the barrier, and read after
                    // it: a worker that decided for itself could leave
                    // on a different column from its peers and park
                    // every one of them on the next barrier.
                    if control.cancelled() {
                        cancelled.store(true, Ordering::Relaxed);
                    }
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
                    if cancelled.load(Ordering::Relaxed) {
                        return;
                    }
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
                    drop(g);
                    if reporting {
                        control.step(crate::par2repair::control::RepairPhase::Solve, 1);
                    }
                }
            });
        }
    });
    if cancelled.load(Ordering::Relaxed) {
        return Err(RepairError::Cancelled);
    }
    if singular.load(Ordering::Relaxed) {
        return Err(RepairError::SingularMatrix);
    }
    // inv[piv[col]] is column `col`'s row of A⁻¹.
    Ok(piv
        .into_iter()
        .map(|p| std::mem::take(&mut inv[p.into_inner()]))
        .collect())
}

#[cfg(test)]
pub(super) fn invert_serial(a: Vec<Vec<u16>>) -> Result<Vec<Vec<u16>>, RepairError> {
    invert_serial_controlled(a, &crate::par2repair::control::RepairControl::default())
}

/// [`invert_serial`] under a control - see [`invert_controlled`].
pub(super) fn invert_serial_controlled(
    mut a: Vec<Vec<u16>>,
    control: &crate::par2repair::control::RepairControl,
) -> Result<Vec<Vec<u16>>, RepairError> {
    let m = a.len();
    let mut inv: Vec<Vec<u16>> = (0..m)
        .map(|i| {
            let mut row = vec![0u16; m];
            row[i] = 1;
            row
        })
        .collect();
    for col in 0..m {
        control.check()?;
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
        control.step(crate::par2repair::control::RepairPhase::Solve, 1);
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

/// Zero means no ceiling, which is the default: a caller that has not
/// said otherwise is assumed to be a person who asked for this repair.
pub(super) static UNATTENDED_UNSTRUCTURED_CEILING: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Cap the UNSTRUCTURED solve for a process that nobody is watching.
///
/// **NOTHING IN THIS REPO CALLS THIS IN PRODUCTION SINCE 16 Sep 2026,
/// and that is the finished state rather than a gap to fill.** The
/// daemon set it from `serve/mod.rs` until then; that call is deleted,
/// and the block where it stood carries the census that deleted it.
/// What survives here is the MECHANISM - still live, still tested, and
/// still the right answer for an embedder whose repair callers cannot
/// be watched.
///
/// # What it caps, and what it never did
///
/// The dense arm's memory bound says what FITS. This says what a given
/// process should START, and the two are different questions: a gapped
/// set at m = 16,384 fits comfortably in 1 GB and still takes about four
/// minutes, and one near the unstructured ceiling takes about half an
/// hour. That is fine when a person typed the command and can watch it
/// or interrupt it. It was not fine unattended, because until
/// 12 Sep 2026 this engine emitted no progress inside a fold and polled
/// nothing that could stop one - a long repair and a wedged one were
/// indistinguishable from outside, and a cancel would not be honoured
/// until it finished anyway.
///
/// Only the UNSTRUCTURED arm is capped. A structured repair is roughly
/// linear in m and finishes in seconds even with every block missing
/// (8.9 s at m = 32,768, the format's ceiling), so capping it by m would
/// refuse fast work for no reason.
///
/// # Why the daemon stopped setting it
///
/// RAISING THE NUMBER WAS THE WRONG READING OF THIS DOC ALL ALONG, and
/// the doc said so from 12 Sep. The ceiling is not a guess at what a
/// daemon can afford; it is a stand-in for "nobody can see this repair
/// or stop it", and that question is answered per REPAIR rather than
/// per process. So [`super::reconstruct::check_repair_dim_dense`] skips
/// the ceiling entirely for a caller supplying BOTH halves of a
/// [`RepairControl`](super::RepairControl) - see
/// `RepairControl::is_attended` - and the work was to give every
/// daemon-reachable caller one, not to pick a bigger m.
///
/// That finished on 16 Sep 2026 (claim
/// `repair-control-two-censused-sites-16sep`). The census below is the
/// one taken THAT day, walked outwards from the two production solve
/// drivers - `par2repair::repair_mapped_inner` and the disk driver's
/// `repair_dir_set` body are the only two functions in the tree that
/// construct a [`Reconstructor`](super::reconstruct::Reconstructor) -
/// over every caller of every `pub` repair entry `par2repair` exposes:
///
///  - CONTROLLED, and all five are daemon-reachable:
///    `repair::nativepass` (the download disk repair and its adoption
///    probe), `get::latesets` (the late-set round),
///    `unpack::nested_par2_repair` (the nested extraction ladder) -
///    those three since 12 Sep - plus `get::settle::noset` (the no-set
///    obfuscated arm, through
///    [`PacketCatalog::repair_present_or_renamed_sets_controlled`](
///    super::PacketCatalog::repair_present_or_renamed_sets_controlled))
///    and the MAPPED in-stream driver `repair::try_mapped_repair`
///    (through
///    [`repair_mapped_catalog_resumed_controlled`](
///    super::repair_mapped_catalog_resumed_controlled)), both since
///    16 Sep.
///  - CLI-only, and unaffected either way: `unpack::extract_local`
///    (`nzbfast extract`) and `parfast`.
///
/// The previous version of this block listed the last two as STILL
/// UNCONTROLLED and named them "the reason this call survives". They
/// are not, and it does not.
///
/// # When to set it again
///
/// When a process genuinely cannot watch its own repairs - an embedder
/// driving this engine from callers that have no progress sink and no
/// cancel. Setting it is not the fix for a NEW unwatched path in the
/// daemon: it is process-wide, so it would re-cap the five callers
/// above that earned their exemption. Give the new path a control
/// instead.
///
/// Zero (the default) means no ceiling: a caller that has not said
/// otherwise is assumed to be a person who asked for this repair.
/// Pinned by `inline_tests::
/// a_controlled_caller_is_exempt_from_the_unattended_ceiling`, which
/// drives the exemption and the refusal at the same m, so the mechanism
/// cannot rot while no production caller uses it.
pub fn set_unattended_unstructured_ceiling(m: usize) {
    UNATTENDED_UNSTRUCTURED_CEILING.store(m, std::sync::atomic::Ordering::Relaxed);
}

/// The ceiling this process will start an unstructured solve under, or
/// zero for none. Lives beside [`invert`] because it is a policy about
/// the Gauss-Jordan inverse's cost, not about the caller that asked.
pub(super) fn unattended_unstructured_ceiling() -> usize {
    UNATTENDED_UNSTRUCTURED_CEILING.load(std::sync::atomic::Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::coeff_table_admitted;

    /// The prepared table is real memory and is charged to the `Sub` the
    /// caller named, for the length of the call and no longer. It went
    /// ungauged when the proportional arm landed (105 MB at m = 900 over
    /// 1 MiB blocks, sitting in the unattributed remainder), which is
    /// the whole reason `fold_parallel` takes a gauge argument.
    ///
    /// **The `Sub` here is a sub production never charges, and that is
    /// load-bearing.** The gauges are process-global counters and this
    /// test asserts ABSOLUTE values on them, so it is only correct while
    /// nothing else in the process is charging the same sub. It named
    /// `RepairWork` until 7 Sep 2026, which was safe only by luck: the
    /// budgeted Forney stripe started charging its stage arenas to
    /// `RepairWork` too, and this test then failed about one run in five
    /// under `cargo test -p nzbkit-base --lib` - a solve in another test
    /// thread charging between the `reset_for_tests` and the assertion.
    /// `one_gauge_test_at_a_time` does not cover that: it serialises
    /// gauge TESTS against each other, not against production code
    /// running in unrelated tests. The class is invisible to nextest,
    /// which gives every test its own process (CONTRIBUTING.md, the
    /// `cargo test --lib` note).
    ///
    /// What the test is about is unchanged - `fold_parallel` charges the
    /// sub the CALLER named, which is what its name says - and the
    /// second assertion below now pins that no other sub is touched
    /// either, which the `RepairWork` spelling could never have checked.
    #[test]
    fn a_prepared_coefficient_table_is_charged_to_the_callers_sub() {
        use crate::memgauge::{self, Sub};
        let _one = memgauge::one_gauge_test_at_a_time();
        // Charged by nothing in this crate (`Sub::RawFree` is the
        // pipeline's raw-article pool, an nzbfast-engine term), so a
        // concurrent test cannot move it. The memgauge unit tests use
        // the same spellings for the same reason, under the same lock.
        const GAUGE: Sub = Sub::RawFree;
        // A shape the FLAT arm admits on every architecture, so this
        // test measures the charge and not the ceiling.
        let (rows, srcs_n, words) = (8usize, 8usize, 4096usize);
        assert!(coeff_table_admitted(rows, srcs_n));
        let src = vec![0u8; words * 2];
        let srcs: Vec<&[u8]> = (0..srcs_n).map(|_| src.as_slice()).collect();
        let want = if crate::gf16::multi_fold_width() > 0 {
            (rows * srcs_n * std::mem::size_of::<crate::gf16::FoldCoeff>()) as u64
        } else {
            // No multi-fold kernel here, so no table is prepared at all
            // and there is nothing to charge - the honest reading either
            // way, never a skipped assertion.
            0
        };

        memgauge::reset_for_tests();
        let mut dsts = vec![vec![0u16; words]; rows];
        super::fold_parallel(
            &mut dsts,
            &srcs,
            &|j, i| (j * 7 + i + 1) as u16,
            Some(GAUGE),
        );
        assert_eq!(
            memgauge::snapshot().peak_of(GAUGE),
            want,
            "the table's bytes reach the gauge while the fold runs"
        );
        assert_eq!(
            memgauge::cur(GAUGE),
            0,
            "and are given back when the call returns"
        );

        // ...and a caller that names no `Sub` charges nothing, which is
        // the creator's case.
        memgauge::reset_for_tests();
        let mut dsts = vec![vec![0u16; words]; rows];
        super::fold_parallel(&mut dsts, &srcs, &|j, i| (j * 7 + i + 1) as u16, None);
        assert_eq!(memgauge::snapshot().peak_of(GAUGE), 0);
        // And the named sub is the ONLY one the charged call moves - the
        // half `RepairWork` could not assert, because production charges
        // it. `OutFree` stands in for "some other sub".
        memgauge::reset_for_tests();
        let mut dsts = vec![vec![0u16; words]; rows];
        super::fold_parallel(
            &mut dsts,
            &srcs,
            &|j, i| (j * 7 + i + 1) as u16,
            Some(GAUGE),
        );
        assert_eq!(memgauge::snapshot().peak_of(Sub::OutFree), 0);
        memgauge::reset_for_tests();
    }

    /// The prepared-coefficient ceiling: a FLAT entry allowance, and the
    /// shapes either side of it.
    ///
    /// A destination-proportional second arm lived here and was REVERTED
    /// (6 Sep 2026). It measured +4.6% wall and +2.1% CPU on the 10 GiB
    /// / 900-row repair it was aimed at, both ranges disjoint over three
    /// mirrored pairs, because it priced the table BUILDS it saves and
    /// never the 105 MB table's own traffic. `coeff_table_admitted`
    /// carries the reasoning. Do not re-add one without running that leg.
    #[test]
    fn the_coefficient_ceiling_is_a_flat_entry_allowance() {
        // Admitted, and the rule does not consult the destination at all
        // - a small product is cheap to prepare whatever the block size.
        assert!(coeff_table_admitted(101, 101));
        // 262,144 entries is the allowance: exactly it passes, one more
        // does not.
        assert!(coeff_table_admitted(512, 512));
        assert!(!coeff_table_admitted(513, 512));
        // Both big-repair shapes are refused, which is the MEASURED
        // answer and not a conservative guess: at m = 900 the table is
        // 105 MB on x86 and costs more to stream past the fold than the
        // per-tile builds it removes.
        assert!(!coeff_table_admitted(900, 900));
        assert!(!coeff_table_admitted(1500, 1500));
    }
}
