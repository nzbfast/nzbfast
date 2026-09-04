//! Forney-style back-substitution: the repair solve as two small
//! transforms instead of the m x m dense product.
//!
//! One subject per file, the way `linalg.rs` and `fastpar.rs` are: this
//! is the LAST phase of a repair, and only the last phase. It takes the
//! syndrome rows and the missing columns' base logs and returns the
//! rebuilt blocks; it never sees a file, a packet or a recovery set, and
//! the policy question of WHICH solve runs is answered by
//! [`backsub_gate`] before any arithmetic starts.
//!
//! # Why
//!
//! `Reconstructor::finish_reported` ends every repair with
//! `fold_parallel(&mut out, &syn_bytes, &|j, i| inverse[j][i])` - the
//! explicit m x m inverse times the m syndrome rows, `O(m^2 * words)` of
//! kernel work. That fold runs AT the kernel's measured peak (147.5 GB
//! in 257 ms at m = 1,500 on the M3 Ultra, audit section 3), so there is
//! nothing to win by folding it better. There is something to win by
//! folding LESS: at the `MAX_REPAIR_DIM` = 8,192 cap the same product is
//! 4.4 TB and ~7.4 s on that box, and it grows quadratically while every
//! other phase of the repair grows linearly.
//!
//! # The identity
//!
//! Both repair paths pick the SMALLEST available recovery exponents, so
//! the exponents are consecutive `e_r = e0 + r` and the matrix factors
//! `A[r][c] = g_c^{e0} * g_c^r` (`linalg::invert_vandermonde` exists for
//! the same reason). Writing `y_c = g_c^{e0} x_c`, the syndromes
//! `S_r = Σ_c y_c g_c^r` are the power sums of the unknowns at the nodes
//! `g_c`, and with `P(z) = Π_c (z + g_c)` and `Q_c = P/(z + g_c)`,
//!
//! ```text
//!     Σ_r Q_c[r] S_r = Σ_{c'} y_{c'} Q_c(g_{c'}) = d_c * y_c,
//!     d_c = Q_c(g_c) = P'(g_c)   (char 2: the odd coefficients)
//! ```
//!
//! because `Q_c` vanishes at every other node. Synthetic division gives
//! `Q_c[r] = Σ_{j>=r} p[j+1] g_c^{j-r}`, so substituting `j = r + t`
//! splits the sum into two stages that no longer mention `c` and `r`
//! together:
//!
//! ```text
//! T_t = Σ_r S_r * p[r + t + 1]                (a HANKEL product)
//!     x_c = (g_c^{-e0} / d_c) * Σ_t T_t * g_c^t   (an EVALUATION)
//! ```
//!
//! Both stages are still `O(m^2)` written that way; the point is that
//! both are now STRUCTURED, and each has a transform that does it in
//! roughly `O(m)` block folds.
//!
//! # Stage 1, the Hankel product
//!
//! `T` is a Toeplitz/Hankel matvec, so it is a convolution. Cut the
//! index into segments of [`BLK`] = 128 and every `(output segment,
//! input segment)` pair becomes one cyclic convolution of length
//! [`CONV`] = 255 - and 255 divides 65535, so GF(2^16) has a root of
//! that order and the convolution is a length-255 DFT, a pointwise
//! product and a length-255 inverse DFT. Transform each input segment
//! ONCE, accumulate in the spectral domain, transform each output
//! segment back once: `2 * m * CONV / BLK` ... in block folds,
//! `2 * CONV * m` for the transforms plus `CONV * nseg(nseg+1)/2` for
//! the spectral accumulate (only half the pairs: `p[r+t+1]` is zero past
//! `r + t = m - 1`, so the Hankel matrix is triangular).
//!
//! The first implementation did each length-255 DFT directly, as a dense
//! 255 x 128 fold. That is an exact baseline, not a lower bound: because
//! `255 = 3 * 5 * 17` with pairwise-coprime radices, a Good-Thomas network
//! factors the transform without twiddles. Putting radix 17 first lets the
//! forward transform prune the 127 padded input rows; putting it last in the
//! inverse lets that transform prune the 127 outputs the Hankel product never
//! consumes. For a full segment, each direction therefore needs 4,216
//! coefficient/source folds instead of 32,640 (7.74x fewer). Two reusable
//! 255-row stripe arenas carry the intermediate coordinates.
//!
//! # Stage 2, the evaluation
//!
//! `Σ_t T_t g_c^t = Σ_t T_t 2^{k_c t}` is one output of the 65535-point
//! DFT `par2ntt` already computes - with the roles swapped (inputs on
//! the contiguous prefix `t < m`, outputs at the scattered `k_c`), which
//! is the TRANSPOSE of the shape `FlatPlan` implements. Rather than
//! transpose that network, this stage takes the Good-Thomas split
//! `65535 = 255 * 257` straight: with `α = 2^{257*128}` (order 255) and
//! `β = 2^{255*128}` (order 257), CRT gives
//! `2^{k t} = α^{(k mod 255)(t mod 255)} * β^{(k mod 257)(t mod 257)}`,
//! so one pass over `T` per distinct `k_c mod 255` builds 257 partial
//! rows, and each column is then one 257-source fold of those.
//!
//! That costs `|K1| * m + 257 * m` block folds where `|K1|` is the
//! number of distinct `k_c mod 255`. Base logs are coprime to 65535, so
//! `k_c mod 255` is coprime to 255 and `|K1| <= φ(255) = 128` however
//! large `m` gets. The two-level form holds ONE 257-row scratch per
//! worker where the full `FlatPlan` tree would hold `needed <= 65535`
//! rows (the outputs here are scattered over the whole group, so its
//! prefix pruning does not apply) - 60-160 MB per worker at the shipped
//! stripe width, which is why the cheaper network is not the one used.
//!
//! # What it costs, and where it crosses over
//!
//! In block folds (one fused source pass through
//! `gf16::xor_mul_multi_into`, the unit audit section 18 prices
//! everything in), against the dense product's `m^2`:
//!
//! ```text
//!     stage 1: 34m + 4080*nseg + CONV*nseg(nseg+1)/2,
//!              nseg = ceil(m / BLK)
//!     stage 2: (|K1| + 257) * m
//! ```
//!
//! The first two stage-1 terms are the pruned 3x5x17 transforms; the last is
//! the unchanged triangular spectral accumulation. This is linear in `m`
//! up to the `nseg^2` term, and that term is `CONV/(2*BLK^2) = 0.0078` per
//! `m^2` - 128x under the dense product's coefficient. Fused-kernel calls
//! are fewer again because each call consumes several coefficient/source
//! pairs.
//!
//! The conservative transform-vs-dense gate was measured 3 Sep 2026 with
//! the original direct stage-1 DFT, 64 KiB blocks, best of three, solve only
//! (`examples/par2_fold_bench`; the tables and the method are in
//! `research/PAR2-PERF-AUDIT-2026-09-02.md` section 20). Transform
//! against dense:
//!
//! ```text
//!     m       512   1024   1500   2048   3000   6000   8192
//! M3 Ultra 32c   0.38x  0.89x  1.38x  1.90x  2.72x  5.25x  7.29x
//! Zen 4 EPYC 8t  0.43x  0.81x  1.11x  1.45x  2.04x  3.35x  4.51x
//! ```
//!
//! Those direct-DFT baseline crossovers were m ~ 1,200 on the M3 and ~1,350
//! on the Zen 4; the mixed-radix stage only lowers the transform side, so the
//! existing 2,048 gate stays conservative. At the
//! `MAX_REPAIR_DIM` cap the whole solve is 1.05 s against 7.6 s and
//! 3.7 s against 16.6 s. Setup is cheaper on this route as well (33 ms
//! against 48 ms at the cap on the M3): the tables here are `O(m)` wide
//! where the explicit inverse is `O(m^2)`.
//!
//! # What is NOT here
//!
//! Gapped exponents. When recovery packets are themselves missing the
//! exponents are not consecutive, `A` is a generalized Vandermonde with
//! no factorization, and the repair falls back to Gauss-Jordan and the
//! dense product exactly as before - untouched by any of this.

use crate::gf16::{self, MulTable};
use crate::sync::MutexExt;
use tracing::info;

/// Segment length of the blocked Hankel product. Paired with
/// [`CONV`] = `2*BLK - 1`: the linear convolution of two length-`BLK`
/// sequences is exactly `2*BLK - 1` long, so a cyclic convolution of
/// that length carries it with no wraparound and no padding waste.
/// 128 is the largest such pairing whose length divides 65535 (255
/// does; 511 and 1023 do not), and the `nseg^2` spectral-accumulate
/// term wants `BLK` as large as the field allows.
const BLK: usize = 128;
/// The cyclic-convolution length, `2*BLK - 1`. `255 = 3*5*17` divides
/// `65535`, so `2^257` is a root of unity of exactly this order.
const CONV: usize = 2 * BLK - 1;
/// The 257 half of the Good-Thomas split `65535 = 255 * 257` used by
/// the evaluation stage.
const GT2: usize = 257;

/// `NZBFAST_BACKSUB` default: the missing-block count at or above which
/// the transform solve replaces the dense product.
///
/// Set from the same kind of sweep `fastpar::NTT_MIN_MISSING` rests on -
/// both solves timed at the same shapes on an M3 Ultra and a Zen 4 EPYC,
/// audit section 20 - and set ABOVE the measured crossover for the same
/// reason: one constant cannot be right on every box, and the dense
/// product is the one that has run in the field for a year. Measured
/// crossover m ~ 1,200 (M3) and ~ 1,350 (Zen 4); 2,048 is ~1.5x past
/// both, is already 1.90x / 1.45x AT the gate, and reaches 2.72x /
/// 2.04x by m = 3,000. The Windows parts are unmeasured here, which is
/// the margin's other job.
pub(crate) const BACKSUB_MIN_MISSING: usize = 2048;

/// Stripe-width granule, in u16 words: 32 words = 64 bytes, the widest
/// granule any shipped fused kernel takes (`gf16::xor_mul_multi_gfni512`
/// works in 64-byte chunks; the NEON and AVX2 kernels take 32). A width
/// off this granule leaves a remainder on EVERY fold, and the remainder
/// path builds a 1.2 KB `FoldTable` per source per call - measured on
/// the Zen 4 EPYC at m = 6,000, where the budget happened to land on
/// 336 words (672 bytes = ten 64-byte chunks and a 32-byte tail): the
/// whole solve ran 10.4 s against 3.7 s at m = 8,192, a shape with 33%
/// MORE work. Alignment here is not a micro-optimisation.
const STRIPE_GRAN: usize = 32;

/// Per-worker byte budget for stage 1's spectral arena, which is
/// `nseg * CONV * w` words. The stripe width is chosen to fit it, so a
/// deep repair narrows its stripes rather than growing its footprint.
/// `NZBFAST_BACKSUB_W` pins the width instead (a bench knob).
const SPECTRA_BUDGET: usize = 8 << 20;

/// Whether this shape takes the transform solve. `NZBFAST_BACKSUB` is
/// the escape hatch in both directions (`forney` / `dense`), the way
/// `NZBFAST_NTT` is for the syndrome path; unset, the gate is the
/// measured constant alone.
///
/// Deliberately NOT tied to the fast-par setting or its trip-breaker:
/// this solve reads no untrusted geometry (the nodes are the missing
/// blocks' own base logs) and has no fallback to retry INTO - it is
/// bit-identical to the dense product or it is a bug, which is what
/// the differential harness in `inline_tests` is for.
pub(crate) fn backsub_gate(m: usize) -> bool {
    match std::env::var("NZBFAST_BACKSUB")
        .unwrap_or_default()
        .as_str()
    {
        "forney" | "1" => true,
        "dense" | "0" | "off" => false,
        // Every count above is priced in FUSED folds. Without a multi
        // kernel both solves fall back to a `FoldTable` per source, and
        // the dense product's tiled loop amortises those table builds
        // across a whole column sweep where the small per-stage folds
        // here cannot - so on a part with no fused kernel (armv7, or an
        // `NZBFAST_GF16_MULTI=0` kernel A/B) the measured ratios do not
        // transfer and the dense product keeps the shape. The forced
        // arm above still reaches it, which is what the harness needs.
        _ => gf16::multi_fold_width() > 0 && m >= BACKSUB_MIN_MISSING,
    }
}

/// Stage-1 transform policy. The measured Good-Thomas network is the
/// production default; `direct` is the rollback and benchmark arm. Read this
/// while preparing the plan so each repair builds and retains only the tables
/// its selected implementation can use.
fn mixed_dft_gate() -> bool {
    !matches!(
        std::env::var("NZBFAST_BACKSUB_DFT").as_deref(),
        Ok("direct" | "0" | "off")
    )
}

/// `dst ^= Σ_s coeffs[s] * srcs[s]`, every source the same length as
/// `dst`, fused in groups of 8 with the kernel's sub-granule tail taken
/// per source. The word-slice twin of `par2ntt::fold_into` - same
/// grouping, same tail rule, different source representation (rows of
/// an arena here, caller pointers there).
fn fold_rows(dst: &mut [u16], srcs: &[&[u16]], coeffs: &[u16]) {
    debug_assert_eq!(srcs.len(), coeffs.len());
    let words = dst.len();
    let mut g = 0;
    while g < srcs.len() {
        let cnt = (srcs.len() - g).min(8);
        let mut group: [&[u8]; 8] = [&[]; 8];
        for (t, s) in srcs[g..g + cnt].iter().enumerate() {
            debug_assert_eq!(s.len(), words);
            group[t] = gf16::words_as_bytes(s);
        }
        let done = gf16::xor_mul_multi_into(dst, &group[..cnt], &coeffs[g..g + cnt]);
        if done < words {
            // The sub-32-byte tail, and the WHOLE fold on a build with
            // no fused kernel - same rule as par2ntt::fold_into.
            for (src, &c) in group[..cnt].iter().zip(&coeffs[g..g + cnt]) {
                if c != 0 {
                    gf16::FoldTable::new(c).xor_mul_into(&mut dst[done..], &src[done * 2..]);
                }
            }
        }
        g += cnt;
    }
}

// Good-Thomas coordinates for 255 = 3 * 5 * 17. The three CRT
// idempotents are 85, 51 and 120: each is one modulo its own radix and
// zero modulo the other two. Consequently
//
//   w^(k*n) = (w^85)^(k3*n3) (w^51)^(k5*n5) (w^120)^(k17*n17)
//
// with no twiddle factors between the three transforms.
#[inline]
fn gt_index(a: usize, b: usize, c: usize) -> usize {
    (a * 5 + b) * 17 + c
}

#[inline]
fn gt_natural(a: usize, b: usize, c: usize) -> usize {
    (85 * a + 51 * b + 120 * c) % CONV
}

/// Dense radix transform matrix, row-major by output then input. `idem`
/// is the radix's CRT idempotent in Z/255; negating its exponent gives
/// the inverse transform. The missing 1/255 factor is one in
/// characteristic two, exactly as for the old direct inverse table.
fn dft_matrix(wpow: &[u16], radix: usize, idem: usize, inverse: bool) -> Vec<u16> {
    let mut out = vec![0u16; radix * radix];
    for k in 0..radix {
        for n in 0..radix {
            let mut e = idem * k * n % CONV;
            if inverse && e != 0 {
                e = CONV - e;
            }
            out[k * radix + n] = wpow[e];
        }
    }
    out
}

/// First forward stage, pruned at the source: only the caller's at-most
/// 128 natural-order rows exist. Radix 17 goes first because that makes
/// each butterfly roughly half-full while eliminating the most work;
/// the later radix-5 and radix-3 stages are dense.
fn dft17_sparse(src: &[&[u16]], dst: &mut [u16], words: usize, coeff: &[u16]) {
    debug_assert_eq!(dst.len(), CONV * words);
    // A group is one fixed (n mod 3, n mod 5), which is one residue mod
    // 15, so a segment of at most BLK = 128 natural rows puts at most
    // ceil(128/15) = 9 of them in any group - which is why the three
    // scratch arrays below are nine wide and need no bounds check in the
    // loop. The caller clamps every segment to BLK; assert it here so
    // that a change to BLK fails at this line rather than as an index
    // panic inside the butterfly.
    debug_assert!(
        src.len() <= BLK,
        "dft17_sparse takes one segment, at most BLK rows"
    );
    const GROUP_MAX: usize = BLK.div_ceil(15);
    let mut rows: [&[u16]; GROUP_MAX] = [&[]; GROUP_MAX];
    let mut residues = [0usize; GROUP_MAX];
    let mut selected = [0u16; GROUP_MAX];
    for a in 0..3 {
        for b in 0..5 {
            let mut count = 0;
            for (n, &row) in src.iter().enumerate() {
                if n % 3 == a && n % 5 == b {
                    rows[count] = row;
                    residues[count] = n % 17;
                    count += 1;
                }
            }
            for k in 0..17 {
                for q in 0..count {
                    selected[q] = coeff[k * 17 + residues[q]];
                }
                let d = gt_index(a, b, k) * words;
                fold_rows(&mut dst[d..d + words], &rows[..count], &selected[..count]);
            }
        }
    }
}

/// Middle radix-5 stage, with both arenas in Good-Thomas coordinate
/// order `[mod 3][mod 5][mod 17]`.
fn dft5(src: &[u16], dst: &mut [u16], words: usize, coeff: &[u16]) {
    debug_assert_eq!(src.len(), CONV * words);
    debug_assert_eq!(dst.len(), CONV * words);
    let mut rows: [&[u16]; 5] = [&[]; 5];
    for a in 0..3 {
        for c in 0..17 {
            for b in 0..5 {
                let s = gt_index(a, b, c) * words;
                rows[b] = &src[s..s + words];
            }
            for k in 0..5 {
                let d = gt_index(a, k, c) * words;
                fold_rows(&mut dst[d..d + words], &rows, &coeff[k * 5..][..5]);
            }
        }
    }
}

/// Last forward radix-3 stage. The destination is put back in natural
/// spectral order because the pointwise product consumes `sigma`
/// contiguously.
fn dft3_to_natural(src: &[u16], dst: &mut [u16], words: usize, coeff: &[u16]) {
    debug_assert_eq!(src.len(), CONV * words);
    debug_assert_eq!(dst.len(), CONV * words);
    let mut rows: [&[u16]; 3] = [&[]; 3];
    for b in 0..5 {
        for c in 0..17 {
            for a in 0..3 {
                let s = gt_index(a, b, c) * words;
                rows[a] = &src[s..s + words];
            }
            for k in 0..3 {
                let d = gt_natural(k, b, c) * words;
                fold_rows(&mut dst[d..d + words], &rows, &coeff[k * 3..][..3]);
            }
        }
    }
}

/// First inverse radix-3 stage: natural spectral order into
/// Good-Thomas coordinate order.
fn idft3_from_natural(src: &[u16], dst: &mut [u16], words: usize, coeff: &[u16]) {
    debug_assert_eq!(src.len(), CONV * words);
    debug_assert_eq!(dst.len(), CONV * words);
    let mut rows: [&[u16]; 3] = [&[]; 3];
    for b in 0..5 {
        for c in 0..17 {
            for a in 0..3 {
                let s = gt_natural(a, b, c) * words;
                rows[a] = &src[s..s + words];
            }
            for k in 0..3 {
                let d = gt_index(k, b, c) * words;
                fold_rows(&mut dst[d..d + words], &rows, &coeff[k * 3..][..3]);
            }
        }
    }
}

/// Last inverse radix-17 stage, pruned at the destination. Stage 1
/// needs only natural indices `v = 254-t`, `t < 128`, so computing the
/// other 127 inverse outputs would be pure waste.
fn idft17_pruned(src: &[u16], dst: &mut [&mut [u16]], words: usize, coeff: &[u16]) {
    debug_assert_eq!(src.len(), CONV * words);
    let mut rows: [&[u16]; 17] = [&[]; 17];
    for (t, out) in dst.iter_mut().enumerate() {
        let v = CONV - 1 - t;
        let (a, b, c) = (v % 3, v % 5, v % 17);
        for n in 0..17 {
            let s = gt_index(a, b, n) * words;
            rows[n] = &src[s..s + words];
        }
        fold_rows(&mut out[..], &rows, &coeff[c * 17..][..17]);
    }
}

/// Per-stripe disjoint views of every row, built by repeated
/// `split_at_mut` so the borrows are provably disjoint - the shape
/// `linalg::fold_parallel` uses to own its destination cells. Returns
/// `(column offset, one slice per row)` per stripe.
fn column_stripes(rows: &mut [Vec<u16>], w: usize) -> Vec<(usize, Vec<&mut [u16]>)> {
    let words = rows.first().map_or(0, |r| r.len());
    let n = words.div_ceil(w.max(1)).max(1);
    let mut out: Vec<(usize, Vec<&mut [u16]>)> = (0..n)
        .map(|i| (i * w, Vec::with_capacity(rows.len())))
        .collect();
    for row in rows.iter_mut() {
        let mut rest: &mut [u16] = row.as_mut_slice();
        for slot in out.iter_mut() {
            let take = rest.len().min(w);
            let (head, tail) = rest.split_at_mut(take);
            slot.1.push(head);
            rest = tail;
        }
    }
    out
}

/// Run `body` over the column stripes of `rows`, one worker per unit
/// until they run out. Units are popped off one mutex exactly as
/// `fold_parallel` drains its grid, so a slow core never sets the wall.
fn per_stripe<F>(rows: &mut [Vec<u16>], w: usize, body: F)
where
    F: Fn(usize, &mut Vec<&mut [u16]>) + Sync,
{
    if rows.is_empty() {
        return;
    }
    let stripes = column_stripes(rows, w);
    let workers = crate::mem::cpu_workers().max(1).min(stripes.len().max(1));
    let units = std::sync::Mutex::new(stripes);
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| {
                loop {
                    let unit = units.lock_ok().pop();
                    let Some((off, mut cells)) = unit else { return };
                    body(off, &mut cells);
                }
            });
        }
    });
}

/// Build one of the plan's coefficient tables across the machine:
/// `stride` words per unit, `f(unit index, unit)`, units independent.
/// The same split `invert_vandermonde` fans its columns out with, and
/// for the same reason - at the repair cap these tables are millions of
/// entries each and they are pure setup, on the wall of every repair
/// that takes this path.
fn par_build(
    out: &mut [u16],
    stride: usize,
    min_units: usize,
    f: impl Fn(usize, &mut [u16]) + Sync,
) {
    let units = out.len() / stride.max(1);
    // `min_units` is the caller's "a thread should own at least this
    // many units to be worth spawning", the same shape
    // `invert_vandermonde` splits its columns on. It is a WORK
    // threshold, not a size one: the `scales` table is m words wide and
    // O(m^2) to build, so a rule keyed on the output length alone left
    // the most expensive table in the plan single-threaded.
    let threads = crate::mem::cpu_workers()
        .min(units / min_units.max(1))
        .max(1);
    if threads < 2 {
        for (i, unit) in out.chunks_mut(stride).enumerate() {
            f(i, unit);
        }
        return;
    }
    let per = units.div_ceil(threads) * stride;
    std::thread::scope(|s| {
        for (w, slab) in out.chunks_mut(per).enumerate() {
            let f = &f;
            s.spawn(move || {
                let base = w * (per / stride);
                for (i, unit) in slab.chunks_mut(stride).enumerate() {
                    f(base + i, unit);
                }
            });
        }
    });
}

/// Exactly one implementation of the 255-point transforms used by stage 1.
/// Keeping this as a plan-time choice matters beyond the small coefficient
/// tables themselves: the direct arm must not allocate mixed scratch, and the
/// mixed arm must not retain 65,280 dead direct coefficients per repair.
enum Stage1Plan {
    Direct {
        fwd: Vec<u16>,
        inv: Vec<u16>,
    },
    Mixed {
        f3: Vec<u16>,
        f5: Vec<u16>,
        f17: Vec<u16>,
        i3: Vec<u16>,
        i5: Vec<u16>,
        i17: Vec<u16>,
    },
}

impl Stage1Plan {
    #[inline]
    fn is_mixed(&self) -> bool {
        matches!(self, Stage1Plan::Mixed { .. })
    }
}

/// The scalar half of the solve, built once per repair from the missing
/// columns' base logs and the first recovery exponent: the master
/// polynomial that drives stage 1 and the per-column coefficients that
/// drive stage 2.
pub(super) struct ForneyPlan {
    m: usize,
    /// `ceil(m / BLK)`: input AND output segments, and (because the
    /// Hankel matrix is triangular) also the number of live kernels.
    nseg: usize,
    /// Spectra of the reversed Hankel kernels, `[s * CONV + sigma]`,
    /// `s` in `0..nseg`.
    rhat: Vec<u16>,
    /// Direct or Good-Thomas coefficient tables, selected once at prepare
    /// time. The forward mixed transform runs 17 -> 5 -> 3 (source-pruned
    /// at 17); its inverse runs 3 -> 5 -> 17 (destination-pruned at 17).
    stage1: Stage1Plan,
    /// `T` row indices in `t mod 257` order, with `t_off` the 258 group
    /// boundaries into it.
    t_order: Vec<u32>,
    t_off: Vec<usize>,
    /// Stage-2 group coefficients laid out to match `t_order`:
    /// `[g * m + idx] = α^{k1_g * (t_order[idx] mod 255)}`.
    stage_a: Vec<u16>,
    /// Stage-2 per-column coefficients, `[c * GT2 + t2]`, with the
    /// column's whole scale folded in.
    evalc: Vec<u16>,
    /// Column indices per stage-2 group, parallel to `stage_a`'s rows.
    groups: Vec<Vec<u32>>,
}

impl ForneyPlan {
    /// Build the plan for missing columns with base logs `ks` and first
    /// recovery exponent `e0`. `None` on a duplicate base - the same
    /// theoretically-impossible case `invert_vandermonde` returns `None`
    /// for, and the same fallback (Gauss-Jordan and the dense product).
    pub(super) fn prepare(ks: &[u32], e0: u32) -> Option<ForneyPlan> {
        Self::prepare_with_dft(ks, e0, mixed_dft_gate())
    }

    /// Constructor with an explicit stage-one implementation. Tests use
    /// this to compare both arithmetic paths in one process without mutating
    /// the process-global environment; production enters through `prepare`.
    fn prepare_with_dft(ks: &[u32], e0: u32, mixed: bool) -> Option<ForneyPlan> {
        let m = ks.len();
        if m == 0 {
            return None;
        }
        let bases: Vec<u16> = ks.iter().map(|&k| gf16::pow2(k as u64)).collect();
        // P(z) = Π (z + g_c), degree m: p[i] is the z^i coefficient.
        // Identical to invert_vandermonde's build - the same polynomial
        // in the same order, because it is the same factorization.
        let mut p = vec![0u16; m + 1];
        p[0] = 1;
        for (deg, &g) in bases.iter().enumerate() {
            let t = MulTable::new(g);
            p[deg + 1] = p[deg];
            for i in (1..=deg).rev() {
                p[i] = p[i - 1] ^ t.mul(p[i]);
            }
            p[0] = t.mul(p[0]);
        }
        // d_c = Π_{k≠c}(g_c + g_k) = P'(g_c), and in characteristic 2
        // the formal derivative keeps only the odd coefficients:
        // P'(z) = Σ_j p[2j+1] * (z^2)^j.
        let dodd: Vec<u16> = (0..)
            .map(|j| 2 * j + 1)
            .take_while(|&i| i <= m)
            .map(|i| p[i])
            .collect();
        let mut scales = vec![0u16; m];
        par_build(&mut scales, 1, 64, |c, slot| {
            let z2 = MulTable::new(gf16::mul(bases[c], bases[c]));
            let mut d = 0u16;
            for &coef in dodd.iter().rev() {
                d = z2.mul(d) ^ coef;
            }
            // A zero here is a duplicate base, which cannot happen for
            // valid ks; it leaves the scale zero and the caller refuses
            // below rather than solving a singular system quietly.
            slot[0] = if d == 0 {
                0
            } else {
                let neg_e0 = gf16::ORDER as u64 - (ks[c] as u64 * e0 as u64) % gf16::ORDER as u64;
                gf16::mul(gf16::inv(d), gf16::pow2(neg_e0))
            };
        });
        if scales.contains(&0) {
            return None; // duplicate base - Gauss-Jordan takes it from here
        }

        let nseg = m.div_ceil(BLK);
        // ω = 2^257 has order 65535/257 = 255 = CONV.
        let wpow: Vec<u16> = (0..CONV)
            .map(|i| gf16::pow2(257 * i as u64 % gf16::ORDER as u64))
            .collect();
        // The reversed Hankel kernels: R_s[w] = p[s*BLK + 2*BLK-1 - w],
        // reversed so the correlation T_t = Σ_r S_r p[r+t+1] reads off
        // the CONVOLUTION at v = 2*BLK-2-t. Zero for s >= nseg, which is
        // the triangularity the spectral accumulate exploits below.
        let mut rhat = vec![0u16; nseg * CONV];
        par_build(&mut rhat, CONV, 1, |s, out| {
            for w in 0..CONV {
                let idx = s * BLK + 2 * BLK - 1 - w;
                let rv = if idx <= m { p[idx] } else { 0 };
                if rv == 0 {
                    continue;
                }
                let t = MulTable::new(rv);
                for (sigma, slot) in out.iter_mut().enumerate() {
                    *slot ^= t.mul(wpow[sigma * w % CONV]);
                }
            }
        });
        let stage1 = if mixed {
            // Good-Thomas split 255 = 3*5*17.  85, 51 and 120 are the CRT
            // idempotents for those radices. There are no twiddle factors;
            // the inverse matrices only negate the root exponent. Since
            // 255 is odd its field representation is one in characteristic
            // two, so the inverse DFT has no additional scale.
            Stage1Plan::Mixed {
                f3: dft_matrix(&wpow, 3, 85, false),
                f5: dft_matrix(&wpow, 5, 51, false),
                f17: dft_matrix(&wpow, 17, 120, false),
                i3: dft_matrix(&wpow, 3, 85, true),
                i5: dft_matrix(&wpow, 5, 51, true),
                i17: dft_matrix(&wpow, 17, 120, true),
            }
        } else {
            let mut fwd = vec![0u16; CONV * BLK];
            for sigma in 0..CONV {
                for r in 0..BLK {
                    fwd[sigma * BLK + r] = wpow[sigma * r % CONV];
                }
            }
            // Output v = 2*BLK-2-t, the same pruned direct inverse the
            // shipped path uses.
            let mut inv = vec![0u16; BLK * CONV];
            for t in 0..BLK {
                let v = 2 * BLK - 2 - t;
                for sigma in 0..CONV {
                    inv[t * CONV + sigma] = wpow[(CONV - sigma * v % CONV) % CONV];
                }
            }
            Stage1Plan::Direct { fwd, inv }
        };

        // Stage 2. α and β are the Good-Thomas halves: CRT on the
        // exponent ring Z_65535 ≅ Z_255 x Z_257 with 257^-1 ≡ 128 (mod
        // 255) and 255^-1 ≡ 128 (mod 257).
        let apow: Vec<u16> = (0..CONV)
            .map(|i| gf16::pow2(257 * 128 * i as u64 % gf16::ORDER as u64))
            .collect();
        let bpow: Vec<u16> = (0..GT2)
            .map(|i| gf16::pow2(255 * 128 * i as u64 % gf16::ORDER as u64))
            .collect();
        let mut t_order: Vec<u32> = Vec::with_capacity(m);
        let mut t_off: Vec<usize> = Vec::with_capacity(GT2 + 1);
        for t2 in 0..GT2 {
            t_off.push(t_order.len());
            let mut t = t2;
            while t < m {
                t_order.push(t as u32);
                t += GT2;
            }
        }
        t_off.push(t_order.len());
        // Columns grouped by k1 = k_c mod 255. Base logs are coprime to
        // 65535, so k1 is coprime to 255 and at most φ(255) = 128 groups
        // ever exist, whatever m is.
        let mut seen: Vec<Option<usize>> = vec![None; CONV];
        let mut k1s: Vec<usize> = Vec::new();
        let mut groups: Vec<Vec<u32>> = Vec::new();
        for (c, &k) in ks.iter().enumerate() {
            let k1 = k as usize % CONV;
            let g = *seen[k1].get_or_insert_with(|| {
                k1s.push(k1);
                groups.push(Vec::new());
                k1s.len() - 1
            });
            groups[g].push(c as u32);
        }
        let mut stage_a = vec![0u16; k1s.len() * m];
        par_build(&mut stage_a, m, 1, |g, row| {
            let k1 = k1s[g];
            for (idx, &t) in t_order.iter().enumerate() {
                row[idx] = apow[k1 * (t as usize % CONV) % CONV];
            }
        });
        let mut evalc = vec![0u16; m * GT2];
        par_build(&mut evalc, GT2, 8, |c, row| {
            let k2 = ks[c] as usize % GT2;
            let sc = MulTable::new(scales[c]);
            for (t2, slot) in row.iter_mut().enumerate() {
                *slot = sc.mul(bpow[k2 * t2 % GT2]);
            }
        });
        Some(ForneyPlan {
            m,
            nseg,
            rhat,
            stage1,
            t_order,
            t_off,
            stage_a,
            evalc,
            groups,
        })
    }

    /// Stripe width: a POWER OF TWO between [`STRIPE_GRAN`] and 512
    /// words, the largest that keeps stage 1's spectral arena inside
    /// [`SPECTRA_BUDGET`] per worker. A deep repair therefore narrows
    /// its stripes rather than growing its footprint.
    /// `NZBFAST_BACKSUB_W` pins the width instead (a bench knob).
    ///
    /// A power of two, not merely a multiple of the granule, so that
    /// the LAST stripe is aligned too: block sizes are multiples of 64
    /// bytes in every set anyone posts, so `words % w` is then a whole
    /// number of granules as well.
    fn stripe_w(&self, words: usize) -> usize {
        if let Some(w) = std::env::var("NZBFAST_BACKSUB_W")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&w| w >= 16)
        {
            return w.min(words.max(1));
        }
        let per_word = (self.nseg * CONV).max(1) * 2;
        let by_budget = (SPECTRA_BUDGET / per_word).clamp(STRIPE_GRAN, 512);
        // Largest power of two that fits the budget.
        let w = 1usize << by_budget.ilog2();
        w.min(words.max(1))
    }

    /// Stage 1: `T_t = Σ_r S_r * p[r + t + 1]`, the blocked Hankel
    /// product. Consumes nothing; the caller drops the syndromes as
    /// soon as this returns, so the peak stays the two `m x block`
    /// buffers the dense product also holds.
    pub(super) fn hankel(&self, syn: &[Vec<u16>], words: usize) -> Vec<Vec<u16>> {
        let t0 = std::time::Instant::now();
        let mut t: Vec<Vec<u16>> = vec![vec![0u16; words]; self.m];
        let w = self.stripe_w(words);
        let mixed = self.stage1.is_mixed();
        per_stripe(&mut t, w, |off, cells| {
            let len = cells[0].len();
            let mut shat = vec![0u16; self.nseg * CONV * len];
            let mut chat = vec![0u16; CONV * len];
            // Two transform arenas, reused by every segment. They add
            // 510 rows to the nseg*255 spectral arena but replace each
            // direct 255x128 transform with the 3x5x17 network.
            let dft_words = if mixed { CONV * len } else { 0 };
            let mut dft_a = vec![0u16; dft_words];
            let mut dft_b = vec![0u16; dft_words];
            let mut ssrc: Vec<&[u16]> = Vec::with_capacity(BLK);
            let mut sp: Vec<&[u16]> = Vec::with_capacity(self.nseg);
            let mut coeffs: Vec<u16> = Vec::with_capacity(self.nseg);
            // Forward: one length-CONV DFT per input segment.
            for j in 0..self.nseg {
                let r0 = j * BLK;
                let r1 = (r0 + BLK).min(self.m);
                ssrc.clear();
                ssrc.extend(syn[r0..r1].iter().map(|row| &row[off..off + len]));
                match &self.stage1 {
                    Stage1Plan::Mixed { f3, f5, f17, .. } => {
                        dft_a.fill(0);
                        dft_b.fill(0);
                        dft17_sparse(&ssrc, &mut dft_a, len, f17);
                        dft5(&dft_a, &mut dft_b, len, f5);
                        dft3_to_natural(&dft_b, &mut shat[j * CONV * len..][..CONV * len], len, f3);
                    }
                    Stage1Plan::Direct { fwd, .. } => {
                        for sigma in 0..CONV {
                            let dst = &mut shat[(j * CONV + sigma) * len..][..len];
                            fold_rows(dst, &ssrc, &fwd[sigma * BLK..][..ssrc.len()]);
                        }
                    }
                }
            }
            // One output segment at a time: accumulate its spectrum,
            // then transform it straight back into T's rows, so only
            // ONE output spectrum is ever resident.
            for i in 0..self.nseg {
                chat.fill(0);
                // Kernels past nseg-1 are zero (p[.] runs out), so the
                // pair loop is triangular: j <= nseg-1-i.
                let jn = self.nseg - i;
                for sigma in 0..CONV {
                    sp.clear();
                    coeffs.clear();
                    for j in 0..jn {
                        sp.push(&shat[(j * CONV + sigma) * len..][..len]);
                        coeffs.push(self.rhat[(i + j) * CONV + sigma]);
                    }
                    let dst = &mut chat[sigma * len..][..len];
                    fold_rows(dst, &sp, &coeffs);
                }
                let t0 = i * BLK;
                let t1 = (t0 + BLK).min(self.m);
                match &self.stage1 {
                    Stage1Plan::Mixed { i3, i5, i17, .. } => {
                        dft_a.fill(0);
                        dft_b.fill(0);
                        idft3_from_natural(&chat, &mut dft_a, len, i3);
                        dft5(&dft_a, &mut dft_b, len, i5);
                        idft17_pruned(&dft_b, &mut cells[t0..t1], len, i17);
                    }
                    Stage1Plan::Direct { inv, .. } => {
                        let cs: Vec<&[u16]> = (0..CONV).map(|s| &chat[s * len..][..len]).collect();
                        for (tp, row) in cells[t0..t1].iter_mut().enumerate() {
                            fold_rows(&mut row[..], &cs, &inv[tp * CONV..][..CONV]);
                        }
                    }
                }
            }
        });
        if std::env::var_os("NZBFAST_REPAIR_TIMING").is_some() {
            info!(
                target: "repair-timing",
                "  forney stage 1 (hankel, nseg={}, stripe {w}w, dft={}): {:.2?}",
                self.nseg,
                if mixed { "3x5x17" } else { "direct" },
                t0.elapsed()
            );
        }
        t
    }

    /// Stage 2: `x_c = scale_c * Σ_t T_t * 2^{k_c t}`, through the
    /// Good-Thomas split of the 65535-point transform. `out` must be
    /// zeroed - every row is written by exactly one stripe unit.
    pub(super) fn evaluate(&self, t: &[Vec<u16>], out: &mut [Vec<u16>]) {
        let t0 = std::time::Instant::now();
        let words = out.first().map_or(0, |r| r.len());
        let w = self.stripe_w(words);
        // Groups are TILED, and the tile is the whole point of the loop
        // order below. Stage 2 sweeps every row of T once per group, and
        // a row's stripe is a few hundred bytes out of every block-sized
        // row - a strided gather over the whole m x block buffer, with
        // nothing but the stripe of each page used. Measured at m =
        // 8,192 / 64 KiB on the M3 Ultra, one group at a time ran the
        // stage at 240 GB/s against stage 1's 472; tiling the groups so
        // one gather feeds `gtile` destinations puts the re-reads in
        // cache and takes the stage back to the kernel's rate. The tile
        // is sized by the same per-worker budget the stripe width is.
        let gtile = (SPECTRA_BUDGET / (GT2 * w.max(1) * 2)).clamp(1, self.groups.len().max(1));
        per_stripe(out, w, |off, cells| {
            let len = cells[0].len();
            let mut b = vec![0u16; gtile * GT2 * len];
            let mut tsrc: Vec<&[u16]> = Vec::with_capacity(self.m.div_ceil(GT2).max(1));
            for (tile, gt) in self.groups.chunks(gtile).enumerate() {
                let base = tile * gtile;
                b.fill(0);
                for t2 in 0..GT2 {
                    let (a, z) = (self.t_off[t2], self.t_off[t2 + 1]);
                    if a == z {
                        continue;
                    }
                    tsrc.clear();
                    tsrc.extend(
                        self.t_order[a..z]
                            .iter()
                            .map(|&r| &t[r as usize][off..off + len]),
                    );
                    for gi in 0..gt.len() {
                        let arow = &self.stage_a[(base + gi) * self.m..][..self.m];
                        fold_rows(&mut b[(gi * GT2 + t2) * len..][..len], &tsrc, &arow[a..z]);
                    }
                }
                for (gi, cols) in gt.iter().enumerate() {
                    let bs: Vec<&[u16]> = (0..GT2)
                        .map(|s| &b[(gi * GT2 + s) * len..][..len])
                        .collect();
                    for &c in cols {
                        let c = c as usize;
                        fold_rows(&mut cells[c][..], &bs, &self.evalc[c * GT2..][..GT2]);
                    }
                }
            }
        });
        if std::env::var_os("NZBFAST_REPAIR_TIMING").is_some() {
            info!(
                target: "repair-timing",
                "  forney stage 2 (evaluate, {} group(s) in tiles of {gtile}, stripe {w}w): {:.2?}",
                self.groups.len(),
                t0.elapsed()
            );
        }
    }

    /// Both stages, for the harness and the bench door. The repair
    /// driver calls the halves separately so it can drop the syndromes
    /// between them.
    pub(super) fn solve(&self, syn: &[Vec<u16>], words: usize) -> Vec<Vec<u16>> {
        let t = self.hankel(syn, words);
        let mut out: Vec<Vec<u16>> = vec![vec![0u16; words]; self.m];
        self.evaluate(&t, &mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The constants are load-bearing arithmetic, not tuning: the
    /// blocked convolution is exact only because `CONV = 2*BLK - 1`, and
    /// the evaluation stage is a Good-Thomas split only because
    /// `CONV * GT2 = 65535` with the two halves coprime.
    #[test]
    fn split_constants_are_the_ones_the_algebra_needs() {
        assert_eq!(CONV, 2 * BLK - 1);
        assert_eq!(CONV * GT2, gf16::ORDER as usize);
        // Coprime halves are what makes the CRT index map a bijection.
        let (mut a, mut b) = (CONV, GT2);
        while b != 0 {
            (a, b) = (b, a % b);
        }
        assert_eq!(a, 1, "the Good-Thomas halves must be coprime");
    }

    /// `2^257` must have order exactly `CONV`, or the length-255 cyclic
    /// convolution in stage 1 is not a convolution at all.
    #[test]
    fn conv_root_has_exactly_the_convolution_order() {
        let w = gf16::pow2(257);
        let mut v = 1u16;
        for i in 1..=CONV {
            v = gf16::mul(v, w);
            assert_eq!(v == 1, i == CONV, "2^257 hit 1 at {i}, wanted {CONV}");
        }
    }

    /// The Good-Thomas layout must be a permutation of natural indices,
    /// and each coordinate must really be the three advertised residues.
    /// This is also the proof that source- and destination-pruning below
    /// cannot alias or silently omit a live row.
    #[test]
    fn good_thomas_coordinates_are_a_bijection() {
        let mut seen = [false; CONV];
        for a in 0..3 {
            for b in 0..5 {
                for c in 0..17 {
                    let n = gt_natural(a, b, c);
                    assert_eq!((n % 3, n % 5, n % 17), (a, b, c));
                    assert!(!seen[n], "CRT coordinates aliased natural index {n}");
                    seen[n] = true;
                }
            }
        }
        assert!(seen.into_iter().all(|v| v));

        // Every legal partial segment: the sparse forward admits exactly
        // n=0..len, and the pruned inverse emits exactly v=254-t for the
        // same local t range. Hold the sets independently of arithmetic.
        for len in 0..=BLK {
            let mut forward = [false; CONV];
            let mut inverse = [false; CONV];
            for n in 0..len {
                let coord = gt_index(n % 3, n % 5, n % 17);
                assert!(!forward[coord]);
                forward[coord] = true;
            }
            for t in 0..len {
                let v = CONV - 1 - t;
                let coord = gt_index(v % 3, v % 5, v % 17);
                assert!(!inverse[coord]);
                inverse[coord] = true;
            }
            assert_eq!(forward.into_iter().filter(|&v| v).count(), len);
            assert_eq!(inverse.into_iter().filter(|&v| v).count(), len);
        }
    }

    /// Hold the mixed-radix network to the definition of the direct DFT
    /// at partial-segment and fused-kernel tail boundaries. This calls
    /// the real row-fold helpers; the oracle is scalar GF multiplication
    /// and shares neither the factorization nor its indexing.
    #[test]
    fn mixed_dft_matches_direct_at_segment_edges() {
        let wpow: Vec<u16> = (0..CONV)
            .map(|i| gf16::pow2(257 * i as u64 % gf16::ORDER as u64))
            .collect();
        let (f3, f5, f17) = (
            dft_matrix(&wpow, 3, 85, false),
            dft_matrix(&wpow, 5, 51, false),
            dft_matrix(&wpow, 17, 120, false),
        );
        let (i3, i5, i17) = (
            dft_matrix(&wpow, 3, 85, true),
            dft_matrix(&wpow, 5, 51, true),
            dft_matrix(&wpow, 17, 120, true),
        );
        for (rows, words) in [
            (1usize, 1usize),
            (2, 15),
            (3, 16),
            (16, 17),
            (17, 31),
            (63, 32),
            (127, 33),
            (128, 48),
        ] {
            let input: Vec<Vec<u16>> = (0..rows)
                .map(|n| {
                    (0..words)
                        .map(|w| ((n * 0x9e37 + w * 0x79b9 + 1) & 0xffff) as u16)
                        .collect()
                })
                .collect();
            let refs: Vec<&[u16]> = input.iter().map(Vec::as_slice).collect();
            let mut a = vec![0u16; CONV * words];
            let mut b = vec![0u16; CONV * words];
            let mut got = vec![0u16; CONV * words];
            dft17_sparse(&refs, &mut a, words, &f17);
            dft5(&a, &mut b, words, &f5);
            dft3_to_natural(&b, &mut got, words, &f3);
            let mut want = vec![0u16; CONV * words];
            for sigma in 0..CONV {
                for n in 0..rows {
                    let c = wpow[sigma * n % CONV];
                    for w in 0..words {
                        want[sigma * words + w] ^= gf16::mul(c, input[n][w]);
                    }
                }
            }
            assert_eq!(got, want, "forward DFT: rows={rows} words={words}");

            // Independent, fully populated spectrum: an inverse of the
            // sparse forward alone would mostly return padded zeros and
            // would under-exercise the destination-pruning coefficients.
            let spectrum: Vec<u16> = (0..CONV * words)
                .map(|i| ((i * 0xd1b5 + rows * 0x4a33 + 7) & 0xffff) as u16)
                .collect();
            a.fill(0);
            b.fill(0);
            idft3_from_natural(&spectrum, &mut a, words, &i3);
            dft5(&a, &mut b, words, &i5);
            let mut out: Vec<Vec<u16>> = vec![vec![0; words]; rows];
            let mut out_refs: Vec<&mut [u16]> = out.iter_mut().map(Vec::as_mut_slice).collect();
            idft17_pruned(&b, &mut out_refs, words, &i17);
            for (t, row) in out.iter().enumerate() {
                let v = CONV - 1 - t;
                let mut direct = vec![0u16; words];
                for sigma in 0..CONV {
                    let e = sigma * v % CONV;
                    let c = wpow[if e == 0 { 0 } else { CONV - e }];
                    for w in 0..words {
                        direct[w] ^= gf16::mul(c, spectrum[sigma * words + w]);
                    }
                }
                assert_eq!(&direct, row, "inverse DFT: t={t} rows={rows} words={words}");
            }
        }
    }

    /// Whole Hankel-stage differential against the shipped direct DFT.
    /// The row counts straddle complete and partial 128-row segments;
    /// word widths straddle the 16-word NEON/AVX2 granule as well as the
    /// 32-word AVX-512 granule. A non-zero e0 also proves that building
    /// both plans through the real constructor does not perturb its
    /// other tables.
    #[test]
    fn mixed_hankel_matches_direct_across_segment_and_stripe_edges() {
        for (m, words) in [
            (1usize, 1usize),
            (127, 15),
            (128, 16),
            (129, 17),
            (254, 31),
            (255, 32),
            (256, 33),
            (257, 48),
            (389, 16),
        ] {
            let ks = crate::par2repair::input_base_logs(m).expect("inside PAR2 block limit");
            let direct_plan =
                ForneyPlan::prepare_with_dft(&ks, 0x51, false).expect("input bases are distinct");
            let mixed_plan =
                ForneyPlan::prepare_with_dft(&ks, 0x51, true).expect("input bases are distinct");
            let syn: Vec<Vec<u16>> = (0..m)
                .map(|r| {
                    (0..words)
                        .map(|w| ((r * 0x9e37 + w * 0x79b9 + 0x243f) & 0xffff) as u16)
                        .collect()
                })
                .collect();
            let direct = direct_plan.hankel(&syn, words);
            let mixed = mixed_plan.hankel(&syn, words);
            assert_eq!(mixed, direct, "Hankel stage: m={m} words={words}");
        }
    }

    /// Selection happens before table construction: a rollback plan must not
    /// pay for mixed matrices, and the production plan must not retain the
    /// much larger direct coefficient tables.
    #[test]
    fn stage1_plan_retains_only_the_selected_transform_tables() {
        let ks = crate::par2repair::input_base_logs(3).unwrap();
        let direct = ForneyPlan::prepare_with_dft(&ks, 7, false).unwrap();
        let mixed = ForneyPlan::prepare_with_dft(&ks, 7, true).unwrap();
        match direct.stage1 {
            Stage1Plan::Direct { fwd, inv } => {
                assert_eq!(fwd.len(), CONV * BLK);
                assert_eq!(inv.len(), BLK * CONV);
            }
            Stage1Plan::Mixed { .. } => panic!("direct plan retained the mixed implementation"),
        }
        match mixed.stage1 {
            Stage1Plan::Mixed {
                f3,
                f5,
                f17,
                i3,
                i5,
                i17,
            } => {
                assert_eq!(f3.len() + i3.len(), 2 * 3 * 3);
                assert_eq!(f5.len() + i5.len(), 2 * 5 * 5);
                assert_eq!(f17.len() + i17.len(), 2 * 17 * 17);
            }
            Stage1Plan::Direct { .. } => panic!("mixed plan retained the direct implementation"),
        }
    }

    /// `SPECTRA_BUDGET` caps the large `nseg*255` arena. The mixed
    /// network adds exactly two reusable 255-row arenas; together with
    /// the already-shipped output spectrum, fixed overhead stays below
    /// 765 KiB per worker at the maximum 512-word stripe.
    #[test]
    fn mixed_dft_worker_scratch_is_bounded() {
        const MAX_FIXED: usize = 3 * CONV * 512 * 2;
        assert_eq!(MAX_FIXED, 783_360);
        for nseg in 1..=crate::par2repair::MAX_REPAIR_DIM.div_ceil(BLK) {
            let per_word = nseg * CONV * 2;
            let by_budget = (SPECTRA_BUDGET / per_word).clamp(STRIPE_GRAN, 512);
            let w = 1usize << by_budget.ilog2();
            assert!(nseg * CONV * w * 2 <= SPECTRA_BUDGET);
            assert!(3 * CONV * w * 2 <= MAX_FIXED);
        }
    }

    /// The identity stage 2 is built on: with `α = 2^{257·128}` and
    /// `β = 2^{255·128}`, CRT on the exponent ring `Z_65535 ≅ Z_255 ×
    /// Z_257` gives `2^e = α^{e mod 255} · β^{e mod 257}`. Checked over
    /// the whole group, since it is only 65535 values and a sampled
    /// check would not be a proof of a CRT constant.
    #[test]
    fn good_thomas_halves_reconstruct_every_power() {
        let apow: Vec<u16> = (0..CONV)
            .map(|i| gf16::pow2(257 * 128 * i as u64 % gf16::ORDER as u64))
            .collect();
        let bpow: Vec<u16> = (0..GT2)
            .map(|i| gf16::pow2(255 * 128 * i as u64 % gf16::ORDER as u64))
            .collect();
        for e in 0..gf16::ORDER as usize {
            assert_eq!(
                gf16::pow2(e as u64),
                gf16::mul(apow[e % CONV], bpow[e % GT2]),
                "CRT split disagreed at e={e}"
            );
        }
    }

    /// The default arm of the gate, pinned to the constant it documents.
    /// Deliberately does NOT set `NZBFAST_BACKSUB`: it is a process-wide
    /// escape hatch and this binary runs every other test beside this
    /// one (the one-process rule in CLAUDE.md's build section).
    ///
    /// The default arm is TWO conditions, and this pins both. It used to
    /// assert a bare `true` at the constant, which is the answer on every
    /// part that has a fused multi kernel and the WRONG one on a part that
    /// does not - `backsub_gate` says so itself, four lines above the
    /// expression: "on a part with no fused kernel (armv7, or an
    /// `NZBFAST_GF16_MULTI=0` kernel A/B) the measured ratios do not
    /// transfer and the dense product keeps the shape". So the nightly
    /// armv7-cross job failed here on a gate that was behaving exactly as
    /// documented (run 33737735769), and an `NZBFAST_GF16_MULTI=0` A/B on
    /// any box would have failed it the same way.
    ///
    /// Derived from `multi_fold_width()` rather than gated out on armv7:
    /// the constant is still pinned wherever it is observable, and where
    /// it is not, the no-kernel behaviour the gate promises is pinned
    /// instead. Both arms are checked on every part.
    #[test]
    fn gate_defaults_to_the_measured_constant() {
        if std::env::var_os("NZBFAST_BACKSUB").is_some() {
            return;
        }
        let fused = gf16::multi_fold_width() > 0;
        assert!(!backsub_gate(BACKSUB_MIN_MISSING - 1));
        assert_eq!(
            backsub_gate(BACKSUB_MIN_MISSING),
            fused,
            "at the constant the gate is the fused-multi-kernel arm alone"
        );
    }
}
