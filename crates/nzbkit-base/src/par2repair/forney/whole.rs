//! Size-matched ordinary polynomial multiplication over PAR2's
//! GF(2^16): stage 1 of the JOINT solve.
//!
//! # What it replaces
//!
//! [`super::ForneyPlan::hankel`] computes `T_t = Σ_r S_r * p[r+t+1]` as
//! a blocked cyclic convolution: segments of 128, a length-255 DFT per
//! segment, a triangular spectral accumulate, an inverse DFT per output
//! segment. That is a correlation done in a MULTIPLICATIVE transform
//! domain, and its cost has an `nseg^2` term because the segments have
//! to be paired.
//!
//! The same correlation is one ordinary polynomial product of the
//! reversed syndrome vector with `B = p[1..]`, and over a field of
//! characteristic two that product has an ADDITIVE transform with no
//! segmenting at all: pad both to `n = next_power_of_two(2m - 1)`,
//! transform, multiply pointwise, transform back. `B` is a plan
//! constant, so its spectrum ([`Kernel::bhat`]) is built once per repair
//! and the solve pays for one forward transform, one scale and one
//! inverse per stripe.
//!
//! # Three prunings, all of them load-bearing
//!
//! The naive form would transform `n` rows where only `m` are live and
//! invert `n` rows where only `m` are read:
//!
//! - [`forward_rows`] tracks a LIVE map and skips any butterfly whose
//!   source is still zero. The input occupies the low `m` of `n/2`
//!   rows, so at `m` just past a power of two most of the first levels
//!   are skipped entirely.
//! - [`demand::Plan`] walks the inverse transform BACKWARD from the
//!   `m..2m-1` rows the caller will actually read and records, per
//!   level, exactly which butterflies feed them - coalesced into
//!   contiguous runs so the surviving work is still native-width folds.
//! - [`backward_band`] does the same for the basis conversion that
//!   follows: every edge runs from a higher coefficient to a lower one,
//!   so coefficients above the product degree are zero and destinations
//!   below the requested band cannot reach a requested output.
//!
//! # Memory: this arena replaces stage 1's, it does not add to it
//!
//! A stripe holds `n * w` words here where the two-stage path holds
//! `(nseg + 3) * CONV * w`. [`admitted_width`] is the reconciliation:
//! it takes the width the shipped budget already granted and halves it
//! until the additive arena fits inside the byte allowance the
//! multiplicative one would have had. So the joint arm can only ever
//! hold LESS per worker than the arm it replaces, and a zero return
//! means even the narrowest stripe would not fit - the caller then
//! falls back to the shipped path rather than spending more.
use crate::gf16;

mod demand;

/// The Cantor basis, the same one [`super::poly`] uses. Kept as its own
/// copy because these two transforms are different sizes and different
/// element types (block rows here, scalars there) and share no code;
/// the RELATION between the two tables is asserted in [`terms`].
const CANTOR: [u16; 16] = [
    1, 350, 26, 7410, 5786, 48044, 64994, 18058, 1810, 7030, 44396, 17984, 42910, 62132, 63354,
    32738,
];

/// One repair's stage-1 kernel: the transform geometry plus the
/// spectrum of `B`. Built once in [`super::joint::JointPlan::new`] and
/// read by every stripe of every solve.
pub(super) struct Kernel {
    /// Transform size: `next_power_of_two(2 * b.len() - 1)`, at least 2.
    pub(super) n: usize,
    levels: usize,
    terms: Vec<Vec<usize>>,
    tw: Vec<Vec<gf16::FoldCoeff>>,
    /// `B` transformed: one prepared coefficient per point.
    bhat: Vec<gf16::FoldCoeff>,
    demand: demand::Plan,
}

/// The level-`i` subspace polynomial at `x`. Linear over GF(2), which is
/// what the Cantor basis buys and what [`terms`] asserts.
fn lin_eval(terms: &[usize], lead: usize, x: u16) -> u16 {
    let mut v = 0;
    let mut p = x;
    for j in 0..=lead {
        if j == lead || terms.contains(&j) {
            v ^= p;
        }
        p = gf16::mul(p, p);
    }
    v
}

/// The per-level term sets, derived by squaring the previous level's
/// subspace polynomial. Every step asserts the Cantor relation and the
/// normalisation `s_i(C[i]) = 1`, so a wrong constant fails here rather
/// than as a silently wrong repair.
fn terms(levels: usize) -> Vec<Vec<usize>> {
    assert!((1..=16).contains(&levels));
    let mut coeff = vec![1u16];
    let mut out = Vec::new();
    for (i, &v) in CANTOR.iter().enumerate().take(levels) {
        if i > 0 {
            assert_eq!(gf16::mul(v, v) ^ v, CANTOR[i - 1]);
        }
        let ts: Vec<_> = (0..i).filter(|&j| coeff[j] == 1).collect();
        assert!(coeff.iter().all(|&c| c <= 1));
        assert_eq!(coeff[i], 1);
        assert_eq!(lin_eval(&ts, i, v), 1);
        out.push(ts);
        let mut next = vec![0; coeff.len() + 1];
        for (j, &c) in coeff.iter().enumerate() {
            next[j + 1] ^= gf16::mul(c, c);
            next[j] ^= c;
        }
        coeff = next;
    }
    out
}

/// The twiddle for block `b` of level `i`: the level's subspace
/// polynomial evaluated at the block's coset representative.
fn twiddle(terms: &[Vec<usize>], levels: usize, i: usize, b: usize) -> u16 {
    let mut beta = 0;
    for (t, &v) in CANTOR.iter().enumerate().take(levels).skip(i + 1) {
        if (b >> (t - i - 1)) & 1 != 0 {
            beta ^= v;
        }
    }
    lin_eval(&terms[i], i, beta)
}

/// Monomial basis to Cantor basis, scalar coefficients. The plan-time
/// half of [`forward_rows`].
fn scalar_convert(terms: &[Vec<usize>], a: &mut [u16], levels: usize) {
    for i in (0..levels).rev() {
        let half = 1 << i;
        let blk = 2 * half;
        for base in (0..a.len()).step_by(blk) {
            for t in (half..blk).rev() {
                let q = a[base + t];
                for &j in &terms[i] {
                    a[base + t - half + (1 << j)] ^= q;
                }
            }
        }
    }
}

impl Kernel {
    pub(super) fn heap_bytes(&self) -> usize {
        self.terms.capacity() * std::mem::size_of::<Vec<usize>>()
            + self
                .terms
                .iter()
                .map(|v| v.capacity() * std::mem::size_of::<usize>())
                .sum::<usize>()
            + self.tw.capacity() * std::mem::size_of::<Vec<gf16::FoldCoeff>>()
            + self
                .tw
                .iter()
                .map(|v| v.capacity() * std::mem::size_of::<gf16::FoldCoeff>())
                .sum::<usize>()
            + self.bhat.capacity() * std::mem::size_of::<gf16::FoldCoeff>()
            + self.demand.heap_bytes()
    }

    /// The kernel for `B`, whose coefficients are `p[1..]` of the
    /// locator polynomial. `b` must be non-empty and at most 32,768
    /// long, which `MAX_REPAIR_DIM` already guarantees.
    pub(super) fn new(b: &[u16]) -> Self {
        assert!(!b.is_empty() && b.len() <= 32768);
        let n = (2 * b.len() - 1).next_power_of_two().max(2);
        let levels = n.trailing_zeros() as usize;
        let terms = terms(levels);
        let tw: Vec<Vec<_>> = (0..levels)
            .map(|i| {
                (0..n >> (i + 1))
                    .map(|b| gf16::FoldCoeff::new(twiddle(&terms, levels, i, b)))
                    .collect()
            })
            .collect();
        let mut a = vec![0; n];
        a[..b.len()].copy_from_slice(b);
        scalar_convert(&terms, &mut a, levels);
        for i in (0..levels).rev() {
            let half = 1 << i;
            let blk = 2 * half;
            for (b, base) in (0..n).step_by(blk).enumerate() {
                let c = tw[i][b].coeff();
                for j in 0..half {
                    let v = a[base + half + j];
                    let u = a[base + j] ^ gf16::mul(c, v);
                    a[base + j] = u;
                    a[base + half + j] = u ^ v;
                }
            }
        }
        let bhat = a.into_iter().map(gf16::FoldCoeff::new).collect();
        let demand = demand::Plan::new(n, &tw, b.len());
        Self {
            n,
            levels,
            terms,
            tw,
            bhat,
            demand,
        }
    }
}

/// Two disjoint row views of one arena, by `split_at_mut` so the borrows
/// are provably disjoint - the same shape `column_stripes` uses.
fn two_rows(buf: &mut [u16], w: usize, a: usize, b: usize) -> (&mut [u16], &mut [u16]) {
    assert_ne!(a, b);
    if a < b {
        let (l, r) = buf.split_at_mut(b * w);
        (&mut l[a * w..(a + 1) * w], &mut r[..w])
    } else {
        let (l, r) = buf.split_at_mut(a * w);
        (&mut r[..w], &mut l[b * w..(b + 1) * w])
    }
}

fn xor(d: &mut [u16], s: &[u16]) {
    for (d, &s) in d.iter_mut().zip(s) {
        *d ^= s;
    }
}

/// The product with the full inverse transform, then the banded basis
/// conversion. Used where the demand plan cannot help, which is every
/// shape whose caller reads a band that already spans the transform.
pub(super) fn linear_band(k: &Kernel, buf: &mut [u16], w: usize, count: usize) {
    linear_impl(k, buf, w, count, false);
}

/// The product with the DEMAND-pruned inverse transform and the banded
/// basis conversion: the fully-pruned arm, and the one the
/// power-of-two whole kernel takes.
pub(super) fn linear_demand(k: &Kernel, buf: &mut [u16], w: usize, count: usize) {
    linear_impl(k, buf, w, count, true);
}

/// `buf` is `k.n` rows of `w` words. On entry the low `count` rows hold
/// the (reversed) input and everything above is zero; on return rows
/// `count-1 ..= 2*count-2` hold the product's corresponding
/// coefficients. Rows outside that band are scratch and are NOT
/// meaningful - the two prunings above exist precisely because they are
/// not computed.
fn linear_impl(k: &Kernel, buf: &mut [u16], w: usize, count: usize, demand: bool) {
    assert!(w > 0 && w.is_multiple_of(16) && buf.len() == k.n * w && count <= k.n / 2);
    assert!(count > 0);
    let halfn = k.n / 2;
    let mut live = vec![false; halfn];
    live[..count].fill(true);
    forward_rows(k, buf, w, &mut live);
    let (lo, hi) = buf.split_at_mut(halfn * w);
    hi.copy_from_slice(lo);
    for i in (0..k.levels - 1).rev() {
        let half = 1 << i;
        let blk = 2 * half;
        for (b, base) in (0..k.n).step_by(blk).enumerate() {
            let (lo, hi) = buf.split_at_mut((base + half) * w);
            assert_eq!(
                gf16::butterfly(&mut lo[base * w..], &mut hi[..half * w], &k.tw[i][b], false),
                half * w
            );
        }
    }
    // The caller admitted this arm only where a fused scale kernel
    // exists (`super::joint` checks `scale_available`); assert rather
    // than branch, because a scalar fallback here would be the whole
    // stage running one word at a time.
    assert!(gf16::scale_available());
    for p in 0..k.n {
        assert_eq!(gf16::scale(&mut buf[p * w..(p + 1) * w], &k.bhat[p]), w);
    }
    if demand {
        k.demand.apply(k, buf, w);
    } else {
        inverse_full(k, buf, w);
    }
    backward_band(k, buf, w, count - 1, 2 * count - 2);
}

/// The unpruned inverse transform: every butterfly at every level.
fn inverse_full(k: &Kernel, buf: &mut [u16], w: usize) {
    for i in 0..k.levels {
        let half = 1 << i;
        let blk = 2 * half;
        for (b, base) in (0..k.n).step_by(blk).enumerate() {
            let (lo, hi) = buf.split_at_mut((base + half) * w);
            assert_eq!(
                gf16::butterfly(&mut lo[base * w..], &mut hi[..half * w], &k.tw[i][b], true),
                half * w
            );
        }
    }
}

/// The stripe width this kernel may use, given the byte allowance the
/// two-stage path would have had at `old_w` (`old_rows` rows of it).
/// Zero means even the narrowest supported stripe does not fit, and the
/// caller must fall back rather than spend more than the shipped budget.
pub(super) fn admitted_width(n: usize, old_rows: usize, old_w: usize) -> usize {
    let ceiling = old_rows.saturating_mul(old_w).saturating_mul(2);
    let mut w = old_w;
    while w >= 16 {
        if n.saturating_mul(w).saturating_mul(2).saturating_add(n / 2) <= ceiling {
            return w;
        }
        w /= 2;
    }
    0
}

/// Monomial to Cantor basis over block rows, skipping any source row
/// still known to be zero. The live map is updated as rows become
/// non-zero, so the pruning compounds down the levels.
fn forward_rows(k: &Kernel, buf: &mut [u16], w: usize, live: &mut [bool]) {
    let halfn = k.n / 2;
    for i in (0..k.levels - 1).rev() {
        let half = 1 << i;
        let blk = 2 * half;
        for base in (0..halfn).step_by(blk) {
            for t in (half..blk).rev() {
                let src = base + t;
                if !live[src] {
                    continue;
                }
                for &j in &k.terms[i] {
                    let dst = base + t - half + (1 << j);
                    let (d, s) = two_rows(buf, w, dst, src);
                    xor(d, s);
                    live[dst] = true;
                }
            }
        }
    }
}

/// Cantor to monomial basis, restricted to the band `lower..=upper`.
///
/// Every edge goes from a higher coefficient to a lower one. Values
/// above the product degree are zero, and destinations below the
/// requested band cannot feed any requested output - so both ends can be
/// clipped. The level and block order is the full converter's, unchanged,
/// which is what makes the two byte-identical inside the band.
fn backward_band(k: &Kernel, buf: &mut [u16], w: usize, lower: usize, upper: usize) {
    for i in 0..k.levels {
        let half = 1 << i;
        let blk = 2 * half;
        let Some(&last) = k.terms[i].last() else {
            continue;
        };
        for base in (0..=upper).step_by(blk) {
            let begin = half.max(
                lower
                    .saturating_add(half)
                    .saturating_sub(base + (1 << last)),
            );
            let end = blk.min(upper + 1 - base);
            for t in begin..end {
                for &j in &k.terms[i] {
                    let dst = base + t - half + (1 << j);
                    if dst >= lower {
                        let (d, s) = two_rows(buf, w, dst, base + t);
                        xor(d, s);
                    }
                }
            }
        }
    }
}

/// The unpruned basis conversion. The reference [`backward_band`] is
/// proved against; not on any solve path.
#[cfg(test)]
fn backward_rows(k: &Kernel, buf: &mut [u16], w: usize) {
    for i in 0..k.levels {
        let half = 1 << i;
        let blk = 2 * half;
        for base in (0..k.n).step_by(blk) {
            for t in half..blk {
                for &j in &k.terms[i] {
                    let (d, s) = two_rows(buf, w, base + t - half + (1 << j), base + t);
                    xor(d, s);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    /// The banded basis conversion must agree with the full one on
    /// every coefficient the solve reads, at every transform size the
    /// repair cap admits and at widths on and off the fold granule.
    #[test]
    fn bounded_conversion_preserves_required_band() {
        for levels in 1..=16 {
            let n = 1usize << levels;
            let k = super::Kernel::new(&vec![1; n / 2]);
            for m in [1, (n / 4 + 1).min(n / 2), n / 2] {
                for w in [1, 16, 33] {
                    let mut full: Vec<u16> = (0..n * w)
                        .map(|x| {
                            if x / w < 2 * m - 1 {
                                (x.wrapping_mul(7919) ^ (x >> 3)) as u16
                            } else {
                                0
                            }
                        })
                        .collect();
                    let mut band = full.clone();
                    super::backward_rows(&k, &mut full, w);
                    super::backward_band(&k, &mut band, w, m - 1, 2 * m - 2);
                    assert_eq!(
                        &full[(m - 1) * w..(2 * m - 1) * w],
                        &band[(m - 1) * w..(2 * m - 1) * w],
                        "levels={levels} m={m} w={w}"
                    );
                }
            }
        }
    }

    /// The width reconciliation never grants more bytes than the
    /// two-stage path would have held, and the three pinned cells are
    /// the halving, the exact fit and the refusal.
    #[test]
    fn budget_is_never_enlarged() {
        for m in 1usize..=32768 {
            let n = (2 * m - 1).next_power_of_two().max(2);
            let rows = m.div_ceil(128) * 255 + 765;
            for w in [16, 32, 64, 128, 256, 512] {
                let got = super::admitted_width(n, rows, w);
                assert!(got == 0 || n * got * 2 + n / 2 <= rows * w * 2);
            }
        }
        assert_eq!(super::admitted_width(65536, 49725, 512), 256);
        assert_eq!(super::admitted_width(65536, 66045, 512), 512);
        assert_eq!(super::admitted_width(65536, 49725, 16), 0);
    }
}
