//! The Rader-257 leaf's 256-point cyclic convolution through a 512-point
//! ADDITIVE FFT (Lin, Chung and Han, FOCS 2014: the "novel polynomial
//! basis"), in place of the dense O(n^2) convolution `leaf_dense` and
//! `conjugate::leaf` run.
//!
//! The leaf computes `X[g^m] = x0 + sum_i a_i * b[(m - i) mod 256]`: the
//! cyclic convolution of the leaf's sources (indexed by Rader index i)
//! with the fixed kernel `b`. The dense evaluators spend 257 constant
//! multiplies per source word for it (the paired leaf halves the lookups
//! by conjugacy, it does not change the order), and the leaf is 93% of a
//! big transform on both bench boxes. This routine spends ~19 per source
//! word at a full leaf: cyclic convolution is polynomial multiplication
//! modulo x^256 + 1, a product of two degree-255 polynomials is fixed by
//! its values at 512 points, and over GF(2^16) a 512-point subspace has
//! an O(n log n) evaluation and interpolation - the additive FFT - whose
//! butterflies are one constant multiply and two XORs.
//!
//! Why this and not a multiplicative FFT: 256 does not divide 65,535, so
//! GF(2^16)* has no 256- or 512-point DFT; the additive group has every
//! power of two up to 2^16. (Why the WHOLE transform cannot go this way:
//! PAR2's evaluation points are the multiplicative group, not a
//! subspace, and Bluestein's bridge needs 131,071 points, more than the
//! field has. The Rader leaf's convolution is the one place the two
//! structures meet.)
//!
//! The field is PAR2's, x^16 + x^12 + x^3 + x + 1 (0x1100B), and its
//! degree is a power of two, so it carries a CANTOR basis: v_0 = 1 and
//! v_i^2 + v_i = v_{i-1}. With that basis every subspace polynomial
//! s_i(x) = prod_{a in span(v_0..v_{i-1})} (x - a) has coefficients in
//! {0, 1} and s_i(v_i) = 1 (verified at build, `Kernel::new` refuses
//! otherwise), which is what makes the two basis conversions XOR-only:
//!
//! - novel basis X_j(x) = prod_{i : bit i of j} s_i(x), degree j;
//! - monomial -> novel is long division by s_{k-1}, then by s_{k-2} on
//!   each half, and so on; s_i is monic of degree 2^i with at most i
//!   further terms, all at powers 2^j, so each level is a few XORs of
//!   whole rows;
//! - novel -> monomial is the same XORs in the reverse order.
//!
//! The FFT proper (LCH 2014, Algorithm 2): at stage i the array is
//! blocks of 2^(i+1) rows; for block b with coset base beta_b (the sum of
//! v_t for the bits of b, t > i) and twiddle c = s_i(beta_b), each pair
//! (u, v) at distance 2^i becomes (u + c v, u + c v + v). Output row p
//! holds the evaluation at sum_i bit_i(p) v_i, natural order. The
//! inverse runs the stages the other way with (v + u, u + c v).
//!
//! Per lane word at a full leaf, measured in field multiplies (each a
//! call of the fold kernel over a row): forward FFT 8 x 256 (the ninth
//! stage is a copy: the data occupies degrees < 256, so its top half is
//! zero), pointwise 512, inverse 9 x 256 = 4,864, against 65,792 dense;
//! XORs ~20K (the conversions ~11K, the butterflies ~9K), which the
//! vector units take three per cycle. Sparse leaves pay the same fixed
//! cost, so below ~90 sources the paired leaf is expected to stay ahead;
//! `Kernel::admits` is the gate and the measured crossover belongs
//! there.
//!
//! Numerically checked before this was written (7 Sep 2026): the
//! Cantor chain, binary s_i, FFT against direct evaluation, the inverse
//! as an exact inverse, and the convolution against the direct sum, all
//! in the same field (`research/parfast-rigs-2026-09-05/additive-fft-feas.py`).

use crate::gf16;

/// log2 of the transform size: 512 points, enough for a product of two
/// polynomials of degree < 256.
const K: usize = 9;
/// The transform size.
pub(super) const N2: usize = 1 << K;

/// The Cantor basis of the 9-dimensional subspace, v_0 = 1 and
/// v_i^2 + v_i = v_{i-1} in PAR2's field; the smallest root at each
/// step. Verified by `Kernel::new` rather than trusted.
const CANTOR: [u16; K] = [
    0x0001, 0x015e, 0x001a, 0x1cf2, 0x169a, 0xbbac, 0xfde2, 0x468a, 0x0712,
];

/// The additive leaf's kernel: the twiddles per (stage, block), the
/// kernel polynomial's transform, and the subspace polynomials' term
/// lists the conversions XOR by.
pub(super) struct Kernel {
    /// `tw[i]` is stage i's twiddles, one per block of 2^(i+1) rows.
    tw: Vec<Vec<gf16::FoldCoeff>>,
    /// The Rader kernel b, as a degree-255 polynomial, evaluated at the
    /// 512 points: what the data's transform is multiplied by.
    bhat: Vec<gf16::FoldCoeff>,
    /// `terms[i]` lists the j < i with x^(2^j) present in s_i (the
    /// leading x^(2^i) is implicit).
    terms: Vec<Vec<usize>>,
}

/// `s(x)` for a binary linearised polynomial given by its term list,
/// leading term 2^lead implicit.
fn lin_eval(terms: &[usize], lead: usize, x: u16) -> u16 {
    let mut r = 0u16;
    let mut p = x;
    for j in 0..=lead {
        if j == lead || terms.contains(&j) {
            r ^= p;
        }
        p = gf16::mul(p, p);
    }
    r
}

/// The subspace polynomials s_0..s_K of the Cantor basis, as term
/// lists, or None if the basis is not Cantor in this field (the
/// recurrence s_{i+1} = s_i^2 + s_i(v_i) s_i then leaves a coefficient
/// outside {0, 1}).
fn subspace_terms() -> Option<Vec<Vec<usize>>> {
    // Coefficients c_j of x^(2^j), full precision while building.
    let mut coeffs: Vec<Vec<u16>> = vec![vec![1]];
    for i in 0..K {
        let ci = &coeffs[i];
        let mut siv = 0u16;
        let mut p = CANTOR[i];
        for &c in ci {
            siv ^= gf16::mul(c, p);
            p = gf16::mul(p, p);
        }
        if siv != 1 {
            return None;
        }
        let mut next = vec![0u16; ci.len() + 1];
        for (j, &c) in ci.iter().enumerate() {
            next[j + 1] ^= gf16::mul(c, c);
            next[j] ^= c; // siv == 1
        }
        coeffs.push(next);
    }
    let mut terms = Vec::with_capacity(K + 1);
    for (i, ci) in coeffs.iter().enumerate() {
        if ci.iter().any(|&c| c > 1) || ci[i] != 1 {
            return None;
        }
        terms.push((0..i).filter(|&j| ci[j] == 1).collect::<Vec<_>>());
    }
    Some(terms)
}

/// Stage i, block b's twiddle: s_i at the block's coset base.
fn twiddle(terms: &[Vec<usize>], i: usize, b: usize) -> u16 {
    let mut beta = 0u16;
    for t in i + 1..K {
        if (b >> (t - i - 1)) & 1 == 1 {
            beta ^= CANTOR[t];
        }
    }
    lin_eval(&terms[i], i, beta)
}

/// Scalar monomial -> novel conversion, in place, over `n = 2^levels`
/// coefficients (the row version's mirror, for the kernel's transform
/// and the tests).
fn convert_scalar_forward(terms: &[Vec<usize>], a: &mut [u16], levels: usize) {
    for i in (0..levels).rev() {
        let blk = 1usize << (i + 1);
        let half = 1usize << i;
        for base in (0..a.len()).step_by(blk) {
            for t in (half..blk).rev() {
                let q = a[base + t];
                if q == 0 {
                    continue;
                }
                for &j in &terms[i] {
                    a[base + t - half + (1 << j)] ^= q;
                }
            }
        }
    }
}

/// Scalar forward FFT over `2^levels` novel coefficients, in place.
fn fft_scalar(terms: &[Vec<usize>], a: &mut [u16], levels: usize) {
    for i in (0..levels).rev() {
        let blk = 1usize << (i + 1);
        let half = 1usize << i;
        for (b, base) in (0..a.len()).step_by(blk).enumerate() {
            let c = twiddle(terms, i, b);
            for j in 0..half {
                let v = a[base + half + j];
                let u = a[base + j] ^ gf16::mul(c, v);
                a[base + j] = u;
                a[base + half + j] = u ^ v;
            }
        }
    }
}

impl Kernel {
    /// Build for the Rader kernel `b` (256 values); None if this field's
    /// Cantor chain does not check out, which the fixed field makes a
    /// build error in practice rather than a runtime path.
    pub(super) fn new(b: &[u16; 256]) -> Option<Kernel> {
        for i in 1..K {
            let v = CANTOR[i];
            if gf16::mul(v, v) ^ v != CANTOR[i - 1] {
                return None;
            }
        }
        let terms = subspace_terms()?;
        let mut tw = Vec::with_capacity(K);
        for i in 0..K {
            let blocks = N2 >> (i + 1);
            tw.push(
                (0..blocks)
                    .map(|blk| gf16::FoldCoeff::new(twiddle(&terms, i, blk)))
                    .collect::<Vec<_>>(),
            );
        }
        let mut bp = vec![0u16; N2];
        bp[..256].copy_from_slice(b);
        convert_scalar_forward(&terms, &mut bp, K);
        fft_scalar(&terms, &mut bp, K);
        let bhat = bp.iter().map(|&c| gf16::FoldCoeff::new(c)).collect();
        Some(Kernel { tw, bhat, terms })
    }

    /// Whether a leaf of `count` sources should take this kernel rather
    /// than the paired or dense one: the transform's cost is fixed per
    /// leaf, the dense evaluators' is linear in the sources.
    pub(super) fn admits(&self, count: usize) -> bool {
        count >= min_sources()
    }
}

/// The shipping gate, read once: `NZBFAST_NTT_ADDITIVE=0|1`; unset is
/// ON. Measured 7 Sep 2026 on the 32 x 1 GiB / 1 MiB / 3,276-row
/// create (~141 sources per leaf), outputs identical: M3 Ultra
/// 12.7-17.1 -> 9.2-9.7 s; i5-10600KF (AVX2 nibble, the paired leaf
/// not hoisted) 52.9-53.8 -> 45.5-47.6 (rounds BI/BJ). The fill gate
/// below is what makes it safe: forced at ~44 per leaf the i5's
/// 10 GiB create is 2x SLOWER (17.4 -> 34.3 s).
pub(super) fn enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| !matches!(std::env::var("NZBFAST_NTT_ADDITIVE").as_deref(), Ok("0")))
}

/// `NZBFAST_NTT_ADDITIVE_MIN=<sources>`: the leaf fill from which the
/// additive kernel is taken.
///
/// **128, and re-confirmed by measurement after the second cut rather
/// than kept out of caution** (7 Sep 2026). The second cut made the
/// additive leaf cheaper on both boxes, so its crossover against the
/// paired leaf moved down INSIDE the old 96 -> 128 step of `leaf_bench`
/// and the gate could not be argued about from that bracket; 104, 112
/// and 120 exist in that list for this reason. Measured then, ms per
/// leaf at w=512, paired vs additive:
///
/// | fill | M3 paired | M3 additive | i5 paired | i5 additive |
/// |---|---|---|---|---|
/// | 96 | 0.482 | 0.632 | 0.469 | 0.545 |
/// | 112 | 0.569 | 0.633 | - | - |
/// | 120 | 0.608 | 0.629 | - | - |
/// | 128 | 0.671 | 0.655 | 0.687 | 0.558 |
///
/// The M3 crosses at ~124 and BINDS: at 120 the paired leaf is still 3%
/// ahead there, so a gate at 112 or 120 would be a regression on the
/// box with the narrower margin. The i5 crosses near 110 and would take
/// a lower gate happily - at 128 the additive leaf is already 19% ahead
/// of the paired one there, against 2% on the M3. One arm winning at
/// the boundary on one box is not a reason to move a gate both share.
///
/// Earlier evidence, still true: the real transform at ~141 per leaf was
/// -30% on the M3 and -12% on the i5, and the i5 FORCED at ~44 per leaf
/// was 2x SLOWER - the fill gate is the whole safety of the default.
///
/// **Re-measured 9 Sep 2026 on both classes, and the two have
/// CONVERGED.** Same rig, three reps each, medians: the M3 now brackets
/// its crossover at 112-120 (it read ~124 above) and the i5 brackets
/// 112-120 as well (it read ~110), so the 14-point spread the paragraph
/// above reasons from is gone. So is its 19%: at fill 128 the additive
/// leaf leads by 2% on the i5 now, not 19%, because the PAIRED leaf got
/// faster there (0.621 ms against 0.687). The gate stays 128, but it now
/// stays on evidence rather than on caution, and it does not want
/// splitting per class - both classes want the same number.
///
/// It is not moved to 120 because this rig's own header says it
/// overstates a method that trades arithmetic for memory, which is
/// precisely what the additive leaf does; because the band a move would
/// change is only 112-128 wide; and because the boundary rows are inside
/// the noise (the i5 reads 0.547 against 0.548 at fill 112). A move
/// wants the transform at its production worker count, not this rig.
const MIN_SOURCES: usize = 128;

pub(super) fn min_sources() -> usize {
    static N: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *N.get_or_init(|| {
        std::env::var("NZBFAST_NTT_ADDITIVE_MIN")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(MIN_SOURCES)
    })
}

/// Words of scratch one worker needs at stripe width `w`: the 512
/// working rows.
pub(super) fn scratch_words(w: usize) -> usize {
    N2 * w
}

/// Row `r` of `buf` (rows of `w` words).
fn row(buf: &[u16], w: usize, r: usize) -> &[u16] {
    &buf[r * w..(r + 1) * w]
}

/// Rows `a` and `b` of `buf`, mutably, `a != b`.
fn two_rows(buf: &mut [u16], w: usize, a: usize, b: usize) -> (&mut [u16], &mut [u16]) {
    debug_assert_ne!(a, b);
    if a < b {
        let (l, r) = buf.split_at_mut(b * w);
        (&mut l[a * w..(a + 1) * w], &mut r[..w])
    } else {
        let (l, r) = buf.split_at_mut(a * w);
        (&mut r[..w], &mut l[b * w..(b + 1) * w])
    }
}

/// A block's two halves, `half` rows each from row `base`, mutably.
fn two_ranges(buf: &mut [u16], w: usize, base: usize, half: usize) -> (&mut [u16], &mut [u16]) {
    let (l, r) = buf.split_at_mut((base + half) * w);
    (&mut l[base * w..], &mut r[..half * w])
}

/// `dst ^= src`, whole rows.
fn xor_row(dst: &mut [u16], src: &[u16]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= *s;
    }
}

/// Monomial -> novel over `2^levels` rows in place.
///
/// `nonzero[r]` says whether row r may hold anything: an XOR out of a
/// row that is still all zeros is a no-op, and a leaf at the 10 GiB
/// shape fills ~44 of its 256 data rows, so at that fill most of this
/// pass is XORing zeros over the whole stripe. Rows this pass writes are
/// marked as it goes, so the propagation is exact rather than a
/// first-level guess. The caller hands in all-true to disable it
/// (`NZBFAST_NTT_ADDITIVE_SPARSE=0`), which is the A/B arm and also what
/// a caller with no fill map passes.
fn convert_rows_forward(
    terms: &[Vec<usize>],
    buf: &mut [u16],
    w: usize,
    levels: usize,
    nonzero: &mut [bool],
) {
    let rows = 1usize << levels;
    debug_assert_eq!(nonzero.len(), rows);
    for i in (0..levels).rev() {
        let blk = 1usize << (i + 1);
        let half = 1usize << i;
        for base in (0..rows).step_by(blk) {
            for t in (half..blk).rev() {
                let src = base + t;
                if !nonzero[src] {
                    continue;
                }
                for &j in &terms[i] {
                    let dst = base + t - half + (1 << j);
                    let (d, s) = two_rows(buf, w, dst, src);
                    xor_row(d, s);
                    nonzero[dst] = true;
                }
            }
        }
    }
}

/// `NZBFAST_NTT_ADDITIVE_SCALE=0`: the pointwise step goes back to
/// folding each row into a zeroed temporary and copying it back - the
/// arm [`gf16::scale`] is measured against, in one binary. The leaf
/// takes that arm anyway where `gf16::inplace_scale_preferred()` says
/// no - which is an x86 with no vector scale at all, and a GFNI part,
/// where the in-place kernel became reachable only on 11 Sep 2026 and
/// this leaf's arm has not been measured yet. That predicate, and NOT
/// `scale_available`, is deliberately what this reads: the joint solve
/// is opt-in behind `parfast --fast` and can take a newly opened kernel
/// on one box's evidence; this leaf is on every create and repair and
/// cannot. Read once.
fn inplace_scale_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| !std::env::var_os("NZBFAST_NTT_ADDITIVE_SCALE").is_some_and(|v| v == "0"))
}

/// `dst ^= c * src` over a row, through the fold kernel: the pointwise
/// step's pre-[`gf16::scale`] form, kept as that A/B's other arm.
fn xor_mul_row(dst: &mut [u16], src: &[u16], c: &gf16::FoldCoeff, w: usize) {
    if c.coeff() == 0 {
        return;
    }
    super::fold_into_prepared(dst, &[src.as_ptr() as *const u8], &[c], w);
}

/// `NZBFAST_NTT_ADDITIVE_SPARSE=0`: the forward conversion runs over
/// every data row whether or not anything reached it - the arm the
/// pruning above is measured against, in one binary. Read once.
fn sparse_conversion_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| !std::env::var_os("NZBFAST_NTT_ADDITIVE_SPARSE").is_some_and(|v| v == "0"))
}

/// Novel -> monomial over `2^levels` rows in place: the forward pass's
/// XORs in the reverse order.
fn convert_rows_backward(terms: &[Vec<usize>], buf: &mut [u16], w: usize, levels: usize) {
    let rows = 1usize << levels;
    for i in 0..levels {
        let blk = 1usize << (i + 1);
        let half = 1usize << i;
        for base in (0..rows).step_by(blk) {
            for t in half..blk {
                for &j in &terms[i] {
                    let (d, s) = two_rows(buf, w, base + t - half + (1 << j), base + t);
                    xor_row(d, s);
                }
            }
        }
    }
}

/// One leaf on the additive kernel: X[0] and all 256 convolution rows
/// into `out` (257 rows of `w` words). `scratch` holds `scratch_words(w)`
/// words. Returns false, having written nothing, when the stripe is not
/// a whole number of 16-word chunks or the scratch is short (the caller
/// runs another leaf).
pub(super) fn leaf(
    kernel: &Kernel,
    leaf: &super::LeafPlan,
    g_pow: &[usize; 256],
    src_of: &dyn Fn(super::SrcId) -> *const u8,
    w: usize,
    out: &mut [u16],
    scratch: &mut [u16],
) -> bool {
    if w == 0 || !w.is_multiple_of(16) || scratch.len() < scratch_words(w) {
        return false;
    }
    let buf = &mut scratch[..N2 * w];
    let bytes = w * 2;
    // Rows 0..256 hold the data polynomial a (monomial basis, by Rader
    // index). Two blocks of the 512 need no zeroing: rows 256..512,
    // which the forward FFT's ninth stage overwrites wholesale with a
    // copy of the bottom half, and any row a source assigns outright
    // below. At a full leaf that is ~78% of the 512 rows, and the
    // scratch is reused leaf after leaf, so it is a real pass. It rides
    // the sparse knob because it reads the same fill map, which makes
    // `NZBFAST_NTT_ADDITIVE_SPARSE=0` an exact reproduction of the
    // pre-second-cut leaf rather than most of one.
    let mut nonzero = [false; 256];
    for &(i, _) in &leaf.conv_sources {
        nonzero[i as usize] = true;
    }
    let sparse = sparse_conversion_enabled();
    if sparse {
        for (r, &nz) in nonzero.iter().enumerate() {
            if !nz {
                buf[r * w..(r + 1) * w].fill(0);
            }
        }
    } else {
        buf.fill(0);
    }
    // X[0] accumulates on the way.
    out[..w].fill(0);
    for &(i, src) in &leaf.conv_sources {
        // SAFETY: `src_of` resolves to `w * 2` readable bytes for this
        // transform (FlatPlan::transform's contract, the same one the
        // dense leaf reads under).
        let src = unsafe { std::slice::from_raw_parts(src_of(src), bytes) };
        let r = i as usize;
        for ((d, x0), x) in buf[r * w..(r + 1) * w]
            .iter_mut()
            .zip(out[..w].iter_mut())
            .zip(src.as_chunks::<2>().0)
        {
            let v = u16::from_le_bytes(*x);
            *d = v;
            *x0 ^= v;
        }
    }
    // Only X[0] is live in out. Keep x0 in the last physical output
    // row until the other rows have consumed it, then finish that row
    // last. This retains word-based XOR without a temporary allocation.
    let (out, last_output) = out.split_at_mut(256 * w);
    let last_output = &mut last_output[..w];
    if let Some(id) = leaf.x0 {
        // SAFETY: as for the convolution sources above.
        let src = unsafe { std::slice::from_raw_parts(src_of(id), bytes) };
        for (d, x) in last_output.iter_mut().zip(src.as_chunks::<2>().0) {
            *d = u16::from_le_bytes(*x);
        }
        xor_row(&mut out[..w], last_output);
    } else {
        last_output.fill(0);
    }
    // Monomial -> novel on the 256 data rows (the top block's division by
    // s_8 is empty: degree < 256 = deg s_8).
    let mut reached = if sparse { nonzero } else { [true; 256] };
    convert_rows_forward(&kernel.terms, &mut buf[..256 * w], w, K - 1, &mut reached);
    // Forward FFT. Stage 8's block is the whole array and its top half is
    // zero, so (u, v) -> (u, u): a copy.
    {
        let (lo, hi) = buf.split_at_mut(256 * w);
        hi.copy_from_slice(lo);
    }
    // Every pair of a block shares its twiddle and the block's two halves
    // are contiguous, so a stage is one fold call and one XOR pass over
    // `half` rows per block: 511 kernel calls per transform, not 2,304
    // single-row ones (the call overhead was a third of the leaf).
    for i in (0..K - 1).rev() {
        let blk = 1usize << (i + 1);
        let half = 1usize << i;
        for (b, base) in (0..N2).step_by(blk).enumerate() {
            let c = &kernel.tw[i][b];
            let (u, v) = two_ranges(buf, w, base, half);
            let done = gf16::butterfly(u, v, c, false);
            debug_assert_eq!(done, half * w);
        }
    }
    // Pointwise by the kernel's transform: row p = bhat[p] * row p,
    // through the in-place scale kernel. It used to zero a temporary
    // row, fold into it and copy back - three passes over the row and a
    // second row of cache, 512 times per leaf.
    if inplace_scale_enabled() && gf16::inplace_scale_preferred() {
        for p in 0..N2 {
            let done = gf16::scale(&mut buf[p * w..(p + 1) * w], &kernel.bhat[p]);
            debug_assert_eq!(done, w);
        }
    } else {
        // Only X[0] is live in out so far. Reuse the next row as a
        // temporary; final assembly below overwrites this temporary row
        // before reading it. This needs no additional worker storage.
        let tmp = &mut out[w..2 * w];
        for p in 0..N2 {
            tmp.fill(0);
            xor_mul_row(tmp, row(buf, w, p), &kernel.bhat[p], w);
            buf[p * w..(p + 1) * w].copy_from_slice(tmp);
        }
    }
    // Inverse FFT.
    for i in 0..K {
        let blk = 1usize << (i + 1);
        let half = 1usize << i;
        for (b, base) in (0..N2).step_by(blk).enumerate() {
            let c = &kernel.tw[i][b];
            let (u, v) = two_ranges(buf, w, base, half);
            let done = gf16::butterfly(u, v, c, true);
            debug_assert_eq!(done, half * w);
        }
    }
    // Novel -> monomial, then the cyclic fold y[m] = c[m] + c[m + 256],
    // and X[g^m] = x0 + y[m].
    convert_rows_backward(&kernel.terms, buf, w, K);
    let mut last_m = None;
    for m in 0..256usize {
        if g_pow[m] == 256 {
            last_m = Some(m);
            continue;
        }
        let dst = &mut out[g_pow[m] * w..(g_pow[m] + 1) * w];
        dst.copy_from_slice(row(buf, w, m));
        xor_row(dst, row(buf, w, m + 256));
        if leaf.x0.is_some() {
            xor_row(dst, last_output);
        }
    }
    // g_pow permutes all nonzero field rows. last_output still holds
    // x0 (or zero), so finish it by XOR rather than overwriting it.
    let m = last_m.expect("Rader permutation includes row 256");
    xor_row(last_output, row(buf, w, m));
    xor_row(last_output, row(buf, w, m + 256));
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Where a full leaf's time goes, phase by phase (ms, best of 3),
    /// on this box at `NZBFAST_NTT_W` (512). A research rig: it prints
    /// and asserts nothing.
    ///
    ///     cargo test --release -p nzbkit-base --lib --features test-support \
    ///       par2ntt::additive::tests::phase_split -- --ignored --nocapture
    #[test]
    #[ignore = "research rig: prints timings, asserts nothing"]
    fn phase_split() {
        let w: usize = std::env::var("NZBFAST_NTT_W")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(512);
        let (_, _, kernel) = super::super::rader_tables();
        let k = Kernel::new(&kernel).expect("cantor");
        let mut rng = 0x1EAFu64;
        let mut word = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            (rng >> 16) as u16
        };
        let mut buf: Vec<u16> = (0..N2 * w).map(|_| word()).collect();
        let reps = 20;
        let ms = |t: std::time::Duration| t.as_secs_f64() * 1e3 / reps as f64;
        let mut best = [f64::MAX; 7];
        for _ in 0..3 {
            let t = std::time::Instant::now();
            for _ in 0..reps {
                convert_rows_forward(&k.terms, &mut buf[..256 * w], w, K - 1, &mut [true; 256]);
            }
            best[0] = best[0].min(ms(t.elapsed()));
            let t = std::time::Instant::now();
            for _ in 0..reps {
                for i in (0..K - 1).rev() {
                    let blk = 1usize << (i + 1);
                    let half = 1usize << i;
                    for (b, base) in (0..N2).step_by(blk).enumerate() {
                        let c = &k.tw[i][b];
                        let (u, v) = two_ranges(&mut buf, w, base, half);
                        gf16::butterfly(u, v, c, false);
                    }
                }
            }
            best[1] = best[1].min(ms(t.elapsed()));
            let t = std::time::Instant::now();
            for _ in 0..reps {
                for p in 0..N2 {
                    gf16::scale(&mut buf[p * w..(p + 1) * w], &k.bhat[p]);
                }
            }
            best[2] = best[2].min(ms(t.elapsed()));
            let t = std::time::Instant::now();
            for _ in 0..reps {
                let mut tmp = vec![0u16; w];
                for p in 0..N2 {
                    tmp.fill(0);
                    xor_mul_row(&mut tmp, row(&buf, w, p), &k.bhat[p], w);
                    buf[p * w..(p + 1) * w].copy_from_slice(&tmp);
                }
            }
            best[6] = best[6].min(ms(t.elapsed()));
            let t = std::time::Instant::now();
            for _ in 0..reps {
                for i in 0..K {
                    let blk = 1usize << (i + 1);
                    let half = 1usize << i;
                    for (b, base) in (0..N2).step_by(blk).enumerate() {
                        let c = &k.tw[i][b];
                        let (u, v) = two_ranges(&mut buf, w, base, half);
                        gf16::butterfly(u, v, c, true);
                    }
                }
            }
            best[3] = best[3].min(ms(t.elapsed()));
            let t = std::time::Instant::now();
            for _ in 0..reps {
                convert_rows_backward(&k.terms, &mut buf, w, K);
            }
            best[4] = best[4].min(ms(t.elapsed()));
            let t = std::time::Instant::now();
            for _ in 0..reps {
                for _ in 0..4 {
                    let (lo, hi) = buf.split_at_mut(256 * w);
                    xor_row(lo, hi);
                }
            }
            best[5] = best[5].min(ms(t.elapsed()));
        }
        println!(
            "additive phase split w={w}: fwd-conv {:.3} fft {:.3} pointwise {:.3} (temp-row {:.3}) ifft {:.3} bwd-conv {:.3} fold-ish {:.3} ms",
            best[0], best[1], best[2], best[6], best[3], best[4], best[5]
        );
    }

    /// The Cantor chain, the binary subspace polynomials and the FFT's
    /// inverse, from the definitions.
    #[test]
    fn the_cantor_basis_and_the_transform_check_out_in_par2s_field() {
        for i in 1..K {
            let v = CANTOR[i];
            assert_eq!(gf16::mul(v, v) ^ v, CANTOR[i - 1], "cantor step {i}");
        }
        let terms = subspace_terms().expect("cantor subspace polynomials are binary");
        assert_eq!(terms[8], vec![0], "s_8 = x^256 + x");
        // s_i vanishes on its subspace and is 1 at v_i.
        for i in 0..K {
            for mask in 0..(1u32 << i) {
                let mut x = 0u16;
                for t in 0..i {
                    if (mask >> t) & 1 == 1 {
                        x ^= CANTOR[t];
                    }
                }
                assert_eq!(lin_eval(&terms[i], i, x), 0, "s_{i} on its subspace");
            }
            assert_eq!(lin_eval(&terms[i], i, CANTOR[i]), 1, "s_{i}(v_{i})");
        }
        // Forward conversion + FFT evaluates the monomial polynomial.
        let mut rng = 0x9E3779B97F4A7C15u64;
        let mut word = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            (rng >> 16) as u16
        };
        let mono: Vec<u16> = (0..N2).map(|_| word()).collect();
        let mut a = mono.clone();
        convert_scalar_forward(&terms, &mut a, K);
        fft_scalar(&terms, &mut a, K);
        for p in (0..N2).step_by(29) {
            let mut x = 0u16;
            for i in 0..K {
                if (p >> i) & 1 == 1 {
                    x ^= CANTOR[i];
                }
            }
            let mut r = 0u16;
            for &c in mono.iter().rev() {
                r = gf16::mul(r, x) ^ c;
            }
            assert_eq!(a[p], r, "evaluation at point {p}");
        }
    }
}
