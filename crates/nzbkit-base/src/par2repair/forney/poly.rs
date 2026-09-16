//! Scalar-coefficient additive FFT over GF(2^16): the ordinary product
//! and the whole-field evaluation the joint CONSTRUCTOR is built on.
//!
//! One subject per file, like the rest of `forney/`: this module knows
//! nothing about syndromes, stripes or repairs. It multiplies two
//! coefficient vectors, and it evaluates one polynomial at every element
//! of the field. Both are plan-time operations - they run once per
//! repair inside [`super::ForneyPlan::prepare`], never inside the solve.
//!
//! # Why an additive FFT and not the multiplicative one
//!
//! `par2ntt` already has a 65,535-point multiplicative transform, but it
//! is built for BLOCK rows (thousands of words per coefficient) and its
//! domain omits zero. Here every coefficient is a single `u16` and the
//! evaluation must cover the whole field INCLUDING zero, so the Cantor
//! basis additive transform is the right shape: its domain is the whole
//! additive group, it is `O(n log n)` scalar operations with no twiddle
//! table per point, and 65,536 is a power of two where 65,535 is not.
//!
//! [`C`] is the Cantor basis: `C[i]^2 + C[i] = C[i-1]`, which is what
//! makes each level's subspace vanishing polynomial LINEAR, and is
//! asserted at plan time rather than trusted.
//!
//! # What uses it
//!
//! - [`Context::multiply`] backs [`super::locator::build`]'s product
//!   tree: `P(z) = Π (z + g_c)` as `log(m/LEAF)` levels of pairwise
//!   products instead of one `O(m^2)` coefficient chain.
//! - [`evaluate_field`] backs the FIELD-DERIVATIVE scale table: the
//!   dense product's `d_c = P'(g_c)` is `m` Horner evaluations of an
//!   `m/2`-term polynomial, `O(m^2)` in total; one whole-field
//!   evaluation answers every column at once and is then a lookup.
//!
//! Both are armed by [`super::joint_gate`] - the default on aarch64
//! since 11 Sep 2026 and on every x86 kernel class since 12 Sep 2026,
//! with `--fast` or `NZBFAST_FORNEY_JOINT=1` to force it and
//! `NZBFAST_FORNEY_JOINT=0` to take the shipped solve instead. When that
//! gate says no neither runs and the constructor is the coefficient
//! chain it has always been.
use crate::gf16;

/// The Cantor basis of GF(2^16) over GF(2): `C[i]^2 + C[i] = C[i-1]`,
/// with `C[0] = 1`. Asserted in [`Transform::new`] rather than trusted,
/// because every level of the transform depends on the relation.
const C: [u16; 16] = [
    1, 350, 26, 7410, 5786, 48044, 64994, 18058, 1810, 7030, 44396, 17984, 42910, 62132, 63354,
    32738,
];

/// One additive-FFT size: the per-level subspace polynomial terms and
/// the per-block twiddles. Built once per size and cached by
/// [`Context`], because the product tree walks the same few sizes many
/// times.
struct Transform {
    n: usize,
    terms: Vec<Vec<usize>>,
    tw: Vec<Vec<u16>>,
}

/// The level-`i` subspace polynomial evaluated at `x`: `Σ_j x^{2^j}`
/// over the level's term set plus the leading `x^{2^i}`. Linear in `x`
/// over GF(2), which is the whole point of the Cantor basis.
fn linear(ts: &[usize], i: usize, x: u16) -> u16 {
    let mut p = x;
    let mut v = 0;
    for j in 0..=i {
        if j == i || ts.contains(&j) {
            v ^= p;
        }
        p = gf16::mul(p, p);
    }
    v
}

impl Transform {
    fn new(n: usize) -> Self {
        assert!(n.is_power_of_two() && (2..=65536).contains(&n));
        let levels = n.trailing_zeros() as usize;
        // Over the Cantor basis the level-i subspace polynomial's term
        // set is exactly the submask of i - a closed form, so no
        // polynomial arithmetic is needed to derive it. The asserts
        // below are the proof that this closed form and the basis agree.
        let terms: Vec<Vec<usize>> = (0..levels)
            .map(|i| (0..i).filter(|&j| j & i == j).collect())
            .collect();
        for (i, ts) in terms.iter().enumerate() {
            if i > 0 {
                assert_eq!(gf16::mul(C[i], C[i]) ^ C[i], C[i - 1]);
            }
            assert_eq!(linear(ts, i, C[i]), 1);
        }
        let tw = (0..levels)
            .map(|i| {
                (0..n >> (i + 1))
                    .map(|b| {
                        let mut beta = 0;
                        for (t, &v) in C.iter().enumerate().take(levels).skip(i + 1) {
                            if b >> (t - i - 1) & 1 != 0 {
                                beta ^= v;
                            }
                        }
                        linear(&terms[i], i, beta)
                    })
                    .collect()
            })
            .collect();
        Self { n, terms, tw }
    }

    /// Coefficients in, values on the Cantor-ordered domain out.
    fn forward(&self, a: &mut [u16]) {
        let levels = self.terms.len();
        for i in (0..levels).rev() {
            let half = 1 << i;
            let blk = half * 2;
            for base in (0..self.n).step_by(blk) {
                for t in (half..blk).rev() {
                    let q = a[base + t];
                    for &j in &self.terms[i] {
                        a[base + t - half + (1 << j)] ^= q;
                    }
                }
            }
        }
        for i in (0..levels).rev() {
            let half = 1 << i;
            let blk = half * 2;
            for (b, base) in (0..self.n).step_by(blk).enumerate() {
                let c = self.tw[i][b];
                for j in 0..half {
                    let v = a[base + half + j];
                    let u = a[base + j] ^ gf16::mul(c, v);
                    a[base + j] = u;
                    a[base + half + j] = u ^ v;
                }
            }
        }
    }

    /// The exact inverse of [`Transform::forward`], stage for stage.
    fn inverse(&self, a: &mut [u16]) {
        for i in 0..self.terms.len() {
            let half = 1 << i;
            let blk = half * 2;
            for (b, base) in (0..self.n).step_by(blk).enumerate() {
                let c = self.tw[i][b];
                for j in 0..half {
                    let v = a[base + j] ^ a[base + half + j];
                    a[base + j] ^= gf16::mul(c, v);
                    a[base + half + j] = v;
                }
            }
        }
        for i in 0..self.terms.len() {
            let half = 1 << i;
            let blk = half * 2;
            for base in (0..self.n).step_by(blk) {
                for t in half..blk {
                    let q = a[base + t];
                    for &j in &self.terms[i] {
                        a[base + t - half + (1 << j)] ^= q;
                    }
                }
            }
        }
    }

    fn heap(&self) -> usize {
        self.terms.capacity() * std::mem::size_of::<Vec<usize>>()
            + self
                .terms
                .iter()
                .map(|v| v.capacity() * std::mem::size_of::<usize>())
                .sum::<usize>()
            + self.tw.capacity() * std::mem::size_of::<Vec<u16>>()
            + self.tw.iter().map(|v| v.capacity() * 2).sum::<usize>()
    }
}

/// A cache of transform sizes plus the running peak-heap bound, so the
/// product tree pays for each size once and can still report what it
/// held. Seventeen slots: one per power of two from 1 to 65,536.
pub(super) struct Context {
    plans: Vec<Option<Transform>>,
    /// The largest live heap this context has bounded, in bytes. A
    /// BOUND, not a measurement: it is what the caller must budget for,
    /// and it is what [`super::locator::Stats`] reports.
    pub(super) peak_heap_bound: usize,
}

impl Context {
    pub(super) fn new() -> Self {
        Self {
            plans: (0..17).map(|_| None).collect(),
            peak_heap_bound: 0,
        }
    }

    pub(super) fn cache_heap(&self) -> usize {
        self.plans.capacity() * std::mem::size_of::<Option<Transform>>()
            + self
                .plans
                .iter()
                .flatten()
                .map(Transform::heap)
                .sum::<usize>()
    }

    /// The ordinary product `a * b`, exact and untruncated.
    /// `live_heap` is what the CALLER already holds, so the recorded
    /// bound covers the whole tree and not just this one product.
    pub(super) fn multiply(&mut self, a: &[u16], b: &[u16], live_heap: usize) -> Vec<u16> {
        assert!(!a.is_empty() && !b.is_empty());
        let len = a.len() + b.len() - 1;
        assert!(len <= 65536);
        let n = len.next_power_of_two().max(2);
        let k = n.trailing_zeros() as usize;
        if self.plans[k].is_none() {
            self.plans[k] = Some(Transform::new(n));
        }
        // Conservative live-array bound: the caller's own live heap, the
        // cached transforms, the two FFT arrays here and a slack term
        // for small construction temporaries.
        self.peak_heap_bound = self
            .peak_heap_bound
            .max(live_heap + self.cache_heap() + 4 * n + 512);
        let p = self.plans[k].as_ref().expect("just inserted above");
        let mut x = vec![0; n];
        let mut y = vec![0; n];
        x[..a.len()].copy_from_slice(a);
        y[..b.len()].copy_from_slice(b);
        p.forward(&mut x);
        p.forward(&mut y);
        for (a, &b) in x.iter_mut().zip(&y) {
            *a = gf16::mul(*a, b);
        }
        p.inverse(&mut x);
        x.truncate(len);
        x
    }
}

/// `coefficients` evaluated at EVERY field element, indexed by the
/// element itself: `values[z] = Σ_i coefficients[i] * z^i`.
///
/// Returns the values and a bound on the heap the call held, so the
/// constructor can charge it. The Gray-code walk at the end is what
/// turns the transform's Cantor-ordered output into ordinary
/// field-element order without allocating an inverse lookup table:
/// successive Cantor indices differ by exactly one basis vector, so the
/// field element can be maintained incrementally.
pub(super) fn evaluate_field(coefficients: &[u16]) -> (Vec<u16>, usize) {
    assert!(coefficients.len() <= 65536);
    let p = Transform::new(65536);
    let mut x = vec![0u16; 65536];
    x[..coefficients.len()].copy_from_slice(coefficients);
    p.forward(&mut x);
    let mut values = vec![0u16; 65536];
    let mut value = 0u16;
    for i in 0usize..65536 {
        let gray = i ^ (i >> 1);
        values[value as usize] = x[gray];
        if i < 65535 {
            value ^= C[(i + 1).trailing_zeros() as usize];
        }
    }
    let heap = p.heap() + x.capacity() * 2 + values.capacity() * 2 + 512;
    (values, heap)
}
