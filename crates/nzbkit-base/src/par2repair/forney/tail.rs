//! Direct short-tail correction at `m = 2^k + q`, `2 <= q <= 8`.
//!
//! The generalization of [`super::peel`]: instead of peeling ONE monic
//! term off `B`, peel the top `q` of them. The kernel then runs at
//! `d = 2^k` terms - half the size the whole kernel would need - and the
//! correction is at most `2q` extra sources per output row, which is at
//! most 16 and therefore fits `gf16::xor_mul_multi_prepared`'s fan-in in
//! ONE call.
//!
//! [`MAX_Q`] is where that stops being true: past eight peeled terms the
//! correction needs a second fold call per row and the transform saving
//! is being spent on it again. Above `MAX_Q` the whole kernel takes the
//! shape.
//!
//! Coefficients are prepared once ([`gf16::FoldCoeff`]) because the same
//! `2q` of them are folded on every row of every stripe, and on the
//! nibble kernels an unprepared coefficient rebuilds eight 16-byte
//! tables per source per call.
use crate::{gf16, par2repair::forney::whole};

/// The largest tail this arm takes: `2 * MAX_Q = 16` is the fan-in of
/// one prepared multi-fold call.
pub(super) const MAX_Q: usize = 8;

pub(super) struct Plan {
    pub(super) kernel: whole::Kernel,
    /// The power-of-two part: the kernel's own term count.
    pub(super) d: usize,
    /// The peeled tail length, `m - d`.
    pub(super) q: usize,
    coeffs: Vec<gf16::FoldCoeff>,
}

impl Plan {
    /// `b` is `B`'s coefficients, low to high. `None` unless `b` is
    /// monic, not itself a power of two long, and its tail is short.
    pub(super) fn new(b: &[u16]) -> Option<Self> {
        let m = b.len();
        if !(3..=32768).contains(&m) || m.is_power_of_two() || b.last() != Some(&1) {
            return None;
        }
        let d = m.next_power_of_two() / 2;
        let q = m - d;
        if q > MAX_Q {
            return None;
        }
        Some(Self {
            kernel: whole::Kernel::new(&b[..d]),
            d,
            q,
            coeffs: b.iter().map(|&c| gf16::FoldCoeff::new(c)).collect(),
        })
    }

    pub(super) fn heap_bytes(&self) -> usize {
        self.kernel.heap_bytes() + self.coeffs.capacity() * std::mem::size_of::<gf16::FoldCoeff>()
    }

    /// One output row of the correlation: the half-size kernel's
    /// residual where one exists, plus at most `2q` peeled-term sources
    /// in a single fused fold.
    ///
    /// `syn` is one already-column-sliced stripe - one `&[u16]` per
    /// syndrome row, all as wide as `dst`. Taking pre-sliced rows rather
    /// than `&[Vec<u16>]` plus a column offset is what lets the combined
    /// owned+joint arm call this body from inside a scheduler that no
    /// longer holds the syndromes as indexable owned rows.
    pub(super) fn finish_row_stripe(
        &self,
        dst: &mut [u16],
        syn: &[&[u16]],
        r: usize,
        residual: Option<&[u16]>,
    ) {
        let m = self.d + self.q;
        assert_eq!(syn.len(), m);
        assert!((m - 1..2 * m - 1).contains(&r));
        if let Some(row) = residual {
            dst.copy_from_slice(row);
        } else {
            dst.fill(0);
        }
        let mut src: [&[u8]; 2 * MAX_Q] = [&[]; 2 * MAX_Q];
        let mut coeff: [&gf16::FoldCoeff; 2 * MAX_Q] = [&self.coeffs[0]; 2 * MAX_Q];
        let mut n = 0;
        for j in 0..self.q {
            let k = r - self.d - j;
            if k < self.d {
                src[n] = gf16::words_as_bytes(syn[m - 1 - k]);
                coeff[n] = &self.coeffs[self.d + j];
                n += 1;
            }
            if k < m {
                src[n] = gf16::words_as_bytes(syn[self.q - 1 - j]);
                coeff[n] = &self.coeffs[k];
                n += 1;
            }
        }
        // `xor_mul_multi_prepared` returns the WORDS it covered and
        // leaves the remainder to the caller. How many that is depends
        // on the granule of the kernel its dispatch picked, which is a
        // property of the BOX and not of this call: 32 bytes on NEON and
        // the AVX2/SSSE3 arms, 64 on `gf16::xor_mul_multi_gfni512`. A
        // span of 32 to 63 bytes is therefore covered whole on one part
        // and declined ENTIRELY on another.
        //
        // This used to assert the return was `dst.len()`, i.e. that
        // there was never a remainder - true only while every
        // dispatchable kernel took the 32-byte unit. It is the granule
        // class of `69cbf2e2` a second time: on an AVX-512 GFNI part
        // `joint`'s short last stripe, padded there to a multiple of 16
        // WORDS because 32 bytes is the unit every OTHER kernel takes,
        // is exactly the span the 512-bit arm returns 0 for, and the
        // repair panicked from a scoped worker (EPYC 9354P with
        // `NZBFAST_GF16_ROWOP_GFNI=1`, which was then the only door to
        // this path on a GFNI part and is no longer - the gate ships on
        // and `scale` no longer waits on it -
        // `research/GFNI-ROWOP-EVIDENCE-2026-09-11.md` section 5).
        //
        // Finish per source what the fused kernel declined, the way
        // `par2ntt::fold_into`, `par2ntt::fold_into_prepared`,
        // `super::fold_rows`, `par2repair::linalg::fold_chunk_tiled` and
        // `gf16::butterfly_two_pass` all already do - this was the ONE
        // caller of the multi-source fold that asserted the remainder
        // away instead of running it. `FoldTable::xor_mul_into` covers
        // any length, tail included, so the span is whole after this
        // whatever the kernel took. Two fixes that are NOT this one: do
        // not relax the assert to `>=` (that writes a partly folded row
        // and is SILENT, the failure mode the gate exists to prevent),
        // and do not pad `dst` to 64 bytes in `joint` (that buys this
        // caller and leaves the next 64-byte-granule caller to find the
        // same granule the same way).
        let done = gf16::xor_mul_multi_prepared(dst, &src[..n], &coeff[..n]);
        if done < dst.len() {
            for (s, c) in src[..n].iter().zip(&coeff[..n]) {
                if c.coeff() != 0 {
                    gf16::FoldTable::new(c.coeff()).xor_mul_into(&mut dst[done..], &s[done * 2..]);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    /// The admission rule, both directions: every `m` up to the repair
    /// cap, and a non-monic `B` refused outright.
    #[test]
    fn only_short_monic_tails_are_admitted() {
        for m in 0usize..=32769 {
            let expected = (3..=32768).contains(&m)
                && !m.is_power_of_two()
                && m - m.next_power_of_two() / 2 <= super::MAX_Q;
            assert_eq!(super::Plan::new(&vec![1; m]).is_some(), expected, "m={m}");
        }
        assert!(super::Plan::new(&[1, 2, 3]).is_none());
    }

    /// A stripe NARROWER than the fold kernel's granule must still come
    /// out whole.
    ///
    /// `finish_row_stripe` hands the whole destination to
    /// `gf16::xor_mul_multi_prepared`, which returns the WORDS it
    /// covered and leaves the remainder to the caller. How many that is
    /// depends on the granule of the kernel the dispatch picked, which
    /// is a property of the BOX: 32 bytes on NEON and the AVX2/SSSE3
    /// arms, 64 on `gf16::xor_mul_multi_gfni512`. So a width that is
    /// covered whole on one part is declined ENTIRELY on another, and
    /// the caller cannot know which from here.
    ///
    /// That is what took the two `forney::joint` tests red on an EPYC
    /// 9354P with `NZBFAST_GF16_ROWOP_GFNI=1`
    /// (`research/GFNI-ROWOP-EVIDENCE-2026-09-11.md`): `joint` pads a
    /// short last stripe to a multiple of 16 WORDS - 32 bytes, the unit
    /// every other kernel takes - and the 512-bit arm declines exactly
    /// that, returning 0 where the old full-coverage assert wanted 16.
    ///
    /// The oracle is WIDTH INVARIANCE, so this is not a re-statement of
    /// the formula: one call over a width every shipped kernel covers
    /// whole must equal the same row assembled from column slices of
    /// any width. The widths below bracket every granule - 8 words is
    /// 16 bytes, which NO kernel here covers, so the fold declines the
    /// span outright and the remainder is the whole stripe. That arm
    /// fails on EVERY architecture without the per-source finish, which
    /// is why this test does not need GFNI silicon to be worth running.
    #[test]
    fn a_stripe_narrower_than_the_fold_granule_is_still_complete() {
        // m = 5, so d = 4 and q = 1: the smallest admitted shape.
        let b = [3u16, 7, 11, 5, 1];
        let p = super::Plan::new(&b).expect("monic, not a power of two, short tail");
        let m = b.len();
        // 128 bytes: two whole 64-byte chunks, so the fused kernel
        // covers it on every part and the reference row is the
        // all-kernel path.
        const WIDE: usize = 64;
        let rows: Vec<Vec<u16>> = (0..m)
            .map(|i| {
                (0..WIDE)
                    .map(|c| (i * 7919 + c * 104_729 + 1) as u16)
                    .collect()
            })
            .collect();
        let residual: Vec<u16> = (0..WIDE).map(|c| (c * 40_499 + 12_345) as u16).collect();
        for r in m - 1..2 * m - 1 {
            for res in [None, Some(&residual[..])] {
                let syn: Vec<&[u16]> = rows.iter().map(|v| &v[..]).collect();
                let mut want = vec![0u16; WIDE];
                p.finish_row_stripe(&mut want, &syn, r, res);
                for w in [1usize, 7, 8, 15, 16, 17, 24, 32, 33] {
                    let mut got = vec![0u16; WIDE];
                    for c0 in (0..WIDE).step_by(w) {
                        let c1 = (c0 + w).min(WIDE);
                        let cols: Vec<&[u16]> = rows.iter().map(|v| &v[c0..c1]).collect();
                        p.finish_row_stripe(&mut got[c0..c1], &cols, r, res.map(|x| &x[c0..c1]));
                    }
                    assert_eq!(got, want, "r={r} w={w} residual={}", res.is_some());
                }
            }
        }
    }
}
