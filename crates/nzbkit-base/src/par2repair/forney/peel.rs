//! Highest-degree peeling at `m = 2^k + 1`.
//!
//! [`super::whole::Kernel`] transforms at `n = next_power_of_two(2m-1)`,
//! so a single missing block past a power of two DOUBLES the transform:
//! at `m = 8,193` the kernel is 32,768 points where `m = 8,192` needs
//! 16,384. That one extra root is not worth a doubling.
//!
//! `B` is monic (`P` is a product of distinct monic linear factors, so
//! `p[m] = 1` and `B[m-1] = 1`), which means the top term can be peeled
//! off exactly:
//!
//! ```text
//!     B(z) = z^{m-1} + B_lo(z),   deg B_lo < m - 1
//! ```
//!
//! The correlation with `z^{m-1}` is a pure index shift - each output
//! row is one syndrome row scaled by one coefficient - and the residual
//! correlation with `B_lo` runs on a HALF-SIZE kernel. So the whole
//! stage costs one kernel of `m-1` terms plus one fused scale-and-XOR
//! per output row.
//!
//! Admission is deliberately narrow: `m - 1` must itself be a power of
//! two, which is exactly the shape where the doubling would otherwise
//! happen. Anything else takes [`super::tail`] or the whole kernel.
use crate::{gf16, par2repair::forney::whole};

/// The peeled plan: the half-size kernel plus `B`'s low coefficients,
/// prepared once so a nibble kernel does not rebuild its tables per row.
pub(super) struct Plan {
    pub(super) kernel: whole::Kernel,
    coeffs: Vec<gf16::FoldCoeff>,
}

impl Plan {
    /// `b` is `B`'s coefficients, low to high. `None` unless `b` is
    /// monic and `b.len() - 1` is a power of two.
    pub(super) fn new(b: &[u16]) -> Option<Self> {
        if b.len() < 2
            || b.len() > 32768
            || !(b.len() - 1).is_power_of_two()
            || b.last() != Some(&1)
        {
            return None;
        }
        let d = b.len() - 1;
        Some(Self {
            kernel: whole::Kernel::new(&b[..d]),
            coeffs: b[..d].iter().map(|&c| gf16::FoldCoeff::new(c)).collect(),
        })
    }

    pub(super) fn count(&self) -> usize {
        self.coeffs.len()
    }

    pub(super) fn heap_bytes(&self) -> usize {
        self.kernel.heap_bytes() + self.coeffs.capacity() * std::mem::size_of::<gf16::FoldCoeff>()
    }

    /// One output row: the peeled monic term (`high` scaled by
    /// `B[j]`), the shifted syndrome row `low`, and the half-size
    /// kernel's residual where one exists.
    pub(super) fn finish_row(
        &self,
        dst: &mut [u16],
        high: &[u16],
        low: &[u16],
        residual: Option<&[u16]>,
        j: usize,
    ) {
        assert_eq!(dst.len(), high.len());
        assert_eq!(dst.len(), low.len());
        dst.copy_from_slice(high);
        assert_eq!(gf16::scale(dst, &self.coeffs[j]), dst.len());
        for (v, &a) in dst.iter_mut().zip(low) {
            *v ^= a;
        }
        if let Some(residual) = residual {
            assert_eq!(dst.len(), residual.len());
            for (v, &a) in dst.iter_mut().zip(residual) {
                *v ^= a;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    /// The admission rule is the whole safety of this arm: a non-monic
    /// or wrong-length `B` must be refused rather than peeled wrongly.
    #[test]
    fn only_supported_monic_boundaries_are_admitted() {
        for m in 0usize..=32769 {
            let b = vec![1; m];
            assert_eq!(
                super::Plan::new(&b).is_some(),
                (2..=32768).contains(&m) && (m - 1).is_power_of_two()
            );
        }
        assert!(super::Plan::new(&[1, 2, 3]).is_none());
    }
}
