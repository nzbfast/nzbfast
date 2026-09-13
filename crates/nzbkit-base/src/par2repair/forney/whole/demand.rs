//! The inverse transform pruned to what the caller will actually read,
//! coalesced back into contiguous native-width runs.
//!
//! [`super::linear_impl`] needs only rows `count-1 ..= 2*count-2` of the
//! inverse transform: the product of two degree-`count-1` polynomials
//! has `2*count-1` coefficients, and the correlation the solve wants
//! reads the top half of them. At `count = m` and `n = 65,536` that is
//! half the rows, and the levels that feed only the other half are pure
//! waste.
//!
//! # How the plan is derived
//!
//! Walk the levels from the LAST one backwards, carrying a `need` map.
//! At each level a butterfly's two inputs are needed if either output is
//! needed, except where the twiddle makes one input drop out (`c == 0`
//! kills the low input's dependence, `c == 1` turns the pair into a
//! copy). That gives, per level, an operation per position:
//!
//! - `XorHigh` - only the high output is live, so the butterfly degrades
//!   to one XOR.
//! - `CopyLow` - only the low output is live and the twiddle is one, so
//!   it degrades to a copy.
//! - `Butterfly` - both live: the full fused butterfly.
//!
//! Adjacent positions with the same operation inside one block are then
//! merged into RUNS, so the surviving work is still handed to
//! `gf16::butterfly` as one call over many rows rather than one call per
//! row. That merge is the difference between a pruning that pays and one
//! that trades folds for call overhead.
//!
//! A level whose `need` map has become all-true is recorded as `None`
//! and runs the full unpruned stage - there is nothing left to prune and
//! the run bookkeeping would only cost.
use super::{Kernel, gf16};

#[derive(Clone, Copy, PartialEq)]
enum Op {
    XorHigh,
    CopyLow,
    Butterfly,
}

struct Run {
    start: usize,
    len: usize,
    op: Op,
}

/// One repair's pruned inverse transform. Built with the kernel and
/// read by every stripe.
pub(super) struct Plan {
    stages: Vec<Option<Vec<Run>>>,
}

impl Plan {
    /// `count` is the number of live input rows, so the caller's band is
    /// `count-1 ..= 2*count-2`.
    pub(super) fn new(n: usize, tw: &[Vec<gf16::FoldCoeff>], count: usize) -> Self {
        let mut need = vec![false; n];
        need[count - 1..2 * count - 1].fill(true);
        let mut stages: Vec<Option<Vec<Run>>> = (0..tw.len()).map(|_| None).collect();
        for i in (0..tw.len()).rev() {
            if need.iter().all(|&x| x) {
                break;
            }
            let half = 1usize << i;
            let mut prev = vec![false; n];
            let mut runs: Vec<Run> = Vec::new();
            for (b, base) in (0..n).step_by(2 * half).enumerate() {
                let c = tw[i][b].coeff();
                for j in 0..half {
                    let u = base + j;
                    let v = u + half;
                    let low = need[u];
                    let high = need[v];
                    prev[u] = high || (low && c != 1);
                    prev[v] = high || (low && c != 0);
                    let op = match (low, high, c) {
                        (false, false, _) | (true, false, 0) => None,
                        (_, true, 0) | (false, true, _) => Some(Op::XorHigh),
                        (true, false, 1) => Some(Op::CopyLow),
                        _ => Some(Op::Butterfly),
                    };
                    if let Some(op) = op {
                        if let Some(last) = runs.last_mut()
                            && j != 0
                            && last.start + last.len == u
                            && last.op == op
                        {
                            last.len += 1;
                        } else {
                            runs.push(Run {
                                start: u,
                                len: 1,
                                op,
                            });
                        }
                    }
                }
            }
            stages[i] = Some(runs);
            need = prev;
        }
        Self { stages }
    }

    pub(super) fn heap_bytes(&self) -> usize {
        self.stages.capacity() * std::mem::size_of::<Option<Vec<Run>>>()
            + self
                .stages
                .iter()
                .flatten()
                .map(|r| r.capacity() * std::mem::size_of::<Run>())
                .sum::<usize>()
    }

    pub(super) fn apply(&self, k: &Kernel, buf: &mut [u16], w: usize) {
        for (i, stage) in self.stages.iter().enumerate() {
            let half = 1usize << i;
            if let Some(runs) = stage {
                for r in runs {
                    let b = r.start / (2 * half);
                    let (lo, hi) = buf.split_at_mut((r.start + half) * w);
                    let lo = &mut lo[r.start * w..(r.start + r.len) * w];
                    let hi = &mut hi[..r.len * w];
                    match r.op {
                        Op::XorHigh => super::xor(hi, lo),
                        Op::CopyLow => lo.copy_from_slice(hi),
                        Op::Butterfly => {
                            assert_eq!(gf16::butterfly(lo, hi, &k.tw[i][b], true), r.len * w)
                        }
                    }
                }
            } else {
                for (b, base) in (0..k.n).step_by(2 * half).enumerate() {
                    let (lo, hi) = buf.split_at_mut((base + half) * w);
                    assert_eq!(
                        gf16::butterfly(
                            &mut lo[base * w..],
                            &mut hi[..half * w],
                            &k.tw[i][b],
                            true
                        ),
                        half * w
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    /// The pruned inverse must agree with the full one on every row the
    /// caller reads, at every transform size the repair cap admits.
    /// Three input modes so a pruning that happened to preserve zeros
    /// cannot pass.
    #[test]
    fn demand_matches_full_native_inverse() {
        for levels in 1..=16 {
            let n = 1usize << levels;
            for m in [(n / 4 + 1).min(n / 2), n / 2] {
                let k = super::Kernel::new(&vec![1; m]);
                assert_eq!(k.n, n);
                for w in [16, 32] {
                    for mode in 0..3 {
                        let mut a: Vec<u16> = (0..n * w)
                            .map(|j| match mode {
                                0 => 0,
                                1 => u16::from(j == n * w / 3),
                                // wrapping_mul: `j` reaches 2^21 here and
                                // 2^21 * 7919 overflows a 32-bit usize,
                                // which is a panic under armv7-cross's
                                // overflow-checks (found 11 Sep 2026 under
                                // qemu-arm). The value is truncated to u16
                                // anyway, and wrapping keeps the low bits,
                                // so every 64-bit host sees the same input.
                                _ => (j.wrapping_mul(7919) ^ (j >> 3) ^ 317) as u16,
                            })
                            .collect();
                        let mut b = a.clone();
                        super::super::inverse_full(&k, &mut a, w);
                        k.demand.apply(&k, &mut b, w);
                        assert_eq!(
                            &a[(m - 1) * w..(2 * m - 1) * w],
                            &b[(m - 1) * w..(2 * m - 1) * w],
                            "levels={levels} m={m} w={w} mode={mode}"
                        );
                    }
                }
            }
        }
    }
}
