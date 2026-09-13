//! Coefficients shared by sibling nodes during ONE plan construction.
use std::{collections::HashMap, sync::Arc};

/// Input preparation differs for sparse sets, but recursion and coefficients do not.
pub(super) trait Input: Copy {
    fn len(self) -> usize;
    fn vacant(self) -> bool;
    fn child(self, class: usize, radix: usize) -> Self;
    fn leaf(
        self,
        buf: usize,
        g_pow: &[usize; 256],
        sources: &mut [(u16, super::SrcId); 256],
    ) -> super::LeafPlan;
}

/// A decimated view of the original slots. Child classes only change the
/// starting offset and stride; constructing them never copies source ids.
#[derive(Clone, Copy)]
pub(super) struct Slots<'a> {
    data: &'a [Option<super::SrcId>],
    stride: usize,
    len: usize,
}

impl<'a> Slots<'a> {
    pub(super) fn new(data: &'a [Option<super::SrcId>]) -> Self {
        Self {
            data,
            stride: 1,
            len: data.len(),
        }
    }

    pub(super) fn len(self) -> usize {
        self.len
    }

    pub(super) fn vacant(self) -> bool {
        self.data
            .iter()
            .step_by(self.stride)
            .take(self.len)
            .all(Option::is_none)
    }

    pub(super) fn get(self, i: usize) -> Option<super::SrcId> {
        debug_assert!(i < self.len);
        self.data[i * self.stride]
    }

    pub(super) fn child(self, class: usize, radix: usize) -> Self {
        debug_assert!(class < radix && self.len.is_multiple_of(radix));
        Self {
            data: &self.data[class * self.stride..],
            stride: self.stride * radix,
            len: self.len / radix,
        }
    }
}

impl Input for Slots<'_> {
    fn len(self) -> usize {
        Slots::len(self)
    }
    fn vacant(self) -> bool {
        Slots::vacant(self)
    }
    fn child(self, class: usize, radix: usize) -> Self {
        Slots::child(self, class, radix)
    }
    fn leaf(
        self,
        buf: usize,
        g_pow: &[usize; 256],
        sources: &mut [(u16, super::SrcId); 256],
    ) -> super::LeafPlan {
        // Stage at most 256 sources, then allocate their final storage
        // once. The same staging array serves every leaf in this build;
        // no spare Vec capacity survives in the immutable plan.
        let mut count = 0;
        // Walk the fixed inverse Rader permutation in its final order.
        // Sorting the occupied slots repeats the same permutation work for
        // every leaf and every plan, despite the order never changing.
        for i in 0..256 {
            if let Some(src) = self.get(g_pow[(256 - i) & 255]) {
                sources[count] = (i as u16, src);
                count += 1;
            }
        }
        super::LeafPlan {
            buf,
            conv_sources: sources[..count].to_vec(),
            x0: self.get(0),
        }
    }
}

#[derive(Default)]
pub(super) struct Coefficients {
    tables: HashMap<(u64, u32), Arc<[u16]>>,
    orders: HashMap<u64, Option<Arc<[u32]>>>,
    ranges: HashMap<u64, Arc<RangeRows>>,
}

pub(super) struct RangeRows {
    pub(super) residues: Vec<usize>,
    pub(super) child_rows: Arc<[usize]>,
}

impl Coefficients {
    /// As with coefficients, selected residues depend on the tree level,
    /// not its live inputs. Reduce, sort and index them once per level.
    pub(super) fn range(&mut self, root_log: u64, q: usize, selected: &[usize]) -> Arc<RangeRows> {
        self.ranges
            .entry(root_log)
            .or_insert_with(|| {
                // Once the selected list is at least a child transform long,
                // an index table is cheaper than sorting repeated residues
                // and binary-searching every selected row. Keep the sparse
                // path below so short ranges do not allocate q entries.
                if selected.len() >= q {
                    let mut positions = vec![usize::MAX; q];
                    for &k in selected {
                        positions[k % q] = 0;
                    }
                    let mut residues = Vec::with_capacity(q);
                    for (r, index) in positions.iter_mut().enumerate() {
                        if *index != usize::MAX {
                            *index = residues.len();
                            residues.push(r);
                        }
                    }
                    let child_rows: Vec<_> = selected
                        .iter()
                        .map(|k| if q == 257 { k % q } else { positions[k % q] })
                        .collect();
                    return Arc::new(RangeRows {
                        residues,
                        child_rows: child_rows.into(),
                    });
                }
                let mut residues: Vec<_> = selected.iter().map(|k| k % q).collect();
                residues.sort_unstable();
                residues.dedup();
                let child_rows: Vec<_> = selected
                    .iter()
                    .map(|k| {
                        if q == 257 {
                            k % q
                        } else {
                            residues.binary_search(&(k % q)).unwrap()
                        }
                    })
                    .collect();
                Arc::new(RangeRows {
                    residues,
                    child_rows: child_rows.into(),
                })
            })
            .clone()
    }

    /// Child-row selection is identical across a tree level, even when the
    /// live input classes differ. Sort the output traversal only once.
    pub(super) fn order(
        &mut self,
        root_log: u64,
        child_rows: impl FnOnce() -> Vec<usize>,
    ) -> Option<Arc<[u32]>> {
        self.orders
            .entry(root_log)
            .or_insert_with(|| super::grouped_order(&child_rows()).map(Into::into))
            .clone()
    }

    /// Every node at a given depth has the same root_log and output sequence:
    /// prefix construction clamps the same prefix, range construction reduces
    /// the same selected residues. Only the live child classes can differ.
    /// A cache belongs to exactly one build, never to another output interval
    /// or present set. Retained tables are immutable and die with that plan.
    pub(super) fn get(
        &mut self,
        root_log: u64,
        lives: &[usize],
        outputs: impl ExactSizeIterator<Item = usize>,
    ) -> Arc<[u16]> {
        let mask = lives.iter().fold(0u32, |mask, &u| mask | (1 << u));
        self.tables
            .entry((root_log, mask))
            .or_insert_with(|| {
                let mut values = Vec::with_capacity(outputs.len() * lives.len());
                for k in outputs {
                    for &u in lives {
                        values.push(crate::gf16::pow2(
                            root_log * u as u64 * k as u64 % super::N as u64,
                        ));
                    }
                }
                values.into()
            })
            .clone()
    }
}

/// The fixed root-2 kernels do not depend on inputs or recovery exponents.
/// Cache only these bounded, immutable tables process-wide. Scratch and the
/// input-dependent tree remain private to a worker and a plan respectively.
pub(super) struct Fixed {
    pub(super) g_pow: [usize; 256],
    pub(super) prepared: Box<[crate::gf16::FoldCoeff; 256]>,
    pub(super) one: crate::gf16::FoldCoeff,
    pub(super) paired: Option<super::conjugate::Kernel>,
    pub(super) additive: Option<super::additive::Kernel>,
}

pub(super) fn fixed() -> &'static Fixed {
    static FIXED: std::sync::OnceLock<Fixed> = std::sync::OnceLock::new();
    FIXED.get_or_init(|| {
        let (g_pow, _, kernel) = super::rader_tables();
        Fixed {
            g_pow,
            prepared: super::prepare_kernel(&kernel),
            one: crate::gf16::FoldCoeff::new(1),
            paired: super::conjugate::Kernel::new(&kernel),
            additive: super::additive::enabled()
                .then(|| super::additive::Kernel::new(&kernel))
                .flatten(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::super::{FlatPlan, N};

    #[test]
    fn slot_views_partition_every_field_position() {
        let data: Vec<_> = (0..N)
            .map(|i| (!i.is_multiple_of(7)).then_some(i as u32))
            .collect();
        let root = super::Slots::new(&data);
        assert!(!root.vacant());
        let mut seen = vec![false; N];
        for u in 0..3 {
            for v in 0..5 {
                for t in 0..17 {
                    let leaf = root.child(u, 3).child(v, 5).child(t, 17);
                    assert_eq!(leaf.len(), 257);
                    for j in 0..257 {
                        let original = u + 3 * v + 15 * t + 255 * j;
                        assert!(!seen[original]);
                        seen[original] = true;
                        assert_eq!(leaf.get(j), data[original]);
                    }
                }
            }
        }
        assert!(seen.into_iter().all(|s| s));
        assert!(super::Slots::new(&vec![None; N]).child(2, 3).vacant());
    }

    #[test]
    fn indexed_range_rows_match_sort_reference_even_with_holes() {
        for q in [257, 4369, 21845] {
            for len in [q - 1, q, q + 31, 2 * q] {
                for sparse in [false, true] {
                    let selected: Vec<_> = (0..len)
                        .map(|i| {
                            if sparse {
                                (i % 17) * 512 + 249
                            } else {
                                i + q - 19
                            }
                        })
                        .collect();
                    let mut expected: Vec<_> = selected.iter().map(|k| k % q).collect();
                    expected.sort_unstable();
                    expected.dedup();
                    let mut tables = super::Coefficients::default();
                    let actual = tables.range(1, q, &selected);
                    assert_eq!(actual.residues, expected);
                    for (k, &index) in selected.iter().zip(actual.child_rows.iter()) {
                        let want = if q == 257 {
                            k % q
                        } else {
                            expected.binary_search(&(k % q)).unwrap()
                        };
                        assert_eq!(index, want, "q={q} len={len} sparse={sparse}");
                    }
                }
            }
        }
    }

    fn polynomial_mul(mut a: u16, mut b: u16) -> u16 {
        let mut result = 0;
        for _ in 0..16 {
            if b & 1 != 0 {
                result ^= a;
            }
            let high = a >> 15;
            a <<= 1;
            if high != 0 {
                a ^= 0x100b;
            }
            b >>= 1;
        }
        result
    }

    #[test]
    fn reused_scratch_with_changing_sources_and_wrapped_ranges() {
        // Non-coprime logs exercise different live-child masks. Ranges cross
        // each internal node boundary, including the field's final exponent.
        // Reuse dirty scratch at both SIMD and tail widths, as successive
        // copied input windows do; no source or previous result may survive.
        for first in [0, 250, 4350, 21835, N - 32] {
            let initial = FlatPlan::build_range(&[(1, 0)], first, 32).unwrap();
            let mut scratch = initial.new_scratch(32);
            let mut out = vec![0xdead; 32 * 32];
            for (window, w) in [32, 17, 32].into_iter().enumerate() {
                let present: Vec<_> = (0..97)
                    .map(|i| (((i * 631 + window * 1987) % N) as u32, i as u32))
                    .collect();
                let data: Vec<Vec<u8>> = (0..97)
                    .map(|i| {
                        (0..w)
                            .flat_map(|j| ((i * 977 + j * 79 + window * 319) as u16).to_le_bytes())
                            .collect()
                    })
                    .collect();
                let plan = FlatPlan::build_range(&present, first, 32).unwrap();
                plan.transform(&|id| data[id as usize].as_ptr(), w, &mut scratch, &mut out);
                for row in 0..32 {
                    for word in 0..w {
                        let mut expected = 0;
                        for &(log, id) in &present {
                            let bytes = &data[id as usize][word * 2..];
                            let value = u16::from_le_bytes([bytes[0], bytes[1]]);
                            let coefficient = crate::gf16::pow2(log as u64 * (first + row) as u64);
                            expected ^= polynomial_mul(value, coefficient);
                        }
                        assert_eq!(
                            out[row * w + word],
                            expected,
                            "first={first} window={window} row={row} word={word}"
                        );
                    }
                }
            }
        }
    }
}
