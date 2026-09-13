//! Sparse setup visits occupied leaf positions rather than full coefficient slots.
use super::{BuildState, LeafPlan, N, Node, SrcId, planning::Input};

/// Keep sorting bounded; dense plans retain their direct field-slot traversal.
pub(super) const LIMIT: usize = 2048;

struct Sources {
    // Key = leaf class * 257 + inverse Rader rank; rank 256 denotes x0.
    entries: Vec<(u32, SrcId)>,
    offsets: [usize; 256],
}

impl Sources {
    fn new(present: &[(u32, SrcId)], g_pow: &[usize; 256]) -> Result<Self, String> {
        let mut rank = [0u16; 257];
        rank[0] = 256;
        for i in 0..256 {
            rank[g_pow[(256 - i) & 255]] = i as u16;
        }
        let mut entries = Vec::with_capacity(present.len());
        for &(log, id) in present {
            if log as usize >= N {
                return Err(format!("base log {log} out of range"));
            }
            let key = (log % 255) * 257 + u32::from(rank[log as usize / 255]);
            entries.push((key, id));
        }
        entries.sort_unstable_by_key(|&(key, _)| key);
        for pair in entries.windows(2) {
            if pair[0].0 == pair[1].0 {
                let key = pair[0].0;
                let r = key as usize % 257;
                let position = if r == 256 { 0 } else { g_pow[(256 - r) & 255] };
                let log = key as usize / 257 + 255 * position;
                return Err(format!("duplicate base log {log}"));
            }
        }
        let mut offsets = [0; 256];
        let mut cursor = 0;
        for (leaf, start) in offsets[..255].iter_mut().enumerate() {
            *start = cursor;
            while cursor < entries.len() && entries[cursor].0 as usize / 257 == leaf {
                cursor += 1;
            }
        }
        offsets[255] = entries.len();
        Ok(Self { entries, offsets })
    }
}

#[derive(Clone, Copy)]
struct View<'a> {
    sources: &'a Sources,
    offset: usize,
    stride: usize,
}

impl Input for View<'_> {
    fn len(self) -> usize {
        N / self.stride
    }

    fn vacant(self) -> bool {
        (self.offset..255)
            .step_by(self.stride)
            .all(|leaf| self.sources.offsets[leaf] == self.sources.offsets[leaf + 1])
    }

    fn child(self, class: usize, radix: usize) -> Self {
        debug_assert!(class < radix && self.len().is_multiple_of(radix));
        Self {
            offset: self.offset + class * self.stride,
            stride: self.stride * radix,
            ..self
        }
    }

    fn leaf(self, buf: usize, _: &[usize; 256], _: &mut [(u16, SrcId); 256]) -> LeafPlan {
        debug_assert_eq!(self.stride, 255);
        let entries = &self.sources.entries
            [self.sources.offsets[self.offset]..self.sources.offsets[self.offset + 1]];
        let x0 = entries
            .last()
            .filter(|&&(key, _)| key % 257 == 256)
            .map(|&(_, id)| id);
        let conv = &entries[..entries.len() - usize::from(x0.is_some())];
        LeafPlan {
            buf,
            conv_sources: conv
                .iter()
                .map(|&(key, id)| ((key % 257) as u16, id))
                .collect(),
            x0,
        }
    }
}

pub(super) fn tree(
    present: &[(u32, SrcId)],
    first: usize,
    count: usize,
    g_pow: &[usize; 256],
) -> Result<Node, String> {
    let sources = Sources::new(present, g_pow)?;
    let view = View {
        sources: &sources,
        offset: 0,
        stride: 1,
    };
    let mut state = BuildState::default();
    let root = if first == 0 {
        super::build_node(view, 1, count, 0, g_pow, &mut state)
    } else {
        let selected: Vec<_> = (first..first + count).collect();
        super::build_node_range(view, 1, &selected, 0, g_pow, &mut state)
    };
    Ok(root.expect("nonempty set built no tree"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorted_leaves_match_dense_views_over_the_entire_field() {
        let fixed = super::super::planning::fixed();
        for holes in [false, true] {
            let present: Vec<_> = (0..N as u32)
                .rev()
                .filter(|&i| !holes || i % 7 != 3)
                .map(|i| (i, if i == 65534 { 0 } else { u32::MAX - i }))
                .collect();
            let sources = Sources::new(&present, &fixed.g_pow).unwrap();
            let sparse = View {
                sources: &sources,
                offset: 0,
                stride: 1,
            };
            let mut data = vec![None; N];
            for &(log, id) in &present {
                data[log as usize] = Some(id);
            }
            let dense = super::super::planning::Slots::new(&data);
            let mut staging = [(0, 0); 256];
            for u in 0..3 {
                for v in 0..5 {
                    for t in 0..17 {
                        let a = sparse.child(u, 3).child(v, 5).child(t, 17);
                        let b = dense.child(u, 3).child(v, 5).child(t, 17);
                        assert_eq!(a.len(), b.len());
                        assert_eq!(a.vacant(), b.vacant());
                        let a = a.leaf(0, &fixed.g_pow, &mut staging);
                        let b = b.leaf(0, &fixed.g_pow, &mut staging);
                        assert_eq!(a.x0, b.x0);
                        assert_eq!(a.conv_sources, b.conv_sources);
                    }
                }
            }
        }
    }

    #[test]
    fn sparse_validation_preserves_opaque_ids_and_rejects_duplicate_logs() {
        use super::super::FlatPlan;
        for first in [0, 257] {
            for log in [0, 7, 255, 262, N as u32 - 1] {
                assert!(FlatPlan::build_range(&[(log, u32::MAX)], first, 1).is_ok());
                assert!(FlatPlan::build_range(&[(log, 0), (log, u32::MAX)], first, 1).is_err());
            }
            for log in [N as u32, u32::MAX] {
                assert!(FlatPlan::build_range(&[(log, 0)], first, 1).is_err());
            }
            assert!(FlatPlan::build_range(&[], first, 1).is_err());
            assert!(FlatPlan::build_range(&[(1, 0)], first, 0).is_err());
        }
    }

    fn multiply(mut a: u16, mut b: u16) -> u16 {
        let mut result = 0;
        for _ in 0..16 {
            if b & 1 != 0 {
                result ^= a;
            }
            let carry = a >> 15;
            a <<= 1;
            if carry != 0 {
                a ^= 0x100b;
            }
            b >>= 1;
        }
        result
    }

    #[test]
    fn sparse_and_dense_dispatch_match_scalar_with_reused_scratch() {
        use super::super::FlatPlan;
        for first in [0, 250, N - 32] {
            let initial = FlatPlan::build_range(&[(1, 0)], first, 32).unwrap();
            let mut scratch = initial.new_scratch(1);
            let mut out = vec![0xdead; 32];
            for n in [1, 257, LIMIT, LIMIT + 1, 32] {
                let present: Vec<_> = (0..n)
                    .map(|i| {
                        let log = if n == 257 {
                            i * 255
                        } else {
                            (i * 251 + 65000) % N
                        };
                        (
                            log as u32,
                            if i % 3 == 0 {
                                u32::MAX - i as u32
                            } else {
                                i as u32
                            },
                        )
                    })
                    .collect();
                let data: Vec<_> = (0..n)
                    .map(|i| ((i * 977 + 319) as u16).to_le_bytes())
                    .collect();
                let index = |id: u32| {
                    if id > 65535 {
                        (u32::MAX - id) as usize
                    } else {
                        id as usize
                    }
                };
                let plan = FlatPlan::build_range(&present, first, 32).unwrap();
                plan.transform(&|id| data[index(id)].as_ptr(), 1, &mut scratch, &mut out);
                for (row, &actual) in out.iter().enumerate() {
                    let mut expected = 0;
                    for &(log, id) in &present {
                        let coefficient = crate::gf16::pow2(log as u64 * (first + row) as u64);
                        expected ^= multiply(u16::from_le_bytes(data[index(id)]), coefficient);
                    }
                    assert_eq!(actual, expected, "n={n} first={first} row={row}");
                }
            }
        }
    }
}
