//! The eight BLAKE2sp leaves as `blake2s_simd` states, hashed on a small
//! scoped thread team. The default everywhere except aarch64, where
//! `blake2s_simd` has no many-way kernel and [`super::ManyLeaves`] takes
//! over; compiled there too so the tests can hold the two together.
#![cfg_attr(target_arch = "aarch64", allow(dead_code))]

use super::{LeafSet, BLOCK_BYTES, GROUP_BYTES, OUT_BYTES, PARALLELISM};

pub(super) const HASH_THREADS: usize = 4;

fn leaf_params(index: usize) -> blake2s_simd::Params {
    let mut params = blake2s_simd::Params::new();
    params
        .hash_length(OUT_BYTES)
        .fanout(PARALLELISM as u8)
        .max_depth(2)
        .max_leaf_length(0)
        .node_offset(index as u64)
        .node_depth(0)
        .inner_hash_length(OUT_BYTES);
    if index == PARALLELISM - 1 {
        params.last_node(true);
    }
    params
}

/// Leaves as `blake2s_simd` states, hashed on a scoped thread team.
#[derive(Clone)]
pub(crate) struct PortableLeaves {
    leaves: Vec<blake2s_simd::State>,
}

impl LeafSet for PortableLeaves {
    fn new() -> Self {
        Self {
            leaves: (0..PARALLELISM)
                .map(|index| leaf_params(index).to_state())
                .collect(),
        }
    }

    fn absorb_groups(&mut self, groups: &[u8]) {
        hash_groups_parallel(&mut self.leaves, groups);
    }

    fn finalize(mut self, tail: &[u8]) -> [[u8; OUT_BYTES]; PARALLELISM] {
        for (leaf, block) in self.leaves.iter_mut().zip(tail.chunks(BLOCK_BYTES)) {
            leaf.update(block);
        }
        let mut out = [[0u8; OUT_BYTES]; PARALLELISM];
        for (digest, leaf) in out.iter_mut().zip(&self.leaves) {
            digest.copy_from_slice(leaf.finalize().as_bytes());
        }
        out
    }
}

/// Hash whole 512-byte groups into the leaves, splitting the leaf set
/// across a small scoped thread team. Each worker gathers its leaves'
/// 64-byte blocks into a contiguous scratch buffer and hashes it in one
/// update call.
fn hash_groups_parallel(leaves: &mut [blake2s_simd::State], groups: &[u8]) {
    debug_assert_eq!(groups.len() % GROUP_BYTES, 0);
    let group_count = groups.len() / GROUP_BYTES;
    if groups.is_empty() {
        return;
    }
    let leaves_per_thread = PARALLELISM / HASH_THREADS;
    let mut chunks: Vec<&mut [blake2s_simd::State]> =
        leaves.chunks_mut(leaves_per_thread).collect();
    std::thread::scope(|scope| {
        for (thread_index, thread_leaves) in chunks.iter_mut().enumerate() {
            let first_leaf = thread_index * leaves_per_thread;
            scope.spawn(move || {
                let mut scratch = vec![0u8; group_count * BLOCK_BYTES];
                for (offset, leaf) in thread_leaves.iter_mut().enumerate() {
                    let leaf_index = first_leaf + offset;
                    let slot = leaf_index * BLOCK_BYTES;
                    for group in 0..group_count {
                        let src = group * GROUP_BYTES + slot;
                        scratch[group * BLOCK_BYTES..(group + 1) * BLOCK_BYTES]
                            .copy_from_slice(&groups[src..src + BLOCK_BYTES]);
                    }
                    leaf.update(&scratch);
                }
            });
        }
    });
}
