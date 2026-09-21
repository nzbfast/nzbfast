//! The eight BLAKE2sp leaves as `blake2s_simd` states, hashed on a small
//! scoped thread team, each worker gathering its leaves' 64-byte blocks
//! out of the 512-byte groups first.
//!
//! This was the x86 production path until 2026-09-03, when
//! [`super::simd::SimdHasher`] - the crate's own blake2sp, which reads the
//! leaf blocks in place at a stride of eight and compresses them
//! eight-wide under AVX2 - took over there. It is still the INDEPENDENT
//! implementation of the RAR5 tree that the agreement tests hold the
//! shipping kernels to, on every target. Do not delete it to buy the lines -
//! without it, `check_kernels` compares the many-way kernel only with
//! itself on x86.
//!
//! It is ALSO the reference the wide leaf team was chosen against. On
//! 2026-09-18 an eight-worker shape of THIS team - one leaf each, the
//! blocks gathered as always - was measured beside an eight-worker team
//! that reads the same blocks IN PLACE
//! ([`super::many::ScalarLeafTeam`]), and lost at every batch size by 4%
//! to 23%: the gather copies every byte of the stream once before
//! anything is compressed. The in-place team is production on aarch64
//! above [`WIDE_THREADS`] cores; this one keeps its four-worker shape as
//! the cross-check and its eight-worker shape as the losing arm the rig
//! still prints, so the choice can be re-measured rather than believed.
//! `blake2sp::tests::timing_matrix` has the table.
#![allow(dead_code)]

use super::{LeafSet, BLOCK_BYTES, GROUP_BYTES, OUT_BYTES, PARALLELISM};

/// The team the agreement tests run as the independent implementation.
pub(super) const HASH_THREADS: usize = 4;

/// One leaf per worker: the whole of the tree's parallelism, since a
/// BLAKE2sp leaf is a serial chain and there are eight of them. Also the
/// core count at or above which [`super::Kernel`] takes a wide team at
/// all.
pub(super) const WIDE_THREADS: usize = PARALLELISM;

/// Whole groups in one `absorb_groups` call below which the team is not
/// worth its spawns and the leaves are fed on the calling thread. 512
/// groups is 256 KiB, the smallest batch the 18 Sep 2026 sweep still had
/// the eight-worker team winning at.
const TEAM_MIN_GROUPS: usize = 512;

/// Groups gathered per dispatch, which bounds a worker's scratch to
/// `GATHER_MAX_GROUPS * BLOCK_BYTES` - 1 MiB here. Without the cap a
/// one-shot `blake2sp::hash` over a buffered member (up to the 512 MiB
/// decode limit) would gather an eighth of it per leaf and keep that
/// scratch in the thread-local for the rest of the process. 16384 groups
/// is 8 MiB, which the 18 Sep 2026 sweep had within 3% of the rate the
/// team reaches with no batching limit at all.
pub(super) const GATHER_MAX_GROUPS: usize = 16384;

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

/// Leaves as `blake2s_simd` states, hashed on a scoped team of `THREADS`
/// workers taking `PARALLELISM / THREADS` leaves each.
#[derive(Clone)]
pub(crate) struct LeafTeam<const THREADS: usize> {
    leaves: Vec<blake2s_simd::State>,
}

/// The four-worker shape, which is what the agreement tests cross-check.
pub(crate) type PortableLeaves = LeafTeam<HASH_THREADS>;

/// The eight-worker shape. NOT production - it is the arm the in-place
/// team beat on 18 Sep 2026, kept so the rig can re-run the comparison
/// and the agreement tests can cover a second eight-worker split.
pub(crate) type WideLeafTeam = LeafTeam<WIDE_THREADS>;

impl<const THREADS: usize> LeafSet for LeafTeam<THREADS> {
    fn new() -> Self {
        Self {
            leaves: (0..PARALLELISM)
                .map(|index| leaf_params(index).to_state())
                .collect(),
        }
    }

    fn absorb_groups(&mut self, groups: &[u8]) {
        absorb_pieces::<THREADS>(&mut self.leaves, &[groups]);
    }

    fn absorb_group_pieces(&mut self, pieces: &[&[u8]]) {
        absorb_pieces::<THREADS>(&mut self.leaves, pieces);
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

thread_local! {
    /// A worker's gather buffer, kept between batches: a 1 MiB piece would
    /// otherwise allocate and zero 128 KiB per leaf per call.
    static SCRATCH: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Gather leaf `leaf_index`'s 64-byte blocks out of every piece and hash
/// them in one update, reusing this worker's scratch buffer. Each piece is
/// a whole number of 512-byte groups, so the leaf's blocks run straight on
/// across a piece boundary.
fn absorb_leaf(leaf: &mut blake2s_simd::State, pieces: &[&[u8]], leaf_index: usize) {
    let slot = leaf_index * BLOCK_BYTES;
    SCRATCH.with(|cell| {
        let mut scratch = cell.borrow_mut();
        scratch.clear();
        let groups: usize = pieces.iter().map(|piece| piece.len() / GROUP_BYTES).sum();
        scratch.reserve(groups * BLOCK_BYTES);
        for piece in pieces {
            for group in 0..piece.len() / GROUP_BYTES {
                let src = group * GROUP_BYTES + slot;
                scratch.extend_from_slice(&piece[src..src + BLOCK_BYTES]);
            }
        }
        leaf.update(&scratch);
    });
}

/// Hash whole 512-byte groups - given as one or more group-aligned pieces,
/// hashed as if concatenated - into the leaves, splitting the leaf set
/// across a scoped team. A batch too small to pay for the spawns is fed on
/// the calling thread.
fn absorb_pieces<const THREADS: usize>(leaves: &mut [blake2s_simd::State], pieces: &[&[u8]]) {
    let mut window: Vec<&[u8]> = Vec::with_capacity(pieces.len());
    let mut budget = GATHER_MAX_GROUPS;
    for piece in pieces {
        debug_assert_eq!(piece.len() % GROUP_BYTES, 0);
        let mut rest = *piece;
        while rest.len() / GROUP_BYTES > budget {
            let (head, tail) = rest.split_at(budget * GROUP_BYTES);
            window.push(head);
            absorb_window::<THREADS>(leaves, &window, GATHER_MAX_GROUPS);
            window.clear();
            budget = GATHER_MAX_GROUPS;
            rest = tail;
        }
        budget -= rest.len() / GROUP_BYTES;
        window.push(rest);
    }
    absorb_window::<THREADS>(leaves, &window, GATHER_MAX_GROUPS - budget);
}

/// One dispatch: `groups` whole groups spread over `window`.
fn absorb_window<const THREADS: usize>(
    leaves: &mut [blake2s_simd::State],
    pieces: &[&[u8]],
    groups: usize,
) {
    if groups == 0 {
        return;
    }
    let threads = THREADS.clamp(1, PARALLELISM);
    if threads == 1 || groups < TEAM_MIN_GROUPS {
        for (index, leaf) in leaves.iter_mut().enumerate() {
            absorb_leaf(leaf, pieces, index);
        }
        return;
    }
    let leaves_per_thread = PARALLELISM / threads;
    let mut chunks: Vec<&mut [blake2s_simd::State]> =
        leaves.chunks_mut(leaves_per_thread).collect();
    std::thread::scope(|scope| {
        // The last worker's share stays on the calling thread: eight
        // leaves on eight cores means seven spawns, not eight.
        let (last, rest) = chunks.split_last_mut().expect("at least one worker");
        let last_first_leaf = rest.len() * leaves_per_thread;
        for (thread_index, thread_leaves) in rest.iter_mut().enumerate() {
            let first_leaf = thread_index * leaves_per_thread;
            scope.spawn(move || {
                for (offset, leaf) in thread_leaves.iter_mut().enumerate() {
                    absorb_leaf(leaf, pieces, first_leaf + offset);
                }
            });
        }
        for (offset, leaf) in last.iter_mut().enumerate() {
            absorb_leaf(leaf, pieces, last_first_leaf + offset);
        }
    });
}
