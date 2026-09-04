//! BLAKE2sp over `blake2s_simd`'s own many-way kernel: the eight leaves
//! compressed side by side in one SIMD batch, on one thread.
//!
//! The default everywhere except aarch64, where that crate's many-way
//! kernel does not exist (`guts::MAX_DEGREE` is 1 off x86) and
//! [`super::many::ManyLeaves`] takes over; compiled there too so the tests
//! can hold every kernel to the same digests.
//!
//! This replaced [`super::portable::PortableLeaves`] as the x86 production
//! path on 2026-09-03. That one held the eight leaves as eight independent
//! `blake2s_simd::State`s and spread them over four scoped threads per
//! buffered chunk, each thread GATHERING its leaves' 64-byte blocks out of
//! the 512-byte groups into a scratch buffer first - so a megabyte of input
//! cost a megabyte of zeroed allocation, a megabyte of copying and four
//! thread spawns before a single compression, and each leaf then ran on the
//! crate's ONE-instance kernel. `blake2s_simd::blake2sp` needs none of it:
//! its leaves read their blocks in place at a stride of eight (`guts`'
//! `Stride::Parallel`) and compress eight-wide under AVX2 or four-wide
//! under SSE4.1, picked by `Implementation::detect()` at construction with
//! the crate's portable compression as the fallback. Measured in audit
//! round 25 (`research/RAR-PERF-AUDIT-2026-09-02.md`).
//!
//! It is the same tree this module builds by hand - eight leaves, fanout 8,
//! depth 2, 32-byte inner hashes, last-node flag on leaf 7, one root pass -
//! so the digests are equal by construction, and the tests assert it.
#![cfg_attr(target_arch = "aarch64", allow(dead_code))]

use super::OUT_BYTES;

/// BLAKE2sp-256 as `blake2s_simd`'s own streaming blake2sp state.
#[derive(Clone)]
pub(crate) struct SimdHasher {
    state: blake2s_simd::blake2sp::State,
}

impl SimdHasher {
    pub(crate) fn new() -> Self {
        Self {
            state: blake2s_simd::blake2sp::Params::new()
                .hash_length(OUT_BYTES)
                .to_state(),
        }
    }

    pub(crate) fn update(&mut self, input: &[u8]) {
        self.state.update(input);
    }

    pub(crate) fn finalize(self) -> [u8; OUT_BYTES] {
        let mut out = [0u8; OUT_BYTES];
        out.copy_from_slice(self.state.finalize().as_bytes());
        out
    }
}
