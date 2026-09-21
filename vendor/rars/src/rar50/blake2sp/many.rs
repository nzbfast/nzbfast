//! Four-way BLAKE2s leaf kernel on NEON.
//!
//! nzbfast-local change, 2026-08-22 (TODO 11 later list, "NEON blake2s
//! kernel"). `blake2s_simd` has SSE4.1/AVX2 many-way kernels but nothing for
//! aarch64, so on Apple silicon and every ARM NAS the eight BLAKE2sp leaves
//! ran one scalar compress at a time. This module keeps four leaf states
//! side by side, one `uint32x4_t` per state word, and compresses four leaves
//! per pass: the G mixes are `add.4s`/`eor.16b`, the rotates `rev32.8h`
//! (16), `tbl.16b` (8) and `shl`+`usra` (12, 7), and the four message
//! blocks are transposed into sixteen lane vectors with `zip1`/`zip2`.
//!
//! On the `unsafe`: this module carries two sites and they are there on
//! two different arguments. The first is the call in [`compress_blocks`]
//! below; the second is the persistent leaf team at the foot of the
//! file, whose own argument is stated there and is about a borrow
//! outliving a thread rather than about NEON. NEON
//! intrinsics are SAFE to call inside a `#[target_feature(enable = "neon")]`
//! fn, and every load and store here goes through `vcreate`/`vgetq_lane`
//! on integers rather than pointers - so the intrinsic bodies themselves
//! need no unsafe. What stable Rust cannot express is ENTERING such a fn
//! from plain code: a `#[target_feature]` fn implements no `Fn` trait, will
//! not coerce to a fn pointer, and the feature being part of the target
//! baseline does not count (rustc says so in the diagnostic). The one
//! `unsafe` therefore asserts exactly one thing, that NEON is present, which
//! on aarch64 is not a runtime property: Advanced SIMD is part of the
//! ARMv8-A base ISA and every aarch64 Rust target assumes it. An alternative
//! was a structure-of-arrays `[u32; 4]` kernel in safe code hoping for
//! autovectorization; measured on 22 Aug 2026, LLVM's SLP pass declines the
//! 80-deep in-register chain outright (no `-slp-threshold` flips it) and
//! the result was 0.73 GB/s, SLOWER than `blake2s_simd`'s scalar 0.93.
//!
//! aarch64 only; every other target keeps the `blake2s_simd` leaf states,
//! which carry that crate's x86 many-way kernels.

use super::{LeafSet, BLOCK_BYTES, GROUP_BYTES, OUT_BYTES, PARALLELISM};
use std::arch::aarch64::{
    uint32x4_t, vaddq_u32, vcombine_u32, vcreate_u32, vdupq_n_u32, veorq_u32, vgetq_lane_u64,
    vqtbl1q_u8, vreinterpretq_u16_u32, vreinterpretq_u32_u16, vreinterpretq_u32_u64,
    vreinterpretq_u32_u8, vreinterpretq_u64_u32, vreinterpretq_u8_u32, vrev32q_u16, vshlq_n_u32,
    vsriq_n_u32, vzip1q_u32, vzip1q_u64, vzip2q_u32, vzip2q_u64,
};

type V = uint32x4_t;

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

/// Lanes per kernel call. Two halves cover the eight BLAKE2sp leaves.
const LANES: usize = 4;
const HALVES: usize = PARALLELISM / LANES;
/// Whole groups per `absorb_groups` call above which the two halves run on
/// two threads. One half is one thread's worth of vector work; below this
/// the spawn costs more than it buys.
const THREAD_MIN_GROUPS: usize = 1024;

/// One lane vector as its little-endian bytes: the state words live in this
/// form between kernel calls so no pointer ever reaches an intrinsic.
type LaneBytes = [u8; 16];

#[inline]
#[target_feature(enable = "neon")]
fn load(bytes: &[u8]) -> V {
    let lo = u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    let hi = u64::from_le_bytes([
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ]);
    vcombine_u32(vcreate_u32(lo), vcreate_u32(hi))
}

#[inline]
#[target_feature(enable = "neon")]
fn load_words(w: [u32; LANES]) -> V {
    vcombine_u32(
        vcreate_u32(w[0] as u64 | (w[1] as u64) << 32),
        vcreate_u32(w[2] as u64 | (w[3] as u64) << 32),
    )
}

#[inline]
#[target_feature(enable = "neon")]
fn store(v: V) -> LaneBytes {
    let v = vreinterpretq_u64_u32(v);
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&vgetq_lane_u64::<0>(v).to_le_bytes());
    out[8..].copy_from_slice(&vgetq_lane_u64::<1>(v).to_le_bytes());
    out
}

#[inline]
#[target_feature(enable = "neon")]
fn rot16(x: V) -> V {
    vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(x)))
}

#[inline]
#[target_feature(enable = "neon")]
fn rot12(x: V) -> V {
    vsriq_n_u32::<12>(vshlq_n_u32::<20>(x), x)
}

#[inline]
#[target_feature(enable = "neon")]
fn rot8(x: V) -> V {
    // Byte shuffle: each 32-bit lane rotated right by one byte.
    let index = vreinterpretq_u8_u32(load_words([
        0x0003_0201,
        0x0407_0605,
        0x080B_0A09,
        0x0C0F_0E0D,
    ]));
    vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(x), index))
}

#[inline]
#[target_feature(enable = "neon")]
fn rot7(x: V) -> V {
    vsriq_n_u32::<7>(vshlq_n_u32::<25>(x), x)
}

#[inline]
#[target_feature(enable = "neon")]
fn g(v: &mut [V; 16], a: usize, b: usize, c: usize, d: usize, x: V, y: V) {
    v[a] = vaddq_u32(vaddq_u32(v[a], v[b]), x);
    v[d] = rot16(veorq_u32(v[d], v[a]));
    v[c] = vaddq_u32(v[c], v[d]);
    v[b] = rot12(veorq_u32(v[b], v[c]));
    v[a] = vaddq_u32(vaddq_u32(v[a], v[b]), y);
    v[d] = rot8(veorq_u32(v[d], v[a]));
    v[c] = vaddq_u32(v[c], v[d]);
    v[b] = rot7(veorq_u32(v[b], v[c]));
}

/// One BLAKE2s round with its sigma permutation spelled out as literals.
/// A `for s in SIGMA` loop does not unroll here and leaves every message
/// word a bounds-checked indexed stack load (measured 22 Aug 2026: 16
/// compare-and-branch pairs per round, and the kernel no faster than the
/// scalar crate).
macro_rules! round {
    ($v:ident, $m:ident, $s0:literal, $s1:literal, $s2:literal, $s3:literal, $s4:literal,
     $s5:literal, $s6:literal, $s7:literal, $s8:literal, $s9:literal, $s10:literal,
     $s11:literal, $s12:literal, $s13:literal, $s14:literal, $s15:literal) => {
        g(&mut $v, 0, 4, 8, 12, $m[$s0], $m[$s1]);
        g(&mut $v, 1, 5, 9, 13, $m[$s2], $m[$s3]);
        g(&mut $v, 2, 6, 10, 14, $m[$s4], $m[$s5]);
        g(&mut $v, 3, 7, 11, 15, $m[$s6], $m[$s7]);
        g(&mut $v, 0, 5, 10, 15, $m[$s8], $m[$s9]);
        g(&mut $v, 1, 6, 11, 12, $m[$s10], $m[$s11]);
        g(&mut $v, 2, 7, 8, 13, $m[$s12], $m[$s13]);
        g(&mut $v, 3, 4, 9, 14, $m[$s14], $m[$s15]);
    };
}

/// Transpose four 64-byte blocks into sixteen four-lane message words.
#[inline]
#[target_feature(enable = "neon")]
fn load_message(blocks: [&[u8]; LANES]) -> [V; 16] {
    let mut m = [vdupq_n_u32(0); 16];
    for quarter in 0..4 {
        let at = quarter * 16;
        let a = load(&blocks[0][at..at + 16]);
        let b = load(&blocks[1][at..at + 16]);
        let c = load(&blocks[2][at..at + 16]);
        let d = load(&blocks[3][at..at + 16]);
        let ab_lo = vreinterpretq_u64_u32(vzip1q_u32(a, b));
        let ab_hi = vreinterpretq_u64_u32(vzip2q_u32(a, b));
        let cd_lo = vreinterpretq_u64_u32(vzip1q_u32(c, d));
        let cd_hi = vreinterpretq_u64_u32(vzip2q_u32(c, d));
        m[quarter * 4] = vreinterpretq_u32_u64(vzip1q_u64(ab_lo, cd_lo));
        m[quarter * 4 + 1] = vreinterpretq_u32_u64(vzip2q_u64(ab_lo, cd_lo));
        m[quarter * 4 + 2] = vreinterpretq_u32_u64(vzip1q_u64(ab_hi, cd_hi));
        m[quarter * 4 + 3] = vreinterpretq_u32_u64(vzip2q_u64(ab_hi, cd_hi));
    }
    m
}

/// Compress `count` blocks into four lane states. Block `i` of lane `l`
/// starts at `data[i * stride + l * 64]`. `t_first` is the per-lane byte
/// counter AFTER the first block (it advances by 64 per block); `f0`/`f1`
/// are all-ones lane masks for the final-block and last-node flags and
/// apply to every block, so a multi-block call passes zeros.
#[target_feature(enable = "neon")]
fn compress_blocks_neon(
    h: &mut [LaneBytes; 8],
    data: &[u8],
    stride: usize,
    count: usize,
    t_first: [u64; LANES],
    f0: [u32; LANES],
    f1: [u32; LANES],
) {
    let mut hv = [vdupq_n_u32(0); 8];
    for (word, bytes) in hv.iter_mut().zip(h.iter()) {
        *word = load(bytes);
    }
    let iv: [V; 8] = [
        vdupq_n_u32(IV[0]),
        vdupq_n_u32(IV[1]),
        vdupq_n_u32(IV[2]),
        vdupq_n_u32(IV[3]),
        vdupq_n_u32(IV[4]),
        vdupq_n_u32(IV[5]),
        vdupq_n_u32(IV[6]),
        vdupq_n_u32(IV[7]),
    ];
    let f0 = veorq_u32(iv[6], load_words(f0));
    let f1 = veorq_u32(iv[7], load_words(f1));
    let mut t = t_first;
    for block in 0..count {
        let base = block * stride;
        let m = load_message([
            &data[base..base + BLOCK_BYTES],
            &data[base + BLOCK_BYTES..base + 2 * BLOCK_BYTES],
            &data[base + 2 * BLOCK_BYTES..base + 3 * BLOCK_BYTES],
            &data[base + 3 * BLOCK_BYTES..base + 4 * BLOCK_BYTES],
        ]);
        let t_lo = load_words([t[0] as u32, t[1] as u32, t[2] as u32, t[3] as u32]);
        let t_hi = load_words([
            (t[0] >> 32) as u32,
            (t[1] >> 32) as u32,
            (t[2] >> 32) as u32,
            (t[3] >> 32) as u32,
        ]);
        let mut v: [V; 16] = [
            hv[0],
            hv[1],
            hv[2],
            hv[3],
            hv[4],
            hv[5],
            hv[6],
            hv[7],
            iv[0],
            iv[1],
            iv[2],
            iv[3],
            veorq_u32(iv[4], t_lo),
            veorq_u32(iv[5], t_hi),
            f0,
            f1,
        ];
        round!(v, m, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
        round!(v, m, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3);
        round!(v, m, 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4);
        round!(v, m, 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8);
        round!(v, m, 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13);
        round!(v, m, 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9);
        round!(v, m, 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11);
        round!(v, m, 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10);
        round!(v, m, 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5);
        round!(v, m, 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0);
        for word in 0..8 {
            hv[word] = veorq_u32(veorq_u32(hv[word], v[word]), v[word + 8]);
        }
        for lane in &mut t {
            *lane += BLOCK_BYTES as u64;
        }
    }
    for (bytes, word) in h.iter_mut().zip(hv.iter()) {
        *bytes = store(*word);
    }
}

/// The first of this module's two unsafe sites. See the module comment:
/// the only thing asserted is that NEON is present, and on aarch64 it
/// always is. The second is the persistent leaf team at the foot of the
/// file, whose argument is its own.
#[allow(unsafe_code)]
fn compress_blocks(
    h: &mut [LaneBytes; 8],
    data: &[u8],
    stride: usize,
    count: usize,
    t_first: [u64; LANES],
    f0: [u32; LANES],
    f1: [u32; LANES],
) {
    debug_assert!(
        data.len() >= count.saturating_sub(1) * stride + LANES * BLOCK_BYTES || count == 0
    );
    // SAFETY: Advanced SIMD (NEON) is mandatory in the ARMv8-A base
    // architecture and assumed by every aarch64 target rustc ships, so the
    // `#[target_feature(enable = "neon")]` precondition holds unconditionally
    // on the only architecture this module is compiled for. The callee takes
    // safe slices and integers only; no pointer, lifetime or aliasing claim
    // is being made here.
    unsafe { compress_blocks_neon(h, data, stride, count, t_first, f0, f1) }
}

/// Four leaves with consecutive indices, kept lane-wise.
#[derive(Clone)]
struct Half {
    /// State word `w` of the four lanes, as `h[w]`'s little-endian bytes.
    h: [LaneBytes; 8],
    /// The most recent full block of each lane, withheld because BLAKE2s
    /// cannot compress a block until it knows whether more input follows.
    pending: Option<[[u8; BLOCK_BYTES]; LANES]>,
    /// Bytes fed to each lane so far, pending block included. Uniform
    /// across lanes until finalization, because whole groups feed every
    /// leaf exactly one block.
    fed: u64,
}

impl Half {
    fn new(first_leaf: usize) -> Self {
        let mut h = [[0u8; 16]; 8];
        for lane in 0..LANES {
            let leaf = first_leaf + lane;
            // Parameter block, words 0..8: digest_length | key_length << 8 |
            // fanout << 16 | depth << 24; leaf_length; node_offset (48 bits,
            // low word then high half-word) | node_depth << 16 |
            // inner_length << 24; then salt and personalization, all zero.
            let params: [u32; 8] = [
                (OUT_BYTES as u32) | (PARALLELISM as u32) << 16 | 2 << 24,
                0,
                leaf as u32,
                (OUT_BYTES as u32) << 24,
                0,
                0,
                0,
                0,
            ];
            for word in 0..8 {
                h[word][lane * 4..lane * 4 + 4]
                    .copy_from_slice(&(IV[word] ^ params[word]).to_le_bytes());
            }
        }
        Self {
            h,
            pending: None,
            fed: 0,
        }
    }

    /// Feed whole groups. Lane `i` takes block `first_leaf + i` of every
    /// group, `first_leaf` being the block offset of this half's lanes.
    fn absorb_groups(&mut self, groups: &[u8], first_leaf: usize) {
        let slot = first_leaf * BLOCK_BYTES;
        let group_count = groups.len() / GROUP_BYTES;
        if group_count == 0 {
            return;
        }
        if let Some(pending) = self.pending.take() {
            compress_blocks(
                &mut self.h,
                pending.as_flattened(),
                0,
                1,
                [self.fed; LANES],
                [0; LANES],
                [0; LANES],
            );
        }
        // Every group but the last; the last is withheld.
        let lead = group_count - 1;
        compress_blocks(
            &mut self.h,
            &groups[slot..],
            GROUP_BYTES,
            lead,
            [self.fed + BLOCK_BYTES as u64; LANES],
            [0; LANES],
            [0; LANES],
        );
        let lanes =
            &groups[lead * GROUP_BYTES + slot..lead * GROUP_BYTES + slot + LANES * BLOCK_BYTES];
        let mut pending = [[0u8; BLOCK_BYTES]; LANES];
        for (lane, block) in pending.iter_mut().enumerate() {
            block.copy_from_slice(&lanes[lane * BLOCK_BYTES..(lane + 1) * BLOCK_BYTES]);
        }
        self.pending = Some(pending);
        self.fed += (group_count * BLOCK_BYTES) as u64;
    }

    /// Finish every lane. `tail` is this half's share of the final partial
    /// group (up to `LANES * BLOCK_BYTES` bytes, lane `i` owning bytes
    /// `i * 64..`); `last_node` marks the lane carrying the last-node flag.
    fn finalize(mut self, tail: &[u8], last_node: Option<usize>) -> [[u8; OUT_BYTES]; LANES] {
        let lane_len = |lane: usize| -> usize {
            tail.len()
                .saturating_sub(lane * BLOCK_BYTES)
                .min(BLOCK_BYTES)
        };
        let f1_for = |lane: usize| -> u32 {
            if last_node == Some(lane) {
                u32::MAX
            } else {
                0
            }
        };
        // Step 1: the withheld block. It is the final block of any lane the
        // tail gives nothing to.
        if let Some(pending) = self.pending.take() {
            let mut f0 = [0u32; LANES];
            let mut f1 = [0u32; LANES];
            for lane in 0..LANES {
                if lane_len(lane) == 0 {
                    f0[lane] = u32::MAX;
                    f1[lane] = f1_for(lane);
                }
            }
            compress_blocks(
                &mut self.h,
                pending.as_flattened(),
                0,
                1,
                [self.fed; LANES],
                f0,
                f1,
            );
            // Step 2 (pending case): lanes that received tail bytes compress
            // them as their final block; the others are finished already.
            let active: Vec<usize> = (0..LANES).filter(|&lane| lane_len(lane) > 0).collect();
            if !active.is_empty() {
                self.final_tail(tail, &active, f1_for);
            }
        } else {
            // No pending block: every lane's final block is its tail share,
            // empty shares included (an empty leaf still compresses one
            // zero block, per RFC 7693).
            let active: Vec<usize> = (0..LANES).collect();
            self.final_tail(tail, &active, f1_for);
        }
        let mut out = [[0u8; OUT_BYTES]; LANES];
        for (lane, digest) in out.iter_mut().enumerate() {
            for word in 0..8 {
                digest[word * 4..word * 4 + 4]
                    .copy_from_slice(&self.h[word][lane * 4..lane * 4 + 4]);
            }
        }
        out
    }

    fn final_tail(&mut self, tail: &[u8], active: &[usize], f1_for: impl Fn(usize) -> u32) {
        let mut blocks = [[0u8; BLOCK_BYTES]; LANES];
        let mut t = [self.fed; LANES];
        let mut f0 = [0u32; LANES];
        let mut f1 = [0u32; LANES];
        for &lane in active {
            let start = (lane * BLOCK_BYTES).min(tail.len());
            let end = ((lane + 1) * BLOCK_BYTES).min(tail.len());
            blocks[lane][..end - start].copy_from_slice(&tail[start..end]);
            t[lane] += (end - start) as u64;
            f0[lane] = u32::MAX;
            f1[lane] = f1_for(lane);
        }
        let mut h = self.h;
        compress_blocks(&mut h, blocks.as_flattened(), 0, 1, t, f0, f1);
        for &lane in active {
            for (mine, theirs) in self.h.iter_mut().zip(&h) {
                mine[lane * 4..lane * 4 + 4].copy_from_slice(&theirs[lane * 4..lane * 4 + 4]);
            }
        }
    }
}

/// The eight BLAKE2sp leaves as two four-lane halves.
#[derive(Clone)]
pub(crate) struct ManyLeaves {
    halves: [Half; HALVES],
}

impl LeafSet for ManyLeaves {
    fn new() -> Self {
        Self {
            halves: [Half::new(0), Half::new(LANES)],
        }
    }

    fn absorb_groups(&mut self, groups: &[u8]) {
        debug_assert_eq!(groups.len() % GROUP_BYTES, 0);
        if groups.is_empty() {
            return;
        }
        let [first, second] = &mut self.halves;
        if groups.len() / GROUP_BYTES >= THREAD_MIN_GROUPS {
            std::thread::scope(|scope| {
                scope.spawn(|| second.absorb_groups(groups, LANES));
                first.absorb_groups(groups, 0);
            });
        } else {
            first.absorb_groups(groups, 0);
            second.absorb_groups(groups, LANES);
        }
    }

    fn finalize(self, tail: &[u8]) -> [[u8; OUT_BYTES]; PARALLELISM] {
        debug_assert!(tail.len() < GROUP_BYTES);
        let [first, second] = self.halves;
        let split = tail.len().min(LANES * BLOCK_BYTES);
        let a = first.finalize(&tail[..split], None);
        let b = second.finalize(&tail[split..], Some(LANES - 1));
        let mut out = [[0u8; OUT_BYTES]; PARALLELISM];
        out[..LANES].copy_from_slice(&a);
        out[LANES..].copy_from_slice(&b);
        out
    }
}

// ---- The in-place scalar leaf team: aarch64 production above 8 cores ----
//
// A BLAKE2sp leaf is a serial chain and there are eight of them, so eight
// workers is the whole of the tree's parallelism and the four-lane kernel
// above - two halves, two threads - can never use more than two cores.
// Where a box has a core per leaf, one leaf per core wins wall outright.
//
// Each worker reads its own 64-byte blocks IN PLACE at a stride of 512 and
// runs them through the scalar compression below. The alternative, kept in
// `portable.rs` as the independent cross-check, gathers a leaf's blocks
// into a scratch buffer first and hands the gathered run to a
// `blake2s_simd` state. Both were measured in ONE process on a 32-core
// arm64 desktop, 256 MiB, best of five, three runs agreeing within 2%
// (`blake2sp::tests::timing_matrix` prints this table):
//
//     feed        256K   1M    4M    16M   one-shot
//     NEON 2 thr  2.41  2.71  2.88  2.96  3.00
//     gathered 8  3.05  3.97  5.05  5.26  5.24
//     in place 8  3.16  4.28  5.71  6.24  6.43
//
// In place wins at every size - 13% at the 4 MiB batch a stored extract's
// digester produces, 23% at the ceiling - because the gather copies every
// byte of the stream once before any of it is compressed. It also needs no
// scratch at all, so a worker holds eight words of state and nothing else.
//
// The kernel is the design and the code from the lane that left
// `research/rar-extraction-review-2026-09-18/BLAKE2SP-LEAF-TEAM-AND-EXTRACT-IDEAS.md`
// (in the nzbfast repo, with its own measurements on a different Apple
// part); it is carried here rather than rewritten.

#[inline(always)]
fn gs(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

macro_rules! round_s {
    ($v:ident, $m:ident, $s0:literal, $s1:literal, $s2:literal, $s3:literal, $s4:literal,
     $s5:literal, $s6:literal, $s7:literal, $s8:literal, $s9:literal, $s10:literal,
     $s11:literal, $s12:literal, $s13:literal, $s14:literal, $s15:literal) => {
        gs(&mut $v, 0, 4, 8, 12, $m[$s0], $m[$s1]);
        gs(&mut $v, 1, 5, 9, 13, $m[$s2], $m[$s3]);
        gs(&mut $v, 2, 6, 10, 14, $m[$s4], $m[$s5]);
        gs(&mut $v, 3, 7, 11, 15, $m[$s6], $m[$s7]);
        gs(&mut $v, 0, 5, 10, 15, $m[$s8], $m[$s9]);
        gs(&mut $v, 1, 6, 11, 12, $m[$s10], $m[$s11]);
        gs(&mut $v, 2, 7, 8, 13, $m[$s12], $m[$s13]);
        gs(&mut $v, 3, 4, 9, 14, $m[$s14], $m[$s15]);
    };
}

/// One non-final scalar BLAKE2s compression.
#[inline(always)]
fn compress_scalar(h: &mut [u32; 8], block: &[u8], t: u64) {
    let block: &[u8; BLOCK_BYTES] = block[..BLOCK_BYTES].try_into().unwrap();
    let mut m = [0u32; 16];
    for (i, w) in m.iter_mut().enumerate() {
        *w = u32::from_le_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    let mut v = [0u32; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t as u32;
    v[13] ^= (t >> 32) as u32;
    round_s!(v, m, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    round_s!(v, m, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3);
    round_s!(v, m, 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4);
    round_s!(v, m, 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8);
    round_s!(v, m, 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13);
    round_s!(v, m, 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9);
    round_s!(v, m, 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11);
    round_s!(v, m, 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10);
    round_s!(v, m, 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5);
    round_s!(v, m, 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0);
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// One leaf over a batch: the withheld block, then every block of this leaf
/// but the batch's last, which comes back as the new withheld block.
fn leaf_run(
    h: &mut [u32; 8],
    pending: Option<[u8; BLOCK_BYTES]>,
    fed: u64,
    pieces: &[&[u8]],
    leaf: usize,
) -> [u8; BLOCK_BYTES] {
    let mut t = fed;
    if let Some(block) = pending {
        compress_scalar(h, &block, t);
    }
    let slot = leaf * BLOCK_BYTES;
    let last_piece = pieces.len() - 1;
    let mut withheld = [0u8; BLOCK_BYTES];
    for (index, piece) in pieces.iter().enumerate() {
        let groups = piece.len() / GROUP_BYTES;
        let lead = if index == last_piece {
            groups - 1
        } else {
            groups
        };
        for group in piece.chunks_exact(GROUP_BYTES).take(lead) {
            t += BLOCK_BYTES as u64;
            compress_scalar(h, &group[slot..slot + BLOCK_BYTES], t);
        }
        if index == last_piece {
            let at = lead * GROUP_BYTES + slot;
            withheld.copy_from_slice(&piece[at..at + BLOCK_BYTES]);
        }
    }
    withheld
}

impl ManyLeaves {
    /// Every piece is a non-empty whole number of groups. `threads` is 2
    /// (the NEON halves, one spawn per BATCH), or 4 / 8 (scalar leaves).
    /// With a `pool`, the scalar shares go to workers that outlive the
    /// batch; without one, to a `std::thread::scope` of its own.
    pub(crate) fn absorb_pieces(
        &mut self,
        pieces: &[&[u8]],
        threads: usize,
        pool: Option<&LeafPool>,
    ) {
        if pieces.is_empty() {
            return;
        }
        if threads <= 2 {
            let [first, second] = &mut self.halves;
            std::thread::scope(|scope| {
                scope.spawn(|| {
                    for piece in pieces {
                        second.absorb_groups(piece, LANES);
                    }
                });
                for piece in pieces {
                    first.absorb_groups(piece, 0);
                }
            });
            return;
        }
        let total: usize = pieces.iter().map(|p| p.len() / GROUP_BYTES).sum();
        let mut states = [[0u32; 8]; PARALLELISM];
        let mut pendings: [Option<[u8; BLOCK_BYTES]>; PARALLELISM] = [None; PARALLELISM];
        let mut withheld = [[0u8; BLOCK_BYTES]; PARALLELISM];
        for leaf in 0..PARALLELISM {
            let half = &self.halves[leaf / LANES];
            let lane = leaf % LANES;
            for (word, state) in states[leaf].iter_mut().enumerate() {
                *state =
                    u32::from_le_bytes(half.h[word][lane * 4..lane * 4 + 4].try_into().unwrap());
            }
            pendings[leaf] = half.pending.map(|p| p[lane]);
        }
        let fed = self.halves[0].fed;
        let per = PARALLELISM / threads;
        if let Some(pool) = pool {
            #[allow(unused_mut)]
            let mut job = Job {
                pieces: pieces.as_ptr().cast(),
                pieces_len: pieces.len(),
                states: states.as_mut_ptr(),
                withheld: withheld.as_mut_ptr(),
                pendings: pendings.as_ptr(),
                fed,
                per,
                #[cfg(test)]
                panic_share: usize::MAX,
            };
            #[cfg(test)]
            {
                job.panic_share = PANIC_IN_SHARE.with(std::cell::Cell::get);
            }
            pool.dispatch(job, threads);
        } else {
            Self::spawn_shares(
                pieces,
                threads,
                per,
                fed,
                &pendings,
                &mut states,
                &mut withheld,
            );
        }
        Self::rejoin(self, &states, &withheld, total);
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_shares(
        pieces: &[&[u8]],
        threads: usize,
        per: usize,
        fed: u64,
        pendings: &[Option<[u8; BLOCK_BYTES]>; PARALLELISM],
        states: &mut [[u32; 8]; PARALLELISM],
        withheld: &mut [[u8; BLOCK_BYTES]; PARALLELISM],
    ) {
        std::thread::scope(|scope| {
            let mut rest_s = &mut states[..];
            let mut rest_w = &mut withheld[..];
            for team in 0..threads {
                let (s, tail_s) = rest_s.split_at_mut(per);
                let (w, tail_w) = rest_w.split_at_mut(per);
                rest_s = tail_s;
                rest_w = tail_w;
                let pendings = &pendings;
                let mut work = move || {
                    for k in 0..per {
                        let leaf = team * per + k;
                        w[k] = leaf_run(&mut s[k], pendings[leaf], fed, pieces, leaf);
                    }
                };
                if team + 1 == threads {
                    work();
                } else {
                    scope.spawn(work);
                }
            }
        });
    }

    /// Fold the per-leaf states and withheld blocks back into the lane
    /// vectors the NEON halves and `finalize` read.
    fn rejoin(
        &mut self,
        states: &[[u32; 8]; PARALLELISM],
        withheld: &[[u8; BLOCK_BYTES]; PARALLELISM],
        total: usize,
    ) {
        for leaf in 0..PARALLELISM {
            let half = &mut self.halves[leaf / LANES];
            let lane = leaf % LANES;
            for (word, state) in states[leaf].iter().enumerate() {
                half.h[word][lane * 4..lane * 4 + 4].copy_from_slice(&state.to_le_bytes());
            }
            let mut pending = half.pending.unwrap_or([[0u8; BLOCK_BYTES]; LANES]);
            pending[lane] = withheld[leaf];
            half.pending = Some(pending);
        }
        for half in &mut self.halves {
            half.fed += (total * BLOCK_BYTES) as u64;
        }
    }
}

/// `ManyLeaves` driven through [`ManyLeaves::absorb_pieces`] at `THREADS`
/// workers, as a `LeafSet`. `THREADS` of 4 or 8 puts one or two leaves on
/// each worker's in-place scalar run; 2 or fewer falls back to the NEON
/// halves, with one spawn per BATCH rather than per piece.
pub(crate) struct ScalarLeafTeam<const THREADS: usize, const POOLED: bool> {
    leaves: ManyLeaves,
    /// Built on the first wide batch, not on `new`: a hasher over a
    /// member too small to reach one never pays for a thread.
    pool: Option<LeafPool>,
}

/// A clone starts with no team of its own. The hasher holding this is
/// cloned per member, and a clone that shared a team would either
/// serialise two members onto it or outlive the original.
impl<const THREADS: usize, const POOLED: bool> Clone for ScalarLeafTeam<THREADS, POOLED> {
    fn clone(&self) -> Self {
        Self {
            leaves: self.leaves.clone(),
            pool: None,
        }
    }
}

impl<const THREADS: usize, const POOLED: bool> ScalarLeafTeam<THREADS, POOLED> {
    /// Workers this hasher's own team currently has running.
    #[cfg(test)]
    pub(crate) fn live_workers(&self) -> usize {
        self.pool.as_ref().map_or(0, |pool| {
            pool.shared.live.load(std::sync::atomic::Ordering::SeqCst)
        })
    }

    fn run(&mut self, pieces: &[&[u8]]) {
        // A team is built on the first batch big enough to want one, and
        // never for a hasher that only ever sees small ones - a member
        // finishing with one leftover group would otherwise start seven
        // threads to hash 512 bytes. Once built it takes every batch,
        // large or small: the threads are already there.
        let groups: usize = pieces.iter().map(|piece| piece.len() / GROUP_BYTES).sum();
        if POOLED && THREADS > 2 && self.pool.is_none() && groups >= THREAD_MIN_GROUPS {
            // One share stays on this thread, so the team is one short.
            self.pool = Some(LeafPool::new(THREADS - 1));
        }
        self.leaves
            .absorb_pieces(pieces, THREADS, self.pool.as_ref());
    }
}

impl<const THREADS: usize, const POOLED: bool> LeafSet for ScalarLeafTeam<THREADS, POOLED> {
    fn new() -> Self {
        Self {
            leaves: ManyLeaves::new(),
            pool: None,
        }
    }

    fn absorb_groups(&mut self, groups: &[u8]) {
        // `leaf_run` takes the batch's last group apart, so a piece that
        // carries no whole group would underflow its `groups - 1`.
        if groups.len() < GROUP_BYTES {
            return;
        }
        self.run(&[groups]);
    }

    fn absorb_group_pieces(&mut self, pieces: &[&[u8]]) {
        let pieces: Vec<&[u8]> = pieces
            .iter()
            .copied()
            .filter(|piece| piece.len() >= GROUP_BYTES)
            .collect();
        if pieces.is_empty() {
            return;
        }
        self.run(&pieces);
    }

    fn finalize(self, tail: &[u8]) -> [[u8; OUT_BYTES]; PARALLELISM] {
        self.leaves.finalize(tail)
    }
}

// ---- The persistent leaf team ----
//
// `absorb_pieces` above opens a `std::thread::scope` per BATCH, so a
// member hashed in 4 MiB batches pays seven `pthread_create`s every
// 4 MiB, and the in-place team's throughput climbs with the batch size
// purely because that cost amortises. Workers that live as long as the
// hasher and take a batch over a condvar remove it. Measured on a
// 32-core arm64 desktop, 256 MiB, best of five, three runs agreeing
// within 2% (`blake2sp::tests::timing_matrix` prints this table):
//
//     feed        256K   1M    4M    16M   one-shot
//     NEON 2 thr  2.41  2.70  2.85  2.89  2.92
//     gathered 8  3.20  3.99  5.04  5.26  5.24
//     in place 8  3.26  4.57  5.74  6.22  6.43
//     one team    4.45  5.46  6.13  6.31  6.41
//
// The win is largest where the batches are smallest - 36% at 256 KiB,
// 20% at 1 MiB - and 7% at the 4 MiB a stored extract's digester
// produces. It is nil fed the whole 256 MiB in one call, which is the
// control: one dispatch has one scope either way. End to end on a 2 GiB
// stored member with a BLAKE2sp record, `rarfast t`, both arms in one
// binary and the reps interleaved: 0.36 s against 0.39 s, and LESS CPU
// (0.25 s system against 0.31 s), the spawns being syscalls.
//
// TWO CHEAPER THINGS WERE MEASURED FIRST AND NEITHER PAID, so do not
// re-derive them (same box, same rig, arms interleaved in one binary):
//
// - A 64 KiB worker stack instead of the default 2 MiB: 5.78 against
//   5.78 at 4 MiB. The cost is the thread creation, not the mapping.
// - Reading each message word out of the block at the point of use
//   rather than unpacking all sixteen up front - sixteen state words
//   plus sixteen message words being one live value more than aarch64
//   has registers: 5.77 against 5.78. The chain is latency bound rather
//   than register bound, and LLVM was already scheduling those loads.
//   Hoisting the leaf state into a local across the block loop, in case
//   the `&mut` aliased the input, was measurably WORSE (5.98): it was
//   already being promoted.
//
// ON THE `unsafe`: this module's header argues its first site, the NEON
// entry. This is the second, and it is a different argument. A worker
// that outlives one batch cannot borrow that batch: `std::thread::scope`
// exists precisely to lend a borrow to a thread, and it can only do so
// by ending the thread at the end of the borrow, which is the cost being
// removed here. So the batch reaches the workers as raw pointers, and
// what makes them sound is the same property `scope` enforces by
// construction and this code enforces by blocking: `dispatch` does not
// return until every share it handed out has signalled completion, so no
// pointer here outlives the frame it addresses. The two ways that could
// break are a worker panicking (it would never signal) and a panic in
// the dispatcher's own share (it would unwind past the wait) - both are
// caught, counted, and re-raised only once the team is idle. All three
// properties have tests, and every one of them runs the body on a thread
// under a deadline rather than joining it, because the failure being
// guarded against is a hang and a join would simply hang with it.

use std::sync::{Arc, Condvar, Mutex};

/// One batch, as the pointers a worker needs to find its own leaves in
/// it. Every field addresses a local of the dispatching frame.
#[derive(Clone, Copy)]
struct Job {
    pieces: *const &'static [u8],
    pieces_len: usize,
    states: *mut [u32; 8],
    withheld: *mut [u8; BLOCK_BYTES],
    pendings: *const Option<[u8; BLOCK_BYTES]>,
    fed: u64,
    /// Leaves per worker share.
    per: usize,
    /// The share to panic in, or `usize::MAX`. Carried in the job rather
    /// than read from a static: the lib tests share one process, and a
    /// global injector fires in whatever sibling test is dispatching.
    #[cfg(test)]
    panic_share: usize,
}

// SAFETY: a `Job` is only ever read inside `run_share`, which runs
// between `dispatch` publishing it and `dispatch` observing every
// worker's completion - so the dispatching frame, which owns every
// target, is alive throughout. Share `s` touches `states[s * per ..]`
// and `withheld[s * per ..]` and no other share's, so the two `*mut`
// arrays are partitioned rather than aliased; `pieces` and `pendings`
// are read-only for the whole dispatch.
#[allow(unsafe_code)]
unsafe impl Send for Job {}

/// Run share `share` of `job`: its `per` leaves, in place.
///
/// # Safety
///
/// `job`'s pointers must be valid for the call, and no other live call
/// may name the same `share`.
#[allow(unsafe_code)]
unsafe fn run_share(job: &Job, share: usize) {
    #[cfg(test)]
    assert!(job.panic_share != share, "injected leaf-worker panic");
    // SAFETY: the caller guarantees the pointers; the partitioning is the
    // `unsafe impl Send` argument above.
    unsafe {
        let pieces = std::slice::from_raw_parts(job.pieces, job.pieces_len);
        for k in 0..job.per {
            let leaf = share * job.per + k;
            *job.withheld.add(leaf) = leaf_run(
                &mut *job.states.add(leaf),
                *job.pendings.add(leaf),
                job.fed,
                pieces,
                leaf,
            );
        }
    }
}

struct Slot {
    /// Bumped once per batch; a worker takes work when this passes the
    /// generation it last ran, which is what makes a missed notify
    /// harmless rather than a hang.
    generation: u64,
    shutdown: bool,
    outstanding: usize,
    job: Option<Job>,
    panicked: bool,
}

struct Shared {
    #[cfg(test)]
    live: std::sync::atomic::AtomicUsize,
    slot: Mutex<Slot>,
    /// Workers wait here for a new generation.
    ready: Condvar,
    /// The dispatcher waits here for `outstanding` to reach zero.
    idle: Condvar,
}

/// Workers that outlive a batch. Created on a hasher's first wide batch
/// and joined when it is dropped, so a hasher abandoned mid-stream (an
/// extraction that stops early) leaves no thread behind.
pub(crate) struct LeafPool {
    shared: Arc<Shared>,
    workers: Vec<std::thread::JoinHandle<()>>,
}

/// A leaf worker holds eight state words, a block and a message array.
const LEAF_STACK: usize = 64 << 10;

fn lock(shared: &Shared) -> std::sync::MutexGuard<'_, Slot> {
    // A worker only panics inside `catch_unwind`, so the lock is never
    // held by a panicking frame; take the inner guard rather than adding
    // a failure mode that cannot happen.
    shared.slot.lock().unwrap_or_else(|e| e.into_inner())
}

// The share to panic in on the NEXT dispatch from this thread, for the
// test that proves a worker panic surfaces on the dispatcher rather
// than wedging it. Thread-local, and read into the job at dispatch: the
// lib tests share one process, so a static here would fire in whatever
// sibling test happened to be hashing.
#[cfg(test)]
thread_local! {
    pub(crate) static PANIC_IN_SHARE: std::cell::Cell<usize> =
        const { std::cell::Cell::new(usize::MAX) };
}

/// A worker counted in its own pool for as long as it is running, so a
/// test can assert a team is there and then gone without reading a
/// count some other test's team is also writing.
#[cfg(test)]
struct Census<'a>(&'a Shared);

#[cfg(test)]
impl<'a> Census<'a> {
    fn enter(shared: &'a Shared) -> Self {
        shared
            .live
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self(shared)
    }
}

#[cfg(test)]
impl Drop for Census<'_> {
    fn drop(&mut self) {
        self.0
            .live
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[allow(unsafe_code)]
fn worker_loop(shared: &Shared, share: usize) {
    #[cfg(test)]
    let _census = Census::enter(shared);
    let mut seen = 0u64;
    loop {
        let job = {
            let mut slot = lock(shared);
            loop {
                if slot.shutdown {
                    return;
                }
                if slot.generation != seen {
                    seen = slot.generation;
                    break slot.job;
                }
                slot = shared.ready.wait(slot).unwrap_or_else(|e| e.into_inner());
            }
        };
        if let Some(job) = job {
            // SAFETY: `dispatch` published these pointers and is blocked
            // on `idle` until this share signals below, so the frame they
            // address is alive for the whole call. `share` is this
            // worker's alone.
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                run_share(&job, share)
            }));
            let mut slot = lock(shared);
            slot.panicked |= outcome.is_err();
            slot.outstanding -= 1;
            if slot.outstanding == 0 {
                shared.idle.notify_all();
            }
        }
    }
}

impl LeafPool {
    /// `workers` threads, each taking one share. Spawning fewer than
    /// asked is not an error: [`Self::dispatch`] runs whatever shares
    /// have no worker on the dispatching thread.
    fn new(workers: usize) -> Self {
        let shared = Arc::new(Shared {
            #[cfg(test)]
            live: std::sync::atomic::AtomicUsize::new(0),
            slot: Mutex::new(Slot {
                generation: 0,
                shutdown: false,
                outstanding: 0,
                job: None,
                panicked: false,
            }),
            ready: Condvar::new(),
            idle: Condvar::new(),
        });
        let mut handles = Vec::with_capacity(workers);
        for share in 0..workers {
            let mine = Arc::clone(&shared);
            let spawned = std::thread::Builder::new()
                .name("blake2sp-leaf".to_owned())
                .stack_size(LEAF_STACK)
                .spawn(move || worker_loop(&mine, share));
            match spawned {
                Ok(handle) => handles.push(handle),
                Err(_) => break,
            }
        }
        Self {
            shared,
            workers: handles,
        }
    }

    /// Run all `shares` of `job`, returning once every one of them is
    /// complete.
    #[allow(unsafe_code)]
    fn dispatch(&self, job: Job, shares: usize) {
        let woken = self.workers.len().min(shares);
        if woken > 0 {
            let mut slot = lock(&self.shared);
            slot.job = Some(job);
            slot.outstanding = woken;
            slot.generation = slot.generation.wrapping_add(1);
            drop(slot);
            self.shared.ready.notify_all();
        }
        // The shares no worker took. Caught rather than propagated: an
        // unwind from here would leave the frame `job` points into while
        // the workers are still reading it.
        let mut panicked = false;
        for share in woken..shares {
            // SAFETY: as in `worker_loop`, and this thread owns the frame.
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                run_share(&job, share)
            }));
            panicked |= outcome.is_err();
        }
        if woken > 0 {
            let mut slot = lock(&self.shared);
            while slot.outstanding != 0 {
                slot = self
                    .shared
                    .idle
                    .wait(slot)
                    .unwrap_or_else(|e| e.into_inner());
            }
            panicked |= slot.panicked;
            slot.panicked = false;
            slot.job = None;
        }
        assert!(!panicked, "a BLAKE2sp leaf worker panicked");
    }
}

impl Drop for LeafPool {
    fn drop(&mut self) {
        {
            let mut slot = lock(&self.shared);
            slot.shutdown = true;
        }
        self.shared.ready.notify_all();
        for handle in self.workers.drain(..) {
            let _ = handle.join();
        }
    }
}
