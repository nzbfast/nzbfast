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
//! On the `unsafe`: the crate otherwise carries no unsafe code, and this
//! module adds exactly one block, the call in [`compress_blocks`]. NEON
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

/// The crate's one unsafe block. See the module comment: the only thing
/// asserted is that NEON is present, and on aarch64 it always is.
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
