//! Eight MD5 chains at once on AVX2: one `u32` lane per message, the
//! sixty-four steps run as vector ops, so eight INDEPENDENT messages
//! cost about what one costs on the scalar chain.
//!
//! Why: MD5 is a serial dependency chain, ~5 cycles per byte however
//! the box is built, and the creator hashes every input block on its
//! own chain (the IFSC digest) beside the whole-file chain - ~2
//! CPU-seconds per GiB on an i5-10600KF, spent while the recovery fold
//! wants the same cores (the create-pipeline handoff, 5 Sep 2026,
//! section 5). Per-block digests are independent messages, so eight of
//! them in lockstep is the classic multi-buffer trick ParPar ships as
//! its "SIMD MD5". Only the block function is vectorised: message words
//! are transposed into lanes 64 bytes at a time (two 8x8 `u32`
//! transposes per step), the padding block is built per lane exactly as
//! RFC 1321 says, and a lane whose message ends takes the next pending
//! message so mixed lengths keep every lane busy. The chaining words
//! live in registers across blocks and only meet memory when a lane
//! changes message.
//!
//! [`md5_many`] is the whole API: any number of messages, any lengths,
//! digests in input order; off AVX2 and off NEON it is the scalar
//! hasher in a loop, so callers need no cfg of their own. Measured on
//! the i5-10600KF (5 Sep 2026, the multi-buffer handoff): numbers there.
//!
//! aarch64 runs the same scheme four lanes wide (a `uint32x4_t` per
//! message word), from THREE messages up: the review's kernel sweep on an
//! M1 (5 Sep 2026) had two lanes at 0.78x the scalar chain - half the
//! vector idle, and the two-lane case is exactly the 2 MiB block create,
//! which it regressed 5% - three at 1.18x and four at 1.58x. On the M3
//! Ultra (same binary, `NZBFAST_MD5_NEON=0` as the off arm, three
//! mirrored rounds, outputs byte-identical) the 1 GiB / 1 MiB create
//! spends 8.3-8.8 user-CPU-seconds against 8.8-9.1 and the 64 KiB create
//! 11.2-11.4 against 11.7-11.8; the wall is flat on 32 cores and was
//! -5% on the review's M1, where the cores the hash frees are the cores the
//! fold wants. `NZBFAST_MD5_NEON=0` is the scalar arm.

use super::{Digest, Md5};

/// MD5 of every message, in order. Eight at a time on AVX2 x86-64,
/// four at a time on NEON aarch64 (three messages or more), one at a
/// time elsewhere; identical bytes either way.
pub fn md5_many(msgs: &[&[u8]]) -> Vec<[u8; 16]> {
    #[cfg(target_arch = "aarch64")]
    if msgs.len() >= 3 && neon_enabled() {
        // SAFETY: NEON checked in `neon_enabled`; every source is a
        // valid byte slice.
        return unsafe { md5_many_neon(msgs) };
    }
    #[cfg(target_arch = "x86_64")]
    {
        if msgs.len() >= 2 && is_x86_feature_detected!("avx2") {
            // SAFETY: avx2 verified at runtime just above.
            return unsafe { md5_many_avx2(msgs) };
        }
    }
    msgs.iter().map(|m| Md5::digest(m).into()).collect()
}

/// Whether the vector path is the one [`md5_many`] takes here.
pub fn multi_available() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        is_x86_feature_detected!("avx2")
    }
    #[cfg(target_arch = "aarch64")]
    {
        neon_enabled()
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
}

/// The four-lane NEON path is on by default; `NZBFAST_MD5_NEON=0` is
/// the scalar arm of the A/B. Read once: `md5_many` runs once per
/// eight-block pass of the creator's scan, thousands of times a create.
#[cfg(target_arch = "aarch64")]
fn neon_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        std::env::var("NZBFAST_MD5_NEON").as_deref() != Ok("0")
            && std::arch::is_aarch64_feature_detected!("neon")
    })
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const INIT: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

/// One lane's feed: which message it is on, how far, and the padded
/// tail block(s) once the message runs out of whole blocks.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
struct Lane {
    /// Index into `msgs`, or `usize::MAX` when idle.
    msg: usize,
    /// Next byte offset in the message.
    pos: usize,
    /// Padded tail: up to two 64-byte blocks, `tail_len` of them.
    tail: [u8; 128],
    tail_len: usize,
    tail_pos: usize,
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
impl Lane {
    const IDLE: usize = usize::MAX;

    fn idle() -> Lane {
        Lane {
            msg: Self::IDLE,
            pos: 0,
            tail: [0; 128],
            tail_len: 0,
            tail_pos: 0,
        }
    }

    fn start(&mut self, msg: usize, data: &[u8]) {
        self.msg = msg;
        self.pos = 0;
        self.tail_len = 0;
        self.tail_pos = 0;
        self.build_tail_if_due(data);
    }

    /// Once fewer than 64 whole bytes remain, lay the RFC 1321 padding
    /// out: the rest of the message, 0x80, zeros, and the bit length.
    fn build_tail_if_due(&mut self, data: &[u8]) {
        if self.tail_len != 0 || data.len() - self.pos >= 64 {
            return;
        }
        let rest = &data[self.pos..];
        self.tail = [0; 128];
        self.tail[..rest.len()].copy_from_slice(rest);
        self.tail[rest.len()] = 0x80;
        let blocks = if rest.len() + 1 + 8 <= 64 { 1 } else { 2 };
        let bits = (data.len() as u64).wrapping_mul(8);
        self.tail[blocks * 64 - 8..blocks * 64].copy_from_slice(&bits.to_le_bytes());
        self.tail_len = blocks * 64;
        self.tail_pos = 0;
    }

    /// The next 64 bytes this lane absorbs, or None when its message is
    /// finished.
    fn next_block<'a>(&'a mut self, data: &'a [u8]) -> Option<&'a [u8]> {
        self.build_tail_if_due(data);
        if self.tail_len != 0 {
            if self.tail_pos >= self.tail_len {
                return None;
            }
            let b = &self.tail[self.tail_pos..self.tail_pos + 64];
            self.tail_pos += 64;
            return Some(b);
        }
        let b = &data[self.pos..self.pos + 64];
        self.pos += 64;
        Some(b)
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn md5_many_neon(msgs: &[&[u8]]) -> Vec<[u8; 16]> {
    use std::arch::aarch64::*;
    let mut out = vec![[0u8; 16]; msgs.len()];
    let mut lanes: [Lane; 4] = std::array::from_fn(|_| Lane::idle());
    let mut next = 0usize;
    let mut active = 0usize;
    for lane in lanes.iter_mut() {
        if next < msgs.len() {
            lane.start(next, msgs[next]);
            next += 1;
            active += 1;
        }
    }
    let zero_block = [0u8; 64];
    let mut blocks: [*const u8; 4] = [zero_block.as_ptr(); 4];
    let mut words = [vdupq_n_u32(0); 16];
    // The chaining words live in registers across blocks; they are
    // written back to `lane_state` only when a lane finishes a message
    // (to read its digest and seed the next one), then reloaded.
    let mut lane_state: [[u32; 4]; 4] = [[0; 4]; 4];
    for (w, row) in lane_state.iter_mut().enumerate() {
        *row = [INIT[w]; 4];
    }
    let mut st = [vdupq_n_u32(0); 4];
    let mut reload = true;
    while active > 0 {
        // Phase 1: each lane's next block, or a note that it finished.
        let mut finished = [false; 4];
        let mut any_finished = false;
        for (j, lane) in lanes.iter_mut().enumerate() {
            if lane.msg == Lane::IDLE {
                blocks[j] = zero_block.as_ptr();
                continue;
            }
            match lane.next_block(msgs[lane.msg]) {
                Some(b) => blocks[j] = b.as_ptr(),
                None => {
                    finished[j] = true;
                    any_finished = true;
                }
            }
        }
        // Phase 2: finished lanes hand out their digest and take the next
        // message; this is the one place the registers meet the arrays.
        if any_finished {
            if !reload {
                // SAFETY: plain stores of four vectors into 4-word arrays.
                unsafe {
                    for (w, sv) in st.iter().enumerate() {
                        vst1q_u32(lane_state[w].as_mut_ptr(), *sv);
                    }
                }
            }
            for (j, lane) in lanes.iter_mut().enumerate() {
                if !finished[j] {
                    continue;
                }
                for (w, row) in lane_state.iter_mut().enumerate() {
                    out[lane.msg][w * 4..w * 4 + 4].copy_from_slice(&row[j].to_le_bytes());
                    row[j] = INIT[w];
                }
                active -= 1;
                if next < msgs.len() {
                    lane.start(next, msgs[next]);
                    next += 1;
                    active += 1;
                    blocks[j] = lane
                        .next_block(msgs[next - 1])
                        .expect("a fresh message always has a first block")
                        .as_ptr();
                } else {
                    lane.msg = Lane::IDLE;
                    blocks[j] = zero_block.as_ptr();
                }
            }
            reload = true;
        }
        if active == 0 {
            break;
        }
        // SAFETY: every `blocks[j]` points at 64 readable bytes (a whole
        // message block, a lane's padded tail, or the zero block); neon
        // is on per #[target_feature], verified by the caller.
        unsafe {
            if reload {
                for (w, sv) in st.iter_mut().enumerate() {
                    *sv = vld1q_u32(lane_state[w].as_ptr());
                }
                reload = false;
            }
            // Four unaligned 16-byte loads per word group; transpose the
            // four messages into one vector per MD5 message word.
            for base in (0..16).step_by(4) {
                let r: [uint32x4_t; 4] =
                    std::array::from_fn(|j| vld1q_u32(blocks[j].add(base * 4).cast::<u32>()));
                let a = vtrn1q_u32(r[0], r[1]);
                let b = vtrn2q_u32(r[0], r[1]);
                let c = vtrn1q_u32(r[2], r[3]);
                let d = vtrn2q_u32(r[2], r[3]);
                words[base] = vcombine_u32(vget_low_u32(a), vget_low_u32(c));
                words[base + 1] = vcombine_u32(vget_low_u32(b), vget_low_u32(d));
                words[base + 2] = vcombine_u32(vget_high_u32(a), vget_high_u32(c));
                words[base + 3] = vcombine_u32(vget_high_u32(b), vget_high_u32(d));
            }
            compress4(&mut st, &words);
        }
    }
    out
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
#[inline]
unsafe fn compress4(
    st: &mut [std::arch::aarch64::uint32x4_t; 4],
    words: &[std::arch::aarch64::uint32x4_t; 16],
) {
    use std::arch::aarch64::*;
    let (mut a, mut b, mut c, mut d) = (st[0], st[1], st[2], st[3]);
    macro_rules! ff {
        ($b:expr, $c:expr, $d:expr) => {
            veorq_u32($d, vandq_u32($b, veorq_u32($c, $d)))
        };
    }
    macro_rules! gg {
        ($b:expr, $c:expr, $d:expr) => {
            veorq_u32($c, vandq_u32($d, veorq_u32($b, $c)))
        };
    }
    macro_rules! hh {
        ($b:expr, $c:expr, $d:expr) => {
            veorq_u32(veorq_u32($b, $c), $d)
        };
    }
    macro_rules! ii {
        ($b:expr, $c:expr, $d:expr) => {
            veorq_u32($c, vorrq_u32($b, veorq_u32($d, vdupq_n_u32(u32::MAX))))
        };
    }
    macro_rules! step {
        ($f:ident, $k:expr, $s:literal, $g:expr) => {
            let sum = vaddq_u32(
                vaddq_u32(a, $f!(b, c, d)),
                vaddq_u32(vdupq_n_u32($k as u32), words[$g]),
            );
            let rot = vorrq_u32(vshlq_n_u32::<$s>(sum), vshrq_n_u32::<{ 32 - $s }>(sum));
            let nb = vaddq_u32(b, rot);
            a = d;
            d = c;
            c = b;
            b = nb;
        };
    }
    step!(ff, 0xd76aa478u32, 7, 0);
    step!(ff, 0xe8c7b756u32, 12, 1);
    step!(ff, 0x242070dbu32, 17, 2);
    step!(ff, 0xc1bdceeeu32, 22, 3);
    step!(ff, 0xf57c0fafu32, 7, 4);
    step!(ff, 0x4787c62au32, 12, 5);
    step!(ff, 0xa8304613u32, 17, 6);
    step!(ff, 0xfd469501u32, 22, 7);
    step!(ff, 0x698098d8u32, 7, 8);
    step!(ff, 0x8b44f7afu32, 12, 9);
    step!(ff, 0xffff5bb1u32, 17, 10);
    step!(ff, 0x895cd7beu32, 22, 11);
    step!(ff, 0x6b901122u32, 7, 12);
    step!(ff, 0xfd987193u32, 12, 13);
    step!(ff, 0xa679438eu32, 17, 14);
    step!(ff, 0x49b40821u32, 22, 15);
    step!(gg, 0xf61e2562u32, 5, 1);
    step!(gg, 0xc040b340u32, 9, 6);
    step!(gg, 0x265e5a51u32, 14, 11);
    step!(gg, 0xe9b6c7aau32, 20, 0);
    step!(gg, 0xd62f105du32, 5, 5);
    step!(gg, 0x02441453u32, 9, 10);
    step!(gg, 0xd8a1e681u32, 14, 15);
    step!(gg, 0xe7d3fbc8u32, 20, 4);
    step!(gg, 0x21e1cde6u32, 5, 9);
    step!(gg, 0xc33707d6u32, 9, 14);
    step!(gg, 0xf4d50d87u32, 14, 3);
    step!(gg, 0x455a14edu32, 20, 8);
    step!(gg, 0xa9e3e905u32, 5, 13);
    step!(gg, 0xfcefa3f8u32, 9, 2);
    step!(gg, 0x676f02d9u32, 14, 7);
    step!(gg, 0x8d2a4c8au32, 20, 12);
    step!(hh, 0xfffa3942u32, 4, 5);
    step!(hh, 0x8771f681u32, 11, 8);
    step!(hh, 0x6d9d6122u32, 16, 11);
    step!(hh, 0xfde5380cu32, 23, 14);
    step!(hh, 0xa4beea44u32, 4, 1);
    step!(hh, 0x4bdecfa9u32, 11, 4);
    step!(hh, 0xf6bb4b60u32, 16, 7);
    step!(hh, 0xbebfbc70u32, 23, 10);
    step!(hh, 0x289b7ec6u32, 4, 13);
    step!(hh, 0xeaa127fau32, 11, 0);
    step!(hh, 0xd4ef3085u32, 16, 3);
    step!(hh, 0x04881d05u32, 23, 6);
    step!(hh, 0xd9d4d039u32, 4, 9);
    step!(hh, 0xe6db99e5u32, 11, 12);
    step!(hh, 0x1fa27cf8u32, 16, 15);
    step!(hh, 0xc4ac5665u32, 23, 2);
    step!(ii, 0xf4292244u32, 6, 0);
    step!(ii, 0x432aff97u32, 10, 7);
    step!(ii, 0xab9423a7u32, 15, 14);
    step!(ii, 0xfc93a039u32, 21, 5);
    step!(ii, 0x655b59c3u32, 6, 12);
    step!(ii, 0x8f0ccc92u32, 10, 3);
    step!(ii, 0xffeff47du32, 15, 10);
    step!(ii, 0x85845dd1u32, 21, 1);
    step!(ii, 0x6fa87e4fu32, 6, 8);
    step!(ii, 0xfe2ce6e0u32, 10, 15);
    step!(ii, 0xa3014314u32, 15, 6);
    step!(ii, 0x4e0811a1u32, 21, 13);
    step!(ii, 0xf7537e82u32, 6, 4);
    step!(ii, 0xbd3af235u32, 10, 11);
    step!(ii, 0x2ad7d2bbu32, 15, 2);
    step!(ii, 0xeb86d391u32, 21, 9);
    st[0] = vaddq_u32(st[0], a);
    st[1] = vaddq_u32(st[1], b);
    st[2] = vaddq_u32(st[2], c);
    st[3] = vaddq_u32(st[3], d);
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn md5_many_avx2(msgs: &[&[u8]]) -> Vec<[u8; 16]> {
    use std::arch::x86_64::*;
    let mut out = vec![[0u8; 16]; msgs.len()];
    let mut lanes: [Lane; 8] = std::array::from_fn(|_| Lane::idle());
    let mut next = 0usize;
    let mut active = 0usize;
    for lane in lanes.iter_mut() {
        if next < msgs.len() {
            lane.start(next, msgs[next]);
            next += 1;
            active += 1;
        }
    }
    let zero_block = [0u8; 64];
    let mut blocks: [*const u8; 8] = [zero_block.as_ptr(); 8];
    let mut words = [_mm256_setzero_si256(); 16];
    // The chaining words live in registers across blocks; they are
    // written back to `lane_state` only when a lane finishes a message
    // (to read its digest and seed the next one), then reloaded.
    let mut lane_state: [[u32; 8]; 4] = [[0; 8]; 4];
    for (w, row) in lane_state.iter_mut().enumerate() {
        *row = [INIT[w]; 8];
    }
    let mut st = [_mm256_setzero_si256(); 4];
    let mut reload = true;
    while active > 0 {
        // Phase 1: each lane's next block, or a note that it finished.
        let mut finished = [false; 8];
        let mut any_finished = false;
        for (j, lane) in lanes.iter_mut().enumerate() {
            if lane.msg == Lane::IDLE {
                blocks[j] = zero_block.as_ptr();
                continue;
            }
            match lane.next_block(msgs[lane.msg]) {
                Some(b) => blocks[j] = b.as_ptr(),
                None => {
                    finished[j] = true;
                    any_finished = true;
                }
            }
        }
        // Phase 2: finished lanes hand out their digest and take the next
        // message; this is the one place the registers meet the arrays.
        if any_finished {
            if !reload {
                // SAFETY: plain stores of four vectors into 8-word arrays.
                unsafe {
                    for (w, sv) in st.iter().enumerate() {
                        _mm256_storeu_si256(lane_state[w].as_mut_ptr() as *mut __m256i, *sv);
                    }
                }
            }
            for (j, lane) in lanes.iter_mut().enumerate() {
                if !finished[j] {
                    continue;
                }
                for (w, row) in lane_state.iter_mut().enumerate() {
                    out[lane.msg][w * 4..w * 4 + 4].copy_from_slice(&row[j].to_le_bytes());
                    row[j] = INIT[w];
                }
                active -= 1;
                if next < msgs.len() {
                    lane.start(next, msgs[next]);
                    next += 1;
                    active += 1;
                    blocks[j] = lane
                        .next_block(msgs[next - 1])
                        .expect("a fresh message always has a first block")
                        .as_ptr();
                } else {
                    lane.msg = Lane::IDLE;
                    blocks[j] = zero_block.as_ptr();
                }
            }
            reload = true;
        }
        if active == 0 {
            break;
        }
        // SAFETY: every `blocks[j]` points at 64 readable bytes (a whole
        // message block, a lane's padded tail, or the zero block); avx2
        // is on per #[target_feature], verified by the caller.
        unsafe {
            if reload {
                for (w, sv) in st.iter_mut().enumerate() {
                    *sv = _mm256_loadu_si256(lane_state[w].as_ptr() as *const __m256i);
                }
                reload = false;
            }
            // Transpose: word i of lane j -> words[i] lane j. Two 8x8
            // u32 transposes (words 0-7 and 8-15).
            for half in 0..2 {
                let mut r: [__m256i; 8] = [_mm256_setzero_si256(); 8];
                for (j, r_j) in r.iter_mut().enumerate() {
                    *r_j = _mm256_loadu_si256(blocks[j].add(half * 32) as *const __m256i);
                }
                let t0 = _mm256_unpacklo_epi32(r[0], r[1]);
                let t1 = _mm256_unpackhi_epi32(r[0], r[1]);
                let t2 = _mm256_unpacklo_epi32(r[2], r[3]);
                let t3 = _mm256_unpackhi_epi32(r[2], r[3]);
                let t4 = _mm256_unpacklo_epi32(r[4], r[5]);
                let t5 = _mm256_unpackhi_epi32(r[4], r[5]);
                let t6 = _mm256_unpacklo_epi32(r[6], r[7]);
                let t7 = _mm256_unpackhi_epi32(r[6], r[7]);
                let u0 = _mm256_unpacklo_epi64(t0, t2);
                let u1 = _mm256_unpackhi_epi64(t0, t2);
                let u2 = _mm256_unpacklo_epi64(t1, t3);
                let u3 = _mm256_unpackhi_epi64(t1, t3);
                let u4 = _mm256_unpacklo_epi64(t4, t6);
                let u5 = _mm256_unpackhi_epi64(t4, t6);
                let u6 = _mm256_unpacklo_epi64(t5, t7);
                let u7 = _mm256_unpackhi_epi64(t5, t7);
                let base = half * 8;
                words[base] = _mm256_permute2x128_si256(u0, u4, 0x20);
                words[base + 1] = _mm256_permute2x128_si256(u1, u5, 0x20);
                words[base + 2] = _mm256_permute2x128_si256(u2, u6, 0x20);
                words[base + 3] = _mm256_permute2x128_si256(u3, u7, 0x20);
                words[base + 4] = _mm256_permute2x128_si256(u0, u4, 0x31);
                words[base + 5] = _mm256_permute2x128_si256(u1, u5, 0x31);
                words[base + 6] = _mm256_permute2x128_si256(u2, u6, 0x31);
                words[base + 7] = _mm256_permute2x128_si256(u3, u7, 0x31);
            }
            compress8(&mut st, &words);
        }
    }
    out
}

/// The MD5 block function on eight lanes: `words[i]` holds message
/// word `i` of every lane, `st` the four chaining words per lane.
/// Fully unrolled (generated), so every shift is an immediate and every
/// round function is chosen at compile time.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn compress8(
    st: &mut [std::arch::x86_64::__m256i; 4],
    words: &[std::arch::x86_64::__m256i; 16],
) {
    use std::arch::x86_64::*;
    let (mut a, mut b, mut c, mut d) = (st[0], st[1], st[2], st[3]);
    macro_rules! ff {
        ($b:expr, $c:expr, $d:expr) => {
            _mm256_xor_si256($d, _mm256_and_si256($b, _mm256_xor_si256($c, $d)))
        };
    }
    macro_rules! gg {
        ($b:expr, $c:expr, $d:expr) => {
            _mm256_xor_si256($c, _mm256_and_si256($d, _mm256_xor_si256($b, $c)))
        };
    }
    macro_rules! hh {
        ($b:expr, $c:expr, $d:expr) => {
            _mm256_xor_si256(_mm256_xor_si256($b, $c), $d)
        };
    }
    macro_rules! ii {
        ($b:expr, $c:expr, $d:expr) => {
            _mm256_xor_si256(
                $c,
                _mm256_or_si256($b, _mm256_xor_si256($d, _mm256_set1_epi32(-1))),
            )
        };
    }
    macro_rules! step {
        ($f:ident, $k:expr, $s:literal, $g:expr) => {
            let sum = _mm256_add_epi32(
                _mm256_add_epi32(a, $f!(b, c, d)),
                _mm256_add_epi32(_mm256_set1_epi32($k as i32), words[$g]),
            );
            let rot = _mm256_or_si256(
                _mm256_slli_epi32::<$s>(sum),
                _mm256_srli_epi32::<{ 32 - $s }>(sum),
            );
            let nb = _mm256_add_epi32(b, rot);
            a = d;
            d = c;
            c = b;
            b = nb;
        };
    }
    step!(ff, 0xd76aa478u32, 7, 0);
    step!(ff, 0xe8c7b756u32, 12, 1);
    step!(ff, 0x242070dbu32, 17, 2);
    step!(ff, 0xc1bdceeeu32, 22, 3);
    step!(ff, 0xf57c0fafu32, 7, 4);
    step!(ff, 0x4787c62au32, 12, 5);
    step!(ff, 0xa8304613u32, 17, 6);
    step!(ff, 0xfd469501u32, 22, 7);
    step!(ff, 0x698098d8u32, 7, 8);
    step!(ff, 0x8b44f7afu32, 12, 9);
    step!(ff, 0xffff5bb1u32, 17, 10);
    step!(ff, 0x895cd7beu32, 22, 11);
    step!(ff, 0x6b901122u32, 7, 12);
    step!(ff, 0xfd987193u32, 12, 13);
    step!(ff, 0xa679438eu32, 17, 14);
    step!(ff, 0x49b40821u32, 22, 15);
    step!(gg, 0xf61e2562u32, 5, 1);
    step!(gg, 0xc040b340u32, 9, 6);
    step!(gg, 0x265e5a51u32, 14, 11);
    step!(gg, 0xe9b6c7aau32, 20, 0);
    step!(gg, 0xd62f105du32, 5, 5);
    step!(gg, 0x02441453u32, 9, 10);
    step!(gg, 0xd8a1e681u32, 14, 15);
    step!(gg, 0xe7d3fbc8u32, 20, 4);
    step!(gg, 0x21e1cde6u32, 5, 9);
    step!(gg, 0xc33707d6u32, 9, 14);
    step!(gg, 0xf4d50d87u32, 14, 3);
    step!(gg, 0x455a14edu32, 20, 8);
    step!(gg, 0xa9e3e905u32, 5, 13);
    step!(gg, 0xfcefa3f8u32, 9, 2);
    step!(gg, 0x676f02d9u32, 14, 7);
    step!(gg, 0x8d2a4c8au32, 20, 12);
    step!(hh, 0xfffa3942u32, 4, 5);
    step!(hh, 0x8771f681u32, 11, 8);
    step!(hh, 0x6d9d6122u32, 16, 11);
    step!(hh, 0xfde5380cu32, 23, 14);
    step!(hh, 0xa4beea44u32, 4, 1);
    step!(hh, 0x4bdecfa9u32, 11, 4);
    step!(hh, 0xf6bb4b60u32, 16, 7);
    step!(hh, 0xbebfbc70u32, 23, 10);
    step!(hh, 0x289b7ec6u32, 4, 13);
    step!(hh, 0xeaa127fau32, 11, 0);
    step!(hh, 0xd4ef3085u32, 16, 3);
    step!(hh, 0x04881d05u32, 23, 6);
    step!(hh, 0xd9d4d039u32, 4, 9);
    step!(hh, 0xe6db99e5u32, 11, 12);
    step!(hh, 0x1fa27cf8u32, 16, 15);
    step!(hh, 0xc4ac5665u32, 23, 2);
    step!(ii, 0xf4292244u32, 6, 0);
    step!(ii, 0x432aff97u32, 10, 7);
    step!(ii, 0xab9423a7u32, 15, 14);
    step!(ii, 0xfc93a039u32, 21, 5);
    step!(ii, 0x655b59c3u32, 6, 12);
    step!(ii, 0x8f0ccc92u32, 10, 3);
    step!(ii, 0xffeff47du32, 15, 10);
    step!(ii, 0x85845dd1u32, 21, 1);
    step!(ii, 0x6fa87e4fu32, 6, 8);
    step!(ii, 0xfe2ce6e0u32, 10, 15);
    step!(ii, 0xa3014314u32, 15, 6);
    step!(ii, 0x4e0811a1u32, 21, 13);
    step!(ii, 0xf7537e82u32, 6, 4);
    step!(ii, 0xbd3af235u32, 10, 11);
    step!(ii, 0x2ad7d2bbu32, 15, 2);
    step!(ii, 0xeb86d391u32, 21, 9);
    st[0] = _mm256_add_epi32(st[0], a);
    st[1] = _mm256_add_epi32(st[1], b);
    st[2] = _mm256_add_epi32(st[2], c);
    st[3] = _mm256_add_epi32(st[3], d);
}

/// Eight STREAMING MD5 chains in lockstep: the fused create pass feeds
/// each lane one member's blocks in order, all lanes a block per step,
/// and finalises a lane when its member ends (then seeds the next one).
/// The block function is [`compress8`]; a lane fed fewer bytes than the
/// others in a step is snapshotted around the compress and restored, so
/// its chain is untouched. Off AVX2 the lanes are eight scalar hashers.
///
/// Contract: every feed to a lane is a multiple of 64 bytes except the
/// LAST feed of its message (the tail block, which `finalize` pads); the
/// creator only takes this path when the slice size is a multiple of 64.
pub struct Md5Lanes {
    #[cfg(target_arch = "x86_64")]
    vec: Option<LanesVec>,
    scalar: Option<Vec<Md5>>,
}

#[cfg(target_arch = "x86_64")]
struct LanesVec {
    /// Chaining words, word-major: `state[w][lane]`.
    state: [[u32; 8]; 4],
    /// The final partial block of each lane (under 64 bytes) and its
    /// length, held until `finalize` pads it.
    pending: [[u8; 64]; 8],
    pending_len: [usize; 8],
    /// Bytes absorbed per lane, for the padding's length field.
    total: [u64; 8],
}

impl Default for Md5Lanes {
    fn default() -> Self {
        Self::new()
    }
}

impl Md5Lanes {
    pub fn new() -> Md5Lanes {
        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx2") {
                return Md5Lanes {
                    vec: Some(LanesVec {
                        state: [[INIT[0]; 8], [INIT[1]; 8], [INIT[2]; 8], [INIT[3]; 8]],
                        pending: [[0; 64]; 8],
                        pending_len: [0; 8],
                        total: [0; 8],
                    }),
                    scalar: None,
                };
            }
        }
        Md5Lanes {
            #[cfg(target_arch = "x86_64")]
            vec: None,
            scalar: Some((0..8).map(|_| Md5::new()).collect()),
        }
    }

    /// Feed every lane at once. `chunks[j]` is lane j's next bytes (empty
    /// for an idle lane); whole 64-byte blocks are absorbed in lockstep
    /// and a lane's trailing partial block is held for `finalize`.
    pub fn update(&mut self, chunks: [&[u8]; 8]) {
        if let Some(h) = self.scalar.as_mut() {
            for (lane, c) in h.iter_mut().zip(chunks) {
                lane.update(c);
            }
        }
        #[cfg(target_arch = "x86_64")]
        if let Some(v) = self.vec.as_mut() {
            // SAFETY: the vector lanes exist only when avx2 was detected
            // at construction.
            unsafe { v.update_avx2(chunks) };
        }
    }

    /// Finish lane `lane`'s message, returning its digest and resetting the
    /// lane for the next message.
    pub fn finalize(&mut self, lane: usize) -> [u8; 16] {
        if let Some(h) = self.scalar.as_mut() {
            let d: [u8; 16] = std::mem::replace(&mut h[lane], Md5::new())
                .finalize()
                .into();
            return d;
        }
        #[cfg(target_arch = "x86_64")]
        if let Some(v) = self.vec.as_mut() {
            // SAFETY: as in `update`.
            return unsafe { v.finalize_avx2(lane) };
        }
        unreachable!("a lane set is vector or scalar")
    }
}

#[cfg(target_arch = "x86_64")]
impl LanesVec {
    #[target_feature(enable = "avx2")]
    unsafe fn update_avx2(&mut self, chunks: [&[u8]; 8]) {
        use std::arch::x86_64::*;
        // Top up a pending partial block first: a lane may be fed its tail
        // in pieces smaller than 64 by a caller that split a block.
        let mut cursors: [&[u8]; 8] = chunks;
        for j in 0..8 {
            if self.pending_len[j] > 0 && !cursors[j].is_empty() {
                let take = (64 - self.pending_len[j]).min(cursors[j].len());
                self.pending[j][self.pending_len[j]..self.pending_len[j] + take]
                    .copy_from_slice(&cursors[j][..take]);
                self.pending_len[j] += take;
                cursors[j] = &cursors[j][take..];
            }
        }
        let steps = (0..8)
            .map(|j| cursors[j].len() / 64 + usize::from(self.pending_len[j] == 64))
            .max()
            .unwrap_or(0);
        let zero = [0u8; 64];
        let mut st = [_mm256_setzero_si256(); 4];
        // SAFETY: loads/stores of the four 8-word state rows; every block
        // pointer is 64 readable bytes (a whole block of a chunk, a full
        // pending buffer, or the zero block); avx2 on per
        // #[target_feature].
        unsafe {
            for (w, sv) in st.iter_mut().enumerate() {
                *sv = _mm256_loadu_si256(self.state[w].as_ptr() as *const __m256i);
            }
            let mut words = [_mm256_setzero_si256(); 16];
            for _ in 0..steps {
                let mut blocks: [*const u8; 8] = [zero.as_ptr(); 8];
                let mut idle = [false; 8];
                for j in 0..8 {
                    if self.pending_len[j] == 64 {
                        blocks[j] = self.pending[j].as_ptr();
                        self.pending_len[j] = 0;
                        self.total[j] += 64;
                    } else if cursors[j].len() >= 64 {
                        blocks[j] = cursors[j].as_ptr();
                        cursors[j] = &cursors[j][64..];
                        self.total[j] += 64;
                    } else {
                        idle[j] = true;
                    }
                }
                // Idle lanes: remember their words and put them back.
                let mut saved = [[0u32; 8]; 4];
                let any_idle = idle.iter().any(|&b| b);
                if any_idle {
                    for (w, sv) in st.iter().enumerate() {
                        _mm256_storeu_si256(saved[w].as_mut_ptr() as *mut __m256i, *sv);
                    }
                }
                transpose_blocks(&blocks, &mut words);
                compress8(&mut st, &words);
                if any_idle {
                    let mut now = [[0u32; 8]; 4];
                    for (w, sv) in st.iter().enumerate() {
                        _mm256_storeu_si256(now[w].as_mut_ptr() as *mut __m256i, *sv);
                    }
                    for j in 0..8 {
                        if idle[j] {
                            for w in 0..4 {
                                now[w][j] = saved[w][j];
                            }
                        }
                    }
                    for (w, sv) in st.iter_mut().enumerate() {
                        *sv = _mm256_loadu_si256(now[w].as_ptr() as *const __m256i);
                    }
                }
            }
            for (w, sv) in st.iter().enumerate() {
                _mm256_storeu_si256(self.state[w].as_mut_ptr() as *mut __m256i, *sv);
            }
        }
        // Whatever is left of each chunk is under 64 bytes: hold it.
        for j in 0..8 {
            let rest = cursors[j];
            if !rest.is_empty() {
                debug_assert!(self.pending_len[j] + rest.len() < 64);
                self.pending[j][self.pending_len[j]..self.pending_len[j] + rest.len()]
                    .copy_from_slice(rest);
                self.pending_len[j] += rest.len();
            }
        }
    }

    #[target_feature(enable = "avx2")]
    unsafe fn finalize_avx2(&mut self, lane: usize) -> [u8; 16] {
        use std::arch::x86_64::*;
        let n = self.pending_len[lane];
        let total = self.total[lane] + n as u64;
        let mut tail = [0u8; 128];
        tail[..n].copy_from_slice(&self.pending[lane][..n]);
        tail[n] = 0x80;
        let blocks = if n + 1 + 8 <= 64 { 1 } else { 2 };
        tail[blocks * 64 - 8..blocks * 64].copy_from_slice(&total.wrapping_mul(8).to_le_bytes());
        // Run the padded block(s) through this lane only: the other lanes'
        // words are restored afterwards.
        let saved = self.state;
        let zero = [0u8; 64];
        let mut st = [_mm256_setzero_si256(); 4];
        // SAFETY: as in update_avx2.
        unsafe {
            for (w, sv) in st.iter_mut().enumerate() {
                *sv = _mm256_loadu_si256(self.state[w].as_ptr() as *const __m256i);
            }
            let mut words = [_mm256_setzero_si256(); 16];
            for b in 0..blocks {
                let mut ptrs: [*const u8; 8] = [zero.as_ptr(); 8];
                ptrs[lane] = tail[b * 64..].as_ptr();
                transpose_blocks(&ptrs, &mut words);
                compress8(&mut st, &words);
            }
            for (w, sv) in st.iter().enumerate() {
                _mm256_storeu_si256(self.state[w].as_mut_ptr() as *mut __m256i, *sv);
            }
        }
        let mut out = [0u8; 16];
        for w in 0..4 {
            out[w * 4..w * 4 + 4].copy_from_slice(&self.state[w][lane].to_le_bytes());
        }
        for w in 0..4 {
            for j in 0..8 {
                self.state[w][j] = if j == lane { INIT[w] } else { saved[w][j] };
            }
        }
        self.pending_len[lane] = 0;
        self.total[lane] = 0;
        out
    }
}

/// Word i of lane j's 64-byte block -> `words[i]` lane j: two 8x8 u32
/// transposes.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn transpose_blocks(blocks: &[*const u8; 8], words: &mut [std::arch::x86_64::__m256i; 16]) {
    use std::arch::x86_64::*;
    // SAFETY: every block pointer is 64 readable bytes (the callers'
    // contract); avx2 on per #[target_feature].
    unsafe {
        for half in 0..2 {
            let mut r: [__m256i; 8] = [_mm256_setzero_si256(); 8];
            for (j, r_j) in r.iter_mut().enumerate() {
                *r_j = _mm256_loadu_si256(blocks[j].add(half * 32) as *const __m256i);
            }
            let t0 = _mm256_unpacklo_epi32(r[0], r[1]);
            let t1 = _mm256_unpackhi_epi32(r[0], r[1]);
            let t2 = _mm256_unpacklo_epi32(r[2], r[3]);
            let t3 = _mm256_unpackhi_epi32(r[2], r[3]);
            let t4 = _mm256_unpacklo_epi32(r[4], r[5]);
            let t5 = _mm256_unpackhi_epi32(r[4], r[5]);
            let t6 = _mm256_unpacklo_epi32(r[6], r[7]);
            let t7 = _mm256_unpackhi_epi32(r[6], r[7]);
            let u0 = _mm256_unpacklo_epi64(t0, t2);
            let u1 = _mm256_unpackhi_epi64(t0, t2);
            let u2 = _mm256_unpacklo_epi64(t1, t3);
            let u3 = _mm256_unpackhi_epi64(t1, t3);
            let u4 = _mm256_unpacklo_epi64(t4, t6);
            let u5 = _mm256_unpackhi_epi64(t4, t6);
            let u6 = _mm256_unpacklo_epi64(t5, t7);
            let u7 = _mm256_unpackhi_epi64(t5, t7);
            let base = half * 8;
            words[base] = _mm256_permute2x128_si256(u0, u4, 0x20);
            words[base + 1] = _mm256_permute2x128_si256(u1, u5, 0x20);
            words[base + 2] = _mm256_permute2x128_si256(u2, u6, 0x20);
            words[base + 3] = _mm256_permute2x128_si256(u3, u7, 0x20);
            words[base + 4] = _mm256_permute2x128_si256(u0, u4, 0x31);
            words[base + 5] = _mm256_permute2x128_si256(u1, u5, 0x31);
            words[base + 6] = _mm256_permute2x128_si256(u2, u6, 0x31);
            words[base + 7] = _mm256_permute2x128_si256(u3, u7, 0x31);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rng(seed: &mut u64) -> u64 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    }

    /// Every length class the padding has (0, <56, 56..64, exactly 64,
    /// multi-block, off-by-one around block edges), mixed together so
    /// lanes finish at different steps and refill, against the scalar
    /// hasher.
    #[test]
    fn md5_many_matches_scalar_for_mixed_lengths() {
        let mut seed = 0x1234_5678_9abc_def1u64;
        let lens = [
            0usize,
            1,
            3,
            55,
            56,
            57,
            63,
            64,
            65,
            119,
            120,
            127,
            128,
            129,
            200,
            1000,
            4096,
            65536,
            65536,
            65537,
            1 << 20,
            7,
            64 * 3,
            64 * 3 + 56,
        ];
        let msgs: Vec<Vec<u8>> = lens
            .iter()
            .map(|&n| (0..n).map(|_| rng(&mut seed) as u8).collect())
            .collect();
        let refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
        let got = md5_many(&refs);
        for (m, d) in refs.iter().zip(&got) {
            let want: [u8; 16] = Md5::digest(m).into();
            assert_eq!(*d, want, "length {}", m.len());
        }
    }

    /// Research rig, asserts nothing: throughput of the 8-lane path
    /// against the scalar chain over 64 messages of 1 MiB, best of five.
    ///
    ///     cargo test --release -p nzbkit-base --features test-support --lib \
    ///       md5fast::multi::tests::md5_many_throughput -- --ignored --nocapture
    #[test]
    #[ignore = "research rig: prints timings, asserts nothing"]
    fn md5_many_throughput() {
        let mut seed = 99u64;
        let msgs: Vec<Vec<u8>> = (0..64)
            .map(|_| (0..(1 << 20)).map(|_| rng(&mut seed) as u8).collect())
            .collect();
        let refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
        let bytes = (refs.len() << 20) as f64;
        let mut best_multi = f64::MAX;
        let mut best_scalar = f64::MAX;
        for _ in 0..5 {
            let t = std::time::Instant::now();
            std::hint::black_box(md5_many(&refs));
            best_multi = best_multi.min(t.elapsed().as_secs_f64());
            let t = std::time::Instant::now();
            for m in &refs {
                std::hint::black_box(<[u8; 16]>::from(Md5::digest(m)));
            }
            best_scalar = best_scalar.min(t.elapsed().as_secs_f64());
        }
        println!(
            "md5_many (vector path {}): {:.1} MB/s per thread; scalar chain: {:.1} MB/s",
            multi_available(),
            bytes / best_multi / 1e6,
            bytes / best_scalar / 1e6
        );
    }

    /// Streaming lanes: eight members of unequal lengths fed a block per
    /// step in lockstep (tails short, lanes idling and refilling), against
    /// the scalar hasher per member.
    #[test]
    fn md5_lanes_stream_matches_scalar() {
        let mut seed = 0xC0FFEEu64;
        let bs = 4096usize;
        let lens = [
            10 * bs,
            3 * bs + 100,
            7 * bs,
            bs,
            12 * bs + 63,
            2 * bs + 4095,
            5 * bs,
            9 * bs + 1,
            4 * bs,
            6 * bs + 2000,
            64,
            0,
        ];
        let msgs: Vec<Vec<u8>> = lens
            .iter()
            .map(|&n| (0..n).map(|_| rng(&mut seed) as u8).collect())
            .collect();
        let mut lanes = Md5Lanes::new();
        let mut got: Vec<Option<[u8; 16]>> = vec![None; msgs.len()];
        let mut lane_msg: [Option<usize>; 8] = [None; 8];
        let mut lane_pos = [0usize; 8];
        let mut next = 0usize;
        for j in 0..8 {
            if next < msgs.len() {
                lane_msg[j] = Some(next);
                next += 1;
            }
        }
        loop {
            let mut chunks: [&[u8]; 8] = [&[]; 8];
            let mut any = false;
            for j in 0..8 {
                if let Some(m) = lane_msg[j] {
                    let data = &msgs[m];
                    let take = (data.len() - lane_pos[j]).min(bs);
                    chunks[j] = &data[lane_pos[j]..lane_pos[j] + take];
                    any = true;
                }
            }
            if !any {
                break;
            }
            lanes.update(chunks);
            for j in 0..8 {
                if let Some(m) = lane_msg[j] {
                    lane_pos[j] += chunks[j].len();
                    if lane_pos[j] >= msgs[m].len() {
                        got[m] = Some(lanes.finalize(j));
                        lane_pos[j] = 0;
                        lane_msg[j] = if next < msgs.len() {
                            next += 1;
                            Some(next - 1)
                        } else {
                            None
                        };
                    }
                }
            }
        }
        for (m, d) in msgs.iter().zip(&got) {
            assert_eq!(
                d.unwrap(),
                <[u8; 16]>::from(Md5::digest(m)),
                "len {}",
                m.len()
            );
        }
    }

    /// The four-lane NEON kernel, called directly (the dispatcher's
    /// admission is a separate question): every padding class, mixed so
    /// lanes finish at different steps and refill, and lane counts on
    /// both sides of four, against the scalar hasher.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn md5_many_neon_matches_scalar() {
        if !std::arch::is_aarch64_feature_detected!("neon") {
            return;
        }
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let lens = [
            0usize,
            1,
            3,
            55,
            56,
            57,
            63,
            64,
            65,
            119,
            120,
            127,
            128,
            129,
            200,
            1000,
            4096,
            65536,
            65537,
            1 << 20,
            7,
            64 * 3,
            64 * 3 + 56,
        ];
        let msgs: Vec<Vec<u8>> = lens
            .iter()
            .map(|&n| (0..n).map(|_| rng(&mut seed) as u8).collect())
            .collect();
        let refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
        for n in [1usize, 2, 3, 4, 5, 8, 9, 16, 17, refs.len()] {
            // SAFETY: NEON checked above; every message is a valid slice.
            let got = unsafe { md5_many_neon(&refs[..n]) };
            assert_eq!(got.len(), n);
            for (m, d) in refs[..n].iter().zip(&got) {
                let want: [u8; 16] = Md5::digest(m).into();
                assert_eq!(*d, want, "n={n} length {}", m.len());
            }
        }
    }

    #[test]
    fn md5_many_handles_fewer_than_eight_and_exactly_eight() {
        let mut seed = 7u64;
        for n in [1usize, 2, 7, 8, 9, 16, 17] {
            let msgs: Vec<Vec<u8>> = (0..n)
                .map(|i| (0..(i * 37 + 1)).map(|_| rng(&mut seed) as u8).collect())
                .collect();
            let refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
            let got = md5_many(&refs);
            for (m, d) in refs.iter().zip(&got) {
                assert_eq!(
                    *d,
                    <[u8; 16]>::from(Md5::digest(m)),
                    "n={n} len {}",
                    m.len()
                );
            }
        }
    }
}
