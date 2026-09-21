//! A carry-less folded CRC-32 for aarch64: the kernel behind
//! [`super::Crc32::update`] where the CPU has PMULL, the CRC32 instructions
//! and EOR3.
//!
//! crc32fast takes the ARM CRC32 instruction, eight bytes per `crc32d`, and
//! that is latency-bound: every instruction waits for the previous one's
//! result. 1.5.0 runs one chain (about 10 GB/s on an M3 Ultra) and 1.5.1
//! three interleaved chains past 1.5 KiB (about 29). Folding instead keeps
//! `LANES` independent 128-bit accumulators over the stream and moves each
//! one `16 * LANES` bytes forward per pass with two carry-less multiplies by
//! a constant and one three-way XOR, so nothing waits on anything but the
//! load. Eight lanes measured 68 GB/s on 1 MiB buffers on the same box (four
//! lanes 43, sixteen 74); the table is in the rarfast bench note, section
//! 12.7. What is left over when the loop ends is a message of `16 * LANES`
//! bytes whose CRC from a zero register equals the running one, so the
//! CRC32 instructions finish it and the tail.
//!
//! The method is the fold of Gopal et al., "Fast CRC computation for generic
//! polynomials using PCLMULQDQ instruction" (Intel, 2009), in the bit
//! reflected form: for a fold of `D` bits a lane's low half is multiplied by
//! `reflect(x^(D+32) mod P) << 1` and its high half by
//! `reflect(x^(D-32) mod P) << 1`. The code is written here for NEON; the
//! constants are the ones crc32fast's x86 fold uses (crc32fast is MIT OR
//! Apache-2.0, this crate's own licence), and a test re-derives every one of
//! them from the polynomial. Nothing is taken from rapidyenc or zlib-ng.
//!
//! Only with EOR3 (the SHA3 extension) as well: that is every Apple core and
//! the ARMv8.2+ server cores, where the multiply is cheap. On an older
//! Cortex-A core with PMULL but no SHA3 the CRC32 instructions were the
//! faster choice (Linux dropped its arm64 PMULL CRC-32 for that reason), so
//! such a CPU, and every other architecture, keeps crc32fast.
//!
//! This module is the crate's THIRD home of `unsafe`, on the argument
//! `Cargo.toml` gives for the other two: the intrinsics are unsafe to call
//! only because the target features must be present, which the runtime
//! detect checks, and every load stays inside the slice the safe wrapper
//! hands in. `unsafe_is_confined_to_the_neon_entry` pins the count at three
//! files. (nzbfast-local addition, 16 Sep 2026; see VENDORING.md.)
#![allow(unsafe_code)]

/// Below this many bytes a plain `crc32d` chain; the fold's setup and its
/// closing pass over the lanes cost more than they save.
#[cfg(target_arch = "aarch64")]
const FOLD4_MIN_BYTES: usize = 256;

/// From here eight lanes; between the two, four.
#[cfg(target_arch = "aarch64")]
const FOLD8_MIN_BYTES: usize = 1024;

/// `[reflect(x^(D+32) mod P) << 1, reflect(x^(D-32) mod P) << 1]` for a fold
/// of `D` = 512 and 1024 bits.
#[cfg(any(target_arch = "aarch64", test))]
const K_512: [u64; 2] = [0x1_5444_2bd4, 0x1_c6e4_1596];
#[cfg(any(target_arch = "aarch64", test))]
const K_1024: [u64; 2] = [0x1_e88e_f372, 0x1_4a7f_e880];

/// The raw (pre-inverted) register after `input`, or `None` where this CPU
/// has no kernel here and the caller should use crc32fast.
#[inline]
pub(super) fn update(register: u32, input: &[u8]) -> Option<u32> {
    #[cfg(target_arch = "aarch64")]
    if supported() {
        // SAFETY: `supported` verified PMULL, CRC32 and SHA3 on this CPU.
        return Some(unsafe { update_aarch64(register, input) });
    }
    let _ = (register, input);
    None
}

#[cfg(target_arch = "aarch64")]
fn supported() -> bool {
    std::arch::is_aarch64_feature_detected!("pmull")
        && std::arch::is_aarch64_feature_detected!("crc")
        && std::arch::is_aarch64_feature_detected!("sha3")
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon,aes,crc,sha3")]
unsafe fn update_aarch64(register: u32, input: &[u8]) -> u32 {
    // SAFETY: this function's own features are the ones the kernels need.
    unsafe {
        if input.len() >= FOLD8_MIN_BYTES {
            fold::<8>(register, input, K_1024)
        } else if input.len() >= FOLD4_MIN_BYTES {
            fold::<4>(register, input, K_512)
        } else {
            chain(register, input)
        }
    }
}

/// The fold over `LANES` lanes with the constants for `16 * LANES * 8` bits.
/// Any length is correct; one shorter than a whole pass goes to [`chain`].
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon,aes,crc,sha3")]
unsafe fn fold<const LANES: usize>(register: u32, input: &[u8], keys: [u64; 2]) -> u32 {
    use std::arch::aarch64::*;
    let step = 16 * LANES;
    if input.len() < step {
        // SAFETY: the CRC32 feature is enabled on this function.
        return unsafe { chain(register, input) };
    }
    let src = input.as_ptr();
    // SAFETY: every load reads the 16 bytes at `at + 16 * lane` for a lane
    // below LANES and an `at` with `at + step <= input.len()`, so inside
    // `input`; the features are enabled on this function.
    unsafe {
        let load = |at: usize| vreinterpretq_u64_u8(vld1q_u8(src.add(at)));
        let high_key = vreinterpretq_p64_u64(vcombine_u64(vcreate_u64(keys[0]), vcreate_u64(keys[1])));
        let mut lanes = [vdupq_n_u64(0); LANES];
        for (lane, value) in lanes.iter_mut().enumerate() {
            *value = load(16 * lane);
        }
        // The register joins the stream as the XOR of its first four bytes.
        lanes[0] = veorq_u64(lanes[0], vcombine_u64(vcreate_u64(u64::from(register)), vcreate_u64(0)));
        let mut at = step;
        while input.len() - at >= step {
            for (lane, value) in lanes.iter_mut().enumerate() {
                let low = vreinterpretq_u64_p128(vmull_p64(vgetq_lane_u64(*value, 0), keys[0]));
                let high = vreinterpretq_u64_p128(vmull_high_p64(vreinterpretq_p64_u64(*value), high_key));
                *value = veor3q_u64(low, high, load(at + 16 * lane));
            }
            at += step;
        }
        // The lanes, read in order, are a message congruent to everything
        // folded so far: its CRC from a zero register is the running one.
        let mut folded = 0;
        for value in lanes {
            folded = __crc32d(folded, vgetq_lane_u64(value, 0));
            folded = __crc32d(folded, vgetq_lane_u64(value, 1));
        }
        chain(folded, &input[at..])
    }
}

/// One `crc32d` per eight bytes, then `crc32b` per byte.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "crc")]
unsafe fn chain(mut register: u32, input: &[u8]) -> u32 {
    use std::arch::aarch64::{__crc32b, __crc32d};
    let mut words = input.chunks_exact(8);
    for word in &mut words {
        let word = u64::from_le_bytes(word.try_into().expect("an eight-byte chunk"));
        register = __crc32d(register, word);
    }
    for &byte in words.remainder() {
        register = __crc32b(register, byte);
    }
    register
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(register: u32, input: &[u8]) -> u32 {
        let mut hasher = crc32fast::Hasher::new_with_initial(!register);
        hasher.update(input);
        !hasher.finalize()
    }

    fn noise(len: usize, mut state: u64) -> Vec<u8> {
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    /// `reflect(x^n mod P) << 1` for P = 0x1_04C1_1DB7, from the polynomial.
    fn fold_constant(n: u32) -> u64 {
        let mut value: u32 = 1;
        for _ in 0..n {
            let carry = value & 0x8000_0000 != 0;
            value <<= 1;
            if carry {
                value ^= 0x04C1_1DB7;
            }
        }
        u64::from(value.reverse_bits()) << 1
    }

    #[test]
    fn the_fold_constants_are_the_powers_they_claim() {
        for (keys, bits) in [(K_512, 512), (K_1024, 1024)] {
            assert_eq!(keys, [fold_constant(bits + 32), fold_constant(bits - 32)], "D = {bits}");
        }
    }

    /// Every length 0..=4097 at sixteen start alignments, whole and split in
    /// two, through the dispatcher and through each kernel directly whatever
    /// its threshold. On a CPU with no kernel the dispatcher must decline.
    #[test]
    fn every_kernel_matches_crc32fast_over_lengths_alignments_and_splits() {
        let pool = noise(4097 + 16, 7);
        #[cfg(target_arch = "aarch64")]
        let direct = supported();
        #[cfg(not(target_arch = "aarch64"))]
        let direct = false;
        if !direct {
            assert_eq!(update(0, &pool), None, "no kernel, yet the dispatcher answered");
            eprintln!("no PMULL + CRC32 + SHA3 on this CPU: crc32fast is the only path");
            return;
        }
        for len in 0..=4097usize {
            for align in 0..16usize {
                let input = &pool[align..align + len];
                let register = 0x1234_5678 ^ (len as u32).rotate_left(align as u32);
                let want = reference(register, input);
                let cut = (len * 7 + align * 131) % (len + 1);
                let (left, right) = input.split_at(cut);
                let split = update(update(register, left).unwrap(), right);
                assert_eq!(update(register, input), Some(want), "len {len} align {align}");
                assert_eq!(split, Some(want), "len {len} align {align} cut {cut}");
                #[cfg(target_arch = "aarch64")]
                // SAFETY: `supported` held above.
                unsafe {
                    assert_eq!(chain(register, input), want, "chain len {len}");
                    assert_eq!(fold::<4>(register, input, K_512), want, "fold4 len {len}");
                    assert_eq!(fold::<8>(register, input, K_1024), want, "fold8 len {len}");
                }
            }
        }
    }

    /// Several MiB fed through the public wrapper in pieces of scattered
    /// sizes, against one crc32fast pass.
    #[test]
    fn a_long_stream_in_scattered_pieces_matches_one_pass() {
        let data = noise(3 * (1 << 20) + 1, 11);
        let mut crc = super::super::Crc32::new();
        let mut state = 0x9e37_79b9_u32;
        let mut at = 0;
        while at < data.len() {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let size = match state >> 29 {
                0 => (state >> 8) as usize % 16,
                1 | 2 => (state >> 8) as usize % 1100,
                3 | 4 => (state >> 8) as usize % 70_000,
                _ => (state >> 8) as usize % (1 << 20),
            };
            let end = (at + size).min(data.len());
            crc.update(&data[at..end]);
            at = end;
        }
        assert_eq!(crc.finish(), crc32fast::hash(&data));
    }
}
