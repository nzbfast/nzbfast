//! SIMD multiply-by-constant over GF(2^16) for the recovery folds.
//!
//! `Gf16MulTable::fold_into` XORs `c * source` into a parity row two bytes
//! at a time through two 256-entry tables, about 1.8 GB/s per core. A
//! recovery record at 10% folds every archive byte into twenty rows, and
//! the streamed writer folds them on the writing thread as the bytes pass,
//! so on an 8-vCPU guest a 1 GiB `-rr10` spent 7.5 s of its 9 s in this
//! kernel where rar 7.23 takes 4.3 s for the whole archive.
//!
//! This is the nibble-shuffle form the PAR2 engine in this repository
//! uses over the SAME field (both are GF(2^16) reduced by 0x1100B): a
//! word's product is the XOR of its four nibbles' contributions, each one
//! 16-entry table shuffle (`vqtbl1q_u8` on NEON, `pshufb` on x86; four
//! `gf2p8affineqb` bit-matrix products where GFNI exists), sixteen or
//! thirty-two words per iteration. The tables are derived from the field's
//! own multiply here, and every kernel is pinned to the scalar fold by a
//! differential over odd lengths and every coefficient class.
//!
//! This module is the crate's SECOND home of `unsafe` (the first is the
//! NEON BLAKE2sp entry, whose argument in `Cargo.toml` this one shares):
//! the intrinsics are unsafe to CALL only because the target feature must
//! be present, which the runtime detects check on x86 and which is the
//! baseline on aarch64, and every pointer access stays inside the slices
//! the safe wrappers hand in. `unsafe_is_confined_to_the_neon_entry` pins
//! the count at two files. (nzbfast-local addition, 6 Sep 2026; see
//! VENDORING.md.)
#![allow(unsafe_code)]

/// The low- and high-byte nibble tables of one coefficient:
/// `nl[j][n]` / `nh[j][n]` are the low / high byte of `c * (n << 4j)`.
#[derive(Clone, Copy)]
pub(super) struct FoldTables {
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    nl: [[u8; 16]; 4],
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    nh: [[u8; 16]; 4],
    /// GFNI 8x8 bit-matrices `[ll, hl, lh, hh]`: product low / high byte
    /// from source low / high byte.
    #[cfg(target_arch = "x86_64")]
    affine: [u64; 4],
}

impl FoldTables {
    /// Tables for multiply-by-`c`, from the xtime chain over the field:
    /// `c * x^k` for `k` in 0..16, then every nibble entry as the XOR of
    /// the powers its bits select.
    pub(super) fn new(c: u16) -> Self {
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        let (nl, nh) = {
            let mut powers = [0u16; 16];
            let mut value = c;
            for slot in powers.iter_mut() {
                *slot = value;
                let carry = value & 0x8000 != 0;
                value <<= 1;
                if carry {
                    value ^= 0x100B;
                }
            }
            let mut nl = [[0u8; 16]; 4];
            let mut nh = [[0u8; 16]; 4];
            for (j, (low, high)) in nl.iter_mut().zip(nh.iter_mut()).enumerate() {
                let mut table = [0u16; 16];
                for bit in 0..4 {
                    let basis = powers[4 * j + bit];
                    for i in 0..(1usize << bit) {
                        table[i | (1 << bit)] = table[i] ^ basis;
                    }
                }
                for n in 0..16 {
                    low[n] = table[n] as u8;
                    high[n] = (table[n] >> 8) as u8;
                }
            }
            (nl, nh)
        };
        #[cfg(target_arch = "x86_64")]
        let affine = {
            let gf = super::rar5::shared_gf16();
            let low_products: [u16; 8] = std::array::from_fn(|j| gf.mul(c, 1 << j));
            let high_products: [u16; 8] = std::array::from_fn(|j| gf.mul(c, 1 << (8 + j)));
            [
                affine_matrix(&low_products, |p| p as u8),
                affine_matrix(&high_products, |p| p as u8),
                affine_matrix(&low_products, |p| (p >> 8) as u8),
                affine_matrix(&high_products, |p| (p >> 8) as u8),
            ]
        };
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        let _ = c;
        Self {
            #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
            nl,
            #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
            nh,
            #[cfg(target_arch = "x86_64")]
            affine,
        }
    }
}

/// Pack the byte-to-byte GF(2)-linear map `j -> take(products[j])` into a
/// `gf2p8affineqb` matrix operand: destination bit `i`'s row lives in
/// qword byte `7 - i`, and bit `j` of a row selects source bit `j`.
#[cfg(target_arch = "x86_64")]
fn affine_matrix(products: &[u16; 8], take: fn(u16) -> u8) -> u64 {
    let mut matrix = 0u64;
    for i in 0..8 {
        let mut row = 0u8;
        for (j, &product) in products.iter().enumerate() {
            row |= ((take(product) >> i) & 1) << j;
        }
        matrix |= (row as u64) << (8 * (7 - i));
    }
    matrix
}

/// `destination ^= c * source` over the leading whole SIMD chunks of two
/// equal-length little-endian symbol streams; returns how many BYTES were
/// folded (a multiple of 32). The caller folds the rest through the scalar
/// tables. Folds nothing where no kernel applies.
#[inline]
pub(super) fn fold_simd(tables: &FoldTables, destination: &mut [u8], source: &[u8]) -> usize {
    debug_assert_eq!(destination.len(), source.len());
    let len = destination.len().min(source.len());
    let (destination, source) = (&mut destination[..len], &source[..len]);
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: NEON is baseline on aarch64; the slices are equal in
        // length and the kernel touches only whole 32-byte chunks of them.
        unsafe { fold_neon(&tables.nl, &tables.nh, destination, source) }
    }
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("gfni") && is_x86_feature_detected!("avx2") {
            // SAFETY: the features are verified on this branch; equal-length
            // slices, whole 64-byte chunks only.
            unsafe { fold_gfni(&tables.affine, destination, source) }
        } else if is_x86_feature_detected!("avx2") {
            // SAFETY: as above, for AVX2.
            unsafe { fold_avx2(&tables.nl, &tables.nh, destination, source) }
        } else if is_x86_feature_detected!("ssse3") {
            // SAFETY: as above, for SSSE3.
            unsafe { fold_ssse3(&tables.nl, &tables.nh, destination, source) }
        } else {
            0
        }
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        let _ = (tables, destination, source);
        0
    }
}

/// NEON: sixteen words per 32-byte chunk through the nibble tables.
#[cfg(target_arch = "aarch64")]
unsafe fn fold_neon(nl: &[[u8; 16]; 4], nh: &[[u8; 16]; 4], dst: &mut [u8], src: &[u8]) -> usize {
    use std::arch::aarch64::*;
    let chunks = src.len().min(dst.len()) / 32;
    if chunks == 0 {
        return 0;
    }
    // SAFETY: NEON intrinsics have no feature precondition on aarch64;
    // every access is inside the first chunks * 32 bytes of both slices.
    unsafe {
        let (t0l, t1l, t2l, t3l) = (
            vld1q_u8(nl[0].as_ptr()),
            vld1q_u8(nl[1].as_ptr()),
            vld1q_u8(nl[2].as_ptr()),
            vld1q_u8(nl[3].as_ptr()),
        );
        let (t0h, t1h, t2h, t3h) = (
            vld1q_u8(nh[0].as_ptr()),
            vld1q_u8(nh[1].as_ptr()),
            vld1q_u8(nh[2].as_ptr()),
            vld1q_u8(nh[3].as_ptr()),
        );
        let mask = vdupq_n_u8(0x0f);
        for c in 0..chunks {
            let s = vld2q_u8(src.as_ptr().add(c * 32));
            let n0 = vandq_u8(s.0, mask);
            let n1 = vshrq_n_u8::<4>(s.0);
            let n2 = vandq_u8(s.1, mask);
            let n3 = vshrq_n_u8::<4>(s.1);
            let plo = veorq_u8(
                veorq_u8(vqtbl1q_u8(t0l, n0), vqtbl1q_u8(t1l, n1)),
                veorq_u8(vqtbl1q_u8(t2l, n2), vqtbl1q_u8(t3l, n3)),
            );
            let phi = veorq_u8(
                veorq_u8(vqtbl1q_u8(t0h, n0), vqtbl1q_u8(t1h, n1)),
                veorq_u8(vqtbl1q_u8(t2h, n2), vqtbl1q_u8(t3h, n3)),
            );
            let dp = dst.as_mut_ptr().add(c * 32);
            let d = vld2q_u8(dp);
            vst2q_u8(dp, uint8x16x2_t(veorq_u8(d.0, plo), veorq_u8(d.1, phi)));
        }
    }
    chunks * 32
}

/// SSSE3: the `pshufb` twin of the NEON path, sixteen words per 32-byte
/// chunk; low and high bytes split with mask and `packus`, the products
/// re-interleaved with `unpack` before the XOR into the destination.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "ssse3")]
unsafe fn fold_ssse3(nl: &[[u8; 16]; 4], nh: &[[u8; 16]; 4], dst: &mut [u8], src: &[u8]) -> usize {
    use std::arch::x86_64::*;
    let chunks = src.len().min(dst.len()) / 32;
    if chunks == 0 {
        return 0;
    }
    // SAFETY: SSSE3 is enabled per the target feature and verified by the
    // caller; every access is inside the first chunks * 32 bytes.
    unsafe {
        let (t0l, t1l, t2l, t3l) = (
            _mm_loadu_si128(nl[0].as_ptr() as *const __m128i),
            _mm_loadu_si128(nl[1].as_ptr() as *const __m128i),
            _mm_loadu_si128(nl[2].as_ptr() as *const __m128i),
            _mm_loadu_si128(nl[3].as_ptr() as *const __m128i),
        );
        let (t0h, t1h, t2h, t3h) = (
            _mm_loadu_si128(nh[0].as_ptr() as *const __m128i),
            _mm_loadu_si128(nh[1].as_ptr() as *const __m128i),
            _mm_loadu_si128(nh[2].as_ptr() as *const __m128i),
            _mm_loadu_si128(nh[3].as_ptr() as *const __m128i),
        );
        let nib = _mm_set1_epi8(0x0f);
        let lo8 = _mm_set1_epi16(0x00ff);
        for c in 0..chunks {
            let sp = src.as_ptr().add(c * 32) as *const __m128i;
            let v0 = _mm_loadu_si128(sp);
            let v1 = _mm_loadu_si128(sp.add(1));
            let slo = _mm_packus_epi16(_mm_and_si128(v0, lo8), _mm_and_si128(v1, lo8));
            let shi = _mm_packus_epi16(_mm_srli_epi16(v0, 8), _mm_srli_epi16(v1, 8));
            let n0 = _mm_and_si128(slo, nib);
            let n1 = _mm_and_si128(_mm_srli_epi16(slo, 4), nib);
            let n2 = _mm_and_si128(shi, nib);
            let n3 = _mm_and_si128(_mm_srli_epi16(shi, 4), nib);
            let plo = _mm_xor_si128(
                _mm_xor_si128(_mm_shuffle_epi8(t0l, n0), _mm_shuffle_epi8(t1l, n1)),
                _mm_xor_si128(_mm_shuffle_epi8(t2l, n2), _mm_shuffle_epi8(t3l, n3)),
            );
            let phi = _mm_xor_si128(
                _mm_xor_si128(_mm_shuffle_epi8(t0h, n0), _mm_shuffle_epi8(t1h, n1)),
                _mm_xor_si128(_mm_shuffle_epi8(t2h, n2), _mm_shuffle_epi8(t3h, n3)),
            );
            let dp = dst.as_mut_ptr().add(c * 32) as *mut __m128i;
            let d0 = _mm_loadu_si128(dp);
            let d1 = _mm_loadu_si128(dp.add(1));
            _mm_storeu_si128(dp, _mm_xor_si128(d0, _mm_unpacklo_epi8(plo, phi)));
            _mm_storeu_si128(dp.add(1), _mm_xor_si128(d1, _mm_unpackhi_epi8(plo, phi)));
        }
    }
    chunks * 32
}

/// AVX2: the SSSE3 path widened to thirty-two words per 64-byte chunk;
/// every step is lane-local, so the framing is the 128-bit one twice.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn fold_avx2(nl: &[[u8; 16]; 4], nh: &[[u8; 16]; 4], dst: &mut [u8], src: &[u8]) -> usize {
    use std::arch::x86_64::*;
    let chunks = src.len().min(dst.len()) / 64;
    if chunks == 0 {
        return 0;
    }
    // SAFETY: AVX2 is enabled per the target feature and verified by the
    // caller; every access is inside the first chunks * 64 bytes.
    unsafe {
        let bc = |t: &[u8; 16]| {
            _mm256_broadcastsi128_si256(_mm_loadu_si128(t.as_ptr() as *const __m128i))
        };
        let (t0l, t1l, t2l, t3l) = (bc(&nl[0]), bc(&nl[1]), bc(&nl[2]), bc(&nl[3]));
        let (t0h, t1h, t2h, t3h) = (bc(&nh[0]), bc(&nh[1]), bc(&nh[2]), bc(&nh[3]));
        let nib = _mm256_set1_epi8(0x0f);
        let lo8 = _mm256_set1_epi16(0x00ff);
        for c in 0..chunks {
            let sp = src.as_ptr().add(c * 64) as *const __m256i;
            let v0 = _mm256_loadu_si256(sp);
            let v1 = _mm256_loadu_si256(sp.add(1));
            let slo = _mm256_packus_epi16(_mm256_and_si256(v0, lo8), _mm256_and_si256(v1, lo8));
            let shi = _mm256_packus_epi16(_mm256_srli_epi16(v0, 8), _mm256_srli_epi16(v1, 8));
            let n0 = _mm256_and_si256(slo, nib);
            let n1 = _mm256_and_si256(_mm256_srli_epi16(slo, 4), nib);
            let n2 = _mm256_and_si256(shi, nib);
            let n3 = _mm256_and_si256(_mm256_srli_epi16(shi, 4), nib);
            let plo = _mm256_xor_si256(
                _mm256_xor_si256(_mm256_shuffle_epi8(t0l, n0), _mm256_shuffle_epi8(t1l, n1)),
                _mm256_xor_si256(_mm256_shuffle_epi8(t2l, n2), _mm256_shuffle_epi8(t3l, n3)),
            );
            let phi = _mm256_xor_si256(
                _mm256_xor_si256(_mm256_shuffle_epi8(t0h, n0), _mm256_shuffle_epi8(t1h, n1)),
                _mm256_xor_si256(_mm256_shuffle_epi8(t2h, n2), _mm256_shuffle_epi8(t3h, n3)),
            );
            let dp = dst.as_mut_ptr().add(c * 64) as *mut __m256i;
            let d0 = _mm256_loadu_si256(dp);
            let d1 = _mm256_loadu_si256(dp.add(1));
            _mm256_storeu_si256(dp, _mm256_xor_si256(d0, _mm256_unpacklo_epi8(plo, phi)));
            _mm256_storeu_si256(
                dp.add(1),
                _mm256_xor_si256(d1, _mm256_unpackhi_epi8(plo, phi)),
            );
        }
    }
    chunks * 64
}

/// GFNI with AVX2: the eight table shuffles replaced by four
/// `gf2p8affineqb` bit-matrix products, no nibble extraction.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "gfni,avx2")]
unsafe fn fold_gfni(affine: &[u64; 4], dst: &mut [u8], src: &[u8]) -> usize {
    use std::arch::x86_64::*;
    let chunks = src.len().min(dst.len()) / 64;
    if chunks == 0 {
        return 0;
    }
    // SAFETY: GFNI and AVX2 are enabled per the target feature and verified
    // by the caller; every access is inside the first chunks * 64 bytes.
    unsafe {
        let mll = _mm256_set1_epi64x(affine[0] as i64);
        let mhl = _mm256_set1_epi64x(affine[1] as i64);
        let mlh = _mm256_set1_epi64x(affine[2] as i64);
        let mhh = _mm256_set1_epi64x(affine[3] as i64);
        let lo8 = _mm256_set1_epi16(0x00ff);
        for c in 0..chunks {
            let sp = src.as_ptr().add(c * 64) as *const __m256i;
            let v0 = _mm256_loadu_si256(sp);
            let v1 = _mm256_loadu_si256(sp.add(1));
            let slo = _mm256_packus_epi16(_mm256_and_si256(v0, lo8), _mm256_and_si256(v1, lo8));
            let shi = _mm256_packus_epi16(_mm256_srli_epi16(v0, 8), _mm256_srli_epi16(v1, 8));
            let plo = _mm256_xor_si256(
                _mm256_gf2p8affine_epi64_epi8::<0>(slo, mll),
                _mm256_gf2p8affine_epi64_epi8::<0>(shi, mhl),
            );
            let phi = _mm256_xor_si256(
                _mm256_gf2p8affine_epi64_epi8::<0>(slo, mlh),
                _mm256_gf2p8affine_epi64_epi8::<0>(shi, mhh),
            );
            let dp = dst.as_mut_ptr().add(c * 64) as *mut __m256i;
            let d0 = _mm256_loadu_si256(dp);
            let d1 = _mm256_loadu_si256(dp.add(1));
            _mm256_storeu_si256(dp, _mm256_xor_si256(d0, _mm256_unpacklo_epi8(plo, phi)));
            _mm256_storeu_si256(
                dp.add(1),
                _mm256_xor_si256(d1, _mm256_unpackhi_epi8(plo, phi)),
            );
        }
    }
    chunks * 64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every kernel this box has against the scalar two-table fold, over
    /// lengths that leave every kind of tail and coefficients from every
    /// class (zero, one, a power of two, the top bit, the top value).
    #[test]
    fn simd_fold_matches_the_scalar_tables() {
        let gf = super::super::rar5::shared_gf16();
        for &c in &[0u16, 1, 2, 0x8000, 0xffff, 0x1234, 0xabcd, 0x0100, 0x00ff] {
            let tables = FoldTables::new(c);
            let mut lo = [0u16; 256];
            let mut hi = [0u16; 256];
            for byte in 0..256u16 {
                lo[byte as usize] = gf.mul(c, byte);
                hi[byte as usize] = gf.mul(c, byte << 8);
            }
            for len in (0..300).chain([4_094, 4_096, 65_536, 65_538]) {
                let len = len / 2 * 2;
                let source: Vec<u8> = (0..len)
                    .map(|i| ((i as u64 * 0x9E37_79B9 + c as u64) >> 5) as u8)
                    .collect();
                let mut expected: Vec<u8> = (0..len).map(|i| (i * 7 % 251) as u8).collect();
                let mut actual = expected.clone();
                for (d, s) in expected.chunks_exact_mut(2).zip(source.chunks_exact(2)) {
                    let product = lo[usize::from(s[0])] ^ hi[usize::from(s[1])];
                    d[0] ^= (product & 0xff) as u8;
                    d[1] ^= (product >> 8) as u8;
                }
                let done = fold_simd(&tables, &mut actual, &source);
                assert!(done <= len && done % 32 == 0, "c {c:#x} len {len}: done {done}");
                for (d, s) in actual[done..]
                    .chunks_exact_mut(2)
                    .zip(source[done..].chunks_exact(2))
                {
                    let product = lo[usize::from(s[0])] ^ hi[usize::from(s[1])];
                    d[0] ^= (product & 0xff) as u8;
                    d[1] ^= (product >> 8) as u8;
                }
                assert!(actual == expected, "c {c:#x} len {len}: fold differs");
            }
        }
    }
}
