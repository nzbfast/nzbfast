//! The transform leaf in a quadratic basis, with conjugate output rows
//! computed in pairs.
//!
//! # Where this comes from
//!
//! the review's `conjugate-integrated` research (5 Sep 2026): a Rader-257 leaf
//! whose arithmetic runs in GF(65536) represented as GF(256)[t]/(t² + t + 2)
//! rather than as 16-bit words over the standard polynomial, and which
//! produces the two conjugate output rows of every pair from ONE set of
//! table lookups. Confirmed on a quiet i5-10600KF with their binary, same
//! binary paired vs off: heavy repair 3.16-3.27 s vs 4.26-4.45, the 64 KiB
//! create 2.36-2.40 vs 3.68-3.85, outputs byte-identical; on an M1 Ultra
//! (NEON) their 64 KiB create 0.94 vs 1.37. This is that kernel, ported
//! into this crate's style; the arithmetic is theirs line for line.
//!
//! # The arithmetic
//!
//! Every element x of GF(65536) is written x = a + b·t with a, b in
//! GF(256) (reduction polynomial 0x1CF, [`POLY`] as its low byte) and
//! t² = t + 2. [`ENC`] / [`DEC`] are the change of basis from the crate's
//! standard representation (the 0x1100B polynomial, `gf16`) to the pair
//! (a, b) and back - linear maps, so four 16-entry nibble tables XORed
//! together each way. The product with a coefficient c + d·t is
//!
//! ```text
//! (a + b t)(c + d t) = (ac + 2bd) + (ad + bc + bd) t
//! ```
//!
//! i.e. four GF(256) byte products, each a pair of nibble shuffles, on
//! the two byte planes of the source. Frobenius x -> x^256 fixes GF(256)
//! and sends t to t + 1 (the other root of t² + t + 2), so the conjugate
//! of c + d t is (c + d) + d t - and in the leaf the coefficient of Rader
//! row m + 128 is the conjugate of row m's (the frequencies k and 257 - k
//! of the length-257 transform, since the primitive root's inverse is its
//! 256th power). The four byte products c·a, c·b, d·a, d·b of one source
//! therefore give BOTH rows:
//!
//! ```text
//! row m:        low = c·a + 2·d·b          high = c·b + d·a + d·b
//! row m + 128:  low' = low + d·a            high' = high + d·b
//! ```
//!
//! Eight shuffles per source per 32 words for two output rows, where the
//! nibble kernel spends eight per row. Sources are converted into the
//! (a, b) plane layout once per leaf (a copy the planar fold makes
//! anyway), both output rows of a pair are converted back once, and the
//! DC row X[0] stays a plain XOR of the standard-basis sources.
//!
//! # Where it runs
//!
//! [`Kernel::new`] builds it where the nibble kernels are the selected
//! ones - AVX2 without GFNI (`gf16::PreparedSources::enabled`) and NEON -
//! and `NZBFAST_NTT_PAIRED=0` / `=1` overrides either way. A leaf whose
//! packed sources would not fit [`SCRATCH_CAP`], or a stripe width that is
//! not a multiple of 32 words, takes the dense leaf as before. GFNI and
//! AVX-512 parts keep their affine kernels: not measured against this.

use crate::gf16;

/// GF(256)'s reduction polynomial less its top bit: x^8 + x^7 + x^6 + x^3 +
/// x^2 + x + 1 = 0x1CF.
const POLY: u8 = 0xCF;

/// Standard basis -> (a, b): the quadratic coordinates of `x` are the XOR
/// of `ENC[n][x's n-th nibble]` over n; low byte a, high byte b.
const ENC: [[u16; 16]; 4] = [
    [
        0, 1, 55518, 55519, 44079, 44078, 29937, 29936, 53461, 53460, 2059, 2058, 31994, 31995,
        42020, 42021,
    ],
    [
        0, 2279, 23561, 21742, 60650, 58381, 45283, 47108, 16491, 18572, 7266, 5253, 44161, 42086,
        61576, 63599,
    ],
    [
        0, 16404, 55118, 38746, 18125, 1753, 37251, 53655, 46960, 63332, 24638, 8234, 61885, 45481,
        9971, 26343,
    ],
    [
        0, 53672, 59057, 14105, 55619, 2283, 16370, 61018, 30557, 42741, 37356, 16452, 44574,
        32694, 18607, 39175,
    ],
];

/// (a, b) -> standard basis, the inverse of [`ENC`] in the same shape.
const DEC: [[u16; 16]; 4] = [
    [
        0, 1, 5726, 5727, 23160, 23161, 19494, 19495, 2664, 2665, 7222, 7223, 20496, 20497, 17998,
        17999,
    ],
    [
        0, 42880, 63183, 20815, 5760, 45312, 57423, 18383, 45125, 6085, 18058, 57610, 42693, 325,
        20490, 63370,
    ],
    [
        0, 2006, 37194, 38556, 40806, 39088, 3628, 2554, 7229, 7147, 36215, 35489, 33627, 33933,
        4625, 5575,
    ],
    [
        0, 30186, 57849, 37907, 64760, 35090, 7425, 26859, 53798, 42956, 13279, 17973, 11998,
        23348, 53031, 47821,
    ],
];

/// A standard-basis element's quadratic coordinates, packed a | b << 8.
fn to_quadratic(x: u16) -> u16 {
    ENC.iter()
        .enumerate()
        .fold(0, |v, (n, table)| v ^ table[(x as usize >> (4 * n)) & 15])
}

/// GF(256) doubling: multiply by x, reduced by [`POLY`].
fn double(x: u8) -> u8 {
    x.wrapping_add(x) ^ if x & 0x80 != 0 { POLY } else { 0 }
}

/// Nibble tables for multiplying GF(256) bytes by the two coordinates of
/// one coefficient: `lo[k][n]` is coordinate k times the byte n (a low
/// nibble), `hi[k][n]` coordinate k times n << 4.
#[derive(Clone)]
pub(super) struct PairCoeff {
    lo: [[u8; 16]; 2],
    hi: [[u8; 16]; 2],
}

impl PairCoeff {
    /// Tables for the standard-basis coefficient `c`.
    fn new(c: u16) -> PairCoeff {
        let q = to_quadratic(c);
        let mut out = PairCoeff {
            lo: [[0; 16]; 2],
            hi: [[0; 16]; 2],
        };
        for (k, coord) in [q as u8, (q >> 8) as u8].into_iter().enumerate() {
            // coord * 2^bit for bit 0..8, by doubling.
            let mut powers = [0u8; 8];
            let mut v = coord;
            for p in powers.iter_mut() {
                *p = v;
                v = double(v);
            }
            for n in 1usize..16 {
                let bit = n.trailing_zeros() as usize;
                let rest = n & (n - 1);
                out.lo[k][n] = out.lo[k][rest] ^ powers[bit];
                out.hi[k][n] = out.hi[k][rest] ^ powers[bit + 4];
            }
        }
        out
    }
}

/// Packed-source scratch per worker: the leaf's sources in the (a, b)
/// plane layout, `count x w x 2` bytes, sized for a FULL leaf at the
/// stripe the transform runs: all 256 convolution sources plus the x0
/// row. the review's 256 KiB was one row short of that, so every leaf
/// carrying x0 fell back to the dense path unnoticed - and the fixed
/// 512-word cap that replaced it did the same thing one step later:
/// `default_stripe_words` made 1,024 the x86 default at blocks of 1 MiB
/// and up (6 Sep 2026) and every leaf of more than 128 sources, which
/// is every full leaf of a big create or repair, took the dense kernel
/// with nothing saying so. The cap follows `w` now; `SCRATCH_CAP` is
/// the 512-word floor the accounting and the tests keep.
/// That 1,024 is narrower since 16 Sep 2026 - the create takes it only
/// below the additive leaf's gate, where the paired kernel is the one
/// running - but it is not gone, and a skewed plan can still reach this
/// cap at a full leaf, so the cap must keep following `w`.
/// `NZBFAST_NTT_PAIRED_CAPW=<words>` pins it (the A/B arm: 512 is the
/// shipped-until-now behaviour).
pub(super) const SCRATCH_CAP: usize = 257 * 512 * 2;

/// The packed-source scratch for stripe width `w`, never under
/// [`SCRATCH_CAP`].
pub(super) fn scratch_cap(w: usize) -> usize {
    static PIN: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    let words = PIN
        .get_or_init(|| {
            std::env::var("NZBFAST_NTT_PAIRED_CAPW")
                .ok()
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(w);
    (257 * words * 2).max(SCRATCH_CAP)
}

/// The kernel's coefficient tables: one [`PairCoeff`] per Rader kernel
/// entry, and the tables for 1 (the x[0] occupant's coefficient).
pub(super) struct Kernel {
    coeffs: Box<[PairCoeff; 256]>,
    one: PairCoeff,
}

impl Kernel {
    /// The kernel where it runs (see the module doc), else None.
    pub(super) fn new(rader_kernel: &[u16; 256]) -> Option<Kernel> {
        if !enabled() {
            return None;
        }
        Self::build(rader_kernel)
    }

    /// The kernel regardless of the shipping gate, where the CPU can run
    /// it at all (tests compare it against the dense leaf).
    #[cfg(test)]
    pub(super) fn new_forced(rader_kernel: &[u16; 256]) -> Option<Kernel> {
        if !cpu_supported() {
            return None;
        }
        Self::build(rader_kernel)
    }

    /// None unless the kernel has the property the pairing rests on:
    /// entry j + 128 is the conjugate (256th power) of entry j, which the
    /// Rader kernel of the length-257 transform has by construction and
    /// an arbitrary table does not. Checked here so no caller can feed the
    /// pairing a kernel it is wrong for.
    fn build(rader_kernel: &[u16; 256]) -> Option<Kernel> {
        let conjugate = |mut x: u16| {
            for _ in 0..8 {
                x = gf16::mul(x, x);
            }
            x
        };
        if (0..256).any(|j| conjugate(rader_kernel[j]) != rader_kernel[(j + 128) & 255]) {
            return None;
        }
        Some(Kernel {
            coeffs: Box::new(std::array::from_fn(|i| PairCoeff::new(rader_kernel[i]))),
            one: PairCoeff::new(1),
        })
    }
}

/// Whether this CPU runs the kernel at all.
fn cpu_supported() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        is_x86_feature_detected!("avx2")
    }
    #[cfg(target_arch = "aarch64")]
    {
        true
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
}

/// The shipping gate, read once: `NZBFAST_NTT_PAIRED=0|1`, else on where
/// the nibble kernels are the selected ones (AVX2 without GFNI, NEON).
pub(super) fn enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        if !cpu_supported() {
            return false;
        }
        match std::env::var("NZBFAST_NTT_PAIRED").ok().as_deref() {
            Some("0") => false,
            Some("1") => true,
            _ => {
                #[cfg(target_arch = "x86_64")]
                {
                    gf16::PreparedSources::enabled()
                }
                #[cfg(not(target_arch = "x86_64"))]
                {
                    true
                }
            }
        }
    })
}

/// One leaf on the paired kernel: X[0] and all 256 convolution rows into
/// `out` (257 rows of `w` words), sources packed through `scratch`. Returns
/// false, having written nothing, when the leaf does not fit (the caller
/// runs the dense leaf).
pub(super) fn leaf(
    kernel: &Kernel,
    leaf: &super::LeafPlan,
    g_pow: &[usize; 256],
    src_of: &dyn Fn(super::SrcId) -> *const u8,
    w: usize,
    out: &mut [u16],
    scratch: &mut [u8],
) -> bool {
    let count = leaf.conv_sources.len() + usize::from(leaf.x0.is_some());
    let bytes = w * 2;
    let Some(total) = count.checked_mul(bytes) else {
        return false;
    };
    if !w.is_multiple_of(32) || count == 0 || total > scratch.len() {
        return false;
    }
    let packed = &mut scratch[..total];
    out[..257 * w].fill(0);
    // Pack every source into the (a, b) plane layout, and XOR its standard
    // bytes into X[0] on the way (the DC row is not transformed).
    for i in 0..count {
        let id = if i < leaf.conv_sources.len() {
            leaf.conv_sources[i].1
        } else {
            leaf.x0.expect("count includes x0 only when present")
        };
        // SAFETY: `src_of` resolves to `w * 2` readable bytes for this
        // transform (FlatPlan::transform's contract, the same one the
        // dense leaf reads under).
        let src = unsafe { std::slice::from_raw_parts(src_of(id), bytes) };
        for (d, x) in out[..w].iter_mut().zip(src.as_chunks::<2>().0) {
            *d ^= u16::from_le_bytes(*x);
        }
        let dst = &mut packed[i * bytes..(i + 1) * bytes];
        dst.copy_from_slice(src);
        convert(dst, true);
    }
    // Rows m and m + 128 are conjugates: both from one pass over the
    // sources, four at a time - or, hoisted, every source into
    // register-resident accumulators one column chunk at a time, the
    // rows written once per chunk (`pair_fold_hoisted`).
    let hoist = hoist_enabled();
    // The leaf has at most 256 convolution sources plus x0.
    let mut cs = [&kernel.one; 257];
    for m in 0..128usize {
        let row = g_pow[m];
        let other = g_pow[m + 128];
        if hoist {
            for (c, &(i, _)) in cs.iter_mut().zip(&leaf.conv_sources) {
                *c = &kernel.coeffs[(m + 256 - i as usize) & 255];
            }
            let (a, b) = if row < other {
                let (l, r) = out.split_at_mut(other * w);
                (&mut l[row * w..(row + 1) * w], &mut r[..w])
            } else {
                let (l, r) = out.split_at_mut(row * w);
                (&mut r[..w], &mut l[other * w..(other + 1) * w])
            };
            // SAFETY: as `pair_fold` - the CPU feature was verified when
            // the kernel was built; the arm checks every length.
            unsafe { pair_fold_hoisted(a, b, packed, bytes, &cs[..count]) };
            convert(words_as_bytes_mut(&mut out[row * w..(row + 1) * w]), false);
            convert(
                words_as_bytes_mut(&mut out[other * w..(other + 1) * w]),
                false,
            );
            continue;
        }
        for start in (0..count).step_by(4) {
            let n = (count - start).min(4);
            let mut srcs: [&[u8]; 4] = [&[]; 4];
            let mut coeffs: [&PairCoeff; 4] = [&kernel.one; 4];
            for j in 0..n {
                let i = start + j;
                srcs[j] = &packed[i * bytes..(i + 1) * bytes];
                if i < leaf.conv_sources.len() {
                    coeffs[j] = &kernel.coeffs[(m + 256 - leaf.conv_sources[i].0 as usize) & 255];
                }
            }
            let (a, b) = if row < other {
                let (l, r) = out.split_at_mut(other * w);
                (&mut l[row * w..(row + 1) * w], &mut r[..w])
            } else {
                let (l, r) = out.split_at_mut(row * w);
                (&mut r[..w], &mut l[other * w..(other + 1) * w])
            };
            pair_fold(a, b, &srcs[..n], &coeffs[..n]);
        }
        convert(words_as_bytes_mut(&mut out[row * w..(row + 1) * w]), false);
        convert(
            words_as_bytes_mut(&mut out[other * w..(other + 1) * w]),
            false,
        );
    }
    true
}

/// The hoisted-accumulator leaf loop (`pair_fold_hoisted`): ON on
/// aarch64, OFF on x86-64, `NZBFAST_NTT_PAIRED_HOIST=1|0` either way.
/// Measured 5 Sep 2026, same binary, mirrored: the M3 Ultra's leaf
/// micro-bench -16..-19% at every source count and the heavy repair
/// (1,500 rows) -8% (0.595-0.632 vs 0.621-0.745 s), the 10 GiB /
/// 900-row repair's transform 2.55-3.12 vs 2.75-4.43 s on a loaded box;
/// the i5-10600KF (AVX2) heavy repair +3% (2.80-2.90 vs 2.74-2.80),
/// 64 KiB create +3..4%, the 10 GiB repair +6% - sixteen ymm registers
/// and two load ports cannot afford four table broadcasts per source
/// per chunk, where NEON's thirty-two registers and register-resident
/// `tbl` can. Read once.
fn hoist_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(
        || match std::env::var("NZBFAST_NTT_PAIRED_HOIST").as_deref() {
            Ok("1") => true,
            Ok("0") => false,
            _ => cfg!(target_arch = "aarch64"),
        },
    )
}

/// Every packed source into the conjugate row pair `(d0, d1)`, one column
/// chunk at a time: the four byte-product accumulators stay in registers
/// across ALL `count` sources and the two rows are read and written once
/// per chunk, where [`pair_fold`] reads and writes them once per group
/// of four sources. `packed` holds `count` sources of `bytes` each in the
/// (a, b) plane layout; `coeffs[i]` is source i's coefficient for this
/// row.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn pair_fold_hoisted(
    d0: &mut [u16],
    d1: &mut [u16],
    packed: &[u8],
    bytes: usize,
    coeffs: &[&PairCoeff],
) {
    use std::arch::aarch64::*;
    let count = coeffs.len();
    assert_eq!(d0.len(), d1.len());
    assert_eq!(bytes, d0.len() * 2);
    assert!(bytes.is_multiple_of(32) && packed.len() >= count * bytes);
    // SAFETY: neon on per #[target_feature]; every access is a 16-byte
    // load at `i * bytes + off (+ 16)` with `off + 32 <= bytes` and
    // `i < count`, inside `packed` by the assert; the rows are read and
    // written at `off` and `off + 16` inside `bytes`; table loads read
    // 16-byte arrays.
    unsafe {
        let z = vdupq_n_u8(0);
        let mask = vdupq_n_u8(15);
        let poly = vdupq_n_u8(POLY);
        let base = packed.as_ptr();
        for off in (0..bytes).step_by(32) {
            let (mut ca, mut cb, mut da, mut db) = (z, z, z, z);
            for (i, c) in coeffs.iter().enumerate() {
                let sp = base.add(i * bytes + off);
                let a = vld1q_u8(sp);
                let b = vld1q_u8(sp.add(16));
                let n0 = vandq_u8(a, mask);
                let n1 = vshrq_n_u8::<4>(a);
                let n2 = vandq_u8(b, mask);
                let n3 = vshrq_n_u8::<4>(b);
                let l0 = vld1q_u8(c.lo[0].as_ptr());
                let h0 = vld1q_u8(c.hi[0].as_ptr());
                let l1 = vld1q_u8(c.lo[1].as_ptr());
                let h1 = vld1q_u8(c.hi[1].as_ptr());
                ca = veorq_u8(ca, veorq_u8(vqtbl1q_u8(l0, n0), vqtbl1q_u8(h0, n1)));
                cb = veorq_u8(cb, veorq_u8(vqtbl1q_u8(l0, n2), vqtbl1q_u8(h0, n3)));
                da = veorq_u8(da, veorq_u8(vqtbl1q_u8(l1, n0), vqtbl1q_u8(h1, n1)));
                db = veorq_u8(db, veorq_u8(vqtbl1q_u8(l1, n2), vqtbl1q_u8(h1, n3)));
            }
            let top = vreinterpretq_u8_s8(vshrq_n_s8::<7>(vreinterpretq_s8_u8(db)));
            let two_db = veorq_u8(vaddq_u8(db, db), vandq_u8(top, poly));
            let low = veorq_u8(ca, two_db);
            let high = veorq_u8(cb, veorq_u8(da, db));
            let p = d0.as_mut_ptr().cast::<u8>().add(off);
            let q = d1.as_mut_ptr().cast::<u8>().add(off);
            vst1q_u8(p, veorq_u8(vld1q_u8(p), low));
            vst1q_u8(p.add(16), veorq_u8(vld1q_u8(p.add(16)), high));
            vst1q_u8(q, veorq_u8(vld1q_u8(q), veorq_u8(low, da)));
            vst1q_u8(q.add(16), veorq_u8(vld1q_u8(q.add(16)), veorq_u8(high, db)));
        }
    }
}

/// [`pair_fold_hoisted`] on AVX2: 64-byte chunks, the tables broadcast
/// from memory per source (one load-port op each beside the shuffle).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn pair_fold_hoisted(
    d0: &mut [u16],
    d1: &mut [u16],
    packed: &[u8],
    bytes: usize,
    coeffs: &[&PairCoeff],
) {
    use std::arch::x86_64::*;
    let count = coeffs.len();
    assert_eq!(d0.len(), d1.len());
    assert_eq!(bytes, d0.len() * 2);
    assert!(bytes.is_multiple_of(64) && packed.len() >= count * bytes);
    // SAFETY: avx2 on per #[target_feature]; every access is a 32-byte
    // load at `i * bytes + off (+ 32)` with `off + 64 <= bytes` and
    // `i < count`, inside `packed` by the assert; the rows are read and
    // written at `off` and `off + 32` inside `bytes`; table broadcasts
    // read 16-byte arrays.
    unsafe {
        let bc = |t: &[u8; 16]| {
            _mm256_broadcastsi128_si256(_mm_loadu_si128(t.as_ptr().cast::<__m128i>()))
        };
        let z = _mm256_setzero_si256();
        let mask = _mm256_set1_epi8(15);
        let poly = _mm256_set1_epi8(POLY as i8);
        let base = packed.as_ptr();
        for off in (0..bytes).step_by(64) {
            let (mut ca, mut cb, mut da, mut db) = (z, z, z, z);
            for (i, c) in coeffs.iter().enumerate() {
                let sp = base.add(i * bytes + off);
                let a = _mm256_loadu_si256(sp.cast());
                let b = _mm256_loadu_si256(sp.add(32).cast());
                let n0 = _mm256_and_si256(a, mask);
                let n1 = _mm256_and_si256(_mm256_srli_epi16(a, 4), mask);
                let n2 = _mm256_and_si256(b, mask);
                let n3 = _mm256_and_si256(_mm256_srli_epi16(b, 4), mask);
                let l0 = bc(&c.lo[0]);
                let h0 = bc(&c.hi[0]);
                let l1 = bc(&c.lo[1]);
                let h1 = bc(&c.hi[1]);
                ca = _mm256_xor_si256(
                    ca,
                    _mm256_xor_si256(_mm256_shuffle_epi8(l0, n0), _mm256_shuffle_epi8(h0, n1)),
                );
                cb = _mm256_xor_si256(
                    cb,
                    _mm256_xor_si256(_mm256_shuffle_epi8(l0, n2), _mm256_shuffle_epi8(h0, n3)),
                );
                da = _mm256_xor_si256(
                    da,
                    _mm256_xor_si256(_mm256_shuffle_epi8(l1, n0), _mm256_shuffle_epi8(h1, n1)),
                );
                db = _mm256_xor_si256(
                    db,
                    _mm256_xor_si256(_mm256_shuffle_epi8(l1, n2), _mm256_shuffle_epi8(h1, n3)),
                );
            }
            let two_db = _mm256_xor_si256(
                _mm256_add_epi8(db, db),
                _mm256_and_si256(_mm256_cmpgt_epi8(z, db), poly),
            );
            let low = _mm256_xor_si256(ca, two_db);
            let high = _mm256_xor_si256(cb, _mm256_xor_si256(da, db));
            let p = d0.as_mut_ptr().cast::<u8>().add(off);
            let q = d1.as_mut_ptr().cast::<u8>().add(off);
            _mm256_storeu_si256(
                p.cast(),
                _mm256_xor_si256(_mm256_loadu_si256(p.cast()), low),
            );
            _mm256_storeu_si256(
                p.add(32).cast(),
                _mm256_xor_si256(_mm256_loadu_si256(p.add(32).cast()), high),
            );
            _mm256_storeu_si256(
                q.cast(),
                _mm256_xor_si256(_mm256_loadu_si256(q.cast()), _mm256_xor_si256(low, da)),
            );
            _mm256_storeu_si256(
                q.add(32).cast(),
                _mm256_xor_si256(
                    _mm256_loadu_si256(q.add(32).cast()),
                    _mm256_xor_si256(high, db),
                ),
            );
        }
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
unsafe fn pair_fold_hoisted(_: &mut [u16], _: &mut [u16], _: &[u8], _: usize, _: &[&PairCoeff]) {
    unreachable!("the paired kernel is never built here (cpu_supported)")
}

fn words_as_bytes_mut(d: &mut [u16]) -> &mut [u8] {
    // SAFETY: a u16 slice viewed as twice as many bytes; same allocation,
    // same lifetime, u8 has no alignment or validity requirement.
    unsafe { std::slice::from_raw_parts_mut(d.as_mut_ptr().cast(), d.len() * 2) }
}

/// Fold up to four packed sources into the conjugate row pair `(a, b)`.
fn pair_fold(a: &mut [u16], b: &mut [u16], srcs: &[&[u8]], coeffs: &[&PairCoeff]) {
    // SAFETY: the CPU feature each arm enables was verified by
    // `cpu_supported` before the kernel was built; the arms check every
    // length they read or write.
    unsafe {
        match srcs.len() {
            1 => pair_fold_n::<1>(a, b, srcs, coeffs),
            2 => pair_fold_n::<2>(a, b, srcs, coeffs),
            3 => pair_fold_n::<3>(a, b, srcs, coeffs),
            4 => pair_fold_n::<4>(a, b, srcs, coeffs),
            _ => unreachable!("groups of at most four sources"),
        }
    }
}

/// Standard interleaved words <-> the (a, b) plane layout, in place, 64
/// bytes at a time (32 words): forward splits each word's bytes into a
/// low plane and a high plane and applies [`ENC`]; backward applies
/// [`DEC`] and interleaves again.
fn convert(buf: &mut [u8], forward: bool) {
    // SAFETY: as in `pair_fold`.
    unsafe { convert_arch(buf, forward) }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn convert_arch(buf: &mut [u8], forward: bool) {
    use std::arch::x86_64::*;
    assert!(buf.len().is_multiple_of(64));
    let t = if forward { &ENC } else { &DEC };
    let mut lo = [[0u8; 16]; 4];
    let mut hi = [[0u8; 16]; 4];
    for n in 0..4 {
        for i in 0..16 {
            lo[n][i] = t[n][i] as u8;
            hi[n][i] = (t[n][i] >> 8) as u8;
        }
    }
    // SAFETY: avx2 on per #[target_feature]; every load and store is at
    // `off` or `off + 32` with `off + 64 <= len` by the assert above; the
    // table broadcasts read 16 bytes of a 16-byte array.
    unsafe {
        let lv: [__m256i; 4] = std::array::from_fn(|n| {
            _mm256_broadcastsi128_si256(_mm_loadu_si128(lo[n].as_ptr().cast()))
        });
        let hv: [__m256i; 4] = std::array::from_fn(|n| {
            _mm256_broadcastsi128_si256(_mm_loadu_si128(hi[n].as_ptr().cast()))
        });
        let mask = _mm256_set1_epi8(15);
        let bytes = _mm256_set1_epi16(255);
        for off in (0..buf.len()).step_by(64) {
            let p = buf.as_mut_ptr().add(off);
            let x = _mm256_loadu_si256(p.cast());
            let y = _mm256_loadu_si256(p.add(32).cast());
            let (a, b) = if forward {
                (
                    _mm256_packus_epi16(_mm256_and_si256(x, bytes), _mm256_and_si256(y, bytes)),
                    _mm256_packus_epi16(_mm256_srli_epi16(x, 8), _mm256_srli_epi16(y, 8)),
                )
            } else {
                (x, y)
            };
            let nibbles = [
                _mm256_and_si256(a, mask),
                _mm256_and_si256(_mm256_srli_epi16(a, 4), mask),
                _mm256_and_si256(b, mask),
                _mm256_and_si256(_mm256_srli_epi16(b, 4), mask),
            ];
            let mut l = _mm256_setzero_si256();
            let mut h = _mm256_setzero_si256();
            for n in 0..4 {
                l = _mm256_xor_si256(l, _mm256_shuffle_epi8(lv[n], nibbles[n]));
                h = _mm256_xor_si256(h, _mm256_shuffle_epi8(hv[n], nibbles[n]));
            }
            let (l, h) = if forward {
                (l, h)
            } else {
                (_mm256_unpacklo_epi8(l, h), _mm256_unpackhi_epi8(l, h))
            };
            _mm256_storeu_si256(p.cast(), l);
            _mm256_storeu_si256(p.add(32).cast(), h);
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn pair_fold_n<const N: usize>(
    d0: &mut [u16],
    d1: &mut [u16],
    srcs: &[&[u8]],
    coeffs: &[&PairCoeff],
) {
    use std::arch::x86_64::*;
    assert_eq!(srcs.len(), N);
    assert_eq!(coeffs.len(), N);
    assert_eq!(d0.len(), d1.len());
    assert!(d0.len().is_multiple_of(32) && srcs.iter().all(|s| s.len() == d0.len() * 2));
    // SAFETY: avx2 on per #[target_feature]; the asserts above bound every
    // 64-byte step inside each source and both rows; table broadcasts
    // read 16-byte arrays.
    unsafe {
        let z = _mm256_setzero_si256();
        let mut lo = [[z; 2]; N];
        let mut hi = [[z; 2]; N];
        for i in 0..N {
            for k in 0..2 {
                lo[i][k] =
                    _mm256_broadcastsi128_si256(_mm_loadu_si128(coeffs[i].lo[k].as_ptr().cast()));
                hi[i][k] =
                    _mm256_broadcastsi128_si256(_mm_loadu_si128(coeffs[i].hi[k].as_ptr().cast()));
            }
        }
        let mask = _mm256_set1_epi8(15);
        let poly = _mm256_set1_epi8(POLY as i8);
        for off in (0..d0.len() * 2).step_by(64) {
            // Per source: c·a, c·b, d·a, d·b over the 32-byte planes.
            let (mut ca, mut cb, mut da, mut db) = (z, z, z, z);
            for i in 0..N {
                let a = _mm256_loadu_si256(srcs[i].as_ptr().add(off).cast());
                let b = _mm256_loadu_si256(srcs[i].as_ptr().add(off + 32).cast());
                let n = [
                    _mm256_and_si256(a, mask),
                    _mm256_and_si256(_mm256_srli_epi16(a, 4), mask),
                    _mm256_and_si256(b, mask),
                    _mm256_and_si256(_mm256_srli_epi16(b, 4), mask),
                ];
                ca = _mm256_xor_si256(
                    ca,
                    _mm256_xor_si256(
                        _mm256_shuffle_epi8(lo[i][0], n[0]),
                        _mm256_shuffle_epi8(hi[i][0], n[1]),
                    ),
                );
                cb = _mm256_xor_si256(
                    cb,
                    _mm256_xor_si256(
                        _mm256_shuffle_epi8(lo[i][0], n[2]),
                        _mm256_shuffle_epi8(hi[i][0], n[3]),
                    ),
                );
                da = _mm256_xor_si256(
                    da,
                    _mm256_xor_si256(
                        _mm256_shuffle_epi8(lo[i][1], n[0]),
                        _mm256_shuffle_epi8(hi[i][1], n[1]),
                    ),
                );
                db = _mm256_xor_si256(
                    db,
                    _mm256_xor_si256(
                        _mm256_shuffle_epi8(lo[i][1], n[2]),
                        _mm256_shuffle_epi8(hi[i][1], n[3]),
                    ),
                );
            }
            // 2·db in GF(256): shift, reduce where the top bit was set.
            let two_db = _mm256_xor_si256(
                _mm256_add_epi8(db, db),
                _mm256_and_si256(_mm256_cmpgt_epi8(z, db), poly),
            );
            let low = _mm256_xor_si256(ca, two_db);
            let high = _mm256_xor_si256(cb, _mm256_xor_si256(da, db));
            let p = d0.as_mut_ptr().cast::<u8>().add(off);
            let q = d1.as_mut_ptr().cast::<u8>().add(off);
            _mm256_storeu_si256(
                p.cast(),
                _mm256_xor_si256(_mm256_loadu_si256(p.cast()), low),
            );
            _mm256_storeu_si256(
                p.add(32).cast(),
                _mm256_xor_si256(_mm256_loadu_si256(p.add(32).cast()), high),
            );
            _mm256_storeu_si256(
                q.cast(),
                _mm256_xor_si256(_mm256_loadu_si256(q.cast()), _mm256_xor_si256(low, da)),
            );
            _mm256_storeu_si256(
                q.add(32).cast(),
                _mm256_xor_si256(
                    _mm256_loadu_si256(q.add(32).cast()),
                    _mm256_xor_si256(high, db),
                ),
            );
        }
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn convert_arch(buf: &mut [u8], forward: bool) {
    use std::arch::aarch64::*;
    assert!(buf.len().is_multiple_of(32));
    let t = if forward { &ENC } else { &DEC };
    let mut lo = [[0u8; 16]; 4];
    let mut hi = [[0u8; 16]; 4];
    for n in 0..4 {
        for i in 0..16 {
            lo[n][i] = t[n][i] as u8;
            hi[n][i] = (t[n][i] >> 8) as u8;
        }
    }
    // SAFETY: neon on per #[target_feature]; every access is 32 bytes at
    // `off` with `off + 32 <= len` by the assert above; table loads read
    // 16-byte arrays.
    unsafe {
        let lv: [uint8x16_t; 4] = std::array::from_fn(|n| vld1q_u8(lo[n].as_ptr()));
        let hv: [uint8x16_t; 4] = std::array::from_fn(|n| vld1q_u8(hi[n].as_ptr()));
        let mask = vdupq_n_u8(15);
        for off in (0..buf.len()).step_by(32) {
            let p = buf.as_mut_ptr().add(off);
            let (a, b) = if forward {
                let z = vld2q_u8(p);
                (z.0, z.1)
            } else {
                (vld1q_u8(p), vld1q_u8(p.add(16)))
            };
            let nibbles = [
                vandq_u8(a, mask),
                vshrq_n_u8::<4>(a),
                vandq_u8(b, mask),
                vshrq_n_u8::<4>(b),
            ];
            let mut l = vdupq_n_u8(0);
            let mut h = vdupq_n_u8(0);
            for n in 0..4 {
                l = veorq_u8(l, vqtbl1q_u8(lv[n], nibbles[n]));
                h = veorq_u8(h, vqtbl1q_u8(hv[n], nibbles[n]));
            }
            if forward {
                vst1q_u8(p, l);
                vst1q_u8(p.add(16), h);
            } else {
                vst2q_u8(p, uint8x16x2_t(l, h));
            }
        }
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn pair_fold_n<const N: usize>(
    d0: &mut [u16],
    d1: &mut [u16],
    srcs: &[&[u8]],
    coeffs: &[&PairCoeff],
) {
    use std::arch::aarch64::*;
    assert_eq!(srcs.len(), N);
    assert_eq!(coeffs.len(), N);
    assert_eq!(d0.len(), d1.len());
    assert!(d0.len().is_multiple_of(16) && srcs.iter().all(|s| s.len() == d0.len() * 2));
    // SAFETY: neon on per #[target_feature]; the asserts above bound every
    // 32-byte step inside each source and both rows; table loads read
    // 16-byte arrays.
    unsafe {
        let z = vdupq_n_u8(0);
        let mut lo = [[z; 2]; N];
        let mut hi = [[z; 2]; N];
        for i in 0..N {
            for k in 0..2 {
                lo[i][k] = vld1q_u8(coeffs[i].lo[k].as_ptr());
                hi[i][k] = vld1q_u8(coeffs[i].hi[k].as_ptr());
            }
        }
        let mask = vdupq_n_u8(15);
        let poly = vdupq_n_u8(POLY);
        for off in (0..d0.len() * 2).step_by(32) {
            let (mut ca, mut cb, mut da, mut db) = (z, z, z, z);
            for i in 0..N {
                let a = vld1q_u8(srcs[i].as_ptr().add(off));
                let b = vld1q_u8(srcs[i].as_ptr().add(off + 16));
                let n = [
                    vandq_u8(a, mask),
                    vshrq_n_u8::<4>(a),
                    vandq_u8(b, mask),
                    vshrq_n_u8::<4>(b),
                ];
                ca = veorq_u8(
                    ca,
                    veorq_u8(vqtbl1q_u8(lo[i][0], n[0]), vqtbl1q_u8(hi[i][0], n[1])),
                );
                cb = veorq_u8(
                    cb,
                    veorq_u8(vqtbl1q_u8(lo[i][0], n[2]), vqtbl1q_u8(hi[i][0], n[3])),
                );
                da = veorq_u8(
                    da,
                    veorq_u8(vqtbl1q_u8(lo[i][1], n[0]), vqtbl1q_u8(hi[i][1], n[1])),
                );
                db = veorq_u8(
                    db,
                    veorq_u8(vqtbl1q_u8(lo[i][1], n[2]), vqtbl1q_u8(hi[i][1], n[3])),
                );
            }
            let top = vreinterpretq_u8_s8(vshrq_n_s8::<7>(vreinterpretq_s8_u8(db)));
            let two_db = veorq_u8(vaddq_u8(db, db), vandq_u8(top, poly));
            let low = veorq_u8(ca, two_db);
            let high = veorq_u8(cb, veorq_u8(da, db));
            let p = d0.as_mut_ptr().cast::<u8>().add(off);
            let q = d1.as_mut_ptr().cast::<u8>().add(off);
            vst1q_u8(p, veorq_u8(vld1q_u8(p), low));
            vst1q_u8(p.add(16), veorq_u8(vld1q_u8(p.add(16)), high));
            vst1q_u8(q, veorq_u8(vld1q_u8(q), veorq_u8(low, da)));
            vst1q_u8(q.add(16), veorq_u8(vld1q_u8(q.add(16)), veorq_u8(high, db)));
        }
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
unsafe fn convert_arch(_: &mut [u8], _: bool) {
    unreachable!("the paired kernel is never built here (cpu_supported)")
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
unsafe fn pair_fold_n<const N: usize>(_: &mut [u16], _: &mut [u16], _: &[&[u8]], _: &[&PairCoeff]) {
    unreachable!("the paired kernel is never built here (cpu_supported)")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The quadratic basis is a faithful representation: round trips, and
    /// the (a, b) product law agrees with the standard multiplication for
    /// random pairs, including the conjugate identity the pairing rests on.
    #[test]
    fn quadratic_basis_matches_standard_arithmetic() {
        fn gf256_mul(mut x: u8, mut y: u8) -> u8 {
            let mut acc = 0u8;
            while y != 0 {
                if y & 1 != 0 {
                    acc ^= x;
                }
                x = double(x);
                y >>= 1;
            }
            acc
        }
        fn from_quadratic(q: u16) -> u16 {
            DEC.iter()
                .enumerate()
                .fold(0, |v, (n, table)| v ^ table[(q as usize >> (4 * n)) & 15])
        }
        fn quad_mul(x: u16, y: u16) -> u16 {
            let (a, b) = (x as u8, (x >> 8) as u8);
            let (c, d) = (y as u8, (y >> 8) as u8);
            let bd = gf256_mul(b, d);
            let low = gf256_mul(a, c) ^ double(bd);
            let high = gf256_mul(a, d) ^ gf256_mul(b, c) ^ bd;
            low as u16 | (high as u16) << 8
        }
        let mut seed = 0x5EEDu64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for x in [0u16, 1, 2, 0x8000, 0xFFFF] {
            assert_eq!(from_quadratic(to_quadratic(x)), x);
        }
        for _ in 0..20_000 {
            let x = next() as u16;
            let y = next() as u16;
            assert_eq!(from_quadratic(to_quadratic(x)), x);
            assert_eq!(
                to_quadratic(gf16::mul(x, y)),
                quad_mul(to_quadratic(x), to_quadratic(y)),
                "product of {x:#06x} and {y:#06x}"
            );
            // x^256 in the standard basis is (a + b) + b t in the quadratic one.
            let mut p = x;
            for _ in 0..8 {
                p = gf16::mul(p, p);
            }
            let q = to_quadratic(x);
            let (a, b) = (q as u8, (q >> 8) as u8);
            assert_eq!(
                to_quadratic(p),
                (a ^ b) as u16 | (b as u16) << 8,
                "conjugate of {x:#06x}"
            );
        }
    }
}
