use super::*;

/// The fused butterfly against the definition, both directions,
/// and the inverse undoing the forward.
#[test]
fn butterfly_matches_the_definition_and_inverts() {
    let mut rng = 0x2A17u64;
    let mut word = || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        (rng >> 16) as u16
    };
    // Widths in WORDS, and the point of the list is the 64-byte
    // boundary: this test ran at 64 words (128 bytes) alone, which is
    // an exact multiple of the 512-bit GFNI kernel's chunk, so the one
    // arm that consumes 64 bytes rather than 32 was never asked for a
    // span it would decline. 16 and 48 words are 32 and 96 bytes, both
    // 32 past a multiple of 64, which is precisely where that kernel
    // returns short (0 and 32 words) and `butterfly_two_pass` has to
    // finish the fold itself. Without that remainder the multiply is
    // silently skipped on an AVX-512 GFNI part - the defect that took
    // unit-one-process red on 69cbf2e2. 80 keeps a straddling width
    // above the production stripe's step.
    for &c in &[0u16, 1, 2, 0x100B, 0x8000, 0xFFFF, 12345] {
        for &n in &[16usize, 32, 48, 64, 80] {
            let u0: Vec<u16> = (0..n).map(|_| word()).collect();
            let v0: Vec<u16> = (0..n).map(|_| word()).collect();
            let (mut u, mut v) = (u0.clone(), v0.clone());
            let fc = FoldCoeff::new(c);
            assert_eq!(butterfly(&mut u, &mut v, &fc, false), n, "forward n={n}");
            for i in 0..n {
                let want_u = u0[i] ^ mul(c, v0[i]);
                assert_eq!(u[i], want_u, "forward u c={c:#x} n={n} i={i}");
                assert_eq!(v[i], want_u ^ v0[i], "forward v c={c:#x} n={n} i={i}");
            }
            assert_eq!(butterfly(&mut u, &mut v, &fc, true), n, "inverse n={n}");
            assert_eq!(u, u0, "inverse restores u c={c:#x} n={n}");
            assert_eq!(v, v0, "inverse restores v c={c:#x} n={n}");
        }
    }
}

/// [`scale`] against the definition at the same widths, including
/// the odd 32-byte unit the AVX2 arm finishes at half width, and the
/// coefficient shortcuts. The kernel writes over its own input, so
/// the failure this catches is a lane read after it was overwritten.
#[test]
fn scale_matches_the_definition_in_place() {
    let mut rng = 0x3C71u64;
    let mut word = || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        (rng >> 16) as u16
    };
    for &c in &[0u16, 1, 2, 0x100B, 0x8000, 0xFFFF, 12345] {
        for &n in &[16usize, 32, 48, 64, 80] {
            let r0: Vec<u16> = (0..n).map(|_| word()).collect();
            let mut r = r0.clone();
            assert_eq!(scale(&mut r, &FoldCoeff::new(c)), n, "words c={c:#x} n={n}");
            for i in 0..n {
                assert_eq!(r[i], mul(c, r0[i]), "scale c={c:#x} n={n} i={i}");
            }
        }
    }
}

/// [`scale`] is [`butterfly`]'s multiply with the destination
/// replaced rather than XORed, so the two must agree word for word
/// on the same input - the differential that would catch one arm
/// drifting from the other's table or lane order.
#[test]
fn scale_agrees_with_the_butterflys_multiply() {
    let mut rng = 0xB105u64;
    let mut word = || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        (rng >> 16) as u16
    };
    for &c in &[2u16, 0x100B, 0x8000, 0xFFFF, 12345] {
        let fc = FoldCoeff::new(c);
        for &n in &[16usize, 48, 80] {
            let v0: Vec<u16> = (0..n).map(|_| word()).collect();
            // `u = 0` makes the forward butterfly's u output exactly
            // the product.
            let mut u = vec![0u16; n];
            let mut v = v0.clone();
            butterfly(&mut u, &mut v, &fc, false);
            let mut scaled = v0.clone();
            scale(&mut scaled, &fc);
            assert_eq!(u, scaled, "scale vs butterfly c={c:#x} n={n}");
        }
    }
}

/// `butterfly_two_pass` finishes whatever the multi kernel declined
/// with `MulTable::xor_mul_into`, because the 512-bit GFNI arm consumes
/// 64 bytes at a time and returns short for a span sized to the 32-byte
/// unit every other kernel here takes.
///
/// NO MAC SELECTS THAT KERNEL - `butterfly` takes the NEON sha3 arm on
/// aarch64 before it ever reaches the fixed function - but the fleet
/// DOES have one that does: a Zen 4 EPYC linux box carrying
/// avx512f + avx512bw + gfni (named in memory
/// `nzbfast-simd-arm-rots-when-no-box-selects-it`, with the ssh
/// details - a hostname does not belong in a file that ships).
/// Verified there 7 Sep 2026 by lifting this
/// one file into a standalone crate (it imports nothing but
/// `std::sync::OnceLock`, so the lift is a copy plus an allow header,
/// and that memory topic carries the recipe): with the remainder
/// branch removed,
/// `butterfly_matches_the_definition_and_inverts` panics `left: 0,
/// right: 16`, the same two numbers CI reported; with it, 14 of 14 pass.
/// Do that A/B rather than reasoning about this arm - it takes about a
/// minute.
///
/// What this test adds on top, and what makes it worth running on a Mac
/// too, is the property the branch rests on: a fold split into two calls
/// must equal the same fold done in one, at every split. If that stops
/// holding, the remainder is silently wrong on hardware most machines
/// here cannot reach.
#[test]
fn a_fold_finished_in_two_calls_equals_one_call() {
    let mut rng = 0x5EED_1234u64;
    let mut word = || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        (rng >> 16) as u16
    };
    for &c in &[2u16, 0x100B, 0x8000, 0xFFFF, 12345] {
        let table = MulTable::new(c);
        for &n in &[16usize, 32, 48, 64, 80, 129] {
            let dst0: Vec<u16> = (0..n).map(|_| word()).collect();
            let src: Vec<u16> = (0..n).map(|_| word()).collect();
            let src_bytes = words_as_bytes(&src);
            let mut whole = dst0.clone();
            table.xor_mul_into(&mut whole, src_bytes);
            // Every split, including the two the GFNI-512 arm actually
            // produces (0, and a multiple of 32 words).
            for split in 0..=n {
                let mut parts = dst0.clone();
                table.xor_mul_into(&mut parts[..split], &src_bytes[..split * 2]);
                table.xor_mul_into(&mut parts[split..], &src_bytes[split * 2..]);
                assert_eq!(
                    parts, whole,
                    "fold split at {split} of {n} words differs, c={c:#x}"
                );
            }
        }
    }
}

#[test]
fn known_values() {
    // 2^16 mod the generator polynomial: 0x1100B with bit 16 dropped.
    assert_eq!(pow2(16), 0x100B);
    assert_eq!(pow2(0), 1);
    assert_eq!(pow2(1), 2);
    // Full cycle wraps to 1.
    assert_eq!(pow2(ORDER as u64), 1);
}

#[test]
fn field_axioms_sampled() {
    let xs = [1u16, 2, 3, 0x100B, 0x8000, 0xFFFF, 12345];
    for &a in &xs {
        assert_eq!(mul(a, 1), a);
        assert_eq!(mul(a, 0), 0);
        assert_eq!(mul(a, inv(a)), 1, "a·a⁻¹ = 1 for {a:#x}");
        for &b in &xs {
            assert_eq!(mul(a, b), mul(b, a));
            for &c in &xs {
                assert_eq!(mul(a, mul(b, c)), mul(mul(a, b), c));
                // Distributivity over XOR (field addition).
                assert_eq!(mul(a, b ^ c), mul(a, b) ^ mul(a, c));
            }
        }
    }
}

#[test]
fn mul_table_matches_scalar_mul() {
    for c in [0u16, 1, 2, 0x1234, 0xFFFF] {
        let t = MulTable::new(c);
        for w in [0u16, 1, 0xFF, 0x100, 0xABCD, 0xFFFF] {
            assert_eq!(t.mul(w), mul(c, w), "c={c:#x} w={w:#x}");
        }
    }
}

#[test]
fn xor_mul_words_matches_per_word_mul() {
    let mut state = 0x243F6A8885A308D3u64;
    let mut rng = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for c in [0u16, 1, 2, 0x1234, 0xABCD, 0xFFFF] {
        let t = MulTable::new(c);
        for len in [0usize, 1, 15, 16, 17, 64, 4097] {
            let src: Vec<u16> = (0..len).map(|_| rng() as u16).collect();
            let base: Vec<u16> = (0..len).map(|_| rng() as u16).collect();
            let mut want = base.clone();
            for (d, s) in want.iter_mut().zip(&src) {
                *d ^= mul(c, *s);
            }
            let mut got = base.clone();
            t.xor_mul_words(&mut got, &src);
            assert_eq!(got, want, "c={c:#x} len={len}");
        }
    }
}

#[test]
fn xor_mul_into_handles_short_and_odd_src() {
    let c = 0x1234u16;
    let t = MulTable::new(c);
    let src = [1u8, 2, 3, 4, 5]; // odd length: last word is 0x0005
    let mut dst = vec![0u16; 4];
    t.xor_mul_into(&mut dst, &src);
    assert_eq!(dst[0], mul(c, u16::from_le_bytes([1, 2])));
    assert_eq!(dst[1], mul(c, u16::from_le_bytes([3, 4])));
    assert_eq!(dst[2], mul(c, 5));
    assert_eq!(dst[3], 0, "beyond src stays untouched (zero pad)");
}

/// The multi-source fused kernel must equal per-source table folds
/// exactly: every group width up to the platform maximum, coefficient
/// classes incl. 0/1/low-byte-only/high-byte-only, random data, and
/// a non-zero starting dst so the accumulate is exercised. This is
/// the differential oracle for the ParPar-style pmull port - a wrong
/// Barrett reduction silently corrupts every repair.
/// The planar (prepared-layout) AVX2 fold is the fused fold, byte for
/// byte: same words consumed, same destination, over every fan-in it
/// accepts, coefficient pools that include zero and one, unaligned
/// source slices and a destination that is not zero to begin with.
/// Only reachable on an x86 part where the nibble kernel is selected
/// and `NZBFAST_FOLD_PLANAR=1` is set - the differential the review
/// lane ran out of tree (1,600 cases, 4 Sep 2026), in the tree.
#[test]
#[cfg(target_arch = "x86_64")]
fn planar_fold_matches_prepared_fold() {
    if !PreparedSources::enabled() {
        return;
    }
    let mut state = 0x5EED_1234_ABCD_0001u64;
    let mut rng = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let pool = [
        0u16, 1, 2, 0x00FF, 0xFF00, 0x0101, 0x100B, 0x8000, 0xFFFF, 0x1234, 0xABCD,
    ];
    let mut cases = 0usize;
    for n in 1..=4usize {
        for words in [32usize, 64, 96, 480, 2048, 2080, 4096] {
            for skew in [0usize, 1, 3] {
                let owned: Vec<Vec<u8>> = (0..n)
                    .map(|_| (0..words * 2 + skew).map(|_| rng() as u8).collect())
                    .collect();
                let srcs: Vec<&[u8]> = owned.iter().map(|v| &v[skew..]).collect();
                let coeffs: Vec<FoldCoeff> = (0..n)
                    .map(|i| FoldCoeff::new(pool[(rng() as usize + i) % pool.len()]))
                    .collect();
                let refs: Vec<&FoldCoeff> = coeffs.iter().collect();
                let base: Vec<u16> = (0..words).map(|_| rng() as u16).collect();
                let mut want = base.clone();
                let done_want = xor_mul_multi_prepared(&mut want, &srcs, &refs);
                let mut packed = PreparedSources::default();
                assert!(packed.prepare(&srcs), "prepare refused n={n} words={words}");
                let mut got = base.clone();
                let done_got = packed.fold(&mut got, &refs);
                assert_eq!(
                    done_got, done_want,
                    "consumed n={n} words={words} skew={skew}"
                );
                assert_eq!(got, want, "n={n} words={words} skew={skew}");
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 4 * 7 * 3);
}

/// [`split_tables`] is the subset walk over [`power_chain`] where the
/// old form was 512 calls to [`mul`], so nothing but this test says the
/// two agree - and they must agree for EVERY coefficient, because these
/// tables are `MulTable`'s scalar multiply on every arch and the WHOLE
/// fold on one with no SIMD kernel. Exhaustive over all 65,536: 33.5 M
/// comparisons, well under a second natively, and the emulated targets
/// that select the table for real are exactly the ones that cannot
/// afford a sampled pin.
#[test]
fn split_tables_match_mul() {
    for c in 0..=u16::MAX {
        let (lo, hi) = split_tables(c);
        for b in 0..256u16 {
            assert_eq!(lo[b as usize], mul(c, b), "c={c:04x} lo[{b}]");
            assert_eq!(hi[b as usize], mul(c, b << 8), "c={c:04x} hi[{b}]");
        }
    }
}

/// The zero and identity shortcuts in [`xor_mul_single_into`] must be
/// the table fold's own answer, not merely a plausible one - they skip
/// a [`FoldTable`] entirely, so a wrong odd-byte or short-source rule
/// would corrupt a repair only on a kernel-less part, which is the
/// configuration no box on this fleet runs. Compared against the table
/// path for every coefficient class and both source parities.
#[test]
fn single_fold_shortcuts_match_the_table_fold() {
    let mut state = 0x5DEECE66Du64;
    let mut byte = || {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        (state >> 33) as u8
    };
    let src: Vec<u8> = (0..64).map(|_| byte()).collect();
    let base: Vec<u16> = (0..32)
        .map(|_| u16::from(byte()) << 8 | u16::from(byte()))
        .collect();
    for c in [0u16, 1, 2, 3, 0x8000, 0x100B, 0xFFFF] {
        // Whole words, an odd trailing byte, a source shorter than dst
        // and an empty one: the four shapes the shortcut has to get
        // right on its own.
        for len in [64usize, 63, 31, 30, 1, 0] {
            let mut want = base.clone();
            FoldTable::new(c).xor_mul_into(&mut want, &src[..len]);
            let mut got = base.clone();
            xor_mul_single_into(&mut got, &src[..len], c);
            assert_eq!(got, want, "c={c:04x} len={len}");
        }
    }
}

#[test]
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn nibble_tables_match_mul() {
    // The basis form is the chain form, for every coefficient.
    for c in 0..=u16::MAX {
        assert_eq!(nibble_tables(c), nibble_tables_chain(c), "coefficient {c}");
    }
    // Every nibble position and value, for a spread of coefficients
    // including the ones whose xtime chain crosses the reduction.
    let mut state = 0xC0FFEE1234567890u64;
    let mut coeffs: Vec<u16> = vec![0, 1, 2, 3, 0x8000, 0x8001, 0xFFFF, 0x100B, 0x1234];
    for _ in 0..2000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        coeffs.push(state as u16);
    }
    for c in coeffs {
        let (nl, nh) = nibble_tables(c);
        for j in 0..4 {
            for n in 0..16u16 {
                let p = mul(c, n << (4 * j));
                assert_eq!(nl[j][n as usize], p as u8, "c={c:04x} j={j} n={n}");
                assert_eq!(nh[j][n as usize], (p >> 8) as u8, "c={c:04x} j={j} n={n}");
            }
        }
    }
}

/// The scheduling granule must be the SELECTED kernel's real
/// destination chunk, not a guess: a buffer of exactly one granule is
/// consumed whole, and - where the granule is wider than 16 - half a
/// granule is consumed by nothing at all. That second half is the
/// point. `fold_parallel` and `fold_chunk_multi` align their column
/// units and cache tiles to this number precisely so no unit ends
/// mid-chunk and falls to the per-source remainder path, so a kernel
/// that later changes its chunk width must fail here rather than
/// quietly cost the scheduler a fold table per (row, group, source).
///
/// This pins the SHIPPING geometry, so it reads the unforced
/// function: `NZBFAST_GF16_GRANULE` deliberately overrides it and
/// nothing here sets that variable (a `OnceLock` read is per
/// process, and the one-process suite would carry a forced value
/// into every later test in the binary).
#[test]
fn schedule_granule_is_the_selected_kernels_chunk() {
    let fan_in = multi_fold_width();
    let granule = multi_fold_schedule_granule_words(fan_in);
    assert!(
        granule == 16 || granule == 32,
        "granule {granule} is not one of the two kernel chunk widths"
    );
    assert_eq!(
        granule == 32,
        cfg!(target_arch = "x86_64") && fan_in == 12,
        "only the twelve-source 512-bit GFNI arm consumes 32 words \
         (fan_in={fan_in}, arch x86_64={})",
        cfg!(target_arch = "x86_64")
    );
    // A box only ever dispatches to its BEST kernel, so the checks
    // above see exactly one arm - and that is how the AVX2 nibble
    // arm shipped scheduled at 16 words while consuming 64 bytes
    // (3 Sep 2026, red on the 4-vCPU x86-64 CI runner). It is
    // unreachable by dispatch on both parts the granule was
    // developed on: aarch64 folds 32-byte chunks and a Zen 4 with
    // AVX-512 GFNI takes the 512-bit arm. So pin EVERY arm this CPU
    // can run against the granule its row of the table claims, not
    // just the selected one - the arm a future GFNI-everywhere fleet
    // stops dispatching to is exactly the arm that rots.
    #[cfg(target_arch = "x86_64")]
    {
        // 64 bytes covers the widest arm's granule; each probe reads
        // only the first `want * 2`.
        let wide: Vec<u8> = (0..64).map(|i| i as u8).collect();
        let srcs = [wide.as_slice()];
        let whole = |want: usize, got: usize, arm: &str| {
            assert_eq!(
                got, want,
                "{arm} must consume its {want}-word granule whole"
            );
        };
        if is_x86_feature_detected!("avx2") {
            let mut dst = vec![0u16; 16];
            // SAFETY: AVX2 verified by the detect; the source covers
            // dst's full byte length.
            let got = unsafe { xor_mul_multi_avx2(&mut dst, &srcs, &[0x1234]) };
            whole(16, got, "the AVX2 nibble kernel");
        }
        if is_x86_feature_detected!("ssse3") {
            let mut dst = vec![0u16; 16];
            // SAFETY: SSSE3 verified by the detect; source as above.
            let got = unsafe { xor_mul_multi_ssse3(&mut dst, &srcs, &[0x1234]) };
            whole(16, got, "the SSSE3 nibble kernel");
        }
        if is_x86_feature_detected!("gfni") && is_x86_feature_detected!("avx2") {
            let mut dst = vec![0u16; 16];
            // SAFETY: GFNI and AVX2 verified by the detect; source as
            // above.
            let got = unsafe { xor_mul_multi_gfni(&mut dst, &srcs, &[0x1234]) };
            whole(16, got, "the GFNI affine2x kernel");
        }
        if is_x86_feature_detected!("avx512f")
            && is_x86_feature_detected!("avx512bw")
            && is_x86_feature_detected!("gfni")
        {
            let mut dst = vec![0u16; 32];
            // SAFETY: the three features verified by the detects;
            // source as above.
            let got = unsafe { xor_mul_multi_gfni512(&mut dst, &srcs, &[0x1234]) };
            whole(32, got, "the 512-bit GFNI kernel");
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        let wide: Vec<u8> = (0..32).map(|i| i as u8).collect();
        let srcs = [wide.as_slice()];
        let mut dst = vec![0u16; 16];
        // SAFETY: plain NEON is baseline on aarch64; the source
        // covers dst's full byte length.
        let got = unsafe { xor_mul_multi_neon(&mut dst, &srcs, &[0x1234]) };
        assert_eq!(
            got, 16,
            "the NEON PMULL kernel must consume its granule whole"
        );
        if std::arch::is_aarch64_feature_detected!("sha3") {
            let mut dst = vec![0u16; 16];
            // SAFETY: sha3 verified by the detect; source as above.
            let got = unsafe { xor_mul_multi_neon_sha3(&mut dst, &srcs, &[0x1234]) };
            assert_eq!(
                got, 16,
                "the NEON sha3 kernel must consume its granule whole"
            );
        }
    }
    if fan_in == 0 {
        return; // no fused kernel selected; the table path schedules
    }
    let src: Vec<u8> = (0..granule * 2).map(|i| i as u8).collect();
    let srcs = [src.as_slice()];
    let mut dst = vec![0u16; granule];
    assert_eq!(
        xor_mul_multi_into(&mut dst, &srcs, &[0x1234]),
        granule,
        "one granule must be consumed whole, or every aligned unit \
         still ends mid-chunk"
    );
    if granule > 16 {
        let mut half = vec![0u16; granule / 2];
        assert_eq!(
            xor_mul_multi_into(&mut half, &srcs, &[0x1234]),
            0,
            "half a granule must reach no kernel chunk, or the \
             granule is wider than the kernel actually needs"
        );
    }
}

#[test]
fn xor_mul_multi_matches_single_source_folds() {
    let width = multi_fold_width();
    if width == 0 {
        return; // no multi kernel on this arch (yet)
    }
    let mut state = 0x0123456789ABCDEFu64;
    let mut rng = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let coeff_pool = [
        0u16, 1, 2, 0x00FF, 0xFF00, 0x0101, 0x100B, 0x8000, 0xFFFF, 0x1234, 0xABCD,
    ];
    // `width + 2` deliberately overshoots the group width: callers
    // never do, but the kernels accept it (the x86 affine2x kernel
    // splits internally into register-resident groups; the aarch64
    // kernels loop sources), and the split path must stay correct.
    for n in 1..=width + 2 {
        for words in [16usize, 17, 32, 48, 160, 4096, 4097] {
            let srcs_owned: Vec<Vec<u8>> = (0..n)
                .map(|_| (0..words * 2).map(|_| rng() as u8).collect())
                .collect();
            let srcs: Vec<&[u8]> = srcs_owned.iter().map(|v| v.as_slice()).collect();
            let coeffs: Vec<u16> = (0..n)
                .map(|i| coeff_pool[(rng() as usize + i) % coeff_pool.len()])
                .collect();
            let base: Vec<u16> = (0..words).map(|_| rng() as u16).collect();
            let mut want = base.clone();
            for (s, c) in srcs.iter().zip(&coeffs) {
                MulTable::new(*c).xor_mul_into(&mut want, s);
            }
            let mut got = base.clone();
            let done = xor_mul_multi_into(&mut got, &srcs, &coeffs);
            // Kernels work in whole chunks (16 words on aarch64, 32
            // on x86); whatever they leave is finished per-source.
            assert!(
                done <= words && done.is_multiple_of(16),
                "chunk accounting n={n} words={words} done={done}"
            );
            // The prepared entry is the same kernel with its table
            // build hoisted: same words consumed, same bytes.
            let prepared: Vec<FoldCoeff> = coeffs.iter().map(|&c| FoldCoeff::new(c)).collect();
            let prefs: Vec<&FoldCoeff> = prepared.iter().collect();
            let mut got_p = base.clone();
            let done_p = xor_mul_multi_prepared(&mut got_p, &srcs, &prefs);
            assert_eq!(
                done_p, done,
                "prepared consumed differently n={n} words={words}"
            );
            assert_eq!(
                got_p, got,
                "prepared differs n={n} words={words} coeffs={coeffs:x?}"
            );
            for (s, c) in srcs.iter().zip(&coeffs) {
                MulTable::new(*c).xor_mul_into(&mut got[done..], &s[done * 2..]);
            }
            assert_eq!(got, want, "n={n} words={words} coeffs={coeffs:x?}");
            // All-one is a dedicated direct-XOR SIMD kernel (the
            // exponent-0 repair row). Pin it for every source
            // count and chunk boundary rather than relying on the
            // random coefficient pool to happen to select it.
            let ones = vec![1u16; n];
            let mut want_ones = base.clone();
            for src in &srcs {
                MulTable::new(1).xor_mul_into(&mut want_ones, src);
            }
            let mut got_ones = base.clone();
            let done = xor_mul_multi_into(&mut got_ones, &srcs, &ones);
            for src in &srcs {
                MulTable::new(1).xor_mul_into(&mut got_ones[done..], &src[done * 2..]);
            }
            assert_eq!(got_ones, want_ones, "all-one n={n} words={words}");
            // Drive BOTH aarch64 kernels directly - runtime dispatch
            // only ever exercises the best one this CPU has.
            #[cfg(target_arch = "aarch64")]
            {
                let mut got = base.clone();
                // SAFETY: plain NEON is baseline on aarch64; every src
                // holds words * 2 bytes, covering dst's byte length.
                let done = unsafe { xor_mul_multi_neon(&mut got, &srcs, &coeffs) };
                for (s, c) in srcs.iter().zip(&coeffs) {
                    MulTable::new(*c).xor_mul_into(&mut got[done..], &s[done * 2..]);
                }
                assert_eq!(got, want, "plain-neon n={n} words={words}");
                if std::arch::is_aarch64_feature_detected!("sha3") {
                    let mut got = base.clone();
                    // SAFETY: sha3 verified by the detect above;
                    // source coverage as above.
                    let done = unsafe { xor_mul_multi_neon_sha3(&mut got, &srcs, &coeffs) };
                    for (s, c) in srcs.iter().zip(&coeffs) {
                        MulTable::new(*c).xor_mul_into(&mut got[done..], &s[done * 2..]);
                    }
                    assert_eq!(got, want, "sha3 n={n} words={words}");
                }
            }
            // Same forcing for the x86 GFNI multi kernel (dispatch
            // covers it only on gfni+avx2 hardware, which is also
            // the only place it can run - but force it so the test
            // name pins WHICH kernel failed).
            #[cfg(target_arch = "x86_64")]
            if is_x86_feature_detected!("gfni") && is_x86_feature_detected!("avx2") {
                let mut got = base.clone();
                // SAFETY: GFNI and AVX2 verified by the detect above;
                // the kernel clamps to the shortest source.
                let done = unsafe { xor_mul_multi_gfni(&mut got, &srcs, &coeffs) };
                for (s, c) in srcs.iter().zip(&coeffs) {
                    MulTable::new(*c).xor_mul_into(&mut got[done..], &s[done * 2..]);
                }
                assert_eq!(got, want, "gfni-multi n={n} words={words}");
            }
            #[cfg(target_arch = "x86_64")]
            if is_x86_feature_detected!("avx512f")
                && is_x86_feature_detected!("avx512bw")
                && is_x86_feature_detected!("gfni")
            {
                let mut got = base.clone();
                // SAFETY: the three features verified by the detects
                // above; the kernel clamps to the shortest source.
                let done = unsafe { xor_mul_multi_gfni512(&mut got, &srcs, &coeffs) };
                assert!(
                    done.is_multiple_of(16),
                    "gfni512 chunk accounting done={done}"
                );
                for (s, c) in srcs.iter().zip(&coeffs) {
                    MulTable::new(*c).xor_mul_into(&mut got[done..], &s[done * 2..]);
                }
                assert_eq!(got, want, "gfni512-multi n={n} words={words}");
            }
            // And the two shuffle kernels, which dispatch never picks
            // on a GFNI box but which every other x86 runs.
            #[cfg(target_arch = "x86_64")]
            if is_x86_feature_detected!("avx2") {
                let mut got = base.clone();
                // SAFETY: AVX2 verified by the detect above; the
                // kernel clamps to the shortest source.
                let done = unsafe { xor_mul_multi_avx2(&mut got, &srcs, &coeffs) };
                assert!(done.is_multiple_of(16), "avx2 chunk accounting done={done}");
                for (s, c) in srcs.iter().zip(&coeffs) {
                    MulTable::new(*c).xor_mul_into(&mut got[done..], &s[done * 2..]);
                }
                assert_eq!(got, want, "avx2-multi n={n} words={words}");
            }
            #[cfg(target_arch = "x86_64")]
            if is_x86_feature_detected!("ssse3") {
                let mut got = base.clone();
                // SAFETY: SSSE3 verified by the detect above; same clamp.
                let done = unsafe { xor_mul_multi_ssse3(&mut got, &srcs, &coeffs) };
                assert!(
                    done.is_multiple_of(16),
                    "ssse3 chunk accounting done={done}"
                );
                for (s, c) in srcs.iter().zip(&coeffs) {
                    MulTable::new(*c).xor_mul_into(&mut got[done..], &s[done * 2..]);
                }
                assert_eq!(got, want, "ssse3-multi n={n} words={words}");
            }
        }
    }
}

/// The uneven-source fixture the two clamp tests below share: a 47-byte
/// source beside a 96-byte one, so only ONE 32-byte chunk is legal and a
/// kernel that clamped to the LONGEST source would read out of bounds.
/// Returns (sources, starting dst, the scalar oracle's answer).
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn xor_multi_clamp_fixture() -> (Vec<Vec<u8>>, Vec<u16>, Vec<u16>) {
    let srcs = vec![vec![0x5a; 47], vec![0xa5; 96]];
    let base: Vec<u16> = (0..64).map(|i| i as u16 * 257).collect();
    let mut want = base.clone();
    for src in &srcs {
        MulTable::new(1).xor_mul_into(&mut want[..16], &src[..32]);
    }
    (srcs, base, want)
}

/// Each direct-XOR kernel gets its own test rather than one test with
/// per-arch arms inside it: a reference under a STATEMENT `#[cfg]` does
/// not carry that cfg to a reader (`cfg-symbol-gate` reads the enclosing
/// item's), so the kernel and the only thing that names it share one
/// `#[cfg]` line here.
#[test]
#[cfg(target_arch = "aarch64")]
fn xor_multi_neon_clamps_to_shortest_source() {
    let (srcs, mut got, want) = xor_multi_clamp_fixture();
    let refs: Vec<&[u8]> = srcs.iter().map(Vec::as_slice).collect();
    // SAFETY: NEON is baseline on aarch64; the intentionally uneven
    // source lengths exercise the kernel's shortest-source clamp.
    let done = unsafe { xor_multi_neon(&mut got, &refs) };
    assert_eq!(done, 16);
    assert_eq!(got, want);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn xor_multi_x86_clamps_to_shortest_source() {
    let (srcs, base, want) = xor_multi_clamp_fixture();
    let refs: Vec<&[u8]> = srcs.iter().map(Vec::as_slice).collect();
    // Both x86 kernels are driven directly - runtime dispatch only ever
    // exercises the best one this CPU has, which would leave the SSE2
    // fallback untested on every box in the fleet.
    let mut got = base.clone();
    // SAFETY: SSE2 is baseline on x86_64; uneven source lengths
    // exercise the shortest-source clamp.
    let done = unsafe { xor_multi_sse2(&mut got, &refs) };
    assert_eq!(done, 16);
    assert_eq!(got, want);
    if is_x86_feature_detected!("avx2") {
        let mut got = base;
        // SAFETY: AVX2 verified by the detect above; same clamp.
        let done = unsafe { xor_multi_avx2(&mut got, &refs) };
        assert_eq!(done, 16);
        assert_eq!(got, want);
    }
}

/// `xor_mul_into` must match a straight per-word GF multiply for every
/// length across, and just past, the NEON 32-byte chunk boundary and
/// odd tails - on aarch64 this is the NEON path vs a scalar oracle,
/// with a non-zero starting `dst` so the accumulate (`^=`) is exercised.
#[test]
fn xor_mul_into_matches_scalar_all_lengths() {
    let mut state = 0x9E3779B97F4A7C15u64;
    let mut rng = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for c in [0u16, 1, 2, 0x00FF, 0x0101, 0x1234, 0xABCD, 0xFFFF] {
        let t = MulTable::new(c);
        for len in [0usize, 1, 2, 3, 15, 16, 31, 32, 33, 64, 65, 127, 4096, 4097] {
            let src: Vec<u8> = (0..len).map(|_| rng() as u8).collect();
            let words = len.div_ceil(2);
            let base: Vec<u16> = (0..words + 3).map(|_| rng() as u16).collect();
            // Oracle: start from `base`, add c·word per src word.
            let mut want = base.clone();
            for (i, s) in src.chunks(2).enumerate() {
                let w = if s.len() == 2 {
                    u16::from_le_bytes([s[0], s[1]])
                } else {
                    s[0] as u16
                };
                want[i] ^= mul(c, w);
            }
            let mut got = base.clone();
            t.xor_mul_into(&mut got, &src);
            assert_eq!(got, want, "c={c:#x} len={len}");

            // On x86_64 also drive each kernel directly - runtime
            // dispatch would only ever exercise the best one the CPU
            // has (e.g. AVX2 shadowing SSSE3).
            #[cfg(target_arch = "x86_64")]
            {
                if is_x86_feature_detected!("ssse3") {
                    let mut got = base.clone();
                    // SAFETY: SSSE3 verified by the detect above; got
                    // holds words + 3 elements, a word for every byte
                    // pair of src.
                    let done = unsafe { fold_ssse3(&t.nl, &t.nh, &mut got, &src) };
                    MulTable::xor_mul_scalar(&t.lo, &t.hi, &mut got[done..], &src[done * 2..]);
                    assert_eq!(got, want, "ssse3 c={c:#x} len={len}");
                }
                if is_x86_feature_detected!("avx2") {
                    let mut got = base.clone();
                    // SAFETY: AVX2 verified by the detect above; got
                    // covers src as above.
                    let done = unsafe { fold_avx2(&t.nl, &t.nh, &mut got, &src) };
                    MulTable::xor_mul_scalar(&t.lo, &t.hi, &mut got[done..], &src[done * 2..]);
                    assert_eq!(got, want, "avx2 c={c:#x} len={len}");
                }
                if is_x86_feature_detected!("gfni") && is_x86_feature_detected!("avx2") {
                    let mut got = base.clone();
                    // SAFETY: GFNI and AVX2 verified by the detect
                    // above; got covers src as above.
                    let done = unsafe { fold_gfni(&t.affine, &mut got, &src) };
                    MulTable::xor_mul_scalar(&t.lo, &t.hi, &mut got[done..], &src[done * 2..]);
                    assert_eq!(got, want, "gfni c={c:#x} len={len}");
                }
            }
        }
    }
}

/// [`FoldTable`] must match the same per-word oracle as
/// [`MulTable::xor_mul_into`] at every length class - in particular
/// the sub-chunk tails and the odd trailing byte, which exercise
/// the nibble-table scalar path the compact table falls back on.
#[test]
fn fold_table_matches_scalar_all_lengths() {
    let mut state = 0xD1B54A32D192ED03u64;
    let mut rng = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for c in [0u16, 1, 2, 0x00FF, 0x0101, 0x1234, 0xABCD, 0xFFFF] {
        let t = FoldTable::new(c);
        for len in [0usize, 1, 2, 3, 15, 16, 31, 32, 33, 64, 65, 127, 4096, 4097] {
            let src: Vec<u8> = (0..len).map(|_| rng() as u8).collect();
            let words = len.div_ceil(2);
            let base: Vec<u16> = (0..words + 3).map(|_| rng() as u16).collect();
            let mut want = base.clone();
            for (i, s) in src.chunks(2).enumerate() {
                let w = if s.len() == 2 {
                    u16::from_le_bytes([s[0], s[1]])
                } else {
                    s[0] as u16
                };
                want[i] ^= mul(c, w);
            }
            let mut got = base.clone();
            t.xor_mul_into(&mut got, &src);
            assert_eq!(got, want, "fold-table c={c:#x} len={len}");
        }
    }
}

/// The kernel selection, `scale_available()` and the remedy text are one
/// rule read three ways, and a diagnostic that disagreed with the
/// dispatch would be worse than none - TODO 340 exists because a user
/// was told nothing; being told the WRONG thing is the next defect
/// along.
///
/// Host-dependent by nature, so what is pinned is the INVARIANT rather
/// than the sentence: exactly the scalar arm has a remedy, and exactly
/// the scalar arm is unavailable.
#[test]
fn the_scale_kernel_its_availability_and_its_remedy_agree() {
    let k = scale_kernel();
    assert_eq!(
        scale_available(),
        k != ScaleKernel::Scalar,
        "scale_available must be exactly 'not the scalar arm', got {k:?}"
    );
    assert_eq!(
        k.remedy().is_some(),
        !scale_available(),
        "a remedy is owed exactly when there is no vector kernel, arm {k:?}"
    );
    assert!(!k.name().is_empty());
    // THE REGRESSION GUARD THE SSSE3 GAP NEEDED. Any x86-64 part with
    // `pshufb` and no GFNI now has a vector scale, so landing on the
    // scalar arm there is a bug rather than an old CPU. Before
    // `scale_ssse3` this failed on every pre-Haswell Intel and
    // pre-Excavator AMD - exactly the population `--fast` was silently
    // declining for.
    //
    // THE GFNI EXCLUSION IS GONE, as its own comment instructed. It read
    // `&& !gfni256_available()` while the row-op gate still decided
    // `scale` - a GFNI part reached neither nibble arm, because
    // `nibble_kernel_selected` is false exactly when the CPU has GFNI.
    // That hole is closed, so the assertion is unconditional again, and
    // leaving the exclusion in would have hidden the next gap the way it
    // hid this one.
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("ssse3") {
        assert!(
            scale_available(),
            "an x86-64 part with ssse3 must have a vector scale kernel, got {k:?}"
        );
    }

    // The two questions were separate while a GFNI part had the kernel
    // (`scale_available`) and the additive leaf still folded through a
    // temporary (`inplace_scale_preferred`) pending its own measurement.
    // That measurement landed on 11 Sep 2026 and the x86 arm went with
    // it, so they now agree on every target. Both assertions are kept
    // and one is TIGHTENED rather than dropped: the invariant that
    // matters is still that preference cannot outrun existence, and
    // pinning the equality is what would catch a target quietly
    // re-cutting the seam without saying so.
    assert!(
        !inplace_scale_preferred() || scale_available(),
        "preference cannot outrun existence"
    );
    assert_eq!(
        inplace_scale_preferred(),
        scale_available(),
        "the leaf's arm is a pass-through now - re-introducing a divergence \
         needs its own measurement and its own comment, not a silent edit"
    );
    if let Some(r) = k.remedy() {
        // It has to say what to DO, not merely that something is wrong.
        assert!(r.len() > 20, "remedy is not actionable: {r:?}");
        // House copy rules reach this: it is printed to a user.
        assert!(!r.contains('\u{2014}') && !r.contains('\u{2013}'), "{r:?}");
    }
}
