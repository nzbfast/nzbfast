//! Exact-output oracle for the GF16 fold scheduler's tile and
//! column-chunk boundaries.
//!
//! Each output row is recomputed independently through
//! `MulTable::xor_mul_into` and compared with what the scheduler
//! produced, so a geometry change that leaves a tail in the tile or the
//! column chunk fails here rather than in a benchmark's noise. Three of
//! the eight shapes straddle a 16-word edge; the last two are
//! production-size (89 and 409 rows over 32,768 words). The printed FNV
//! hash per shape lets two builds be compared by eye.

use nzbkit::gf16::{self, MulTable};
use nzbkit::par2repair::bench_fold;

fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn one(rows: usize, nsrc: usize, words: usize) -> u64 {
    let mut state = 0x243f_6a88_85a3_08d3u64 ^ rows as u64 ^ (words as u64) << 17;
    let srcs_owned: Vec<Vec<u8>> = (0..nsrc)
        .map(|_| (0..words * 2).map(|_| next(&mut state) as u8).collect())
        .collect();
    let srcs: Vec<&[u8]> = srcs_owned.iter().map(Vec::as_slice).collect();
    let coeffs: Vec<Vec<u16>> = (0..rows)
        .map(|j| {
            (0..nsrc)
                .map(|i| gf16::pow2((j as u64 + 3) * (i as u64 + 5)))
                .collect()
        })
        .collect();
    let base: Vec<Vec<u16>> = (0..rows)
        .map(|_| (0..words).map(|_| next(&mut state) as u16).collect())
        .collect();
    let mut want = base.clone();
    for (j, row) in want.iter_mut().enumerate() {
        for (i, src) in srcs.iter().enumerate() {
            MulTable::new(coeffs[j][i]).xor_mul_into(row, src);
        }
    }
    let mut got = base;
    bench_fold(&mut got, &srcs, &|j, i| coeffs[j][i]);
    assert_eq!(got, want, "rows={rows} nsrc={nsrc} words={words}");
    got.iter().flatten().fold(0xcbf2_9ce4_8422_2325, |h, &w| {
        (h ^ w as u64).wrapping_mul(0x100_0000_01b3)
    })
}

fn main() {
    for shape in [
        (3, 13, 15),
        (3, 13, 16),
        (3, 13, 17),
        (5, 25, 31),
        (5, 25, 32),
        (5, 25, 33),
        // Production-size ranges whose old 16-word geometry leaves an
        // AVX-512 tail in the tile (89) or tile and column chunk (409).
        (89, 12, 32_768),
        (409, 12, 32_768),
    ] {
        println!("{shape:?} {:016x}", one(shape.0, shape.1, shape.2));
    }
}
