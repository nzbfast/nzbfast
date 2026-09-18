//! mcbench - prices the static musl `memcpy` (`memops::copy_disjoint`)
//! against the `compiler_rt.memcpy.memcpyFast` a static musl download links
//! today, over a RELATIVE-ALIGNMENT sweep.
//! Claim `memcpy-misaligned-relalign-17sep`.
//!
//! WHY A NEW GRID. `harness/mmbench.rs` (16 Sep) varied `n`, the
//! gap and the direction; the 15 Sep round varied `n` alone and moved source
//! and destination at the SAME offset. Neither varies `(src - dest) % 8`
//! with the ranges DISJOINT, which is the axis `copy_disjoint` collapses on:
//! it aligns the DESTINATION and then runs `rep movsq`, which wants both
//! ends aligned. So every cell here is a (length, dest alignment, source
//! alignment) triple and the reported key is the relative one.
//!
//! TWO BINARIES FROM ONE SOURCE, the method all three landed memops rounds
//! used: `base` (no `--features cand`, so `compiler_rt`'s weak symbol
//! serves) and `cand` (`fast_mem_ops!()` stamped in, so the strong one wins
//! the link). BOTH arms reach the routine through the LINKED symbol, so the
//! ratio is the routine's and not a call-shape difference. `nm` on the two
//! binaries is what proves which is which.
//!
//! `src/memops.rs` is a SYMLINK to the real `crates/nzbkit-base/src/memops.rs`
//! for the `cand` build, so it cannot measure a stale copy. The probe
//! variants retarget that symlink at a generated file and say so in their
//! own name.

#[path = "memops.rs"]
mod memops;

#[cfg(feature = "cand")]
fast_mem_ops!();

use std::time::Instant;

extern "C" {
    #[link_name = "memcpy"]
    fn linked_memcpy(d: *mut u8, s: *const u8, n: usize) -> *mut u8;
}

/// 256 MiB: the two regions are 128 MiB apart so the largest cell can never
/// overlap and neither region can sit in the other's cache set by accident.
const ARENA: usize = 256 << 20;
const DBASE: usize = 1 << 20;
const SBASE: usize = 128 << 20;

/// Lengths. Below `STRING_OP_MIN` (2,048) the vector arm serves, above it the
/// string op does, so the ladder is dense either side of that crossover and
/// then thins out to 4 MiB (past this part's 32 MiB L3 per CCD for a pair).
const NS: &[usize] = &[
    1024, 2048, 3072, 4096, 8192, 16384, 65536, 262144, 1048576, 4194304,
];

/// Destination alignments, as an address offset from a 4 KiB boundary.
/// 0 is what every earlier bench measured; the rest are what a real
/// allocation gives you.
const DALIGNS: &[usize] = &[1, 8, 16, 32, 63];

/// How far the source sits ABOVE the end of the destination, in the
/// proximity grid. `0` is the closest legal `memcpy` - the two ranges
/// touch - and is what separates "the relative alignment costs" from
/// "the two ranges being near each other costs".
const EXTRAS: &[usize] = &[0, 64, 4096, 65536, 1 << 20];

fn leg(d: *mut u8, s: *const u8, n: usize, reps: u64) -> f64 {
    let t0 = Instant::now();
    for _ in 0..reps {
        unsafe {
            let r = linked_memcpy(d, s, n);
            std::hint::black_box(r);
        }
    }
    t0.elapsed().as_secs_f64()
}

/// `(n, dalign, srel, sep)`: `srel` is added to `dalign` on the SOURCE side
/// so `(src - dest) % 16 == srel % 16` exactly whatever `dalign` is, and
/// `sep` is where the source region starts relative to the destination -
/// `None` for the far region 128 MiB away, `Some(k)` for `dest + n + k`,
/// i.e. the source `k` bytes above the destination's end.
///
/// WHY THE PROXIMITY AXIS EXISTS, and it is the whole round. The 16 Sep
/// round's grid placed the source at `dest + gap` with `gap` BOTH the
/// separation and the relative alignment: its regressing cells were
/// `gap = n - 1` (so `gap % 8 == 7` at every length it used) and its clean
/// ones `gap = n / 2` (so `gap % 8 == 0`). Those two readings are one
/// variable there and two here.
fn cells() -> Vec<(usize, usize, usize, Option<i64>, char)> {
    let mut v = Vec::new();
    // Grid A: relative alignment ALONE, with the source 128 MiB away so
    // nothing about proximity can enter. Every one of the 16 offsets mod 16,
    // at every length.
    for &n in NS {
        for srel in 0..16usize {
            v.push((n, 0, srel, None, 'A'));
        }
    }
    // Grid C: the proximity axis. Eight relative offsets - enough to
    // separate `% 8 == 0` from the rest - at five separations.
    for &n in &[2048usize, 4096, 65536, 262144, 1048576] {
        for &e in EXTRAS {
            for srel in 0..8usize {
                v.push((n, 0, srel, Some(e as i64), 'C'));
            }
        }
    }
    // Grid B: the same question with the destination NOT aligned, because a
    // routine that aligns one end has to be judged where neither end starts
    // aligned.
    for &n in &[4096usize, 65536] {
        for &da in DALIGNS {
            for srel in 0..8usize {
                v.push((n, da, srel, None, 'B'));
            }
        }
    }
    // Grid D: THE 16 SEP ROUND'S OWN TWO GAPS, reproduced through `memcpy`
    // so this round can say what that reading was. Round 1 of that round
    // routed a wide ASCENDING overlap into `copy_disjoint` and measured
    // 0.418x at `gap = n - 1` beside 1.618x at `gap = n / 2`; here the
    // source sits `n - 1` and `n / 2` above the destination, which is
    // exactly those two inputs to exactly that routine. An overlap is
    // outside the C `memcpy` contract and these cells are a TIMING of the
    // routine on the bytes that round gave it, not a claim that `memcpy`
    // may be called this way.
    for &n in &[4096usize, 65536, 1048576] {
        for g in [n / 2, n - 1, n - 8] {
            for srel in 0..8usize {
                v.push((n, 0, srel, Some(g as i64 - n as i64), 'D'));
            }
        }
    }
    // Grid E: `(src - dest) mod 4096`, with the ranges DISJOINT throughout.
    // This is the axis grid D turned out to be about. Grid D's slow cells are
    // not the misaligned ones - at n = 4096 every one of the eight relative
    // offsets is fast at `gap = 2048` and every one is slow at
    // `gap = 4088..4095` - they are the ones where the copy's own load
    // stream sits a few bytes BELOW a multiple of 4 KiB above its store
    // stream, which is 4 KiB aliasing: a load whose address matches a
    // pending store's in bits 11:0 cannot be disambiguated and stalls. So
    // this grid asks the question for a legal `memcpy`: keep `gap >= n` and
    // sweep the residue.
    for &n in &[2048usize, 4096, 16384, 65536] {
        for &r in &[0usize, 8, 24, 64, 128, 256, 512, 1024, 2048, 3072, 3840, 4032, 4072, 4088] {
            // The smallest `gap = 4096k + r` that keeps the ranges disjoint
            // with a little slack, so every cell here is inside the C
            // `memcpy` contract.
            let mut gap = r;
            while gap < n + 64 {
                gap += 4096;
            }
            v.push((n, 0, 0, Some(gap as i64 - n as i64), 'E'));
        }
    }
    v
}

fn bench(arena: *mut u8) {
    let rounds: u64 = std::env::var("ROUNDS").ok().and_then(|v| v.parse().ok()).unwrap_or(9);
    let legs: u64 = std::env::var("LEGS").ok().and_then(|v| v.parse().ok()).unwrap_or(15);
    let min_s: f64 = std::env::var("MIN_S").ok().and_then(|v| v.parse().ok()).unwrap_or(0.002);
    let arm = if cfg!(feature = "cand") { "cand" } else { "base" };
    let label = std::env::var("ARM").unwrap_or_else(|_| arm.to_string());

    let want = std::env::var("GRIDS").unwrap_or_else(|_| "ABCD".to_string());
    let cs: Vec<_> = cells().into_iter().filter(|c| want.contains(c.4)).collect();
    let mut best: Vec<f64> = vec![f64::MAX; cs.len()];
    // The relative offset as the ADDRESSES give it - grid D's gaps are not
    // a multiple of 16, so `srel` alone does not name it.
    let mut rel: Vec<usize> = vec![0; cs.len()];
    for round in 0..rounds {
        for (ci, &(n, da, srel, sep, _g)) in cs.iter().enumerate() {
            // Walk the page-aligned base per round so no cell keeps one
            // cache-set position, and keep the alignment exact by moving in
            // whole pages.
            let step = (round as usize * 4096) % (1 << 19);
            let (d, s) = unsafe {
                let d = arena.add(DBASE + step + da);
                let s = match sep {
                    None => arena.add(SBASE + step + da + srel),
                    Some(e) => d.offset(n as isize + e as isize + srel as isize),
                };
                (d, s as *const u8)
            };
            rel[ci] = (s as usize).wrapping_sub(d as usize);
            let mut reps: u64 = 1;
            loop {
                let t = leg(d, s, n, reps);
                if t >= min_s || reps > (1 << 30) {
                    let per = t / reps as f64;
                    reps = ((min_s / per).ceil() as u64).max(1);
                    break;
                }
                reps = (reps * 4).max(1);
            }
            for _ in 0..legs {
                let t = leg(d, s, n, reps) / reps as f64;
                if t < best[ci] {
                    best[ci] = t;
                }
            }
        }
    }
    for (ci, &(n, da, srel, sep, g)) in cs.iter().enumerate() {
        println!(
            "CELL arm={} grid={} n={} dalign={} srel={} sep={} rel8={} rel16={} s={:.9} gbs={:.3}",
            label,
            g,
            n,
            da,
            srel,
            match sep {
                None => i64::MIN,
                Some(e) => e,
            },
            rel[ci] % 8,
            rel[ci] % 16,
            best[ci],
            n as f64 / best[ci] / 1e9
        );
    }
}

/// Correctness over the EXPORTED symbol on the real target. A green bench on
/// a wrong routine is the failure this exists to refuse.
fn check(arena: *mut u8) -> i32 {
    let mut bad = 0usize;
    let mut checked = 0usize;
    let mut seed: u64 = 0x9E3779B97F4A7C15;
    let mut rnd = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut ns: Vec<usize> = (0..=320).collect();
    ns.extend([
        511, 512, 513, 1023, 1024, 1025, 2039, 2040, 2041, 2047, 2048, 2049, 2050, 2055, 2056,
        2057, 3071, 3072, 3073, 4095, 4096, 4097, 8191, 8192, 8193, 65535, 65536, 65537,
        1048575, 1048576, 1048577,
    ]);
    let mut gold = vec![0u8; 1048576 + 1024];
    for b in gold.iter_mut() {
        *b = (rnd() & 0xFF) as u8;
    }
    for &n in &ns {
        for da in 0..17usize {
            for srel in 0..17usize {
                unsafe {
                    let d = arena.add(DBASE + da);
                    let s = arena.add(SBASE + da + srel);
                    std::ptr::copy_nonoverlapping(gold.as_ptr(), s, n);
                    // Poison the destination and the bytes either side of it,
                    // so an overrun in either direction is caught.
                    std::ptr::write_bytes(d.sub(64), 0xA5, n + 128);
                    linked_memcpy(d, s, n);
                    checked += 1;
                    let got = std::slice::from_raw_parts(d, n);
                    let pre = std::slice::from_raw_parts(d.sub(64), 64);
                    let post = std::slice::from_raw_parts(d.add(n), 64);
                    if got != &gold[..n] || pre.iter().any(|&b| b != 0xA5) || post.iter().any(|&b| b != 0xA5) {
                        if bad < 12 {
                            let at = got.iter().zip(gold.iter()).position(|(a, b)| a != b);
                            println!(
                                "BAD n={} dalign={} srel={} first_diff={:?} pre_ok={} post_ok={}",
                                n,
                                da,
                                srel,
                                at,
                                pre.iter().all(|&b| b == 0xA5),
                                post.iter().all(|&b| b == 0xA5)
                            );
                        }
                        bad += 1;
                    }
                }
            }
        }
    }
    println!("CHECK cases={} bad={}", checked, bad);
    if bad == 0 {
        println!("ALL-OK");
        0
    } else {
        1
    }
}

fn main() {
    let arena = unsafe {
        let layout = std::alloc::Layout::from_size_align(ARENA, 4096).unwrap();
        let p = std::alloc::alloc(layout);
        assert!(!p.is_null());
        let mut v: u8 = 1;
        for i in 0..ARENA {
            *p.add(i) = v;
            v = v.wrapping_mul(31).wrapping_add(7);
        }
        std::hint::black_box(linked_memcpy(p, p.add(ARENA / 2), 64));
        p
    };
    let mode = std::env::args().nth(1).unwrap_or_else(|| "bench".into());
    match mode.as_str() {
        "check" => std::process::exit(check(arena)),
        _ => bench(arena),
    }
}
