//! membench-overlap - prices `memmove`'s OVERLAPPING shapes against the
//! `compiler_rt.memmove.memmoveFast` a static musl download links today.
//! Claim `memops-memmove-overlap-regression-16sep`.
//!
//! TWO BINARIES FROM ONE SOURCE, the method both landed memops rounds used
//! (an internal note section 2,
//! an internal note section 3):
//!   base  - no `--features cand`, so `compiler_rt`'s weak symbol serves;
//!   cand  - `fast_mem_ops!()` stamped in, so the strong one wins the link.
//! BOTH arms reach the routine through the LINKED symbol (the `extern "C"`
//! block below), so the ratio is the routine's and not a call-shape
//! difference. `nm` on the two binaries is what proves which is which.
//!
//! `src/memops.rs` is a SYMLINK to the real
//! `crates/nzbkit-base/src/memops.rs`, so this cannot measure a stale copy.

#[path = "memops.rs"]
mod memops;

#[cfg(feature = "cand")]
fast_mem_ops!();

use std::time::Instant;

extern "C" {
    #[link_name = "memmove"]
    fn linked_memmove(d: *mut u8, s: *const u8, n: usize) -> *mut u8;
    #[link_name = "memcpy"]
    fn linked_memcpy(d: *mut u8, s: *const u8, n: usize) -> *mut u8;
}

const ARENA: usize = 96 << 20;

/// Lengths. Dense where a compaction lives (a few hundred bytes to a few
/// KiB) and thin above it, plus the two bounds the shipped code names.
const NS: &[usize] = &[
    16, 32, 48, 64, 96, 128, 160, 192, 256, 384, 512, 768, 1024, 1536, 2048,
    3072, 4096, 8192, 16384, 65536, 262144, 1048576,
];

/// Gaps (|dst - src|). Only `gap < n` is an overlap; `gap >= n` is the
/// disjoint control and is measured too, because the fix must not move it.
/// `0` FIRST, and it is the population this round is about: a self-move
/// (`dest == src`) is 161,095 of the 291,000 memmove calls in a TLS leg.
const GAPS: &[usize] = &[0, 1, 8, 16, 24, 32, 48, 64, 128, 256, 1024, 4096, 16384];

fn now() -> Instant {
    Instant::now()
}

/// One timed leg: `reps` calls, returns seconds.
fn leg(d: *mut u8, s: *const u8, n: usize, reps: u64) -> f64 {
    let t0 = now();
    for _ in 0..reps {
        unsafe {
            let r = linked_memmove(d, s, n);
            std::hint::black_box(r);
        }
    }
    t0.elapsed().as_secs_f64()
}

fn bench(arena: *mut u8) {
    // Enough legs that the best-of is a real minimum, each long enough that
    // the clock is not the measurement.
    let rounds: u64 = std::env::var("ROUNDS").ok().and_then(|v| v.parse().ok()).unwrap_or(9);
    let legs: u64 = std::env::var("LEGS").ok().and_then(|v| v.parse().ok()).unwrap_or(15);
    let min_s: f64 = std::env::var("MIN_S").ok().and_then(|v| v.parse().ok()).unwrap_or(0.002);
    let arm = if cfg!(feature = "cand") { "cand" } else { "base" };
    let label = std::env::var("ARM").unwrap_or_else(|_| arm.to_string());

    let mut cells: Vec<(usize, usize, u8)> = Vec::new();
    for &n in NS {
        for &g in GAPS {
            if g >= n {
                continue;
            }
            if g == 0 {
                cells.push((n, 0, 0));
                continue;
            }
            cells.push((n, g, 0)); // ascending overlap: dst below src
            cells.push((n, g, 1)); // descending overlap: dst above src
        }
        // n/2 and n-1, the two relative gaps a compaction actually makes.
        for g in [n / 2, n - 1] {
            if g == 0 || GAPS.contains(&g) {
                continue;
            }
            cells.push((n, g, 0));
            cells.push((n, g, 1));
        }
        // The disjoint control: this arm must not move.
        cells.push((n, n, 0));
    }

    let mut best: Vec<f64> = vec![f64::MAX; cells.len()];
    for round in 0..rounds {
        for (ci, &(n, g, dir)) in cells.iter().enumerate() {
            // Place the pair in the middle of the arena, and walk the base
            // per round so no cell keeps one cache-set position.
            let off = (1 << 20) + (round as usize * 4096) % (1 << 20);
            let (d, s) = unsafe {
                if dir == 0 {
                    (arena.add(off), arena.add(off + g) as *const u8)
                } else {
                    (arena.add(off + g), arena.add(off) as *const u8)
                }
            };
            // Calibrate reps once per cell per round so a slow arm does not
            // simply run fewer bytes.
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
    for (ci, &(n, g, dir)) in cells.iter().enumerate() {
        let gbs = n as f64 / best[ci] / 1e9;
        println!(
            "CELL arm={} n={} gap={} dir={} s={:.9} gbs={:.3}",
            label,
            n,
            g,
            if g >= n { "disjoint" } else if dir == 0 { "asc" } else { "desc" },
            best[ci],
            gbs
        );
    }
}

/// Correctness over the EXPORTED symbol on the real target, which is the
/// standalone harness the x86_64 round ran beside the unit tests. A green
/// bench on a wrong routine is the failure this exists to refuse.
fn check(arena: *mut u8) -> i32 {
    let mut bad = 0usize;
    let mut checked = 0usize;
    let base = 1 << 16;
    let mut seed: u64 = 0x9E3779B97F4A7C15;
    let mut rnd = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut ns: Vec<usize> = (0..=300).collect();
    ns.extend([
        511, 512, 513, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097, 8191, 8192,
        65535, 65536, 65537,
    ]);
    for &n in &ns {
        let mut gaps: Vec<usize> = (0..=40).collect();
        gaps.extend([47, 48, 63, 64, 65, 95, 127, 128, 129, 1023, 1024, 1025]);
        for extra in [n / 2, n.saturating_sub(1), n, n + 1, n + 31, 2 * n] {
            if extra > 0 {
                gaps.push(extra);
            }
        }
        gaps.sort_unstable();
        gaps.dedup();
        for &g in &gaps {
            for dir in 0..2u8 {
                let doffs: &[usize] =
                    if n <= 300 { &[0usize, 1, 3, 7, 8, 15, 16, 31, 63] } else { &[0usize, 1, 15] };
                for &doff in doffs {
                    let span = n + g + 128;
                    let mut gold = vec![0u8; span];
                    for b in gold.iter_mut() {
                        *b = (rnd() & 0xFF) as u8;
                    }
                    unsafe {
                        let p = arena.add(base + doff);
                        std::ptr::copy_nonoverlapping(gold.as_ptr(), p, span);
                        let (d, s) = if dir == 0 {
                            (p, p.add(g) as *const u8)
                        } else {
                            (p.add(g), p as *const u8)
                        };
                        let dofs = d as usize - p as usize;
                        let sofs = s as usize - p as usize;
                        linked_memmove(d, s, n);
                        // Reference: the same move on the gold copy.
                        let mut want = gold.clone();
                        let src_slice: Vec<u8> = want[sofs..sofs + n].to_vec();
                        want[dofs..dofs + n].copy_from_slice(&src_slice);
                        let got = std::slice::from_raw_parts(p, span);
                        checked += 1;
                        if got != &want[..] {
                            if bad < 12 {
                                let at = got.iter().zip(want.iter()).position(|(a, b)| a != b);
                                println!(
                                    "BAD n={} gap={} dir={} doff={} first_diff={:?}",
                                    n, g, dir, doff, at
                                );
                            }
                            bad += 1;
                        }
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
        // Touch every page so no timing includes a first-touch fault, and
        // give the arena a non-trivial content.
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
