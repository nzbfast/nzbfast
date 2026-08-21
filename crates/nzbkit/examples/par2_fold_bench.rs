//! Repair-math microbenchmark: the GF(2^16) multi-accumulate alone.
//!
//! Times `dsts[j] ^= Σ_i coeff(j,i)·srcs[i]` directly, with every buffer
//! allocated and filled up front, so nothing but the fold is inside the
//! timer. An earlier version drove the full `Reconstructor` and was
//! swamped by allocator cost on Windows (the alloc/fill/free floor
//! exceeded the whole measured run), which is worth remembering before
//! trusting any repair number that includes buffer churn.
//!
//! The sweep over MISSING is the point: work is split by row, and rows
//! ARE the missing-block count, so light damage - the common field case
//! - is where a parallelism ceiling shows up.
//!
//! cargo run --release -p nzbkit --example par2_fold_bench

use std::time::Instant;

use nzbkit::par2repair::bench_fold;

/// 640 KiB: a usenet-typical PAR2 block size.
const BLOCK_DEFAULT: usize = 640 << 10;

const REPEATS_DEFAULT: usize = 9;

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn main() {
    // nzbkit emits its timing lines as tracing events; an example binary
    // has to install a sink or NZBFAST_REPAIR_TIMING prints nothing.
    tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        // Keep the target: it is the `repair-timing` / `fold-trace`
        // key these lines have always been grepped by.
        .with_target(true)
        .with_writer(std::io::stderr)
        .init();
    // Env overrides so the sweep can mimic any repair shape:
    // NZBFAST_FOLD_BLOCK (bytes), NZBFAST_FOLD_MISSING (comma list),
    // NZBFAST_FOLD_BATCH (bytes of sources per fold call).
    let block: usize = std::env::var("NZBFAST_FOLD_BLOCK")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(BLOCK_DEFAULT);
    let words = block / 2;
    let batch: usize = std::env::var("NZBFAST_FOLD_BATCH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(32 << 20);
    let inputs = (batch / block).max(1);
    let missing: Vec<usize> = std::env::var("NZBFAST_FOLD_MISSING")
        .ok()
        .map(|v| v.split(',').filter_map(|x| x.trim().parse().ok()).collect())
        .unwrap_or_else(|| vec![1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024]);
    let cores = std::thread::available_parallelism().map_or(0, |n| n.get());
    println!(
        "block {} KiB · {inputs} sources/batch · {cores} cores · fold only",
        block >> 10
    );

    // Sources: built once, reused by every configuration.
    let mut state = 0x243F6A88_85A308D3u64;
    let srcs_owned: Vec<Vec<u8>> = (0..inputs)
        .map(|_| {
            let mut v = vec![0u8; block];
            for c in v.chunks_mut(8) {
                let r = xorshift(&mut state).to_le_bytes();
                c.copy_from_slice(&r[..c.len()]);
            }
            v
        })
        .collect();
    let srcs: Vec<&[u8]> = srcs_owned.iter().map(|v| v.as_slice()).collect();

    println!(
        "{:>8}  {:>10}  {:>12}  {:>10}",
        "missing", "best (ms)", "fold GB/s", "vs 1-miss"
    );
    let mut baseline_rate = 0.0f64;
    for &m in &missing {
        // Destinations allocated once, outside the timer, and reused:
        // the fold is an XOR accumulate, so repeating it changes the
        // contents but not the work done.
        let mut dsts: Vec<Vec<u16>> = (0..m).map(|_| vec![0u16; words]).collect();
        let exps: Vec<u32> = (0..m as u32).collect();

        let repeats: usize = std::env::var("NZBFAST_FOLD_ROUNDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(REPEATS_DEFAULT);
        let trace = std::env::var_os("NZBFAST_FOLD_ROUNDS").is_some();
        let mut best = f64::MAX;
        for r in 0..repeats {
            let t0 = Instant::now();
            bench_fold(&mut dsts, &srcs, &|j, i| {
                nzbkit::gf16::pow2(i as u64 * exps[j] as u64)
            });
            let dt = t0.elapsed().as_secs_f64();
            if trace {
                println!(
                    "  m={m} round {r}: {:.0} ms ({:.1} GB/s)",
                    dt * 1e3,
                    inputs as f64 * block as f64 * m as f64 / dt / 1e9
                );
            }
            best = best.min(dt);
            std::hint::black_box(&dsts);
        }
        let work = inputs as f64 * block as f64 * m as f64;
        let rate = work / best / 1e9;
        if m == 1 {
            baseline_rate = rate;
        }
        println!(
            "{m:>8}  {:>10.2}  {:>12.1}  {:>9.2}x",
            best * 1e3,
            rate,
            rate / baseline_rate
        );
    }

    // Scalar-path guard: matrix inversion timing (Vandermonde +
    // Gauss-Jordan), so a fold-table A/B can prove the scalar solve
    // untouched. Best of 3, like the fold rows.
    for &m in &[128usize, 1024] {
        let mut best = f64::MAX;
        let mut sum = 0u16;
        for _ in 0..3 {
            let t0 = Instant::now();
            sum = nzbkit::par2repair::bench_invert(m);
            best = best.min(t0.elapsed().as_secs_f64());
        }
        println!("invert m={m}: {:.1} ms (checksum {sum:04x})", best * 1e3);
    }
}
