//! LiveVerifier name-matching microbenchmark (perf chip B6).
//!
//! Times the match tiers alone through the `bench_match` hook, with the
//! set and probe slots built up front, so nothing but `try_match` is
//! inside the timer - the fold-bench lesson: a harness that includes
//! buffer churn measures the allocator, not the work.
//!
//! Shape under test: V descriptors ("release.partNNNN.rar"), 8 probe
//! slots whose names match nothing and whose heads never complete
//! (.nfo/.sfv/sample subjects) - the exact hot path, where the pre-B6
//! matcher ran a full V scan with per-candidate sanitize allocations on
//! EVERY article, under the claimed mutex all decode threads share.
//!
//! cargo run --release -p nzbkit --example live_match_bench
//!
//! Env: NZBFAST_MATCH_V (comma list, default 100,600,1200 - corpus p99
//! is 234 volumes, max 1229), NZBFAST_MATCH_CALLS (default 100000).

use std::sync::Arc;
use std::time::Instant;

use nzbkit::live::bench_match;
use nzbkit::par2::{Par2File, Par2Set};

fn synth_set(n: usize) -> Arc<Par2Set> {
    let files = (0..n)
        .map(|i| {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
            let mut md5_16k = [0u8; 16];
            md5_16k[8..].copy_from_slice(&(i as u64).to_le_bytes());
            Par2File {
                file_id: id,
                name: format!("release.part{:04}.rar", i + 1),
                length: 50 << 20,
                md5: [0u8; 16],
                md5_16k,
                blocks: Vec::new(),
            }
        })
        .collect();
    Arc::new(Par2Set {
        recovery_set_id: [1u8; 16],
        block_size: 640 << 10,
        files,
        recovery_blocks_seen: 0,
    })
}

fn time_leg(set: &Arc<Par2Set>, probes: &[String], calls: usize, indexed: bool) -> f64 {
    // Median of 5, warmup discarded.
    let mut runs: Vec<f64> = (0..6)
        .map(|_| {
            let t0 = Instant::now();
            let claimed = bench_match(set, probes, calls, indexed);
            assert_eq!(claimed, 0, "worst-case probes must never match");
            t0.elapsed().as_secs_f64() / calls as f64 * 1e9
        })
        .skip(1)
        .collect();
    runs.sort_by(|a, b| a.total_cmp(b));
    runs[runs.len() / 2]
}

fn main() {
    let vs: Vec<usize> = std::env::var("NZBFAST_MATCH_V")
        .ok()
        .map(|v| v.split(',').filter_map(|x| x.trim().parse().ok()).collect())
        .unwrap_or_else(|| vec![100, 600, 1200]);
    let calls: usize = std::env::var("NZBFAST_MATCH_CALLS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000);
    let probes: Vec<String> = (0..8).map(|i| format!("obfuscated{i:02}.nfo")).collect();

    println!("live match bench: {calls} calls, 8 unmatched probe slots");
    println!(
        "{:>6} {:>14} {:>14} {:>8}",
        "V", "linear ns", "indexed ns", "speedup"
    );
    for v in vs {
        let set = synth_set(v);
        // Cross-check first: both paths must agree on a mixed probe set
        // (some claim, some miss) before any timing is trusted.
        let mixed: Vec<String> = (0..8)
            .map(|i| {
                if i % 2 == 0 {
                    format!("release.part{:04}.rar", i + 1)
                } else {
                    format!("miss{i}.nfo")
                }
            })
            .collect();
        let a = bench_match(&set, &mixed, 64, true);
        let b = bench_match(&set, &mixed, 64, false);
        assert_eq!(a, b, "impls disagree at V={v}");

        let lin = time_leg(&set, &probes, calls, false);
        let idx = time_leg(&set, &probes, calls, true);
        println!("{v:>6} {lin:>14.1} {idx:>14.1} {:>7.1}x", lin / idx);
    }
}
