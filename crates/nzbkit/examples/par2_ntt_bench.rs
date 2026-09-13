//! Reconstructor-level A/B of the syndrome paths: streaming fold vs the
//! experimental resident-source NTT (merged NTT plan Stage 2). Times
//! the WHOLE Reconstructor life cycle - feed (arena packing), syndrome
//! pass, and back-substitution - on the synthetic heavy geometry, and
//! byte-compares the reconstructed slices between the two paths.
//!
//! This is the integration-shaped measurement between the Stage 1 hot
//! loop and Stage 3's full disk-path competitive round: everything but
//! file I/O and verification.
//!
//! cargo run --release -p nzbkit -F rars/parallel --example par2_ntt_bench
//! Env: NZBFAST_NTT_BLOCK (bytes, 65536), NZBFAST_NTT_TOTAL (16384),
//!      NZBFAST_NTT_MISS (1500), NZBFAST_NTT_ROUNDS (3), plus the
//!      production knobs (NZBFAST_NTT_W, NZBFAST_NTT_THREADS).
//!
//! NZBFAST_NTT_EXP_SPAN (default: `miss`, a consecutive set) makes the
//! recovery exponents SPARSE over `[0, span)` instead of consecutive -
//! the fixture family `fastpar::NTT_MIN_WORK_PER_ROW` has never had. The
//! transform evaluates every row in the span it is handed, while the
//! fold only ever computes the `miss` rows it wants, so a sparse set is
//! the one shape where the transform pays for rows nobody asked for and
//! the fold does not. The exponents are deliberately IRREGULAR: an
//! arithmetic progression relabels to a consecutive set
//! (`fastpar::exponent_span`), so a plain stride would measure nothing.
//! Read the effective span off the `ntt syndromes (... needed=N ...)`
//! timing line under NZBFAST_REPAIR_TIMING=1 rather than assuming it.

use nzbkit::gf16;
use nzbkit::par2repair::{Reconstructor, SyndromePath, input_base_logs};
use std::time::Instant;

fn envn(k: &str, d: usize) -> usize {
    std::env::var(k)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(d)
}

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
    let block = envn("NZBFAST_NTT_BLOCK", 65536);
    let total = envn("NZBFAST_NTT_TOTAL", 16384);
    let miss = envn("NZBFAST_NTT_MISS", 1500);
    let rounds = envn("NZBFAST_NTT_ROUNDS", 3);
    let exp_span = envn("NZBFAST_NTT_EXP_SPAN", miss);
    assert!(miss < total);
    assert!(
        exp_span >= miss,
        "a span under the row count cannot hold {miss} distinct exponents"
    );
    assert!(
        exp_span <= 65535,
        "max exponent must stay inside the transform's group order"
    );
    println!(
        "block {} KiB, {total} total, {miss} missing ({} present, {:.2} GiB corpus)",
        block >> 10,
        total - miss,
        ((total - miss) * block) as f64 / (1u64 << 30) as f64
    );

    // Deterministic corpus; missing set scattered by stride.
    let mut state = 0x243F6A88_85A308D3u64;
    let slices: Vec<Vec<u8>> = (0..total)
        .map(|_| {
            let mut v = vec![0u8; block];
            for c in v.chunks_mut(8) {
                let r = xorshift(&mut state).to_le_bytes();
                c.copy_from_slice(&r[..c.len()]);
            }
            v
        })
        .collect();
    let missing: Vec<usize> = {
        let stride = total / miss;
        (0..miss).map(|i| i * stride).collect()
    };
    let is_missing: Vec<bool> = {
        let mut v = vec![false; total];
        for &j in &missing {
            v[j] = true;
        }
        v
    };

    // The exponents the recovery rows carry. Consecutive by default;
    // with NZBFAST_NTT_EXP_SPAN set, `miss` distinct values spread over
    // [0, span) with the ends pinned so the span is exactly what was
    // asked for. Chosen off the same deterministic xorshift as the
    // corpus, so a leg is reproducible, and SORTED because the plan
    // reads them in order.
    let exps: Vec<u32> = if exp_span == miss {
        (0..miss as u32).collect()
    } else {
        let mut taken = vec![false; exp_span];
        taken[0] = true;
        taken[exp_span - 1] = true;
        let mut n = 2;
        while n < miss {
            let c = (xorshift(&mut state) % exp_span as u64) as usize;
            if !taken[c] {
                taken[c] = true;
                n += 1;
            }
        }
        (0..exp_span)
            .filter(|&i| taken[i])
            .map(|i| i as u32)
            .collect()
    };
    assert_eq!(exps.len(), miss);
    println!(
        "exponents: {miss} rows spanning {} (first {}, last {})",
        exps[miss - 1] - exps[0] + 1,
        exps[0],
        exps[miss - 1]
    );

    // Recovery slices R_e = Σ g_i^e·D_i for the exponents above,
    // generated with the same multi-fold the product uses (this is the
    // expensive part of the setup; done once, off every clock).
    let logs = input_base_logs(total).unwrap();
    let t0 = Instant::now();
    let words = block / 2;
    let mut recovery_words: Vec<Vec<u16>> = vec![vec![0u16; words]; miss];
    let srcs: Vec<&[u8]> = slices.iter().map(|s| s.as_slice()).collect();
    nzbkit::par2repair::bench_fold(&mut recovery_words, &srcs, &|j, i| {
        gf16::pow2(logs[i] as u64 * exps[j] as u64)
    });
    let recovery: Vec<(u32, Vec<u8>)> = recovery_words
        .into_iter()
        .enumerate()
        .map(|(k, w)| (exps[k], gf16::words_as_bytes(&w).to_vec()))
        .collect();
    println!(
        "recovery generation: {:.1}s (setup, unclocked)",
        t0.elapsed().as_secs_f64()
    );

    let mut baseline: Option<Vec<Vec<u8>>> = None;
    for (name, path) in [
        ("fold", SyndromePath::Fold),
        ("ntt ", SyndromePath::NttForce(usize::MAX)),
    ] {
        for round in 0..rounds {
            let t0 = Instant::now();
            let mut rec =
                Reconstructor::new_with_path(block, total, &missing, &recovery, path).unwrap();
            let t_new = t0.elapsed();
            for (i, s) in slices.iter().enumerate() {
                if !is_missing[i] {
                    rec.feed(i, s);
                }
            }
            let t_fed = t0.elapsed();
            let out = rec.finish();
            let t_done = t0.elapsed();
            println!(
                "{name} round {round}: total {:.3}s (new {:.3}s, feed {:.3}s, finish {:.3}s)",
                t_done.as_secs_f64(),
                t_new.as_secs_f64(),
                (t_fed - t_new).as_secs_f64(),
                (t_done - t_fed).as_secs_f64()
            );
            match &baseline {
                None => baseline = Some(out),
                Some(b) => assert_eq!(b, &out, "paths disagree"),
            }
        }
    }
    println!("outputs byte-identical across paths and rounds");
}
