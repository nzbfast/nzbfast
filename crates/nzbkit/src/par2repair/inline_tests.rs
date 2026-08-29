//! The repair math and mapped-driver tests, moved out of par2repair.rs
//! bodily (TODO 106).
//!
//! These were `mod tests` inside par2repair.rs. A child module of
//! `par2repair`, the sibling of `unit_tests` (which covers the on-disk
//! entry points), so `super::*` still names the private internals.

use super::linalg::*;
use super::*;
use crate::gf16::MulTable;

/// Destination identity is a filesystem question, not a string question.
/// The colliding-target guard, the adoption-source exclusion and the
/// "never patch a file that is still being read" check all key on this,
/// and on a case-insensitive volume an exact path compare silently treats
/// two aliases of ONE file as two independent destinations - which is how
/// a repair lands over an intact file and still reports success.
#[test]
fn path_identity_key_folds_only_when_told_to() {
    let a = Path::new("/out/README.txt");
    let b = Path::new("/out/readme.txt");
    // Folding: two aliases of ONE file on a case-insensitive volume.
    assert_eq!(path_identity_key(true, a), path_identity_key(true, b));
    // Not folding: genuinely distinct files on a case-sensitive volume.
    assert_ne!(path_identity_key(false, a), path_identity_key(false, b));
    // Genuinely different names must never collapse, either way.
    for fold in [true, false] {
        assert_ne!(
            path_identity_key(fold, Path::new("/out/a.bin")),
            path_identity_key(fold, Path::new("/out/b.bin"))
        );
    }
}

#[test]
fn base_log_sequence_matches_the_spec() {
    let logs = input_base_logs(9).unwrap();
    assert_eq!(logs, vec![1, 2, 4, 7, 8, 11, 13, 14, 16]);
    // Constants themselves: 2, 4, 16, 128, 256, 2048, 8192, 16384, 0x100B.
    let bases: Vec<u16> = logs.iter().map(|&k| gf16::pow2(k as u64)).collect();
    assert_eq!(bases, vec![2, 4, 16, 128, 256, 2048, 8192, 16384, 0x100B]);
}

#[test]
fn base_logs_cap_at_32768() {
    let logs = input_base_logs(MAX_INPUT_SLICES).unwrap();
    assert_eq!(logs.len(), MAX_INPUT_SLICES);
    assert!(*logs.last().unwrap() < 65535);
    assert!(input_base_logs(MAX_INPUT_SLICES + 1).is_err());
}

/// The tiled multi-accumulate must match the naive row x source
/// double loop for every awkward shape: sources shorter than the
/// rows, odd source lengths, tiles smaller/larger than rows, and a
/// table budget small enough to force multiple source groups.
#[test]
fn fold_chunk_tiled_matches_naive() {
    let mut state = 0xB5297A4D3F84D5B5u64;
    let mut rng = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for (rows, nsrc, words, tile) in [
        (1usize, 1usize, 7usize, 4usize),
        (3, 5, 64, 16),
        (4, 7, 33, 8),
        (2, 3, 100, 1024), // tile bigger than the row: single tile
        (5, 9, 96, 32),
    ] {
        let coeffs: Vec<Vec<u16>> = (0..rows)
            .map(|_| (0..nsrc).map(|_| rng() as u16).collect())
            .collect();
        // Mix of full, short, odd, and empty sources.
        let srcs: Vec<Vec<u8>> = (0..nsrc)
            .map(|i| {
                let len = match i % 4 {
                    0 => words * 2,
                    1 => words,         // short (and odd when words is odd)
                    2 => words * 2 - 1, // odd tail byte
                    _ => 0,             // empty
                };
                (0..len).map(|_| rng() as u8).collect()
            })
            .collect();
        let base: Vec<Vec<u16>> = (0..rows)
            .map(|_| (0..words).map(|_| rng() as u16).collect())
            .collect();

        let mut want = base.clone();
        for (j, row) in want.iter_mut().enumerate() {
            for (i, src) in srcs.iter().enumerate() {
                MulTable::new(coeffs[j][i]).xor_mul_into(row, src);
            }
        }

        let src_refs: Vec<&[u8]> = srcs.iter().map(|s| s.as_slice()).collect();
        // A one-byte budget forces group size 1 (max grouping stress).
        for budget in [1usize, TABLE_BUDGET] {
            let mut got = base.clone();
            {
                let mut views: Vec<&mut [u16]> = got.iter_mut().map(|v| v.as_mut_slice()).collect();
                fold_chunk_tiled(&mut views, &src_refs, &|j, i| coeffs[j][i], 0, tile, budget);
            }
            assert_eq!(
                got, want,
                "rows={rows} nsrc={nsrc} words={words} tile={tile} budget={budget}"
            );
        }

        // The row x column scheduler must agree with the same
        // oracle. This is the path that splits each row's word
        // range across threads and re-windows every source to
        // match, so short/odd/empty sources are the interesting
        // part - a mis-windowed source silently corrupts a repair.
        let mut got = base.clone();
        fold_parallel(&mut got, &src_refs, &|j, i| coeffs[j][i]);
        assert_eq!(
            got, want,
            "fold_parallel rows={rows} nsrc={nsrc} words={words}"
        );
    }
}

/// Reference recovery-slice generator: R_e = Σ_i g_i^e · D_i, the
/// same formula par2cmdline uses to CREATE recovery data. Tests
/// build sets with it and reconstruct after synthetic damage; the
/// real-par2cmdline fixture test (tests/integration/par2repair_reference.rs)
/// pins the formula itself against reference-tool output.
fn generate_recovery(slices: &[Vec<u8>], block_size: usize, e: u32) -> Vec<u8> {
    let logs = input_base_logs(slices.len()).unwrap();
    let mut acc = vec![0u16; block_size / 2];
    for (d, &k) in slices.iter().zip(&logs) {
        MulTable::new(gf16::pow2(k as u64 * e as u64)).xor_mul_into(&mut acc, d);
    }
    acc.iter().flat_map(|w| w.to_le_bytes()).collect()
}

fn demo_slices(n: usize, block_size: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| {
            (0..block_size)
                .map(|j| ((i * 7919 + j * 104729 + j / 3) % 251) as u8)
                .collect()
        })
        .collect()
}

/// The dispatch gates: light/medium damage (the 3- and 101-block
/// benchmark legs), small source sets, pathological exponent gaps,
/// and over-budget corpora must all stay on the fold. The heavy
/// benchmark shape must pass.
#[test]
fn ntt_gates_route_field_shapes_correctly() {
    let gib = 1usize << 30;
    // The gate's budget operand, sized so the shapes below are decided
    // by the gate and not by the operand: 4 GiB is not representable in
    // a 32-bit `usize`, and the largest corpus asserted here is
    // 16381 x 64 KiB (~1 GiB), so usize::MAX serves the same purpose on
    // armv7. `ntt_default_budget`'s own 32-bit ceiling is pinned
    // separately in `ntt_default_budget_scales_to_the_machine`.
    #[cfg(target_pointer_width = "32")]
    let budget = usize::MAX;
    #[cfg(not(target_pointer_width = "32"))]
    let budget = 4 * gib;
    // Heavy leg: 16384 x 64 KiB, 1500 missing -> NTT.
    assert!(ntt_gates_pass(65536, 14884, 1500, 1499, budget));
    // Light/medium damage: fold.
    assert!(!ntt_gates_pass(65536, 16381, 3, 2, budget));
    assert!(!ntt_gates_pass(65536, 16283, 101, 100, budget));
    // Below the measured crossover margin: fold. 300 sits under the
    // m~288 end-to-end crossover measured on both the 32-core and the
    // 20-core box; 384 (the gate) sits above it.
    assert!(!ntt_gates_pass(65536, 16084, 300, 299, budget));
    assert!(ntt_gates_pass(65536, 16000, 384, 383, budget));
    // Small source set (640 KiB / 1 MiB blocks at ~1 GiB): fold,
    // regardless of damage fraction.
    assert!(!ntt_gates_pass(655360, 870, 768, 767, budget));
    // Pathological exponent gap (max exponent >= 3m): fold.
    assert!(!ntt_gates_pass(65536, 14884, 1500, 4500, budget));
    // Realistic gaps stay eligible (alt = 2m - 2).
    assert!(ntt_gates_pass(65536, 14884, 1500, 2998, budget));
    // Corpus over the memory budget: fold (amendment 2).
    assert!(!ntt_gates_pass(65536, 14884, 1500, 1499, gib / 2));
}

/// Stage 2 gate (merged NTT plan): the experimental NTT syndrome
/// path must round-trip byte-identically with the fold path - same
/// slices, same damage, same recovery set - including gapped
/// exponents and a short (odd-length) tail slice.
#[test]
fn ntt_syndrome_path_matches_fold_path() {
    let (n, bs, m) = (600usize, 64usize, 40usize);
    let mut slices = demo_slices(n, bs);
    // Missing set scattered through the range.
    let missing: Vec<usize> = (0..m).map(|i| (i * 13 + 3) % n).collect::<Vec<_>>();
    let mut missing = missing;
    missing.sort_unstable();
    missing.dedup();
    let missing = missing;
    // A short odd-length tail among the PRESENT slices (padded copy
    // used for recovery generation, raw short bytes fed).
    let tail_idx = (0..n).find(|i| !missing.contains(i)).unwrap();
    let tail_len = bs - 5;
    slices[tail_idx].truncate(tail_len);
    let padded: Vec<Vec<u8>> = slices
        .iter()
        .map(|s| {
            let mut p = s.clone();
            p.resize(bs, 0);
            p
        })
        .collect();
    // Gapped exponents: every third, starting at 2 (max well within
    // the 3m dispatch bound but far from consecutive).
    let exps: Vec<u32> = (0..missing.len() as u32).map(|i| 2 + 3 * i).collect();
    let recovery: Vec<(u32, Vec<u8>)> = exps
        .iter()
        .map(|&e| (e, generate_recovery(&padded, bs, e)))
        .collect();
    let mut outs: Vec<Vec<Vec<u8>>> = Vec::new();
    for path in [SyndromePath::Fold, SyndromePath::NttForce(usize::MAX)] {
        let mut rec = Reconstructor::new_with_path(bs, n, &missing, &recovery, path).unwrap();
        for (i, s) in slices.iter().enumerate() {
            if !missing.contains(&i) {
                rec.feed(i, s);
            }
        }
        outs.push(rec.finish());
    }
    assert_eq!(outs[0], outs[1], "NTT and fold paths disagree");
    for (c, &j) in missing.iter().enumerate() {
        assert_eq!(outs[1][c], padded[j], "missing slice {j} wrong via NTT");
    }
}

/// The smallest `(block_size, n_inputs, n_missing)` that clears
/// every clause of [`ntt_gates_pass`]: 8192 present slices,
/// `NTT_MIN_MISSING` missing, max exponent one under it and so
/// inside the 3x factor. At a 1 KiB block the stripe geometry is one
/// stripe wide, so the worker count clamps to 1 on EVERY machine and
/// the whole footprint is 8 MB of corpus plus a single worker's
/// arena. The admission tests use this rather than the
/// 64 KiB/16384/1500 benchmark leg because that leg needs 930 MB of
/// corpus budget on top of a core-count-dependent arena charge,
/// which made the expected value a function of the host's RAM, its
/// cgroup limit and its visible parallelism: red on a 4 GiB dev box,
/// in a `--memory=4g` container on a many-core host, and under any
/// exported `NZBFAST_NTT_BUDGET`.
///
/// Tracks `NTT_MIN_MISSING` deliberately: a shape that stops being
/// minimal when the gate moves stops testing the gate's boundary.
const MINIMAL_NTT_SHAPE: (usize, usize, usize) = (1024, 8192 + NTT_MIN_MISSING, NTT_MIN_MISSING);

/// True when any NTT knob is exported. All four move what
/// [`resolve_syndrome_path`] returns - the budget directly, `W` and
/// `THREADS` through the arena charge - so the admission tests opt
/// out wholesale rather than fight a bench operator's shell.
/// Mutating the vars from inside the test is not an option: the lib
/// tests run in parallel with other readers of them.
fn ntt_env_knob_set() -> bool {
    [
        "NZBFAST_NTT",
        "NZBFAST_NTT_BUDGET",
        "NZBFAST_NTT_W",
        "NZBFAST_NTT_THREADS",
    ]
    .iter()
    .any(|k| std::env::var_os(k).is_some())
}

/// The Auto arm's return value is the RETENTION budget, so it must
/// be what is left after the per-worker arenas are paid for - the
/// arenas are spoken for the moment the NTT is selected, and the
/// runtime backstop that consumes this number can only be honest if
/// it is comparing retained bytes against retained headroom. The
/// explicit force arms keep returning the caller's budget verbatim.
#[test]
fn ntt_auto_retention_budget_excludes_the_worker_arenas() {
    if ntt_env_knob_set() {
        return; // the env overrides are exercised manually, not here
    }
    let _g = NTT_STATE.lock_ok();
    FAST_PAR_TRIPPED.store(false, std::sync::atomic::Ordering::Relaxed);
    set_fast_par_enabled(true);
    let (bs, n_inputs, m) = MINIMAL_NTT_SHAPE;
    let exps: Vec<u32> = (0..m as u32).collect();
    let arenas = ntt_worker_arenas(bs, m);
    assert!(arenas > 0, "the arenas are never free");
    assert_eq!(
        resolve_syndrome_path(SyndromePath::Auto, bs, n_inputs, m, &exps),
        Some(ntt_budget_env().saturating_sub(arenas)),
        "Auto must hand back the corpus budget, not the whole budget"
    );
    assert_eq!(
        resolve_syndrome_path(SyndromePath::NttForce(3 * bs), bs, n_inputs, m, &exps),
        Some(3 * bs),
        "the force arms pass the caller's budget through untouched"
    );
    // Additionally pin the published benchmark leg (64 KiB blocks,
    // 16384 inputs, 1500 missing), but ONLY on a host whose budget
    // clears its corpus - that is the machine-dependent part, and
    // it is computed here with the same arithmetic the gate uses
    // rather than assumed.
    let heavy: Vec<u32> = (0..1500).collect();
    let heavy_corpus = ntt_budget_env().saturating_sub(ntt_worker_arenas(65536, 1500));
    if heavy_corpus >= (16384 - 1500) * 65536 {
        assert_eq!(
            resolve_syndrome_path(SyndromePath::Auto, 65536, 16384, 1500, &heavy),
            Some(heavy_corpus),
            "the benchmark leg still dispatches to the NTT where it fits"
        );
    }
    set_fast_par_enabled(FAST_PAR_DEFAULT);
}

/// Shrinking the admission tests to [`MINIMAL_NTT_SHAPE`] collapses
/// the geometry to one stripe and therefore one worker, which turns
/// the `saturating_mul(threads)` factor in [`ntt_worker_arenas`]
/// into a no-op there. That factor is the whole point of the
/// arena charge (a many-core host inside a `--memory` cap is the
/// shape it defends against), so pin it here as a RELATION rather
/// than as a constant - no dependence on this machine's core count
/// or RAM.
#[test]
fn ntt_worker_arenas_price_every_worker() {
    if ntt_env_knob_set() {
        return; // W and THREADS both move the geometry
    }
    let (w, threads) = ntt_stripe_geometry(65536);
    assert!(threads >= 1, "there is always at least one worker");
    assert_eq!(
        ntt_worker_arenas(65536, 1500),
        crate::par2ntt::FlatPlan::scratch_bytes(1500, w).saturating_mul(threads),
        "the arena charge is per worker, not per repair"
    );
}

/// A set whose present slices are nearly all SHORT tails (many small
/// files, each just under one block) costs the NTT an extra
/// zero-padded block per slice, in a side arena nothing prices. Only
/// the fed bytes are visible in the retained batches, so the runtime
/// backstop has to charge the pad it knows is coming: a corpus that
/// fits the budget only because its tails are short must fold
/// mid-flight, bit-identically. Full-length slices pay no pad and
/// must still be admitted - the backstop must not over-tighten.
#[test]
fn ntt_short_tail_pad_counts_against_the_retention_budget() {
    let (n, bs, m) = (200usize, 64usize, 8usize);
    let full = demo_slices(n, bs);
    let missing: Vec<usize> = (0..m).map(|i| i * 17).collect();
    let present: Vec<usize> = (0..n).filter(|i| !missing.contains(i)).collect();
    let tail_len = bs - 8;
    // Every slice is a short tail: the pathological many-small-files
    // shape, where the pad arena rivals the whole retained corpus.
    let fed: Vec<Vec<u8>> = full.iter().map(|s| s[..tail_len].to_vec()).collect();
    let padded: Vec<Vec<u8>> = fed
        .iter()
        .map(|s| {
            let mut p = s.clone();
            p.resize(bs, 0);
            p
        })
        .collect();
    let exps: Vec<u32> = (0..m as u32).collect();
    let recovery: Vec<(u32, Vec<u8>)> = exps
        .iter()
        .map(|&e| (e, generate_recovery(&padded, bs, e)))
        .collect();
    // A budget the fed bytes clear on their own but the tail pads do not.
    let arena_bytes = present.len() * tail_len;
    let pad_bytes = present.len() * bs;
    let budget = arena_bytes + pad_bytes / 2;
    assert!(arena_bytes <= budget && arena_bytes + pad_bytes > budget);
    let run = |slices: &[Vec<u8>], recovery: &[(u32, Vec<u8>)], path| {
        let mut rec = Reconstructor::new_with_path(bs, n, &missing, recovery, path).unwrap();
        for &i in &present {
            rec.feed(i, &slices[i]);
        }
        rec.finish_reported()
    };
    let (fold_out, _) = run(&fed, &recovery, SyndromePath::Fold);
    let (out, report) = run(&fed, &recovery, SyndromePath::NttForce(budget));
    assert!(
        !report.ntt_used,
        "the tail pad must count against the retention budget"
    );
    assert_eq!(out, fold_out, "the fold fallback must stay bit-identical");
    for (c, &j) in missing.iter().enumerate() {
        assert_eq!(out[c], padded[j], "missing slice {j} wrong after fallback");
    }
    // Control: the same corpus at full block length pays no pad, so
    // the same budget still admits the NTT.
    let recovery_full: Vec<(u32, Vec<u8>)> = exps
        .iter()
        .map(|&e| (e, generate_recovery(&full, bs, e)))
        .collect();
    let (out_full, report_full) = run(&full, &recovery_full, SyndromePath::NttForce(budget));
    assert!(
        report_full.ntt_used,
        "full-length slices pay no pad and must still run the NTT"
    );
    for (c, &j) in missing.iter().enumerate() {
        assert_eq!(out_full[c], full[j], "missing slice {j} wrong via NTT");
    }
}

/// Blowing the retention budget mid-feed must fall back to the fold
/// and still reconstruct correctly (the unconditional-fallback
/// requirement, exercised through the real worker path).
#[test]
fn ntt_budget_overflow_falls_back_to_fold() {
    let (n, bs, m) = (200usize, 64usize, 8usize);
    let slices = demo_slices(n, bs);
    let missing: Vec<usize> = (0..m).map(|i| i * 17).collect();
    let exps: Vec<u32> = (0..m as u32).collect();
    let recovery: Vec<(u32, Vec<u8>)> = exps
        .iter()
        .map(|&e| (e, generate_recovery(&slices, bs, e)))
        .collect();
    // Budget far below the corpus: overflow is guaranteed.
    let mut rec =
        Reconstructor::new_with_path(bs, n, &missing, &recovery, SyndromePath::NttForce(3 * bs))
            .unwrap();
    for (i, s) in slices.iter().enumerate() {
        if !missing.contains(&i) {
            rec.feed(i, s);
        }
    }
    let out = rec.finish();
    for (c, &j) in missing.iter().enumerate() {
        assert_eq!(out[c], slices[j], "missing slice {j} wrong after fallback");
    }
}

/// A duplicate feed is representable by the XOR fold (the two
/// contributions cancel) but not by NTT coefficient slots - the plan
/// must refuse and the fold fallback must keep both paths
/// bit-identical.
#[test]
fn ntt_duplicate_feed_falls_back_and_matches_fold() {
    let (n, bs, m) = (150usize, 64usize, 4usize);
    let slices = demo_slices(n, bs);
    let missing = [1usize, 30, 60, 90];
    let exps: Vec<u32> = (0..m as u32).collect();
    let recovery: Vec<(u32, Vec<u8>)> = exps
        .iter()
        .map(|&e| (e, generate_recovery(&slices, bs, e)))
        .collect();
    let mut outs: Vec<Vec<Vec<u8>>> = Vec::new();
    for path in [SyndromePath::Fold, SyndromePath::NttForce(usize::MAX)] {
        let mut rec = Reconstructor::new_with_path(bs, n, &missing, &recovery, path).unwrap();
        for (i, s) in slices.iter().enumerate() {
            if !missing.contains(&i) {
                rec.feed(i, s);
            }
        }
        rec.feed(0, &slices[0]); // duplicate: cancels its own contribution
        outs.push(rec.finish());
    }
    assert_eq!(outs[0], outs[1], "paths disagree on duplicate feed");
}

#[test]
fn round_trip_reconstructs_scattered_missing_slices() {
    let (n, bs) = (11, 64);
    let slices = demo_slices(n, bs);
    let missing = [0usize, 4, 5, 10];
    // Non-consecutive exponents on purpose.
    let recovery: Vec<(u32, Vec<u8>)> = [3u32, 0, 7, 5]
        .iter()
        .map(|&e| (e, generate_recovery(&slices, bs, e)))
        .collect();
    let mut rec = Reconstructor::new(bs, n, &missing, &recovery).unwrap();
    for (i, s) in slices.iter().enumerate() {
        if !missing.contains(&i) {
            rec.feed(i, s);
        }
    }
    let rebuilt = rec.finish();
    for (out, &j) in rebuilt.iter().zip(&missing) {
        assert_eq!(out, &slices[j], "slice {j} reconstructed byte-identical");
    }
}

#[test]
fn round_trip_with_short_tail_slice() {
    let (n, bs) = (5, 32);
    let mut slices = demo_slices(n, bs);
    slices[4].truncate(13); // odd-length tail, like a real file tail
    let mut padded = slices.clone();
    padded[4].resize(bs, 0);
    let missing = [1usize, 4];
    let recovery: Vec<(u32, Vec<u8>)> = [0u32, 1]
        .iter()
        .map(|&e| (e, generate_recovery(&padded, bs, e)))
        .collect();
    let mut rec = Reconstructor::new(bs, n, &missing, &recovery).unwrap();
    for (i, s) in slices.iter().enumerate() {
        if !missing.contains(&i) {
            rec.feed(i, s); // short tails fed unpadded
        }
    }
    let rebuilt = rec.finish();
    assert_eq!(rebuilt[0], padded[1]);
    assert_eq!(
        &rebuilt[1][..13],
        &slices[4][..],
        "tail slice reconstructed"
    );
    assert!(rebuilt[1][13..].iter().all(|&b| b == 0), "padding is zeros");
}

#[test]
fn wrong_recovery_count_is_rejected() {
    let (n, bs) = (4, 32);
    let slices = demo_slices(n, bs);
    let recovery = vec![(0u32, generate_recovery(&slices, bs, 0))];
    assert!(matches!(
        Reconstructor::new(bs, n, &[0, 1], &recovery),
        Err(RepairError::Malformed(_))
    ));
}

#[test]
fn matrix_inversion_round_trips() {
    // A · A⁻¹ = I for a small PAR2-shaped matrix.
    let logs = input_base_logs(6).unwrap();
    let missing = [1usize, 3, 5];
    let exps = [0u32, 1, 2];
    let a: Vec<Vec<u16>> = exps
        .iter()
        .map(|&e| {
            missing
                .iter()
                .map(|&j| gf16::pow2(logs[j] as u64 * e as u64))
                .collect()
        })
        .collect();
    let inv = invert(a.clone()).unwrap();
    for i in 0..3 {
        for j in 0..3 {
            let mut dot = 0u16;
            for k in 0..3 {
                dot ^= gf16::mul(a[i][k], inv[k][j]);
            }
            assert_eq!(dot, u16::from(i == j), "({i},{j})");
        }
    }
}

/// Vec-backed VolumeIo for mapped-driver tests.
struct MemIo {
    files: std::sync::Mutex<Vec<Vec<u8>>>,
    /// When set, writes to this (file, byte offset in the file's
    /// backing store) get flipped - simulates a broken write path,
    /// which the whole-file MD5 must catch.
    corrupt_write_at: Option<(usize, usize)>,
    /// When set, this (file, offset) is flipped on the FIRST write to
    /// any file - i.e. after every syndrome read has happened, so the
    /// rot cannot poison the reconstruction and the only thing that
    /// can catch it is the self-prove re-reading a file it did not
    /// rebuild.
    rot_on_first_write: Option<(usize, usize)>,
    rotted: std::sync::atomic::AtomicBool,
}
impl MemIo {
    fn new(files: Vec<Vec<u8>>, corrupt_write_at: Option<(usize, usize)>) -> MemIo {
        MemIo {
            files: std::sync::Mutex::new(files),
            corrupt_write_at,
            rot_on_first_write: None,
            rotted: std::sync::atomic::AtomicBool::new(false),
        }
    }
    fn rotting(files: Vec<Vec<u8>>, at: (usize, usize)) -> MemIo {
        MemIo {
            files: std::sync::Mutex::new(files),
            corrupt_write_at: None,
            rot_on_first_write: Some(at),
            rotted: std::sync::atomic::AtomicBool::new(false),
        }
    }
    fn snapshot(&self) -> Vec<Vec<u8>> {
        self.files.lock().unwrap().clone()
    }
}
impl VolumeIo for MemIo {
    fn read(&self, file: usize, off: u64, buf: &mut [u8]) -> std::io::Result<()> {
        let files = self.files.lock().unwrap();
        let off = off as usize;
        buf.copy_from_slice(&files[file][off..off + buf.len()]);
        Ok(())
    }
    fn write(&self, file: usize, off: u64, data: &[u8]) -> std::io::Result<()> {
        let mut files = self.files.lock().unwrap();
        let off = off as usize;
        files[file][off..off + data.len()].copy_from_slice(data);
        if let Some((rf, ro)) = self.rot_on_first_write
            && !self.rotted.swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            files[rf][ro] ^= 0xFF;
        }
        if let Some((cf, co)) = self.corrupt_write_at
            && cf == file
            && (off..off + data.len()).contains(&co)
        {
            files[file][co] ^= 0xFF;
        }
        Ok(())
    }
}

/// Two files (one with an odd tail), slices + recovery generated
/// with the reference formula. Returns (files-with-present, bs,
/// recovery, pristine bytes).
fn mapped_fixture(
    damage: &[(usize, usize)],
) -> (
    Vec<(Par2File, Vec<bool>)>,
    usize,
    Vec<(u32, Vec<u8>)>,
    Vec<Vec<u8>>,
) {
    let bs = 64usize;
    let lens = [200usize, 97]; // 4 slices (tail 8) + 2 slices (tail 33)
    let pristine: Vec<Vec<u8>> = lens
        .iter()
        .enumerate()
        .map(|(i, &l)| payload_bytes(l, i as u64 + 10))
        .collect();
    // Global padded slices in file order.
    let mut slices: Vec<Vec<u8>> = Vec::new();
    for d in &pristine {
        for c in d.chunks(bs) {
            let mut v = c.to_vec();
            v.resize(bs, 0);
            slices.push(v);
        }
    }
    let recovery: Vec<(u32, Vec<u8>)> = (0..4u32)
        .map(|e| (e, generate_recovery(&slices, bs, e)))
        .collect();
    let mut files: Vec<(Par2File, Vec<bool>)> = Vec::new();
    for (fi, d) in pristine.iter().enumerate() {
        let n = d.len().div_ceil(bs);
        let mut present = vec![true; n];
        for &(df, di) in damage {
            if df == fi {
                present[di] = false;
            }
        }
        files.push((
            Par2File {
                file_id: [fi as u8; 16],
                name: format!("f{fi}.bin"),
                length: d.len() as u64,
                md5: Md5::digest(d).into(),
                md5_16k: Md5::digest(d).into(),
                blocks: Vec::new(),
            },
            present,
        ));
    }
    (files, bs, recovery, pristine)
}

fn payload_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s >> 24) as u8
        })
        .collect()
}

/// The verify-failure fold retry (fast PAR mode's safety net): an
/// NTT that produces wrong syndromes fails whole-file verification,
/// and the driver must transparently redo the repair on the fold
/// path AND record the divergence for field telemetry. Same for an
/// NTT that panics outright. Both scenarios run inside ONE test
/// because the divergence log is process-global: draining it here
/// cannot race another test's events.
/// The default retention budget scales to the machine: the flat
/// 4 GiB ceiling holds on big RAM, small hosts get RAM/4, and a
/// cgroup limit (the OOM-kill line) caps at a quarter regardless of
/// host RAM - an OOM kill is the one failure the verify-retry
/// cannot rescue, so the budget must gate dispatch up front.
#[test]
fn ntt_default_budget_scales_to_the_machine() {
    let gib = 1u64 << 30;
    // The flat ceiling is 4 GiB, which a 32-bit `usize` cannot hold, so
    // there it lands on the address-space ceiling instead. Naming the
    // expectation per width keeps BOTH facts pinned; writing
    // `(4 * gib) as usize` here is what let the production wrap-to-zero
    // through in the first place (the cast agreed with itself).
    #[cfg(target_pointer_width = "32")]
    let ceil = 1usize << 30;
    #[cfg(not(target_pointer_width = "32"))]
    let ceil = (4 * gib) as usize;
    assert_eq!(ntt_default_budget(None, None), ceil);
    assert_eq!(ntt_default_budget(Some(64 * gib), None), ceil);
    assert_eq!(
        ntt_default_budget(Some(8 * gib), None),
        ((2 * gib) as usize).min(ceil)
    );
    assert_eq!(ntt_default_budget(Some(4 * gib), None), gib as usize);
    assert_eq!(
        ntt_default_budget(Some(64 * gib), Some(2 * gib)),
        (gib / 2) as usize,
        "cgroup limit caps regardless of host RAM"
    );
    // A budget is never zero and never wraps, whatever the probes say.
    // The 4 GiB ceiling is exactly 2^32: `b as usize` used to hand a
    // 32-bit host a budget of 0, which fails the gate for every corpus
    // and made the NTT path unreachable on armv7 without one line of
    // code saying so.
    assert!(ntt_default_budget(None, None) >= gib as usize);
    // The heavy benchmark corpus (~0.93 GiB) still clears the gate
    // on a 16 GiB machine (budget 4 GiB, or the 1 GiB address-space
    // ceiling on 32-bit - the corpus fits either) but not on a 2 GiB
    // one.
    assert!(ntt_gates_pass(
        65536,
        14884,
        1500,
        1499,
        ntt_default_budget(Some(16 * gib), None)
    ));
    assert!(!ntt_gates_pass(
        65536,
        14884,
        1500,
        1499,
        ntt_default_budget(Some(2 * gib), None)
    ));
}

/// Serializes the tests that touch the process-global fast-par
/// state (breaker, setting, divergence log) against each other.
static NTT_STATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn ntt_divergence_falls_back_to_fold_and_records() {
    let _g = NTT_STATE.lock_ok();
    FAST_PAR_TRIPPED.store(false, std::sync::atomic::Ordering::Relaxed);
    let _ = take_ntt_divergences(); // start from a clean log
    for (path, expect_panicked) in [
        (SyndromePath::NttForceCorrupt(usize::MAX), false),
        (SyndromePath::NttForcePanic(usize::MAX), true),
    ] {
        let damage = [(0usize, 1usize), (1usize, 0usize)];
        let (files, bs, recovery, pristine) = mapped_fixture(&damage);
        let io = MemIo::new(
            files
                .iter()
                .zip(&pristine)
                .map(|((_, present), d)| {
                    // Zero the damaged blocks so a "repair" that did
                    // nothing cannot pass verification by accident.
                    let mut v = d.clone();
                    for (i, &p) in present.iter().enumerate() {
                        if !p {
                            let end = ((i + 1) * bs).min(v.len());
                            v[i * bs..end].fill(0);
                        }
                    }
                    v
                })
                .collect(),
            None,
        );
        let n = repair_mapped_with_path(&files, bs, &recovery, &io, false, path)
            .unwrap_or_else(|e| panic!("fold retry did not rescue {path:?}: {e}"));
        assert_eq!(n, 2, "both damaged blocks rebuilt ({path:?})");
        assert_eq!(io.snapshot(), pristine, "retry output pristine ({path:?})");
        assert!(fast_par_tripped(), "divergence must trip the breaker");
        let events: Vec<NttDivergence> = take_ntt_divergences()
            .into_iter()
            .filter(|d| d.context == "f0.bin" && d.panicked == expect_panicked)
            .collect();
        assert_eq!(events.len(), 1, "one recorded divergence ({path:?})");
        let d = &events[0];
        assert_eq!((d.m, d.block_size), (2, bs), "geometry recorded ({path:?})");
        if !expect_panicked {
            assert_eq!(d.n_present, 4, "present slices recorded");
        }
    }
    // Reset the process-global breaker: dispatch-path tests elsewhere
    // read it, and test order must not matter.
    FAST_PAR_TRIPPED.store(false, std::sync::atomic::Ordering::Relaxed);
}

/// The daemon's "fast par mode" setting reaches the dispatcher, and
/// the trip-breaker overrides it; the explicit NttForce test hook
/// ignores both (it models the env escape hatch's precedence).
#[test]
fn fast_par_setting_gates_the_auto_path() {
    if ntt_env_knob_set() {
        return; // the env overrides are exercised manually, not here
    }
    let _g = NTT_STATE.lock_ok();
    // A shape that passes every gate on any host.
    let (bs, n_inputs, m) = MINIMAL_NTT_SHAPE;
    let exps: Vec<u32> = (0..m as u32).collect();
    let resolve = || resolve_syndrome_path(SyndromePath::Auto, bs, n_inputs, m, &exps);
    set_fast_par_enabled(false);
    assert!(resolve().is_none(), "setting off: fold");
    set_fast_par_enabled(true);
    assert!(resolve().is_some(), "setting on + gates pass: NTT");
    FAST_PAR_TRIPPED.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(resolve().is_none(), "tripped breaker forces fold");
    assert!(
        resolve_syndrome_path(SyndromePath::NttForce(usize::MAX), bs, n_inputs, m, &exps).is_some(),
        "explicit force path ignores the breaker"
    );
    FAST_PAR_TRIPPED.store(false, std::sync::atomic::Ordering::Relaxed);
    set_fast_par_enabled(false);
    // Gates still apply on the setting path: the 3-block shape folds.
    set_fast_par_enabled(true);
    let small: Vec<u32> = (0..3).collect();
    assert!(
        resolve_syndrome_path(SyndromePath::Auto, bs, n_inputs, 3, &small).is_none(),
        "small shapes stay on the fold even with the setting on"
    );
    set_fast_par_enabled(FAST_PAR_DEFAULT);
}

/// Non-daemon entry points (the CLI) never call
/// [`set_fast_par_enabled`]; they get [`FAST_PAR_DEFAULT`] because
/// it is the flag's initializer. This pins the default itself -
/// flipping it is a product decision (2026-07-31: ON), not a
/// side effect.
#[test]
fn fast_par_defaults_on_for_every_entry_point() {
    assert!(FAST_PAR_DEFAULT, "fast par mode ships default ON");
}

/// The self-prove covers the WHOLE SET, not just the files that
/// received a rebuilt block.
///
/// The present-block ledger comes from verification done as the bytes
/// ARRIVED, off the wire - never off disk. So a covered file whose
/// bytes went bad after they were written (a failed pwrite, a bad
/// sector) is "present" as far as this driver knows, is never
/// rebuilt, and used to sail through a successful repair into a
/// Completed job. The directory path never had that hole because par2
/// reads the whole set off disk.
#[test]
fn mapped_driver_rereads_files_it_did_not_rebuild() {
    // IFSC checksums present, so an untouched file takes the cheap
    // per-block CRC32 path rather than MD5.
    let with_ifsc = |files: &mut Vec<(Par2File, Vec<bool>)>, pristine: &[Vec<u8>], bs: usize| {
        for ((f, _), data) in files.iter_mut().zip(pristine) {
            f.blocks = data
                .chunks(bs)
                .map(|c| {
                    let mut padded = c.to_vec();
                    padded.resize(bs, 0);
                    BlockCheck {
                        md5: Md5::digest(&padded).into(),
                        crc32: crc32fast::hash(&padded),
                    }
                })
                .collect();
        }
    };

    for full_verify in [false, true] {
        let damage = [(0usize, 1usize)];
        let (mut files, bs, recovery, pristine) = mapped_fixture(&damage);
        with_ifsc(&mut files, &pristine, bs);

        // File 0 is damaged and will be rebuilt. File 1 is untouched by
        // the repair, and goes bad on disk once the syndrome reads are
        // done - so nothing but the self-prove can notice. (Rotting it
        // up front instead would poison the reconstruction itself,
        // which is a different, already-covered failure.)
        let mut on_disk = pristine.clone();
        on_disk[0][bs..2 * bs].fill(0);
        let io = MemIo::rotting(on_disk, (1, 3));

        let got = repair_mapped(&files, bs, &recovery, &io, full_verify);
        assert!(
            matches!(&got, Err(RepairError::VerifyFailed(n)) if n == "f1.bin"),
            "a repair that left a corrupt covered file did not fail on it \
             (full_verify={full_verify}): {got:?}"
        );
    }

    // ...and the same set with an intact file 1 still repairs, so the
    // new read is a check and not a blocker.
    let damage = [(0usize, 1usize)];
    let (mut files, bs, recovery, pristine) = mapped_fixture(&damage);
    with_ifsc(&mut files, &pristine, bs);
    let mut on_disk = pristine.clone();
    on_disk[0][bs..2 * bs].fill(0);
    let io = MemIo::new(on_disk, None);
    assert_eq!(
        repair_mapped(&files, bs, &recovery, &io, false).expect("repairs"),
        1
    );
    assert_eq!(io.snapshot(), pristine, "byte-identical restoration");
}

#[test]
fn mapped_driver_rebuilds_and_self_verifies() {
    let damage = [(0usize, 1usize), (0, 3), (1, 1)]; // incl. both tails
    let (files, bs, recovery, pristine) = mapped_fixture(&damage);
    let io = MemIo::new(
        pristine
            .iter()
            .enumerate()
            .map(|(fi, d)| {
                let mut v = d.clone();
                // Zero the damaged blocks' bytes so a bug that skips
                // rebuilding can't accidentally verify.
                for &(df, di) in &damage {
                    if df == fi {
                        let s = di * bs;
                        let e = (s + bs).min(v.len());
                        v[s..e].fill(0);
                    }
                }
                v
            })
            .collect(),
        None,
    );
    let n = repair_mapped(&files, bs, &recovery, &io, false).expect("repairs");
    assert_eq!(n, 3);
    assert_eq!(io.snapshot(), pristine, "byte-identical restoration");
}

#[test]
fn mapped_driver_parallel_readers_many_slices() {
    // M2c.2: enough slices that every reader thread gets a real
    // contiguous chunk (chunks straddle file boundaries), varied
    // file lengths incl. a zero-length file and odd tails. Damage
    // spread across files; result must be byte-identical.
    let bs = 64usize;
    let lens = [0usize, 64 * 37 + 9, 64 * 3, 97, 64 * 41, 64 * 20 + 33];
    let pristine: Vec<Vec<u8>> = lens
        .iter()
        .enumerate()
        .map(|(i, &l)| payload_bytes(l, i as u64 + 99))
        .collect();
    let mut slices: Vec<Vec<u8>> = Vec::new();
    for d in &pristine {
        for c in d.chunks(bs) {
            let mut v = c.to_vec();
            v.resize(bs, 0);
            slices.push(v);
        }
    }
    assert!(
        slices.len() > 100,
        "fixture must exceed one reader chunk each"
    );
    let damage: &[(usize, usize)] = &[(1, 0), (1, 36), (2, 1), (3, 0), (4, 40), (5, 20)];
    let recovery: Vec<(u32, Vec<u8>)> = (0..damage.len() as u32)
        .map(|e| (e, generate_recovery(&slices, bs, e)))
        .collect();
    let mut files: Vec<(Par2File, Vec<bool>)> = Vec::new();
    for (fi, d) in pristine.iter().enumerate() {
        let n = d.len().div_ceil(bs);
        let mut present = vec![true; n];
        for &(df, di) in damage {
            if df == fi {
                present[di] = false;
            }
        }
        files.push((
            Par2File {
                file_id: [fi as u8; 16],
                name: format!("f{fi}.bin"),
                length: d.len() as u64,
                md5: Md5::digest(d).into(),
                md5_16k: Md5::digest(d).into(),
                blocks: Vec::new(),
            },
            present,
        ));
    }
    let io = MemIo::new(
        pristine
            .iter()
            .enumerate()
            .map(|(fi, d)| {
                let mut v = d.clone();
                for &(df, di) in damage {
                    if df == fi {
                        let s = di * bs;
                        let e = (s + bs).min(v.len());
                        v[s..e].fill(0);
                    }
                }
                v
            })
            .collect(),
        None,
    );
    let n = repair_mapped(&files, bs, &recovery, &io, false).expect("repairs");
    assert_eq!(n, damage.len());
    assert_eq!(io.snapshot(), pristine, "byte-identical restoration");
}

#[test]
fn mapped_driver_catches_a_lying_write_path() {
    let damage = [(0usize, 1usize)];
    let (files, bs, recovery, pristine) = mapped_fixture(&damage);
    let io = MemIo::new(pristine.clone(), Some((0, bs + 5))); // inside the rebuilt block
    match repair_mapped(&files, bs, &recovery, &io, false) {
        Err(RepairError::VerifyFailed(name)) => assert_eq!(name, "f0.bin"),
        other => panic!("expected VerifyFailed, got {other:?}"),
    }
}

#[test]
fn mapped_driver_rejects_short_recovery_and_bad_present_len() {
    let (files, bs, recovery, pristine) = mapped_fixture(&[(0, 0), (0, 1), (0, 2), (1, 0), (1, 1)]);
    let io = MemIo::new(pristine.clone(), None);
    // 5 missing, only 4 recovery slices. NOT `Malformed` (§282 item
    // 15): a set that simply does not carry enough recovery is the
    // everyday shortfall, and calling it malformed sent readers after
    // a corrupt PAR2 set when the set was fine.
    assert!(matches!(
        repair_mapped(&files, bs, &recovery, &io, false),
        Err(RepairError::RecoveryShort { have: 4, need: 5 })
    ));
    // Present-vector length mismatch, which IS malformed input - the
    // caller's ledger contradicts the FileDesc, and no amount of
    // recovery data would make it coherent. The pair is the point:
    // these two are different failures and now say so.
    let mut bad = files.clone();
    bad[0].1.push(true);
    assert!(matches!(
        repair_mapped(&bad, bs, &recovery, &io, false),
        Err(RepairError::Malformed(_))
    ));
    // No damage at all is a no-op success.
    let clean: Vec<(Par2File, Vec<bool>)> = files
        .iter()
        .map(|(f, p)| (f.clone(), vec![true; p.len()]))
        .collect();
    assert_eq!(repair_mapped(&clean, bs, &recovery, &io, false).unwrap(), 0);
    assert_eq!(io.snapshot(), pristine, "no-op wrote nothing");
}

/// Every block of every mapped file missing (a par-only post, or a
/// posted set whose data articles were all lost, recovery
/// plentiful): parity as a source. There are no present slices to
/// stream, so the recovery slices ARE the syndromes and the solve
/// rebuilds the whole set from them alone - byte-identical, MD5
/// self-proved through the same io. (This used to DECLINE - and
/// before that, `work.chunks(0)` panicked here.)
#[test]
fn mapped_driver_rebuilds_a_wholly_missing_set_from_parity_alone() {
    let bs = 64usize;
    let lens = [200usize, 97]; // 4 slices (odd tail) + 2 slices
    let pristine: Vec<Vec<u8>> = lens
        .iter()
        .enumerate()
        .map(|(i, &l)| payload_bytes(l, i as u64 + 42))
        .collect();
    let mut slices: Vec<Vec<u8>> = Vec::new();
    for d in &pristine {
        for c in d.chunks(bs) {
            let mut v = c.to_vec();
            v.resize(bs, 0);
            slices.push(v);
        }
    }
    let recovery: Vec<(u32, Vec<u8>)> = (0..slices.len() as u32)
        .map(|e| (e, generate_recovery(&slices, bs, e)))
        .collect();
    let files: Vec<(Par2File, Vec<bool>)> = pristine
        .iter()
        .enumerate()
        .map(|(fi, d)| {
            (
                Par2File {
                    file_id: [fi as u8 + 7; 16],
                    name: format!("f{fi}.bin"),
                    length: d.len() as u64,
                    md5: Md5::digest(d).into(),
                    md5_16k: Md5::digest(d).into(),
                    blocks: Vec::new(),
                },
                vec![false; d.len().div_ceil(bs)],
            )
        })
        .collect();
    let io = MemIo::new(pristine.iter().map(|d| vec![0u8; d.len()]).collect(), None);
    let n = repair_mapped(&files, bs, &recovery, &io, false).expect("rebuilds from parity");
    assert_eq!(n, slices.len(), "every block rebuilt");
    assert_eq!(io.snapshot(), pristine, "byte-identical reconstruction");
}

/// The parity-alone rebuild with too FEW recovery slices must still
/// fail loudly, not fabricate bytes: one slice short of the set.
#[test]
fn mapped_driver_wholly_missing_set_short_recovery_declines() {
    let bs = 64usize;
    let pristine = payload_bytes(200, 43); // 4 slices
    let mut slices: Vec<Vec<u8>> = Vec::new();
    for c in pristine.chunks(bs) {
        let mut v = c.to_vec();
        v.resize(bs, 0);
        slices.push(v);
    }
    let recovery: Vec<(u32, Vec<u8>)> = (0..slices.len() as u32 - 1)
        .map(|e| (e, generate_recovery(&slices, bs, e)))
        .collect();
    let files = vec![(
        Par2File {
            file_id: [9u8; 16],
            name: "f.bin".into(),
            length: pristine.len() as u64,
            md5: Md5::digest(&pristine).into(),
            md5_16k: Md5::digest(&pristine).into(),
            blocks: Vec::new(),
        },
        vec![false; slices.len()],
    )];
    let io = MemIo::new(vec![vec![0u8; pristine.len()]], None);
    assert!(
        repair_mapped(&files, bs, &recovery, &io, false).is_err(),
        "3 recovery slices cannot rebuild 4 missing blocks"
    );
}

#[test]
fn rolling_crc_matches_crc32fast_at_every_offset() {
    for &window in &[4usize, 6, 64, 1000] {
        let data: Vec<u8> = (0..2500u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        let roll = RollingCrc::new(window);
        let mut reg = 0xFFFF_FFFFu32;
        for &b in &data[..window] {
            reg = roll.push(reg, b);
        }
        assert_eq!(reg ^ !0, crc32fast::hash(&data[..window]), "w{window} o0");
        for o in 1..=data.len() - window {
            reg = roll.roll(reg, data[o - 1], data[o + window - 1]);
            assert_eq!(
                reg ^ !0,
                crc32fast::hash(&data[o..o + window]),
                "window {window} offset {o}"
            );
        }
        // Virtual zero tail: rolling zeros in must equal the CRC of
        // the zero-padded final windows (the spec's padded tail).
        let mut padded = data.clone();
        padded.resize(data.len() + window - 1, 0);
        for o in data.len() - window + 1..data.len() {
            reg = roll.roll(reg, padded[o - 1], padded[o + window - 1]);
            assert_eq!(
                reg ^ !0,
                crc32fast::hash(&padded[o..o + window]),
                "padded window {window} offset {o}"
            );
        }
    }
}

#[test]
fn singular_matrix_is_reported() {
    // Duplicate rows are singular by construction.
    let a = vec![vec![1u16, 2], vec![1u16, 2]];
    assert!(matches!(invert(a), Err(RepairError::SingularMatrix)));
}

/// The structured Vandermonde inverse must equal the Gauss-Jordan
/// inverse EXACTLY (the inverse is unique) for consecutive
/// exponents, at small and fanned-out sizes, with and without an
/// exponent offset e0, and on non-prefix missing sets (scattered
/// bases). This is the differential oracle for the O(m²) path.
#[test]
fn vandermonde_inverse_matches_gauss_jordan() {
    for (m, e0, scatter) in [
        (1usize, 0u32, false),
        (2, 0, false),
        (5, 3, true),
        (37, 0, true),
        (PAR_INVERT_MIN + 16, 2, true),
    ] {
        // Scattered missing sets exercise non-contiguous bases.
        let logs = input_base_logs(if scatter { m * 3 } else { m }).unwrap();
        let ks: Vec<u32> = (0..m)
            .map(|i| logs[if scatter { i * 3 + 1 } else { i }])
            .collect();
        let a: Vec<Vec<u16>> = (0..m)
            .map(|r| {
                ks.iter()
                    .map(|&k| gf16::pow2(k as u64 * (e0 as u64 + r as u64)))
                    .collect()
            })
            .collect();
        let want = invert(a).expect("PAR2-shaped matrix inverts");
        let got = invert_vandermonde(&ks, e0).expect("distinct bases cannot fail");
        assert_eq!(got, want, "m={m} e0={e0} scatter={scatter}");
    }
}

/// The fanned-out inversion must agree with the serial one exactly
/// (the inverse is unique, so pivot-order differences must wash
/// out), at a size past PAR_INVERT_MIN so the parallel path really
/// runs. Also: a singular matrix that large must still be REPORTED,
/// not solved wrong or deadlocked on - every worker has to leave the
/// barrier dance on the same column.
#[test]
fn parallel_invert_matches_serial_and_reports_singular() {
    let m = PAR_INVERT_MIN + 32;
    let logs = input_base_logs(m).unwrap();
    let a: Vec<Vec<u16>> = (0..m)
        .map(|e| {
            (0..m)
                .map(|j| gf16::pow2(logs[j] as u64 * e as u64))
                .collect()
        })
        .collect();
    let par = invert(a.clone()).expect("PAR2-shaped matrix inverts");
    let ser = invert_serial(a.clone()).expect("serial agrees it inverts");
    assert_eq!(par, ser, "parallel and serial inverses must be identical");

    let mut sing = a;
    sing[m - 1] = sing[0].clone(); // duplicate row: singular
    assert!(matches!(invert(sing), Err(RepairError::SingularMatrix)));
}

/// [`MAX_REPAIR_DIM`] is the repair-time DoS ceiling, and TODO §283 item
/// 14 doubted it was enforced anywhere but the mapped planner in
/// `crates/nzbfast/src/repair.rs` - which only DECLINES its own route and
/// falls through to the disk one. It is enforced here, in the engine
/// constructor all three routes funnel through, and nothing pinned the
/// boundary until this test.
///
/// Measured on an M3 Ultra, release, 24 Aug 2026, so the ceiling's own
/// arithmetic is on the record rather than extrapolated: AT the cap a
/// consecutive-exponent set (the Vandermonde shortcut, O(m^2)) inverts in
/// 62 ms, and a GAPPED one - recovery packets themselves lost, so
/// Gauss-Jordan O(m^3) - takes 23.7 s. That is the worst case the
/// constant deliberately admits. One doubling costs 8x, so the spec's own
/// 32768-slice bound would be ~25 minutes and ~4.3 GB, which is exactly
/// the "pin multiple GB and run for hours" the doc block describes.
///
/// Both arms are gate-isolated rather than run for real: each asserts
/// WHICH refusal comes back, so a later edit that moves the cap behind
/// another check fails here instead of quietly costing the 23.7 s.
#[test]
fn the_repair_matrix_cap_binds_at_exactly_max_repair_dim() {
    let bs = 2usize;
    // One over: refused, and refused BEFORE the per-slice length check -
    // the recovery buffers here are the wrong size on purpose, so a cap
    // that ever moved below the syndrome-widening loop would report that
    // instead, having already allocated m of them.
    let over = MAX_REPAIR_DIM + 1;
    let missing: Vec<usize> = (0..over).collect();
    let recovery: Vec<(u32, Vec<u8>)> = (0..over as u32).map(|e| (e, vec![0u8; bs + 2])).collect();
    let Err(err) = Reconstructor::new(bs, MAX_INPUT_SLICES, &missing, &recovery) else {
        panic!("one block over the cap must be refused");
    };
    assert!(
        matches!(&err, RepairError::Malformed(m)
            if m.contains(&format!("{over} missing blocks")) && m.contains("repair-matrix cap")),
        "the cap must be the reported reason, not a later check: {err}"
    );
    // Exactly at the cap: NOT refused by the cap. Proven by the next gate
    // down answering instead - `n_inputs` is deliberately far too small
    // for these indices, so the only way to reach that message is to have
    // cleared the dimension check at m == MAX_REPAIR_DIM.
    let missing: Vec<usize> = (0..MAX_REPAIR_DIM).collect();
    let recovery: Vec<(u32, Vec<u8>)> = (0..MAX_REPAIR_DIM as u32)
        .map(|e| (e, vec![0u8; bs]))
        .collect();
    let Err(err) = Reconstructor::new(bs, 16, &missing, &recovery) else {
        panic!("16 inputs cannot hold slice 16");
    };
    assert!(
        matches!(&err, RepairError::Malformed(m) if m.contains("out of range")),
        "the cap must admit exactly MAX_REPAIR_DIM, not one under: {err}"
    );
}
