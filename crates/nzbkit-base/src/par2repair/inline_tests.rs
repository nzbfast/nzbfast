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

/// M4-44: the same question one fold weaker. Every pair below is ONE
/// file object on APFS (measured 31 Aug 2026) and was TWO keys under the
/// `str::to_lowercase` this site used until then - so the colliding-target
/// guard saw no collision and let one target's repair land over another's
/// bytes, the adoption scan left the file holding the missing blocks in
/// `exclude` and reported Unrepairable, and the spent-donor sweep could
/// DELETE a target it had just written.
///
/// `name_identity_key` is checked too and is not the same test: it
/// sanitizes first, so it has to fold what `sanitize_out_name` LEAVES.
#[test]
fn destination_identity_folds_the_way_the_volume_does() {
    for (a, b) in [
        ("/out/Straße.mkv", "/out/STRASSE.MKV"),
        ("/out/ﬁle.txt", "/out/file.txt"),
        ("/out/ſample.par2", "/out/sample.par2"),
    ] {
        assert_eq!(
            path_identity_key(true, Path::new(a)),
            path_identity_key(true, Path::new(b)),
            "{a} and {b} name ONE object on a case-insensitive volume"
        );
        assert_ne!(
            path_identity_key(false, Path::new(a)),
            path_identity_key(false, Path::new(b)),
            "{a} and {b} are distinct on a case-sensitive volume"
        );
    }
    assert_eq!(
        name_identity_key(true, "Straße.mkv"),
        name_identity_key(true, "STRASSE.MKV")
    );
    // Over-folding costs a `.dup-<fid>` suffix on a correctly repaired
    // file here, so it is cheap but not free: APFS keeps these apart and
    // so must the fold.
    assert_ne!(
        path_identity_key(true, Path::new("/out/I.bin")),
        path_identity_key(true, Path::new("/out/ı.bin"))
    );
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

#[test]
fn in_place_feed_batch_fill_commits_only_complete_slices() {
    let mut batch = FeedBatch::with_capacity(16);
    batch
        .push_with(7, 4, |dst| {
            dst.copy_from_slice(b"good");
            Ok::<_, ()>(())
        })
        .unwrap();
    assert_eq!(batch.arena, b"good");
    assert_eq!(batch.slices, vec![(7, 0, 4)]);
    assert_eq!(batch.charged_bytes(), 4);

    let error = batch.push_with(11, 5, |dst| {
        dst.copy_from_slice(b"short");
        Err::<(), _>("read failed")
    });
    assert_eq!(error, Err("read failed"));
    assert_eq!(batch.arena, b"good", "failed read reservation rolled back");
    assert_eq!(batch.slices, vec![(7, 0, 4)], "no partial slice fed");
    assert_eq!(batch.charged_bytes(), 4, "partial bytes were not charged");
}

/// A folded batch's arena comes back out of the pool with its capacity
/// and no contents; past the cap it is dropped; and the gauge carries a
/// pooled arena at capacity, a taken one at nothing.
#[test]
fn arena_pool_recycles_up_to_its_cap() {
    let pool = linalg::ArenaPool::new(1);
    let mut a = pool.take(64);
    a.push(1, &[7u8; 40]);
    let cap_a = a.arena.capacity();
    assert!(cap_a >= 64);
    let b = pool.take(64);
    pool.put(a);
    assert_eq!(pool.pooled(), 1);
    pool.put(b);
    assert_eq!(
        pool.pooled(),
        1,
        "second arena past the cap is freed, not kept"
    );
    let c = pool.take(64);
    assert_eq!(
        c.arena.capacity(),
        cap_a,
        "the pooled arena is the one handed back"
    );
    assert!(c.arena.is_empty() && c.slices.is_empty());
    assert_eq!(c.charged_bytes(), 0);
    assert_eq!(pool.pooled(), 0);
    let d = pool.take(cap_a * 4);
    assert!(
        d.arena.capacity() >= cap_a * 4,
        "a too-small pooled arena is not handed out"
    );
}

/// Sources packed once at read (`prepack_planar_in_place`) and folded
/// through `fold_parallel_prepacked` must equal the plain fold over the
/// interleaved bytes, tile edges and column splits included.
#[test]
fn prepacked_fold_matches_plain_fold() {
    let words = 4096 + 2048 + 32; // tiles plus one packed chunk, not a power of two
    let rows = 11;
    if !linalg::prepacked_fold_admissible(words, rows) {
        return; // planar kernel not selected on this host
    }
    let n = 9;
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let raw: Vec<Vec<u8>> = (0..n)
        .map(|_| (0..words * 2).map(|_| next() as u8).collect())
        .collect();
    let mut packed = raw.clone();
    for p in packed.iter_mut() {
        assert!(crate::gf16::prepack_planar_in_place(p));
    }
    let coeff = |j: usize, i: usize| crate::gf16::pow2((j as u64 + 1) * (i as u64 * 7 + 3));
    let mut plain: Vec<Vec<u16>> = vec![vec![0x5a5a; words]; rows];
    let mut viaprepack = plain.clone();
    let raw_refs: Vec<&[u8]> = raw.iter().map(|v| v.as_slice()).collect();
    let packed_refs: Vec<&[u8]> = packed.iter().map(|v| v.as_slice()).collect();
    fold_parallel(&mut plain, &raw_refs, &coeff, None);
    linalg::fold_parallel_prepacked(&mut viaprepack, &packed_refs, &coeff, None);
    assert_eq!(plain, viaprepack);
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
        fold_parallel(&mut got, &src_refs, &|j, i| coeffs[j][i], None);
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
    assert!(ntt_gates_pass(65536, 14884, 1500, 1499, budget, false));
    // Light/medium damage: fold.
    assert!(!ntt_gates_pass(65536, 16381, 3, 2, budget, false));
    assert!(!ntt_gates_pass(65536, 16283, 101, 100, budget, false));
    // Just under the row gate: fold; at it: transform. The gate is the
    // arch's re-measured constant (`ntt_min_missing`: 192 on aarch64
    // since the paired leaf moved the M3's crossover to ~160, 320 on the
    // x86 arms until their sweep lands), so pin it relative to that.
    let gate = ntt_min_missing();
    assert!(!ntt_gates_pass(
        65536,
        16384 - gate + 1,
        gate - 1,
        gate - 2,
        budget,
        false
    ));
    assert!(ntt_gates_pass(
        65536,
        16384 - gate,
        gate,
        gate - 1,
        budget,
        false
    ));
    // The small-source shape this test asserted the FOLD for until
    // 7 Sep 2026 - 640 KiB blocks, 870 present, 768 missing - is a
    // transform win, and the 8,192 present floor was the only reason it
    // folded. Measured on the M3 Ultra at 872 present: 29.03 CPU-s
    // against the fold's 39.00, -26%, 1.34x on feed+fold+solve, eleven
    // mirrored legs, every one SHA-identical to the pristine corpus
    // (research/NTT-MIN-PRESENT-CROSSOVER-2026-09-07.md).
    assert!(ntt_gates_pass(655360, 870, 768, 767, budget, false));
    // What still folds, stated against the constants rather than a
    // literal so a re-sweep moves the shape with the gate. Under the
    // present floor: fold, however deep the damage.
    let (min_p, min_w, min_m) = (NTT_MIN_PRESENT, NTT_MIN_WORK, ntt_min_missing());
    assert!(!ntt_gates_pass(
        655360,
        min_p - 1,
        4096,
        4095,
        budget,
        false
    ));
    assert!(ntt_gates_pass(655360, min_p, 4096, 4095, budget, false));
    // Over the present floor but under the WORK floor: fold. This is
    // the clause a single flat present count cannot express - at the row
    // gate's own minimum the measured crossover is ~1,630 present on
    // NEON, 3x the floor, and it falls as 1/m from there.
    let thin = min_w / min_m;
    assert!(thin > min_p, "the work floor is what binds at the row gate");
    assert!(!ntt_gates_pass(
        65536,
        thin - 1,
        min_m,
        min_m - 1,
        budget,
        false
    ));
    assert!(ntt_gates_pass(
        65536,
        thin + 1,
        min_m,
        min_m - 1,
        budget,
        false
    ));
    // The exponent SPAN gate, at its boundary and stated against the
    // constant rather than a literal, so a re-sweep moves the shape with
    // the gate. It fires when recovery VOLUMES are missing and what
    // survives is a union of ranges, which is why the admitted side
    // below is the realistic one.
    let span_gate = (14884 * 1500usize).div_ceil(NTT_MIN_WORK_PER_ROW);
    assert!(!ntt_gates_pass(
        65536, 14884, 1500, span_gate, budget, false
    ));
    assert!(ntt_gates_pass(
        65536,
        14884,
        1500,
        span_gate - 1,
        budget,
        false
    ));
    // The floor arm: a set posted whole spans `m - 1` and is admitted
    // whatever the work per row says, which is what keeps the ordinary
    // shape on the transform at the low present counts NTT_MIN_PRESENT
    // admits. 320 present at m = 2,048 carries 853 of work per row,
    // well under the gate, so it is admitted consecutive and refused
    // one row wider - the corner the flat factor of 3 got wrong, where
    // the M3 measured 0.92-0.95 against the fold (8 Sep 2026).
    assert!(ntt_gates_pass(65536, 320, 2048, 2047, budget, false));
    assert!(!ntt_gates_pass(65536, 320, 2048, 2048, budget, false));
    // The span is what the plan produces: a consecutive set that starts
    // at 8,192 spans 1,499 rows, and a stride-2 set from 11 relabels to
    // the same, so both are admitted where the prefix (8,192 or 3,009
    // rows) was refused above.
    // (The span honours the two A/B knobs - with the range plan off it
    // IS the prefix - so the expectations hold for the shipped default.)
    if std::env::var_os("NZBFAST_REPAIR_NTT_RANGE").is_none()
        && std::env::var_os("NZBFAST_REPAIR_NTT_PROGRESSION").is_none()
    {
        let high: Vec<u32> = (8192..8192 + 1500).collect();
        assert_eq!(exponent_span(&high), 1499);
        let stepped: Vec<u32> = (0..1500).map(|i| 11 + 2 * i).collect();
        assert_eq!(exponent_span(&stepped), 1499);
        let gappy = [0u32, 1, 4500];
        assert_eq!(exponent_span(&gappy), 4500);
    }
    // Corpus over the memory budget with windows off: fold (amendment 2).
    assert!(!ntt_gates_pass(65536, 14884, 1500, 1499, gib / 2, false));
    // ...and with them on it is admitted, because half a gibibyte holds
    // 8,192 of that set's 64 KiB blocks - well past the window floor.
    // The corpus clause is a floor on ONE window now, not on the whole
    // corpus; the budget, and so the peak resident set, is untouched.
    assert!(ntt_gates_pass(65536, 14884, 1500, 1499, gib / 2, true));
    // A budget too small to hold a window worth transforming folds
    // even with windows on: the shape clauses pass, the retention one
    // does not.
    let thin = (NTT_MIN_WINDOW_PRESENT - 1) * 65536;
    assert!(!ntt_gates_pass(65536, 14884, 1500, 1499, thin, true));
    assert!(ntt_gates_pass(
        65536,
        14884,
        1500,
        1499,
        NTT_MIN_WINDOW_PRESENT * 65536,
        true
    ));
    // The shape gates still decide first: a window-sized budget cannot
    // buy the transform for a 101-block repair.
    assert!(!ntt_gates_pass(
        65536,
        16283,
        101,
        100,
        NTT_MIN_WINDOW_PRESENT * 65536,
        true
    ));
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
/// every clause of [`ntt_gates_pass`]: `NTT_MIN_MISSING` missing, the
/// present count both present clauses want at that depth, and a max
/// exponent one under `m` and so inside the 3x factor. At a 1 KiB block
/// the stripe geometry is one stripe wide, so the worker count clamps
/// to 1 on EVERY machine and the whole footprint is ~1 MB of corpus
/// plus a single worker's arena. The admission tests use this rather than the
/// 64 KiB/16384/1500 benchmark leg because that leg needs 930 MB of
/// corpus budget on top of a core-count-dependent arena charge,
/// which made the expected value a function of the host's RAM, its
/// cgroup limit and its visible parallelism: red on a 4 GiB dev box,
/// in a `--memory=4g` container on a many-core host, and under any
/// exported `NZBFAST_NTT_BUDGET`.
///
/// Derived from the gates rather than written down: a shape that stops
/// being minimal when a gate moves stops testing the gate's boundary,
/// and both the present floor and the work floor moved on 7 Sep 2026.
/// A function and not a `const` because [`ntt_min_missing`] is
/// per-arch, and the present count the work floor asks for follows it.
fn minimal_ntt_shape() -> (usize, usize, usize) {
    let m = NTT_MIN_MISSING.max(ntt_min_missing());
    let present = NTT_MIN_PRESENT.max(NTT_MIN_WORK.div_ceil(m));
    (1024, present + m, m)
}

/// True when any NTT knob is exported. All five move what
/// [`resolve_syndrome_path`] returns - the budget directly, `W` and
/// `THREADS` through the arena charge, `STREAM` through the retention
/// clause - so the admission tests opt out wholesale rather than fight
/// a bench operator's shell.
/// Mutating the vars from inside the test is not an option: the lib
/// tests run in parallel with other readers of them.
fn ntt_env_knob_set() -> bool {
    [
        "NZBFAST_NTT",
        "NZBFAST_NTT_BUDGET",
        "NZBFAST_NTT_W",
        "NZBFAST_NTT_THREADS",
        // The streaming-admission A/B arm: `=0` restores the flat
        // "the corpus must fit" clause, which is the one thing the
        // over-budget admission test asserts against.
        "NZBFAST_NTT_STREAM",
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
    let (bs, n_inputs, m) = minimal_ntt_shape();
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

/// The dispatcher's half of the streaming admission: a corpus BIGGER
/// than the retention budget is selected for the transform, and the
/// budget it hands back is the WINDOW the fold worker fills, transforms
/// and releases - not a promise that the corpus fits.
///
/// Until 5 Sep 2026 the retention clause demanded the whole corpus fit,
/// so every repair larger than a quarter of the box's RAM streamed the
/// fold however big the machine was: a 16 GB box budgets 4 GiB, and the
/// 10 GiB / 900-row set measured 19.8 s on the fold against 9.2 s in
/// three windows on an M3 Ultra (SHA-gated, forced arms).
#[test]
fn ntt_auto_admits_a_corpus_bigger_than_the_budget() {
    if ntt_env_knob_set() {
        return; // the env overrides are exercised manually, not here
    }
    let _g = NTT_STATE.lock_ok();
    FAST_PAR_TRIPPED.store(false, std::sync::atomic::Ordering::Relaxed);
    set_fast_par_enabled(true);
    // A 1 KiB block, as in [`minimal_ntt_shape`] and for the same
    // reason: it keeps the window floor clear of this host's budget
    // whatever its RAM or cgroup limit, so the shape is decided by the
    // clause under test and not by the machine.
    let bs = 1024usize;
    let m = ntt_min_missing();
    let exps: Vec<u32> = (0..m as u32).collect();
    let corpus_budget = ntt_budget_env().saturating_sub(ntt_worker_arenas(bs, m));
    assert!(
        corpus_budget / bs >= NTT_MIN_WINDOW_PRESENT,
        "a 1 KiB block's window clears the floor on any host this builds for"
    );
    // Twice what the budget can retain, so the whole-corpus clause
    // cannot be what admits it.
    let n_present = (corpus_budget / bs).saturating_mul(2);
    assert!(n_present.saturating_mul(bs) > corpus_budget);
    assert_eq!(
        resolve_syndrome_path(SyndromePath::Auto, bs, n_present + m, m, &exps),
        Some(corpus_budget),
        "an over-budget corpus takes the transform one window at a time"
    );
    // ...and the retained-only arm (`NZBFAST_NTT_STREAM=0`) refuses
    // exactly this shape, which is what makes the assertion above about
    // the new clause rather than about the shape gates.
    assert!(!ntt_gates_pass(
        bs,
        n_present,
        m,
        m - 1,
        corpus_budget,
        false
    ));
    set_fast_par_enabled(FAST_PAR_DEFAULT);
}

/// Shrinking the admission tests to [`minimal_ntt_shape`] collapses
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

/// The default stripe width keys on the block size only on the x86
/// nibble arms: everywhere else it is 512 at every block size, and on
/// those arms it steps to 1,024 exactly at 1 MiB (the measured class,
/// see `default_stripe_words`).
#[test]
fn default_stripe_words_keys_on_block_size_only_on_the_nibble_arms() {
    let nibble = cfg!(target_arch = "x86_64") && crate::gf16::multi_fold_width() == 4;
    assert_eq!(super::fastpar::default_stripe_words(65536), 512);
    assert_eq!(super::fastpar::default_stripe_words((1 << 20) - 2), 512);
    let big = super::fastpar::default_stripe_words(1 << 20);
    assert_eq!(big, if nibble { 1024 } else { 512 });
    assert_eq!(super::fastpar::default_stripe_words(4 << 20), big);
    if !ntt_env_knob_set() {
        assert_eq!(
            ntt_stripe_geometry(4 << 20).0,
            big,
            "the geometry takes the rule"
        );
    }
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
    // Since 2 Sep 2026 an over-budget corpus is transformed in WINDOWS
    // as the budget fills rather than folded, so the transform still
    // ran; what the pad charge decides is where the window closes, and
    // what this pins is that the windowed answer is the fold's answer
    // bit for bit on the shape whose pad rivals its payload.
    assert!(
        report.ntt_used,
        "the transform runs in windows once the pad charge fills the budget"
    );
    assert_eq!(
        out, fold_out,
        "windowed transform must stay bit-identical to the fold"
    );
    for (c, &j) in missing.iter().enumerate() {
        assert_eq!(out[c], padded[j], "missing slice {j} wrong after windowing");
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

/// The streaming admission's own shape, end to end: a corpus SEVERAL
/// windows deep, every slice full length (no tail pads), through the
/// real feed worker. The transform is linear in its sources, so the
/// partial rows of disjoint windows XOR into the same syndromes one
/// plan over the whole corpus would produce - that identity is what
/// admits a corpus bigger than the retention budget at all
/// (`fastpar::ntt_retention_admits`), and this is where it is checked
/// against the fold rather than argued.
///
/// Multi-window was reachable before this test only through
/// `ntt_short_tail_pad_counts_against_the_retention_budget`, whose
/// corpus is one batch and therefore ONE window - the pad charge closes
/// it, and nothing else. Here the feed handle's 1 MiB assembly buffer
/// is what splits the corpus, so the windows are real ones.
#[test]
fn ntt_multi_window_transform_matches_fold_path() {
    // 2.2 MB of corpus at 512-byte blocks: the Feeder's floor for
    // `max_batch` is 1 MiB, so three batches arrive and a budget under
    // one of them closes a window per batch.
    let (n, bs) = (4400usize, 512usize);
    let slices = demo_slices(n, bs);
    let missing: Vec<usize> = {
        let mut v: Vec<usize> = (0..40).map(|i| (i * 97 + 5) % n).collect();
        v.sort_unstable();
        v.dedup();
        v
    };
    let m = missing.len();
    let exps: Vec<u32> = (0..m as u32).collect();
    let recovery: Vec<(u32, Vec<u8>)> = exps
        .iter()
        .map(|&e| (e, generate_recovery(&slices, bs, e)))
        .collect();
    let run = |path| {
        let rec = Reconstructor::new_with_path(bs, n, &missing, &recovery, path).unwrap();
        {
            // One feed handle, so the split is the batch boundary and
            // not an interleaving of producers - the windows are then
            // deterministic and the count below is a real assertion.
            let mut feeder = rec.feeder(1 << 20);
            for (i, s) in slices.iter().enumerate() {
                if !missing.contains(&i) {
                    feeder.feed(i, s);
                }
            }
        }
        rec.finish_reported()
    };
    let (fold_out, fold_report) = run(SyndromePath::Fold);
    assert_eq!(fold_report.windows, 0, "the fold retains nothing");
    // Half a mebibyte: every 1 MiB batch overflows it on arrival.
    let (out, report) = run(SyndromePath::NttForce(512 << 10));
    assert!(report.ntt_used, "the windows must transform, not fold");
    assert!(
        report.windows >= 3,
        "expected the corpus to split into windows, got {}",
        report.windows
    );
    assert_eq!(
        report.n_present,
        n - m,
        "every present slice is fed to exactly one window"
    );
    assert_eq!(
        out, fold_out,
        "windowed transform must stay bit-identical to the fold"
    );
    for (c, &j) in missing.iter().enumerate() {
        assert_eq!(out[c], slices[j], "missing slice {j} wrong after windowing");
    }
    // Control: the same corpus in ONE window is the retained path, and
    // must agree with both.
    let (retained_out, retained_report) = run(SyndromePath::NttForce(usize::MAX));
    assert_eq!(retained_report.windows, 1, "one window retains everything");
    assert_eq!(retained_out, fold_out, "the retained path is the fold too");
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
/// 64 GiB ceiling holds on very big RAM, everything else gets RAM/4, and a
/// cgroup limit (the OOM-kill line) caps at a quarter regardless of
/// host RAM - an OOM kill is the one failure the verify-retry
/// cannot rescue, so the budget must gate dispatch up front.
#[test]
fn ntt_default_budget_scales_to_the_machine() {
    let gib = 1u64 << 30;
    // SATURATE, never truncate. `(16 * gib) as usize` is ZERO on a 32-bit
    // `usize`, and an expectation that wraps agrees with itself exactly the
    // way the production cast used to - which is the trap the paragraph below
    // names and this test then walked into three lines later, taking nightly's
    // armv7-cross red on 6 Sep 2026 (left 1 GiB, right 0). Production
    // saturates with `usize::try_from(..).unwrap_or(usize::MAX)`; the
    // expectations must be written the same way, so this closure is the only
    // route from a `u64` figure to a `usize` one in this test.
    let bytes = |n: u64| usize::try_from(n).unwrap_or(usize::MAX);
    // The flat ceiling is 64 GiB, which a 32-bit `usize` cannot hold, so
    // there it lands on the address-space ceiling instead. Naming the
    // expectation per width keeps BOTH facts pinned.
    #[cfg(target_pointer_width = "32")]
    let ceil = 1usize << 30;
    #[cfg(not(target_pointer_width = "32"))]
    let ceil = bytes(64 * gib);
    assert_eq!(ntt_default_budget(None, None), ceil);
    assert_eq!(ntt_default_budget(Some(512 * gib), None), ceil);
    // A 64 GB box gets 16 GiB, which admits a 10 GiB corpus the old
    // 4 GiB ceiling refused on every box (the big-file round, 5 Sep 2026).
    assert_eq!(
        ntt_default_budget(Some(64 * gib), None),
        bytes(16 * gib).min(ceil)
    );
    assert_eq!(
        ntt_default_budget(Some(8 * gib), None),
        bytes(2 * gib).min(ceil)
    );
    assert_eq!(
        ntt_default_budget(Some(4 * gib), None),
        bytes(gib).min(ceil)
    );
    assert_eq!(
        ntt_default_budget(Some(64 * gib), Some(2 * gib)),
        bytes(gib / 2),
        "cgroup limit caps regardless of host RAM"
    );
    // A budget is never zero and never wraps, whatever the probes say.
    // The ceiling was 4 GiB, exactly 2^32: `b as usize` used to hand a
    // 32-bit host a budget of 0, which fails the gate for every corpus
    // and made the NTT path unreachable on armv7 without one line of
    // code saying so.
    assert!(ntt_default_budget(None, None) >= bytes(gib));
    // The heavy benchmark corpus (~0.93 GiB) still clears the gate
    // on a 16 GiB machine (budget 4 GiB, or the 1 GiB address-space
    // ceiling on 32-bit - the corpus fits either) but not on a 2 GiB
    // one.
    assert!(ntt_gates_pass(
        65536,
        14884,
        1500,
        1499,
        ntt_default_budget(Some(16 * gib), None),
        false
    ));
    assert!(!ntt_gates_pass(
        65536,
        14884,
        1500,
        1499,
        ntt_default_budget(Some(2 * gib), None),
        false
    ));
    // With window streaming on, the 2 GiB box takes that corpus a
    // window at a time instead: its 512 MiB budget holds 8,192 of the
    // set's 64 KiB blocks, and the budget - the OOM guard this whole
    // arithmetic exists for - is the same number either way.
    assert!(ntt_gates_pass(
        65536,
        14884,
        1500,
        1499,
        ntt_default_budget(Some(2 * gib), None),
        true
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
    let (bs, n_inputs, m) = minimal_ntt_shape();
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

/// Fill in the IFSC grid the prefix arm (and the untouched-file arm)
/// close against. Every real set carries one; `mapped_fixture` does not,
/// because most of its rows are about the repair math.
fn with_ifsc(files: &mut [(Par2File, Vec<bool>)], pristine: &[Vec<u8>], bs: usize) {
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
}

/// The digest the live verifier's prefix hasher would have reached: the
/// first `blocks` blocks of `data`, hashed in file order.
fn prefix_of(data: &[u8], bs: usize, blocks: usize) -> Md5Resume {
    let end = blocks * bs;
    let mut h = Md5::new();
    h.update(&data[..end]);
    Md5Resume::bench_prefix(end as u64, h)
}

/// A prefix digest over the WRONG bytes, for the rows that assert a
/// guard: if the guard lets it through, the FileDesc MD5 cannot match
/// and the repair fails - which is the only direction a bad resume can
/// move (see `Md5Resume::from_prefix`).
fn bogus_prefix(bs: usize, blocks: usize) -> Md5Resume {
    let mut h = Md5::new();
    h.update(vec![0xA5u8; blocks * bs]);
    Md5Resume::bench_prefix((blocks * bs) as u64, h)
}

/// A caller-supplied prefix moves the whole-file MD5 off the repair's
/// tail without moving the verdict: the FileDesc MD5 is still computed
/// over the whole file, and the span the digest covers is still reread
/// from disk - against the IFSC CRC32s rather than MD5, which is ~16x
/// cheaper measured through the same reader (2 Sep 2026: 1024 MiB of
/// CRC32 in 96.7 ms against 1548 ms of MD5).
#[test]
fn mapped_prefix_resumes_the_filedesc_md5_and_still_rereads_the_span() {
    let damage = [(0usize, 2usize)];
    let (mut files, bs, recovery, pristine) = mapped_fixture(&damage);
    with_ifsc(&mut files, &pristine, bs);
    let mut on_disk = pristine.clone();
    on_disk[0][2 * bs..3 * bs].fill(0);
    let io = MemIo::new(on_disk, None);
    // Two whole blocks, stopping exactly at the first hole.
    let prefixes = vec![Some(prefix_of(&pristine[0], bs, 2)), None];
    assert_eq!(
        repair_mapped_prefixed(&files, bs, &recovery, &io, false, &prefixes).expect("repairs"),
        1
    );
    assert_eq!(io.snapshot(), pristine, "byte-identical restoration");
}

/// THE HOLE THE CRC RECHECK EXISTS TO CLOSE. Bytes UNDER the prefix
/// boundary are never MD5'd again - that is the whole saving - so a
/// sector that went bad there after the digest was taken is invisible to
/// the resumed hash. The per-block CRC32 reread is what sees it, and
/// this row fails without it.
#[test]
fn mapped_prefix_rot_below_the_boundary_is_caught_by_the_crc_recheck() {
    let damage = [(0usize, 2usize)];
    let (mut files, bs, recovery, pristine) = mapped_fixture(&damage);
    with_ifsc(&mut files, &pristine, bs);
    let mut on_disk = pristine.clone();
    on_disk[0][2 * bs..3 * bs].fill(0);
    // Rot block 0 - inside the prefix - only once the syndrome reads
    // are done, so nothing but the post-patch reread can notice.
    let io = MemIo::rotting(on_disk, (0, 3));
    let prefixes = vec![Some(prefix_of(&pristine[0], bs, 2)), None];
    let got = repair_mapped_prefixed(&files, bs, &recovery, &io, false, &prefixes);
    assert!(
        matches!(&got, Err(RepairError::VerifyFailed(n)) if n == "f0.bin"),
        "rot under the prefix boundary sailed through the self-prove: {got:?}"
    );
}

/// The self-prove covers the WHOLE SET even when a prefix shortens the
/// rebuilt file's own work - `mapped_driver_rereads_files_it_did_not_
/// rebuild`'s guarantee is not something the prefix arm may trade away.
#[test]
fn mapped_prefix_does_not_stop_the_untouched_file_being_reread() {
    let damage = [(0usize, 2usize)];
    let (mut files, bs, recovery, pristine) = mapped_fixture(&damage);
    with_ifsc(&mut files, &pristine, bs);
    let mut on_disk = pristine.clone();
    on_disk[0][2 * bs..3 * bs].fill(0);
    let io = MemIo::rotting(on_disk, (1, 3));
    let prefixes = vec![Some(prefix_of(&pristine[0], bs, 2)), None];
    let got = repair_mapped_prefixed(&files, bs, &recovery, &io, false, &prefixes);
    assert!(
        matches!(&got, Err(RepairError::VerifyFailed(n)) if n == "f1.bin"),
        "a repair that left a corrupt covered file did not fail on it: {got:?}"
    );
}

/// Every arm of `usable_prefix`, and `full_verify` besides. Each row
/// hands in a digest over bytes that are NOT on disk, so the guard is
/// proved by the repair SUCCEEDING: had the prefix been used, the
/// FileDesc MD5 could not have matched.
#[test]
fn an_unusable_prefix_is_dropped_rather_than_trusted() {
    // (label, prefix, full_verify, ifsc)
    let cases: Vec<(&str, Md5Resume, bool, bool)> = vec![
        ("past the first hole", bogus_prefix(64, 3), false, true),
        (
            "not block-aligned",
            Md5Resume::bench_prefix(65, Md5::new()),
            false,
            true,
        ),
        ("past end of file", bogus_prefix(64, 99), false, true),
        (
            "no IFSC to recheck against",
            bogus_prefix(64, 2),
            false,
            false,
        ),
        ("full_verify asked for MD5", bogus_prefix(64, 2), true, true),
    ];
    for (label, prefix, full_verify, ifsc) in cases {
        let damage = [(0usize, 2usize)];
        let (mut files, bs, recovery, pristine) = mapped_fixture(&damage);
        assert_eq!(bs, 64, "the cases above spell the block size");
        if ifsc {
            with_ifsc(&mut files, &pristine, bs);
        }
        let mut on_disk = pristine.clone();
        on_disk[0][2 * bs..3 * bs].fill(0);
        let io = MemIo::new(on_disk, None);
        let prefixes = vec![Some(prefix), None];
        assert_eq!(
            repair_mapped_prefixed(&files, bs, &recovery, &io, full_verify, &prefixes)
                .unwrap_or_else(|e| panic!(
                    "{label}: a dropped prefix must leave a working repair: {e:?}"
                )),
            1,
            "{label}"
        );
        assert_eq!(io.snapshot(), pristine, "{label}: byte-identical");
    }
}

/// A prefix that IS usable by every structural test but describes the
/// wrong bytes fails the repair. It can never pass one: the verdict is
/// still `digest == FileDesc MD5` over the whole file.
#[test]
fn a_usable_but_wrong_prefix_fails_and_cannot_pass() {
    let damage = [(0usize, 2usize)];
    let (mut files, bs, recovery, pristine) = mapped_fixture(&damage);
    with_ifsc(&mut files, &pristine, bs);
    let mut on_disk = pristine.clone();
    on_disk[0][2 * bs..3 * bs].fill(0);
    let io = MemIo::new(on_disk, None);
    let prefixes = vec![Some(bogus_prefix(bs, 2)), None];
    let got = repair_mapped_prefixed(&files, bs, &recovery, &io, false, &prefixes);
    assert!(
        matches!(&got, Err(RepairError::VerifyFailed(n)) if n == "f0.bin"),
        "a prefix over bytes that are not on disk must fail the verdict: {got:?}"
    );
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

/// ---- The back-substitution differential harness ------------------
///
/// The dense `m x m` product and the transform solve
/// (`forney::ForneyPlan`) must agree WORD FOR WORD - this is exact
/// arithmetic in GF(2^16), and both compute `A^-1 S` for the same
/// nonsingular `A`, so any disagreement at all is a bug in one of them.
/// The dense side is itself already pinned to Gauss-Jordan by
/// `vandermonde_inverse_matches_gauss_jordan` above, so this chains onto
/// a reference that does not share a line of code with either.
///
/// Random syndrome rows rather than syndromes of a known payload: every
/// `S` has exactly one solution (a Vandermonde with distinct nodes is
/// never singular), so random rows exercise the same map with no
/// consistency constraint to satisfy - and the round-trip case below
/// covers the direction a shared misreading of the algebra could hide in.
///
/// It exists to hold a SECOND solve to the shipped one, the way
/// `par2ntt::tests::leaf_case` holds a second leaf. Nothing about the
/// transform route ships until this is green at every size.
fn backsub_case(m: usize, words: usize, e0: u32, scatter: usize, seed: u64) {
    let mut state = seed | 1;
    let mut word = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        (state >> 32) as u16
    };
    // Scattered bases: the missing set is rarely a prefix of the inputs,
    // and `k_c mod 255` grouping in the evaluation stage is exactly what
    // a prefix would under-exercise.
    let logs = input_base_logs(m * scatter).unwrap();
    let ks: Vec<u32> = (0..m).map(|i| logs[i * scatter]).collect();
    let syn: Vec<Vec<u16>> = (0..m)
        .map(|_| (0..words).map(|_| word()).collect())
        .collect();
    let inv = invert_vandermonde(&ks, e0).expect("distinct bases cannot fail");
    let mut want: Vec<Vec<u16>> = vec![vec![0u16; words]; m];
    let bytes: Vec<&[u8]> = syn.iter().map(|s| gf16::words_as_bytes(s)).collect();
    fold_parallel(&mut want, &bytes, &|j, i| inv[j][i], None);
    let plan = super::forney::ForneyPlan::prepare(&ks, e0).expect("distinct bases cannot fail");
    let got = plan.solve(&syn, words);
    assert_eq!(
        got, want,
        "transform solve diverged: m={m} words={words} e0={e0} scatter={scatter}"
    );
}

/// The always-on arm: sizes small enough for a debug build, chosen for
/// the shape EDGES rather than for scale - one segment and several, a
/// segment boundary landing mid-`BLK`, one stripe and several (including
/// a last stripe that is not a whole number of kernel granules), a
/// non-zero `e0`, and scattered bases. The sizes that actually matter
/// for SPEED are in the ignored arm below, which is a release-build
/// question.
#[test]
fn backsub_transform_matches_dense_product() {
    for (m, words, e0, scatter) in [
        (1usize, 16usize, 0u32, 1usize),
        (2, 8, 5, 3),
        (5, 24, 1, 2),
        (17, 16, 0, 7),
        (129, 48, 3, 1),
        (260, 16, 11, 2),
        // Every case above is ONE stripe wide (the width clamps to 512
        // words and none of them reach it), so these two are what
        // exercise the striped worker path at all: 1,088 words is three
        // stripes with an aligned tail, 1,000 is two with a tail that is
        // NOT a whole number of kernel granules - the slow-but-correct
        // side of the width rule STRIPE_GRAN documents.
        (40, 1088, 2, 1),
        (45, 1000, 0, 3),
    ] {
        backsub_case(m, words, e0, scatter, 0x9E3779B97F4A7C15);
    }
}

/// The direction random syndromes cannot check: fold a known payload
/// forward through the repair matrix, solve, and get the payload back.
/// A sign error shared by both solves would pass the differential above
/// and fail here.
#[test]
fn backsub_transform_round_trips_a_known_payload() {
    let (m, words, e0) = (140usize, 32usize, 9u32);
    let logs = input_base_logs(m * 2).unwrap();
    let ks: Vec<u32> = (0..m).map(|i| logs[i * 2]).collect();
    let mut state = 0x243F6A8885A308D3u64;
    let mut word = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        (state >> 32) as u16
    };
    let x: Vec<Vec<u16>> = (0..m)
        .map(|_| (0..words).map(|_| word()).collect())
        .collect();
    // S_r = Σ_c g_c^{e0+r} · x_c, straight from the definition.
    let mut syn: Vec<Vec<u16>> = vec![vec![0u16; words]; m];
    for (r, row) in syn.iter_mut().enumerate() {
        for (c, &k) in ks.iter().enumerate() {
            let t = MulTable::new(gf16::pow2(k as u64 * (e0 as u64 + r as u64)));
            t.xor_mul_words(row, &x[c]);
        }
    }
    let plan = super::forney::ForneyPlan::prepare(&ks, e0).expect("distinct bases cannot fail");
    assert_eq!(plan.solve(&syn, words), x, "solve did not invert the fold");
}

/// The scale arm, `--ignored` because it is a release-build question:
/// the m values the crossover sweep is taken at (audit section 19) and
/// stripe widths on both sides of the shipped one. Run it with
/// `cargo test --release -p nzbkit --lib backsub_transform_at_scale
/// -- --ignored --nocapture`.
#[test]
#[ignore = "minutes in a debug build; the release differential for the sweep sizes"]
fn backsub_transform_at_scale() {
    for m in [64usize, 512, 1500, 3000, 6000, 8192] {
        for words in [16usize, 512, 4096] {
            backsub_case(m, words, 0x51, 1, 0xD1B54A32D192ED03);
        }
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
/// `crates/nzbfast-unpack/src/repair.rs` - which only DECLINES its own route and
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
/// The Gauss-Jordan arm keeps `MAX_REPAIR_DIM` even though
/// `check_repair_dim` admitted the set.
///
/// This is the hole the per-arm cap opened and the reason the guard is
/// in TWO places. `check_repair_dim` runs before the recovery exponents
/// are examined, so it cannot know whether the solve will find structure
/// to exploit; it admits a large `m` on the strength of the Forney arm's
/// memory bound. A set whose exponents are neither consecutive nor a
/// relabelable progression - which is what "recovery packets were
/// themselves lost" looks like - then falls through to Gauss-Jordan on
/// an explicit `m x m`: `~4*m^2` bytes and `O(m^3)` scalar ops, about a
/// gigabyte and hours at these sizes. That is precisely the repair-time
/// DoS the constant exists to refuse, so the arm re-asserts it.
#[test]
fn the_unstructured_arm_is_bounded_by_its_own_memory_not_by_a_dimension() {
    // The arm's bound is checked directly rather than through
    // `Reconstructor::new`: past the old cap the constructor now goes on
    // to INVERT the matrix, and an 8,193 x 8,193 Gauss-Jordan is not a
    // unit test. What is under test is the rule, not the arithmetic.
    let bs = 64 << 10;
    let over = MAX_REPAIR_DIM + 1;

    // The window ALONE admits it - which is exactly why the dense arm
    // needs a bound of its own, and why sharing Forney's was the hole.
    let window = 2 * over * bs;
    assert!(
        super::reconstruct::check_repair_dim_within(over, bs, u64::MAX).is_ok(),
        "an unlimited budget must admit it: the dimension no longer refuses"
    );

    // Its real footprint is the window plus the matrix and its inverse,
    // and only the DENSE check knows that: `check_repair_dim_within`
    // charges whichever arm `backsub_gate` names, which at this m is
    // Forney, and it runs before the exponents are examined at all. That
    // is why the dense bound is re-asserted once the arm is known.
    let need = window + 4 * over * over;
    assert!(
        super::reconstruct::check_repair_dim_dense_within(over, bs, need as u64).is_ok(),
        "a budget covering its whole footprint must admit it"
    );
    let Err(err) = super::reconstruct::check_repair_dim_dense_within(over, bs, need as u64 - 1)
    else {
        panic!("a budget one byte short of the dense footprint must refuse");
    };
    assert!(
        matches!(&err, RepairError::SolveBudget { .. }),
        "the refusal must name MEMORY, not a matrix: the recovery set is good and a \
         bigger budget admits it: {err}"
    );

    // And the format's own ceiling is still absolute, whatever the RAM.
    let Err(err) = super::reconstruct::check_repair_dim_within(MAX_INPUT_SLICES + 1, bs, u64::MAX)
    else {
        panic!("past the PAR2 input-slice ceiling nothing may be admitted");
    };
    assert!(
        matches!(&err, RepairError::Malformed(m) if m.contains("input-slice ceiling")),
        "the outer guard must still name the spec ceiling: {err}"
    );
}

/// The slab planner: memory sets the PASS COUNT, never a verdict.
///
/// Driven as a pure function on a handed-in budget, the same seam
/// `check_repair_dim_within` uses and for the same reason - a test that
/// read the host's real budget would assert something different on every
/// box in the fleet.
#[test]
fn plan_slabs_never_refuses_and_takes_the_fewest_passes() {
    use super::reconstruct::plan_slabs;
    let gib = |n: u64| n << 30;

    // 1. THE ORDINARY CASE IS ONE SLAB, and one slab must be the
    //    untouched fast path - every driver below branches on this.
    let p = plan_slabs(101, 1 << 20, gib(2));
    assert_eq!(p.slabs, 1, "a repair well inside the budget must not slab");
    assert_eq!(p.width, 1 << 20, "one slab is the whole block");

    // 2. THE pain65 GEOMETRY, which is why this exists. 65 GiB / 50%
    //    parity, 16 of 65 members gone: m = 8,064 at a 2,130,944 B
    //    block is a 32.0076 GiB window, against the 32 GiB budget a
    //    128 GiB machine derives. It used to be `SolveBudget` and a
    //    repair of nothing.
    let (m, bs) = (8_064, 2_130_944);
    let p = plan_slabs(m, bs, gib(32));
    assert_eq!(
        p.slabs, 2,
        "it misses by 0.024%, so it costs ONE extra pass"
    );
    // ...and the two passes are BALANCED. The widest legal slab here is
    // 504 bytes short of the whole block, so a greedy cut would spend
    // the second full sweep of a 65 GiB payload carrying 504 bytes.
    assert_eq!(p.width, 1_065_472);
    assert!(
        p.width * 2 >= bs,
        "two slabs must actually cover the block between them"
    );

    // 3. The same set on a 256 GiB box (64 GiB budget) is ONE slab, so
    //    the machine that has the memory pays nothing for this feature.
    assert_eq!(plan_slabs(m, bs, gib(64)).slabs, 1);

    // 4. Every plan fits the budget it was given, covers the block
    //    exactly, and has an even width - the solve works in u16 words,
    //    and an odd slab would split one.
    for &budget in &[gib(1), gib(2), gib(8), gib(16), gib(32), gib(64)] {
        for &(m, bs) in &[
            (8_064usize, 2_130_944usize),
            (32_768, 2_130_944),
            (1, 4 << 20),
            (948, 5_376_000),
            (10_240, 1 << 20),
        ] {
            let p = plan_slabs(m, bs, budget);
            assert!(p.width.is_multiple_of(2), "slab width must be whole words");
            assert!(p.slabs >= 1 && p.width >= 2);
            assert!(
                p.slabs * p.width >= bs,
                "the slabs must cover the block: {p:?} for m={m} bs={bs}"
            );
            assert!(
                (p.slabs - 1) * p.width < bs,
                "no slab may be entirely past the end of the block: {p:?}"
            );
            // The window this plan actually asks for, which is what the
            // whole exercise is about.
            // Widened BEFORE the product, not after: `2 * m * p.width`
            // is a `usize` multiply that overflows at 32-bit pointer width
            // for the GiB-scale geometries below, and `(a * b) as u64`
            // panics before the cast ever runs.
            let window = 2 * m as u64 * p.width as u64;
            assert!(
                window <= budget || p.width == 2,
                "a plan must fit its budget: {p:?} asks {window} of {budget} \
                 for m={m} bs={bs}"
            );
        }
    }

    // 5. THE NEVER-REFUSE PROPERTY, at the format's own ceiling and a
    //    budget far below anything a real box would derive: 32,768
    //    inputs is the most PAR2 permits, and even a 16 MiB budget
    //    plans rather than failing.
    let p = plan_slabs(MAX_INPUT_SLICES, 4 << 20, 16 << 20);
    assert!(p.slabs > 1 && p.width >= 2);
    assert!(p.slabs * p.width >= (4 << 20));

    // 6. Degenerate shapes do not panic and do not divide by zero.
    assert_eq!(plan_slabs(0, 1 << 20, gib(1)).slabs, 1);
    assert_eq!(plan_slabs(0, 0, gib(1)).slabs, 1);
}

/// The UNATTENDED ceiling: a policy about who is watching, not about
/// what fits.
///
/// The engine bounds the unstructured solve by memory, which is right
/// for a person who typed a command. A daemon sets this instead, because
/// it can neither show a fold's progress nor interrupt one, so it starts
/// only what it has always started. Driven as a pure function on
/// purpose - storing to the process-wide ceiling here would be visible
/// to every later test in a `cargo test` one-process run.
#[test]
fn the_unattended_ceiling_refuses_by_policy_and_says_so() {
    use super::reconstruct::unattended_refusal;

    // Zero is the default and means no ceiling: nothing is refused, which
    // is what a command-line tool gets.
    assert!(unattended_refusal(MAX_INPUT_SLICES, 0).is_ok());

    // At the ceiling, admitted; one past it, refused.
    assert!(unattended_refusal(MAX_REPAIR_DIM, MAX_REPAIR_DIM).is_ok());
    let Err(err) = unattended_refusal(MAX_REPAIR_DIM + 1, MAX_REPAIR_DIM) else {
        panic!("one block past the unattended ceiling must be refused");
    };
    // The message has to say it is a POLICY and that the work is
    // possible, or the next reader files it as an engine limit - which is
    // exactly how the flat matrix cap came to be believed for a year.
    let RepairError::Malformed(text) = &err else {
        panic!("the unattended refusal is a Malformed, not a capacity error: {err}");
    };
    assert!(
        text.contains("unattended ceiling") && text.contains("possible but slow"),
        "the refusal must name the policy and say the repair is possible: {text}"
    );
}

/// THE EXEMPTION, and the reason the ceiling's number never had to be
/// raised.
///
/// `set_unattended_unstructured_ceiling`'s doc named the day in-fold
/// progress and a cancel arrived as the day to raise the number. Raising
/// it would have been the wrong reading: the ceiling stands in for
/// "nobody can see this repair or stop it", and that is a question about
/// the CALLER and not about the process. So a caller supplying both
/// halves is admitted at any m, at the same instant an uncontrolled
/// caller in the same process is refused - which is what lets the daemon
/// keep setting the ceiling for its uncontrolled repair paths while its
/// controlled ones run past it.
///
/// WHICH PATHS ARE WHICH moved on 12 Sep 2026 and is censused on
/// `linalg::set_unattended_unstructured_ceiling`. The short form: the
/// download repair, the late-set pass and the nested extraction
/// ladder's per-level PAR2 pass are controlled; `get::settle::noset`'s
/// obfuscated arm and the MAPPED in-stream driver are not, and are the
/// whole reason `serve/mod.rs` still makes that call. The `inert` arm
/// below is exactly the control both of them pass.
///
/// BOTH HALVES OR NEITHER is the part with the most riding on it: the
/// two one-sided controls below are the shapes somebody would reach for
/// when wiring this up in a hurry, and neither is attended.
#[test]
fn a_controlled_caller_is_exempt_from_the_unattended_ceiling() {
    use super::reconstruct::unattended_refusal_for;
    use crate::par2repair::control::{PauseGate, RepairControl, RepairPhase};
    use std::sync::Arc;

    let over = MAX_REPAIR_DIM + 1;
    let sink = Arc::new(|_: RepairPhase, _: u64, _: u64| {});

    // The shape the daemon now passes: a sink AND a gate.
    let watched = RepairControl::new(Some(sink.clone()), Some(PauseGate::new()));
    assert!(watched.is_attended());
    assert!(
        unattended_refusal_for(over, MAX_REPAIR_DIM, &watched).is_ok(),
        "a caller that can both see this repair and stop it is attended whatever \
         process it is in - refusing it is refusing work nobody is waiting blind for"
    );

    // ...and the same instant, in the same process, for a caller that
    // passes nothing. This is the pairing that makes the exemption a
    // narrowing rather than a hole.
    let inert = RepairControl::default();
    assert!(!inert.is_attended());
    assert!(
        unattended_refusal_for(over, MAX_REPAIR_DIM, &inert).is_err(),
        "the ceiling still holds for a caller that reports nothing and cannot be \
         stopped - which is what `get::settle::noset` and the mapped in-stream driver \
         still pass, and why `serve/mod.rs` still sets it"
    );

    // HALF A CONTROL IS NOT A WATCHER. Progress with no cancel leaves
    // somebody who can see a half-hour fold and not end it; a cancel
    // with no progress leaves somebody who cannot tell when to press it.
    let report_only = RepairControl::new(Some(sink), None);
    let cancel_only = RepairControl::new(None, Some(PauseGate::new()));
    for (what, c) in [("report-only", &report_only), ("cancel-only", &cancel_only)] {
        assert!(!c.is_attended(), "{what} must not count as attended");
        assert!(
            unattended_refusal_for(over, MAX_REPAIR_DIM, c).is_err(),
            "{what} was admitted past the ceiling"
        );
    }

    // The ceiling's DEFAULT is zero, which means no ceiling, so a
    // command-line tool is unaffected either way - asserted here too,
    // because the exemption must not be the only thing keeping it open.
    assert!(unattended_refusal_for(over, 0, &inert).is_ok());
}

/// The repair's dimension guard, per arm, at every boundary it has.
///
/// It used to be one flat cap and this test asserted that. It is now
/// three rules, because the two solves cost different things:
///
/// - Over the PAR2 input-slice ceiling nothing is admitted, whatever
///   the memory. That is the outer guard the DoS argument rests on.
/// - The DENSE product keeps `MAX_REPAIR_DIM`, whose doc comment prices
///   exactly that arm (`~4*m^2` bytes, `O(m^3)` setup). On this build a
///   fused kernel sends everything past `backsub_min_missing()` to
///   Forney, so the dense cap is reached only when dispatch says dense.
/// - FORNEY is bounded by MEMORY instead - `2 * m * block_size`, the
///   back-substitution's peak window - because its solve is an
///   evaluation linear in `m`, not a cubic. Capping it at 8,192 refused
///   the ordinary full-rebuild workflow (every data file deleted,
///   repair from over-100% parity, so `m` is every input block) on sets
///   par2cmdline-turbo completes.
///
/// Driven through `check_repair_dim_within` so both sides of the memory
/// boundary are reachable without mutating a process-global env.
#[test]
fn the_repair_dimension_guard_is_per_arm_at_every_boundary() {
    use super::reconstruct::check_repair_dim_within;

    /// `n` GiB as a `usize`, saturating where the address space cannot
    /// hold it. Written through `u64` because `8 * (1 << 30)` as a
    /// `usize` literal is a const-eval overflow on a 32-bit target and
    /// does not COMPILE - which is what took the armv7 nightly red on
    /// 8 Sep 2026 (claim `red-armv7-cross-d7d319c4`). Saturation is the
    /// right answer for every budget below except the one gated to
    /// 64-bit: the 20 GiB window is over EVERY budget a 32-bit `usize`
    /// can name, so the refusals hold at either width.
    const fn gib(n: u64) -> u64 {
        n << 30
    }

    // 1. Past the slice ceiling: refused however small the blocks are.
    let over = MAX_INPUT_SLICES + 1;
    let Err(err) = check_repair_dim_within(over, 2, u64::MAX) else {
        panic!("a set over the PAR2 slice ceiling must be refused");
    };
    assert!(
        matches!(&err, RepairError::Malformed(m)
            if m.contains(&format!("{over} missing blocks")) && m.contains("input-slice ceiling")),
        "the ceiling must be the stated reason: {err}"
    );

    // 2. The Forney arm, bounded by memory and not by a matrix. A 10 GiB
    //    set at 1 MiB blocks fully rebuilt is m = 10,240: 20 GB of peak
    //    window, so it turns on the budget and nothing else.
    let m = 10_240;
    let bs = 1 << 20;
    // WHICH arm this m takes is NOT asserted here, and that is the fix
    // rather than an omission. It used to be `assert!(backsub_gate(m))`,
    // which is a KERNEL property, not a memory one: `backsub_gate`
    // reaches Forney only where a fused GF16 multi kernel exists, so on
    // armv7 - which has none - this shape correctly takes the dense
    // product and that line alone took the nightly red. Restating any
    // PART of the gate's rule here fails the same way one step removed:
    // a `multi_fold_width() > 0` guard is wrong under `NZBFAST_BACKSUB=
    // dense`, the gate's own documented escape hatch, which is how this
    // was caught locally.
    //
    // Nothing is lost by dropping it. The gate's threshold has its own
    // test (`backsub_gate(gate - 1)` in forney.rs) and its boundary is
    // the last block of THIS test. And every assertion below holds on
    // EITHER arm, which is why this is a comment and not a `cfg`: both
    // arms hold the same two `m x block` buffers, and the dense arm only
    // adds its `~4*m^2` matrix on top - so a window over budget is over
    // budget either way, and a budget admitting the wider dense
    // footprint admits the Forney one too.
    let Err(err) = check_repair_dim_within(m, bs, gib(8)) else {
        panic!("20 GB of window must not fit an 8 GB budget");
    };
    assert!(
        matches!(&err, RepairError::SolveBudget { .. }),
        "over budget must be a capacity refusal, never Malformed - a good recovery set must \
         not be reported as corrupt just because this machine's memory budget is too small: {err}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("budget") && msg.contains("solve") && msg.contains("retry"),
        "the message must name the budget and tell the user it is retryable: {msg}"
    );
    // The same m, admitted where the memory is there - this is the case
    // the old flat cap refused outright.
    //
    // THIS USED TO BE A `cfg` FORK, and retiring it is the point of the
    // 10 Sep 2026 widening. The budget is a byte count, and it was a
    // `usize`: 32 GiB could not be NAMED at 32-bit pointer width, so
    // this half was gated to 64-bit and the narrow target got a
    // consolation assertion that the shape is refused whatever budget
    // is asked for. Both halves were artefacts of the parameter's type.
    // `check_repair_dim_within` has always done its arithmetic in `u64`
    // - the window is a saturating `u64` product - so taking the budget
    // as one too makes this boundary mean the same thing at either
    // width, and the admitted side is checked on armv7 rather than
    // excused there.
    assert!(check_repair_dim_within(m, bs, gib(32)).is_ok());
    // ...and admitted far past the old cap when the blocks are small,
    // because then the window is small. 128 KiB of window here, so this
    // one holds at either width.
    assert!(check_repair_dim_within(MAX_INPUT_SLICES, 2, gib(8)).is_ok());

    // 3. The dense arm keeps its own cap, whatever the memory. Reached
    //    here by asking below the fused gate on a build that has one, and
    //    on a build that has no fused kernel every m lands here anyway.
    let dense_m = 64;
    assert!(!super::forney::backsub_gate(dense_m));
    assert!(check_repair_dim_within(dense_m, 2, u64::MAX).is_ok());
    // PAST `MAX_REPAIR_DIM`, THE DENSE ARM IS BOUNDED BY MEMORY AND
    // NOTHING ELSE, which is what `454141ce0f` decided on 8 Sep 2026:
    // three of the flat cap's four premises did not survive being
    // measured, and the fourth - memory - is charged here instead. This
    // used to assert the cap still refused, and went unnoticed because
    // it only runs where `backsub_gate` says dense at this m, which is
    // a build with no fused GF16 kernel. armv7 is that build, and armv7
    // was already failing earlier in this test, so the stale arm was
    // never reached. Admitted when the footprint fits...
    let over_dim = MAX_REPAIR_DIM + 1;
    if !super::forney::backsub_gate(over_dim) {
        let need = 2 * over_dim as u64 * 2 + 4 * over_dim as u64 * over_dim as u64;
        assert!(
            check_repair_dim_within(over_dim, 2, u64::MAX).is_ok(),
            "past the old flat cap the dense arm must be admitted when the memory is there -              refusing it is what sent an m = 10,000 set to a SLOWER tool"
        );
        // ...and refused on MEMORY, naming memory, when it does not.
        let Err(err) = check_repair_dim_within(over_dim, 2, need - 1) else {
            panic!("a budget one byte short of the dense footprint must refuse");
        };
        assert!(
            matches!(&err, RepairError::SolveBudget { .. }),
            "past the flat cap the refusal must be a capacity one, naming memory rather than \
             a matrix dimension - a bigger budget admits it: {err}"
        );
    }

    // 4. ...and the dense arm is charged for MEMORY too, which it was
    //    not until 8 Sep 2026. EVERY dense assertion above passes
    //    `block_size = 2`, where the window is 256 bytes and no budget
    //    can bind - so the arm was covered at every DIMENSION boundary
    //    and at no MEMORY one, and the missing test was invisible.
    //    Sizes here are therefore realistic on purpose.
    //
    //    The cliff this closes was one block wide: on a box whose gate
    //    sits at `backsub_min_missing()`, the m just below it took the
    //    dense arm and allocated the same window the m just above it was
    //    refused for.
    let gate = super::forney::backsub_min_missing();
    if gate > 1 {
        let below = gate - 1;
        assert!(
            !super::forney::backsub_gate(below),
            "{below} must sit on the dense side of the gate"
        );
        // 64 KiB rather than 1 MiB, and the size is load-bearing: when
        // the generic gate was 2,048 the Forney half below computed
        // `2 * 2048 * 1 MiB`, exactly 2^32, which does not fit a 32-bit
        // `usize` - it panics under test on the shipped armv7 build and
        // wraps to 0 in release. The 10 Sep 2026 recalibration lowered
        // every gate (1,280 generic and nibble, 704 NEON), so that exact
        // product no longer overflows - but the margin is what this line
        // is for and a gate can move back up, so it stays well clear.
        // The production window is `u64` and saturating; this arithmetic
        // is not.
        let bs = 64 << 10;
        // Both arms hold two m x block_size buffers; the DENSE arm holds
        // its `~4*m^2` matrix and inverse on top, so its bound is its own
        // and is strictly larger. Until 8 Sep 2026 the two were charged
        // the same window and the dense arm's matrix was not priced at
        // all - it was covered by a flat dimension cap instead, which is
        // the thing that got removed.
        let window = 2 * below * bs;
        let dense_need = window + 4 * below * below;
        let Err(err) = check_repair_dim_within(below, bs, dense_need as u64 - 1) else {
            panic!("the dense arm must be refused when its footprint is over budget");
        };
        assert!(
            matches!(&err, RepairError::SolveBudget { .. }),
            "the dense arm's memory refusal must be a capacity refusal, not Malformed - \
             the recovery set is good and a bigger budget admits it: {err}"
        );
        assert!(
            check_repair_dim_within(below, bs, dense_need as u64).is_ok(),
            "exactly its own footprint must still be admitted"
        );
        assert!(
            check_repair_dim_within(below, bs, window as u64).is_err(),
            "the WINDOW alone must no longer admit the dense arm - the matrix is real \
             memory and this assertion is what stops it going unpriced again"
        );
        // The gate is a KERNEL boundary and not a memory one, so the two
        // arms must answer the same way one block either side of it.
        if super::forney::backsub_gate(gate) {
            let forney_window = 2 * gate * bs;
            assert!(
                matches!(
                    check_repair_dim_within(gate, bs, forney_window as u64 - 1),
                    Err(RepairError::SolveBudget { .. })
                ),
                "one block either side of the arm gate must refuse alike"
            );
        }
    }
}

/// The back-substitution arm is decided by the EXPONENT SET, and the
/// third arm is expensive enough that which one a repair reaches is a
/// performance property worth pinning.
///
/// Consecutive exponents make `A` a Vandermonde times a diagonal, whose
/// explicit inverse is `O(m^2)` and which factors again into the Forney
/// transform past `forney::backsub_gate`. An arithmetic progression
/// relabels onto the same shape (`progression_parameters`). ANY OTHER
/// set - one gap is enough - is a generalized Vandermonde with no
/// factorization and falls onto Gauss-Jordan: `O(m^3)` setup plus the
/// dense product, and the one arm `MAX_REPAIR_DIM` still refuses past.
///
/// Measured 8 Sep 2026 on the M3 Ultra at m = 2,048 / 64 KiB blocks
/// (`par2_ntt_bench`, `NZBFAST_NTT_EXP_SPAN`): 4.8 ms setup + 122 ms
/// solve consecutive, against 940 ms setup + 395 ms dense with one gap -
/// 5.6x over the whole reconstructor, and identical on the fold and the
/// NTT syndrome paths because this arm is chosen before any syndrome
/// exists. That is what `catalog::select_consecutive_run` exists to
/// avoid paying, and why both repair drivers select through it.
#[test]
fn the_backsub_arm_is_decided_by_the_exponent_set() {
    let bs = 64usize;
    let slices = demo_slices(6, bs);
    let missing = [0usize, 2, 4];
    let arm = |exps: &[u32]| -> &'static str {
        let recovery: Vec<(u32, Vec<u8>)> = exps
            .iter()
            .map(|&e| (e, generate_recovery(&slices, bs, e)))
            .collect();
        Reconstructor::new(bs, slices.len(), &missing, &recovery)
            .expect("well-formed set")
            .backsub_arm()
    };
    // Consecutive: the structured arm. (m = 3 is far under
    // `backsub_gate`, so it is the explicit inverse rather than Forney;
    // the gate's own tests cover the Forney side.)
    assert_eq!(arm(&[0, 1, 2]), "vandermonde");
    assert_eq!(arm(&[7, 8, 9]), "vandermonde");
    // An arithmetic progression relabels onto it - but only when the
    // stride is a UNIT modulo 65535. 2 is; 3 is not (65535 = 3*5*17*257),
    // so a stride-3 set keeps the unstructured arm.
    assert_eq!(arm(&[1, 3, 5]), "vandermonde");
    assert_eq!(arm(&[0, 3, 6]), "gauss-jordan");
    // One gap and the structure is gone.
    assert_eq!(arm(&[0, 1, 3]), "gauss-jordan");
    assert_eq!(arm(&[0, 2, 3]), "gauss-jordan");
}

/// The MAPPED driver picks the lowest consecutive RUN, not the `m`
/// smallest exponents - the selection the disk driver has made since
/// 6 Sep 2026 and this one, the in-place repair the download pipeline
/// runs, did not until 8 Sep 2026.
///
/// With recovery at `[0, 1, 3, 4, 5]` and three blocks missing, taking
/// the smallest three gives `[0, 1, 3]`, which is neither consecutive
/// nor a progression and so lands on Gauss-Jordan for no reason at all:
/// the same set holds the clean run `[3, 4, 5]`. See
/// `the_backsub_arm_is_decided_by_the_exponent_set` for what that costs.
#[test]
fn the_mapped_driver_selects_the_consecutive_run_not_the_smallest() {
    // The selection expression the driver evaluates, over the exponent
    // set below. The arm each of the two answers reaches is pinned by
    // the sibling test above.
    let offered = [0u32, 1, 3, 4, 5];
    let chosen = super::catalog::select_consecutive_run(&offered, 3);
    assert_eq!(chosen, vec![3, 4, 5], "a run was available and not taken");
    let mut smallest = offered.to_vec();
    smallest.truncate(3);
    assert_ne!(
        chosen, smallest,
        "the fixture must discriminate the two rules"
    );

    // ...and the driver still repairs byte-exactly through it. Three
    // damaged blocks, all in file 0, against the gapped offer.
    let damage = [(0usize, 0usize), (0, 1), (0, 2)];
    let (files, bs, _consecutive, pristine) = mapped_fixture(&damage);
    let mut slices: Vec<Vec<u8>> = Vec::new();
    for d in &pristine {
        for c in d.chunks(bs) {
            let mut v = c.to_vec();
            v.resize(bs, 0);
            slices.push(v);
        }
    }
    let recovery: Vec<(u32, Vec<u8>)> = offered
        .iter()
        .map(|&e| (e, generate_recovery(&slices, bs, e)))
        .collect();
    let mut on_disk = pristine.clone();
    on_disk[0][..3 * bs].fill(0);
    let io = MemIo::new(on_disk, None);
    assert_eq!(
        repair_mapped(&files, bs, &recovery, &io, false).expect("repairs"),
        3
    );
    assert_eq!(io.snapshot(), pristine, "byte-identical restoration");
}

/// The fold's cache probe must answer a PLAUSIBLE per-core L2 wherever
/// the platform supports the query, because both consumers
/// (`l2_target_words`, `unit_dst_budget`) size the fold's tiles off it.
///
/// The value is machine-specific, so this asserts a range rather than a
/// number - but the range is what a decode bug actually violates. These
/// OIDs are NOT all the same width (`hw.l2cachesize` answers 8 bytes on
/// an M3 Ultra, `hw.perflevel0.*` answer 4), so reading one at the wrong
/// width yields either a huge number (high garbage) or zero, and both
/// land outside this window. A silently wrong budget is invisible in
/// every correctness test in this file - the fold still computes the
/// right answer, just with the wrong residency - which is why the probe
/// is pinned here instead.
#[test]
fn l2_probe_answers_a_plausible_per_core_size() {
    let Some(bytes) = l2_per_core_bytes() else {
        // A platform that cannot say (musl, and anything not
        // Windows/Linux-gnu/macOS) is a supported answer: the callers
        // take their default budget. Nothing to check.
        return;
    };
    assert!(
        (64 << 10..=64 << 20).contains(&bytes),
        "per-core L2 probe answered {bytes} bytes, outside 64 KiB..64 MiB - \
         a plausible per-core L2 cannot sit outside that, so this is a \
         decode or OID fault rather than an unusual part"
    );
}
