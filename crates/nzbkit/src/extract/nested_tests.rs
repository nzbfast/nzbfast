//! The nested one-pass extraction tests (store-in-store, the chasing
//! decompressor, depth/memory accounting), moved out of extract/mod.rs
//! bodily (TODO 106).
//!
//! extract/mod.rs carried a 3,018-line inline `mod tests`. It splits at the
//! banner below: the flat-set/shape half is `mod_tests.rs`, the recursive
//! half is here. Two files because either half alone would otherwise need a
//! size-gate entry of its own. Child modules of `extract`, so `super::*`
//! and `super::testutil::*` name exactly what they named inline.

use super::*;
use crate::rar::fixtures;

use super::testutil::*;

// -- encrypted RAR5 store sets (native AES decryption) --

// -- Finding 4 (TODO 30): promoted plain children --

/// A routed child slot that classifies its inner file as Plain is
/// terminal, so the parent caches the child's `Arc<FileWriter>` in
/// `routed_plain` and every later article writes straight into it -
/// parent lock, child lock, child pwrite, parent re-lock collapses to
/// one off-lock pwrite. Landed unpinned in `3f6c129f`; this is the pin.
///
/// Two assertions, because neither alone is worth much:
///
/// * the parent group really holds a `routed_plain` entry for the raw
///   inner name - without it the test passes verbatim on the
///   pre-promotion ladder and pins nothing;
/// * the output writer's PHYSICAL byte count (`written`, every
///   `write_at`) equals the file size, so every byte was written
///   exactly once. This is the failure the promotion could plausibly
///   introduce: leaving the child on the per-article path as well as
///   the parent would write each span twice, which `covered` (unique
///   bytes) and the on-disk bytes both hide - the second write lands
///   at the same offset with the same payload.
///
/// Volumes are fed IN ORDER here rather than through the shuffling
/// `feed`: with the offset-0 sniff arriving first the promotion is live
/// from the second article on, and measured with a doubling probe on
/// the depth-0 job loop it then carries 343,041 of the 350,000 bytes -
/// 98%, everything but the first article, which still walks the child
/// ladder and is what promotes. Under a shuffled feed most of the file
/// arrives pre-classification and drains under the lock instead, so the
/// promoted route would carry a third of it and the byte-count
/// assertion would be mostly about a path this test is not named for.
#[test]
fn promoted_plain_child_writes_each_byte_exactly_once() {
    let e01 = payload(350_000, 21);
    let vols: Vec<Vec<u8>> = vec![
        fixtures::rar5_volume_n(&[("E01.mkv", 350_000, &e01[..120_000], false, true)], 0),
        fixtures::rar5_volume_n(
            &[("E01.mkv", 350_000, &e01[120_000..240_000], true, true)],
            1,
        ),
        fixtures::rar5_volume_n(&[("E01.mkv", 350_000, &e01[240_000..], true, false)], 2),
    ];
    let dir = tmpdir("f4promote");
    let ex = Extractor::new(&dir, 3, true);
    for (vi, vol) in vols.iter().enumerate() {
        let name = format!("obf{:02x}.bin", (vi as u8) ^ 0x5a);
        for s in (0..vol.len()).step_by(7000) {
            let e = (s + 7000).min(vol.len());
            ex.write(vi, &name, vol.len() as u64, s as u64, &vol[s..e])
                .unwrap();
        }
    }
    let promoted: Vec<String> = {
        let inner = ex.inner.lock_ok();
        inner
            .groups
            .values()
            .flat_map(|g| g.routed_plain.keys().cloned())
            .collect()
    };
    let writers = ex.writers_snapshot();
    let rep = ex.finish().unwrap();

    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(rep.extracted, vec![("E01.mkv".to_string(), 350_000)]);
    assert_eq!(std::fs::read(dir.join("E01.mkv")).unwrap(), e01);
    assert_eq!(promoted, vec!["E01.mkv".to_string()], "no promotion");

    let w = writers
        .iter()
        .find(|(n, _)| n == "E01.mkv")
        .map(|(_, w)| w)
        .expect("no writer for the promoted child output");
    assert_eq!(
        w.written(),
        350_000,
        "promoted child bytes written more than once"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

// -- nested one-pass: store-in-store via the recursive child --

/// Outer store volumes wrapping a store archive wrapping the final
/// files: both layers map in one pass - the final files land
/// byte-exact and NEITHER the outer volumes NOR the intermediate
/// archive ever exist on disk. Driven across three feed orders
/// (mirroring `multi_file_store_set_survives_all_feed_orders`).
#[test]
fn two_level_store_set_extracts_one_pass() {
    let a = payload(300_000, 81);
    let b = payload(150_000, 82);
    let inner_arch = fixtures::rar5_volume(&[
        ("A.mkv", 300_000, &a, false, false),
        ("B.mkv", 150_000, &b, false, false),
    ]);
    let n = inner_arch.len();
    // WinRAR-true: vol 0's piece is one byte longer than vol 1's.
    let (c1, c2) = (n / 3 + 1, n / 3 + 1 + n / 3);
    let vols: Vec<Vec<u8>> = vec![
        fixtures::rar5_volume_n(
            &[("inner.rar", n as u64, &inner_arch[..c1], false, true)],
            0,
        ),
        fixtures::rar5_volume_n(
            &[("inner.rar", n as u64, &inner_arch[c1..c2], true, true)],
            1,
        ),
        fixtures::rar5_volume_n(
            &[("inner.rar", n as u64, &inner_arch[c2..], true, false)],
            2,
        ),
    ];
    for (t, order) in [[0usize, 1, 2], [2, 1, 0], [1, 2, 0]].iter().enumerate() {
        let dir = tmpdir(&format!("nested2l{t}"));
        let ex = Extractor::new(&dir, 3, true);
        for &vi in order {
            let name = format!("obf{:02x}.bin", (vi as u8) ^ 0x3c);
            feed(&ex, vi, &name, &vols[vi], 7000, 70 + vi as u64);
        }
        // Finding 4's counter-case: `inner.rar` is a routed child whose
        // slot classifies as Rar, never Plain, so the outer group must
        // never cache a writer for it - a promotion here would pwrite
        // the intermediate archive to disk and lose the second pass.
        assert!(
            ex.inner
                .lock_ok()
                .groups
                .values()
                .all(|g| g.routed_plain.is_empty()),
            "order {order:?}: a nested RAR child promoted"
        );
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks.is_empty(),
            "order {order:?}: {:?}",
            rep.fallbacks
        );
        assert_eq!(
            rep.extracted,
            vec![
                ("A.mkv".to_string(), 300_000),
                ("B.mkv".to_string(), 150_000)
            ],
            "order {order:?}"
        );
        assert_eq!(
            std::fs::read(dir.join("A.mkv")).unwrap(),
            a,
            "order {order:?}"
        );
        assert_eq!(
            std::fs::read(dir.join("B.mkv")).unwrap(),
            b,
            "order {order:?}"
        );
        // One pass: no outer volume, no intermediate archive.
        assert_eq!(
            dir_files(&dir),
            vec!["A.mkv".to_string(), "B.mkv".to_string()],
            "order {order:?}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// An INNER volume boundary spanning two OUTER volumes: the child's
/// base for the final file's continuation piece resolves through the
/// composed cum-chain, with the level-1 volume's bytes arriving via
/// two different parent slots.
#[test]
fn nested_split_chain() {
    let f = payload(400_000, 83);
    let iv1 = fixtures::rar5_volume_n(&[("F.mkv", 400_000, &f[..200_000], false, true)], 0);
    let iv2 = fixtures::rar5_volume_n(&[("F.mkv", 400_000, &f[200_000..], true, false)], 1);
    let cut = iv2.len() / 2;
    let vols: Vec<Vec<u8>> = vec![
        fixtures::rar5_volume_n(
            &[
                ("inner.part1.rar", iv1.len() as u64, &iv1, false, false),
                (
                    "inner.part2.rar",
                    iv2.len() as u64,
                    &iv2[..cut],
                    false,
                    true,
                ),
            ],
            0,
        ),
        fixtures::rar5_volume_n(
            &[(
                "inner.part2.rar",
                iv2.len() as u64,
                &iv2[cut..],
                true,
                false,
            )],
            1,
        ),
    ];
    for (t, order) in [[0usize, 1], [1, 0]].iter().enumerate() {
        let dir = tmpdir(&format!("nestedsplit{t}"));
        let ex = Extractor::new(&dir, 2, true);
        for &vi in order {
            feed(
                &ex,
                vi,
                &format!("zz{vi}.bin"),
                &vols[vi],
                8000,
                90 + vi as u64,
            );
        }
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks.is_empty(),
            "order {order:?}: {:?}",
            rep.fallbacks
        );
        assert_eq!(
            rep.extracted,
            vec![("F.mkv".to_string(), 400_000)],
            "order {order:?}"
        );
        assert_eq!(
            std::fs::read(dir.join("F.mkv")).unwrap(),
            f,
            "order {order:?}"
        );
        assert_eq!(
            dir_files(&dir),
            vec!["F.mkv".to_string()],
            "order {order:?}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// Reusing the verified article CRC must compose to exactly what
/// hashing the routed bytes composes: a clean nested store set still
/// one-passes with no demotion, in every feed order.
#[test]
fn a_reused_article_crc_extracts_the_same_as_hashing() {
    let f = payload(400_000, 86);
    let whole = crc32fast::hash(&f);
    let iv = [
        // WinRAR-true geometry: volume 0 carries one byte more (its
        // main header has no volume-number field).
        fixtures::rar5_volume_n_crc(
            &[(
                "F.mkv",
                400_000,
                &f[..150_001],
                false,
                true,
                Some(crc32fast::hash(&f[..150_001])),
            )],
            0,
        ),
        fixtures::rar5_volume_n_crc(
            &[(
                "F.mkv",
                400_000,
                &f[150_001..300_001],
                true,
                true,
                Some(crc32fast::hash(&f[150_001..300_001])),
            )],
            1,
        ),
        fixtures::rar5_volume_n_crc(
            &[("F.mkv", 400_000, &f[300_001..], true, false, Some(whole))],
            2,
        ),
    ];
    let outer = fixtures::rar5_volume(&[
        ("i.part1.rar", iv[0].len() as u64, &iv[0], false, false),
        ("i.part2.rar", iv[1].len() as u64, &iv[1], false, false),
        ("i.part3.rar", iv[2].len() as u64, &iv[2], false, false),
    ]);
    for seed in [11u64, 12, 13] {
        let dir = tmpdir(&format!("reusecrc{seed}"));
        let ex = Extractor::new(&dir, 1, true);
        feed_verified(&ex, 0, "o.rar", &outer, 7000, seed, 0);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "seed {seed}: {:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("F.mkv")).unwrap(), f, "seed {seed}");
        assert_eq!(dir_files(&dir), vec!["F.mkv".to_string()], "seed {seed}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// The reused value must actually REACH the composition, and be the
/// thing the finish gate judges. A single-level store volume whose
/// entry carries a real header CRC is the case where the composed
/// value is actually compared: hand over article CRCs that do not
/// describe the bytes and the gate has to demote. The payload itself
/// is intact, so nothing but the passed-in CRC can cause that - and
/// if the run came out clean, the caller's CRC was being ignored and
/// the fast path would be vouching for nothing.
#[test]
fn a_wrong_article_crc_is_not_taken_on_trust() {
    let f = payload(300_000, 88);
    let vol = fixtures::rar5_volume_n_crc(
        &[(
            "F.mkv",
            300_000,
            &f,
            false,
            false,
            Some(crc32fast::hash(&f)),
        )],
        0,
    );

    // Truthful CRCs: extracts, no demotion.
    let dir = tmpdir("reusecrcok1");
    let ex = Extractor::new(&dir, 1, true);
    feed_verified(&ex, 0, "v.rar", &vol, 7000, 11, 0);
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks.is_empty(),
        "clean set demoted: {:?}",
        rep.fallbacks
    );
    assert_eq!(std::fs::read(dir.join("F.mkv")).unwrap(), f);
    std::fs::remove_dir_all(&dir).unwrap();

    // Same bytes, CRCs that describe nothing: must NOT pass the gate.
    let dir = tmpdir("reusecrcbad");
    let ex = Extractor::new(&dir, 1, true);
    feed_verified(&ex, 0, "v.rar", &vol, 7000, 11, 0x5AA5_5AA5);
    let rep = ex.finish().unwrap();
    assert!(
        !rep.fallbacks.is_empty(),
        "a CRC that describes nothing was accepted as proof the payload is good"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Store inner volumes carrying real header CRCs (last piece = whole
/// file, earlier pieces = their own bytes, like real archivers write):
/// intact data one-pass extracts with NO demotion in any feed order -
/// the in-stream CRC gate must never false-positive on clean sets.
#[test]
fn nested_store_with_crcs_extracts_clean() {
    let f = payload(400_000, 86);
    let whole = crc32fast::hash(&f);
    let iv = [
        // WinRAR-true geometry: volume 0 carries one byte more (its
        // main header has no volume-number field).
        fixtures::rar5_volume_n_crc(
            &[(
                "F.mkv",
                400_000,
                &f[..150_001],
                false,
                true,
                Some(crc32fast::hash(&f[..150_001])),
            )],
            0,
        ),
        fixtures::rar5_volume_n_crc(
            &[(
                "F.mkv",
                400_000,
                &f[150_001..300_001],
                true,
                true,
                Some(crc32fast::hash(&f[150_001..300_001])),
            )],
            1,
        ),
        fixtures::rar5_volume_n_crc(
            &[("F.mkv", 400_000, &f[300_001..], true, false, Some(whole))],
            2,
        ),
    ];
    let outer = fixtures::rar5_volume(&[
        ("i.part1.rar", iv[0].len() as u64, &iv[0], false, false),
        ("i.part2.rar", iv[1].len() as u64, &iv[1], false, false),
        ("i.part3.rar", iv[2].len() as u64, &iv[2], false, false),
    ]);
    for seed in [11u64, 12, 13] {
        let dir = tmpdir(&format!("nestcrcok{seed}"));
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "o.rar", &outer, 7000, seed);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "seed {seed}: {:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("F.mkv")).unwrap(), f, "seed {seed}");
        assert_eq!(dir_files(&dir), vec!["F.mkv".to_string()], "seed {seed}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// The residual gauntlet gap: a store inner set whose DATA was
/// damaged before packing (headers intact, header CRCs computed over
/// the original bytes). Mapping succeeds, so without the CRC gate the
/// corrupt payload would ship silently with rc=0. The gate must
/// demote the nested level to materialized volumes - byte-exact as
/// packed, damage included, where a par2 set can reach them - and
/// delete the corrupt extracted output.
#[test]
fn nested_store_data_damage_demotes_on_crc() {
    let f = payload(400_000, 87);
    let whole = crc32fast::hash(&f);
    let mut iv = [
        // WinRAR-true geometry: volume 0 carries one byte more (its
        // main header has no volume-number field).
        fixtures::rar5_volume_n_crc(
            &[(
                "F.mkv",
                400_000,
                &f[..150_001],
                false,
                true,
                Some(crc32fast::hash(&f[..150_001])),
            )],
            0,
        ),
        fixtures::rar5_volume_n_crc(
            &[(
                "F.mkv",
                400_000,
                &f[150_001..300_001],
                true,
                true,
                Some(crc32fast::hash(&f[150_001..300_001])),
            )],
            1,
        ),
        fixtures::rar5_volume_n_crc(
            &[("F.mkv", 400_000, &f[300_001..], true, false, Some(whole))],
            2,
        ),
    ];
    // Poster damage: flip bytes in the middle of i.part2.rar - deep
    // inside its 150 KB data area, nowhere near the headers.
    let mid = iv[1].len() / 2;
    for b in &mut iv[1][mid..mid + 64] {
        *b ^= 0xA5;
    }
    let outer = fixtures::rar5_volume(&[
        ("i.part1.rar", iv[0].len() as u64, &iv[0], false, false),
        ("i.part2.rar", iv[1].len() as u64, &iv[1], false, false),
        ("i.part3.rar", iv[2].len() as u64, &iv[2], false, false),
    ]);
    let dir = tmpdir("nestcrcbad");
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "o.rar", &outer, 7000, 21);
    let rep = ex.finish().unwrap();
    let nested: Vec<_> = rep
        .fallbacks
        .iter()
        .filter(|(_, w)| w.starts_with("nested fallback:"))
        .collect();
    assert_eq!(nested.len(), 1, "{:?}", rep.fallbacks);
    assert!(
        nested[0].1.contains("failed its stored CRC"),
        "{:?}",
        rep.fallbacks
    );
    for (_, w) in &rep.fallbacks {
        assert!(
            !w.contains("compressed")
                && !w.contains("encrypted")
                && !w.contains("password")
                && !w.contains("held-bytes cap")
                && !w.contains("incomplete mapping"),
            "nested reason leaks a volume-remediation trigger: {w}"
        );
    }
    // The corrupt payload must not masquerade as output; the volumes
    // materialize byte-exact AS PACKED (damage included) so a
    // recovery set can verify and repair them.
    assert!(!dir.join("F.mkv").exists(), "corrupt output survived");
    for (i, v) in iv.iter().enumerate() {
        let p = dir.join(format!("i.part{}.rar", i + 1));
        assert_eq!(
            &std::fs::read(&p).unwrap(),
            v,
            "volume {} not byte-exact",
            i + 1
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A nested RAR4 store file now verifies IN-STREAM (finding 9): the v4
/// parser retains the header CRC, so clean inner data extracts on the
/// fast path (no demote to a materialized level-1 archive), and
/// damaged-before-packing data is caught by the composed CRC and
/// demoted honestly instead of shipping with rc=0.
#[test]
fn nested_rar4_store_verifies_in_stream() {
    // Clean inner RAR4: composed CRC matches, one-pass extract, no demote.
    let dir = tmpdir("nest-rar4-gate");
    let data = payload(60_000, 71);
    let v4 = fixtures::rar4_volume(&[("old.avi", 60_000, &data, false, false)]);
    let outer = fixtures::rar5_volume(&[("inner.rar", v4.len() as u64, &v4, false, false)]);
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "v.rar", &outer, 5000, 17);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("old.avi")).unwrap(), data);
    assert!(
        !dir.join("inner.rar").exists(),
        "clean inner RAR4 should not materialize"
    );
    std::fs::remove_dir_all(&dir).unwrap();

    // Damaged inner RAR4: header CRC over pristine bytes, data area
    // flipped - the gate must demote, never ship the corrupt payload.
    let dir = tmpdir("nest-rar4-gate-bad");
    let mut v4b = fixtures::rar4_volume(&[("old.avi", 60_000, &data, false, false)]);
    let off = {
        let mut m = crate::rar::VolumeMapper::new(v4b.len() as u64);
        m.feed(0, &v4b);
        m.entries[0].data_off as usize
    };
    for b in &mut v4b[off + 30_000..off + 30_064] {
        *b ^= 0x5A;
    }
    let outer = fixtures::rar5_volume(&[("inner.rar", v4b.len() as u64, &v4b, false, false)]);
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "v.rar", &outer, 5000, 29);
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks
            .iter()
            .any(|(_, w)| w.contains("failed its stored CRC")),
        "{:?}",
        rep.fallbacks
    );
    assert!(
        !dir.join("old.avi").exists(),
        "corrupt inner RAR4 payload shipped"
    );
    assert_eq!(std::fs::read(dir.join("inner.rar")).unwrap(), v4b);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Compressed inner archive: the child demotes and materializes the
/// level-1 file intact - exactly the single-level output the disk
/// post-pass expects - reported as a nested fallback whose wording
/// must never pattern-match the caller's volume-level remediation
/// branches. The job itself succeeds.
#[test]
fn nested_compressed_inner_demotes() {
    let dir = tmpdir("nestedcomp");
    let junk = payload(120_000, 84);
    let inner_arch = rar5_compressed_volume("F.bin", &junk);
    let outer = fixtures::rar5_volume(&[(
        "inner.rar",
        inner_arch.len() as u64,
        &inner_arch,
        false,
        false,
    )]);
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "v.rar", &outer, 7000, 9);
    let rep = ex.finish().unwrap();
    assert_eq!(std::fs::read(dir.join("inner.rar")).unwrap(), inner_arch);
    assert!(!dir.join("v.rar").exists(), "one-pass: no outer volume");
    assert!(
        rep.extracted
            .iter()
            .any(|(n, s)| n == "inner.rar" && *s == inner_arch.len() as u64),
        "{:?}",
        rep.extracted
    );
    let nested: Vec<_> = rep
        .fallbacks
        .iter()
        .filter(|(_, w)| w.starts_with("nested fallback:"))
        .collect();
    assert_eq!(nested.len(), 1, "{:?}", rep.fallbacks);
    for (_, w) in &rep.fallbacks {
        assert!(
            !w.contains("compressed")
                && !w.contains("encrypted")
                && !w.contains("password")
                && !w.contains("held-bytes cap")
                && !w.contains("incomplete mapping"),
            "nested reason leaks a volume-remediation trigger: {w}"
        );
    }
    assert_eq!(dir_files(&dir), vec!["inner.rar".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Phase 0(b): the prevalence tally reflects a known nested fixture. A
/// store-in-store (outer -> inner.rar -> movie.mkv) streams the inner
/// payload entirely in RAM, so the depth-1 child logs one in-stream
/// `rar-store` level and bumps `in_stream` + `rar_store`. Depth 0 (the
/// outer set) is never counted. The tally is process-global under the
/// parallel runner, so the assertions are lower-bound deltas, not
/// absolutes.
#[test]
fn nested_prevalence_counts_in_stream_store() {
    let before = nested_prevalence();
    let dir = tmpdir("nestprev");
    let data = payload(90_000, 91);
    let inner_arch =
        fixtures::rar5_volume(&[("movie.mkv", data.len() as u64, &data, false, false)]);
    let outer = fixtures::rar5_volume(&[(
        "inner.rar",
        inner_arch.len() as u64,
        &inner_arch,
        false,
        false,
    )]);
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "v.rar", &outer, 7000, 41);
    let rep = ex.finish().unwrap();
    // In-stream store-in-store: the inner payload is produced directly,
    // no volume ever materialized, no fallback.
    assert_eq!(
        rep.extracted,
        vec![("movie.mkv".to_string(), data.len() as u64)]
    );
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    let after = nested_prevalence();
    assert!(
        after.in_stream > before.in_stream,
        "in_stream did not advance ({} -> {})",
        before.in_stream,
        after.in_stream
    );
    assert!(
        after.rar_store > before.rar_store,
        "rar_store did not advance ({} -> {})",
        before.rar_store,
        after.rar_store
    );
    assert!(
        after.levels > before.levels,
        "levels did not advance ({} -> {})",
        before.levels,
        after.levels
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Phase 0(b) false-positive guard: `slot_inner_kind` names only the
/// three nested-archive modes and stays silent (`None`) for a plain
/// file, an unclassified span, or an already-demoted slot - so a
/// demoting non-archive can never emit a `demoted` line and bias the
/// tally. Deterministic (no counter, no fixture): the whole risk is
/// this classifier saying "archive" for a non-archive.
#[test]
fn slot_inner_kind_ignores_non_archive_slots() {
    let dir = tmpdir("slotkind");
    let ex = Extractor::new(&dir, 1, true);
    let mut g = ex.inner.lock().unwrap();
    let base = g.slots.len();
    for m in [
        SlotMode::Plain,
        SlotMode::Unknown,
        SlotMode::RarFallback,
        SlotMode::Discard,
        SlotMode::SevenZ,
    ] {
        let mut s = Extractor::new_slot();
        s.mode = m;
        g.slots.push(s);
    }
    assert_eq!(Extractor::slot_inner_kind(&g, base), None, "Plain");
    assert_eq!(Extractor::slot_inner_kind(&g, base + 1), None, "Unknown");
    assert_eq!(
        Extractor::slot_inner_kind(&g, base + 2),
        None,
        "RarFallback"
    );
    assert_eq!(Extractor::slot_inner_kind(&g, base + 3), None, "Discard");
    assert_eq!(
        Extractor::slot_inner_kind(&g, base + 4),
        Some("7z"),
        "SevenZ"
    );
    drop(g);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Phase 0(b): a group-less nested inner that DEMOTES (an encrypted 7z
/// with no password) emits the `demoted` diagnostic at the demote site
/// - so `demoted` advances while `levels`/`in_stream` do NOT (the
/// materialized .7z is counted under `disk` by the disk post-pass, not
/// here). Lower-bound deltas: the tally is process-global.
#[test]
fn nested_prevalence_counts_demoted_sevenz() {
    let before = nested_prevalence();
    let f = payload(120_000, 173);
    let arch = sevenz_archive(
        &[("F.bin", &f)],
        Some(vec![
            sevenz_rust2::encoder_options::AesEncoderOptions::new(sevenz_rust2::Password::from(
                "secret",
            ))
            .into(),
        ]),
        false,
    );
    let outer = store_outer("inner.7z", &arch);
    let dir = tmpdir("prev-7z-demote");
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "v.rar", &outer, 7000, 51);
    let rep = ex.finish().unwrap();
    // The 7z demoted to a materialized volume, as its own test proves.
    assert!(
        rep.fallbacks
            .iter()
            .any(|(_, w)| w.starts_with("nested fallback:")),
        "{:?}",
        rep.fallbacks
    );
    let after = nested_prevalence();
    assert!(
        after.demoted > before.demoted,
        "demoted did not advance ({} -> {})",
        before.demoted,
        after.demoted
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Phase 0(b): the GROUPED demote topology (a multi-volume store set
/// whose data is CRC-damaged demotes the whole group via the finish-time
/// CRC gate -> fallback_group) also bumps `demoted` - but through
/// `report_nested_prevalence`'s groups loop, NOT the demote site. This
/// is the double-emit-safe counterpart to the group-less 7z demote test
/// above: the two demote topologies take structurally different emit
/// paths, and both must count. Lower-bound delta (process-global tally).
#[test]
fn nested_prevalence_counts_grouped_demote() {
    let before = nested_prevalence();
    let f = payload(400_000, 177);
    let whole = crc32fast::hash(&f);
    let mut iv = [
        // WinRAR-true geometry: volume 0 carries one byte more (its
        // main header has no volume-number field).
        fixtures::rar5_volume_n_crc(
            &[(
                "F.mkv",
                400_000,
                &f[..150_001],
                false,
                true,
                Some(crc32fast::hash(&f[..150_001])),
            )],
            0,
        ),
        fixtures::rar5_volume_n_crc(
            &[(
                "F.mkv",
                400_000,
                &f[150_001..300_001],
                true,
                true,
                Some(crc32fast::hash(&f[150_001..300_001])),
            )],
            1,
        ),
        fixtures::rar5_volume_n_crc(
            &[("F.mkv", 400_000, &f[300_001..], true, false, Some(whole))],
            2,
        ),
    ];
    // Poster damage deep in volume 2's data area -> the CRC gate demotes
    // the whole store group at finish.
    let mid = iv[1].len() / 2;
    for b in &mut iv[1][mid..mid + 64] {
        *b ^= 0xA5;
    }
    let outer = fixtures::rar5_volume(&[
        ("i.part1.rar", iv[0].len() as u64, &iv[0], false, false),
        ("i.part2.rar", iv[1].len() as u64, &iv[1], false, false),
        ("i.part3.rar", iv[2].len() as u64, &iv[2], false, false),
    ]);
    let dir = tmpdir("prev-grouped-demote");
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "o.rar", &outer, 7000, 57);
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks
            .iter()
            .any(|(_, w)| w.starts_with("nested fallback:")),
        "{:?}",
        rep.fallbacks
    );
    let after = nested_prevalence();
    assert!(
        after.demoted > before.demoted,
        "grouped demoted did not advance ({} -> {})",
        before.demoted,
        after.demoted
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A 6-deep STORE chain, and the rule that a stored layer does not
/// spend a level of the depth cap.
///
/// This test pinned the opposite until `c0b1c788a` (31 Aug 2026), which
/// made the cap count COMPRESSING layers only: it is a
/// decompression-bomb backstop, and a stored layer is the same bytes
/// with a header on the front, so it cannot expand. That commit changed
/// `extract/mod.rs` and `extract/config.rs` and did not come back here,
/// so this test went on asserting the old contract and reddened
/// `linux-tests`, `unit-one-process` and `windows-unit` on main - one
/// defect, three jobs. The assertions below are the NEW contract.
///
/// So a store-only ladder now maps all the way down whatever the cap
/// says, at the default cap AND at an explicitly configured shallower
/// one. That is the point of the change (a real 10-deep store ladder in
/// the bench corpus went manual-intervention 9/12 to auto-complete
/// 12/12), and it is why `set_nested_max_depth` no longer binds a
/// stored chain: the operator knob is a bomb guard, and this is not a
/// bomb. What DOES bound a store ladder is
/// `NESTED_MAX_DEPTH_HARD_CEILING`, pinned by
/// `nested_store_ladder_stops_at_the_hard_ceiling` below.
///
/// `fixtures::rar5_volume` builds STORE members only, so this chain
/// cannot be rebuilt as a compressing one to keep the old assertion -
/// the cap-lands-here property is exercised on a compressing layer by
/// the fallback and demotion tests above, not here.
#[test]
fn nested_depth_cap_materializes() {
    let data = payload(50_000, 85);
    let wrap = |name: &str, inner: &[u8]| {
        fixtures::rar5_volume(&[(name, inner.len() as u64, inner, false, false)])
    };
    // A 6-deep store chain: outer(a1) < a2 < a3 < a4 < a5 < payload.
    // Extracting akN yields ak(N+1).
    let payload_rar = wrap("payload.bin", &data);
    let c5 = wrap("a5.rar", &payload_rar);
    let c4 = wrap("a4.rar", &c5);
    let c3 = wrap("a3.rar", &c4);
    let c2 = wrap("a2.rar", &c3);
    let outer = wrap("a1.rar", &c2);

    // Default cap (5): every layer is stored, so none of them spends a
    // level and the chain maps to the payload itself.
    let dir = tmpdir("nesteddepth");
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "outer.rar", &outer, 7000, 12);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(
        rep.extracted,
        vec![("payload.bin".to_string(), data.len() as u64)]
    );
    assert_eq!(std::fs::read(dir.join("payload.bin")).unwrap(), data);
    assert_eq!(dir_files(&dir), vec!["payload.bin".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();

    // Configured shallower cap (3): the SAME chain still reaches the
    // payload. The knob counts compressing layers, and there are none -
    // it is not ignored here, it has nothing to charge. A test that
    // wants the knob to bind needs a layer that actually compresses.
    let dir3 = tmpdir("nesteddepth3");
    let ex3 = Extractor::new(&dir3, 1, true);
    ex3.set_nested_max_depth(3);
    feed(&ex3, 0, "outer.rar", &outer, 7000, 12);
    let rep3 = ex3.finish().unwrap();
    assert!(rep3.fallbacks.is_empty(), "{:?}", rep3.fallbacks);
    assert_eq!(
        rep3.extracted,
        vec![("payload.bin".to_string(), data.len() as u64)]
    );
    assert_eq!(std::fs::read(dir3.join("payload.bin")).unwrap(), data);
    assert_eq!(dir_files(&dir3), vec!["payload.bin".to_string()]);
    std::fs::remove_dir_all(&dir3).unwrap();
}

/// The store exemption is REVOCABLE: a level that grants a child the
/// extra depth level a store-only archive buys does not get to keep it
/// once something at that level is seen to compress.
///
/// `Extractor::ensure_child` reads `saw_store && !saw_compressed`, and
/// both flags are latched in `chase.rs::rar_span` as headers PARSE. The
/// child is built the instant the first inner file routes, so that read
/// happens with the level's evidence still arriving: the compressed
/// entry behind the stored one, or the compressed archive beside the
/// store-only one, has not been seen yet. The child was built ONCE
/// (`inner.child.is_none()`), `enabled` had one read site and nothing
/// revoked it, and `nested_max_depth` on the child was never lowered -
/// so the raise survived the evidence that contradicted it. One such
/// level per layer ladders the cap up in step with the depth, all the
/// way to `NESTED_MAX_DEPTH_HARD_CEILING`: 64 live compressing levels
/// where the operator configured 5. The extract byte budget does not
/// cover this - it bounds BYTES, not levels, and every level is a real
/// extractor with real buffers.
///
/// The shape here is two archives at ONE level, which is what the
/// escalation actually needs, and it is an ordinary release layout
/// rather than a contrived one: `a.rar` stores its members, `b.rar`
/// compresses. A single MIXED volume latches the same way and cannot
/// be used to show it, because `try_attach_chase` refuses a mixed
/// store/compressed set outright (a "healthy group with mapped
/// (non-chased) members" demotes) - it still poisons the level's child
/// for every other group, which is the same defect, just not one an
/// on-disk assertion can see.
///
/// Fed in three parts, in order, and the order IS the case: enough of
/// `a.rar` to route `filler.bin` and build the child with the raise,
/// then all of `b.rar` so the compressed latch fires, then the rest of
/// `a.rar` so `inner.rar` routes into a child that should by then have
/// been switched off. Correct: `inner.rar` materializes whole.
/// Buggy: the child keeps the raise, classifies it as a store RAR and
/// `payload.bin` comes out instead.
///
/// `set_nested_max_depth(1)` makes the whole difference one layer wide,
/// and `anchor` is what lets the ROOT chase `b.rar` at all (the depth-0
/// chase worker reaches its extractor through `self_weak`, which only
/// an Arc-owned root has - `top_level_chase_gate_off_materializes`
/// builds it the same way).
#[test]
fn nested_store_raise_is_revoked_by_a_compressed_archive_at_the_same_level() {
    let payload_bytes = noisy(20_000, 7);
    let inner_rar = fixtures::rar5_volume(&[(
        "payload.bin",
        payload_bytes.len() as u64,
        &payload_bytes,
        false,
        false,
    )]);
    // Big enough that the feed can be cut in the middle of its data
    // area, which is where the child gets built.
    let filler = payload(300_000, 44);
    let a_rar = fixtures::rar5_volume(&[
        ("filler.bin", filler.len() as u64, &filler, false, false),
        (
            "inner.rar",
            inner_rar.len() as u64,
            &inner_rar,
            false,
            false,
        ),
    ]);
    let comp_bytes = noisy(60_000, 133);
    let b_rar = rars_compressed_volume(&[("comp.bin", &comp_bytes)]);
    assert_not_store(&b_rar);
    let cut = 100_000;
    assert!(
        cut < a_rar.len() - inner_rar.len(),
        "cut is past filler.bin"
    );

    let dir = tmpdir("nestedstorerevoke");
    let ex = Arc::new(Extractor::new(&dir, 2, true));
    ex.anchor();
    ex.set_nested_max_depth(1);
    let feed_range = |from: usize, to: usize| {
        for s in (from..to).step_by(7000) {
            let e = (s + 7000).min(to);
            ex.write(0, "a.rar", a_rar.len() as u64, s as u64, &a_rar[s..e])
                .unwrap();
        }
    };
    feed_range(0, cut);
    for s in (0..b_rar.len()).step_by(7000) {
        let e = (s + 7000).min(b_rar.len());
        ex.write(1, "b.rar", b_rar.len() as u64, s as u64, &b_rar[s..e])
            .unwrap();
    }
    feed_range(cut, a_rar.len());
    let rep = ex.finish().unwrap();

    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(
        dir_files(&dir),
        vec![
            "comp.bin".to_string(),
            "filler.bin".to_string(),
            "inner.rar".to_string(),
        ],
        "the compressed archive revoked the store raise, so nothing \
         below level 1 may be extracted"
    );
    // Not just the NAME: `inner.rar` has to be the archive itself,
    // whole, which is what materializing means here - a name check
    // alone passes on a truncated or empty file.
    assert_eq!(std::fs::read(dir.join("inner.rar")).unwrap(), inner_rar);
    assert_eq!(std::fs::read(dir.join("filler.bin")).unwrap(), filler);
    assert_eq!(std::fs::read(dir.join("comp.bin")).unwrap(), comp_bytes);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The bound on the store exemption: a store ladder deeper than
/// [`NESTED_MAX_DEPTH_HARD_CEILING`] materializes AT the ceiling.
///
/// `c0b1c788a` (31 Aug 2026) stopped charging stored layers against the
/// depth cap, because a stored layer cannot be a decompression bomb.
/// Its own comment says that is "right about the BOMB and would be
/// wrong as an open licence" - a store ladder a million levels deep
/// inflates no byte and still costs a real extractor, real buffers and
/// real scratch per level - and names the hard ceiling as the backstop
/// for that residue. NOTHING TESTED IT: `NESTED_MAX_DEPTH_HARD_CEILING`
/// was referenced only at its own clamp site in `extract/mod.rs`, so
/// the clamp could have been dropped, inverted or made unreachable and
/// every suite would have stayed green while the exemption became the
/// open licence that comment refuses. Written while un-redding the
/// three test jobs that same commit left red on
/// `nested_depth_cap_materializes` above.
///
/// The expected name is DERIVED from the constant rather than spelled
/// `L64.rar`, so raising or lowering the ceiling moves this test with
/// it instead of leaving a magic number that passes for the wrong
/// reason. Materializing is the whole point: it is never a hard
/// failure, so `fallbacks` must stay empty.
#[test]
fn nested_store_ladder_stops_at_the_hard_ceiling() {
    let data = payload(1_000, 91);
    let wrap = |name: &str, inner: &[u8]| {
        fixtures::rar5_volume(&[(name, inner.len() as u64, inner, false, false)])
    };
    // Deeper than the ceiling, so the clamp is the thing that stops it
    // and not the end of the ladder.
    let depth = NESTED_MAX_DEPTH_HARD_CEILING + 6;
    let mut cur = wrap("payload.bin", &data);
    let mut at_ceiling = Vec::new();
    for i in (1..=depth).rev() {
        if i == NESTED_MAX_DEPTH_HARD_CEILING {
            // The bytes that SHOULD be left on disk. Captured BEFORE the
            // wrap, not after: `wrap` returns the archive CONTAINING an
            // entry called `L64.rar`, while the file materialized under
            // that name is that entry's CONTENT - the ladder as it stood
            // one level down. Capturing after passes the name assertion
            // and fails the byte one by exactly a header.
            at_ceiling = cur.clone();
        }
        cur = wrap(&format!("L{i:02}.rar"), &cur);
    }
    let want = format!("L{NESTED_MAX_DEPTH_HARD_CEILING:02}.rar");

    let dir = tmpdir("nestedceil");
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "outer.rar", &cur, 7000, 12);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(dir_files(&dir), vec![want.clone()]);
    // Not just the NAME: the bytes left behind are the whole remaining
    // ladder, which is what "materializes" has to mean here - a name
    // check alone passes on a truncated or empty file.
    let got = std::fs::read(dir.join(&want)).unwrap();
    assert_eq!(got.len(), at_ceiling.len());
    assert_eq!(got, at_ceiling);
    assert_eq!(rep.extracted, vec![(want, at_ceiling.len() as u64)]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The rollout gates: NZBFAST_NO_NESTED_ONEPASS=1 turns routing off
/// at construction, and the runtime setter drives the same
/// `nested_on` flag. With routing off the level-1 archive
/// materializes exactly as before the nested path existed. The env
/// PARSE is asserted on the pure helper - actually setting the
/// process env here would flip the gate for every extractor other
/// tests construct in the window (process-global state under the
/// parallel runner), so the behavioral half runs through the setter,
/// which gates the very same routing decision.
#[test]
fn nested_disabled_by_env() {
    // Env latch parse: "1" disables, anything else leaves routing on.
    assert!(nested_env_off_value(Some("1")));
    assert!(!nested_env_off_value(Some("0")));
    assert!(!nested_env_off_value(None));
    let dir = tmpdir("nestedenv");
    let ex = Extractor::new(&dir, 1, true);
    assert!(ex.inner.lock().unwrap().nested_on, "gate must default on");
    ex.set_nested_one_pass(false);

    let data = payload(90_000, 86);
    let inner_arch =
        fixtures::rar5_volume(&[("movie.mkv", data.len() as u64, &data, false, false)]);
    let outer = fixtures::rar5_volume(&[(
        "inner.rar",
        inner_arch.len() as u64,
        &inner_arch,
        false,
        false,
    )]);
    feed(&ex, 0, "v.rar", &outer, 7000, 5);
    let rep = ex.finish().unwrap();
    assert_eq!(
        rep.extracted,
        vec![("inner.rar".to_string(), inner_arch.len() as u64)]
    );
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("inner.rar")).unwrap(), inner_arch);
    assert_eq!(dir_files(&dir), vec!["inner.rar".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();

    // Same behavior through the runtime setter (daemon rollout knob).
    let dir2 = tmpdir("nestedenv2");
    let ex2 = Extractor::new(&dir2, 1, true);
    ex2.set_nested_one_pass(false);
    feed(&ex2, 0, "v.rar", &outer, 7000, 6);
    let rep2 = ex2.finish().unwrap();
    assert_eq!(
        rep2.extracted,
        vec![("inner.rar".to_string(), inner_arch.len() as u64)]
    );
    assert_eq!(std::fs::read(dir2.join("inner.rar")).unwrap(), inner_arch);
    std::fs::remove_dir_all(&dir2).unwrap();
}

// -- nested one-pass phase 2: the chasing decompressor --

// -- nested one-pass: extreme shapes + depth memory accounting --

/// Every level of a 4-deep store chain carries a required sibling
/// data file next to the deeper archive: level k holds "docs_k.txt"
/// plus the level-(k+1) archive, the innermost holding the final
/// payload. All four siblings and the payload land byte-exact in the
/// output dir; no archive at ANY level and no volume ever touch
/// disk. Driven forward and reverse (offset 0 last: every level
/// classifies off drained holds).
#[test]
fn nested_mixed_payload_every_level() {
    let docs: Vec<Vec<u8>> = (0..4u8)
        .map(|k| payload(30_000 + k as usize * 1_000, 0xA0 + k))
        .collect();
    let final_pay = payload(200_000, 0xB1);
    let a3 = fixtures::rar5_volume(&[
        ("docs_3.txt", docs[3].len() as u64, &docs[3], false, false),
        (
            "payload.bin",
            final_pay.len() as u64,
            &final_pay,
            false,
            false,
        ),
    ]);
    let a2 = fixtures::rar5_volume(&[
        ("docs_2.txt", docs[2].len() as u64, &docs[2], false, false),
        ("a3.rar", a3.len() as u64, &a3, false, false),
    ]);
    let a1 = fixtures::rar5_volume(&[
        ("docs_1.txt", docs[1].len() as u64, &docs[1], false, false),
        ("a2.rar", a2.len() as u64, &a2, false, false),
    ]);
    let outer = fixtures::rar5_volume(&[
        ("docs_0.txt", docs[0].len() as u64, &docs[0], false, false),
        ("a1.rar", a1.len() as u64, &a1, false, false),
    ]);
    let want: Vec<(String, u64)> = vec![
        ("docs_0.txt".to_string(), docs[0].len() as u64),
        ("docs_1.txt".to_string(), docs[1].len() as u64),
        ("docs_2.txt".to_string(), docs[2].len() as u64),
        ("docs_3.txt".to_string(), docs[3].len() as u64),
        ("payload.bin".to_string(), final_pay.len() as u64),
    ];
    for rev in [false, true] {
        let dir = tmpdir(&format!("nestedmix{}", rev as u8));
        let ex = Extractor::new(&dir, 1, true);
        let art = 7000usize;
        let n_arts = outer.len().div_ceil(art);
        let order: Vec<usize> = if rev {
            (0..n_arts).rev().collect()
        } else {
            (0..n_arts).collect()
        };
        for i in order {
            let s = i * art;
            let e = (s + art).min(outer.len());
            ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..e])
                .unwrap();
        }
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "rev={rev}: {:?}", rep.fallbacks);
        assert_eq!(rep.extracted, want, "rev={rev}");
        for (k, d) in docs.iter().enumerate() {
            assert_eq!(
                &std::fs::read(dir.join(format!("docs_{k}.txt"))).unwrap(),
                d,
                "rev={rev} docs_{k}"
            );
        }
        assert_eq!(
            std::fs::read(dir.join("payload.bin")).unwrap(),
            final_pay,
            "rev={rev}"
        );
        assert_eq!(
            dir_files(&dir),
            vec![
                "docs_0.txt".to_string(),
                "docs_1.txt".to_string(),
                "docs_2.txt".to_string(),
                "docs_3.txt".to_string(),
                "payload.bin".to_string(),
            ],
            "rev={rev}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// Same shape with the level-3 archive COMPRESSED (the chase engages
/// at depth): it carries its own sibling plus a STORE archive whose
/// payload keeps streaming below the chase. Store-level siblings,
/// the chased sibling, and the deepest payload all land byte-exact;
/// no archive at any level materializes.
#[test]
fn nested_mixed_payload_chase_at_depth() {
    let docs: Vec<Vec<u8>> = (0..4u8)
        .map(|k| payload(28_000 + k as usize * 1_000, 0x60 + k))
        .collect();
    let g = payload(150_000, 0x71);
    let deep = fixtures::rar5_volume(&[("G.bin", g.len() as u64, &g, false, false)]);
    let a3 = rars_compressed_volume(&[("docs_3.txt", &docs[3]), ("deep.rar", &deep)]);
    assert_not_store(&a3);
    let a2 = fixtures::rar5_volume(&[
        ("docs_2.txt", docs[2].len() as u64, &docs[2], false, false),
        ("a3.rar", a3.len() as u64, &a3, false, false),
    ]);
    let a1 = fixtures::rar5_volume(&[
        ("docs_1.txt", docs[1].len() as u64, &docs[1], false, false),
        ("a2.rar", a2.len() as u64, &a2, false, false),
    ]);
    let outer = fixtures::rar5_volume(&[
        ("docs_0.txt", docs[0].len() as u64, &docs[0], false, false),
        ("a1.rar", a1.len() as u64, &a1, false, false),
    ]);
    let dir = tmpdir("nestedmixchase");
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "v.rar", &outer, 7000, 17);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    for (k, d) in docs.iter().enumerate() {
        assert_eq!(
            &std::fs::read(dir.join(format!("docs_{k}.txt"))).unwrap(),
            d,
            "docs_{k}"
        );
    }
    assert_eq!(std::fs::read(dir.join("G.bin")).unwrap(), g);
    assert_eq!(
        dir_files(&dir),
        vec![
            "G.bin".to_string(),
            "docs_0.txt".to_string(),
            "docs_1.txt".to_string(),
            "docs_2.txt".to_string(),
            "docs_3.txt".to_string(),
        ]
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// One nested level fanning WIDE: a level-1 archive split across
/// three outer volumes carries EIGHT sibling files around one deeper
/// archive - the out_names/name-claim machinery holds up with many
/// concurrent child slots at depth. Two volume feed orders.
#[test]
fn nested_many_siblings_wide() {
    let sibs: Vec<Vec<u8>> = (0..8u8)
        .map(|i| payload(40_000 + i as usize * 3_000, 0xC0 + i))
        .collect();
    let names: Vec<String> = (0..8).map(|i| format!("sib_{i}.dat")).collect();
    let fpay = payload(180_000, 0xD5);
    let deep = fixtures::rar5_volume(&[("final.bin", fpay.len() as u64, &fpay, false, false)]);
    let mut entries: Vec<(&str, u64, &[u8], bool, bool)> = Vec::new();
    for i in 0..4 {
        entries.push((
            names[i].as_str(),
            sibs[i].len() as u64,
            &sibs[i],
            false,
            false,
        ));
    }
    entries.push(("deep.rar", deep.len() as u64, &deep, false, false));
    for i in 4..8 {
        entries.push((
            names[i].as_str(),
            sibs[i].len() as u64,
            &sibs[i],
            false,
            false,
        ));
    }
    let inner1 = fixtures::rar5_volume(&entries);
    let n = inner1.len();
    let (c1, c2) = (n / 3, 2 * n / 3);
    let vols: Vec<Vec<u8>> = vec![
        fixtures::rar5_volume_n(&[("inner1.rar", n as u64, &inner1[..c1], false, true)], 0),
        fixtures::rar5_volume_n(&[("inner1.rar", n as u64, &inner1[c1..c2], true, true)], 1),
        fixtures::rar5_volume_n(&[("inner1.rar", n as u64, &inner1[c2..], true, false)], 2),
    ];
    for (t, order) in [[0usize, 1, 2], [2, 0, 1]].iter().enumerate() {
        let dir = tmpdir(&format!("nestedwide{t}"));
        let ex = Extractor::new(&dir, 3, true);
        for &vi in order {
            feed(
                &ex,
                vi,
                &format!("w{vi}.bin"),
                &vols[vi],
                8000,
                120 + vi as u64,
            );
        }
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks.is_empty(),
            "order {order:?}: {:?}",
            rep.fallbacks
        );
        for (i, s) in sibs.iter().enumerate() {
            assert_eq!(
                &std::fs::read(dir.join(&names[i])).unwrap(),
                s,
                "order {order:?} sib {i}"
            );
        }
        assert_eq!(
            std::fs::read(dir.join("final.bin")).unwrap(),
            fpay,
            "order {order:?}"
        );
        let mut want = names.clone();
        want.push("final.bin".to_string());
        want.sort();
        assert_eq!(dir_files(&dir), want, "order {order:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// Depth memory accounting: an 8 MB payload wrapped 1..5 store
/// levels deep, fed in order - the chain-wide HoldsBudget peak must
/// stay far under the cap and must NOT grow with depth (each level
/// is an offset remap, not a buffered copy). A chased compressed
/// inner at the same scale reports alongside: its frontier retention
/// charges the same budget and stays bounded by it, not by the
/// archive size.
#[test]
fn nested_depth_holds_peak_bounded() {
    let data = payload(8 << 20, 0x55);
    let art = 65_536usize;
    let mut rows: Vec<(String, usize)> = Vec::new();
    let mut store_peaks: Vec<usize> = Vec::new();
    for depth in 1..=5usize {
        let mut cur =
            fixtures::rar5_volume(&[("payload.bin", data.len() as u64, &data, false, false)]);
        for k in (1..depth).rev() {
            let name = format!("a{k}.rar");
            cur = fixtures::rar5_volume(&[(name.as_str(), cur.len() as u64, &cur, false, false)]);
        }
        // In-order (the honest-post shape) and shuffled (out-of-order
        // arrival forces real held spans at every level).
        for shuffled in [false, true] {
            let dir = tmpdir(&format!("nestedmem{depth}{}", shuffled as u8));
            let ex = Extractor::new(&dir, 1, true);
            if shuffled {
                feed(&ex, 0, "outer.rar", &cur, art, 200 + depth as u64);
            } else {
                for (i, chunk) in cur.chunks(art).enumerate() {
                    ex.write(0, "outer.rar", cur.len() as u64, (i * art) as u64, chunk)
                        .unwrap();
                }
            }
            let rep = ex.finish().unwrap();
            assert!(
                rep.fallbacks.is_empty(),
                "depth {depth}: {:?}",
                rep.fallbacks
            );
            assert_eq!(
                std::fs::read(dir.join("payload.bin")).unwrap(),
                data,
                "depth {depth}"
            );
            let peak = ex.holds_peak();
            if shuffled {
                store_peaks.push(peak);
                rows.push((format!("store x{depth} shuf"), peak));
            } else {
                rows.push((format!("store x{depth} seq"), peak));
            }
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }
    // Chased compressed inner at the same scale (~8 MB unpacked,
    // half-entropy input keeps the packed stream near half size).
    {
        let f = noisy(8 << 20, 0x99);
        let inner_arch = rars_compressed_volume(&[("F.bin", &f)]);
        assert_not_store(&inner_arch);
        let outer = fixtures::rar5_volume(&[(
            "inner.rar",
            inner_arch.len() as u64,
            &inner_arch,
            false,
            false,
        )]);
        let dir = tmpdir("nestedmemchase");
        let ex = Extractor::new(&dir, 1, true);
        for (i, chunk) in outer.chunks(art).enumerate() {
            ex.write(0, "outer.rar", outer.len() as u64, (i * art) as u64, chunk)
                .unwrap();
        }
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
        rows.push(("chase 8 MB".to_string(), ex.holds_peak()));
        std::fs::remove_dir_all(&dir).unwrap();
    }
    println!("shape          holds_peak (bytes)");
    for (tag, p) in &rows {
        println!("{tag:<14} {p:>10}");
    }
    for (tag, p) in &rows {
        assert!(*p < 64 << 20, "{tag}: holds peak {p} breaches 64 MB");
    }
    // Not linear in depth: five levels must not retain per-level
    // copies (linear scaling would add ~8 MB of held payload per
    // extra level; the allowance covers shuffle variance only).
    assert!(
        store_peaks[4] <= store_peaks[0] + (2 << 20),
        "peak grows with depth: {store_peaks:?}"
    );
}

// -- nested one-pass phase 3: 7z inner archives via tail prefetch --

// -- TODO 37 step 1: the SAME chase, one level up (posted .7z) --

// -- one-pass zip (phase 2): the SAME chase, zip parser --

// -- one-pass zip, byte-split `.zip.001` sets --

// -- TODO 37 step 3: `.7z.001` split sets --

// -- TODO 37 step 2: drop-behind trimming --
