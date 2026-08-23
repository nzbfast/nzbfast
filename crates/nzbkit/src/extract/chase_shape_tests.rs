//! The chase suite's shape-and-volume half, split off `chase_tests.rs`
//! whole (TODO 106 size gate) - the code is verbatim, only this header
//! and one visibility keyword are new. `chase_tests.rs` was sitting
//! EXACTLY on the 3,000-line file ceiling on 23 Aug 2026 (the gate
//! counts 3,000 where `wc -l` says 2,999, because it splits on "\n"
//! over newline-terminated text), so the next test anyone added to the
//! file every chase lane adds tests to would have reddened main for
//! everyone.
//!
//! What lives here rather than beside the engine tests: the coverage
//! that asks WHICH archive shapes and entry points chase at all and
//! still finish byte-exact - multi-volume, RAR4, encrypted and
//! header-encrypted inners, the top-level chase, the mapped-repair
//! re-entry at multi-volume scale, the store layer below a chase sink,
//! the env gate and the worker's exit on drop - plus the TODO 220 / 250
//! group about the volume itself: the incremental header walk, decoding
//! a volume whose tail has not arrived, and surviving a trim of the
//! volume the deferred walk resumes in. `chase_tests.rs` keeps the
//! engine's dynamics: gating, frontier gaps, the holds budget, the
//! drop-behind trim, paging and the resume ledger.
//!
//! Same shape as the sibling it came from: a `#[path]` child of
//! `chase.rs`, so `super::*` still reaches everything the one file
//! reached. `chase_decodes_a_volume_before_its_tail_arrives` came
//! across with its TODO 220 group and is still a case of
//! `chase_volume_set_cases` over in `chase_tests` - it is `pub(in
//! crate::extract)` for that call and for no other reason. The fusion
//! it belongs to is unharmed by the module boundary: `chase_volume_set`
//! is a `OnceLock` behind a function, and a function-local static is one
//! object in the binary however many modules call it, so the one process
//! that runs the fused test still builds the 5 MiB compressed set once.
//! Verified rather than assumed, by counting builds and not the clock: an
//! `eprintln!` in the `get_or_init` printed exactly ONCE in the fused
//! test's process after the split (temporary, reverted). The clock could
//! not have answered it that day - this box was at load average 140 with
//! nine sessions compiling, and the fused test measured 56.2 s before the
//! split and then 94.6 s and 132.4 s after it, the last two off the SAME
//! post-split binary. A 40% spread with nothing changing between the runs
//! is what a loaded box reads like. Its CPU time barely
//! moves, because the cases spend their wall time asleep on watermark
//! polls; a second fixture build would have cost about 19 CPU-seconds and
//! shown up there, not in the wall figure.

use super::*;
use crate::rar::fixtures;

use crate::extract::testutil::*;

use super::chase_tests::chase_volume_set;

/// A compressed member split across FOUR inner volumes, all wrapped
/// in one store outer: the sequence driver pulls volume k+1 only
/// after k, split read-back reaches retained earlier volumes, and
/// the final payload lands byte-exact with nothing else on disk.
#[test]
fn chase_multi_volume_compressed_inner() {
    let f = noisy(300_000, 98);
    let vols = rars_compressed_volumes("F.bin", &f, 50_000);
    assert!(
        vols.len() >= 3,
        "want a real multi-volume set, got {}",
        vols.len()
    );
    for v in &vols {
        assert_not_store(v);
    }
    let pieces: Vec<(String, &Vec<u8>)> = vols
        .iter()
        .enumerate()
        .map(|(i, v)| (format!("inner.part{}.rar", i + 1), v))
        .collect();
    let outer_entries: Vec<(&str, u64, &[u8], bool, bool)> = pieces
        .iter()
        .map(|(n, v)| (n.as_str(), v.len() as u64, v.as_slice(), false, false))
        .collect();
    let outer = fixtures::rar5_volume(&outer_entries);
    // Two feed orders: forward and reverse (later inner volumes'
    // buffers register before the chase can use them).
    for (t, rev) in [false, true].iter().enumerate() {
        let dir = tmpdir(&format!("chase-mv{t}"));
        let ex = Extractor::new(&dir, 1, true);
        let art = 7000usize;
        let n_arts = outer.len().div_ceil(art);
        let order: Vec<usize> = if *rev {
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
        assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f, "rev={rev}");
        assert_eq!(dir_files(&dir), vec!["F.bin".to_string()], "rev={rev}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// A store outer wrapping a COMPRESSED RAR4 (RAR 2.9/3.x) inner: the
/// chase engages through the `rar15_40` engine, the payload lands
/// byte-identical, and neither the outer volume nor the inner archive
/// ever exists on disk.
#[test]
fn chase_compressed_rar4_inner_one_pass() {
    let dir = tmpdir("chase-v4");
    let f = payload(300_000, 191);
    let inner_arch = rars_v4_compressed_volume(&[("F.bin", &f)]);
    assert_not_store(&inner_arch);
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
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
    assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A compressed RAR4 member split across volumes, both naming
/// schemes: `.partNN.rar` (1-based, shifts down) and old-style
/// `.rar`/`.r00`/`.r01` (already 0-based) - the volume index comes
/// from the NAME for RAR4, so both must sequence correctly, forward
/// and reverse arrival.
#[test]
fn chase_multi_volume_compressed_rar4_inner() {
    let f = noisy(300_000, 198);
    let vols = rars_v4_compressed_volumes("F.bin", &f, 50_000);
    assert!(
        vols.len() >= 3,
        "want a real multi-volume set, got {}",
        vols.len()
    );
    for v in &vols {
        assert_not_store(v);
    }
    let naming: [Box<dyn Fn(usize) -> String>; 2] = [
        Box::new(|i| format!("inner.part{}.rar", i + 1)),
        Box::new(|i| {
            if i == 0 {
                "inner.rar".to_string()
            } else {
                format!("inner.r{:02}", i - 1)
            }
        }),
    ];
    for (scheme, name_of) in naming.iter().enumerate() {
        let pieces: Vec<(String, &Vec<u8>)> = vols
            .iter()
            .enumerate()
            .map(|(i, v)| (name_of(i), v))
            .collect();
        let outer_entries: Vec<(&str, u64, &[u8], bool, bool)> = pieces
            .iter()
            .map(|(n, v)| (n.as_str(), v.len() as u64, v.as_slice(), false, false))
            .collect();
        let outer = fixtures::rar5_volume(&outer_entries);
        for (t, rev) in [false, true].iter().enumerate() {
            let dir = tmpdir(&format!("chase-v4mv{scheme}{t}"));
            let ex = Extractor::new(&dir, 1, true);
            let art = 7000usize;
            let n_arts = outer.len().div_ceil(art);
            let order: Vec<usize> = if *rev {
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
            assert!(
                rep.fallbacks.is_empty(),
                "scheme={scheme} rev={rev}: {:?}",
                rep.fallbacks
            );
            assert_eq!(
                std::fs::read(dir.join("F.bin")).unwrap(),
                f,
                "scheme={scheme} rev={rev}"
            );
            assert_eq!(
                dir_files(&dir),
                vec!["F.bin".to_string()],
                "scheme={scheme} rev={rev}"
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }
}

/// Encrypted (-p) compressed RAR4, split across volumes: the chase
/// decrypts through the rar15_40 engine's own sequential cipher (a
/// salt per member, key derived once per member on the WORKER thread,
/// never in the mapper - the §RAR4 KDF-DoS rule), payload byte-exact,
/// one pass.
#[test]
fn chase_encrypted_compressed_rar4_inner_one_pass() {
    let f = noisy(300_000, 199);
    let vols = rars_v4_encrypted_volumes("F.bin", &f, 60_000, "chasepw", false);
    assert!(vols.len() >= 2, "want a split set, got {}", vols.len());
    for v in &vols {
        assert_not_store(v);
    }
    let pieces: Vec<(String, &Vec<u8>)> = vols
        .iter()
        .enumerate()
        .map(|(i, v)| (format!("inner.part{}.rar", i + 1), v))
        .collect();
    let outer_entries: Vec<(&str, u64, &[u8], bool, bool)> = pieces
        .iter()
        .map(|(n, v)| (n.as_str(), v.len() as u64, v.as_slice(), false, false))
        .collect();
    let outer = fixtures::rar5_volume(&outer_entries);
    let dir = tmpdir("chase-v4enc");
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("chasepw");
    feed(&ex, 0, "v.rar", &outer, 7000, 13);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
    assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The -hp shape: RAR4 with ENCRYPTED HEADERS. The mapper needs the
/// password to enumerate entries at all; past that the chase drives
/// the same engine (parse_stream decrypts headers per block).
#[test]
fn chase_header_encrypted_compressed_rar4_inner() {
    let f = noisy(200_000, 201);
    let vols = rars_v4_encrypted_volumes("F.bin", &f, 80_000, "hppw", true);
    // A password-less mapper must see nothing but EncryptedHeaders -
    // that both proves the -hp shape and stands in for
    // assert_not_store, which cannot read a method byte it cannot
    // decrypt.
    for v in &vols {
        let mut m = crate::rar::VolumeMapper::new(v.len() as u64);
        m.feed(0, v);
        assert_eq!(m.blocker, Some(crate::rar::MapBlocker::EncryptedHeaders));
    }
    let pieces: Vec<(String, &Vec<u8>)> = vols
        .iter()
        .enumerate()
        .map(|(i, v)| (format!("inner.part{}.rar", i + 1), v))
        .collect();
    let outer_entries: Vec<(&str, u64, &[u8], bool, bool)> = pieces
        .iter()
        .map(|(n, v)| (n.as_str(), v.len() as u64, v.as_slice(), false, false))
        .collect();
    let outer = fixtures::rar5_volume(&outer_entries);
    let dir = tmpdir("chase-v4hp");
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("hppw");
    feed(&ex, 0, "v.rar", &outer, 7000, 17);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
    assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Encrypted RAR4 with NO password available: the chase must not
/// attach (nothing can decode anywhere) - the set demotes to
/// byte-exact materialized volumes, today's output.
#[test]
fn chase_encrypted_rar4_without_password_demotes() {
    let f = noisy(120_000, 203);
    let vol = rars_v4_encrypted_volume("F.bin", &f, "nopw");
    let outer =
        fixtures::rar5_volume(&[("inner.rar", vol.len() as u64, vol.as_slice(), false, false)]);
    let dir = tmpdir("chase-v4enc-nopw");
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "v.rar", &outer, 5000, 19);
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks
            .iter()
            .any(|(_, w)| w.starts_with("nested fallback:")),
        "{:?}",
        rep.fallbacks
    );
    assert_eq!(std::fs::read(dir.join("inner.rar")).unwrap(), vol);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// TOP-LEVEL chase (the RAR analogue of TODO 37 step 1): a POSTED
/// compressed RAR5 - no store wrapper - chases at depth 0, its
/// payload promotes to the root output, and neither the volume nor
/// any intermediate archive ever exists on disk. Three arrival
/// orders, mirroring the 7z twin.
#[test]
fn top_level_compressed_rar_chases_one_pass() {
    let f = payload(300_000, 131);
    let arch = rars_compressed_volume(&[("F.bin", &f)]);
    assert_not_store(&arch);
    let art = 7000usize;
    let n_arts = arch.len().div_ceil(art);
    let orders: Vec<Vec<usize>> = vec![
        (0..n_arts).collect(),
        (0..n_arts).rev().collect(),
        (0..n_arts).map(|i| (i * 7 + 3) % n_arts).collect(),
    ];
    for (t, order) in orders.iter().enumerate() {
        let dir = tmpdir(&format!("rar-top-onepass{t}"));
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        let mut seen = vec![false; n_arts];
        for &i in order {
            if std::mem::replace(&mut seen[i], true) {
                continue;
            }
            let s = i * art;
            let e = (s + art).min(arch.len());
            ex.write(0, "release.rar", arch.len() as u64, s as u64, &arch[s..e])
                .unwrap();
        }
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "order {t}: {:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f, "order {t}");
        assert_eq!(dir_files(&dir), vec!["F.bin".to_string()], "order {t}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// The multi-volume shape at depth 0: each volume of a posted
/// compressed set is its own top-level file (own slot, own name),
/// registering with the group's chase at its header volume number.
/// Forward and reverse volume-arrival orders.
#[test]
fn top_level_compressed_rar_multivolume_chases_one_pass() {
    let f = noisy(300_000, 132);
    let vols = rars_compressed_volumes("F.bin", &f, 50_000);
    assert!(
        vols.len() >= 3,
        "want a real multi-volume set, got {}",
        vols.len()
    );
    for v in &vols {
        assert_not_store(v);
    }
    for (t, rev) in [false, true].iter().enumerate() {
        let dir = tmpdir(&format!("rar-top-mv{t}"));
        let ex = Arc::new(Extractor::new(&dir, vols.len(), true));
        ex.anchor();
        let order: Vec<usize> = if *rev {
            (0..vols.len()).rev().collect()
        } else {
            (0..vols.len()).collect()
        };
        for &vi in &order {
            feed(
                &ex,
                vi,
                &format!("release.part{}.rar", vi + 1),
                &vols[vi],
                7000,
                33 + vi as u64,
            );
        }
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "rev={rev}: {:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f, "rev={rev}");
        assert_eq!(dir_files(&dir), vec!["F.bin".to_string()], "rev={rev}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// The kill switch restores the pre-lift behaviour exactly: gate
/// off, a posted compressed RAR materializes byte-exact with the
/// NotStore demote reason and no partial output. Also pins the env
/// parse ("1" and nothing else).
#[test]
fn top_level_chase_gate_off_materializes() {
    assert!(top_chase_env_off_value(Some("1")));
    assert!(!top_chase_env_off_value(Some("0")));
    assert!(!top_chase_env_off_value(None));
    let f = noisy(300_000, 133);
    let arch = rars_compressed_volume(&[("F.bin", &f)]);
    assert_not_store(&arch);
    let dir = tmpdir("rar-top-gateoff");
    let ex = Arc::new(Extractor::new(&dir, 1, true));
    ex.anchor();
    ex.set_top_level_chase(false);
    feed(&ex, 0, "release.rar", &arch, 7000, 34);
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks
            .iter()
            .any(|(_, w)| w.contains("compressed or encrypted entries")),
        "{:?}",
        rep.fallbacks
    );
    assert_eq!(std::fs::read(dir.join("release.rar")).unwrap(), arch);
    assert!(!dir.join("F.bin").exists(), "gate off must not stream");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A depth-0 chase over the holds cap demotes cleanly: the volume
/// materializes COMPLETE for the unrar ladder (whose "held-bytes
/// cap" keying the reason carries), and no partial payload survives.
/// This is the pre-lift exit path, reached through the chase.
#[test]
fn top_level_chase_budget_breach_demotes_to_volume() {
    let f = noisy(2_400_000, 134);
    let arch = rars_compressed_volume(&[("F.bin", &f)]);
    assert_not_store(&arch);
    assert!(arch.len() > 900_000, "packed too small: {}", arch.len());
    let dir = tmpdir("rar-top-budget");
    let ex = Arc::new(Extractor::new(&dir, 3, true));
    ex.anchor();
    ex.set_holds_cap(1); // floors at 8 MB
    let junk = payload(65_000, 135);
    for slot in [1usize, 2] {
        for i in 0..60u64 {
            ex.write(
                slot,
                &format!("dummy{slot}.bin"),
                8_000_000,
                64_000 + i * 65_000,
                &junk,
            )
            .unwrap();
        }
    }
    for (i, chunk) in arch.chunks(50_000).enumerate() {
        ex.write(
            0,
            "release.rar",
            arch.len() as u64,
            (i * 50_000) as u64,
            chunk,
        )
        .unwrap();
    }
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks
            .iter()
            .any(|(_, w)| w.contains("held-bytes cap: chase memory")),
        "{:?}",
        rep.fallbacks
    );
    assert_eq!(std::fs::read(dir.join("release.rar")).unwrap(), arch);
    assert_resume_ledger_honest(&dir, "F.bin", &rep, &f);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Encrypted + compressed at depth 0: with the password set the
/// chase attaches (the gate admits an encrypted compressed entry
/// when `inner.password` is some) and the worker decrypts through
/// `rar_read_options` - byte-exact payload, no volume on disk.
/// Without a password the same set must demote and materialize:
/// nothing can decode it anywhere, and a partial output would be
/// garbage. First test of the chase's decrypt path at ANY depth.
#[test]
fn top_level_encrypted_compressed_rar_chases_one_pass() {
    use rars::rar50::{EncryptedCompressedEntry, Rar50VolumeWriter, WriterOptions};
    let f = noisy(300_000, 137);
    let mut features = rars::FeatureSet::store_only();
    features.file_encryption = true;
    let opts = WriterOptions::new(rars::ArchiveVersion::Rar50, features);
    let vols = Rar50VolumeWriter::new(opts)
        .encrypted_compressed_entries(&[EncryptedCompressedEntry {
            name: b"F.bin",
            data: &f,
            mtime: None,
            attributes: 0,
            host_os: 0,
            password: b"hunter2",
        }])
        .max_payload_per_volume(50_000)
        .finish()
        .unwrap();
    assert!(
        vols.len() >= 3,
        "want a real multi-volume set, got {}",
        vols.len()
    );
    for v in &vols {
        assert_not_store(v);
    }
    // Password in hand: one-pass.
    let dir = tmpdir("rar-top-enccomp");
    let ex = Arc::new(Extractor::new(&dir, vols.len(), true));
    ex.anchor();
    ex.set_password("hunter2");
    for (vi, vol) in vols.iter().enumerate() {
        feed(
            &ex,
            vi,
            &format!("release.part{}.rar", vi + 1),
            vol,
            7000,
            60 + vi as u64,
        );
    }
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
    assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
    // No password: demote, volumes materialize byte-exact.
    let dir = tmpdir("rar-top-enccomp-nopw");
    let ex = Arc::new(Extractor::new(&dir, vols.len(), true));
    ex.anchor();
    for (vi, vol) in vols.iter().enumerate() {
        feed(
            &ex,
            vi,
            &format!("release.part{}.rar", vi + 1),
            vol,
            7000,
            70 + vi as u64,
        );
    }
    let rep = ex.finish().unwrap();
    assert!(!rep.fallbacks.is_empty(), "no-password set must demote");
    for (vi, vol) in vols.iter().enumerate() {
        assert_eq!(
            std::fs::read(dir.join(format!("release.part{}.rar", vi + 1))).unwrap(),
            *vol,
            "volume {vi} must materialize byte-exact"
        );
    }
    assert!(!dir.join("F.bin").exists(), "no partial decrypt output");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A resumed run never chases at the top level (twin of the 7z
/// pin): the disabled extractor materializes the volume untouched
/// for the disk path.
#[test]
fn top_level_chase_never_runs_on_a_resumed_run() {
    let f = noisy(200_000, 136);
    let arch = rars_compressed_volume(&[("F.bin", &f)]);
    assert_not_store(&arch);
    let dir = tmpdir("rar-top-resume");
    let ex = Arc::new(Extractor::with_resume(&dir, 1, false, true));
    ex.anchor();
    feed(&ex, 0, "release.rar", &arch, 7000, 55);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("release.rar")).unwrap(), arch);
    assert_eq!(dir_files(&dir), vec!["release.rar".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Chase + repair at multi-volume scale (the multi-volume extension
/// of `chase_unblocks_on_patched_volume_span`): a compressed member
/// split across 3+ inner volumes, wrapped in a TWO-volume store
/// outer with an inner volume file spanning the outer boundary. One
/// article is lost inside the packed stream of EACH outer volume;
/// everything else arrives, then both holes are patched via
/// patch_volume_span (the mapped-repair re-entry path). The blocked
/// chase must resume through both fills and complete byte-exact,
/// with neither an outer volume nor an inner archive on disk.
#[test]
fn chase_multi_volume_patched_spans_complete() {
    let dir = tmpdir("chase-mv-patch");
    let f = noisy(300_000, 101);
    let vols = rars_compressed_volumes("F.bin", &f, 50_000);
    assert!(
        vols.len() >= 3,
        "want a real multi-volume set, got {}",
        vols.len()
    );
    for v in &vols {
        assert_not_store(v);
    }
    // Outer vol 1: inner.part1.rar whole + the head of inner.part2.rar;
    // outer vol 2: the rest of inner.part2.rar + the remaining volumes.
    let cut = vols[1].len() / 2;
    let names: Vec<String> = (1..=vols.len())
        .map(|i| format!("inner.part{i}.rar"))
        .collect();
    let o1_entries: Vec<(&str, u64, &[u8], bool, bool)> = vec![
        (
            names[0].as_str(),
            vols[0].len() as u64,
            &vols[0][..],
            false,
            false,
        ),
        (
            names[1].as_str(),
            vols[1].len() as u64,
            &vols[1][..cut],
            false,
            true,
        ),
    ];
    let mut o2_entries: Vec<(&str, u64, &[u8], bool, bool)> = vec![(
        names[1].as_str(),
        vols[1].len() as u64,
        &vols[1][cut..],
        true,
        false,
    )];
    for (i, v) in vols.iter().enumerate().skip(2) {
        o2_entries.push((names[i].as_str(), v.len() as u64, v, false, false));
    }
    let outers = [
        fixtures::rar5_volume_n(&o1_entries, 0),
        fixtures::rar5_volume_n(&o2_entries, 1),
    ];
    // Lose one article deep inside each outer volume's first data
    // area - packed LZ bitstream bytes, not envelope.
    let art = 1000usize;
    let lost: Vec<usize> = outers
        .iter()
        .map(|o| {
            let mut m = VolumeMapper::new(o.len() as u64);
            m.feed(0, o);
            let e = &m.entries[0];
            ((e.data_off + e.data_len / 2) / art as u64) as usize
        })
        .collect();
    let ex = Extractor::new(&dir, 2, true);
    for (si, o) in outers.iter().enumerate() {
        for i in 0..o.len().div_ceil(art) {
            if i == lost[si] {
                continue;
            }
            let s = i * art;
            let e = (s + art).min(o.len());
            ex.write(
                si,
                &format!("o.part{}.rar", si + 1),
                o.len() as u64,
                s as u64,
                &o[s..e],
            )
            .unwrap();
        }
    }
    // "Repair" both holes - rebuilt blocks re-enter through the
    // normal patch path, exactly as mapped PAR2 repair delivers them.
    for (si, o) in outers.iter().enumerate() {
        let (s, e) = (lost[si] * art, ((lost[si] + 1) * art).min(o.len()));
        assert!(
            !ex.covered(si, s as u64, e - s),
            "vol {si} hole really is a hole"
        );
        ex.patch_volume_span(si, s as u64, &o[s..e]).unwrap();
    }
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
    assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The chase SINK is the routing seam (n-deep): a compressed layer
/// wrapping a STORE archive - the chase's decompressed output routes
/// into a child slot, sniffs as RAR, and the store layer below keeps
/// streaming. Only the innermost payload ever touches disk.
#[test]
fn chase_output_store_archive_streams_below() {
    let dir = tmpdir("chase-deep");
    let g = payload(120_000, 99);
    let deep = fixtures::rar5_volume(&[("G.bin", 120_000, &g, false, false)]);
    let inner_arch = rars_compressed_volume(&[("deep.rar", &deep)]);
    assert_not_store(&inner_arch);
    let outer = fixtures::rar5_volume(&[(
        "inner.rar",
        inner_arch.len() as u64,
        &inner_arch,
        false,
        false,
    )]);
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "v.rar", &outer, 7000, 13);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("G.bin")).unwrap(), g);
    // No outer volume, no compressed archive, no store archive.
    assert_eq!(dir_files(&dir), vec!["G.bin".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The chase gates: NZBFAST_NO_NESTED_CHASE=1 parses as off, and the
/// runtime setter drives the same latch - with it off, a compressed
/// inner demotes to a materialized file exactly as before the chase
/// existed (nested routing itself stays on). The env PARSE is
/// asserted on the pure helper for the same parallel-runner reason
/// as `nested_disabled_by_env`.
#[test]
fn chase_disabled_by_env() {
    assert!(chase_env_off_value(Some("1")));
    assert!(!chase_env_off_value(Some("0")));
    assert!(!chase_env_off_value(None));

    let dir = tmpdir("chase-env");
    let f = payload(200_000, 90);
    let inner_arch = rars_compressed_volume(&[("F.bin", &f)]);
    assert_not_store(&inner_arch);
    let outer = fixtures::rar5_volume(&[(
        "inner.rar",
        inner_arch.len() as u64,
        &inner_arch,
        false,
        false,
    )]);
    let ex = Extractor::new(&dir, 1, true);
    assert!(ex.inner.lock().unwrap().chase_on, "gate must default on");
    ex.set_nested_chase(false);
    feed(&ex, 0, "v.rar", &outer, 7000, 15);
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks
            .iter()
            .any(|(_, w)| w.starts_with("nested fallback:")),
        "{:?}",
        rep.fallbacks
    );
    assert_eq!(std::fs::read(dir.join("inner.rar")).unwrap(), inner_arch);
    assert!(!dir.join("F.bin").exists());
    assert_eq!(dir_files(&dir), vec!["inner.rar".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Cancel semantics: dropping an extractor mid-chase (job abandoned)
/// aborts the chase buffers and the worker exits - the drop returns
/// instead of hanging on a frontier that will never fill.
#[test]
fn chase_worker_exits_on_extractor_drop() {
    let dir = tmpdir("chase-drop");
    let f = noisy(300_000, 89);
    let inner_arch = rars_compressed_volume(&[("F.bin", &f)]);
    assert_not_store(&inner_arch);
    let outer = fixtures::rar5_volume(&[(
        "inner.rar",
        inner_arch.len() as u64,
        &inner_arch,
        false,
        false,
    )]);
    let ex = Extractor::new(&dir, 1, true);
    // Just enough for the chase to attach and its worker to block at
    // the frontier - then abandon the job.
    ex.write(0, "v.rar", outer.len() as u64, 0, &outer[..4000])
        .unwrap();
    drop(ex);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// TODO 220: the engine must be decoding a volume that is STILL
/// ARRIVING, not waiting for it to land.
///
/// The header walk skips each member's data area arithmetically, so the
/// next header sits a whole member ahead and the walk's last read is the
/// END record at the volume TAIL. Parsed eagerly, that meant a chased
/// volume was pinned in the holds budget in full before the engine read
/// one packed byte - and a set whose VOLUMES were larger than the cap
/// could therefore never be chased at all: the budget broke during the
/// wait, with no consumption watermark published, so the drop-behind
/// trim found nothing to release and the set forfeited. Measured 22 Aug
/// 2026 at 2.002x payload of disk against 1.0-1.5x, unchanged at 2x, 5x
/// and 10x the cap, unchanged at a quarter of the line rate (the decoder
/// was idle-waiting on 14% of one core, not losing a race), and
/// identical at depth 0 and depth 1. Re-packing the SAME payload with
/// volumes SMALLER than the cap carried it one-pass, which is what
/// pointed at the volume size rather than the set size, the depth or the
/// trim's release floor.
///
/// So the pin is the mechanism, not the cost: with volume 0 arrived
/// except for its last article, the engine has consumed most of it.
/// Before the fix this was a flat zero - and a zero here is
/// indistinguishable from the outside from a chase that is merely one
/// volume behind, which is why `chase_watermark_bytes` exists.
pub(in crate::extract) fn chase_decodes_a_volume_before_its_tail_arrives() {
    let dir = tmpdir("chase-tailwait");
    let (f, vols, names) = chase_volume_set();
    let art = 7000usize;

    let ex = Arc::new(Extractor::new(&dir, vols.len(), true));
    ex.anchor();
    // No budget pressure anywhere: this is about whether the engine
    // STARTS, and a forfeit would only confuse the reading. Fed in
    // order and with the volume's TRUE declared length, so what is
    // missing is exactly its last article.
    let total = vols[0].len() as u64;
    let held = vols[0].len() - art;
    for s in (0..held).step_by(art) {
        let e = (s + art).min(held);
        ex.write(0, &names[0], total, s as u64, &vols[0][s..e])
            .unwrap();
    }

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let want = held as u64 / 2;
    while ex.chase_watermark_bytes() < want && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    let watermark = ex.chase_watermark_bytes();
    assert!(
        watermark >= want,
        "the engine consumed {watermark} B of the {held} B that had arrived \
         of volume 0 ({} B): it is waiting for the volume's tail instead of \
         decoding behind the frontier",
        vols[0].len()
    );

    // And it still finishes byte-exact once the rest lands: the walk
    // that was deferred is finished by the engine, not skipped.
    ex.write(0, &names[0], total, held as u64, &vols[0][held..])
        .unwrap();
    for (index, vol) in vols.iter().enumerate().skip(1) {
        feed(&ex, index, &names[index], vol, art, 33 + index as u64);
    }
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(&std::fs::read(dir.join("F.bin")).unwrap(), f);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The engine-side half of the same contract, with no chase around it:
/// the eager walk waits for the volume's tail, the incremental one does
/// not - and what it hands back over a head-only frontier is the entry
/// the chase is about to decode.
///
/// A volume whose only member is flagged SPLIT_AFTER needs no completion
/// at all: by the format nothing can follow a member that continues into
/// the next volume but the END record, so the truncated walk has already
/// seen every entry there is.
#[test]
fn the_incremental_header_walk_does_not_wait_for_the_volume_tail() {
    let piece = payload(400_000, 5);
    let vol = fixtures::rar5_volume_n(&[("F.bin", 800_000, &piece, false, true)], 0);
    let opts = crate::mem::rar_read_options(None);

    // Head only - the member's data area, and so the END record behind
    // it, is nowhere near arrived.
    let head = Arc::new(FrontierBuffer::new(vol.len() as u64));
    head.write_span(0, &vol[..4096]);
    let archive = rars::rar50::Archive::parse_stream_incremental(
        head.clone() as Arc<dyn rars::BlockingRangeSource>,
        vol.len() as u64,
        opts,
    )
    .unwrap();
    assert_eq!(
        archive
            .files()
            .map(|f| f.name_bytes().to_vec())
            .collect::<Vec<_>>(),
        vec![b"F.bin".to_vec()],
        "the incremental walk did not reach the entry the engine needs"
    );
    assert!(
        archive.is_partially_enumerated(),
        "the walk ran past the member's data area, which has not arrived"
    );

    // The eager walk over the same frontier is still sitting on the tail.
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (src, len, flag) = (head.clone(), vol.len() as u64, done.clone());
    let worker = std::thread::spawn(move || {
        let parsed = rars::rar50::Archive::parse_stream(
            src as Arc<dyn rars::BlockingRangeSource>,
            len,
            crate::mem::rar_read_options(None),
        );
        flag.store(true, Ordering::Relaxed);
        parsed.map(|a| a.files().count())
    });
    std::thread::sleep(std::time::Duration::from_millis(250));
    let waited = !done.load(Ordering::Relaxed);
    head.write_span(4096, &vol[4096..]);
    assert_eq!(worker.join().unwrap().unwrap(), 1);
    assert!(
        waited,
        "the eager walk returned without the volume's tail - this test no \
         longer measures the difference it is named for"
    );

    // And the deferred half of the walk is finished, not skipped: over
    // the now-complete volume the same archive enumerates whole.
    let mut archive = archive;
    archive.enumerate_rest(None).unwrap();
    assert!(!archive.is_partially_enumerated());
    assert_eq!(archive.files().count(), 1);
}

/// TODO 220, the cost half at mock scale: a chased set whose VOLUMES
/// are larger than the holds cap must trim from INSIDE a volume and
/// carry one-pass. `chase_decodes_a_volume_before_its_tail_arrives`
/// pins the mechanism with no budget pressure; this puts the cap under
/// the volume, which is the field shape (two 3.3 GB volumes under a
/// 1.3 GB cap forfeited at 2.002x at every rung and either depth, while
/// the same payload in 500 MiB volumes trimmed and went one-pass).
///
/// Two packed volumes, the first 9.4 MB against the 8 MiB cap floor,
/// fed IN ORDER (the field's arrival order - the shuffled `feed` can
/// land the END record early, which is exactly what the chase cannot
/// count on) and paced on the engine's own watermark so the decoder
/// has every chance to get ahead of the cap. Depth 0, because the round
/// measured depth to be no variable here. Its own fixture, hence not in
/// `chase_volume_set_cases`: the shared set's volumes are 200 KB, far
/// under the cap floor. With the eager open swapped back in this fails
/// with the field's exact reason, `held-bytes cap: chase memory`.
#[test]
fn a_chase_whose_volumes_exceed_the_cap_trims_from_inside_the_volume() {
    let f = noisy(16 << 20, 220);
    let vols = rars_compressed_volumes("F.bin", &f, 9 << 20);
    volumes_over_the_cap_trim_and_carry_one_pass("chase-volume-over-cap", &f, vols);
}

/// The RAR4 twin of `chase_decodes_a_volume_before_its_tail_arrives`:
/// `rar15_40::Archive::parse_stream` had the same eager walk to the end
/// block and `chase_next_volume_v4` the same whole-volume wait, so a
/// chased RAR4 set whose volumes exceed the cap forfeited the same way.
/// Mechanism shape rather than the over-cap shape above: the debug
/// RAR29 encoder takes over ten CPU-minutes on the 16 MiB payload the
/// cap floor demands, and the mechanism is what differs between the
/// families - the cap arithmetic downstream of it is shared.
#[test]
fn a_v4_chase_decodes_a_volume_before_its_tail_arrives() {
    let dir = tmpdir("chase-v4-tailwait");
    let f = noisy(600_000, 221);
    let vols = rars_v4_compressed_volumes("F.bin", &f, 120_000);
    assert!(vols.len() >= 3, "want several volumes, got {}", vols.len());
    // WinRAR's tail: every real RAR3 volume ends in an ENDARC block, and
    // that block is what the eager walk waited for. The rars writer
    // emits none, and without it the eager parse needs no tail read and
    // the negative control (eager open swapped back in) passes.
    let last = vols.len() - 1;
    let vols: Vec<Vec<u8>> = vols
        .into_iter()
        .enumerate()
        .map(|(i, v)| fixtures::with_rar4_end_block(v, i < last))
        .collect();
    for v in &vols {
        assert_not_store(v);
    }
    let names: Vec<String> = (0..vols.len())
        .map(|i| format!("release.part{}.rar", i + 1))
        .collect();
    let art = 7000usize;

    let ex = Arc::new(Extractor::new(&dir, vols.len(), true));
    ex.anchor();
    // No budget pressure: this is about whether the engine STARTS. Fed
    // in order with the volume's true length, so what is missing is
    // exactly its last article.
    let total = vols[0].len() as u64;
    let held = vols[0].len() - art;
    for s in (0..held).step_by(art) {
        let e = (s + art).min(held);
        ex.write(0, &names[0], total, s as u64, &vols[0][s..e])
            .unwrap();
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let want = held as u64 / 2;
    while ex.chase_watermark_bytes() < want && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    let watermark = ex.chase_watermark_bytes();
    assert!(
        watermark >= want,
        "the v4 engine consumed {watermark} B of the {held} B that had arrived \
         of volume 0 ({} B): it is waiting for the volume's tail instead of \
         decoding behind the frontier",
        vols[0].len()
    );
    ex.write(0, &names[0], total, held as u64, &vols[0][held..])
        .unwrap();
    for (index, vol) in vols.iter().enumerate().skip(1) {
        feed(&ex, index, &names[index], vol, art, 33 + index as u64);
    }
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(&std::fs::read(dir.join("F.bin")).unwrap(), &f);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// TODO 250's defect, refused on the RAR4 side too (§254 step 2): by the
/// time the deferred header walk runs, the chase has RELEASED the
/// volume's prefix - that is the point of deferring it - so
/// `rar15_40::Archive::enumerate_rest` must RESUME at the stop offset and
/// never re-read the signature. The RAR5 twin's first cut re-walked from
/// byte 0 and was measured failing at offset 8 behind the trim point,
/// costing a chase 1.0x of payload; `39b1001df` made it resume, and the
/// RAR4 port (`d6e084c6c`) landed with the re-walk. The engine-side pin,
/// cheap enough to run on every sweep: the chase-scale twin is
/// `a_chase_survives_trimming_the_volume_its_deferred_walk_resumes_in`,
/// which has no RAR4 form because the debug RAR29 encoder cannot build
/// three over-cap volumes in unit-test time. The stop
/// offset is the END record, which sits exactly at the engine's
/// watermark; a trim to that watermark leaves it readable and
/// everything below it gone. With the v4 walk started from byte 0
/// instead this fails with `chase source read 0 behind the trim point`
/// - TODO 250's exact signature (run as a negative control, reverted).
#[test]
fn a_v4_deferred_header_walk_never_rereads_the_trimmed_prefix() {
    let f = noisy(120_000, 142);
    let mut vols = rars_v4_compressed_volumes("F.bin", &f, 40_000);
    assert!(vols.len() >= 2, "want a split member, got {}", vols.len());
    let vol = fixtures::with_rar4_end_block(std::mem::take(&mut vols[0]), true);
    let stop = vol.len() as u64 - 7; // the END record the walk stops on

    // Everything but the END record has arrived: the incremental walk
    // stops exactly there.
    let buf = Arc::new(FrontierBuffer::new(vol.len() as u64));
    buf.write_span(0, &vol[..stop as usize]);
    let mut archive = rars::rar15_40::Archive::parse_stream_incremental(
        buf.clone() as Arc<dyn rars::BlockingRangeSource>,
        vol.len() as u64,
        crate::mem::rar_read_options(None),
    )
    .unwrap();
    assert_eq!(archive.files().count(), 1);
    assert!(archive.is_partially_enumerated());

    // The engine is done with the fragment: trim everything below the
    // stop offset off the buffer, as the drop-behind trim does.
    let (at, released) = buf.trim_to(stop, 1).expect("a trim to the stop offset");
    assert_eq!((at, released.len() as u64), (0, stop));
    assert_eq!(buf.base(), stop);

    buf.write_span(stop, &vol[stop as usize..]);
    archive.enumerate_rest(None).unwrap();
    assert!(!archive.is_partially_enumerated());
    assert_eq!(archive.files().count(), 1);
    assert!(
        archive
            .blocks
            .iter()
            .any(|b| matches!(b, rars::rar15_40::Block::End(_))),
        "the finished walk should have reached the END record"
    );
}

fn volumes_over_the_cap_trim_and_carry_one_pass(tag: &str, f: &[u8], vols: Vec<Vec<u8>>) {
    let dir = tmpdir(tag);
    assert!(
        vols.len() >= 2,
        "want a split member, got {} volume",
        vols.len()
    );
    assert!(
        vols[0].len() > 8 << 20,
        "the first volume must be past the cap floor or the test proves nothing: {}",
        vols[0].len()
    );
    for v in &vols {
        assert_not_store(v);
    }
    let names: Vec<String> = (0..vols.len())
        .map(|i| format!("release.part{}.rar", i + 1))
        .collect();
    let ex = Arc::new(Extractor::new(&dir, vols.len() + 3, true));
    ex.anchor();
    ex.set_holds_cap(1); // floors at 8 MB, under the first volume
    let art = 256 << 10;
    let lead = 1u64 << 20;
    // `chase_watermark_bytes` sums the watermarks with finished volumes
    // counted whole, so the engine's position inside volume k is that
    // sum less the volumes before k.
    let mut before = 0u64;
    for (index, vol) in vols.iter().enumerate() {
        for i in 0..vol.len().div_ceil(art) {
            let s = i * art;
            let e = (s + art).min(vol.len());
            ex.write(index, &names[index], vol.len() as u64, s as u64, &vol[s..e])
                .unwrap();
            // Let the engine catch up to within `lead` of the frontier,
            // for a bounded time: a decoder that cannot start (the
            // regression) must not hang the feed, it must forfeit.
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(250);
            while ex.chase_watermark_bytes().saturating_sub(before) + lead < e as u64
                && ex.chase_retained_bytes() > 0
                && std::time::Instant::now() < deadline
            {
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        }
        before += vol.len() as u64;
    }
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert!(
        ex.chase_trimmed_bytes() > 0,
        "nothing was ever trimmed: holds peak {} B against an 8 MB cap",
        ex.holds_peak()
    );
    assert_eq!(&std::fs::read(dir.join("F.bin")).unwrap(), f);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// TODO 220 / 250: the chase must SURVIVE its own trim. The test above
/// stops one volume short of the field: its second volume (~7 MB) sits
/// under the 8 MiB cap floor, so the FINISH volume is never trimmed and
/// the deferred header walk `extract_volume_sequence_to_with_progress`
/// runs over it after the member lands (`enumerate_rest`) finds every
/// byte still there. In the field both volumes were 3.3 GB: the finish
/// volume trimmed, the deferred walk started over from the signature,
/// and `FrontierBuffer` refused the read - `chase source read 8 behind
/// the trim point` on every leg, 2.002x -> 3.001x because 6 GB of spill
/// went to waste on top of the materialization.
///
/// So: three packed volumes, EVERY one over the cap floor, fed in order
/// and paced on the watermark exactly as above. The finish volume now
/// trims before its walk is finished, and the walk has to resume where
/// it stopped rather than behind the trim point.
#[test]
fn a_chase_survives_trimming_the_volume_its_deferred_walk_resumes_in() {
    let dir = tmpdir("chase-volume-over-cap-finish");
    let f = noisy(37 << 20, 250);
    let vols = rars_compressed_volumes("F.bin", &f, 9 << 20);
    assert!(
        vols.len() >= 3,
        "want a member spanning three volumes, got {}",
        vols.len()
    );
    for (i, v) in vols.iter().enumerate() {
        assert!(
            v.len() > 8 << 20,
            "volume {i} must be past the cap floor or the finish volume never trims: {}",
            v.len()
        );
        assert_not_store(v);
    }
    let names: Vec<String> = (0..vols.len())
        .map(|i| format!("release.part{}.rar", i + 1))
        .collect();
    let ex = Arc::new(Extractor::new(&dir, vols.len() + 3, true));
    ex.anchor();
    ex.set_holds_cap(1); // floors at 8 MB, under every volume
    let art = 256 << 10;
    let lead = 1u64 << 20;
    let mut before = 0u64;
    for (index, vol) in vols.iter().enumerate() {
        for i in 0..vol.len().div_ceil(art) {
            let s = i * art;
            let e = (s + art).min(vol.len());
            ex.write(index, &names[index], vol.len() as u64, s as u64, &vol[s..e])
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(250);
            while ex.chase_watermark_bytes().saturating_sub(before) + lead < e as u64
                && ex.chase_retained_bytes() > 0
                && std::time::Instant::now() < deadline
            {
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        }
        before += vol.len() as u64;
    }
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    let last = vols.len() - 1;
    let trimmed = ex.chase_trimmed_bytes();
    assert!(
        trimmed > vols[..last].iter().map(|v| v.len() as u64).sum::<u64>(),
        "the finish volume was never trimmed (trimmed {trimmed} B), so this \
         test no longer reaches the deferred walk over a trimmed volume"
    );
    assert_eq!(&std::fs::read(dir.join("F.bin")).unwrap(), &f);
    std::fs::remove_dir_all(&dir).unwrap();
}
