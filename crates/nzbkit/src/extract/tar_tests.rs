//! Tests for the TAR chase (TODO 163 item 6). A sibling file rather
//! than an inline `mod tests` so `tar.rs` stays well inside the size
//! gate's ceiling as coverage grows - the `zip_tests.rs` pattern.

use super::*;

use crate::extract::testutil::*;
use crate::tar::fixtures::{Spec, tar_of};

/// A tar of two payload files, the shape most of these tests want.
fn two_file_tar(a: &[u8], b: &[u8]) -> Vec<u8> {
    tar_of(&[Spec::file("a.bin", a), Spec::file("b.bin", b)])
}

/// A posted `.tar` streams both members out and the container never
/// touches disk. Three feed orders, including the reversed one - tar
/// has no tail structure, so unlike zip and 7z the shuffle is testing
/// the holds/drain path rather than a promote.
#[test]
fn tar_top_level_extracts_one_pass() {
    let a = payload(180_000, 190);
    let b = payload(60_000, 191);
    let arch = two_file_tar(&a, &b);
    let art = 7000usize;
    let n_arts = arch.len().div_ceil(art);
    // A real permutation each time, including the shape that pins the
    // holds path: article 0 - the only one carrying the magic - dead
    // last, so every earlier span is parked unclassified until it
    // lands. (The zip tests' `(i * 7 + 3) % n` trick is a permutation
    // only when 7 and n are coprime; this fixture's article count is a
    // multiple of 7, and a silently-shortened feed is not a test.)
    let orders: Vec<Vec<usize>> = vec![
        (0..n_arts).collect(),
        (0..n_arts).rev().collect(),
        shuffled_zero_last(n_arts, 190),
    ];
    for (t, order) in orders.iter().enumerate() {
        let dir = tmpdir(&format!("tar-top-onepass{t}"));
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        let mut seen = vec![false; n_arts];
        for &i in order {
            if std::mem::replace(&mut seen[i], true) {
                continue;
            }
            let s = i * art;
            let e = (s + art).min(arch.len());
            ex.write(0, "release.tar", arch.len() as u64, s as u64, &arch[s..e])
                .unwrap();
        }
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "order {t}: {:?}", rep.fallbacks);
        assert!(
            rep.extracted
                .iter()
                .any(|(n, s)| n == "a.bin" && *s == a.len() as u64),
            "order {t}: {:?}",
            rep.extracted
        );
        assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a, "order {t}");
        assert_eq!(std::fs::read(dir.join("b.bin")).unwrap(), b, "order {t}");
        // The point of the whole exercise: no materialized archive.
        assert_eq!(
            dir_files(&dir),
            vec!["a.bin".to_string(), "b.bin".to_string()],
            "order {t}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// The shape this arm exists for (TODO 163 item 6's own words: the
/// honest case is a tar nested inside a RAR): a `.tar` INSIDE a store
/// RAR one-passes exactly like nested zip and 7z - payload byte-exact,
/// NOTHING else on disk, no inner `.tar` and no outer volume.
#[test]
fn tar_nested_in_store_rar_extracts_one_pass() {
    let a = payload(180_000, 192);
    let b = payload(60_000, 193);
    let arch = two_file_tar(&a, &b);
    let outer = store_outer("inner.tar", &arch);
    let art = 7000usize;
    let n_arts = outer.len().div_ceil(art);
    let orders: Vec<Vec<usize>> = vec![
        (0..n_arts).collect(),
        (0..n_arts).rev().collect(),
        shuffled_zero_last(n_arts, 192),
    ];
    for (t, order) in orders.iter().enumerate() {
        let dir = tmpdir(&format!("tar-nested-onepass{t}"));
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        let mut seen = vec![false; n_arts];
        for &i in order {
            if std::mem::replace(&mut seen[i], true) {
                continue;
            }
            let s = i * art;
            let e = (s + art).min(outer.len());
            ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..e])
                .unwrap();
        }
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "order {t}: {:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a, "order {t}");
        assert_eq!(std::fs::read(dir.join("b.bin")).unwrap(), b, "order {t}");
        assert_eq!(
            dir_files(&dir),
            vec!["a.bin".to_string(), "b.bin".to_string()],
            "order {t}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// Entry names with a provably safe directory component keep their
/// TREE (RAR, 7z and zip inners do the same since the relpath-preserve
/// ruling), directory members produce nothing, and a zero-byte member
/// still lands as an empty file.
#[test]
fn tar_entries_keep_their_tree_and_empty_files_land() {
    let a = payload(50_000, 194);
    let arch = tar_of(&[
        Spec::dir("Pack/"),
        Spec::file("Pack/a.bin", &a),
        Spec::file("empty.txt", b""),
    ]);
    let dir = tmpdir("tar-top-flat");
    let ex = Arc::new(Extractor::new(&dir, 1, true));
    ex.anchor();
    feed(&ex, 0, "release.tar", &arch, 7000, 80);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("Pack").join("a.bin")).unwrap(), a);
    assert_eq!(std::fs::read(dir.join("empty.txt")).unwrap(), b"");
    assert_eq!(
        dir_files(&dir),
        vec!["Pack".to_string(), "empty.txt".to_string()]
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Both long-name spellings survive the whole route to disk - the GNU
/// `L` member and the pax `path=` record. The names are longer than
/// ustar's 100-byte field, so a reader that ignored either would write
/// a truncated name and the assert would name it.
#[test]
fn tar_long_names_reach_disk() {
    let long = format!("Release.Group/{}/payload.mkv", "d".repeat(140));
    let data = payload(40_000, 195);
    let gnu = tar_of(&[Spec {
        gnu: true,
        long_name: Some(&long),
        ..Spec::file(&long[..100], &data)
    }]);
    let pax = tar_of(&[Spec {
        pax: vec![("path".to_string(), long.clone())],
        ..Spec::file(&long[..100], &data)
    }]);
    // The path is provably safe, so the long name keeps its tree.
    let rel: std::path::PathBuf = long.split('/').collect();
    for (tag, arch) in [("gnu", gnu), ("pax", pax)] {
        let dir = tmpdir(&format!("tar-longname-{tag}"));
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        feed(&ex, 0, "release.tar", &arch, 7000, 81);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{tag}: {:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join(&rel)).unwrap(), data, "{tag}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// Every refusal declines the WHOLE container and materializes it
/// byte-exact under the tar marker, so the demote is precisely what a
/// posted `.tar` did before this arm existed. Each reason is pinned
/// with the word a user would read.
#[test]
fn tar_top_level_declines_materialize_under_the_tar_marker() {
    let data = payload(40_000, 196);
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        (
            "symlink",
            tar_of(&[Spec::file("a.bin", &data), Spec::special("link", b'2')]),
            "symlink",
        ),
        (
            "sparse",
            tar_of(&[Spec::special("disk.img", b'S')]),
            "sparse",
        ),
        // Damage in a LATER header, so the container attaches on a
        // sound first block and the refusal happens mid-walk - the
        // demote path this case is here for. A damaged FIRST header
        // never attaches at all (the sniff checks it), which is a
        // decline, not a demote, and is pinned on `looks_like_tar`.
        (
            "damaged",
            tar_of(&[
                Spec::file("a.bin", &data),
                Spec {
                    bad_checksum: true,
                    ..Spec::file("b.bin", &data)
                },
            ]),
            "checksum",
        ),
        (
            "empty",
            tar_of(&[Spec::dir("only-a-directory/")]),
            "contains no files",
        ),
        // Cut on a block boundary between two members: every member
        // read is well-formed and the payload of the first one is
        // whole, so this is the shape that would otherwise publish a
        // truncated archive as a complete one.
        (
            "truncated",
            {
                let full = tar_of(&[Spec::file("a.bin", &data), Spec::file("b.bin", &data)]);
                // Exactly where the first member's padding ends, which
                // is where the one-member archive's end blocks start.
                let cut = tar_of(&[Spec::file("a.bin", &data)]).len() - crate::tar::BLOCK * 2;
                full[..cut].to_vec()
            },
            "end-of-archive marker",
        ),
    ];
    for (tag, arch, word) in cases {
        let dir = tmpdir(&format!("tar-top-decline-{tag}"));
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        feed(&ex, 0, "release.tar", &arch, 7000, 82);
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.starts_with(TAR_DISK_FALLBACK_PREFIX) && w.contains(word)),
            "{tag}: {:?}",
            rep.fallbacks
        );
        assert_eq!(
            std::fs::read(dir.join("release.tar")).unwrap(),
            arch,
            "{tag}"
        );
        assert_eq!(dir_files(&dir), vec!["release.tar".to_string()], "{tag}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// A refused member at depth demotes the inner container alone: the
/// `.tar` materializes byte-exact for the disk pass and no half-written
/// payload survives beside it. The reason folds through the child as a
/// nested fallback, so the caller's volume remediation never keys off
/// it.
#[test]
fn tar_nested_decline_materializes_byte_exact() {
    let data = payload(90_000, 197);
    let arch = tar_of(&[Spec::file("a.bin", &data), Spec::special("link", b'2')]);
    let outer = store_outer("inner.tar", &arch);
    let dir = tmpdir("tar-nested-decline");
    let ex = Arc::new(Extractor::new(&dir, 1, true));
    ex.anchor();
    feed(&ex, 0, "v.rar", &outer, 7000, 83);
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks
            .iter()
            .any(|(_, w)| w.starts_with("nested fallback:") && w.contains("symlink")),
        "{:?}",
        rep.fallbacks
    );
    assert_eq!(std::fs::read(dir.join("inner.tar")).unwrap(), arch);
    assert!(
        !dir.join("a.bin").exists(),
        "no payload from a demoted chase"
    );
    assert_eq!(dir_files(&dir), vec!["inner.tar".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The held-bytes forfeit, driven directly (the budget path reaches
/// `chase_forfeit` exactly as `chase_span` would): the inner tar
/// materializes COMPLETE - including the article that arrives after the
/// demote - and no partial child output survives.
#[test]
fn tar_nested_budget_demote_materializes_byte_exact() {
    let a = payload(200_000, 198);
    let arch = tar_of(&[Spec::file("a.bin", &a)]);
    let outer = store_outer("inner.tar", &arch);
    let art = 7000usize;
    let n_arts = outer.len().div_ceil(art);
    let dir = tmpdir("tar-nested-budget");
    let ex = Arc::new(Extractor::new(&dir, 1, true));
    ex.anchor();
    // Withhold the LAST article so the chase is still live.
    for i in 0..n_arts - 1 {
        let s = i * art;
        let e = (s + art).min(outer.len());
        ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..e])
            .unwrap();
    }
    let child = ex
        .inner
        .lock()
        .unwrap()
        .child
        .clone()
        .expect("the outer store RAR must have routed into a child");
    {
        let mut g = child.inner.lock().unwrap();
        let inner = &mut *g;
        assert!(
            matches!(inner.slots[0].mode, SlotMode::SevenZ),
            "the inner tar must be chased before the forfeit"
        );
        child
            .chase_forfeit(inner, 0, "held-bytes cap: chase memory")
            .unwrap();
    }
    // The tail lands after the demote, as a late article would.
    let s = (n_arts - 1) * art;
    ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..])
        .unwrap();
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks
            .iter()
            .any(|(_, w)| w.starts_with("nested fallback:")),
        "{:?}",
        rep.fallbacks
    );
    assert_eq!(
        std::fs::read(dir.join("inner.tar")).unwrap(),
        arch,
        "the materialized inner tar lost bytes across the demote"
    );
    assert!(
        !dir.join("a.bin").exists(),
        "no payload from a demoted chase"
    );
    assert_eq!(dir_files(&dir), vec!["inner.tar".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The depth ceiling holds for tar exactly as it does for zip: a tar
/// inside a tar streams both layers by default, and with the ceiling
/// lowered the inner container simply lands on disk.
#[test]
fn tar_in_tar_respects_the_depth_ceiling() {
    let a = payload(120_000, 199);
    let inner_tar = tar_of(&[Spec::file("a.bin", &a)]);
    let outer_tar = tar_of(&[Spec::file("inner.tar", &inner_tar)]);

    let dir = tmpdir("tartar-allowed");
    let ex = Arc::new(Extractor::new(&dir, 1, true));
    ex.anchor();
    feed(&ex, 0, "release.tar", &outer_tar, 7000, 84);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a);
    assert_eq!(dir_files(&dir), vec!["a.bin".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();

    let dir = tmpdir("tartar-ceiling");
    let ex = Arc::new(Extractor::new(&dir, 1, true));
    ex.anchor();
    ex.set_nested_max_depth(1);
    feed(&ex, 0, "release.tar", &outer_tar, 7000, 85);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("inner.tar")).unwrap(), inner_tar);
    assert_eq!(dir_files(&dir), vec!["inner.tar".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A resumed run never chases at ANY depth (the rule RAR, 7z and zip
/// all keep): extraction is disabled wholesale, so the outer volume
/// classifies Plain on its first span and lands on disk.
#[test]
fn tar_never_chases_on_a_resumed_run() {
    let a = payload(160_000, 200);
    let arch = tar_of(&[Spec::file("a.bin", &a)]);
    let outer = store_outer("inner.tar", &arch);
    let dir = tmpdir("tar-nested-resume");
    let ex = Arc::new(Extractor::with_resume(&dir, 1, false, true));
    ex.anchor();
    feed(&ex, 0, "v.rar", &outer, 7000, 86);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("v.rar")).unwrap(), outer);
    assert_eq!(dir_files(&dir), vec!["v.rar".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The tar gate, `NZBFAST_NO_TAR`: the value parses as off, and the
/// runtime setter drives the same latch at every depth - one gate,
/// where zip has a nested/top pair. The env PARSE is asserted on the
/// pure helper for the same parallel-runner reason the other gate tests
/// give.
#[test]
fn tar_disabled_by_env() {
    assert!(tar_env_off_value(Some("1")));
    assert!(!tar_env_off_value(Some("0")));
    assert!(!tar_env_off_value(None));

    let a = payload(120_000, 201);
    let arch = tar_of(&[Spec::file("a.bin", &a)]);
    let outer = store_outer("inner.tar", &arch);
    for (tag, feed_name, feed_bytes, landed) in [
        ("nested", "v.rar", outer.clone(), "inner.tar"),
        ("top", "release.tar", arch.clone(), "release.tar"),
    ] {
        let dir = tmpdir(&format!("tar-gate-{tag}"));
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        assert!(ex.inner.lock().unwrap().tar_on, "gate must default on");
        ex.set_tar(false);
        feed(&ex, 0, feed_name, &feed_bytes, 7000, 87);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{tag}: {:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join(landed)).unwrap(), arch, "{tag}");
        assert_eq!(dir_files(&dir), vec![landed.to_string()], "{tag}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// The name gate holds against the stream, not just in the unit test:
/// a compressed tarball carries gzip magic at offset 0 and no ustar at
/// 257, so it never attaches and lands byte-exact - which is the whole
/// of the `.tar.gz` story, since nothing here decompresses one.
#[test]
fn a_compressed_tarball_never_attaches() {
    let arch = tar_of(&[Spec::file("a.bin", &payload(40_000, 202))]);
    let mut gz = vec![0x1fu8, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 0x03];
    gz.extend_from_slice(&arch);
    let dir = tmpdir("tar-gz");
    let ex = Arc::new(Extractor::new(&dir, 1, true));
    ex.anchor();
    feed(&ex, 0, "release.tar.gz", &gz, 7000, 88);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("release.tar.gz")).unwrap(), gz);
    assert_eq!(dir_files(&dir), vec!["release.tar.gz".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A NAMED non-tar is never magic-sniffed. The bytes here ARE a tar,
/// the name says `.mkv`, and the file is the deliverable - unpacking it
/// would be the `.cbz` mistake in a new costume.
#[test]
fn a_named_payload_never_attaches() {
    let arch = tar_of(&[Spec::file("a.bin", &payload(40_000, 203))]);
    let dir = tmpdir("tar-named-payload");
    let ex = Arc::new(Extractor::new(&dir, 1, true));
    ex.anchor();
    feed(&ex, 0, "movie.mkv", &arch, 7000, 89);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), arch);
    assert_eq!(dir_files(&dir), vec!["movie.mkv".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// An obfuscated post - no extension at all - is sniffed, which is the
/// case the name gate deliberately leaves open (the same trade-off the
/// zip and RAR sniffs make).
#[test]
fn an_obfuscated_tar_attaches_on_its_magic() {
    let a = payload(90_000, 204);
    let arch = tar_of(&[Spec::file("a.bin", &a)]);
    let dir = tmpdir("tar-obfuscated");
    let ex = Arc::new(Extractor::new(&dir, 1, true));
    ex.anchor();
    feed(&ex, 0, "a3f9c1d2e7b4", &arch, 7000, 90);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a);
    assert_eq!(dir_files(&dir), vec!["a.bin".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}
