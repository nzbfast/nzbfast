//! Unit tests for the native PAR2 creator.
//!
//! The set this builds is judged by OUR OWN reader (`par2::Par2Set::parse`,
//! `par2repair`) rather than by re-deriving the spec here, which is the
//! only comparison that means anything: a creator and a parser that agree
//! on a mistake would pass a hand-written assertion just as happily.
//! Interop against the real par2cmdline is the `e2e_norar` half, where the
//! `have_par2()` guard belongs.

use super::*;
use crate::par2::Par2Set;

fn payload(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(31).wrapping_add(seed as usize * 7)) as u8)
        .collect()
}

/// A temp directory that cleans itself up; the crate has no dev-dep on
/// tempfile and one three-line helper is cheaper than acquiring one.
struct Tmp(PathBuf);
impl Tmp {
    fn new(tag: &str) -> Tmp {
        let p = std::env::temp_dir().join(format!(
            "nzbfast-par2gen-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
    fn write(&self, name: &str, data: &[u8]) -> Member {
        let path = self.0.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, data).unwrap();
        Member {
            name: name.to_string(),
            path,
        }
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn read_all(dir: &Path, names: &[String]) -> Vec<Vec<u8>> {
    names
        .iter()
        .map(|n| std::fs::read(dir.join(n)).unwrap())
        .collect()
}

fn parse(blobs: &[Vec<u8>]) -> Par2Set {
    let refs: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
    Par2Set::parse(&refs).expect("our own parser must read our own set")
}

#[test]
fn an_index_only_set_names_every_member_and_verifies_it() {
    let t = Tmp::new("index");
    let a = payload(40_000, 3);
    let b = payload(9_000, 11);
    let members = vec![t.write("Show.S01E01.mkv", &a), t.write("readme.nfo", &b)];
    let names = create_into(
        &t.0,
        &members,
        "testset",
        &Par2Spec {
            redundancy_pct: 0,
            block_size: Some(4096),
        },
    )
    .unwrap();
    // Zero redundancy is the index alone - no volumes at all.
    assert_eq!(names, vec!["testset.par2".to_string()], "{names:?}");
    let set = parse(&read_all(&t.0, &names));
    let mut got: Vec<String> = set.files.iter().map(|f| f.name.clone()).collect();
    got.sort();
    assert_eq!(got, vec!["Show.S01E01.mkv", "readme.nfo"]);
    assert_eq!(set.block_size, 4096);
    // The block checksums have to be right, not merely present: verify
    // the real bytes against the descriptors we just wrote.
    for (m, data) in members.iter().zip([&a, &b]) {
        let f = set
            .files
            .iter()
            .find(|f| f.name == m.name)
            .unwrap_or_else(|| panic!("{} missing from the set", m.name));
        assert_eq!(f.length, data.len() as u64);
        let v = crate::par2::verify_file(f, set.block_size, data);
        assert!(
            v.md5_ok && v.md5_16k_ok && v.blocks.iter().all(|&b| b),
            "{} did not verify against the FileDesc/IFSC we wrote for it",
            m.name
        );
    }
}

#[test]
fn a_zero_byte_member_is_described_where_par2cmdline_would_skip_it() {
    // Matrix finding F3: par2cmdline prints "Skipping 0 byte file" and
    // omits the member, so the VIDEO_TS-placeholder shape cannot be
    // produced by it. This is the whole reason the creator is native.
    let t = Tmp::new("zerobyte");
    let members = vec![
        t.write("VIDEO_TS/VTS_01_1.VOB", &payload(20_000, 5)),
        t.write("VIDEO_TS/VIDEO_TS.BUP", b""),
    ];
    let names = create_into(&t.0, &members, "dvd", &Par2Spec::default()).unwrap();
    let set = parse(&read_all(&t.0, &names));
    let empty = set
        .files
        .iter()
        .find(|f| f.name == "VIDEO_TS/VIDEO_TS.BUP")
        .expect("the 0-byte placeholder must be named by the set");
    assert_eq!(empty.length, 0);
    // The tree survives in the FileDesc, which is the only place it
    // exists once the wire names are obfuscated.
    assert!(
        set.files.iter().any(|f| f.name == "VIDEO_TS/VTS_01_1.VOB"),
        "the directory tree must ride in the FileDesc names"
    );
}

#[test]
fn recovery_slices_reconstruct_a_deleted_member() {
    // The self-proving half: our own repair path reads the parity this
    // wrote and puts back bytes it never saw. A wrong RS constant, a
    // wrong exponent, or a byte-order slip all fail here.
    let t = Tmp::new("repair");
    let a = payload(30_000, 7);
    let b = payload(12_000, 19);
    let members = vec![t.write("payload.bin", &a), t.write("second.bin", &b)];
    let names = create_into(
        &t.0,
        &members,
        "rset",
        &Par2Spec {
            redundancy_pct: 60,
            block_size: Some(4096),
        },
    )
    .unwrap();
    assert!(
        names.len() > 1,
        "60% redundancy must emit volumes: {names:?}"
    );

    // Damage the first member beyond any single-block doubt.
    let mut broken = a.clone();
    broken[1000..9000].fill(0xAB);
    std::fs::write(&members[0].path, &broken).unwrap();

    let status = crate::par2repair::repair_dir(&t.0)
        .unwrap_or_else(|e| panic!("repair over our own parity failed: {e}"));
    assert!(
        matches!(status, crate::par2repair::RepairStatus::Repaired(_)),
        "repair did not run: {status:?}"
    );
    assert_eq!(
        std::fs::read(&members[0].path).unwrap(),
        a,
        "the repaired member is not byte-exact"
    );
    assert_eq!(std::fs::read(&members[1].path).unwrap(), b);
}

#[test]
fn volumes_repeat_the_critical_packets_so_a_lost_index_still_names_the_set() {
    let t = Tmp::new("critical");
    let members = vec![t.write("only.bin", &payload(20_000, 2))];
    let names = create_into(
        &t.0,
        &members,
        "vset",
        &Par2Spec {
            redundancy_pct: 30,
            block_size: Some(4096),
        },
    )
    .unwrap();
    // Read the VOLUMES alone - the index file is deliberately excluded.
    let vols: Vec<String> = names.iter().skip(1).cloned().collect();
    assert!(!vols.is_empty());
    let set = parse(&read_all(&t.0, &vols));
    assert_eq!(set.files.len(), 1);
    assert_eq!(set.files[0].name, "only.bin");
}

#[test]
fn a_duplicate_or_empty_member_name_is_refused() {
    let t = Tmp::new("dupname");
    let m = t.write("x.bin", &payload(100, 1));
    let dup = vec![
        m.clone(),
        Member {
            name: "x.bin".into(),
            path: m.path.clone(),
        },
    ];
    let err = create_into(&t.0, &dup, "s", &Par2Spec::default()).unwrap_err();
    assert!(
        format!("{err}").contains("cannot name one slot twice"),
        "{err}"
    );

    let blank = vec![Member {
        name: String::new(),
        path: m.path.clone(),
    }];
    let err = create_into(&t.0, &blank, "s", &Par2Spec::default()).unwrap_err();
    assert!(format!("{err}").contains("empty name"), "{err}");
}

#[test]
fn a_bad_block_size_or_base_name_is_refused_before_anything_is_written() {
    let t = Tmp::new("badspec");
    let members = vec![t.write("a.bin", &payload(100, 1))];
    for bs in [0u64, 6, 4095] {
        let err = create_into(
            &t.0,
            &members,
            "s",
            &Par2Spec {
                redundancy_pct: 0,
                block_size: Some(bs),
            },
        )
        .unwrap_err();
        assert!(format!("{err}").contains("multiple of 4"), "{bs}: {err}");
    }
    // A base name carrying a separator would write outside `dir`.
    for base in ["", "sub/set", "sub\\set"] {
        let err = create_into(&t.0, &members, base, &Par2Spec::default()).unwrap_err();
        assert!(
            format!("{err}").contains("single path component"),
            "{base:?}: {err}"
        );
    }
}

#[test]
fn the_default_block_size_is_always_a_legal_slice() {
    // Everything from an empty post to a large one has to land on a
    // positive multiple of 4 inside the parser's own ceiling, or the
    // set we write is one our own reader refuses.
    for total in [0u64, 1, 4095, 700_000, 1 << 30, 1 << 40] {
        let bs = default_block_size(total);
        assert!(bs > 0 && bs.is_multiple_of(4), "{total} -> {bs}");
        assert!(bs <= 256 << 20, "{total} -> {bs} over the parser ceiling");
    }
}

#[test]
fn the_volume_layout_covers_every_exponent_exactly_once() {
    for n in [1usize, 2, 3, 7, 8, 100, 401] {
        for cap in [1usize, 3, 64, 1000] {
            let layout = volume_layout(n, cap);
            let mut next = 0usize;
            for &(first, count) in &layout {
                assert_eq!(first, next, "n={n} cap={cap} layout={layout:?}");
                assert!(count > 0 && count <= cap, "n={n} cap={cap} count={count}");
                next += count;
            }
            assert_eq!(next, n, "n={n} cap={cap} layout={layout:?}");
        }
    }
}

#[test]
fn a_set_batched_across_several_passes_still_repairs() {
    // Drives the multi-batch path: a tiny block size makes the
    // accumulator budget bite, so the recovery slices are built in more
    // than one pass over the payload and the exponent bookkeeping that
    // stitches them together is actually exercised.
    let t = Tmp::new("batched");
    let a = payload(64_000, 23);
    let members = vec![t.write("wide.bin", &a)];
    let names = create_into(
        &t.0,
        &members,
        "bset",
        &Par2Spec {
            // 64000/4 = 16000 slices at 100% would blow the input limit;
            // 40% over 16 slices at a 4000-byte block is 7 volumes.
            redundancy_pct: 50,
            block_size: Some(4000),
        },
    )
    .unwrap();
    assert!(names.len() >= 4, "expected several volumes: {names:?}");
    let mut broken = a.clone();
    broken[0..12_000].fill(0);
    std::fs::write(&members[0].path, &broken).unwrap();
    let status = crate::par2repair::repair_dir(&t.0).expect("repair");
    assert!(
        matches!(status, crate::par2repair::RepairStatus::Repaired(_)),
        "{status:?}"
    );
    assert_eq!(std::fs::read(&members[0].path).unwrap(), a);
}

#[test]
fn a_set_of_only_empty_members_refuses_to_pretend_it_has_parity() {
    // Reachable rather than theoretical: the recovery count is rounded
    // UP and floored at one, so a set with no slices at all still asks
    // for a slice, and building parity over nothing would write a
    // volume that proves nothing. Zero redundancy names them fine.
    let t = Tmp::new("allempty");
    let members = vec![t.write("VIDEO_TS.BUP", b""), t.write("VIDEO_TS.IFO", b"")];
    let err = create_into(
        &t.0,
        &members,
        "empty",
        &Par2Spec {
            redundancy_pct: 10,
            block_size: Some(4096),
        },
    )
    .unwrap_err();
    assert!(format!("{err}").contains("no slices"), "{err}");

    let names = create_into(&t.0, &members, "empty", &Par2Spec::default()).unwrap();
    let set = parse(&read_all(&t.0, &names));
    assert_eq!(set.files.len(), 2);
    assert!(set.files.iter().all(|f| f.length == 0));
}

/// `R_e = Σ_i g_i^e · D_i` written out the way the spec states it: no
/// batching, no threads, no tables, one scalar [`crate::gf16::mul`] per
/// word. Deliberately a SECOND implementation rather than a rearranged
/// first one - it shares nothing with the fold under test but the
/// constants, so a wrong coefficient, a wrong table or a wrong batch
/// boundary all show up as different bytes.
fn textbook_recovery(
    blocks: &[Vec<u8>],
    block_size: u64,
    first: usize,
    count: usize,
) -> Vec<Vec<u8>> {
    let logs = crate::par2repair::input_base_logs(blocks.len()).unwrap();
    let words = (block_size / 2) as usize;
    (0..count)
        .map(|j| {
            let e = (first + j) as u64;
            let mut acc = vec![0u16; words];
            for (i, b) in blocks.iter().enumerate() {
                let c = crate::gf16::pow2(logs[i] as u64 * e % crate::gf16::ORDER as u64);
                for (w, a) in acc.iter_mut().enumerate() {
                    *a ^= crate::gf16::mul(c, u16::from_le_bytes([b[2 * w], b[2 * w + 1]]));
                }
            }
            crate::gf16::words_as_bytes(&acc).to_vec()
        })
        .collect()
}

/// The payload in INPUT-SLICE order - members by sorted file id, blocks
/// in file order, the tail zero-padded - which is the order the RS
/// constants are assigned along.
fn slices_in_order(scanned: &[Scanned], block_size: u64) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for s in scanned {
        if s.blocks.is_empty() {
            continue;
        }
        let data = std::fs::read(&s.path).unwrap();
        for c in data.chunks(block_size as usize) {
            let mut b = c.to_vec();
            b.resize(block_size as usize, 0);
            out.push(b);
        }
    }
    out
}

#[test]
fn the_batched_parallel_fold_agrees_with_the_textbook_definition() {
    // The recovery fold is `par2repair`'s `fold_parallel`, run over a
    // BATCH of input blocks at a time, and neither half of that is free:
    // a batch boundary in the wrong place mis-assigns a coefficient, and
    // a parallel fold can disagree with itself between runs. So the
    // whole point of this test is the LAST loop - the same set folded at
    // several read budgets, INCLUDING one block per batch, which is the
    // one-at-a-time shape this code had before it was parallelized. Every
    // budget must produce the same bytes as a definition that shares no
    // code with any of them.
    let t = Tmp::new("foldref");
    let members = [
        t.write("a/one.bin", &payload(9_000, 5)),
        // Not a whole number of blocks at any size below, so the
        // zero-padded tail rides the fold at every budget.
        t.write("two.bin", &payload(4_321, 9)),
        // A 0-byte member takes no slice and must not shift the index.
        t.write("VIDEO_TS.BUP", b""),
        t.write("three.bin", &payload(1_000, 200)),
    ];
    for bs in [4u64, 64, 1_000, 4_096] {
        let mut scanned: Vec<Scanned> = members.iter().map(|m| scan(m, bs).unwrap()).collect();
        scanned.sort_by_key(|s| s.file_id);
        let blocks = slices_in_order(&scanned, bs);
        let n = scanned.iter().map(|s| s.blocks.len()).sum::<usize>();
        assert_eq!(blocks.len(), n, "bs={bs}");
        for (first, count) in [(0usize, 1usize), (0, 3), (5, 4), (300, 2)] {
            let want = textbook_recovery(&blocks, bs, first, count);
            // One block per batch, two, three, and the whole payload in
            // one go: same slices out of all four, or the batching is
            // deciding an answer it has no business deciding.
            for budget in [bs, 2 * bs, 3 * bs, 1 << 24] {
                let got = recovery_slices(&scanned, bs, n, first, count, budget).unwrap();
                assert_eq!(
                    got, want,
                    "bs={bs} first={first} count={count} budget={budget}"
                );
            }
        }
    }
}
