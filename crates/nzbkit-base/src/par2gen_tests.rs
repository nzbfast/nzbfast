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
            for plan in [
                VolumePlan::Variable,
                VolumePlan::Even(1),
                VolumePlan::Even(3),
                VolumePlan::Even(7),
                VolumePlan::Even(64),
            ] {
                let layout = volume_layout(n, cap, plan, 0);
                let mut next = 0usize;
                for &(first, count) in &layout {
                    assert_eq!(first, next, "n={n} cap={cap} {plan:?} layout={layout:?}");
                    assert!(count > 0 && count <= cap, "n={n} cap={cap} count={count}");
                    next += count;
                }
                assert_eq!(next, n, "n={n} cap={cap} {plan:?} layout={layout:?}");
            }
        }
    }
}

/// `-f`, the First Recovery-Block-Number: the split is unchanged and
/// every volume's exponent moves by the offset.
///
/// The point of the switch is a set that COMPLEMENTS one already on
/// disk, so what matters is that the exponents it emits are disjoint
/// from `0..first` and that the counts - which decide the file names -
/// are the ones the plan would have produced anyway. Measured against
/// par2cmdline 1.3.0 on 4 Sep 2026: `-b32 -c4 -f7` writes
/// `vol07+1`, `vol08+2`, `vol10+1`, and parfast now writes the same
/// three. It used to write `vol00+1`, `vol01+2`, `vol03+1` - starting
/// at zero, over the top of the set the user was complementing.
#[test]
fn a_first_exponent_offsets_every_volume_and_changes_no_count() {
    let at = |first: usize| -> Vec<(usize, usize)> {
        volume_layout(7, usize::MAX, VolumePlan::Variable, first)
    };
    let base = at(0);
    assert_eq!(base, vec![(0, 1), (1, 2), (3, 4)]);
    // Shape preserved, origin moved.
    let moved = at(7);
    assert_eq!(moved, vec![(7, 1), (8, 2), (10, 4)]);
    let counts = |v: &[(usize, usize)]| -> Vec<usize> { v.iter().map(|&(_, c)| c).collect() };
    assert_eq!(counts(&base), counts(&moved));
    // And the offset composes with an explicit volume count.
    assert_eq!(
        volume_layout(20, usize::MAX, VolumePlan::Even(3), 100),
        vec![(100, 7), (107, 7), (114, 6)]
    );
    // Zero is the identity, which is what every engine caller passes.
    assert_eq!(at(0), volume_layout(7, usize::MAX, VolumePlan::Variable, 0));
}

/// The `-u` / `-n` split, in the shape par2cmdline 1.3.0 was MEASURED to
/// write it on 3 Sep 2026 (research/CLI-SUBSTITUTION-2026-09-03.md):
/// `k` volumes, the remainder to the EARLIEST of them. The direction
/// matters - 20 over 3 is 7, 7, 6 - because a set whose volumes are the
/// right sizes in the wrong order still has different file names, and
/// the next tool along finds volumes by name.
#[test]
fn an_even_plan_hands_the_remainder_to_the_earliest_volumes() {
    let counts = |n: usize, k: usize| -> Vec<usize> {
        volume_layout(n, usize::MAX, VolumePlan::Even(k), 0)
            .iter()
            .map(|&(_, c)| c)
            .collect()
    };
    assert_eq!(counts(20, 3), vec![7, 7, 6]);
    assert_eq!(counts(20, 7), vec![3, 3, 3, 3, 3, 3, 2]);
    assert_eq!(counts(10, 4), vec![3, 3, 2, 2]);
    assert_eq!(counts(64, 5), vec![13, 13, 13, 13, 12]);
    assert_eq!(counts(20, 1), vec![20]);
    // `-u` with no `-n` asks for as many volumes as the variable plan
    // would have written, then spreads evenly across them.
    assert_eq!(variable_volume_count(20), 5);
    assert_eq!(counts(20, variable_volume_count(20)), vec![4, 4, 4, 4, 4]);
    assert_eq!(variable_volume_count(16), 5);
    assert_eq!(counts(16, variable_volume_count(16)), vec![4, 3, 3, 3, 3]);
    assert_eq!(variable_volume_count(33), 6);
    assert_eq!(
        counts(33, variable_volume_count(33)),
        vec![6, 6, 6, 5, 5, 5]
    );
    assert_eq!(variable_volume_count(64), 7);
    assert_eq!(
        counts(64, variable_volume_count(64)),
        vec![10, 9, 9, 9, 9, 9, 9]
    );
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

/// The recovery ceiling is ONE predicate, and the create refuses through
/// it: 32,768 slices is legal, 32,769 is not, and the create's refusal
/// carries the predicate's own words. A preview pane asks the same
/// function before laying out any volume, so the two cannot disagree.
#[test]
fn the_recovery_ceiling_is_one_predicate_the_create_refuses_through() {
    assert!(check_recovery_count(0).is_ok());
    assert!(check_recovery_count(MAX_INPUT_SLICES as u64).is_ok());
    let over = check_recovery_count(MAX_INPUT_SLICES as u64 + 1).unwrap_err();
    assert!(check_recovery_count(u64::MAX).is_err());

    // The refusal is the shape check's, before any slice is computed or
    // any byte written, so it costs nothing to reach at a 4-byte source.
    let t = Tmp::new("recovceil");
    let members = vec![t.write("a.bin", b"test")];
    let err = create_into_exact(
        &t.0,
        &members,
        "set",
        Some(1 << 20),
        MAX_INPUT_SLICES + 1,
        CreatePlan::ENGINE,
    )
    .unwrap_err();
    assert_eq!(format!("{err}"), format!("{over}"));
    assert!(!t.0.join("set.par2").exists(), "nothing written");
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
fn slices_in_order(slots: &[(std::path::PathBuf, u64)], block_size: u64) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for (path, length) in slots {
        if *length == 0 {
            continue;
        }
        let data = std::fs::read(path).unwrap();
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
        let mut scanned: Vec<Scanned> = members.iter().map(|m| scan(m, bs, 1).unwrap()).collect();
        scanned.sort_by_key(|s| s.file_id);
        // Slice order is by file id; `scan_head` is what fixes it in
        // `create_into`, so pair the members the same way.
        let mut slots: Vec<([u8; 16], std::path::PathBuf, u64)> = members
            .iter()
            .map(|m| {
                let (len, _, id) = scan_head(m).unwrap();
                (id, m.path.clone(), len)
            })
            .collect();
        slots.sort_by_key(|(id, _, _)| *id);
        let slots: Vec<(std::path::PathBuf, u64)> =
            slots.into_iter().map(|(_, p, l)| (p, l)).collect();
        let blocks = slices_in_order(&slots, bs);
        let n = scanned.iter().map(|s| s.blocks.len()).sum::<usize>();
        assert_eq!(blocks.len(), n, "bs={bs}");
        for (first, count) in [(0usize, 1usize), (0, 3), (5, 4), (300, 2)] {
            let want = textbook_recovery(&blocks, bs, first, count);
            // One block per batch, two, three, and the whole payload in
            // one go: same slices out of all four, or the batching is
            // deciding an answer it has no business deciding.
            for budget in [bs, 2 * bs, 3 * bs, 1 << 24] {
                let got: Vec<Vec<u8>> = recovery_slices(
                    &slots,
                    bs,
                    n,
                    first,
                    count,
                    budget,
                    None,
                    &CreateControl::default(),
                )
                .unwrap()
                .iter()
                .map(|w| crate::gf16::words_as_bytes(w).to_vec())
                .collect();
                assert_eq!(
                    got, want,
                    "bs={bs} first={first} count={count} budget={budget}"
                );
            }
        }
    }
}

/// The block-parallel member scan must agree with a single reader on all
/// three digest products, and the whole-file lane must not read through a
/// cursor the positional lanes are moving.
///
/// `scan`'s parallel branch (`length >= SCAN_PAR_MIN_BYTES && n_blocks >= 2`
/// - i.e. every real member) had NO test at all before 3 Sep 2026, and on
/// Windows it was wrong: the block workers share the caller's `File` and
/// `disk::read_exact_at` is `seek_read` there, which moves that handle's
/// cursor, while the whole-file/16k lane reads THROUGH the cursor with a
/// `BufReader` over the same handle. The FileDesc MD5 written into the set
/// was therefore whatever bytes a positional worker had last left the
/// pointer on. Unix `pread` leaves the cursor alone, so this only ever
/// failed on Windows - which is exactly why it needs a test that RUNS
/// there rather than a comment.
///
/// Nine MiB and 64 KiB slices so the parallel branch is taken (its floor is
/// 8 MiB) with 144 blocks over several workers; the oracle is a plain
/// serial hash of the same bytes.
#[test]
fn the_parallel_member_scan_agrees_with_one_reader_on_every_digest() {
    let t = Tmp::new("parallel-scan-digests");
    let data = payload(9 << 20, 41);
    let member = t.write("wide.bin", &data);
    let block_size = 64u64 << 10;

    let parallel = scan(&member, block_size, 8).expect("parallel scan");
    let serial = scan(&member, block_size, 1).expect("serial scan");

    let whole: [u8; 16] = Md5::digest(&data).into();
    let head: [u8; 16] = Md5::digest(&data[..16384]).into();
    assert_eq!(
        parallel.md5_whole, whole,
        "the whole-file MD5 must not depend on how many block lanes ran"
    );
    assert_eq!(parallel.md5_16k, head, "the 16k head MD5");
    assert_eq!(
        parallel.md5_whole, serial.md5_whole,
        "parallel and serial scans of one member must agree"
    );
    assert_eq!(parallel.md5_16k, serial.md5_16k);
    assert_eq!(parallel.blocks, serial.blocks, "per-block MD5/CRC pairs");
    assert_eq!(parallel.blocks.len(), 144);
}

/// THE CREATOR MUST NOT WRITE A SET ITS OWN PARSER CALLS MALFORMED.
///
/// `par2::parse_main` refuses a slice size above `MAX_BLOCK_SIZE` (256 MiB)
/// and, per its own comment, a set past that cap is "treated as malformed and
/// verification is skipped - the download still completes". That is the right
/// answer for a hostile set off the wire and the wrong one for a set WE wrote:
/// before this guard, `create_into` accepted `bs = 512 MiB` and produced a
/// 537 MB set that `par2_repair_dir` then answered `NoMainPacket` on, so a
/// user's own large-block set would silently skip verification instead of
/// failing loudly (reproduced end to end on 0f9f638e3 -
/// `research/DEFECT-2026-09-03-create-blocksize-ceiling.md`).
///
/// The refusal therefore has to happen at CREATE time, with a named error,
/// and the boundary itself has to stay legal - so this pins both sides of it
/// and asserts nothing was written on the refusing side.
#[test]
fn a_block_size_past_the_parsers_own_ceiling_is_refused_at_create_time() {
    let t = Tmp::new("bsceiling");
    let members = vec![t.write("a.bin", &payload(100, 1))];
    let spec = |bs: u64| Par2Spec {
        redundancy_pct: 0,
        block_size: Some(bs),
    };

    // Exactly at the ceiling is a legal set and must still be written.
    let out = create_into(&t.0, &members, "at", &spec(crate::par2::MAX_BLOCK_SIZE))
        .expect("the ceiling itself is a legal PAR2 slice size");
    assert!(t.0.join(&out[0]).is_file(), "{out:?}");

    // One legal 4-multiple past it, and a round 512 MiB, are both refused
    // here rather than by a reader after 537 MB has been written.
    for bs in [crate::par2::MAX_BLOCK_SIZE + 4, 512 << 20] {
        let err = create_into(&t.0, &members, "over", &spec(bs)).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("no larger than"), "bs={bs}: {msg}");
        assert!(
            msg.contains(&crate::par2::MAX_BLOCK_SIZE.to_string()),
            "the refusal must name the ceiling it enforces: {msg}"
        );
        assert!(
            !t.0.join("over.par2").exists(),
            "bs={bs} was refused but still wrote an index"
        );
    }
}

/// The accumulator budget moved from `physical_ram() / 8` to a share of the
/// PROCESS budget on 3 Sep 2026, and the whole case for that being safe is
/// that the two agree exactly wherever no budget was published. This is that
/// claim, checked rather than argued: `MemBudget::auto` is
/// `clamp(ram / 4, 256 MiB, 16 GiB)`, so half of it clamped to
/// `[256 MiB, 8 GiB]` must reproduce `clamp(ram / 8, 256 MiB, 8 GiB)` at
/// every host size, floors and ceilings included.
#[test]
fn the_accumulator_budget_is_unchanged_wherever_no_process_budget_was_published() {
    for ram in [
        512u64 << 20,
        1 << 30,
        2 << 30,
        4 << 30,
        8 << 30,
        16 << 30,
        64 << 30,
        128 << 30,
        512 << 30,
    ] {
        let auto = (ram / 4).clamp(256 << 20, 16 << 30);
        let was = (ram / 8).clamp(ACCUM_MIN_BYTES, ACCUM_MAX_BYTES);
        assert_eq!(
            accum_budget_from(auto),
            was,
            "ram {ram}: the process-budget derivation must reproduce the RAM one"
        );
    }
}

/// A published budget must actually bind the accumulators. Before the change
/// above, `--mem-limit 512M` left one create free to hold 8 GiB of them - a
/// 2 GiB / 1 MiB / 50% set measured a 2.247 GB peak RSS against that 512 MiB
/// budget on an M3 Ultra.
#[test]
fn a_small_published_budget_bounds_the_accumulators() {
    assert_eq!(accum_budget_from(512 << 20), ACCUM_MIN_BYTES);
    assert_eq!(accum_budget_from(4 << 30), 2 << 30);
    // And the ceiling still holds against an enormous one.
    assert_eq!(accum_budget_from(1 << 40), ACCUM_MAX_BYTES);
}

/// The first create in an idle process must derive exactly what the
/// per-invocation formulas gave before the admission gauge existed - that is
/// the whole reason no shipping single-create path needs re-measuring - and a
/// second, concurrent create must divide what is LEFT rather than take a
/// second full share.
///
/// Held exclusive against every other create in the process, not merely
/// against the other admission test, because the gauge is process-wide and
/// `cargo test` puts a crate's whole lib in ONE process on parallel threads.
/// A mutex covering the two admission tests alone was not enough: see
/// [`super::ADMISSION_QUIESCE`] for the create that was live underneath this
/// one and the numbers it produced.
#[test]
fn a_concurrent_create_divides_what_is_left_instead_of_taking_a_second_share() {
    let _held = super::admission_quiesced_for_tests();
    let ceiling = crate::mem::process_budget().total;
    let solo = CreateAdmission::acquire();
    assert_eq!(solo.scan_pool, scan_pool_budget(ceiling));
    assert_eq!(solo.accum, accum_budget_from(ceiling));

    let second = CreateAdmission::acquire();
    assert!(
        second.claimed <= solo.claimed,
        "a create starting second must not claim more than the first: \
         {} vs {}",
        second.claimed,
        solo.claimed
    );
    // The bound the gauge buys: two lanes together stay inside one ceiling
    // plus the FLOOR PLAN that keeps the second lane working, rather than two
    // whole ceilings. The floor plan is the deliberate escape - a late create
    // pays extra passes over its own payload, it never blocks.
    //
    // Derived from the same function the gauge uses, never summed from the
    // constants: `SCAN_POOL_MIN_BYTES + ACCUM_MIN_BYTES + READ_BUDGET` is
    // 64 MiB SHORT, because `read_arena_claim` doubles the read window while
    // overlap is on. That is what took nightly's armv7-cross red on 6 Sep
    // 2026 (two lanes claimed 1,477,013,504 against a 1,007,251,456 ceiling),
    // and nothing about it is 32-bit: a process budget anywhere between about
    // 512 MiB and 1.25 GiB has the first lane claim the ceiling EXACTLY and
    // the second fall all the way to the floor plan, which is the only band
    // where the term is visible. No box that runs this suite on a bigger
    // budget can see it, which is why
    // `the_two_lane_bound_holds_at_every_process_ceiling` walks the ceilings
    // this one does not have.
    let floors = admission_plan(0).2;
    // `solo.claimed.max(ceiling)` is the same escape one level up: a budget
    // smaller than a single floor plan cannot bound anything, and the first
    // lane takes its floor plan there rather than blocking.
    assert!(
        solo.claimed + second.claimed <= solo.claimed.max(ceiling) + floors,
        "two lanes claimed {} against a {ceiling} ceiling and {floors} of floors",
        solo.claimed + second.claimed
    );
}

/// The two-lane bound at ceilings THIS box does not have.
///
/// The test above can only ever observe one number - this machine's process
/// budget - so the band where the admission floors actually bind is invisible
/// to it on anything with a few GiB. Nightly's armv7 guest had a budget of
/// 1,007,251,456 bytes, inside that band, and found the bound stated 64 MiB
/// short; every other box in the fleet passed the same assertion because its
/// first lane never reached the ceiling. Walking the arithmetic directly costs
/// microseconds and covers the class on every machine.
#[test]
fn the_two_lane_bound_holds_at_every_process_ceiling() {
    let floors = admission_plan(0).2;
    let mut floor_bound_seen = 0usize;
    let mut ceilings: Vec<u64> = (1..=4096u64).map(|mib| mib << 20).collect();
    ceilings.extend((4..=256u64).map(|gib| gib << 30));
    // The armv7 guest's own ceiling, pinned by value: it is the case that
    // failed, and a grid that stepped over it would not have caught it.
    ceilings.push(1_007_251_456);
    for ceiling in ceilings {
        let solo = admission_plan(ceiling).2;
        let second = admission_plan(ceiling.saturating_sub(solo)).2;
        assert!(
            second <= solo,
            "a create starting second must not claim more than the first at              a {ceiling} ceiling: {second} vs {solo}"
        );
        assert!(
            solo + second <= solo.max(ceiling) + floors,
            "two lanes claimed {} against a {ceiling} ceiling and {floors} of floors",
            solo + second
        );
        if solo >= ceiling {
            floor_bound_seen += 1;
            assert_eq!(
                second, floors,
                "a second lane with nothing left must take exactly the floor                  plan at a {ceiling} ceiling"
            );
        }
    }
    assert!(
        floor_bound_seen > 0,
        "the grid never reached a ceiling where the floors bind, so the arm          that took armv7-cross red is not covered"
    );
}

/// Releasing is what makes the gauge a bound rather than a ratchet: a create
/// that returns - by any path, which is why it is a `Drop` - must give its
/// share back, or the second create in a sequential caller like postfast's
/// two-set build would be throttled by the first one that already finished.
#[test]
fn a_finished_create_gives_its_share_back() {
    let _held = super::admission_quiesced_for_tests();
    let first = { CreateAdmission::acquire().claimed };
    let second = CreateAdmission::acquire();
    assert_eq!(
        second.claimed, first,
        "a sequential second create must find the gauge empty again"
    );
}

/// par2cmdline's interleave, as MEASURED on 4 Sep 2026 against
/// par2cmdline 1.3.0 by dumping the packet order of real volumes.
///
/// Two independent things are pinned. The COPY COUNT: a volume carries
/// as many whole copies of the critical block as `count` has bits, so a
/// 64-slice volume gets 7 and not 64. And the SPREAD: those copies are
/// distributed by a running proportional total, which is why 12 packets
/// over 8 slices alternate 1, 2, 1, 2 rather than arriving in a lump.
/// Both are load-bearing for the drop-in claim, because a volume with
/// the right packets in the wrong number of copies is a different SIZE,
/// and four e2e fixtures read the size (G2 in
/// research/CLI-SUBSTITUTION-2026-09-03.md).
#[test]
fn the_interleave_reproduces_par2cmdlines_measured_distribution() {
    // Three critical packets - the one-member set the numbers came from.
    assert_eq!(interleave_schedule(1, 3), vec![3]);
    assert_eq!(interleave_schedule(2, 3), vec![3, 3]);
    assert_eq!(interleave_schedule(4, 3), vec![2, 2, 2, 3]);
    assert_eq!(interleave_schedule(5, 3), vec![1, 2, 2, 2, 2]);
    assert_eq!(interleave_schedule(8, 3), vec![1, 2, 1, 2, 1, 2, 1, 2]);
    assert_eq!(
        interleave_schedule(16, 3),
        vec![0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
    );
    assert_eq!(
        interleave_schedule(23, 3),
        vec![
            0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1
        ]
    );
    // Seven critical packets - the three-member set, `-n4`, five slices
    // to a volume: 3 copies of 7 spread 4, 4, 4, 4, 5.
    assert_eq!(interleave_schedule(5, 7), vec![4, 4, 4, 4, 5]);
}

/// The two invariants every schedule owes, over shapes no measurement
/// covered: it accounts for exactly `bits(count)` whole copies, and it
/// never owes a copy to a slice that does not exist.
#[test]
fn every_interleave_schedule_closes_a_whole_number_of_copies() {
    for count in [1usize, 2, 3, 7, 9, 17, 64, 65, 255, 1000, 4096] {
        for n_cycle in [1usize, 3, 7, 40, 999] {
            let s = interleave_schedule(count, n_cycle);
            assert_eq!(s.len(), count, "count={count} cycle={n_cycle}");
            let copies = (usize::BITS - count.leading_zeros()) as usize;
            assert_eq!(
                s.iter().sum::<usize>(),
                copies * n_cycle,
                "count={count} cycle={n_cycle} owes {copies} copies"
            );
        }
    }
}

/// The interleave has to leave a set our own reader still reads.
///
/// It moves the critical packets away from offset 0 and hands the
/// backfill a list of offsets instead of one, so a set written under it
/// is the shape most likely to carry a stale placeholder: an
/// unbackfilled FileDesc holds a zeroed whole-file MD5, and this asserts
/// on exactly that field. The `Head` arm runs the same assertions, so a
/// failure here names the layout that broke rather than the creator.
#[test]
fn an_interleaved_set_still_verifies_against_our_own_reader() {
    for critical in [CriticalLayout::Head, CriticalLayout::Interleaved] {
        let t = Tmp::new("interleave");
        let a = payload(40_000, 3);
        let b = payload(9_000, 11);
        let members = vec![t.write("Show.S01E01.mkv", &a), t.write("readme.nfo", &b)];
        let names = create_into_exact(
            &t.0,
            &members,
            "testset",
            Some(4096),
            9,
            CreatePlan::ENGINE.with_critical(critical),
        )
        .unwrap();
        assert!(names.len() > 1, "{critical:?}: expected volumes, {names:?}");
        // Every VOLUME on its own, with the index withheld: that is the
        // repetition's whole point, and it is what the backfill has to
        // have reached.
        for name in names.iter().skip(1) {
            let blobs = read_all(&t.0, std::slice::from_ref(name));
            let set = parse(&blobs);
            let mut got: Vec<String> = set.files.iter().map(|f| f.name.clone()).collect();
            got.sort();
            assert_eq!(got, vec!["Show.S01E01.mkv", "readme.nfo"], "{name}");
            for (m, data) in members.iter().zip([&a, &b]) {
                let f = set.files.iter().find(|f| f.name == m.name).unwrap();
                let v = crate::par2::verify_file(f, set.block_size, data);
                assert!(
                    v.md5_ok && v.md5_16k_ok && v.blocks.iter().all(|&x| x),
                    "{name} ({critical:?}): {} did not verify - a critical packet copy \
                     kept its placeholder",
                    m.name
                );
            }
        }
    }
}

/// Every copy of the critical block inside a volume must be the SAME
/// bytes as the index's, or a reader that picks up the third copy gets
/// a different answer from one that picks up the first. The backfill
/// patches each copy separately, so this is the assertion that a
/// recorded offset named the packet it was written at.
#[test]
fn every_interleaved_copy_matches_the_index_packet_for_packet() {
    let t = Tmp::new("copies");
    let members = vec![
        t.write("a.bin", &payload(30_000, 2)),
        t.write("b.bin", &payload(12_000, 8)),
        t.write("c.bin", &payload(5_000, 19)),
    ];
    let names = create_into_exact(
        &t.0,
        &members,
        "set",
        Some(2048),
        20,
        CreatePlan::ENGINE.with_critical(CriticalLayout::Interleaved),
    )
    .unwrap();
    let index = std::fs::read(t.0.join(&names[0])).unwrap();
    let idx = critical_index(&index);
    let want: Vec<Vec<u8>> = idx
        .cycle
        .iter()
        .map(|&(o, l)| index[o..o + l].to_vec())
        .collect();
    for name in names.iter().skip(1) {
        let vol = std::fs::read(t.0.join(name)).unwrap();
        let mut seen = Vec::new();
        let mut off = 0usize;
        while off + 64 <= vol.len() {
            let len = u64::from_le_bytes(vol[off + 8..off + 16].try_into().unwrap()) as usize;
            if &vol[off + 48..off + 64] != TYPE_RECVSLIC && &vol[off + 48..off + 64] != TYPE_CREATOR
            {
                seen.push(vol[off..off + len].to_vec());
            }
            off += len;
        }
        assert!(
            seen.len() >= want.len(),
            "{name}: {} critical packets for a {}-packet block",
            seen.len(),
            want.len()
        );
        assert_eq!(
            seen.len() % want.len(),
            0,
            "{name}: {} packets is not a whole number of copies of {}",
            seen.len(),
            want.len()
        );
        for (k, got) in seen.iter().enumerate() {
            assert_eq!(
                got,
                &want[k % want.len()],
                "{name}: critical copy {k} is not the index's packet {}",
                k % want.len()
            );
        }
    }
}

/// The lane order keeps every member's blocks in order, spreads members
/// over eight lanes, skips empty members, and maps each position back to
/// its original slice (the base log's owner).
#[test]
fn interleave_plan_keeps_member_order_and_slice_identity() {
    // Members of 3, 0, 5, 1, 2, 9, 1, 1, 4, 2 blocks (ten members, so the
    // ninth and tenth wait for a free lane).
    let counts = [3usize, 0, 5, 1, 2, 9, 1, 1, 4, 2];
    let mut plan = Vec::new();
    for (mi, &n) in counts.iter().enumerate() {
        for b in 0..n {
            plan.push((mi, b as u64 * 64, 64usize));
        }
    }
    let (out, slice_of, lane_of) = super::interleave_plan(&plan);
    assert_eq!(out.len(), plan.len());
    assert_eq!(slice_of.len(), plan.len());
    // A permutation of the slices.
    let mut seen = slice_of.clone();
    seen.sort_unstable();
    assert_eq!(seen, (0..plan.len()).collect::<Vec<_>>());
    for (pos, &k) in slice_of.iter().enumerate() {
        assert_eq!(out[pos], plan[k]);
    }
    // Per member: offsets ascend in output order, and one lane throughout.
    for mi in 0..counts.len() {
        let mut last = None;
        let mut lane = None;
        for (pos, &(m, off, _)) in out.iter().enumerate() {
            if m != mi {
                continue;
            }
            assert!(last.is_none_or(|l| off > l), "member {mi} out of order");
            last = Some(off);
            assert!(
                lane.is_none_or(|l| l == lane_of[pos]),
                "member {mi} changed lane"
            );
            lane = Some(lane_of[pos]);
        }
    }
    // The first round is one block of each of the first eight non-empty
    // members, in lane order.
    let first_round: Vec<usize> = out[..8].iter().map(|&(m, _, _)| m).collect();
    assert_eq!(first_round, vec![0, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(&lane_of[..8], &[0, 1, 2, 3, 4, 5, 6, 7]);
}

/// A member that SHRANK between the head scan and the map is refused,
/// not mapped at its stale length.
///
/// `MappedPlan::open` passes the length `scan_heads` recorded and does
/// not re-stat, and the plan indexes into the mapping immediately - so
/// `bytes()` was a `from_raw_parts` over a length the mapping no longer
/// had. On Windows the section is created 0/0, meaning the file's
/// CURRENT size, so the slice ran straight off it.
#[test]
fn a_mapped_member_refuses_a_length_the_file_no_longer_has() {
    let d = std::env::temp_dir().join(format!("nzbfast-maplen-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let p = d.join("m.bin");
    std::fs::write(&p, vec![7u8; 4096]).unwrap();
    // The honest length maps.
    let m = MappedMember::open(&p, 4096).expect("the real length maps");
    assert_eq!(m.expect("a non-empty member maps").bytes().len(), 4096);
    // A stale, longer length is refused rather than mapped.
    assert!(
        MappedMember::open(&p, 8192).is_err(),
        "a length the file no longer has was mapped anyway"
    );
    // ...and so is a stale SHORTER one: either way the head scan and
    // the map disagree about the member, and a plan built from the scan
    // cannot be trusted over these bytes.
    assert!(MappedMember::open(&p, 2048).is_err());
    // An empty member is still "nothing to map", not an error.
    let e = d.join("e.bin");
    std::fs::write(&e, b"").unwrap();
    assert!(
        MappedMember::open(&e, 0)
            .expect("an empty member is Ok")
            .is_none()
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn mapped_tail_checksums_match_materialized_padding() {
    for bs in [4usize, 64, 68, 32768, 32772, 131076] {
        let mut sizes = vec![0, 1, 2, 3, bs / 2, bs - 1, bs];
        sizes.extend([55, 56, 63, 64, 65, 32767, 32768, 32769]);
        sizes.retain(|&n| n <= bs);
        sizes.sort_unstable();
        sizes.dedup();
        for len in sizes {
            let bytes = payload(len + 1, 173);
            let tail = &bytes[1..]; // deliberately unaligned
            let mut padded = vec![0u8; bs];
            padded[..len].copy_from_slice(tail);
            let expected = (Md5::digest(&padded).into(), crc32fast::hash(&padded));
            assert_eq!(
                mapped_tail_checksums(tail, bs),
                expected,
                "len={len} bs={bs}"
            );
        }
    }
}

/// [`plan_files`] must name and SIZE exactly what the creator writes,
/// under both critical layouts. This is the whole reason the door
/// exists: a GUI preview that added packet headers up for itself would
/// be a second copy of the format, and this is the assertion that there
/// is only one.
#[test]
fn the_plan_preview_matches_what_the_creator_actually_writes() {
    for critical in [CriticalLayout::Head, CriticalLayout::Interleaved] {
        for (tag, recovery) in [("plan-small", 1usize), ("plan-mid", 20), ("plan-odd", 13)] {
            let t = Tmp::new(&format!("{tag}-{critical:?}"));
            let members = vec![
                t.write("a.bin", &payload(30_000, 2)),
                t.write("b.bin", &payload(12_000, 8)),
                t.write("c.bin", &payload(5_000, 19)),
            ];
            let plan = CreatePlan::ENGINE.with_critical(critical);
            let want = plan_files(
                &members
                    .iter()
                    .map(|m| (m.name.clone(), std::fs::metadata(&m.path).unwrap().len()))
                    .collect::<Vec<_>>(),
                "set",
                2048,
                recovery,
                plan,
            );
            let names =
                create_into_exact(&t.0, &members, "set", Some(2048), recovery, plan).unwrap();
            assert_eq!(
                want.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
                names.iter().map(String::as_str).collect::<Vec<_>>(),
                "{tag} {critical:?}: planned names"
            );
            for f in &want {
                let got = std::fs::metadata(t.0.join(&f.name)).unwrap().len();
                assert_eq!(
                    f.bytes, got,
                    "{tag} {critical:?}: {} planned {} bytes, wrote {got}",
                    f.name, f.bytes
                );
            }
            assert_eq!(
                want.iter().map(|f| f.blocks).sum::<usize>(),
                recovery,
                "{tag} {critical:?}: every recovery slice is placed exactly once"
            );
        }
    }
}

/// A create with no recovery at all still writes the index, and the
/// plan says so rather than answering an empty list.
#[test]
fn the_plan_preview_of_a_zero_recovery_set_is_the_index_alone() {
    let files = plan_files(
        &[("a.bin".to_string(), 30_000)],
        "set",
        2048,
        0,
        CreatePlan::ENGINE,
    );
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, "set.par2");
    assert_eq!(files[0].blocks, 0);
    assert!(files[0].bytes > 64, "the index carries the critical block");
}

// ---- the optional comment packet (plan 4.2 item 2) -------------------

/// Create one small set twice over the same payload, once with a
/// comment and once without, and hand back both directories' files.
///
/// Two Tmps rather than one, because the second create would otherwise
/// write over the first set's volumes under the same base name.
fn comment_pair(tag: &str, comment: &str) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let build = |t: &Tmp, c: Option<&str>| {
        let members = vec![
            t.write("Show.S01E01.mkv", &payload(40_000, 3)),
            t.write("readme.nfo", &payload(9_000, 11)),
        ];
        let names = create_into_exact_with_comment(
            &t.0,
            &members,
            "cmt",
            Some(4096),
            6,
            CreatePlan::ENGINE,
            c,
        )
        .expect("create");
        read_all(&t.0, &names)
    };
    let with = Tmp::new(&format!("{tag}-with"));
    let without = Tmp::new(&format!("{tag}-without"));
    (build(&with, Some(comment)), build(&without, None))
}

#[test]
fn a_comment_round_trips_through_the_engines_own_reader() {
    let (with, _) = comment_pair("round", "Season pack, remuxed from the retail disc.");
    assert_eq!(
        parse(&with).comment.as_deref(),
        Some("Season pack, remuxed from the retail disc.")
    );
}

/// Every file of the set carries it, not only the index - the comment
/// rides in the critical block, which is what makes a set whose index
/// article was lost still describable from one volume.
#[test]
fn every_file_of_a_commented_set_carries_the_comment() {
    let (with, _) = comment_pair("perfile", "hello from the index");
    assert!(with.len() > 1, "the set has volumes to check");
    for (i, blob) in with.iter().enumerate() {
        assert_eq!(
            parse(std::slice::from_ref(blob)).comment.as_deref(),
            Some("hello from the index"),
            "file {i} lost the comment"
        );
    }
}

/// THE LOAD-BEARING ONE. A create given no comment writes the bytes it
/// has always written, because the critical block's LENGTH is what a
/// volume's byte size is built from and four e2e fixtures poison or band
/// a volume by its byte count.
#[test]
fn no_comment_is_byte_identical_to_the_plain_create() {
    let t = Tmp::new("identical-plain");
    let u = Tmp::new("identical-door");
    let build = |t: &Tmp, door: bool| {
        let members = vec![
            t.write("Show.S01E01.mkv", &payload(40_000, 3)),
            t.write("readme.nfo", &payload(9_000, 11)),
        ];
        let names = if door {
            create_into_exact_with_comment(
                &t.0,
                &members,
                "cmt",
                Some(4096),
                6,
                CreatePlan::ENGINE,
                None,
            )
        } else {
            create_into_exact(&t.0, &members, "cmt", Some(4096), 6, CreatePlan::ENGINE)
        }
        .expect("create");
        let blobs = read_all(&t.0, &names);
        (names, blobs)
    };
    let (plain_names, plain) = build(&t, false);
    let (door_names, door) = build(&u, true);
    assert_eq!(plain_names, door_names);
    assert_eq!(
        plain, door,
        "the comment door changed a set with no comment"
    );
    // And an EMPTY comment is the absence of one, which is what an
    // untouched Comment field in a UI sends.
    let v = Tmp::new("identical-empty");
    let members = vec![
        v.write("Show.S01E01.mkv", &payload(40_000, 3)),
        v.write("readme.nfo", &payload(9_000, 11)),
    ];
    let names = create_into_exact_with_comment(
        &v.0,
        &members,
        "cmt",
        Some(4096),
        6,
        CreatePlan::ENGINE,
        Some(""),
    )
    .expect("create");
    assert_eq!(read_all(&v.0, &names), plain);
}

/// The comment costs exactly one packet in every file and nothing else
/// moves: same file names, same volume count, and each file longer by
/// the packet's own size times the copies that file carries.
#[test]
fn a_comment_adds_one_packet_and_changes_nothing_else() {
    let (with, without) = comment_pair("sizes", "x");
    assert_eq!(with.len(), without.len());
    for (a, b) in with.iter().zip(&without) {
        let grew = a.len() - b.len();
        assert!(grew > 0 && grew.is_multiple_of(64 + 4), "grew by {grew}");
    }
}

/// A non-ASCII comment takes the Unicode packet and nothing lossy
/// happens on the way back.
#[test]
fn a_unicode_comment_round_trips_as_utf16() {
    let (with, _) = comment_pair("uni", "Björk - Vespertine (日本盤)");
    assert_eq!(
        parse(&with).comment.as_deref(),
        Some("Björk - Vespertine (日本盤)")
    );
    let has = |t: &[u8; 16]| with[0].windows(16).any(|w| w == t.as_slice());
    assert!(has(crate::par2::TYPE_COMMUNI), "wrote the Unicode packet");
    assert!(!has(crate::par2::TYPE_COMMASCI), "and only that one");
}

#[test]
fn an_ascii_comment_takes_the_ascii_packet_alone() {
    let (with, _) = comment_pair("ascii", "plain words");
    let has = |t: &[u8; 16]| with[0].windows(16).any(|w| w == t.as_slice());
    assert!(has(crate::par2::TYPE_COMMASCI), "wrote the ASCII packet");
    assert!(!has(crate::par2::TYPE_COMMUNI), "and only that one");
}

/// The write rule IS the read rule: anything this engine will write, it
/// reads back, and anything it will not read back it refuses to write.
/// A comment that round-tripped as something else would be worse than
/// either refusal alone.
#[test]
fn every_comment_this_engine_writes_reads_back() {
    for text in [
        "one line",
        "two\nlines\twith a tab",
        "trailing spaces   ",
        "Björk",
        "\u{1F600} emoji",
        &"x".repeat(MAX_COMMENT_BYTES),
    ] {
        let t = Tmp::new("writes-reads");
        let members = vec![t.write("a.bin", &payload(9_000, 2))];
        let names = create_into_exact_with_comment(
            &t.0,
            &members,
            "cmt",
            Some(4096),
            2,
            CreatePlan::ENGINE,
            Some(text),
        )
        .expect("create");
        assert_eq!(
            parse(&read_all(&t.0, &names)).comment.as_deref(),
            Some(text),
            "{text:?} did not read back"
        );
    }
}

#[test]
fn a_comment_the_reader_would_refuse_is_refused_at_the_create() {
    let t = Tmp::new("refuse");
    let members = vec![t.write("a.bin", &payload(9_000, 2))];
    let create = |c: &str| {
        create_into_exact_with_comment(
            &t.0,
            &members,
            "cmt",
            Some(4096),
            2,
            CreatePlan::ENGINE,
            Some(c),
        )
    };
    for bad in ["esc \u{1b}[2J here", "nul \u{0} here", "bell \u{7}"] {
        let e = create(bad).expect_err("a control character is refused");
        assert!(format!("{e}").contains("control character"), "{e}");
    }
    let e = create(&"x".repeat(MAX_COMMENT_BYTES + 1)).expect_err("over the ceiling");
    assert!(format!("{e}").contains("over the"), "{e}");
}

/// The preview and the create it previews cannot disagree about the
/// comment either - `plan_files` exists precisely so a pane is not a
/// second copy of the packet format.
#[test]
fn the_plan_preview_prices_the_comment_packet() {
    let comment = "a comment long enough to be worth a line in the preview";
    let t = Tmp::new("plan-comment");
    let members = vec![
        t.write("Show.S01E01.mkv", &payload(40_000, 3)),
        t.write("readme.nfo", &payload(9_000, 11)),
    ];
    let names = create_into_exact_with_comment(
        &t.0,
        &members,
        "cmt",
        Some(4096),
        6,
        CreatePlan::ENGINE,
        Some(comment),
    )
    .expect("create");
    let shapes: Vec<(String, u64)> = members
        .iter()
        .map(|m| (m.name.clone(), std::fs::metadata(&m.path).unwrap().len()))
        .collect();
    let planned =
        plan_files_with_comment(&shapes, "cmt", 4096, 6, CreatePlan::ENGINE, Some(comment));
    let on_disk: Vec<(String, u64)> = names
        .iter()
        .map(|n| (n.clone(), std::fs::metadata(t.0.join(n)).unwrap().len()))
        .collect();
    let previewed: Vec<(String, u64)> = planned.iter().map(|f| (f.name.clone(), f.bytes)).collect();
    assert_eq!(previewed, on_disk);
    // And a comment the create would refuse is priced as no comment,
    // matching a plain create rather than inventing a size.
    assert_eq!(
        plan_files_with_comment(
            &shapes,
            "cmt",
            4096,
            6,
            CreatePlan::ENGINE,
            Some("bad \u{1b}")
        ),
        plan_files(&shapes, "cmt", 4096, 6, CreatePlan::ENGINE)
    );
}

// ---- no-clobber: the engine's own O_EXCL door -------------------------

/// The `AlreadyExists` inside a create's error, or a panic naming what
/// it really was. Kept as one helper so all four tests below refuse in
/// the SAME way rather than each settling for "it failed".
fn already_exists_path(e: &Par2GenError) -> PathBuf {
    match e {
        Par2GenError::Io { path, source } if source.kind() == std::io::ErrorKind::AlreadyExists => {
            path.clone()
        }
        other => panic!("expected an AlreadyExists refusal, got {other:?}"),
    }
}

/// The INDEX is the first file of the set the engine creates, so it is
/// where a no-clobber create most often stops - and it must stop there
/// without having touched a byte of what was in the way.
#[test]
fn a_no_clobber_create_refuses_an_existing_index() {
    let t = Tmp::new("noclobber-index");
    let members = vec![t.write("a.bin", &payload(30_000, 3))];
    let theirs = payload(4_096, 91);
    std::fs::write(t.0.join("set.par2"), &theirs).unwrap();

    let e = create_into_exact(
        &t.0,
        &members,
        "set",
        Some(2048),
        4,
        CreatePlan::ENGINE.with_no_clobber(true),
    )
    .expect_err("a no-clobber create must not write over an existing index");
    assert_eq!(already_exists_path(&e), t.0.join("set.par2"));
    assert_eq!(
        std::fs::read(t.0.join("set.par2")).unwrap(),
        theirs,
        "the index was truncated by a create that claimed to refuse it"
    );
}

/// A VOLUME already there, with the index name free: the set whose
/// `.par2` was deleted, which is the shape finding P2 of the 17 Sep
/// 2026 sweep is about. The create gets past the index and must still
/// refuse - and the volume's bytes must survive, which is the whole
/// point of refusing.
#[test]
fn a_no_clobber_create_refuses_an_existing_volume() {
    let t = Tmp::new("noclobber-volume");
    let members = vec![t.write("a.bin", &payload(30_000, 3))];
    let theirs = payload(8_192, 77);
    // The engine's own fixed-width spelling, which is what it opens.
    std::fs::write(t.0.join("set.vol000+01.par2"), &theirs).unwrap();

    let e = create_into_exact(
        &t.0,
        &members,
        "set",
        Some(2048),
        4,
        CreatePlan::ENGINE.with_no_clobber(true),
    )
    .expect_err("a no-clobber create must not write over an existing volume");
    assert_eq!(already_exists_path(&e), t.0.join("set.vol000+01.par2"));
    assert_eq!(
        std::fs::read(t.0.join("set.vol000+01.par2")).unwrap(),
        theirs,
        "a volume of a set whose index had been deleted was destroyed anyway"
    );
}

/// THE CONTROL ARM, and the one that would catch this landing as a
/// behaviour change: the default is still to overwrite, because
/// par2cmdline overwrites and re-running a create is ordinary use.
#[test]
fn the_default_create_still_writes_over_an_existing_set() {
    let t = Tmp::new("clobber-default");
    let members = vec![t.write("a.bin", &payload(30_000, 3))];
    std::fs::write(t.0.join("set.par2"), payload(4_096, 91)).unwrap();
    std::fs::write(t.0.join("set.vol000+01.par2"), payload(8_192, 77)).unwrap();

    let names = create_into_exact(&t.0, &members, "set", Some(2048), 4, CreatePlan::ENGINE)
        .expect("the default create writes over what is there");
    let set = parse(&read_all(&t.0, &names));
    assert_eq!(set.files.len(), 1);
}

/// THE CASE A PREFLIGHT CANNOT COVER, which is why the engine has a
/// door at all: two creates started TOGETHER on one base.
///
/// A caller that stats the directory first answers for the instant it
/// looked; both of these would look, both would see nothing, and both
/// would then truncate the other's files. With the `O_EXCL` open
/// exactly one gets the index and the other stops there.
///
/// A BARRIER and not a sleep: the two threads are released into the
/// create at the same instant by construction, so this fails on a fact
/// rather than on timing. The assertion is on the OUTCOME - one whole
/// readable set, no half-written file - which is what a race leaves
/// wrong however the interleaving fell.
#[test]
fn two_concurrent_no_clobber_creates_leave_exactly_one_whole_set() {
    let t = Tmp::new("noclobber-race");
    let members = vec![
        t.write("a.bin", &payload(60_000, 3)),
        t.write("b.bin", &payload(23_000, 9)),
    ];
    let start = std::sync::Barrier::new(2);
    let results: Vec<Result<Vec<String>, Par2GenError>> = std::thread::scope(|sc| {
        let hs: Vec<_> = (0..2)
            .map(|_| {
                let (dir, members, start) = (&t.0, &members, &start);
                sc.spawn(move || {
                    start.wait();
                    create_into_exact(
                        dir,
                        members,
                        "set",
                        Some(2048),
                        6,
                        CreatePlan::ENGINE.with_no_clobber(true),
                    )
                })
            })
            .collect();
        hs.into_iter()
            .map(|h| h.join().expect("create thread panicked"))
            .collect()
    });

    let winners: Vec<&Vec<String>> = results.iter().filter_map(|r| r.as_ref().ok()).collect();
    let losers: Vec<&Par2GenError> = results.iter().filter_map(|r| r.as_ref().err()).collect();
    assert_eq!(
        winners.len(),
        1,
        "exactly one of two concurrent creates may own the set, got {results:?}"
    );
    already_exists_path(losers[0]);

    // The loser must not have left a truncated file behind, which is
    // the failure a race produces and an exit code does not show: the
    // winner's whole set has to read back through our own parser.
    let set = parse(&read_all(&t.0, winners[0]));
    assert_eq!(set.files.len(), 2);
    // And nothing beyond the winner's own names is sitting in the
    // directory - a refused create writes NO file, not even an empty one.
    let mut on_disk: Vec<String> = std::fs::read_dir(&t.0)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".par2"))
        .collect();
    on_disk.sort();
    let mut want = winners[0].clone();
    want.sort();
    assert_eq!(on_disk, want);
}

// ---- a failed create, and the index it would have replaced ------------
//
// Findings A4, A4b and A28 of the 9 Nov 2026 parfast sweep.

/// Every name in `dir`, sorted - hidden staging names included, which is
/// the point: a leftover staging file is a leftover.
fn listing(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// A create that FAILS - not cancelled - after its index is written must
/// not leave that index behind. It was the placeholder: real set id and
/// names, every hash zero, so every reader parses it and calls each intact
/// member damaged. A DIRECTORY on the first volume's name is the portable
/// way to fail the create between the index and the volumes. Both write
/// policies: no-clobber writes its index straight to the final name, an
/// overwriting create to a staging name, and neither may leave anything.
#[test]
fn a_failed_create_leaves_no_placeholder_index_behind() {
    for no_clobber in [false, true] {
        let t = Tmp::new(if no_clobber {
            "fail-noindex-excl"
        } else {
            "fail-noindex"
        });
        let members = vec![t.write("a.bin", &payload(30_000, 3))];
        std::fs::create_dir(t.0.join("set.vol000+01.par2")).unwrap();
        let e = create_into_exact(
            &t.0,
            &members,
            "set",
            Some(2048),
            4,
            CreatePlan::ENGINE.with_no_clobber(no_clobber),
        )
        .expect_err("a create that cannot write a volume must fail");
        assert_eq!(
            listing(&t.0),
            vec!["a.bin".to_string(), "set.vol000+01.par2".to_string()],
            "no_clobber={no_clobber}: the failed create ({e}) left files behind"
        );
    }
}

/// A4b, the non-cancel half: a RE-CREATE that fails must leave the previous
/// set's index exactly as it was. An overwriting create truncated
/// `<base>.par2` as its first write, so the old index was gone before the
/// new set had a single volume - and the unlink then removed the empty file.
/// The member changes first, so a re-create that ran to the end would write
/// a different index and an unchanged one cannot be the new run's.
#[test]
fn a_failed_re_create_keeps_the_previous_index_whole() {
    let t = Tmp::new("fail-keepindex");
    let members = vec![t.write("a.bin", &payload(30_000, 3))];
    create_into_exact(&t.0, &members, "set", Some(2048), 4, CreatePlan::ENGINE).unwrap();
    let old_index = std::fs::read(t.0.join("set.par2")).unwrap();
    std::fs::write(&members[0].path, payload(30_000, 4)).unwrap();
    std::fs::remove_file(t.0.join("set.vol000+01.par2")).unwrap();
    std::fs::create_dir(t.0.join("set.vol000+01.par2")).unwrap();

    create_into_exact(&t.0, &members, "set", Some(2048), 4, CreatePlan::ENGINE)
        .expect_err("a re-create that cannot write a volume must fail");
    assert_eq!(
        std::fs::read(t.0.join("set.par2")).unwrap(),
        old_index,
        "a failed re-create destroyed the index of the set it was replacing"
    );
    assert!(
        listing(&t.0).iter().all(|n| !n.starts_with(".set.par2.")),
        "a staging file was left behind: {:?}",
        listing(&t.0)
    );
    // And a re-create that FINISHES does replace it.
    std::fs::remove_dir(t.0.join("set.vol000+01.par2")).unwrap();
    let names =
        create_into_exact(&t.0, &members, "set", Some(2048), 4, CreatePlan::ENGINE).unwrap();
    assert_ne!(std::fs::read(t.0.join("set.par2")).unwrap(), old_index);
    assert_eq!(parse(&read_all(&t.0, &names)).files.len(), 1);
    assert!(listing(&t.0).iter().all(|n| !n.starts_with('.')));
}

/// A same-length write to a member past its 16 KiB head, DURING a create
/// on a non-fused route, is refused. Those routes read every member twice
/// - once for the fold, once for the hashes - and compared only the head
/// scan's length and head digest, so a write between the two reads gave a
/// set whose hashes describe the new bytes and whose recovery slices the
/// old: it verifies and cannot repair. The fused arm's twin is
/// `a_same_length_write_during_a_fused_create_is_refused`.
#[test]
fn a_same_length_write_during_a_non_fused_create_is_refused() {
    use std::io::{Seek, SeekFrom, Write};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let t = Tmp::new("nonfused-write");
    let data = payload(4 << 20, 61);
    let member = t.write("m.bin", &data);
    // An mtime well in the past, so the write below moves it even on a
    // filesystem with whole-second timestamps.
    backdate(&member.path);
    let wrote = Arc::new(AtomicBool::new(false));
    // The fused arm emits the same refusal text, so the ROUTE is asserted:
    // only a non-fused create reports member hashing as its own phase
    // (`control`'s module doc - on the fused arm `Verify` never reports).
    let hashed = Arc::new(AtomicBool::new(false));
    let sink = {
        let wrote = wrote.clone();
        let hashed = hashed.clone();
        let path = member.path.clone();
        move |phase: control::CreatePhase, done: u64, _total: u64| {
            if phase == control::CreatePhase::Verify && done > 0 {
                hashed.store(true, Ordering::SeqCst);
            }
            if phase != control::CreatePhase::Fold
                || done == 0
                || wrote.swap(true, Ordering::SeqCst)
            {
                return;
            }
            let mut w = std::fs::File::options()
                .write(true)
                .open(&path)
                .expect("writer");
            w.seek(SeekFrom::Start(1 << 20)).expect("seek");
            w.write_all(&payload(1 << 20, 62)).expect("rewrite");
        }
    };
    let control = control::CreateControl::new(Some(Arc::new(sink)), None);
    let got = create_into_exact_controlled(
        &t.0,
        std::slice::from_ref(&member),
        "set",
        Some(65_536),
        3,
        CreatePlan::ENGINE,
        None,
        &control,
    );
    assert!(
        wrote.load(Ordering::SeqCst),
        "the write was never injected, so this proves nothing"
    );
    assert!(
        hashed.load(Ordering::SeqCst),
        "no Verify progress, so this create took the fused arm and proves nothing here"
    );
    let err = got.expect_err("a create over a member written mid-create must refuse");
    assert!(
        err.to_string()
            .contains("changed while the PAR2 set was being built"),
        "refused, but not by the change check: {err}"
    );
    assert_eq!(listing(&t.0), vec!["m.bin".to_string()]);
}

/// Set `path`'s mtime an hour back.
fn backdate(path: &Path) {
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(3600))
        .unwrap();
}

/// ...and what the change check must NOT refuse: a member whose metadata
/// moved and whose bytes did not. A permission change moves ctime - so do a
/// Finder tag, a last-used-date xattr and a backup tool clearing the
/// archive bit - and a check over ctime (or over a FUSE mount's renumbered
/// inodes) failed a healthy create at its very end and removed the set.
#[cfg(unix)]
#[test]
fn a_metadata_only_change_during_a_create_is_not_a_change() {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let t = Tmp::new("nonfused-chmod");
    let member = t.write("m.bin", &payload(4 << 20, 63));
    backdate(&member.path);
    let touched = Arc::new(AtomicBool::new(false));
    let sink = {
        let touched = touched.clone();
        let path = member.path.clone();
        move |phase: control::CreatePhase, done: u64, _total: u64| {
            if phase == control::CreatePhase::Fold
                && done > 0
                && !touched.swap(true, Ordering::SeqCst)
            {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                    .expect("chmod");
            }
        }
    };
    let control = control::CreateControl::new(Some(Arc::new(sink)), None);
    let names = create_into_exact_controlled(
        &t.0,
        std::slice::from_ref(&member),
        "set",
        Some(65_536),
        3,
        CreatePlan::ENGINE,
        None,
        &control,
    )
    .expect("a chmod mid-create is not a change to the member's bytes");
    assert!(
        touched.load(Ordering::SeqCst),
        "the chmod was never injected"
    );
    assert_eq!(parse(&read_all(&t.0, &names)).files.len(), 1);
}

/// A sink that does `act` (with the output directory) the first time the
/// create sizes its WRITE phase - after the index placeholder is written,
/// before the final rename.
fn on_write_phase(
    dir: PathBuf,
    act: impl Fn(&Path) + Send + Sync + 'static,
) -> control::CreateControl {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let once = AtomicBool::new(false);
    let sink = move |phase: control::CreatePhase, _done: u64, _total: u64| {
        if phase == control::CreatePhase::Write && !once.swap(true, Ordering::SeqCst) {
            act(&dir);
        }
    };
    control::CreateControl::new(Some(Arc::new(sink)), None)
}

/// A rename that fails for a moment (another process holding the old index,
/// an antivirus scanner just after the close) is retried, and the create
/// lands. A DIRECTORY on the final name for 300 ms is the portable stand-in.
#[test]
fn the_final_rename_is_retried_past_a_short_lock() {
    let t = Tmp::new("rename-retry");
    let members = vec![t.write("a.bin", &payload(30_000, 3))];
    let control = on_write_phase(t.0.clone(), |dir| {
        let blocker = dir.join("set.par2");
        std::fs::create_dir(&blocker).unwrap();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(300));
            std::fs::remove_dir(&blocker).unwrap();
        });
    });
    let names = create_into_exact_controlled(
        &t.0,
        &members,
        "set",
        Some(2048),
        4,
        CreatePlan::ENGINE,
        None,
        &control,
    )
    .expect("a lock that clears inside the retry window must not fail the create");
    assert_eq!(parse(&read_all(&t.0, &names)).files.len(), 1);
    assert!(listing(&t.0).iter().all(|n| !n.starts_with('.')));
}

/// A FRESH create whose index cannot take its final name keeps everything:
/// the set is complete by then, it replaces nothing that existed before the
/// run, and removing it would destroy the only copy of the work. The error
/// names the staged index. A directory that appears on the index's name
/// mid-run and never goes is refused by the commit's probe, before any
/// rename - which, for a fresh create, is still a KEEP (`CreateTrail::
/// commit`); the re-create twin below is the case that removes.
#[test]
fn a_final_rename_that_keeps_failing_destroys_nothing() {
    let t = Tmp::new("rename-stuck");
    let members = vec![t.write("a.bin", &payload(30_000, 3))];
    let control = on_write_phase(t.0.clone(), |dir| {
        std::fs::create_dir(dir.join("set.par2")).unwrap();
        std::fs::write(dir.join("set.par2").join("keep"), b"x").unwrap();
    });
    let e = create_into_exact_controlled(
        &t.0,
        &members,
        "set",
        Some(2048),
        4,
        CreatePlan::ENGINE,
        None,
        &control,
    )
    .expect_err("an index that cannot take its name must fail the create");
    let on_disk = listing(&t.0);
    let staged: Vec<&String> = on_disk
        .iter()
        .filter(|n| n.starts_with(".set.par2."))
        .collect();
    assert_eq!(
        staged.len(),
        1,
        "the finished index was removed: {on_disk:?}"
    );
    assert!(
        e.to_string().contains(staged[0].as_str()),
        "the error does not name the staged index: {e}"
    );
    assert!(
        on_disk.iter().any(|n| n.starts_with("set.vol")),
        "the finished volumes were removed: {on_disk:?}"
    );
    assert_eq!(
        std::fs::read(t.0.join("set.par2").join("keep")).unwrap(),
        b"x"
    );
}

/// ...and the same failure through the test seam - the index rename itself
/// refused after its probe passed - keeps the fresh set as well.
#[test]
fn a_fresh_create_whose_index_rename_fails_keeps_its_finished_set() {
    let t = Tmp::new("rename-fresh-seam");
    let members = vec![t.write("a.bin", &payload(30_000, 3))];
    control::rename_faults::fail_onto(&t.0.join("set.par2"));
    let r = create_into_exact(&t.0, &members, "set", Some(2048), 4, CreatePlan::ENGINE);
    control::rename_faults::clear();
    let e = r.expect_err("an index rename that fails must fail the create");
    let on_disk = listing(&t.0);
    let staged: Vec<&String> = on_disk
        .iter()
        .filter(|n| n.starts_with(".set.par2."))
        .collect();
    assert_eq!(
        staged.len(),
        1,
        "the finished index was removed: {on_disk:?}"
    );
    assert!(e.to_string().contains(staged[0].as_str()), "{e}");
    assert_eq!(
        on_disk.iter().filter(|n| n.starts_with("set.vol")).count(),
        3,
        "the finished volumes were removed: {on_disk:?}"
    );
}

/// The RE-CREATE twin: the previous set's index is the one file the commit
/// would replace (the new volumes' names are all new, so only the index is
/// staged), its rename is refused, and nothing has moved - so this run's
/// files go and the previous set is exactly as it was.
#[test]
fn a_re_create_whose_index_rename_fails_leaves_the_previous_set_whole() {
    let reference = CreatePlan::ENGINE.with_naming(VolumeNaming::Reference { std_naming: false });
    let t = Tmp::new("rename-recreate-seam");
    let members = recreate_members(&t, 21);
    let before = previous_set(&t, &members, 5, reference);
    control::rename_faults::fail_onto(&t.0.join("set.par2"));
    let r = create_into_exact(&t.0, &members, "set", Some(2048), 40, reference);
    control::rename_faults::clear();
    r.expect_err("an index rename that fails must fail the create");
    assert_previous_set_whole(&t, &before, "re-create, index rename refused");
}

// ---- an overwriting RE-CREATE that does not finish ----------------------
//
// The handoff's E4 (9 Nov 2026 parfast sweep): the old set's recovery
// VOLUMES were truncated by a re-create's opens and then unlinked by its
// failure cleanup. Every test here holds the WHOLE previous set - index and
// every volume - to its bytes, and the directory to no leftover.

/// Every file in `dir` with its bytes, hidden ones included - the whole of
/// what a create could have touched.
fn snapshot(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut v: Vec<(String, Vec<u8>)> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            let b = std::fs::read(e.path()).unwrap();
            (n, b)
        })
        .collect();
    v.sort();
    v
}

/// [`snapshot`] without the members, which a failing test rewrites on
/// purpose: the SET's files and anything hidden.
fn set_snapshot(dir: &Path) -> Vec<(String, Vec<u8>)> {
    snapshot(dir)
        .into_iter()
        .filter(|(n, _)| n.ends_with(".par2") || n.starts_with('.'))
        .collect()
}

/// Two members, so the create takes a NON-fused route (the fused arm wants
/// one large member) and reads every member twice - which is what lets a
/// member written mid-create fail it at the END, after its volumes are
/// down.
fn recreate_members(t: &Tmp, seed: u8) -> Vec<Member> {
    vec![
        t.write("a.bin", &payload(60_000, seed)),
        t.write("b.bin", &payload(23_000, seed.wrapping_add(1))),
    ]
}

/// The previous set, written by an ordinary create, and its snapshot.
fn previous_set(
    t: &Tmp,
    members: &[Member],
    rows: usize,
    plan: CreatePlan,
) -> Vec<(String, Vec<u8>)> {
    create_into_exact(&t.0, members, "set", Some(2048), rows, plan).expect("the previous set");
    let before = set_snapshot(&t.0);
    assert!(
        before.len() > 3,
        "the previous set is too small to prove anything"
    );
    before
}

/// A control whose sink runs `act` ONCE, at the first WRITE report after a
/// volume has really been written (`done > 0`), and records whether any of
/// this run's staging files were on disk at that moment - the proof that
/// the re-create was writing replacements for the previous set's files
/// when it was stopped, and so that the case reached what it is about.
fn on_a_written_volume(
    dir: PathBuf,
    gate: Option<std::sync::Arc<crate::par2repair::PauseGate>>,
    act: impl Fn() + Send + Sync + 'static,
) -> (
    control::CreateControl,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let staged_seen = Arc::new(AtomicBool::new(false));
    let once = AtomicBool::new(false);
    let seen = staged_seen.clone();
    let sink = move |phase: control::CreatePhase, done: u64, _total: u64| {
        if phase != control::CreatePhase::Write || done == 0 || once.swap(true, Ordering::SeqCst) {
            return;
        }
        let staging = std::fs::read_dir(&dir).unwrap().flatten().any(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n.starts_with(".set.vol") && n.ends_with(".tmp")
        });
        seen.store(staging, Ordering::SeqCst);
        act();
    };
    (
        control::CreateControl::new(Some(Arc::new(sink)), gate),
        staged_seen,
    )
}

/// The previous set's every file byte-identical, and nothing of the run
/// left - the invariant, asserted the one way for every case below.
fn assert_previous_set_whole(t: &Tmp, before: &[(String, Vec<u8>)], what: &str) {
    let after = set_snapshot(&t.0);
    let names = |v: &[(String, Vec<u8>)]| v.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>();
    assert_eq!(
        names(&after),
        names(before),
        "{what}: the directory's set files are not the previous set's (a staging \
         file left, a volume gone, or a new one left behind)"
    );
    for ((n, a), (_, b)) in after.iter().zip(before) {
        assert!(
            a == b,
            "{what}: {n} is not byte-identical to the previous set's"
        );
    }
}

/// A FAILED overwriting re-create - a member written while it ran, refused
/// at the end, after every volume was down - leaves the previous index and
/// every previous volume byte-identical. The same plan both times, so every
/// name of the new set is a name of the old one and every file is staged:
/// the exact shape of the measured loss.
#[test]
fn a_failed_re_create_keeps_every_previous_volume_and_index_byte_identical() {
    let t = Tmp::new("recreate-fail");
    let members = recreate_members(&t, 3);
    for m in &members {
        backdate(&m.path);
    }
    let before = previous_set(&t, &members, 16, CreatePlan::ENGINE);
    let victim = members[0].path.clone();
    let (control, staged_seen) = on_a_written_volume(t.0.clone(), None, move || {
        // Same length, new bytes, a new mtime: the end-of-create check
        // refuses it (`scan::first_changed`).
        std::fs::write(&victim, payload(60_000, 99)).unwrap();
    });
    let e = create_into_exact_controlled(
        &t.0,
        &members,
        "set",
        Some(2048),
        16,
        CreatePlan::ENGINE,
        None,
        &control,
    )
    .expect_err("a re-create over a member that changed must fail");
    assert!(
        e.to_string().contains("changed"),
        "it failed, but not on the injected change: {e}"
    );
    assert!(
        staged_seen.load(std::sync::atomic::Ordering::SeqCst),
        "no staging file existed while the volumes were written, so this re-create never \
         wrote a replacement and proves nothing"
    );
    assert_previous_set_whole(&t, &before, "failed re-create");
}

/// ...and a CANCELLED one, the user's own stop, likewise - cancelled once a
/// volume has really been written.
#[test]
fn a_cancelled_re_create_keeps_every_previous_volume_and_index_byte_identical() {
    let t = Tmp::new("recreate-cancel");
    let members = recreate_members(&t, 5);
    let before = previous_set(&t, &members, 16, CreatePlan::ENGINE);
    std::fs::write(&members[1].path, payload(23_000, 77)).unwrap();
    let gate = crate::par2repair::PauseGate::new();
    let g = gate.clone();
    let (control, staged_seen) = on_a_written_volume(t.0.clone(), Some(gate), move || g.cancel());
    let e = create_into_exact_controlled(
        &t.0,
        &members,
        "set",
        Some(2048),
        16,
        CreatePlan::ENGINE,
        None,
        &control,
    )
    .expect_err("a cancelled re-create must not report success");
    assert!(matches!(e, Par2GenError::Cancelled), "{e:?}");
    assert!(staged_seen.load(std::sync::atomic::Ordering::SeqCst));
    assert_previous_set_whole(&t, &before, "cancelled re-create");
}

/// ...and one that PANICS - the unwind guard, not `settle`, is what runs.
#[test]
fn a_panicking_re_create_keeps_every_previous_volume_and_index_byte_identical() {
    let t = Tmp::new("recreate-panic");
    let members = recreate_members(&t, 7);
    let before = previous_set(&t, &members, 16, CreatePlan::ENGINE);
    std::fs::write(&members[1].path, payload(23_000, 78)).unwrap();
    let (control, staged_seen) = on_a_written_volume(t.0.clone(), None, || {
        panic!("a sink that panics mid-create");
    });
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        create_into_exact_controlled(
            &t.0,
            &members,
            "set",
            Some(2048),
            16,
            CreatePlan::ENGINE,
            None,
            &control,
        )
    }));
    assert!(
        r.is_err(),
        "the create did not unwind, so the guard was never reached"
    );
    assert!(staged_seen.load(std::sync::atomic::Ordering::SeqCst));
    assert_previous_set_whole(&t, &before, "panicking re-create");
}

/// ...and on the FUSED route - one large member whose recovery fits one
/// batch, where the fold's own reader does the hashing - CANCELLED once a
/// volume is down. Forced onto that arm for this thread through
/// `scan::FUSE_FOR_TESTS` (the shipped gate wants hundreds of megabytes),
/// and the arm is PROVEN rather than assumed: only a non-fused create
/// reports member hashing as `Verify` (`control`'s module doc).
#[test]
fn a_cancelled_fused_re_create_keeps_every_previous_volume_and_index_byte_identical() {
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Fused;
    impl Drop for Fused {
        fn drop(&mut self) {
            scan::FUSE_FOR_TESTS.with(|f| f.set(false));
        }
    }
    scan::FUSE_FOR_TESTS.with(|f| f.set(true));
    let _fused = Fused;
    let bs = 1u64 << 20;
    let t = Tmp::new("recreate-fused");
    let members = vec![t.write("m.bin", &payload(12 << 20, 41))];
    create_into_exact(&t.0, &members, "set", Some(bs), 3, CreatePlan::ENGINE).unwrap();
    let before = set_snapshot(&t.0);
    assert!(before.len() >= 3, "{before:?}");
    std::fs::write(&members[0].path, payload(12 << 20, 42)).unwrap();

    let gate = crate::par2repair::PauseGate::new();
    let g = gate.clone();
    let hashed = std::sync::Arc::new(AtomicBool::new(false));
    let h = hashed.clone();
    let staged_seen = std::sync::Arc::new(AtomicBool::new(false));
    let seen = staged_seen.clone();
    let dir = t.0.clone();
    let sink = move |phase: control::CreatePhase, done: u64, _total: u64| {
        if phase == control::CreatePhase::Verify && done > 0 {
            h.store(true, Ordering::SeqCst);
        }
        if phase == control::CreatePhase::Write && done > 0 && !g.is_cancelled() {
            let staged = std::fs::read_dir(&dir).unwrap().flatten().any(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                n.starts_with(".set.vol") && n.ends_with(".tmp")
            });
            seen.store(staged, Ordering::SeqCst);
            g.cancel();
        }
    };
    let control = control::CreateControl::new(Some(std::sync::Arc::new(sink)), Some(gate));
    let e = create_into_exact_controlled(
        &t.0,
        &members,
        "set",
        Some(bs),
        3,
        CreatePlan::ENGINE,
        None,
        &control,
    )
    .expect_err("a cancelled fused re-create must not report success");
    assert!(matches!(e, Par2GenError::Cancelled), "{e:?}");
    assert!(
        !hashed.load(Ordering::SeqCst),
        "the create reported Verify progress, so it took a NON-fused route and this proves \
         nothing about the fused one"
    );
    assert!(
        staged_seen.load(Ordering::SeqCst),
        "no volume was staged when the cancel landed"
    );
    assert_previous_set_whole(&t, &before, "cancelled fused re-create");
}

/// The drop-in CLI's naming over a DIFFERENTLY sliced previous set - the
/// measured shape (`-r5` then `-r30`): the old set's names and the new
/// set's do not coincide at all now that the engine writes the final names
/// (`VolumeNaming`), so the previous set must come through a cancel whole,
/// and come through a SUCCESS untouched too, its stale volumes left where
/// they were (par2cmdline leaves them; nothing here starts deleting them).
#[test]
fn a_differently_sliced_previous_set_survives_a_cancel_and_a_success() {
    let reference = CreatePlan::ENGINE.with_naming(VolumeNaming::Reference { std_naming: false });
    let t = Tmp::new("recreate-sliced");
    let members = recreate_members(&t, 9);
    let before = previous_set(&t, &members, 5, reference);
    let gate = crate::par2repair::PauseGate::new();
    let g = gate.clone();
    let (control, _) = on_a_written_volume(t.0.clone(), Some(gate), move || g.cancel());
    create_into_exact_controlled(
        &t.0,
        &members,
        "set",
        Some(2048),
        40,
        reference,
        None,
        &control,
    )
    .expect_err("cancelled");
    assert_previous_set_whole(&t, &before, "cancelled re-sliced re-create");

    let names = create_into_exact(&t.0, &members, "set", Some(2048), 40, reference).unwrap();
    assert!(listing(&t.0).iter().all(|n| !n.starts_with('.')));
    let after: std::collections::HashMap<String, Vec<u8>> = snapshot(&t.0).into_iter().collect();
    for (n, b) in &before {
        if names.contains(n) {
            continue;
        }
        assert_eq!(
            after.get(n),
            Some(b),
            "{n}, a stale volume of the previous set, was touched"
        );
    }
    assert_eq!(parse(&read_all(&t.0, &names)).recovery_blocks_seen, 40);
}

/// A re-create that SUCCEEDS writes exactly what a fresh create of the same
/// inputs writes: the same names, the same bytes, nothing else - for both
/// namings, over a previous set of the same shape (every file replaced).
#[test]
fn a_successful_re_create_writes_exactly_what_a_fresh_create_writes() {
    for naming in [
        VolumeNaming::Engine,
        VolumeNaming::Reference { std_naming: false },
        VolumeNaming::Reference { std_naming: true },
    ] {
        let plan = CreatePlan::ENGINE.with_naming(naming);
        let over = Tmp::new("recreate-ok-over");
        let fresh = Tmp::new("recreate-ok-fresh");
        let old = recreate_members(&over, 11);
        previous_set(&over, &old, 16, plan);
        let new_over = recreate_members(&over, 12);
        let new_fresh = recreate_members(&fresh, 12);
        let a = create_into_exact(&over.0, &new_over, "set", Some(2048), 16, plan).unwrap();
        let b = create_into_exact(&fresh.0, &new_fresh, "set", Some(2048), 16, plan).unwrap();
        assert_eq!(
            a, b,
            "{naming:?}: the re-create named its files differently"
        );
        assert_eq!(
            snapshot(&over.0),
            snapshot(&fresh.0),
            "{naming:?}: the re-created directory is not the fresh one"
        );
    }
}

/// A rename that fails AFTER others have landed stops there and destroys
/// NOTHING, and says what is left: the volumes already replaced are the new
/// set's, the index (renamed last) is still the previous one, and the new
/// index is still under its staging name, which the error names. The test
/// seam fails exactly that last rename after its probe has passed.
#[test]
fn a_rename_that_fails_midway_destroys_nothing_and_names_what_is_left() {
    let t = Tmp::new("recreate-midway");
    let members = recreate_members(&t, 13);
    let before = previous_set(&t, &members, 16, CreatePlan::ENGINE);
    let old_index = std::fs::read(t.0.join("set.par2")).unwrap();
    std::fs::write(&members[1].path, payload(23_000, 79)).unwrap();
    control::rename_faults::fail_onto(&t.0.join("set.par2"));
    let r = create_into_exact(&t.0, &members, "set", Some(2048), 16, CreatePlan::ENGINE);
    control::rename_faults::clear();
    let e = r.expect_err("a commit whose index rename failed must fail the create");
    assert_eq!(
        std::fs::read(t.0.join("set.par2")).unwrap(),
        old_index,
        "the index is renamed LAST, so the previous one must still be in place"
    );
    let staged: Vec<String> = listing(&t.0)
        .into_iter()
        .filter(|n| n.starts_with(".set.par2."))
        .collect();
    assert_eq!(
        staged.len(),
        1,
        "the finished new index was removed: {:?}",
        listing(&t.0)
    );
    assert!(
        e.to_string().contains(&staged[0]),
        "the error does not name it: {e}"
    );
    // The volumes landed: every one is a NEW volume, and none was removed.
    let after: std::collections::HashMap<String, Vec<u8>> = snapshot(&t.0).into_iter().collect();
    for (n, b) in before.iter().filter(|(n, _)| n.starts_with("set.vol")) {
        let now = after.get(n).unwrap_or_else(|| panic!("{n} was removed"));
        assert_ne!(
            now, b,
            "{n} was not replaced, so the commit stopped earlier than claimed"
        );
    }
}

/// ...while the FIRST rename failing has moved nothing, so it is a commit
/// that never started: the run's own files go and the previous set is
/// exactly as it was.
#[test]
fn a_first_rename_that_fails_leaves_the_previous_set_whole() {
    let t = Tmp::new("recreate-first-rename");
    let members = recreate_members(&t, 15);
    let before = previous_set(&t, &members, 16, CreatePlan::ENGINE);
    std::fs::write(&members[1].path, payload(23_000, 80)).unwrap();
    // The volumes are renamed in name order, so this one is first.
    let first = before
        .iter()
        .map(|(n, _)| n.clone())
        .filter(|n| n.starts_with("set.vol"))
        .min()
        .unwrap();
    control::rename_faults::fail_onto(&t.0.join(&first));
    let r = create_into_exact(&t.0, &members, "set", Some(2048), 16, CreatePlan::ENGINE);
    control::rename_faults::clear();
    r.expect_err("a commit whose first rename failed must fail the create");
    assert_previous_set_whole(&t, &before, "first rename refused");
}

/// A VOLUME of the previous set that the run may not replace (read-only)
/// is refused at the START, before anything is written - the volume
/// twin of `an_index_the_run_may_not_write_is_refused_before_anything_is_written`.
/// And one made read-only DURING the run is refused at the commit's probe,
/// with the previous set whole.
#[cfg(unix)]
#[test]
fn a_previous_volume_the_run_may_not_replace_is_refused_and_kept() {
    use std::os::unix::fs::PermissionsExt;
    let t = Tmp::new("recreate-readonly-volume");
    let members = recreate_members(&t, 17);
    let before = previous_set(&t, &members, 16, CreatePlan::ENGINE);
    let vol = t.0.join(
        before
            .iter()
            .map(|(n, _)| n.clone())
            .find(|n| n.starts_with("set.vol"))
            .unwrap(),
    );
    std::fs::set_permissions(&vol, std::fs::Permissions::from_mode(0o444)).unwrap();
    if std::fs::OpenOptions::new().write(true).open(&vol).is_ok() {
        return; // root: permissions do not bind
    }
    std::fs::write(&members[1].path, payload(23_000, 81)).unwrap();
    let e = create_into_exact(&t.0, &members, "set", Some(2048), 16, CreatePlan::ENGINE)
        .expect_err("a read-only previous volume must refuse the re-create");
    assert!(
        matches!(&e, Par2GenError::Io { source, .. }
            if source.kind() == std::io::ErrorKind::PermissionDenied),
        "{e:?}"
    );
    assert_previous_set_whole(&t, &before, "read-only volume, up front");

    // DURING the run: writable at the start, read-only by the commit.
    std::fs::set_permissions(&vol, std::fs::Permissions::from_mode(0o644)).unwrap();
    let v = vol.clone();
    let (control, _) = on_a_written_volume(t.0.clone(), None, move || {
        std::fs::set_permissions(&v, std::fs::Permissions::from_mode(0o444)).unwrap();
    });
    create_into_exact_controlled(
        &t.0,
        &members,
        "set",
        Some(2048),
        16,
        CreatePlan::ENGINE,
        None,
        &control,
    )
    .expect_err("a volume made read-only mid-run must refuse the commit");
    assert_previous_set_whole(&t, &before, "read-only volume, mid-run");
}

/// A LEFTOVER staging file - what a `kill -9` of an earlier run leaves -
/// neither breaks the next create nor leaks into it, and is NEVER OPENED:
/// the create succeeds, every leftover is byte-identical (it may be another
/// live process's), and the set the next reader scans is the new one alone.
///
/// The leftovers are planted on the very names this process is about to
/// mint - its own pid and the next thousand staging sequence numbers, so
/// creates on other threads advancing the counter meanwhile still leave a
/// collision -
/// beside a dead pid's, so the exclusive staging open is what is tested
/// rather than the luck of a pid that differs.
#[test]
fn a_leftover_staging_file_does_not_break_or_leak_into_the_next_create() {
    let t = Tmp::new("staging-leftover");
    let members = recreate_members(&t, 19);
    previous_set(&t, &members, 8, CreatePlan::ENGINE);
    let pid = std::process::id();
    let next = control::staging_seq_for_tests();
    let mut junk: Vec<(String, Vec<u8>)> = vec![
        (".set.par2.99999-0.tmp".into(), payload(700, 1)),
        (".set.vol000+01.par2.99999-1.tmp".into(), payload(900, 2)),
    ];
    // A thousand: far past what the other tests' creates in this process
    // mint meanwhile (the counter is process-wide, and a 16-wide band was
    // MEASURED to miss under the parallel lib run, passing this test for the
    // wrong reason), and inside the door's cap on passing taken names over.
    for n in next..next + 1024 {
        junk.push((format!(".set.par2.{pid}-{n}.tmp"), payload(64, n as u8)));
        junk.push((
            format!(".set.vol000+01.par2.{pid}-{n}.tmp"),
            payload(80, n as u8),
        ));
    }
    for (n, b) in &junk {
        std::fs::write(t.0.join(n), b).unwrap();
    }
    std::fs::write(&members[0].path, payload(60_000, 20)).unwrap();
    let names = create_into_exact(&t.0, &members, "set", Some(2048), 8, CreatePlan::ENGINE)
        .expect("a re-create beside leftovers on its own next staging names");
    for (n, b) in &junk {
        assert_eq!(&std::fs::read(t.0.join(n)).unwrap(), b, "{n} was opened");
    }
    assert_eq!(
        listing(&t.0).iter().filter(|n| n.starts_with('.')).count(),
        junk.len(),
        "the run left a staging file of its own"
    );
    assert_eq!(parse(&read_all(&t.0, &names)).files.len(), 2);
    // The directory's own reader ignores the leftovers too.
    let status = crate::par2repair::repair_dir(&t.0).expect("verify the directory");
    assert!(
        matches!(status, crate::par2repair::RepairStatus::NoDamage),
        "{status:?}"
    );
}

/// An existing index the run may not write - read-only here, held open
/// without write sharing on Windows - is refused at the START, before a
/// volume is written, as the truncating open used to refuse it. Staging
/// would otherwise find out only at the final rename, or silently replace
/// a read-only file.
#[cfg(unix)]
#[test]
fn an_index_the_run_may_not_write_is_refused_before_anything_is_written() {
    use std::os::unix::fs::PermissionsExt;
    let t = Tmp::new("readonly-index");
    let members = vec![t.write("a.bin", &payload(30_000, 3))];
    let index = t.0.join("set.par2");
    std::fs::write(&index, b"the previous index").unwrap();
    std::fs::set_permissions(&index, std::fs::Permissions::from_mode(0o444)).unwrap();
    if std::fs::OpenOptions::new().write(true).open(&index).is_ok() {
        // Running as root: permissions do not bind, so nothing to refuse.
        return;
    }
    let before = listing(&t.0);
    let e = create_into_exact(&t.0, &members, "set", Some(2048), 4, CreatePlan::ENGINE)
        .expect_err("a read-only index must refuse the create");
    assert!(
        matches!(&e, Par2GenError::Io { source, .. }
            if source.kind() == std::io::ErrorKind::PermissionDenied),
        "{e:?}"
    );
    assert_eq!(listing(&t.0), before, "the refused create wrote something");
    assert_eq!(std::fs::read(&index).unwrap(), b"the previous index");
}

/// A28: a batch of more volumes than `MAX_VOLUME_WRITERS` is written by
/// that many writers at most, each holding one volume open at a time. One
/// thread and one descriptor per volume died on EMFILE past macOS's 256 for
/// a GUI app. A set of many one-slice volumes, all in one batch.
#[test]
fn a_batch_of_many_volumes_spawns_a_bounded_number_of_writers() {
    let t = Tmp::new("many-volumes");
    let members = vec![t.write("a.bin", &payload(60_000, 5))];
    let rows = volwrite::MAX_VOLUME_WRITERS * 3 / 2;
    let names = create_into_exact(
        &t.0,
        &members,
        "set",
        Some(512),
        rows,
        CreatePlan::ENGINE.with_max_blocks_per_volume(Some(1)),
    )
    .unwrap();
    assert_eq!(names.len(), rows + 1, "one volume per recovery slice");
    assert_eq!(parse(&read_all(&t.0, &names)).recovery_blocks_seen, rows);
    let most = volwrite::writers_for_tests::most(&t.0);
    assert!(
        (1..=volwrite::MAX_VOLUME_WRITERS).contains(&most),
        "{most} writers for {rows} volumes"
    );
}

/// ...and the stripe-first arm, which holds EVERY volume open for its whole
/// run, refuses a layout past the same bound and leaves it to the batched
/// writer. The control is the same shape with a handful of volumes, which
/// it admits - otherwise the refusal would be read off some other gate.
#[test]
fn stripe_first_leaves_a_many_volume_layout_to_the_batched_writer() {
    if matches!(std::env::var("NZBFAST_NTT").as_deref(), Ok("0") | Ok("off"))
        || std::env::var("NZBFAST_CREATE_STRIPE_FIRST").as_deref() == Ok("0")
    {
        return;
    }
    let bs = 4096;
    let (slices, rows) = ntt_range::floor_shape_for_tests(bs);
    assert!(
        stripe_first::admissible(2, 8, false, bs, slices, 0, rows).is_some(),
        "the control shape is refused, so the case below proves nothing"
    );
    assert_eq!(
        stripe_first::admissible(
            2,
            volwrite::MAX_VOLUME_WRITERS + 1,
            false,
            bs,
            slices,
            0,
            rows
        ),
        None
    );
}
