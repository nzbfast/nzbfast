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
                let got: Vec<Vec<u8>> = recovery_slices(&slots, bs, n, first, count, budget, None)
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
    // plus the floors that keep the second lane working, rather than two
    // whole ceilings. The floors are the deliberate escape - a late create
    // pays extra passes over its own payload, it never blocks.
    let floors = SCAN_POOL_MIN_BYTES + ACCUM_MIN_BYTES + READ_BUDGET;
    assert!(
        solo.claimed + second.claimed <= ceiling + floors,
        "two lanes claimed {} against a {ceiling} ceiling and {floors} of floors",
        solo.claimed + second.claimed
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
