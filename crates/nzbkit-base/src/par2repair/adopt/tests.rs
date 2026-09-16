//! Differential tests for the parallel adoption passes (R2 / N11).
//!
//! Both references below are the pre-fan-out code, kept verbatim so the
//! comparison is against the shipped behaviour rather than against a
//! restatement of the new one - with ONE later edit, applied to both
//! sides in the same commit: the M4-40 virtual-padding bound (see
//! `scan_candidate`). It had to move here too, because this oracle is a
//! statement about what the SERIAL walk does, and leaving it behind
//! would make the differential test red about a difference nobody
//! introduced. What that costs is stated rather than hidden: a mistake
//! made identically in both copies is invisible to this test, which is
//! why the bound has its own direct pin
//! (`padding_never_donates_a_full_block_from_a_shorter_candidate`) and
//! an e2e row of its own. What is being defended is not "the repair
//! still works" - the end-to-end cases in `unit_tests.rs` cover that -
//! but that the DECISIONS are identical: which candidate a slice is
//! adopted from and at which offset, because both reach the user through
//! `adopted_from` and `consumed_sources`, and a candidate a repair
//! deletes as a spent donor is not a decision that may drift between
//! runs.

use super::*;

// --- the pre-fan-out implementations, kept as oracles ---------------

fn sliding_scan_serial(
    cands: &[(PathBuf, u64)],
    indices: &[usize],
    targets: &[Target],
    missing_set: &HashSet<usize>,
    bs: usize,
    adopted: &mut HashMap<usize, AdoptSrc>,
) {
    let mut by_crc: HashMap<u32, Vec<usize>> = HashMap::new();
    let mut md5s: HashMap<usize, [u8; 16]> = HashMap::new();
    let mut tail: HashMap<usize, usize> = HashMap::new();
    for t in targets {
        for (i, c) in t.file.blocks.iter().enumerate() {
            let g = t.first_slice + i;
            if missing_set.contains(&g) && !adopted.contains_key(&g) {
                by_crc.entry(c.crc32).or_default().push(g);
                md5s.insert(g, c.md5);
                let start = (i as u64) * bs as u64;
                tail.insert(
                    g,
                    crate::disk::chunk_len(t.file.length.saturating_sub(start), bs),
                );
            }
        }
    }
    if by_crc.is_empty() {
        return;
    }
    let mut filter = vec![0u64; 1024];
    for &crc in by_crc.keys() {
        filter[(crc & 0xFFFF) as usize >> 6] |= 1 << (crc & 63);
    }
    let roll = RollingCrc::new(bs);
    let mut remaining = md5s.len();
    for &ci in indices {
        if remaining == 0 {
            break;
        }
        let (p, len) = &cands[ci];
        scan_candidate_serial(
            p,
            *len,
            bs,
            &roll,
            &filter,
            &by_crc,
            &md5s,
            &tail,
            ci,
            adopted,
            &mut remaining,
        );
    }
}

#[expect(clippy::too_many_arguments)]
fn scan_candidate_serial(
    path: &Path,
    len: u64,
    bs: usize,
    roll: &RollingCrc,
    filter: &[u64],
    by_crc: &HashMap<u32, Vec<usize>>,
    md5s: &HashMap<usize, [u8; 16]>,
    tail: &HashMap<usize, usize>,
    cand: usize,
    adopted: &mut HashMap<usize, AdoptSrc>,
    remaining: &mut usize,
) {
    let mut f = File::open(path).expect("candidate opens");
    let mut ring = vec![0u8; bs];
    let mut pos = 0usize;
    let mut reg = 0xFFFF_FFFFu32;
    let mut buf = vec![0u8; 1 << 18];
    let mut i: u64 = 0;
    let total = len + bs as u64 - 1;
    'stream: while i < total {
        let n = if i < len {
            let want = crate::disk::chunk_len(len - i, buf.len());
            f.read(&mut buf[..want]).expect("candidate reads")
        } else {
            let want = crate::disk::chunk_len(total - i, buf.len());
            buf[..want].fill(0);
            want
        };
        assert!(n > 0, "candidate file shrank mid-scan");
        for &b in &buf[..n] {
            let old = ring[pos];
            reg = if i < bs as u64 {
                roll.push(reg, b)
            } else {
                roll.roll(reg, old, b)
            };
            ring[pos] = b;
            pos += 1;
            if pos == bs {
                pos = 0;
            }
            i += 1;
            if i < bs as u64 {
                continue;
            }
            let crc = reg ^ 0xFFFF_FFFF;
            if filter[(crc & 0xFFFF) as usize >> 6] & (1 << (crc & 63)) == 0 {
                continue;
            }
            let Some(slices) = by_crc.get(&crc) else {
                continue;
            };
            if slices.iter().all(|g| adopted.contains_key(g)) {
                continue;
            }
            let mut h = Md5::new();
            h.update(&ring[pos..]);
            h.update(&ring[..pos]);
            let md5: [u8; 16] = h.finalize().into();
            let offset = i - bs as u64;
            let real = len - offset;
            for &g in slices {
                if real < tail[&g] as u64 {
                    continue;
                }
                if md5s[&g] == md5 && !adopted.contains_key(&g) {
                    adopted.insert(g, AdoptSrc { cand, offset });
                    *remaining -= 1;
                    if *remaining == 0 {
                        break 'stream;
                    }
                }
            }
        }
    }
}

/// [`adopt_blocks`]'s whole-file fast path with no prefetch: the lazy,
/// one-file-at-a-time hashing the parallel version has to agree with.
fn adopt_blocks_serial(
    cands: &[(PathBuf, u64)],
    targets: &[Target],
    missing_set: &HashSet<usize>,
    bs: usize,
) -> (Vec<bool>, HashMap<usize, AdoptSrc>) {
    let mut adopted: HashMap<usize, AdoptSrc> = HashMap::new();
    let mut consumed = vec![false; cands.len()];
    let mut head_cache: Vec<Option<[u8; 16]>> = vec![None; cands.len()];
    let mut md5_cache: Vec<Option<[u8; 16]>> = vec![None; cands.len()];
    for t in targets {
        let unidentified = !(t.exists && (t.intact || t.present.iter().any(|&p| p)));
        if t.n_slices == 0 || t.file.length == 0 || !unidentified {
            continue;
        }
        for (ci, (p, len)) in cands.iter().enumerate() {
            if consumed[ci] || *len != t.file.length {
                continue;
            }
            let head = match head_cache[ci] {
                Some(h) => h,
                None => {
                    let h = md5_of_file(p, Some((*len).min(16384))).expect("head hashes");
                    head_cache[ci] = Some(h);
                    h
                }
            };
            if head != t.file.md5_16k {
                continue;
            }
            let whole = match md5_cache[ci] {
                Some(h) => h,
                None => {
                    let h = md5_of_file(p, None).expect("whole hashes");
                    md5_cache[ci] = Some(h);
                    h
                }
            };
            if whole != t.file.md5 {
                continue;
            }
            for i in 0..t.n_slices {
                let g = t.first_slice + i;
                if missing_set.contains(&g) {
                    adopted.entry(g).or_insert(AdoptSrc {
                        cand: ci,
                        offset: i as u64 * bs as u64,
                    });
                }
            }
            consumed[ci] = true;
            break;
        }
    }
    (consumed, adopted)
}

// --- generators -----------------------------------------------------

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next() >> 33) as u8).collect()
    }
}

fn tmpdir(tag: &str) -> crate::testscratch::ScratchDir {
    crate::testscratch::ScratchDir::attach(&std::env::temp_dir().join(format!(
        "nzbfast-adopt-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    )))
}

fn crc32_of(data: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new();
    h.update(data);
    h.finalize()
}

fn md5_of(data: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(data);
    h.finalize().into()
}

/// A synthetic recovery set: `n` targets whose content exists only in
/// the caller's hands, so every slice is "missing" and adoptable.
fn make_targets(rng: &mut Rng, dir: &Path, bs: usize, n: usize) -> (Vec<Target>, Vec<Vec<u8>>) {
    let mut targets = Vec::new();
    let mut contents = Vec::new();
    let mut first_slice = 0usize;
    for ti in 0..n {
        let n_slices = 1 + rng.below(4);
        // One target in three ends mid-slice, so its tail block is only
        // findable through the scan's virtual zero padding.
        let trim = if ti % 3 == 2 {
            1 + rng.below(bs - 1)
        } else {
            0
        };
        let length = (n_slices * bs - trim) as u64;
        let content = rng.bytes(length as usize);
        let mut blocks = Vec::new();
        for i in 0..n_slices {
            let mut blk = vec![0u8; bs];
            let off = i * bs;
            let take = bs.min(content.len() - off);
            blk[..take].copy_from_slice(&content[off..off + take]);
            blocks.push(BlockCheck {
                md5: md5_of(&blk),
                crc32: crc32_of(&blk),
            });
        }
        let head_len = content.len().min(16384);
        let md5_16k = content[..head_len].to_vec();
        targets.push(Target {
            file: Par2File {
                file_id: [ti as u8; 16],
                name: format!("t{ti}.bin"),
                length,
                md5: md5_of(&content),
                md5_16k: md5_of(&md5_16k),
                blocks,
            },
            path: dir.join(format!("t{ti}.bin")),
            first_slice,
            n_slices,
            present: vec![false; n_slices],
            intact: false,
            exists: false,
            resume: None,
            md5_unfinished: false,
        });
        first_slice += n_slices;
        contents.push(content);
    }
    (targets, contents)
}

/// Candidate files stuffed with true slice content at random (often
/// unaligned) offsets, deliberately repeating slices within a file and
/// across files so both tie-breaks - earliest candidate, then earliest
/// offset - actually decide something.
fn make_candidates(
    rng: &mut Rng,
    dir: &Path,
    bs: usize,
    targets: &[Target],
    contents: &[Vec<u8>],
    n: usize,
) -> Vec<(PathBuf, u64)> {
    let mut out = Vec::new();
    for ci in 0..n {
        let lead = rng.below(3 * bs);
        let mut body = rng.bytes(lead);
        for _ in 0..(1 + rng.below(5)) {
            let ti = rng.below(targets.len());
            let si = rng.below(targets[ti].n_slices);
            let off = si * bs;
            let take = bs.min(contents[ti].len() - off);
            body.extend_from_slice(&contents[ti][off..off + take]);
            // A tail slice's checksum covers zero padding; sometimes
            // supply it mid-file so only the padded copy matches.
            if take < bs && rng.below(2) == 0 {
                body.extend(std::iter::repeat_n(0u8, bs - take));
            }
            let gap = rng.below(bs);
            body.extend(rng.bytes(gap));
        }
        let p = dir.join(format!("cand{ci:02}"));
        std::fs::write(&p, &body).unwrap();
        out.push((p, body.len() as u64));
    }
    out.sort();
    out
}

// --- the differential tests ------------------------------------------

#[test]
fn parallel_sliding_scan_reproduces_the_serial_adoption_decisions() {
    let mut adoptions = 0usize;
    let mut donors: HashSet<usize> = HashSet::new();
    for seed in 1..=24u64 {
        let dir = tmpdir(&format!("slide{seed}"));
        let bs = 64;
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let n_targets = 1 + rng.below(4);
        let (targets, contents) = make_targets(&mut rng, &dir, bs, n_targets);
        let n_cands = 2 + rng.below(6);
        let cands = make_candidates(&mut rng, &dir, bs, &targets, &contents, n_cands);
        let total: usize = targets.iter().map(|t| t.n_slices).sum();
        let missing_set: HashSet<usize> = (0..total).filter(|_| rng.below(4) != 0).collect();
        // Every slot, and (the last-resort escalation's shape) a
        // late-starting window over a subset of them.
        for indices in [
            (0..cands.len()).collect::<Vec<_>>(),
            (cands.len() / 2..cands.len()).collect::<Vec<_>>(),
        ] {
            let mut want: HashMap<usize, AdoptSrc> = HashMap::new();
            sliding_scan_serial(&cands, &indices, &targets, &missing_set, bs, &mut want);
            let mut got: HashMap<usize, AdoptSrc> = HashMap::new();
            sliding_scan(&cands, &indices, 0..0, &targets, &missing_set, bs, &mut got).unwrap();
            assert_eq!(
                fmt_adopted(&want),
                fmt_adopted(&got),
                "seed {seed}, indices {indices:?}"
            );
            adoptions += got.len();
            donors.extend(got.values().map(|s| s.cand));
        }
    }
    // The comparison is worthless if the corpus adopts nothing, or
    // always from the same slot - the tie-breaks are the whole subject.
    assert!(adoptions > 100, "only {adoptions} adoptions generated");
    assert!(donors.len() > 4, "donors came from only {:?}", donors);
}

/// Every candidate holds every slice, so all the workers race for the
/// same ordinals at once and the answer is only right if the earliest
/// slot wins every one of them. Files big enough that the scans really
/// do overlap, repeated so a lost race would have to be lucky twice.
#[test]
fn every_worker_racing_for_the_same_slices_still_yields_the_first_slot() {
    let dir = tmpdir("race");
    let bs = 1024;
    let mut rng = Rng(0x7A7A_7A7A_1234_5679);
    let (targets, contents) = make_targets(&mut rng, &dir, bs, 3);
    let total: usize = targets.iter().map(|t| t.n_slices).sum();
    let mut cands: Vec<(PathBuf, u64)> = Vec::new();
    for ci in 0..8 {
        // Padding before the payload differs per file, so every slice
        // sits at a different unaligned offset in every candidate.
        let mut body = rng.bytes(64 * (ci + 1));
        for c in &contents {
            body.extend_from_slice(c);
            body.extend(std::iter::repeat_n(0u8, bs));
        }
        body.extend(rng.bytes(1 << 16));
        let p = dir.join(format!("race{ci:02}"));
        std::fs::write(&p, &body).unwrap();
        cands.push((p, body.len() as u64));
    }
    cands.sort();
    let missing_set: HashSet<usize> = (0..total).collect();
    let indices: Vec<usize> = (0..cands.len()).collect();
    let mut want: HashMap<usize, AdoptSrc> = HashMap::new();
    sliding_scan_serial(&cands, &indices, &targets, &missing_set, bs, &mut want);
    assert_eq!(want.len(), total, "the corpus must cover every slice");
    assert!(
        want.values().all(|s| s.cand == 0),
        "the oracle itself should take everything from the first slot"
    );
    for _ in 0..6 {
        let mut got: HashMap<usize, AdoptSrc> = HashMap::new();
        sliding_scan(&cands, &indices, 0..0, &targets, &missing_set, bs, &mut got).unwrap();
        assert_eq!(fmt_adopted(&want), fmt_adopted(&got));
    }
}

#[test]
fn a_pre_adopted_slice_is_never_re_sourced_by_the_parallel_scan() {
    let dir = tmpdir("pre");
    let bs = 64;
    let mut rng = Rng(0xC0FF_EE12_3456_789D);
    let (targets, contents) = make_targets(&mut rng, &dir, bs, 3);
    let cands = make_candidates(&mut rng, &dir, bs, &targets, &contents, 5);
    let total: usize = targets.iter().map(|t| t.n_slices).sum();
    let missing_set: HashSet<usize> = (0..total).collect();
    // The whole-file fast path's leavings: a couple of slices already
    // sourced elsewhere, which the scan must leave exactly alone.
    let seed_adopted: HashMap<usize, AdoptSrc> = [0usize, total / 2]
        .into_iter()
        .map(|g| {
            (
                g,
                AdoptSrc {
                    cand: usize::MAX,
                    offset: 4242,
                },
            )
        })
        .collect();
    let indices: Vec<usize> = (0..cands.len()).collect();
    let mut want = seed_adopted.clone();
    sliding_scan_serial(&cands, &indices, &targets, &missing_set, bs, &mut want);
    let mut got = seed_adopted.clone();
    sliding_scan(&cands, &indices, 0..0, &targets, &missing_set, bs, &mut got).unwrap();
    assert_eq!(fmt_adopted(&want), fmt_adopted(&got));
    for (g, s) in &seed_adopted {
        assert_eq!(got[g].cand, s.cand, "slice {g} was re-sourced");
    }
}

#[test]
fn the_parallel_scan_is_byte_identical_run_to_run() {
    let dir = tmpdir("stable");
    let bs = 128;
    let mut rng = Rng(0x5151_5151_5151_5151);
    let (targets, contents) = make_targets(&mut rng, &dir, bs, 4);
    let cands = make_candidates(&mut rng, &dir, bs, &targets, &contents, 8);
    let total: usize = targets.iter().map(|t| t.n_slices).sum();
    let missing_set: HashSet<usize> = (0..total).collect();
    let indices: Vec<usize> = (0..cands.len()).collect();
    let mut first: Option<Vec<(usize, usize, u64)>> = None;
    for _ in 0..8 {
        let mut got: HashMap<usize, AdoptSrc> = HashMap::new();
        sliding_scan(&cands, &indices, 0..0, &targets, &missing_set, bs, &mut got).unwrap();
        let s = fmt_adopted(&got);
        match &first {
            None => first = Some(s),
            Some(f) => assert_eq!(f, &s, "adoption drifted between runs"),
        }
    }
}

#[test]
fn a_missing_candidate_still_fails_the_scan() {
    let dir = tmpdir("gone");
    let bs = 64;
    let mut rng = Rng(0x1234_5678_9ABC_DEF1);
    let (targets, contents) = make_targets(&mut rng, &dir, bs, 2);
    let mut cands = make_candidates(&mut rng, &dir, bs, &targets, &contents, 2);
    cands.insert(0, (dir.join("not-there"), 4096));
    let total: usize = targets.iter().map(|t| t.n_slices).sum();
    let missing_set: HashSet<usize> = (0..total).collect();
    let indices: Vec<usize> = (0..cands.len()).collect();
    let mut got: HashMap<usize, AdoptSrc> = HashMap::new();
    let err = sliding_scan(&cands, &indices, 0..0, &targets, &missing_set, bs, &mut got)
        .expect_err("an unreadable candidate is an error, not a silent skip");
    assert!(matches!(err, RepairError::Io(_)), "{err:?}");
}

/// The same vanished file, this time inside the donor range: the slot
/// is dropped and the scan carries on, and the surviving candidates
/// still adopt everything they hold - the file-level half of §293's
/// "a racing cleanup degrades to no-donation, never to a failed
/// repair" (sweep S3: only the directory-level half existed, so a
/// donor file deleted between the walk and the read failed the whole
/// repair through `slot.transpose()?`).
#[test]
fn a_vanished_donor_candidate_is_dropped_not_fatal() {
    let dir = tmpdir("donor-gone");
    let bs = 64;
    let mut rng = Rng(0x1234_5678_9ABC_DEF1);
    let (targets, contents) = make_targets(&mut rng, &dir, bs, 3);
    // Candidates carry only the first two targets' bytes: the third's
    // slices are findable nowhere, so the merge can never early-exit on
    // full coverage - the vanished slot's error is always reached, and
    // this test cannot pass on the strength of the fold's own
    // drop-after-coverage behaviour.
    let mut cands = make_candidates(&mut rng, &dir, bs, &targets[..2], &contents[..2], 2);
    // What the donor walk saw, deleted before the scan reads it - the
    // exact path shape of the race, minus the timing.
    cands.push((dir.join("donor").join("not-there"), 4096));
    let total: usize = targets.iter().map(|t| t.n_slices).sum();
    let missing_set: HashSet<usize> = (0..total).collect();
    let indices: Vec<usize> = (0..cands.len()).collect();
    // What the readable candidates alone would decide.
    let readable: Vec<usize> = (0..cands.len() - 1).collect();
    let mut want: HashMap<usize, AdoptSrc> = HashMap::new();
    sliding_scan_serial(&cands, &readable, &targets, &missing_set, bs, &mut want);
    let mut got: HashMap<usize, AdoptSrc> = HashMap::new();
    sliding_scan(
        &cands,
        &indices,
        cands.len() - 1..cands.len(),
        &targets,
        &missing_set,
        bs,
        &mut got,
    )
    .expect("a vanished donor file must not fail the scan");
    assert_eq!(
        fmt_adopted(&want),
        fmt_adopted(&got),
        "the surviving candidates' decisions must be untouched"
    );
    assert!(!got.is_empty(), "the corpus must actually adopt something");
}

#[test]
fn prefetched_whole_file_adoption_matches_the_lazy_walk() {
    for seed in 1..=12u64 {
        let dir = tmpdir(&format!("whole{seed}"));
        let bs = 64;
        let mut rng = Rng(seed.wrapping_mul(0xD6E8_FEB8_6659_FD93) | 1);
        let n_targets = 1 + rng.below(4);
        let (targets, contents) = make_targets(&mut rng, &dir, bs, n_targets);
        // Renamed copies - some targets present twice under junk names,
        // some absent, plus decoys of the same length and 16k head.
        let mut cands: Vec<(PathBuf, u64)> = Vec::new();
        for (ti, c) in contents.iter().enumerate() {
            for copy in 0..(rng.below(3)) {
                let p = dir.join(format!("junk-{ti}-{copy}"));
                std::fs::write(&p, c).unwrap();
                cands.push((p, c.len() as u64));
            }
            if rng.below(2) == 0 {
                // Same length and same first 16k, different tail: the
                // head prefilter passes and the whole-file MD5 rejects.
                let mut decoy = c.clone();
                *decoy.last_mut().unwrap() ^= 0xFF;
                let p = dir.join(format!("decoy-{ti}"));
                std::fs::write(&p, &decoy).unwrap();
                cands.push((p, decoy.len() as u64));
            }
        }
        cands.sort();
        let total: usize = targets.iter().map(|t| t.n_slices).sum();
        let missing_set: HashSet<usize> = (0..total).collect();
        let (want_consumed, want) = adopt_blocks_serial(&cands, &targets, &missing_set, bs);

        let probing: Vec<&Target> = targets
            .iter()
            .filter(|t| {
                let unidentified = !(t.exists && (t.intact || t.present.iter().any(|&p| p)));
                t.n_slices > 0 && t.file.length > 0 && unidentified
            })
            .collect();
        let mut heads: Vec<Option<[u8; 16]>> = vec![None; cands.len()];
        let mut wholes: Vec<Option<[u8; 16]>> = vec![None; cands.len()];
        prefetch_heads(&cands, &probing, &mut heads);
        prefetch_wholes(&cands, &probing, &heads, &mut wholes);
        for (ci, (p, len)) in cands.iter().enumerate() {
            if let Some(h) = heads[ci] {
                assert_eq!(h, md5_of_file(p, Some((*len).min(16384))).unwrap());
            }
            if let Some(h) = wholes[ci] {
                assert_eq!(h, md5_of_file(p, None).unwrap());
            }
        }
        // A prefetched cache may only ever save the walk a read, so the
        // walk over it must land on the same donors as the lazy one.
        let (got_consumed, got) =
            adopt_blocks_over(&cands, &targets, &missing_set, bs, &heads, &wholes);
        assert_eq!(want_consumed, got_consumed, "seed {seed}");
        assert_eq!(fmt_adopted(&want), fmt_adopted(&got), "seed {seed}");
        // At most one whole-file read per probing target: the "directory
        // of identical copies" shape must not hash every copy.
        assert!(
            wholes.iter().filter(|h| h.is_some()).count() <= probing.len(),
            "seed {seed}: prefetch over-read"
        );
    }
}

/// The shipped matching loop, run over caches the caller supplies - the
/// half of [`adopt_blocks`] the prefetch is not allowed to move.
fn adopt_blocks_over(
    cands: &[(PathBuf, u64)],
    targets: &[Target],
    missing_set: &HashSet<usize>,
    bs: usize,
    heads: &[Option<[u8; 16]>],
    wholes: &[Option<[u8; 16]>],
) -> (Vec<bool>, HashMap<usize, AdoptSrc>) {
    let mut head_cache = heads.to_vec();
    let mut md5_cache = wholes.to_vec();
    let mut adopted: HashMap<usize, AdoptSrc> = HashMap::new();
    let mut consumed = vec![false; cands.len()];
    for t in targets {
        let unidentified = !(t.exists && (t.intact || t.present.iter().any(|&p| p)));
        if t.n_slices == 0 || t.file.length == 0 || !unidentified {
            continue;
        }
        for (ci, (p, len)) in cands.iter().enumerate() {
            if consumed[ci] || *len != t.file.length {
                continue;
            }
            let head = match head_cache[ci] {
                Some(h) => h,
                None => {
                    let h = md5_of_file(p, Some((*len).min(16384))).unwrap();
                    head_cache[ci] = Some(h);
                    h
                }
            };
            if head != t.file.md5_16k {
                continue;
            }
            let whole = match md5_cache[ci] {
                Some(h) => h,
                None => {
                    let h = md5_of_file(p, None).unwrap();
                    md5_cache[ci] = Some(h);
                    h
                }
            };
            if whole != t.file.md5 {
                continue;
            }
            for i in 0..t.n_slices {
                let g = t.first_slice + i;
                if missing_set.contains(&g) {
                    adopted.entry(g).or_insert(AdoptSrc {
                        cand: ci,
                        offset: i as u64 * bs as u64,
                    });
                }
            }
            consumed[ci] = true;
            break;
        }
    }
    (consumed, adopted)
}

/// Adoption decisions as a sorted, printable list, so a mismatch names
/// the slice and the source it drifted to.
fn fmt_adopted(a: &HashMap<usize, AdoptSrc>) -> Vec<(usize, usize, u64)> {
    let mut v: Vec<(usize, usize, u64)> = a.iter().map(|(&g, s)| (g, s.cand, s.offset)).collect();
    v.sort_unstable();
    v
}

/// One target built by hand, so the two halves of the M4-40 rule can be
/// asked separately of the same scan.
fn one_target(dir: &Path, bs: usize, content: &[u8]) -> Vec<Target> {
    let n_slices = content.len().div_ceil(bs);
    let mut blocks = Vec::new();
    for i in 0..n_slices {
        let mut blk = vec![0u8; bs];
        let off = i * bs;
        let take = bs.min(content.len() - off);
        blk[..take].copy_from_slice(&content[off..off + take]);
        blocks.push(BlockCheck {
            md5: md5_of(&blk),
            crc32: crc32_of(&blk),
        });
    }
    let head = &content[..content.len().min(16384)];
    vec![Target {
        file: Par2File {
            file_id: [7u8; 16],
            name: "t.bin".into(),
            length: content.len() as u64,
            md5: md5_of(content),
            md5_16k: md5_of(head),
            blocks,
        },
        path: dir.join("t.bin"),
        first_slice: 0,
        n_slices,
        present: vec![false; n_slices],
        intact: false,
        exists: false,
        resume: None,
        md5_unfinished: false,
    }]
}

fn scan_one(bs: usize, targets: &[Target], cand: &Path) -> HashMap<usize, AdoptSrc> {
    let len = std::fs::metadata(cand).unwrap().len();
    let cands = vec![(cand.to_path_buf(), len)];
    let n: usize = targets.iter().map(|t| t.n_slices).sum();
    let missing: HashSet<usize> = (0..n).collect();
    let mut got: HashMap<usize, AdoptSrc> = HashMap::new();
    sliding_scan(&cands, &[0], 0..0, targets, &missing, bs, &mut got).unwrap();
    got
}

/// M4-40 (no-RAR matrix, third extreme pass). The scan runs `bs - 1`
/// virtual zero bytes past a candidate's EOF so a PAR2 tail slice - whose
/// checksum covers zero padding - is findable at end-of-file. Unbounded,
/// that padding MANUFACTURES content: a one-byte `0x00` file yields
/// exactly one window, all zeros, and could donate any all-zero block of
/// any target. It is not a harmless over-match. `proven_spent`'s
/// fully-donated arm is satisfied by one adoption covering a one-byte
/// file, so the junk was reported spent and deleted - measured
/// end-to-end before the bound
/// (`e2e_norar::a_one_byte_zero_decoy_never_donates_a_full_all_zero_block`).
///
/// Both halves are asked of the same rule, because a bound that kills
/// the legitimate case is not a fix: the padding must still reach a
/// candidate that genuinely ENDS with a target's partial tail block.
#[test]
fn padding_never_donates_a_full_block_from_a_shorter_candidate() {
    let dir = tmpdir("padbound");
    let bs = 64usize;

    // (a) two full blocks, the second all zeros. A one-byte 0x00 file
    // holds one byte of it and 63 bytes of nothing.
    let mut content = vec![0u8; 2 * bs];
    for (i, b) in content[..bs].iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(37).wrapping_add(11) | 1;
    }
    let targets = one_target(&dir, bs, &content);
    let decoy = dir.join("decoy");
    std::fs::write(&decoy, [0u8]).unwrap();
    let got = scan_one(bs, &targets, &decoy);
    assert!(
        got.is_empty(),
        "a 1-byte zero file donated a full all-zero block: {got:?}"
    );
    // The block really is all zeros - the refusal is the bound, not a
    // fixture that never matched. A file of `bs` real zeros holds it.
    let honest = dir.join("honest");
    std::fs::write(&honest, vec![0u8; bs]).unwrap();
    assert_eq!(
        scan_one(bs, &targets, &honest).len(),
        1,
        "the all-zero block is unfindable even in a full block of real zeros"
    );

    // (b) the legitimate padded match: a target ending mid-slice, and a
    // candidate that IS its bytes. The tail block is reachable only
    // through the virtual padding, and must still be reached.
    let partial: Vec<u8> = (0..(bs + bs / 2))
        .map(|i| (i as u8).wrapping_mul(97).wrapping_add(5) | 1)
        .collect();
    let targets = one_target(&dir, bs, &partial);
    let twin = dir.join("twin");
    std::fs::write(&twin, &partial).unwrap();
    let got = scan_one(bs, &targets, &twin);
    assert_eq!(
        got.len(),
        2,
        "the bound ate a genuine partial tail block at the candidate's own EOF: {got:?}"
    );
    assert_eq!(
        got[&1].offset, bs as u64,
        "tail block found at the wrong offset"
    );

    // And the same tail block still matches when the candidate carries
    // it followed by REAL zeros rather than by end-of-file - those are
    // bytes the file has, not bytes the scan invented.
    let mut padded = partial.clone();
    padded.extend(std::iter::repeat_n(0u8, bs));
    let inner = dir.join("inner");
    std::fs::write(&inner, &padded).unwrap();
    assert_eq!(
        scan_one(bs, &targets, &inner).len(),
        2,
        "a real zero-padded copy of the tail block stopped matching"
    );
}

/// Claim `adopt-sniff-window-outlier` (31 Aug 2026) at the ENGINE seam:
/// [`adoption_candidates`] must not offer a prefixed volume as a donor.
///
/// [`is_recovery_by_name_and_content`] is what excludes this
/// directory's own parity from the candidate list, and until this claim
/// it asked for the magic at byte 0 while every other packet sniff in
/// the product asked [`par2::head_is_packet_file`] - the magic
/// BEGINNING within [`par2::SNIFF_WINDOW`], which row M4-65 widened it
/// to because a volume behind a UTF-8 BOM is still the post's parity.
/// So a prefixed volume was recovery data to `collect_packet_files` and
/// a PAYLOAD here, in the same repair. Measured before the fix on a real
/// `repair_dir`: `blocks_adopted: 1`, `adopted_from:
/// ["post.vol000+01.par2"]` - the set's own parity named to the user as
/// a donor.
///
/// That donation is structural rather than a 2^-160 coincidence, which
/// is why it is worth a pin here and not only at the gate: for exponent
/// 0 every input's Reed-Solomon coefficient is 1, so a one-input-block
/// set has a `vol000+01` slice byte-identical to that block, and the
/// sliding scan matches at any offset.
///
/// The far side of the window is the control, exactly as the collect
/// seam's `a_short_prefix_in_front_of_the_magic_does_not_hide_a_volume`
/// pins it: past [`par2::SNIFF_WINDOW`] a file is a candidate again, so
/// this widening cannot be read as "any `.par2` name is skipped" - which
/// is the NAME rule row M4-52 ended and must not come back.
#[test]
fn a_prefixed_volume_is_not_offered_as_an_adoption_source() {
    let dir = tmpdir("adopt-sniff-window");
    let bs = 4096usize;
    let content: Vec<u8> = (0..bs as u32 * 2).map(|i| (i % 251) as u8).collect();
    let targets = one_target(&dir, bs, &content);
    let volume = {
        let mut v = Vec::from(par2::MAGIC.as_slice());
        v.resize(4096, 0u8);
        v
    };
    let behind = |n: usize| -> Vec<u8> {
        let mut v = vec![0xEFu8; n];
        v.extend_from_slice(&volume);
        v
    };
    std::fs::write(dir.join("plain.par2"), &volume).unwrap();
    std::fs::write(dir.join("bom.par2"), {
        let mut v = vec![0xEFu8, 0xBB, 0xBF];
        v.extend_from_slice(&volume);
        v
    })
    .unwrap();
    std::fs::write(dir.join("edge.par2"), behind(par2::SNIFF_WINDOW)).unwrap();
    std::fs::write(dir.join("past.par2"), behind(par2::SNIFF_WINDOW + 1)).unwrap();
    // The M4-52 payload the screen exists to KEEP: the extension
    // nominates, the content decides, and this content denies.
    std::fs::write(dir.join("9f3a1c40b2.par2"), vec![7u8; 210_000]).unwrap();

    let (cands, _) = adoption_candidates(&dir, &[], &targets, &HashSet::new()).expect("walk");
    let names: Vec<String> = cands
        .iter()
        .map(|(p, _)| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert!(
        !names.contains(&"bom.par2".to_string())
            && !names.contains(&"plain.par2".to_string())
            && !names.contains(&"edge.par2".to_string()),
        "a volume within the sniff window is this directory's own parity, \
         prefix or not - offering it to the sliding scan makes one file \
         both the repair's recovery data and its donor: {names:?}"
    );
    assert!(
        names.contains(&"past.par2".to_string()),
        "past the window the sniff denies nothing, so the name cannot be \
         what decides - this is the control against re-reading the \
         extension as proof (M4-52): {names:?}"
    );
    assert!(
        names.contains(&"9f3a1c40b2.par2".to_string()),
        "M4-52's own composition: a payload wearing the extension and \
         carrying no magic is still a donor: {names:?}"
    );
}

// --- the verify-side door: `scan_members_for_blocks` -----------------
//
// G4 of `research/CLI-SUBSTITUTION-2026-09-03.md`: par2cmdline's DEFAULT
// verify rolls a block window over its source files, so a member that
// has been shifted still reports every block present, and `parfast`'s
// aligned-grid pass read the same set as `Found 0 of 30 data blocks`
// where the reference reads `Found 30 of 30`. These pin both halves of
// the door that closed it - what it now finds, and what its length
// screen deliberately declines to look for.

/// One member of a synthetic set, its content, and the paths vector the
/// door takes.
fn one_member(rng: &mut Rng, dir: &Path, bs: usize) -> (Vec<Par2File>, Vec<u8>, PathBuf) {
    let (targets, contents) = make_targets(rng, dir, bs, 1);
    let path = targets[0].path.clone();
    let files: Vec<Par2File> = targets.into_iter().map(|t| t.file).collect();
    (
        files,
        contents.into_iter().next().expect("one member"),
        path,
    )
}

#[test]
fn a_prefixed_member_is_found_at_its_real_offset() {
    let bs = 512;
    let mut rng = Rng(0x5CA7);
    let dir = tmpdir("scan-prefix");
    let (files, content, path) = one_member(&mut rng, &dir, bs);
    let n = files[0].blocks.len();
    // The audit's own shape: junk prepended, so nothing sits on the grid.
    let mut shifted = vec![b'X'; 700];
    shifted.extend_from_slice(&content);
    std::fs::write(&path, &shifted).expect("write shifted member");

    let out = scan_members_for_blocks(&files, &[Some(path)], &[vec![false; n]], bs);
    assert_eq!(
        out[0].iter().filter(|&&ok| ok).count(),
        n,
        "every declared block is in the file, at an offset the aligned grid cannot see"
    );
}

#[test]
fn a_member_at_its_declared_length_is_never_reopened() {
    // THE LENGTH SCREEN, pinned deliberately rather than incidentally:
    // this file DOES carry the missing block, at an unaligned offset,
    // and the scan still does not go looking - because keeping the
    // declared length while moving a block takes an insertion and a
    // deletion that cancel, which is no corruption a download produces
    // and is the one case the screen gives up. See the screen itself.
    let bs = 512;
    let mut rng = Rng(0xD15C);
    let dir = tmpdir("scan-samelen");
    let (files, content, path) = one_member(&mut rng, &dir, bs);
    let n = files[0].blocks.len();
    assert!(n >= 2, "the fixture needs a block to move");
    let mut same: Vec<u8> = vec![b'Z'; 7];
    same.extend_from_slice(&content[..content.len() - 7]);
    assert_eq!(same.len(), content.len(), "the shift kept the length");
    std::fs::write(&path, &same).expect("write same-length member");

    let proven = vec![false; n];
    let out = scan_members_for_blocks(&files, &[Some(path)], std::slice::from_ref(&proven), bs);
    assert_eq!(out[0], proven, "the screen held and nothing was scanned");
}

#[test]
fn a_fully_proven_set_opens_nothing() {
    // The clean verify. Every path below is a file that does not exist,
    // so anything that opened one would fail the run rather than pass it.
    let bs = 512;
    let mut rng = Rng(0xC1EA);
    let dir = tmpdir("scan-clean");
    let (files, _content, path) = one_member(&mut rng, &dir, bs);
    let n = files[0].blocks.len();
    assert!(!path.exists(), "the fixture never wrote this member");

    let out = scan_members_for_blocks(&files, &[Some(path)], &[vec![true; n]], bs);
    assert_eq!(out[0], vec![true; n]);
}

#[test]
fn a_blocks_neighbour_credits_the_member_that_declares_it() {
    // A block is credited to its OWNER wherever it is found, which is
    // what lets one member's shifted copy account for another's slice.
    let bs = 512;
    let mut rng = Rng(0xBEE7);
    let dir = tmpdir("scan-neighbour");
    let (targets, contents) = make_targets(&mut rng, &dir, bs, 2);
    let files: Vec<Par2File> = targets.iter().map(|t| t.file.clone()).collect();
    let counts: Vec<usize> = files.iter().map(|f| f.blocks.len()).collect();
    // Member 0 is missing outright; member 1's file carries BOTH bodies
    // behind a prefix, so its length is not its declared one either.
    let mut both = vec![b'Q'; 33];
    both.extend_from_slice(&contents[0]);
    both.extend_from_slice(&contents[1]);
    std::fs::write(&targets[1].path, &both).expect("write the carrier");

    let out = scan_members_for_blocks(
        &files,
        &[None, Some(targets[1].path.clone())],
        &[vec![false; counts[0]], vec![false; counts[1]]],
        bs,
    );
    assert_eq!(
        out[0].iter().filter(|&&ok| ok).count(),
        counts[0],
        "the absent member's blocks are credited to it, found in a neighbour's file"
    );
    assert_eq!(out[1].iter().filter(|&&ok| ok).count(), counts[1]);
}

// --- within-candidate chunking (16 Sep 2026) -------------------------
//
// Claim `par2-adoption-scan-within-candidate-16sep`. The tests above
// hold the fan-out ACROSS candidates to the serial oracle; these hold
// the fan-out WITHIN one to the same oracle, and to the narrow path on
// the same bytes. `sliding_scan_planned` is what makes that comparable:
// production sizes a chunk at `min_scan_chunk(bs)` - megabytes - so a
// fixture that could be scanned both ways in a unit test would never be
// split at all, and a test that built a real one would be measuring the
// disk. The floor is passed in instead, so these run the SAME code the
// repair runs with the only free parameter turned down.

/// Every candidate split every way it can be, against the pre-fan-out
/// serial walk, over the corpus whose whole purpose is that both
/// tie-breaks - earliest candidate, then earliest offset - decide
/// something. A chunk boundary landing mid-slice is the case this is
/// really about: the window that straddles it belongs to the unit
/// BEFORE it, and is the one an off-by-one loses.
#[test]
fn chunking_one_candidate_reproduces_the_serial_adoption_decisions() {
    let mut adoptions = 0usize;
    let mut split_units = 0usize;
    for seed in 1..=24u64 {
        let dir = tmpdir(&format!("chunk{seed}"));
        let bs = 64;
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let n_targets = 1 + rng.below(4);
        let (targets, contents) = make_targets(&mut rng, &dir, bs, n_targets);
        let n_cands = 2 + rng.below(6);
        let cands = make_candidates(&mut rng, &dir, bs, &targets, &contents, n_cands);
        let total: usize = targets.iter().map(|t| t.n_slices).sum();
        let missing_set: HashSet<usize> = (0..total).filter(|_| rng.below(4) != 0).collect();
        let indices: Vec<usize> = (0..cands.len()).collect();

        let mut want: HashMap<usize, AdoptSrc> = HashMap::new();
        sliding_scan_serial(&cands, &indices, &targets, &missing_set, bs, &mut want);
        adoptions += want.len();

        // Floors from one byte (every candidate cut as finely as the
        // width allows, boundaries all over the payload) up past the
        // fixture's whole length (no cut at all - the control).
        for floor in [1u64, 7, 64, 97, 1 << 20] {
            for width in [1usize, 2, 3, 8, 32] {
                let units = plan_units(&cands, &indices, width, floor);
                split_units += units.len() - indices.len();
                let mut got: HashMap<usize, AdoptSrc> = HashMap::new();
                sliding_scan_planned(
                    &cands,
                    &indices,
                    0..0,
                    &targets,
                    &missing_set,
                    bs,
                    &mut got,
                    width,
                    floor,
                )
                .unwrap();
                assert_eq!(
                    fmt_adopted(&want),
                    fmt_adopted(&got),
                    "seed {seed}, width {width}, floor {floor}"
                );
            }
        }
    }
    // Measured 95 over these 24 seeds; the bar is under it so an
    // unrelated change to the generator does not red this, and well
    // clear of zero so a corpus that stopped adopting does.
    assert!(adoptions > 80, "only {adoptions} adoptions generated");
    // The comparison is worthless if nothing was ever actually split.
    assert!(split_units > 1000, "only {split_units} extra units planned");
}

/// The shape the claim is about: ONE wholly-unidentified member, so the
/// across-candidate fan-out has nothing to fan out over. The narrow
/// path and the wide one must name the same source at the same offset
/// for every slice, because both reach the user - `adopted_from` feeds
/// the shortfall accounting and `consumed_sources` decides which files
/// a repair may delete.
#[test]
fn a_single_candidate_scanned_wide_names_the_same_sources_as_narrow() {
    let dir = tmpdir("chunk-one");
    let bs = 256;
    let mut rng = Rng(0x5EED_0001);
    let (targets, contents) = make_targets(&mut rng, &dir, bs, 3);
    let total: usize = targets.iter().map(|t| t.n_slices).sum();
    // One donor holding every slice, each body repeated so the
    // earliest-offset tie-break has something to decide, and at an
    // unaligned lead so no hit sits on a chunk boundary by luck.
    let mut body = rng.bytes(37);
    for _ in 0..3 {
        for c in &contents {
            body.extend_from_slice(c);
            body.extend(std::iter::repeat_n(0u8, bs));
            body.extend(rng.bytes(13));
        }
    }
    let p = dir.join("lone-donor.bin");
    std::fs::write(&p, &body).unwrap();
    let cands = vec![(p, body.len() as u64)];
    let indices = vec![0usize];
    let missing_set: HashSet<usize> = (0..total).collect();

    let mut narrow: HashMap<usize, AdoptSrc> = HashMap::new();
    sliding_scan_planned(
        &cands,
        &indices,
        0..0,
        &targets,
        &missing_set,
        bs,
        &mut narrow,
        1,
        u64::MAX,
    )
    .unwrap();
    assert_eq!(narrow.len(), total, "the lone donor holds every slice");
    // ...and it is genuinely one unit at production sizing, which is
    // the defect this claim was opened on.
    assert_eq!(
        plan_units(&cands, &indices, 8, min_scan_chunk(bs)).len(),
        1,
        "a fixture this small is below the production chunk floor"
    );

    for width in [2usize, 4, 8, 16] {
        let units = plan_units(&cands, &indices, width, 64);
        assert!(units.len() > 1, "width {width} planned no split");
        // The ranges partition the file, in ascending order, with no
        // gap and no overlap - the property the merge's "first unit
        // wins is first offset wins" rests on.
        let mut at = 0u64;
        for u in &units {
            assert_eq!(u.start, at, "width {width} left a gap or overlapped");
            assert!(u.end > u.start, "width {width} planned an empty unit");
            at = u.end;
        }
        assert_eq!(
            at,
            body.len() as u64,
            "width {width} did not cover the file"
        );

        let mut wide: HashMap<usize, AdoptSrc> = HashMap::new();
        sliding_scan_planned(
            &cands,
            &indices,
            0..0,
            &targets,
            &missing_set,
            bs,
            &mut wide,
            width,
            64,
        )
        .unwrap();
        assert_eq!(
            fmt_adopted(&narrow),
            fmt_adopted(&wide),
            "width {width} changed a source or an offset"
        );
    }
}

/// The M4-40 virtual-padding bound is a statement about the FILE's end,
/// and a chunk boundary must not move it. A candidate that is one
/// target's tail slice and nothing else donates that slice through its
/// own zero padding at EOF; split the same file and the interior units
/// must still see real bytes where the last unit sees padding, so the
/// answer cannot change and no unit may manufacture a block.
#[test]
fn chunk_boundaries_do_not_move_the_virtual_padding() {
    let dir = tmpdir("chunk-pad");
    let bs = 128;
    let mut rng = Rng(0x0BAD_F00D);
    let (targets, contents) = make_targets(&mut rng, &dir, bs, 3);
    let total: usize = targets.iter().map(|t| t.n_slices).sum();
    // A carrier that ENDS on a target's content, so its final windows
    // are the zero-padded ones, plus a long zero run in the middle that
    // an over-eager interior unit would happily call an all-zero block.
    let mut body = rng.bytes(5);
    body.extend(std::iter::repeat_n(0u8, 4 * bs));
    body.extend(rng.bytes(3));
    body.extend_from_slice(contents.last().unwrap());
    let p = dir.join("tail-carrier.bin");
    std::fs::write(&p, &body).unwrap();
    let cands = vec![(p, body.len() as u64)];
    let indices = vec![0usize];
    let missing_set: HashSet<usize> = (0..total).collect();

    let mut want: HashMap<usize, AdoptSrc> = HashMap::new();
    sliding_scan_serial(&cands, &indices, &targets, &missing_set, bs, &mut want);
    assert!(!want.is_empty(), "the carrier donates its tail slice");
    for width in [1usize, 2, 5, 9] {
        for floor in [1u64, 16, 128] {
            let mut got: HashMap<usize, AdoptSrc> = HashMap::new();
            sliding_scan_planned(
                &cands,
                &indices,
                0..0,
                &targets,
                &missing_set,
                bs,
                &mut got,
                width,
                floor,
            )
            .unwrap();
            assert_eq!(
                fmt_adopted(&want),
                fmt_adopted(&got),
                "width {width}, floor {floor}"
            );
        }
    }
}

/// The plan is one unit per candidate whenever there are at least
/// `width` of them, which is what keeps the ordinary many-candidate
/// repair on byte-for-byte the code it had before this change.
#[test]
fn a_wide_enough_candidate_list_is_never_split() {
    let dir = tmpdir("chunk-plan");
    let cands: Vec<(PathBuf, u64)> = (0..8)
        .map(|i| (dir.join(format!("c{i}")), 1u64 << 30))
        .collect();
    let indices: Vec<usize> = (0..cands.len()).collect();
    for width in [1usize, 2, 8] {
        let units = plan_units(&cands, &indices, width, 1);
        assert_eq!(
            units.len(),
            indices.len(),
            "width {width} split a full list"
        );
        for (pos, u) in units.iter().enumerate() {
            assert_eq!(
                *u,
                ScanUnit {
                    pos,
                    start: 0,
                    end: 1 << 30
                }
            );
        }
    }
    // One candidate short of the width, and it splits.
    let narrow: Vec<usize> = (0..7).collect();
    assert!(plan_units(&cands, &narrow, 8, 1).len() > narrow.len());
}

/// The chunk floor's OVERLAP BUDGET, pinned at the corner the 16 Sep
/// measurement moved. `min_scan_chunk` is `max(M * bs, 4 MiB)`, and `M`
/// is the reciprocal of the reread a floor-limited split is allowed to
/// pay - so this test is about the multiple, not about a length.
///
/// The 192 MiB / 16 MiB candidate is the shape
/// `research/PAR2-ADOPTION-WITHIN-CANDIDATE-2026-09-16.md` named as
/// getting nothing from the within-candidate split: 12 blocks, which at
/// `M = 8` could not clear twice the floor and ran on one core.
#[test]
fn the_chunk_floor_splits_the_large_block_corner() {
    let bs = 16usize << 20;
    let len = 192u64 << 20;
    let cands = vec![(PathBuf::from("c.bin"), len)];
    let indices = vec![0usize];
    let units = plan_units(&cands, &indices, 8, min_scan_chunk(bs));
    assert_eq!(
        units.len(),
        3,
        "a 12-block candidate must reach a three-way cut"
    );
    // The budget itself: a floor-limited cut may not pay more than
    // `1 / M` of the candidate in straddle reread.
    let reread = (units.len() as u64 - 1) * (bs as u64 - 1);
    assert!(
        reread * 4 <= len,
        "a floor-limited cut paid more than a quarter in reread"
    );
    // And which of the two terms binds where: the 4 MiB floor on small
    // blocks, the multiple on large ones.
    assert_eq!(min_scan_chunk(512 << 10), 4 << 20);
    assert_eq!(min_scan_chunk(16 << 20), 64 << 20);
}

// --- the timing rig for the two sliding-scan constants ---------------

/// Prices [`min_scan_chunk`]'s block multiple and [`adoption_fanout`]'s
/// `.min(8)` cap, for `research/PAR2-ADOPTION-WITHIN-CANDIDATE-2026-09-16.md`
/// (claim `adoption-fanout-constants-measure-16sep`). Kept so the next
/// sweep of either constant does not rebuild it.
///
/// THE SWEEP IS OVER CHUNK COUNT, NOT OVER THE FLOOR, and the two are
/// the same sweep: for one candidate `plan_units` computes
/// `chunks = min(width, len / floor)`, so the floor's whole job is to
/// pick a chunk count and the cap's whole job is to bound it. Driving
/// `sliding_scan_planned(width = c, floor = 1)` forces exactly `c`
/// chunks, which turns a two-constant question into one curve.
///
/// The donor holds NONE of the wanted slices. That is the deterministic
/// case - no CRC hit, so no MD5, no `covered` early exit, and the whole
/// file walked identically in every arm - and it is also the worst case
/// the scan actually pays, since a candidate that donates nothing is
/// still read to the end.
///
/// BOTH WALL AND CPU ARE REPORTED, because only one of them is readable
/// on a shared box: `cpu` (getrusage, whole process, and this rig is
/// the only thing in it at `--test-threads=1`) measures WORK and so
/// prices the straddle overlap and the per-unit fixed cost under any
/// load, while `wall` prices the parallel speedup and is only
/// meaningful with cores going spare. `load` is the 1-minute loadavg,
/// carried on every record so a reader can tell which column to trust.
///
/// RUN (release, or the per-byte rate is the debug build's and no rung
/// means anything):
///
/// ```text
/// ADOPT_RIG_BS=16777216 ADOPT_RIG_MB=192 ADOPT_RIG_CHUNKS=1,2,3,4,6,8,12,16 \
/// ADOPT_RIG_REPS=5 cargo test -p nzbkit-base --lib --release \
///   --features test-support rig_sliding_scan_costs -- --ignored --nocapture
/// ```
#[test]
#[ignore = "timing rig - read the header for the env and which column to trust"]
fn rig_sliding_scan_costs() {
    fn envn(k: &str, d: usize) -> usize {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    }
    /// The rig's load-robust column, taken from `crate::mem` and NOT
    /// from a `getrusage` of this module's own.
    ///
    /// `getrusage` does not exist on Windows, and `windows-build` /
    /// `windows-clippy` compile `--all-targets`, so a private copy in a
    /// `#[cfg(test)]` module is enough to hold both jobs red - and
    /// because `windows-unit` is `needs:`-gated on the build, the whole
    /// Windows TEST SUITE then reads `skipped` rather than red, which is
    /// not a pass. Nothing on this fleet catches that locally: every
    /// documented gate line is host-target, which is why
    /// `tools/win-portability-gate.py` exists.
    ///
    /// This is the SECOND time the same trap has been walked into here:
    /// `cpu_user_sys_secs`'s own doc records `tests/delivery_cost.rs`
    /// doing it, and this rig repeated it on 16 Sep 2026 (claim
    /// `red-rust-gates-655000bf`). The helper carries real unix AND
    /// Windows arms, so asking it costs the rig nothing.
    fn cpu_secs() -> Option<f64> {
        crate::mem::cpu_time_secs()
    }

    /// One-minute load average - CONTEXT on the reading above, never a
    /// column a conclusion rests on. The rig's finding is read off
    /// `cpu`, which is load-robust by construction, so a target without
    /// a load average loses context and no result.
    ///
    /// There is no portable helper for this and `getloadavg` is unix
    /// only, so elsewhere it is simply ABSENT - and absent prints as
    /// JSON `null`, not as `NaN`. A number-shaped value in a numeric
    /// column is a fabricated reading a later pass cannot tell from a
    /// real one, and `NaN` is not legal JSON either, so a reader would
    /// have to guess twice to get back to "there was no reading".
    fn load1() -> Option<f64> {
        #[cfg(unix)]
        {
            let mut a = [0f64; 3];
            // SAFETY: getloadavg writes at most 3 doubles through the pointer.
            if unsafe { libc::getloadavg(a.as_mut_ptr(), 3) } >= 1 {
                return Some(a[0]);
            }
        }
        None
    }

    /// A reading as a JSON number, or `null` when there was none.
    fn num(v: Option<f64>, prec: usize) -> String {
        v.map_or_else(|| "null".to_string(), |x| format!("{x:.prec$}"))
    }

    let bs = envn("ADOPT_RIG_BS", 1 << 20);
    let len = (envn("ADOPT_RIG_MB", 192) as u64) << 20;
    let reps = envn("ADOPT_RIG_REPS", 3);
    let chunks: Vec<usize> = std::env::var("ADOPT_RIG_CHUNKS")
        .unwrap_or_else(|_| "1,2,4,8".into())
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    assert!(!chunks.is_empty(), "ADOPT_RIG_CHUNKS named no arm");

    let dir = tmpdir("scanrig");
    let p = dir.join("donor.bin");
    let mut rng = Rng(0xA00D_0001);
    {
        use std::io::Write;
        let mut f = std::io::BufWriter::new(std::fs::File::create(&p).unwrap());
        let mut left = len;
        while left > 0 {
            let n = (1u64 << 20).min(left) as usize;
            f.write_all(&rng.bytes(n)).unwrap();
            left -= n as u64;
        }
        f.flush().unwrap();
    }

    // Wanted slices whose CRCs no random donor window will carry, so the
    // scan is a full pass with no MD5 and no early exit. A fabricated
    // `Target` is enough: the scan reads a target's blocks and length
    // and never opens its file.
    let n_slices = 64usize;
    let blocks: Vec<BlockCheck> = (0..n_slices)
        .map(|_| {
            let mut md5 = [0u8; 16];
            for b in md5.iter_mut() {
                *b = (rng.next() >> 33) as u8;
            }
            md5[0] |= 1; // never the UNPROVEN placeholder
            BlockCheck {
                md5,
                crc32: rng.next() as u32,
            }
        })
        .collect();
    let targets = vec![Target {
        file: Par2File {
            file_id: [7u8; 16],
            name: "rig.bin".into(),
            length: n_slices as u64 * bs as u64,
            md5: [0u8; 16],
            md5_16k: [0u8; 16],
            blocks,
        },
        path: dir.join("rig.bin"),
        first_slice: 0,
        n_slices,
        present: vec![false; n_slices],
        intact: false,
        exists: false,
        resume: None,
        md5_unfinished: false,
    }];
    let missing_set: HashSet<usize> = (0..n_slices).collect();
    let cands = vec![(p, len)];
    let indices = vec![0usize];

    for rep in 0..reps {
        // Arms mirrored within a rep, so a box drifting under us cannot
        // favour one end of the ladder.
        let mut order = chunks.clone();
        if rep % 2 == 1 {
            order.reverse();
        }
        for &c in &order {
            let units = plan_units(&cands, &indices, c, 1);
            let total = len + bs as u64 - 1;
            let bytes: u64 = units
                .iter()
                .map(|u| (u.end + bs as u64 - 1).min(total) - u.start)
                .sum();
            let mut adopted: HashMap<usize, AdoptSrc> = HashMap::new();
            let (w0, c0, l0) = (std::time::Instant::now(), cpu_secs(), load1());
            sliding_scan_planned(
                &cands,
                &indices,
                0..0,
                &targets,
                &missing_set,
                bs,
                &mut adopted,
                c,
                1,
            )
            .unwrap();
            let wall = w0.elapsed().as_secs_f64();
            let cpu = cpu_secs().zip(c0).map(|(now, then)| now - then);
            assert!(adopted.is_empty(), "the rig donor must adopt nothing");
            println!(
                "RIG {{\"rep\":{rep},\"bs\":{bs},\"len\":{len},\"chunks\":{c},\
                 \"units\":{},\"bytes\":{bytes},\"wall\":{wall:.4},\"cpu\":{},\
                 \"load0\":{},\"load1\":{}}}",
                units.len(),
                num(cpu, 4),
                num(l0, 1),
                num(load1(), 1)
            );
        }
    }
}
