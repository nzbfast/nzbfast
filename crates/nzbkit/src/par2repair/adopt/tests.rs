//! Differential tests for the parallel adoption passes (R2 / N11).
//!
//! Both references below are the pre-fan-out code, kept verbatim so the
//! comparison is against the shipped behaviour rather than against a
//! restatement of the new one. What is being defended is not "the repair
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
    for t in targets {
        for (i, c) in t.file.blocks.iter().enumerate() {
            let g = t.first_slice + i;
            if missing_set.contains(&g) && !adopted.contains_key(&g) {
                by_crc.entry(c.crc32).or_default().push(g);
                md5s.insert(g, c.md5);
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
            for &g in slices {
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

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "nzbfast-adopt-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
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
        let _ = std::fs::remove_dir_all(&dir);
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
    let _ = std::fs::remove_dir_all(&dir);
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
    let _ = std::fs::remove_dir_all(&dir);
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
    let _ = std::fs::remove_dir_all(&dir);
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
    let _ = std::fs::remove_dir_all(&dir);
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
    let _ = std::fs::remove_dir_all(&dir);
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
        let _ = std::fs::remove_dir_all(&dir);
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
