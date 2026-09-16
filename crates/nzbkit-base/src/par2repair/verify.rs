//! The verify half of the repair: the parallel block-hash pass that
//! answers per-block presence, the pass-1 whole-file verdict and the
//! resume snapshot it leaves behind, and the final `md5_matches` proof
//! a patched member has to clear before it is published.
//!
//! Split out of `par2repair.rs` on 10 Sep 2026, when that file stood at
//! 3,999 lines against the size gate's 4,000-line production ceiling -
//! one line free, and two lanes that week had already routed around it
//! (claim `par2repair-file-split-10sep`). This is a contiguous lift:
//! the bodies, and every measured finding and incident note in their
//! comments, moved verbatim. Only the visibility words are new, because
//! a child module's items have to be spelled `pub(super)` to stay
//! reachable from the parent they were written in.

use super::*;

/// Per-worker read-chunk size for the parallel block-hash pass. Blocks
/// larger than this are streamed through the chunk incrementally, so
/// the buffer bound holds whatever the wire-supplied block size is
/// (`bs` goes up to [`crate::par2::MAX_BLOCK_SIZE`], 256 MiB).
pub(super) const HASH_CHUNK: usize = 4 << 20;
/// Small proved slices can share one positioned read. Keep the window below
/// the normal streaming chunk: this is large enough to amortize syscall and
/// `FileExt` overhead without charging sparse IFSC grids for dense buffers.
pub(super) const HASH_POSITIONED_WINDOW: usize = 512 << 10;
/// Ceiling on total chunk-buffer bytes across hash workers - the same
/// role the partials budget plays for the download path: parallelism
/// must never buy unbounded reader memory. 16 workers x 4 MiB.
pub(super) const HASH_POOL_BYTES: usize = 64 << 20;
/// Below this many readable bytes the thread fan-out is not worth its
/// setup; the serial single-pass scanner keeps the small-file path.
#[cfg(not(fuzzing))]
pub(super) const HASH_PAR_MIN_BYTES: u64 = 8 << 20;
/// Under cargo-fuzz the gate drops to 8 KiB. `par2_verify_diff` exists to
/// prove the two verify paths cannot disagree, and a gate it can only
/// cross by writing 8 MiB per case would cost ~30 executions a second -
/// the parallel branch would be fuzzed at a rate that finds nothing. The
/// threshold is a performance choice, not part of the verdict rule, so
/// lowering it changes which path answers and never what it answers.
#[cfg(fuzzing)]
pub(super) const HASH_PAR_MIN_BYTES: u64 = 8 << 10;

/// The pool gate, readable from outside the crate so `par2_verify_diff`
/// can assert it is small enough for the files that target writes. The
/// failure this guards is silent: if `--cfg fuzzing` ever stops reaching
/// this crate, the gate goes back to 8 MiB, every generated case takes
/// the serial path, and the differential keeps passing while proving
/// nothing about the parallel one.
#[doc(hidden)]
pub fn hash_par_min_bytes() -> u64 {
    HASH_PAR_MIN_BYTES
}

/// Per-block CRC32 presence for one file, across a worker pool.
///
/// `crc_ok[i]` reproduces the serial scanner's presence decision
/// exactly: full blocks close at `bs`, the tail extends through its
/// zero padding via `crc32_zeros`, and a block whose declared bytes are
/// not all on disk is damage by definition and stays false.
///
/// PRESENCE only. This pool used to also check the per-block IFSC MD5s
/// and hand back "every block matched" as a whole-file verdict (§129),
/// which is a claim about the IFSC list, not about the FileDesc MD5 the
/// contract names - see [`verify_pass1`] and [`md5_matches`] for why
/// that stopped being a verdict (H7). Presence needs no such premise:
/// it is defined by the IFSC CRC32s, so it is the pool's to answer.
///
/// `limit` is how many bytes are readable (min of declared length and
/// disk length); `threads` is this file's share of the machine. The calling
/// file-level worker hashes range zero and only the remaining ranges become
/// child threads, so nested file-level and block-level pools stay inside that
/// share. On Windows each child owns a separate handle because its positioned
/// read compatibility primitive moves the handle cursor.
pub(super) fn hash_blocks_par(
    _path: &Path,
    _source: &File,
    limit: u64,
    length: u64,
    blocks: &[BlockCheck],
    bs: usize,
    threads: usize,
) -> Result<Vec<bool>, RepairError> {
    let n_slices = length.div_ceil(bs as u64) as usize;
    if n_slices == 0 {
        return Ok(Vec::new());
    }
    let mut crc_ok = vec![false; n_slices];
    let diagnostic_slices = hash_diagnostic_slice_count(&blocks[..blocks.len().min(n_slices)]);
    if diagnostic_slices == 0 {
        return Ok(crc_ok);
    }
    let chunk_buf = hash_positioned_buffer_len(&blocks[..diagnostic_slices], bs);
    let proven_slices = blocks[..diagnostic_slices]
        .iter()
        .filter(|check| check.is_proven())
        .count();
    let workers = bounded_hash_workers(threads, proven_slices, chunk_buf);
    // Contiguous block ranges per worker: N sequential read streams,
    // not a random-access shuffle.
    let (per, ranges) = hash_range_geometry(diagnostic_slices, workers);
    let (caller_blocks, child_blocks) = crc_ok[..diagnostic_slices].split_at_mut(per);
    let mut child_out: Vec<Result<(), RepairError>> = (1..ranges).map(|_| Ok(())).collect();
    let hash_range = |first_block: usize,
                      oks: &mut [bool],
                      _independent_handle: bool|
     -> Result<(), RepairError> {
        #[cfg(unix)]
        let src = _source;
        // The caller is the only user of the original handle on this branch;
        // every concurrent Windows child needs its own cursor.
        #[cfg(windows)]
        let owned = if _independent_handle {
            Some(File::open(_path)?)
        } else {
            None
        };
        #[cfg(windows)]
        let src = owned.as_ref().unwrap_or(_source);
        let mut buf = Vec::new();
        let mut crc = crc32fast::Hasher::new();
        let mut j = 0usize;
        while j < oks.len() {
            let bidx = first_block + j;
            let Some(check) = blocks.get(bidx).filter(|check| check.is_proven()) else {
                j += 1;
                continue;
            };
            let off = bidx as u64 * bs as u64;
            let declared = (length - off).min(bs as u64);
            let avail = limit.saturating_sub(off).min(bs as u64);
            if avail < declared {
                // Truncation: the serial pass never closes this block's CRC
                // either.
                j += 1;
                continue;
            }
            if buf.is_empty() {
                buf = vec![0u8; chunk_buf];
            }

            // A lane owns a contiguous range of slice slots. Adjacent proved
            // full slices share a positioned read, but an UNPROVEN cell or a
            // short physical/declaration tail ends the run. In particular,
            // this never reads a fixed-false IFSC gap as incidental read-ahead.
            if avail == bs as u64 && declared == bs as u64 && bs <= buf.len() {
                let max_run = hash_full_run_limit(
                    (buf.len() / bs).min(oks.len() - j),
                    limit - off,
                    length - off,
                    bs as u64,
                );
                let run = hash_proven_run_len(&blocks[bidx..], max_run);
                debug_assert!(run > 0);
                let bytes = run * bs;
                crate::disk::read_exact_at(src, &mut buf[..bytes], off)?;
                for k in 0..run {
                    crc.update(&buf[k * bs..(k + 1) * bs]);
                    let crc_val = crc.clone().finalize();
                    crc.reset();
                    oks[j + k] = blocks[bidx + k].crc_matches(crc_val);
                }
                j += run;
                continue;
            }

            let mut p = 0u64;
            while p < avail {
                let take = crate::disk::chunk_len(avail - p, buf.len());
                crate::disk::read_exact_at(src, &mut buf[..take], off + p)?;
                crc.update(&buf[..take]);
                p += take as u64;
            }
            // Tail zero padding in O(log n), exactly as the serial scanner
            // does it.
            let crc_val = if avail == bs as u64 {
                crc.clone().finalize()
            } else {
                crate::yenc_simd::crc32_zeros(crc.clone().finalize(), bs as u64 - avail)
            };
            crc.reset();
            oks[j] = check.crc_matches(crc_val);
            j += 1;
        }
        Ok(())
    };
    let caller_out = std::thread::scope(|s| {
        for (child_index, (oks, res)) in child_blocks
            .chunks_mut(per)
            .zip(child_out.iter_mut())
            .enumerate()
        {
            let hash_range = &hash_range;
            s.spawn(move || {
                *res = hash_range((child_index + 1) * per, oks, true);
            });
        }
        hash_range(0, caller_blocks, false)
    });
    caller_out?;
    for r in child_out {
        r?;
    }
    Ok(crc_ok)
}

/// Number of consecutive proved cells a coalesced read may cross. Keeping the
/// UNPROVEN stop in a small pure helper makes the no-incidental-read boundary
/// directly testable rather than merely inferred from a checksum result.
pub(super) fn hash_proven_run_len(blocks: &[BlockCheck], max_run: usize) -> usize {
    blocks
        .iter()
        .take(max_run)
        .take_while(|check| check.is_proven())
        .count()
}

/// Clamp full-slice availability before narrowing to pointer width. The lane
/// cap is already tiny, while `readable` and `declared` are wire/file `u64`s;
/// narrowing either quotient first can wrap to zero on a 32-bit target.
pub(super) fn hash_full_run_limit(
    lane_slots: usize,
    readable: u64,
    declared: u64,
    block_size: u64,
) -> usize {
    (readable / block_size)
        .min(declared / block_size)
        .min(lane_slots as u64) as usize
}

/// Buffer size for one block-hash lane. The longest consecutive proved run
/// controls allocation so an isolated sparse grid retains the old one-slice
/// buffer, while dense small-slice grids receive a bounded coalescing window.
pub(super) fn hash_positioned_buffer_len(blocks: &[BlockCheck], bs: usize) -> usize {
    if bs >= HASH_POSITIONED_WINDOW {
        return bs.min(HASH_CHUNK);
    }
    let max_run = HASH_POSITIONED_WINDOW / bs;
    let mut run = 0usize;
    let mut longest = 0usize;
    for check in blocks {
        if check.is_proven() {
            run += 1;
            longest = longest.max(run);
            if longest == max_run {
                break;
            }
        } else {
            run = 0;
        }
    }
    longest.max(1) * bs
}

/// Resolve the block-hash pool width from work that can still become true.
/// Geometry continues to span the diagnostic prefix so offsets stay exact,
/// but UNPROVEN holes must not buy empty child threads.
pub(super) fn bounded_hash_workers(
    requested: usize,
    proven_slices: usize,
    chunk_buf: usize,
) -> usize {
    if proven_slices == 0 {
        return 0;
    }
    requested
        .min(proven_slices)
        .min((HASH_POOL_BYTES / chunk_buf.max(1)).max(1))
        .max(1)
}

pub(super) fn hash_range_geometry(blocks: usize, workers: usize) -> (usize, usize) {
    if blocks == 0 || workers == 0 {
        return (0, 0);
    }
    let per = blocks.div_ceil(workers);
    (per, blocks.div_ceil(per))
}

/// Last slice for which IFSC evidence can possibly produce `true`. Missing
/// entries and a fitted UNPROVEN suffix have fixed-false verdicts and require
/// neither positioned reads nor worker ranges.
pub(super) fn hash_diagnostic_slice_count(blocks: &[BlockCheck]) -> usize {
    blocks
        .iter()
        .rposition(BlockCheck::is_proven)
        .map_or(0, |index| index + 1)
}

/// What the verify pass learned about one target file.
///
/// `#[doc(hidden)] pub` for the same reason [`SyndromeReport`] is: the
/// `par2_verify_diff` fuzz target lives outside this crate and has to
/// compare the verdicts of both verify paths against each other and
/// against bytes it generated. Not part of the supported API surface.
#[doc(hidden)]
pub struct Pass1Out {
    pub exists: bool,
    /// `clean` AND the disk length is exactly the declared one. Read it
    /// beside `md5_unfinished`: these three verdicts are a TRI-state,
    /// and false under that flag is "not proven", not "disproven".
    pub intact: bool,
    /// Whole-file MD5 matched over the declared length: every block is
    /// present even if trailing junk keeps `intact` false. Same
    /// tri-state as `intact` - see `md5_unfinished`.
    pub clean: bool,
    /// Per-block presence from the in-stream block CRC32s, for a
    /// damaged file with IFSC data (None when clean, absent, or the
    /// set has no IFSC packets - those fall back to all-false).
    pub present: Option<Vec<bool>>,
    /// Where the post-repair self-prove may pick the whole-file MD5
    /// back up (TODO 133.1 cost work) - see [`Md5Resume`].
    pub resume: Option<Md5Resume>,
    /// The whole-file MD5 stopped at the first failed block, so `clean`
    /// is false on IFSC evidence alone and the digest was never
    /// finished - see [`verify_pass1`]. Always false when `resume` is
    /// None.
    ///
    /// This is the flag that makes the two above a tri-state, and a
    /// caller that reads them without it reads an IFSC verdict as a
    /// FileDesc one. In-tree the only reader is [`verify_all_targets`],
    /// which carries the flag through to `Target`, and the one verdict
    /// it can change is arbitrated in `repair_dir_set_inner`. What the
    /// early stop can NOT do is manufacture a positive: `md5_ok` is
    /// gated on it, so a false "clean" - the H7 direction - stays
    /// unreachable
    /// (`filedesc_md5_over_bytes_the_ifsc_denies_is_unproven_not_damaged`).
    pub md5_unfinished: bool,
}

/// The whole-file MD5 state this verify pass had reached at the byte
/// boundary of the first block it could not prove present - the point
/// up to which the file's bytes have been read (and hashed) once
/// already, and before which an IN-PLACE patch writes nothing: every
/// block the patch touches is a not-present block, and those all start
/// at or after this boundary (so do `set_len`'s zero-extension bytes).
/// Hashing `[offset..length]` of the patched file from `state` is
/// therefore the same FileDesc-MD5 proof over the same final bytes as
/// a full reread; the only thing it stops re-checking is that nothing
/// OUTSIDE the repair rewrote the already-verified prefix in the
/// window between verify and patch, which the full reread only caught
/// by accident. Temp-file rebuilds do NOT get this: their prefix is a
/// fresh copy whose bytes nobody has hashed, so they keep the full
/// reread ([`md5_matches`]).
///
/// The self-prove itself stays a separate read-back-from-disk step
/// after the patch - fusing it into the syndrome feed is the shape the
/// mapped driver's safety contract forbids
/// (`mapped_driver_rereads_files_it_did_not_rebuild`), and this
/// mirrors that: prove what landed, never what was about to be fed.
///
/// `#[doc(hidden)] pub` for `par2_verify_diff`, which asserts the
/// resumed verdict can never disagree with the full one.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct Md5Resume {
    // `pub(super)` rather than private: the parent reads both fields
    // directly (`usable_prefix`, `prove_with_prefix`, the resume tally),
    // which was in-module access before the 10 Sep lift. This spells the
    // same reach - `par2repair` and its children, nothing wider.
    pub(super) offset: u64,
    pub(super) state: Md5,
}

impl Md5Resume {
    /// A resume point built OUTSIDE a verify pass: the live verifier's
    /// prefix hasher (`live::prefix`), which hashes a slot's
    /// PAR2-vouched prefix off disk while the download runs. Same
    /// meaning, same obligations - `offset` must be a point below which
    /// the patch writes nothing, and `state` must be the digest of the
    /// bytes on disk under it - which is why the mapped self-prove
    /// rechecks that span against the IFSC CRC32s anyway before it
    /// trusts the resume (`self_prove_set`).
    /// A RESUME POINT CAN ONLY FAIL, NEVER PASS. The verdict is still
    /// `digest == f.md5` over the whole file, so a state that does not
    /// describe the bytes under `offset` produces a digest that does
    /// not match and the repair reports `VerifyFailed`. That is what
    /// makes this constructor safe to expose to the bench and the
    /// verifier alike: the worst a wrong prefix can do is throw the
    /// mapped route away and fall back to the directory path.
    pub(crate) fn from_prefix(offset: u64, state: Md5) -> Md5Resume {
        Md5Resume { offset, state }
    }

    /// How far this resume point reaches, and the digest it would
    /// finalize to. Test-only: `live/prefix_tests.rs` asserts the
    /// hasher's output IS the FileDesc MD5 of the proven prefix, which
    /// is the whole of what it promises the repair.
    #[cfg(test)]
    pub(crate) fn offset_for_test(&self) -> u64 {
        self.offset
    }

    #[cfg(test)]
    pub(crate) fn finish_for_test(&self) -> [u8; 16] {
        self.state.clone().finalize().into()
    }

    /// [`Md5Resume::from_prefix`] for `par2_mapped_repair_bench`, which
    /// stands in for the live verifier's download-time hasher and lives
    /// outside this crate. Not part of the supported API surface.
    #[doc(hidden)]
    pub fn bench_prefix(offset: u64, state: Md5) -> Md5Resume {
        Md5Resume::from_prefix(offset, state)
    }
}

/// Blocks below this stop the resume snapshotting: one `Md5` clone per
/// block start is noise against hashing 64 KiB, but a wire-supplied
/// 4-byte block size would turn it into the dominant term of the scan.
#[cfg(not(fuzzing))]
pub(super) const RESUME_MIN_BLOCK: usize = 64 << 10;
/// Under cargo-fuzz the gate drops to 16 bytes for the same reason
/// `HASH_PAR_MIN_BYTES` does: `par2_verify_diff` asserts the resumed
/// self-prove verdict against the full one, and a gate the generated
/// block sizes never cross would leave that assertion passing while
/// proving nothing. The threshold is a performance choice; the snapshot
/// it gates is either taken or not, never different.
#[cfg(fuzzing)]
pub(super) const RESUME_MIN_BLOCK: usize = 16;

/// The resume gate, readable from outside the crate so
/// `par2_verify_diff` can assert it is small enough for the block sizes
/// that target generates - the same silent-coverage guard as
/// [`hash_par_min_bytes`].
#[doc(hidden)]
pub fn resume_min_block() -> usize {
    RESUME_MIN_BLOCK
}

/// Target verification in ONE streaming pass: the whole-file MD5 and
/// the per-block IFSC CRC32s are computed from the same buffered read.
/// The old shape hashed every damaged file twice (whole-file MD5, then
/// a second full pass of per-block MD5+CRC); the CRC costs a few
/// percent on top of the MD5 and deletes that second pass outright.
///
/// Presence is decided by the block CRC32 ALONE. The block MD5s are
/// deliberately not consulted: a corrupt block that collides CRC32
/// (2⁻³² per damaged block, and damage is honest randomness) would
/// poison the syndromes and make the repair produce wrong bytes for
/// OTHER blocks - and that is exactly what the mandatory whole-file
/// self-prove after patching catches, so the failure mode is a FAILED
/// repair, never a wrong "Repaired". Same trade par2cmdline's own
/// scanning makes, with a stronger backstop.
///
/// The CLEAN verdict is the FileDesc whole-file MD5 and only that.
/// "Every padded block MD5 matched" is a statement about the IFSC list,
/// which is a SEPARATE claim in the same set - nothing binds the two,
/// so a PAR2 pairing one file's FileDesc with another's IFSC under one
/// file id passed the block proof and failed the MD5 (H7, 08-08 sweep;
/// `ifsc_contradicting_the_filedesc_md5_is_rejected_by_both_paths`).
/// Recomputing the spec's file id does not bind them either - it hashes
/// hash16k, length and name, not the whole-file MD5 beside them.
///
/// `threads` is this file's share of the machine (see
/// [`verify_all_targets`]). It buys parallelism for one shape only: a
/// file SHORT of its declared length cannot be clean whatever any hash
/// says, so [`hash_blocks_par`]'s block-CRC32 presence scan is the
/// whole answer there and runs across lanes. Everything else takes the
/// serial pass below, which gets the whole-file MD5 and the per-block
/// CRC32s out of one read.
///
/// `#[doc(hidden)] pub` for `par2_verify_diff` (see [`Pass1Out`]), which
/// calls it at both thread counts over the same file.
#[doc(hidden)]
pub fn verify_pass1(
    path: &Path,
    file: &Par2File,
    bs: usize,
    threads: usize,
) -> Result<Pass1Out, RepairError> {
    verify_pass1_tiered(path, file, bs, threads, crate::par2::fast_check_enabled())
}

/// [`verify_pass1`] with the fast-check tier chosen by the caller rather
/// than read from [`crate::par2::fast_check_enabled`].
///
/// THE FAST TIER (13 Sep 2026, `parfast --fast-check`, the daemon's
/// `fast_final_check`, `nzbfast verify --fast` - one global, one rule):
/// the CLEAN verdict rests on the per-block IFSC MD5 + CRC32 over every
/// block plus the FileDesc's 16 KiB head, all-core, instead of the
/// whole-file MD5 chain, which is one serial thread and the entire wall
/// of a single large member (8.86 GB: 11.4 s against 0.45 s, research/
/// PARFAST-SINGLE-FILE-MD5-HEADROOM-2026-09-13.md addendum 2). Presence
/// for a damaged member is the same per-block answer either way. What the
/// tier gives up is the one spec-legal set where the two claims disagree
/// (H7: a FileDesc from file A beside an IFSC from file B, same name,
/// length and head - `the_fast_tier_diverges_only_on_h7` pins it), and
/// that is why it is opt-in. The bool is a parameter here for the same
/// reason [`crate::par2::verify_file_path_tiered`] takes one: the tests
/// run both tiers over one fixture in one process, which a global two
/// parallel tests race on cannot do.
///
/// The tier answers only when the IFSC describes every byte of the
/// member; otherwise it declines to the unchanged pass. It never carries
/// a `resume` state (no chain ran), so a repair's self-prove of such a
/// target takes the per-block route too ([`blocks_match_fast`]).
#[doc(hidden)]
pub fn verify_pass1_tiered(
    path: &Path,
    file: &Par2File,
    bs: usize,
    threads: usize,
    fast: bool,
) -> Result<Pass1Out, RepairError> {
    verify_pass1_retaining(path, file, bs, threads, 0, None, fast)
}

/// The fast tier's pass: `None` when it cannot answer (no per-block
/// checksums for every byte), otherwise the same [`Pass1Out`] shape the
/// chain pass produces, with `clean` resting on the blocks and the head.
fn fast_pass1(
    path: &Path,
    file: &Par2File,
    bs: usize,
    threads: usize,
) -> Result<Option<Pass1Out>, RepairError> {
    if !crate::par2::ifsc_covers_every_block(file, bs as u64) {
        return Ok(None);
    }
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Some(Pass1Out {
                exists: false,
                intact: false,
                clean: false,
                present: None,
                resume: None,
                md5_unfinished: false,
            }));
        }
        Err(e) => return Err(e.into()),
    };
    let disk_len = f.metadata()?.len();
    let head_ok = crate::par2::verify_head(file, &mut f)?;
    let blocks = crate::par2::verify_blocks_path_or_streaming(
        path, &mut f, file, bs as u64, disk_len, threads,
    )?;
    let all = !blocks.is_empty() && blocks.iter().all(|&b| b);
    let clean = head_ok && all;
    Ok(Some(Pass1Out {
        exists: true,
        intact: clean && disk_len == file.length,
        clean,
        present: if clean { None } else { Some(blocks) },
        resume: None,
        md5_unfinished: false,
    }))
}

/// The fast tier's self-prove of a written target: every block's IFSC
/// MD5 + CRC32 plus the 16 KiB head, all-core, in place of
/// [`md5_matches`]'s whole-file chain. Same verdict on every honest
/// file; the H7 caveat of [`verify_pass1_tiered`] applies.
pub fn blocks_match_fast(path: &Path, file: &Par2File, bs: usize) -> Result<bool, RepairError> {
    if !crate::par2::ifsc_covers_every_block(file, bs as u64) {
        return md5_matches(path, file);
    }
    let mut f = File::open(path)?;
    let disk_len = f.metadata()?.len();
    if disk_len != file.length {
        return Ok(false);
    }
    if !crate::par2::verify_head(file, &mut f)? {
        return Ok(false);
    }
    let threads = crate::mem::cpu_workers().max(1);
    let blocks = crate::par2::verify_blocks_path_or_streaming(
        path, &mut f, file, bs as u64, disk_len, threads,
    )?;
    Ok(!blocks.is_empty() && blocks.iter().all(|&b| b))
}

/// [`verify_pass1`] that also hands every block it proves to `sink`
/// (the verify pass's retention, see `retain`): a block is opened at
/// its first byte, appended as the chunks go by, and sealed or dropped
/// when its CRC is decided. `first_slice` is the member's first global
/// block index. The pool branch for truncated members retains nothing.
pub(super) fn verify_pass1_retaining(
    path: &Path,
    file: &Par2File,
    bs: usize,
    threads: usize,
    first_slice: usize,
    mut sink: Option<&mut retain::RetainSink<'_>>,
    fast: bool,
) -> Result<Pass1Out, RepairError> {
    // The fast-check tier (`verify_pass1_tiered`) sits under the
    // retaining entry too, because the repair's scan comes in here with
    // a sink and its chain up to the first hole was 5.7 s of an 11.4 s
    // single-member repair. It RETAINS NOTHING: the parallel block
    // verifier does not hand chunks to the sink, and an empty sink is
    // the shape retention already has when its budget is spent or the
    // knob is 0 - the fold re-reads the blocks it needs from the file.
    if fast && let Some(out) = fast_pass1(path, file, bs, threads)? {
        return Ok(out);
    }
    let f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Pass1Out {
                exists: false,
                intact: false,
                clean: false,
                present: None,
                resume: None,
                md5_unfinished: false,
            });
        }
        Err(e) => return Err(e.into()),
    };
    let disk_len = f.metadata()?.len();
    // The digest cache (`crate::digest_cache`), on the whole-file tier
    // only and only for a member of exactly its declared length. A record
    // whose BLAKE3 matches the bytes on disk IS this member's whole-file
    // MD5: equal to the FileDesc's, the member is clean with no chain;
    // different, it is not the set's file and the pass below still runs
    // for the block map. With no record, the pass below enrols the member.
    let cache = crate::digest_cache::active().filter(|_| disk_len == file.length);
    let mut digest = crate::digest_cache::MemberDigest::begin(
        cache.as_ref(),
        &f,
        path,
        disk_len,
        crate::digest_cache::FLAG_VERIFY,
    );
    if digest.validated_md5() == Some(file.md5) {
        if let Ok((_, Some(pending))) = digest.resolve(None) {
            pending.commit();
        }
        return Ok(Pass1Out {
            exists: true,
            intact: true,
            clean: true,
            present: None,
            resume: None,
            md5_unfinished: false,
        });
    }
    let n_slices = file.length.div_ceil(bs as u64) as usize;
    let track = !file.blocks.is_empty();
    if threads > 1
        && n_slices >= 2
        && file.blocks.len() >= n_slices
        && disk_len < file.length
        && disk_len >= HASH_PAR_MIN_BYTES
    {
        let crc_ok = hash_blocks_par(path, &f, disk_len, file.length, &file.blocks, bs, threads)?;
        return Ok(Pass1Out {
            exists: true,
            intact: false,
            clean: false,
            present: Some(crc_ok),
            // The pool branch never computes the whole-file MD5, so
            // there is no state to resume from - such targets keep the
            // full-reread self-prove.
            resume: None,
            md5_unfinished: false,
        });
    }
    let mut whole = Md5::new();
    let mut blocks_ok = track.then(|| vec![false; n_slices]);
    let mut crc = crc32fast::Hasher::new();
    let mut bfill = 0usize;
    let mut bidx = 0usize;
    // Resume snapshotting (TODO 133.1): `pending` is the whole-file
    // MD5 state at the START of the block currently being scanned;
    // when a block fails its CRC, that clone becomes the frozen
    // `snap` the self-prove resumes from. Cloning stops the moment a
    // failure is frozen - after that only the hash itself keeps going.
    let snapping = track && bs >= RESUME_MIN_BLOCK;
    let mut snap: Option<Md5Resume> = None;
    let mut pending: Option<Md5Resume> = None;
    // EARLY STOP (2 Sep 2026): once a block has failed its CRC the
    // whole-file digest can no longer prove the file clean, and the
    // self-prove after the patch resumes from `snap` - the state at
    // that block's start - and hashes everything past it anyway. So the
    // bytes past the first failure were hashed TWICE, once here to a
    // digest nobody reads and once after the patch; on a 1 GiB single
    // member damaged at block 2 that was 1.4 s of a 3.1 s repair
    // (measured, M3 Ultra, md5 at 0.75 GB/s). The per-block CRCs keep
    // going - presence is still decided here - and only the digest
    // stops. What that gives up is the one case where an unfinished
    // digest WOULD have mattered: an IFSC entry disagreeing with a
    // byte-exact file (the whole-file MD5 arbitrates, M4-69). For that
    // shape the repair rebuilds the disputed block to the bytes it
    // already had and the resumed self-prove passes, so the file comes
    // out identical; the only verdict it can change is a SHORTFALL,
    // which is why `repair_dir_set_inner` finishes the digest before
    // declaring one - see its arbitration step. Never on the pool
    // branch above (no snapshot to resume from) and never below
    // RESUME_MIN_BLOCK, where no snapshot is taken.
    //
    // IT IS ALSO WHY A DAMAGED `--slow` VERIFY BEATS A CLEAN ONE, which
    // reads like a defect and is not (research/DESIGN-DIGEST-CACHE-
    // 2026-09-15.md section 9b-3, last bullet; settled 16 Sep 2026).
    // `parfast v --slow` is `set_fast_check(false)`, so every member
    // comes through here rather than through `fast_pass1`, and the MD5
    // chain is the whole wall: stop it at the first failed block and
    // only the per-block CRC32 walks the rest, several times cheaper.
    // Measured on a 320 MiB member damaged in block 0 (M3 Ultra, warm):
    // 0.41 s of user time clean against 0.07 s damaged; 9b-3's 8.86 GB
    // fixture showed 10.44 s against 5.55 s, the smaller ratio being
    // where in the file its byte was rewritten.
    //
    // THE VERDICT IS UNAFFECTED ON ANY HONEST SET. A failed block CRC32
    // says the bytes are not the ones the set describes, so the FileDesc
    // MD5 could not have matched either - `md5_ok` is false either way.
    // The one set where the two claims can disagree is H7's mirror (a
    // FileDesc over bytes its own IFSC denies), and there this withholds
    // a positive rather than deciding a negative - that is what
    // `md5_unfinished` is, pinned by
    // `filedesc_md5_over_bytes_the_ifsc_denies_is_unproven_not_damaged`.
    let mut md5_stopped = false;
    // The buffer is bounded regardless of the slice size - `bs` is
    // wire-supplied up to `par2::MAX_BLOCK_SIZE` (256 MiB), and this allocates
    // once per parallel worker. The in-stream block CRC accumulates
    // across reads (`bfill`), so blocks may straddle buffers freely.
    let limit = file.length.min(disk_len);
    // The read-side cache policy (disk::readpolicy). This loop is a
    // single front-to-back pass over the target, and for the common
    // outcome - the file is clean - nothing reads those bytes again.
    // Measured on a 23.4 GB member: -11.4% cold, flat warm, and the
    // unrelated working set on the box goes from 17-19% evicted to zero
    // (`DROP_BEHIND_DEFAULT`). It gives back only what THIS read
    // faulted in, so a payload somebody else cached is left alone.
    //
    // THE TRADE, STATED HERE because this is where it lands: a member
    // past the policy's floor (a quarter of RAM, so 8 GiB on a 32 GB
    // host) that turns out to be DAMAGED is re-read by the repair, and
    // the bytes this pass brought in are now cold. Every RAR volume
    // shape is far below that floor and is untouched either way; a
    // member that large was never going to be held in cache whole.
    let scan = crate::disk::ScanCache::attach(&f, path, disk_len);
    // THE CHUNK SIZE IS THE READ-SIDE LEVER, not a reader thread. This
    // loop's read and its MD5 take turns on one thread; on a Windows page
    // cache the read of a 51 MB member costs 30-40 ms beside its 54 ms
    // MD5 chain, and the cost of that read is set by whether the buffer
    // fits the core's L2 (256 KB on a Skylake-class desktop): a 1 MiB
    // buffer streams through DRAM twice, a 256 KiB one is filled at
    // cache speed - the i5-10600KF's verify phase 201-213 ms -> 174-191
    // (4 Sep 2026). A reader thread ahead of the hash was built and
    // measured on the same box: no better than the serial 256 KiB loop,
    // so it ships OFF (`ChunkSource::readahead_enabled`). Knobs:
    // `NZBFAST_VERIFY_READAHEAD=1`, `NZBFAST_VERIFY_CHUNK` (bytes).
    let mut source = ChunkSource::open(f, scan, bs, limit);
    let mut pos = 0u64;
    while pos < limit {
        let (chunk, take) = match source.next()? {
            Some(c) => c,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "file shorter than its metadata length",
                )
                .into());
            }
        };
        let buf: &[u8] = &chunk[..take];
        if !snapping {
            whole.update(&buf[..take]);
        }
        if let Some(ok) = blocks_ok.as_mut() {
            let mut p = 0usize;
            while p < take {
                if snapping && bfill == 0 && snap.is_none() {
                    pending = Some(Md5Resume {
                        offset: pos + p as u64,
                        state: whole.clone(),
                    });
                }
                let seg = (bs - bfill).min(take - p);
                if snapping && !md5_stopped {
                    // Fed per block segment instead of per read so the
                    // state at each block boundary exists to clone;
                    // segments are >= RESUME_MIN_BLOCK except at
                    // buffer straddles, so the per-call overhead stays
                    // noise.
                    whole.update(&buf[p..p + seg]);
                }
                let crc_proven = file.blocks.get(bidx).is_some_and(BlockCheck::is_proven);
                // An all-zero IFSC MD5 is the reserved UNPROVEN marker.
                // `crc_matches` can therefore never accept this cell, so its
                // CRC state has a fixed false answer before touching bytes.
                // The FileDesc MD5 above still sees the payload whenever its
                // proof remains live, and later proved blocks retain their
                // independent CRC state.
                if crc_proven {
                    crc.update(&buf[p..p + seg]);
                    if let Some(sink) = sink.as_deref_mut() {
                        if bfill == 0 {
                            sink.begin(first_slice + bidx);
                        }
                        sink.append(&buf[p..p + seg]);
                    }
                }
                bfill += seg;
                p += seg;
                if bfill == bs {
                    let matched = if crc_proven {
                        let done = std::mem::replace(&mut crc, crc32fast::Hasher::new());
                        file.blocks[bidx].crc_matches(done.finalize())
                    } else {
                        false
                    };
                    if let Some(sink) = sink.as_deref_mut() {
                        if matched {
                            sink.commit();
                        } else {
                            sink.abort();
                        }
                    }
                    if let Some(slot) = ok.get_mut(bidx) {
                        *slot = matched;
                    }
                    if !matched && snap.is_none() {
                        snap = pending.take();
                        // Only with a snapshot in hand: the self-prove
                        // must be able to resume from it.
                        md5_stopped = snap.is_some();
                    }
                    bfill = 0;
                    bidx += 1;
                }
            }
        }
        pos += take as u64;
        source.recycle(chunk);
    }
    if bfill > 0
        && let Some(ok) = blocks_ok.as_mut()
    {
        // Tail block, zero-padded to the block size per spec - but
        // only when the declared bytes were all on disk (a tail cut
        // short by a truncated file is damage by definition).
        let off = bidx as u64 * bs as u64;
        let expect = (file.length - off).min(bs as u64);
        if limit - off >= expect
            && let Some(check) = file.blocks.get(bidx)
            && check.is_proven()
        {
            // Extended through the padding in O(log n) rather than by
            // hashing a zero buffer: `bs` is wire-supplied up to 256 MiB,
            // and a set of many one-byte targets made every parallel
            // worker allocate one of those at its tail block - a
            // metadata-driven `targets x block_size` memory spike on a
            // file that could be a few KB. The read buffer above is
            // already clamped for exactly this reason.
            let padded = crate::yenc_simd::crc32_zeros(crc.clone().finalize(), (bs - bfill) as u64);
            ok[bidx] = check.crc_matches(padded);
        }
        if let Some(sink) = sink {
            if ok.get(bidx).copied().unwrap_or(false) {
                sink.commit();
            } else {
                sink.abort();
            }
        }
        if !ok.get(bidx).copied().unwrap_or(true) && snap.is_none() {
            // Tail block unproven (bad padded CRC, cut short, or no
            // IFSC entry): the resume boundary is its start.
            snap = pending.take();
        }
    }
    // No block failed IN the streamed bytes: any remaining damage
    // (blocks wholly past a boundary-truncated EOF, or nothing but a
    // length mismatch `set_len` fixes) starts at or after `limit`, so
    // the state right here resumes it. A partial tail that FAILED set
    // `snap` above, so reaching here with `bfill > 0` means the tail
    // proved out - the only in-place mutation left is `set_len`, which
    // never touches a byte below `limit`. Cloned before `finalize`
    // consumes the hasher.
    if snapping && snap.is_none() {
        snap = Some(Md5Resume {
            offset: limit,
            state: whole.clone(),
        });
    }
    let md5: [u8; 16] = whole.finalize().into();
    let md5_ok = !md5_stopped && disk_len >= file.length && md5 == file.md5;
    // Only a chain that saw every byte of an exact-length member is an MD5
    // worth recording. Every other outcome records nothing and SAYS SO -
    // the early stop above means a damaged member never reaches the
    // `resolve`, so the route was invisible under `NZBFAST_REPAIR_TIMING`
    // where the enrolled case prints `hit`.
    if !md5_stopped && disk_len == file.length {
        if let Ok((_, Some(pending))) = digest.resolve(Some(md5)) {
            pending.commit();
        }
    } else {
        digest.unresolved(if md5_stopped {
            "the member is damaged, so no whole-file MD5 was finished"
        } else {
            "the member is not its declared length"
        });
    }
    Ok(Pass1Out {
        exists: true,
        intact: md5_ok && disk_len == file.length,
        clean: md5_ok,
        present: if md5_ok { None } else { blocks_ok },
        // Kept even when the MD5 matched: a clean-but-oversized target
        // (`needs_resize`) is patched by a bare `set_len` truncation,
        // and its resume boundary is `limit` - the whole proof is the
        // already-computed state, no reread at all.
        resume: snap,
        md5_unfinished: md5_stopped,
    })
}

/// How many files [`verify_all_targets`] hashes at once: the published
/// `-T` when a CLI named one, otherwise the machine width, clamped to
/// the work either way.
///
/// Split out as a pure function because the published value is a
/// process-wide global and this crate's unit tests share ONE process
/// (the `cargo test -p nzbkit-base --lib` line). A test that called
/// `set_file_workers` to reach this rule would pin the width for every
/// test that ran after it - the exact pollution class that line exists
/// to catch. Same decision, and the same reason, as `cpu_workers_override`.
pub(super) fn file_lanes(published: Option<usize>, machine: usize, targets: usize) -> usize {
    published.unwrap_or(machine).min(targets).max(1)
}

/// Verify every target from a size-descending work queue (biggest file
/// first, so no fixed-chunk straggler). One streaming pass per file
/// does everything - see [`verify_pass1`].
pub(super) fn verify_all_targets(
    targets: &mut [Target],
    bs: usize,
    retain: Option<&retain::RetainedCorpus>,
    control: &control::RepairControl,
) -> Result<(), RepairError> {
    // The fast-check tier, read ONCE for the whole scan so every member
    // of one set answers under one rule (see `verify_pass1_tiered`).
    let fast_check = crate::par2::fast_check_enabled();
    if targets.is_empty() {
        return Ok(());
    }
    let mut order: Vec<usize> = (0..targets.len()).collect();
    order.sort_by_key(|&ti| targets[ti].file.length); // pop() takes the largest
    let queue = std::sync::Mutex::new(order);
    let machine = crate::mem::cpu_workers();
    // `-T`, the file axis, when a CLI published one; otherwise the
    // machine, which is what this derived before the switch was plumbed
    // and so is unchanged by default. Clamped to the work either way:
    // a `-T24` over three targets is three workers, not 24 idle ones.
    //
    // This is the site `parfast -T<n>` was missing on repair. It parsed,
    // and was read only by the CLI's OWN survey - which a repair reaches
    // only on the resurvey fallback - so the switch bound `parfast v`
    // and nothing on the main repair route, where the engine surveys the
    // set and this loop is the file-parallel hashing `-T` names.
    // Measured with the reference on the same 1.5 GiB / 24-member set,
    // one damaged block, 10 Sep 2026: par2cmdline-turbo 1.5.0 repairs in
    // 2.73 s at `-T1`, 1.65 s at its default and 0.61 s at `-T24`, so
    // this is a 4.5x span on the reference and was flat here.
    let cores = file_lanes(crate::mem::file_workers(), machine, targets.len());
    // Each file-level worker hands its big files a fair share of the
    // remaining cores for block-parallel hashing - one 8 GB target on a
    // 24-core box gets all 24 lanes instead of one. The two axes
    // MULTIPLY, so pinning the file axis narrows the pool and widens
    // each lane rather than re-scaling what `-t` asked for.
    //
    // What a WIDER lane actually buys is small today, and a reader
    // should not assume it compensates: `verify_pass1_retaining`'s
    // block-parallel branch is gated on a TRUNCATED member
    // (`disk_len < file.length`), so a full-length one takes the serial
    // streaming pass whatever `inner` says. That is TODO 339, not this
    // switch - `-T1` is meant to be slow, it is just slower here than
    // the reference is.
    let inner = (machine / cores).max(1);
    let targets_ref: &[Target] = targets;
    let mut results: Vec<Result<Vec<(usize, Pass1Out)>, RepairError>> = Vec::new();
    std::thread::scope(|s| {
        let handles: Vec<_> = (0..cores)
            .map(|_| {
                s.spawn(|| {
                    let mut out: Vec<(usize, Pass1Out)> = Vec::new();
                    let mut sink = retain.map(|r| r.sink());
                    loop {
                        // PER MEMBER, never per block: this is the one
                        // control poll and the one progress bump of the
                        // hashing loop, and a member is the unit the
                        // queue below deals in. A relaxed load and a
                        // relaxed add against hashing a whole file.
                        //
                        // IT PARKS HERE, and it is allowed to: the queue
                        // lock is not held (the pop is below) and this
                        // worker owns no member yet, so a paused worker
                        // holds nothing another could take - the rule on
                        // `control::PauseGate`. It is also the only way
                        // Pause reaches the half of a repair that is
                        // reading the whole payload.
                        //
                        // The CANCEL leaves by `return`, not by error:
                        // every worker leaves with what it has, the
                        // scope joins, and the driver turns the cancel
                        // into `RepairError::Cancelled` at the check
                        // below. Erroring here would race N workers to
                        // report one cancel.
                        if control.gate_if_held().is_err() {
                            return Ok(out);
                        }
                        let Some(ti) = queue.lock_ok().pop() else {
                            return Ok(out);
                        };
                        let t = &targets_ref[ti];
                        out.push((
                            ti,
                            verify_pass1_retaining(
                                &t.path,
                                &t.file,
                                bs,
                                inner,
                                t.first_slice,
                                sink.as_mut(),
                                fast_check,
                            )?,
                        ));
                        control.step(control::RepairPhase::Verify, t.file.length);
                    }
                })
            })
            .collect();
        results = handles
            .into_iter()
            .map(|h| h.join().expect("verify worker panicked"))
            .collect();
    });
    let mut p1s: Vec<(usize, Pass1Out)> = Vec::with_capacity(targets.len());
    for r in results {
        p1s.extend(r?);
    }
    for (ti, out) in p1s {
        let t = &mut targets[ti];
        t.exists = out.exists;
        t.intact = out.intact;
        t.present = match out.present {
            Some(p) => p,
            None => vec![out.clean; t.n_slices],
        };
        t.resume = out.resume;
        t.md5_unfinished = out.md5_unfinished;
    }
    // A cancelled pass left members unverified - and `Target::present`
    // for those is the `Vec::new()` they were built with, which every
    // reader downstream would take as "nothing present" and repair
    // against. So the cancel is reported HERE rather than being allowed
    // to look like a verdict.
    control.check()
}

/// The chunks [`verify_pass1`] hashes, either read in line or by a
/// reader thread a chunk or two ahead - see the comment at its loop.
pub(super) enum ChunkSource {
    Serial {
        f: File,
        scan: crate::disk::ScanCache,
        buf: Option<Vec<u8>>,
        chunk: usize,
        pos: u64,
        limit: u64,
    },
    /// The reader is not joined: both of its blocking points are the
    /// two channels, and both close when this drops - `free.recv()`
    /// errors once `ret` is gone and `tx.send` once `rx` is - so an early
    /// exit (an error mid-file) releases it within one chunk, and on the
    /// normal path it has already returned when the last chunk is
    /// received. Nothing it holds outlives the file it reads.
    Ahead {
        rx: std::sync::mpsc::Receiver<std::io::Result<(Vec<u8>, usize)>>,
        ret: std::sync::mpsc::SyncSender<Vec<u8>>,
    },
}

impl ChunkSource {
    /// Chunks in flight ahead of the hash: the one being hashed plus
    /// these many read ahead.
    const AHEAD: usize = 2;

    fn chunk_bytes(bs: usize) -> usize {
        // `bs` is kept in the signature for the knob's caller and its
        // tests; the default no longer scales with it (see below).
        static CHUNK: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
        let knob = *CHUNK.get_or_init(|| {
            std::env::var("NZBFAST_VERIFY_CHUNK")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .filter(|&n| n >= 4096)
        });
        // 256 KiB, whatever the slice size: the in-stream block CRC
        // accumulates across reads (`bfill`), so blocks straddle chunks
        // freely, and the chunk's job is to fit the L2 beside the MD5
        // state with a chunk or two in flight. Measured on an i5-10600KF
        // (256 KB of L2 per core, 4 Sep 2026), verify phase over 1 GiB /
        // 21 members, two mirrored rounds: 1 MiB chunks read ahead
        // 232-243 ms, serial 202-226, 512 KiB 202-210, **256 KiB 179-191**;
        // on a Core Ultra 9 (2 MB L2) the three are within noise of each
        // other. The old `bs.clamp(1 MiB, 8 MiB)` was sized for syscall
        // amortisation on a serial loop that no longer exists past 8 MiB.
        let _ = bs;
        knob.unwrap_or(256 << 10)
    }

    /// Whether a member of `limit` bytes gets the reader thread. The
    /// thread was built for the i5-10600KF's verify phase and measured
    /// there against its own serial arm at the same 256 KiB chunk on
    /// ~51 MB members, two mirrored rounds: serial 174 / 176 / 191 ms,
    /// read-ahead 186 / 198 / 198 (baseline 1 MiB serial 201-213) - the
    /// chunk size was the whole win and the thread only a hand-off. It
    /// is a different story when ONE member's chain is the long pole:
    /// the same box, a single 10 GiB member (6 Sep 2026, rounds AK/AL),
    /// verify 14.24-16.41 s serial against 12.83-13.00 with the reader
    /// (turbo 1.5.0 15.6-15.8), because the page-cache copy that the
    /// chain thread otherwise makes for itself is ~3 s of that wall;
    /// ten 1 GiB members 2.09-2.12 either way (ten chains already fill
    /// the cores) and the 21-member rig flat. The M3 Ultra was flat on
    /// every shape measured then (its page-cache read costs ~40 ms per
    /// GiB), which is why this was Windows-only until 13 Sep 2026. That
    /// day, one 8.86 GB member, `parfast v`, mirrored, three pairs each:
    /// M3 Ultra serial 11.59 / 11.71 / 11.83 s against 11.49 / 11.43 /
    /// 11.20 with the reader (three of three, -2.4% on medians); Zen 4
    /// EPYC Linux 12.66 / 12.49 / 12.41 against 11.65 / 11.58 / 12.85
    /// (two of three, -7%); Windows Core Ultra 9 8.68 either way, which
    /// is this rule already on there. So: members of
    /// [`READAHEAD_MIN_BYTES`] and up on every platform; `NZBFAST_
    /// VERIFY_READAHEAD=1` forces the thread for every member above the
    /// parallel floor, `0` keeps every member serial (research/PARFAST-
    /// SINGLE-FILE-MD5-HEADROOM-2026-09-13.md).
    fn readahead_enabled(limit: u64) -> bool {
        static KNOB: std::sync::OnceLock<Option<bool>> = std::sync::OnceLock::new();
        match *KNOB.get_or_init(|| {
            match std::env::var("NZBFAST_VERIFY_READAHEAD").ok().as_deref() {
                Some("1") => Some(true),
                Some("0") => Some(false),
                _ => None,
            }
        }) {
            Some(forced) => forced,
            None => limit >= Self::READAHEAD_MIN_BYTES,
        }
    }

    /// The member size from which the reader thread pays on Windows
    /// (see [`Self::readahead_enabled`]): flat at 1 GiB members, -12..-20%
    /// at 10 GiB; the threshold sits at the smallest size on the
    /// measured winning side of the gap.
    const READAHEAD_MIN_BYTES: u64 = 2 << 30;

    fn open(mut f: File, scan: crate::disk::ScanCache, bs: usize, limit: u64) -> ChunkSource {
        let chunk = Self::chunk_bytes(bs);
        if !Self::readahead_enabled(limit) || limit < HASH_PAR_MIN_BYTES || limit <= chunk as u64 {
            return ChunkSource::Serial {
                f,
                scan,
                buf: Some(vec![0u8; chunk]),
                chunk,
                pos: 0,
                limit,
            };
        }
        let (tx, rx) =
            std::sync::mpsc::sync_channel::<std::io::Result<(Vec<u8>, usize)>>(Self::AHEAD);
        let (ret, free) = std::sync::mpsc::sync_channel::<Vec<u8>>(Self::AHEAD + 1);
        for _ in 0..=Self::AHEAD {
            let _ = ret.send(vec![0u8; chunk]);
        }
        std::thread::spawn(move || {
            let mut pos = 0u64;
            while pos < limit {
                // A closed return channel means the consumer is gone.
                let Ok(mut buf) = free.recv() else { return };
                let take = crate::disk::chunk_len(limit - pos, chunk);
                let r = read_full(&mut f, &mut buf[..take]).map(|()| {
                    scan.consumed(&f, pos + take as u64);
                    (buf, take)
                });
                let failed = r.is_err();
                if tx.send(r).is_err() || failed {
                    return;
                }
                pos += take as u64;
            }
        });
        ChunkSource::Ahead { rx, ret }
    }

    /// The next chunk and how many of its bytes are live; `None` at the
    /// end of the span.
    fn next(&mut self) -> std::io::Result<Option<(Vec<u8>, usize)>> {
        match self {
            ChunkSource::Serial {
                f,
                scan,
                buf,
                chunk,
                pos,
                limit,
            } => {
                if *pos >= *limit {
                    return Ok(None);
                }
                let mut b = buf.take().expect("chunk recycled before the next read");
                let take = crate::disk::chunk_len(*limit - *pos, *chunk);
                read_full(f, &mut b[..take])?;
                scan.consumed(f, *pos + take as u64);
                *pos += take as u64;
                Ok(Some((b, take)))
            }
            ChunkSource::Ahead { rx, .. } => match rx.recv() {
                Ok(r) => r.map(Some),
                Err(_) => Ok(None),
            },
        }
    }

    /// Hand a chunk back once hashed.
    fn recycle(&mut self, chunk: Vec<u8>) {
        match self {
            ChunkSource::Serial { buf, .. } => *buf = Some(chunk),
            ChunkSource::Ahead { ret, .. } => {
                let _ = ret.try_send(chunk);
            }
        }
    }
}

pub(super) fn read_full(f: &mut File, mut buf: &mut [u8]) -> std::io::Result<()> {
    while !buf.is_empty() {
        match f.read(buf) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "file shorter than its metadata length",
                ));
            }
            Ok(n) => buf = &mut buf[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Whole-file proof for a patched target: the FileDesc MD5 over the
/// bytes as they will actually be read afterwards - M2c's self-proving
/// contract, and nothing else stands in for it (H7).
///
/// `#[doc(hidden)] pub` for `par2_verify_diff` (see [`Pass1Out`]): the
/// third verdict in the differential, and the one the other two must
/// not contradict.
#[doc(hidden)]
pub fn md5_matches(path: &Path, file: &Par2File) -> Result<bool, RepairError> {
    let f = File::open(path)?;
    if f.metadata()?.len() != file.length {
        return Ok(false);
    }
    let hasher = Md5::new();
    let md5 = hash_rest(f, file.length, hasher)?;
    Ok(md5 == file.md5)
}

/// The rest of `f` from its current position through `hasher`, with a
/// reader thread ahead of the chain where it pays: the final verify
/// hashes a FEW members (the repaired ones) on a box whose other cores
/// are idle, so the page-cache copy a Windows thread makes for itself
/// (~2.9 GB/s) is the whole of what a second thread can hide -
/// [`ChunkSource::readahead_enabled`] keys the first pass, which runs
/// every member at once, on 2 GiB; here the floor is
/// [`FINAL_READAHEAD_MIN_BYTES`]. `NZBFAST_VERIFY_READAHEAD=1|0` forces
/// either way, as there. Off Windows the loop stays serial (the M3's
/// read is ~40 ms per GiB).
pub(super) fn hash_rest(
    mut f: File,
    remaining: u64,
    mut hasher: Md5,
) -> Result<[u8; 16], RepairError> {
    let chunk = ChunkSource::chunk_bytes(1 << 20);
    let readahead = match std::env::var("NZBFAST_VERIFY_READAHEAD").ok().as_deref() {
        Some("1") => true,
        Some("0") => false,
        _ => cfg!(windows) && remaining >= FINAL_READAHEAD_MIN_BYTES,
    };
    if !readahead {
        let mut buf = vec![0u8; chunk];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        return Ok(hasher.finalize().into());
    }
    let (tx, rx) = std::sync::mpsc::sync_channel::<std::io::Result<(Vec<u8>, usize)>>(2);
    let (ret, free) = std::sync::mpsc::sync_channel::<Vec<u8>>(3);
    for _ in 0..3 {
        let _ = ret.send(vec![0u8; chunk]);
    }
    let reader = std::thread::spawn(move || {
        loop {
            let Ok(mut buf) = free.recv() else { return };
            let r = f.read(&mut buf).map(|n| (buf, n));
            let done = matches!(r, Ok((_, 0)) | Err(_));
            if tx.send(r).is_err() || done {
                return;
            }
        }
    });
    let mut result: Result<(), RepairError> = Ok(());
    for msg in rx {
        match msg {
            Ok((buf, 0)) => {
                drop(buf);
                break;
            }
            Ok((buf, n)) => {
                hasher.update(&buf[..n]);
                let _ = ret.send(buf);
            }
            Err(e) => {
                result = Err(e.into());
                break;
            }
        }
    }
    drop(ret);
    let _ = reader.join();
    result?;
    Ok(hasher.finalize().into())
}

/// The member size from which the final verify's reader thread pays on
/// Windows: the pass runs a few members on idle cores, so the floor
/// sits where a page-cache copy is worth a thread (see
/// [`ChunkSource::readahead_enabled`] for the first pass's 2 GiB, which
/// is measured; this floor is the same mechanism on a pass with the
/// cores to spare).
pub(super) const FINAL_READAHEAD_MIN_BYTES: u64 = 256 << 20;

/// [`md5_matches`] resumed from the verify pass's snapshot: the same
/// FileDesc whole-file proof, minus a reread of the prefix the verify
/// pass already hashed and an in-place patch cannot have touched (see
/// [`Md5Resume`] for why that equivalence holds, and for why temp-file
/// rebuilds never take this path).
///
/// `#[doc(hidden)] pub` for `par2_verify_diff`: the fourth verdict in
/// the differential - on an unpatched file it must equal
/// [`md5_matches`] exactly.
#[doc(hidden)]
pub fn md5_matches_resumed(
    path: &Path,
    file: &Par2File,
    resume: &Md5Resume,
) -> Result<bool, RepairError> {
    use std::io::Seek;
    let mut f = File::open(path)?;
    if f.metadata()?.len() != file.length {
        return Ok(false);
    }
    let hasher = resume.state.clone();
    f.seek(std::io::SeekFrom::Start(resume.offset))?;
    // The same chunk the verify pass reads by, for the same reason (a
    // buffer that fits the L2 beside the MD5 state - see `chunk_bytes`),
    // and the same reader-thread rule as `md5_matches`.
    let md5 = hash_rest(f, file.length.saturating_sub(resume.offset), hasher)?;
    Ok(md5 == file.md5)
}
