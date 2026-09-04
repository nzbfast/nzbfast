//! The block-check grid and the whole-file verifiers that read it.
//!
//! Split out of `par2.rs` on 31 Aug 2026 under the size gate (TODO 106),
//! which the parent had reached EXACTLY - 3,000 of 3,000 lines. The
//! sibling half is `par2/packet.rs`: what a packet SAYS is there, what is
//! done with it once said is here.
//!
//! [`fit_ifsc`] is on this side of that seam rather than beside the IFSC
//! parser that feeds it, and deliberately: what it produces is the GRID.
//! It is the one function that decides how many [`BlockCheck`] cells a
//! file has and which of them are [`BlockCheck::UNPROVEN`], and every
//! consumer of that decision - [`verify_file_blocks`] below,
//! `crate::live::check_block`, the repairer's self-prove - reads the grid
//! and never the packet.
//!
//! Nothing about the public surface moved: par2.rs re-exports every name
//! below, so `crate::par2::BlockCheck`, `crate::par2::verify_file`,
//! `crate::par2::verify_file_blocks`,
//! `crate::par2::verify_file_streaming` and `crate::par2::fit_ifsc` all
//! still resolve exactly as they did.

use super::{FileVerify, HASH16K_LEN, Par2File};
use crate::md5fast::{Digest, Md5};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Checksums for one `block_size` slice of a file (last slice zero-padded).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockCheck {
    pub md5: [u8; 16],
    pub crc32: u32,
}

impl BlockCheck {
    /// A slice the set describes but carries no checksums for: an IFSC
    /// packet that stopped short of the file's declared length leaves
    /// these behind (see [`super::Par2Set::parse`]).
    ///
    /// The grid has to span the whole file - every consumer sizes its
    /// per-block state from `blocks.len()`, so a list shorter than the
    /// file would vouch for a tail nobody checked - and a placeholder in
    /// it must never read as proven over any bytes at all. An all-zero
    /// MD5 does that without a flag: producing a slice that satisfies it
    /// is a 128-bit MD5 preimage, which is not a thing anyone can do.
    /// The CRC32 is set to zero for tidiness only; the MD5 is the guard,
    /// and [`Self::is_proven`] tests exactly that field.
    ///
    /// So an all-zero MD5 is RESERVED here - do not reach for it as a
    /// don't-care in a fixture (one test did, and went red the day this
    /// landed). A wire IFSC entry spelling the same value reads as
    /// unproven too, which is conservative rather than exploitable: that
    /// slice simply never verifies and is repaired.
    pub const UNPROVEN: BlockCheck = BlockCheck {
        md5: [0u8; 16],
        crc32: 0,
    };

    /// Whether this entry came from an IFSC packet at all. A file whose
    /// grid holds any unproven slice cannot be settled on its blocks
    /// alone - the whole-file MD5 is the only thing that covers those
    /// bytes.
    pub fn is_proven(&self) -> bool {
        self.md5 != Self::UNPROVEN.md5
    }

    /// Whether `crc` is this slice's CRC32 - always false for an
    /// [`Self::UNPROVEN`] entry, whatever `crc` is.
    ///
    /// The MD5 is what makes the placeholder unsatisfiable, and the
    /// CRC-ONLY tiers never reach it: fast verify claims a block on its
    /// CRC32 alone, and so do the repairer's self-prove and pass-1
    /// scans. Every u32 is somebody's CRC32 and four appended bytes
    /// choose which, so a placeholder's zero would otherwise be a value
    /// a crafted block could walk straight past. Compare through here,
    /// never against the field.
    pub fn crc_matches(&self, crc: u32) -> bool {
        self.is_proven() && self.crc32 == crc
    }
}

/// How far [`fit_ifsc`] will PAD a grid the packet did not pay for.
///
/// `want` there is wire arithmetic - a declared length over a declared
/// block size - so a hundred-byte IFSC could otherwise ask for a
/// terabyte of placeholder cells. It bounds the padding ONLY: a packet
/// that carries `want` cells or more has already spent that much input
/// on them, so trimming to `want` allocates nothing new and no ceiling
/// applies (`a_four_byte_block_size_is_bounded_by_the_ifsc_it_must_carry`
/// is a legitimate 262144-cell member, hand-built above what par2cmdline
/// will emit). The figure is the set-wide input-slice ceiling, spelled
/// here rather than imported from `par2repair::MAX_INPUT_SLICES` to keep
/// the parser free of the repairer.
const MAX_IFSC_PAD_SLICES: u64 = 32768;

/// Fit an IFSC packet's checks to the grid the FileDesc declares (M4-37).
///
/// The grid MUST span the whole file: every consumer sizes its per-block
/// state from `blocks.len()`, so a list shorter than the file would vouch
/// for a tail nobody checked - the hazard
/// `a_short_ifsc_never_vouches_past_what_it_describes` was written for,
/// and a hostile
/// poster's cheapest way to have a 1000-block file called clean off one
/// slice. That was met by DROPPING any disagreeing packet, which is
/// where this fell down: an empty `blocks` is not merely a weaker
/// description, it is none at all, so a single flipped byte fails the
/// whole-file MD5, no slice can be proven present, and a file that one
/// recovery block would have repaired needs as many as it has slices.
///
/// So fit instead of discard. A LONG list is trimmed - the first `want`
/// entries describe the file completely and the surplus describes slices
/// it does not have. A SHORT one keeps its prefix and the rest of the
/// grid is [`BlockCheck::UNPROVEN`], which cannot read as proven over any
/// bytes at all: the covered prefix still finds damage in the covered
/// prefix, and the uncovered tail still forces the whole-file MD5.
pub(crate) fn fit_ifsc(
    mut blocks: Vec<BlockCheck>,
    length: u64,
    block_size: u64,
) -> Vec<BlockCheck> {
    if block_size == 0 {
        return Vec::new();
    }
    let want = length.div_ceil(block_size);
    if blocks.len() as u64 >= want {
        // The packet paid for these cells, so trimming allocates
        // nothing: bounded by the input whatever the declared length.
        blocks.truncate(want as usize);
        return blocks;
    }
    if want > MAX_IFSC_PAD_SLICES {
        // Padding this far is state the input never carried: fall back
        // to the whole-file MD5, which needs no per-block state at all.
        return Vec::new();
    }
    blocks.resize(want as usize, BlockCheck::UNPROVEN);
    blocks
}

/// Prove one FULLY RESIDENT block against its IFSC entry, cheap digest first.
///
/// Both digests have to match, and a conjunction does not care which is
/// tested first, so the order is ours to choose. On every box we own MD5
/// runs at 0.75-0.94 GB/s per core and CRC32 at about 28
/// (research/PAR2-PERF-AUDIT-2026-09-02.md section 3), so asking the CRC
/// first rejects a block that is actually BAD for about a thirtieth of the
/// cost, and a block that is CLEAN pays exactly the same two whole-block
/// walks it always did, in the other order. It can therefore only help; the
/// win is proportional to how much of the member is damaged.
///
/// MEASURED 3 Sep 2026 (claim `par2-cheap-hash-first`), M3 Ultra and Zen 4,
/// verdict bitmaps byte-identical on both: a fully damaged member costs
/// about HALF the retired instructions at the two exact-size doors and
/// about a fiftieth at the size-mismatch one, with clean controls flat
/// within 0.2%. **Wall follows that only where the block hashing is on the
/// critical path.** It is at the serial streamer (one thread does both
/// chains) and at the positioned door (no whole-file chain beside it),
/// which came back -48.07% and -91.87% on a quiet box; it is NOT at the
/// pipeline door, where these lanes run beside the sequential FileDesc MD5
/// that actually sets the wall - there the same -49.52% of instructions
/// bought -3.68% of time. Do not quote this as a wall win for a single
/// large member. Full round in
/// research/PAR2-TWO-LANES-COMPARED-2026-09-03.md.
///
/// `data` MUST be the whole slice, and that is the condition the callers
/// carry: this is free ONLY because the bytes are already in a buffer
/// somebody else read. Where a block is wider than the read window, the
/// interleaved arms beside each caller keep feeding both digests in one
/// pass - deferring the MD5 there would mean either buffering a block that
/// may legally be 256 MiB or reading it a second time, and a second pass
/// over CLEAN data is the common case, so both prices are worse than the
/// thing they buy. Do not "simplify" those arms into this one.
///
/// `pad` is the PAR2-mandated zero tail for a final short slice. Both
/// hashers are handed back reset on every path, including the early return,
/// so a caller can keep reusing them (constructing `crc32fast::Hasher`
/// repeats its runtime CPU-feature selection).
fn prove_resident_block(
    check: &BlockCheck,
    data: &[u8],
    pad: u64,
    bcrc: &mut crc32fast::Hasher,
    bmd5: &mut Md5,
) -> bool {
    bcrc.update(data);
    let mut crc = bcrc.clone().finalize();
    bcrc.reset();
    if pad > 0 {
        crc = crate::yenc_simd::crc32_zeros(crc, pad);
    }
    // Through `crc_matches`, never the field: an UNPROVEN placeholder's
    // zero would otherwise be a CRC32 a crafted block could walk past, and
    // here the CRC is the FIRST gate rather than a test behind the MD5.
    if !check.crc_matches(crc) {
        return false;
    }
    bmd5.update(data);
    if pad > 0 {
        const ZEROS: [u8; 8192] = [0u8; 8192];
        let mut left = pad;
        while left > 0 {
            let take = crate::disk::chunk_len(left, ZEROS.len());
            bmd5.update(&ZEROS[..take]);
            left -= take as u64;
        }
    }
    <[u8; 16]>::from(bmd5.finalize_reset()) == check.md5
}

/// Hash `data` in `block_size` chunks (last chunk zero-padded to `block_size`,
/// per spec) and compare against `file.blocks`. Returns one flag per expected
/// block: `true` only when both MD5 and CRC32 match. If `data` is shorter
/// than the file, missing blocks are `false`; extra trailing data doesn't
/// create extra flags.
///
/// This is the reference implementation the future incremental hasher is
/// differential-tested against.
pub fn verify_file_blocks(file: &Par2File, block_size: u64, data: &[u8]) -> Vec<bool> {
    let bs = block_size as usize;
    if bs == 0 {
        return vec![false; file.blocks.len()];
    }
    // Most blocks are complete and can hash in place. Allocate a padded
    // block only if a proved final slice actually needs one; in particular,
    // an entirely UNPROVEN grid now allocates nothing proportional to a
    // potentially 256 MiB block size.
    let mut padded = Vec::new();
    file.blocks
        .iter()
        .enumerate()
        .map(|(i, check)| {
            // An UNPROVEN cell is deliberately unsatisfiable: it is a
            // placeholder for bytes the IFSC packet did not describe, not
            // a checksum pair.  The whole-file digest may still settle it
            // in `verify_file`, but once that proof has failed no payload
            // bytes can change this answer.
            if !check.is_proven() {
                return false;
            }
            let start = i * bs;
            if start >= data.len() {
                return false;
            }
            let end = (start + bs).min(data.len());
            let chunk: &[u8] = if end - start == bs {
                &data[start..end]
            } else {
                padded.resize(bs, 0);
                padded.fill(0);
                padded[..end - start].copy_from_slice(&data[start..end]);
                &padded
            };
            // Cheap digest first (see `prove_resident_block`): this
            // reference implementation keeps the one-shot helpers rather
            // than threading reusable hashers through the closure, but the
            // ORDER is the same one every hot caller below uses.
            if !check.crc_matches(crc32fast::hash(chunk)) {
                return false;
            }
            <[u8; 16]>::from(Md5::digest(chunk)) == check.md5
        })
        .collect()
}

/// Full verification of a candidate `data` buffer against `file`: per-block
/// flags plus the whole-file MD5 and MD5-16k checks.
///
/// THE WHOLE-FILE MD5 ARBITRATES (M4-69, 30 Aug 2026). Where it matches
/// over the declared length, every block flag is `true` whatever the IFSC
/// entries say, and the per-block pass is skipped entirely. The FileDesc
/// digest covers every byte of every block, so a file that hashes to it IS
/// the file the set describes - and an IFSC entry disagreeing about those
/// bytes is then provably wrong about them, not evidence of damage.
///
/// It is a NO-OP on any well-formed set: an honest IFSC entry is the
/// checksum pair of the bytes the FileDesc digest covers, so the two can
/// only ever agree. What it changes is a set whose entries do NOT agree
/// with the descriptor beside them - `verify_file_blocks` requires the MD5
/// AND the CRC32, so a forged block MD5 turned a byte-exact file into
/// 100% damage, and this reported `n/n blocks bad, md5 ok` in one breath.
/// That is the house rule inverted: the strongest evidence available over
/// the settled file was already in hand and a weaker per-block claim
/// overruled it.
///
/// The rule is not new to this crate - [`crate::par2repair`]'s own verify
/// pass has always answered `present` from the whole-file MD5 when it
/// matched (`Pass1Out::clean`), which is why the DISK repair path never
/// carried this. Bringing it here makes the two halves of the product read
/// one malformed set one way, the discipline W4-10 established for
/// `SetReplay`.
///
/// [`verify_file_blocks`] itself is unchanged, deliberately: it answers a
/// strictly per-block question with no whole-file evidence in scope, which
/// is the contract `crate::live::check_block` is held to.
///
/// It settles an UNPROVEN slice too - the placeholder `fit_ifsc` pads a
/// short IFSC out with (M4-37) - and that is the same rule rather than a
/// second one. Such a slice can never be proven BY THE GRID, which is
/// what stops a short list vouching for an unposted tail; the whole-file
/// digest is different evidence and covers those bytes directly. Where it
/// FAILS, nothing but the grid is left and the unproven slice stays
/// false, which is what
/// `a_short_ifsc_keeps_its_prefix_and_proves_nothing_past_it` pins from
/// both sides.
pub fn verify_file(file: &Par2File, block_size: u64, data: &[u8]) -> FileVerify {
    let md5: [u8; 16] = Md5::digest(data).into();
    // See module docs: first min(len, 16k) bytes, NOT zero-padded.
    let head = &data[..data.len().min(HASH16K_LEN)];
    let md5_16k: [u8; 16] = Md5::digest(head).into();
    let md5_ok = data.len() as u64 == file.length && md5 == file.md5;
    FileVerify {
        blocks: if md5_ok {
            vec![true; file.blocks.len()]
        } else {
            verify_file_blocks(file, block_size, data)
        },
        md5_ok,
        md5_16k_ok: md5_16k == file.md5_16k,
    }
}

/// One read pass' worth of bytes. Big enough that the per-read syscall and
/// the hashers' per-call overhead vanish against the copy, small enough to
/// stay resident in L2 while both MD5 passes and the CRC walk it - the same
/// figure `par2repair`'s self-prove reader uses.
pub(super) const VERIFY_CHUNK: usize = 1 << 20;

/// Hash a reader against the FileDesc's whole-file MD5 without paying for
/// per-block diagnostics the caller will not inspect.
///
/// This is the narrow door for post-repair proofs and duplicate-fill
/// arbitration: both only ask whether the complete file is the one the
/// FileDesc names. They used to call [`verify_file_streaming`], which also
/// ran an independent per-block MD5 chain plus CRC32 over every byte and then
/// discarded that work.
///
/// Like [`verify_file_streaming`], this reads from the reader's current
/// position through EOF. Extra trailing bytes therefore fail the length
/// check rather than being silently ignored.
pub fn verify_file_md5_streaming<R: Read>(file: &Par2File, mut src: R) -> std::io::Result<bool> {
    verify_md5_sized(file, &mut src, VERIFY_CHUNK)
}

/// File-backed whole-MD5 proof for callers that do not need a block bitmap.
///
/// A regular file's size is available without reading its payload, so a
/// mismatch returns `false` immediately. Matching-size files are streamed
/// through the same bounded buffer as [`verify_file_md5_streaming`], sized
/// down for small members. This also avoids computing the MD5-16k value that
/// MD5-only callers discard.
pub fn verify_file_md5_path(path: &Path, file: &Par2File) -> std::io::Result<bool> {
    // The ONE site in this file whose every read is sequential - a size
    // mismatch returns before a byte is touched, and any other outcome
    // streams the whole payload front to back - so it can declare the
    // pattern at OPEN time. That matters only on Windows, where
    // `FILE_FLAG_SEQUENTIAL_SCAN` has no after-the-fact equivalent and
    // also asks the cache manager to evict behind the reader.
    // `verify_file_path` and `par2repair::verify_pass1` deliberately do
    // NOT use this door: both may branch to positioned diagnostic reads,
    // and that flag on a seeking reader evicts pages the next seek wants.
    let mut src = crate::disk::open_for_scan(path)?;
    let metadata = src.metadata()?;
    let disk_len = metadata.len();
    if metadata.is_file() && disk_len != file.length {
        return Ok(false);
    }
    let buffer_len = if metadata.is_file() {
        whole_file_buffer_len(file.length, disk_len)
    } else {
        VERIFY_CHUNK
    };
    if !metadata.is_file() {
        return verify_md5_sized(file, &mut src, buffer_len);
    }
    // A regular file here is read once, front to back, and never looked
    // at again by this call - the shape the read-side cache policy is
    // for. `ScanReader` declares the pattern and gives back the pages
    // this read brought in, so a 23 GB digest stops evicting the rest
    // of the box (disk::readpolicy's `DROP_BEHIND_DEFAULT`).
    let mut scan = crate::disk::ScanReader::adopt(src, path, disk_len);
    verify_md5_sized(file, &mut scan, buffer_len)
}

/// Streaming verification for a reader that can rewind.
///
/// The whole-file FileDesc MD5 is the strongest evidence and arbitrates the
/// block grid (see [`verify_file`]). Most verification runs are clean, so do
/// that proof first and return immediately when it matches. Only a mismatch
/// rewinds and computes the per-block MD5+CRC32 diagnostics. Compared with
/// [`verify_file_streaming`], the clean path removes one complete MD5 chain;
/// the damaged path performs the same proved-block hash work in two
/// bounded-memory read passes so it can still report the exact bad-block
/// bitmap.
///
/// That is deliberately a clean-case tradeoff, not a universal I/O win. A
/// damaged member larger than the page cache (or resident on a cold network
/// or rotational volume) may require two physical reads. Callers that value
/// one-pass damaged-file I/O over the common clean-file CPU saving should
/// keep using [`verify_file_streaming`].
///
/// Both passes begin at the reader's current position. A seek failure is an
/// I/O failure, never a weaker verification verdict. A fitted UNPROVEN suffix
/// needs no diagnostic bytes: its flags are necessarily false after the first
/// pass has rejected the whole-file proof.
pub fn verify_file_seekable<R: Read + Seek>(
    file: &Par2File,
    block_size: u64,
    mut src: R,
) -> std::io::Result<FileVerify> {
    let start = src.stream_position()?;
    let whole = verify_whole(file, &mut src)?;
    let blocks = if whole.md5_ok {
        vec![true; file.blocks.len()]
    } else {
        src.seek(SeekFrom::Start(start))?;
        verify_blocks_streaming(file, block_size, &mut src)?
    };
    Ok(FileVerify {
        blocks,
        md5_ok: whole.md5_ok,
        md5_16k_ok: whole.md5_16k_ok,
    })
}

/// File-backed one-pass verification with a size-mismatch shortcut and a
/// parallel diagnostic pass for that known-failing case.
///
/// An exact-size regular file retains [`verify_file_streaming`]'s one-pass I/O
/// behavior. For a large member, its sequential FileDesc MD5 lends the same
/// bounded buffers to at most two independent block-hash lanes, overlapping
/// the two MD5 chains without reading the payload again. The calling thread is
/// the FileDesc lane and counts against `threads`; buffers are recycled under
/// the same 64 MiB pool ceiling as positioned diagnostics. Small files and a
/// one-thread budget keep the serial streamer. Non-regular inputs also keep
/// serial streaming semantics: metadata lengths for pipes and devices do not
/// describe how many bytes their readers will yield, and positioned reads need
/// not be supported.
///
/// A regular file whose metadata length differs from the FileDesc is already
/// known to fail its whole-file MD5. That case goes directly to a bounded 16
/// KiB prefix check plus block diagnostics, avoiding a redundant complete
/// first pass. The independent block checks are divided into contiguous ranges
/// with positioned reads. `threads` is a caller hint, clamped to machine
/// parallelism, a hard thread ceiling, the block count and a byte budget. The
/// calling thread is one of those lanes, keeping this pool inside its budget
/// when nested under file-parallel verification.
///
/// After the FileDesc proof fails, UNPROVEN entries have a fixed `false`
/// verdict. Positioned lanes therefore omit those reads entirely and trim a
/// fitted short-IFSC suffix before partitioning work. On Unix all lanes share
/// the initially opened descriptor; Windows duplicates that pinned handle
/// because its positioned-read compatibility primitive moves the handle
/// cursor.
pub fn verify_file_path(
    path: &Path,
    file: &Par2File,
    block_size: u64,
    threads: usize,
) -> std::io::Result<FileVerify> {
    verify_file_path_tiered(path, file, block_size, threads, fast_check_enabled())
}

/// [`verify_file_path`] with the fast-check tier chosen by the caller
/// instead of resolved from [`fast_check_enabled`].
///
/// TWO CALLERS, ONE REASON. A whole-directory pass resolves the choice
/// ONCE and hands it to every member here, so a daemon setting flipped
/// mid-pass cannot make two members of one set answer under different
/// rules. And the differential in `par2.rs` runs BOTH tiers over one
/// fixture and requires the same answer, which a process-global toggle
/// two parallel tests would race on could not do.
pub fn verify_file_path_tiered(
    path: &Path,
    file: &Par2File,
    block_size: u64,
    threads: usize,
    ifsc_only: bool,
) -> std::io::Result<FileVerify> {
    let mut src = File::open(path)?;
    let metadata = src.metadata()?;
    let disk_len = metadata.len();
    if !metadata.is_file() {
        return verify_file_streaming_sized(file, block_size, src, VERIFY_CHUNK);
    }
    if !regular_file_size_mismatch(true, disk_len, file.length) {
        // The experimental IFSC-only tier, default off. It reads through
        // positioned lanes rather than the sequential handle, so it does
        // NOT carry the read-side cache policy below.
        //
        // ITS ORIGINAL JUSTIFICATION HAS EXPIRED, and the note is left
        // here rather than deleted because the next reader will
        // otherwise re-derive it: this said the trade was fair "because
        // the arm it would want (drop-behind) is off by default". That
        // arm is ON by default as of the gated round (`readpolicy`'s
        // `DROP_BEHIND_DEFAULT`), so the reason is now simply that THIS
        // TIER is the experimental one and default off. A lane that
        // ships the tier on owes the policy a positioned equivalent, or
        // owes a measurement showing a member large enough to reach the
        // size floor does not care.
        if ifsc_only
            && let Some(verified) =
                ifsc_only_attempt(path, &mut src, file, block_size, disk_len, threads)?
        {
            return Ok(verified);
        }
        // Every `None` above is a fall back to the unchanged path, and the
        // attempt may have consumed the 16 KiB head or (on Windows) moved
        // the cursor with a positioned read.
        src.seek(SeekFrom::Start(0))?;
        // The one-pass branch: every payload byte is read exactly once
        // and nothing in this call reads them again, so the handle
        // carries the read-side cache policy (disk::readpolicy) - the
        // sequential declaration, and drop-behind of the pages this
        // pass brought in, for a member past the policy's size floor.
        return verify_file_streaming_path(
            file,
            block_size,
            crate::disk::ScanReader::adopt(src, path, disk_len),
            disk_len,
            threads,
            whole_file_buffer_len(file.length, disk_len),
        );
    }
    // A different byte count makes the FileDesc MD5 impossible before a
    // byte is read. Do not spend a complete first pass proving that known
    // fact and then read the payload again for its useful block diagnosis.
    // The block grid ignores bytes past its last slice just like
    // `verify_file_blocks`; MD5-16k still needs the actual prefix. An
    // oversized candidate can contribute bytes to its final expected
    // slice (where the FileDesc length is not block-aligned), so that
    // slice is still read through its boundary to preserve the reference
    // bitmap exactly; bytes after that boundary are never read.
    let md5_16k_ok = verify_head(file, &mut src)?;
    let blocks =
        verify_blocks_path_or_streaming(path, &mut src, file, block_size, disk_len, threads)?;
    Ok(FileVerify {
        blocks,
        md5_ok: false,
        md5_16k_ok,
    })
}

/// Whether `NZBFAST_VERIFY_IFSC_ONLY=1` is set in this process.
///
/// Read once per process: the environment cannot change under a running
/// program in any way this code should honour, and a second read would
/// only make two members of one set answer under different rules.
fn fast_check_from_env() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        std::env::var_os("NZBFAST_VERIFY_IFSC_ONLY").is_some_and(|value| value == "1")
    })
}

/// The explicit fast-check choice, if a surface has made one.
///
/// Tri-state, because "no choice" and "chosen off" have to be told
/// apart: only the first falls through to the environment.
/// [`FAST_CHECK_UNSET`] is the value at process start.
static FAST_CHECK: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(FAST_CHECK_UNSET);
const FAST_CHECK_UNSET: u8 = 0;
const FAST_CHECK_OFF: u8 = 1;
const FAST_CHECK_ON: u8 = 2;

/// Choose the fast final check for this process, overriding the environment.
///
/// THIS IS THE ONE VALUE. `nzbfast verify --fast` and the daemon's
/// `fast_final_check` setting both land here, and
/// `NZBFAST_VERIFY_IFSC_ONLY` is only consulted when neither has
/// spoken, so the precedence is CLI flag, then setting, then
/// environment variable, then off. Splitting it - letting the CLI and
/// the daemon answer under different rules - is worse than either rule
/// alone, which is why there is a single global here rather than a
/// parameter on each surface.
///
/// EXPERIMENTAL, DEFAULT OFF, and it changes what "verified" MEANS -
/// see [`ifsc_only_attempt`] for exactly what the verdict then rests on
/// and for the one spec-legal set on which the two tiers disagree. The
/// policy section of `research/PAR2-PERF-AUDIT-2026-09-02.md` carries
/// the decision.
pub fn set_fast_check(on: bool) {
    FAST_CHECK.store(
        if on { FAST_CHECK_ON } else { FAST_CHECK_OFF },
        std::sync::atomic::Ordering::Relaxed,
    );
}

/// Drop any explicit choice, returning this process to the environment.
///
/// For tests that need to leave the global as they found it. Nothing in
/// production calls it: a surface that has made a choice keeps it.
pub fn clear_fast_check() {
    FAST_CHECK.store(FAST_CHECK_UNSET, std::sync::atomic::Ordering::Relaxed);
}

/// Is the fast final check on, under the precedence [`set_fast_check`] documents?
pub fn fast_check_enabled() -> bool {
    match FAST_CHECK.load(std::sync::atomic::Ordering::Relaxed) {
        FAST_CHECK_ON => true,
        FAST_CHECK_OFF => false,
        _ => fast_check_from_env(),
    }
}

/// Whether the IFSC describes EVERY byte of the member with a real
/// checksum pair.
///
/// The grid `fit_ifsc` builds always spans the file, but its cells may
/// be [`BlockCheck::UNPROVEN`] placeholders for bytes no IFSC packet
/// described. Those cover nothing, so a verdict resting on the grid
/// alone needs all of them real and needs the grid to be the exact
/// length the declared size asks for. A zero-length member has no
/// blocks at all: "every block proved" is then vacuously true over no
/// bytes, which is precisely the claim this must never make.
fn ifsc_covers_every_block(file: &Par2File, block_size: u64) -> bool {
    if block_size == 0 || file.length == 0 {
        return false;
    }
    let want = file.length.div_ceil(block_size);
    file.blocks.len() as u64 == want && file.blocks.iter().all(BlockCheck::is_proven)
}

/// The `NZBFAST_VERIFY_IFSC_ONLY` tier: settle a clean exact-size member
/// on its per-block IFSC proofs, without the serial whole-file MD5.
///
/// WHY IT EXISTS. A clean verify of a large member is bound by one
/// serial MD5 chain over every byte - 0.75-0.94 GB/s on a single core,
/// about 30 s for a 23 GB member on any box this fleet owns - and MD5
/// is a chained state machine, so that chain cannot be split. The
/// per-block IFSC digests cover the SAME bytes and are independent
/// chains, so they already run all-core. Dropping the whole-file chain
/// moves clean verify of a big member from one core to all of them.
///
/// WHAT IT RETURNS. `Some` only for a verdict of CLEAN. Every other
/// outcome is `None`, meaning "this tier declines, run the unchanged
/// path", and the caller then produces exactly today's answer. That is
/// deliberate and it is what keeps the tiers equal on damage: a member
/// whose blocks do not all match may still satisfy the FileDesc MD5
/// (the H7 MIRROR shape - `filedesc_md5_over_bytes_the_ifsc_denies_is_
/// unproven_not_damaged` in `par2repair/unit_tests.rs`), and only the
/// whole-file chain can tell. Declining costs a re-read of a member
/// already known to be interesting; taking the answer would be wrong.
///
/// WHAT THE VERDICT RESTS ON. With the knob ON: a 128-bit MD5 plus a
/// CRC32 over every byte of the member, per block, from the IFSC
/// packet, plus the FileDesc's own 16 KiB head digest. With it OFF: a
/// 128-bit MD5 over the whole file, from the FileDesc packet.
///
/// THE ONE SHAPE THE TWO TIERS DISAGREE ON, and it is spec-legal.
/// Nothing in PAR2 binds an IFSC packet to the FileDesc beside it: the
/// file id is `MD5(hash16k || length || name)` and does not hash the
/// whole-file MD5. So a set may pair file A's FileDesc with file B's
/// IFSC under one id whenever A and B share a name, a length and a
/// first 16 KiB - and then bytes B on disk satisfy every block while
/// failing the FileDesc digest. That is H7 from the 08-08 sweep, and
/// `ifsc_contradicting_the_filedesc_md5_is_rejected_by_both_paths`
/// pins the knob-off behaviour on it. IT CANNOT BE DETECTED HERE: the
/// only evidence that separates the two claims is the whole-file
/// digest this tier exists to skip. The head check below narrows it -
/// it refuses every pairing whose first 16 KiB differ, which is the
/// only H7 shape a random or accidental set produces - but a
/// deliberately built one with a shared prefix walks past it, and
/// `the_ifsc_only_tier_diverges_only_on_the_h7_shape` pins that
/// honestly rather than claiming a fallback that does not exist. This
/// is the whole of the policy question, and it is why the default is
/// OFF and why moving it is a product decision rather than a code one.
///
/// The head check is free in the sense that matters: 16 KiB against a
/// member measured in gigabytes.
fn ifsc_only_attempt(
    path: &Path,
    src: &mut File,
    file: &Par2File,
    block_size: u64,
    disk_len: u64,
    threads: usize,
) -> std::io::Result<Option<FileVerify>> {
    if !ifsc_covers_every_block(file, block_size) {
        return Ok(None);
    }
    src.seek(SeekFrom::Start(0))?;
    if !verify_head(file, src)? {
        return Ok(None);
    }
    let blocks = verify_blocks_path_or_streaming(path, src, file, block_size, disk_len, threads)?;
    if !blocks.iter().all(|&ok| ok) {
        return Ok(None);
    }
    Ok(Some(FileVerify {
        blocks,
        md5_ok: true,
        md5_16k_ok: true,
    }))
}

/// One file-read buffer handed from the sequential FileDesc hasher to a
/// block-hash lane. `valid` keeps every allocation fully initialized and
/// reusable without clearing it between reads.
struct VerifyPipelineBatch {
    buf: Vec<u8>,
    valid: usize,
    offset: u64,
}

/// Two block lanes reach the mandatory sequential whole-file MD5 floor. A
/// fourth lane was neutral on the 4 GiB control while consuming two more cores
/// and buffers, so do not turn one file into a wider fanout.
const VERIFY_PIPELINE_MAX_HASH_WORKERS: usize = 2;

fn bounded_pipeline_workers(
    requested_threads: usize,
    active_groups: usize,
    buffer_len: usize,
) -> usize {
    if active_groups == 0 {
        return 0;
    }
    let machine_children = crate::mem::cpu_workers().max(1).saturating_sub(1);
    let memory_children = (VERIFY_POOL_BYTES / buffer_len.max(1)).saturating_sub(1);
    requested_threads
        .saturating_sub(1)
        .min(machine_children)
        .min(VERIFY_MAX_WORKERS.saturating_sub(1))
        .min(VERIFY_PIPELINE_MAX_HASH_WORKERS)
        .min(memory_children)
        .min(active_groups)
}

fn verify_pipeline_lane(
    rx: std::sync::mpsc::Receiver<VerifyPipelineBatch>,
    recycle: std::sync::mpsc::Sender<Vec<u8>>,
    file: &Par2File,
    block_size: u64,
) -> Vec<usize> {
    let bs = block_size as usize;
    let mut matches = Vec::new();
    let mut active_block = None;
    let mut filled = 0usize;
    let mut bmd5 = Md5::new();
    let mut bcrc = crc32fast::Hasher::new();

    while let Ok(batch) = rx.recv() {
        let mut p = 0usize;
        while p < batch.valid {
            let absolute = batch.offset + p as u64;
            let bidx = (absolute / block_size) as usize;
            let within = (absolute % block_size) as usize;
            let seg = (bs - within).min(batch.valid - p);
            let check = &file.blocks[bidx];
            // A group never straddles a read (`verify_file_streaming_path`
            // clamps each request to its group end), so for any block no
            // wider than the read window the whole slice is resident in
            // THIS batch and the CRC can gate the MD5 for free. A block
            // wider than the window still arrives in several batches and
            // keeps the interleaved feed below.
            if within == 0 && seg == bs && check.is_proven() {
                debug_assert!(active_block.is_none());
                debug_assert_eq!(filled, 0);
                if prove_resident_block(check, &batch.buf[p..p + seg], 0, &mut bcrc, &mut bmd5) {
                    matches.push(bidx);
                }
                p += seg;
                continue;
            }
            if check.is_proven() {
                match active_block {
                    Some(index) => {
                        debug_assert_eq!(index, bidx);
                        debug_assert_eq!(filled, within);
                    }
                    None => {
                        debug_assert_eq!(within, 0);
                        active_block = Some(bidx);
                    }
                }
                bmd5.update(&batch.buf[p..p + seg]);
                bcrc.update(&batch.buf[p..p + seg]);
                filled += seg;
            }
            p += seg;

            if within + seg == bs {
                if check.is_proven() {
                    let md5: [u8; 16] = bmd5.finalize_reset().into();
                    let crc = bcrc.clone().finalize();
                    bcrc.reset();
                    if md5 == check.md5 && crc == check.crc32 {
                        matches.push(bidx);
                    }
                }
                active_block = None;
                filled = 0;
            }
        }
        let _ = recycle.send(batch.buf);
    }

    // A short read (including a shrink after metadata()) closes the current
    // block with the PAR2-mandated zero padding, exactly like the serial
    // streamer. Blocks never reached remain false in the caller's bitmap.
    if let Some(bidx) = active_block {
        const ZEROS: [u8; 8192] = [0u8; 8192];
        let mut pad = bs - filled;
        while pad > 0 {
            let take = pad.min(ZEROS.len());
            bmd5.update(&ZEROS[..take]);
            pad -= take;
        }
        let md5: [u8; 16] = bmd5.finalize().into();
        let crc = crate::yenc_simd::crc32_zeros(bcrc.finalize(), (bs - filled) as u64);
        let check = &file.blocks[bidx];
        if md5 == check.md5 && crc == check.crc32 {
            matches.push(bidx);
        }
    }
    matches
}

/// File-backed one-pass verifier. The caller owns the only file cursor and
/// advances the sequential whole-file MD5 before lending each bounded buffer
/// to independent per-block hash lanes. Consequently a clean or damaged
/// member reads every payload byte exactly once while the two mandatory MD5
/// chains overlap on different cores.
fn verify_file_streaming_path<R: Read>(
    file: &Par2File,
    block_size: u64,
    mut src: R,
    disk_len: u64,
    threads: usize,
    buffer_len: usize,
) -> std::io::Result<FileVerify> {
    let Ok(bs) = usize::try_from(block_size) else {
        return verify_file_streaming_sized(file, block_size, src, buffer_len);
    };
    let diagnostic_blocks = diagnostic_block_count(&file.blocks);
    if bs == 0 || diagnostic_blocks == 0 || disk_len < VERIFY_PAR_MIN_BYTES || threads < 2 {
        return verify_file_streaming_sized(file, block_size, src, buffer_len);
    }

    // Each group belongs to one lane and ends on a PAR2 block boundary. Small
    // blocks share a read-sized group; blocks larger than the read window are
    // streamed to the same lane in several batches, so even a legal 256 MiB
    // block never requires a block-sized allocation.
    let blocks_per_group = (buffer_len / bs).max(1);
    let group_count = diagnostic_blocks.div_ceil(blocks_per_group);
    let mut active_groups = Vec::with_capacity(group_count);
    for group in 0..group_count {
        let first = group * blocks_per_group;
        let end = (first + blocks_per_group).min(diagnostic_blocks);
        active_groups.push(file.blocks[first..end].iter().any(BlockCheck::is_proven));
    }
    let active_count = active_groups.iter().filter(|&&active| active).count();
    let workers = bounded_pipeline_workers(threads, active_count, buffer_len);
    if workers == 0 {
        return verify_file_streaming_sized(file, block_size, src, buffer_len);
    }

    // Assign only groups that actually carry an IFSC proof. Skipped UNPROVEN
    // runs therefore neither consume a queue slot nor distort the round-robin
    // balance of real hash work.
    let mut next_lane = 0usize;
    let group_lanes: Vec<usize> = active_groups
        .into_iter()
        .map(|active| {
            if !active {
                return usize::MAX;
            }
            let lane = next_lane;
            next_lane = (next_lane + 1) % workers;
            lane
        })
        .collect();

    let mut senders = Vec::with_capacity(workers);
    let mut receivers = Vec::with_capacity(workers);
    for _ in 0..workers {
        let (tx, rx) = std::sync::mpsc::sync_channel::<VerifyPipelineBatch>(1);
        senders.push(tx);
        receivers.push(rx);
    }
    let (recycle_tx, recycle_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    // One buffer can be under the file cursor while every hash lane owns one.
    // `bounded_pipeline_workers` includes this extra buffer in the 64 MiB cap.
    let mut buffers: Vec<Vec<u8>> = (0..=workers)
        .map(|_| vec![0u8; buffer_len.max(1)])
        .collect();
    let group_bytes = block_size.saturating_mul(blocks_per_group as u64);
    let diagnostic_end = block_size.saturating_mul(diagnostic_blocks as u64);
    let mut whole = Md5::new();
    let mut head = Md5::new();
    let mut total = 0u64;

    let (read_result, lane_matches) = std::thread::scope(|scope| {
        let handles: Vec<_> = receivers
            .into_iter()
            .map(|rx| {
                let recycle = recycle_tx.clone();
                scope.spawn(move || verify_pipeline_lane(rx, recycle, file, block_size))
            })
            .collect();
        drop(recycle_tx);

        let read_result = (|| -> std::io::Result<()> {
            loop {
                let mut buf = match buffers.pop() {
                    Some(buf) => buf,
                    None => recycle_rx.recv().map_err(|_| {
                        std::io::Error::other("PAR2 verify hash workers stopped early")
                    })?,
                };
                let request = if total < diagnostic_end {
                    let group = total / group_bytes;
                    let group_end = group
                        .saturating_add(1)
                        .saturating_mul(group_bytes)
                        .min(diagnostic_end);
                    crate::disk::chunk_len(group_end - total, buf.len())
                } else {
                    buf.len()
                };
                let n = read_retry(&mut src, &mut buf[..request])?;
                if n == 0 {
                    buffers.push(buf);
                    break;
                }

                whole.update(&buf[..n]);
                if total < HASH16K_LEN as u64 {
                    let take = ((HASH16K_LEN as u64 - total) as usize).min(n);
                    head.update(&buf[..take]);
                }

                let offset = total;
                total += n as u64;
                if offset < diagnostic_end {
                    let group = (offset / group_bytes) as usize;
                    let lane = group_lanes[group];
                    if lane != usize::MAX {
                        senders[lane]
                            .send(VerifyPipelineBatch {
                                buf,
                                valid: n,
                                offset,
                            })
                            .map_err(|_| {
                                std::io::Error::other("PAR2 verify hash worker stopped early")
                            })?;
                        continue;
                    }
                }
                buffers.push(buf);
            }
            Ok(())
        })();
        drop(senders);
        let lane_matches = handles
            .into_iter()
            .flat_map(|handle| handle.join().expect("PAR2 verify hash worker panicked"))
            .collect::<Vec<_>>();
        (read_result, lane_matches)
    });
    read_result?;

    let md5: [u8; 16] = whole.finalize().into();
    let md5_16k: [u8; 16] = head.finalize().into();
    let md5_ok = total == file.length && md5 == file.md5;
    let mut blocks = vec![false; file.blocks.len()];
    if md5_ok {
        blocks.fill(true);
    } else {
        for index in lane_matches {
            blocks[index] = true;
        }
    }
    Ok(FileVerify {
        blocks,
        md5_ok,
        md5_16k_ok: md5_16k == file.md5_16k,
    })
}

fn regular_file_size_mismatch(is_file: bool, observed: u64, expected: u64) -> bool {
    is_file && observed != expected
}

fn verify_blocks_path_or_streaming(
    path: &Path,
    src: &mut File,
    file: &Par2File,
    block_size: u64,
    disk_len: u64,
    threads: usize,
) -> std::io::Result<Vec<bool>> {
    if threads > 1 && file.blocks.len() > 1 && disk_len >= VERIFY_PAR_MIN_BYTES && block_size > 0 {
        verify_blocks_path_parallel(path, src, file, block_size, disk_len, threads)
    } else {
        src.seek(SeekFrom::Start(0))?;
        verify_blocks_streaming(file, block_size, src)
    }
}

struct WholeVerify {
    md5_ok: bool,
    md5_16k_ok: bool,
}

fn verify_whole<R: Read>(file: &Par2File, src: &mut R) -> std::io::Result<WholeVerify> {
    verify_whole_sized(file, src, VERIFY_CHUNK)
}

// File-backed verification knows both the described and current lengths.
// Avoid zeroing a full MiB for every tiny member while keeping a 64 KiB
// floor so a file that grows after metadata() cannot turn into a syscall per
// handful of bytes. Large payloads retain the measured one-MiB window.
const VERIFY_MIN_CHUNK: usize = 64 << 10;

fn whole_file_buffer_len(file_len: u64, disk_len: u64) -> usize {
    file_len
        .max(disk_len)
        .clamp(VERIFY_MIN_CHUNK as u64, VERIFY_CHUNK as u64) as usize
}

fn verify_whole_sized<R: Read>(
    file: &Par2File,
    src: &mut R,
    buffer_len: usize,
) -> std::io::Result<WholeVerify> {
    let mut buf = vec![0u8; buffer_len.max(1)];
    let mut whole = Md5::new();
    let mut head = Md5::new();
    let mut total = 0u64;
    loop {
        let n = read_retry(src, &mut buf)?;
        if n == 0 {
            break;
        }
        whole.update(&buf[..n]);
        if total < HASH16K_LEN as u64 {
            let take = ((HASH16K_LEN as u64 - total) as usize).min(n);
            head.update(&buf[..take]);
        }
        total += n as u64;
    }
    let md5: [u8; 16] = whole.finalize().into();
    let md5_16k: [u8; 16] = head.finalize().into();
    Ok(WholeVerify {
        md5_ok: total == file.length && md5 == file.md5,
        md5_16k_ok: md5_16k == file.md5_16k,
    })
}

fn verify_md5_sized<R: Read>(
    file: &Par2File,
    src: &mut R,
    buffer_len: usize,
) -> std::io::Result<bool> {
    let mut buf = vec![0u8; buffer_len.max(1)];
    let mut whole = Md5::new();
    let mut total = 0u64;
    loop {
        let n = read_retry(src, &mut buf)?;
        if n == 0 {
            break;
        }
        whole.update(&buf[..n]);
        total += n as u64;
    }
    Ok(total == file.length && <[u8; 16]>::from(whole.finalize()) == file.md5)
}

fn verify_head<R: Read>(file: &Par2File, src: &mut R) -> std::io::Result<bool> {
    let mut buf = [0u8; HASH16K_LEN];
    let mut filled = 0usize;
    while filled < buf.len() {
        let n = read_retry(src, &mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(<[u8; 16]>::from(Md5::digest(&buf[..filled])) == file.md5_16k)
}

/// Bound the second-pass pool to 64 one-MiB buffers even when a launcher's
/// worker ceiling is much higher than a desktop's core count.
const VERIFY_POOL_BYTES: usize = 64 << 20;
/// Hard ceiling on verification hash lanes. The byte cap above is not a
/// thread cap when PAR2 slices are tiny: at the legal four-byte minimum it
/// would admit more than sixteen million four-byte buffers. Keep both the
/// public `threads` hint and the directory-level scheduler from turning a
/// malformed or accidental request into a thread-exhaustion panic.
#[doc(hidden)]
pub const VERIFY_MAX_WORKERS: usize = 64;
#[cfg(not(any(test, fuzzing)))]
const VERIFY_PAR_MIN_BYTES: u64 = 8 << 20;
// Exercise the production branch cheaply in unit tests. The threshold only
// chooses an implementation; both are held to the buffered oracle.
#[cfg(any(test, fuzzing))]
const VERIFY_PAR_MIN_BYTES: u64 = 64 << 10;

fn verify_blocks_path_parallel(
    _path: &Path,
    _source: &File,
    file: &Par2File,
    block_size: u64,
    disk_len: u64,
    threads: usize,
) -> std::io::Result<Vec<bool>> {
    let bs = block_size as usize;
    let diagnostic_blocks = diagnostic_block_count(&file.blocks);
    if bs == 0 || diagnostic_blocks == 0 {
        return Ok(vec![false; file.blocks.len()]);
    }
    let proven_blocks = file.blocks[..diagnostic_blocks]
        .iter()
        .filter(|check| check.is_proven())
        .count();
    // ONE SLICE PER READ, deliberately. Lane B coalesced consecutive proved
    // slices into <=512 KiB positioned reads here and measured -20.6% wall
    // on a dense 64 KiB grid; re-measured through this path on 3 Sep 2026 it
    // was FLAT on both an M3 Ultra and a Zen 4 box, warm cache and cold, and
    // cost +23 MB of resident buffers - see the verify section of
    // research/PAR2-TWO-LANES-COMPARED-2026-09-03.md. Its number came from a
    // single-threaded in-library harness; the ranges above already spread the
    // reads over up to 64 lanes, which is what hides the syscall count.
    // Worth revisiting ONLY on high-latency storage (a NAS or network mount),
    // where a pread is a round trip rather than a page-cache hit and neither
    // box on this fleet can see the difference.
    let chunk_buf = bs.min(VERIFY_CHUNK);
    let workers = bounded_verify_workers(threads, proven_blocks, chunk_buf);
    let (per, raw_ranges) = raw_range_geometry(diagnostic_blocks, workers);
    let balanced = (proven_blocks < diagnostic_blocks)
        .then(|| balanced_proven_ranges(&file.blocks[..diagnostic_blocks], workers, proven_blocks))
        .flatten();
    let first_end = balanced.as_ref().map_or(per, |ranges| ranges.ends()[0]);
    let range_count = balanced.as_ref().map_or(raw_ranges, |ranges| ranges.len());
    let mut blocks = vec![false; file.blocks.len()];
    let (caller_blocks, child_blocks) = blocks[..diagnostic_blocks].split_at_mut(first_end);
    let mut child_out: Vec<std::io::Result<()>> = (1..range_count).map(|_| Ok(())).collect();
    let verify_range = |first_block: usize, oks: &mut [bool]| -> std::io::Result<()> {
        // Unix pread is cursor-independent, so every lane can share the
        // handle already opened for the whole-file pass. Besides avoiding
        // repeated open/name lookup, this keeps an atomic path replacement
        // between passes on the same inode and removes up to 64 live
        // descriptors.
        #[cfg(unix)]
        let src = _source;
        // Windows FileExt::seek_read moves the handle cursor; independent
        // lanes therefore still require independent handles there. Reopen
        // from the pinned source handle, never its pathname, so a replacement
        // between passes cannot switch the file being diagnosed. This includes
        // the caller range: one handle per simultaneously active lane.
        #[cfg(windows)]
        let owned = crate::disk::reopen_read_handle(_source)?;
        #[cfg(windows)]
        let src = &owned;
        let mut buf = Vec::new();
        // Reuse the selected implementations as well as their state. In
        // particular, constructing crc32fast::Hasher repeats its runtime
        // CPU-feature selection.
        let mut bmd5 = Md5::new();
        let mut bcrc = crc32fast::Hasher::new();
        let mut j = 0usize;
        while j < oks.len() {
            let bidx = first_block + j;
            let check = &file.blocks[bidx];
            // Positioned workers can omit the read as well as both hashes.
            // This matters for a short IFSC: its fitted UNPROVEN suffix may
            // span most of a large member, and every corresponding verdict
            // is already known to be false.
            if !check.is_proven() {
                j += 1;
                continue;
            }
            let off = bidx as u64 * block_size;
            if off >= disk_len {
                j += 1;
                continue;
            }
            if buf.is_empty() {
                // Keep the allocator's zero-page behaviour: a resize from an
                // empty Vec eagerly dirties the buffer on some allocators,
                // while `vec![0; n]` can stay demand-zero until positioned
                // reads populate it.
                buf = vec![0u8; chunk_buf];
            }
            let avail = (disk_len - off).min(block_size);

            // One read holds the whole slice whenever the block is no wider
            // than the read window, which is every block at or below
            // `VERIFY_CHUNK` - the shape a dense grid actually has. Its
            // bytes are then resident and the CRC can gate the MD5 for
            // free. Wider blocks fall through to the interleaved loop.
            if avail <= buf.len() as u64 {
                let take = avail as usize;
                crate::disk::read_exact_at(src, &mut buf[..take], off)?;
                oks[j] = prove_resident_block(
                    check,
                    &buf[..take],
                    block_size - avail,
                    &mut bcrc,
                    &mut bmd5,
                );
                j += 1;
                continue;
            }

            let mut pos = 0u64;
            while pos < avail {
                let take = crate::disk::chunk_len(avail - pos, buf.len());
                crate::disk::read_exact_at(src, &mut buf[..take], off + pos)?;
                bmd5.update(&buf[..take]);
                bcrc.update(&buf[..take]);
                pos += take as u64;
            }
            if avail < block_size {
                const ZEROS: [u8; 8192] = [0u8; 8192];
                let mut pad = block_size - avail;
                while pad > 0 {
                    let take = crate::disk::chunk_len(pad, ZEROS.len());
                    bmd5.update(&ZEROS[..take]);
                    pad -= take as u64;
                }
            }
            let md5: [u8; 16] = bmd5.finalize_reset().into();
            let crc = bcrc.clone().finalize();
            bcrc.reset();
            let crc = if avail == block_size {
                crc
            } else {
                crate::yenc_simd::crc32_zeros(crc, block_size - avail)
            };
            oks[j] = md5 == check.md5 && crc == check.crc32;
            j += 1;
        }
        Ok(())
    };
    let caller_out = std::thread::scope(|scope| {
        if let Some(ranges) = balanced.as_ref() {
            let mut remaining = child_blocks;
            let mut first_block = first_end;
            for (&end, result) in ranges.ends()[1..].iter().zip(child_out.iter_mut()) {
                let (oks, rest) = remaining.split_at_mut(end - first_block);
                remaining = rest;
                let range_start = first_block;
                first_block = end;
                let verify_range = &verify_range;
                scope.spawn(move || {
                    *result = verify_range(range_start, oks);
                });
            }
        } else {
            for (child_index, (oks, result)) in child_blocks
                .chunks_mut(per)
                .zip(child_out.iter_mut())
                .enumerate()
            {
                let verify_range = &verify_range;
                scope.spawn(move || {
                    *result = verify_range((child_index + 1) * per, oks);
                });
            }
        }
        verify_range(0, caller_blocks)
    });
    caller_out?;
    for result in child_out {
        result?;
    }
    Ok(blocks)
}

/// Width and actual range count for a requested diagnostic pool. Keeping the
/// actual count explicit makes the thread budget unambiguous: range zero runs
/// on the caller and only `ranges - 1` children are created.
pub(crate) fn raw_range_geometry(blocks: usize, workers: usize) -> (usize, usize) {
    if blocks == 0 || workers == 0 {
        return (0, 0);
    }
    let per = blocks.div_ceil(workers);
    (per, blocks.div_ceil(per))
}

/// End offsets for a sparse diagnostic layout worth rebalancing. The fixed
/// array keeps planning inside the same 64-worker ceiling as execution.
pub(crate) struct ProvenRangeEnds {
    ends: [usize; VERIFY_MAX_WORKERS],
    len: usize,
}

impl ProvenRangeEnds {
    pub(crate) fn ends(&self) -> &[usize] {
        &self.ends[..self.len]
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }
}

/// Contiguous diagnostic ranges balanced by checks that can still become
/// true, rather than by placeholder slots. Already-balanced sparse grids keep
/// the raw path; only a lane more than 25% above ideal pays for new boundaries.
/// Every returned lane still walks increasing file offsets.
pub(crate) fn balanced_proven_ranges(
    blocks: &[BlockCheck],
    workers: usize,
    proven_blocks: usize,
) -> Option<ProvenRangeEnds> {
    if blocks.is_empty() || workers == 0 || proven_blocks == 0 || proven_blocks == blocks.len() {
        return None;
    }
    let (per, raw_ranges) = raw_range_geometry(blocks.len(), workers.min(VERIFY_MAX_WORKERS));
    let mut raw_work = [0usize; VERIFY_MAX_WORKERS];
    for (index, check) in blocks.iter().enumerate() {
        if check.is_proven() {
            raw_work[(index / per).min(raw_ranges - 1)] += 1;
        }
    }
    debug_assert_eq!(raw_work[..raw_ranges].iter().sum::<usize>(), proven_blocks);
    let ideal = proven_blocks.div_ceil(raw_ranges);
    let rebalance_above = ideal.saturating_add(ideal / 4);
    if raw_work[..raw_ranges]
        .iter()
        .copied()
        .max()
        .is_none_or(|work| work <= rebalance_above)
    {
        return None;
    }

    let lanes = raw_ranges.min(proven_blocks);
    let base = proven_blocks / lanes;
    let extra = proven_blocks % lanes;
    let mut ends = [0usize; VERIFY_MAX_WORKERS];
    let mut len = 0usize;
    let mut in_lane = 0usize;
    let mut quota = base + usize::from(extra > 0);
    for (index, check) in blocks.iter().enumerate() {
        if check.is_proven() {
            in_lane += 1;
        }
        if in_lane == quota && len + 1 < lanes {
            ends[len] = index + 1;
            len += 1;
            in_lane = 0;
            quota = base + usize::from(len < extra);
        }
    }
    ends[len] = blocks.len();
    len += 1;
    debug_assert_eq!(len, lanes);
    Some(ProvenRangeEnds { ends, len })
}

/// Number of leading block slots a diagnostic pass may have to visit.
///
/// `fit_ifsc` pads a short packet with an UNPROVEN suffix. Looking from the
/// back makes the well-formed/common case one comparison, while letting all
/// readers stop before a potentially enormous suffix whose answer is already
/// known. Adversarial interior UNPROVEN cells remain in the span and are
/// skipped individually so later real checks still see their proper offsets.
fn diagnostic_block_count(blocks: &[BlockCheck]) -> usize {
    blocks
        .iter()
        .rposition(BlockCheck::is_proven)
        .map_or(0, |index| index + 1)
}

/// Resolve a caller's worker hint without ever permitting zero lanes or a
/// pool wider than this machine can run. Split out so the hostile extrema
/// (`0`, `usize::MAX`, and a zero-sized hypothetical buffer) can be tested
/// without actually trying to create the corresponding threads.
fn bounded_verify_workers(requested: usize, blocks: usize, chunk_buf: usize) -> usize {
    if blocks == 0 {
        return 0;
    }
    requested
        .max(1)
        .min(blocks)
        .min(crate::mem::cpu_workers().max(1))
        .min(VERIFY_MAX_WORKERS)
        .min((VERIFY_POOL_BYTES / chunk_buf.max(1)).max(1))
}

/// The diagnostic half of [`verify_file_seekable`], split out so its second
/// pass does not recompute the whole-file digest it already knows failed.
fn verify_blocks_streaming<R: Read>(
    file: &Par2File,
    block_size: u64,
    mut src: R,
) -> std::io::Result<Vec<bool>> {
    let bs = block_size as usize;
    let diagnostic_blocks = diagnostic_block_count(&file.blocks);
    if bs == 0 || diagnostic_blocks == 0 {
        return Ok(vec![false; file.blocks.len()]);
    }
    let mut buf = vec![0u8; VERIFY_CHUNK];
    let mut blocks = Vec::with_capacity(file.blocks.len());
    let mut bmd5 = Md5::new();
    let mut bcrc = crc32fast::Hasher::new();
    let mut filled = 0usize;
    let mut bytes_left = block_size.saturating_mul(diagnostic_blocks as u64);
    while blocks.len() < diagnostic_blocks {
        let take = crate::disk::chunk_len(bytes_left, buf.len());
        let n = read_retry(&mut src, &mut buf[..take])?;
        if n == 0 {
            break;
        }
        bytes_left -= n as u64;
        let mut p = 0usize;
        while p < n && blocks.len() < diagnostic_blocks {
            let seg = (bs - filled).min(n - p);
            let check = &file.blocks[blocks.len()];
            let proven = check.is_proven();
            // Whole slice resident in this read: CRC gates the MD5 for
            // free. A block split across reads keeps the interleaved feed.
            if filled == 0 && seg == bs {
                blocks.push(
                    proven
                        && prove_resident_block(check, &buf[p..p + seg], 0, &mut bcrc, &mut bmd5),
                );
                p += seg;
                continue;
            }
            if proven {
                bmd5.update(&buf[p..p + seg]);
                bcrc.update(&buf[p..p + seg]);
            }
            filled += seg;
            p += seg;
            if filled == bs {
                if proven {
                    let md5: [u8; 16] = std::mem::take(&mut bmd5).finalize().into();
                    let crc = std::mem::replace(&mut bcrc, crc32fast::Hasher::new()).finalize();
                    blocks.push(md5 == check.md5 && crc == check.crc32);
                } else {
                    blocks.push(false);
                }
                filled = 0;
            }
        }
    }
    finish_partial_block(file, bs, &mut blocks, bmd5, bcrc, filled);
    blocks.resize(file.blocks.len(), false);
    Ok(blocks)
}

fn finish_partial_block(
    file: &Par2File,
    bs: usize,
    blocks: &mut Vec<bool>,
    mut bmd5: Md5,
    bcrc: crc32fast::Hasher,
    filled: usize,
) {
    if filled == 0 || blocks.len() >= file.blocks.len() {
        return;
    }
    let check = &file.blocks[blocks.len()];
    if !check.is_proven() {
        blocks.push(false);
        return;
    }
    const ZEROS: [u8; 8192] = [0u8; 8192];
    let mut pad = bs - filled;
    while pad > 0 {
        let take = pad.min(ZEROS.len());
        bmd5.update(&ZEROS[..take]);
        pad -= take;
    }
    let md5: [u8; 16] = bmd5.finalize().into();
    let crc = crate::yenc_simd::crc32_zeros(bcrc.finalize(), (bs - filled) as u64);
    blocks.push(md5 == check.md5 && crc == check.crc32);
}

fn read_retry<R: Read>(src: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    loop {
        match src.read(buf) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

/// Streaming twin of [`verify_file`]: identical verdicts, one pass over the
/// bytes, ~1 MiB resident whatever the file's size.
///
/// [`verify_file`] needs the whole candidate in memory and then walks it
/// twice - once for the whole-file MD5, once again per block - so a 30 GB
/// set member cost 30 GB of RSS and two full MD5 passes over cold pages.
/// This reads `src` in [`VERIFY_CHUNK`] pieces and feeds the whole-file
/// MD5, the 16k head MD5 and the per-block MD5+CRC32 from the one copy.
/// UNPROVEN cells still contribute to both FileDesc hashes, but do not pay
/// for block hash state whose verdict is necessarily false on a mismatch.
///
/// The buffered form stays as the reference implementation these results
/// are differential-tested against (see `verify_file_blocks`' docs); a
/// divergence between the two is a verification verdict changing under a
/// performance change, which this crate does not permit.
///
/// `src` is read to EOF, so the byte count it yields plays the role
/// `data.len()` plays in [`verify_file`]: short input leaves the blocks
/// past it `false` and fails the whole-file MD5, trailing input past the
/// last expected block feeds only the whole-file MD5.
pub fn verify_file_streaming<R: Read>(
    file: &Par2File,
    block_size: u64,
    src: R,
) -> std::io::Result<FileVerify> {
    verify_file_streaming_sized(file, block_size, src, VERIFY_CHUNK)
}

fn verify_file_streaming_sized<R: Read>(
    file: &Par2File,
    block_size: u64,
    mut src: R,
    buffer_len: usize,
) -> std::io::Result<FileVerify> {
    let bs = block_size as usize;
    let mut buf = vec![0u8; buffer_len.max(1)];
    let mut whole = Md5::new();
    let mut head = Md5::new();
    let mut total: u64 = 0;

    let mut blocks: Vec<bool> = Vec::with_capacity(file.blocks.len());
    let mut bmd5 = Md5::new();
    let mut bcrc = crc32fast::Hasher::new();
    let mut filled = 0usize; // bytes of the current block already fed
    let diagnostic_blocks = diagnostic_block_count(&file.blocks);

    loop {
        let n = read_retry(&mut src, &mut buf)?;
        if n == 0 {
            break;
        }
        whole.update(&buf[..n]);
        // See module docs: first min(len, 16k) bytes, NOT zero-padded.
        if total < HASH16K_LEN as u64 {
            let take = ((HASH16K_LEN as u64 - total) as usize).min(n);
            head.update(&buf[..take]);
        }
        total += n as u64;

        // Blocks straddle reads freely; the hashers accumulate across them
        // and close at each boundary. Stops once every expected block has a
        // flag - trailing bytes past the last block are the whole-file
        // MD5's business only, exactly as in the buffered form.
        if bs > 0 {
            let mut p = 0usize;
            while p < n && blocks.len() < diagnostic_blocks {
                let seg = (bs - filled).min(n - p);
                let check = &file.blocks[blocks.len()];
                let proven = check.is_proven();
                // Whole slice resident in this read: the CRC gates the MD5
                // for free. THIS is the arm a normal multi-member set takes
                // - `verify_dir` gives each outer worker `machine/workers`
                // inner lanes, so a 21-volume release arrives here with one
                // lane and this streamer, not the pipeline above. A block
                // split across reads keeps the interleaved feed below.
                if filled == 0 && seg == bs {
                    blocks.push(
                        proven
                            && prove_resident_block(
                                check,
                                &buf[p..p + seg],
                                0,
                                &mut bcrc,
                                &mut bmd5,
                            ),
                    );
                    p += seg;
                    continue;
                }
                if proven {
                    bmd5.update(&buf[p..p + seg]);
                    bcrc.update(&buf[p..p + seg]);
                }
                filled += seg;
                p += seg;
                if filled == bs {
                    if proven {
                        let md5: [u8; 16] = std::mem::take(&mut bmd5).finalize().into();
                        let crc = std::mem::replace(&mut bcrc, crc32fast::Hasher::new()).finalize();
                        blocks.push(md5 == check.md5 && crc == check.crc32);
                    } else {
                        blocks.push(false);
                    }
                    filled = 0;
                }
            }
        }
    }

    // The final short block uses the diagnostic pass' identical padding
    // and UNPROVEN semantics. Keeping one closer avoids the one-pass and
    // rewind implementations drifting at this unusually expensive edge
    // (`bs` reaches 256 MiB).
    finish_partial_block(file, bs, &mut blocks, bmd5, bcrc, filled);
    // Blocks the input never reached at all.
    blocks.resize(file.blocks.len(), false);

    let md5: [u8; 16] = whole.finalize().into();
    let md5_16k: [u8; 16] = head.finalize().into();
    let md5_ok = total == file.length && md5 == file.md5;
    Ok(FileVerify {
        // The whole-file MD5 arbitrates - see [`verify_file`], whose
        // verdicts this must match byte for byte. The streaming form
        // cannot skip the per-block work the way the buffered one does
        // (it learns `md5_ok` only at EOF, by which time the blocks are
        // already hashed out of the same copy), so it overwrites instead.
        blocks: if md5_ok {
            vec![true; file.blocks.len()]
        } else {
            blocks
        },
        md5_ok,
        md5_16k_ok: md5_16k == file.md5_16k,
    })
}

#[cfg(test)]
mod worker_bound_tests {
    use super::*;

    fn proven(byte: u8) -> BlockCheck {
        BlockCheck {
            md5: [byte; 16],
            crc32: byte as u32,
        }
    }

    #[test]
    fn diagnostic_span_trims_only_the_unproven_suffix() {
        assert_eq!(diagnostic_block_count(&[]), 0);
        assert_eq!(diagnostic_block_count(&[BlockCheck::UNPROVEN; 4]), 0);
        assert_eq!(diagnostic_block_count(&[proven(1)]), 1);
        assert_eq!(
            diagnostic_block_count(&[
                BlockCheck::UNPROVEN,
                proven(2),
                BlockCheck::UNPROVEN,
                proven(3),
                BlockCheck::UNPROVEN,
            ]),
            4,
            "an interior placeholder cannot move a later check's offset"
        );
    }

    #[test]
    fn verify_worker_hint_is_bounded_at_hostile_extrema() {
        let machine_cap = crate::mem::cpu_workers().clamp(1, VERIFY_MAX_WORKERS);
        assert_eq!(
            bounded_verify_workers(usize::MAX, usize::MAX, 4),
            machine_cap
        );
        assert_eq!(bounded_verify_workers(0, usize::MAX, 4), 1);
        assert_eq!(bounded_verify_workers(usize::MAX, 0, 4), 0);
        assert_eq!(
            bounded_verify_workers(usize::MAX, usize::MAX, usize::MAX),
            1,
            "a buffer larger than the byte budget still gets one progress lane"
        );
        assert_eq!(
            bounded_verify_workers(usize::MAX, usize::MAX, 0),
            machine_cap,
            "zero cannot divide the byte budget or produce zero lanes"
        );
    }

    #[test]
    fn caller_lane_keeps_nested_fanout_inside_the_machine_budget() {
        assert_eq!(raw_range_geometry(0, 8), (0, 0));
        assert_eq!(raw_range_geometry(8, 0), (0, 0));
        for blocks in 1..=257usize {
            for workers in 1..=128usize {
                let (per, ranges) = raw_range_geometry(blocks, workers);
                assert!(per > 0);
                assert_eq!(ranges, blocks.div_ceil(per));
                assert!(ranges <= workers.min(blocks));
                assert_eq!(
                    ranges.saturating_sub(1),
                    blocks.saturating_sub(per).div_ceil(per)
                );
            }
        }

        // `verify_all_targets` uses `inner = machine / outer`. Its outer
        // threads are the caller lanes here, so including only the remaining
        // inner ranges as children can never oversubscribe that budget.
        for machine in 1..=128usize {
            for outer in 1..=machine {
                let inner = machine / outer;
                let (_, ranges) = raw_range_geometry(4096, inner);
                let peak_nested_threads = outer + outer * (ranges - 1);
                assert!(peak_nested_threads <= machine);
            }
        }
    }

    #[test]
    fn only_materially_clustered_proofs_replace_raw_ranges() {
        let mut clustered = [BlockCheck::UNPROVEN; 64];
        clustered[32..].fill(proven(1));
        let plan = balanced_proven_ranges(&clustered, 8, 32).unwrap();
        assert_eq!(plan.ends(), &[36, 40, 44, 48, 52, 56, 60, 64]);
        let mut start = 0usize;
        for &end in plan.ends() {
            assert_eq!(
                clustered[start..end]
                    .iter()
                    .filter(|check| check.is_proven())
                    .count(),
                4
            );
            start = end;
        }

        assert!(balanced_proven_ranges(&[proven(2); 64], 8, 64).is_none());
        let mut periodic = [BlockCheck::UNPROVEN; 64];
        for check in periodic.iter_mut().step_by(2) {
            *check = proven(3);
        }
        assert!(
            balanced_proven_ranges(&periodic, 8, 32).is_none(),
            "an already-even sparse grid must retain the allocation-free raw path"
        );

        // Exhaust all short layouts. Whenever the imbalance gate elects to
        // replace raw geometry, the result covers every slot exactly once,
        // never exceeds the worker ceiling, and differs by at most one proved
        // cell between lanes.
        for bits in 2..=12usize {
            for mask in 1usize..(1usize << bits) {
                let mut checks = vec![BlockCheck::UNPROVEN; bits];
                for (index, check) in checks.iter_mut().enumerate() {
                    if mask & (1 << index) != 0 {
                        *check = proven(4);
                    }
                }
                let proved = mask.count_ones() as usize;
                for workers in 1..=8usize {
                    let Some(plan) = balanced_proven_ranges(&checks, workers, proved) else {
                        continue;
                    };
                    assert!(plan.len() <= workers.min(VERIFY_MAX_WORKERS));
                    assert_eq!(plan.ends().last().copied(), Some(bits));
                    let mut start = 0usize;
                    let mut least = usize::MAX;
                    let mut most = 0usize;
                    for &end in plan.ends() {
                        assert!(end > start && end <= bits);
                        let work = checks[start..end]
                            .iter()
                            .filter(|check| check.is_proven())
                            .count();
                        least = least.min(work);
                        most = most.max(work);
                        start = end;
                    }
                    assert!(most - least <= 1, "mask={mask:#x} workers={workers}");
                }
            }
        }
    }

    #[test]
    fn file_hash_window_shrinks_only_for_small_known_files() {
        assert_eq!(whole_file_buffer_len(0, 0), VERIFY_MIN_CHUNK);
        assert_eq!(
            whole_file_buffer_len(17, VERIFY_MIN_CHUNK as u64 + 9),
            VERIFY_MIN_CHUNK + 9
        );
        assert_eq!(
            whole_file_buffer_len(VERIFY_CHUNK as u64 * 2, 0),
            VERIFY_CHUNK
        );
        assert_eq!(
            whole_file_buffer_len(0, VERIFY_CHUNK as u64 * 2),
            VERIFY_CHUNK
        );
    }

    #[test]
    fn only_regular_size_mismatches_take_the_diagnostic_shortcut() {
        assert!(!regular_file_size_mismatch(true, 4096, 4096));
        assert!(regular_file_size_mismatch(true, 4095, 4096));
        assert!(regular_file_size_mismatch(true, 4097, 4096));
        assert!(
            !regular_file_size_mismatch(false, 0, 4096),
            "a FIFO or device length is not its stream length"
        );
        assert!(!regular_file_size_mismatch(false, 4096, 4096));
    }

    /// A FIFO reports no useful metadata length and cannot seek. It must be
    /// consumed by the one-pass verifier even when its writer yields a complete
    /// member whose declared length is nonzero.
    #[cfg(unix)]
    #[test]
    fn file_path_streams_non_regular_input() {
        use std::ffi::CString;
        use std::io::Write;
        use std::os::unix::ffi::OsStrExt;

        const BS: usize = 4096;
        let data: Vec<u8> = (0..BS + 137)
            .map(|i| (i as u8).wrapping_mul(29).wrapping_add((i >> 6) as u8))
            .collect();
        let mut padded = vec![0u8; BS];
        let blocks = data
            .chunks(BS)
            .map(|chunk| {
                padded.fill(0);
                padded[..chunk.len()].copy_from_slice(chunk);
                BlockCheck {
                    md5: Md5::digest(&padded).into(),
                    crc32: crc32fast::hash(&padded),
                }
            })
            .collect();
        let file = Par2File {
            file_id: [0; 16],
            name: "stream.fifo".into(),
            length: data.len() as u64,
            md5: Md5::digest(&data).into(),
            md5_16k: Md5::digest(&data).into(),
            blocks,
        };
        let path =
            std::env::temp_dir().join(format!("nzbkit-verify-stream-fifo-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c_path` is a live, NUL-terminated pathname and mode carries
        // only ordinary permission bits.
        let made = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(
            made,
            0,
            "mkfifo failed: {}",
            std::io::Error::last_os_error()
        );

        let writer_path = path.clone();
        let writer_data = data.clone();
        let writer = std::thread::spawn(move || {
            let mut fifo = std::fs::OpenOptions::new()
                .write(true)
                .open(writer_path)
                .unwrap();
            fifo.write_all(&writer_data).unwrap();
        });
        let got = verify_file_path(&path, &file, BS as u64, 4).unwrap();
        writer.join().unwrap();
        let _ = std::fs::remove_file(path);

        assert!(got.md5_ok);
        assert!(got.md5_16k_ok);
        assert_eq!(got.blocks, [true, true]);
    }

    /// Unix FileExt is a true pread: all diagnostic workers can share the
    /// already-open handle, even after its directory entry is gone. This
    /// pins the resource optimization and, more importantly, stops a path
    /// replacement between passes from silently switching the inode being
    /// diagnosed. Windows has cursor-moving `seek_read` and deliberately
    /// reopens one independent cursor per lane from that same pinned handle.
    #[cfg(unix)]
    #[test]
    fn unix_parallel_diagnostics_use_the_existing_handle() {
        const BS: usize = 4096;
        let data: Vec<u8> = (0..3 * BS)
            .map(|i| (i as u8).wrapping_mul(37).wrapping_add((i >> 7) as u8))
            .collect();
        let blocks = data
            .as_chunks::<BS>()
            .0
            .iter()
            .map(|block| BlockCheck {
                md5: Md5::digest(block).into(),
                crc32: crc32fast::hash(block),
            })
            .collect();
        let file = Par2File {
            file_id: [0; 16],
            name: "unlinked.bin".into(),
            length: data.len() as u64,
            md5: Md5::digest(&data).into(),
            md5_16k: Md5::digest(&data).into(),
            blocks,
        };
        let path = std::env::temp_dir().join(format!(
            "nzbkit-shared-verify-handle-{}",
            std::process::id()
        ));
        std::fs::write(&path, &data).unwrap();
        let source = File::open(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let got =
            verify_blocks_path_parallel(&path, &source, &file, BS as u64, data.len() as u64, 3)
                .unwrap();
        assert_eq!(got, [true, true, true]);
    }

    /// The metadata length is deliberately larger than the file backing the
    /// reader. Trying to read either trailing cell would therefore return an
    /// unexpected-EOF error; both are UNPROVEN, so their exact and sufficient
    /// diagnostic verdict is `false` without touching those offsets.
    #[test]
    fn positioned_diagnostics_do_not_read_an_unproven_suffix() {
        const BS: usize = 64 << 10;
        let data: Vec<u8> = (0..BS)
            .map(|i| (i as u8).wrapping_mul(37).wrapping_add((i >> 7) as u8))
            .collect();
        let check = BlockCheck {
            md5: Md5::digest(&data).into(),
            crc32: crc32fast::hash(&data),
        };
        let file = Par2File {
            file_id: [0; 16],
            name: "short-ifsc.bin".into(),
            length: (3 * BS) as u64,
            md5: [0x55; 16],
            md5_16k: Md5::digest(&data[..HASH16K_LEN]).into(),
            blocks: vec![check, BlockCheck::UNPROVEN, BlockCheck::UNPROVEN],
        };
        let path = std::env::temp_dir().join(format!(
            "nzbkit-unproven-positioned-read-{}",
            std::process::id()
        ));
        std::fs::write(&path, &data).unwrap();
        let source = File::open(&path).unwrap();
        let got =
            verify_blocks_path_parallel(&path, &source, &file, BS as u64, file.length, usize::MAX)
                .unwrap();
        let _ = std::fs::remove_file(path);
        assert_eq!(got, [true, false, false]);
    }

    #[test]
    fn clustered_positioned_ranges_match_the_buffered_oracle() {
        const BS: usize = 4096;
        const BLOCKS: usize = 32;
        let expected: Vec<u8> = (0..BLOCKS * BS)
            .map(|i| (i as u8).wrapping_mul(29).wrapping_add((i >> 8) as u8))
            .collect();
        let mut checks = vec![BlockCheck::UNPROVEN; BLOCKS];
        for (index, block) in expected.as_chunks::<BS>().0.iter().enumerate().skip(24) {
            checks[index] = BlockCheck {
                md5: Md5::digest(block).into(),
                crc32: crc32fast::hash(block),
            };
        }
        let file = Par2File {
            file_id: [0; 16],
            name: "clustered.bin".into(),
            length: expected.len() as u64,
            md5: Md5::digest(&expected).into(),
            md5_16k: Md5::digest(&expected[..HASH16K_LEN]).into(),
            blocks: checks,
        };
        let mut candidate = expected.clone();
        candidate[29 * BS + 17] ^= 0x5a;
        // Keep the file-backed production route on positioned diagnostics:
        // exact-size regular files deliberately use the one-pass verifier.
        candidate.pop();
        let oracle = verify_file(&file, BS as u64, &candidate);
        let path = std::env::temp_dir().join(format!(
            "nzbkit-clustered-positioned-{}",
            std::process::id()
        ));
        std::fs::write(&path, &candidate).unwrap();
        let got = verify_file_path(&path, &file, BS as u64, 8).unwrap();
        let _ = std::fs::remove_file(path);
        assert_eq!(got.blocks, oracle.blocks);
        assert_eq!(got.md5_ok, oracle.md5_ok);
        assert_eq!(got.md5_16k_ok, oracle.md5_16k_ok);
        assert_eq!(got.blocks.iter().filter(|&&ok| ok).count(), 6);
        assert!(!got.blocks[29]);
        assert!(!got.blocks[31]);
    }

    #[test]
    fn caller_and_child_ranges_match_streaming_diagnostics() {
        const BS: usize = 64 << 10;
        let expected: Vec<u8> = (0..7 * BS + 123)
            .map(|i| (i as u8).wrapping_mul(73).wrapping_add((i >> 9) as u8))
            .collect();
        let mut padded = vec![0u8; BS];
        let mut checks: Vec<BlockCheck> = expected
            .chunks(BS)
            .map(|chunk| {
                padded.fill(0);
                padded[..chunk.len()].copy_from_slice(chunk);
                BlockCheck {
                    md5: Md5::digest(&padded).into(),
                    crc32: crc32fast::hash(&padded),
                }
            })
            .collect();
        checks[2] = BlockCheck::UNPROVEN;
        let file = Par2File {
            file_id: [0; 16],
            name: "fanout-differential.bin".into(),
            length: expected.len() as u64,
            md5: Md5::digest(&expected).into(),
            md5_16k: Md5::digest(&expected[..HASH16K_LEN]).into(),
            blocks: checks,
        };

        let mut candidate = expected;
        candidate[17] ^= 0xa5; // caller range
        candidate[4 * BS + 31] ^= 0x5a; // child range
        candidate.truncate(candidate.len() - 37); // padded final child range
        let path = std::env::temp_dir().join(format!(
            "nzbkit-verify-caller-differential-{}",
            std::process::id()
        ));
        std::fs::write(&path, &candidate).unwrap();
        let source = File::open(&path).unwrap();
        let parallel = verify_blocks_path_parallel(
            &path,
            &source,
            &file,
            BS as u64,
            candidate.len() as u64,
            4,
        )
        .unwrap();
        let streaming =
            verify_blocks_streaming(&file, BS as u64, File::open(&path).unwrap()).unwrap();
        let _ = std::fs::remove_file(path);

        assert_eq!(parallel, streaming);
        assert_eq!(
            parallel,
            [false, true, false, true, false, true, true, false]
        );
    }

    fn synth_file(data: &[u8], bs: usize) -> Par2File {
        let mut padded = vec![0u8; bs];
        let blocks = data
            .chunks(bs)
            .map(|chunk| {
                padded.fill(0);
                padded[..chunk.len()].copy_from_slice(chunk);
                BlockCheck {
                    md5: Md5::digest(&padded).into(),
                    crc32: crc32fast::hash(&padded),
                }
            })
            .collect();
        Par2File {
            file_id: [0; 16],
            name: "pipeline.bin".into(),
            length: data.len() as u64,
            md5: Md5::digest(data).into(),
            md5_16k: Md5::digest(&data[..data.len().min(HASH16K_LEN)]).into(),
            blocks,
        }
    }

    fn pipeline_temp_path(label: &str) -> std::path::PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "nzbkit-verify-pipeline-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
    }

    fn assert_same_verify(want: &FileVerify, got: &FileVerify, case: &str) {
        assert_eq!(got.md5_ok, want.md5_ok, "{case}: whole MD5");
        assert_eq!(got.md5_16k_ok, want.md5_16k_ok, "{case}: head MD5");
        assert_eq!(got.blocks, want.blocks, "{case}: block bitmap");
    }

    /// The cheap-digest-first order must not move a single verdict, and the
    /// shape it exists FOR is a member whose blocks are mostly bad - which
    /// nothing else here builds (the geometry test damages two). Both sides
    /// of the resident/split boundary are covered (`VERIFY_CHUNK` is 1 MiB)
    /// and so is every door: the buffered reference, the serial streamer,
    /// the exact-size pipeline, the seekable rewind, and the positioned
    /// diagnostics a size mismatch takes.
    ///
    /// One block is left INTACT on purpose. An all-bad file agrees
    /// vacuously - every door would answer false even if the MD5 had
    /// stopped being asked for - so the survivor is what proves the
    /// expensive digest still runs and still says yes behind the cheap one.
    #[test]
    fn a_mostly_damaged_member_agrees_on_every_door_either_side_of_the_read_window() {
        const SURVIVOR: usize = 2;
        // 1 MiB is `VERIFY_CHUNK` exactly (one read holds a whole block);
        // the third is deliberately just WIDER than it, which is the only
        // way to reach the interleaved fallback arms. Kept small: this test
        // hashes each shape through eleven doors in a debug build.
        for bs in [64 << 10, 1 << 20, (1 << 20) + (64 << 10)] {
            let data: Vec<u8> = (0..4 * bs + 291)
                .map(|i| (i as u8).wrapping_mul(31).wrapping_add((i >> 9) as u8))
                .collect();
            let file = synth_file(&data, bs);
            let mut damaged = data.clone();
            for b in 0..file.blocks.len() {
                if b == SURVIVOR {
                    continue;
                }
                // 17 bytes in, so the head MD5 is disturbed too and the
                // final short block is hit inside its real bytes.
                let off = b * bs + 17;
                if off < damaged.len() {
                    damaged[off] ^= 0xff;
                }
            }

            let want = verify_file(&file, bs as u64, &damaged);
            assert!(!want.md5_ok, "bs={bs}: the whole-file proof must fail");
            assert!(want.blocks[SURVIVOR], "bs={bs}: the intact block proves");
            assert_eq!(
                want.blocks.iter().filter(|ok| **ok).count(),
                1,
                "bs={bs}: exactly one block survives"
            );

            let path = pipeline_temp_path(&format!("mostly-bad-{bs}"));
            std::fs::write(&path, &damaged).unwrap();
            // `threads` 1 takes the serial streamer, many takes the pipeline.
            for threads in [0, 1, 2, usize::MAX] {
                let got = verify_file_path(&path, &file, bs as u64, threads).unwrap();
                assert_same_verify(&want, &got, &format!("exact size bs={bs} t={threads}"));
            }
            let got = verify_file_streaming(&file, bs as u64, &damaged[..]).unwrap();
            assert_same_verify(&want, &got, &format!("serial stream bs={bs}"));
            let got =
                verify_file_seekable(&file, bs as u64, std::io::Cursor::new(&damaged)).unwrap();
            assert_same_verify(&want, &got, &format!("seekable bs={bs}"));

            // One byte longer: a known-impossible whole-file MD5 sends
            // `verify_file_path` down the POSITIONED diagnostic shortcut,
            // which is the door with no whole-file chain beside it and so
            // the one this change moves furthest.
            let mut longer = damaged.clone();
            longer.push(0x5a);
            let want_mm = verify_file(&file, bs as u64, &longer);
            assert!(
                want_mm.blocks[SURVIVOR],
                "bs={bs}: survivor across the mismatch"
            );
            std::fs::write(&path, &longer).unwrap();
            for threads in [0, 1, 2, usize::MAX] {
                let got = verify_file_path(&path, &file, bs as u64, threads).unwrap();
                assert_same_verify(
                    &want_mm,
                    &got,
                    &format!("size mismatch bs={bs} t={threads}"),
                );
            }
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn exact_size_pipeline_matches_clean_and_damaged_at_every_geometry() {
        for bs in [64 << 10, 1 << 20, 16 << 20] {
            let data: Vec<u8> = (0..3 * bs + 137)
                .map(|i| (i as u8).wrapping_mul(29).wrapping_add((i >> 11) as u8))
                .collect();
            let file = synth_file(&data, bs);
            let path = pipeline_temp_path(&format!("geometry-{bs}"));
            std::fs::write(&path, &data).unwrap();

            let want_clean = verify_file(&file, bs as u64, &data);
            for threads in [0, 1, 2, usize::MAX] {
                let got = verify_file_path(&path, &file, bs as u64, threads).unwrap();
                assert_same_verify(&want_clean, &got, &format!("clean bs={bs} t={threads}"));
            }

            let mut damaged = data.clone();
            damaged[17] ^= 0x80;
            damaged[2 * bs + 31] ^= 0x40;
            std::fs::write(&path, &damaged).unwrap();
            let want_damaged = verify_file(&file, bs as u64, &damaged);
            for threads in [0, 1, 2, usize::MAX] {
                let got = verify_file_path(&path, &file, bs as u64, threads).unwrap();
                assert_same_verify(&want_damaged, &got, &format!("damaged bs={bs} t={threads}"));
            }
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn pipeline_preserves_unproven_and_partial_tail_semantics() {
        const BS: usize = 1 << 20;
        let data: Vec<u8> = (0..3 * BS + 137)
            .map(|i| (i as u8).wrapping_mul(73).wrapping_add((i >> 13) as u8))
            .collect();
        let path = pipeline_temp_path("unproven-tail");
        std::fs::write(&path, &data).unwrap();

        // Force the bitmap to arbitrate while leaving the short final block
        // byte-exact, so its zero-padding must hash successfully.
        let mut partial = synth_file(&data, BS);
        partial.md5[0] ^= 0x80;
        let want = verify_file(&partial, BS as u64, &data);
        let got = verify_file_path(&path, &partial, BS as u64, usize::MAX).unwrap();
        assert_same_verify(&want, &got, "proved partial tail");
        assert!(got.blocks.iter().all(|&ok| ok));

        // An interior placeholder must not shift later offsets. A suffix
        // placeholder must cost no block-hash work and still remain false.
        let mut sparse = partial.clone();
        sparse.blocks[1] = BlockCheck::UNPROVEN;
        sparse.blocks[3] = BlockCheck::UNPROVEN;
        let mut damaged = data.clone();
        damaged[2 * BS + 11] ^= 0x20;
        std::fs::write(&path, &damaged).unwrap();
        let want = verify_file(&sparse, BS as u64, &damaged);
        let got = verify_file_path(&path, &sparse, BS as u64, usize::MAX).unwrap();
        assert_same_verify(&want, &got, "interior and suffix UNPROVEN");
        assert_eq!(got.blocks, [true, false, false, false]);
        let _ = std::fs::remove_file(path);
    }

    struct CountedChoked<R> {
        inner: R,
        bytes: usize,
        max_read: usize,
    }

    impl<R: Read> Read for CountedChoked<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let cap = buf.len().min(self.max_read);
            let n = self.inner.read(&mut buf[..cap])?;
            self.bytes += n;
            Ok(n)
        }
    }

    #[test]
    fn pipeline_reads_grown_and_shrunk_after_metadata_streams_once() {
        const BS: usize = 64 << 10;
        let expected: Vec<u8> = (0..35 * BS + 137)
            .map(|i| (i as u8).wrapping_mul(41).wrapping_add((i >> 9) as u8))
            .collect();
        let file = synth_file(&expected, BS);
        let mut grown = expected.clone();
        grown.extend((0..2 * BS + 79).map(|i| (i as u8).wrapping_mul(97)));
        let shrunk = &expected[..expected.len() - BS - 17];

        for (label, actual) in [("grown", grown.as_slice()), ("shrunk", shrunk)] {
            let want =
                verify_file_streaming(&file, BS as u64, std::io::Cursor::new(actual)).unwrap();
            let mut counted = CountedChoked {
                inner: std::io::Cursor::new(actual),
                bytes: 0,
                max_read: 19_997,
            };
            let got = verify_file_streaming_path(
                &file,
                BS as u64,
                &mut counted,
                file.length,
                usize::MAX,
                VERIFY_CHUNK,
            )
            .unwrap();
            assert_same_verify(&want, &got, label);
            assert_eq!(
                counted.bytes,
                actual.len(),
                "{label}: exactly one read pass"
            );
        }
    }

    #[test]
    fn pipeline_counts_the_caller_and_bounds_every_buffer() {
        assert_eq!(bounded_pipeline_workers(0, usize::MAX, VERIFY_CHUNK), 0);
        assert_eq!(bounded_pipeline_workers(1, usize::MAX, VERIFY_CHUNK), 0);
        assert_eq!(bounded_pipeline_workers(2, usize::MAX, VERIFY_CHUNK), 1);
        let workers = bounded_pipeline_workers(usize::MAX, usize::MAX, VERIFY_CHUNK);
        assert!(workers <= VERIFY_PIPELINE_MAX_HASH_WORKERS);
        assert!(workers < VERIFY_MAX_WORKERS);
        assert!(workers < crate::mem::cpu_workers().max(1));
        assert!((workers + 1) * VERIFY_CHUNK <= VERIFY_POOL_BYTES);
        assert_eq!(bounded_pipeline_workers(usize::MAX, 1, VERIFY_CHUNK), 1);
        assert_eq!(bounded_pipeline_workers(usize::MAX, 0, VERIFY_CHUNK), 0);
    }
}
