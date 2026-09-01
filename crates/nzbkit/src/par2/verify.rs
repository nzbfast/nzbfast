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
use md5::{Digest, Md5};

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
    let mut padded = vec![0u8; bs];
    file.blocks
        .iter()
        .enumerate()
        .map(|(i, check)| {
            let start = i * bs;
            if start >= data.len() {
                return false;
            }
            let end = (start + bs).min(data.len());
            let chunk: &[u8] = if end - start == bs {
                &data[start..end]
            } else {
                padded.fill(0);
                padded[..end - start].copy_from_slice(&data[start..end]);
                &padded
            };
            let md5: [u8; 16] = Md5::digest(chunk).into();
            md5 == check.md5 && crc32fast::hash(chunk) == check.crc32
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

/// Streaming twin of [`verify_file`]: identical verdicts, one pass over the
/// bytes, ~1 MiB resident whatever the file's size.
///
/// [`verify_file`] needs the whole candidate in memory and then walks it
/// twice - once for the whole-file MD5, once again per block - so a 30 GB
/// set member cost 30 GB of RSS and two full MD5 passes over cold pages.
/// This reads `src` in [`VERIFY_CHUNK`] pieces and feeds the whole-file
/// MD5, the 16k head MD5 and the per-block MD5+CRC32 from the one copy.
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
pub fn verify_file_streaming<R: std::io::Read>(
    file: &Par2File,
    block_size: u64,
    mut src: R,
) -> std::io::Result<FileVerify> {
    let bs = block_size as usize;
    let mut buf = vec![0u8; VERIFY_CHUNK];
    let mut whole = Md5::new();
    let mut head = Md5::new();
    let mut total: u64 = 0;

    let mut blocks: Vec<bool> = Vec::with_capacity(file.blocks.len());
    let mut bmd5 = Md5::new();
    let mut bcrc = crc32fast::Hasher::new();
    let mut filled = 0usize; // bytes of the current block already fed

    loop {
        let n = match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
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
            while p < n && blocks.len() < file.blocks.len() {
                let seg = (bs - filled).min(n - p);
                bmd5.update(&buf[p..p + seg]);
                bcrc.update(&buf[p..p + seg]);
                filled += seg;
                p += seg;
                if filled == bs {
                    let check = &file.blocks[blocks.len()];
                    let md5: [u8; 16] = std::mem::take(&mut bmd5).finalize().into();
                    let crc = std::mem::replace(&mut bcrc, crc32fast::Hasher::new()).finalize();
                    blocks.push(md5 == check.md5 && crc == check.crc32);
                    filled = 0;
                }
            }
        }
    }

    // The final short block is zero-padded to `block_size` per spec. MD5
    // has to digest that padding for real, so it is fed from a small
    // reused run of zeros rather than from a `bs`-sized allocation - `bs`
    // reaches 256 MiB. CRC32 reaches the same answer arithmetically and
    // touches nothing.
    if filled > 0 && blocks.len() < file.blocks.len() {
        const ZEROS: [u8; 8192] = [0u8; 8192];
        let mut pad = bs - filled;
        while pad > 0 {
            let take = pad.min(ZEROS.len());
            bmd5.update(&ZEROS[..take]);
            pad -= take;
        }
        let check = &file.blocks[blocks.len()];
        let md5: [u8; 16] = bmd5.finalize().into();
        let crc = crate::yenc_simd::crc32_zeros(bcrc.finalize(), (bs - filled) as u64);
        blocks.push(md5 == check.md5 && crc == check.crc32);
    }
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
