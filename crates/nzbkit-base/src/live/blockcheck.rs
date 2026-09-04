//! The IFSC block-check primitives: what one recovery-set block's bytes
//! are compared against, and how.
//!
//! Split out of live.rs on 30 Aug 2026 under the size gate (TODO 106),
//! as one subject rather than by the line: everything here answers "do
//! these bytes satisfy this `BlockCheck`", from the hot one-shot
//! comparison to the chunked form a 256 MiB block needs and the
//! zero-padding both of them owe the spec. Reached by `#[path]` from
//! live.rs, so `use super::*` names the verifier's own module and the
//! call sites above are unchanged.

use super::*;

/// Hash `bytes` (the real bytes of one block, zero-padded to `block_size`
/// per spec) and compare with the IFSC checksums. MD5 + CRC32 must both
/// match - identical semantics to `par2::verify_file_blocks`. CRC32 runs
/// first: hardware CRC is ~13× faster than MD5, so a mismatching (damaged)
/// block never pays for the MD5 pass.
pub fn check_block(check: &BlockCheck, block_size: usize, bytes: &[u8]) -> bool {
    check_block_verdict(check, block_size, bytes) == BlockVerdict::Ok
}

/// What one IFSC entry said about one block's bytes (M4-69).
///
/// [`check_block`] collapses this to a bool and keeps its documented
/// parity with `par2::verify_file_blocks`; this is the same walk with the
/// one distinction that walk cannot express.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockVerdict {
    /// Both digests matched: these are the bytes the entry describes.
    Ok,
    /// The CRC32 did not match. Ordinary damage - the MD5 is not
    /// consulted.
    ///
    /// MEASURED REFUSAL, 31 Aug 2026 (M4-69's stated limit). The MIRROR
    /// of `Contradicted` - a lying CRC32 beside an honest MD5 - lands
    /// here, so a hostile or broken producer's forged CRCs read as
    /// damage over byte-exact bytes. Telling the two apart HERE means
    /// hashing a block whose CRC has already failed, which is the one
    /// thing the CRC-first order exists to avoid: MD5 measured at
    /// ~0.78 GB/s against CRC32 at 8.6-31 GB/s on the dev box that day,
    /// so it is an MD5 pass over every damaged block of every damaged
    /// download, forever, to catch a set whose own packets lie. Refused.
    ///
    /// It is not left uncovered. `LiveVerifier::finish_slot_from` escalates
    /// to the FileDesc whole-file MD5 where every block of a file
    /// arrived and every one failed - the one shape whose price is
    /// bounded by what it prevents, and free to screen for. The
    /// arithmetic is written out there. What stays uncovered is the same
    /// forgery over PARTIAL damage, where the hash would scale with the
    /// file and the spend it saves scales with the damage.
    Damaged,
    /// The CRC32 matched and the MD5 did not. The entry describes two
    /// different blocks, so it describes neither, and it is unusable
    /// rather than a report of damage. Free to detect: reaching the MD5
    /// at all means the CRC already matched.
    Contradicted,
}

/// [`check_block_crc`] in [`BlockVerdict`] terms. A CRC-only claim knows
/// nothing about the MD5 beside it, so it can only ever answer `Ok` or
/// `Damaged` - never `Contradicted`, which is a statement about the PAIR.
pub(super) fn check_block_crc_verdict(
    check: &BlockCheck,
    block_size: usize,
    bytes: &[u8],
) -> BlockVerdict {
    if check_block_crc(check, block_size, bytes) {
        BlockVerdict::Ok
    } else {
        BlockVerdict::Damaged
    }
}

/// [`check_block`] with the reason it failed.
pub fn check_block_verdict(check: &BlockCheck, block_size: usize, bytes: &[u8]) -> BlockVerdict {
    if !check_block_crc(check, block_size, bytes) {
        return BlockVerdict::Damaged;
    }
    let mut md5 = Md5::new();
    md5.update(bytes);
    pad_to(block_size, bytes.len(), |z| md5.update(z));
    if <[u8; 16]>::from(md5.finalize()) == check.md5 {
        BlockVerdict::Ok
    } else {
        BlockVerdict::Contradicted
    }
}

/// The IFSC digests `bytes` (the real bytes of one block, zero-padded to
/// `block_size` per spec) actually carries.
///
/// [`check_block`] asks whether a block is ONE descriptor's; this
/// answers whose it is, which is what the twin tier needs when several
/// identical-head candidates are on the table - one hash of the block,
/// compared against every candidate, rather than one read per candidate.
/// Same padding semantics as `check_block`, so the two cannot disagree.
pub(super) fn block_digest(block_size: usize, bytes: &[u8]) -> BlockCheck {
    debug_assert!(bytes.len() <= block_size);
    let mut crc = crc32fast::Hasher::new();
    crc.update(bytes);
    let mut md5 = Md5::new();
    md5.update(bytes);
    pad_to(block_size, bytes.len(), |z| md5.update(z));
    BlockCheck {
        md5: md5.finalize().into(),
        crc32: crate::yenc_simd::crc32_zeros(
            crc.finalize(),
            (block_size.saturating_sub(bytes.len())) as u64,
        ),
    }
}

/// CRC32-only block check - the fast-verify hot path. The caller must only
/// use this for bytes that already carry an independent integrity check
/// (in-stream spans passed their yEnc pcrc32 in the decoder); a false
/// accept then requires corruption that survives two independent CRC32s
/// over differently-aligned spans.
pub fn check_block_crc(check: &BlockCheck, block_size: usize, bytes: &[u8]) -> bool {
    debug_assert!(bytes.len() <= block_size);
    let mut crc = crc32fast::Hasher::new();
    crc.update(bytes);
    // O(log n) through the padding rather than hashing it, exactly as
    // `StreamedBlock::finish` does. Saturating so a caller that broke
    // the assert above pays a wrong answer, not a wrapped length.
    // (The MD5 half of `check_block` keeps the real zero bytes - MD5
    // has no zero-extension trick.)
    check.crc_matches(crate::yenc_simd::crc32_zeros(
        crc.finalize(),
        (block_size.saturating_sub(bytes.len())) as u64,
    ))
}

/// [`check_block`] fed in pieces, for a block too big to hold at once.
///
/// Both digests run together, so the CRC-before-MD5 short circuit is gone -
/// which is why the caller only uses this above the chunking threshold, where
/// holding the whole block is the larger cost by far.
pub(super) struct StreamedBlock {
    crc: crc32fast::Hasher,
    md5: Md5,
    len: usize,
}

impl StreamedBlock {
    pub(super) fn new() -> Self {
        Self {
            crc: crc32fast::Hasher::new(),
            md5: Md5::new(),
            len: 0,
        }
    }

    pub(super) fn update(&mut self, bytes: &[u8]) {
        self.crc.update(bytes);
        self.md5.update(bytes);
        self.len += bytes.len();
    }

    /// Pad to `block_size` per spec and hand back the digests
    /// themselves - what the twin tier compares against several
    /// candidates' IFSC entries at once, where [`finish`](Self::finish)
    /// answers about exactly one.
    pub(super) fn digest(mut self, block_size: usize) -> BlockCheck {
        let crc =
            crate::yenc_simd::crc32_zeros(self.crc.finalize(), (block_size - self.len) as u64);
        pad_to(block_size, self.len, |z| self.md5.update(z));
        BlockCheck {
            md5: self.md5.finalize().into(),
            crc32: crc,
        }
    }

    /// Pad to `block_size` per spec and compare both digests. Same
    /// three-valued answer as [`check_block_verdict`], for the same
    /// reason and at the same (zero) cost.
    pub(super) fn finish(mut self, check: &BlockCheck, block_size: usize) -> BlockVerdict {
        // O(log n) through the padding rather than hashing it: the padding on
        // a 256 MiB block is itself most of a block.
        if !check.crc_matches(crate::yenc_simd::crc32_zeros(
            self.crc.finalize(),
            (block_size - self.len) as u64,
        )) {
            return BlockVerdict::Damaged;
        }
        pad_to(block_size, self.len, |z| self.md5.update(z));
        if <[u8; 16]>::from(self.md5.finalize()) == check.md5 {
            BlockVerdict::Ok
        } else {
            BlockVerdict::Contradicted
        }
    }
}

/// Read one block through `buf` in `buf.len()` pieces, hashing as it goes.
/// `None` if any read failed - a block that cannot be read is damage.
pub(super) fn read_block_chunked(
    src: &ReadAt<'_>,
    file: Option<&std::fs::File>,
    base: u64,
    blen: usize,
    buf: &mut [u8],
) -> Option<StreamedBlock> {
    let mut check = StreamedBlock::new();
    let mut done = 0usize;
    while done < blen {
        let n = (blen - done).min(buf.len());
        let ok = match (src, file) {
            (ReadAt::Path(_), Some(f)) => {
                crate::disk::read_exact_at(f, &mut buf[..n], base + done as u64).is_ok()
            }
            (ReadAt::Reader(r), _) => r(base + done as u64, &mut buf[..n]).is_ok(),
            _ => false,
        };
        if !ok {
            return None;
        }
        check.update(&buf[..n]);
        done += n;
    }
    Some(check)
}

/// Feed `block_size - len` zero-padding bytes to a hasher, chunk-wise.
pub(super) fn pad_to(block_size: usize, len: usize, mut update: impl FnMut(&[u8])) {
    const ZEROS: [u8; 4096] = [0; 4096];
    let mut rem = block_size - len;
    while rem > 0 {
        let n = rem.min(ZEROS.len());
        update(&ZEROS[..n]);
        rem -= n;
    }
}
