//! PAR 2.0 packet parser - parsing + verification metadata only, no repair math.
//!
//! Powers incremental verification and minimum-download logic (design: M2):
//! from the small main `.par2` index we learn the recovery set's block size,
//! file names/lengths, whole-file MD5s, and per-block MD5+CRC32 checksums, so
//! downloaded articles can be verified block-by-block and exactly enough
//! recovery volumes fetched when blocks are bad.
//!
//! Spec: <https://parchive.github.io/docs/specifications/parity-volume-spec/article-spec.html>
//!
//! Packet layout (all integers little-endian):
//! ```text
//! offset  size  field
//!      0     8  magic "PAR2\0PKT"
//!      8     8  packet length in bytes (u64; includes this 64-byte header,
//!               always a multiple of 4)
//!     16    16  MD5 of the packet from offset 32 to the end (setid+type+body)
//!     32    16  RecoverySetId
//!     48    16  packet type
//!     64     …  type-specific body
//! ```
//!
//! Hard-learned spec subtleties (verified against par2cmdline 1.2.0 output):
//! - **md5_16k** is the MD5 of the first `min(len, 16384)` bytes of the file.
//!   For a file shorter than 16 KiB it is *not* zero-padded - it simply equals
//!   the whole-file MD5. (Checked empirically on a 10 KiB fixture: the
//!   FileDesc hash16k field matches the raw MD5, not the padded-to-16k MD5.)
//! - The **last block** of a file *is* zero-padded to `block_size` for its
//!   IFSC MD5 and CRC32.
//! - Packets are **duplicated across volumes** (every .volNN+MM file repeats
//!   the critical packets), so the parser dedupes by packet MD5.

use crate::md5fast::{Digest, Md5};
use std::collections::HashMap;

/// Public: the engine's in-stream sniff (issue #14) tests a decoded
/// offset-0 article against this to identify obfuscated recovery volumes.
pub const MAGIC: &[u8; 8] = b"PAR2\0PKT";

/// How far into a file the first packet may begin and still let a
/// content sniff recognise the file as a recovery volume (M4-65).
///
/// The sniff exists for the obfuscated post, whose volumes carry a hash
/// name and no `.par2` extension - there is no other way to find them.
/// It used to require [`MAGIC`] at byte 0 EXACTLY, so any prefix at all
/// defeated it: a 3-byte UTF-8 BOM from a producer that touched the file
/// as text, a two-byte header, anything. The volume was then never a
/// packet file, the inner set never activated, and the payload stayed
/// hashed with the parity sitting unread beside it.
///
/// 64 bytes, which is one packet header - short enough that a prefix
/// this tolerates is a header somebody stuck on the front, long enough
/// to cover the shapes that occur. It is deliberately NOT the
/// whole-buffer walk `find_magic` does for a file already collected: a
/// sniff decides whether to read a file WHOLE (up to
/// `par2repair::MAX_PACKET_FILE_BYTES`), so how far it looks is how much
/// attacker-chosen input one directory entry can turn into a read.
///
/// IT ALSO BOUNDS WHAT THE CLEANUP SWEEP MAY DELETE, and that is worth
/// knowing before touching either half. `par_cleanup` removes a spent
/// volume only when `par2repair::is_recovery_volume_shape` agrees
/// (M4-53), and that walk starts its packet chain at
/// [`packet_file_head_offset`] - the same window, read by the same
/// function - so the two halves agree BY CONSTRUCTION rather than by
/// anyone remembering to move both.
///
/// They did not, for a day. This constant landed with a note saying the
/// shape test still began at offset 0 and that widening it was a
/// decision about deleting files belonging to its own row; that row ran
/// on 31 Aug 2026 and this is its answer. The residue it left was
/// measured rather than argued: a BOM-prefixed volume was sniffed, its
/// remaining articles CANCELLED by the in-stream deferral, and the
/// truncated file then kept for ever, because the sweep could not see
/// it. That is not a leftover kept out of caution - it is a file this
/// engine deliberately holed and then abandoned in the user's output
/// directory, which is issue #9 with an extra insult.
///
/// Read the widening at `par2repair::is_recovery_volume_shape` before
/// touching this: what moved is the walk's ENTRY POINT, never its chain
/// or its zero-tail rule.
///
/// A gzipped volume stays out of reach and that is a decision, not an
/// oversight: deflate leaves no magic anywhere in the bytes, so no window
/// can see one, and inflating every candidate in the 64 B..1 GiB band -
/// on every file in an output directory - is an unbounded decompression
/// surface over attacker-chosen input, bought for a shape nothing is
/// known to produce.
pub const SNIFF_WINDOW: usize = 64;

/// Does this file's head identify it as a PAR2 packet file?
///
/// The one predicate behind every content sniff in the product - the
/// disk walk, the repair catalog's incremental relist, and the engine's
/// in-stream offset-0 sniff. Written once because those three are the
/// kind of hand-copied siblings this tree keeps finding drifted: a
/// sniffer two lanes widen and narrow independently ends up believing
/// the union of two individually-correct rules.
///
/// `head` is the start of the file - hand it
/// `SNIFF_WINDOW + MAGIC.len()` bytes, or the whole file when it is
/// shorter. The magic must BEGIN at an offset of at most
/// [`SNIFF_WINDOW`]; a longer `head` is truncated rather than searched,
/// so a caller that passes a whole 30 GB article does not get the
/// whole-buffer walk by accident.
pub fn head_is_packet_file(head: &[u8]) -> bool {
    packet_file_head_offset(head).is_some()
}

/// WHERE the packet chain of a sniffed file begins: the offset of the
/// first [`MAGIC`] beginning at most [`SNIFF_WINDOW`] bytes in, or
/// `None` when there is none.
///
/// [`head_is_packet_file`] IS this function - it asks whether the answer
/// exists - so the "does it sniff" and "where does it start" questions
/// cannot give answers about different bytes. That matters because the
/// two are asked by opposite halves of one decision: the sniff nominates
/// a file and the shape walk at
/// `par2repair::is_recovery_volume_shape` decides whether it may be
/// DELETED, and those two halves disagreeing for a day is exactly what
/// left a prefixed volume both used and unsweepable (M4-65 / M4-53, the
/// residue closed 31 Aug 2026).
///
/// FIRST magic only, never a retry at the next one. A second candidate
/// inside the window would be a strictly more permissive rule bought for
/// a coincidence at ~2^-64 a byte, and the failure direction of getting
/// the start wrong is a chain that does not walk - which KEEPS the file.
pub fn packet_file_head_offset(head: &[u8]) -> Option<usize> {
    let n = head.len().min(SNIFF_WINDOW + MAGIC.len());
    head[..n].windows(MAGIC.len()).position(|w| w == MAGIC)
}

/// yEnc inflates an article by roughly 2%, and NZB `bytes=` attributes
/// are the ENCODED figure - so raw payload is about this fraction of
/// what the NZB declares. Only ever used to shrink an estimate, never
/// to grow one: every caller here is bounding something.
pub const YENC_RAW_FRACTION: f64 = 0.98;

/// Per-slice packet overhead in a recovery volume: the 64-byte packet
/// header plus the 4-byte exponent that precedes the slice data.
pub const SLICE_PACKET_OVERHEAD: u64 = 68;

/// The smallest share of a yEnc-encoded size that the raw payload
/// behind it is taken to be, when nothing exact is known about the
/// file.
///
/// [`YENC_RAW_FRACTION`] is the wrong constant for a FLOOR and the 15
/// Aug post says why: 3,332,350,599 encoded bytes carried 3,229,432,857
/// raw ones, an overhead of 3.19% where 0.98 allows 2%. The two sources
/// of that overhead are both structural rather than incidental - CRLF
/// every 128 output characters is 1.56%, and on payload that is already
/// compressed or encrypted the four byte values yEnc must escape turn
/// up at about their random-data rate of 1.6% - so a real post landing
/// past 2% is the expectation, not the exception.
///
/// 0.95 leaves 1.8 points of headroom over that measurement, which is
/// the whole job here: this is only ever multiplied into a number that
/// a verdict then uses to STOP a download, so it must understate the
/// raw bytes rather than flatter them.
///
/// It is a conservative constant, not a proof. Escaping can in
/// principle double a file - a payload made mostly of the four byte
/// values that escape would blow past any fraction - and the rigorous
/// bound that follows from that, near 0.49, is worthless: it would put
/// back the halving that a census sample was just released from, and no
/// real recovery-set payload is anywhere near it. When the exact length
/// IS known (a PAR2 FileDesc packet states it), use that instead of
/// this: `raw >= encoded_missing - (encoded_total - exact_length)` is a
/// true bound and needs no constant.
pub const YENC_RAW_FRACTION_FLOOR: f64 = 0.95;

/// A conservative LOWER bound on the raw bytes behind `encoded_bytes`
/// of yEnc - the conversion every deficit needs before it may be
/// divided by a RAW block size.
///
/// NZB `bytes=` attributes are the encoded figure and a PAR2 block size
/// is a raw one, so dividing one by the other over-counts damage by the
/// whole yEnc overhead. That over-count used to be hidden by a flat 0.5
/// margin on the deficit; at a census margin of 1.0 it is not, and it
/// can carry a "floor" past the number of blocks the file even has.
pub fn min_raw_bytes(encoded_bytes: u64) -> u64 {
    (encoded_bytes as f64 * YENC_RAW_FRACTION_FLOOR) as u64
}

/// Recovery blocks a volume of `encoded_bytes` PROBABLY holds.
///
/// The point estimate the repair path has always used for volumes whose
/// name declares no count (`.vol-NN.par2`): raw bytes over the packet
/// stride. It is neither a floor nor a ceiling - a volume also carries a
/// copy of the critical packets, which inflates it, and the yEnc figure
/// is approximate - so it is the number to SHOW a user, never the number
/// a verdict leans on. For that, see [`max_recovery_blocks`].
pub fn est_recovery_blocks(encoded_bytes: u64, block_size: u64) -> usize {
    if block_size == 0 {
        return 0;
    }
    // The +100 (rather than the exact SLICE_PACKET_OVERHEAD of 68) is
    // the repair path's long-standing figure and is deliberately kept:
    // it absorbs the critical packets every volume repeats, which is
    // what makes this an ESTIMATE rather than a bound.
    (encoded_bytes as f64 * YENC_RAW_FRACTION / (block_size as f64 + 100.0)) as usize
}

/// The MOST recovery blocks a volume of `encoded_bytes` could possibly
/// hold - the only recovery figure a verdict that STOPS a download may
/// rest on.
///
/// A slice costs `block_size + SLICE_PACKET_OVERHEAD` raw bytes and the
/// NZB's `bytes=` is the larger, yEnc-encoded figure, so dividing the
/// encoded size by the bare block size can only ever over-count. Every
/// byte a volume spends on critical packets is another block it does
/// not hold. That one-sidedness is the point: an IMPOSSIBLE verdict
/// compares a floor on the damage against this ceiling on the cure, so
/// neither half can flatter the answer into stopping a job that would
/// have finished.
///
/// Returns u64, and the caller compares in u64, because `as usize` is a
/// SILENT truncation on a 32-bit target and we ship one
/// (`armv7-unknown-linux-musleabihf`). `encoded_bytes` is the NZB's
/// poster-controlled `bytes=` and `parse_main` admits a block size as
/// small as 4, so 16 GiB declared on one volume is enough to wrap the
/// quotient past 2^32 - and a ceiling that wraps to 0 turns any deficit
/// into a false IMPOSSIBLE, which is the one direction this function's
/// whole one-sidedness exists to forbid.
pub fn max_recovery_blocks(encoded_bytes: u64, block_size: u64) -> u64 {
    if block_size == 0 {
        return 0;
    }
    encoded_bytes / block_size
}

/// Blocks that `missing_bytes` of payload MUST have damaged.
///
/// Wherever those bytes sit, they cannot all hide inside fewer than
/// `missing_bytes / block_size` slices - blocks do not span files and a
/// block is damaged by a single absent byte. Rounded DOWN rather than up
/// (the true bound is the ceiling) because this figure exists to be
/// compared against [`max_recovery_blocks`], and every rounding here
/// should move away from claiming impossibility.
///
/// u64 for the same reason as [`max_recovery_blocks`], and here the
/// narrowing cast was the less dangerous of the two only by luck: it
/// wraps the DEFICIT down, which softens a verdict rather than
/// manufacturing one. Saturating it instead would be the false-IMPOSSIBLE
/// direction, so the fix on both sides is to not narrow at all.
pub fn min_damaged_blocks(missing_bytes: u64, block_size: u64) -> u64 {
    if block_size == 0 {
        return 0;
    }
    missing_bytes / block_size
}

/// MD5 of a file's first `min(16384, length)` bytes - the quantity a
/// FileDesc packet's `md5_16k` records (short files are NOT zero-padded).
/// For callers holding a decoded offset-0 span; None when the span does
/// not cover that whole prefix.
pub fn md5_16k_of_head(head: &[u8], file_length: u64) -> Option<[u8; 16]> {
    let want = file_length.min(16384) as usize;
    (want > 0 && head.len() >= want).then(|| Md5::digest(&head[..want]).into())
}
pub const TYPE_MAIN: &[u8; 16] = b"PAR 2.0\0Main\0\0\0\0";
pub const TYPE_FILEDESC: &[u8; 16] = b"PAR 2.0\0FileDesc";
pub const TYPE_IFSC: &[u8; 16] = b"PAR 2.0\0IFSC\0\0\0\0";
pub(crate) const TYPE_RECVSLIC: &[u8; 16] = b"PAR 2.0\0RecvSlic";
/// The optional Unicode Filename packet (PAR2 spec 2.0). MultiPar and
/// QuickPar emit one beside every FileDesc whose real name does not fit
/// the FileDesc's own byte field: `16 bytes file id` then the name as
/// UTF-16. See [`parse_unifilen`] for why we read it and what it costs.
pub(crate) const TYPE_UNIFILEN: &[u8; 16] = b"PAR 2.0\0UniFileN";

/// Header size of every packet.
const HEADER_LEN: u64 = 64;
/// MD5 of the first this-many bytes of a file = the FileDesc "hash16k" field.
pub(crate) const HASH16K_LEN: usize = 16384;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Par2Error {
    /// No valid Main packet found in any input - we can't even know the
    /// block size, so nothing useful can be built.
    #[error("no valid PAR2 Main packet found in the input")]
    NoMainPacket,
    /// Inputs contained valid packets from more than one recovery set.
    ///
    /// Raised only when more than one set carries a Main packet, i.e.
    /// when the inputs genuinely describe several sets and the caller
    /// has to group them ([`crate::live::pick_sets`] does). A stray
    /// packet from another set inside one physical file is NOT this -
    /// see `parse`'s own doc comment.
    #[error("packets from multiple recovery sets mixed in the input")]
    MixedRecoverySets,
    /// Two individually valid Main packets of ONE recovery set disagree
    /// about the block geometry, so there is no trusted answer to the
    /// question every block checksum and every repair plan is derived
    /// from. Refused rather than resolved: picking either one lets the
    /// order the packets arrived in decide what the set is taken to say.
    #[error("contradictory PAR2 Main packets in one recovery set")]
    ContradictoryPackets,
}

/// One source file described by the recovery set.
#[derive(Debug, Clone)]
pub struct Par2File {
    pub file_id: [u8; 16],
    pub name: String,
    pub length: u64,
    /// MD5 of the entire file.
    pub md5: [u8; 16],
    /// MD5 of the first `min(length, 16384)` bytes (see module docs - the
    /// short-file case is NOT zero-padded).
    pub md5_16k: [u8; 16],
    /// Per-block checksums, in file order, ALWAYS spanning the declared
    /// length when non-empty - see [`fit_ifsc`], which reconciles the
    /// IFSC packet to the grid the FileDesc declares. Empty when no IFSC
    /// packet for this file survived parsing; entries a short packet
    /// never described are [`BlockCheck::UNPROVEN`].
    pub blocks: Vec<BlockCheck>,
}

// The block-check grid and the whole-file verifiers that read it: one
// subject, its own file under the size gate (TODO 106). Re-exported
// under the names they have always had, so `BlockCheck` and the three
// `verify_file*` doors are spelled the same at every call site they
// already have.
mod verify;
pub(crate) use verify::fit_ifsc;
pub use verify::{
    BlockCheck, VERIFY_MAX_WORKERS, clear_fast_check, fast_check_enabled, set_fast_check,
    verify_file, verify_file_blocks, verify_file_md5_path, verify_file_md5_streaming,
    verify_file_path, verify_file_path_tiered, verify_file_seekable, verify_file_streaming,
};

/// Parsed metadata of one PAR2 recovery set.
#[derive(Debug, Clone)]
pub struct Par2Set {
    pub recovery_set_id: [u8; 16],
    /// Slice/block size in bytes (multiple of 4 per spec).
    pub block_size: u64,
    /// Files in the recovery set, in Main-packet (file-id-sorted) order.
    ///
    /// THIS LIST IS THE GLOBAL SLICE INDEX SPACE. Repair lays files onto
    /// input-slice numbers by walking it in order, so nothing that is not
    /// a recovery-set member may ever be added to it - see
    /// [`Par2Set::nonrecovery`].
    pub files: Vec<Par2File>,
    /// Every file this set DESCRIBES but carries no parity for, resolved
    /// through its FileDesc packet. Same shape as [`Par2Set::files`],
    /// deliberately a different list.
    ///
    /// Two populations, one rule. The Main packet's NON-recovery id list
    /// (M4-21, 30 Aug 2026), and then any FileDesc whose id the Main
    /// packet lists in NEITHER half (M4-64, 30 Aug 2026) - an ORPHAN
    /// descriptor, which MultiPar and some rebuild tools emit and which
    /// this parser used to drop on the floor. They are one list because
    /// they are one kind of evidence, a name plus a whole-file MD5, and
    /// splitting them would be a second rule for one clue. Orphans sort
    /// after the declared ones, by file id.
    ///
    /// PAR2's Main packet lists the recovery-set ids and then, optionally,
    /// ids the set describes but does NOT carry parity for - QuickPar's
    /// "verify but do not repair". Until this field existed those
    /// descriptors were parsed and then dropped on the floor: the files
    /// were never named, never verified and nothing said so. An orphan
    /// descriptor is the same loss reached the other way round, and gets
    /// the same answer.
    ///
    /// They are a SEPARATE list and not extra entries in `files` because
    /// two invariants forbid the merge, and neither is recoverable after
    /// the fact. The slice-index one above is the hard one - repair's
    /// exponents are positional. The second is a verdict question: a
    /// recovery-set member that is missing or damaged fails the job and
    /// summons repair, and a verify-only member must do neither, or a
    /// poster's `.nfo` afterthought turns a complete download into a
    /// failed one.
    ///
    /// What they ARE good for is naming, on exactly the evidence they
    /// carry: a name plus a whole-file MD5 is a nomination the content
    /// finalizes. `get::sfvname` consumes them as checksum entries beside
    /// the sidecar ones, under that tier's own ambiguity and
    /// never-overwrite rules.
    pub nonrecovery: Vec<Par2File>,
    /// This set's repair power: distinct recovery EXPONENTS whose slice
    /// payload can actually serve one of its blocks.
    ///
    /// DEDUPED BY EXPONENT, not by packet MD5 (X5-15): a recovery slice
    /// is one row of the coding matrix and its exponent is which row, so
    /// two checksum-valid packets at one exponent are one unit of
    /// capacity however different their bytes are - and different bytes
    /// is exactly what makes them two packet MD5s.
    ///
    /// JUDGED BY [`slice_fits_block`] (Y4b): a packet carrying less than
    /// one `block_size` of slice data cannot serve a block, and both
    /// SELECTION sites refuse it. Until 31 Aug 2026 the only length test
    /// on this path was "carries an exponent", so a set advertised
    /// repair power for every exponent MENTIONED.
    ///
    /// BOTH `on_hand` readers SEED off this field and then ADD a count
    /// that DID apply the rule - `get::settle`'s exact-fit fetch planner
    /// (`usable_slices_of` per prefetched or resumed volume) and §146's
    /// tail give-up (`cached_recovery_blocks` per volume on disk) - so an
    /// over-count here is two different questions added together. The
    /// planner's `needed = damage - on_hand` comes out too SMALL and the
    /// exact-fit fetch buys too little; the repair still lands, off the
    /// last-resort escalation that buys every REMAINING volume, at the
    /// price of the whole ladder where one rung would have done.
    pub recovery_blocks_seen: usize,
}

/// May a RecvSlic packet of this payload length serve as a recovery
/// slice for a set whose Main declares `bs`?
///
/// THE ONE SPELLING OF THE RULE. It lives in `par2` because it is a
/// statement about a PAR2 PACKET - the spec's own layout and nothing
/// about repair - and because the parse itself has to ask it: this file
/// counts [`Par2Set::recovery_blocks_seen`], which is the planner's
/// seed, and `par2repair` already depends on `par2`, so the rule could
/// not stay one spelling anywhere further up. It is re-exported by
/// [`crate::par2repair::slice_fits_block`], next to the two finders
/// whose output it judges, and that is still where a repair-side reader
/// should expect to meet it.
///
/// M4-56 fixed this rule in the two SELECTION sites and left the
/// COUNTING sites spelling `== bs`, so for a day the halves disagreed:
/// a padded volume repaired perfectly while the fetch planner and the
/// tail give-up both read it as holding no parity at all. Y4 moved
/// those two, and Y4b found the THIRD - `recovery_blocks_seen` had no
/// length test at all, only "carries an exponent", so a set advertised
/// repair power for every exponent MENTIONED. Every site that turns a
/// slice length into a yes/no calls this now - the in-memory selection
/// (`repair_dir_set_inner`), the mapped one (`load_mapped_recovery`),
/// the parse's own count ([`Par2Set::parse`]), the fetch planner's
/// on-hand count (`nzbfast get::settle`) and the tail give-up's census
/// (`nzbfast get::workers::recovery`). Do NOT re-spell `>= bs` at a
/// call site.
///
/// M4-56 (wave-4 matrix read, 30 Aug 2026). A recovery slice packet's
/// body is `exponent || slice_data`, and the spec fixes `slice_data` at
/// exactly one `block_size`. Both selection sites used to demand
/// `len == bs` and drop anything else WITHOUT A WORD, so a volume whose
/// writer padded the packet vanished entirely and the set reported
/// itself short of parity it was holding. Measured on the 30 Aug
/// baseline: four valid slices for one missing block, every packet MD5
/// intact, `Unrepairable { needed: 1, have: 0 }`.
///
/// The two directions are NOT symmetric and the asymmetry is the whole
/// rule.
///
/// A packet carrying MORE than `bs` is USED, truncated to `bs`. The
/// slice can only be the leading `bs` bytes - that is the only reading
/// the spec's layout admits - and the packet MD5, which covers set id,
/// type, exponent and the whole payload alike, proves nothing in it
/// moved. It is safe to be wrong about, too: every repaired file is
/// re-hashed against its FileDesc MD5 before the rename commits
/// (`RepairError::VerifyFailed`, which rolls the whole repair back), so
/// a misread slice costs a loud refusal and can never make a false
/// green.
///
/// A packet carrying LESS is REFUSED. Zero-extending it to `bs` would
/// feed bytes nobody has into the solve, which is M4-40's defect on the
/// input side - the scan's virtual padding manufacturing a donor's
/// content - and there the harm was destructive. There is no reading of
/// a short packet that recovers a full slice, so it is dropped; what
/// changes is that the drop is now COUNTED and said out loud by both
/// selection sites, because "the set looks short of parity it actually
/// has" is the symptom that has to reach a human.
///
/// A COUNTING caller refuses a short slice silently and must. The two
/// per-tick counters run over every volume on disk, so a warn line each
/// would be the same sentence a few hundred times a minute; the parse's
/// own count is not per tick but has no reader to tell either - a
/// `Par2Set` is a value, not a session. The selection site the repair
/// itself goes through says it once, loudly, at the moment it decides.
///
/// `len` is a `usize` and not the `u32` a catalog `RecLoc` carries:
/// four of the five callers hold a `usize` straight off a packet body,
/// and `u32 -> usize` is lossless on every target this ships to while
/// `usize -> u32` is a silent truncation.
pub fn slice_fits_block(len: usize, bs: usize) -> bool {
    len >= bs
}

/// Whole-file verification result from [`verify_file`].
#[derive(Debug, Clone)]
pub struct FileVerify {
    /// One flag per expected block, `true` when both the MD5 and CRC32 match.
    pub blocks: Vec<bool>,
    /// Whole-file MD5 matched.
    pub md5_ok: bool,
    /// First-16k MD5 matched.
    pub md5_16k_ok: bool,
}

/// FileDesc body fields, keyed by file id during parsing.
///
/// `PartialEq` is load-bearing rather than derived by reflex: `parse`
/// and the disk catalog's `SetReplay` both detect CONTRADICTORY
/// descriptors for one file id by comparing two parsed readings, and
/// comparing the parsed form rather than the packet bytes is what keeps
/// two legitimately re-padded copies of one descriptor from reading as
/// a contradiction (`parse_filedesc` trims the name's null padding, so
/// the same descriptor written with different padding parses equal).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Desc {
    pub(crate) name: String,
    pub(crate) length: u64,
    pub(crate) md5: [u8; 16],
    pub(crate) md5_16k: [u8; 16],
}

// The framing walk and the packet-body parsers: one subject, its own
// file under the size gate (TODO 106). Re-exported under the names they
// have always had - par2repair, preflight, `get::settle` and the e2e
// suites all reach these through `crate::par2::…`, and not one of those
// paths moves.
//
// `RawPacket` is deliberately NOT among them: every caller of
// `scan_packets` receives one in a closure and reads its fields, so no
// site in this crate has ever named the type. It stays `pub(crate)` in
// `packet` so a caller that does need to name it gets a re-export added
// here, rather than a path reaching through a private module.
mod packet;
use packet::packet_spans;
pub(crate) use packet::{
    MAX_BLOCK_SIZE, parse_filedesc, parse_ifsc, parse_main, parse_unifilen, scan_packets,
};

/// The spec's file id for a descriptor: the MD5 of its LAST three fields
/// - the first-16k hash, the 8-byte length, and the name without its null
/// padding. Confirmed against par2cmdline 1.3.0 output, and every one of
/// the 18 FileDesc packets in this repository's fixtures binds its own id
/// under this rule (measured 30 Aug 2026).
///
/// It hashes the DECODED name, which is what [`parse_filedesc`] keeps, so
/// a descriptor whose name bytes are not UTF-8 reads as unbound: the
/// lossy decode has already replaced them. That costs such a descriptor
/// nothing except a CONTESTED id, because [`Claim::offer_desc`]
/// out-ranks rather than refuses - which is the whole reason it does.
pub(crate) fn filedesc_id(d: &Desc) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(d.md5_16k);
    h.update(d.length.to_le_bytes());
    h.update(d.name.as_bytes());
    h.finalize().into()
}

/// One field of a recovery set as the packets CLAIM it, resolved
/// without reference to the order they arrived in.
///
/// A set is malformed when two individually valid packets say different
/// things about one thing - two FileDescs under one file id, two Main
/// packets with different block sizes. The reading that must never be
/// chosen is "whichever the scanner reached first": that is article
/// arrival order on the wire, input-vector order at the call, and
/// lexicographic packet-file order on disk, none of which is evidence
/// about the post. So a contradicted claim LATCHES empty and stays
/// empty - the two readings annihilate rather than race, which is the
/// same answer in every order (W4-10).
struct Claim<T> {
    value: Option<T>,
    contradicted: bool,
}

// Hand-written rather than derived: `#[derive(Default)]` on a generic
// struct bounds `T: Default`, and neither `Desc` nor `(u64, Vec<..>)`
// has a meaningful empty value - an empty claim is the ABSENCE of one.
impl<T> Default for Claim<T> {
    fn default() -> Self {
        Claim {
            value: None,
            contradicted: false,
        }
    }
}

impl<T: PartialEq> Claim<T> {
    /// Offer one packet's reading. A repeat of what is already held is a
    /// no-op (packets legitimately repeat across volumes); a DIFFERENT
    /// reading empties the claim for good.
    fn offer(&mut self, v: T) {
        if self.contradicted {
            return;
        }
        match &self.value {
            None => self.value = Some(v),
            Some(cur) if *cur != v => {
                self.value = None;
                self.contradicted = true;
            }
            Some(_) => {}
        }
    }

    fn into_settled(self) -> Option<T> {
        self.value
    }
}

impl Claim<Desc> {
    /// [`Claim::offer`] with M4-38's tiebreak: a descriptor that BINDS
    /// `fid` outranks one that merely carries a copy of it, so the two
    /// are not a contradiction at all.
    ///
    /// A file id is not an opaque label - [`filedesc_id`] fixes it from
    /// the descriptor's own fields - so a packet whose id was COPIED
    /// from another file cannot also bind it: the name, length or 16k
    /// hash it forged differs, and MD5 is what stands between those two
    /// facts. Without this, a forgery beside the real descriptor is an
    /// equivocation, and W4-10 empties the claim: the honest file leaves
    /// the set entirely, which is safe and is still a whole member lost
    /// to a packet anyone can write. Two SELF-BOUND descriptors cannot
    /// share an id short of an MD5 collision, so the tiebreak is a
    /// decision procedure and not a preference.
    ///
    /// It OUT-RANKS rather than refuses, deliberately. Nothing in the
    /// format makes a producer's ids verifiable by any other tool -
    /// par2cmdline never recomputes them - so a set that numbers its
    /// files by some other rule is self-consistent and must still
    /// parse. An unbound descriptor still describes its own file; it
    /// only loses a CONTESTED id, and where neither or both bind it the
    /// W4-10 rule is untouched.
    fn offer_desc(&mut self, fid: [u8; 16], v: Desc) {
        if !self.contradicted
            && let Some(cur) = &self.value
            && *cur != v
        {
            let new_binds = filedesc_id(&v) == fid;
            if new_binds != (filedesc_id(cur) == fid) {
                if new_binds {
                    self.value = Some(v);
                }
                return;
            }
        }
        self.offer(v);
    }
}

/// Everything one recovery set's packets claim, accumulated across every
/// input. Sets are kept APART during the walk - a stray packet from
/// another set inside one physical file must not be able to say anything
/// about this one, which is what binding the set id to the first packet
/// seen used to let it do (X5-14).
#[derive(Default)]
struct SetClaims {
    main: Claim<(u64, Vec<[u8; 16]>)>,
    /// Whether any structurally parseable Main packet was seen at all -
    /// true even once `main` has been contradicted empty, because a set
    /// that CLAIMS to be a recovery set is still a candidate and must
    /// not be silently passed over in favour of one that does not.
    saw_main: bool,
    /// The Main packet's NON-recovery id list (M4-21), claimed APART
    /// from the geometry above rather than as part of it.
    ///
    /// Folding it into `main` would make two Main packets that agree
    /// about the block size and the recovery set, and differ only about
    /// which verify-only members the set describes, a CONTRADICTED main
    /// - which is fatal, and would refuse a set that repairs perfectly
    /// over a disagreement about files carrying no parity. Claimed here
    /// it annihilates on its own, degrading to what this build did
    /// before the list was read at all.
    nonrec: Claim<Vec<[u8; 16]>>,
    /// The UNION of every id any structurally valid Main packet of this
    /// set mentioned, in either half - not a claim, and deliberately not
    /// one. It is what scopes the ORPHAN pass (M4-64): a descriptor is an
    /// orphan only when NO Main packet ever named it, so an id that was
    /// named and then lost to a contradiction stays lost.
    ///
    /// Without this the two rules would not compose. Two Main packets
    /// agreeing about the geometry and disagreeing about which
    /// verify-only members exist annihilate `nonrec` on purpose (W4-10),
    /// and an orphan pass over "whatever is left in `descs`" would hand
    /// every one of those descriptors straight back - quietly making that
    /// annihilation inert. Both rules are about the same question from
    /// opposite ends, and the honest reading is: Main saying nothing is
    /// not the same as Main contradicting itself.
    mentioned: std::collections::HashSet<[u8; 16]>,
    descs: HashMap<[u8; 16], Claim<Desc>>,
    ifscs: HashMap<[u8; 16], Claim<Vec<BlockCheck>>>,
    /// file id -> the optional Unicode Filename packet's spelling of the
    /// name (M4-22). A `Claim` like everything else here: two that
    /// disagree annihilate and the FileDesc's own spelling stands, which
    /// is the same answer in every packet order.
    unis: HashMap<[u8; 16], Claim<String>>,
    /// Recovery exponent -> the LONGEST slice payload seen carrying it.
    ///
    /// Keyed by exponent because that is what repair power is measured
    /// in. Deliberately not a packet count: two checksum-valid RecvSlic
    /// packets carrying the same exponent with different bytes are one
    /// unit of capacity, and the native repair catalog dedupes by
    /// exponent, so counting packets advertises parity the repair will
    /// not find (X5-15).
    ///
    /// The LENGTH is carried because [`slice_fits_block`] is what turns
    /// this map into a count and the block size is not known here: a
    /// RecvSlic may be scanned before the Main packet that declares it,
    /// so the judgement cannot happen at the insert (Y4b). LONGEST and
    /// not first-seen, because a short packet and a full-length one at
    /// one exponent are one row of the matrix that the set CAN serve -
    /// which is the same answer the selection sites reach, since they
    /// filter by this rule and only then dedupe.
    exps: std::collections::HashMap<u32, usize>,
}

impl Par2Set {
    /// Parse the raw bytes of one or more .par2 files (main index + any
    /// .volNN+MM volumes). Duplicated packets are deduped by packet MD5,
    /// unknown packet types and corrupt packets are skipped, and trailing
    /// garbage is tolerated.
    ///
    /// Packets are grouped BY SET ID and the set carrying the Main packet
    /// is the one described. So a physical `.par2` that opens with one
    /// stray packet from another set - or carries any amount of foreign
    /// noise that does not itself claim to be a recovery set - still
    /// yields the set it actually describes, where binding the identity
    /// to the first packet seen threw the whole file away (X5-14).
    /// `MixedRecoverySets` is now reserved for the case a caller can
    /// actually act on: MORE THAN ONE set with a Main packet, which is a
    /// post to be GROUPED (GH #63's per-file sets, and what
    /// [`crate::live::pick_sets`] does with the error).
    ///
    /// Within the chosen set, two valid packets that CONTRADICT each
    /// other resolve to nothing rather than to whichever came first -
    /// see [`Claim`]. A contradicted Main is fatal
    /// ([`Par2Error::ContradictoryPackets`]), because the block geometry
    /// is what every checksum and every repair plan is derived from; a
    /// contradicted FileDesc drops just that file, exactly as a MISSING
    /// one already did; a contradicted IFSC drops to the whole-file MD5,
    /// exactly as a length-disagreeing one already did.
    pub fn parse(inputs: &[&[u8]]) -> Result<Par2Set, Par2Error> {
        Par2Set::parse_inner(inputs, None)
    }

    /// [`Par2Set::parse`] and [`packet_census`] out of ONE walk, one
    /// census per input in the order the inputs were given.
    ///
    /// Both of those functions scan through `scan_packets`, which
    /// MD5-VERIFIES every packet, so a caller that wants the set AND
    /// the per-file counts hashes the whole recovery set twice.
    /// `parfast` is that caller - it has to print
    /// `Loaded 6 new packets including 1 recovery blocks` per file
    /// before it prints anything else - and on the published 1 GiB /
    /// 21-volume corpus the second walk over 104 MB of volumes was
    /// worth ~1.1G retired instructions, measured 4 Sep 2026.
    ///
    /// The census is EVERY structurally valid packet in that input,
    /// duplicates across volumes included, because "how many packets
    /// did this file ADD" is the caller's own running question and only
    /// it knows what it has already counted. That is the same list
    /// [`packet_census`] returns for the same bytes; the dedupe below
    /// is the SET's, and it happens after.
    ///
    /// The set is still settled from all the inputs together, so a
    /// caller feeding files it has not yet filtered gets whichever set
    /// dominates - check `recovery_set_id` if you needed a particular
    /// one.
    pub fn parse_censused(inputs: &[&[u8]]) -> (Result<Par2Set, Par2Error>, Vec<Vec<PacketInfo>>) {
        let mut census: Vec<Vec<PacketInfo>> = vec![Vec::new(); inputs.len()];
        let set = Par2Set::parse_inner(inputs, Some(&mut census));
        (set, census)
    }

    fn parse_inner(
        inputs: &[&[u8]],
        mut census: Option<&mut Vec<Vec<PacketInfo>>>,
    ) -> Result<Par2Set, Par2Error> {
        // Every set's claims are kept until the walk ends, because which
        // set is described is not known until the last packet has been
        // read. That holds more than the old first-set-wins walk did on
        // a multi-set input - bounded by roughly the input's own size,
        // since each stored claim is smaller than the packet it came
        // from, and the input is already resident. Deciding the set from
        // a cheap header pre-pass instead would trade that back for a
        // worse answer: a forged Main HEADER whose MD5 does not check
        // would win the pre-pass and take the real set down with it.
        let mut groups: HashMap<[u8; 16], SetClaims> = HashMap::new();
        let mut seen: std::collections::HashSet<[u8; 16]> = Default::default();

        for (i, input) in inputs.iter().enumerate() {
            let mut census = census.as_deref_mut().map(|c| &mut c[i]);
            scan_packets(input, |pkt| {
                // BEFORE the dedupe: a census is per FILE and a packet
                // repeated across volumes is present in each of them.
                if let Some(c) = census.as_deref_mut() {
                    c.push(census_entry(&pkt));
                }
                if !seen.insert(pkt.md5) {
                    return; // duplicate (packets repeat across volumes)
                }
                let g = groups.entry(pkt.set_id).or_default();
                match &pkt.ptype {
                    // Main body: slice_size u64, file-count u32, then
                    // 16-byte file ids (recovery-set files first, then
                    // optional non-recovery file ids).
                    t if t == TYPE_MAIN => {
                        if let Some((bs, ids, non)) = parse_main(pkt.body) {
                            g.saw_main = true;
                            g.mentioned.extend(ids.iter().chain(non.iter()).copied());
                            g.main.offer((bs, ids));
                            g.nonrec.offer(non);
                        }
                    }
                    t if t == TYPE_FILEDESC => {
                        if let Some((fid, desc)) = parse_filedesc(pkt.body) {
                            g.descs.entry(fid).or_default().offer_desc(fid, desc);
                        }
                    }
                    t if t == TYPE_IFSC => {
                        if let Some((fid, blocks)) = parse_ifsc(pkt.body) {
                            g.ifscs.entry(fid).or_default().offer(blocks);
                        }
                    }
                    // The optional Unicode name, claimed per file id under
                    // the same rule as everything else here: two that
                    // disagree annihilate, and the FileDesc's own spelling
                    // is what stands (M4-22).
                    t if t == TYPE_UNIFILEN => {
                        if let Some((fid, name)) = parse_unifilen(pkt.body) {
                            g.unis.entry(fid).or_default().offer(name);
                        }
                    }
                    // A RecvSlic too short to carry an exponent falls to
                    // the catch-all: it names no row of the coding matrix,
                    // so it is no repair power.
                    //
                    // Whether the payload behind that exponent is long
                    // enough to SERVE the row is a second question, and
                    // it cannot be asked here - the Main packet that
                    // declares the block size may not have been scanned
                    // yet. So the length is banked and judged at the
                    // count below, where `block_size` has settled (Y4b).
                    t if t == TYPE_RECVSLIC && pkt.body.len() >= 4 => {
                        let e = u32::from_le_bytes(pkt.body[0..4].try_into().unwrap());
                        let data = pkt.body.len() - 4;
                        let seen = g.exps.entry(e).or_insert(0);
                        *seen = (*seen).max(data);
                    }
                    _ => {} // Creator + anything unknown: skip
                }
            });
        }

        // Exactly one set claiming to be a recovery set is a set to
        // describe; several is a post to group; none is nothing at all.
        // Answered from the COUNT, so the (unordered) map iteration
        // cannot reach the verdict.
        let candidates: Vec<[u8; 16]> = groups
            .iter()
            .filter(|(_, g)| g.saw_main)
            .map(|(id, _)| *id)
            .collect();
        let set_id = match candidates.len() {
            0 => return Err(Par2Error::NoMainPacket),
            1 => candidates[0],
            _ => return Err(Par2Error::MixedRecoverySets),
        };
        let SetClaims {
            main,
            saw_main: _,
            nonrec,
            mut descs,
            mut ifscs,
            mut unis,
            exps,
            mentioned,
        } = groups.remove(&set_id).expect("candidate came from groups");
        let (block_size, file_ids) = main.into_settled().ok_or(Par2Error::ContradictoryPackets)?;
        // A contradicted NON-recovery list is not fatal, and that is the
        // whole reason it is claimed apart from the geometry beside it.
        // Two Main packets disagreeing about the verify-only members
        // still agree about every byte repair is derived from, so the
        // proportionate answer is to lose the naming those members would
        // have fed - which is exactly what this build did before they
        // were read at all - rather than to refuse a set that repairs.
        let nonrecovery_ids = nonrec.into_settled().unwrap_or_default();

        // Taken BEFORE the first resolve, because `resolve` borrows
        // `descs` mutably for the rest of the block. Scoped by
        // `mentioned` (see its own note): a descriptor is an orphan only
        // where no Main packet of this set ever named its id.
        let mut orphan_ids: Vec<[u8; 16]> = descs
            .keys()
            .copied()
            .filter(|fid| !mentioned.contains(fid))
            .collect();
        orphan_ids.sort_unstable();

        let mut resolve = |fid: [u8; 16]| -> Option<Par2File> {
            // A file id with no usable descriptor is dropped: either
            // no FileDesc packet survived, or two of them disagreed
            // about the name, length or digest AND neither outranks
            // the other (`Claim::offer_desc`), and in all of those we
            // do not know what file this is. The other members of the
            // set still verify and still repair.
            let d = descs.remove(&fid)?.into_settled()?;
            // Two IFSC packets that disagree with EACH OTHER are
            // dropped for that same reason, with the whole-file MD5 as
            // the cover. One whose entry COUNT disagrees with the
            // declared length is a different question and is FITTED to
            // the declared grid rather than binned - see `fit_ifsc`.
            let blocks = ifscs
                .remove(&fid)
                .and_then(Claim::into_settled)
                .map(|b| fit_ifsc(b, d.length, block_size))
                .unwrap_or_default();
            Some(Par2File {
                file_id: fid,
                // The Unicode Filename packet's spelling wins where the
                // producer shipped one, and only where it settled
                // (M4-22). `descs.remove` is what makes an id listed in
                // BOTH halves of the Main packet resolve once, as a
                // recovery member, rather than twice.
                name: unis
                    .remove(&fid)
                    .and_then(Claim::into_settled)
                    .unwrap_or(d.name),
                length: d.length,
                md5: d.md5,
                md5_16k: d.md5_16k,
                blocks,
            })
        };
        let files: Vec<Par2File> = file_ids.into_iter().filter_map(&mut resolve).collect();
        let mut nonrecovery: Vec<Par2File> = nonrecovery_ids
            .into_iter()
            .filter_map(&mut resolve)
            .collect();
        // ORPHAN descriptors (M4-64): a well-formed FileDesc for a file id
        // the Main packet lists in NEITHER half. MultiPar and some rebuild
        // tools emit them, and until this ran they were parsed and then
        // dropped on the floor - the inverse of M4-21, and the same cost:
        // an obfuscated post whose only honest name sits in one of these
        // packets kept its posted hash, and nothing said a name had been
        // read and discarded.
        //
        // They join `nonrecovery` rather than getting a list of their own,
        // because the EVIDENCE is identical to a verify-only member's - a
        // name plus a whole-file MD5, which is exactly what that list is
        // for and what `get::sfvname` already consumes under its own
        // ambiguity and never-overwrite rules. A second list would be a
        // second rule for one kind of clue.
        //
        // What they must never join is `files`: that list is the global
        // slice index space repair lays exponents onto positionally, and a
        // member the Main packet never counted has no slices in it. It is
        // also not a verdict: a set does not fail because a descriptor
        // nobody asked for went unmatched.
        //
        // Sorted by file id, which `descs` (a HashMap) cannot supply - the
        // set's meaning must not depend on the order its packets, or a
        // hasher, happened to put them in (W4-10).
        //
        // An id Main DID mention is not here, whatever became of it: a
        // recovery member, a declared verify-only member and a
        // contradicted descriptor are all governed by the rules that
        // already read them. Only silence makes an orphan.
        nonrecovery.extend(orphan_ids.into_iter().filter_map(&mut resolve));

        Ok(Par2Set {
            recovery_set_id: set_id,
            block_size,
            files,
            nonrecovery,
            // Y4b. `exps.len()` counted every exponent MENTIONED, so a
            // volume of short slices advertised repair power both
            // selection sites refuse. `usize::MAX` on the narrowing
            // failure is the honest answer rather than a truncation: a
            // block bigger than this target can address is one no packet
            // length can ever reach, so nothing fits and the count is 0.
            recovery_blocks_seen: {
                let bs = usize::try_from(block_size).unwrap_or(usize::MAX);
                exps.values().filter(|n| slice_fits_block(**n, bs)).count()
            },
        })
    }

    /// Which recovery set a physical `.par2` file mostly BELONGS to, or
    /// `None` if the buffer holds no structurally valid packet at all.
    ///
    /// Every packet of a `.par2` file - main index and `.volNN+MM`
    /// volume alike - carries its set id in the header, so this
    /// identifies which set a downloaded file belongs to WITHOUT
    /// needing a Main packet in it. That is what makes it the right key
    /// for [`crate::live::pick_sets`]: a recovery volume must be parsed
    /// TOGETHER with its own set's index (its slices are what
    /// `recovery_blocks_seen` counts), and parsing each input alone -
    /// what the single-set fallback used to do - both loses those
    /// slices and cannot tell a volume from a second release.
    ///
    /// It used to answer with the FIRST packet's id, on the stated
    /// ground that a mixed-set buffer does not occur. It does occur, and
    /// one stray packet was enough: a file that is one harmless Creator
    /// packet of set A followed by a COMPLETE set B was filed under A,
    /// the A group then reparsed to `MixedRecoverySets`, and no B group
    /// was ever formed - the whole valid set vanished (X5-14).
    ///
    /// So the answer is a TALLY over every packet, and the rule is fixed
    /// rather than positional:
    ///
    /// 1. a set carrying a Main packet wins, and if exactly one does it
    ///    wins outright - that is the set `Par2Set::parse` will describe
    ///    out of these same bytes, so the grouping key and the parse
    ///    agree by construction rather than by luck;
    /// 2. otherwise the set holding the most BYTES (a volume file is
    ///    almost entirely its own set's slices), then the most packets,
    ///    then the numerically smallest id.
    ///
    /// Every step is a property of the buffer, so the answer does not
    /// move with the order the packets happen to sit in.
    ///
    /// HEADER-BOUNDED: it walks the packet framing and never hashes,
    /// because this is a grouping HINT and `Par2Set::parse` re-decides
    /// it authoritatively with every MD5 checked. The full-scanner
    /// version made the mixed fallback hash a large input about three
    /// times over - once in the initial parse, again per input here, and
    /// again in the grouped parse (the scan budget X5-14 asked for).
    pub fn set_id_of(input: &[u8]) -> Option<[u8; 16]> {
        // (has a Main packet, bytes, packets) per set id.
        let mut tally: HashMap<[u8; 16], (bool, u64, u64)> = HashMap::new();
        for (start, end) in packet_spans(input) {
            let id: [u8; 16] = input[start + 32..start + 48].try_into().unwrap();
            let is_main = &input[start + 48..start + 64] == TYPE_MAIN.as_slice();
            let e = tally.entry(id).or_insert((false, 0, 0));
            e.0 |= is_main;
            e.1 = e.1.saturating_add((end - start) as u64);
            e.2 += 1;
        }
        let with_main = tally.values().filter(|(m, _, _)| *m).count();
        tally
            .into_iter()
            .max_by(|a, b| {
                // `max_by` keeps the LAST maximum, so every comparison
                // has to be total or iteration order leaks back in: the
                // id is the final tie-break and ids in one map are
                // distinct, so no two entries ever compare Equal.
                let key = |(id, (m, bytes, pkts)): &([u8; 16], (bool, u64, u64))| {
                    (*m && with_main == 1, *bytes, *pkts, std::cmp::Reverse(*id))
                };
                key(a).cmp(&key(b))
            })
            .map(|(id, _)| id)
    }

    /// The set's member files as `(hash16k hex, member name)`.
    ///
    /// `hash16k` is the MD5 of the first 16 KiB of a member file, and
    /// the member files of a usenet post are its OUTER volumes - so this
    /// fingerprints a release without reading a byte of its payload and
    /// without needing an archive to open. That is what makes it the one
    /// identity in the pipeline that survives RAR header encryption: the
    /// sidecar describes the `.r00` files, not what is inside them.
    ///
    /// Recovery volumes are excluded (they are not in the recovery set),
    /// and so are members shorter than 16 KiB, whose hash16k is just the
    /// whole-file MD5 of a sample or an nfo and would collide across
    /// unrelated releases.
    pub fn member_hash16k(&self) -> Vec<(String, String)> {
        self.files
            .iter()
            .filter(|f| f.length >= HASH16K_LEN as u64)
            .map(|f| (hex16(&f.md5_16k), f.name.clone()))
            .collect()
    }
}

/// One structurally valid packet, as a CENSUS rather than as a parse.
///
/// [`packet_census`]'s element type - see that function for why the door
/// exists at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketInfo {
    /// The packet's own MD5, which is how PAR2 identifies a packet: two
    /// files carrying the same packet carry the same 16 bytes here, and
    /// that is what makes "how many packets did this file ADD" answerable.
    pub md5: [u8; 16],
    /// The recovery set the packet claims membership of.
    pub set_id: [u8; 16],
    /// The recovery exponent, when this is a RecvSlic packet long enough
    /// to carry one. `None` for every other packet type.
    pub recovery_exponent: Option<u32>,
    /// Bytes of packet BODY. A caller counting repair power must put this
    /// through [`slice_fits_block`] rather than comparing it itself: the
    /// short/long asymmetry is that function's rule and has three call
    /// sites already.
    pub body_len: usize,
}

/// Every structurally valid, checksum-verified packet in `input`.
///
/// # This is a REPORTING door and decides nothing
///
/// `parfast`, the par2cmdline-dialect CLI over this engine, has to print
/// `Loaded 6 new packets including 1 recovery blocks` per file it loads,
/// and that is a per-FILE census of packet identities - a question
/// [`Par2Set::parse`] deliberately does not answer, because it merges
/// its inputs into one set and dedupes as it goes. Without this door the
/// CLI would carry its own PAR2 framing walker, which is the second copy
/// of a parser this repository spends gates refusing.
///
/// So: it hands back what the scan already found and draws no conclusion.
/// Every verdict - which packets form a set, which slices can serve a
/// block, whether a file verifies - stays in this module and in
/// `par2repair`. A caller that starts making decisions from this list is
/// re-implementing the parser one field at a time, and the fix is to move
/// the decision here.
///
/// Corrupt packets are skipped exactly as [`Par2Set::parse`] skips them,
/// because it is the same walk; leading and trailing garbage is
/// tolerated for the same reason.
pub fn packet_census(input: &[u8]) -> Vec<PacketInfo> {
    let mut out = Vec::new();
    scan_packets(input, |pkt| out.push(census_entry(&pkt)));
    out
}

/// One scanned packet as a [`PacketInfo`] - the single copy of that
/// mapping, because [`packet_census`] and [`Par2Set::parse_censused`]
/// both produce the list and a census that differed between the two
/// doors would be a census of which door you asked.
fn census_entry(pkt: &packet::RawPacket<'_>) -> PacketInfo {
    PacketInfo {
        md5: pkt.md5,
        set_id: pkt.set_id,
        recovery_exponent: (pkt.ptype == *TYPE_RECVSLIC && pkt.body.len() >= 4)
            .then(|| u32::from_le_bytes([pkt.body[0], pkt.body[1], pkt.body[2], pkt.body[3]])),
        body_len: pkt.body.len(),
    }
}

/// Lowercase hex of a 16-byte digest - the storage form of a hash16k.
pub fn hex16(d: &[u8; 16]) -> String {
    use std::fmt::Write as _;
    d.iter().fold(String::with_capacity(32), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    mod name_tests;

    use super::*;
    // The internals `use super::*` picked up while they lived in this
    // file, now reached by name (TODO 106). They stay `pub(super)`
    // rather than public because nothing outside `par2` has ever named
    // them: `scan_packets_counted` exists so the hostile-input test can
    // assert on BYTES HASHED rather than on elapsed time, and
    // `scan_packets_serial` so the parallel walk can be differentially
    // tested against the path it falls back to.
    use super::packet::{PAR_SCAN_MIN, scan_packets_counted, scan_packets_serial};
    use super::verify::VERIFY_CHUNK;

    // What a set is taken to say when its packets disagree - one
    // subject, its own file under the size gate (TODO 106). A CHILD of
    // this module so it reaches the packet builders below through `use
    // super::*` rather than copying them, which is also why it resolves
    // to `par2/tests/trust_tests.rs`: an inline `mod tests` roots its
    // children under its own name, and a `#[path]` fighting that would
    // only hide where the file is.
    mod trust_tests;

    /// A crafted `.par2` of overlapping magics with EOF-reaching lengths used
    /// to make `scan_packets` quadratic: every 16-byte cell paid an MD5 over
    /// the rest of the file and then advanced ONE byte. `.par2` files come off
    /// the wire and are read whole with no size cap, so this was an hours-long
    /// CPU burn (an effective hang) from one downloaded file. The hash budget
    /// bounds it; the scan must find no packets and digest a linear number of
    /// bytes doing so.
    ///
    /// Asserted on bytes hashed, never on elapsed time: hashed bytes are
    /// exactly what the budget controls and are identical on every machine,
    /// whereas a wall-clock bound says nothing on a box where this process
    /// holds a fraction of a core - a 5s bound here failed reproducibly on a
    /// fully loaded machine while the budget was working perfectly.
    #[test]
    fn hostile_overlapping_magics_do_not_hash_quadratically() {
        const N: usize = 4 << 20; // 4 MiB: ~275 GB of MD5 before the fix
        let mut input = vec![0u8; N];
        let mut start = 0usize;
        while start + 16 <= N {
            input[start..start + 8].copy_from_slice(MAGIC);
            // Length reaching to EOF, >= HEADER_LEN and 4-aligned, so it passes
            // the structural gate; the stored-MD5 field is the next cell's
            // bytes, so verification always fails and the scan resumes at +1.
            let len = ((N - start) & !3) as u64;
            input[start + 8..start + 16].copy_from_slice(&len.to_le_bytes());
            start += 16;
        }
        let mut seen = 0usize;
        let hashed = scan_packets_counted(&input, |_| seen += 1);
        assert_eq!(seen, 0, "no cell has a valid MD5, so none may be yielded");
        // The optimistic parallel walk hashes each span once and its spans
        // never overlap, so it digests at most N; the serial scan it falls
        // back to stops the moment its budget (4N, here also the 16 MiB
        // floor) would be exceeded. 5N is therefore the true ceiling and 6N
        // is a margin - against ~65536N had the budget been removed.
        assert!(
            hashed <= 6 * N as u64,
            "scan_packets hashed {hashed} bytes over a {N}-byte input \
             - the hash budget is not bounding it"
        );
        // Guard the guard: a bound nothing reaches would pass even if the
        // scan silently stopped doing any work at all.
        assert!(
            hashed >= N as u64,
            "the hostile input must actually be scanned"
        );
    }

    /// The parallel scan (buffers ≥ PAR_SCAN_MIN) must agree with the
    /// serial scan packet-for-packet, in order - on a clean buffer, on one
    /// with inter-packet garbage, and on one with a corrupt packet (which
    /// makes the parallel walk abandon and fall back). A divergence here
    /// is silent data corruption in repair, so compare full packet
    /// identity, not just counts.
    #[test]
    fn parallel_scan_matches_serial_scan() {
        let set_id = [3u8; 16];
        let body = |i: u32| {
            // Recovery-slice-shaped: exponent + ~256 KiB payload, so a
            // handful of packets crosses the parallel threshold.
            let mut b = i.to_le_bytes().to_vec();
            b.extend((0..256 << 10).map(|j| (i as usize * 31 + j) as u8));
            b
        };
        for corrupt_one in [false, true] {
            let mut buf = Vec::new();
            for i in 0..24u32 {
                if i == 7 {
                    buf.extend_from_slice(b"garbage between packets");
                }
                buf.extend(pkt(set_id, TYPE_RECVSLIC, &body(i)));
            }
            assert!(
                buf.len() >= PAR_SCAN_MIN,
                "fixture must take the parallel path"
            );
            if corrupt_one {
                let mid = buf.len() / 2;
                buf[mid] ^= 0xFF;
            }
            let mut serial: Vec<([u8; 16], usize, usize)> = Vec::new();
            scan_packets_serial(&buf, |p| serial.push((p.md5, p.body_offset, p.body.len())));
            let mut both: Vec<([u8; 16], usize, usize)> = Vec::new();
            scan_packets(&buf, |p| both.push((p.md5, p.body_offset, p.body.len())));
            assert_eq!(both, serial, "corrupt_one={corrupt_one}");
            assert_eq!(both.len(), if corrupt_one { 23 } else { 24 });
        }
    }

    /// Build a Main-packet body: block_size ‖ nfiles ‖ nfiles×16 id bytes.
    fn main_body(block_size: u64, nfiles: u32) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&block_size.to_le_bytes());
        b.extend_from_slice(&nfiles.to_le_bytes());
        b.extend(std::iter::repeat_n(0u8, nfiles as usize * 16));
        b
    }

    /// Wrap a body in a valid packet header (magic, length, body MD5).
    fn pkt(set_id: [u8; 16], ptype: &[u8; 16], body: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(MAGIC);
        p.extend_from_slice(&(HEADER_LEN + body.len() as u64).to_le_bytes());
        p.extend_from_slice(&[0u8; 16]); // md5 patched below
        p.extend_from_slice(&set_id);
        p.extend_from_slice(ptype);
        p.extend_from_slice(body);
        let md5: [u8; 16] = Md5::digest(&p[32..]).into();
        p[16..32].copy_from_slice(&md5);
        p
    }

    /// A Main-packet body naming REAL file ids, where `main_body`
    /// above names `nfiles` zero ids - these tests need the ids to match
    /// the FileDesc packets beside them.
    fn main_ids(block_size: u64, ids: &[[u8; 16]]) -> Vec<u8> {
        let mut b = block_size.to_le_bytes().to_vec();
        b.extend_from_slice(&(ids.len() as u32).to_le_bytes());
        for id in ids {
            b.extend_from_slice(id);
        }
        b
    }

    /// Body of a FileDesc packet, name null-padded to a multiple of 4.
    fn desc_body(fid: [u8; 16], md5: u8, length: u64, name: &str) -> Vec<u8> {
        let mut b = fid.to_vec();
        b.extend_from_slice(&[md5; 16]);
        b.extend_from_slice(&[md5; 16]);
        b.extend_from_slice(&length.to_le_bytes());
        b.extend_from_slice(name.as_bytes());
        while !b.len().is_multiple_of(4) {
            b.push(0);
        }
        b
    }

    /// [`main_ids`] with a NON-recovery id list after the recovery one
    /// (M4-21) - the "verify but do not repair" half of a Main packet,
    /// which `main_ids` cannot express because it derives `nfiles` from
    /// the single list it is given.
    fn main_ids_nonrec(block_size: u64, rec: &[[u8; 16]], non: &[[u8; 16]]) -> Vec<u8> {
        let mut b = main_ids(block_size, rec);
        for id in non {
            b.extend_from_slice(id);
        }
        b
    }

    /// [`desc_body`] over REAL bytes rather than a fill byte: the
    /// verify-only naming tier finalizes on the whole-file MD5, so the
    /// one test that follows a descriptor out to that tier needs a
    /// descriptor whose digests are the payload's own.
    fn desc_body_over(fid: [u8; 16], name: &str, data: &[u8]) -> Vec<u8> {
        let mut b = fid.to_vec();
        let whole: [u8; 16] = Md5::digest(data).into();
        b.extend_from_slice(&whole);
        let h16: [u8; 16] = Md5::digest(&data[..data.len().min(HASH16K_LEN)]).into();
        b.extend_from_slice(&h16);
        b.extend_from_slice(&(data.len() as u64).to_le_bytes());
        b.extend_from_slice(name.as_bytes());
        while !b.len().is_multiple_of(4) {
            b.push(0);
        }
        b
    }

    /// Body of a RecvSlic packet: exponent then the slice data.
    fn slice_body(exp: u32, fill: u8) -> Vec<u8> {
        let mut b = exp.to_le_bytes().to_vec();
        b.extend_from_slice(&[fill; 64]);
        b
    }

    /// The identity a parse settled on, as a comparable string - what a
    /// differential over input order compares.
    fn identity(r: &Result<Par2Set, Par2Error>) -> String {
        match r {
            Err(e) => format!("Err({e:?})"),
            Ok(s) => format!(
                "bs={} files={:?}",
                s.block_size,
                s.files
                    .iter()
                    .map(|f| (f.name.clone(), f.length, hex16(&f.md5)))
                    .collect::<Vec<_>>()
            ),
        }
    }

    /// X5-14. A physical `.par2` whose FIRST valid packet belongs to set A
    /// and whose remainder is a complete set B describes B. Binding the
    /// identity to the first packet filed the whole file under A, and the
    /// A group then reparsed to `MixedRecoverySets` - so B vanished.
    #[test]
    fn a_stray_foreign_packet_does_not_hide_the_set_it_precedes() {
        let a = [0xA5u8; 16];
        let b = [0x5Bu8; 16];
        let fid = [0x31u8; 16];

        let mut mixed = pkt(a, b"PAR 2.0\0Creator\0", b"someone-else\0\0\0\0");
        mixed.extend(pkt(b, TYPE_MAIN, &main_ids(100, &[fid])));
        mixed.extend(pkt(b, TYPE_FILEDESC, &desc_body(fid, 0xDD, 400, "b.bin")));
        mixed.extend(pkt(b, TYPE_RECVSLIC, &slice_body(0, 0x11)));

        assert_eq!(
            Par2Set::set_id_of(&mixed),
            Some(b),
            "grouped under the Main"
        );
        let set = Par2Set::parse(&[&mixed]).expect("set B is still described");
        assert_eq!(set.recovery_set_id, b);
        assert_eq!(set.files.len(), 1);
        assert_eq!(set.files[0].name, "b.bin");

        // Two sets that BOTH claim to be one are still a post to group,
        // which is the case `live::pick_sets` acts on - and the answer
        // must not depend on which index was concatenated first.
        let a_index = {
            let mut v = pkt(a, TYPE_MAIN, &main_ids(200, &[fid]));
            v.extend(pkt(a, TYPE_FILEDESC, &desc_body(fid, 0xEE, 900, "a.bin")));
            v
        };
        let mut both = a_index.clone();
        both.extend_from_slice(&mixed);
        assert_eq!(
            Par2Set::parse(&[&both]).unwrap_err(),
            Par2Error::MixedRecoverySets,
            "two Main-bearing sets in one buffer are grouped, not merged"
        );
        assert_eq!(
            Par2Set::parse(&[&mixed, &a_index]).unwrap_err(),
            Par2Error::MixedRecoverySets
        );
    }

    /// X5-14, classification arm. A recovery VOLUME carries no Main at
    /// all, so the tie-break that decides it is bytes - and a stray
    /// foreign packet is a rounding error against a volume's own slices.
    #[test]
    fn set_id_of_a_volume_follows_the_bytes_not_the_first_packet() {
        let a = [0xA5u8; 16];
        let b = [0x5Bu8; 16];
        let mut vol = pkt(a, b"PAR 2.0\0Creator\0", b"noise\0\0\0");
        for e in 0..4u32 {
            vol.extend(pkt(b, TYPE_RECVSLIC, &slice_body(e, e as u8)));
        }
        assert_eq!(Par2Set::set_id_of(&vol), Some(b));
        assert_eq!(Par2Set::set_id_of(b"not a par2 file"), None);

        // Where the two rules DISAGREE, the Main packet wins - and this
        // is the case that makes the rule load-bearing rather than
        // decorative, so it is pinned separately. A file that is mostly
        // set A's slices but carries set B's index describes B, because
        // that is the set `Par2Set::parse` will hand back out of these
        // same bytes: `pick_sets` files the buffer under this key and
        // then parses the group, so a key that disagreed with the parse
        // would file a set under an id that is not its own.
        let mut most_bytes_a = Vec::new();
        for e in 0..8u32 {
            most_bytes_a.extend(pkt(a, TYPE_RECVSLIC, &slice_body(e, e as u8)));
        }
        let fid = [0x51u8; 16];
        most_bytes_a.extend(pkt(b, TYPE_MAIN, &main_ids(64, &[fid])));
        most_bytes_a.extend(pkt(b, TYPE_FILEDESC, &desc_body(fid, 0x77, 64, "b.bin")));
        assert_eq!(
            Par2Set::set_id_of(&most_bytes_a),
            Some(b),
            "the set with the Main packet is the set parse describes"
        );
        assert_eq!(
            Par2Set::parse(&[&most_bytes_a])
                .expect("the indexed set is described")
                .recovery_set_id,
            b,
            "the grouping key and the parse must agree on one buffer"
        );
    }

    /// X5-15. Repair power is DISTINCT EXPONENTS, not packets. Two
    /// checksum-valid slices at exponent 0 with different bytes are two
    /// packet MD5s and one row of the coding matrix; the planner sizes
    /// its fetch on this number, and the native repair catalog dedupes by
    /// exponent, so counting packets advertises capacity that is not
    /// there and escalates into fetching every remaining volume.
    ///
    /// Asserted on `recovery_blocks_seen` alone since Y4b deleted
    /// `Par2Set::recovery_block_count`, which is what this pinned first.
    /// That function took only BYTES, so it could not know a block size
    /// and could not apply [`slice_fits_block`] - and no production
    /// caller had ever named it. This field is what the planner actually
    /// reads, so the rule is pinned where it is consumed.
    #[test]
    fn duplicate_recovery_exponents_are_one_block_of_capacity() {
        let set = [0x5Au8; 16];
        let fid = [0x41u8; 16];
        let mut index = pkt(set, TYPE_MAIN, &main_ids(64, &[fid]));
        index.extend(pkt(set, TYPE_FILEDESC, &desc_body(fid, 0xFF, 64, "x.bin")));

        let mut vol = pkt(set, TYPE_RECVSLIC, &slice_body(0, 0x11));
        vol.extend(pkt(set, TYPE_RECVSLIC, &slice_body(0, 0x22)));
        let one = Par2Set::parse(&[&index, &vol]).expect("parses");
        assert_eq!(one.recovery_blocks_seen, 1);

        // A genuinely different exponent is genuinely more capacity, and
        // the count is over the WHOLE parse - across inputs as within one.
        vol.extend(pkt(set, TYPE_RECVSLIC, &slice_body(1, 0x33)));
        let two = Par2Set::parse(&[&index, &vol]).expect("parses");
        assert_eq!(two.recovery_blocks_seen, 2);
    }

    /// Y4b. The other half of the same field, and the direction that is
    /// UNSAFE. A RecvSlic short of one `block_size` cannot serve a block
    /// and both SELECTION sites refuse it, but the only length test on
    /// this path was `body.len() >= 4` - "carries an exponent" - so the
    /// set advertised repair power for every exponent MENTIONED.
    /// `get::settle` seeds each set's `on_hand` off this field, so an
    /// over-count makes `needed = damage - on_hand` too SMALL and the
    /// exact-fit fetch buys too little; the repair still lands, off the
    /// last-resort escalation that buys every remaining volume.
    ///
    /// The three arms are the rule: exactly one block short is refused,
    /// an EMPTY payload is refused, and the two directions are not
    /// symmetric - an over-long packet still counts, exactly as
    /// [`slice_fits_block`] says the selection sites read it.
    #[test]
    fn a_recovery_slice_shorter_than_the_block_is_no_repair_power() {
        let set = [0x5Au8; 16];
        let fid = [0x41u8; 16];
        let mut index = pkt(set, TYPE_MAIN, &main_ids(64, &[fid]));
        index.extend(pkt(set, TYPE_FILEDESC, &desc_body(fid, 0xFF, 64, "x.bin")));
        // Payload lengths stay 4-byte aligned - `pkt` asserts it, and a
        // real producer's packets are padded to that boundary anyway.
        let sized = |exp: u32, data: usize| {
            let mut b = exp.to_le_bytes().to_vec();
            b.extend_from_slice(&vec![0x11u8; data]);
            pkt(set, TYPE_RECVSLIC, &b)
        };
        let seen = |data: usize| {
            let mut vol = Vec::new();
            for e in 0..4u32 {
                vol.extend(sized(e, data));
            }
            Par2Set::parse(&[&index, &vol])
                .expect("parses")
                .recovery_blocks_seen
        };
        assert_eq!(seen(64), 4, "a slice of exactly one block serves it");
        assert_eq!(seen(68), 4, "an over-long slice is cut to the block");
        assert_eq!(seen(60), 0, "four bytes short of a block serves nothing");
        assert_eq!(seen(0), 0, "an empty payload is not one block of parity");
    }

    /// Y4b. LONGEST-WINS at one exponent, which is what keeps this count
    /// agreeing with the selection sites: they filter by
    /// [`slice_fits_block`] and only THEN dedupe by exponent, so a full
    /// slice sitting beside a short one at the same exponent is a row the
    /// set can serve. First-seen would answer 0 or 1 depending on packet
    /// order, and the meaning of a set must not turn on that (W4-10).
    #[test]
    fn a_short_and_a_full_slice_at_one_exponent_are_one_block() {
        let set = [0x5Au8; 16];
        let fid = [0x41u8; 16];
        let mut index = pkt(set, TYPE_MAIN, &main_ids(64, &[fid]));
        index.extend(pkt(set, TYPE_FILEDESC, &desc_body(fid, 0xFF, 64, "x.bin")));
        let sized = |exp: u32, data: usize, fill: u8| {
            let mut b = exp.to_le_bytes().to_vec();
            b.extend_from_slice(&vec![fill; data]);
            pkt(set, TYPE_RECVSLIC, &b)
        };
        for (a, b, label) in [(60, 64, "short first"), (64, 60, "full first")] {
            let mut vol = sized(0, a, 0x11);
            vol.extend(sized(0, b, 0x22));
            assert_eq!(
                Par2Set::parse(&[&index, &vol])
                    .expect("parses")
                    .recovery_blocks_seen,
                1,
                "{label}"
            );
        }
    }

    /// A hostile poster can declare a 1000-block file and ship an IFSC
    /// listing ONE block. Live verify sizes its per-block state from the
    /// list, so a grid shorter than the file would check slice 0, find no
    /// bad blocks, and report the file clean while the other 999 MiB were
    /// never posted. The grid therefore always spans the declared length:
    /// a long list is trimmed to it, and a short one is filled out with
    /// [`BlockCheck::UNPROVEN`], which no bytes can satisfy - so the
    /// slices the packet never described still force the whole-file MD5.
    ///
    /// This used to DROP the packet outright, which met the same hazard
    /// and cost every slice's evidence with it; see [`fit_ifsc`] for what
    /// that cost a repair. It was named `short_ifsc_is_dropped_not_trusted`
    /// while it did.
    #[test]
    fn a_short_ifsc_never_vouches_past_what_it_describes() {
        let set_id = [7u8; 16];
        let fid = [9u8; 16];
        let block_size: u64 = 1 << 20;
        let length: u64 = 4 << 20; // 4 blocks

        let mut main = Vec::new();
        main.extend_from_slice(&block_size.to_le_bytes());
        main.extend_from_slice(&1u32.to_le_bytes());
        main.extend_from_slice(&fid);

        let mut desc = Vec::new();
        desc.extend_from_slice(&fid);
        desc.extend_from_slice(&[1u8; 16]); // md5
        desc.extend_from_slice(&[2u8; 16]); // md5_16k
        desc.extend_from_slice(&length.to_le_bytes());
        desc.extend_from_slice(b"data.bin");

        // Entries are distinguishable from a placeholder, or the point
        // of the assertions below could not be made: `0xNN` repeated is
        // never the all-zero MD5 `UNPROVEN` carries.
        let ifsc = |n: usize| {
            let mut b = fid.to_vec();
            for i in 0..n {
                b.extend_from_slice(&[i as u8 + 1; 16]);
                b.extend_from_slice(&(i as u32).to_le_bytes());
            }
            b
        };

        let build = |n: usize| {
            let mut buf = pkt(set_id, TYPE_MAIN, &main);
            buf.extend(pkt(set_id, TYPE_FILEDESC, &desc));
            buf.extend(pkt(set_id, TYPE_IFSC, &ifsc(n)));
            buf
        };

        // Short list: the one entry it carries is kept, and the three
        // slices it says nothing about cannot be vouched for.
        let short = build(1);
        let set = Par2Set::parse(&[&short]).unwrap();
        assert_eq!(set.files.len(), 1);
        let b = &set.files[0].blocks;
        assert_eq!(b.len(), 4, "the grid spans the declared length");
        assert!(b[0].is_proven());
        assert!(
            b[1..].iter().all(|c| !c.is_proven()),
            "a 1-entry IFSC must not vouch for a 4-block file"
        );

        // A long list describes slices the file does not have; the
        // surplus is dropped and the file's own four are kept.
        let long = build(9);
        let b = Par2Set::parse(&[&long]).unwrap().files[0].blocks.clone();
        assert_eq!(b.len(), 4);
        assert!(b.iter().all(|c| c.is_proven()));
        assert_eq!(b, ifsc_checks_of(&long)[..4]);

        // The honest count still parses and is kept.
        assert_eq!(
            Par2Set::parse(&[&build(4)]).unwrap().files[0].blocks.len(),
            4
        );
    }

    /// The checks an IFSC packet in `buf` literally carries, read back
    /// independently of `Par2Set::parse` so a trim can be compared
    /// against the packet rather than against itself.
    fn ifsc_checks_of(buf: &[u8]) -> Vec<BlockCheck> {
        let mut out = Vec::new();
        scan_packets(buf, |pkt| {
            if &pkt.ptype == TYPE_IFSC
                && let Some((_, b)) = parse_ifsc(pkt.body)
            {
                out = b;
            }
        });
        out
    }

    #[test]
    fn block_size_bound_rejects_oversized_main() {
        // A real slice parses.
        assert!(parse_main(&main_body(768_000, 1)).is_some());
        // Exactly at the cap is still accepted…
        assert!(parse_main(&main_body(256 << 20, 1)).is_some());
        // …just past it is rejected (would OOM the verifier otherwise).
        assert!(parse_main(&main_body((256 << 20) + 4, 1)).is_none());
        // The crafted 2^62-ish value that drove the out-of-memory kill.
        assert!(parse_main(&main_body(0x7FFF_FFFF_FFFF_FFFC, 1)).is_none());
        // Existing guards still hold: zero, and non-multiple-of-4.
        assert!(parse_main(&main_body(0, 1)).is_none());
        assert!(parse_main(&main_body(1002, 1)).is_none());
    }

    /// M4-25 of the no-RAR matrix, decoder half. `parse_main` above bounds
    /// the block size from ABOVE; nothing bounds it from BELOW, so a set
    /// may declare `block_size = 4` and turn a modest member into hundreds
    /// of thousands of IFSC entries and that many live-verify cells. The
    /// row predicted the allocator or the verifier would blow up.
    ///
    /// It cannot arrive from a creator: par2cmdline REFUSES above 32768
    /// source blocks ("Too many source blocks (262144 > 32768)", measured
    /// on this box 30 Aug 2026), which is exactly why the hostile shape has
    /// to be hand-built here rather than through `par2 create` - and why
    /// the decoder is the only thing standing in front of it.
    ///
    /// MEASURED CLEAN (wave-5 verification round, 30 Aug 2026): a 1 MiB
    /// member at 4-byte blocks parses its 262144 cells in 71 ms and takes
    /// a live activate plus a full 1 MiB feed in 117 ms.
    ///
    /// The row allows EITHER answer - refuse below a floor, or accept and
    /// bound the work - so this holds the disjunction rather than today's
    /// half of it: a floor added later is a fix, not a regression, and must
    /// not redden this. The 65536-byte CONTROL is what stops that arm being
    /// a free pass, since a parser that refused every set would otherwise
    /// read as "a floor was added".
    ///
    /// What the accepting arm pins is the SHAPE and not the timings: one
    /// cell per declared block and not one more, which IS the memory bound,
    /// because a cell is fixed-size and that list is all the state there is
    /// to hold. The elapsed check is a deliberate backstop, not a perf
    /// assertion - `hostile_overlapping_magics_do_not_hash_quadratically`
    /// above records that a 5s bound in this file failed reproducibly on a
    /// loaded box, so this one is ~300x the measured cost and exists only
    /// to catch the row's actual prediction of "minutes".
    #[test]
    fn a_four_byte_block_size_is_bounded_by_the_ifsc_it_must_carry() {
        const LEN: u64 = 1 << 20;
        let set_id = [0x25u8; 16];
        let fid = [0x26u8; 16];

        // One whole set at a chosen slice: Main, FileDesc, and an IFSC
        // carrying the honest one-entry-per-block list that size implies.
        let build = |block_size: u64| {
            let blocks = (LEN / block_size) as usize;
            let mut main = block_size.to_le_bytes().to_vec();
            main.extend_from_slice(&1u32.to_le_bytes());
            main.extend_from_slice(&fid);

            let mut desc = fid.to_vec();
            desc.extend_from_slice(&[0x27u8; 16]); // md5
            desc.extend_from_slice(&[0x28u8; 16]); // md5_16k
            desc.extend_from_slice(&LEN.to_le_bytes());
            desc.extend_from_slice(b"Tiny.Blocks.bin");
            desc.push(0); // 4-byte align the name region

            let mut ifsc = Vec::with_capacity(16 + blocks * 20);
            ifsc.extend_from_slice(&fid);
            for i in 0..blocks {
                let cell: [u8; 16] = Md5::digest((i as u64).to_le_bytes()).into();
                ifsc.extend_from_slice(&cell);
                ifsc.extend_from_slice(&(i as u32).to_le_bytes());
            }

            let mut buf = pkt(set_id, TYPE_MAIN, &main);
            buf.extend(pkt(set_id, TYPE_FILEDESC, &desc));
            buf.extend(pkt(set_id, TYPE_IFSC, &ifsc));
            (buf, blocks)
        };

        // The control: an ordinary slice over the same member. Whatever
        // happens below, THIS must parse into its 16 cells - so a refusal
        // of the 4-byte set is a floor and never a broken parser.
        let (sane, sane_blocks) = build(65536);
        let ok = Par2Set::parse(&[&sane]).expect("an ordinary 64 KiB slice must parse");
        assert_eq!(
            ok.files[0].blocks.len(),
            sane_blocks,
            "the control set must reach its IFSC, or the arm below proves nothing"
        );

        const BLOCKS: usize = (LEN / 4) as usize;
        let (hostile, blocks) = build(4);
        assert_eq!(blocks, BLOCKS);

        let t = std::time::Instant::now();
        let Ok(parsed) = Par2Set::parse(&[&hostile]) else {
            // A block-size floor was added. That is the row's other
            // acceptable answer and there is no work left to bound.
            return;
        };
        assert_eq!(parsed.block_size, 4, "the declared slice must survive");
        assert_eq!(
            parsed.files.len(),
            1,
            "one FileDesc in, one file out - a fan-out here is the blow-up"
        );
        assert_eq!(
            parsed.files[0].blocks.len(),
            BLOCKS,
            "{BLOCKS} declared blocks must yield exactly {BLOCKS} cells - \
             fewer means the IFSC was dropped and this arm pins nothing, \
             more means the state is not bounded by the input"
        );

        // The live verifier sizes its per-block state from that list, so
        // activating and feeding the whole member is where a per-cell cost
        // would show. Fed in ONE call on purpose: a chunked feed would let
        // a per-call walk of all 262144 cells hide in the chunk count.
        let v = crate::live::LiveVerifier::new(1);
        v.set_name_hint(0, "Tiny.Blocks.bin");
        v.activate(&[&hostile])
            .expect("the set the parser just accepted must also activate");
        v.on_data(0, "Tiny.Blocks.bin", LEN, 0, &vec![0u8; LEN as usize]);
        let secs = t.elapsed().as_secs_f64();

        assert!(
            secs < 60.0,
            "a hand-crafted 4-byte-block set over a {LEN}-byte member cost \
             {secs:.1}s to parse, activate and feed ({BLOCKS} cells) - the \
             missing block-size floor has stopped being harmless"
        );
    }

    #[test]
    fn a_wrapping_file_count_is_refused_not_accepted() {
        // Hand-built rather than through `main_body`, which sizes its id
        // list to the count - the point here is a count the body cannot
        // back. nfiles * 16 == 2^32 WRAPS to 0 in a 32-bit usize
        // multiply, so the old `ids_bytes.len() < nfiles * 16` guard
        // passed a tiny crafted Main packet on ARMv7 (and panicked under
        // overflow-checks, which is what a fuzzer on a 32-bit host would
        // have hit). The division form cannot wrap on any width (Codex
        // sweep 24 Aug, F-02).
        let body = |nfiles: u32| {
            let mut b = Vec::new();
            b.extend_from_slice(&768_000u64.to_le_bytes());
            b.extend_from_slice(&nfiles.to_le_bytes());
            b.extend_from_slice(&[0u8; 16]); // one id, however many claimed
            b
        };
        assert!(parse_main(&body(0x1000_0000)).is_none());
        assert!(parse_main(&body(u32::MAX)).is_none());
        // ...and an honest count over the same 16-byte list still parses.
        assert_eq!(parse_main(&body(1)).unwrap().1.len(), 1);
    }

    /// The three block figures, and which way each of them leans.
    ///
    /// A verdict that STOPS a download compares a FLOOR on the damage
    /// against a CEILING on the cure, so the estimate that sits between
    /// them may never be substituted for either. Real numbers from the
    /// 15 Aug post: 1,614,720-byte slices, and volumes the repair path
    /// found held 40 blocks between them.
    #[test]
    fn the_recovery_bounds_never_cross_the_estimate() {
        const BLOCK: u64 = 1_614_720;
        let volumes = [
            1_708_175u64,
            3_415_979,
            6_790_307,
            13_497_147,
            15_163_522,
            26_869_479,
        ];
        let est: usize = volumes.iter().map(|&b| est_recovery_blocks(b, BLOCK)).sum();
        let ceil: u64 = volumes.iter().map(|&b| max_recovery_blocks(b, BLOCK)).sum();
        assert_eq!(est, 40, "the estimate reproduces the budget repair found");
        assert_eq!(ceil, 40u64);
        // The ceiling can never come in under the estimate - that is the
        // only relationship a verdict may lean on.
        for &b in &volumes {
            assert!(
                max_recovery_blocks(b, BLOCK) >= est_recovery_blocks(b, BLOCK) as u64,
                "{b} bytes: ceiling below estimate"
            );
        }
        // A volume too small for one slice holds none, however named.
        assert_eq!(max_recovery_blocks(41_901, BLOCK), 0);
        assert_eq!(est_recovery_blocks(41_901, BLOCK), 0);
        // A zero block size is not a set: every figure is zero rather
        // than a division by it.
        assert_eq!(max_recovery_blocks(1 << 30, 0), 0);
        assert_eq!(est_recovery_blocks(1 << 30, 0), 0);
        assert_eq!(min_damaged_blocks(1 << 30, 0), 0);
    }

    /// Missing bytes cannot hide in fewer slices than they fill. The
    /// count rounds DOWN, one step further from claiming impossibility
    /// than the true bound (which is the ceiling) already is.
    #[test]
    fn missing_bytes_force_at_least_that_many_damaged_blocks() {
        assert_eq!(min_damaged_blocks(0, 4_096), 0);
        assert_eq!(min_damaged_blocks(1, 4_096), 0);
        assert_eq!(min_damaged_blocks(4_095, 4_096), 0);
        assert_eq!(min_damaged_blocks(4_096, 4_096), 1);
        assert_eq!(min_damaged_blocks(4_097, 4_096), 1);
        // The 15 Aug post: 1.45 GB gone, 1.6 MB slices. RAW bytes -
        // feeding this the NZB's encoded figure is the units error
        // [`min_raw_bytes`] exists to stop.
        assert_eq!(min_damaged_blocks(1_453_188_000, 1_614_720), 899);
    }

    /// The encoded-to-raw conversion has one job: never overstate the
    /// raw payload, because everything downstream of it is a damage
    /// FLOOR that stops a download.
    ///
    /// The 15 Aug post is the measurement it is set against -
    /// 3,332,350,599 encoded bytes over 3,229,432,857 raw ones, 3.19%
    /// overhead where [`YENC_RAW_FRACTION`] allows 2%. Whole-file damage
    /// is where an overstatement shows up as an outright impossibility:
    /// the file has 2,000 slices and the unconverted figure claimed
    /// 2,063 of them damaged.
    #[test]
    fn encoded_bytes_convert_to_a_raw_floor_the_real_post_clears() {
        const ENCODED: u64 = 3_332_350_599;
        const RAW: u64 = 3_229_432_857;
        const BLOCK: u64 = 1_614_720;

        assert!(
            min_raw_bytes(ENCODED) <= RAW,
            "the floor overstates the payload it is a floor for"
        );
        assert!(
            min_damaged_blocks(min_raw_bytes(ENCODED), BLOCK) <= RAW.div_ceil(BLOCK),
            "whole-file damage claimed more blocks than the file has"
        );
        // And it gives up only the overhead: a bound that threw the
        // deficit away would be safe and useless.
        assert!(min_raw_bytes(ENCODED) * 10 >= RAW * 9);
        // 0.98 is the ESTIMATE fraction and would not have caught this
        // post - the reason a second, blunter constant exists at all.
        assert!((ENCODED as f64 * YENC_RAW_FRACTION) as u64 > RAW);

        assert_eq!(min_raw_bytes(0), 0);
    }

    /// The Main packet of a real par2 index states the slice size in its
    /// first 92 bytes - which is what makes the pre-flight probe one
    /// small article rather than a download.
    #[test]
    fn a_real_index_states_its_block_size_in_its_first_bytes() {
        const INDEX: &[u8] = include_bytes!("../tests/fixtures/par2/testset.par2");
        let set = Par2Set::parse(&[INDEX]).expect("fixture is a valid set");
        assert_eq!(set.block_size, 4_096);
        // And from the head alone: the Main packet is the first thing in
        // the file, so a partial read is enough.
        let head = Par2Set::parse(&[&INDEX[..256]]).expect("Main packet is in the first bytes");
        assert_eq!(head.block_size, 4_096);
    }

    /// Both verdict bounds must survive a quotient past 2^32.
    ///
    /// They used to narrow the u64 quotient with `as usize`, which is a
    /// silent truncation of the low 32 bits on a 32-bit target - and we
    /// ship one (`armv7-unknown-linux-musleabihf`). `encoded_bytes` is
    /// the NZB's poster-controlled `bytes=` with no cap on this path and
    /// `parse_main` admits a block size as small as 4, so 16 GiB
    /// declared on one volume wraps the CEILING to zero and any deficit
    /// at all becomes a false IMPOSSIBLE - refusing a job that would
    /// have finished, which is the exact direction these two functions
    /// exist to forbid. Keeping the arithmetic in u64 makes the
    /// truncation unrepresentable; on a 64-bit host this test cannot
    /// fail either way, so it is here as the shape guard, not as proof.
    #[test]
    fn the_verdict_bounds_do_not_wrap_at_a_32_bit_quotient() {
        const WRAP: u64 = 1 << 32;
        // A ceiling of exactly 2^32 blocks: the value `as usize`
        // truncated to 0 on armv7.
        let ceiling: u64 = max_recovery_blocks(4 * WRAP, 4);
        assert_eq!(ceiling, WRAP);
        assert!(
            ceiling > u32::MAX as u64,
            "the guard needs a wrapping value"
        );
        // The deficit half wrapped DOWN, which softens rather than
        // condemns - but it is the same cast and the same fix.
        assert_eq!(min_damaged_blocks(4 * WRAP, 4), WRAP);
        // And the ordering the whole module rests on holds across the
        // boundary: equal bytes on both sides never condemns.
        assert!(min_damaged_blocks(4 * WRAP, 4) <= max_recovery_blocks(4 * WRAP, 4));
    }

    // -- streaming vs buffered verification -------------------------------
    //
    // `verify_file` stays the reference implementation (see its docs and
    // `verify_file_blocks`'). `verify_file_streaming` is the one the
    // download and CLI paths actually run, so every verdict it reaches has
    // to be the reference's verdict, byte for byte. The fixture-driven
    // half of this differential - real par2cmdline output, choked reads,
    // corrupt/short/empty inputs - lives in tests/integration/par2_parse.rs; this half
    // covers what a 33 KiB fixture cannot reach: a file several read
    // windows long, whose blocks straddle those windows at an offset that
    // never repeats.

    /// A `Par2File` describing `data` exactly, with honest per-block
    /// checksums (last block zero-padded per spec). Deliberately built
    /// with the plain one-shot hashers rather than with either verifier,
    /// so it is an independent third party to the comparison.
    fn synth_file(data: &[u8], bs: usize) -> Par2File {
        let mut padded = vec![0u8; bs];
        let blocks = (0..data.len().div_ceil(bs))
            .map(|i| {
                let start = i * bs;
                let end = (start + bs).min(data.len());
                padded.fill(0);
                padded[..end - start].copy_from_slice(&data[start..end]);
                BlockCheck {
                    md5: Md5::digest(&padded).into(),
                    crc32: crc32fast::hash(&padded),
                }
            })
            .collect();
        Par2File {
            file_id: [0u8; 16],
            name: "synth.bin".into(),
            length: data.len() as u64,
            md5: Md5::digest(data).into(),
            md5_16k: Md5::digest(&data[..data.len().min(HASH16K_LEN)]).into(),
            blocks,
        }
    }

    fn assert_agrees(file: &Par2File, block_size: u64, data: &[u8], case: &str) {
        static NEXT_PATH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let want = verify_file(file, block_size, data);
        let got = verify_file_streaming(file, block_size, std::io::Cursor::new(data))
            .expect("a cursor cannot fail to read");
        let seekable = verify_file_seekable(file, block_size, std::io::Cursor::new(data))
            .expect("a cursor cannot fail to seek or read");
        let path = std::env::temp_dir().join(format!(
            "nzbkit-par2-path-differential-{}-{}",
            std::process::id(),
            NEXT_PATH.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        ));
        std::fs::write(&path, data).expect("write path-verifier fixture");
        let path_got = verify_file_path(&path, file, block_size, 8)
            .expect("a regular fixture file cannot fail to read");
        let path_md5_got =
            verify_file_md5_path(&path, file).expect("a regular fixture file cannot fail to read");
        let _ = std::fs::remove_file(path);
        assert_eq!(want.blocks, got.blocks, "{case}: per-block flags");
        assert_eq!(want.md5_ok, got.md5_ok, "{case}: whole-file MD5");
        assert_eq!(want.md5_16k_ok, got.md5_16k_ok, "{case}: MD5-16k");
        assert_eq!(want.blocks, seekable.blocks, "{case}: seekable blocks");
        assert_eq!(want.md5_ok, seekable.md5_ok, "{case}: seekable MD5");
        assert_eq!(
            want.md5_16k_ok, seekable.md5_16k_ok,
            "{case}: seekable MD5-16k"
        );
        assert_eq!(want.blocks, path_got.blocks, "{case}: file-path blocks");
        assert_eq!(want.md5_ok, path_got.md5_ok, "{case}: file-path MD5");
        assert_eq!(
            want.md5_16k_ok, path_got.md5_16k_ok,
            "{case}: file-path MD5-16k"
        );
        assert_eq!(
            want.md5_ok,
            verify_file_md5_streaming(file, std::io::Cursor::new(data))
                .expect("a cursor cannot fail to read"),
            "{case}: narrow MD5 verifier"
        );
        assert_eq!(want.md5_ok, path_md5_got, "{case}: file-path MD5 verifier");
    }

    struct Counted<R> {
        inner: R,
        bytes_read: usize,
    }

    impl<R: std::io::Read> std::io::Read for Counted<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.bytes_read += n;
            Ok(n)
        }
    }

    impl<R: std::io::Seek> std::io::Seek for Counted<R> {
        fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    /// Clean is the common standalone-verify case. Its whole-file digest
    /// settles every block, so reading the payload again for block hashes is
    /// pure work. A damaged file still takes the diagnostic second pass.
    #[test]
    fn seekable_verify_only_rewinds_for_damage() {
        const BS: usize = 64 << 10;
        let data: Vec<u8> = (0..3 * BS + 117)
            .map(|i| (i as u8).wrapping_mul(29).wrapping_add((i >> 9) as u8))
            .collect();
        let file = synth_file(&data, BS);

        let mut clean = Counted {
            inner: std::io::Cursor::new(&data),
            bytes_read: 0,
        };
        let clean_v = verify_file_seekable(&file, BS as u64, &mut clean).unwrap();
        assert!(clean_v.md5_ok && clean_v.blocks.iter().all(|&ok| ok));
        assert_eq!(clean.bytes_read, data.len(), "clean must be one read pass");

        let mut hurt = data.clone();
        hurt[BS + 3] ^= 0x80;
        let mut damaged = Counted {
            inner: std::io::Cursor::new(&hurt),
            bytes_read: 0,
        };
        let damaged_v = verify_file_seekable(&file, BS as u64, &mut damaged).unwrap();
        assert!(!damaged_v.md5_ok);
        assert_eq!(
            damaged_v.blocks.iter().filter(|&&ok| !ok).count(),
            1,
            "the diagnostic pass must still identify the exact block"
        );
        assert_eq!(
            damaged.bytes_read,
            2 * data.len(),
            "damage must pay exactly one diagnostic reread"
        );

        let path = std::env::temp_dir().join(format!(
            "nzbkit-par2-parallel-verify-{}",
            std::process::id()
        ));
        std::fs::write(&path, &hurt).unwrap();
        let parallel = verify_file_path(&path, &file, BS as u64, 8).unwrap();
        assert_eq!(parallel.blocks, damaged_v.blocks);
        assert_eq!(parallel.md5_ok, damaged_v.md5_ok);
        assert_eq!(parallel.md5_16k_ok, damaged_v.md5_16k_ok);

        // The FileDesc and IFSC are separate claims. Exercise that hostile
        // pairing through the parallel path too: a matching CRC must not
        // launder a block whose IFSC MD5 disagrees.
        let mut inconsistent = file.clone();
        inconsistent.blocks[0].md5 = [0x5a; 16];
        let want = verify_file(&inconsistent, BS as u64, &hurt);
        let got = verify_file_path(&path, &inconsistent, BS as u64, 8).unwrap();
        assert_eq!(got.blocks, want.blocks, "parallel IFSC-conflict bitmap");
        assert_eq!(got.md5_ok, want.md5_ok, "parallel IFSC-conflict MD5");
        let _ = std::fs::remove_file(path);
    }

    /// A fitted short IFSC is a real checksum prefix followed by UNPROVEN
    /// cells. Once the whole-file MD5 has failed, the suffix cannot become
    /// true for any bytes, so the rewind pass owes only the prefix. Keep the
    /// one-pass streamer in the same differential: it must still consume the
    /// whole source for FileDesc MD5, but must return the identical bitmap.
    #[test]
    fn a_short_ifsc_diagnostic_reads_only_its_proven_prefix() {
        const BS: usize = 64 << 10;
        let data: Vec<u8> = (0..4 * VERIFY_CHUNK + 117)
            .map(|i| (i as u8).wrapping_mul(29).wrapping_add((i >> 9) as u8))
            .collect();
        let mut file = synth_file(&data, BS);
        const PROVEN: usize = 3;
        file.blocks[PROVEN..].fill(BlockCheck::UNPROVEN);
        // Force the diagnostic pass while leaving every proved prefix block
        // byte-exact. This is also an adversarial FileDesc/IFSC pairing: the
        // two packet claims are intentionally independent.
        file.md5[0] ^= 0x80;

        let mut seekable = Counted {
            inner: std::io::Cursor::new(&data),
            bytes_read: 0,
        };
        let got = verify_file_seekable(&file, BS as u64, &mut seekable).unwrap();
        assert!(!got.md5_ok);
        assert!(got.blocks[..PROVEN].iter().all(|&ok| ok));
        assert!(got.blocks[PROVEN..].iter().all(|&ok| !ok));
        assert_eq!(
            seekable.bytes_read,
            data.len() + PROVEN * BS,
            "the rewind pass must stop exactly after the last real IFSC cell"
        );

        let mut one_pass = Counted {
            inner: std::io::Cursor::new(&data),
            bytes_read: 0,
        };
        let streamed = verify_file_streaming(&file, BS as u64, &mut one_pass).unwrap();
        assert_eq!(streamed.blocks, got.blocks);
        assert_eq!(streamed.md5_ok, got.md5_ok);
        assert_eq!(streamed.md5_16k_ok, got.md5_16k_ok);
        assert_eq!(
            one_pass.bytes_read,
            data.len(),
            "the one-pass form still owes the complete FileDesc hashes"
        );
        assert_agrees(&file, BS as u64, &data, "short IFSC proven prefix");
    }

    /// Exercise the shapes a parser can hand verification after fitting a
    /// malformed IFSC: no entries, a short suffix, and reserved all-zero MD5
    /// entries interleaved between real checks. The buffered implementation
    /// remains the oracle and the path call crosses the test-only positioned
    /// threshold, so every implementation is included in each comparison.
    #[test]
    fn unproven_diagnostics_match_the_buffered_oracle_in_every_position() {
        const BS: usize = 131_068;
        let data: Vec<u8> = (0..2 * VERIFY_CHUNK + 19_117)
            .map(|i| (i as u8).wrapping_mul(41).wrapping_add((i >> 11) as u8))
            .collect();
        let honest = synth_file(&data, BS);
        assert!(honest.blocks.len() > 8);

        let mut disk = data.clone();
        disk[4 * BS + 17] ^= 0x5a;

        let mut no_ifsc = honest.clone();
        no_ifsc.blocks.clear();
        assert_agrees(&no_ifsc, BS as u64, &disk, "missing IFSC");

        let mut zero_entry_ifsc = honest.clone();
        zero_entry_ifsc.blocks.fill(BlockCheck::UNPROVEN);
        assert_agrees(
            &zero_entry_ifsc,
            BS as u64,
            &disk,
            "zero-entry IFSC fitted entirely with placeholders",
        );

        let mut short = honest.clone();
        short.blocks[3..].fill(BlockCheck::UNPROVEN);
        let short_want = verify_file(&short, BS as u64, &disk);
        assert_eq!(short_want.blocks[..3], [true, true, true]);
        assert!(short_want.blocks[3..].iter().all(|&ok| !ok));
        assert_agrees(&short, BS as u64, &disk, "short IFSC suffix");

        let mut mixed = honest.clone();
        for index in [0, 2, 7, mixed.blocks.len() - 1] {
            mixed.blocks[index] = BlockCheck::UNPROVEN;
        }
        let mixed_want = verify_file(&mixed, BS as u64, &disk);
        assert!(!mixed_want.blocks[0]);
        assert!(!mixed_want.blocks[2]);
        assert!(!mixed_want.blocks[4], "the damaged real check stays bad");
        assert!(mixed_want.blocks[5], "a later real check keeps its offset");
        assert!(!mixed_want.blocks[7]);
        assert!(!mixed_want.blocks[mixed.blocks.len() - 1]);
        assert_agrees(&mixed, BS as u64, &disk, "interior UNPROVEN entries");
        assert_agrees(
            &mixed,
            BS as u64,
            &disk[..2 * BS + 17],
            "EOF inside an interior UNPROVEN entry",
        );
    }

    /// Blocks that straddle the read window - the one thing the streaming
    /// form does that the buffered form never had to. 300,004 bytes into a
    /// 1 MiB window means no block boundary ever lands on a window
    /// boundary, and the file spans four windows, so a block is split at
    /// three different offsets within itself.
    #[test]
    fn streaming_verify_matches_reference_across_read_windows() {
        const BS: usize = 300_004;
        // Not a round multiple of BS: the last block is short and padded.
        let len = 3 * VERIFY_CHUNK + 7;
        let data: Vec<u8> = (0..len as u64)
            .map(|i| (i.wrapping_mul(2654435761) >> 16) as u8)
            .collect();
        let f = synth_file(&data, BS);
        assert!(f.blocks.len() > 10, "the case needs several blocks");

        // Guard the guard: with garbage checksums both implementations
        // would answer `false` everywhere and agree vacuously.
        let clean = verify_file(&f, BS as u64, &data);
        assert!(clean.blocks.iter().all(|&ok| ok) && clean.md5_ok && clean.md5_16k_ok);
        assert_agrees(&f, BS as u64, &data, "clean");

        // One flipped byte in a block that a read window splits.
        let mut hurt = data.clone();
        hurt[VERIFY_CHUNK + 3] ^= 0xff;
        let v = verify_file(&f, BS as u64, &hurt);
        assert_eq!(v.blocks.iter().filter(|ok| !**ok).count(), 1);
        assert_agrees(&f, BS as u64, &hurt, "one flipped byte");

        // A flip inside the short, zero-padded final block.
        let mut tail = data.clone();
        let last = tail.len() - 1;
        tail[last] ^= 0x01;
        assert_agrees(&f, BS as u64, &tail, "flipped tail byte");

        // Truncated mid-block, and grown past the last expected block.
        assert_agrees(&f, BS as u64, &data[..len - 5], "truncated");
        assert_agrees(&f, BS as u64, &data[..BS + 17], "truncated to one block");
        let mut longer = data.clone();
        longer.extend_from_slice(b"trailing bytes past the recovery set");
        assert_agrees(&f, BS as u64, &longer, "trailing bytes");
    }
    /// A Unicode Filename packet body: file id then the name in UTF-16,
    /// null-padded to a multiple of 4 like every other packet body.
    fn uni_body(fid: [u8; 16], name: &str, le: bool, bom: bool) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&fid);
        let mut put =
            |u: u16| b.extend_from_slice(&if le { u.to_le_bytes() } else { u.to_be_bytes() });
        if bom {
            put(0xFEFF);
        }
        for u in name.encode_utf16() {
            put(u);
        }
        while !b.len().is_multiple_of(4) {
            b.push(0);
        }
        b
    }

    // -- M4-37 / M4-38: what a packet is allowed to assert ----------------

    /// A FileDesc body describing `data` truthfully under `name`, with
    /// a file id the caller chooses - so a test can post an honest one,
    /// or forge another file's. Named for what it does rather than
    /// `desc_body`, which is a different helper in this same module.
    fn desc_of(fid: [u8; 16], name: &str, data: &[u8]) -> Vec<u8> {
        let mut b = fid.to_vec();
        b.extend_from_slice(&<[u8; 16]>::from(Md5::digest(data)));
        b.extend_from_slice(&<[u8; 16]>::from(Md5::digest(
            &data[..data.len().min(HASH16K_LEN)],
        )));
        b.extend_from_slice(&(data.len() as u64).to_le_bytes());
        let mut nb = name.as_bytes().to_vec();
        nb.resize(nb.len().next_multiple_of(4), 0);
        b.extend_from_slice(&nb);
        b
    }

    /// The spec's file id: MD5 of the FileDesc's own hash16k, length and
    /// name - the LAST three fields, without the name's null padding.
    /// Confirmed against par2cmdline 1.3.0 output before it was relied on.
    fn honest_fid(name: &str, data: &[u8]) -> [u8; 16] {
        let mut h = Md5::new();
        h.update(Md5::digest(&data[..data.len().min(HASH16K_LEN)]));
        h.update((data.len() as u64).to_le_bytes());
        h.update(name.as_bytes());
        h.finalize().into()
    }

    /// An IFSC body carrying honest checks for `data`, but only `n` of
    /// them - `n` short of, equal to, or past the file's real block count.
    fn ifsc_body(fid: [u8; 16], data: &[u8], bs: usize, n: usize) -> Vec<u8> {
        let mut b = fid.to_vec();
        let mut padded = vec![0u8; bs];
        for i in 0..n {
            let start = i * bs;
            padded.fill(0);
            if start < data.len() {
                let end = (start + bs).min(data.len());
                padded[..end - start].copy_from_slice(&data[start..end]);
            }
            b.extend_from_slice(&<[u8; 16]>::from(Md5::digest(&padded)));
            b.extend_from_slice(&crc32fast::hash(&padded).to_le_bytes());
        }
        b
    }

    /// M4-21 (30 Aug 2026): a Main packet's NON-recovery file ids - the
    /// "verify but do not repair" half QuickPar and MultiPar both write -
    /// resolve through their FileDescs into `nonrecovery`, and NEVER into
    /// `files`.
    ///
    /// Both halves of that assertion are load-bearing and for different
    /// reasons. Before this they were parsed and dropped, so the file was
    /// never named, never verified and nothing said so. Putting them in
    /// `files` instead would be worse than the gap: repair lays files onto
    /// the global input-slice index by walking that list in order, so one
    /// extra entry shifts every exponent after it.
    #[test]
    fn nonrecovery_file_ids_are_kept_out_of_the_recovery_set_and_still_read() {
        let set_id = [11u8; 16];
        let rec = [1u8; 16];
        let non = [2u8; 16];
        let payload: Vec<u8> = (0..64u8).collect();
        let mut buf = pkt(set_id, TYPE_MAIN, &main_ids_nonrec(4, &[rec], &[non]));
        buf.extend(pkt(
            set_id,
            TYPE_FILEDESC,
            &desc_body_over(rec, "payload.bin", &payload),
        ));
        buf.extend(pkt(
            set_id,
            TYPE_FILEDESC,
            &desc_body_over(non, "notes.nfo", b"notes"),
        ));
        let set = Par2Set::parse(&[&buf]).unwrap();
        assert_eq!(
            set.files
                .iter()
                .map(|f| f.name.as_str())
                .collect::<Vec<_>>(),
            ["payload.bin"],
            "a verify-only member must not enter the slice index space"
        );
        assert_eq!(
            set.nonrecovery
                .iter()
                .map(|f| f.name.as_str())
                .collect::<Vec<_>>(),
            ["notes.nfo"]
        );
        // The whole-file MD5 is what the naming tier finalizes on, so it
        // has to be the descriptor's own and not a placeholder.
        assert_eq!(
            set.nonrecovery[0].md5,
            <[u8; 16]>::from(Md5::digest(b"notes"))
        );
        assert_eq!(set.nonrecovery[0].length, 5);
    }

    /// An id listed in BOTH halves of one Main packet resolves ONCE, as a
    /// recovery member. `descs.remove` is what makes that true; a `get`
    /// would hand the same descriptor to repair AND to the weak naming
    /// tier, which is a file being named by a tier that has no business
    /// speaking about a member the set already covers.
    #[test]
    fn an_id_in_both_main_halves_resolves_once_as_a_recovery_member() {
        let set_id = [12u8; 16];
        let fid = [3u8; 16];
        let mut buf = pkt(set_id, TYPE_MAIN, &main_ids_nonrec(4, &[fid], &[fid]));
        buf.extend(pkt(
            set_id,
            TYPE_FILEDESC,
            &desc_body(fid, 1, 4, "both.bin"),
        ));
        let set = Par2Set::parse(&[&buf]).unwrap();
        assert_eq!(set.files.len(), 1);
        assert!(set.nonrecovery.is_empty());
    }

    /// M4-22 (30 Aug 2026): a MultiPar-shaped Unicode Filename packet
    /// carries the real name where the FileDesc's byte field holds a
    /// lossy transliteration. Bare UTF-16LE with no BOM is what producers
    /// write and is the shape that must work.
    #[test]
    fn a_unicode_filename_packet_overrides_a_lossy_filedesc_spelling() {
        let set_id = [13u8; 16];
        let fid = [4u8; 16];
        let mut buf = pkt(set_id, TYPE_MAIN, &main_ids(4, &[fid]));
        buf.extend(pkt(
            set_id,
            TYPE_FILEDESC,
            &desc_body(fid, 0xAB, 4, "Bjork - Vesperti.mkv"),
        ));
        buf.extend(pkt(
            set_id,
            TYPE_UNIFILEN,
            &uni_body(fid, "Björk - Vespertine.mkv", true, false),
        ));
        let set = Par2Set::parse(&[&buf]).unwrap();
        assert_eq!(set.files[0].name, "Björk - Vespertine.mkv");
        // It renames and nothing else: the file id every reader keys
        // packets by, and the checksums the content tiers prove a
        // nomination with, are the FileDesc's own.
        assert_eq!(set.files[0].file_id, fid);
        assert_eq!(set.files[0].md5, [0xABu8; 16]);
        assert_eq!(set.files[0].length, 4);
    }

    /// A BOM is two bytes of unambiguous evidence, so it is honoured -
    /// and STRIPPED. Leaving it on is a real directory entry whose name
    /// starts with U+FEFF (the W4-13 defect, one file over).
    #[test]
    fn a_unicode_filename_packet_honours_and_strips_a_byte_order_mark() {
        for (le, label) in [(true, "LE"), (false, "BE")] {
            let set_id = [14u8; 16];
            let fid = [5u8; 16];
            let mut buf = pkt(set_id, TYPE_MAIN, &main_ids(4, &[fid]));
            buf.extend(pkt(
                set_id,
                TYPE_FILEDESC,
                &desc_body(fid, 1, 1, "ascii.mkv"),
            ));
            buf.extend(pkt(
                set_id,
                TYPE_UNIFILEN,
                &uni_body(fid, "Ünïcøde.mkv", le, true),
            ));
            let set = Par2Set::parse(&[&buf]).unwrap();
            assert_eq!(set.files[0].name, "Ünïcøde.mkv", "{label} BOM");
        }
    }

    /// Nothing is guessed and nothing is half-taken: a body that does not
    /// decode, is empty, or carries an interior NUL is REFUSED and the
    /// FileDesc's name stands. A wrong name that looks landed is the one
    /// outcome neither answer may produce.
    ///
    /// EVERY BODY HERE IS 4-ALIGNED, and that is not cosmetic. Both arms
    /// of `scan_packets` refuse a packet whose declared length is not a
    /// multiple of 4, so a body that is not one never reaches
    /// `parse_unifilen` at all and a case built from one asserts the
    /// SCANNER's rule while reporting this function's. Two of these cases
    /// were written that way first and one of them then survived a
    /// mutation that deleted the guard it was supposed to be about.
    #[test]
    fn an_undecodable_unicode_filename_packet_leaves_the_filedesc_name() {
        let set_id = [15u8; 16];
        let fid = [6u8; 16];
        let base = |extra: &[u8]| {
            let mut b = fid.to_vec();
            b.extend_from_slice(extra);
            assert!(
                (b.len() + HEADER_LEN as usize).is_multiple_of(4),
                "fixture body must survive the packet scanner"
            );
            b
        };
        let bodies: Vec<(&str, Vec<u8>)> = vec![
            // Unpaired high surrogate.
            ("unpaired surrogate", base(&[0x00, 0xD8, b'a', 0])),
            // File id only.
            ("empty", fid.to_vec()),
            // NUL between two characters - a truncation for any consumer
            // that treats the name as a C string. Padded to 4 so it is
            // this function refusing it and not the scanner.
            ("interior NUL", base(&[b'a', 0, 0, 0, b'b', 0, 0, 0])),
        ];
        for (label, body) in bodies {
            let mut buf = pkt(set_id, TYPE_MAIN, &main_ids(4, &[fid]));
            buf.extend(pkt(
                set_id,
                TYPE_FILEDESC,
                &desc_body(fid, 1, 1, "kept.mkv"),
            ));
            buf.extend(pkt(set_id, TYPE_UNIFILEN, &body));
            let set = Par2Set::parse(&[&buf]).unwrap();
            assert_eq!(set.files[0].name, "kept.mkv", "{label}");
        }
    }

    /// A name region that is not a whole number of code units is refused,
    /// asserted at the FUNCTION because it is unreachable through
    /// `Par2Set::parse`: the packet scanner's 4-alignment rule means a
    /// body reaching this is always a multiple of 4 bytes, so its name
    /// region is always even. The guard stays because `parse_unifilen` is
    /// a crate-visible parser with its own contract, and dropping the
    /// last byte in silence is the half-take this whole family refuses -
    /// but a pin that pretends the scanner would deliver one is a pin
    /// about the scanner.
    #[test]
    fn a_unicode_filename_body_of_half_a_code_unit_is_refused() {
        let fid = [6u8; 16];
        let mut body = fid.to_vec();
        body.extend_from_slice(&[b'a', 0, b'b']);
        assert!(parse_unifilen(&body).is_none());
        // The same bytes one longer DO decode, so the case is about the
        // odd byte and not about the content.
        body.push(0);
        assert_eq!(parse_unifilen(&body).unwrap().1, "ab");
    }

    /// The two name packets answer an interior NUL DIFFERENTLY, on
    /// purpose: `parse_unifilen` refuses the name outright (M4-22) and
    /// `parse_filedesc` keeps the byte and hands it downstream.
    ///
    /// A PIN, not a defect, and the reason is at [`parse_filedesc`]:
    /// refusing costs the OPTIONAL packet nothing (the FileDesc name
    /// stands) and costs the REQUIRED one the whole descriptor - the
    /// length and both MD5s with it - so the same strictness is right
    /// at one and wrong at the other. Recorded 31 Aug 2026 because
    /// "two readers of the same concept disagree" is the shape that
    /// gets tidied into agreement by somebody who has not priced both
    /// sides.
    ///
    /// The interior byte is safe because the FILESYSTEM boundary maps
    /// it, not the parser: `sanitize_filename_for` turns every
    /// `char::is_control` into `_`, asserted here beside the parsers so
    /// the two halves of the answer are read together, and end-to-end
    /// by `hostile_filedesc_name_forms_land_contained_and_sanitized`.
    #[test]
    fn the_two_name_packets_answer_an_interior_nul_differently() {
        let fid = [9u8; 16];

        // The optional packet REFUSES. `foo\0bar` in UTF-16LE, padded to
        // a whole number of 4-byte units the way a real packet is.
        let mut uni = fid.to_vec();
        for c in "foo\0bar".chars() {
            uni.extend_from_slice(&(c as u16).to_le_bytes());
        }
        uni.extend_from_slice(&[0, 0]);
        assert!(
            parse_unifilen(&uni).is_none(),
            "M4-22: an interior NUL is refused, and the FileDesc name stands"
        );
        // Same bytes without the interior NUL DO decode, so the case is
        // about that byte and not about the encoding or the padding.
        let mut ok = fid.to_vec();
        for c in "foobar".chars() {
            ok.extend_from_slice(&(c as u16).to_le_bytes());
        }
        assert_eq!(parse_unifilen(&ok).unwrap().1, "foobar");

        // The required packet KEEPS it - 16 id + 16 md5 + 16 md5_16k +
        // 8 length, then the name null-padded to a multiple of 4.
        let mut desc = vec![9u8; 16];
        desc.extend_from_slice(&[1u8; 16]);
        desc.extend_from_slice(&[2u8; 16]);
        desc.extend_from_slice(&99u64.to_le_bytes());
        desc.extend_from_slice(b"foo\0bar.mkv");
        let (_, d) = parse_filedesc(&desc).expect("a descriptor is never dropped over its name");
        assert_eq!(d.name, "foo\0bar.mkv");
        assert_eq!(d.length, 99, "the fields a refusal would have cost");

        // And the byte never reaches a directory entry.
        for windows in [false, true] {
            assert_eq!(
                crate::disk::sanitize_filename_for(&d.name, windows),
                "foo_bar.mkv"
            );
        }

        // Only the spec's own TRAILING padding is trimmed, which is what
        // makes the two cases distinguishable at all.
        let mut padded = desc[..48 + 8].to_vec();
        padded.extend_from_slice(b"tail.mkv\0\0\0\0");
        assert_eq!(parse_filedesc(&padded).unwrap().1.name, "tail.mkv");
    }

    /// The two rows compose: a verify-only member's name can itself come
    /// from a Unicode Filename packet.
    #[test]
    fn a_unicode_name_reaches_a_nonrecovery_member_too() {
        let set_id = [16u8; 16];
        let rec = [7u8; 16];
        let non = [8u8; 16];
        let mut buf = pkt(set_id, TYPE_MAIN, &main_ids_nonrec(4, &[rec], &[non]));
        buf.extend(pkt(set_id, TYPE_FILEDESC, &desc_body(rec, 1, 1, "a.bin")));
        buf.extend(pkt(
            set_id,
            TYPE_FILEDESC,
            &desc_body(non, 2, 1, "Notes.nfo"),
        ));
        buf.extend(pkt(
            set_id,
            TYPE_UNIFILEN,
            &uni_body(non, "Notés.nfo", true, false),
        ));
        let set = Par2Set::parse(&[&buf]).unwrap();
        assert_eq!(set.files[0].name, "a.bin");
        assert_eq!(set.nonrecovery[0].name, "Notés.nfo");
    }
    fn main_of(bs: u64, fids: &[[u8; 16]]) -> Vec<u8> {
        let mut b = bs.to_le_bytes().to_vec();
        b.extend_from_slice(&(fids.len() as u32).to_le_bytes());
        for f in fids {
            b.extend_from_slice(f);
        }
        b
    }

    /// M4-37. A four-block file whose IFSC lists FIVE entries is fully
    /// described by the first four: the surplus entry describes a block
    /// the file does not have. Dropping the whole packet over it costs
    /// every block's evidence, so one flipped byte prices the file
    /// WHOLLY missing and a repair that needed one recovery block needs
    /// four.
    #[test]
    fn a_long_ifsc_keeps_the_blocks_the_file_actually_has() {
        const BS: usize = 4096;
        let data: Vec<u8> = (0..4u32 * BS as u32).map(|i| (i % 251) as u8).collect();
        let fid = honest_fid("data.bin", &data);
        let set_id = [7u8; 16];

        let mut buf = pkt(set_id, TYPE_MAIN, &main_of(BS as u64, &[fid]));
        buf.extend(pkt(set_id, TYPE_FILEDESC, &desc_of(fid, "data.bin", &data)));
        buf.extend(pkt(set_id, TYPE_IFSC, &ifsc_body(fid, &data, BS, 5)));

        let set = Par2Set::parse(&[&buf]).unwrap();
        let f = &set.files[0];
        assert_eq!(f.blocks.len(), 4, "the grid must cover the file exactly");
        let v = verify_file(f, BS as u64, &data);
        assert!(
            v.blocks.iter().all(|&ok| ok),
            "the four kept checks must be the file's own"
        );

        // One flipped byte in block 2 is ONE bad block, not four.
        let mut hurt = data.clone();
        hurt[2 * BS + 9] ^= 0xff;
        let v = verify_file(f, BS as u64, &hurt);
        assert_eq!(v.blocks.iter().filter(|ok| !**ok).count(), 1);
    }

    /// M4-37, the other half. A THREE-entry IFSC does not describe block
    /// 3, and that block must never read as proven - the hazard
    /// `short_ifsc_is_dropped_not_trusted` was written for. But the three
    /// entries it does carry are the file's own, and throwing them away
    /// is what makes a one-block flip cost four recovery blocks.
    #[test]
    fn a_short_ifsc_keeps_its_prefix_and_proves_nothing_past_it() {
        const BS: usize = 4096;
        let data: Vec<u8> = (0..4u32 * BS as u32).map(|i| (i % 241) as u8).collect();
        let fid = honest_fid("data.bin", &data);
        let set_id = [7u8; 16];

        let mut buf = pkt(set_id, TYPE_MAIN, &main_of(BS as u64, &[fid]));
        buf.extend(pkt(set_id, TYPE_FILEDESC, &desc_of(fid, "data.bin", &data)));
        buf.extend(pkt(set_id, TYPE_IFSC, &ifsc_body(fid, &data, BS, 3)));

        let set = Par2Set::parse(&[&buf]).unwrap();
        let f = &set.files[0];
        assert_eq!(f.blocks.len(), 4, "the grid still spans the whole file");
        assert!(
            f.blocks[..3].iter().all(|b| b.is_proven()),
            "the three entries the packet carried are evidence"
        );
        assert!(
            !f.blocks[3].is_proven(),
            "block 3 has no check and must not be provable"
        );

        // Over the file's OWN bytes the WHOLE-FILE MD5 settles it, block
        // 3 included: that digest covers every byte of every block, so a
        // file that hashes to the descriptor has a proven tail whatever
        // the block grid can express about it (M4-69). This assertion
        // read `[true, true, true, false]` for the hours between the two
        // lanes landing, on the reasoning that an unproven entry must
        // never vouch for an unposted tail - which is right about the
        // ENTRY and was being asked of the wrong evidence. It is also
        // what `par2repair`'s verify pass has always answered
        // (`Pass1Out::clean`), so the three halves now read one set one
        // way.
        let v = verify_file(f, BS as u64, &data);
        assert!(v.md5_ok, "the whole-file MD5 still covers every byte");
        assert_eq!(v.blocks, vec![true, true, true, true]);

        // AND THIS IS WHERE THE SHORT LIST IS HELD, which is why nothing
        // was lost above: with the whole-file MD5 FAILING there is no
        // evidence but the grid, and the unproven block stays false - a
        // flip inside the covered prefix is found by the prefix, and the
        // uncovered tail is still not vouched for by anything.
        let mut hurt = data.clone();
        hurt[BS + 5] ^= 0xff;
        let v = verify_file(f, BS as u64, &hurt);
        assert!(!v.md5_ok);
        assert_eq!(v.blocks, vec![true, false, true, false]);
    }

    /// M4-37's bound, and it is a bound on PADDING alone. `want` comes
    /// off the wire (a declared length over a declared block size), so
    /// filling a grid out to it must not let a 100-byte packet ask for a
    /// terabyte of cells; past the ceiling such a packet is dropped
    /// exactly as before. A packet that CARRIES its cells is bounded by
    /// the input and keeps them however many there are - which
    /// `a_four_byte_block_size_is_bounded_by_the_ifsc_it_must_carry`
    /// pins from the other side, at 262144.
    #[test]
    fn a_wire_block_count_past_the_slice_limit_is_not_padded_to() {
        const BS: u64 = 4;
        let fid = [3u8; 16];
        let set_id = [7u8; 16];
        // 4 bytes per block, so this declares 2^40 blocks.
        let mut desc = fid.to_vec();
        desc.extend_from_slice(&[1u8; 16]);
        desc.extend_from_slice(&[2u8; 16]);
        desc.extend_from_slice(&(4u64 << 40).to_le_bytes());
        desc.extend_from_slice(b"huge.bin");
        let mut ifsc = fid.to_vec();
        ifsc.extend_from_slice(&[0u8; 20]);

        let mut buf = pkt(set_id, TYPE_MAIN, &main_of(BS, &[fid]));
        buf.extend(pkt(set_id, TYPE_FILEDESC, &desc));
        buf.extend(pkt(set_id, TYPE_IFSC, &ifsc));
        let set = Par2Set::parse(&[&buf]).unwrap();
        assert!(
            set.files[0].blocks.is_empty(),
            "an unbounded grid falls back to the whole-file MD5"
        );
    }

    /// M4-37's sharpest edge, and the one a placeholder made of zeros
    /// invites: the guard on an [`BlockCheck::UNPROVEN`] slice is its
    /// all-zero MD5, and the CRC-ONLY tiers never reach an MD5. Fast
    /// verify claims a block on its CRC32 alone, and so do the
    /// repairer's self-prove and pass-1 scans. Every u32 is somebody's
    /// CRC32 and four appended bytes choose which, so a comparison
    /// against the placeholder's zero FIELD is one a crafted block walks
    /// straight past - `[157, 10, 217, 109]` is four bytes that hash to
    /// exactly it. [`BlockCheck::crc_matches`] is what refuses it, and
    /// every CRC-only site goes through that rather than the field.
    #[test]
    fn a_crafted_zero_crc_does_not_verify_an_unproven_slice() {
        const ZERO_CRC: [u8; 4] = [157, 10, 217, 109];
        assert_eq!(crc32fast::hash(&ZERO_CRC), 0, "the fixture is the point");
        assert_eq!(
            BlockCheck::UNPROVEN.crc32,
            0,
            "so a bare field comparison would have said yes"
        );
        assert!(!BlockCheck::UNPROVEN.crc_matches(0));
        assert!(!crate::live::check_block_crc(
            &BlockCheck::UNPROVEN,
            ZERO_CRC.len(),
            &ZERO_CRC
        ));
        // A real check with the same CRC value still answers for it -
        // the guard is the MD5 field, not the number.
        let real = BlockCheck {
            md5: [3u8; 16],
            crc32: 0,
        };
        assert!(real.crc_matches(0));
        assert!(!real.crc_matches(1));
        assert!(crate::live::check_block_crc(
            &real,
            ZERO_CRC.len(),
            &ZERO_CRC
        ));
    }

    /// M4-38. A file id is not an opaque label: the spec fixes it as the
    /// MD5 of the descriptor's own hash16k, length and name, so a
    /// descriptor either binds its own id or it does not. A packet that
    /// COPIED another file's id must not out-race the real descriptor for
    /// that id and hand its IFSC and Main slot to the wrong name and
    /// MD5s.
    #[test]
    fn a_forged_file_id_never_beats_the_descriptor_that_binds_it() {
        const BS: usize = 4096;
        let real: Vec<u8> = (0..2u32 * BS as u32).map(|i| (i % 253) as u8).collect();
        let fid = honest_fid("real.bin", &real);
        let set_id = [7u8; 16];

        // The forgery: a different name, length and MD5s, wearing
        // `real.bin`'s id.
        let evil = vec![0xABu8; 64];
        let forged = desc_of(fid, "evil.bin", &evil);
        let honest = desc_of(fid, "real.bin", &real);

        for forged_first in [false, true] {
            let mut buf = pkt(set_id, TYPE_MAIN, &main_of(BS as u64, &[fid]));
            let (a, b) = if forged_first {
                (&forged, &honest)
            } else {
                (&honest, &forged)
            };
            buf.extend(pkt(set_id, TYPE_FILEDESC, a));
            buf.extend(pkt(set_id, TYPE_FILEDESC, b));
            buf.extend(pkt(set_id, TYPE_IFSC, &ifsc_body(fid, &real, BS, 2)));

            let set = Par2Set::parse(&[&buf]).unwrap();
            assert_eq!(set.files.len(), 1);
            assert_eq!(
                set.files[0].name, "real.bin",
                "forged_first={forged_first}: arrival order must not pick the name"
            );
            assert_eq!(set.files[0].length, real.len() as u64);
            assert_eq!(set.files[0].md5, <[u8; 16]>::from(Md5::digest(&real)));
        }
    }

    /// M4-38 must not become a refusal. Every FileDesc packet in this
    /// repository's fixtures binds its own id (18 of 18, measured 30 Aug
    /// 2026), but nothing in the format makes a producer's id
    /// verifiable by any other tool - par2cmdline never recomputes it -
    /// so a set whose ids simply follow a different rule still has to
    /// parse. An unbound id is only ever OUT-RANKED, never dropped.
    #[test]
    fn an_unbound_file_id_still_describes_its_file() {
        const BS: usize = 4096;
        let data: Vec<u8> = (0..2u32 * BS as u32).map(|i| (i % 239) as u8).collect();
        let fid = [0x5Au8; 16]; // binds nothing
        let set_id = [7u8; 16];

        let mut buf = pkt(set_id, TYPE_MAIN, &main_of(BS as u64, &[fid]));
        buf.extend(pkt(set_id, TYPE_FILEDESC, &desc_of(fid, "odd.bin", &data)));
        buf.extend(pkt(set_id, TYPE_IFSC, &ifsc_body(fid, &data, BS, 2)));

        let set = Par2Set::parse(&[&buf]).unwrap();
        assert_eq!(set.files.len(), 1, "an unbound id is not a refusal");
        assert_eq!(set.files[0].name, "odd.bin");
        assert_eq!(set.files[0].blocks.len(), 2);
    }

    // -- NZBFAST_VERIFY_IFSC_ONLY: the experimental verdict tier --------
    //
    // The knob is default off and changes what "verified" MEANS, so the
    // whole of its licence to exist is this differential: for every set
    // and every damage shape below, the two tiers must reach the SAME
    // FileVerify - except on the one spec-legal shape that is proved
    // undetectable here and pinned by name.

    /// Scratch path for a fixture, unique per process and call so the
    /// suite stays safe under nextest's process-per-test and under
    /// `cargo test`'s one process for the whole crate.
    fn scratch_path(tag: &str) -> std::path::PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "nzbkit-par2-ifsc-only-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        ))
    }

    /// Run one fixture through BOTH verdict tiers and require the same
    /// answer in all three fields. Returns that answer.
    fn assert_tiers_agree(
        file: &Par2File,
        block_size: u64,
        bytes: &[u8],
        case: &str,
    ) -> FileVerify {
        let path = scratch_path("agree");
        std::fs::write(&path, bytes).expect("write IFSC-only fixture");
        // Both thread hints, because the tier declines into
        // `verify_blocks_path_or_streaming`, whose serial and positioned
        // halves are chosen by exactly this number.
        let mut answer = None;
        for threads in [1usize, 8] {
            let off = verify_file_path_tiered(&path, file, block_size, threads, false)
                .expect("a regular fixture file cannot fail to read");
            let on = verify_file_path_tiered(&path, file, block_size, threads, true)
                .expect("a regular fixture file cannot fail to read");
            assert_eq!(off.blocks, on.blocks, "{case} (threads {threads}): blocks");
            assert_eq!(off.md5_ok, on.md5_ok, "{case} (threads {threads}): md5_ok");
            assert_eq!(
                off.md5_16k_ok, on.md5_16k_ok,
                "{case} (threads {threads}): md5_16k_ok"
            );
            answer = Some(off);
        }
        let _ = std::fs::remove_file(path);
        answer.expect("both thread hints ran")
    }

    /// Deterministic xorshift, so a failure is reproducible from the
    /// case index alone and the suite never depends on the clock.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    /// THE DIFFERENTIAL. Random honest sets, random damage, both tiers.
    ///
    /// The lengths straddle `VERIFY_PAR_MIN_BYTES` (64 KiB in a test
    /// build) so the positioned pool, the pipelined one-pass reader and
    /// the serial streamer all answer somewhere in the sweep, and the
    /// block sizes are deliberately not divisors of the lengths so the
    /// zero-padded final slice is exercised on nearly every case.
    #[test]
    fn the_ifsc_only_tier_matches_the_default_tier_over_random_damage() {
        let mut rng = Rng(0x9E3779B97F4A7C15);
        for case in 0..96u32 {
            let bs = [1024usize, 4096, 16 << 10, 64 << 10][rng.below(4)];
            let len = bs * (1 + rng.below(24)) + rng.below(bs.min(4096) + 1);
            let mut data: Vec<u8> = (0..len)
                .map(|i| (i as u8) ^ ((i >> 8) as u8).wrapping_mul(37) ^ case as u8)
                .collect();
            let file = synth_file(&data, bs);
            match rng.below(6) {
                // Clean: the case the knob exists for.
                0 | 1 => {}
                // One flipped bit, somewhere.
                2 => {
                    let at = rng.below(len);
                    data[at] ^= 1 << rng.below(8);
                }
                // A whole slice replaced, so a lane's range is all bad.
                3 => {
                    let block = rng.below(len.div_ceil(bs));
                    let start = block * bs;
                    let end = (start + bs).min(len);
                    for (k, byte) in data[start..end].iter_mut().enumerate() {
                        *byte = (k as u8).wrapping_mul(97).wrapping_add(11);
                    }
                }
                // Short on disk: the size-mismatch shortcut.
                4 => {
                    let keep = rng.below(len);
                    data.truncate(keep);
                }
                // Long on disk: also a size mismatch, other side.
                _ => {
                    let extra = 1 + rng.below(bs * 2);
                    data.extend((0..extra).map(|i| (i as u8).wrapping_mul(31)));
                }
            }
            assert_tiers_agree(&file, bs as u64, &data, &format!("case {case}"));
        }
    }

    /// The shapes the tier must DECLINE, each for its own reason, and on
    /// which it therefore answers exactly as the default tier does.
    #[test]
    fn the_ifsc_only_tier_declines_every_grid_that_does_not_cover_the_file() {
        const BS: usize = 4096;
        let len = (128 << 10) + 517;
        let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(53)).collect();

        // A zero-length member: "every block proved" is vacuously true
        // over no bytes at all, which is the one claim this must never
        // make. Its grid is empty, so the tier declines on the length.
        let empty = synth_file(&[], BS);
        assert_eq!(empty.blocks.len(), 0);
        let got = assert_tiers_agree(&empty, BS as u64, &[], "zero-length member");
        assert!(got.md5_ok, "an empty member still verifies the old way");

        // A short IFSC fitted out with UNPROVEN cells: the suffix covers
        // nothing, so only the whole-file digest can settle those bytes.
        let mut short = synth_file(&data, BS);
        short.blocks[3..].fill(BlockCheck::UNPROVEN);
        let got = assert_tiers_agree(&short, BS as u64, &data, "short IFSC, clean payload");
        assert!(got.md5_ok, "the whole-file digest still settles it");

        // An INTERIOR unproven cell, which no truncation produces and
        // only a crafted set carries. Same rule, reached from the middle.
        let mut interior = synth_file(&data, BS);
        interior.blocks[5] = BlockCheck::UNPROVEN;
        let got = assert_tiers_agree(&interior, BS as u64, &data, "interior UNPROVEN cell");
        assert!(got.md5_ok);

        // No IFSC at all (`fit_ifsc` refuses to pad this far, or the set
        // simply carries none).
        let mut none = synth_file(&data, BS);
        none.blocks.clear();
        assert_tiers_agree(&none, BS as u64, &data, "no IFSC");

        // A grid whose length disagrees with the declared size. Nothing
        // well-formed reaches this, and the tier must not read a
        // truncated grid as covering the tail.
        let mut trimmed = synth_file(&data, BS);
        trimmed.blocks.truncate(trimmed.blocks.len() - 1);
        assert_tiers_agree(&trimmed, BS as u64, &data, "grid shorter than the file");
    }

    /// H7's MIRROR: the bytes on disk carry the FileDesc whole-file MD5
    /// and the IFSC beside it describes a DIFFERENT payload. The default
    /// tier calls that clean, because the FileDesc digest arbitrates
    /// (`verify_file`'s contract). The IFSC-only tier sees failing
    /// blocks - and MUST decline rather than report damage, which is why
    /// `ifsc_only_attempt` returns `Some` for a clean verdict only.
    #[test]
    fn the_ifsc_only_tier_declines_when_the_ifsc_denies_bytes_the_filedesc_proves() {
        const BS: usize = 4096;
        let len = (128 << 10) + 91;
        let real: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(101)).collect();
        let other: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(103)).collect();
        let desc = synth_file(&real, BS);
        let ifsc = synth_file(&other, BS);
        let meta = Par2File {
            blocks: ifsc.blocks,
            ..desc
        };
        let got = assert_tiers_agree(&meta, BS as u64, &real, "H7 mirror");
        assert!(got.md5_ok, "the FileDesc digest still arbitrates");
        assert!(
            got.blocks.iter().all(|&ok| ok),
            "and settles every block it covers"
        );
    }

    /// THE ONE SHAPE THE TWO TIERS DISAGREE ON, pinned honestly.
    ///
    /// Nothing in PAR2 binds an IFSC packet to the FileDesc beside it -
    /// the file id hashes hash16k, length and name, never the whole-file
    /// MD5 - so a spec-legal set can pair file A's descriptor with file
    /// B's IFSC. With bytes B on disk, every block proves and the
    /// FileDesc digest fails. This is H7 (08-08 sweep), and it is
    /// UNDETECTABLE by a tier that does not compute the whole-file
    /// digest, so there is no fallback to write: the honest thing is to
    /// pin the divergence and put the policy question to a human.
    ///
    /// Both halves matter. The 16 KiB head check refuses the pairing a
    /// random or accidental set produces, so the tiers still agree
    /// there; a pairing built with a SHARED first 16 KiB - which is what
    /// a well-formed set needs anyway, since both packets must carry the
    /// same file id - walks past it, and that is the divergence.
    #[test]
    fn the_ifsc_only_tier_diverges_only_on_the_h7_shape() {
        const BS: usize = 4096;
        let len = (128 << 10) + 33;
        assert!(len > HASH16K_LEN, "the head check must be reachable");

        // (a) The naive pairing: the two payloads differ from byte 0, so
        // hash16k separates them and the tier declines.
        let a: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(11)).collect();
        let b: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(13)).collect();
        let naive = Par2File {
            blocks: synth_file(&b, BS).blocks,
            ..synth_file(&a, BS)
        };
        let got = assert_tiers_agree(&naive, BS as u64, &b, "H7 with differing heads");
        assert!(!got.md5_ok, "the FileDesc digest denies these bytes");

        // (b) The pairing a real set would have to use: A and B share a
        // name, a length AND a first 16 KiB, so both packets compute the
        // same file id and the head check cannot separate them.
        let mut c = a.clone();
        for (i, byte) in c[HASH16K_LEN..].iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(17).wrapping_add(5);
        }
        assert_eq!(a[..HASH16K_LEN], c[..HASH16K_LEN]);
        assert_ne!(a, c);
        let crafted = Par2File {
            blocks: synth_file(&c, BS).blocks,
            ..synth_file(&a, BS)
        };

        let path = scratch_path("h7");
        std::fs::write(&path, &c).expect("write H7 fixture");
        let off = verify_file_path_tiered(&path, &crafted, BS as u64, 8, false).unwrap();
        let on = verify_file_path_tiered(&path, &crafted, BS as u64, 8, true).unwrap();
        let _ = std::fs::remove_file(path);

        assert!(
            !off.md5_ok,
            "knob off: the FileDesc whole-file MD5 is the verdict, and it fails"
        );
        assert!(
            off.blocks.iter().all(|&ok| ok),
            "knob off: every IFSC block still matches - that is the contradiction"
        );
        assert!(
            on.md5_ok,
            "knob on: the IFSC is the verdict, and it passes - THE divergence, \
             and the whole of the policy question"
        );
        assert!(on.md5_16k_ok, "both packets agree about the head");
    }

    // -- The ONE value: which surface wins ------------------------------
    //
    // `nzbfast verify --fast`, the daemon's `fast_final_check` setting
    // and NZBFAST_VERIFY_IFSC_ONLY all resolve HERE, and section 21 of
    // research/PAR2-PERF-AUDIT-2026-09-02.md makes that load-bearing:
    // letting the CLI and the daemon answer under different rules is
    // worse than either rule alone. These tests are the pin.
    //
    // They share one process-global, so they are ONE test: two of them
    // would race under `cargo test`'s single process for the crate, and
    // the trap is documented in CLAUDE.md's build section.

    #[test]
    fn the_fast_check_surfaces_resolve_to_one_value() {
        // The global starts unset, so the answer is the environment's -
        // and the suite runs with the variable unset, so it is off. This
        // is also the KEEP RULE: with nothing set, behaviour is today's.
        clear_fast_check();
        assert!(
            !fast_check_enabled(),
            "default off: no surface has spoken and the variable is unset"
        );

        // An explicit choice from any surface beats that default, in
        // BOTH directions - a surface saying off has to be told apart
        // from a surface saying nothing, or a setting could never turn
        // off what the environment turned on.
        set_fast_check(true);
        assert!(fast_check_enabled(), "an explicit yes is honoured");
        set_fast_check(false);
        assert!(
            !fast_check_enabled(),
            "an explicit no is honoured, and is NOT the same state as unset"
        );

        // Last writer wins, which is what makes the precedence work at
        // the call sites: the daemon restores the saved setting at
        // startup and `apply_setting` overwrites it live, and the CLI
        // writes its flag once before anything reads it.
        set_fast_check(true);
        assert!(
            fast_check_enabled(),
            "a later choice replaces an earlier one"
        );

        // Leave the process as this test found it. Every other test in
        // this crate resolves through the same global.
        clear_fast_check();
        assert!(!fast_check_enabled(), "restored to the default");
    }
}
