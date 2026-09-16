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
/// The optional ASCII Text ("comment") packet (PAR2 spec 2.0): the
/// comment text, NUL-padded to a multiple of four. MultiPar, QuickPar
/// and MacPAR all write and show one; par2cmdline implements neither
/// comment packet at all, which is why no conformance row can see them.
pub(crate) const TYPE_COMMASCI: &[u8; 16] = b"PAR 2.0\0CommASCI";
/// The optional Unicode Text ("comment") packet: 16 bytes of MD5
/// cross-reference to the ASCII packet (zeros where there is none),
/// then the comment as UTF-16. See [`parse_comm_uni`] for why the
/// cross-reference is read past rather than checked.
pub(crate) const TYPE_COMMUNI: &[u8; 16] = b"PAR 2.0\0CommUni\0";

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
    BlockCheck, VERIFY_MAX_WORKERS, clear_fast_check, fast_check_enabled, lane_plan,
    set_fast_check, verify_file, verify_file_blocks, verify_file_md5_path,
    verify_file_md5_streaming, verify_file_path, verify_file_path_tiered, verify_file_seekable,
    verify_file_streaming,
};
pub(crate) use verify::{ifsc_covers_every_block, verify_blocks_path_or_streaming, verify_head};

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
    /// The set's comment, from either optional text packet, or `None`
    /// where the producer wrote neither - which is every set
    /// par2cmdline has ever written, and every set this engine wrote
    /// before 12 Sep 2026.
    ///
    /// It is a STRING FOR A HUMAN and nothing else: it names no file,
    /// keys no packet and takes no part in verify, repair or adoption.
    /// The comment a poster wrote is the only field of a PAR2 set whose
    /// content an attacker chooses freely and which lands in front of a
    /// reader unaltered, so what may be in it is fixed at the parser
    /// (`par2::packet::clean_comment`) rather than at each of the
    /// surfaces that show it.
    ///
    /// Contradiction annihilates, as everywhere else in this parse: two
    /// text packets of one set carrying DIFFERENT comments leave this
    /// `None`, which is the same answer in every packet order (W4-10).
    /// The Unicode packet's spelling wins over the ASCII one where both
    /// settled, for [`Par2File::name`]'s reason - the producer wrote the
    /// ASCII one for readers that understand nothing else.
    pub comment: Option<String>,
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

/// The deferred recovery spans of ONE input ([`Par2Set::parse_deferred`])
/// verified over `input` (the same bytes, or a fresh read of the same
/// file): the exponents of the packets that check, that belong to
/// `set_id`, and whose slice is at least `block_size` long - the same
/// three tests [`Par2Set::recovery_blocks_seen`] applies - keyed by
/// exponent with the longest slice kept, exactly as the parser keeps
/// them. Distinct exponents across every input, merged by the caller,
/// are the set's recovery block count. Hashed in parallel.
pub fn validate_recovery_spans(
    input: &[u8],
    spans: &[(usize, usize)],
    set_id: &[u8; 16],
    block_size: u64,
) -> HashMap<u32, usize> {
    validate_recovery_spans_in(input, spans, set_id, block_size)
}

/// The recovery packets of ONE file at `spans` (FILE offsets and
/// lengths from a [`sparse_frame`] walk) whose MD5 checks out, each as
/// the same [`PacketInfo`] a whole-file [`packet_census`] would have
/// produced, in span order. A span that cannot be read, or whose bytes
/// do not hash to the MD5 in its own header, contributes nothing - the
/// same silence [`packet_census`] keeps about a packet it rejects.
///
/// EACH SPAN IS READ ON ITS OWN, with one positioned read into a
/// buffer the worker reuses for every packet after it, so the file is
/// never resident. It used to be `std::fs::read` of the whole volume,
/// which put the WHOLE recovery set in memory a volume at a time: 2.30
/// GB of peak RSS on a 2 GiB set with 100% parity at 64 KiB blocks
/// (four 512 MiB members, seventeen volumes, the largest 1.08 GB),
/// measured on an M3 Ultra 10 Sep 2026, against 0.10 GB with this walk.
/// The MD5 still runs over every byte and the reads still cover the
/// same bytes; what goes is holding them.
///
/// Peak here is `cpu_workers` buffers of the largest packet - one
/// block plus a header - and the spans are handed out in file order,
/// so the reads march forward through the file rather than seeking
/// about it.
pub fn verify_recovery_file(path: &std::path::Path, spans: &[(u64, u64)]) -> Vec<PacketInfo> {
    // An index file carries no recovery packets and every load walks
    // one, so answering before the open is not a micro-optimisation:
    // it is the difference between a walk that touches the index and
    // one that opens it and spawns a worker to find nothing.
    if spans.is_empty() {
        return Vec::new();
    }
    let Ok(f) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let threads = crate::mem::cpu_workers().clamp(1, spans.len());
    let next = std::sync::atomic::AtomicUsize::new(0);
    let found = std::sync::Mutex::new(Vec::<(usize, PacketInfo)>::new());
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                // ONE buffer per worker, grown to the largest packet it
                // has met and never shrunk: every packet of a set is
                // the same size, so this allocates once.
                let mut buf: Vec<u8> = Vec::new();
                let mut mine: Vec<(usize, PacketInfo)> = Vec::new();
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if i >= spans.len() {
                        break;
                    }
                    let (off, len) = spans[i];
                    let Ok(len) = usize::try_from(len) else {
                        continue;
                    };
                    if len < HEADER_LEN as usize {
                        continue;
                    }
                    if buf.len() < len {
                        buf.resize(len, 0);
                    }
                    if crate::disk::read_exact_at(&f, &mut buf[..len], off).is_err() {
                        continue;
                    }
                    if let Some(pkt) = packet::verify_span(&buf, 0, len) {
                        mine.push((i, census_entry(&pkt)));
                    }
                }
                let mut g = found.lock().unwrap_or_else(|e| e.into_inner());
                g.extend(mine);
            });
        }
    });
    let mut out = found.into_inner().unwrap_or_else(|e| e.into_inner());
    out.sort_unstable_by_key(|(i, _)| *i);
    out.into_iter().map(|(_, p)| p).collect()
}

/// [`validate_recovery_spans`] over spans that are FILE offsets from a
/// [`sparse_frame`] walk: each span read and checked on its own
/// through [`verify_recovery_file`], which is what keeps the volume off
/// the heap, then judged by the same three tests the in-memory door
/// applies. A file that cannot be read, or that shrank under a span,
/// contributes nothing.
pub fn validate_recovery_file(
    path: &std::path::Path,
    spans: &[(u64, u64)],
    set_id: &[u8; 16],
    block_size: u64,
) -> HashMap<u32, usize> {
    let bs = usize::try_from(block_size).unwrap_or(usize::MAX);
    let mut out: HashMap<u32, usize> = HashMap::new();
    for p in verify_recovery_file(path, spans) {
        let Some(e) = p.recovery_exponent else {
            continue;
        };
        if p.set_id != *set_id {
            continue;
        }
        // `recovery_exponent` is `Some` only on a RecvSlic packet whose
        // body carries the four exponent bytes, so the slice is what
        // remains after them - `validate_recovery_spans_in`'s own rule.
        // Saturating anyway, so the arithmetic cannot depend on an
        // invariant held one function away.
        let data = p.body_len.saturating_sub(4);
        if slice_fits_block(data, bs) {
            let v = out.entry(e).or_insert(0);
            *v = (*v).max(data);
        }
    }
    out
}

fn validate_recovery_spans_in(
    input: &[u8],
    spans: &[(usize, usize)],
    set_id: &[u8; 16],
    block_size: u64,
) -> HashMap<u32, usize> {
    let bs = usize::try_from(block_size).unwrap_or(usize::MAX);
    let threads = crate::mem::cpu_workers().clamp(1, spans.len().max(1));
    let next = std::sync::atomic::AtomicUsize::new(0);
    let found = std::sync::Mutex::new(HashMap::<u32, usize>::new());
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                let mut mine: Vec<(u32, usize)> = Vec::new();
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if i >= spans.len() {
                        break;
                    }
                    let (start, end) = spans[i];
                    let Some(pkt) = packet::verify_span(input, start, end) else {
                        continue;
                    };
                    if pkt.set_id != *set_id || pkt.ptype != *TYPE_RECVSLIC || pkt.body.len() < 4 {
                        continue;
                    }
                    let e = u32::from_le_bytes(pkt.body[0..4].try_into().unwrap());
                    let data = pkt.body.len() - 4;
                    if slice_fits_block(data, bs) {
                        mine.push((e, data));
                    }
                }
                let mut f = found.lock().unwrap_or_else(|e| e.into_inner());
                for (e, data) in mine {
                    let v = f.entry(e).or_insert(0);
                    *v = (*v).max(data);
                }
            });
        }
    });
    found.into_inner().unwrap_or_else(|e| e.into_inner())
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
// `RawPacket` was deliberately NOT among them until 14 Sep 2026: every
// caller of `scan_packets` received one in a closure and read its
// fields, so no site named the type. The re-export was added the way
// this comment asked for it, when the catalog needed ONE per-packet
// function for both of its scan arms (the whole read and
// `scan_file_windowed`), rather than a path reaching through a private
// module.
mod packet;
use packet::packet_spans;
#[cfg(test)]
pub(crate) use packet::scan_file_windowed;
pub(crate) use packet::{
    MAX_BLOCK_SIZE, RawPacket, parse_comm_ascii, parse_comm_uni, parse_filedesc, parse_ifsc,
    parse_main, parse_unifilen, scan_file_windowed_in, scan_packets,
};
pub use packet::{SparseFrame, SparseRecovery, sparse_frame};

/// The spec's file id for a descriptor: the MD5 of its LAST three fields
/// - the first-16k hash, the 8-byte length, and the name without its null
/// padding. Confirmed against par2cmdline 1.3.0 output, and every one of
/// the 18 FileDesc packets in this repository's fixtures binds its own id
/// under this rule (measured 30 Aug 2026).
///
/// It hashes the DECODED name, which is what [`parse_filedesc`] keeps, so
/// a descriptor whose name bytes are not UTF-8 reads as unbound: the
/// lossy decode has already replaced them. That costs such a descriptor
/// nothing except a CONTESTED id, because [`DescClaim::offer_desc`]
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
///
/// Stated as the invariant it is, because one rule layered on top of it
/// has already broken it once: what a claim settles to is a function of
/// the SET of distinct readings offered, and of nothing else - not the
/// order they arrived in, not how often each repeated. [`Claim::offer`]
/// holds that by construction (one distinct reading settles, two or
/// more settle nothing, and the latch makes repeats free). A rule
/// layered on top holds it only if the rule is itself a function of
/// that set; [`DescClaim`] is the only such rule, and the shape of the
/// mistake is written up there.
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

/// A claim over one file id's FileDesc packets: [`Claim::offer`] with
/// M4-38's tiebreak, where a descriptor that BINDS `fid` outranks one
/// that merely carries a copy of it, so the two are not a contradiction
/// at all.
///
/// A file id is not an opaque label - [`filedesc_id`] fixes it from the
/// descriptor's own fields - so a packet whose id was COPIED from
/// another file cannot also bind it: the name, length or 16k hash it
/// forged differs, and MD5 is what stands between those two facts.
/// Without this, a forgery beside the real descriptor is an
/// equivocation, and W4-10 empties the claim: the honest file leaves
/// the set entirely, which is safe and is still a whole member lost to
/// a packet anyone can write.
///
/// It OUT-RANKS rather than refuses, deliberately. Nothing in the
/// format makes a producer's ids verifiable by any other tool -
/// par2cmdline never recomputes them - so a set that numbers its files
/// by some other rule is self-consistent and must still parse. An
/// unbound descriptor still describes its own file; it only loses a
/// CONTESTED id.
///
/// THE RULE, stated over the SET of descriptors offered, because that
/// is the only form in which it composes with W4-10. Partition them by
/// whether they bind `fid` - a property of the descriptor ALONE, so
/// which class one falls in never depends on what arrived before it.
/// Fold each class by W4-10 on its own. The binding class answers
/// wherever it was non-empty, EVEN WHERE IT ANNIHILATED; the unbound
/// class answers only where nothing bound the id at all. `bound_seen`
/// is the whole of the extra state that needs: it separates "no binder
/// yet" from "the binders annihilated", and once a binder is seen the
/// unbound class can never be consulted again, so the two folds share
/// one slot.
///
/// Two self-bound descriptors CAN share an id without an MD5 collision,
/// which is why the binding class gets a fold and not a first-past-the-
/// post: [`filedesc_id`] hashes the 16k hash, the length and the name,
/// and NOT the whole-file MD5, so two descriptors that agree on those
/// three and disagree about the file's MD5 both bind the id honestly -
/// both evidence, and so they annihilate like any other disagreeing
/// pair.
///
/// The pairwise form this replaces read the tiebreak against whichever
/// descriptor was held at the time, which is order-dependent the moment
/// THREE meet on one id: two mutually-disagreeing unbound forgeries
/// annihilated the claim between them, and the real binding descriptor
/// arriving after them was then refused by the contradiction latch it
/// should have out-ranked. A,B,C kept the member and B,C,A lost it -
/// the exact race W4-10 exists to remove (bug sweep 16 Sep 2026, item
/// 17; pinned by `three_descriptors_on_one_id_settle_the_same_in_every_order`).
#[derive(Default)]
struct DescClaim {
    inner: Claim<Desc>,
    /// Whether any descriptor offered so far binds `fid`. NOT derivable
    /// from `inner`: once the binding class has annihilated, `inner`
    /// reads exactly as an annihilated unbound class does, and the two
    /// must answer differently to a binder arriving next.
    bound_seen: bool,
}

impl DescClaim {
    fn offer_desc(&mut self, fid: [u8; 16], v: Desc) {
        if filedesc_id(&v) == fid {
            if !self.bound_seen {
                // The first binder out-ranks the whole unbound class,
                // including one that has already annihilated: those
                // readings were never evidence about THIS id, so they
                // are discarded rather than weighed against it.
                self.bound_seen = true;
                self.inner = Claim {
                    value: Some(v),
                    contradicted: false,
                };
                return;
            }
            // A later binder is evidence, and meets the one held under
            // W4-10 below.
        } else if self.bound_seen {
            // Out-ranked, whatever the binding class settled to.
            return;
        }
        self.inner.offer(v);
    }

    fn into_settled(self) -> Option<Desc> {
        self.inner.into_settled()
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
    descs: HashMap<[u8; 16], DescClaim>,
    ifscs: HashMap<[u8; 16], Claim<Vec<BlockCheck>>>,
    /// file id -> the optional Unicode Filename packet's spelling of the
    /// name (M4-22). A `Claim` like everything else here: two that
    /// disagree annihilate and the FileDesc's own spelling stands, which
    /// is the same answer in every packet order.
    unis: HashMap<[u8; 16], Claim<String>>,
    /// The optional ASCII and Unicode Text ("comment") packets, claimed
    /// APART so that a set carrying both does not read as a
    /// contradiction the moment their spellings differ in any byte -
    /// which is the normal case, since a producer writes the ASCII one
    /// precisely because the Unicode one says something it cannot. Two
    /// packets of the SAME type disagreeing is a real contradiction and
    /// annihilates inside its own claim (W4-10).
    comm_ascii: Claim<String>,
    comm_uni: Claim<String>,
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

    /// [`Par2Set::parse_censused`] with the recovery packets DEFERRED:
    /// they are framed, censused (an unverified entry each, so a file's
    /// packet count and set membership read as they would) and their
    /// `(start, end)` spans returned per input, but their MD5s are not
    /// computed and they contribute NOTHING to `recovery_blocks_seen`,
    /// which is 0 for a set parsed this way. The caller settles the count
    /// later with [`validate_recovery_spans`] over the same bytes (or a
    /// fresh read of the same files), and only when a verdict needs it -
    /// a clean verify never does. See `packet::scan_packets_deferring`
    /// for what the unverified header buys and costs.
    ///
    /// ONE input can leave that arrangement on its own: a damaged
    /// CRITICAL packet sends that file down the hashing walk, which
    /// verifies its recovery packets too and counts them. When no other
    /// input deferred, the count is simply settled and correct. When one
    /// did, the two populations cannot be added - they are counts, and
    /// the same exponent carried by both files would be counted twice -
    /// so this exceptional mix is re-settled eagerly below and returned
    /// with nothing deferred.
    #[allow(clippy::type_complexity)]
    pub fn parse_deferred(
        inputs: &[&[u8]],
    ) -> (
        Result<Par2Set, Par2Error>,
        Vec<Vec<PacketInfo>>,
        Vec<Vec<(usize, usize)>>,
    ) {
        let mut census: Vec<Vec<PacketInfo>> = vec![Vec::new(); inputs.len()];
        let mut deferred: Vec<Vec<(usize, usize)>> = vec![Vec::new(); inputs.len()];
        let set = Par2Set::parse_inner_with(inputs, Some(&mut census), Some(&mut deferred));
        // A corrupt critical packet makes one input fall back to the
        // hashing scan, which counts ITS recovery exponents into the
        // set; another input may still have DEFERRED the very same
        // exponents. The result carries only a count, so a caller adding
        // `recovery_blocks_seen` to its own validated spans - which is
        // the whole documented contract, and what `parfast`'s
        // `ensure_recovery` does - counts a duplicated block twice and
        // reports repair power the set does not have. Measured at
        // 618ca2042: a set with two blocks damaged and ONE unique
        // recovery block present in two volumes, one of them carrying a
        // corrupt Creator packet, made `parfast v -q` exit 1 (repair
        // possible) where par2cmdline 1.2.0 exits 2. Settle the whole
        // set together in that exceptional mix, which costs the deferral
        // only where the input was already damaged enough to lose it.
        if set.as_ref().is_ok_and(|s| s.recovery_blocks_seen != 0)
            && deferred.iter().any(|spans| !spans.is_empty())
        {
            let (set, census) = Self::parse_censused(inputs);
            return (set, census, vec![Vec::new(); inputs.len()]);
        }
        (set, census, deferred)
    }

    fn parse_inner(
        inputs: &[&[u8]],
        census: Option<&mut Vec<Vec<PacketInfo>>>,
    ) -> Result<Par2Set, Par2Error> {
        Par2Set::parse_inner_with(inputs, census, None)
    }

    fn parse_inner_with(
        inputs: &[&[u8]],
        mut census: Option<&mut Vec<Vec<PacketInfo>>>,
        mut deferred: Option<&mut Vec<Vec<(usize, usize)>>>,
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
            let deferred = deferred.as_deref_mut().map(|d| &mut d[i]);
            let mut claim = |pkt: packet::RawPacket<'_>| {
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
                    // The two optional Text packets. Neither names a file
                    // or carries a checksum, so a set that has lost both
                    // to a contradiction is exactly as repairable as one
                    // whose producer wrote no comment at all.
                    t if t == TYPE_COMMASCI => {
                        if let Some(c) = parse_comm_ascii(pkt.body) {
                            g.comm_ascii.offer(c);
                        }
                    }
                    t if t == TYPE_COMMUNI => {
                        if let Some(c) = parse_comm_uni(pkt.body) {
                            g.comm_uni.offer(c);
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
            };
            match deferred {
                None => scan_packets(input, &mut claim),
                Some(spans) => {
                    // The deferred entries are censused AFTER the walk
                    // (the claim closure holds the census while it
                    // runs); a census is a count, and the counting
                    // dedupes by MD5, so order within one input does not
                    // change its answer.
                    let mut framed: Vec<PacketInfo> = Vec::new();
                    packet::scan_packets_deferring(input, &mut claim, |start, end| {
                        // Framed only: the entry carries what the header
                        // says, and the header is unverified.
                        let body = &input[start + 64..end];
                        framed.push(PacketInfo {
                            md5: input[start + 16..start + 32].try_into().unwrap(),
                            set_id: input[start + 32..start + 48].try_into().unwrap(),
                            recovery_exponent: (body.len() >= 4)
                                .then(|| u32::from_le_bytes([body[0], body[1], body[2], body[3]])),
                            body_len: body.len(),
                        });
                        spans.push((start, end));
                    });
                    if let Some(c) = census {
                        c.extend(framed);
                    }
                }
            }
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
            comm_ascii,
            comm_uni,
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
            // the other (`DescClaim::offer_desc`), and in all of those we
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
            // The Unicode spelling first, for the same reason a Unicode
            // Filename packet outranks the FileDesc's name: a producer
            // that wrote both wrote the ASCII one for readers that
            // understand nothing else, so it is the lossy half by
            // construction. Either may have annihilated on its own
            // without taking the other with it.
            comment: comm_uni
                .into_settled()
                .or_else(|| comm_ascii.into_settled()),
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

// The case table, out of line so the production file keeps its whole
// ceiling: a `#[cfg(test)] mod foo;` TARGET is scored against size-gate's
// TEST_FILE_CEILING rather than the flat production one. Plain `mod tests;`
// and no `#[path]`: this module has CHILDREN, and the file form roots them
// under `par2/tests/` exactly where the inline form did, so `name_tests.rs`
// and `trust_tests.rs` do not move.
#[cfg(test)]
mod tests;
