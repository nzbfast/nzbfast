//! In-band naming probes: bounded byte-peeks that read a release's real
//! name out of the posted bytes themselves - no external catalogue, no
//! correlation, the name IS in the post.
//!
//! First recipe (uploader-recipe registry entry 1): a single store-mode
//! 7z whose end header carries the real inner filename. Measured on the
//! live index (research/R3-B3-* 9 Aug 2026): 0% header-encrypted, ~94%
//! self-naming at ~1-2 MB per probe. Honest scope: the buildable band is
//! ~29% of currently-dark bytes and is effectively ONE automated
//! reposter's TV output in alt.binaries.tv, so yield tracks that one
//! poster's cadence and can drop to zero on any upload-script change -
//! which is exactly what the lane's daily hit-rate telemetry watches.
//!
//! Second recipe: a multi-volume RAR's own volume head ([`rar_head`],
//! TODO 131 rung 5). ON DEMAND only - the continuation pilot
//! (research/RAR-continuation-pilot-2026-08-10) found 98% of that band
//! BY BYTES header-encrypted, which is a NO-GO for a scan-time lane and
//! a fine answer for a question a human just asked. Its
//! `EncryptedHeader` verdict is what the terminal `header_encrypted`
//! classification is written from.
//!
//! Everything in this module treats its input as hostile: the start
//! header, the end header, the RAR volume head, and every name inside
//! them are bytes some anonymous uploader chose. Parsing is CRC-gated,
//! size-capped, and fuzzed (targets `sevenz_name_probe` and
//! `rar_name_probe`; `rar_map` covers the mapper underneath).

use std::io::{self, Read, Seek};

/// 7z container magic at offset 0. Same six bytes as
/// `extract::sevenz::SEVENZ_MAGIC`; duplicated because that one is
/// private to the extraction engine and this module must stay
/// self-contained for the fuzz harness.
pub const SEVENZ_MAGIC: &[u8] = &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

/// Cap on the declared end-header size BEFORE any fetch or allocation
/// happens on its behalf. A real end header for a store-mode archive
/// holding one media file is a few hundred bytes; 2 MiB is generous
/// slack for large multi-entry archives while still bounding what one
/// hostile start header can make the prober fetch and buffer.
pub const SEVENZ_END_MAX: u64 = 2 << 20;

/// Cap on the LZMA/LZMA2 dictionary a packed header's coder props may
/// declare. `LzDecoder::ensure_capacity` allocates the whole match
/// window up front, and lzma-rust2 does NOT clamp it to the unpack size
/// on the LZMA2 path - so a header declaring 9 bytes of output can still
/// drive a 384 MiB allocation. Found by fuzz on 14 Aug 2026 (a 33-byte
/// window, LZMA2 props byte 0x21 = `3 << 27`); the same byte at its
/// maximum 40 buys 4 GiB. Headers are metadata a real writer compresses
/// with a small window, and the decoded result is capped at
/// [`SEVENZ_END_MAX`] = 2 MiB anyway, so a window bigger than the output
/// it can produce is never useful - 64 MiB matches the PPMd cap and is
/// generous slack over any real writer.
pub const SEVENZ_DICT_MAX: u64 = 64 << 20;

/// Cap on the PPMd model memory a packed header's coder props may
/// declare. `Ppmd7Decoder::new` allocates the props' 32-bit memSize up
/// front - before a single output byte exists for the unpack-size cap
/// to bound - and sevenz-rust2's header decode passes an effectively
/// unlimited mem budget, so a 42-byte window declaring 4 GiB is an
/// instant OOM (found by fuzz). Real writers compress headers with
/// LZMA; a PPMd header at all is exotic, and 7-Zip's own PPMd default
/// is 16 MiB, so 64 MiB is generous slack.
pub const SEVENZ_PPMD_MEM_MAX: u64 = 64 << 20;

/// Property ids of the 7z end-header grammar, as sevenz-rust2 and the
/// reference implementation spell them. Only the ones the declared-size
/// pre-scan below needs.
const K_END: u8 = 0x00;
const K_HEADER: u8 = 0x01;
const K_ARCHIVE_PROPERTIES: u8 = 0x02;
const K_MAIN_STREAMS_INFO: u8 = 0x04;
const K_PACK_INFO: u8 = 0x06;
const K_UNPACK_INFO: u8 = 0x07;
const K_SIZE: u8 = 0x09;
const K_CRC: u8 = 0x0A;
const K_FOLDER: u8 = 0x0B;
const K_CODERS_UNPACK_SIZE: u8 = 0x0C;
const K_ENCODED_HEADER: u8 = 0x17;

/// 7z method id of PPMd, whose construction cost is set by its props
/// (memSize) rather than by the declared output size.
const SEVENZ_ID_PPMD: [u8; 3] = [0x03, 0x04, 0x01];

/// 7z method ids of LZMA1 and LZMA2. Both declare a dictionary size in
/// their props, and `LzDecoder::ensure_capacity` allocates that window
/// whole before a single output byte exists - so, like PPMd, the cost
/// is set by the props and NOT by the declared output size.
const SEVENZ_ID_LZMA1: [u8; 3] = [0x03, 0x01, 0x01];
const SEVENZ_ID_LZMA2: [u8; 1] = [0x21];

/// 7z method ids the packed-header decode below needs to recognise:
/// Copy (a stored header inside a kEncodedHeader wrapper) and
/// AES-256-SHA256 (a `-mhe` encrypted header, which no gate can read
/// without the password).
const SEVENZ_ID_COPY: [u8; 1] = [0x00];
const SEVENZ_ID_AES: [u8; 4] = [0x06, 0xF1, 0x07, 0x01];

/// Floor under which a CONTENT block's declared decoder memory (LZMA
/// dictionaries plus PPMd model sizes) is always accepted. 64 MiB is
/// the dictionary 7-Zip's Ultra preset declares regardless of how small
/// the data is. It bounds the largest SINGLE coder window a block may
/// declare for free; a block's SUMMED cost is held to this plus
/// [`SEVENZ_CONTENT_FILTER_ALLOWANCE`], because a preset-made archive is
/// not always one coder. This is deliberately NOT [`SEVENZ_DICT_MAX`]
/// reused: that cap is for metadata headers, whose decoded output is
/// bounded at [`SEVENZ_END_MAX`] anyway - content has no such output
/// bound, and users legitimately select dictionaries far past 64 MiB, so
/// past the floor the declaration is judged against the packed bytes
/// actually present instead of refused outright.
pub const SEVENZ_CONTENT_COST_FLOOR: u64 = 64 << 20;

/// How much declared decoder memory a MULTI-coder content block may add
/// on top of [`SEVENZ_CONTENT_COST_FLOOR`] for free (TODO 268).
///
/// 7-Zip picks BCJ2 automatically for executable content at `-mx7` and
/// above, and BCJ2 is FOUR coders in one block - `BCJ2 LZMA2:26
/// LZMA:20:lc0:lp2 LZMA:20:lc0:lp2` - whose windows a BCJ2 decode really
/// does hold at once. Summing them is right; judging that sum against a
/// floor calibrated for ONE dictionary was not. 64 + 1 + 1 = 66 MiB
/// cleared the floor by 2 MiB, fell through to the packed-bytes rule,
/// and a well-compressed installer lost there. Measured 23 Aug 2026 on a
/// Windows media-server corpus: four of the nine genuine 7-Zip
/// self-extractors in it extracted ZERO files, Microsoft's own Edge
/// update packages among them, ten days after the same corpus extracted
/// two of them fine.
///
/// 8 MiB is four times what the shape needs. The two auxiliary literal
/// coders are 1 MiB each and stay there: measured with 7-Zip 26.02 at
/// `-mf=BCJ2` on inputs from 4 KiB to 605 MB, the auxiliary dictionaries
/// track the input size up to 1 MiB and then stop, while the main LZMA2
/// dictionary keeps growing with `-md`.
///
/// The allowance is FLAT rather than per-coder, and the floor still
/// bounds the largest single window, so a chain may declare 72 MiB for
/// free no matter how many coders it lists. That is the deliberate
/// answer to the security question: a block whose coders are
/// individually modest and JOINTLY large - eight 32 MiB dictionaries -
/// is still held to its packed bytes, because a decode of it would hold
/// all eight windows at once. Only the auxiliary-filter shape is
/// forgiven, and only up to a fixed size.
pub const SEVENZ_CONTENT_FILTER_ALLOWANCE: u64 = 8 << 20;

/// How far past its own packed bytes a CONTENT block's declared decoder
/// memory may reach before it is refused (TODO 269).
///
/// The rule the packed-bytes anchor started as - `cost <=
/// next_power_of_two(pack)` - is one doubling of slack, and one
/// doubling is not enough, because the two quantities it compares are
/// not measured against the same stream. A dictionary is sized to the
/// UNPACKED data; the pack bytes are what is left after compressing it.
/// For anything that compresses at all, the packed side systematically
/// understates the window the writer honestly chose, and the shortfall
/// IS the compression ratio.
///
/// Measured 23 Aug 2026 on the same Windows corpus as TODO 268, in
/// Microsoft's Edge and Copilot update packages (four of them on one
/// box): one block, chain `BCJ2 LZMA:27 LZMA:22 LZMA:22`, so 128 + 4 +
/// 4 = 136 MiB declared against 43,902,179 packed bytes - which round up
/// to 64 MiB. 136 > 64, refused, zero files extracted, out of a 3.6:1
/// compression ratio that is entirely ordinary for a 150 MB browser
/// payload.
///
/// **The security question this answers is "what is the largest honest
/// compression ratio?", and the answer taken here is 4:1.** A writer
/// never gains from a dictionary larger than the stream it is
/// compressing, so an honest `cost` is at most
/// `next_power_of_two(unpack)`, and `unpack` is `pack * ratio`. Working
/// in powers of two, `next_power_of_two(unpack) <= 4 *
/// next_power_of_two(pack)` holds for every ratio up to 4:1 whatever the
/// alignment, and up to 8:1 when the alignment is favourable. Real
/// writers also cap the dictionary well below the stream size (`-md`),
/// which is why the measured file clears it with room to spare: 136 MiB
/// against the 256 MiB this allows.
///
/// What it costs on the other side is linear and nothing else. The
/// asymmetry the guard is built on is untouched: an attacker still buys
/// allocation only by posting real pack bytes, now at 8 bytes of window
/// per byte posted rather than 2. The checked-in bomb - 384 MiB out of
/// 16 packed bytes - is refused by six orders of magnitude either way,
/// and a block that is individually modest and jointly large is still
/// held to the same arithmetic. This is a strict widening of the old
/// rule, so nothing that passed before can start failing.
pub const SEVENZ_CONTENT_PACK_SLACK: u64 = 4;

/// Named refusals [`sevenz_disk_declared_bomb`] can return; callers put
/// them verbatim into job failure detail. All four mean "the file's own
/// declarations ask for work no honest archive needs", judged before
/// sevenz-rust2 is allowed to allocate on those declarations' say-so.
pub const SEVENZ_REFUSE_ZERO_START: &str =
    "7z start header geometry is zeroed (header recovery scan refused)";
pub const SEVENZ_REFUSE_HEADER: &str = "7z end header declares an oversized decode";
pub const SEVENZ_REFUSE_HEADER_CHAIN: &str = "7z packed header uses an unexpected coder chain";
pub const SEVENZ_REFUSE_CONTENT: &str =
    "7z content declares decoder memory far beyond its packed bytes";

/// The parsed 32-byte 7z start header. Offsets are relative to byte 32,
/// so the end header (the archive map, kept at the TAIL of a 7z)
/// occupies `[32 + header_off, 32 + header_off + header_size)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SevenzStart {
    pub(crate) header_off: u64,
    pub header_size: u64,
    /// CRC32 of the end-header bytes - the field that lets a probe
    /// verify it fetched the right tail window without knowing the
    /// archive's total size.
    pub(crate) header_crc: u32,
}

/// Parse the 32-byte start header, CRC-checked. Sibling of
/// `extract::sevenz::sevenz_start_header`, kept separate because the
/// probe also needs the end-header CRC that the extraction path throws
/// away. None for anything that is not a well-formed 7z start.
pub fn sevenz_start(head: &[u8]) -> Option<SevenzStart> {
    if head.len() < 32 || !head.starts_with(SEVENZ_MAGIC) {
        return None;
    }
    let crc = u32::from_le_bytes(head[8..12].try_into().unwrap());
    if crc32fast::hash(&head[12..32]) != crc {
        return None;
    }
    Some(SevenzStart {
        header_off: u64::from_le_bytes(head[12..20].try_into().unwrap()),
        header_size: u64::from_le_bytes(head[20..28].try_into().unwrap()),
        header_crc: u32::from_le_bytes(head[28..32].try_into().unwrap()),
    })
}

/// Why a probe could not produce a name. The distinctions matter for
/// telemetry: `EncryptedHeader` is the canary that the poster started
/// encrypting headers (the one change that would zero the lane's
/// yield), and it must stay distinguishable from plain parse noise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeError {
    /// Offset-0 bytes are not a CRC-valid 7z start header.
    BadStart,
    /// Declared end-header size is zero or above [`SEVENZ_END_MAX`],
    /// or a packed (`kEncodedHeader`) header declares a decoded size
    /// above the same cap, or a PPMd coder memSize above
    /// [`SEVENZ_PPMD_MEM_MAX`] (a bomb declaration, not a real header).
    HeaderTooBig,
    /// Caller's tail buffer is shorter than the declared header size.
    TailShort,
    /// The trailing window's CRC32 does not match the start header's
    /// claim - wrong bytes, or an archive whose end header does not sit
    /// flush at the file's tail.
    TailCrcMismatch,
    /// The end header is AES-encrypted (7z `-mhe`): the archive knows
    /// its own names but refuses to say without a password. THE canary
    /// this lane's telemetry watches for.
    EncryptedHeader,
    /// The end header is packed (`kEncodedHeader`) and its pack stream
    /// starts before the fetched tail - one or two more trailing
    /// segments might cover it, but the bounded budget decides.
    HeaderUnreachable,
    /// sevenz-rust2 rejected the header bytes.
    Parse(String),
    /// Parsed clean but contains no usable entry.
    NoEntries,
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeError::BadStart => write!(f, "not a 7z start header"),
            ProbeError::HeaderTooBig => write!(f, "end header size out of bounds"),
            ProbeError::TailShort => write!(f, "tail shorter than the declared header"),
            ProbeError::TailCrcMismatch => write!(f, "end header crc mismatch"),
            ProbeError::EncryptedHeader => write!(f, "header encrypted (needs a password)"),
            ProbeError::HeaderUnreachable => {
                write!(f, "packed header reaches before the fetched tail")
            }
            ProbeError::Parse(e) => write!(f, "end header parse: {e}"),
            ProbeError::NoEntries => write!(f, "archive lists no usable entry"),
        }
    }
}

/// One entry read out of the end header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SevenzEntryInfo {
    pub(crate) name: String,
    pub(crate) size: u64,
    pub(crate) has_stream: bool,
}

/// Verify that `tail` (the last bytes of the logical archive; for a
/// `.7z.NNN` split set, of the LAST volume) actually ends in the end
/// header the start header describes. 7z writes the end header flush at
/// the file's end, so the window is the trailing `header_size` bytes;
/// the CRC from the start header proves the identification without
/// knowing the archive's total size - which is what makes split sets
/// probeable without fetching every volume.
pub fn locate_end_header<'a>(start: &SevenzStart, tail: &'a [u8]) -> Result<&'a [u8], ProbeError> {
    if start.header_size == 0 || start.header_size > SEVENZ_END_MAX {
        return Err(ProbeError::HeaderTooBig);
    }
    let hs = start.header_size as usize;
    if tail.len() < hs {
        return Err(ProbeError::TailShort);
    }
    let window = &tail[tail.len() - hs..];
    if crc32fast::hash(window) != start.header_crc {
        return Err(ProbeError::TailCrcMismatch);
    }
    Ok(window)
}

/// Byte cursor for the declared-size pre-scan. Every accessor returns
/// None on truncation; the scan never allocates and never loops more
/// times than there are bytes left, so a hostile window costs at most
/// one linear pass over at most [`SEVENZ_END_MAX`] bytes.
struct Scan<'a> {
    b: &'a [u8],
    i: usize,
}

impl Scan<'_> {
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.i)?;
        self.i += 1;
        Some(v)
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        self.i = self.i.checked_add(n).filter(|&e| e <= self.b.len())?;
        Some(())
    }

    /// 7z variable-length integer, bit-exact with sevenz-rust2's
    /// `read_variable_u64` (first byte's high bits say how many
    /// little-endian payload bytes follow).
    fn num(&mut self) -> Option<u64> {
        let first = self.u8()? as u64;
        let mut mask = 0x80u64;
        let mut value = 0u64;
        for i in 0..8 {
            if first & mask == 0 {
                return Some(value | ((first & (mask - 1)) << (8 * i)));
            }
            value |= (self.u8()? as u64) << (8 * i);
            mask >>= 1;
        }
        Some(value)
    }

    /// Mirror of `read_all_or_bits` byte consumption: returns how many
    /// of `n` flags are set, which is all the CRC-skipping needs.
    fn all_or_bits_count(&mut self, n: u64) -> Option<u64> {
        if self.u8()? != 0 {
            return Some(n);
        }
        let mut set = 0u64;
        let mut byte = 0u8;
        for i in 0..n {
            if i % 8 == 0 {
                byte = self.u8()?;
            }
            if byte & (0x80 >> (i % 8)) != 0 {
                set += 1;
            }
        }
        Some(set)
    }
}

/// What decoding a `kEncodedHeader` window will cost, as DECLARED by
/// the window itself - the numbers sevenz-rust2 turns into allocations
/// before one honest byte is produced.
struct DeclaredCost {
    /// Sum of every unpack size - the number sevenz-rust2 hands
    /// `Read::take` as the decode bound, plus every intermediate coder
    /// buffer.
    unpack: u64,
    /// Sum of every PPMd coder's props-declared memSize -
    /// `Ppmd7Decoder::new` allocates it up front, independent of any
    /// output bound, so it needs its own cap ([`SEVENZ_PPMD_MEM_MAX`]).
    ppmd_mem: u64,
    /// Sum of every LZMA1/LZMA2 coder's props-declared dictionary size.
    /// `LzDecoder::ensure_capacity` allocates the match window whole,
    /// and lzma-rust2 does NOT clamp it to the unpack size on the LZMA2
    /// path - this field used to be assumed away as "clamped", which is
    /// what let a 9-byte declared output allocate 384 MiB. Own cap:
    /// [`SEVENZ_DICT_MAX`].
    dict_size: u64,
}

/// What one coder declaration was, as far as the packed-header decode
/// below cares: enough to run the two chains real writers compress
/// headers with (single LZMA1/LZMA2, or Copy), to recognise `-mhe`
/// encryption, and to lump everything else into Other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScannedCoder {
    Copy,
    Lzma1 { props: u8, dict: u32 },
    Lzma2 { dict: u32 },
    Aes,
    Other,
}

/// One block's declared shape out of a streams-info scan.
struct BlockDecl {
    /// Summed LZMA1/LZMA2 props-declared dictionary sizes.
    dict_size: u64,
    /// Summed PPMd props-declared memSizes.
    ppmd_mem: u64,
    /// The largest SINGLE coder window declared on this chain (an
    /// LZMA/LZMA2 dictionary or a PPMd memSize). The sums above say what
    /// a decode holds at once; this says whether any ONE allocation is
    /// out of scale, which is what stops
    /// [`SEVENZ_CONTENT_FILTER_ALLOWANCE`] being spent on a single
    /// oversized dictionary instead of on the filter coders it is for.
    max_coder: u64,
    /// How many pack streams this block consumes (blocks take them from
    /// the kPackInfo list in order).
    packed: u64,
    /// Total coders declared, and the first one's classified shape -
    /// the packed-header decode only acts when the count is exactly 1.
    coder_count: u64,
    first_coder: ScannedCoder,
    /// Any AES coder anywhere on the chain (an encrypted header or an
    /// encrypted content block).
    has_aes: bool,
}

/// A scanned streams-info section: the shared grammar of a
/// `kEncodedHeader` window and of a real header's kMainStreamsInfo.
struct StreamsDecl {
    pack_pos: u64,
    pack_sizes: Vec<u64>,
    blocks: Vec<BlockDecl>,
    /// Sum of every declared unpack size across all blocks.
    unpack_total: u64,
}

/// Scan a streams-info section starting at `s` (positioned just after
/// the id byte that introduced it). A byte-exact mirror of the
/// library's parse up to `kCodersUnpackSize` (reader.rs:
/// `read_pack_info`, `read_unpack_info`, `read_block`), stopping right
/// after the sizes.
///
/// Returns None when the section does not scan - the library will then
/// reject the same bytes itself BEFORE any decode (its parse is the
/// same grammar, and it cannot reach the decoder without a parsed
/// block), so None safely means "let the library produce its error".
/// Overflow while summing saturates instead of failing: an astronomic
/// declaration must land in the over-cap bucket, not the None one.
/// Vec growth is paced by parsed bytes (every entry consumes at least
/// one), so a hostile section can never balloon them past its own size.
fn streams_info_declared(s: &mut Scan) -> Option<StreamsDecl> {
    let limit = s.b.len() as u64;
    let mut pack_pos = 0u64;
    let mut pack_sizes = Vec::new();
    let mut nid = s.u8()?;
    if nid == K_PACK_INFO {
        pack_pos = s.num()?;
        let num_pack = s.num()?;
        if num_pack > limit {
            return None;
        }
        nid = s.u8()?;
        if nid == K_SIZE {
            for _ in 0..num_pack {
                pack_sizes.push(s.num()?);
            }
            nid = s.u8()?;
        }
        if nid == K_CRC {
            let defined = s.all_or_bits_count(num_pack)?;
            s.skip((defined as usize).checked_mul(4)?)?;
            nid = s.u8()?;
        }
        if nid != K_END {
            return None;
        }
        nid = s.u8()?;
    }
    if nid != K_UNPACK_INFO || s.u8()? != K_FOLDER {
        return None;
    }
    let num_blocks = s.num()?;
    if num_blocks > limit || s.u8()? != 0 {
        return None;
    }
    // Per-block records; pushes are paced by parsed bytes (a block
    // consumes at least two), so a declared-huge `num_blocks` truncates
    // out of the loop before it can balloon this vec.
    let mut blocks = Vec::new();
    let mut block_outs = Vec::new();
    for _ in 0..num_blocks {
        let num_coders = s.num()?;
        if num_coders > limit {
            return None;
        }
        let mut total_in = 0u64;
        let mut total_out = 0u64;
        let mut ppmd_mem = 0u64;
        let mut dict_size = 0u64;
        let mut max_coder = 0u64;
        let mut first_coder = ScannedCoder::Other;
        let mut has_aes = false;
        for coder_idx in 0..num_coders {
            let bits = s.u8()?;
            let id_at = s.i;
            s.skip((bits & 0xF) as usize)?;
            let id = &s.b[id_at..s.i];
            let is_ppmd = id == SEVENZ_ID_PPMD;
            let is_lzma1 = id == SEVENZ_ID_LZMA1;
            let is_lzma2 = id == SEVENZ_ID_LZMA2;
            has_aes |= id == SEVENZ_ID_AES;
            let mut kind = if id == SEVENZ_ID_COPY {
                ScannedCoder::Copy
            } else if id == SEVENZ_ID_AES {
                ScannedCoder::Aes
            } else {
                ScannedCoder::Other
            };
            let (n_in, n_out) = if bits & 0x10 == 0 {
                (1, 1)
            } else {
                (s.num()?, s.num()?)
            };
            total_in = total_in.checked_add(n_in)?;
            total_out = total_out.checked_add(n_out)?;
            if total_in > limit || total_out > limit {
                return None;
            }
            if bits & 0x20 != 0 {
                let props = s.num()?;
                if props > limit {
                    return None;
                }
                let props_at = s.i;
                s.skip(props as usize)?;
                // PPMd props: order byte, then the 32-bit memSize the
                // decoder will allocate whole. Shorter props error in
                // the library before it allocates - safe fall-through.
                if is_ppmd && props >= 5 {
                    let p = &s.b[props_at..];
                    let mem = u32::from_le_bytes([p[1], p[2], p[3], p[4]]);
                    ppmd_mem = ppmd_mem.saturating_add(mem as u64);
                    max_coder = max_coder.max(mem as u64);
                }
                // LZMA1 props: lclppb byte, then the 32-bit dictionary
                // size the LZ decoder allocates whole. Same shape as
                // PPMd's memSize, one field over.
                if is_lzma1 && props >= 5 {
                    let p = &s.b[props_at..];
                    let dict = u32::from_le_bytes([p[1], p[2], p[3], p[4]]);
                    dict_size = dict_size.saturating_add(dict as u64);
                    max_coder = max_coder.max(dict as u64);
                    kind = ScannedCoder::Lzma1 { props: p[0], dict };
                }
                // LZMA2 props: ONE byte, and the dictionary it names
                // grows exponentially - `(2 | p & 1) << (p / 2 + 11)`,
                // so 0x21 is 384 MiB and the maximum 40 is 4 GiB out of
                // a single attacker-chosen byte. Above 40 the library
                // refuses, and so do we.
                if is_lzma2 && props >= 1 {
                    let p = s.b[props_at];
                    if p > 40 {
                        return None;
                    }
                    let dict = if p == 40 {
                        u32::MAX
                    } else {
                        ((2 | (p as u64 & 1)) << (p / 2 + 11)) as u32
                    };
                    dict_size = dict_size.saturating_add(dict as u64);
                    max_coder = max_coder.max(dict as u64);
                    kind = ScannedCoder::Lzma2 { dict };
                }
            }
            if bits & 0x80 != 0 {
                // Alternative methods: the library refuses these too.
                return None;
            }
            if coder_idx == 0 {
                first_coder = kind;
            }
        }
        if total_out == 0 {
            return None;
        }
        let bind_pairs = total_out - 1;
        for _ in 0..bind_pairs {
            s.num()?;
            s.num()?;
        }
        if total_in < bind_pairs {
            return None;
        }
        let packed = total_in - bind_pairs;
        if packed != 1 {
            for _ in 0..packed {
                s.num()?;
            }
        }
        blocks.push(BlockDecl {
            dict_size,
            ppmd_mem,
            max_coder,
            packed,
            coder_count: num_coders,
            first_coder,
            has_aes,
        });
        block_outs.push(total_out);
    }
    if s.u8()? != K_CODERS_UNPACK_SIZE {
        return None;
    }
    let mut total = 0u64;
    for &outs in &block_outs {
        for _ in 0..outs {
            total = total.saturating_add(s.num()?);
        }
    }
    Some(StreamsDecl {
        pack_pos,
        pack_sizes,
        blocks,
        unpack_total: total,
    })
}

/// The declared decode cost of a `kEncodedHeader` window, summed the
/// way the header caps judge it. See [`streams_info_declared`] for the
/// scan itself and the meaning of None.
fn encoded_header_declared_cost(window: &[u8]) -> Option<DeclaredCost> {
    let mut s = Scan { b: window, i: 1 }; // window[0] == K_ENCODED_HEADER
    let decl = streams_info_declared(&mut s)?;
    let mut ppmd_mem = 0u64;
    let mut dict_size = 0u64;
    for b in &decl.blocks {
        ppmd_mem = ppmd_mem.saturating_add(b.ppmd_mem);
        dict_size = dict_size.saturating_add(b.dict_size);
    }
    Some(DeclaredCost {
        unpack: decl.unpack_total,
        ppmd_mem,
        dict_size,
    })
}

/// The decompression-bomb verdict on a located end-header window,
/// shared by BOTH 7z entry points (the in-stream tail probe and the
/// on-disk password probe): true when a packed (`kEncodedHeader`)
/// window declares a decoded size above [`SEVENZ_END_MAX`], a PPMd
/// memSize above [`SEVENZ_PPMD_MEM_MAX`], or an LZMA/LZMA2 dictionary
/// above [`SEVENZ_DICT_MAX`]. sevenz-rust2 decodes the
/// window with the DECLARED sizes as its only bounds - LZMA ratios
/// would turn a couple MB of hostile pack bytes into hundreds of MB of
/// RAM, synchronously - so the declaration must be read out of the
/// window and judged before the library is allowed to decode it. Real
/// posters' packed headers decode to a few hundred bytes; 2 MiB of
/// decoded header metadata is generous. A PPMd coder's memSize and an
/// LZMA/LZMA2 coder's dictionary size are two FURTHER declared
/// allocations the output cap never touches, so each gets its own cap -
/// the dictionary one because lzma-rust2 does not clamp the LZMA2 window
/// to the unpack size, which this gate assumed until fuzz proved
/// otherwise on 14 Aug 2026.
fn encoded_header_bomb(window: &[u8]) -> bool {
    window.first() == Some(&K_ENCODED_HEADER)
        && encoded_header_declared_cost(window).is_some_and(|d| {
            d.unpack > SEVENZ_END_MAX
                || d.ppmd_mem > SEVENZ_PPMD_MEM_MAX
                || d.dict_size > SEVENZ_DICT_MAX
        })
}

/// A sparse Read+Seek view over the two byte ranges a probe actually
/// holds (the head article and the located end header). Reads inside a
/// gap fail rather than fabricate zeros, so the parser can never be fed
/// bytes the wire did not produce - a `kEncodedHeader` that tries to
/// read its pack streams dies here, cleanly.
struct SparseReader<'a> {
    /// (absolute offset, bytes), non-overlapping, ascending.
    chunks: [(u64, &'a [u8]); 2],
    total: u64,
    pos: u64,
}

impl Read for SparseReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.total || out.is_empty() {
            return Ok(0);
        }
        for &(off, data) in &self.chunks {
            let end = off + data.len() as u64;
            if self.pos >= off && self.pos < end {
                let at = (self.pos - off) as usize;
                let n = out.len().min(data.len() - at);
                out[..n].copy_from_slice(&data[at..at + n]);
                self.pos += n as u64;
                return Ok(n);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("read at {} {GAP_SENTINEL}", self.pos),
        ))
    }
}

impl Seek for SparseReader<'_> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        let target = match pos {
            io::SeekFrom::Start(o) => o as i128,
            io::SeekFrom::End(d) => self.total as i128 + d as i128,
            io::SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if target < 0 || target > u64::MAX as i128 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek range"));
        }
        self.pos = target as u64;
        Ok(self.pos)
    }
}

/// The sentinel a [`SparseReader`] gap read carries, so the error
/// mapping below can tell "the parser wanted bytes we never fetched"
/// from every other IO shape sevenz-rust2 might report.
const GAP_SENTINEL: &str = "outside the fetched tail";

/// Parse the end header out of `head` (the decoded offset-0 bytes, at
/// least 32) plus `tail` (decoded trailing bytes ending at the logical
/// archive's last byte), and list the archive's entries.
///
/// The window is verified by [`locate_end_header`] first, which also
/// pins the archive's total size to `32 + header_off + header_size` -
/// so the sparse view it hands sevenz-rust2 is anchored without knowing
/// any middle volume's size. A packed (`kEncodedHeader`) header decodes
/// in-process when its pack stream falls inside `tail` (7z writers
/// place it directly before the end header, so a normal trailing fetch
/// covers it); an AES-encrypted header reports [`ProbeError::EncryptedHeader`].
pub fn sevenz_tail_names(head: &[u8], tail: &[u8]) -> Result<Vec<SevenzEntryInfo>, ProbeError> {
    let (archive, _) = sevenz_tail_archive(head, tail)?;
    let entries: Vec<SevenzEntryInfo> = archive
        .files
        .iter()
        .map(|e| SevenzEntryInfo {
            name: e.name.clone(),
            size: e.size,
            has_stream: e.has_stream,
        })
        .collect();
    if entries.is_empty() {
        return Err(ProbeError::NoEntries);
    }
    Ok(entries)
}

/// One coder on a 7z block's chain, as the end header declares it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SevenzCoderInfo {
    /// The 7z method id bytes (`0x21` = LZMA2, `03 01 01` = LZMA, ...).
    pub id: Vec<u8>,
    /// sevenz-rust2's name for the id, or `None` when it is one the
    /// library does not know (and so one the extractor cannot decode).
    pub name: Option<&'static str>,
}

/// One block (7z "folder") of the archive: its coder chain and sizes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SevenzBlockInfo {
    /// Coders in declaration order; more than one is a chain (a BCJ or
    /// Delta filter ahead of LZMA2, or AES wrapped around anything).
    pub coders: Vec<SevenzCoderInfo>,
    /// Container bytes this block's pack streams occupy.
    pub packed: u64,
    /// Bytes the block decodes to.
    pub unpacked: u64,
}

/// The archive's block map, read from the same end header as
/// [`sevenz_tail_names`]: total container size plus one entry per block.
/// This is the census reader for "which compression method do posted 7z
/// sets actually use" - the extractor's own parse, not a re-implementation.
pub fn sevenz_tail_blocks(
    head: &[u8],
    tail: &[u8],
) -> Result<(u64, Vec<SevenzBlockInfo>), ProbeError> {
    let (archive, total) = sevenz_tail_archive(head, tail)?;
    let pack_sizes = archive.pack_sizes();
    let firsts = archive.stream_map.block_first_pack_stream_index();
    let blocks = archive
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| {
            let lo = firsts.get(i).copied().unwrap_or(0);
            let hi = firsts.get(i + 1).copied().unwrap_or(pack_sizes.len());
            SevenzBlockInfo {
                coders: b
                    .coders
                    .iter()
                    .map(|c| SevenzCoderInfo {
                        id: c.encoder_method_id().to_vec(),
                        name: sevenz_rust2::EncoderMethod::by_id(c.encoder_method_id())
                            .map(|m| m.name()),
                    })
                    .collect(),
                packed: pack_sizes.get(lo..hi).map(|s| s.iter().sum()).unwrap_or(0),
                unpacked: b.get_unpack_size(),
            }
        })
        .collect();
    Ok((total, blocks))
}

/// Shared parse behind the two tail probes: verify the window, anchor
/// the sparse view, and hand back sevenz-rust2's archive with the total
/// container size.
fn sevenz_tail_archive(
    head: &[u8],
    tail: &[u8],
) -> Result<(sevenz_rust2::Archive, u64), ProbeError> {
    let start = sevenz_start(head).ok_or(ProbeError::BadStart)?;
    let window = locate_end_header(&start, tail)?;
    // Decompression-bomb gate: a packed header's pack stream sits in
    // the fetched tail, and decoding it on the probe lane would cost
    // whatever the (already CRC-verified) window declares - so hold the
    // declaration to the same cap as the stored header first.
    if encoded_header_bomb(window) {
        return Err(ProbeError::HeaderTooBig);
    }
    let total = 32u64
        .checked_add(start.header_off)
        .and_then(|s| s.checked_add(start.header_size))
        .ok_or(ProbeError::HeaderTooBig)?;
    // The CRC match above proved `tail` ends exactly at the archive's
    // last byte, so its absolute position falls out of the total. A
    // tail longer than the archive keeps only the real bytes (tiny
    // archive, generous fetch); any overlap with `head` is fine - the
    // reader serves overlapping ranges first-chunk-first and both hold
    // the same wire bytes.
    let keep = (tail.len() as u64).min(total) as usize;
    let tail = &tail[tail.len() - keep..];
    let mut sparse = SparseReader {
        chunks: [(0, head), (total - keep as u64, tail)],
        total,
        pos: 0,
    };
    let archive = sevenz_rust2::Archive::read(&mut sparse, &sevenz_rust2::Password::default())
        .map_err(|e| match e {
            // Deterministic -mhe verdict: an AES coder on the header
            // chain with no password. This is the telemetry canary.
            sevenz_rust2::Error::PasswordRequired => ProbeError::EncryptedHeader,
            // A gap read wears the sentinel wherever the library
            // buries the io::Error (it rewraps Io as MaybeBadPassword
            // in places, so match on the message, not the variant).
            e if e.to_string().contains(GAP_SENTINEL) => ProbeError::HeaderUnreachable,
            e => ProbeError::Parse(e.to_string()),
        })?;
    Ok((archive, total))
}

/// The one inner filename worth applying: largest real entry, sanitized.
///
/// The name is an anonymous uploader's choice - treat it like any other
/// untrusted string: keep only the final path component, drop control
/// characters, bound the length. Returns None when nothing survives.
pub fn pick_media_name(entries: &[SevenzEntryInfo]) -> Option<String> {
    let best = entries
        .iter()
        .filter(|e| e.has_stream && e.size > 0)
        .max_by_key(|e| e.size)?;
    let base = best.name.rsplit(['/', '\\']).next().unwrap_or(&best.name);
    let clean: String = base
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .to_string();
    if clean.is_empty() || clean.chars().count() > 255 || clean == "." || clean == ".." {
        return None;
    }
    Some(clean)
}

// ---- RAR: the continuation-volume head read (TODO 131 rung 5) --------

/// What one RAR volume's leading bytes said about the file inside it.
///
/// The pilot (research/RAR-continuation-pilot-2026-08-10) established
/// the mechanical fact this type exists to carry: a multi-volume RAR's
/// CONTINUATION volumes repeat the inner file header, so the leading
/// bytes of ANY volume - selected by the stored `part_no=1` tuple, not
/// by a `.partNN.rar` filename - name the file. 44/44 sampled targets
/// decoded at yEnc `begin=1`; 11 of 14 RAR4 sets named in one article.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RarHead {
    /// 4 or 5. Recorded because the plaintext yield is
    /// version-determined (RAR4 79%, RAR5 8%) and the ratio drifts as
    /// posters migrate - a shift shows up here first.
    pub(crate) v5: bool,
    /// RAR5 main-header volume number (0-based), when the volume is a
    /// numbered member. The obfuscation-proof ordering: absent in RAR4
    /// and on a first volume.
    pub(crate) volume_number: Option<u64>,
    pub(crate) entries: Vec<RarEntryInfo>,
}

/// One file piece a volume header described.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RarEntryInfo {
    pub(crate) name: String,
    /// Total unpacked size of the inner file - repeated in EVERY volume,
    /// which is what makes it a usable content key from a mid-set head.
    pub(crate) unpacked_size: u64,
    /// Stored whole-file CRC32, when this piece carries one.
    pub(crate) file_crc: Option<u32>,
    pub(crate) is_dir: bool,
}

/// Read a RAR volume's own leading bytes for the inner filename.
///
/// `head` is the decoded start of ONE volume file (a probe holds a
/// whole article, which is 700 KB against a header of tens of bytes);
/// `volume_size` is that file's declared length, used only for the
/// mapper's EOF rule. Pure - no I/O, no allocation beyond the entries -
/// so the fuzz harness and the unit tests reach it directly.
///
/// The error vocabulary is deliberately the 7z lane's:
/// [`ProbeError::EncryptedHeader`] is THE canary in both containers,
/// and the terminal `header_encrypted` classification keys off it, so
/// the two lanes must not spell the same fact two ways.
pub fn rar_head(head: &[u8], volume_size: u64) -> Result<RarHead, ProbeError> {
    let mut m = crate::rar::VolumeMapper::new(volume_size);
    m.feed(0, head);
    // Blockers first: a mapper can carry entries AND a blocker, and an
    // archive that says "password required" must report that fact even
    // when a stray entry parsed before the wall.
    match &m.blocker {
        // RAR5 type-4 HEAD_CRYPT, or a RAR4 main header with
        // MHD_PASSWORD - nothing after the signature is readable at any
        // fetch budget. 24 of 26 sampled RAR5 sets land here.
        Some(crate::rar::MapBlocker::EncryptedHeaders) => {
            return Err(ProbeError::EncryptedHeader);
        }
        Some(crate::rar::MapBlocker::NotRar) => return Err(ProbeError::BadStart),
        Some(crate::rar::MapBlocker::Corrupt(e)) => {
            return Err(ProbeError::Parse((*e).to_string()));
        }
        // `-p` (data encrypted, headers plain), compressed, or a bad
        // password: the NAMES are still readable, and a name is all this
        // probe wants. Fall through.
        _ => {}
    }
    let v5 = match m.version {
        Some(crate::rar::RarVersion::V5) => true,
        Some(crate::rar::RarVersion::V4) => false,
        // No signature in the bytes we hold: not this volume's head.
        None => return Err(ProbeError::BadStart),
    };
    let entries: Vec<RarEntryInfo> = m
        .entries
        .iter()
        .map(|e| RarEntryInfo {
            name: e.name.clone(),
            // A "size unknown" flag means the field is a placeholder,
            // not a length: refusing to pass it on keeps it out of the
            // content key, where a placeholder would key thousands of
            // unrelated sets together.
            unpacked_size: if e.size_unknown { 0 } else { e.unpacked_size },
            file_crc: e.file_crc,
            is_dir: e.is_dir,
        })
        .collect();
    if entries.is_empty() {
        return Err(ProbeError::NoEntries);
    }
    Ok(RarHead {
        v5,
        volume_number: m.volume_number,
        entries,
    })
}

/// The one inner filename worth applying, and the content key that
/// corroborates it: largest real entry, sanitized by the same rules the
/// 7z lane uses on the same class of untrusted uploader string.
///
/// The key is `{unpacked_size}:{crc32}` from the header the mapper
/// already exposes - exact for the volume, weaker than a PAR2 set ID.
/// When the header carries no CRC (a split piece that is not the last)
/// the size alone keys it, and when it carries neither there is no key:
/// the caller must fall back to the filename, never to a constant, or
/// every keyless RAR in the index would corroborate every other.
pub fn pick_rar_media_name(head: &RarHead) -> Option<(String, Option<String>)> {
    let best = head
        .entries
        .iter()
        .filter(|e| !e.is_dir)
        .max_by_key(|e| e.unpacked_size)?;
    let base = best.name.rsplit(['/', '\\']).next().unwrap_or(&best.name);
    let clean: String = base
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .to_string();
    if clean.is_empty() || clean.chars().count() > 255 || clean == "." || clean == ".." {
        return None;
    }
    let key = match (best.unpacked_size, best.file_crc) {
        (0, _) => None,
        (size, Some(crc)) => Some(format!("{size}:{crc:08x}")),
        (size, None) => Some(format!("{size}")),
    };
    Some((clean, key))
}

/// Does this on-disk 7-Zip container need a password to open?
///
/// The disk-side twin of the `-mhe` verdict [`sevenz_tail_names`] returns
/// as [`ProbeError::EncryptedHeader`]: same question, asked of a finished
/// file rather than a head/tail pair. `rar::needs_password` has answered
/// it for RAR volumes since the password affordance shipped; without this,
/// the daemon's post-processing looked for encrypted RARs only, so a
/// header-encrypted 7z ended the job as a generic "an archive could not be
/// unpacked" LOCAL failure - no password prompt, no Retry-with-password -
/// even though the unpacker had already said `PasswordRequired` in the log
/// (soak round 3, 11 Aug, advQ).
///
/// False for anything that is not a readable 7z: a caller asking "does
/// this need a password" about a missing or malformed file wants "no",
/// and the malformed case is somebody else's error to report.
///
/// Bomb-gated like the in-stream twin: the end-header window is read
/// and held to [`encoded_header_bomb`]'s caps BEFORE `Archive::read` is
/// allowed to decode it, and a declared `header_size` past
/// [`SEVENZ_END_MAX`] is refused before this function buffers it. A
/// refused file lands in the same "not a readable 7z" bucket as any
/// other malformed input.
pub fn sevenz_needs_password(path: &std::path::Path) -> bool {
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    if sevenz_disk_header_bomb(&mut f) || f.seek(io::SeekFrom::Start(0)).is_err() {
        return false;
    }
    matches!(
        sevenz_rust2::Archive::read(&mut f, &sevenz_rust2::Password::default()),
        Err(sevenz_rust2::Error::PasswordRequired) | Err(sevenz_rust2::Error::MaybeBadPassword(_))
    )
}

/// Does this 7-Zip container carry ANY encrypted coder - header or
/// content - as read straight off the parsed metadata, with nothing
/// decoded?
///
/// A 7z block lists the coders its data passes through, and AES-256-SHA256
/// is method id `06F10701`; a container none of whose blocks names that
/// coder cannot be encrypted, and proving it costs one end-header parse.
/// The point is what the caller can then SKIP: the daemon's 7z password
/// lane settles "no key needed" by opening the container and decoding its
/// first entry to the checksum (bounded at 64 MiB), which on a plain
/// archive is a full LZMA decode whose only finding is that there was
/// nothing to decrypt - and the real extraction decodes those same bytes
/// again moments later.
///
/// NOT interchangeable with [`sevenz_needs_password`], and this is the
/// whole reason the decode probe existed. That one keys on
/// `Error::PasswordRequired` / `MaybeBadPassword` from `Archive::read`,
/// so it answers only for HEADER-encrypted (`-mhe`) archives: a
/// data-encrypted container written with plaintext headers parses
/// cleanly with no password at all and comes back false there, while
/// its blocks plainly name the AES coder and are read as encrypted
/// here.
///
/// Fails CLOSED, unlike its neighbour: true is "encrypted, or this is
/// not a container we can prove otherwise about", so every unreadable,
/// refused or header-encrypted shape answers true and the caller's
/// existing path runs unchanged. Only a clean parse showing no AES
/// coder anywhere answers false, and only that answer is load-bearing.
///
/// Bomb-gated like [`sevenz_needs_password`]: [`sevenz_disk_header_bomb`]
/// runs through the same reader before `Archive::read` is allowed to
/// decode a packed end header, and a refusal is one of the true
/// answers. Reader-generic because a split `.7z.NNN` set is judged
/// where it lies, through the caller's joining reader. Leaves the
/// cursor wherever the reads ended.
pub fn sevenz_is_encrypted(f: &mut (impl Read + Seek)) -> bool {
    if f.seek(io::SeekFrom::Start(0)).is_err() {
        return true;
    }
    if sevenz_disk_header_bomb(f) || f.seek(io::SeekFrom::Start(0)).is_err() {
        return true;
    }
    let Ok(archive) = sevenz_rust2::Archive::read(f, &sevenz_rust2::Password::default()) else {
        return true; // header-encrypted, malformed, or otherwise unproven
    };
    archive.blocks.iter().any(|b| {
        b.coders
            .iter()
            .any(|c| c.encoder_method_id() == sevenz_rust2::EncoderMethod::ID_AES256_SHA256)
    })
}

/// The Read+Seek half of the bomb gate: read the declared end-header
/// geometry out of `f` and answer whether the caller must refuse the
/// container before the library allocates on the declaration's say-so.
/// Shared by every entry point that hands sevenz-rust2 a whole
/// container: [`sevenz_needs_password`] and [`sevenz_is_encrypted`]
/// here, the chase worker's blocking set view (`extract::sevenz`), and
/// the daemon's disk-side 7z probes and extractor - which is why it is
/// `pub`. True means refuse: the start header declares an end header
/// past [`SEVENZ_END_MAX`] (which `Archive::read` buffers whole), or
/// the window is a `kEncodedHeader` whose declared decode cost
/// [`encoded_header_bomb`] rejects, or the start header is the zeroed
/// shape that would send `Archive::read` into its end-header recovery
/// scan (see the body). False means the geometry gave no reason to
/// refuse - including every OTHER malformed shape (short file, bad
/// start CRC, unreadable window), where the library's own parse fails
/// cheaply and its error keeps the verdict honest. Leaves the cursor
/// wherever the reads ended; the caller rewinds.
pub fn sevenz_disk_header_bomb(f: &mut (impl Read + Seek)) -> bool {
    disk_declared_bomb(f, false).is_some()
}

/// The full declared-size verdict for an entry point about to DECODE
/// CONTENT: everything [`sevenz_disk_header_bomb`] refuses, plus the
/// content blocks' own declarations. Returns the named reason to
/// refuse, or None when the declarations gave none - including every
/// malformed shape, where the library's own parse fails cheaply.
///
/// The content half exists because sevenz-rust2 passes an unlimited
/// memory budget into its content decoders, and lzma-rust2's
/// `LzDecoder::ensure_capacity` sizes and ZERO-FILLS the whole
/// props-declared match window before producing a byte - so an LZMA2
/// props byte of 40 in a content block is a ~4 GiB committed
/// allocation out of a file a few hundred bytes long. The parsed
/// `Archive` does not expose coder props, so the declarations are read
/// out of the raw end header here: directly for a stored (`kHeader`)
/// one, and for a packed (`kEncodedHeader`) one by decoding the header
/// in-process first - a decode the header caps above have already
/// bounded to 2 MiB of output. The verdict itself is
/// [`content_declared_bomb`]'s proportionality rule.
///
/// What this cannot see, it lets pass rather than guess: an
/// AES-encrypted header (`-mhe`) hides its content declarations from
/// everything but the passworded parse, and a scan/decode mismatch
/// means the library will fail on the same bytes anyway. The one
/// fail-closed case is an unencrypted packed header whose coder chain
/// is none of the shapes any known writer emits (single LZMA1, LZMA2,
/// or Copy): the only reason to compress a header with an exotic chain
/// is to hide what it declares. Leaves the cursor wherever the reads
/// ended; the caller rewinds.
pub fn sevenz_disk_declared_bomb(f: &mut (impl Read + Seek)) -> Option<&'static str> {
    disk_declared_bomb(f, true)
}

/// Shared body of the two disk gates above.
fn disk_declared_bomb(f: &mut (impl Read + Seek), check_content: bool) -> Option<&'static str> {
    let mut head = [0u8; 32];
    if f.read_exact(&mut head).is_err() {
        return None;
    }
    // A zeroed start header (magic intact, CRC field AND all twenty
    // geometry bytes zero) is the ONE malformed shape that does not
    // fail cheaply in the library: Archive::read treats exactly it as
    // "guess the end header", scans the last MiB for a header id, and
    // decodes whatever kEncodedHeader it finds with no CRC check and no
    // memory limit - so the caps above never see the declaration. A
    // well-formed archive always has a nonzero start CRC, so refusing
    // the shape outright costs nothing.
    if head.starts_with(SEVENZ_MAGIC) && head[6] == 0 && head[8..32].iter().all(|&b| b == 0) {
        return Some(SEVENZ_REFUSE_ZERO_START);
    }
    let start = sevenz_start(&head)?;
    if start.header_size > SEVENZ_END_MAX {
        return Some(SEVENZ_REFUSE_HEADER);
    }
    let Some(off) = 32u64.checked_add(start.header_off) else {
        return Some(SEVENZ_REFUSE_HEADER);
    };
    let mut window = vec![0u8; start.header_size as usize];
    if f.seek(io::SeekFrom::Start(off)).is_err() || f.read_exact(&mut window).is_err() {
        return None;
    }
    if encoded_header_bomb(&window) {
        return Some(SEVENZ_REFUSE_HEADER);
    }
    if !check_content {
        return None;
    }
    let decl = match window.first() {
        Some(&K_HEADER) => header_content_decl(&window),
        Some(&K_ENCODED_HEADER) => match decode_packed_header(f, &window) {
            PackedHeader::Bytes(h) if h.first() == Some(&K_HEADER) => header_content_decl(&h),
            PackedHeader::Bytes(_) | PackedHeader::Opaque => None,
            PackedHeader::Refuse => return Some(SEVENZ_REFUSE_HEADER_CHAIN),
        },
        _ => None,
    };
    let decl = decl?;
    let file_len = f.seek(io::SeekFrom::End(0)).ok()?;
    content_declared_bomb(&decl, file_len).then_some(SEVENZ_REFUSE_CONTENT)
}

/// Scan a real (stored or already-decoded) header's kMainStreamsInfo.
/// `header[0]` is `K_HEADER`; None when there is no streams info to
/// judge or the bytes do not scan (the library errors on them too).
fn header_content_decl(header: &[u8]) -> Option<StreamsDecl> {
    let mut s = Scan { b: header, i: 1 };
    let mut nid = s.u8()?;
    if nid == K_ARCHIVE_PROPERTIES {
        loop {
            let id = s.u8()?;
            if id == K_END {
                break;
            }
            let size = s.num()?;
            s.skip(usize::try_from(size).ok()?)?;
        }
        nid = s.u8()?;
    }
    if nid != K_MAIN_STREAMS_INFO {
        return None;
    }
    streams_info_declared(&mut s)
}

/// The CONTENT half of the declared-size verdict: true when any block
/// declares decoder memory (LZMA dictionaries plus PPMd model sizes)
/// past what [`SEVENZ_CONTENT_COST_FLOOR`] and
/// [`SEVENZ_CONTENT_FILTER_ALLOWANCE`] pass for free, and past what its
/// own packed bytes justify.
///
/// The asymmetry this keys on: a bomb is a tiny posted file whose
/// declarations buy a huge allocation, while a real archive's memory
/// use is proportionate to real content. Declared UNPACK sizes cannot
/// carry the judgement - inflating one costs the attacker nothing, and
/// the window is allocated before a single output byte could call the
/// bluff. Packed bytes can: the pack region must actually fit inside
/// the file, so declarations past the floor are held to the packed
/// bytes genuinely present, rounded up to the next power of two and
/// then multiplied by [`SEVENZ_CONTENT_PACK_SLACK`] - which is where
/// the compression ratio the writer achieved is paid for, since the
/// dictionary is sized to the unpacked stream and the pack bytes are
/// what is left after compressing it. A 384 MiB dictionary then
/// requires posting tens of MB of real pack data - at which point it
/// is just a big archive, which passes on its own weight. What this
/// refuses beyond bombs: an archive whose dictionary exceeds 64 MiB,
/// exceeds eight times its own packed bytes, AND was sized to the full
/// unpacked stream rather than capped by a `-md` setting - i.e. a
/// past-Ultra dictionary on data that compressed better than 4:1.
/// That corner is accepted: the refusal is a named job failure, not a
/// crash.
///
/// The free pass is in two parts because a block is not always one
/// coder. No single coder window may exceed the floor - that is the
/// part a bomb cannot get around, and for a one-coder block it is the
/// whole rule, unchanged. On top of it a chain may sum to
/// [`SEVENZ_CONTENT_FILTER_ALLOWANCE`] more, which buys the auxiliary
/// coders of a BCJ2 chain and nothing on the scale of a bomb.
fn content_declared_bomb(decl: &StreamsDecl, file_len: u64) -> bool {
    let total_pack = decl
        .pack_sizes
        .iter()
        .fold(0u64, |a, &s| a.saturating_add(s));
    // Do the declared pack streams exist at all? Sizes reaching past
    // the file's end are fiction, and fiction justifies nothing.
    let pack_region_real = 32u64
        .checked_add(decl.pack_pos)
        .and_then(|s| s.checked_add(total_pack))
        .is_some_and(|end| end <= file_len);
    let mut next_pack = 0usize;
    for b in &decl.blocks {
        let pack = decl
            .pack_sizes
            .iter()
            .skip(next_pack)
            .take(b.packed as usize)
            .fold(0u64, |a, &s| a.saturating_add(s));
        next_pack = next_pack.saturating_add(b.packed as usize);
        let cost = b.dict_size.saturating_add(b.ppmd_mem);
        let free = SEVENZ_CONTENT_COST_FLOOR.saturating_add(SEVENZ_CONTENT_FILTER_ALLOWANCE);
        if b.max_coder <= SEVENZ_CONTENT_COST_FLOOR && cost <= free {
            continue;
        }
        let allowed = pack
            .checked_next_power_of_two()
            .unwrap_or(u64::MAX)
            .saturating_mul(SEVENZ_CONTENT_PACK_SLACK);
        if !pack_region_real || cost > allowed {
            return true;
        }
    }
    false
}

/// Outcome of trying to read a packed (`kEncodedHeader`) end header's
/// decoded bytes for the content scan.
enum PackedHeader {
    /// The decoded header (or as much of it as the pack bytes
    /// produced; the library decodes the same bytes to the same
    /// prefix, so scanning it stays equivalent).
    Bytes(Vec<u8>),
    /// Cannot be seen (AES on the chain) or did not decode - the
    /// library will hit the same wall, so the content scan stands
    /// aside without a verdict.
    Opaque,
    /// An unencrypted chain no known writer compresses headers with:
    /// refuse rather than let it smuggle content declarations past the
    /// scan.
    Refuse,
}

/// Decode a packed end header in-process so the content scan can read
/// the real header it hides. Only runs shapes real writers emit - one
/// block, one pack stream, a single LZMA1/LZMA2/Copy coder - and only
/// after [`encoded_header_bomb`] has already capped the declared
/// output at [`SEVENZ_END_MAX`] and the declared dictionary at
/// [`SEVENZ_DICT_MAX`]. The dictionary handed to the decoder is
/// additionally clamped to the declared output rounded up: LZMA match
/// distances can never exceed the bytes produced, so the clamp cannot
/// change the decode, only the allocation.
fn decode_packed_header(f: &mut (impl Read + Seek), window: &[u8]) -> PackedHeader {
    let mut s = Scan { b: window, i: 1 };
    let Some(decl) = streams_info_declared(&mut s) else {
        return PackedHeader::Opaque;
    };
    let [b] = &decl.blocks[..] else {
        return PackedHeader::Refuse;
    };
    if b.has_aes {
        return PackedHeader::Opaque;
    }
    if b.coder_count != 1 || b.packed != 1 || decl.pack_sizes.len() != 1 {
        return PackedHeader::Refuse;
    }
    let unpack = decl.unpack_total;
    let pack = decl.pack_sizes[0];
    if unpack == 0 || unpack > SEVENZ_END_MAX {
        return PackedHeader::Opaque;
    }
    // A "compressed" header bigger than the largest header it could
    // decode to is not compression.
    if pack > SEVENZ_END_MAX {
        return PackedHeader::Refuse;
    }
    let Some(off) = 32u64.checked_add(decl.pack_pos) else {
        return PackedHeader::Refuse;
    };
    if f.seek(io::SeekFrom::Start(off)).is_err() {
        return PackedHeader::Opaque;
    }
    let mut packed = vec![0u8; pack as usize];
    if f.read_exact(&mut packed).is_err() {
        return PackedHeader::Opaque;
    }
    // 4 KiB is LZMA's smallest window; unpack is <= 2 MiB here.
    let need = unpack.next_power_of_two().max(1 << 12) as u32;
    let mut out = Vec::new();
    let done = match b.first_coder {
        ScannedCoder::Copy => {
            packed.truncate(unpack as usize);
            out = packed;
            true
        }
        ScannedCoder::Lzma1 { props, dict } => lzma_rust2::LzmaReader::new_with_props(
            io::Cursor::new(&packed),
            unpack,
            props,
            dict.min(need),
            None,
        )
        .is_ok_and(|r| io::Read::take(r, unpack).read_to_end(&mut out).is_ok()),
        ScannedCoder::Lzma2 { dict } => {
            let r = lzma_rust2::Lzma2Reader::new(io::Cursor::new(&packed), dict.min(need), None);
            io::Read::take(r, unpack).read_to_end(&mut out).is_ok()
        }
        ScannedCoder::Aes | ScannedCoder::Other => return PackedHeader::Refuse,
    };
    if done && !out.is_empty() {
        PackedHeader::Bytes(out)
    } else {
        PackedHeader::Opaque
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fuzz find, 13 Aug 2026 (rar_name_probe, CI): a RAR4 block whose
    /// declared header size sits UNDER the comment shapes' fixed
    /// 13-byte CRC coverage passed the length-vs-hsize guards and the
    /// checksum then sliced past the buffer. The exact crashing bytes,
    /// verbatim from the artifact; the only legal answers are parse
    /// errors, never a panic.
    #[test]
    fn a_comment_block_shorter_than_its_crc_coverage_is_a_parse_error() {
        const CRASH: &[u8] = &[
            0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00, 0x6f, 0x97, 0x73, 0x40, 0x00, 0x0d, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8c, 0xc2, 0x75, 0x00, 0x20, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x2e, 0x3a, 0x20, 0x54, 0x68, 0xde, 0x96, 0x8c, 0xdf, 0x9e, 0x74,
            0x00, 0x80, 0x28, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for head in [CRASH, &CRASH[..CRASH.len() / 2]] {
            for declared in [head.len() as u64, 0] {
                assert!(
                    rar_head(head, declared).is_err(),
                    "crafted bytes must decline, not parse"
                );
            }
        }
    }

    /// A real single-entry 7z built by sevenz-rust2 itself (dev-dep has
    /// the `compress` feature), so the parse path is tested against
    /// bytes the library considers well-formed.
    fn fixture(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut w = sevenz_rust2::ArchiveWriter::new(std::io::Cursor::new(Vec::new())).unwrap();
        w.push_archive_entry(sevenz_rust2::ArchiveEntry::new_file(name), Some(payload))
            .unwrap();
        w.finish().unwrap().into_inner()
    }

    const NAME: &str = "Some.Show.S01E01.1080p.WEB-DL.AAC2.0.x264-GRP.mkv";

    /// Incompressible payload (deterministic LCG), so fixture geometry
    /// resembles a real media post: the body dominates and the header's
    /// pack stream sits in the tail, not up against the start header.
    fn noise(n: usize) -> Vec<u8> {
        let mut x = 0x2545F491_4F6CDD1Du64;
        (0..n)
            .map(|_| {
                x = x
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (x >> 33) as u8
            })
            .collect()
    }

    fn split_head_tail(arch: &[u8]) -> (Vec<u8>, Vec<u8>) {
        // Head = first KiB (a probe holds a whole decoded article, the
        // parser needs 32 bytes); tail = last 4 KiB, like a trailing
        // segment fetch would produce.
        let head = arch[..arch.len().min(1024)].to_vec();
        let tail = arch[arch.len().saturating_sub(4096)..].to_vec();
        (head, tail)
    }

    #[test]
    fn recovers_the_inner_name_from_head_plus_tail() {
        let arch = fixture(NAME, &noise(65536));
        let (head, tail) = split_head_tail(&arch);
        let entries = sevenz_tail_names(&head, &tail).unwrap();
        assert_eq!(pick_media_name(&entries).as_deref(), Some(NAME));
    }

    #[test]
    fn whole_archive_as_tail_also_works() {
        // Tiny archive, generous fetch: the tail buffer covers the
        // whole file and overlaps the head chunk.
        let arch = fixture(NAME, b"tiny");
        let entries = sevenz_tail_names(&arch[..64], &arch).unwrap();
        assert_eq!(pick_media_name(&entries).as_deref(), Some(NAME));
    }

    #[test]
    fn start_header_rejects_garbage_and_truncation() {
        assert!(sevenz_start(&[0u8; 40]).is_none());
        let arch = fixture(NAME, b"x");
        assert!(sevenz_start(&arch[..31]).is_none());
        let mut bad = arch.clone();
        bad[13] ^= 1; // breaks the start-header CRC
        assert!(sevenz_start(&bad).is_none());
    }

    #[test]
    fn wrong_tail_window_is_a_crc_mismatch_not_a_name() {
        let arch = fixture(NAME, &noise(65536));
        let (head, mut tail) = split_head_tail(&arch);
        let start = sevenz_start(&head).unwrap();
        let last = tail.len() - 1;
        tail[last] ^= 1;
        assert_eq!(
            locate_end_header(&start, &tail),
            Err(ProbeError::TailCrcMismatch)
        );
    }

    #[test]
    fn short_tail_reports_tail_short() {
        let arch = fixture(NAME, &noise(65536));
        let (head, _) = split_head_tail(&arch);
        let start = sevenz_start(&head).unwrap();
        let short = vec![0u8; (start.header_size - 1) as usize];
        assert_eq!(
            locate_end_header(&start, &short),
            Err(ProbeError::TailShort)
        );
    }

    #[test]
    fn packed_header_without_its_pack_stream_is_unreachable() {
        // The writer LZMA-packs small headers (kEncodedHeader), placing
        // the pack stream directly before the end header. Hand the
        // parser ONLY the end-header window and that stream is a gap -
        // the outcome a too-short trailing fetch produces in the wild.
        let arch = fixture(NAME, &noise(65536));
        let (head, _) = split_head_tail(&arch);
        let start = sevenz_start(&head).unwrap();
        let window = &arch[arch.len() - start.header_size as usize..];
        assert_eq!(
            sevenz_tail_names(&head, window),
            Err(ProbeError::HeaderUnreachable)
        );
    }

    #[test]
    fn encrypted_header_reports_the_canary() {
        // A real -mhe archive: AES content method + the writer's
        // default encrypt_header=true. The probe must say "encrypted",
        // not fold it into parse noise - it is the telemetry canary.
        let mut w = sevenz_rust2::ArchiveWriter::new(std::io::Cursor::new(Vec::new())).unwrap();
        w.set_content_methods(vec![
            sevenz_rust2::encoder_options::AesEncoderOptions::new(sevenz_rust2::Password::from(
                "secret",
            ))
            .into(),
        ]);
        w.push_archive_entry(
            sevenz_rust2::ArchiveEntry::new_file(NAME),
            Some(&noise(4096)[..]),
        )
        .unwrap();
        let arch = w.finish().unwrap().into_inner();
        let (head, tail) = split_head_tail(&arch);
        assert_eq!(
            sevenz_tail_names(&head, &tail),
            Err(ProbeError::EncryptedHeader)
        );
    }

    #[test]
    fn oversized_declared_header_is_capped_before_any_work() {
        let arch = fixture(NAME, b"y");
        let mut head = arch[..64].to_vec();
        head[20..28].copy_from_slice(&(SEVENZ_END_MAX + 1).to_le_bytes());
        let reseal = crc32fast::hash(&head[12..32]);
        head[8..12].copy_from_slice(&reseal.to_le_bytes());
        let start = sevenz_start(&head).unwrap();
        assert_eq!(
            locate_end_header(&start, &arch),
            Err(ProbeError::HeaderTooBig)
        );
    }

    /// A handcrafted kEncodedHeader window: one LZMA-coded block whose
    /// pack stream is 16 bytes and whose decoded size is `declared`.
    /// Grammar-valid up to kCodersUnpackSize, which is all the gate
    /// reads; the pack bytes themselves can be garbage.
    fn encoded_window(declared: u64) -> Vec<u8> {
        let mut w = vec![
            0x17, // kEncodedHeader
            0x06, 0x00, 0x01, // kPackInfo: pack_pos=0, one pack stream
            0x09, 0x10, // kSize: 16 pack bytes
            0x00, // kEnd (pack info)
            0x07, 0x0B, 0x01, 0x00, // kUnpackInfo, kFolder, 1 block, internal
            0x01, // one coder
            0x23, 0x03, 0x01, 0x01, // flags: 3-byte id + attrs; LZMA
            0x05, 0x5D, 0x00, 0x00, 0x10, 0x00, // 5 props bytes
            0x0C, // kCodersUnpackSize
        ];
        w.push(0xFF); // 8-byte number form
        w.extend_from_slice(&declared.to_le_bytes());
        w.extend_from_slice(&[0x00, 0x00]); // kEnd (unpack info), kEnd
        w
    }

    /// Seal `window` behind a CRC-valid start header with 16 pack bytes
    /// between them, the geometry a real packed-header archive has.
    fn seal(window: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut head = Vec::with_capacity(32);
        head.extend_from_slice(SEVENZ_MAGIC);
        head.extend_from_slice(&[0x00, 0x04, 0, 0, 0, 0]);
        head.extend_from_slice(&16u64.to_le_bytes()); // header_off
        head.extend_from_slice(&(window.len() as u64).to_le_bytes());
        head.extend_from_slice(&crc32fast::hash(window).to_le_bytes());
        let crc = crc32fast::hash(&head[12..32]);
        head[8..12].copy_from_slice(&crc.to_le_bytes());
        let mut tail = vec![0xAB; 16]; // the (garbage) pack stream
        tail.extend_from_slice(window);
        (head, tail)
    }

    #[test]
    fn bomb_declaring_packed_header_is_rejected_before_decode() {
        // Declares 512 MiB of decoded header out of 16 pack bytes - the
        // shape of an LZMA header bomb. Must die at the size gate, not
        // in the decoder.
        let (head, tail) = seal(&encoded_window(512 << 20));
        assert_eq!(
            sevenz_tail_names(&head, &tail),
            Err(ProbeError::HeaderTooBig)
        );
    }

    #[test]
    fn small_declared_packed_header_passes_the_gate() {
        // Same window declaring a sane size: the gate must let it
        // through to the real parser (which then fails on the garbage
        // pack bytes - any error but HeaderTooBig proves the gate is
        // keyed on the declaration, not on kEncodedHeader itself).
        let (head, tail) = seal(&encoded_window(100));
        let err = sevenz_tail_names(&head, &tail).unwrap_err();
        assert_ne!(err, ProbeError::HeaderTooBig, "gate overrejected: {err}");
    }

    /// Like [`encoded_window`] but the coder is PPMd with the given
    /// props memSize, declaring a tiny (64-byte) decoded size - the
    /// unpack cap alone would wave it through.
    fn ppmd_window(mem: u32) -> Vec<u8> {
        let mut w = vec![
            0x17, // kEncodedHeader
            0x06, 0x00, 0x01, // kPackInfo: pack_pos=0, one pack stream
            0x09, 0x10, // kSize: 16 pack bytes
            0x00, // kEnd (pack info)
            0x07, 0x0B, 0x01, 0x00, // kUnpackInfo, kFolder, 1 block, internal
            0x01, // one coder
            0x23, // flags: 3-byte id + attrs
        ];
        w.extend_from_slice(&SEVENZ_ID_PPMD);
        w.push(0x05); // 5 props bytes: order, then memSize LE
        w.push(0x06); // order
        w.extend_from_slice(&mem.to_le_bytes());
        w.push(0x0C); // kCodersUnpackSize
        w.push(0xFF); // 8-byte number form
        w.extend_from_slice(&64u64.to_le_bytes());
        w.extend_from_slice(&[0x00, 0x00]); // kEnd (unpack info), kEnd
        w
    }

    #[test]
    fn ppmd_mem_bomb_is_rejected_before_decode() {
        // The fuzz-found shape: declared output is tiny (the unpack cap
        // passes it) but the PPMd props declare ~4 GiB of model memory,
        // which Ppmd7Decoder::new would allocate whole before decoding
        // a byte. Must die at the gate.
        let (head, tail) = seal(&ppmd_window(0xF923_EF0F));
        assert_eq!(
            sevenz_tail_names(&head, &tail),
            Err(ProbeError::HeaderTooBig)
        );
    }

    #[test]
    fn ppmd_with_sane_mem_passes_the_gate() {
        // Same window with a modest memSize: the gate must key on the
        // declaration, not on the PPMd method id (any error but
        // HeaderTooBig proves it reached the real parser).
        let (head, tail) = seal(&ppmd_window(1 << 20));
        let err = sevenz_tail_names(&head, &tail).unwrap_err();
        assert_ne!(err, ProbeError::HeaderTooBig, "gate overrejected: {err}");
    }

    #[test]
    fn scanner_agrees_with_the_library_on_a_real_packed_header() {
        // The writer LZMA-packs small headers, so the fixture's end
        // header is a genuine kEncodedHeader: the pre-scan must parse
        // it and see a tiny declared size, and the full probe must
        // still recover the name (the no-regression half of the gate).
        let arch = fixture(NAME, &noise(65536));
        let (head, tail) = split_head_tail(&arch);
        let start = sevenz_start(&head).unwrap();
        let window = locate_end_header(&start, &tail).unwrap();
        assert_eq!(window[0], K_ENCODED_HEADER);
        let declared = encoded_header_declared_cost(window).expect("scan the real window");
        assert!(declared.unpack > 0 && declared.unpack <= SEVENZ_END_MAX);
        assert_eq!(declared.ppmd_mem, 0, "writer headers are LZMA, not PPMd");
        let entries = sevenz_tail_names(&head, &tail).unwrap();
        assert_eq!(pick_media_name(&entries).as_deref(), Some(NAME));
    }

    /// A `-mhe` container must answer the on-disk password question the
    /// same way the in-stream probe answers it, and a plain one must not
    /// claim to need a password. Without the disk-side answer, the
    /// daemon's post-processing (which only ever looked for encrypted
    /// RARs) ended an encrypted-7z job as a generic local unpack failure
    /// with no password prompt - soak round 3, 11 Aug, advQ.
    #[test]
    fn a_header_encrypted_sevenz_is_known_to_need_a_password_on_disk() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sevenz");
        assert!(
            sevenz_needs_password(std::path::Path::new(&format!("{dir}/header-encrypted.7z"))),
            "-mhe container must ask for a password"
        );
        assert!(
            !sevenz_needs_password(std::path::Path::new(&format!("{dir}/store-single.7z"))),
            "a plain store container needs no password"
        );
        assert!(
            !sevenz_needs_password(std::path::Path::new(&format!("{dir}/does-not-exist.7z"))),
            "a missing file is not a password question"
        );
    }

    /// The disk-side probe must share the in-stream twin's bomb gate:
    /// a file whose packed end header declares hundreds of MB of
    /// decoded header (or a ~4 GiB PPMd model) must be refused BEFORE
    /// `Archive::read` allocates on the declaration's say-so, and a
    /// declared `header_size` past the cap must be refused before it is
    /// even buffered. The gate verdict is asserted directly because the
    /// end-to-end boolean cannot see it: on the garbage pack bytes the
    /// fixtures carry, the library's decode happens to error out with
    /// the same "no" the gate gives, just after requesting the
    /// allocations the gate exists to prevent.
    #[test]
    fn disk_probe_refuses_bomb_declarations_before_decoding() {
        // seal() places the window at 32 + header_off, so head ++ tail
        // IS the on-disk container the start header describes.
        let refused = |head: &[u8], tail: &[u8]| {
            let mut f = std::io::Cursor::new([head, tail].concat());
            sevenz_disk_header_bomb(&mut f)
        };
        let (head, tail) = seal(&encoded_window(512 << 20));
        assert!(
            refused(&head, &tail),
            "an LZMA header bomb must die at the gate, not in the decoder"
        );
        let (head, tail) = seal(&ppmd_window(0xF923_EF0F));
        assert!(
            refused(&head, &tail),
            "a PPMd memSize bomb must die at the gate, not in the decoder"
        );
        // Stored-header size bomb: a start header declaring a 2 GiB end
        // header, which Archive::read would buffer whole.
        let arch = fixture(NAME, b"y");
        let mut head = arch[..32].to_vec();
        head[20..28].copy_from_slice(&(2u64 << 30).to_le_bytes());
        let reseal = crc32fast::hash(&head[12..32]);
        head[8..12].copy_from_slice(&reseal.to_le_bytes());
        assert!(
            refused(&head, &arch[32..]),
            "an oversize declared header_size must be refused unbuffered"
        );
        // The gate must not eat the honest answers: benign containers
        // (the writer packs headers, so this IS a kEncodedHeader) and
        // the -mhe fixture must pass through to the real parser. The
        // encrypted one still answering "yes" end to end is pinned by
        // a_header_encrypted_sevenz_is_known_to_need_a_password_on_disk.
        assert!(!refused(&arch, &[]), "a benign packed header must pass");
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sevenz");
        let enc = std::fs::read(format!("{dir}/header-encrypted.7z")).unwrap();
        assert!(!refused(&enc, &[]), "-mhe must stay a password question");
        // End to end: a refused file is not a readable 7z, so the
        // password answer is "no" - via the gate, not the decoder.
        let tmp = std::env::temp_dir().join(format!("nzbkit-np-bomb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let (head, tail) = seal(&encoded_window(512 << 20));
        let p = tmp.join("lzma-bomb.7z");
        std::fs::write(&p, [head, tail].concat()).unwrap();
        assert!(!sevenz_needs_password(&p));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// 7z variable-length integer, the encoder half of `Scan::num`.
    fn write_num(out: &mut Vec<u8>, value: u64) {
        let mut first = 0u8;
        let mut mask = 0x80u8;
        let mut extra = 0usize;
        while extra < 8 {
            if value < (1u64 << (7 * (extra + 1))) {
                first |= (value >> (8 * extra)) as u8;
                break;
            }
            first |= mask;
            mask >>= 1;
            extra += 1;
        }
        out.push(first);
        for j in 0..extra {
            out.push((value >> (8 * j)) as u8);
        }
    }

    /// A stored (kHeader) end header declaring one LZMA2 content block:
    /// `props` picks the dictionary, the declared pack/unpack sizes are
    /// the test's to choose. `extras` lands inside the streams info
    /// (sub-streams section) and `tail` after it (files info), for
    /// fixtures that must fully parse; gate-only fixtures pass empty.
    fn content_header_full(
        props: u8,
        declared_pack: u64,
        declared_unpack: u64,
        extras: &[u8],
        tail: &[u8],
    ) -> Vec<u8> {
        let mut h = vec![K_HEADER, K_MAIN_STREAMS_INFO, K_PACK_INFO];
        write_num(&mut h, 0); // pack_pos
        write_num(&mut h, 1); // one pack stream
        h.push(K_SIZE);
        write_num(&mut h, declared_pack);
        h.push(K_END);
        h.extend_from_slice(&[K_UNPACK_INFO, K_FOLDER]);
        write_num(&mut h, 1); // one block
        h.push(0); // stored inline, not external
        write_num(&mut h, 1); // one coder
        h.extend_from_slice(&[0x21, 0x21]); // 1-byte id + props attr; LZMA2
        write_num(&mut h, 1); // props length
        h.push(props);
        h.push(K_CODERS_UNPACK_SIZE);
        write_num(&mut h, declared_unpack);
        h.push(K_END); // unpack info
        h.extend_from_slice(extras);
        h.push(K_END); // streams info
        h.extend_from_slice(tail);
        h.push(K_END); // header
        h
    }

    /// [`content_header_full`] for the gate-only fixtures, which never
    /// need to parse past the sizes.
    fn content_header(props: u8, declared_pack: u64, declared_unpack: u64) -> Vec<u8> {
        content_header_full(props, declared_pack, declared_unpack, &[], &[])
    }

    /// [`content_header`] with a CHAIN of LZMA2 coders in one block -
    /// the shape a filter chain has, and the shape the per-block floor
    /// was never calibrated for. Each coder takes one stream in and
    /// puts one out, so the folder carries `props.len() - 1` bind pairs
    /// and exactly one pack stream, and `kCodersUnpackSize` carries one
    /// size per coder.
    fn content_header_chain(props: &[u8], declared_pack: u64, declared_unpack: u64) -> Vec<u8> {
        let mut h = vec![K_HEADER, K_MAIN_STREAMS_INFO, K_PACK_INFO];
        write_num(&mut h, 0); // pack_pos
        write_num(&mut h, 1); // one pack stream
        h.push(K_SIZE);
        write_num(&mut h, declared_pack);
        h.push(K_END);
        h.extend_from_slice(&[K_UNPACK_INFO, K_FOLDER]);
        write_num(&mut h, 1); // one block
        h.push(0); // stored inline, not external
        write_num(&mut h, props.len() as u64);
        for &p in props {
            h.extend_from_slice(&[0x21, 0x21]); // 1-byte id + props attr; LZMA2
            write_num(&mut h, 1); // props length
            h.push(p);
        }
        for i in 1..props.len() as u64 {
            write_num(&mut h, i); // in index
            write_num(&mut h, i - 1); // out index
        }
        h.push(K_CODERS_UNPACK_SIZE);
        for _ in props {
            write_num(&mut h, declared_unpack);
        }
        h.push(K_END); // unpack info
        h.push(K_END); // streams info
        h.push(K_END); // header
        h
    }

    /// Seal pack bytes + a stored end header into an on-disk container.
    fn seal_disk(pack: &[u8], header: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(SEVENZ_MAGIC);
        f.extend_from_slice(&[0x00, 0x04]);
        f.extend_from_slice(&[0u8; 24]);
        f.extend_from_slice(pack);
        f.extend_from_slice(header);
        let off = pack.len() as u64;
        f[12..20].copy_from_slice(&off.to_le_bytes());
        f[20..28].copy_from_slice(&(header.len() as u64).to_le_bytes());
        f[28..32].copy_from_slice(&crc32fast::hash(header).to_le_bytes());
        let crc = crc32fast::hash(&f[12..32]);
        f[8..12].copy_from_slice(&crc.to_le_bytes());
        f
    }

    /// A fully extractable single-file 7z whose LZMA2 content stream is
    /// hand-built from STORED chunks - so a test can declare any
    /// dictionary size without paying for a real compression pass, and
    /// the decode side still allocates and runs exactly what the props
    /// byte declares.
    fn extractable_lzma2_7z(props: u8, payload: &[u8]) -> Vec<u8> {
        let mut stream = Vec::new();
        let mut first = true;
        for chunk in payload.chunks(0x10000) {
            // LZMA2 stored chunk: 0x01 resets the dictionary (required
            // at stream start), 0x02 preserves it; then len-1 as u16be.
            stream.push(if first { 1 } else { 2 });
            first = false;
            stream.extend_from_slice(&((chunk.len() - 1) as u16).to_be_bytes());
            stream.extend_from_slice(chunk);
        }
        stream.push(0); // end of stream
        const K_SUB_STREAMS_INFO: u8 = 0x08;
        const K_FILES_INFO: u8 = 0x05;
        const K_NAME: u8 = 0x11;
        // Sub-streams with all defaults: one file per block, size =
        // the block's unpack size, no CRCs.
        let sub = [K_SUB_STREAMS_INFO, K_END];
        let mut files = vec![K_FILES_INFO];
        write_num(&mut files, 1); // one file
        files.push(K_NAME);
        let name: Vec<u8> = "a.bin\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        write_num(&mut files, 1 + name.len() as u64);
        files.push(0); // names stored inline
        files.extend_from_slice(&name);
        files.push(K_END); // files-info property list
        let header = content_header_full(
            props,
            stream.len() as u64,
            payload.len() as u64,
            &sub,
            &files,
        );
        seal_disk(&stream, &header)
    }

    fn extract_single(archive: &[u8]) -> Vec<u8> {
        let mut r = sevenz_rust2::ArchiveReader::new(
            std::io::Cursor::new(archive.to_vec()),
            sevenz_rust2::Password::empty(),
        )
        .expect("crafted archive must parse");
        let mut out = Vec::new();
        r.for_each_entries(|_, rd| {
            std::io::Read::read_to_end(rd, &mut out)?;
            Ok(true)
        })
        .expect("crafted archive must extract");
        out
    }

    #[test]
    fn a_zeroed_start_header_is_refused_before_the_recovery_scan() {
        // The recovered-header bypass: real magic, a ZERO start-header
        // CRC and twenty zero geometry bytes. sevenz_start says None,
        // but Archive::read treats exactly this shape as header_valid =
        // false and scans the last MiB for a kEncodedHeader to decode
        // with no CRC check and no memory limit - here, the checked-in
        // 384 MiB dictionary window. The gate must refuse it up front.
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sevenz");
        let window = std::fs::read(format!("{dir}/lzma2-dict-window.bin")).unwrap();
        let mut file = Vec::new();
        file.extend_from_slice(SEVENZ_MAGIC);
        file.extend_from_slice(&[0x00, 0x04]);
        file.extend_from_slice(&[0u8; 24]);
        file.extend_from_slice(&window);
        let mut f = std::io::Cursor::new(file.clone());
        assert!(sevenz_disk_header_bomb(&mut f), "zeroed start must refuse");
        let mut f = std::io::Cursor::new(file.clone());
        assert_eq!(
            sevenz_disk_declared_bomb(&mut f),
            Some(SEVENZ_REFUSE_ZERO_START)
        );
        // A zero CRC field with NONZERO geometry is a different shape:
        // the library reads the start header and fails its checksum
        // cheaply, so the gate must keep standing aside.
        let mut nonzero = file;
        nonzero[13] = 1;
        let mut f = std::io::Cursor::new(nonzero.clone());
        assert!(!sevenz_disk_header_bomb(&mut f));
        assert!(
            sevenz_rust2::Archive::read(
                &mut std::io::Cursor::new(nonzero),
                &sevenz_rust2::Password::empty()
            )
            .is_err(),
            "the library refuses the nonzero-geometry shape itself"
        );
    }

    #[test]
    fn content_dict_bomb_with_tiny_pack_is_refused() {
        // A content block declaring a 384 MiB LZMA2 dictionary (props
        // 0x21) out of 16 packed bytes: the header-scoped caps never
        // see content coders, and the library would zero-fill the whole
        // window before one output byte. The content gate keys on the
        // asymmetry.
        let file = seal_disk(&[0xAB; 16], &content_header(0x21, 16, 100));
        let mut f = std::io::Cursor::new(file.clone());
        assert_eq!(
            sevenz_disk_declared_bomb(&mut f),
            Some(SEVENZ_REFUSE_CONTENT)
        );
        // The header-only gate (probe and password callers) stays out
        // of content judgements.
        let mut f = std::io::Cursor::new(file);
        assert!(!sevenz_disk_header_bomb(&mut f));
    }

    #[test]
    fn ultra_preset_dict_passes_on_the_floor() {
        // Props 28 = a 64 MiB dictionary, what 7-Zip's Ultra preset
        // declares no matter how small the data: always accepted, even
        // with a tiny pack stream.
        let file = seal_disk(&[0xAB; 16], &content_header(28, 16, 100));
        let mut f = std::io::Cursor::new(file);
        assert_eq!(sevenz_disk_declared_bomb(&mut f), None);
    }

    #[test]
    fn stock_bcj2_ultra_archive_of_an_executable_extracts() {
        // 7-Zip picks BCJ2 automatically for executable content at -mx7
        // and above, and BCJ2 is FOUR coders in ONE block. Stock
        // output, no crafted bytes - 7-Zip 26.02 on macOS:
        //
        //   head -c 4096 <any x86 binary> > f.exe
        //   head -c 67104768 /dev/zero >> f.exe
        //   7zz a -t7z -mx9 -md=64m -mf=BCJ2 bcj2-ultra-exe.7z f.exe
        //
        // (-mf=BCJ2 forces on an arm64 Mac what content analysis picks
        // by itself for a real PE; `7zz l -slt` then says `BCJ2
        // LZMA2:26 LZMA:20:lc0:lp2 LZMA:20:lc0:lp2`, i.e. 64 + 1 + 1
        // MiB out of 10,801 bytes on disk.) Summed against a floor
        // calibrated for one dictionary, 66 MiB cleared 64 MiB by two,
        // fell through to the packed-bytes rule and lost: TODO 268, and
        // four of nine real self-extractors on a real box.
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sevenz");
        let arc = std::fs::read(format!("{dir}/bcj2-ultra-exe.7z")).unwrap();
        let mut f = std::io::Cursor::new(arc.clone());
        assert_eq!(
            sevenz_disk_declared_bomb(&mut f),
            None,
            "7-Zip's own Ultra preset on an executable must not be refused"
        );
        // And all the way through the library, which is the claim that
        // matters: the gate is the only thing between a caller and this
        // decode.
        let mut r = sevenz_rust2::ArchiveReader::new(
            std::io::Cursor::new(arc),
            sevenz_rust2::Password::empty(),
        )
        .expect("stock 7-Zip output must parse");
        let mut out = 0u64;
        r.for_each_entries(|_, rd| {
            out += std::io::copy(rd, &mut std::io::sink())?;
            Ok(true)
        })
        .expect("stock 7-Zip output must extract");
        assert_eq!(out, 64 << 20, "the whole payload must come back");
    }

    #[test]
    fn a_filter_chain_gets_the_allowance_and_a_bomb_cannot_spend_it() {
        // Same arithmetic as the fixture above, hand-built so the rule
        // is stated rather than inferred: props 28 = 64 MiB, props 16 =
        // 1 MiB. 64 + 1 + 1 out of 16 packed bytes passes.
        let pass = seal_disk(&[0xAB; 16], &content_header_chain(&[28, 16, 16], 16, 100));
        let mut f = std::io::Cursor::new(pass);
        assert_eq!(sevenz_disk_declared_bomb(&mut f), None);
        // Individually modest, JOINTLY large: four 64 MiB dictionaries
        // in one block is 256 MiB a decode would hold at once, and 16
        // packed bytes justify none of it. This is the side of the line
        // the flat allowance is chosen for - it must still refuse.
        let joint = seal_disk(
            &[0xAB; 16],
            &content_header_chain(&[28, 28, 28, 28], 16, 100),
        );
        let mut f = std::io::Cursor::new(joint);
        assert_eq!(
            sevenz_disk_declared_bomb(&mut f),
            Some(SEVENZ_REFUSE_CONTENT),
            "eight-figure decoder memory is not a filter chain"
        );
        // And the allowance is not spendable on ONE oversized window:
        // props 29 = 96 MiB, past the floor by itself, paired with a
        // second coder small enough to keep the sum modest.
        let single = seal_disk(&[0xAB; 16], &content_header_chain(&[29, 16], 16, 100));
        let mut f = std::io::Cursor::new(single);
        assert_eq!(
            sevenz_disk_declared_bomb(&mut f),
            Some(SEVENZ_REFUSE_CONTENT),
            "a second coder must not launder a past-floor dictionary"
        );
    }

    #[test]
    fn a_well_compressed_vendor_chain_passes_on_the_pack_slack() {
        // TODO 269, measured on a Windows 11 box out of TODO 268's own
        // verification run: Microsoft's Copilot/Edge update packages
        // carve to a 7z whose single block is `BCJ2 LZMA:27 LZMA:22
        // LZMA:22` - 128 + 4 + 4 = 136 MiB declared against 43,902,179
        // packed bytes, which round up to only 64 MiB. Four of them on
        // one box extracted ZERO files. The main coder alone is 128
        // MiB, so no floor can reach this; the ratio is what was wrong,
        // because a dictionary is sized to the UNPACKED stream and this
        // content compresses 3.6:1.
        //
        // Synthetic rather than the real 44 MB archive, but the same
        // arithmetic: LZMA2 props 30 = 128 MiB, props 20 = 4 MiB.
        const PACK: usize = 43_902_179;
        let pack = vec![0u8; PACK];
        let hdr = content_header_chain(&[30, 20, 20], PACK as u64, 157_716_330);
        let file = seal_disk(&pack, &hdr);
        let mut f = std::io::Cursor::new(file);
        assert_eq!(
            sevenz_disk_declared_bomb(&mut f),
            None,
            "a vendor packer's 136 MiB window over 44 MB of real pack bytes must pass"
        );
        // And the slack is bounded, which is the whole security claim:
        // npot(43,902,179) is 64 MiB, so SEVENZ_CONTENT_PACK_SLACK
        // allows 256 MiB and no more. Props 33 = 384 MiB, and posting
        // 44 MB of genuine pack bytes still does not buy it.
        let over = seal_disk(
            &pack,
            &content_header_chain(&[33, 20, 20], PACK as u64, 157_716_330),
        );
        let mut f = std::io::Cursor::new(over);
        assert_eq!(
            sevenz_disk_declared_bomb(&mut f),
            Some(SEVENZ_REFUSE_CONTENT),
            "the slack is a bounded multiple, not an open door"
        );
    }

    #[test]
    fn big_dict_backed_by_real_pack_bytes_passes() {
        // Props 29 = a 96 MiB dictionary, past the floor - legitimate
        // when the archive actually carries data on that scale. 65 MiB
        // of packed bytes genuinely present round up past the
        // declaration, so it passes.
        let pack = vec![0u8; 65 << 20];
        let file = seal_disk(&pack, &content_header(29, pack.len() as u64, 90 << 20));
        let mut f = std::io::Cursor::new(file);
        assert_eq!(sevenz_disk_declared_bomb(&mut f), None);
    }

    #[test]
    fn big_dict_with_fictional_pack_sizes_is_refused() {
        // Same 96 MiB declaration, but the 65 MiB of pack bytes are
        // DECLARED and not present - the region runs past the file's
        // end, and fiction justifies nothing.
        let file = seal_disk(&[0xAB; 16], &content_header(29, 65 << 20, 90 << 20));
        let mut f = std::io::Cursor::new(file);
        assert_eq!(
            sevenz_disk_declared_bomb(&mut f),
            Some(SEVENZ_REFUSE_CONTENT)
        );
    }

    #[test]
    fn packed_header_content_bomb_is_seen_through_the_decode() {
        // The same content bomb hidden behind a kEncodedHeader: the
        // gate must decode the (already size-capped) packed header
        // in-process and judge what it hides. The packed header is a
        // genuine LZMA stream, exactly what real writers emit.
        let build = |props: u8| {
            let inner = content_header(props, 16, 100);
            use std::io::Write as _;
            let mut opts = lzma_rust2::LzmaOptions::with_preset(6);
            opts.dict_size = 1 << 16;
            let mut w = lzma_rust2::LzmaWriter::new_no_header(Vec::new(), &opts, false).unwrap();
            w.write_all(&inner).unwrap();
            let lclppb = w.props();
            let comp = w.finish().unwrap();
            let mut win = vec![K_ENCODED_HEADER, K_PACK_INFO];
            write_num(&mut win, 0); // pack_pos: the compressed header sits at 32
            write_num(&mut win, 1);
            win.push(K_SIZE);
            write_num(&mut win, comp.len() as u64);
            win.push(K_END);
            win.extend_from_slice(&[K_UNPACK_INFO, K_FOLDER]);
            write_num(&mut win, 1);
            win.push(0);
            write_num(&mut win, 1); // one coder
            win.push(0x23); // 3-byte id + props attr
            win.extend_from_slice(&SEVENZ_ID_LZMA1);
            write_num(&mut win, 5);
            win.push(lclppb);
            win.extend_from_slice(&(1u32 << 16).to_le_bytes());
            win.push(K_CODERS_UNPACK_SIZE);
            write_num(&mut win, inner.len() as u64);
            win.extend_from_slice(&[K_END, K_END]);
            seal_disk(&comp, &win)
        };
        let mut f = std::io::Cursor::new(build(0x21));
        assert_eq!(
            sevenz_disk_declared_bomb(&mut f),
            Some(SEVENZ_REFUSE_CONTENT),
            "a packed header must not hide a content dictionary bomb"
        );
        let mut f = std::io::Cursor::new(build(28));
        assert_eq!(
            sevenz_disk_declared_bomb(&mut f),
            None,
            "the same shape declaring the Ultra floor must pass"
        );
    }

    #[test]
    fn exotic_packed_header_chain_is_refused_not_decoded_blind() {
        // A PPMd-compressed header passes the header caps at a sane
        // memSize, but no known writer compresses headers with PPMd -
        // and the content scan cannot see through a chain it cannot
        // run. Refusing beats decoding blind.
        let (head, tail) = seal(&ppmd_window(1 << 20));
        let mut f = std::io::Cursor::new([head, tail].concat());
        assert_eq!(
            sevenz_disk_declared_bomb(&mut f),
            Some(SEVENZ_REFUSE_HEADER_CHAIN)
        );
        // An AES header chain (-mhe) is different: it is a password
        // question, not a refusal, and the content scan stands aside.
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sevenz");
        let enc = std::fs::read(format!("{dir}/header-encrypted.7z")).unwrap();
        let mut f = std::io::Cursor::new(enc);
        assert_eq!(sevenz_disk_declared_bomb(&mut f), None);
    }

    #[test]
    fn ultra_floor_archive_still_extracts_end_to_end() {
        // The no-regression half: a well-formed single-file archive
        // whose content block declares the Ultra-preset 64 MiB
        // dictionary (props 28) over a tiny payload. The gate must
        // pass it and the library must extract it byte-identical.
        let payload = b"ordinary content, ultra preset dictionary".to_vec();
        let arch = extractable_lzma2_7z(28, &payload);
        let mut f = std::io::Cursor::new(arch.clone());
        assert_eq!(sevenz_disk_declared_bomb(&mut f), None);
        assert_eq!(extract_single(&arch), payload);
    }

    #[test]
    fn big_dict_archive_still_extracts_end_to_end() {
        // A user-selected 96 MiB dictionary (props 29) over 65 MiB of
        // incompressible payload: past the floor, justified by its own
        // packed bytes, and it must both pass the gate and extract.
        let payload = noise(65 << 20);
        let arch = extractable_lzma2_7z(29, &payload);
        let mut f = std::io::Cursor::new(arch.clone());
        assert_eq!(sevenz_disk_declared_bomb(&mut f), None);
        assert_eq!(extract_single(&arch), payload);
    }

    #[test]
    fn writer_archives_pass_the_content_gate() {
        // Real sevenz-rust2 writer output (LZMA-packed header, LZMA2
        // content at the default dictionary) must sail through the
        // full declared gate.
        let arch = fixture(NAME, &noise(65536));
        let mut f = std::io::Cursor::new(arch);
        assert_eq!(sevenz_disk_declared_bomb(&mut f), None);
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sevenz");
        let store = std::fs::read(format!("{dir}/store-single.7z")).unwrap();
        let mut f = std::io::Cursor::new(store);
        assert_eq!(sevenz_disk_declared_bomb(&mut f), None);
        let bomb = std::fs::read(format!("{dir}/bomb-container.7z")).unwrap();
        let mut f = std::io::Cursor::new(bomb);
        assert_eq!(
            sevenz_disk_declared_bomb(&mut f),
            Some(SEVENZ_REFUSE_HEADER)
        );
    }

    #[test]
    fn checked_in_fuzz_seeds_keep_their_meaning() {
        // tests/fixtures/sevenz/* seed the sevenz_name_probe fuzz
        // corpus (fuzz-smoke.yml copies them in). Pin what each seed
        // IS, so a regenerated file cannot silently stop covering the
        // path it was built for.
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sevenz");
        let bomb = std::fs::read(format!("{dir}/bomb-container.7z")).unwrap();
        assert_eq!(
            sevenz_tail_names(&bomb[..32], &bomb),
            Err(ProbeError::HeaderTooBig),
            "bomb seed must die at the declared-size gate"
        );
        let real = std::fs::read(format!("{dir}/store-single.7z")).unwrap();
        let entries = sevenz_tail_names(&real[..32], &real).unwrap();
        assert_eq!(
            pick_media_name(&entries).as_deref(),
            Some("Some.Show.S01E01.1080p.WEB-DL.x264-GRP.mkv"),
            "real store-mode seed must still name itself"
        );
        // The window seeds are raw kEncodedHeader windows (the fuzz
        // target seals them into a container itself). All three are bomb
        // declarations and must die at the gate: one declares an
        // oversize decoded size, one a ~4 GiB PPMd memSize (the
        // fuzz-found OOM of 10 Aug 2026), and one a 384 MiB LZMA2
        // dictionary out of a SINGLE props byte while declaring just 9
        // bytes of output - so the unpack cap never saw it, and
        // `LzDecoder::ensure_capacity` allocated the window whole (the
        // fuzz-found OOM of 14 Aug 2026, malloc(402653184)).
        for name in [
            "bomb-encoded-header.bin",
            "ppmd-mem-window.bin",
            "lzma2-dict-window.bin",
        ] {
            let window = std::fs::read(format!("{dir}/{name}")).unwrap();
            let (head, tail) = seal(&window);
            assert_eq!(
                sevenz_tail_names(&head, &tail),
                Err(ProbeError::HeaderTooBig),
                "{name} must die at the declared-cost gate"
            );
        }
        // Whole-container seeds for the disk gate: the zeroed-start
        // shape that would otherwise reach the library's end-header
        // recovery scan, and a content-block dictionary bomb (384 MiB
        // declared out of 16 packed bytes).
        let zeroed = std::fs::read(format!("{dir}/recovered-zero-start.bin")).unwrap();
        assert_eq!(
            sevenz_disk_declared_bomb(&mut std::io::Cursor::new(zeroed)),
            Some(SEVENZ_REFUSE_ZERO_START),
            "recovered-zero-start seed must refuse before the recovery scan"
        );
        let content = std::fs::read(format!("{dir}/bomb-content-dict.7z")).unwrap();
        assert_eq!(
            sevenz_disk_declared_bomb(&mut std::io::Cursor::new(content)),
            Some(SEVENZ_REFUSE_CONTENT),
            "content-dict seed must die at the content gate"
        );
    }

    #[test]
    fn name_sanitizer_strips_paths_and_control_bytes() {
        let e = |name: &str| SevenzEntryInfo {
            name: name.into(),
            size: 10,
            has_stream: true,
        };
        assert_eq!(
            pick_media_name(&[e("dir/sub\\Evil.\u{7}Name.mkv")]).as_deref(),
            Some("Evil.Name.mkv")
        );
        assert_eq!(pick_media_name(&[e("..")]), None);
        assert_eq!(pick_media_name(&[e("   ")]), None);
        // Directory entries (no stream) never win over the payload.
        let dir = SevenzEntryInfo {
            name: "folder".into(),
            size: 0,
            has_stream: false,
        };
        assert_eq!(
            pick_media_name(&[dir, e("Real.mkv")]).as_deref(),
            Some("Real.mkv")
        );
    }

    #[test]
    fn largest_entry_wins() {
        let mk = |name: &str, size: u64| SevenzEntryInfo {
            name: name.into(),
            size,
            has_stream: true,
        };
        assert_eq!(
            pick_media_name(&[mk("sample.mkv", 5), mk("Main.Feature.mkv", 500)]).as_deref(),
            Some("Main.Feature.mkv")
        );
    }

    // ---- RAR head reads -------------------------------------------

    /// THE mechanical claim the pilot proved, in a test: a CONTINUATION
    /// volume - split before AND after, nowhere near physical volume 1 -
    /// repeats the inner file header, so its own leading bytes name the
    /// file. 11 of 14 sampled RAR4 sets named this way, off mid-set
    /// volumes (part43, part51, part19, part22).
    #[test]
    fn a_rar4_continuation_volume_names_the_file_from_its_own_head() {
        // RAR4's header keeps unpacked size in 32 bits (the high half
        // rides a separate field real archivers add and this fixture
        // does not write), so the fixture's ceiling is 4 GiB - fine, the
        // point under test is the repeated header, not the width.
        let vol =
            crate::rar::fixtures::rar4_volume(&[(NAME, 3_000_000_000, &[7u8; 64], true, true)]);
        let head = rar_head(&vol, vol.len() as u64).unwrap();
        assert!(!head.v5);
        assert_eq!(head.entries.len(), 1);
        assert_eq!(head.entries[0].name, NAME);
        assert_eq!(head.entries[0].unpacked_size, 3_000_000_000);
        let (name, key) = pick_rar_media_name(&head).unwrap();
        assert_eq!(name, NAME);
        // A split piece carries no whole-file CRC (only the final
        // fragment does), so the size alone keys it - weaker, but never
        // a constant, which would join every keyless RAR to every other.
        assert_eq!(key.as_deref(), Some("3000000000"));
    }

    /// A RAR5 numbered member surfaces the volume ordinal the bundle
    /// wanted: obfuscation-proof ordering, read from the main header.
    /// Rarely reachable in the wild only because RAR5 sets that bother
    /// to obfuscate also tend to `-hp`.
    #[test]
    fn a_rar5_member_reports_its_volume_ordinal_and_content_key() {
        let vol = crate::rar::fixtures::rar5_volume_n_crc(
            &[(
                NAME,
                4_000_000_000,
                &[9u8; 32],
                false,
                false,
                Some(0xdeadbeef),
            )],
            27,
        );
        let head = rar_head(&vol, vol.len() as u64).unwrap();
        assert!(head.v5);
        assert_eq!(head.volume_number, Some(27));
        let (name, key) = pick_rar_media_name(&head).unwrap();
        assert_eq!(name, NAME);
        assert_eq!(key.as_deref(), Some("4000000000:deadbeef"));
    }

    /// The wall, in both dialects. 24 of 26 sampled RAR5 sets and 3 of
    /// 14 RAR4 sets stop right here, and the answer must be the SAME
    /// error the 7z lane raises - the terminal `header_encrypted`
    /// classification keys off this one variant, and two spellings of
    /// one fact would leave half the band re-probed forever.
    #[test]
    fn header_encrypted_volumes_report_the_canary_in_both_dialects() {
        let v4 = crate::rar::fixtures::rar4_encrypted_headers(4096);
        assert_eq!(
            rar_head(&v4, v4.len() as u64),
            Err(ProbeError::EncryptedHeader),
            "RAR4 MHD_PASSWORD"
        );
        let f = crate::rar::fixtures::encrypt_file("pw!", &[3u8; 4096], 5);
        let v5 = crate::rar::fixtures::rar5_volume_enc_headers(
            &[("Real.Name.mkv", &f, 0..f.cipher.len(), false, false)],
            Some(12),
            "pw!",
            7,
        );
        assert_eq!(
            rar_head(&v5, v5.len() as u64),
            Err(ProbeError::EncryptedHeader),
            "RAR5 type-4 HEAD_CRYPT: the signature is the last readable byte"
        );
    }

    /// Data encryption alone (`rar -p`, plaintext headers) is NOT the
    /// wall: the names are right there. Classifying it as encrypted
    /// would retire a nameable row forever - the exact over-reach the
    /// versioned stamp exists to be able to take back.
    #[test]
    fn data_encryption_with_plain_headers_still_names() {
        let f = crate::rar::fixtures::encrypt_file("pw!", &[4u8; 2048], 6);
        let vol = crate::rar::fixtures::rar5_volume_enc(
            &[(NAME, &f, 0..f.cipher.len(), false, false)],
            Some(3),
        );
        let head = rar_head(&vol, vol.len() as u64).unwrap();
        assert_eq!(pick_rar_media_name(&head).unwrap().0, NAME);
    }

    /// Not a RAR at all, and a truncated head, both report cleanly
    /// rather than naming something. The head a probe holds is one
    /// article off the wire; nothing here may trust its shape.
    #[test]
    fn non_rar_and_truncated_heads_report_rather_than_name() {
        assert_eq!(
            rar_head(b"not an archive at all", 21),
            Err(ProbeError::BadStart)
        );
        assert_eq!(rar_head(&[], 0), Err(ProbeError::BadStart));
        let vol = crate::rar::fixtures::rar4_volume(&[("x.mkv", 100, &[1u8; 8], false, false)]);
        // Signature only, no block behind it: the mapper has not
        // committed to a version, so the honest answer is "no start
        // here" - which for a probe means fetch elsewhere, not "this
        // archive has nothing in it".
        assert_eq!(
            rar_head(&vol[..7], vol.len() as u64),
            Err(ProbeError::BadStart)
        );
    }

    /// CI's own `rar_name_probe` artifact, byte for byte: a RAR4 main
    /// header declaring `head_size` 7 while carrying `MHD_COMMENT`,
    /// whose header CRC covers a fixed 13 bytes. The target's truncated
    /// half left 12 bytes of it, and the CRC helper sliced `h[2..13]`
    /// out of them - "range end index 13 out of range for slice of
    /// length 12". A probe holds ONE article, so a torn header is the
    /// ordinary case and must be an answer, never a panic.
    ///
    /// `868b2603` fixed this against a hand-reduced input; this is the
    /// input the fuzzer actually found, kept in the tree (as
    /// `fuzz/seeds/rar_name_probe/`, replayed into the corpus by
    /// fuzz-smoke.yml) rather than left to expire with the CI artifact.
    #[test]
    fn the_torn_comment_header_repro_answers_rather_than_panicking() {
        const REPRO: &[u8] = include_bytes!(
            "../../nzbkit/fuzz/seeds/rar_name_probe/crash-f064a660a000d079ef552779894d5aa9ba76d15c"
        );
        // Both feed shapes the target drives, and both volume-size
        // configurations: the 19-byte half is the one that panicked.
        for head in [REPRO, &REPRO[..REPRO.len() / 2]] {
            for declared in [head.len() as u64, 0] {
                assert!(
                    rar_head(head, declared).is_err(),
                    "a header too short for its own CRC range named something"
                );
            }
        }
    }

    /// The uploader's string is untrusted exactly like the 7z lane's:
    /// path components, control characters and `..` never reach a title.
    #[test]
    fn rar_inner_names_are_sanitised_like_every_other_uploader_string() {
        let mk = |name: &str, size: u64| RarHead {
            v5: true,
            volume_number: None,
            entries: vec![RarEntryInfo {
                name: name.into(),
                unpacked_size: size,
                file_crc: None,
                is_dir: false,
            }],
        };
        assert_eq!(
            pick_rar_media_name(&mk("dir/sub\\Evil.\u{7}Name.mkv", 10))
                .unwrap()
                .0,
            "Evil.Name.mkv"
        );
        assert_eq!(pick_rar_media_name(&mk("..", 10)), None);
        assert_eq!(pick_rar_media_name(&mk("   ", 10)), None);
        // A directory entry alone names nothing.
        assert_eq!(
            pick_rar_media_name(&RarHead {
                v5: false,
                volume_number: None,
                entries: vec![RarEntryInfo {
                    name: "dir".into(),
                    unpacked_size: 0,
                    file_crc: None,
                    is_dir: true,
                }],
            }),
            None
        );
    }

    /// A "size unknown" RAR5 entry carries a PLACEHOLDER length, not a
    /// real one. It must never become a content key: thousands of
    /// unrelated sets would key together and corroborate each other.
    #[test]
    fn a_placeholder_size_is_never_a_content_key() {
        let head = RarHead {
            v5: true,
            volume_number: None,
            entries: vec![RarEntryInfo {
                name: NAME.into(),
                unpacked_size: 0,
                file_crc: None,
                is_dir: false,
            }],
        };
        let (name, key) = pick_rar_media_name(&head).unwrap();
        assert_eq!(name, NAME);
        assert_eq!(key, None, "no size, no key - the caller must fall back");
    }
}
