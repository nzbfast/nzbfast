use super::address_filters::{self, Direction, X86Format, X86Opcodes};
use super::filters::{self, DeltaErrorMessages, FilterOp};
use super::{huffman, Error, Result};
use std::io::Read;
use std::ops::Range;

/// Opt-in compression experiments; not used by production writers.
#[cfg(feature = "ratio-lab")]
pub mod ratio;
// nzbfast-local change, 7 Sep 2026 - binary-tree match finder; see VENDORING.md.
mod tree;
use tree::{empty_slots, TreeMatchFinder, TREE_CANDIDATE_SLOTS, TREE_NO_MATCH};

/// Entropy-block boundary choice by exact encoded cost - the default emit
/// (nzbfast-local change, 7 Sep 2026; see VENDORING.md).
mod boundaries;

/// Ring-probe stage counters (nzbfast-local change, 8 Sep 2026; see
/// VENDORING.md). `ratio-lab` only - `probe_stat!` compiles to nothing in
/// a production build, so no timing arm ever pays for it.
#[cfg(feature = "ratio-lab")]
pub mod probe_stats;

#[cfg(feature = "ratio-lab")]
macro_rules! probe_stat {
    ($stat:ident) => {
        probe_stats::bump(probe_stats::Stat::$stat, 1)
    };
    ($stat:ident, $by:expr) => {
        probe_stats::bump(probe_stats::Stat::$stat, $by as u64)
    };
}

#[cfg(not(feature = "ratio-lab"))]
macro_rules! probe_stat {
    ($stat:ident) => {};
    ($stat:ident, $by:expr) => {
        let _ = $by;
    };
}


pub const LEVEL_TABLE_SIZE: usize = 20;
pub const MAIN_TABLE_SIZE: usize = 306;
pub const DISTANCE_TABLE_SIZE_50: usize = 64;
pub const DISTANCE_TABLE_SIZE_70: usize = 80;
pub const ALIGN_TABLE_SIZE: usize = 16;
pub const LENGTH_TABLE_SIZE: usize = 44;
const DEFAULT_DICTIONARY_SIZE: usize = 4 * 1024 * 1024;
const MAX_INITIAL_OUTPUT_CAPACITY: usize = 1024 * 1024;
const STREAM_FLUSH_THRESHOLD: usize = 64 * 1024;
// Up-front size ceiling for the streaming ring. The match window reaches back
// the archive's full declared dictionary, but a large declared dictionary must
// not force a large allocation from a tiny archive, so the ring starts no
// bigger than this and grows lazily (see `StreamingOutput::reserve`) toward the
// full dictionary only as decoded output actually reaches further back.
const STREAM_INITIAL_WINDOW_CAP: usize = 64 * 1024 * 1024;
// Streaming filter support: a filter may hold back at most this many bytes
// from the sink while its range materializes (2x unrar's 4MB legal maximum;
// genuine WinRAR filters are <= MAX_FILTER_BLOCK_LENGTH). Longer or
// overlapping-but-not-identical filters fall back via FilteredMember.
const STREAM_FILTER_HOLD_LIMIT: usize = 8 * 1024 * 1024;
const STREAM_MAX_PENDING_FILTERS: usize = 8192;
const MAX_ENCODER_MATCH_OFFSET: usize = DEFAULT_DICTIONARY_SIZE;
const MAX_ENCODER_MATCH_LENGTH: usize = 4096;
pub(crate) const MAX_COMPRESSED_BLOCK_OUTPUT: usize = 4 * 1024 * 1024;
pub(crate) const MAX_FILTER_BLOCK_LENGTH: usize = 0x3ffff;
// nzbfast-local change, 5 Sep 2026 - flat ring match index; see VENDORING.md.
// Bucket count is sized to the indexed span (about one bucket per `depth`
// positions) inside these bounds; the ring depth follows the candidate
// budget inside its own, so `EncodeOptions::new(n)` reaches exactly its n
// newest same-hash positions for n up to MATCH_INDEX_MAX_DEPTH.
const MATCH_INDEX_MIN_BUCKETS: usize = 1 << 10;
const MATCH_INDEX_MAX_BUCKETS: usize = 1 << 16;
const MATCH_INDEX_MIN_DEPTH: usize = 4;
/// At most this many tag bits per ring slot (see `MatchIndex::tag_bits`).
const MATCH_TAG_BITS_MAX: u32 = 8;
/// The long-match table (see `MatchIndex::long`): one position per entry,
/// keyed by a hash of the 32 bytes at an ANCHOR position, an anchor being
/// a position whose four-byte hash has these low bits clear (one in 32).
const LONG_INDEX_MIN_ENTRIES: usize = 1 << 10;
const LONG_INDEX_MAX_ENTRIES: usize = 1 << 20;
const LONG_ANCHOR_MASK: u32 = 31;
const LONG_ANCHOR_SPACING: usize = 32;
/// A long-table candidate must match at least this far to be considered;
/// shorter matches are the ring's business.
const LONG_MATCH_MIN_LENGTH: usize = 32;
const LONG_HASH_BYTES: usize = 32;
const MATCH_INDEX_MAX_DEPTH: usize = 64;
// A match at least this long ends the candidate walk: the remaining
// candidates can only trade a few bits of distance against the cost of
// visiting them (7-Zip's `nice_len`, zstd's `targetLength`).
const MATCH_NICE_LENGTH: usize = 64;
// nzbfast-local change, 5 Sep 2026 - literal-run acceleration; see VENDORING.md.
// Once a run of literals has gone LITERAL_SKIP_STRENGTH-scaled bytes without a
// match, the tokenizer probes every 2nd, then 3rd, ... position instead of
// every one (the LZ4 / zstd fast-level rule), capped at LITERAL_SKIP_MAX.
// Every position is still INSERTED into the index, so a later match can still
// point back into a skipped run; only the probe at the skipped position is
// saved. Compressible data almost never runs 32 literals without a match, so
// this does not fire there; incompressible data fires it at once and stops
// paying the candidate walk on every byte.
const LITERAL_SKIP_STRENGTH: u32 = 5;
const LITERAL_SKIP_MAX: usize = 16;
const MAX_MATCH_CANDIDATES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressedBlock {
    pub header: CompressedBlockHeader,
    pub header_len: usize,
    pub payload: Range<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressedBlockHeader {
    pub flags: u8,
    pub is_last: bool,
    pub has_tables: bool,
    pub final_byte_bits: u8,
    pub payload_size: usize,
    pub payload_bits: usize,
}

#[derive(Debug)]
#[doc(hidden)]
pub enum StreamDecodeError<E> {
    Decode(Error),
    FilteredMember,
    Sink(E),
}

impl<E> From<Error> for StreamDecodeError<E> {
    fn from(error: Error) -> Self {
        Self::Decode(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum DecodedChunk<'a> {
    Bytes(&'a [u8]),
    Repeated { byte: u8, len: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableLengths {
    pub main: Vec<u8>,
    pub distance: Vec<u8>,
    pub align: Vec<u8>,
    pub length: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DecodeTables {
    pub main: HuffmanTable,
    pub distance: HuffmanTable,
    pub align: HuffmanTable,
    pub length: HuffmanTable,
    pub align_mode: bool,
}

impl DecodeTables {
    pub fn from_lengths(lengths: &TableLengths) -> Result<Self> {
        let align_mode = lengths
            .align
            .iter()
            .any(|&length| length != 0 && length != 4);
        Ok(Self {
            main: HuffmanTable::from_lengths(&lengths.main)?,
            distance: HuffmanTable::from_distance_lengths(&lengths.distance)?,
            align: HuffmanTable::from_lengths(&lengths.align)?,
            length: HuffmanTable::from_lengths(&lengths.length)?,
            align_mode,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeMode {
    LiteralOnly,
    Lz,
    LzNoFilters,
}

impl DecodeMode {
    fn uses_lz(self) -> bool {
        matches!(self, Self::Lz | Self::LzNoFilters)
    }

    fn applies_filters(self) -> bool {
        matches!(self, Self::Lz)
    }
}

pub fn parse_compressed_block(input: &[u8]) -> Result<CompressedBlock> {
    if input.len() < 3 {
        return Err(Error::NeedMoreInput);
    }

    let flags = input[0];
    let checksum = input[1];
    let size_bytes = match (flags >> 3) & 0x03 {
        0 => 1,
        1 => 2,
        2 => 3,
        _ => return Err(Error::InvalidData("RAR 5 block size length is invalid")),
    };
    let header_len = 2 + size_bytes;
    if input.len() < header_len {
        return Err(Error::NeedMoreInput);
    }

    let size_data = &input[2..header_len];
    let actual = size_data
        .iter()
        .fold(checksum ^ flags, |acc, &byte| acc ^ byte);
    if actual != 0x5a {
        return Err(Error::InvalidData("RAR 5 block header checksum mismatch"));
    }

    let payload_size = size_data
        .iter()
        .enumerate()
        .fold(0usize, |acc, (index, &byte)| {
            acc | (usize::from(byte) << (index * 8))
        });
    let payload_end = header_len
        .checked_add(payload_size)
        .ok_or(Error::InvalidData("RAR 5 block size overflows"))?;
    if input.len() < payload_end {
        return Err(Error::NeedMoreInput);
    }

    let final_byte_bits = ((flags & 0x07) + 1).min(8);
    let payload_bits = if payload_size == 0 {
        0
    } else {
        (payload_size - 1) * 8 + usize::from(final_byte_bits)
    };

    Ok(CompressedBlock {
        header: CompressedBlockHeader {
            flags,
            is_last: flags & 0x40 != 0,
            has_tables: flags & 0x80 != 0,
            final_byte_bits,
            payload_size,
            payload_bits,
        },
        header_len,
        payload: header_len..payload_end,
    })
}

pub fn read_level_lengths(input: &[u8]) -> Result<([u8; LEVEL_TABLE_SIZE], usize)> {
    let mut bits = BitReader::new(input);
    let mut lengths = [0; LEVEL_TABLE_SIZE];
    let mut pos = 0;
    while pos < LEVEL_TABLE_SIZE {
        let length = bits.read_bits(4)? as u8;
        if length == 15 {
            let zero_count = bits.read_bits(4)? as usize;
            if zero_count == 0 {
                lengths[pos] = 15;
                pos += 1;
            } else {
                let count = zero_count + 2;
                for _ in 0..count {
                    if pos >= LEVEL_TABLE_SIZE {
                        break;
                    }
                    lengths[pos] = 0;
                    pos += 1;
                }
            }
        } else {
            lengths[pos] = length;
            pos += 1;
        }
    }
    Ok((lengths, bits.position()))
}

pub fn table_length_count(algorithm_version: u8) -> Result<usize> {
    match algorithm_version {
        0 => Ok(MAIN_TABLE_SIZE + DISTANCE_TABLE_SIZE_50 + ALIGN_TABLE_SIZE + LENGTH_TABLE_SIZE),
        1 => Ok(MAIN_TABLE_SIZE + DISTANCE_TABLE_SIZE_70 + ALIGN_TABLE_SIZE + LENGTH_TABLE_SIZE),
        _ => Err(Error::InvalidData(
            "RAR 5 unknown compression algorithm version",
        )),
    }
}

pub fn read_table_lengths(input: &[u8], algorithm_version: u8) -> Result<(TableLengths, usize)> {
    let table_size = table_length_count(algorithm_version)?;
    let (level_lengths, level_bits) = read_level_lengths(input)?;
    let level_decoder = HuffmanTable::from_lengths(&level_lengths)?;
    let mut bits = BitReader::new_at(input, level_bits);

    let mut lengths = Vec::with_capacity(table_size);
    while lengths.len() < table_size {
        let number = level_decoder.decode(&mut bits)?;
        match number {
            0..=15 => lengths.push(number as u8),
            16 | 17 => {
                if lengths.is_empty() {
                    return Err(Error::InvalidData(
                        "RAR 5 table repeats missing previous length",
                    ));
                }
                let count = if number == 16 {
                    3 + bits.read_bits(3)? as usize
                } else {
                    11 + bits.read_bits(7)? as usize
                };
                let previous = *lengths.last().unwrap();
                for _ in 0..count {
                    if lengths.len() >= table_size {
                        break;
                    }
                    lengths.push(previous);
                }
            }
            18 | 19 => {
                let count = if number == 18 {
                    3 + bits.read_bits(3)? as usize
                } else {
                    11 + bits.read_bits(7)? as usize
                };
                for _ in 0..count {
                    if lengths.len() >= table_size {
                        break;
                    }
                    lengths.push(0);
                }
            }
            _ => return Err(Error::InvalidData("RAR 5 invalid level-table symbol")),
        }
    }

    let distance_size = match algorithm_version {
        0 => DISTANCE_TABLE_SIZE_50,
        1 => DISTANCE_TABLE_SIZE_70,
        _ => unreachable!("validated by table_length_count"),
    };
    let distance_start = MAIN_TABLE_SIZE;
    let align_start = distance_start + distance_size;
    let length_start = align_start + ALIGN_TABLE_SIZE;

    Ok((
        TableLengths {
            main: lengths[..distance_start].to_vec(),
            distance: lengths[distance_start..align_start].to_vec(),
            align: lengths[align_start..length_start].to_vec(),
            length: lengths[length_start..].to_vec(),
        },
        bits.position(),
    ))
}

pub fn encode_table_lengths(lengths: &TableLengths, algorithm_version: u8) -> Result<Vec<u8>> {
    encode_table_lengths_with_bit_count(lengths, algorithm_version).map(|(data, _)| data)
}

pub fn encode_table_lengths_with_bit_count(
    lengths: &TableLengths,
    algorithm_version: u8,
) -> Result<(Vec<u8>, usize)> {
    let distance_size = match algorithm_version {
        0 => DISTANCE_TABLE_SIZE_50,
        1 => DISTANCE_TABLE_SIZE_70,
        _ => {
            return Err(Error::InvalidData(
                "RAR 5 unknown compression algorithm version",
            ))
        }
    };
    if lengths.main.len() != MAIN_TABLE_SIZE
        || lengths.distance.len() != distance_size
        || lengths.align.len() != ALIGN_TABLE_SIZE
        || lengths.length.len() != LENGTH_TABLE_SIZE
    {
        return Err(Error::InvalidData("RAR 5 table length count mismatch"));
    }

    let flattened = lengths
        .main
        .iter()
        .chain(lengths.distance.iter())
        .chain(lengths.align.iter())
        .chain(lengths.length.iter())
        .copied()
        .collect::<Vec<_>>();
    for &length in &flattened {
        if length > 15 {
            return Err(Error::InvalidData("RAR 5 Huffman length is too large"));
        }
    }

    let level_tokens = encode_table_level_tokens(&flattened);
    let level_lengths = level_code_lengths_for_tokens(&level_tokens);
    let level_table = EncoderTable::from_lengths(&level_lengths)?;
    let mut writer = BitWriter::new();
    write_level_lengths(&mut writer, &level_lengths);
    for token in level_tokens {
        let (code, len) = level_table.code_for_symbol(token.symbol)?;
        writer.write_bits(usize::from(code), usize::from(len));
        if token.extra_bits != 0 {
            writer.write_bits(
                usize::from(token.extra_value),
                usize::from(token.extra_bits),
            );
        }
    }
    let bit_count = writer.bit_pos;
    Ok((writer.finish(), bit_count))
}

pub fn encode_compressed_block(
    payload: &[u8],
    payload_bits: usize,
    has_tables: bool,
    is_last: bool,
) -> Result<Vec<u8>> {
    if payload_bits > payload.len() * 8 {
        return Err(Error::InvalidData("RAR 5 block bit count exceeds payload"));
    }
    if payload.is_empty() && payload_bits != 0 {
        return Err(Error::InvalidData("RAR 5 empty block has payload bits"));
    }
    if !payload.is_empty() && payload_bits <= (payload.len() - 1) * 8 {
        return Err(Error::InvalidData("RAR 5 block has unused payload bytes"));
    }
    if payload.len() > 0x00ff_ffff {
        return Err(Error::InvalidData("RAR 5 block payload is too large"));
    }

    let size_len = if payload.len() <= 0xff {
        1
    } else if payload.len() <= 0xffff {
        2
    } else {
        3
    };
    let final_byte_bits = if payload.is_empty() {
        1
    } else {
        ((payload_bits - 1) % 8) + 1
    };
    let mut flags = (final_byte_bits as u8) - 1;
    flags |= match size_len {
        1 => 0,
        2 => 1 << 3,
        3 => 2 << 3,
        _ => unreachable!("size_len is constrained above"),
    };
    if is_last {
        flags |= 0x40;
    }
    if has_tables {
        flags |= 0x80;
    }

    let mut size_bytes = [0u8; 3];
    let mut size = payload.len();
    for byte in &mut size_bytes[..size_len] {
        *byte = size as u8;
        size >>= 8;
    }
    let checksum = size_bytes[..size_len]
        .iter()
        .fold(0x5a ^ flags, |acc, &byte| acc ^ byte);
    let mut out = Vec::with_capacity(2 + size_len + payload.len());
    out.push(flags);
    out.push(checksum);
    out.extend_from_slice(&size_bytes[..size_len]);
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn decode_literal_only(
    input: &[u8],
    algorithm_version: u8,
    output_size: usize,
) -> Result<Vec<u8>> {
    let mut decoder = Rar50Decoder::new();
    decoder.decode_member(
        input,
        algorithm_version,
        output_size,
        false,
        DecodeMode::LiteralOnly,
    )
}

pub fn decode_lz(input: &[u8], algorithm_version: u8, output_size: usize) -> Result<Vec<u8>> {
    let mut decoder = Rar50Decoder::new();
    decoder.decode_member(input, algorithm_version, output_size, false, DecodeMode::Lz)
}

pub fn encode_literal_only(data: &[u8], algorithm_version: u8) -> Result<Vec<u8>> {
    let distance_size = match algorithm_version {
        0 => DISTANCE_TABLE_SIZE_50,
        1 => DISTANCE_TABLE_SIZE_70,
        _ => {
            return Err(Error::InvalidData(
                "RAR 5 unknown compression algorithm version",
            ))
        }
    };
    let mut lengths = TableLengths {
        main: vec![0; MAIN_TABLE_SIZE],
        distance: vec![0; distance_size],
        align: vec![0; ALIGN_TABLE_SIZE],
        length: vec![0; LENGTH_TABLE_SIZE],
    };
    let present = literal_presence(data);
    let literal_count = present.iter().filter(|&&used| used).count();
    let literal_length = huffman::bits_for_symbol_count(literal_count);
    for (symbol, used) in present.into_iter().enumerate() {
        if used {
            lengths.main[symbol] = literal_length;
        }
    }

    let table = EncoderTable::from_lengths(&lengths.main)?;
    let (table_data, table_bits) =
        encode_table_lengths_with_bit_count(&lengths, algorithm_version)?;
    let mut writer = BitWriter::continuing(table_data, table_bits);
    write_literal_codes(&mut writer, &table, data)?;
    let payload_bits = writer.bit_pos;
    encode_compressed_block(&writer.finish(), payload_bits, true, true)
}

pub fn encode_lz_member(data: &[u8], algorithm_version: u8) -> Result<Vec<u8>> {
    encode_lz_member_with_history(data, &[], algorithm_version)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct EncodeOptions {
    pub max_match_candidates: usize,
    pub lazy_matching: bool,
    pub lazy_lookahead: usize,
    pub max_match_distance: usize,
    /// Parse by least total estimated bits over a window of positions
    /// rather than greedily with a one-position lazy re-probe: see
    /// [`walk_tokens_optimal`]. The level ABOVE `lazy_matching`, which
    /// stays exactly what it was and is what this leaves unset.
    /// (nzbfast-local change, 7 Sep 2026; see VENDORING.md.)
    pub optimal_parse: bool,
    /// Cut the entropy blocks where the exact encoded cost says to cut
    /// (`codec::rar50::boundaries`) instead of every [`ENTROPY_BLOCK_BYTES`]
    /// of input. Independent of the parse above, which fixes the tokens
    /// this then prices. ON by default since 7 Sep 2026: measured -0.76%
    /// on the mixed corpus and -1.1 to -1.3% on member sets for a few
    /// percent of encode CPU. Off restores the fixed cut byte for byte,
    /// which is what a fixture pinning archive bytes wants.
    /// (nzbfast-local change, 7 Sep 2026; see VENDORING.md.)
    pub adaptive_entropy_blocks: bool,
    /// Price each 4 MiB region of a member BOTH ways - as one tokenizer
    /// block, and as [`TOKENIZER_SHORT_HORIZON`]-byte tokenizer blocks -
    /// and keep whichever encoded smaller. OFF by default: it encodes
    /// every region twice. See [`encode_member_region`].
    /// (nzbfast-local change, 7 Sep 2026; see VENDORING.md.)
    pub tokenizer_horizon_choice: bool,
    /// Total encoder working-memory allowance in bytes, or `None` for the
    /// host-sized defaults below ([`ENCODE_WAVE_MEMORY_BUDGET_PER_THREAD`]
    /// per pool thread with a [`ENCODE_WAVE_MEMORY_BUDGET_MIN`] floor, and
    /// a flat [`TREE_HINT_BUDGET_BYTES`] of match hints).
    ///
    /// Those defaults are sized for a desktop and are the reason a caller
    /// on a small target cannot bound this encoder: the floor ALONE is a
    /// gibibyte, which is the whole address space a 32-bit process can
    /// budget for ([`crate::Rar50WritePolicy`]). Set, the allowance is
    /// split between the two - half to the block wave, a quarter to the
    /// hints - and each is still floored at one block, so a budget smaller
    /// than one block in flight encodes serially rather than failing. Each
    /// share is also CEILINGED at its default: an allowance is a limit, and
    /// until 15 Sep 2026 a large one widened the hint wave past the default
    /// and raised peak RSS (rarfast `-mm4g` on Silesia: 7.2 GiB against 6.9
    /// with no allowance at all).
    ///
    /// It is a MEMORY decision and never a ratio one: both budgets choose
    /// how many blocks are in flight, and the same bytes come out at any
    /// width. (nzbfast-local change, 8 Sep 2026; see VENDORING.md.)
    pub working_memory: Option<usize>,
}

impl EncodeOptions {
    pub const fn new(max_match_candidates: usize) -> Self {
        Self {
            max_match_candidates,
            lazy_matching: false,
            lazy_lookahead: 1,
            max_match_distance: MAX_ENCODER_MATCH_OFFSET,
            optimal_parse: false,
            adaptive_entropy_blocks: true,
            tokenizer_horizon_choice: false,
            working_memory: None,
        }
    }

    /// Bounds the encoder's working memory; see
    /// [`EncodeOptions::working_memory`]. `None` restores the host-sized
    /// defaults. (nzbfast-local change, 8 Sep 2026; see VENDORING.md.)
    pub const fn with_working_memory(mut self, bytes: Option<usize>) -> Self {
        self.working_memory = bytes;
        self
    }

    pub const fn with_lazy_matching(mut self, enabled: bool) -> Self {
        self.lazy_matching = enabled;
        self
    }

    pub const fn with_lazy_lookahead(mut self, bytes: usize) -> Self {
        self.lazy_lookahead = bytes;
        self
    }

    pub const fn with_max_match_distance(mut self, distance: usize) -> Self {
        self.max_match_distance = distance;
        self
    }

    /// Turns on the cost-based parse; see [`EncodeOptions::optimal_parse`].
    pub const fn with_optimal_parse(mut self, enabled: bool) -> Self {
        self.optimal_parse = enabled;
        self
    }

    /// Chooses how the entropy blocks are cut; see
    /// [`EncodeOptions::adaptive_entropy_blocks`].
    pub const fn with_adaptive_entropy_blocks(mut self, enabled: bool) -> Self {
        self.adaptive_entropy_blocks = enabled;
        self
    }

    /// Turns on the per-region tokenizer horizon choice; see
    /// [`EncodeOptions::tokenizer_horizon_choice`].
    pub const fn with_tokenizer_horizon_choice(mut self, enabled: bool) -> Self {
        self.tokenizer_horizon_choice = enabled;
        self
    }
}

impl Default for EncodeOptions {
    fn default() -> Self {
        Self::new(MAX_MATCH_CANDIDATES)
    }
}

pub fn encode_lz_member_with_history(
    data: &[u8],
    history: &[u8],
    algorithm_version: u8,
) -> Result<Vec<u8>> {
    encode_lz_member_inner(
        data,
        history,
        algorithm_version,
        &[],
        EncodeOptions::default(),
        None,
    )
}

pub fn encode_lz_member_with_options(
    data: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
) -> Result<Vec<u8>> {
    encode_lz_member_with_history_and_options(data, &[], algorithm_version, options)
}

pub(crate) fn encode_lz_member_with_options_and_progress(
    data: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
    progress: &mut dyn FnMut(usize) -> bool,
) -> Result<Vec<u8>> {
    encode_lz_member_inner(data, &[], algorithm_version, &[], options, Some(progress))
}

pub fn encode_lz_member_with_history_and_options(
    data: &[u8],
    history: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
) -> Result<Vec<u8>> {
    encode_lz_member_inner(data, history, algorithm_version, &[], options, None)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rar50FilterKind {
    Delta { channels: usize },
    E8,
    E8E9,
    Arm,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rar50FilterSpec {
    pub kind: Rar50FilterKind,
    pub range: Option<Range<usize>>,
}

impl Rar50FilterSpec {
    pub fn new(kind: Rar50FilterKind) -> Self {
        Self { kind, range: None }
    }

    pub fn range(kind: Rar50FilterKind, range: Range<usize>) -> Self {
        Self {
            kind,
            range: Some(range),
        }
    }
}

/// The member transformed by its filters exactly as [`filtered_lz_blocks`]
/// transforms it - per 262,143-byte chunk, one record per chunk and filter,
/// executable filters keyed by absolute offset, delta state reset at every
/// chunk - but returned whole, records at their absolute offsets, for the
/// pooled encoder to cut into its own blocks. (nzbfast-local change, 7 Sep
/// 2026; see VENDORING.md.)
fn filtered_lz_member_records(
    data: &[u8],
    filters: &[Rar50FilterSpec],
) -> Result<(Vec<u8>, Vec<EncodeFilter>)> {
    let filters = normalized_filter_specs(data.len(), filters)?;
    let mut transformed = data.to_vec();
    let mut records = Vec::new();
    let mut chunk_start = 0usize;
    while chunk_start < data.len() {
        let chunk_end = (chunk_start + MAX_FILTER_BLOCK_LENGTH).min(data.len());
        for filter in &filters {
            let start = filter.range.start.max(chunk_start);
            let end = filter.range.end.min(chunk_end);
            if start >= end {
                continue;
            }
            let (filter_type, channels) =
                encode_filter_data(filter.kind, &mut transformed[start..end], start)?;
            records.push(EncodeFilter {
                offset: start,
                length: end - start,
                filter_type,
                channels,
            });
        }
        chunk_start = chunk_end;
    }
    Ok((transformed, records))
}

#[cfg(any(test, feature = "ratio-lab"))]
fn filtered_lz_member(
    data: &[u8],
    filters: &[Rar50FilterSpec],
) -> Result<(Vec<u8>, Vec<EncodeFilter>)> {
    let mut filtered = data.to_vec();
    let mut records = Vec::with_capacity(filters.len());
    for filter in filters {
        let range = filter.range.clone().unwrap_or(0..data.len());
        if range.start >= range.end || range.end > data.len() {
            return Err(Error::InvalidData("RAR 5 filter range is invalid"));
        }
        if range.start > u32::MAX as usize {
            return Err(Error::InvalidData("RAR 5 filter offset is too large"));
        }

        let filter_data = &mut filtered[range.clone()];
        let (filter_type, channels) = encode_filter_data(filter.kind, filter_data, range.start)?;
        records.push(EncodeFilter {
            offset: range.start,
            length: range.len(),
            filter_type,
            channels,
        });
    }
    Ok((filtered, records))
}

fn encode_filter_data(
    kind: Rar50FilterKind,
    data: &mut [u8],
    file_offset: usize,
) -> Result<(FilterType, usize)> {
    if file_offset > u32::MAX as usize {
        return Err(Error::InvalidData("RAR 5 filter offset is too large"));
    }
    match kind {
        Rar50FilterKind::Delta { channels } => {
            filters::encode_in_place(
                FilterOp::Delta { channels },
                data,
                0,
                rar50_delta_messages(),
            )?;
            Ok((FilterType::Delta, channels))
        }
        Rar50FilterKind::E8 => {
            address_filters::x86(
                data,
                file_offset as u32,
                Direction::Encode,
                X86Opcodes::Call,
                X86Format::Rar5,
            );
            Ok((FilterType::E8, 0))
        }
        Rar50FilterKind::E8E9 => {
            address_filters::x86(
                data,
                file_offset as u32,
                Direction::Encode,
                X86Opcodes::CallAndJump,
                X86Format::Rar5,
            );
            Ok((FilterType::E8E9, 0))
        }
        Rar50FilterKind::Arm => {
            address_filters::arm(data, file_offset as u32, Direction::Encode);
            Ok((FilterType::Arm, 0))
        }
    }
}

/// Returns the packed blocks and the LZ window as it stands after the last
/// block. That window holds the FILTERED chunks, which is what the decoder
/// keeps, so the caller can assign it straight onto the encoder history.
/// Its trim rule must stay identical to `Rar50Encoder::remember`.
// Reached only from `Rar50Encoder::encode_member_with_filters_chunked`
// below, whose callers all live in `codec::rar50::ratio`, behind the
// `ratio-lab` feature. So in a plain `cfg(test)` build with that feature
// off - which is what `--all-targets` compiles - the whole chain is
// unreferenced. Kept rather than gated to `ratio-lab` alone because the
// pair is the documented control the joint filter/tree encoder is tested
// against, and `test` is where a reader looks for it.
#[allow(dead_code)]
#[cfg(any(test, feature = "ratio-lab"))]
fn filtered_lz_blocks(
    data: &[u8],
    filters: &[Rar50FilterSpec],
    history: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let filters = normalized_filter_specs(data.len(), filters)?;
    let mut out = Vec::new();
    let mut block_history =
        history[history.len().saturating_sub(options.max_match_distance)..].to_vec();
    let mut chunk_start = 0usize;
    while chunk_start < data.len() {
        let chunk_end = (chunk_start + MAX_FILTER_BLOCK_LENGTH).min(data.len());
        let mut chunk = data[chunk_start..chunk_end].to_vec();
        let mut records = Vec::new();
        for filter in &filters {
            let start = filter.range.start.max(chunk_start);
            let end = filter.range.end.min(chunk_end);
            if start >= end {
                continue;
            }
            let local_start = start - chunk_start;
            let local_end = end - chunk_start;
            let (filter_type, channels) =
                encode_filter_data(filter.kind, &mut chunk[local_start..local_end], start)?;
            records.push(EncodeFilter {
                offset: local_start,
                length: local_end - local_start,
                filter_type,
                channels,
            });
        }
        let mut chunk_progress = |position: usize| {
            progress
                .as_deref_mut()
                .is_none_or(|report| report(chunk_start.saturating_add(position)))
        };
        out.extend(encode_lz_block(
            &chunk,
            &block_history,
            algorithm_version,
            &records,
            options,
            chunk_end == data.len(),
            Some(&mut chunk_progress),
        )?);
        block_history.extend_from_slice(&chunk);
        let keep_from = block_history
            .len()
            .saturating_sub(options.max_match_distance);
        if keep_from != 0 {
            block_history.drain(..keep_from);
        }
        chunk_start = chunk_end;
    }
    Ok((out, block_history))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedFilterSpec {
    kind: Rar50FilterKind,
    range: Range<usize>,
}

fn normalized_filter_specs(
    data_len: usize,
    filters: &[Rar50FilterSpec],
) -> Result<Vec<NormalizedFilterSpec>> {
    let mut normalized = Vec::with_capacity(filters.len());
    for filter in filters {
        let range = filter.range.clone().unwrap_or(0..data_len);
        if range.start >= range.end || range.end > data_len {
            return Err(Error::InvalidData("RAR 5 filter range is invalid"));
        }
        normalized.push(NormalizedFilterSpec {
            kind: filter.kind,
            range,
        });
    }
    Ok(normalized)
}

fn encode_lz_member_inner(
    data: &[u8],
    history: &[u8],
    algorithm_version: u8,
    initial_filters: &[EncodeFilter],
    options: EncodeOptions,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<u8>> {
    encode_lz_member_inner_pooled(
        data,
        history,
        algorithm_version,
        initial_filters,
        options,
        progress,
        &EncoderScratchPool::new(),
    )
}

/// [`encode_lz_member_with_history_and_options`] with the encoder scratch
/// taken from `scratch` and returned to it: a writer resolving many
/// members hands one pool to all of them, so a set of small members does
/// not fault a fresh 40 MiB of index and token buffers in per member
/// (200 members of 2.7 MB: 8 s of system time on an 8-vCPU guest, most
/// of the wall). (nzbfast-local change, 6 Sep 2026; see VENDORING.md.)
pub(crate) fn encode_lz_member_pooled(
    data: &[u8],
    history: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
    scratch: &EncoderScratchPool,
) -> Result<Vec<u8>> {
    encode_lz_member_inner_pooled(
        data,
        history,
        algorithm_version,
        &[],
        options,
        progress,
        scratch,
    )
}

fn encode_lz_member_inner_pooled(
    data: &[u8],
    history: &[u8],
    algorithm_version: u8,
    initial_filters: &[EncodeFilter],
    options: EncodeOptions,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
    scratch: &EncoderScratchPool,
) -> Result<Vec<u8>> {
    // `initial_filters` are the member's filter records at their ABSOLUTE
    // offsets in `data`; every block below takes the ones in its range and
    // the emitter writes each at the token that reaches it, so a filtered
    // member walks the same pooled, tree-fed path an unfiltered one does.
    // It used to drop to a serial walk of one-filter-chunk blocks
    // (nzbfast-local change, 7 Sep 2026; see VENDORING.md).
    if data.len() > MAX_COMPRESSED_BLOCK_OUTPUT {
        let wave_width = encode_block_wave_width_for_budget(
            options.max_match_distance,
            !history.is_empty(),
            options.working_memory,
        );
        return encode_lz_member_blocks_in_waves_filtered(
            data,
            history,
            initial_filters,
            algorithm_version,
            options,
            progress,
            wave_width,
            MemberWindow::whole(),
            scratch,
        );
    }

    let mut owned = scratch.take();
    // A member of one region takes the same per-region choice a longer
    // member's regions take: the choice's WIDE arm is this single-block
    // encode, block for block, so the switch cannot cost a byte here
    // either.
    let packed = if options.tokenizer_horizon_choice && data.len() > TOKENIZER_SHORT_HORIZON {
        encode_member_region(
            data,
            history,
            0..data.len(),
            initial_filters,
            algorithm_version,
            options,
            true,
            progress,
            &mut owned,
            None,
            &[],
        )
    } else {
        encode_lz_block_with_scratch(
            data,
            history,
            algorithm_version,
            initial_filters,
            options,
            true,
            progress,
            &mut owned,
        )
    };
    scratch.put(owned);
    packed
}

// nzbfast-local change, 5 Sep 2026 - the blocks of one member are encoded in
// parallel; see VENDORING.md.
//
// A member longer than one compressed block is cut into 4 MiB blocks whose
// tokenizers depend on RAW INPUT only: block k sees the `max_match_distance`
// bytes before it as history, and those bytes are the member's own input (or
// the incoming solid history) - never a previous block's OUTPUT. So the blocks
// are independent, and with the `parallel` feature a bounded pool tokenizes
// and entropy-codes them concurrently, then concatenates them in order. The output is
// byte-identical to the serial walk because each block is handed exactly the
// history the serial walk carried into it (`member_block_history`).
//
// The pool is bounded by memory as well as by cores: every block in flight
// holds its own bounded match index and token vector. Large-dictionary blocks
// borrow ordinary member history/input; only an incoming solid-history seam
// needs a buffer. Smaller dictionaries keep the original copy path.
// The original estimate is retained whenever it is lower. For wide
// dictionaries, account for the bounded index instead of charging four
// index bytes for every byte of history. The shared 1 GiB worker budget stays
// unchanged. Wide dictionaries can use four workers without incoming history;
// an owned solid-history seam still narrows the pool for very wide dictionaries.
#[cfg(feature = "parallel")]
// The budget scales with the box: 128 MiB per pool thread, never under
// 1 GiB. A flat 1 GiB held a 32 MiB-dictionary encode to FOUR workers on a
// 32-core desktop (measured 5 Sep 2026: 26.5 s wall for 102 CPU-seconds on
// the mixed 1 GiB corpus, against rar's 14.5 s for 276), because the
// per-block estimate below is what the workers actually hold and 1 GiB
// buys few of them.
const ENCODE_WAVE_MEMORY_BUDGET_PER_THREAD: usize = 128 << 20;
#[cfg(feature = "parallel")]
const ENCODE_WAVE_MEMORY_BUDGET_MIN: usize = 1 << 30;

#[cfg(all(test, feature = "parallel"))]
fn encode_block_wave_width(dictionary: usize) -> usize {
    encode_block_wave_width_for_history(dictionary, true)
}
// Both callers left are `cfg(all(test, feature = "parallel"))` -
// `encode_block_wave_width` above and
// one assertion in the wave tests - so the non-test build sees no use.
// Kept as the named two-argument form the tests read against; the
// production path calls `encode_block_wave_width_for_budget` directly.
#[allow(dead_code)]
fn encode_block_wave_width_for_history(dictionary: usize, incoming_history: bool) -> usize {
    encode_block_wave_width_for_budget(dictionary, incoming_history, None)
}

/// [`encode_block_wave_width_for_history`] against an explicit working-memory
/// allowance: `None` keeps the host-sized default below.
/// (nzbfast-local change, 8 Sep 2026; see VENDORING.md.)
pub(crate) fn encode_block_wave_width_for_budget(
    dictionary: usize,
    incoming_history: bool,
    working_memory: Option<usize>,
) -> usize {
    #[cfg(feature = "parallel")]
    {
        // What one block in flight holds, measured rather than feared: the
        // ring index (16 MiB at the default depth), the literal price prefix
        // (16 MiB), the token vector (up to 32 MiB), the block's output and
        // its input copy (4 MiB each) - 72 MiB - plus a copy of the history
        // when the block does not borrow it: below 32 MiB dictionaries the
        // tokenizer copies history and input into one span, and at any size
        // an incoming solid history is copied at the seam.
        let copied_history = if dictionary < (32 << 20) || incoming_history {
            dictionary
        } else {
            0
        };
        let per_block = (72usize << 20).saturating_add(copied_history);
        let threads = rayon::current_num_threads();
        // A caller-set allowance is not floored at the default's gibibyte,
        // which is larger than the whole budget of the targets that set
        // this; but it is capped by the default, because an allowance is a
        // limit and never a request for a wider wave than the host would
        // run. Half of the allowance goes here and a quarter to the hints.
        let host = (ENCODE_WAVE_MEMORY_BUDGET_PER_THREAD.saturating_mul(threads))
            .max(ENCODE_WAVE_MEMORY_BUDGET_MIN);
        let budget = working_memory.map_or(host, |bytes| (bytes / 2).min(host));
        let by_memory = (budget / per_block).max(1);
        threads.clamp(1, by_memory)
    }
    #[cfg(not(feature = "parallel"))]
    {
        let _ = (dictionary, incoming_history, working_memory);
        1
    }
}

/// The history the block starting at `start` sees: the last `dictionary`
/// bytes before it, drawn from the member's incoming history and then from
/// `data` itself - exactly what the serial block walk carried into it.
fn member_block_history<'a>(
    data: &'a [u8],
    history_tail: &'a [u8],
    start: usize,
    dictionary: usize,
) -> std::borrow::Cow<'a, [u8]> {
    if start >= dictionary {
        std::borrow::Cow::Borrowed(&data[start - dictionary..start])
    } else if start == 0 {
        std::borrow::Cow::Borrowed(history_tail)
    } else {
        let from_history = &history_tail[history_tail.len().saturating_sub(dictionary - start)..];
        let mut combined = Vec::with_capacity(from_history.len() + start);
        combined.extend_from_slice(from_history);
        combined.extend_from_slice(&data[..start]);
        std::borrow::Cow::Owned(combined)
    }
}

#[allow(clippy::too_many_arguments)]
fn encode_member_block(
    data: &[u8],
    history_tail: &[u8],
    range: Range<usize>,
    filters: &[EncodeFilter],
    algorithm_version: u8,
    options: EncodeOptions,
    is_last: bool,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
    scratch: &mut EncoderScratch,
    anchors: Option<&MemberAnchors<'_>>,
    tree: &[std::sync::atomic::AtomicU32],
) -> Result<Vec<u8>> {
    let block_filters = filters_in_block(filters, &range);
    // Small dictionaries keep their established path; borrowing and wider
    // pools are reserved for the large-history jobs that benefit in timings.
    if options.max_match_distance < 32 << 20 {
        let history =
            member_block_history(data, history_tail, range.start, options.max_match_distance);
        let long_seed = anchors.map(|anchors| LongSeed {
            anchors,
            range_start: range.start,
        });
        return encode_lz_block_in_span(
            &data[range],
            &history,
            algorithm_version,
            &block_filters,
            options,
            is_last,
            progress,
            scratch,
            None,
            long_seed,
            tree,
        );
    }
    encode_member_block_borrowed(
        data,
        history_tail,
        range,
        &block_filters,
        algorithm_version,
        options,
        is_last,
        progress,
        scratch,
        anchors,
        tree,
    )
}

/// The member's filter records that start inside `range`, as records of
/// the block: offsets from `range.start`. The last block also takes any
/// record starting at or past the member's end, which the emitter writes
/// after its final token (a record like that is invalid input and only
/// reaches here from a test of the pricing model).
fn filters_in_block(filters: &[EncodeFilter], range: &Range<usize>) -> Vec<EncodeFilter> {
    filters
        .iter()
        .filter(|filter| filter.offset >= range.start && filter.offset < range.end)
        .map(|filter| EncodeFilter {
            offset: filter.offset - range.start,
            ..*filter
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn encode_member_block_borrowed(
    data: &[u8],
    history_tail: &[u8],
    range: Range<usize>,
    filters: &[EncodeFilter],
    algorithm_version: u8,
    options: EncodeOptions,
    is_last: bool,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
    scratch: &mut EncoderScratch,
    anchors: Option<&MemberAnchors<'_>>,
    tree: &[std::sync::atomic::AtomicU32],
) -> Result<Vec<u8>> {
    let dictionary = options.max_match_distance;
    // Own only the seam between incoming solid history and this member.
    // Otherwise history and input are one contiguous borrowed member slice.
    let span = if range.start >= dictionary || history_tail.is_empty() {
        std::borrow::Cow::Borrowed(&data[range.start.saturating_sub(dictionary)..range.end])
    } else {
        let tail = &history_tail[history_tail.len().saturating_sub(dictionary - range.start)..];
        let mut span = Vec::with_capacity(tail.len() + range.end);
        span.extend_from_slice(tail);
        span.extend_from_slice(&data[..range.end]);
        std::borrow::Cow::Owned(span)
    };
    let history_len = span.len() - range.len();
    let (history, block) = span.split_at(history_len);
    let long_seed = anchors.map(|anchors| LongSeed {
        anchors,
        range_start: range.start,
    });
    encode_lz_block_in_span(
        block,
        history,
        algorithm_version,
        filters,
        options,
        is_last,
        progress,
        scratch,
        Some(&span),
        long_seed,
        tree,
    )
}

/// The tokenizer horizon the SHORT arm of the per-region choice encodes
/// at: a quarter of the 4 MiB region, which is the arm Codex's lab
/// measured as `opt-horizon-balanced` (`research/rar5-ratio-lab/balanced`).
/// Narrower arms (256 KiB, and the seven-way power-of-two screen down to
/// 64 KiB) buy a further 0.03 to 0.07% for two to five times this arm's
/// CPU, which is the wrong end of the trade for a mode anyone runs.
/// (nzbfast-local change, 7 Sep 2026; see VENDORING.md.)
const TOKENIZER_SHORT_HORIZON: usize = 1 << 20;

/// One 4 MiB REGION of a member, encoded the way `options` asks.
///
/// By default a region is one tokenizer block and this is exactly
/// [`encode_member_block`]. With
/// [`EncodeOptions::tokenizer_horizon_choice`] the region is encoded a
/// SECOND time as [`TOKENIZER_SHORT_HORIZON`]-byte tokenizer blocks and
/// the smaller of the two encodings is kept, so the switch can never
/// cost a byte on any shape - only CPU, since it encodes every region
/// twice.
///
/// Why the two arms are comparable, and why the choices compose into one
/// member rather than into a concatenation of archives:
///
/// - **The raw dictionary history is identical either way.** A block's
///   tokenizer sees the `max_match_distance` bytes of MEMBER INPUT before
///   it ([`member_block_history`]), never a previous block's output, so
///   which arm won for the region before this one changes nothing about
///   what this region's tokenizer is handed.
/// - **No repeat state crosses the choice.** Every tokenizer block starts
///   its parse and its emission from `EncoderMatchState::default()`
///   already (see [`emit_entropy_blocks`]), which is what makes the arms
///   independent; a carried rep model would price each arm against a
///   state the other arm did not leave.
/// - **Only the member's real last block carries the final flag**, so the
///   run of blocks this returns for the last region ends the member once.
///
/// The lab arm this reproduces is `opt-horizon-balanced`
/// (`research/rar5-ratio-lab/balanced/README.md`), which writes
/// 111,639,171 bytes on the first 256 MiB of the mixed corpus at a 32 MiB
/// dictionary. This writer wrote 111,639,169 for it - the two bytes are
/// archive framing - and 111,617,844 once the tree finder's per-position
/// candidate list landed beside it, against 112,865,011 with the switch
/// off.
///
/// NOT reached by the switch: a solid member of 4 MiB or less, which
/// [`LiveSpanEncoder`] encodes as one tokenizer block on an index and a
/// tree finder CARRIED ACROSS the group's members. Both arms would have
/// to run over that live state and only one of them may leave its marks
/// on it, and rolling a 32 MiB-dictionary finder back per member costs
/// more than the choice can return. Solid members past 4 MiB fall to the
/// block walk and take the choice like any other member.
/// (nzbfast-local change, 7 Sep 2026; see VENDORING.md.)
#[allow(clippy::too_many_arguments)]
fn encode_member_region(
    data: &[u8],
    history_tail: &[u8],
    range: Range<usize>,
    filters: &[EncodeFilter],
    algorithm_version: u8,
    options: EncodeOptions,
    is_last: bool,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
    scratch: &mut EncoderScratch,
    anchors: Option<&MemberAnchors<'_>>,
    tree: &[std::sync::atomic::AtomicU32],
) -> Result<Vec<u8>> {
    // A region no longer than the short horizon is ONE block either way -
    // same history, same bytes, same final flag, so the same output - and
    // with the switch off there is only ever the one arm.
    if !options.tokenizer_horizon_choice || range.len() <= TOKENIZER_SHORT_HORIZON {
        return encode_member_block(
            data,
            history_tail,
            range,
            filters,
            algorithm_version,
            options,
            is_last,
            progress,
            scratch,
            anchors,
            tree,
        );
    }
    // Both arms walk the same input bytes, so the second one reports no
    // forward progress: the callback sees the high-water mark, which the
    // first arm has already carried to the region's end. It is still
    // POLLED by the second arm, so a refusal stops that arm as promptly
    // as it stops the first.
    let mut reached = 0usize;
    let mut region_progress = |position: usize| {
        reached = reached.max(position);
        progress.as_deref_mut().is_none_or(|report| report(reached))
    };
    let wide = encode_member_block(
        data,
        history_tail,
        range.clone(),
        filters,
        algorithm_version,
        options,
        is_last,
        Some(&mut region_progress),
        scratch,
        anchors,
        tree,
    )?;
    // The finder writes `stride` slots per POSITION and the stride is
    // carried in the slice's own shape (see `encode_tokens_in_span`), so a
    // sub-region's hints are its own positions' slots and nothing else:
    // the finder's answers are a function of the position alone, which is
    // what lets a region's hint span be cut at all.
    let stride = if tree.is_empty() {
        0
    } else {
        tree.len() / range.len()
    };
    let mut short = Vec::with_capacity(wide.len());
    let mut start = range.start;
    while start < range.end {
        let end = (start + TOKENIZER_SHORT_HORIZON).min(range.end);
        let hints = &tree[(start - range.start) * stride..(end - range.start) * stride];
        let block = encode_member_block(
            data,
            history_tail,
            start..end,
            filters,
            algorithm_version,
            options,
            is_last && end == range.end,
            Some(&mut region_progress),
            scratch,
            anchors,
            hints,
        )?;
        short.extend_from_slice(&block);
        // Every remaining block only adds to this, so the wide arm has
        // already won and the rest of the short arm is wasted work.
        if short.len() >= wide.len() {
            return Ok(wide);
        }
        start = end;
    }
    Ok(short)
}

/// The long-table ANCHORS of a member's blocks (see `MatchIndex::long`),
/// computed once per block by the first worker that needs them and shared
/// read-only after. Every block's tokenizer used to rescan its whole history
/// for anchors - up to 32 MiB per 4 MiB block, eight times over the member,
/// about 9% of a large-dictionary encode - where the anchors of a block are a
/// property of its bytes alone. Each list holds offsets within the block
/// (ascending), and the pool's drain loop releases lists no block in flight
/// can still need. (nzbfast-local change, 6 Sep 2026; see VENDORING.md.)
struct MemberAnchors<'a> {
    data: &'a [u8],
    lists: Vec<std::sync::Mutex<Option<std::sync::Arc<Vec<u32>>>>>,
}

/// Where a block's history sits in the member, for `MatchIndex::seed_history`
/// to take its long-table seed from [`MemberAnchors`] instead of a scan.
#[derive(Clone, Copy)]
struct LongSeed<'a> {
    anchors: &'a MemberAnchors<'a>,
    /// The block's first position in the member.
    range_start: usize,
}

impl<'a> MemberAnchors<'a> {
    fn new(data: &'a [u8]) -> Self {
        let blocks = data.len().div_ceil(MAX_COMPRESSED_BLOCK_OUTPUT);
        Self {
            data,
            lists: (0..blocks).map(|_| std::sync::Mutex::new(None)).collect(),
        }
    }

    /// The anchor offsets of `block`, computed on first use.
    fn block(&self, block: usize) -> std::sync::Arc<Vec<u32>> {
        let mut slot = self.lists[block]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(list) = &*slot {
            return list.clone();
        }
        let list = std::sync::Arc::new(Self::compute(
            self.data,
            member_block_range(self.data.len(), block),
        ));
        *slot = Some(list.clone());
        list
    }

    /// Anchors in `range` with the 32 hashed bytes inside the member, as
    /// offsets from `range.start`, ascending - the same positions a scan
    /// of the member would anchor.
    fn compute(data: &[u8], range: Range<usize>) -> Vec<u32> {
        let mut out = Vec::new();
        let end = range
            .end
            .min(data.len().saturating_sub(LONG_HASH_BYTES - 1));
        let mut pos = range.start;
        while pos + 8 <= data.len() && pos + 4 <= end {
            let words = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
            for (i, word) in [
                words as u32,
                (words >> 8) as u32,
                (words >> 16) as u32,
                (words >> 24) as u32,
            ]
            .into_iter()
            .enumerate()
            {
                if long_anchor(word) {
                    out.push((pos + i - range.start) as u32);
                }
            }
            pos += 4;
        }
        while pos < end {
            let word = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
            if long_anchor(word) {
                out.push((pos - range.start) as u32);
            }
            pos += 1;
        }
        out
    }

    /// Drop the lists of every block below `block`: none in flight reads them.
    fn release_below(&self, block: usize) {
        for list in &self.lists[..block.min(self.lists.len())] {
            *list.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        }
    }
}

fn member_block_range(data_len: usize, block: usize) -> Range<usize> {
    block * MAX_COMPRESSED_BLOCK_OUTPUT..((block + 1) * MAX_COMPRESSED_BLOCK_OUTPUT).min(data_len)
}

/// Which blocks of a member's span an encode covers: all of them, or the
/// blocks from `first_block` on, with the earlier ones standing in for the
/// member bytes before them (nzbfast-local change, 6 Sep 2026; see
/// VENDORING.md and [`encode_lz_member_window`]).
#[derive(Clone, Copy)]
struct MemberWindow {
    /// The first block to encode; the blocks before it are history.
    first_block: usize,
    /// Whether the span ends where the member does, so the span's last
    /// block carries the member's `is_last`.
    final_segment: bool,
}

impl MemberWindow {
    fn whole() -> Self {
        Self {
            first_block: 0,
            final_segment: true,
        }
    }
}

/// The compressed blocks of a member from a WINDOW onto it - `span`, whose
/// first `first_block` blocks are member bytes already encoded and whose
/// remaining blocks are the ones to encode now - byte-identical to the
/// blocks the whole-member walk produces for the same member.
///
/// A block's tokenizer depends on its own bytes and the `max_match_distance`
/// bytes before them, never on an earlier block's OUTPUT (see the block
/// pool above), so a caller that holds the member a segment at a time can
/// encode each segment with the previous segment's tail in front of it and
/// concatenate the results: the streamed compressed writer does exactly
/// that, over a window of `first_block` whole blocks (at least the
/// dictionary) plus the segment. The history part must be whole blocks so
/// the block boundaries in the span are the member's own, and every
/// history a block sees is then the same bytes the whole-member walk hands
/// it (`member_block_history` clips it to the dictionary). The long-table
/// anchors of the history blocks are computed from the span on first use,
/// as the whole-member walk computes them. `final_segment` marks the span
/// that ends where the member does; only its last block carries `is_last`.
/// A member of one block or less has no window: encode it whole through
/// [`encode_lz_member_with_options`], which takes the single-block path the
/// whole-member walk takes for it. (nzbfast-local change, 6 Sep 2026; see
/// VENDORING.md.)
pub(crate) fn encode_lz_member_window(
    span: &[u8],
    first_block: usize,
    algorithm_version: u8,
    options: EncodeOptions,
    final_segment: bool,
    scratch: &EncoderScratchPool,
) -> Result<Vec<u8>> {
    if first_block * MAX_COMPRESSED_BLOCK_OUTPUT >= span.len() {
        return Err(Error::InvalidData(
            "RAR 5 member window holds no block to encode",
        ));
    }
    let wave_width = member_window_wave_width(options);
    encode_lz_member_blocks_in_waves(
        span,
        &[],
        algorithm_version,
        options,
        None,
        wave_width,
        MemberWindow {
            first_block,
            final_segment,
        },
        scratch,
    )
}

/// How many windows of one member the streamed writer encodes at once: it
/// reads the next window while the one before it encodes, and one more
/// buffer is the window being filled. (nzbfast-local change, 15 Sep 2026;
/// see VENDORING.md.)
pub(crate) const STREAMED_WINDOWS_IN_FLIGHT: usize = 2;

/// The wave one streamed window encodes at: the pool's wave width, shared
/// between the [`STREAMED_WINDOWS_IN_FLIGHT`] windows when a working-memory
/// allowance is set.
///
/// Every window in flight walks its own tree finder over its wave and holds
/// the finder's answers for the whole wave before any of its blocks encode:
/// four bytes a slot a position, 64 MiB a block at the cost-based parse's
/// stride. The windows share ONE pool, so a wave as wide as the pool in each
/// of them held twice the hints the pool could use at once. Measured 15 Sep
/// 2026 with a heap-tracking allocator on rarfast `-m5` over a 64 MiB text
/// member at a 32 MiB dictionary under an allowance: at four pool threads
/// 1,528 MiB of live heap, 512 MiB of it the two windows' hints; a further
/// thread cost about 157 MiB, 128 of them hints, which is the gap between
/// the wave's 72 MiB a block and the ~175 MiB a cost-parsed block was seen
/// to hold. Shared, the peak is 1,335 MiB at four threads (from 1,528) and
/// 1,529 at eight (from 2,141), and Silesia at four threads 1,571 (from
/// 1,857), the same archive at every width. Byte-neutral: the width of a
/// wave moves no byte, and the pool still runs as many blocks at once, from
/// two windows instead of one. With no allowance nothing moves: an uncapped
/// wide box is held by the hint budget already, and what a narrower wave
/// would cost the pool's feed there is unmeasured.
fn member_window_wave_width(options: EncodeOptions) -> usize {
    let width = encode_block_wave_width_for_budget(
        options.max_match_distance,
        false,
        options.working_memory,
    );
    if options.working_memory.is_some() {
        width.div_ceil(STREAMED_WINDOWS_IN_FLIGHT)
    } else {
        width
    }
}

/// How many blocks a streamed member's window should carry so the block
/// pool stays fed: the pool's width, and never under eight (32 MiB) -
/// unless a working-memory allowance is set.
///
/// The window is also how many small members the streamed writer encodes
/// at once, each on a thread of its own with its own match-finder tree and
/// block scratch, OUTSIDE the pool. So the floor of eight let eight member
/// encodes run beside a pool an allowance had narrowed to two: rarfast's
/// `-m5 -mm2g` over Silesia peaked at 2.2 GiB with its pool at two
/// threads. Under an allowance the window is the wave width and nothing
/// wider. Byte-neutral: a member that now takes the windowed route instead
/// of the whole-member one gets the same sampled verdict and the same
/// blocks (the streamed-matches-in-memory tests hold both routes to the
/// in-memory writer). (nzbfast-local change, 15 Sep 2026.)
///
/// It is the ADMISSION width only: a large member's window takes
/// [`member_window_segment_blocks`], which keeps the floor.
pub(crate) fn member_window_blocks(options: EncodeOptions) -> usize {
    let width = encode_block_wave_width_for_budget(
        options.max_match_distance,
        false,
        options.working_memory,
    );
    if options.working_memory.is_some() {
        width
    } else {
        width.max(8)
    }
}

/// How many blocks a streamed member's window encodes behind its history:
/// the pool's width and never under eight (32 MiB), with an allowance or
/// without one.
///
/// [`member_window_blocks`] lost its floor under an allowance because it is
/// also the small-member admission width, and until this the window lost it
/// too: at one pool thread a member was encoded one 4 MiB block at a time
/// behind 32 MiB of history, and every window builds a fresh tree finder
/// over its whole span before it encodes, so about nine bytes were walked
/// for each byte encoded. Measured 15 Sep 2026 on rarfast `-m5 -mm64g`
/// over a 64 MiB text member at a 32 MiB dictionary, one pool thread, the
/// same archive in every run: 142 s of user CPU and 1,328 MiB peak RSS
/// before, 32 s and 1,050 MiB after, against 30 s and 1,053 MiB with no
/// allowance. The window's size moves no byte (the windowed-walk cells hold
/// every shape), and the finder's tree is sized by the dictionary, not the
/// span, so what the floor costs is the streamed writer's three window
/// buffers of history plus window: at an 8 MiB dictionary and one thread
/// the peak ROSE from 495 to 584 MiB, the one measured cell where it did.
/// (nzbfast-local change, 15 Sep 2026; see VENDORING.md.)
pub(crate) fn member_window_segment_blocks(options: EncodeOptions) -> usize {
    encode_block_wave_width_for_budget(
        options.max_match_distance,
        false,
        options.working_memory,
    )
    .max(8)
}

// Every argument names a different thing the encoder needs and no two
// of them travel together, so a parameter struct here would be a bag
// with one field per argument and a second name for each. The lint's
// ceiling is 7; these are 8 and 10.
#[allow(clippy::too_many_arguments)]
fn encode_lz_member_blocks_in_waves(
    data: &[u8],
    history: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
    wave_width: usize,
    window: MemberWindow,
    scratch_pool: &EncoderScratchPool,
) -> Result<Vec<u8>> {
    encode_lz_member_blocks_in_waves_filtered(
        data,
        history,
        &[],
        algorithm_version,
        options,
        progress,
        wave_width,
        window,
        scratch_pool,
    )
}

/// [`encode_lz_member_blocks_in_waves`] for a member carrying filter
/// records (absolute offsets in `data`); each block takes the records in
/// its range (nzbfast-local change, 7 Sep 2026; see VENDORING.md).
#[allow(clippy::too_many_arguments)]
fn encode_lz_member_blocks_in_waves_filtered(
    data: &[u8],
    history: &[u8],
    filters: &[EncodeFilter],
    algorithm_version: u8,
    options: EncodeOptions,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
    wave_width: usize,
    window: MemberWindow,
    scratch_pool: &EncoderScratchPool,
) -> Result<Vec<u8>> {
    let dictionary = options.max_match_distance;
    let history_tail = &history[history.len().saturating_sub(dictionary)..];
    let block_count = data.len().div_ceil(MAX_COMPRESSED_BLOCK_OUTPUT);
    let first_block = window.first_block.min(block_count);
    // `wave_width` is the number of blocks in flight at once (the name is
    // from the first cut, which ran the blocks in barrier-separated waves).
    let width = wave_width.max(1).min(block_count - first_block);
    // Without the pool there is nothing to run blocks on: the walk is serial
    // whatever width was asked for (the tests ask for several).
    #[cfg(not(feature = "parallel"))]
    let width = {
        let _ = width;
        1
    };
    if tree_match_finder_applies(options, data, history_tail) {
        return encode_blocks_with_tree(
            data,
            filters,
            algorithm_version,
            options,
            block_count,
            width,
            progress,
            window,
            scratch_pool,
        );
    }
    if width > 1 {
        #[cfg(feature = "parallel")]
        return encode_blocks_pooled(
            data,
            history_tail,
            filters,
            algorithm_version,
            options,
            block_count,
            width,
            progress,
            window,
            scratch_pool,
        );
    }
    let anchors = MemberAnchors::new(data);
    let blocks_in_dictionary = dictionary.div_ceil(MAX_COMPRESSED_BLOCK_OUTPUT);
    let mut out = Vec::new();
    let mut completed = 0usize;
    let mut scratch = scratch_pool.take();
    for block in first_block..block_count {
        let range = member_block_range(data.len(), block);
        anchors.release_below(block.saturating_sub(blocks_in_dictionary));
        let mut block_progress = |position: usize| {
            progress
                .as_deref_mut()
                .is_none_or(|report| report(completed.saturating_add(position)))
        };
        out.extend(encode_member_region(
            data,
            history_tail,
            range.clone(),
            filters,
            algorithm_version,
            options,
            window.final_segment && block + 1 == block_count,
            Some(&mut block_progress),
            &mut scratch,
            Some(&anchors),
            &[],
        )?);
        completed = completed.saturating_add(range.len());
    }
    scratch_pool.put(scratch);
    Ok(out)
}

/// A member's dictionary must be at least this wide for the tree match
/// finder to run: below it the ring index's newest-`depth` reach already
/// covers most of the window, and the tree's eight bytes per window byte
/// buy little. (nzbfast-local change, 7 Sep 2026; see VENDORING.md.)
pub(crate) const TREE_MIN_DICTIONARY: usize = MAX_COMPRESSED_BLOCK_OUTPUT;

/// Whether this member's blocks run behind the tree match finder.
///
/// Incoming SOLID history is excluded: the finder indexes one contiguous
/// span in the member's own coordinates, and a member behind a solid seam
/// has its history in another buffer. Solid groups reach the finder
/// through [`LiveSpanEncoder`], which owns the whole group's span.
fn tree_match_finder_applies(options: EncodeOptions, data: &[u8], history_tail: &[u8]) -> bool {
    options.max_match_candidates != 0
        && options.max_match_distance >= TREE_MIN_DICTIONARY
        && history_tail.is_empty()
        && TreeMatchFinder::fits(data.len())
}

/// How many walkers split the finder's ranges (nzbfast-local change,
/// 7 Sep 2026; see VENDORING.md).
///
/// The blocks behind the finder are idle while it runs, so the pool's
/// whole width is available - and taking it is the wrong trade. A tree
/// descent is a chain of dependent loads over a structure far larger than
/// the last-level cache, so walkers past a handful spend their time
/// stalled on memory rather than working, and the stall is charged as
/// user CPU. Measured on the 256 MiB slice at `-md32m`, on an idle
/// twenty-core Apple silicon desktop, same bytes at every width:
///
/// | walkers | wall s | user s |
/// |---|---:|---:|
/// | 1 | 73.2 | 102.8 |
/// | 4 | 29.9 | 112.3 |
/// | 8 | 25.2 | 155.0 |
/// | 12 | 20.4 | 174.2 |
/// | 20 | 17.5 | 211.2 |
///
/// Four is where the wall is most of the way down and the CPU has barely
/// moved.
#[cfg(feature = "parallel")]
const TREE_WALKER_CAP: usize = 4;

/// How many candidate slots the finder records per position for this
/// member (nzbfast-local change, 7 Sep 2026; see VENDORING.md).
///
/// The lazy parser reads one distance and takes the longest, which is what
/// it did before lists existed, so it pays nothing here. The cost-based
/// parse consumes the whole frontier and drops the ring walk for it, which
/// is where both the bytes and the CPU are: the buffer is four bytes per
/// slot per position of the wave in flight, so the wider stride is asked
/// for only by the parse that uses it.
fn tree_candidate_slots(options: EncodeOptions) -> usize {
    // A direct eight-byte hash reports one long hint; the optimal parser
    // retains the ring for its short candidates in this research control.
    #[cfg(feature = "ratio-lab")]
    if std::env::var_os("RARS_TREE_HASH8").is_some() {
        return 1;
    }
    if options.optimal_parse {
        TREE_CANDIDATE_SLOTS
    } else {
        1
    }
}

/// The most the finder's answers may hold for the blocks in flight at
/// once (nzbfast-local change, 7 Sep 2026; see VENDORING.md).
///
/// A wave's hints are four bytes per slot per position and the whole wave
/// is walked before any of its blocks encodes, so at a stride of
/// [`TREE_CANDIDATE_SLOTS`] the buffer is 64 MiB per block in flight -
/// and the pool's own width is chosen by core count, so on a wide box the
/// buffer would grow with the box rather than with the work. Measured on
/// the 256 MiB slice at `-md32m` on a twenty-core M1 Ultra, peak RSS by
/// stride: 2.26 GB at one slot, 2.61 at two, 2.99 at three, 3.49 at four,
/// 4.28 at six, 5.15 at eight. This holds the hints to half a gigabyte,
/// which is eight blocks at the shipped stride.
///
/// The wave width is a memory decision and nothing else - the same bytes
/// come out at any width (`the_hint_budget_narrows_a_wave_without_moving_
/// its_bytes` holds that), so narrowing here costs wall time on a wide
/// box and no ratio.
const TREE_HINT_BUDGET_BYTES: usize = 512 << 20;

/// `width` narrowed so a wave's hints fit [`TREE_HINT_BUDGET_BYTES`].
fn tree_wave_width(width: usize, stride: usize, working_memory: Option<usize>) -> usize {
    let slot = std::mem::size_of::<std::sync::atomic::AtomicU32>();
    let per_block = MAX_COMPRESSED_BLOCK_OUTPUT * stride.max(1) * slot;
    // A quarter of a caller-set allowance, and never more than the default
    // (see the const's own note for why that is a flat half-gigabyte): an
    // allowance only ever narrows. (nzbfast-local change, 15 Sep 2026.)
    let budget = working_memory.map_or(TREE_HINT_BUDGET_BYTES, |bytes| {
        (bytes / 4).min(TREE_HINT_BUDGET_BYTES)
    });
    (budget / per_block.max(1)).clamp(1, width.max(1))
}

fn tree_walkers() -> usize {
    #[cfg(feature = "parallel")]
    {
        rayon::current_num_threads().clamp(1, TREE_WALKER_CAP)
    }
    #[cfg(not(feature = "parallel"))]
    {
        1
    }
}

/// The end of the 4 MiB block grid cell `position` falls in: the finder's
/// walks are cut on this grid so a window of a member builds the tree the
/// whole member builds (see [`tree::TreeMatchFinder::advance_range`]).
fn block_grid_end(data_len: usize, position: usize) -> usize {
    ((position / MAX_COMPRESSED_BLOCK_OUTPUT) + 1)
        .saturating_mul(MAX_COMPRESSED_BLOCK_OUTPUT)
        .min(data_len)
}

/// The blocks of one member with the binary-tree match finder in front of
/// them (nzbfast-local change, 7 Sep 2026; see VENDORING.md).
///
/// The finder walks the member's positions in order - it cannot be
/// re-seeded per block, which is what rules out giving every block its own
/// tree - and hands each block the best distance it found at each of the
/// block's positions. The blocks then tokenize and entropy-code exactly as
/// they do without it, on the pool, each with its own ring index for the
/// near matches the finder does not rank: the finder's answers are a
/// function of the position alone, so a block's output does not depend on
/// how many of them ran at once.
///
/// The walk is cut into WAVES of `width` blocks because the answers have
/// to be held somewhere: four bytes per position, 16 MiB per block in
/// flight. The wave width is a memory decision and nothing else - the same
/// bytes come out at any width.
#[allow(clippy::too_many_arguments)]
fn encode_blocks_with_tree(
    data: &[u8],
    filters: &[EncodeFilter],
    algorithm_version: u8,
    options: EncodeOptions,
    block_count: usize,
    width: usize,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
    window: MemberWindow,
    scratch_pool: &EncoderScratchPool,
) -> Result<Vec<u8>> {
    let mut finder = TreeMatchFinder::new(options.max_match_distance);
    let walkers = tree_walkers();
    let stride = tree_candidate_slots(options);
    let anchors = MemberAnchors::new(data);
    let blocks_in_dictionary = options
        .max_match_distance
        .div_ceil(MAX_COMPRESSED_BLOCK_OUTPUT);
    // A window onto a member starts the finder a full window before its
    // first encoded block, on the block grid: the live tree there is then
    // the one the whole-member walk holds, node for node.
    let first_position = (window.first_block * MAX_COMPRESSED_BLOCK_OUTPUT).min(data.len());
    let mut position = first_position.saturating_sub(finder.window());
    finder.skip_to(position);
    while position < first_position {
        let end = block_grid_end(data.len(), position).min(first_position);
        finder.advance_range(data, position..end, None, stride, walkers);
        position = end;
    }
    let mut out = Vec::new();
    let mut distances = empty_slots(0);
    let mut block = window.first_block;
    let mut tokenized = 0usize;
    let width = tree_wave_width(width, stride, options.working_memory);
    while block < block_count {
        let wave_end = (block + width).min(block_count);
        let wave = member_block_range(data.len(), block).start
            ..member_block_range(data.len(), wave_end - 1).end;
        if distances.len() < wave.len() * stride {
            distances = empty_slots(wave.len() * stride);
        }
        for slot in &distances[..wave.len() * stride] {
            slot.store(TREE_NO_MATCH, std::sync::atomic::Ordering::Relaxed);
        }
        for index in block..wave_end {
            let range = member_block_range(data.len(), index);
            let at = (range.start - wave.start) * stride;
            finder.advance_range(
                data,
                range.clone(),
                Some(&distances[at..at + range.len() * stride]),
                stride,
                walkers,
            );
        }
        let block_output = |index: usize, scratch: &mut EncoderScratch| {
            let range = member_block_range(data.len(), index);
            let at = (range.start - wave.start) * stride;
            encode_member_region(
                data,
                &[],
                range.clone(),
                filters,
                algorithm_version,
                options,
                window.final_segment && index + 1 == block_count,
                None,
                scratch,
                Some(&anchors),
                &distances[at..at + range.len() * stride],
            )
        };
        #[cfg(feature = "parallel")]
        let encoded: Vec<Result<Vec<u8>>> = if wave_end - block > 1 {
            use rayon::prelude::*;
            (block..wave_end)
                .into_par_iter()
                .map(|index| {
                    let mut scratch = scratch_pool.take();
                    let result = block_output(index, &mut scratch);
                    scratch_pool.put(scratch);
                    result
                })
                .collect()
        } else {
            let mut scratch = scratch_pool.take();
            let encoded = vec![block_output(block, &mut scratch)];
            scratch_pool.put(scratch);
            encoded
        };
        #[cfg(not(feature = "parallel"))]
        let encoded: Vec<Result<Vec<u8>>> = {
            let mut scratch = scratch_pool.take();
            let encoded = (block..wave_end)
                .map(|index| block_output(index, &mut scratch))
                .collect();
            scratch_pool.put(scratch);
            encoded
        };
        for packed in encoded {
            out.extend(packed?);
        }
        tokenized = tokenized.saturating_add(wave.len());
        block = wave_end;
        anchors.release_below(block.saturating_sub(blocks_in_dictionary + 1));
        if progress
            .as_deref_mut()
            .is_some_and(|report| !report(tokenized))
        {
            return Err(Error::Cancelled);
        }
    }
    if progress.is_some_and(|report| !report(data.len())) {
        return Err(Error::Cancelled);
    }
    Ok(out)
}

/// The blocks of one member on the rayon pool, `width` at a time, with no
/// barrier between them: `width` worker tasks each take the next block
/// index off a shared counter until the member is exhausted, so a slow
/// block never idles the others (nzbfast-local change, 5 Sep 2026; the
/// first cut ran barrier-separated waves and lost the tail of every wave -
/// see VENDORING.md). The calling thread owns the (single-threaded)
/// progress callback: it drains finished blocks into the output IN ORDER as
/// they complete, so the output held in flight stays near `width` blocks
/// rather than the whole member, and it reports the tokenized bytes on
/// every completion or every few milliseconds, whichever comes first. When
/// the callback refuses, a flag every block's tokenizer polls at its own
/// checkpoints stops the workers within a checkpoint, as on the serial walk.
/// An error in one block stops the workers taking new ones; the first error
/// in block order is the one returned, as the serial walk would have.
#[cfg(feature = "parallel")]
// Every argument names a different thing the encoder needs and no two
// of them travel together, so a parameter struct here would be a bag
// with one field per argument and a second name for each. The lint's
// ceiling is 7; these are 8 and 10.
#[allow(clippy::too_many_arguments)]
fn encode_blocks_pooled(
    data: &[u8],
    history_tail: &[u8],
    filters: &[EncodeFilter],
    algorithm_version: u8,
    options: EncodeOptions,
    block_count: usize,
    width: usize,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
    window: MemberWindow,
    scratch_pool: &EncoderScratchPool,
) -> Result<Vec<u8>> {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Condvar, Mutex};
    let first_block = window.first_block;
    let next_block = AtomicUsize::new(first_block);
    let cancelled = AtomicBool::new(false);
    let failed = AtomicBool::new(false);
    let tokenized = AtomicUsize::new(0);
    let slots: Vec<Mutex<Option<Result<Vec<u8>>>>> =
        (0..block_count).map(|_| Mutex::new(None)).collect();
    // Finished-block count, and the condvar the drain loop parks on.
    let finished = (Mutex::new(0usize), Condvar::new());
    let anchors = MemberAnchors::new(data);
    let blocks_in_dictionary = options
        .max_match_distance
        .div_ceil(MAX_COMPRESSED_BLOCK_OUTPUT);
    let mut out = Vec::new();
    let mut drained = first_block;
    let mut first_error = None;
    // One block, wherever it runs: a spawned worker or - see the drain loop
    // below - the calling thread itself. Shared by both so the two cannot
    // drift; it takes its scratch by reference because a worker keeps one
    // for its whole run.
    let encode_one = |block: usize, scratch: &mut EncoderScratch| {
        let range = member_block_range(data.len(), block);
        let mut last = 0usize;
        let mut block_progress = |position: usize| {
            tokenized.fetch_add(position.saturating_sub(last), Ordering::Relaxed);
            last = last.max(position);
            !cancelled.load(Ordering::Relaxed)
        };
        let result = encode_member_region(
            data,
            history_tail,
            range,
            filters,
            algorithm_version,
            options,
            window.final_segment && block + 1 == block_count,
            Some(&mut block_progress),
            scratch,
            Some(&anchors),
            &[],
        );
        if result.is_err() {
            failed.store(true, Ordering::Relaxed);
        }
        *slots[block]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(result);
        let (count, wake) = &finished;
        *count
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) += 1;
        wake.notify_all();
    };
    let mut owner_scratch: Option<EncoderScratch> = None;
    rayon::in_place_scope(|scope| {
        for _ in 0..width {
            let (next_block, cancelled, failed, encode_one) =
                (&next_block, &cancelled, &failed, &encode_one);
            scope.spawn(move |_| {
                let mut scratch = scratch_pool.take();
                loop {
                    if cancelled.load(Ordering::Relaxed) || failed.load(Ordering::Relaxed) {
                        break;
                    }
                    let block = next_block.fetch_add(1, Ordering::Relaxed);
                    if block >= block_count {
                        break;
                    }
                    encode_one(block, &mut scratch);
                }
                scratch_pool.put(scratch);
            });
        }
        // The calling thread: drain in order, report, and watch for refusal.
        let (count, wake) = &finished;
        let mut seen = 0usize;
        loop {
            while drained < block_count && first_error.is_none() {
                let mut slot = slots[drained]
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                match slot.take() {
                    Some(Ok(bytes)) => {
                        drop(slot);
                        out.extend(bytes);
                        drained += 1;
                        // Blocks in flight are at or past `drained`; their
                        // history begins within `blocks_in_dictionary` of it.
                        anchors.release_below(drained.saturating_sub(blocks_in_dictionary + 1));
                    }
                    Some(Err(error)) => {
                        first_error = Some(error);
                    }
                    None => break,
                }
            }
            if drained == block_count || first_error.is_some() || cancelled.load(Ordering::Relaxed)
            {
                break;
            }
            if progress
                .as_deref_mut()
                .is_some_and(|report| !report(tokenized.load(Ordering::Relaxed).min(data.len())))
            {
                cancelled.store(true, Ordering::Relaxed);
                break;
            }
            // NOTHING TO DRAIN, AND THIS THREAD MUST NOT PARK WHILE A BLOCK
            // IS STILL UNCLAIMED. `in_place_scope` runs the calling thread's
            // body on the calling thread, which under `rayon::join` (the
            // volume writer) or `map_slice_collect` (the multi-group walk) is
            // a POOL thread. Parking it here holds a pool thread that the
            // `width` jobs just spawned need in order to run at all, so with
            // as many concurrent member encodes as the pool has threads every
            // one of them parked waiting for jobs none of them could run -
            // a permanent starvation deadlock at near-zero CPU, not a slow
            // encode. It cap-killed `unit-one-process` on a two-thread runner
            // for an unknown number of pushes (11 Sep 2026), where the two
            // chase fixtures in nzbkit compress concurrently; the 5 ms
            // timeout below made it look like a hang rather than a wedge.
            // Taking a block HERE is what makes progress unconditional: in
            // the worst case, with no worker ever scheduled, the calling
            // thread encodes the whole member itself (nzbfast-local change,
            // 11 Sep 2026).
            let block = next_block.fetch_add(1, Ordering::Relaxed);
            if block < block_count {
                encode_one(
                    block,
                    owner_scratch.get_or_insert_with(|| scratch_pool.take()),
                );
                continue;
            }
            // Every remaining block is claimed, and a block is only ever
            // claimed by a thread that is already RUNNING the closure that
            // finishes it - so this park is always woken.
            let guard = count
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let (guard, _) = wake
                .wait_timeout_while(guard, std::time::Duration::from_millis(5), |done| {
                    *done == seen
                })
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            seen = *guard;
        }
    });
    if let Some(scratch) = owner_scratch.take() {
        scratch_pool.put(scratch);
    }
    if cancelled.load(Ordering::Relaxed) {
        return Err(Error::Cancelled);
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    // Blocks still in their slots finished after the drain loop stopped;
    // the first error in block order wins, as on the serial walk.
    for slot in slots.into_iter().skip(drained) {
        match slot
            .into_inner()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
        {
            Some(Ok(bytes)) => out.extend(bytes),
            Some(Err(error)) => return Err(error),
            None => {
                return Err(Error::InvalidData(
                    "RAR 5 block encoder left a block unencoded",
                ))
            }
        }
    }
    if progress.is_some_and(|report| !report(data.len())) {
        return Err(Error::Cancelled);
    }
    Ok(out)
}

// Live from `codec::rar50::ratio` (the `ratio-lab` feature) and from
// `filtered_lz_blocks`; with the feature off the chain above it is
// unreferenced and this falls out with it.
#[allow(dead_code)]
fn encode_lz_block(
    data: &[u8],
    history: &[u8],
    algorithm_version: u8,
    initial_filters: &[EncodeFilter],
    options: EncodeOptions,
    is_last: bool,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<u8>> {
    encode_lz_block_with_scratch(
        data,
        history,
        algorithm_version,
        initial_filters,
        options,
        is_last,
        progress,
        &mut EncoderScratch::default(),
    )
}

#[allow(clippy::too_many_arguments)]
fn encode_lz_block_with_scratch(
    data: &[u8],
    history: &[u8],
    algorithm_version: u8,
    initial_filters: &[EncodeFilter],
    options: EncodeOptions,
    is_last: bool,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
    scratch: &mut EncoderScratch,
) -> Result<Vec<u8>> {
    encode_lz_block_in_span(
        data,
        history,
        algorithm_version,
        initial_filters,
        options,
        is_last,
        progress,
        scratch,
        None,
        None,
        &[],
    )
}

#[allow(clippy::too_many_arguments)]
fn encode_lz_block_in_span(
    data: &[u8],
    history: &[u8],
    algorithm_version: u8,
    initial_filters: &[EncodeFilter],
    options: EncodeOptions,
    is_last: bool,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
    scratch: &mut EncoderScratch,
    indexed_span: Option<&[u8]>,
    long_seed: Option<LongSeed<'_>>,
    tree: &[std::sync::atomic::AtomicU32],
) -> Result<Vec<u8>> {
    let distance_size = match algorithm_version {
        0 => DISTANCE_TABLE_SIZE_50,
        1 => DISTANCE_TABLE_SIZE_70,
        _ => {
            return Err(Error::InvalidData(
                "RAR 5 unknown compression algorithm version",
            ))
        }
    };
    let tokens = encode_tokens_in_span(
        data,
        history,
        options,
        distance_size,
        progress,
        scratch,
        indexed_span,
        long_seed,
        tree,
    )?;
    let out = encode_token_blocks(
        data,
        &tokens,
        initial_filters,
        algorithm_version,
        distance_size,
        is_last,
        ENTROPY_BLOCK_BYTES,
        options,
        &mut scratch.boundaries,
    )?;
    // The token vector goes back to the scratch for the next block.
    scratch.tokens = tokens;
    scratch.tokens.clear();
    Ok(out)
}

/// How much INPUT one set of Huffman tables covers. The tokenizer's work
/// item stays the 4 MiB block (one history seed, one pool task); its token
/// stream is then cut into entropy blocks of about this many input bytes,
/// each written as its own RAR 5 compressed block with fresh tables, so a
/// stretch of text and the already-compressed bytes after it are not priced
/// with one shared code. One table set per 4 MiB was the larger half of the
/// size gap to `rar` at equal dictionary: on the 1 GiB mixed corpus at a
/// 1 MiB dictionary 663.6 MB -> 587.1 MB at 256 KiB (rar 7.23: 590.1 MB),
/// 580.2 MB at 64 KiB; at 32 MiB 585.6 -> 527.4 MB (rar 468.9, the rest
/// being long-range matches the index does not reach). A table set costs a
/// few hundred bytes and the reader a table decode per block: extracting
/// the 32 MiB-dictionary archive took 0.39 s with one table per 4 MiB,
/// 0.38-0.40 s at 256 KiB and 0.48-0.50 s at 64 KiB, which is why the cut
/// is not finer. The rep-distance state carries across entropy
/// blocks exactly as the reader's does across every block of a file.
/// (nzbfast-local change, 6 Sep 2026; see VENDORING.md.)
const ENTROPY_BLOCK_BYTES: usize = 256 << 10;
/// ...and at least this many tokens per table: a stretch of 4 KiB matches
/// has 64 tokens per 256 KiB, and a table set for 64 symbols costs more
/// than it can save (the repeated-payload corpus grew 1.3% on tables
/// alone before this floor).
const ENTROPY_BLOCK_MIN_TOKENS: usize = 1024;

/// Token ranges covering about `target_bytes` of input each and at least
/// [`ENTROPY_BLOCK_MIN_TOKENS`] tokens, cut at token boundaries (a match is
/// never split), always at least one range.
fn entropy_block_token_ranges(tokens: &[EncodeToken], target_bytes: usize) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut start = 0usize;
    let mut bytes = 0usize;
    for (index, token) in tokens.iter().enumerate() {
        bytes += token.length;
        if bytes >= target_bytes && index + 1 - start >= ENTROPY_BLOCK_MIN_TOKENS {
            ranges.push(start..index + 1);
            start = index + 1;
            bytes = 0;
        }
    }
    if start < tokens.len() || ranges.is_empty() {
        ranges.push(start..tokens.len());
    }
    ranges
}

/// The token stream of one tokenizer block as a run of RAR 5 compressed
/// blocks, each with its own tables (see [`ENTROPY_BLOCK_BYTES`]). The
/// initial filters ride the first block; the last carries `is_last`.
///
/// WHERE the cuts fall is `options.adaptive_entropy_blocks`: by default
/// `boundaries` picks them by exact encoded cost, and with the switch off
/// they are the fixed [`entropy_block_token_ranges`] cut this function
/// always made. (nzbfast-local change, 7 Sep 2026; see VENDORING.md.)
#[allow(clippy::too_many_arguments)]
fn encode_token_blocks(
    data: &[u8],
    tokens: &[EncodeToken],
    initial_filters: &[EncodeFilter],
    algorithm_version: u8,
    distance_size: usize,
    is_last: bool,
    target_bytes: usize,
    options: EncodeOptions,
    scratch: &mut boundaries::BoundaryScratch,
) -> Result<Vec<u8>> {
    if options.adaptive_entropy_blocks {
        return boundaries::encode_token_blocks_adaptive(
            data,
            tokens,
            initial_filters,
            algorithm_version,
            distance_size,
            is_last,
            target_bytes,
            scratch,
        );
    }
    emit_entropy_blocks(
        data,
        tokens,
        &entropy_block_token_ranges(tokens, target_bytes),
        initial_filters,
        algorithm_version,
        distance_size,
        is_last,
    )
}

/// The token ranges of one tokenizer block written out as compressed
/// blocks, in order, with one rep-distance state carried through them.
/// The single emitter both boundary choices go through.
fn emit_entropy_blocks(
    data: &[u8],
    tokens: &[EncodeToken],
    ranges: &[Range<usize>],
    initial_filters: &[EncodeFilter],
    algorithm_version: u8,
    distance_size: usize,
    is_last: bool,
) -> Result<Vec<u8>> {
    let last = ranges.len() - 1;
    let mut out = Vec::new();
    let mut state = EncoderMatchState::default();
    let mut output_pos = 0usize;
    let at_token = filter_token_indices(tokens, initial_filters);
    for (index, range) in ranges.iter().enumerate() {
        // The records whose token falls in this range; the last range also
        // takes those past the final token.
        let filters: Vec<EncodeFilter> = initial_filters
            .iter()
            .zip(&at_token)
            .filter(|(_, &(token, _))| {
                range.contains(&token) || (index == last && token >= range.end)
            })
            .map(|(&filter, _)| filter)
            .collect();
        let (block, next_pos) = encode_token_block(
            data,
            &tokens[range.clone()],
            output_pos,
            &filters,
            algorithm_version,
            distance_size,
            &mut state,
            is_last && index == last,
        )?;
        out.extend_from_slice(&block);
        output_pos = next_pos;
    }
    Ok(out)
}

/// For each filter record (offsets in the coordinates `tokens` cover from
/// position 0), the index of the token whose span holds its start, or
/// `tokens.len()` for a record at or past the end, with the position of
/// that token (the record is written as an offset from it). The emitter writes a
/// record just before that token, as an offset from the position there,
/// so a record anywhere in a tokenizer block is legal input and the
/// pricing in `boundaries` charges it to the entropy block that carries
/// it. (nzbfast-local change, 7 Sep 2026; see VENDORING.md.)
pub(super) fn filter_token_indices(
    tokens: &[EncodeToken],
    filters: &[EncodeFilter],
) -> Vec<(usize, usize)> {
    let mut out = Vec::with_capacity(filters.len());
    let mut token = 0usize;
    let mut pos = 0usize;
    for filter in filters {
        while token < tokens.len() && pos + tokens[token].length <= filter.offset {
            pos += tokens[token].length;
            token += 1;
        }
        out.push((token, pos));
    }
    out
}

/// One RAR 5 compressed block with tables built from exactly these tokens.
/// `state` is the rep-distance state at the block's start and is advanced
/// through it; the frequency pass runs on a copy so both passes see the
/// same states. Returns the framed block and the input position after it.
/// `initial_filters` are written where their offsets fall: each just before
/// the first token whose span reaches it (records must be in offset order),
/// any past the last token after it.
#[allow(clippy::too_many_arguments)]
fn encode_token_block(
    data: &[u8],
    tokens: &[EncodeToken],
    start_pos: usize,
    initial_filters: &[EncodeFilter],
    algorithm_version: u8,
    distance_size: usize,
    state: &mut EncoderMatchState,
    is_last: bool,
) -> Result<(Vec<u8>, usize)> {
    let mut lengths = TableLengths {
        main: vec![0; MAIN_TABLE_SIZE],
        distance: vec![0; distance_size],
        align: vec![0; ALIGN_TABLE_SIZE],
        length: vec![0; LENGTH_TABLE_SIZE],
    };

    let mut main_frequencies = vec![0usize; MAIN_TABLE_SIZE];
    main_frequencies[256] = initial_filters.len();
    let mut distance_frequencies = vec![0usize; distance_size];
    let mut align_frequencies = vec![0usize; ALIGN_TABLE_SIZE];
    let mut length_frequencies = vec![0usize; LENGTH_TABLE_SIZE];
    let mut freq_state = *state;
    let mut output_pos = start_pos;
    for token in tokens {
        let length = token.length;
        let distance = token.distance;
        if distance == 0 {
            for &byte in &data[output_pos..output_pos + length] {
                main_frequencies[usize::from(byte)] += 1;
            }
        } else {
            match freq_state.encode_match(length, distance, distance_size)? {
                EncodedMatch::LastLengthRepeat => main_frequencies[257] += 1,
                EncodedMatch::RepeatDistance {
                    index, length_slot, ..
                } => {
                    main_frequencies[258 + index] += 1;
                    length_frequencies[length_slot] += 1;
                }
                EncodedMatch::New {
                    length_slot,
                    distance_slot,
                    distance_extra,
                    distance_bit_count,
                    ..
                } => {
                    main_frequencies[262 + length_slot] += 1;
                    distance_frequencies[distance_slot] += 1;
                    if distance_bit_count >= 4 {
                        align_frequencies[distance_extra & 0x0f] += 1;
                    }
                }
            }
            freq_state.remember(length, distance);
        }
        output_pos += length;
    }

    lengths.main = huffman::complete_lengths_for_frequencies(&main_frequencies, 15);
    lengths.distance = huffman::complete_lengths_for_frequencies(&distance_frequencies, 15);
    lengths.length = huffman::complete_lengths_for_frequencies(&length_frequencies, 15);
    lengths.align = huffman::complete_lengths_for_frequencies(&align_frequencies, 15);

    let main_table = EncoderTable::from_lengths(&lengths.main)?;
    let distance_table = EncoderTable::from_lengths(&lengths.distance)?;
    let align_table = EncoderTable::from_lengths(&lengths.align)?;
    let length_slot_codes = EncoderTable::from_lengths(&lengths.length)?;
    let (table_data, table_bits) =
        encode_table_lengths_with_bit_count(&lengths, algorithm_version)?;
    let mut writer = BitWriter::continuing(table_data, table_bits);
    let mut pending = initial_filters.iter().peekable();
    // A record's offset is relative to the position it is read at, which is
    // the token's own position; `output_pos` and the offsets share the
    // tokenizer block's coordinates.
    let mut emit_filters_before = |writer: &mut BitWriter, reach: usize, at: usize| -> Result<()> {
        while let Some(filter) = pending.next_if(|filter| filter.offset < reach) {
            let (code, len) = main_table.code_for_symbol(256)?;
            writer.write_bits(usize::from(code), usize::from(len));
            write_filter(
                writer,
                EncodeFilter {
                    offset: filter.offset.saturating_sub(at),
                    ..*filter
                },
            )?;
        }
        Ok(())
    };
    let mut output_pos = start_pos;
    for token in tokens {
        let length = token.length;
        let distance = token.distance;
        emit_filters_before(&mut writer, output_pos + length, output_pos)?;
        if distance == 0 {
            write_literal_codes(
                &mut writer,
                &main_table,
                &data[output_pos..output_pos + length],
            )?;
        } else {
            match state.encode_match(length, distance, distance_size)? {
                EncodedMatch::LastLengthRepeat => {
                    let (code, len) = main_table.code_for_symbol(257)?;
                    writer.write_bits(usize::from(code), usize::from(len));
                }
                EncodedMatch::RepeatDistance {
                    index,
                    length_slot,
                    length_extra,
                } => {
                    let (code, len) = main_table.code_for_symbol(258 + index)?;
                    writer.write_bits(usize::from(code), usize::from(len));
                    let (code, len) = length_slot_codes.code_for_symbol(length_slot)?;
                    writer.write_bits(usize::from(code), usize::from(len));
                    let length_extra_bits = length_slot_extra_bits(length_slot)?;
                    if length_extra_bits != 0 {
                        writer.write_bits(length_extra, usize::from(length_extra_bits));
                    }
                }
                EncodedMatch::New {
                    length_slot,
                    length_extra,
                    distance_slot,
                    distance_extra,
                    distance_bit_count,
                } => {
                    let (code, len) = main_table.code_for_symbol(262 + length_slot)?;
                    writer.write_bits(usize::from(code), usize::from(len));
                    let length_extra_bits = length_slot_extra_bits(length_slot)?;
                    if length_extra_bits != 0 {
                        writer.write_bits(length_extra, usize::from(length_extra_bits));
                    }
                    let (code, len) = distance_table.code_for_symbol(distance_slot)?;
                    writer.write_bits(usize::from(code), usize::from(len));
                    if distance_bit_count >= 4 {
                        if distance_bit_count > 4 {
                            writer.write_bits(distance_extra >> 4, distance_bit_count - 4);
                        }
                        let (code, len) = align_table.code_for_symbol(distance_extra & 0x0f)?;
                        writer.write_bits(usize::from(code), usize::from(len));
                    } else if distance_bit_count != 0 {
                        writer.write_bits(distance_extra, distance_bit_count);
                    }
                }
            }
            state.remember(length, distance);
        }
        output_pos += length;
    }
    emit_filters_before(&mut writer, usize::MAX, output_pos)?;

    let payload_bits = writer.bit_pos;
    Ok((
        encode_compressed_block(&writer.finish(), payload_bits, true, is_last)?,
        output_pos,
    ))
}

#[derive(Debug, Clone, Default)]
pub struct Rar50Encoder {
    history: Vec<u8>,
    options: EncodeOptions,
}

impl Rar50Encoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_options(options: EncodeOptions) -> Self {
        Self {
            history: Vec::new(),
            options,
        }
    }

    pub fn encode_member(&mut self, input: &[u8], algorithm_version: u8) -> Result<Vec<u8>> {
        let packed = encode_lz_member_with_history_and_options(
            input,
            &self.history,
            algorithm_version,
            self.options,
        )?;
        self.remember(input);
        Ok(packed)
    }

    #[cfg(test)]
    pub(crate) fn encode_member_with_progress(
        &mut self,
        input: &[u8],
        algorithm_version: u8,
        progress: &mut dyn FnMut(usize) -> bool,
    ) -> Result<Vec<u8>> {
        let packed = encode_lz_member_inner(
            input,
            &self.history,
            algorithm_version,
            &[],
            self.options,
            Some(progress),
        )?;
        self.remember(input);
        Ok(packed)
    }

    pub fn encode_member_with_filter(
        &mut self,
        input: &[u8],
        algorithm_version: u8,
        filter: Rar50FilterSpec,
    ) -> Result<Vec<u8>> {
        self.encode_member_with_filters(input, algorithm_version, &[filter])
    }

    pub fn encode_member_with_filters(
        &mut self,
        input: &[u8],
        algorithm_version: u8,
        filters: &[Rar50FilterSpec],
    ) -> Result<Vec<u8>> {
        self.encode_member_with_filters_pooled(
            input,
            algorithm_version,
            filters,
            None,
            &EncoderScratchPool::new(),
        )
    }

    /// The filtered member through the same pooled, tree-fed encoder an
    /// unfiltered member takes: the whole member is transformed first, in
    /// the codec's 262,143-byte filter chunks with one record per chunk and
    /// filter, and the records ride the blocks at their absolute offsets.
    /// It used to walk one-chunk blocks serially, without the tree or the
    /// pool (nzbfast-local change, 7 Sep 2026; see VENDORING.md).
    pub(crate) fn encode_member_with_filters_pooled(
        &mut self,
        input: &[u8],
        algorithm_version: u8,
        filters: &[Rar50FilterSpec],
        progress: Option<&mut dyn FnMut(usize) -> bool>,
        scratch: &EncoderScratchPool,
    ) -> Result<Vec<u8>> {
        let (filtered, records) = filtered_lz_member_records(input, filters)?;
        let packed = encode_lz_member_inner_pooled(
            &filtered,
            &self.history,
            algorithm_version,
            &records,
            self.options,
            progress,
            scratch,
        )?;
        // The window a solid successor is compressed against is what the
        // decoder keeps, and the decoder keeps the LZ output: the filtered
        // bytes, not `input`.
        self.remember(&filtered);
        Ok(packed)
    }

    /// The path [`Self::encode_member_with_filters`] took before 7 Sep
    /// 2026: one-filter-chunk blocks, walked serially, with no tree hints.
    /// Kept as the exact control the ratio lab's joint filter/tree
    /// encoder is tested against.
    // See `filtered_lz_blocks`: the callers are `ratio-lab`-only, so
    // this is unreferenced in a plain test build.
    #[allow(dead_code)]
    #[cfg(any(test, feature = "ratio-lab"))]
    pub(crate) fn encode_member_with_filters_chunked(
        &mut self,
        input: &[u8],
        algorithm_version: u8,
        filters: &[Rar50FilterSpec],
    ) -> Result<Vec<u8>> {
        if input.len() > MAX_FILTER_BLOCK_LENGTH {
            let (packed, history) = filtered_lz_blocks(
                input,
                filters,
                &self.history,
                algorithm_version,
                self.options,
                None,
            )?;
            self.history = history;
            return Ok(packed);
        }
        let (filtered, records) = filtered_lz_member(input, filters)?;
        let packed = encode_lz_member_inner(
            &filtered,
            &self.history,
            algorithm_version,
            &records,
            self.options,
            None,
        )?;
        self.remember(&filtered);
        Ok(packed)
    }

    pub(crate) fn encode_member_with_filters_and_progress(
        &mut self,
        input: &[u8],
        algorithm_version: u8,
        filters: &[Rar50FilterSpec],
        progress: &mut dyn FnMut(usize) -> bool,
    ) -> Result<Vec<u8>> {
        self.encode_member_with_filters_pooled(
            input,
            algorithm_version,
            filters,
            Some(progress),
            &EncoderScratchPool::new(),
        )
    }

    fn remember(&mut self, input: &[u8]) {
        self.history.extend_from_slice(input);
        let keep_from = self
            .history
            .len()
            .saturating_sub(self.options.max_match_distance);
        if keep_from != 0 {
            self.history.drain(..keep_from);
        }
    }
}

// nzbfast-local change, 5 Sep 2026 — literal-run tokens; see VENDORING.md.
// A zero distance denotes a literal run in the current block input.
// Match lengths and literal-run lengths share the same field.
#[derive(Debug, Clone, Copy)]
pub(super) struct EncodeToken {
    length: usize,
    distance: usize,
}
impl EncodeToken {
    fn push_literal(tokens: &mut Vec<Self>) {
        Self::push_literals(tokens, 1);
    }
    fn push_literals(tokens: &mut Vec<Self>, count: usize) {
        if let Some(last) = tokens.last_mut() {
            if last.distance == 0 {
                last.length += count;
                return;
            }
        }
        tokens.push(Self {
            length: count,
            distance: 0,
        });
    }
    fn matched(length: usize, distance: usize) -> Self {
        Self { length, distance }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct EncodeFilter {
    offset: usize,
    length: usize,
    filter_type: FilterType,
    channels: usize,
}

#[derive(Debug, Clone, Copy, Default)]
struct EncoderMatchState {
    reps: [usize; 4],
    previous_match_length: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncodedMatch {
    LastLengthRepeat,
    RepeatDistance {
        index: usize,
        length_slot: usize,
        length_extra: usize,
    },
    New {
        length_slot: usize,
        length_extra: usize,
        distance_slot: usize,
        distance_extra: usize,
        distance_bit_count: usize,
    },
}

impl EncoderMatchState {
    fn encode_match(
        &self,
        length: usize,
        distance: usize,
        distance_size: usize,
    ) -> Result<EncodedMatch> {
        if distance == self.reps[0] && length == self.previous_match_length && self.previous_match_length != 0 {
            return Ok(EncodedMatch::LastLengthRepeat);
        }
        if let Some(index) = self
            .reps
            .iter()
            .position(|&repeat_distance| repeat_distance == distance && repeat_distance != 0)
        {
            let (length_slot, length_extra) = length_slot_for_match(length)?;
            return Ok(EncodedMatch::RepeatDistance {
                index,
                length_slot,
                length_extra,
            });
        }

        let (distance_slot, distance_extra) = distance_slot_for_match(distance, distance_size)?;
        let encoded_length = length
            .checked_sub(length_bonus(distance))
            .ok_or(Error::InvalidData("RAR 5 adjusted match length underflows"))?;
        let distance_bit_count = distance_slot_bit_count(distance_slot)?;
        let (length_slot, length_extra) = length_slot_for_match(encoded_length)?;
        Ok(EncodedMatch::New {
            length_slot,
            length_extra,
            distance_slot,
            distance_extra,
            distance_bit_count,
        })
    }

    fn remember(&mut self, length: usize, distance: usize) {
        if distance == self.reps[0] && length == self.previous_match_length {
            return;
        }
        if let Some(index) = self
            .reps
            .iter()
            .position(|&repeat_distance| repeat_distance == distance)
        {
            self.reps[..=index].rotate_right(1);
        } else {
            self.reps.rotate_right(1);
        }
        self.reps[0] = distance;
        self.previous_match_length = length;
    }
}

#[cfg(test)]
fn encode_tokens(
    input: &[u8],
    history: &[u8],
    options: EncodeOptions,
    distance_size: usize,
) -> Vec<EncodeToken> {
    encode_tokens_with_progress(input, history, options, distance_size, None)
        .expect("encoding without cancellation cannot be cancelled")
}

// Match positions are offsets into the combined history/input buffer. Keep
// full-width storage available for spans that do not fit in u32.
// (nzbfast-local change, 5 Sep 2026; see VENDORING.md.)
trait MatchPosition: Copy {
    /// Bits a slot holds - what is left above a position is the tag.
    const BITS: u32;
    fn from_position(pos: usize) -> Self;
    fn position(self) -> usize;
}

impl MatchPosition for usize {
    const BITS: u32 = usize::BITS;
    fn from_position(pos: usize) -> Self {
        pos
    }
    fn position(self) -> usize {
        self
    }
}

impl MatchPosition for u32 {
    const BITS: u32 = u32::BITS;
    fn from_position(pos: usize) -> Self {
        // Dispatch checked the whole indexed span before choosing u32.
        // Insertions only use positions within that span (a tagged slot
        // value keeps its tag inside the 32 bits, by `tag_bits`).
        debug_assert!(u32::try_from(pos).is_ok());
        pos as u32
    }
    fn position(self) -> usize {
        self as usize
    }
}

fn compact_match_index_fits(input_len: usize, history_len: usize, max_distance: usize) -> bool {
    input_len
        .checked_add(history_len.min(max_distance))
        .is_some_and(|len| u32::try_from(len).is_ok())
}

#[cfg(test)]
fn encode_tokens_with_progress(
    input: &[u8],
    history: &[u8],
    options: EncodeOptions,
    distance_size: usize,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<EncodeToken>> {
    encode_tokens_with_scratch(
        input,
        history,
        options,
        distance_size,
        progress,
        &mut EncoderScratch::default(),
    )
}

#[cfg(test)]
fn encode_tokens_with_scratch(
    input: &[u8],
    history: &[u8],
    options: EncodeOptions,
    distance_size: usize,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
    scratch: &mut EncoderScratch,
) -> Result<Vec<EncodeToken>> {
    encode_tokens_in_span(
        input,
        history,
        options,
        distance_size,
        progress,
        scratch,
        None,
        None,
        &[],
    )
}

#[allow(clippy::too_many_arguments)]
fn encode_tokens_in_span(
    input: &[u8],
    history: &[u8],
    options: EncodeOptions,
    distance_size: usize,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
    scratch: &mut EncoderScratch,
    indexed_span: Option<&[u8]>,
    long_seed: Option<LongSeed<'_>>,
    tree: &[std::sync::atomic::AtomicU32],
) -> Result<Vec<EncodeToken>> {
    let mut tokens = std::mem::take(&mut scratch.tokens);
    tokens.clear();
    if options.max_match_candidates == 0 || options.max_match_distance == 0 {
        // The entire input is one literal run. Preserve the original progress
        // checkpoints without allocating a hash index or copying history.
        let mut consumed = 1usize;
        while consumed <= input.len() {
            if progress
                .as_deref_mut()
                .is_some_and(|report| !report(consumed))
            {
                return Err(Error::Cancelled);
            }
            consumed = consumed.saturating_add(1024 * 1024);
        }
        if progress.is_some_and(|report| !report(input.len())) {
            return Err(Error::Cancelled);
        }
        if !input.is_empty() {
            tokens.push(EncodeToken {
                length: input.len(),
                distance: 0,
            });
        }
        return Ok(tokens);
    }
    if compact_match_index_fits(input.len(), history.len(), options.max_match_distance) {
        let indexed_len = input.len() + history.len().min(options.max_match_distance);
        let index = scratch.index(indexed_len, options.max_match_candidates);
        let (tokens, index) = encode_tokens_indexed_in_span::<u32>(
            input,
            history,
            options,
            distance_size,
            progress,
            index,
            tokens,
            indexed_span,
            long_seed,
            tree,
        )?;
        scratch.index = Some(index);
        Ok(tokens)
    } else {
        let indexed_len = input.len() + history.len().min(options.max_match_distance);
        let index = MatchIndex::<usize>::new(indexed_len, options.max_match_candidates);
        encode_tokens_indexed_in_span::<usize>(
            input,
            history,
            options,
            distance_size,
            progress,
            index,
            tokens,
            indexed_span,
            long_seed,
            tree,
        )
        .map(|(tokens, _)| tokens)
    }
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn encode_tokens_indexed<P: MatchPosition>(
    input: &[u8],
    history: &[u8],
    options: EncodeOptions,
    distance_size: usize,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
    buckets: MatchIndex<P>,
    tokens: Vec<EncodeToken>,
) -> Result<(Vec<EncodeToken>, MatchIndex<P>)> {
    encode_tokens_indexed_in_span::<P>(
        input,
        history,
        options,
        distance_size,
        progress,
        buckets,
        tokens,
        None,
        None,
        &[],
    )
}

#[allow(clippy::too_many_arguments)]
fn encode_tokens_indexed_in_span<P: MatchPosition>(
    input: &[u8],
    history: &[u8],
    options: EncodeOptions,
    distance_size: usize,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
    mut buckets: MatchIndex<P>,
    tokens: Vec<EncodeToken>,
    indexed_span: Option<&[u8]>,
    long_seed: Option<LongSeed<'_>>,
    tree: &[std::sync::atomic::AtomicU32],
) -> Result<(Vec<EncodeToken>, MatchIndex<P>)> {
    let history = &history[history.len().saturating_sub(options.max_match_distance)..];
    let combined = if let Some(span) = indexed_span {
        debug_assert_eq!(span.len(), history.len() + input.len());
        std::borrow::Cow::Borrowed(span)
    } else if history.is_empty() {
        std::borrow::Cow::Borrowed(input)
    } else {
        let mut combined = Vec::with_capacity(history.len() + input.len());
        combined.extend_from_slice(history);
        combined.extend_from_slice(input);
        std::borrow::Cow::Owned(combined)
    };
    // The stride is carried in the slice's own shape rather than in a
    // parameter through five call layers: the finder writes `stride` slots
    // per position of `input` and nothing else shares the buffer.
    debug_assert!(tree.is_empty() || tree.len().is_multiple_of(input.len().max(1)));
    let stride = if tree.is_empty() || input.is_empty() {
        0
    } else {
        tree.len() / input.len()
    };
    let tree = TreeMatches {
        base: history.len(),
        distances: tree,
        stride,
    };
    buckets.seed_history(&combined, history.len(), long_seed);
    walk_tokens(
        &combined,
        history.len(),
        combined.len(),
        options,
        distance_size,
        progress,
        buckets,
        tokens,
        tree,
    )
}

/// The tokenizer's walk over `combined[start..end]` with `combined[..start]`
/// as its history, on an index that already holds every position the walk
/// may reach back to: [`encode_tokens_indexed_in_span`] seeds the index
/// and calls this; [`LiveSpanEncoder`] calls it member after member on
/// one index that the walks themselves keep current, so a solid group's
/// members never re-seed the dictionary (nzbfast-local change, 6 Sep
/// 2026; see VENDORING.md). Matches never reach past `end`.
#[allow(clippy::too_many_arguments)]
fn walk_tokens<P: MatchPosition>(
    combined: &[u8],
    start: usize,
    end: usize,
    options: EncodeOptions,
    distance_size: usize,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
    mut buckets: MatchIndex<P>,
    mut tokens: Vec<EncodeToken>,
    tree: TreeMatches<'_>,
) -> Result<(Vec<EncodeToken>, MatchIndex<P>)> {
    if options.optimal_parse {
        return walk_tokens_optimal(
            combined,
            start,
            end,
            options,
            distance_size,
            progress,
            buckets,
            tokens,
            tree,
        );
    }
    let input = &combined[start..end];

    let mut pos = start;
    let mut state = EncoderMatchState::default();
    let mut next_report = 0usize;
    let mut literal_run = 0usize;
    // The lazy parser's probe at `pos + 1` is the search the next iteration
    // would run from scratch when it defers, so it is kept: `probed` is
    // `Some(best_match(pos))` when the previous iteration already computed
    // it. The position deferred over is inserted BEFORE the probe, so the
    // probe sees exactly what the fresh search would have (the old order
    // inserted it after, and the fresh search saw one candidate more).
    // (nzbfast-local change, 5 Sep 2026; see VENDORING.md.)
    let prices = LiteralPrices::new(input, start);
    let mut probed: Option<(Option<MatchCandidate>, bool)> = None;
    while pos < end {
        let (candidate, saw_prefix_match) = match probed.take() {
            Some(probe) => probe,
            None => best_match_probe(
                combined,
                pos,
                end,
                &buckets,
                options,
                &state,
                distance_size,
                &prices,
                tree,
            ),
        };
        if saw_prefix_match {
            literal_run = 0;
        }
        if let Some(candidate) = candidate {
            if options.lazy_matching && pos + 1 < end {
                insert_match_position(combined, pos, &mut buckets);
                let next = best_match_probe(
                    combined,
                    pos + 1,
                    end,
                    &buckets,
                    options,
                    &state,
                    distance_size,
                    &prices,
                    tree,
                );
                let deferred = next.0.is_some_and(|next| {
                    next.score > candidate.score + prices.bits(pos, 1) as isize
                }) || should_lazy_emit_literal_beyond_one(
                    combined,
                    pos,
                    &buckets,
                    options,
                    &state,
                    distance_size,
                    candidate,
                    &prices,
                    tree,
                );
                if deferred {
                    EncodeToken::push_literal(&mut tokens);
                    pos += 1;
                    probed = Some(next);
                    continue;
                }
                let MatchCandidate {
                    length, distance, ..
                } = candidate;
                tokens.push(EncodeToken::matched(length, distance));
                state.remember(length, distance);
                insert_match_range(combined, pos + 1..pos + length, &mut buckets);
                pos += length;
                literal_run = 0;
            } else {
                let MatchCandidate {
                    length, distance, ..
                } = candidate;
                tokens.push(EncodeToken::matched(length, distance));
                state.remember(length, distance);
                insert_match_range(combined, pos..pos + length, &mut buckets);
                pos += length;
            }
        } else {
            let step = (1 + (literal_run >> LITERAL_SKIP_STRENGTH))
                .min(LITERAL_SKIP_MAX)
                .min(end - pos);
            EncodeToken::push_literals(&mut tokens, step);
            insert_match_range(combined, pos..pos + step, &mut buckets);
            literal_run += step;
            pos += step;
        }
        let consumed = pos.saturating_sub(start);
        if consumed >= next_report {
            if progress
                .as_deref_mut()
                .is_some_and(|report| !report(consumed))
            {
                return Err(Error::Cancelled);
            }
            next_report = consumed.saturating_add(1024 * 1024);
        }
    }
    if progress.is_some_and(|report| !report(input.len())) {
        return Err(Error::Cancelled);
    }
    Ok((tokens, buckets))
}

/// The lazy parser's probes at offsets two and beyond; offset one is the
/// tokenizer's own, cached probe.
#[allow(clippy::too_many_arguments)]
fn should_lazy_emit_literal_beyond_one<P: MatchPosition>(
    input: &[u8],
    pos: usize,
    buckets: &MatchIndex<P>,
    options: EncodeOptions,
    state: &EncoderMatchState,
    distance_size: usize,
    current: MatchCandidate,
    prices: &LiteralPrices,
    tree: TreeMatches<'_>,
) -> bool {
    let end = input.len();
    let lookahead = options.lazy_lookahead.max(1);
    if lookahead < 2 {
        return false;
    }
    (2..=lookahead)
        .take_while(|offset| pos + offset < end)
        .any(|offset| {
            best_match_probe(
                input,
                pos + offset,
                end,
                buckets,
                options,
                state,
                distance_size,
                prices,
                tree,
            )
            .0
            .is_some_and(|next| {
                let skipped_literal_score = prices.bits(pos, offset) as isize;
                next.score > current.score + skipped_literal_score
            })
        })
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn should_lazy_emit_literal<P: MatchPosition>(
    input: &[u8],
    pos: usize,
    buckets: &MatchIndex<P>,
    options: EncodeOptions,
    state: &EncoderMatchState,
    distance_size: usize,
    current: MatchCandidate,
    prices: &LiteralPrices,
) -> bool {
    let end = input.len();
    if !options.lazy_matching || pos + 1 >= end {
        return false;
    }
    let lookahead = options.lazy_lookahead.max(1);
    (1..=lookahead)
        .take_while(|offset| pos + offset < end)
        .any(|offset| {
            best_match(
                input,
                pos + offset,
                end,
                buckets,
                options,
                state,
                distance_size,
                prices,
            )
            .is_some_and(|next| {
                let skipped_literal_score = prices.bits(pos, offset) as isize;
                next.score > current.score + skipped_literal_score
            })
        })
}

/// What the block's literals cost, byte by byte: the order-0 Huffman code
/// length of each byte value over the block's own input, prefix-summed so
/// the literal cost of any range is two loads. A match is worth taking only
/// when its estimated bits are fewer than the literals it replaces, and its
/// score is the bits it saves; the old rule (`16 * length - cost`) accepted
/// every match of four bytes or more, so on text, where a literal costs five
/// bits, a four-byte match at a new distance costing ~30 bits was taken over
/// ~20 bits of literals. The final table differs from this estimate (it
/// counts emitted literals only), but the estimate is the same one the
/// block's frequencies would give before any match is chosen.
/// (nzbfast-local change, 5 Sep 2026; see VENDORING.md.)
struct LiteralPrices {
    /// Offset of the block's input inside the combined history/input span.
    base: usize,
    prefix: Vec<u32>,
    /// The per-byte code lengths the prefix was summed from, which the
    /// cost-based parse starts its price model from (see
    /// [`TokenPrices::constant`]).
    byte_price: [u8; 256],
}

impl LiteralPrices {
    /// One price table per tokenizer block. Pricing each 256 KiB entropy
    /// block by its own lengths was tried (6 Sep 2026): -0.4% of size on
    /// the mixed corpus for +13% of CPU, the sharper prices sending the
    /// parser after more matches; not kept.
    fn new(input: &[u8], base: usize) -> Self {
        // Four interleaved histograms break the store-to-load chain a single
        // table has on repeated bytes, and every fourth byte is enough of a
        // sample for a code-length estimate over megabytes (a block under
        // 64 KiB is counted whole). Measured: the single-table full count
        // cost about a millisecond per MiB, a quarter of the model's cost.
        let stride = if input.len() >= 64 << 10 { 4 } else { 1 };
        let mut counts = [[0u32; 256]; 4];
        let mut chunks = input.chunks_exact(4 * stride);
        for chunk in &mut chunks {
            counts[0][usize::from(chunk[0])] += 1;
            counts[1][usize::from(chunk[stride])] += 1;
            counts[2][usize::from(chunk[2 * stride])] += 1;
            counts[3][usize::from(chunk[3 * stride])] += 1;
        }
        for &byte in chunks.remainder() {
            counts[0][usize::from(byte)] += 1;
        }
        let mut frequencies = [0usize; 256];
        for table in &counts {
            for (byte, &count) in table.iter().enumerate() {
                frequencies[byte] += count as usize;
            }
        }
        // A byte the sample never saw still occurs; price it as a rare
        // symbol rather than an absent one.
        let lengths = huffman::lengths_for_frequencies(&frequencies, 15);
        let mut price = [15u8; 256];
        for (byte, &length) in lengths.iter().enumerate() {
            if length != 0 {
                price[byte] = length;
            }
        }
        let mut prefix = Vec::with_capacity(input.len() + 1);
        let mut total = 0u32;
        prefix.push(0);
        for &byte in input {
            total += u32::from(price[usize::from(byte)]);
            prefix.push(total);
        }
        Self {
            base,
            prefix,
            byte_price: price,
        }
    }

    /// The literal cost, in bits, of `length` bytes at `pos` (combined
    /// coordinates; `pos` is at or past the block's start).
    #[inline]
    fn bits(&self, pos: usize, length: usize) -> usize {
        let start = pos - self.base;
        (self.prefix[start + length] - self.prefix[start]) as usize
    }
}

/// The tree finder's answers for the positions of one block: `stride`
/// distances per position, nearest first and each reaching strictly
/// farther than the one before it, with [`TREE_NO_MATCH`] where the list
/// ends. `base` is the combined-span position of the first position's
/// slots, so a probe looks its own position up directly. An empty set is
/// the whole of what a caller without a finder passes, and every probe
/// below is written to cost nothing when it is empty.
///
/// The lazy parser asks for a stride of one and reads
/// [`TreeMatches::best_distance`]; the cost-based parse asks for
/// [`TREE_CANDIDATE_SLOTS`] and consumes the whole list as its candidate
/// source, which is what lets it skip the ring walk. (nzbfast-local
/// change, 7 Sep 2026; see VENDORING.md.)
#[derive(Debug, Clone, Copy, Default)]
struct TreeMatches<'a> {
    base: usize,
    distances: &'a [std::sync::atomic::AtomicU32],
    stride: usize,
}

impl TreeMatches<'_> {
    /// No finder: every probe returns nothing. Only called from
    /// `cfg(test)`, so the non-test build sees no use.
    #[allow(dead_code)]
    fn none() -> Self {
        Self::default()
    }

    /// One position's candidate slots, nearest first; empty without a
    /// finder or past the block the finder answered for.
    #[inline]
    fn candidates(&self, pos: usize) -> &[std::sync::atomic::AtomicU32] {
        if self.stride == 0 {
            return &[];
        }
        let at = match pos.checked_sub(self.base) {
            Some(index) => index * self.stride,
            None => return &[],
        };
        match self.distances.get(at..at + self.stride) {
            Some(slots) => slots,
            None => &[],
        }
    }

    /// The distance of the LONGEST match the finder found at `pos`, if
    /// any: the last filled slot, and with a stride of one the only one.
    #[inline]
    fn best_distance(&self, pos: usize) -> Option<usize> {
        // The walkers filled these in parallel and finished before the
        // tokenizer started; the load is plain (see the `tree` module).
        let mut best = None;
        for slot in self.candidates(pos) {
            match slot.load(std::sync::atomic::Ordering::Relaxed) {
                TREE_NO_MATCH => break,
                distance => best = Some(distance as usize),
            }
        }
        best
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MatchCandidate {
    length: usize,
    distance: usize,
    score: isize,
    cost: usize,
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn best_match<P: MatchPosition>(
    input: &[u8],
    pos: usize,
    end: usize,
    buckets: &MatchIndex<P>,
    options: EncodeOptions,
    state: &EncoderMatchState,
    distance_size: usize,
    prices: &LiteralPrices,
) -> Option<MatchCandidate> {
    best_match_probe(
        input,
        pos,
        end,
        buckets,
        options,
        state,
        distance_size,
        prices,
        TreeMatches::none(),
    )
    .0
}

/// The best match at `pos`, and whether ANY candidate shared its four-byte
/// prefix. The second answer drives literal-run acceleration: a position
/// whose candidates all cost more than their literals is compressible data
/// the parser declined, not the incompressible run the acceleration is for.
#[allow(clippy::too_many_arguments)]
fn best_match_probe<P: MatchPosition>(
    input: &[u8],
    pos: usize,
    end: usize,
    buckets: &MatchIndex<P>,
    options: EncodeOptions,
    state: &EncoderMatchState,
    distance_size: usize,
    prices: &LiteralPrices,
    tree: TreeMatches<'_>,
) -> (Option<MatchCandidate>, bool) {
    let max_distance = pos.min(options.max_match_distance);
    let max_length = (end - pos).min(MAX_ENCODER_MATCH_LENGTH);
    if options.max_match_candidates == 0
        || max_distance == 0
        || max_length < 4
        || pos + 3 >= input.len()
    {
        return (None, false);
    }
    probe_stat!(Probes);
    // Shorter matches cannot win; reject hash collisions before scanning or scoring.
    let prefix = &input[pos..pos + 4];
    let mut best = None;
    let mut saw_prefix_match = false;
    let mut checked = 0usize;
    // Which break ended the ring walk (`ratio-lab` only).
    #[cfg(feature = "ratio-lab")]
    let mut exit_code = probe_stats::Stat::ExitExhausted;
    for distance in state.reps {
        if distance == 0 || distance > max_distance {
            continue;
        }
        probe_stat!(RepChecked);
        if &input[pos - distance..pos - distance + 4] != prefix {
            continue;
        }
        probe_stat!(RepPrefixHit);
        let length = 4 + match_length(input, pos + 4, distance, max_length - 4);
        saw_prefix_match = true;
        consider_match_candidate(
            &mut best,
            state,
            distance_size,
            length,
            distance,
            prices.bits(pos, length),
        );
    }
    for (candidate, tag_matches) in buckets.candidates_tagged(input, pos) {
        if candidate >= pos {
            continue;
        }
        let distance = pos - candidate;
        if distance > max_distance {
            #[cfg(feature = "ratio-lab")]
            {
                exit_code = probe_stats::Stat::ExitDistance;
            }
            break;
        }
        // A rejected prefix still consumes the candidate budget.
        checked += 1;
        probe_stat!(RingChecked);
        // A tag mismatch is a prefix mismatch without the history load;
        // it takes the same exits the byte filter and prefix compare would.
        if !tag_matches {
            probe_stat!(RingTagReject);
            if checked >= options.max_match_candidates {
                #[cfg(feature = "ratio-lab")]
                {
                    exit_code = probe_stats::Stat::ExitCap;
                }
                break;
            }
            continue;
        }
        // Candidates come newest first, so every later one is FARTHER and
        // costs at least as many distance bits: it can only beat `best` by
        // being strictly longer (a byte of length is worth its literal price,
        // at least one bit, and the most a farther distance can save on the
        // length ladder is two bits - so a shorter farther candidate wins
        // only on a one-bit literal, which this filter forgoes). One byte
        // compare at `best.length - 1` settles it before the prefix compare,
        // the length loop and the cost estimate run.
        // The walk's stop rule (a nice-length best ends it) is applied only
        // after a candidate is actually considered, so behind a 64+ byte
        // repeat-distance match the skipped shorter candidates cost a byte
        // each and the first one that could tie or beat it decides; the old
        // walk stopped on the first bucket candidate whatever it was and
        // missed longer matches behind it (measured: a 160-byte match at
        // distance 5,008 behind a 75-byte repeat, on Rust source). Output
        // differs from the old walk only there. (nzbfast-local change,
        // 5 Sep 2026; see VENDORING.md.)
        if let Some(best) = best {
            if input[candidate + best.length - 1] != input[pos + best.length - 1] {
                probe_stat!(RingByteReject);
                if checked >= options.max_match_candidates {
                    #[cfg(feature = "ratio-lab")]
                    {
                        exit_code = probe_stats::Stat::ExitCap;
                    }
                    break;
                }
                continue;
            }
        }
        if &input[candidate..candidate + 4] == prefix {
            probe_stat!(RingPrefixHit);
            let length = 4 + match_length(input, pos + 4, distance, max_length - 4);
            saw_prefix_match = true;
            consider_match_candidate(
                &mut best,
                state,
                distance_size,
                length,
                distance,
                prices.bits(pos, length),
            );
        } else {
            probe_stat!(RingPrefixReject);
        }
        // Repeat distances may already have supplied a maximal match. Keep
        // the original stopping point even when this bucket entry is rejected.
        if best.is_some_and(|best| best.length == max_length || best.length >= MATCH_NICE_LENGTH) {
            #[cfg(feature = "ratio-lab")]
            {
                exit_code = probe_stats::Stat::ExitNice;
            }
            break;
        }
        if checked >= options.max_match_candidates {
            #[cfg(feature = "ratio-lab")]
            {
                exit_code = probe_stats::Stat::ExitCap;
            }
            break;
        }
    }
    #[cfg(feature = "ratio-lab")]
    {
        probe_stats::bump(exit_code, 1);
        probe_stats::bump(probe_stats::walk_bucket(checked), 1);
    }
    // The tree finder: the longest occurrence in this position's bucket,
    // wherever in the dictionary it is, priced against everything above.
    // Its length was capped at the finder's comparison limit, so the real
    // length is recomputed here - a 4,096-byte repeat reported as a
    // 64-byte one is emitted whole. (nzbfast-local change, 7 Sep 2026;
    // see VENDORING.md.)
    if let Some(distance) = tree.best_distance(pos) {
        probe_stat!(TreeProbe);
        if distance <= max_distance && &input[pos - distance..pos - distance + 4] == prefix {
            probe_stat!(TreePrefixHit);
            let length = 4 + match_length(input, pos + 4, distance, max_length - 4);
            saw_prefix_match = true;
            consider_match_candidate(
                &mut best,
                state,
                distance_size,
                length,
                distance,
                prices.bits(pos, length),
            );
        }
    }
    // The long table: a repeat farther back than the ring keeps.
    if best.is_none_or(|best| best.length < LONG_MATCH_MIN_LENGTH) {
        if let Some(candidate) = buckets.long_candidate(input, pos) {
            probe_stat!(LongProbe);
            if candidate < pos
                && pos - candidate <= max_distance
                && &input[candidate..candidate + 4] == prefix
            {
                probe_stat!(LongPrefixHit);
                let distance = pos - candidate;
                let length = 4 + match_length(input, pos + 4, distance, max_length - 4);
                if length >= LONG_MATCH_MIN_LENGTH.min(max_length) {
                    saw_prefix_match = true;
                    consider_match_candidate(
                        &mut best,
                        state,
                        distance_size,
                        length,
                        distance,
                        prices.bits(pos, length),
                    );
                }
            }
        }
    }
    (best, saw_prefix_match)
}

fn match_length(input: &[u8], pos: usize, distance: usize, max_length: usize) -> usize {
    let length = super::fast::match_length(input, pos, distance, max_length);
    probe_stat!(MatchLengthCalls);
    probe_stat!(MatchLengthBytes, length);
    length
}

/// What a match farther back than a megabyte is charged on top of
/// [`estimated_match_cost`], in bits (nzbfast-local change, 7 Sep 2026;
/// see VENDORING.md).
///
/// The cost estimate spends one flat ten-bit constant on the two Huffman
/// symbols a match writes - the main symbol and the distance slot - and
/// counts the slot's extra bits exactly. That is close enough while every
/// match comes from a ring that reaches a few megabytes, and it stops
/// being close enough once the tree finder offers a match from anywhere
/// in a 32 MiB dictionary at nearly every position: the parser then takes
/// the LONGEST match on offer, which is usually the farthest, and pays
/// for it in distance bits. Measured on the first 256 MiB of the mixed
/// corpus at `-md32m` (7 Sep 2026): without the surcharge the encoder
/// emits 4.44 M matches eight or more MiB back and 27.30 bits a match,
/// where rar 7.23 emits 2.21 M and 25.1 bits - and it is 117,291,644
/// bytes against rar's 116,751,028. With it: 116,493,016, under rar's
/// own. The surcharge was swept: 4 bits 116,576,488, 6 bits
/// 116,493,016, 8 bits 116,517,992, 10 bits 116,564,428, 16 bits
/// 116,692,584.
///
/// It is a stand-in for prices read off the real tables. **It is the LAZY
/// walk's stand-in, and the cost-based parse is not what retires it** -
/// measured 7 Sep 2026 by the lane that gave the parse its own candidate
/// list, with this constant set to zero: the `-mo` archive is 112,865,011
/// bytes either way, bit for bit, because the parse prices `MatchRun`s
/// that carry no score and never reaches `consider_match_candidate`,
/// while the LAZY level goes 115,617,428 to 116,416,233, +0.69%. What
/// retires it is real prices inside `estimated_match_cost`, whose flat
/// ten-bit constant for a match's two Huffman symbols is what it corrects
/// for. It is zero below a megabyte, so the writer's own default was
/// untouched by it while that default was 128 KiB; the 2 MiB default of
/// 8 Sep 2026 is above the threshold and does reach it. (nzbfast-local
/// change, 7 Sep 2026.)
const FAR_DISTANCE_SURCHARGE_BITS: usize = 6;
const FAR_DISTANCE_SURCHARGE_FROM: usize = 1 << 20;

#[inline]
fn far_distance_surcharge(distance: usize) -> usize {
    if distance > FAR_DISTANCE_SURCHARGE_FROM {
        FAR_DISTANCE_SURCHARGE_BITS
    } else {
        0
    }
}

fn consider_match_candidate(
    best: &mut Option<MatchCandidate>,
    state: &EncoderMatchState,
    distance_size: usize,
    length: usize,
    distance: usize,
    literal_bits: usize,
) {
    if length < 4 {
        return;
    }
    let Ok(cost) = estimated_match_cost(state, length, distance, distance_size) else {
        return;
    };
    // A match that saves no bits against its literals is not a match.
    if cost >= literal_bits {
        return;
    }
    let candidate = MatchCandidate {
        length,
        distance,
        score: literal_bits as isize - cost as isize - far_distance_surcharge(distance) as isize,
        cost,
    };
    if best.is_none_or(|best| {
        candidate.score > best.score
            || (candidate.score == best.score
                && (candidate.length > best.length
                    || (candidate.length == best.length && candidate.cost < best.cost)
                    || (candidate.length == best.length
                        && candidate.cost == best.cost
                        && candidate.distance < best.distance)))
    }) {
        *best = Some(candidate);
    }
}

fn estimated_match_cost(
    state: &EncoderMatchState,
    length: usize,
    distance: usize,
    distance_size: usize,
) -> Result<usize> {
    if distance == state.reps[0] && length == state.previous_match_length && state.previous_match_length != 0 {
        return Ok(2);
    }
    if state
        .reps
        .iter()
        .any(|&repeat_distance| repeat_distance == distance && repeat_distance != 0)
    {
        let (length_slot, _) = length_slot_for_match(length)?;
        return Ok(5 + usize::from(length_slot_extra_bits(length_slot)?));
    }

    let (distance_slot, _) = distance_slot_for_match(distance, distance_size)?;
    let encoded_length = length
        .checked_sub(length_bonus(distance))
        .ok_or(Error::InvalidData("RAR 5 adjusted match length underflows"))?;
    let (length_slot, _) = length_slot_for_match(encoded_length)?;
    Ok(10
        + usize::from(length_slot_extra_bits(length_slot)?)
        + distance_slot_bit_count(distance_slot)?)
}

// nzbfast-local change, 7 Sep 2026 - cost-based optimal parse; see
// VENDORING.md.
//
// `walk_tokens` is greedy with a one-position lazy re-probe: it takes the
// best-scoring token at each position and never reconsiders. A cost-based
// parse instead prices EVERY reachable token over a window of positions
// and keeps the cheapest total path, which is where LZMA's `GetOptimum`,
// 7-Zip's and zstd's `btultra` levels get their last few percent. RAR 5's
// token set is what makes the difference worth a dynamic program rather
// than a deeper greedy search: four repeat distances that ROTATE on use,
// a two-bit length-repeat token, and a length bonus that depends on the
// distance, so a match three bits dearer now can be eight bits cheaper two
// tokens later by leaving a repeat slot in place. Only a parse that
// carries the repeat state through the search sees that, so every node of
// the program carries its own [`EncoderMatchState`].
//
// Measured on 256 MiB of mixed text, fixed-width records and a replayed
// 32 MiB pool, at a 32 MiB dictionary: 118,507,983 bytes greedy against
// 115,238,274 here, which is 2.76% smaller and under what `rar 7.23`
// writes at either `-m3` (116,751,028) or `-m5` (116,003,986). It costs
// 3.7x the greedy walk's CPU on an idle 20-core box, because it probes
// every position where the greedy walk probes about one in ten, so it
// is the top of the level ladder and not a default.

/// How many input positions one dynamic-programming window decides at a
/// time. The window is solved exactly and then committed, so a longer one
/// is a better parse and a shorter one is less memory and less work thrown
/// away at a forced jump; 16 Ki positions is about 1.2 MB of nodes and puts
/// a window boundary every 16 KiB of input, where the boundary costs
/// nothing at all (the window is allowed to end on any node up to a full
/// match past its limit, so no match is ever cut by the boundary itself).
const OPTIMAL_WINDOW_POSITIONS: usize = 1 << 14;
/// A match at least this long is taken without pricing what else the
/// window could do with those bytes: the parse commits its path up to that
/// position, emits the match, and starts a fresh window after it (LZMA's
/// `numFastBytes` rule, which exists for exactly this reason). Without it
/// a repeated-payload shape prices 4,096 positions inside every 4,096-byte
/// match, and the parse costs many times what the shape can pay back.
/// Measured on the 256 MiB mixed slice at a 32 MiB dictionary (7 Sep
/// 2026, on the tree before the length-limited Huffman codes landed):
/// 64 gives 115,914,564 bytes for 98 user s, 512 gives 115,917,624 for
/// 105 - the shorter threshold is both smaller and cheaper, so a match
/// this long is not worth deliberating over. It is the same length the
/// candidate walk already stops at ([`MATCH_NICE_LENGTH`]).
const OPTIMAL_SUFFICIENT_LENGTH: usize = 64;
/// Per position, at most this many SHORTER lengths are priced beyond each
/// candidate's own full length. Cutting a match short to land on a cheaper
/// token pays near the bottom of the length ladder, so the budget is spent
/// from the shortest candidate upward and the full length of every
/// candidate is always priced.
const OPTIMAL_SHORT_LENGTH_BUDGET: usize = 64;
/// ...and per repeat distance, at most this many rungs from length two up.
/// A repeat is priced from every node, four of them, so its ladder is the
/// parse's most repeated inner loop; the rungs that pay are at the bottom,
/// where a two-byte repeat undercuts two literals.
const OPTIMAL_REPEAT_LENGTH_BUDGET: usize = 16;
/// Prices are in sixteenths of a bit. Huffman code lengths are whole bits,
/// but a token's price is a sum of several of them plus raw bits, and the
/// entropy price of a symbol is not an integer: sixteenths keep the
/// program's comparisons from collapsing into ties.
const PRICE_SHIFT: u32 = 4;
/// A symbol no table entry would reach costs the deepest code a RAR 5
/// table can hold. Nothing is priced free.
const PRICE_MAX: u16 = 15 << PRICE_SHIFT;
/// ...and nothing is priced below one bit, which is a Huffman code's floor.
const PRICE_MIN: u16 = 1 << PRICE_SHIFT;
/// How much input the FIRST price region waits for, against
/// [`ENTROPY_BLOCK_BYTES`] for every region after it. A region is priced
/// by the region before it, so the first one has nothing of its own and
/// runs on the constant model; a short first region gets real code
/// lengths in front of the parse sooner, and on a MEMBER SET that is the
/// difference between a member being parsed on real prices and never
/// leaving the constant model at all.
///
/// Measured 7 Sep 2026 (400 files of about 2.7 MB, and the first 256 MiB
/// of the mixed corpus), user CPU flat to noise across the column:
///
/// | first region | 400 files, 32 MiB | slice, 32 MiB | slice, 128 KiB |
/// |---|---|---|---|
/// | 256 KiB (none) | 492,385,336 | 114,684,633 | 152,021,538 |
/// | 128 KiB | 489,415,177 | 114,597,054 | |
/// | 64 KiB | 488,452,656 | 114,461,903 | 151,615,812 |
/// | **32 KiB** | **488,399,398** | **114,407,187** | **151,473,395** |
/// | 16 KiB | | 114,452,648 | |
///
/// 32 KiB is an optimum and not the end of a trend: 16 KiB is worse
/// again, and below it the region is too small a sample to price from.
///
/// **This dial was 64 KiB for a few hours and had to be RE-TUNED when the
/// adaptive entropy-block splitter landed on by default**, because the
/// splitter cuts the very blocks this model prices for; on the tree
/// before it, 64 KiB was the optimum and 32 KiB measurably worse. Re-run
/// the sweep whenever the block cutter changes: it is four archives, and
/// it has moved the answer once already.
const OPTIMAL_FIRST_REGION_BYTES: usize = 32 << 10;
// A first region at or past a full one would settle nothing early, which
// is the whole point of it; a build error is the right place to say so.
const _: () = assert!(OPTIMAL_FIRST_REGION_BYTES < ENTROPY_BLOCK_BYTES);

/// Sixteenths of a bit of `log2(value)`, by integer log plus four rounds of
/// mantissa squaring. Integer arithmetic throughout, so an archive's bytes
/// do not depend on a platform's `log2`.
fn log2_sixteenths(value: u64) -> u32 {
    debug_assert!(value != 0);
    let integer = 63 - value.leading_zeros();
    // The mantissa in Q30, so [2^30, 2^31) and a square still fits a u64.
    let mut mantissa = if integer >= 30 {
        value >> (integer - 30)
    } else {
        value << (30 - integer)
    };
    let mut fraction = 0u32;
    for bit in (0..PRICE_SHIFT).rev() {
        mantissa = (mantissa * mantissa) >> 30;
        if mantissa >= 1 << 31 {
            fraction |= 1 << bit;
            mantissa >>= 1;
        }
    }
    (integer << PRICE_SHIFT) | fraction
}

/// What each token symbol costs, in sixteenths of a bit, under one set of
/// Huffman tables. The four tables are the four the writer emits, so a
/// token's price here is the bits `encode_token_block` would actually
/// write for it, align symbol included.
#[derive(Clone)]
struct TokenPrices {
    main: Vec<u16>,
    length: Vec<u16>,
    distance: Vec<u16>,
    align: Vec<u16>,
}

impl TokenPrices {
    /// The constant-cost model [`estimated_match_cost`] uses, with the
    /// block's own order-0 literal prices: what the parse prices with
    /// before it has produced any tokens to build a table from. Priced
    /// token for token it is that function exactly, scaled.
    fn constant(literal_bits: &[u8; 256], distance_size: usize) -> Self {
        let mut main = vec![10 << PRICE_SHIFT; MAIN_TABLE_SIZE];
        for (symbol, &bits) in literal_bits.iter().enumerate() {
            main[symbol] = u16::from(bits) << PRICE_SHIFT;
        }
        // 256 is the filter symbol, which the parse never emits.
        main[256] = PRICE_MAX;
        main[257] = 2 << PRICE_SHIFT;
        for symbol in main.iter_mut().take(262).skip(258) {
            *symbol = 5 << PRICE_SHIFT;
        }
        Self {
            main,
            length: vec![0; LENGTH_TABLE_SIZE],
            distance: vec![0; distance_size],
            // The constant model charges a far distance its whole bit
            // count; the exact model writes all but four of those bits
            // raw and the last four as an align symbol, so a flat four
            // bits per align symbol reproduces it.
            align: vec![4 << PRICE_SHIFT; ALIGN_TABLE_SIZE],
        }
    }
}

/// Sixteenths of a bit for each symbol, from the frequencies a completed
/// region of the token stream actually had. A symbol the region never used
/// is priced at the table's deepest code rather than free; a table the
/// region never used at all keeps the constant model's price, so a region
/// with no far matches does not make the next one's far matches
/// unaffordable.
fn price_from_frequencies(prices: &mut [u16], frequencies: &[usize], absent: u16) {
    let total: usize = frequencies.iter().sum();
    if total == 0 {
        prices.fill(absent);
        return;
    }
    let log_total = log2_sixteenths(total as u64);
    for (price, &frequency) in prices.iter_mut().zip(frequencies) {
        *price = if frequency == 0 {
            PRICE_MAX
        } else {
            let bits = log_total - log2_sixteenths(frequency as u64);
            (bits as u16).clamp(PRICE_MIN, PRICE_MAX)
        };
    }
}

/// The parse's price model: the prices in force, and the token frequencies
/// of the region being parsed. Every [`ENTROPY_BLOCK_BYTES`] of committed
/// input the frequencies become the prices and reset, so each region is
/// priced by the one before it - the reader's tables are per region too,
/// so those are the codes the writer is about to build. (zstd's
/// `btultra2` re-parses the same block with the first pass's statistics;
/// pricing from the previous region instead costs one pass rather than
/// two and follows the input where a whole-block statistic cannot.)
struct PriceModel {
    prices: TokenPrices,
    main: Vec<usize>,
    length: Vec<usize>,
    distance: Vec<usize>,
    align: Vec<usize>,
    bytes: usize,
    /// How much committed input the next rebuild waits for: the short
    /// first region ([`OPTIMAL_FIRST_REGION_BYTES`]), then a full one.
    threshold: usize,
    distance_size: usize,
}

impl PriceModel {
    fn new(literals: &LiteralPrices, distance_size: usize) -> Self {
        Self {
            prices: TokenPrices::constant(&literals.byte_price, distance_size),
            main: vec![0; MAIN_TABLE_SIZE],
            length: vec![0; LENGTH_TABLE_SIZE],
            distance: vec![0; distance_size],
            align: vec![0; ALIGN_TABLE_SIZE],
            bytes: 0,
            threshold: OPTIMAL_FIRST_REGION_BYTES,
            distance_size,
        }
    }

    fn observe_literals(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.main[usize::from(byte)] += 1;
        }
        self.bytes += bytes.len();
    }

    fn observe_match(
        &mut self,
        state: &EncoderMatchState,
        length: usize,
        distance: usize,
    ) -> Result<()> {
        match state.encode_match(length, distance, self.distance_size)? {
            EncodedMatch::LastLengthRepeat => self.main[257] += 1,
            EncodedMatch::RepeatDistance {
                index, length_slot, ..
            } => {
                self.main[258 + index] += 1;
                self.length[length_slot] += 1;
            }
            EncodedMatch::New {
                length_slot,
                distance_slot,
                distance_extra,
                distance_bit_count,
                ..
            } => {
                self.main[262 + length_slot] += 1;
                self.distance[distance_slot] += 1;
                if distance_bit_count >= 4 {
                    self.align[distance_extra & 0x0f] += 1;
                }
            }
        }
        self.bytes += length;
        Ok(())
    }

    /// Rebuild the prices when a region's worth of input has been
    /// committed. Called only between windows, so a window's prices, and
    /// the literal price prefix built from them, never move under it.
    fn settle(&mut self) {
        if self.bytes < self.threshold {
            return;
        }
        self.threshold = ENTROPY_BLOCK_BYTES;
        price_from_frequencies(&mut self.prices.main, &self.main, PRICE_MAX);
        price_from_frequencies(&mut self.prices.length, &self.length, 0);
        price_from_frequencies(&mut self.prices.distance, &self.distance, 0);
        price_from_frequencies(&mut self.prices.align, &self.align, 4 << PRICE_SHIFT);
        self.main.fill(0);
        self.length.fill(0);
        self.distance.fill(0);
        self.align.fill(0);
        self.bytes = 0;
    }
}

/// What [`encode_token_block`] would spend on this token, in sixteenths of
/// a bit, under `prices` and with `state` as the repeat state in front of
/// it. Exact for the given tables: the same three arms, the same extra
/// bits, the same align symbol - and the reference [`DistanceArm`], which
/// is what the parse actually runs, is held to it symbol for symbol
/// (`distance_arm_prices_agree_with_the_direct_token_cost`).
#[cfg(test)]
fn priced_match_cost(
    prices: &TokenPrices,
    state: &EncoderMatchState,
    length: usize,
    distance: usize,
    distance_size: usize,
) -> Result<u32> {
    Ok(match state.encode_match(length, distance, distance_size)? {
        EncodedMatch::LastLengthRepeat => u32::from(prices.main[257]),
        EncodedMatch::RepeatDistance {
            index, length_slot, ..
        } => {
            u32::from(prices.main[258 + index])
                + u32::from(prices.length[length_slot])
                + (u32::from(length_slot_extra_bits(length_slot)?) << PRICE_SHIFT)
        }
        EncodedMatch::New {
            length_slot,
            distance_slot,
            distance_extra,
            distance_bit_count,
            ..
        } => {
            let mut cost = u32::from(prices.main[262 + length_slot])
                + (u32::from(length_slot_extra_bits(length_slot)?) << PRICE_SHIFT)
                + u32::from(prices.distance[distance_slot]);
            if distance_bit_count >= 4 {
                cost += ((distance_bit_count as u32 - 4) << PRICE_SHIFT)
                    + u32::from(prices.align[distance_extra & 0x0f]);
            } else {
                cost += (distance_bit_count as u32) << PRICE_SHIFT;
            }
            cost
        }
    })
}

/// Every match length's length slot and that slot's extra-bit count, so
/// pricing a length down a ladder is two array reads. `slot` is 0xff where
/// the length has no slot. Built once per parse; 4 KiB of tables.
struct LengthSlots {
    slot: Vec<u8>,
    extra: Vec<u8>,
}

impl LengthSlots {
    fn new() -> Self {
        let mut slot = vec![0xffu8; MAX_ENCODER_MATCH_LENGTH + 1];
        let mut extra = vec![0u8; MAX_ENCODER_MATCH_LENGTH + 1];
        for length in 2..=MAX_ENCODER_MATCH_LENGTH {
            if let Ok((index, _)) = length_slot_for_match(length) {
                if let Ok(bits) = length_slot_extra_bits(index) {
                    slot[length] = index as u8;
                    extra[length] = bits;
                }
            }
        }
        Self { slot, extra }
    }
}

/// What a fixed distance costs a fixed node, with only the length left to
/// vary. The arm a distance takes (a repeat slot or a new distance) and
/// everything the distance itself pays (its slot code, its raw bits and
/// its align symbol) depend on the node's repeat state and not on the
/// length, so they are decided ONCE per (node, distance) and the ladder of
/// lengths below costs two array reads and an add each. Pricing every
/// length through [`EncoderMatchState::encode_match`] instead re-derived
/// the distance slot, the align symbol and the length bonus for every rung
/// (measured 7 Sep 2026: 126 user s over the 256 MiB slice, against 28 for
/// the lazy parser).
#[derive(Debug, Clone, Copy)]
enum DistanceArm {
    /// One of the four repeat distances, at `main` bits for its symbol;
    /// `repeat_at` is the one length that takes the two-bit length-repeat
    /// token instead (zero when this slot cannot reach it).
    Repeat {
        main: u32,
        repeat_at: usize,
        repeat_price: u32,
    },
    /// A distance the state does not hold: `paid` is everything the
    /// distance costs, `bonus` the length the format gives back for it.
    New { paid: u32, bonus: usize },
}

impl DistanceArm {
    fn new(
        prices: &TokenPrices,
        state: &EncoderMatchState,
        distance: usize,
        distance_size: usize,
    ) -> Option<Self> {
        if let Some(index) = state
            .reps
            .iter()
            .position(|&repeat| repeat == distance && repeat != 0)
        {
            return Some(Self::Repeat {
                main: u32::from(prices.main[258 + index]),
                repeat_at: if index == 0 { state.previous_match_length } else { 0 },
                repeat_price: u32::from(prices.main[257]),
            });
        }
        let (slot, extra) = distance_slot_for_match(distance, distance_size).ok()?;
        let bit_count = distance_slot_bit_count(slot).ok()?;
        let mut paid = u32::from(prices.distance[slot]);
        if bit_count >= 4 {
            paid += ((bit_count as u32 - 4) << PRICE_SHIFT) + u32::from(prices.align[extra & 0x0f]);
        } else {
            paid += (bit_count as u32) << PRICE_SHIFT;
        }
        Some(Self::New {
            paid,
            bonus: length_bonus(distance),
        })
    }

    /// The bits this arm spends on `length`, or `None` where the format
    /// cannot express it.
    #[inline]
    fn price(&self, prices: &TokenPrices, slots: &LengthSlots, length: usize) -> Option<u32> {
        match *self {
            Self::Repeat {
                main,
                repeat_at,
                repeat_price,
            } => {
                if length == repeat_at {
                    return Some(repeat_price);
                }
                let slot = slots.slot[length];
                if slot == 0xff {
                    return None;
                }
                Some(
                    main + u32::from(prices.length[usize::from(slot)])
                        + (u32::from(slots.extra[length]) << PRICE_SHIFT),
                )
            }
            Self::New { paid, bonus } => {
                let encoded = length.checked_sub(bonus)?;
                if encoded < 2 {
                    return None;
                }
                let slot = slots.slot[encoded];
                if slot == 0xff {
                    return None;
                }
                Some(
                    paid + u32::from(prices.main[262 + usize::from(slot)])
                        + (u32::from(slots.extra[encoded]) << PRICE_SHIFT),
                )
            }
        }
    }
}

/// One entry of a position's candidate list: `length` bytes match at
/// `distance`, and no NEARER distance reaches that far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MatchRun {
    length: usize,
    distance: usize,
}

/// The candidate list a cost-based parse needs at `pos`: for each length
/// worth reaching, the NEAREST distance that reaches it, with lengths (and
/// so distances) strictly increasing.
///
/// THIS IS THE PARSE'S ONLY CANDIDATE SOURCE, and it has two of them.
///
/// **The tree finder, where one is running** (a dictionary at or past
/// [`TREE_MIN_DICTIONARY`], and the parse asks it for a stride of
/// [`TREE_CANDIDATE_SLOTS`]). Its descent already visits exactly this
/// frontier - increasing length, nearest distance for each - so its slots
/// ARE the list, and the walk is a descent per position rather than up to
/// `max_match_candidates` scattered slots of a ring far larger than any
/// cache. The lengths are recomputed here at this tokenizer's own
/// boundary, because the finder capped its comparisons at
/// `TREE_NICE_LENGTH` and a 4,096-byte repeat it recorded as a 64-byte one
/// is emitted whole. (nzbfast-local change, 7 Sep 2026; the ring walk was
/// 81% of the parse's CPU before it - see the handoff.)
///
/// **The ring index otherwise** - below the tree's dictionary threshold,
/// and in the tests. It yields the list directly and needs no sort: its
/// walk is newest first, so it visits distances in increasing order, and
/// the first candidate to reach a length is by construction the nearest
/// one that does - which is why the walk keeps only strictly longer
/// candidates. The long-table arm rides both paths: it reaches an anchor
/// farther back than either structure keeps.
fn match_candidates_at<P: MatchPosition>(
    input: &[u8],
    pos: usize,
    end: usize,
    buckets: &MatchIndex<P>,
    options: EncodeOptions,
    tree: TreeMatches<'_>,
    out: &mut Vec<MatchRun>,
) {
    out.clear();
    let max_distance = pos.min(options.max_match_distance);
    let max_length = (end - pos).min(MAX_ENCODER_MATCH_LENGTH);
    if options.max_match_candidates == 0
        || max_distance == 0
        || max_length < 4
        || pos + 3 >= input.len()
    {
        return;
    }
    let prefix = &input[pos..pos + 4];
    let mut best_length = 0usize;
    probe_stat!(OptProbes);
    if tree.stride > 1 {
        probe_stat!(OptTreeProbe);
        // The finder's frontier, nearest first. Its distances increase, so
        // the first one past the parse's own limit ends the list.
        for slot in tree.candidates(pos) {
            let distance = match slot.load(std::sync::atomic::Ordering::Relaxed) {
                TREE_NO_MATCH => break,
                distance => distance as usize,
            };
            if distance > max_distance {
                break;
            }
            if &input[pos - distance..pos - distance + 4] != prefix {
                continue;
            }
            let length = 4 + match_length(input, pos + 4, distance, max_length - 4);
            if length > best_length {
                best_length = length;
                out.push(MatchRun { length, distance });
            }
            if best_length >= max_length {
                break;
            }
        }
    } else {
        let mut checked = 0usize;
        // Which break ended this walk (`ratio-lab` only).
        #[cfg(feature = "ratio-lab")]
        let mut exit_code = probe_stats::Stat::OptExitExhausted;
        for (candidate, tag_matches) in buckets.candidates_tagged(input, pos) {
            if candidate >= pos {
                continue;
            }
            let distance = pos - candidate;
            if distance > max_distance {
                #[cfg(feature = "ratio-lab")]
                {
                    exit_code = probe_stats::Stat::OptExitDistance;
                }
                break;
            }
            // A rejected candidate still spends the budget, as it does in
            // `best_match_probe`: the walk's reach is what the budget names.
            checked += 1;
            probe_stat!(OptRingChecked);
            if !tag_matches {
                probe_stat!(OptRingTagReject);
                if checked >= options.max_match_candidates {
                    #[cfg(feature = "ratio-lab")]
                    {
                        exit_code = probe_stats::Stat::OptExitCap;
                    }
                    break;
                }
                continue;
            }
            // Only a STRICTLY longer match can enter the list, so the byte
            // one past the current best settles the candidate before the
            // prefix compare, the length loop or a push.
            if best_length >= 4 && input[candidate + best_length] != input[pos + best_length] {
                probe_stat!(OptRingByteReject);
                if checked >= options.max_match_candidates {
                    #[cfg(feature = "ratio-lab")]
                    {
                        exit_code = probe_stats::Stat::OptExitCap;
                    }
                    break;
                }
                continue;
            }
            if &input[candidate..candidate + 4] == prefix {
                probe_stat!(OptRingPrefixHit);
                let length = 4 + match_length(input, pos + 4, distance, max_length - 4);
                if length > best_length {
                    best_length = length;
                    out.push(MatchRun { length, distance });
                }
            }
            if best_length >= max_length || best_length >= MATCH_NICE_LENGTH {
                #[cfg(feature = "ratio-lab")]
                {
                    exit_code = probe_stats::Stat::OptExitNice;
                }
                break;
            }
            if checked >= options.max_match_candidates {
                #[cfg(feature = "ratio-lab")]
                {
                    exit_code = probe_stats::Stat::OptExitCap;
                }
                break;
            }
        }
        #[cfg(feature = "ratio-lab")]
        probe_stats::bump(exit_code, 1);
    }
    // The long table: a repeat farther back than either structure keeps.
    // It is appended independently of the frontier's distance order, so
    // when it fires the frontier is rebuilt below.
    // Set when the list may no longer be ordered by distance, so the
    // frontier below is rebuilt. The ring path's flag is raised exactly
    // where it was before the tree returned lists, so that path is
    // byte-for-byte the control this change is measured against.
    let mut rebuild = false;
    if best_length < LONG_MATCH_MIN_LENGTH {
        if let Some(candidate) = buckets.long_candidate(input, pos) {
            if candidate < pos
                && pos - candidate <= max_distance
                && &input[candidate..candidate + 4] == prefix
            {
                let distance = pos - candidate;
                let length = 4 + match_length(input, pos + 4, distance, max_length - 4);
                if length > best_length && length >= LONG_MATCH_MIN_LENGTH.min(max_length) {
                    out.push(MatchRun { length, distance });
                    // The tree's own frontier was ordered until this push.
                    rebuild |= tree.stride > 1;
                }
            }
        }
    }
    // A single hint from a finder the parse did not ask a list of: merge it
    // into the nearest-distance frontier, the ring's candidates still
    // competing. Unchanged from before the list existed, so this path is
    // the control the list is measured against.
    if tree.stride == 1 {
        if let Some(distance) = tree.best_distance(pos) {
            if distance <= max_distance && &input[pos - distance..pos - distance + 4] == prefix {
                let length = 4 + match_length(input, pos + 4, distance, max_length - 4);
                if out.iter().any(|run| run.distance <= distance && run.length >= length) {
                    return;
                }
                out.push(MatchRun { length, distance });
                rebuild = true;
            }
        }
    }
    // The long-table arm is appended independently of the frontier's own
    // distance order, and the parse reads the LAST entry as the longest, so
    // rebuild rather than assume ordering. Neither arm fires at most
    // positions, and neither can drop a candidate that is not dominated by
    // a nearer one reaching as far.
    if rebuild && out.len() > 1 {
        out.sort_unstable_by_key(|run| (run.distance, std::cmp::Reverse(run.length)));
        let mut reached = 0;
        out.retain(|run| {
            if run.length <= reached {
                false
            } else {
                reached = run.length;
                true
            }
        });
    }
}

/// One position of the dynamic program: the cheapest path found to it so
/// far, the position it came from, the token that got it there (a zero
/// distance is a literal), and the repeat state that path leaves behind.
/// The state is per node and not per position: two paths reaching the same
/// byte leave different repeat slots in place, and which one is cheaper
/// from here depends on that.
#[derive(Debug, Clone, Copy)]
struct OptimalNode {
    price: u32,
    from: u32,
    distance: usize,
    state: EncoderMatchState,
}

impl OptimalNode {
    const UNREACHED: Self = Self {
        price: u32::MAX,
        from: 0,
        distance: 0,
        state: EncoderMatchState {
            reps: [0; 4],
            previous_match_length: 0,
        },
    };
}

#[inline]
fn relax_optimal(
    nodes: &mut [OptimalNode],
    from: usize,
    length: usize,
    price: u32,
    distance: usize,
    mut state: EncoderMatchState,
) {
    let to = from + length;
    if price < nodes[to].price {
        if distance != 0 {
            state.remember(length, distance);
        }
        nodes[to] = OptimalNode {
            price,
            from: from as u32,
            distance,
            state,
        };
    }
}

/// The cost-based parse: [`walk_tokens`]'s alternative when
/// [`EncodeOptions::optimal_parse`] is set, one level above the lazy
/// parser and emitting the same `EncodeToken` stream.
///
/// The input is decided one window at a time. Inside a window every
/// position is probed and priced, and the cheapest path across it is kept;
/// the window is then committed and the next one starts where that path
/// ended, so a match is never cut by a window boundary (a window may end
/// up to one full match past its own limit, and the terminal it commits to
/// is the cheapest of those, each charged the literals that would carry it
/// to the same byte). Positions are inserted into the index in their own
/// order, exactly once each, whether the path went over them or through
/// them.
#[allow(clippy::too_many_arguments)]
fn walk_tokens_optimal<P: MatchPosition>(
    combined: &[u8],
    start: usize,
    end: usize,
    options: EncodeOptions,
    distance_size: usize,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
    mut buckets: MatchIndex<P>,
    mut tokens: Vec<EncodeToken>,
    tree: TreeMatches<'_>,
) -> Result<(Vec<EncodeToken>, MatchIndex<P>)> {
    let input = &combined[start..end];
    let literals = LiteralPrices::new(input, start);
    let mut model = PriceModel::new(&literals, distance_size);
    let slots = LengthSlots::new();
    let mut state = EncoderMatchState::default();
    let mut nodes: Vec<OptimalNode> = Vec::new();
    let mut runs: Vec<MatchRun> = Vec::new();
    let mut literal_prefix: Vec<u32> = Vec::new();
    let mut path: Vec<(usize, usize)> = Vec::new();
    let mut pos = start;
    let mut next_report = 0usize;

    while pos < end {
        let limit = OPTIMAL_WINDOW_POSITIONS.min(end - pos);
        // How far past the window's limit a path may end: one full match.
        let horizon = (limit + MAX_ENCODER_MATCH_LENGTH).min(end - pos);
        literal_prefix.clear();
        literal_prefix.push(0);
        let mut running = 0u32;
        for &byte in &combined[pos..pos + horizon] {
            running += u32::from(model.prices.main[usize::from(byte)]);
            literal_prefix.push(running);
        }
        nodes.clear();
        nodes.resize(horizon + 1, OptimalNode::UNREACHED);
        nodes[0] = OptimalNode {
            price: 0,
            from: 0,
            distance: 0,
            state,
        };

        let mut forced: Option<MatchRun> = None;
        let mut settled = limit;
        for index in 0..limit {
            let at = pos + index;
            let node = nodes[index];
            let max_length = (end - at).min(MAX_ENCODER_MATCH_LENGTH);
            let max_distance = at.min(options.max_match_distance);
            // A literal always keeps the window connected, so every node
            // below the limit is reachable and no arm below needs a guard.
            relax_optimal(
                &mut nodes,
                index,
                1,
                node.price + u32::from(model.prices.main[usize::from(combined[at])]),
                0,
                node.state,
            );
            // The repeat distances, read from THIS node's state. RAR 5
            // encodes a repeat match from length two with no distance
            // bonus, so the ladder starts below what a four-byte hash can
            // find, and the length the last match had is the two-bit
            // length-repeat token.
            if max_length >= 2 && max_distance != 0 {
                for slot in 0..4 {
                    let distance = node.state.reps[slot];
                    if distance == 0 || distance > max_distance {
                        continue;
                    }
                    if combined[at - distance] != combined[at]
                        || combined[at - distance + 1] != combined[at + 1]
                    {
                        continue;
                    }
                    let Some(arm) =
                        DistanceArm::new(&model.prices, &node.state, distance, distance_size)
                    else {
                        continue;
                    };
                    let length = 2 + match_length(combined, at + 2, distance, max_length - 2);
                    let short = length.min(2 + OPTIMAL_REPEAT_LENGTH_BUDGET);
                    for reach in 2..=short {
                        relax_priced(
                            &mut nodes,
                            &model.prices,
                            &slots,
                            &arm,
                            &node,
                            index,
                            reach,
                            distance,
                        );
                    }
                    // ...and the full length, plus the one length the
                    // two-bit length-repeat token can reach, when the
                    // ladder above stopped short of them.
                    if length > short {
                        relax_priced(
                            &mut nodes,
                            &model.prices,
                            &slots,
                            &arm,
                            &node,
                            index,
                            length,
                            distance,
                        );
                    }
                    let repeat = node.state.previous_match_length;
                    if slot == 0 && repeat > short && repeat < length {
                        relax_priced(
                            &mut nodes,
                            &model.prices,
                            &slots,
                            &arm,
                            &node,
                            index,
                            repeat,
                            distance,
                        );
                    }
                }
            }
            match_candidates_at(combined, at, end, &buckets, options, tree, &mut runs);
            insert_match_position(combined, at, &mut buckets);
            if let Some(&longest) = runs.last() {
                if longest.length >= OPTIMAL_SUFFICIENT_LENGTH {
                    forced = Some(longest);
                    settled = index;
                    break;
                }
            }
            let mut budget = OPTIMAL_SHORT_LENGTH_BUDGET;
            let mut shortest = 2usize;
            for run in &runs {
                let Some(arm) =
                    DistanceArm::new(&model.prices, &node.state, run.distance, distance_size)
                else {
                    continue;
                };
                relax_priced(
                    &mut nodes,
                    &model.prices,
                    &slots,
                    &arm,
                    &node,
                    index,
                    run.length,
                    run.distance,
                );
                while shortest < run.length && budget != 0 {
                    relax_priced(
                        &mut nodes,
                        &model.prices,
                        &slots,
                        &arm,
                        &node,
                        index,
                        shortest,
                        run.distance,
                    );
                    shortest += 1;
                    budget -= 1;
                }
                shortest = run.length + 1;
            }
        }

        let terminal = if forced.is_some() {
            settled
        } else {
            let mut best = limit;
            let mut best_price = u32::MAX;
            for candidate in limit..=horizon {
                if nodes[candidate].price == u32::MAX {
                    continue;
                }
                // Charge each ending the literals that would carry it to
                // the same byte, so paths covering different amounts of
                // input are compared over the same input.
                let adjusted =
                    nodes[candidate].price + literal_prefix[horizon] - literal_prefix[candidate];
                if adjusted < best_price {
                    best_price = adjusted;
                    best = candidate;
                }
            }
            best
        };

        path.clear();
        let mut cursor = terminal;
        while cursor != 0 {
            let node = nodes[cursor];
            path.push((cursor - node.from as usize, node.distance));
            cursor = node.from as usize;
        }
        let mut at = pos;
        for &(length, distance) in path.iter().rev() {
            if distance == 0 {
                EncodeToken::push_literals(&mut tokens, length);
                model.observe_literals(&combined[at..at + length]);
            } else {
                tokens.push(EncodeToken::matched(length, distance));
                model.observe_match(&state, length, distance)?;
                state.remember(length, distance);
            }
            at += length;
        }
        debug_assert_eq!(at, pos + terminal);

        if let Some(run) = forced {
            tokens.push(EncodeToken::matched(run.length, run.distance));
            model.observe_match(&state, run.length, run.distance)?;
            state.remember(run.length, run.distance);
            // The forced position was inserted before the break; the rest
            // of the match is inserted here, in its own order.
            insert_match_range(combined, at + 1..at + run.length, &mut buckets);
            pos = at + run.length;
        } else {
            // The window probed and inserted every position below its
            // limit; a path that ended past it covered the rest.
            if terminal > limit {
                insert_match_range(combined, pos + limit..pos + terminal, &mut buckets);
            }
            pos += terminal;
        }
        model.settle();

        let consumed = pos - start;
        if consumed >= next_report {
            if progress
                .as_deref_mut()
                .is_some_and(|report| !report(consumed))
            {
                return Err(Error::Cancelled);
            }
            next_report = consumed.saturating_add(1024 * 1024);
        }
    }
    if progress.is_some_and(|report| !report(input.len())) {
        return Err(Error::Cancelled);
    }
    Ok((tokens, buckets))
}

/// Price one length on an already-decided arm and relax the node it
/// reaches. A length the format cannot express at that distance (the
/// distance bonus takes it below two) simply has no edge.
#[allow(clippy::too_many_arguments)]
#[inline]
fn relax_priced(
    nodes: &mut [OptimalNode],
    prices: &TokenPrices,
    slots: &LengthSlots,
    arm: &DistanceArm,
    node: &OptimalNode,
    index: usize,
    length: usize,
    distance: usize,
) {
    let Some(cost) = arm.price(prices, slots, length) else {
        return;
    };
    relax_optimal(
        nodes,
        index,
        length,
        node.price + cost,
        distance,
        node.state,
    );
}

// nzbfast-local change, 5 Sep 2026 — share an eight-byte load across four
// adjacent hashes. Insert every position in its original order, including
// repeated-prefix collisions, and use the scalar path at the input tail.
// See research/rar5-large-2026-09-05 and VENDORING.md.
fn insert_match_range<P: MatchPosition>(
    input: &[u8],
    range: Range<usize>,
    index: &mut MatchIndex<P>,
) {
    let mut pos = range.start;
    let end = range.end.min(input.len().saturating_sub(3));
    while end.saturating_sub(pos) >= 4 && input.len().saturating_sub(pos) >= 8 {
        let words = u64::from_le_bytes(input[pos..pos + 8].try_into().unwrap());
        index.insert_word(words as u32, pos);
        index.insert_word((words >> 8) as u32, pos + 1);
        index.insert_word((words >> 16) as u32, pos + 2);
        index.insert_word((words >> 24) as u32, pos + 3);
        index.long_insert(input, words as u32, pos, true);
        index.long_insert(input, (words >> 8) as u32, pos + 1, true);
        index.long_insert(input, (words >> 16) as u32, pos + 2, true);
        index.long_insert(input, (words >> 24) as u32, pos + 3, true);
        pos += 4;
    }
    for at in pos..end {
        index.insert(input, at);
    }
}

fn insert_match_position<P: MatchPosition>(input: &[u8], pos: usize, index: &mut MatchIndex<P>) {
    index.insert(input, pos);
}

// nzbfast-local change, 5 Sep 2026 - flat ring match index; see VENDORING.md.
//
// Every bucket is a fixed ring of `depth` position slots in one flat
// vector, addressed by a multiplicative hash of the FOUR bytes at a
// position (a match must be four bytes long to be emitted, so a shorter
// hash only manufactures collisions). Insertion overwrites the oldest slot;
// a probe reads the newest `depth` back. No per-bucket allocation, no
// growth, a bounded and cache-local walk. The previous index was 4,096
// growable vectors under a three-byte hash, where most of a probe's
// candidates were other trigrams' positions rejected by the prefix
// compare, and the walk was bounded only by the candidate budget.
struct MatchIndex<P> {
    slots: Vec<P>,
    counts: Vec<u32>,
    hash_shift: u32,
    depth_bits: u32,
    /// Positions in the span need `pos_bits`; the bits above them in a
    /// slot hold a TAG, `tag_bits` of the position's four-byte hash (bits
    /// the bucket does not use), so a candidate whose tag differs is
    /// rejected without loading its history - at a 32 MiB dictionary the
    /// buckets are full and every one of a probe's 64 candidates used to
    /// cost a scattered load for the one-byte filter alone. A tag can only
    /// reject a candidate the prefix compare would have rejected, and a
    /// rejection still spends the candidate, so the walk stops where it
    /// did and the output is byte-identical. Zero `tag_bits` (a span past
    /// 2^32 in a u32 index cannot happen; usize spans get 8) means no tags.
    /// (nzbfast-local change, 6 Sep 2026; see VENDORING.md.)
    pos_bits: u32,
    tag_bits: u32,
    /// The long-match table: at every anchor position (one in 32, chosen by
    /// the four-byte hash so the same bytes anchor the same way wherever
    /// they recur) the position, plus one, under a hash of its next 32
    /// bytes; zero is empty. The ring above keeps the newest `depth`
    /// positions per bucket, which on a 32 MiB dictionary is the newest
    /// four megabytes or so of any common prefix - a repeat farther back
    /// than that was invisible. This table reaches the whole dictionary
    /// at one slot per 32 bytes: a repeated span is found at its first
    /// anchor, and the rep-distance probe carries the match on from there.
    /// Measured on the 1 GiB mixed corpus at a 32 MiB dictionary, where a
    /// third of the bytes are a 32 MiB pool replayed: see the research
    /// record for the round. (nzbfast-local change, 6 Sep 2026; see
    /// VENDORING.md.)
    long: Vec<P>,
    long_shift: u32,
}

#[inline]
fn long_anchor(word: u32) -> bool {
    (word.wrapping_mul(0x9E37_79B1) >> 8) & LONG_ANCHOR_MASK == 0
}

/// Hash of the 32 bytes at `pos`; the caller checks they exist.
#[inline]
fn long_hash(input: &[u8], pos: usize) -> u64 {
    let mut hash = 0u64;
    for chunk in input[pos..pos + LONG_HASH_BYTES].chunks_exact(8) {
        let word = u64::from_le_bytes(chunk.try_into().unwrap());
        hash = (hash ^ word).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        hash ^= hash >> 29;
    }
    hash
}

/// Per-thread encoder buffers a block encoder keeps between blocks: the
/// match index (16 MiB of slots at the default depth, whose fresh pages
/// were faulted in again for every 4 MiB block) and the token vector. A
/// pool worker owns one for the blocks it takes; every other caller gets a
/// fresh, empty one. Reset is the bucket counts only - slots past a
/// bucket's count are never read. (nzbfast-local change, 5 Sep 2026; see
/// VENDORING.md.)
/// A match index carried LIVE across the members of a solid group.
///
/// A solid member's continued arm tokenizes the member against the
/// dictionary of history before it, and the tokenizer seeded a fresh
/// index from that history for every member: up to 32 MiB of ring and
/// long-table inserts per member, ~80 ms, which on 10,240 members of
/// 10 KiB was 1,667 CPU-seconds for 100 MiB of input (rar 7.23: 62). The
/// group's members are consecutive in one span, so the index one member's
/// walk leaves holds exactly what the next member's seed would build (the
/// newest `depth` positions of every bucket, the newest anchor of every
/// long slot), and the walk continues on it: seeded once per group, then
/// the members' own bytes keep it current. The tag geometry is fixed from
/// the group span's length at the start so no slot is read under a split
/// it was not written under. A member longer than one block takes the
/// block path and leaves the index behind; the next member re-seeds. The
/// tokens are the per-member walk's, byte for byte (the solid identity
/// test holds it over tiny members and resets). (nzbfast-local change,
/// 6 Sep 2026; see VENDORING.md.)
pub(crate) struct LiveSpanEncoder {
    index: Option<MatchIndex<u32>>,
    /// The binary-tree match finder, carried across the group's members
    /// exactly as the ring is: it is the reach a solid set of small
    /// members needs, and it cannot be re-seeded per member any more than
    /// the ring can. Present only for dictionaries at or past
    /// [`TREE_MIN_DICTIONARY`]. (nzbfast-local change, 7 Sep 2026; see
    /// VENDORING.md.)
    tree: Option<TreeMatchFinder>,
    /// The finder's answers for the member being encoded.
    tree_distances: Vec<std::sync::atomic::AtomicU32>,
    /// Span positions `[0, covered)` are in the index.
    covered: usize,
    /// ...except `[indexed_to, covered)`: the last three positions of a
    /// member have no four bytes after them until the span grows past it,
    /// so they are inserted at the next call, in their place in the order.
    indexed_to: usize,
    /// The span length the index's position packing was fixed for: a
    /// caller whose span GROWS between calls (the reset walk appends a
    /// member at a time) names the bound up front.
    capacity: usize,
    tokens: Vec<EncodeToken>,
    scratch: EncoderScratchPool,
    /// This encoder emits on the calling thread, so one set of boundary
    /// buffers serves every member (nzbfast-local change, 7 Sep 2026).
    boundaries: boundaries::BoundaryScratch,
}

impl LiveSpanEncoder {
    /// An encoder for spans that are complete before the first call.
    pub(crate) fn new() -> Self {
        Self::with_capacity(0)
    }

    /// An encoder whose span may grow up to `capacity` bytes between
    /// calls, the index continuing across the growth.
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            index: None,
            tree: None,
            tree_distances: empty_slots(0),
            covered: 0,
            indexed_to: 0,
            capacity,
            tokens: Vec::new(),
            scratch: EncoderScratchPool::new(),
            boundaries: boundaries::BoundaryScratch::default(),
        }
    }

    /// `span[start..end]` encoded as one member with `span[..start]` as its
    /// history, the index continued from the previous call when that call
    /// ended at `start` on the same span.
    pub(crate) fn encode_member(
        &mut self,
        span: &[u8],
        start: usize,
        end: usize,
        algorithm_version: u8,
        options: EncodeOptions,
    ) -> Result<Vec<u8>> {
        let data = &span[start..end];
        if data.len() > MAX_COMPRESSED_BLOCK_OUTPUT
            || options.max_match_candidates == 0
            || options.max_match_distance == 0
            || !compact_match_index_fits(
                data.len(),
                start.min(options.max_match_distance),
                options.max_match_distance,
            )
            || u32::try_from(self.capacity.max(span.len())).is_err()
        {
            // Off the live path: the block walk (or the literal-only walk),
            // and the index no longer describes the span.
            self.index = None;
            self.tree = None;
            return encode_lz_member_pooled(
                data,
                &span[..start],
                algorithm_version,
                options,
                None,
                &self.scratch,
            );
        }
        let distance_size = match algorithm_version {
            0 => DISTANCE_TABLE_SIZE_50,
            1 => DISTANCE_TABLE_SIZE_70,
            _ => {
                return Err(Error::InvalidData(
                    "RAR 5 unknown compression algorithm version",
                ))
            }
        };
        // The shape the per-member walk would give this member's index -
        // its history (clipped to the dictionary) plus itself; the live
        // index continues only while that shape holds, which it does once
        // the history reaches the dictionary.
        let shape_len = data.len() + start.min(options.max_match_distance);
        let (buckets, depth) = MatchIndex::<u32>::shape(shape_len, options.max_match_candidates);
        let long_entries = MatchIndex::<u32>::long_entries(shape_len);
        let capacity = self.capacity.max(span.len());
        let continued = self.covered == start
            && capacity == self.capacity
            && self.index.as_ref().is_some_and(|index| {
                index.counts.len() == buckets
                    && index.depth() == depth
                    && index.long.len() == long_entries
            });
        // The finder walks this member's positions after the history
        // before it, in one range per member: its comparisons stop where
        // the tokenizer's matches must stop, at the member's end.
        let tree = if options.max_match_distance >= TREE_MIN_DICTIONARY
            && TreeMatchFinder::fits(capacity)
        {
            let stride = tree_candidate_slots(options);
            let mut finder = match self.tree.take() {
                Some(finder) if continued => finder,
                _ => {
                    let mut finder = TreeMatchFinder::new(options.max_match_distance);
                    let from = start.saturating_sub(finder.window());
                    finder.skip_to(from);
                    finder.advance_range(span, from..start, None, stride, tree_walkers());
                    finder
                }
            };
            let slots = (end - start) * stride;
            if self.tree_distances.len() < slots {
                self.tree_distances = empty_slots(slots);
            }
            for slot in &self.tree_distances[..slots] {
                slot.store(TREE_NO_MATCH, std::sync::atomic::Ordering::Relaxed);
            }
            finder.advance_range(
                span,
                start..end,
                Some(&self.tree_distances[..slots]),
                stride,
                1,
            );
            self.tree = Some(finder);
            &self.tree_distances[..slots]
        } else {
            self.tree = None;
            &[][..]
        };
        let index = match self.index.take() {
            Some(mut index) if continued => {
                for pos in self.indexed_to..start {
                    index.insert(span, pos);
                }
                index
            }
            _ => {
                // Seed once for this span: every position before `start`,
                // newest first; positions farther back than the dictionary
                // are only reached when a bucket has fewer nearer ones and
                // are filtered by distance at lookup, so the walk sees what
                // the per-member seed would have given it.
                let mut index = MatchIndex::<u32>::new_shaped(
                    shape_len,
                    capacity,
                    options.max_match_candidates,
                );
                index.seed_history_at(span, start);
                index
            }
        };
        self.capacity = capacity;
        let tokens = std::mem::take(&mut self.tokens);
        let (tokens, index) = walk_tokens::<u32>(
            span,
            start,
            end,
            options,
            distance_size,
            None,
            index,
            tokens,
            TreeMatches {
                base: start,
                distances: tree,
                stride: if tree.is_empty() || end == start {
                    0
                } else {
                    tree.len() / (end - start)
                },
            },
        )?;
        // Only the shape the index was built for matters for reuse; a
        // different span length next time means a different group.
        index_keep(&mut self.index, index);
        self.covered = end;
        self.indexed_to = end.min(span.len().saturating_sub(3));
        let out = encode_token_blocks(
            data,
            &tokens,
            &[],
            algorithm_version,
            distance_size,
            true,
            ENTROPY_BLOCK_BYTES,
            options,
            &mut self.boundaries,
        )?;
        self.tokens = tokens;
        self.tokens.clear();
        Ok(out)
    }
}

fn index_keep(slot: &mut Option<MatchIndex<u32>>, index: MatchIndex<u32>) {
    *slot = Some(index);
}

/// Encoder scratch handed from one block encode to the next: a member
/// encoded from windows ([`encode_lz_member_window`]) would otherwise
/// give every window's workers fresh buffers - 72 MiB a worker, hundreds
/// of megabytes of fresh pages per window, which on a KVM guest is where
/// the streamed writer's time went (measured 6 Sep 2026: system time
/// 8 -> 18 s over a 1 GiB member). Workers take a scratch when they start
/// and put it back when they finish, so at most as many are held as
/// workers run at once, whichever windows they belong to. (nzbfast-local
/// change, 6 Sep 2026; see VENDORING.md.)
#[derive(Default)]
pub(crate) struct EncoderScratchPool(std::sync::Mutex<Vec<EncoderScratch>>);

impl EncoderScratchPool {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn take(&self) -> EncoderScratch {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop()
            .unwrap_or_default()
    }

    fn put(&self, scratch: EncoderScratch) {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(scratch);
    }
}

#[derive(Default)]
struct EncoderScratch {
    index: Option<MatchIndex<u32>>,
    tokens: Vec<EncodeToken>,
    /// The boundary search's prefix snapshots, ~3.5 MB a block, held here
    /// for the reason the index is (nzbfast-local change, 7 Sep 2026).
    boundaries: boundaries::BoundaryScratch,
}

impl EncoderScratch {
    /// An index of the given shape, reused when the shape matches.
    fn index(&mut self, indexed_len: usize, max_match_candidates: usize) -> MatchIndex<u32> {
        let (buckets, depth) = MatchIndex::<u32>::shape(indexed_len, max_match_candidates);
        match self.index.take() {
            Some(mut index)
                if index.counts.len() == buckets
                    && index.depth() == depth
                    && index.long.len() == MatchIndex::<u32>::long_entries(indexed_len) =>
            {
                index.counts.fill(0);
                index.long.fill(P_ZERO_U32);
                // The span may be longer or shorter than the one this index
                // was shaped for (block 0 has no history, block 8 has 32
                // MiB of it): the position/tag split follows the span, and
                // no slot written under the old split is ever read - reads
                // stop at the bucket count, which is zero again.
                index.set_span(indexed_len);
                index
            }
            _ => MatchIndex::new(indexed_len, max_match_candidates),
        }
    }
}

const P_ZERO_U32: u32 = 0;

/// The shipped rule for `(buckets, depth)`: the ring holds the candidate
/// budget's positions (inside its own bounds) and the span gets about one
/// bucket per `depth` positions.
#[inline]
fn index_geometry_default(indexed_len: usize, max_match_candidates: usize) -> (usize, usize) {
    let depth = max_match_candidates
        .max(1)
        .next_power_of_two()
        .clamp(MATCH_INDEX_MIN_DEPTH, MATCH_INDEX_MAX_DEPTH);
    let buckets = (indexed_len / depth)
        .max(1)
        .next_power_of_two()
        .clamp(MATCH_INDEX_MIN_BUCKETS, MATCH_INDEX_MAX_BUCKETS);
    (buckets, depth)
}

/// Production: the shipped rule, and nothing else. This is the whole of
/// `shape`'s body in a build without `ratio-lab`, so no production binary
/// carries a branch, a lookup or a symbol for the research override below.
#[cfg(not(feature = "ratio-lab"))]
#[inline]
fn index_geometry(indexed_len: usize, max_match_candidates: usize) -> (usize, usize) {
    index_geometry_default(indexed_len, max_match_candidates)
}

/// `ratio-lab` only (nzbfast-local change, 8 Sep 2026; see VENDORING.md and
/// `research/rar5-index-geometry-2026-09-08`): force either axis of the
/// index geometry from the environment, so bucket count and ring depth can
/// be swept INDEPENDENTLY. The 8 Sep ring-probe census found 69.6% of a
/// bucket's candidates are foreign four-byte words, which is a property of
/// this shape rather than of the walk, and the one screen that followed it
/// moved both axes at once.
///
/// `RARS_INDEX_DEPTH` and `RARS_INDEX_BUCKETS` each force their axis
/// exactly; an axis left unset follows the shipped rule GIVEN the other,
/// so a depth-only arm keeps "about one bucket per `depth` positions".
/// With neither set this is `index_geometry_default` by construction, which
/// is what makes the research control reproduce ordinary bytes.
#[cfg(feature = "ratio-lab")]
fn index_geometry(indexed_len: usize, max_match_candidates: usize) -> (usize, usize) {
    let (forced_buckets, forced_depth) = index_geometry_override();
    if forced_buckets.is_none() && forced_depth.is_none() {
        // The research CONTROL is the shipped function itself, not a
        // re-derivation of it that could drift away from it silently.
        return index_geometry_default(indexed_len, max_match_candidates);
    }
    let depth = forced_depth.unwrap_or_else(|| {
        max_match_candidates
            .max(1)
            .next_power_of_two()
            .clamp(MATCH_INDEX_MIN_DEPTH, MATCH_INDEX_MAX_DEPTH)
    });
    let buckets = forced_buckets.unwrap_or_else(|| {
        (indexed_len / depth)
            .max(1)
            .next_power_of_two()
            .clamp(MATCH_INDEX_MIN_BUCKETS, MATCH_INDEX_MAX_BUCKETS)
    });
    (buckets, depth)
}

/// The parsed overrides, read once. A malformed value ABORTS the process
/// rather than falling back to the default: an arm that silently measured
/// the baseline under an arm's label is the one failure this harness cannot
/// detect from its own output, and every reading in this campaign is a
/// paired delta. It aborts rather than panicking because `shape` is reached
/// from an encoder WORKER - a panic there unwinds one rayon thread and
/// leaves the process alive with no output and no exit, which reads as a
/// slow arm rather than as a refusal (observed, 8 Sep 2026).
#[cfg(feature = "ratio-lab")]
fn index_geometry_override() -> (Option<usize>, Option<usize>) {
    static OVERRIDE: std::sync::OnceLock<(Option<usize>, Option<usize>)> =
        std::sync::OnceLock::new();
    *OVERRIDE.get_or_init(|| {
        fn refuse(message: String) -> ! {
            eprintln!("rars ratio-lab: {message}");
            std::process::abort();
        }
        fn read(name: &str, max: usize) -> Option<usize> {
            let raw = std::env::var(name).ok()?;
            let Ok(value) = raw.trim().parse::<usize>() else {
                refuse(format!("{name}: not a number: {raw:?}"));
            };
            if !value.is_power_of_two() || value > max {
                refuse(format!("{name}: want a power of two in 1..={max}, got {value}"));
            }
            Some(value)
        }
        let depth = read("RARS_INDEX_DEPTH", 1 << 12);
        let buckets = read("RARS_INDEX_BUCKETS", 1 << 24);
        // One index is allocated per encoder worker, so a careless pair is
        // gigabytes rather than a slow run.
        let slots =
            buckets.unwrap_or(MATCH_INDEX_MAX_BUCKETS) * depth.unwrap_or(MATCH_INDEX_MAX_DEPTH);
        if slots > 1 << 26 {
            refuse(format!(
                "RARS_INDEX_BUCKETS * RARS_INDEX_DEPTH = {slots} slots is over the lab's 2^26 ceiling"
            ));
        }
        (buckets, depth)
    })
}

impl<P: MatchPosition> MatchIndex<P> {
    /// Entries in the long-match table for a span: one per anchor spacing.
    fn long_entries(indexed_len: usize) -> usize {
        (indexed_len / LONG_ANCHOR_SPACING)
            .max(1)
            .next_power_of_two()
            .clamp(LONG_INDEX_MIN_ENTRIES, LONG_INDEX_MAX_ENTRIES)
    }

    /// `(buckets, depth)` for a span and a candidate budget.
    fn shape(indexed_len: usize, max_match_candidates: usize) -> (usize, usize) {
        index_geometry(indexed_len, max_match_candidates)
    }

    fn new(indexed_len: usize, max_match_candidates: usize) -> Self {
        Self::new_shaped(indexed_len, indexed_len, max_match_candidates)
    }

    /// An index shaped for a span `shape_len` long whose positions are
    /// offsets below `span_len`: the live solid encoder shapes its index
    /// as the per-member walk would (history plus member) while its
    /// positions are offsets in the whole group span.
    fn new_shaped(shape_len: usize, span_len: usize, max_match_candidates: usize) -> Self {
        let (buckets, depth) = Self::shape(shape_len, max_match_candidates);
        let long_entries = Self::long_entries(shape_len);
        let mut index = Self {
            slots: vec![P::from_position(0); buckets * depth],
            counts: vec![0; buckets],
            hash_shift: 32 - buckets.trailing_zeros(),
            depth_bits: depth.trailing_zeros(),
            long: vec![P::from_position(0); long_entries],
            long_shift: 64 - long_entries.trailing_zeros(),
            pos_bits: 0,
            tag_bits: 0,
        };
        index.set_span(span_len);
        index
    }

    /// The position/tag split for a span whose positions are below
    /// `indexed_len`: only valid on an index with every bucket count zero.
    fn set_span(&mut self, indexed_len: usize) {
        debug_assert!(self.counts.iter().all(|&count| count == 0));
        self.pos_bits = (usize::BITS - indexed_len.max(1).leading_zeros()).max(1);
        self.tag_bits = P::BITS
            .saturating_sub(self.pos_bits)
            .min(MATCH_TAG_BITS_MAX);
    }

    /// The tag of a four-byte word: hash bits below the bucket's.
    #[inline]
    fn tag(&self, word: u32) -> usize {
        ((word.wrapping_mul(0x9E37_79B1) >> 8) as usize) & ((1usize << self.tag_bits) - 1)
    }

    /// A slot value: the position with the word's tag above it.
    #[inline]
    fn slot_value(&self, word: u32, pos: usize) -> P {
        P::from_position(pos | (self.tag(word) << self.pos_bits))
    }

    /// A slot's position, without its tag.
    ///
    /// The read half of `slot_value` above, which IS used: kept as the
    /// statement of how a slot is packed, so the two halves of that
    /// encoding stay next to each other. No caller today.
    #[allow(dead_code)]
    #[inline]
    fn slot_position(&self, slot: P) -> usize {
        slot.position() & ((1usize << self.pos_bits) - 1)
    }

    #[inline]
    fn long_slot(&self, input: &[u8], pos: usize) -> usize {
        (long_hash(input, pos) >> self.long_shift) as usize
    }

    /// Record `pos` in the long table if it is an anchor with 32 bytes after
    /// it. Forward insertion overwrites (the newest position wins); reverse
    /// seeding keeps the first write, which is the newest there too.
    #[inline]
    fn long_insert(&mut self, input: &[u8], word: u32, pos: usize, overwrite: bool) {
        if long_anchor(word) && pos + LONG_HASH_BYTES <= input.len() {
            let slot = self.long_slot(input, pos);
            if overwrite || self.long[slot].position() == 0 {
                self.long[slot] = P::from_position(pos + 1);
            }
        }
    }

    /// The long table's position for `pos`, if `pos` is an anchor and the
    /// table has one: the caller verifies the bytes.
    #[inline]
    fn long_candidate(&self, input: &[u8], pos: usize) -> Option<usize> {
        if pos + LONG_HASH_BYTES > input.len() {
            return None;
        }
        let word = u32::from_le_bytes(input[pos..pos + 4].try_into().unwrap());
        if !long_anchor(word) {
            return None;
        }
        let entry = self.long[self.long_slot(input, pos)].position();
        (entry != 0).then(|| entry - 1)
    }

    /// Anchors of the whole history into the long table, newest first, so
    /// the nearest occurrence of a span is the one kept. Runs over ALL of
    /// the history where the ring's seeding stops once every bucket is
    /// full - reach is the point of this table.
    fn seed_long_history(&mut self, input: &[u8], history_len: usize) {
        let mut end = history_len.min(input.len().saturating_sub(LONG_HASH_BYTES - 1));
        while end >= 4 {
            end -= 4;
            let words = u64::from_le_bytes(input[end..end + 8].try_into().unwrap());
            self.long_insert(input, (words >> 24) as u32, end + 3, false);
            self.long_insert(input, (words >> 16) as u32, end + 2, false);
            self.long_insert(input, (words >> 8) as u32, end + 1, false);
            self.long_insert(input, words as u32, end, false);
        }
        while end != 0 {
            end -= 1;
            let word = u32::from_le_bytes(input[end..end + 4].try_into().unwrap());
            self.long_insert(input, word, end, false);
        }
    }

    #[inline]
    fn depth(&self) -> usize {
        1 << self.depth_bits
    }

    #[inline]
    fn bucket(&self, input: &[u8], pos: usize) -> usize {
        let word = u32::from_le_bytes(input[pos..pos + 4].try_into().unwrap());
        (word.wrapping_mul(0x9E37_79B1) >> self.hash_shift) as usize
    }

    /// Positions with fewer than four bytes after them can never start a
    /// match and are not indexed.
    #[inline]
    fn insert(&mut self, input: &[u8], pos: usize) {
        if pos + 3 < input.len() {
            let word = u32::from_le_bytes(input[pos..pos + 4].try_into().unwrap());
            self.insert_word(word, pos);
            self.long_insert(input, word, pos, true);
        }
    }

    #[inline]
    fn insert_word(&mut self, word: u32, pos: usize) {
        let bucket = (word.wrapping_mul(0x9E37_79B1) >> self.hash_shift) as usize;
        let count = self.counts[bucket];
        let slot = (bucket << self.depth_bits) | (count as usize & (self.depth() - 1));
        self.slots[slot] = self.slot_value(word, pos);
        self.counts[bucket] = count.wrapping_add(1);
    }

    /// Seed the history of a member at `to` in `span` into a fresh index
    /// whose positions are span offsets: every position below `to`, newest
    /// first until the buckets fill, exactly as [`Self::seed_history`]
    /// seeds a span that begins at zero. Positions farther back than the
    /// dictionary are filtered by distance at lookup, so the span's start
    /// is only a cost, paid once per group.
    fn seed_history_at(&mut self, span: &[u8], to: usize) {
        self.seed_history(span, to, None);
    }

    fn seed_history(&mut self, input: &[u8], history_len: usize, long_seed: Option<LongSeed<'_>>) {
        // Normalizing a ring preserves its candidate order, but not its
        // absolute insertion count. Keep the original path when a count
        // could wrap anywhere in this combined history/input span.
        if history_len <= self.slots.len() * 2 || u32::try_from(input.len()).is_err() {
            insert_match_range(input, 0..history_len, self);
            return;
        }
        self.seed_history_reverse(input, history_len);
        match long_seed {
            Some(seed) => self.seed_long_from_anchors(input, history_len, seed),
            None => self.seed_long_history(input, history_len),
        }
    }

    /// The long-table seed from the member's shared anchor lists: the same
    /// positions `seed_long_history` would anchor, in the same newest-first
    /// order, so the table and the output are identical. The history of a
    /// block is member bytes before `range_start`, at `history_len -
    /// range_start` from their member positions in this span; any solid
    /// history from an earlier member sits before them and is scanned.
    fn seed_long_from_anchors(&mut self, input: &[u8], history_len: usize, seed: LongSeed<'_>) {
        let window_start = seed.range_start.saturating_sub(history_len);
        let shift = history_len as isize - seed.range_start as isize;
        let first_block = window_start / MAX_COMPRESSED_BLOCK_OUTPUT;
        let end_block = seed.range_start.div_ceil(MAX_COMPRESSED_BLOCK_OUTPUT);
        for block in (first_block..end_block).rev() {
            let list = seed.anchors.block(block);
            let block_base = block * MAX_COMPRESSED_BLOCK_OUTPUT;
            for &offset in list.iter().rev() {
                let data_pos = block_base + offset as usize;
                if data_pos < window_start {
                    break;
                }
                if data_pos >= seed.range_start {
                    continue;
                }
                let pos = (data_pos as isize + shift) as usize;
                if pos + LONG_HASH_BYTES > input.len() {
                    continue;
                }
                let slot = self.long_slot(input, pos);
                if self.long[slot].position() == 0 {
                    self.long[slot] = P::from_position(pos + 1);
                }
            }
        }
        // Solid history from an earlier member (or a streamed member's
        // earlier segment) sits BEFORE the member's own bytes in this span,
        // so it is the OLDEST part of the window and is scanned LAST: the
        // scan this replaced ran newest-first over the whole window, and
        // keep-first semantics make the order the result. (The first cut
        // scanned it first, which handed an older occurrence the slot a
        // newer one should have had whenever both anchored the same way -
        // invisible on a member with no incoming history, which is every
        // shape the identity checks used.)
        let tail_len = history_len.saturating_sub(seed.range_start);
        if tail_len != 0 {
            self.seed_long_history(input, tail_len);
        }
    }

    fn seed_history_reverse(&mut self, input: &[u8], history_len: usize) {
        // Batch scanning helps low-diversity history; the scalar scan is
        // faster when its bucket accesses are dense and irregular. A small
        // projected-bucket sample selects the scan, never the candidates.
        let end = history_len.min(input.len().saturating_sub(3));
        let mut seen = [0u64; 16];
        let mut distinct = 0;
        for pos in (end.saturating_sub(512)..end).rev() {
            let bucket = self.bucket(input, pos) & 1023;
            let bit = 1u64 << (bucket & 63);
            if seen[bucket >> 6] & bit == 0 {
                seen[bucket >> 6] |= bit;
                distinct += 1;
                if distinct > 128 {
                    self.seed_history_reverse_scalar(input, history_len);
                    return;
                }
            }
        }
        self.seed_history_reverse_batched(input, history_len);
    }

    fn seed_history_reverse_scalar(&mut self, input: &[u8], history_len: usize) {
        debug_assert!(self.counts.iter().all(|&count| count == 0));
        let depth = self.depth();
        let mut unfilled = self.counts.len();
        let end = history_len.min(input.len().saturating_sub(3));
        for pos in (0..end).rev() {
            let word = u32::from_le_bytes(input[pos..pos + 4].try_into().unwrap());
            let bucket = (word.wrapping_mul(0x9E37_79B1) >> self.hash_shift) as usize;
            let count = self.counts[bucket] as usize;
            if count == depth {
                continue;
            }
            // Store from the back: after normalization, the newest entry
            // sits immediately before the next insertion slot.
            let slot = (bucket << self.depth_bits) + depth - 1 - count;
            self.slots[slot] = self.slot_value(word, pos);
            self.counts[bucket] += 1;
            if count + 1 == depth {
                unfilled -= 1;
                if unfilled == 0 {
                    break;
                }
            }
        }
        for (bucket, &count) in self.counts.iter().enumerate() {
            let count = count as usize;
            if count != 0 && count < depth {
                let base = bucket << self.depth_bits;
                self.slots
                    .copy_within(base + depth - count..base + depth, base);
            }
        }
    }

    fn seed_history_reverse_batched(&mut self, input: &[u8], history_len: usize) {
        debug_assert!(self.counts.iter().all(|&count| count == 0));
        let depth = self.depth();
        let mut unfilled = self.counts.len();
        let mut end = history_len.min(input.len().saturating_sub(3));
        // An eight-byte load covers four overlapping prefixes. One scalar
        // prefix handles a history ending at the last valid input prefix.
        if end != 0 && input.len() - end < 4 {
            end -= 1;
            let word = u32::from_le_bytes(input[end..end + 4].try_into().unwrap());
            self.seed_history_word(word, end, depth, &mut unfilled);
        }
        while end >= 4 && unfilled != 0 {
            end -= 4;
            let words = u64::from_le_bytes(input[end..end + 8].try_into().unwrap());
            self.seed_history_word((words >> 24) as u32, end + 3, depth, &mut unfilled);
            self.seed_history_word((words >> 16) as u32, end + 2, depth, &mut unfilled);
            self.seed_history_word((words >> 8) as u32, end + 1, depth, &mut unfilled);
            self.seed_history_word(words as u32, end, depth, &mut unfilled);
        }
        while end != 0 && unfilled != 0 {
            end -= 1;
            let word = u32::from_le_bytes(input[end..end + 4].try_into().unwrap());
            self.seed_history_word(word, end, depth, &mut unfilled);
        }
        for (bucket, &count) in self.counts.iter().enumerate() {
            let count = count as usize;
            if count != 0 && count < depth {
                let base = bucket << self.depth_bits;
                self.slots
                    .copy_within(base + depth - count..base + depth, base);
            }
        }
    }

    #[inline(always)]
    fn seed_history_word(&mut self, word: u32, pos: usize, depth: usize, unfilled: &mut usize) {
        let bucket = (word.wrapping_mul(0x9E37_79B1) >> self.hash_shift) as usize;
        let count = self.counts[bucket] as usize;
        if count < depth {
            let slot = (bucket << self.depth_bits) + depth - 1 - count;
            self.slots[slot] = self.slot_value(word, pos);
            self.counts[bucket] += 1;
            if count + 1 == depth {
                *unfilled -= 1;
            }
        }
    }

    /// The bucket's inserted positions, newest first, at most `depth` of them.
    ///
    /// The untagged view of `candidates_tagged` below, which IS what the
    /// walkers call. No caller today; kept as the plain reading of a
    /// bucket, next to the tagged one it is defined from.
    #[allow(dead_code)]
    #[inline]
    fn candidates(&self, input: &[u8], pos: usize) -> impl Iterator<Item = usize> + '_ {
        self.candidates_tagged(input, pos)
            .map(|(candidate, _)| candidate)
    }

    /// The bucket's inserted positions, newest first, each with whether its
    /// tag matches the word at `pos` - `false` means the prefix cannot.
    #[inline]
    fn candidates_tagged(
        &self,
        input: &[u8],
        pos: usize,
    ) -> impl Iterator<Item = (usize, bool)> + '_ {
        let word = u32::from_le_bytes(input[pos..pos + 4].try_into().unwrap());
        let bucket = (word.wrapping_mul(0x9E37_79B1) >> self.hash_shift) as usize;
        let tag = self.tag(word);
        let count = self.counts[bucket];
        let available = (count as usize).min(self.depth());
        let base = bucket << self.depth_bits;
        let mask = self.depth() - 1;
        let pos_mask = (1usize << self.pos_bits) - 1;
        (1..=available).map(move |back| {
            let value =
                self.slots[base | (count.wrapping_sub(back as u32) as usize & mask)].position();
            (value & pos_mask, (value >> self.pos_bits) == tag)
        })
    }
}

fn length_slot_for_match(length: usize) -> Result<(usize, usize)> {
    if length < 2 {
        return Err(Error::InvalidData("RAR 5 match length is too short"));
    }
    let value = length - 2;
    if value < 8 {
        return Ok((value, 0));
    }
    // Four consecutive slots share each extra-bit width.
    let bits = (usize::BITS - 1 - value.leading_zeros()) as usize - 2;
    let slot = 4 * (bits + 1) + ((value >> bits) & 3);
    if slot >= LENGTH_TABLE_SIZE {
        return Err(Error::InvalidData("RAR 5 match length is too long"));
    }
    let base = ((4 | (slot & 3)) << bits) + 2;
    Ok((slot, length - base))
}

/// The inverse of `slot_to_distance`: the slot whose window contains
/// `distance`, and the extra bits within it.
///
/// The window is computed in `u64` for the same reason `distance_wide` is:
/// the top slot's base is `(3 << 31) + 1`, half again past 2^32, and its
/// `max` is 2^33 exactly, so on a 32-bit target both the base and the
/// `base + (1 << bit_count) - 1` above it overflow a `usize` - and they do
/// so for slots the loop must EVALUATE on its way to the small one that
/// actually matches. `distance` is a `usize`
/// and cannot exceed either bound, so widening the window rather than the
/// needle is enough, and the subtraction below is then in range by
/// construction.
fn distance_slot_for_match(distance: usize, distance_size: usize) -> Result<(usize, usize)> {
    if distance == 0 {
        return Err(Error::InvalidData("RAR 5 match distance is zero"));
    }
    let value = distance - 1;
    // Two consecutive distance slots share each extra-bit width.
    let (slot, bits) = if value < 4 {
        (value, 0)
    } else {
        let bits = (usize::BITS - 1 - value.leading_zeros()) as usize - 1;
        (2 * (bits + 1) + ((value >> bits) & 1), bits)
    };
    // Preserve the linear search's error when it would reach invalid slot 66.
    if bits > 31 && distance_size > 66 {
        return Err(Error::InvalidData("RAR 5 distance slot is too large"));
    }
    if slot >= distance_size || bits > 31 {
        return Err(Error::InvalidData("RAR 5 match distance is too large"));
    }
    let base = if slot < 4 {
        slot + 1
    } else {
        ((2 | (slot & 1)) << bits) + 1
    };
    Ok((slot, distance - base))
}

fn literal_presence(data: &[u8]) -> [bool; 256] {
    let mut present = [false; 256];
    for &byte in data {
        present[byte as usize] = true;
    }
    present
}

#[derive(Debug, Clone)]
pub struct Rar50Decoder {
    // Arc so the parallel block decoder can hand the current table set to
    // worker threads without cloning the LUTs; serial paths just deref.
    tables: Option<std::sync::Arc<DecodeTables>>,
    reps: [usize; 4],
    previous_match_length: usize,
    // Solid LZ history, offset-addressed: the live match window is
    // `history[history_start..]`. Trimming the window to the dictionary is
    // an O(1) advance of `history_start` instead of a front `drain` that
    // memmoves megabytes per solid member; dead front bytes are reclaimed
    // by `commit_member`'s compaction (counted by `history_compactions` so
    // a checkpoint can assert its truncate-based restore stayed valid).
    history: Vec<u8>,
    history_start: usize,
    // Sparse zeroes logically in front of `history` from a streamed member
    // whose output was (partly) emitted as unmaterialized zero runs - see
    // `StreamingOutput::zero_prefix`. Carried so a solid member can still
    // reference into a preceding all-zero member's output; reset whenever
    // the bytes ahead of the retained window stop being provably zero.
    history_zero_prefix: usize,
    history_compactions: u64,
    retain_history: bool,
    window_limit: usize,
    // Execution-policy cap on tape-decode workers; usize::MAX = uncapped.
    // A cap of 1 keeps every MT gate below its >=2 threshold, so decode
    // stays fully serial. Never changes output bytes or errors.
    mt_workers_cap: usize,
    // Test-only override forcing the parallel flat-apply path on regardless of
    // member size, so the dedicated flat differential tests exercise it on the
    // large multi-block shapes; never set on the production gate (see 2.2).
    // Read only from `use_flat_mode`, which lives in the `parallel`-gated
    // impl block, so a non-parallel test build never reads it.
    #[cfg(all(test, feature = "parallel"))]
    test_force_flat: bool,
}

/// Owned solid-state snapshot for group-level retry after a failed chain
/// decode (window bytes included). See `snapshot_solid_state`.
#[cfg(feature = "parallel")]
pub struct SolidStateSnapshot {
    window: Vec<u8>,
    zero_prefix: usize,
    tables: Option<std::sync::Arc<DecodeTables>>,
    reps: [usize; 4],
    previous_match_length: usize,
}

/// O(1) snapshot of decoder state before a solid member decodes, so a
/// failed integrity check can rewind and retry (filters off) without
/// cloning the decoder - the clone copied the whole multi-MB solid window
/// per member. Valid to restore only while no compaction has run since the
/// checkpoint; `Rar50Decoder::commit_member` (the only compaction site)
/// must not be called between `solid_checkpoint` and `restore_checkpoint`.
pub struct SolidCheckpoint {
    tables: Option<std::sync::Arc<DecodeTables>>,
    reps: [usize; 4],
    previous_match_length: usize,
    history_start: usize,
    history_len: usize,
    history_zero_prefix: usize,
    compactions: u64,
}

impl Rar50Decoder {
    pub fn new() -> Self {
        Self {
            retain_history: true,
            tables: None,
            reps: [0; 4],
            previous_match_length: 0,
            history: Vec::new(),
            history_start: 0,
            history_zero_prefix: 0,
            history_compactions: 0,
            window_limit: usize::MAX,
            mt_workers_cap: usize::MAX,
            #[cfg(all(test, feature = "parallel"))]
            test_force_flat: false,
        }
    }

    /// The live solid match window (everything a next member's matches may
    /// reach back into).
    #[inline]
    fn history_window(&self) -> &[u8] {
        &self.history[self.history_start..]
    }

    #[inline]
    fn history_window_len(&self) -> usize {
        self.history.len() - self.history_start
    }

    /// Trim the window to `limit` bytes - O(1), no bytes move.
    #[inline]
    fn trim_history_to(&mut self, limit: usize) {
        if self.history_window_len() > limit {
            self.history_start = self.history.len() - limit;
            // The dropped front bytes are no longer provably zero, so any
            // carried sparse run behind them must be dropped with them.
            // Nothing is lost: a window already at `limit` leaves no
            // distance below the limit for the run to serve.
            self.history_zero_prefix = 0;
        }
    }

    /// The window as an owned Vec (front slack dropped) - the streaming
    /// path's ring seeds from this.
    fn take_history_vec(&mut self) -> Vec<u8> {
        if self.history_start > 0 {
            self.history.drain(..self.history_start);
            self.history_start = 0;
            self.history_compactions += 1;
        }
        std::mem::take(&mut self.history)
    }

    /// Snapshot decoder state before a solid member decode (see
    /// `SolidCheckpoint`).
    pub fn solid_checkpoint(&self) -> SolidCheckpoint {
        SolidCheckpoint {
            tables: self.tables.clone(),
            reps: self.reps,
            previous_match_length: self.previous_match_length,
            history_start: self.history_start,
            history_len: self.history.len(),
            history_zero_prefix: self.history_zero_prefix,
            compactions: self.history_compactions,
        }
    }

    /// Rewind to a checkpoint taken before the failed decode. Between the
    /// two calls the decoder only appends history and advances the window
    /// start, so truncate + restored start reinstate the exact window.
    pub fn restore_checkpoint(&mut self, cp: &SolidCheckpoint) {
        assert_eq!(
            cp.compactions, self.history_compactions,
            "solid checkpoint invalidated by a history compaction"
        );
        self.history.truncate(cp.history_len);
        self.history_start = cp.history_start;
        self.history_zero_prefix = cp.history_zero_prefix;
        self.tables = cp.tables.clone();
        self.reps = cp.reps;
        self.previous_match_length = cp.previous_match_length;
    }

    /// A solid member's output is verified and final: reclaim the dead
    /// front of the history buffer once it outweighs the live window.
    pub fn commit_member(&mut self) {
        if self.history_start > 0 && self.history_start >= self.history_window_len() {
            self.history.drain(..self.history_start);
            self.history_start = 0;
            self.history_compactions += 1;
        }
    }

    /// When false, per-member LZ history is not retained after decode —
    /// valid only for non-solid archives, where the next member never
    /// references it. Skips up to dictionary-size copies per member.
    pub fn set_retain_history(&mut self, retain: bool) {
        self.retain_history = retain;
    }

    /// Caps the streaming match window (bytes). The ring never grows past this,
    /// so a member whose declared dictionary exceeds it decodes only while its
    /// back-references stay within the limit; a match that genuinely needs more
    /// fails with `Rar50WindowLimitExceeded` rather than allocating a window the
    /// host may not afford. `usize::MAX` (the default) imposes no cap.
    pub fn set_window_limit(&mut self, limit: usize) {
        self.window_limit = limit.max(1);
    }

    /// Caps the parallel tape-decode workers (execution policy). 1 disables
    /// the MT pipelines entirely; the default is uncapped.
    pub fn set_mt_workers_cap(&mut self, cap: usize) {
        self.mt_workers_cap = cap.max(1);
    }

    /// Host-derived worker count, bounded by the execution policy's cap.
    #[cfg(feature = "parallel")]
    fn capped_workers(&self, output_size: usize) -> usize {
        mt_worker_count(output_size).min(self.mt_workers_cap)
    }

    pub fn decode_member(
        &mut self,
        input: &[u8],
        algorithm_version: u8,
        output_size: usize,
        solid: bool,
        mode: DecodeMode,
    ) -> Result<Vec<u8>> {
        self.decode_member_with_dictionary(
            input,
            algorithm_version,
            output_size,
            DEFAULT_DICTIONARY_SIZE,
            solid,
            mode,
        )
    }

    pub fn decode_member_with_dictionary(
        &mut self,
        input: &[u8],
        algorithm_version: u8,
        output_size: usize,
        dictionary_size: usize,
        solid: bool,
        mode: DecodeMode,
    ) -> Result<Vec<u8>> {
        let mut input = std::io::Cursor::new(input);
        self.decode_member_from_reader_with_dictionary(
            &mut input,
            algorithm_version,
            output_size,
            dictionary_size,
            solid,
            mode,
        )
    }

    pub fn decode_member_from_reader(
        &mut self,
        input: &mut impl Read,
        algorithm_version: u8,
        output_size: usize,
        solid: bool,
        mode: DecodeMode,
    ) -> Result<Vec<u8>> {
        self.decode_member_from_reader_with_dictionary(
            input,
            algorithm_version,
            output_size,
            DEFAULT_DICTIONARY_SIZE,
            solid,
            mode,
        )
    }

    pub fn decode_member_from_reader_with_dictionary(
        &mut self,
        input: &mut impl Read,
        algorithm_version: u8,
        output_size: usize,
        dictionary_size: usize,
        solid: bool,
        mode: DecodeMode,
    ) -> Result<Vec<u8>> {
        if dictionary_size == 0 {
            return Err(Error::InvalidData("RAR 5 dictionary size is zero"));
        }
        if !solid {
            self.reset();
        }

        let mut output = Vec::with_capacity(output_size.min(MAX_INITIAL_OUTPUT_CAPACITY));
        let mut filters = Vec::new();

        let mut payload_buf = Vec::new();
        loop {
            let block_header = read_compressed_block_into(input, &mut payload_buf)?;
            let payload = payload_buf.as_slice();
            let mut payload_bit_pos = 0;
            if block_header.has_tables {
                let (lengths, table_bits) = read_table_lengths(payload, algorithm_version)?;
                self.tables = Some(std::sync::Arc::new(DecodeTables::from_lengths(&lengths)?));
                payload_bit_pos = table_bits;
            }
            let tables = self
                .tables
                .take()
                .ok_or(Error::InvalidData("RAR 5 block reuses missing tables"))?;
            let mut bits = BitReader::new_at(payload, payload_bit_pos);

            while bits.position() < block_header.payload_bits && output.len() < output_size {
                // Literal burst on the LUT fast path (the buffered mirror of
                // StreamingOutput::literal_burst): decode LUT-hit literals in
                // a tight loop. A LUT-hit control symbol is consumed and handed
                // straight to the dispatch below, avoiding a second peek and
                // LUT lookup for every common match; a non-LUT symbol falls
                // back to the canonical decoder. This is the hot path for
                // incompressible spans and the entry to every short-code match.
                let mut burst_control = None;
                while output.len() < output_size && bits.position() < block_header.payload_bits {
                    let entry = tables.main.peek_lut_entry(&mut bits);
                    if !lut_entry_is_literal(entry) {
                        if entry != HUFF_LUT_MISS {
                            bits.consume((entry & HUFF_LUT_LENGTH_MASK) as u8);
                            burst_control = Some(lut_entry_symbol(entry));
                        }
                        break;
                    }
                    bits.consume((entry & HUFF_LUT_LENGTH_MASK) as u8);
                    output.push((entry >> 8) as u8);
                }
                if output.len() >= output_size
                    || (burst_control.is_none() && bits.position() >= block_header.payload_bits)
                {
                    break;
                }
                let symbol = match burst_control {
                    Some(symbol) => symbol,
                    None => tables.main.decode(&mut bits)?,
                };
                match symbol {
                    0..=255 => output.push(symbol as u8),
                    256 if mode.uses_lz() => {
                        filters.push(parse_filter_record(&mut bits, output.len())?);
                    }
                    257 if mode.uses_lz() => {
                        if self.previous_match_length != 0 {
                            self.copy_match(
                                &mut output,
                                self.reps[0],
                                self.previous_match_length,
                                output_size,
                                dictionary_size,
                            )?;
                        }
                    }
                    258..=261 if mode.uses_lz() => {
                        let rep_index = symbol - 258;
                        let distance = self.reps[rep_index];
                        if distance == 0 {
                            return Err(Error::InvalidData(
                                "RAR 5 repeat distance is not initialized",
                            ));
                        }
                        let length_slot = tables.length.decode(&mut bits)?;
                        let length_extra = bits.read_bits(length_slot_extra_bits(length_slot)?)?;
                        let length = match_length_for_slot(length_slot, length_extra)?;
                        self.reps[..=rep_index].rotate_right(1);
                        self.reps[0] = distance;
                        self.previous_match_length = length;
                        self.copy_match(
                            &mut output,
                            distance,
                            length,
                            output_size,
                            dictionary_size,
                        )?;
                    }
                    262.. if mode.uses_lz() => {
                        let length_slot = symbol - 262;
                        let length_extra = bits.read_bits(length_slot_extra_bits(length_slot)?)?;
                        let mut length = match_length_for_slot(length_slot, length_extra)?;
                        #[cfg(feature = "parallel")]
                        let (distance_slot, distance_bit_count) =
                            tables.distance.decode_distance_hot(&mut bits)?;
                        #[cfg(not(feature = "parallel"))]
                        let distance_slot = tables.distance.decode(&mut bits)?;
                        #[cfg(not(feature = "parallel"))]
                        let distance_bit_count = distance_slot_bit_count(distance_slot)?;
                        // The `as u8` casts below are a NO-OP under `parallel`, where
                        // `decode_distance_hot` already answers in `u8`, and LOAD-BEARING
                        // without it, where `distance_slot_bit_count` answers in `usize`.
                        // `unnecessary_cast` only ever sees one of the two configurations, and
                        // taking its advice broke the other (9 Sep 2026: the workspace lint runs
                        // with `parallel` on, and the fuzz crate - which builds `rars` with
                        // default features - stopped compiling).
                        #[allow(clippy::unnecessary_cast)]
                        let distance_extra = if distance_bit_count >= 4 && tables.align_mode {
                            let high = bits.read_bits((distance_bit_count - 4) as u8)?;
                            let low = tables.align.decode(&mut bits)? as u32;
                            (high << 4) | low
                        } else {
                            bits.read_bits(distance_bit_count as u8)?
                        };
                        #[cfg(feature = "parallel")]
                        let distance =
                            slot_distance_value(distance_slot, distance_bit_count, distance_extra);
                        #[cfg(not(feature = "parallel"))]
                        let distance = slot_to_distance(distance_slot, distance_extra)?;
                        length += length_bonus(distance);
                        self.reps.rotate_right(1);
                        self.reps[0] = distance;
                        self.previous_match_length = length;
                        self.copy_match(
                            &mut output,
                            distance,
                            length,
                            output_size,
                            dictionary_size,
                        )?;
                    }
                    _ if mode == DecodeMode::LiteralOnly => {
                        return Err(Error::InvalidData(
                            "RAR 5 literal-only decoder encountered non-literal symbol",
                        ));
                    }
                    _ => {
                        return Err(Error::InvalidData(
                            "RAR 5 decoder encountered unsupported control symbol",
                        ));
                    }
                }
            }

            self.tables = Some(tables);
            if block_header.is_last || output.len() >= output_size {
                break;
            }
        }

        if output.len() == output_size {
            let history_output =
                if self.retain_history && mode.applies_filters() && !filters.is_empty() {
                    Some(output.clone())
                } else {
                    None
                };
            if mode.applies_filters() {
                apply_filters(&mut output, &filters)?;
            }
            if self.retain_history {
                self.history
                    .extend_from_slice(history_output.as_deref().unwrap_or(&output));
                self.trim_history_to(dictionary_size);
            }
            Ok(output)
        } else {
            Err(Error::NeedMoreInput)
        }
    }

    // `Send` bound: the flat-apply path scans on a scoped thread. Every real
    // caller already hands in a Send reader (extract.rs pipelines are Send).
    // Every argument names a different thing the encoder needs and no two
    // of them travel together, so a parameter struct here would be a bag
    // with one field per argument and a second name for each. The lint's
    // ceiling is 7; these are 8 and 10.
    #[allow(clippy::too_many_arguments)]
    pub fn decode_member_from_reader_with_dictionary_to_sink<E>(
        &mut self,
        input: &mut (impl Read + Send),
        algorithm_version: u8,
        output_size: usize,
        dictionary_size: usize,
        solid: bool,
        flat_limit: u64,
        mut sink: impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        if dictionary_size == 0 {
            return Err(Error::InvalidData("RAR 5 dictionary size is zero").into());
        }
        if !solid {
            self.reset();
        }
        // Flat mode (the only consumer of `flat_limit`) is parallel-only.
        #[cfg(not(feature = "parallel"))]
        let _ = flat_limit;

        // The reachable match window is the full dictionary: WinRAR may emit a
        // back-reference at any distance up to the dictionary size, so a decoder
        // that retains fewer bytes rejects legal matches ("match distance
        // exceeds window") on any archive built with a dictionary larger than
        // the retained window. Memory stays bounded because the ring grows only
        // as far back as output actually reaches (see `reserve`), capped at the
        // dictionary -- or at `window_limit`, the caller's ceiling on how large
        // a window it will allocate (RAR 7 dictionaries reach far past what most
        // hosts can afford). A match that needs more than the limit fails with
        // `Rar50WindowLimitExceeded` instead of driving a giant allocation.
        let history_limit = dictionary_size.min(self.window_limit);
        self.trim_history_to(history_limit);

        // Flat-apply mode: a non-solid member small enough to buffer whole
        // decodes into one member-sized buffer with a stripped-down apply
        // stage (no ring masking, no flush watermark, no double copy). Same
        // MT scan/decode pipeline feeds it; only the apply target changes.
        // Gated to non-solid members <= flat_limit; everything else (solid,
        // over-limit, non-parallel builds) keeps the streaming-MT/serial path.
        #[cfg(feature = "parallel")]
        if self.use_flat_mode(
            flat_plan_bytes(0, output_size, history_limit),
            output_size,
            solid,
            flat_limit,
        ) {
            debug_assert!(
                self.history_window_len() == 0,
                "flat mode is gated to non-solid members, which carry no history"
            );
            let mut flat = FlatOutput::new(output_size, dictionary_size, history_limit);
            self.run_blocks_flat(input, algorithm_version, output_size, &mut flat, &mut sink)?;
            return if flat.written() == output_size {
                flat.finish(&mut sink)?;
                if self.retain_history {
                    self.history = flat.into_history(history_limit);
                    self.history_start = 0;
                    // Flat mode is gated to an empty window; everything the
                    // next member can reach is materialized in `history`.
                    self.history_zero_prefix = 0;
                }
                Ok(())
            } else {
                Err(Error::NeedMoreInput.into())
            };
        }

        let mut output = StreamingOutput::new(
            self.take_history_vec(),
            std::mem::take(&mut self.history_zero_prefix),
            output_size,
            dictionary_size,
            history_limit,
        );

        #[cfg(feature = "parallel")]
        let mt_done = if self.capped_workers(output_size) >= 2 {
            self.run_blocks_parallel(
                input,
                algorithm_version,
                output_size,
                &mut output,
                &mut sink,
            )?;
            true
        } else {
            false
        };
        #[cfg(not(feature = "parallel"))]
        let mt_done = false;

        let mut payload_buf = Vec::new();
        // `mt_done` is a pre-computed gate, not a loop variable: the parallel
        // path either consumed the whole member (skip the serial loop) or did
        // not run. The loop itself terminates on `break`/`?`, never on this
        // condition, which is what clippy's immutable-condition lint reads as
        // an infinite loop. Suppressed rather than restructured: this is the
        // primary decode path, and reindenting it into `if !mt_done { loop {`
        // is churn with real regression risk for no behaviour change.
        #[allow(clippy::while_immutable_condition)]
        while !mt_done {
            let block_header = read_compressed_block_into(input, &mut payload_buf)?;
            let payload = payload_buf.as_slice();
            let mut payload_bit_pos = 0;
            if block_header.has_tables {
                let (lengths, table_bits) = read_table_lengths(payload, algorithm_version)?;
                self.tables = Some(std::sync::Arc::new(DecodeTables::from_lengths(&lengths)?));
                payload_bit_pos = table_bits;
            }
            let tables = self
                .tables
                .take()
                .ok_or(Error::InvalidData("RAR 5 block reuses missing tables"))?;
            let mut bits = BitReader::new_at(payload, payload_bit_pos);
            decode_block_serial(
                &tables,
                &mut bits,
                block_header.payload_bits,
                &mut self.reps,
                &mut self.previous_match_length,
                &mut output,
                output_size,
                &mut sink,
            )?;

            self.tables = Some(tables);
            if block_header.is_last || output.written() >= output_size {
                break;
            }
        }

        if output.written() == output_size {
            output.finish(&mut sink)?;
            if self.retain_history {
                let (history, zero_prefix) = output.into_history();
                self.history = history;
                self.history_start = 0;
                self.history_zero_prefix = zero_prefix;
            }
            Ok(())
        } else {
            Err(Error::NeedMoreInput.into())
        }
    }

    /// Decode a SOLID CHAIN - several consecutive solid members treated as
    /// the one continuous compressed stream they are - through the MT
    /// scan/tape pipeline, emitting `member_sizes.iter().sum()` bytes to
    /// `sink` in order. The caller cuts the emitted stream at member
    /// boundaries (`member_sizes`, in the same order) and verifies each
    /// member's digests as the bytes stream past; the decoder needs the
    /// same boundaries because a filter's address origin is member-local.
    /// `next_input` yields each member's packed reader in order (the first
    /// call supplies the first member);
    /// `reset_first` mirrors the serial path's state reset when the chain
    /// starts at a non-solid (first-of-archive) member. Parallel-only: the
    /// serial build keeps the per-member path.
    #[cfg(feature = "parallel")]
    // Every argument names a different thing the encoder needs and no two
    // of them travel together, so a parameter struct here would be a bag
    // with one field per argument and a second name for each. The lint's
    // ceiling is 7; these are 8 and 10.
    #[allow(clippy::too_many_arguments)]
    pub fn decode_solid_chain_to_sink<'a, E>(
        &mut self,
        next_input: &mut (dyn FnMut() -> Option<Box<dyn Read + Send + 'a>> + Send),
        algorithm_version: u8,
        member_sizes: &[usize],
        dictionary_size: usize,
        reset_first: bool,
        flat_limit: u64,
        mut sink: impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        if dictionary_size == 0 {
            return Err(Error::InvalidData("RAR 5 dictionary size is zero").into());
        }
        // The group's members, as cumulative ends. The outputs count the
        // whole group, so this is the only thing that tells a filter which
        // member it belongs to - an address filter's origin is member-local
        // (see `member_base_of`). Taking the sizes rather than the total
        // means the two can never disagree.
        let mut member_ends = Vec::with_capacity(member_sizes.len());
        let mut total_output_size = 0usize;
        for size in member_sizes {
            total_output_size = total_output_size
                .checked_add(*size)
                .ok_or(Error::InvalidData(
                    "RAR 5 solid chain output size overflows",
                ))?;
            member_ends.push(total_output_size);
        }
        if reset_first {
            self.reset();
        }
        let history_limit = dictionary_size.min(self.window_limit);
        self.trim_history_to(history_limit);
        let Some(first) = next_input() else {
            return Err(Error::InvalidData("RAR 5 solid chain is empty").into());
        };
        // A group that fits the flat budget decodes through the flat-apply
        // fast path (wild copies, no ring masking, scan on its own thread)
        // - the same pipeline that put big non-solid members ahead of
        // unrar. A group starting mid-archive seeds the flat buffer with
        // the carried window (matches reach into the prefix exactly as the
        // ring's history), so second and later groups keep the fast path
        // too; the seed counts against the flat budget. A carried sparse
        // zero run still streams: `FlatOutput` knows nothing of the run,
        // so taking this path would silently drop it and reject any match
        // reaching into it - the streaming path below honors it.
        if self.history_zero_prefix == 0
            && flat_plan_bytes(self.history_window_len(), total_output_size, history_limit) as u64
                <= flat_limit
        {
            let mut flat = FlatOutput::new_seeded(
                self.history_window(),
                total_output_size,
                dictionary_size,
                history_limit,
            )
            .with_member_ends(member_ends);
            self.run_blocks_flat_chain(
                first,
                next_input,
                algorithm_version,
                total_output_size,
                &mut flat,
                &mut sink,
            )?;
            return if flat.written() == total_output_size {
                flat.finish(&mut sink)?;
                if self.retain_history {
                    self.history = flat.into_history(history_limit);
                    self.history_start = 0;
                    // Seed and output are both materialized in `history`;
                    // nothing ahead of the window is provably zero.
                    self.history_zero_prefix = 0;
                }
                Ok(())
            } else {
                Err(Error::NeedMoreInput.into())
            };
        }
        let mut output = StreamingOutput::new(
            self.take_history_vec(),
            std::mem::take(&mut self.history_zero_prefix),
            total_output_size,
            dictionary_size,
            history_limit,
        )
        .with_member_ends(member_ends);
        self.run_blocks_chain(
            first,
            next_input,
            algorithm_version,
            total_output_size,
            &mut output,
            &mut sink,
        )?;
        if output.written() == total_output_size {
            output.finish(&mut sink)?;
            if self.retain_history {
                let (history, zero_prefix) = output.into_history();
                self.history = history;
                self.history_start = 0;
                self.history_zero_prefix = zero_prefix;
            }
            Ok(())
        } else {
            Err(Error::NeedMoreInput.into())
        }
    }

    /// Is a solid chain of this total size worth the MT pipeline?
    #[cfg(feature = "parallel")]
    pub fn solid_chain_worthwhile(&self, total_output_size: usize) -> bool {
        self.capped_workers(total_output_size) >= 2
    }

    /// Would an inline decode of a member this size engage the MT block
    /// pipeline? Pool planning must not steal such members from inline MT;
    /// anything below this streams serially inline, where the member pool
    /// is strictly better. Deliberately unaffected by the per-decoder
    /// worker cap: pool planning has no decoder in hand, and the pool
    /// applies the policy's cap to its own workers.
    #[cfg(feature = "parallel")]
    pub fn mt_pipeline_engages(output_size: usize) -> bool {
        mt_worker_count(output_size) >= 2
    }

    /// Owned snapshot of the full solid state, letting a caller retry a
    /// whole GROUP of members serially after a failed chain decode (the
    /// chain consumes the window via `take_history_vec`, so the O(1)
    /// `SolidCheckpoint` cannot rewind across it). One window copy per
    /// group - amortized far below the group's decode cost.
    #[cfg(feature = "parallel")]
    pub fn snapshot_solid_state(&self) -> SolidStateSnapshot {
        SolidStateSnapshot {
            window: self.history_window().to_vec(),
            // The window copy drops the dead front; a carried sparse zero
            // run stays provably in front of it only when nothing live was
            // dropped with the front.
            zero_prefix: if self.history_start == 0 {
                self.history_zero_prefix
            } else {
                0
            },
            tables: self.tables.clone(),
            reps: self.reps,
            previous_match_length: self.previous_match_length,
        }
    }

    /// Reinstate a snapshot taken before a failed chain decode.
    #[cfg(feature = "parallel")]
    pub fn restore_solid_state(&mut self, snapshot: SolidStateSnapshot) {
        self.history = snapshot.window;
        self.history_start = 0;
        self.history_zero_prefix = snapshot.zero_prefix;
        // Any O(1) checkpoint taken before this restore is now stale.
        self.history_compactions += 1;
        self.tables = snapshot.tables;
        self.reps = snapshot.reps;
        self.previous_match_length = snapshot.previous_match_length;
    }

    fn reset(&mut self) {
        self.tables = None;
        self.reps = [0; 4];
        self.previous_match_length = 0;
        self.history.clear();
        self.history_start = 0;
        self.history_zero_prefix = 0;
    }

    fn copy_match(
        &self,
        output: &mut Vec<u8>,
        distance: usize,
        length: usize,
        output_limit: usize,
        dictionary_size: usize,
    ) -> Result<()> {
        // The common match - short, a stride or more back, sourced from
        // this member's own output, under the limits - is appended as
        // fixed 16-byte words and trimmed, so it is a handful of inlined
        // stores rather than a `memmove` libcall: on a 1,600-file -m3 set
        // those calls were 24% of the decoder's CPU (members under the
        // parallel threshold decode here, one per member-pool worker;
        // research/RAR-PERF-AUDIT-2026-09-02.md, round 6). Reading each
        // word after the previous one landed keeps the overlapped-match
        // semantics exact for distance >= 16. Every guard below is false
        // for a match this accepts, so the two paths agree.
        let start = output.len();
        if length <= 64
            && distance >= 16
            && distance <= start
            && distance <= dictionary_size
            && start + length <= output_limit
        {
            let mut src = start - distance;
            let end = start + length;
            while output.len() < end {
                let word: [u8; 16] = output[src..src + 16].try_into().expect("16-byte word");
                output.extend_from_slice(&word);
                src += 16;
            }
            output.truncate(end);
            return Ok(());
        }
        if distance > dictionary_size {
            return Err(Error::InvalidData(
                "RAR 5 match distance exceeds dictionary",
            ));
        }
        // The reachable window is the materialized history plus the sparse
        // zero run logically in front of it (`history_zero_prefix`): a
        // streamed all-zero solid member hands over a few bytes of window
        // and a multi-MiB run, so counting only materialized bytes rejected
        // valid archives here with "match distance exceeds window" whenever
        // the NEXT member was small enough to route down this buffered path.
        // The streaming twin (`StreamingOutput::copy_match`) accepts the
        // same logical window.
        let materialized = self.history_window_len() + output.len();
        let logical_window = materialized.saturating_add(self.history_zero_prefix);
        if distance == 0 || distance > logical_window {
            return Err(Error::InvalidData("RAR 5 match distance exceeds window"));
        }
        if output
            .len()
            .checked_add(length)
            .is_none_or(|end| end > output_limit)
        {
            return Err(Error::InvalidData("RAR 5 match exceeds output limit"));
        }
        let mut remaining = length;
        if distance > materialized {
            // The match starts inside the sparse run. Everything logically
            // older than the materialized history is provably zero while the
            // prefix is nonzero (see `history_zero_prefix`), so the run's
            // share of the match is emitted as zeroes; each one closes the
            // gap by a byte, and once it reaches zero the tail is the
            // ordinary history/output copy below - overlapped matches
            // included, since the emitted zeroes are real output bytes.
            let zeroes = remaining.min(distance - materialized);
            output.resize(output.len() + zeroes, 0);
            remaining -= zeroes;
            if remaining == 0 {
                return Ok(());
            }
        }
        // Head of the match that reaches back into carried-over history.
        while remaining != 0 && distance > output.len() {
            let window = self.history_window();
            let history_distance = distance - output.len();
            let index = window.len() - history_distance;
            let run = remaining.min(history_distance).min(window.len() - index);
            output.extend_from_slice(&window[index..index + run]);
            remaining -= run;
        }
        // Rest comes from the output buffer itself; overlapped matches are
        // copied in non-overlapping chunks of at most `distance` bytes.
        while remaining != 0 {
            let start = output.len() - distance;
            let run = remaining.min(distance);
            output.extend_from_within(start..start + run);
            remaining -= run;
        }
        Ok(())
    }
}

/// Streaming LZ window: one contiguous power-of-two ring.
///
/// Absolute (monotonic) counters index the ring through `mask`:
/// `head` counts bytes materialized into the ring, `flushed` counts bytes
/// already handed to the sink. The unflushed span is `flushed..head`; the
/// match window is that span plus up to `history_limit` flushed bytes
/// behind it. Eviction is free — old bytes are simply overwritten — and
/// match copies are chunked `copy_within` calls instead of per-byte deque
/// probes. Sparse zero runs are NOT materialized (only reported to the
/// sink as `Repeated`), mirroring the previous implementation: `head`
/// tracks materialized bytes, `written` tracks logical output, and
/// `zero_prefix` counts the sparse zeroes so matches may still reach them.
/// A declared filter waiting for its range to materialize in the ring.
/// `filter.start` is the output position this ring counts (the member's,
/// or the whole group's when it streams a chain - `filter.file_start`
/// carries the member-local origin the filter itself needs); `ring_start`
/// is the same position in materialized-byte space (the two differ by however
/// many sparse zero bytes were emitted without materialization — while
/// filters are pending, sparse runs are materialized so the mapping made at
/// declaration time stays valid).
struct StreamFilter {
    filter: PendingFilter,
    ring_start: usize,
}

struct StreamingOutput {
    ring: Box<[u8]>,
    mask: usize,
    head: usize,
    flushed: usize,
    written: usize,
    output_limit: usize,
    dictionary_size: usize,
    history_limit: usize,
    all_zero: bool,
    // Logical zeroes emitted as sparse `Repeated` runs and never
    // materialized, plus any such run carried in from an earlier solid
    // member. Sparse runs are only ever taken while `all_zero` holds, so
    // whenever this is nonzero every logical byte older than the ring's
    // materialized content is provably zero - which is what lets
    // `copy_match` accept a distance reaching past `window_len()` into the
    // run instead of rejecting a valid archive with "match distance exceeds
    // window" after a long leading zero run or an all-zero solid member.
    zero_prefix: usize,
    // Once a filter is seen, every ring growth reserves filter hold-back
    // headroom (see `reserve`); most members never declare one.
    has_filters: bool,
    // Largest `window` the current ring already satisfies, so the common
    // call is one comparison. `reserve` runs per emitted literal and per
    // match, and recomputing headroom + min + next_power_of_two() on each
    // of those made it the second-hottest symbol in the decoder (20% of
    // decode-thread samples on a 128 MiB-dictionary member) long after the
    // ring had stopped growing. Invalidated wherever headroom changes.
    reserve_ok_upto: usize,
    pending_filters: std::collections::VecDeque<StreamFilter>,
    /// Group-relative end of each chained member, in order. Empty when the
    /// ring streams a single member; see `member_base_of`.
    member_ends: Vec<usize>,
    filter_scratch: Vec<u8>,
    /// The delta filter's working buffer, kept alongside `filter_scratch`
    /// so a member full of delta blocks allocates once rather than once
    /// per block. Never read outside the filter-apply helpers.
    /// (nzbfast-local change, 20 Aug and 3 Sep 2026 - see
    /// vendor/rars/VENDORING.md.)
    delta_scratch: Vec<u8>,
    next_flush_check: usize,
}

impl StreamingOutput {
    fn new(
        history: Vec<u8>,
        zero_prefix: usize,
        output_limit: usize,
        dictionary_size: usize,
        history_limit: usize,
    ) -> Self {
        // Size the ring for the initial-window cap (or the carried history,
        // whichever is larger) plus flush-granularity headroom -- not the full
        // dictionary, so a large declared dictionary can't force a large
        // up-front allocation from a tiny archive. `reserve` grows the ring
        // toward the full dictionary as decoded output reaches further back.
        // Filter hold-back headroom is likewise added lazily on the first
        // declared filter (most members have none; this keeps steady-state RSS
        // down).
        let mut initial_window = history_limit
            .min(STREAM_INITIAL_WINDOW_CAP)
            .max(history.len());
        // A large-dictionary member whose output covers the window WILL grow
        // the ring to its ceiling: decoded output reaches past the initial
        // cap almost immediately, and the growth then holds both rings
        // resident across a live-window copy - measured as the RSS peak of
        // the whole extraction (128 MiB initial + 256 MiB grown for a
        // 128 MiB dictionary). Start at the ceiling instead: the pages are
        // untouched until the head actually reaches them, so a stream that
        // never looks far back pays nothing, and one that does skips the
        // copy and the double-residency.
        if history_limit > STREAM_INITIAL_WINDOW_CAP && output_limit >= history_limit {
            initial_window = history_limit;
        }
        let capacity = (initial_window + 2 * STREAM_FLUSH_THRESHOLD)
            .next_power_of_two()
            .max(2 * STREAM_FLUSH_THRESHOLD);
        let mut ring = vec![0u8; capacity].into_boxed_slice();
        debug_assert!(history.len() <= history_limit);
        ring[..history.len()].copy_from_slice(&history);
        Self {
            all_zero: history.iter().all(|&byte| byte == 0),
            zero_prefix,
            mask: capacity - 1,
            head: history.len(),
            flushed: history.len(),
            next_flush_check: history.len() + STREAM_FLUSH_THRESHOLD,
            ring,
            written: 0,
            output_limit,
            dictionary_size,
            history_limit,
            has_filters: false,
            reserve_ok_upto: 0,
            pending_filters: std::collections::VecDeque::new(),
            member_ends: Vec::new(),
            filter_scratch: Vec::new(),
            delta_scratch: Vec::new(),
        }
    }

    /// Declare the member boundaries of a chained group (group-relative
    /// cumulative ends). Only filter origins depend on them, and only a
    /// chain has more than one member, so a single-member ring leaves them
    /// empty. Only `decode_solid_chain_to_sink` (parallel-only) calls this.
    #[cfg(feature = "parallel")]
    fn with_member_ends(mut self, member_ends: Vec<usize>) -> Self {
        self.member_ends = member_ends;
        self
    }

    fn queue_filter<E>(
        &mut self,
        filter: PendingFilter,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        if filter.length > STREAM_FILTER_HOLD_LIMIT
            || self.pending_filters.len() >= STREAM_MAX_PENDING_FILTERS
        {
            return Err(StreamDecodeError::FilteredMember);
        }
        // `written` counts the whole GROUP when this ring streams a chain,
        // but the filter translates addresses against its own member's
        // output start; pin that origin now, while the declaration position
        // is known.
        let mut filter = filter;
        filter.file_start = filter.start - member_base_of(&self.member_ends, filter.start);
        // From here on every ring growth reserves filter hold-back headroom;
        // grow now so the pending range fits ahead of head.
        self.has_filters = true;
        self.reserve_ok_upto = 0; // headroom grew; recompute on next reserve
        self.reserve(self.head);
        // filter.start >= written (parse_filter_record adds a non-negative offset),
        // so the materialized-space start is always at or ahead of head.
        let ring_start = filter.start - self.written + self.head;
        if let Some(back) = self.pending_filters.back() {
            let back_end = back.ring_start + back.filter.length;
            let identical_range =
                ring_start == back.ring_start && filter.length == back.filter.length;
            if !identical_range && ring_start < back_end {
                // Partially-overlapping or out-of-order filters: fall back.
                return Err(StreamDecodeError::FilteredMember);
            }
        }
        self.pending_filters
            .push_back(StreamFilter { filter, ring_start });
        Ok(())
    }

    fn written(&self) -> usize {
        self.written
    }

    /// Ensure the ring can hold a match window reaching `window` bytes back
    /// from the current head (clamped to the dictionary), plus flush headroom
    /// and, once any filter has been seen, filter hold-back headroom. Growth is
    /// lazy: the ring starts sized for the initial-window cap and doubles toward
    /// `next_pow2(dict + headroom)` only as decoded output actually reaches
    /// further back, so memory tracks real output rather than the declared
    /// dictionary. The live span is re-placed at its positions under the new
    /// mask. A no-op in the steady state, where the ring is already large
    /// enough.
    /// Hot path: one comparison, always inlined. This runs per emitted
    /// literal and per match, and leaving it out of line still cost ~18%
    /// of decode-thread samples in pure call overhead even once the guard
    /// was short-circuiting every call.
    #[inline(always)]
    fn reserve(&mut self, window: usize) {
        if window > self.reserve_ok_upto {
            self.reserve_grow(window);
        }
    }

    #[cold]
    #[inline(never)]
    fn reserve_grow(&mut self, window: usize) {
        let headroom = 2 * STREAM_FLUSH_THRESHOLD
            + if self.has_filters {
                STREAM_FILTER_HOLD_LIMIT
            } else {
                0
            };
        let needed = window
            .min(self.history_limit)
            .saturating_add(headroom)
            .next_power_of_two();
        if self.ring.len() >= needed {
            self.note_reserve_ok(headroom);
            return;
        }
        // Grow straight to the largest ring this member can ever need
        // rather than doubling into it. The cap is known up front
        // (history_limit, itself bounded by the declared dictionary), and
        // every intermediate size costs a full zeroing allocation plus a
        // copy of the live window - on a 128 MiB dictionary that was
        // ~256 MiB of memset and ~256 MiB of memmove spread over eight
        // doublings, with both rings resident across each one.
        let ceiling = self
            .history_limit
            .saturating_add(headroom)
            .next_power_of_two();
        let needed = needed.max(ceiling.min(Self::growth_ceiling(self.output_limit, headroom)));
        let mut ring = vec![0u8; needed].into_boxed_slice();
        let new_mask = needed - 1;
        let live = self.head.min(self.ring.len());
        let mut pos = self.head - live;
        while pos < self.head {
            let src = pos & self.mask;
            let dst = pos & new_mask;
            let len = (self.head - pos)
                .min(self.ring.len() - src)
                .min(needed - dst);
            ring[dst..dst + len].copy_from_slice(&self.ring[src..src + len]);
            pos += len;
        }
        self.ring = ring;
        self.mask = new_mask;
        self.note_reserve_ok(headroom);
    }

    /// Record the largest `window` the current ring satisfies. Once the
    /// ring covers `history_limit + headroom` no window can ever need
    /// more, so the guard short-circuits for the rest of the member.
    fn note_reserve_ok(&mut self, headroom: usize) {
        let full = self
            .history_limit
            .saturating_add(headroom)
            .next_power_of_two();
        self.reserve_ok_upto = if self.ring.len() >= full {
            usize::MAX
        } else {
            self.ring.len().saturating_sub(headroom)
        };
    }

    /// A member never needs window past its own output, so a small member
    /// declaring a huge dictionary still allocates only what it can use.
    fn growth_ceiling(output_limit: usize, headroom: usize) -> usize {
        // `output_limit` is the member's DECLARED unpacked size, which an
        // untrusted header can set anywhere up to `usize::MAX`.
        // `saturating_add` alone is NOT enough and reading it as enough is
        // the trap here: `next_power_of_two` has no next power to give above
        // `1 << (BITS - 1)`, so it panics with "attempt to add with overflow"
        // in a debug build and returns 0 in release - and 0 is worse than the
        // panic, because it silently removes the anti-thrash ceiling this
        // function exists to impose. `checked_` plus `unwrap_or(usize::MAX)`
        // is the saturating spelling the whole expression needs: the value is
        // only ever a `min` bound on a ring whose real cap is
        // `history_limit`, so `usize::MAX` means "no bound from the declared
        // output", which is the right answer for an absurd claim.
        output_limit
            .saturating_add(headroom)
            .checked_next_power_of_two()
            .unwrap_or(usize::MAX)
    }

    /// Bytes materialized but not yet flushed to the sink.
    #[inline]
    fn pending_len(&self) -> usize {
        self.head - self.flushed
    }

    /// Reachable match window: unflushed bytes plus retained history.
    #[inline]
    fn window_len(&self) -> usize {
        self.pending_len() + self.flushed.min(self.history_limit)
    }

    fn push<E>(
        &mut self,
        byte: u8,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        if self.written >= self.output_limit {
            return Err(Error::InvalidData("RAR 5 match exceeds output limit").into());
        }
        if byte != 0 {
            self.all_zero = false;
        }
        self.reserve(self.head + 1);
        self.ring[self.head & self.mask] = byte;
        self.head += 1;
        self.written += 1;
        self.maybe_flush(sink)
    }

    /// Decode a run of LUT-hit literals in a tight loop, storing straight
    /// into the ring. A LUT-hit control symbol is consumed and returned to the
    /// caller, so its full dispatch does not repeat the same peek and LUT load;
    /// a non-LUT symbol is left untouched for canonical decoding. Stops at the
    /// payload/output boundary or when a flush is due. This is the hot path for
    /// incompressible spans and the entry to every short-code match.
    fn literal_burst<E>(
        &mut self,
        table: &HuffmanTable,
        bits: &mut BitReader<'_>,
        payload_bits: usize,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<Option<usize>, StreamDecodeError<E>> {
        loop {
            let flush_room = self.next_flush_check.saturating_sub(self.head);
            let out_room = self.output_limit.saturating_sub(self.written);
            if flush_room == 0 && out_room != 0 {
                self.maybe_flush(sink)?;
                continue;
            }
            let mut remaining = flush_room.min(out_room);
            if remaining == 0 {
                return Ok(None);
            }
            self.reserve(self.head + remaining);
            let mut zero_acc = true;
            while remaining != 0 {
                if bits.position() >= payload_bits {
                    self.all_zero &= zero_acc;
                    return Ok(None);
                }
                let entry = table.peek_lut_entry(bits);
                if !lut_entry_is_literal(entry) {
                    self.all_zero &= zero_acc;
                    if entry != HUFF_LUT_MISS {
                        bits.consume((entry & HUFF_LUT_LENGTH_MASK) as u8);
                        return Ok(Some(lut_entry_symbol(entry)));
                    }
                    return Ok(None);
                }
                bits.consume((entry & HUFF_LUT_LENGTH_MASK) as u8);
                let byte = (entry >> 8) as u8;
                self.ring[self.head & self.mask] = byte;
                self.head += 1;
                self.written += 1;
                zero_acc &= byte == 0;
                remaining -= 1;
            }
            self.all_zero &= zero_acc;
        }
    }

    /// Bulk literal append: same ring/flush-watermark behavior as pushing
    /// each byte, in slice-sized copies. Used by the parallel tape apply.
    #[cfg(feature = "parallel")]
    fn push_bytes<E>(
        &mut self,
        mut bytes: &[u8],
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        if self
            .written
            .checked_add(bytes.len())
            .is_none_or(|end| end > self.output_limit)
        {
            return Err(Error::InvalidData("RAR 5 match exceeds output limit").into());
        }
        // Grow the ring before advancing `head`, exactly as literal_burst and
        // push_repeated do. Without this a literal run longer than the current
        // ring (which is only sized to history_limit.min(64 MiB) up front) wraps
        // head past ring.len() and overwrites bytes still inside the live match
        // window - silent corruption, or a spurious CRC/BLAKE2 failure, on a
        // >64 MB-dictionary member decoded via the parallel tape-apply path.
        self.reserve(self.head + bytes.len());
        if self.all_zero && bytes.iter().any(|&byte| byte != 0) {
            self.all_zero = false;
        }
        while !bytes.is_empty() {
            let flush_room = self.next_flush_check.saturating_sub(self.head);
            if flush_room == 0 {
                self.maybe_flush(sink)?;
                continue;
            }
            let offset = self.head & self.mask;
            let take = bytes.len().min(flush_room).min(self.ring.len() - offset);
            self.ring[offset..offset + take].copy_from_slice(&bytes[..take]);
            self.head += take;
            self.written += take;
            bytes = &bytes[take..];
        }
        Ok(())
    }

    /// Attempt a flush once per flush-threshold of newly materialized bytes.
    /// (A pending filter can keep the unflushed span above the threshold, so
    /// the trigger is a watermark, not the span length.)
    #[inline]
    fn maybe_flush<E>(
        &mut self,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        if self.head >= self.next_flush_check {
            self.flush(sink)?;
            self.next_flush_check = self.head + STREAM_FLUSH_THRESHOLD;
        }
        Ok(())
    }

    fn push_repeated<E>(
        &mut self,
        byte: u8,
        mut count: usize,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        if self
            .written
            .checked_add(count)
            .is_none_or(|end| end > self.output_limit)
        {
            return Err(Error::InvalidData("RAR 5 match exceeds output limit").into());
        }
        if byte != 0 {
            self.all_zero = false;
        }
        self.reserve(self.head + count);
        while count > 0 {
            let offset = self.head & self.mask;
            let take = count
                .min(STREAM_FLUSH_THRESHOLD - (self.pending_len() % STREAM_FLUSH_THRESHOLD))
                .min(self.ring.len() - offset);
            self.ring[offset..offset + take].fill(byte);
            self.head += take;
            self.written += take;
            count -= take;
            self.maybe_flush(sink)?;
        }
        Ok(())
    }

    fn push_zeroes<E>(
        &mut self,
        count: usize,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        if self
            .written
            .checked_add(count)
            .is_none_or(|end| end > self.output_limit)
        {
            return Err(Error::InvalidData("RAR 5 match exceeds output limit").into());
        }
        // While filters are pending, sparse runs must be materialized: the
        // sink sees bytes strictly in order, and the written<->materialized
        // position mapping recorded at filter declaration must stay fixed.
        if !self.pending_filters.is_empty() {
            return self.push_repeated(0, count, sink);
        }
        self.flush(sink)?;
        sink(DecodedChunk::Repeated {
            byte: 0,
            len: count,
        })
        .map_err(StreamDecodeError::Sink)?;
        self.written += count;
        // Keep one materialized zero so distance-1 matches against a purely
        // sparse window still resolve (previous implementation seeded the
        // history deque with a single zero byte).
        if self.head == 0 && self.history_limit != 0 {
            self.ring[0] = 0;
            self.head = 1;
            self.flushed = 1;
            // The seed materializes one of the run's zeroes; the rest of the
            // run stays logical-only and is accounted for below.
            self.zero_prefix += count.saturating_sub(1);
        } else {
            self.zero_prefix += count;
        }
        Ok(())
    }

    fn copy_match<E>(
        &mut self,
        distance: usize,
        length: usize,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        if distance > self.dictionary_size {
            return Err(Error::InvalidData("RAR 5 match distance exceeds dictionary").into());
        }
        // `history_limit` is below `dictionary_size` only when the caller capped
        // the window: the match is legal for the archive but needs more memory
        // than allowed, so surface that distinctly rather than as corruption.
        if distance > self.history_limit {
            return Err(Error::WindowLimitExceeded {
                limit: self.history_limit as u64,
                required: distance as u64,
            }
            .into());
        }
        // The reachable window is the materialized ring PLUS the sparse zero
        // run logically in front of it: those bytes were emitted as
        // `Repeated` zeroes and never stored, so `window_len()` alone
        // under-counts what a valid archive may reference (a member opening
        // with a multi-MiB zero run, or one following an all-zero solid
        // member, was rejected here with "match distance exceeds window").
        let logical_window = self.window_len().saturating_add(self.zero_prefix);
        if self.all_zero && distance <= logical_window {
            return self.push_zeroes(length, sink);
        }
        if distance == 0 || distance > logical_window {
            return Err(Error::InvalidData("RAR 5 match distance exceeds window").into());
        }
        if self
            .written
            .checked_add(length)
            .is_none_or(|end| end > self.output_limit)
        {
            return Err(Error::InvalidData("RAR 5 match exceeds output limit").into());
        }
        let mut length = length;
        let window = self.window_len();
        if distance > window {
            // The match starts inside the sparse zero run. Everything
            // logically older than the ring's content is zero while
            // `zero_prefix` is nonzero (see the field), so the head of the
            // match emits zeroes - MATERIALIZED, via push_repeated, so ring
            // positions stay aligned with logical positions for the tail
            // copy and for every later reference. Once the run's share is
            // emitted the window has grown to exactly `distance`, and the
            // tail (window bytes, then period-`distance` repetition for
            // overlapped matches) is the ordinary ring copy below.
            let zeroes = length.min(distance - window);
            self.push_repeated(0, zeroes, sink)?;
            length -= zeroes;
            if length == 0 {
                return Ok(());
            }
        }
        if distance == 1 {
            let byte = self.ring[(self.head - 1) & self.mask];
            return self.push_repeated(byte, length, sink);
        }

        self.reserve(self.head + length);
        // Short non-overlapping matches are the overwhelmingly common case,
        // and a `memmove` call per 2-32 byte copy is mostly call overhead.
        // Copy a fixed 32 bytes through a register temporary instead: the
        // over-copy past `length` lands in [head+length, head+32), which is
        // unmaterialized space the next emit overwrites. Requires both the
        // source and destination 32-byte spans to sit inside the ring
        // without wrapping, and `distance >= length` so the true bytes read
        // are match-window content (the over-read past the source span may
        // see anything materialized, which is fine - only garbage bytes
        // land in the don't-care tail).
        if length <= 32 && distance >= length {
            let src_off = (self.head - distance) & self.mask;
            let dst_off = self.head & self.mask;
            if src_off + 32 <= self.ring.len() && dst_off + 32 <= self.ring.len() {
                let tmp: [u8; 32] = self.ring[src_off..src_off + 32]
                    .try_into()
                    .expect("32-byte span");
                self.ring[dst_off..dst_off + 32].copy_from_slice(&tmp);
                self.head += length;
                self.written += length;
                return self.maybe_flush(sink);
            }
        }
        // Short-period overlapped repeats (length exceeding a small distance)
        // take a period-doubling loop: each full-period run makes [head-2p,
        // head) periodic, so the run cap grows geometrically and
        // length/distance tiny copies become log2 of that. Everything else -
        // the overwhelmingly common case - keeps the original tight loop,
        // whose per-call cost this specialization must not touch.
        const PERIOD_DOUBLE_CEILING: usize = 4096;
        if length > distance && distance <= PERIOD_DOUBLE_CEILING {
            // The cap keeps `period + run <= ring capacity`, so within one
            // run every source slot stays distinct from every destination
            // slot; growth also stops at a small ceiling - larger periods
            // already move whole cache lines and only get colder-source
            // reads from growing further.
            let period_cap = self.ring.len() - STREAM_FLUSH_THRESHOLD;
            let mut remaining = length;
            let mut period = distance;
            while remaining > 0 {
                let run = remaining.min(period).min(STREAM_FLUSH_THRESHOLD);
                let mut src = self.head - period;
                let mut dst = self.head;
                let mut left = run;
                while left > 0 {
                    let src_off = src & self.mask;
                    let dst_off = dst & self.mask;
                    let segment = left
                        .min(self.ring.len() - src_off)
                        .min(self.ring.len() - dst_off);
                    self.ring.copy_within(src_off..src_off + segment, dst_off);
                    src += segment;
                    dst += segment;
                    left -= segment;
                }
                self.head += run;
                self.written += run;
                remaining -= run;
                // Only a full-period run makes the doubled span periodic;
                // partial runs (remaining or flush cap) keep the period,
                // which must stay a multiple of `distance`.
                if run == period && period * 2 <= period_cap.min(2 * PERIOD_DOUBLE_CEILING) {
                    period *= 2;
                }
                self.maybe_flush(sink)?;
            }
            return Ok(());
        }
        let mut remaining = length;
        while remaining > 0 {
            // Cap runs at the match distance (overlapped matches repeat with
            // that period) and at flush granularity.
            let run = remaining.min(distance).min(STREAM_FLUSH_THRESHOLD);
            let mut src = self.head - distance;
            let mut dst = self.head;
            let mut left = run;
            while left > 0 {
                let src_off = src & self.mask;
                let dst_off = dst & self.mask;
                let segment = left
                    .min(self.ring.len() - src_off)
                    .min(self.ring.len() - dst_off);
                self.ring.copy_within(src_off..src_off + segment, dst_off);
                src += segment;
                dst += segment;
                left -= segment;
            }
            self.head += run;
            self.written += run;
            remaining -= run;
            self.maybe_flush(sink)?;
        }
        Ok(())
    }

    fn flush<E>(
        &mut self,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        loop {
            // Bytes below the first pending filter's range are final.
            let plain_limit = self
                .pending_filters
                .front()
                .map(|held| held.ring_start)
                .unwrap_or(usize::MAX)
                .min(self.head);
            while self.flushed < plain_limit {
                let offset = self.flushed & self.mask;
                let len = (plain_limit - self.flushed).min(self.ring.len() - offset);
                sink(DecodedChunk::Bytes(&self.ring[offset..offset + len]))
                    .map_err(StreamDecodeError::Sink)?;
                self.flushed += len;
            }
            let Some(front) = self.pending_filters.front() else {
                return Ok(());
            };
            let end = front
                .ring_start
                .checked_add(front.filter.length)
                .ok_or(Error::InvalidData("RAR 5 filter range overflows"))?;
            if self.head < end {
                // Range not fully decoded yet; held back until it is.
                return Ok(());
            }

            // Linearize the filter's range, apply the filter (and any
            // identical-range chain behind it) to the copy, and emit it.
            // The ring keeps the unfiltered bytes: LZ matches reference the
            // pre-filter window.
            self.filter_scratch.clear();
            let mut pos = front.ring_start;
            while pos < end {
                let offset = pos & self.mask;
                let len = (end - pos).min(self.ring.len() - offset);
                self.filter_scratch
                    .extend_from_slice(&self.ring[offset..offset + len]);
                pos += len;
            }
            loop {
                let held = self
                    .pending_filters
                    .pop_front()
                    .expect("pending filter chain underflow");
                // `filter.start` is a group position in a chain; the filter
                // wants the offset inside its own member, pinned at
                // declaration by `queue_filter`.
                apply_filter_to_vec(
                    &mut self.filter_scratch,
                    &held.filter,
                    held.filter.file_start,
                    &mut self.delta_scratch,
                )?;
                match self.pending_filters.front() {
                    Some(next)
                        if next.ring_start == held.ring_start
                            && next.filter.length == held.filter.length =>
                    {
                        continue;
                    }
                    _ => break,
                }
            }
            if !self.filter_scratch.is_empty() {
                sink(DecodedChunk::Bytes(&self.filter_scratch)).map_err(StreamDecodeError::Sink)?;
            }
            self.flushed = end;
        }
    }

    fn finish<E>(
        &mut self,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        self.flush(sink)?;
        if !self.pending_filters.is_empty() {
            return Err(Error::InvalidData("RAR 5 filter range exceeds output").into());
        }
        Ok(())
    }

    /// The retained window, plus the count of sparse zeroes logically in
    /// front of it for the next solid member to keep honoring (an all-zero
    /// streamed member materializes almost nothing, so the window alone
    /// would shrink the next member's reachable history to a few bytes).
    fn into_history(self) -> (Vec<u8>, usize) {
        let keep = self.flushed.min(self.history_limit).min(self.head);
        // The carried count is only meaningful while every logical byte
        // older than the returned bytes is provably zero. Truncation drops
        // materialized bytes ahead of the run, so it keeps that true only
        // when the whole stream was zero (`all_zero`, where the dropped
        // bytes join the run); otherwise the run must be dropped rather
        // than guessed at - 0 is always safe, it merely narrows the next
        // member's accepted distances back to the ring itself.
        let zero_prefix = if self.all_zero {
            self.zero_prefix + (self.head - keep)
        } else if keep == self.head {
            self.zero_prefix
        } else {
            0
        };
        let mut history = Vec::with_capacity(keep);
        let mut pos = self.head - keep;
        while pos < self.head {
            let offset = pos & self.mask;
            let len = (self.head - pos).min(self.ring.len() - offset);
            history.extend_from_slice(&self.ring[offset..offset + len]);
            pos += len;
        }
        (history, zero_prefix)
    }
}

/// Like `read_compressed_block` but reuses `payload` across calls —
/// the decode loops read one block per iteration and a fresh zeroed Vec
/// per block costs a redundant memset of every compressed byte.
/// Decode one compressed block's symbols into the streaming output. Stops at
/// the block's payload boundary or when the member's output size is reached.
/// Shared by the serial member loop and the parallel path's in-place resume.
#[allow(clippy::too_many_arguments)]
fn decode_block_serial<E>(
    tables: &DecodeTables,
    bits: &mut BitReader<'_>,
    payload_bits: usize,
    reps: &mut [usize; 4],
    previous_match_length: &mut usize,
    output: &mut StreamingOutput,
    output_size: usize,
    sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
) -> std::result::Result<(), StreamDecodeError<E>> {
    while bits.position() < payload_bits && output.written() < output_size {
        let burst_control = output.literal_burst(&tables.main, bits, payload_bits, sink)?;
        if output.written() >= output_size
            || (burst_control.is_none() && bits.position() >= payload_bits)
        {
            break;
        }
        let symbol = match burst_control {
            Some(symbol) => symbol,
            None => tables.main.decode(bits)?,
        };
        match symbol {
            0..=255 => output.push(symbol as u8, sink)?,
            256 => {
                let filter = parse_filter_record(bits, output.written())?;
                output.queue_filter(filter)?;
            }
            257 => {
                if *previous_match_length != 0 {
                    output.copy_match(reps[0], *previous_match_length, sink)?;
                }
            }
            258..=261 => {
                let rep_index = symbol - 258;
                let distance = reps[rep_index];
                if distance == 0 {
                    return Err(
                        Error::InvalidData("RAR 5 repeat distance is not initialized").into(),
                    );
                }
                let length_slot = tables.length.decode(bits)?;
                let length_extra = bits.read_bits(length_slot_extra_bits(length_slot)?)?;
                let length = match_length_for_slot(length_slot, length_extra)?;
                reps[..=rep_index].rotate_right(1);
                reps[0] = distance;
                *previous_match_length = length;
                output.copy_match(distance, length, sink)?;
            }
            262.. => {
                let length_slot = symbol - 262;
                let length_extra = bits.read_bits(length_slot_extra_bits(length_slot)?)?;
                let mut length = match_length_for_slot(length_slot, length_extra)?;
                #[cfg(feature = "parallel")]
                let (distance_slot, distance_bit_count) =
                    tables.distance.decode_distance_hot(bits)?;
                #[cfg(not(feature = "parallel"))]
                let distance_slot = tables.distance.decode(bits)?;
                #[cfg(not(feature = "parallel"))]
                let distance_bit_count = distance_slot_bit_count(distance_slot)?;
                // The `as u8` casts below are a NO-OP under `parallel`, where
                // `decode_distance_hot` already answers in `u8`, and LOAD-BEARING
                // without it, where `distance_slot_bit_count` answers in `usize`.
                // `unnecessary_cast` only ever sees one of the two configurations, and
                // taking its advice broke the other (9 Sep 2026: the workspace lint runs
                // with `parallel` on, and the fuzz crate - which builds `rars` with
                // default features - stopped compiling).
                #[allow(clippy::unnecessary_cast)]
                let distance_extra = if distance_bit_count >= 4 && tables.align_mode {
                    let high = bits.read_bits((distance_bit_count - 4) as u8)?;
                    let low = tables.align.decode(bits)? as u32;
                    (high << 4) | low
                } else {
                    bits.read_bits(distance_bit_count as u8)?
                };
                #[cfg(feature = "parallel")]
                let distance =
                    slot_distance_value(distance_slot, distance_bit_count, distance_extra);
                #[cfg(not(feature = "parallel"))]
                let distance = slot_to_distance(distance_slot, distance_extra)?;
                length += length_bonus(distance);
                reps.rotate_right(1);
                reps[0] = distance;
                *previous_match_length = length;
                output.copy_match(distance, length, sink)?;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Parallel block decode.
//
// A RAR 5 compressed stream is a chain of blocks whose boundaries (and table
// sections) are parseable without decoding any symbols, and whose symbol
// streams depend only on the active Huffman tables - never on the LZ window
// or the repeat-distance state. Those facts split member decode into:
//
//   scan (serial, cheap)  - read block payloads, thread table sets through
//   decode (parallel)     - Huffman-decode each block into an op tape,
//                           leaving rep distances and last-length symbolic
//   apply (serial)        - resolve rep state, run the window, feed the sink
//
// The apply stage reproduces the serial decoder's observable behavior
// exactly: same output bytes, same early stop at the member size, same
// errors at the same output positions. Work the serial decoder would never
// have reached (bits past the output limit, blocks read ahead) has its
// errors deferred and swallowed unless the member genuinely needs them.
// ---------------------------------------------------------------------------

/// Hard ceiling on tape workers; the execution policy's `max_workers`
/// (2 on a constrained host, 8 otherwise) caps BELOW this, never above it,
/// so this must not sit under what the policy would grant. It was 4 from
/// the first MT commit, and "4 -> 8 measured zero" held only while the
/// ring chain scanned inline on the apply thread: with the scan on its own
/// thread the apply thread waited on tapes 17% of the time at 4 workers,
/// and 8 took a 1 GiB -m3 member from 1.44 s to 1.32 s on a 20-core M1
/// Ultra (12 was no better; +15 MB peak RSS). Worst-case tape memory is
/// bounded per worker by `TAPE_OPS_CAP` / `TAPE_LITS_CAP`
/// (research/RAR-PERF-AUDIT-2026-09-02.md).
#[cfg(feature = "parallel")]
const MT_MAX_WORKERS: usize = 8;
/// Members below this size decode serially: thread spinup and tape overhead
/// only pay for themselves on bulk decodes.
#[cfg(all(feature = "parallel", not(test)))]
const MT_MIN_OUTPUT: usize = 16 << 20;
/// Tests force the parallel path onto every streaming decode so the whole
/// suite differentially exercises it (mirrors the BUFFERED_DECODE_LIMIT
/// override in rar50/extract.rs).
#[cfg(all(feature = "parallel", test))]
const MT_MIN_OUTPUT: usize = 0;
/// Per-tape bounds: a worker that exceeds either parks the block at its
/// current bit position and the apply stage finishes it with the serial
/// decoder. Keeps adversarial streams (1-bit codes, giant blocks) from
/// ballooning tape memory; realistic blocks never get near these. Tests
/// shrink them so the park-and-resume boundary is crossed constantly.
#[cfg(all(feature = "parallel", not(test)))]
const TAPE_OPS_CAP: usize = 1 << 21;
#[cfg(all(feature = "parallel", test))]
const TAPE_OPS_CAP: usize = 1 << 10;
#[cfg(all(feature = "parallel", not(test)))]
const TAPE_LITS_CAP: usize = 4 << 20;
#[cfg(all(feature = "parallel", test))]
const TAPE_LITS_CAP: usize = 16 << 10;
/// A hostile block can grow a tape bundle far beyond useful steady-state
/// sizes. The channel retains at most one 4 MiB bundle per worker (32 MiB at
/// the eight-worker ceiling), while normal smaller blocks remain reusable.
#[cfg(feature = "parallel")]
const TAPE_RECYCLE_BYTES_MAX: usize = 4 << 20;

#[cfg(feature = "parallel")]
// `MT_MIN_OUTPUT` is cfg-dependent and deliberately 0 under `test`, so the
// suite forces every streaming decode down the parallel path. In that build
// the comparison is trivially false - which is correct, not a mistake - and
// clippy's absurd-comparison lint would otherwise deny the whole crate.
#[allow(clippy::absurd_extreme_comparisons)]
fn mt_worker_count(output_size: usize) -> usize {
    if output_size < MT_MIN_OUTPUT {
        return 0;
    }
    std::thread::available_parallelism()
        .map(|cores| cores.get().saturating_sub(1))
        .unwrap_or(0)
        .min(MT_MAX_WORKERS)
}

/// Tape op kinds. `TapeOp` is a plain struct rather than a Rust enum, so
/// the kind is a field; see the type's comment for why.
#[cfg(feature = "parallel")]
mod tape_kind {
    /// Emit the next `length` bytes from the tape's literal buffer.
    pub(super) const LITS: u32 = 0;
    /// Fully resolved match (symbol 262..).
    pub(super) const MATCH: u32 = 1;
    /// Repeat-distance match (symbols 258..=261); `distance` carries the rep
    /// INDEX (0..=3), resolved against the live rep state at apply.
    pub(super) const REP: u32 = 2;
    /// Symbol 257: reuse the last distance and length (no-op when none yet).
    pub(super) const REP_LAST: u32 = 3;
    /// Symbol 256: filter declaration; the payload is the next entry of
    /// `BlockTape::filters` and its start offset resolves at apply.
    pub(super) const FILTER: u32 = 4;
}

/// One op on a worker's tape: 8 bytes, both fields naturally aligned.
///
/// This was a Rust enum until 3 Sep 2026, and the enum shape was the single
/// most expensive thing in the tape worker. Its widest variant was
/// `Filter(RawFilter)`, the worker built each op inside a
/// `Result<Option<TapeOp>>`, and the compiler assembled and then re-read
/// that aggregate with OVERLAPPING unaligned stack moves - a 4-byte store
/// at `0x20(%rsp)` followed by a 4-byte load at `0x21(%rsp)`, which no
/// store buffer can forward. A `perf` profile of the -m3 leg on an EPYC put
/// **38% of the whole worker** on the two instructions that consumed those
/// reloads (research/RAR-PERF-AUDIT-2026-09-02.md, round 13). Keeping the
/// filter payload out of band (`BlockTape::filters`, one entry per FILTER
/// op, in order) is what lets every op be this flat, and takes the op from
/// 16 bytes to 8 as well (round 6 had taken it 24 -> 16).
///
/// `kind_length` packs the kind into the top `TAPE_KIND_SHIFT` bits and the
/// length below it. Both are bounded by the format, not by hope: a length
/// slot is under `LENGTH_TABLE_SIZE` (44) in every RAR 5 and RAR 7 table, so
/// `match_length_for_slot` yields at most 4,097 plus a bonus of 3, and a literal
/// run is capped at `TAPE_LITS_CAP`. `min` is belt and braces so a
/// malformed stream can never carry a length into the kind bits.
///
/// `distance`: a distance the window can hold is under the 1 GiB stream
/// window limit; a stream distance past `u32::MAX` (a RAR 7
/// giant-dictionary archive, which the window limit refuses anyway)
/// saturates and errors as "exceeds dictionary". For a `REP` op it carries
/// the rep INDEX instead.
#[cfg(feature = "parallel")]
#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct TapeOp {
    kind_length: u32,
    distance: u32,
}

/// Bit position of the kind inside `TapeOp::kind_length`.
#[cfg(feature = "parallel")]
const TAPE_KIND_SHIFT: u32 = 29;
#[cfg(feature = "parallel")]
const TAPE_LENGTH_MASK: u32 = (1 << TAPE_KIND_SHIFT) - 1;

#[cfg(feature = "parallel")]
impl TapeOp {
    #[inline]
    fn new(kind: u32, length: u32, distance: u32) -> Self {
        debug_assert!(length <= TAPE_LENGTH_MASK);
        Self {
            kind_length: (kind << TAPE_KIND_SHIFT) | length.min(TAPE_LENGTH_MASK),
            distance,
        }
    }

    #[inline]
    fn kind(self) -> u32 {
        self.kind_length >> TAPE_KIND_SHIFT
    }

    #[inline]
    fn length(self) -> usize {
        (self.kind_length & TAPE_LENGTH_MASK) as usize
    }

    #[inline]
    fn lits(count: u32) -> Self {
        Self::new(tape_kind::LITS, count, 0)
    }

    #[inline]
    fn match_at(distance: u32, length: u32) -> Self {
        Self::new(tape_kind::MATCH, length, distance)
    }

    #[inline]
    fn rep(index: u32, length: u32) -> Self {
        Self::new(tape_kind::REP, length, index)
    }

    #[inline]
    fn rep_last() -> Self {
        Self::new(tape_kind::REP_LAST, 0, 0)
    }

    #[inline]
    fn filter() -> Self {
        Self::new(tape_kind::FILTER, 0, 0)
    }
}

/// Huffman table set whose LUT construction is deferred to the first worker
/// that needs it. The scanner was building all four LUTs serially per table
/// block (~half its critical-path time on solid chains, starving the
/// workers); now it only parses `TableLengths` and the first worker to
/// receive a block of the set pays the build, concurrently with other
/// workers building other sets. Blocks that reuse a set share the same
/// `Arc`, so every set still builds exactly once, and a build failure is
/// cloned to every dependent block (raised only when the ordered apply
/// semantically reaches it - see `decode_block_tape`).
#[cfg(feature = "parallel")]
struct LazyDecodeTables {
    /// `None` only for a set seeded from already-built tables
    /// (`Self::prebuilt`), whose `built` cell is pre-populated.
    lengths: Option<TableLengths>,
    built: std::sync::OnceLock<Result<std::sync::Arc<DecodeTables>>>,
}

#[cfg(feature = "parallel")]
impl LazyDecodeTables {
    fn new(lengths: TableLengths) -> Self {
        Self {
            lengths: Some(lengths),
            built: std::sync::OnceLock::new(),
        }
    }

    /// Wrap tables that already exist (the decoder's carried state seeding a
    /// chain, or a test fixture) so the pipeline sees one type.
    fn prebuilt(tables: std::sync::Arc<DecodeTables>) -> Self {
        let built = std::sync::OnceLock::new();
        built
            .set(Ok(tables))
            .expect("fresh OnceLock accepts a value");
        Self {
            lengths: None,
            built,
        }
    }

    fn get(&self) -> Result<&std::sync::Arc<DecodeTables>> {
        match self.built.get_or_init(|| {
            let lengths = self
                .lengths
                .as_ref()
                .expect("unbuilt lazy tables always carry lengths");
            DecodeTables::from_lengths(lengths).map(std::sync::Arc::new)
        }) {
            Ok(tables) => Ok(tables),
            Err(error) => Err(error.clone()),
        }
    }
}

#[cfg(feature = "parallel")]
#[derive(Default)]
/// Allocation bundle returned from ordered apply to the scanner. Keeping the
/// packed ops and out-of-band filter payloads with the other tape vectors lets
/// one block reuse the complete allocation set without allocator traffic in
/// the worker queues. (nzbfast-local change, 3 Sep 2026; see VENDORING.md.)
struct TapeBuffers {
    payload: Vec<u8>,
    lits: Vec<u8>,
    ops: Vec<TapeOp>,
    filters: Vec<RawFilter>,
}

#[cfg(feature = "parallel")]
impl TapeBuffers {
    fn retained_bytes(&self) -> usize {
        self.payload
            .capacity()
            .saturating_add(self.lits.capacity())
            .saturating_add(
                self.ops
                    .capacity()
                    .saturating_mul(std::mem::size_of::<TapeOp>()),
            )
            .saturating_add(
                self.filters
                    .capacity()
                    .saturating_mul(std::mem::size_of::<RawFilter>()),
            )
    }

    fn recycle(self, tx: &std::sync::mpsc::SyncSender<Self>) {
        if self.retained_bytes() <= TAPE_RECYCLE_BYTES_MAX {
            let _ = tx.try_send(self);
        }
    }
}

#[cfg(feature = "parallel")]
struct TapeJob {
    seq: usize,
    tables: std::sync::Arc<LazyDecodeTables>,
    buffers: TapeBuffers,
    start_bit: usize,
    payload_bits: usize,
}

#[cfg(feature = "parallel")]
struct BlockTape {
    seq: usize,
    tables: std::sync::Arc<LazyDecodeTables>,
    payload: Vec<u8>,
    payload_bits: usize,
    lits: Vec<u8>,
    ops: Vec<TapeOp>,
    /// Filter payloads, one per `tape_kind::FILTER` op, in tape order (the
    /// op itself is flat - see `TapeOp`).
    filters: Vec<RawFilter>,
    /// Bit position where the worker parked (tape caps hit); the apply stage
    /// resumes this block with the serial decoder from here.
    resume_bit: Option<usize>,
    /// Decode error hit after the recorded ops. Raised by the apply stage
    /// only if the member still needs output when the tape runs out - the
    /// serial decoder would have stopped consuming at the output limit and
    /// never seen bits beyond it.
    tail_error: Option<Error>,
}

#[cfg(feature = "parallel")]
impl BlockTape {
    fn take_buffers(&mut self) -> TapeBuffers {
        TapeBuffers {
            payload: std::mem::take(&mut self.payload),
            lits: std::mem::take(&mut self.lits),
            ops: std::mem::take(&mut self.ops),
            filters: std::mem::take(&mut self.filters),
        }
    }
}

/// Huffman-decode one block's symbol stream into an op tape (worker side;
/// no window, no rep state, no sink).
#[cfg(feature = "parallel")]
fn decode_block_tape(job: TapeJob) -> BlockTape {
    let TapeJob {
        seq,
        tables: lazy_tables,
        buffers,
        start_bit,
        payload_bits,
    } = job;
    let TapeBuffers {
        payload,
        mut lits,
        mut ops,
        mut filters,
    } = buffers;
    lits.clear();
    ops.clear();
    filters.clear();

    // First use of a table set builds it here, off the scanner's critical
    // path. A build failure yields an empty tape carrying the error: the
    // ordered apply raises it only if the member still needs output when it
    // reaches this block - the serial decoder would have built (and failed)
    // these tables at exactly that point in the stream, and never at all if
    // the output completed first.
    let tables = match lazy_tables.get() {
        Ok(tables) => tables,
        Err(error) => {
            return BlockTape {
                seq,
                tables: lazy_tables,
                payload,
                payload_bits,
                lits,
                ops,
                filters,
                resume_bit: None,
                tail_error: Some(error),
            }
        }
    };
    let tables = &**tables;
    let mut bits = BitReader::new_at(&payload, start_bit);
    let mut lit_run: u32 = 0;
    let mut resume_bit = None;
    let mut tail_error = None;

    macro_rules! flush_lits {
        () => {
            if lit_run != 0 {
                ops.push(TapeOp::lits(lit_run));
                lit_run = 0;
            }
        };
    }

    'blocks: while bits.position() < payload_bits {
        if ops.len() >= TAPE_OPS_CAP || lits.len() >= TAPE_LITS_CAP {
            flush_lits!();
            resume_bit = Some(bits.position());
            break;
        }
        // Literal burst on the LUT fast path (the mirror of
        // StreamingOutput::literal_burst, decoding into the tape buffer).
        // Consume and retain a LUT-hit control so the packed-op decoder below
        // does not repeat its peek and LUT lookup; a long-code miss stays
        // untouched for canonical decoding.
        let burst_limit = lits.len() + (64 << 10);
        let mut burst_control = None;
        while lits.len() < burst_limit {
            if bits.position() >= payload_bits {
                flush_lits!();
                break 'blocks;
            }
            let entry = tables.main.peek_lut_entry(&mut bits);
            if !lut_entry_is_literal(entry) {
                if entry != HUFF_LUT_MISS {
                    bits.consume((entry & HUFF_LUT_LENGTH_MASK) as u8);
                    burst_control = Some(lut_entry_symbol(entry));
                }
                break;
            }
            bits.consume((entry & HUFF_LUT_LENGTH_MASK) as u8);
            lits.push((entry >> 8) as u8);
            lit_run += 1;
        }
        if lits.len() >= burst_limit {
            continue;
        }
        let symbol = match burst_control {
            Some(symbol) => symbol,
            None => match tables.main.decode(&mut bits) {
                Ok(symbol) => symbol,
                Err(error) => {
                    flush_lits!();
                    tail_error = Some(error);
                    break;
                }
            },
        };
        if symbol < 256 {
            // Literal that missed the LUT (long code): decoded via the
            // canonical fallback inside decode().
            lits.push(symbol as u8);
            lit_run += 1;
            continue;
        }
        // The op is decoded into a flat local and pushed here rather than
        // returned out of a `Result<Option<TapeOp>>` closure: that aggregate
        // is what the compiler was assembling and re-reading with
        // overlapping unaligned stack moves (see `TapeOp`).
        let op = match decode_tape_op(symbol, tables, &mut bits, &mut filters) {
            Ok(op) => op,
            Err(error) => {
                flush_lits!();
                tail_error = Some(error);
                break;
            }
        };
        flush_lits!();
        ops.push(op);
    }
    if lit_run != 0 {
        ops.push(TapeOp::lits(lit_run));
    }

    BlockTape {
        seq,
        tables: lazy_tables,
        payload,
        payload_bits,
        lits,
        ops,
        filters,
        resume_bit,
        tail_error,
    }
}

/// Decode one non-literal symbol's operands into a tape op (worker side).
///
/// `symbol` is 256 or above; literals never reach here. A filter's payload
/// is appended to `filters` and the op itself carries only the kind, which
/// keeps `TapeOp` flat - see its comment.
#[cfg(feature = "parallel")]
#[inline]
fn decode_tape_op(
    symbol: usize,
    tables: &DecodeTables,
    bits: &mut BitReader<'_>,
    filters: &mut Vec<RawFilter>,
) -> Result<TapeOp> {
    match symbol {
        256 => {
            filters.push(parse_filter_record_fields(bits)?);
            Ok(TapeOp::filter())
        }
        257 => Ok(TapeOp::rep_last()),
        258..=261 => {
            let length_slot = tables.length.decode(bits)?;
            let length = read_slot_length(length_slot, bits)?;
            Ok(TapeOp::rep((symbol - 258) as u32, length))
        }
        _ => {
            let length_slot = symbol - 262;
            let length = read_slot_length(length_slot, bits)?;
            let (distance_slot, distance_bit_count) = tables.distance.decode_distance_hot(bits)?;
            let distance_extra = if distance_bit_count >= 4 && tables.align_mode {
                let high = bits.read_bits(distance_bit_count - 4)?;
                let low = tables.align.decode(bits)? as u32;
                (high << 4) | low
            } else {
                bits.read_bits(distance_bit_count)?
            };
            let distance = slot_distance_value(distance_slot, distance_bit_count, distance_extra);
            Ok(TapeOp::match_at(
                u32::try_from(distance).unwrap_or(u32::MAX),
                length + length_bonus(distance) as u32,
            ))
        }
    }
}

/// Extra-bit count for every length slot, and the corresponding low
/// `4 | (slot & 3)` base. The slot is a symbol of a `LENGTH_TABLE_SIZE`
/// table (or `symbol - 262` off a `MAIN_TABLE_SIZE` one, which is the same
/// range), so the whole ladder is 44 entries wide in RAR 5 and RAR 7 alike.
#[cfg(feature = "parallel")]
static LENGTH_SLOT_EXTRA_BITS: [u8; LENGTH_TABLE_SIZE] = build_length_slot_extra_bits();

#[cfg(feature = "parallel")]
const fn build_length_slot_extra_bits() -> [u8; LENGTH_TABLE_SIZE] {
    let mut table = [0u8; LENGTH_TABLE_SIZE];
    let mut slot = 8;
    while slot < LENGTH_TABLE_SIZE {
        table[slot] = ((slot >> 2) - 1) as u8;
        slot += 1;
    }
    table
}

/// Read one length slot's extra bits and form the length, in one pass.
///
/// `length_slot_extra_bits` + `match_length_for_slot` recomputed `(slot >> 2) - 1`
/// and its range check twice per match and re-checked an `extra_bits` value
/// that `read_bits` had just produced with exactly that width, so it could
/// not be out of range (round 13). The table lookup is the range check.
#[cfg(feature = "parallel")]
#[inline]
fn read_slot_length(slot: usize, bits: &mut BitReader<'_>) -> Result<u32> {
    // These symbols encode the entire length: no table load or bit read is
    // needed. Keep that common tape-worker case ahead of the operand path.
    if slot < 8 {
        return Ok(slot as u32 + 2);
    }
    let Some(&extra_bits) = LENGTH_SLOT_EXTRA_BITS.get(slot) else {
        return Err(Error::InvalidData("RAR 5 length slot is too large"));
    };
    let extra = bits.read_bits(extra_bits)?;
    Ok((((4 | (slot as u32 & 3)) << extra_bits) | extra) + 2)
}

/// Extra-bit count for every distance slot, `u8::MAX` where the slot is out
/// of the format's range (RAR 7 tables reach slot 79, whose count exceeds
/// the 31 a distance may use).
#[cfg(feature = "parallel")]
static DISTANCE_SLOT_BITS: [u8; DISTANCE_TABLE_SIZE_70] = build_distance_slot_bits();

#[cfg(feature = "parallel")]
const fn build_distance_slot_bits() -> [u8; DISTANCE_TABLE_SIZE_70] {
    let mut table = [0u8; DISTANCE_TABLE_SIZE_70];
    let mut slot = 4;
    while slot < DISTANCE_TABLE_SIZE_70 {
        let bits = (slot - 2) >> 1;
        table[slot] = if bits > 31 { u8::MAX } else { bits as u8 };
        slot += 1;
    }
    table
}

/// `distance_slot_bit_count` as a table lookup; see `read_slot_length`.
#[cfg(feature = "parallel")]
#[inline]
fn slot_distance_bits(slot: usize) -> Result<u8> {
    match DISTANCE_SLOT_BITS.get(slot) {
        Some(&bits) if bits != u8::MAX => Ok(bits),
        _ => Err(Error::InvalidData("RAR 5 distance slot is too large")),
    }
}

/// `slot_to_distance` with the slot's bit count already in hand and the
/// range check already made by `slot_distance_bits` or `decode_distance_hot`.
/// `extra` came out of a `read_bits` of exactly `bit_count` bits, or a high-bit
/// read plus the four-bit alignment alphabet, so it cannot exceed the slot -
/// the check the public function repeats is unreachable from here.
#[cfg(feature = "parallel")]
#[inline]
fn slot_distance_value(slot: usize, bit_count: u8, extra: u32) -> usize {
    if slot < 4 {
        return slot + 1;
    }
    distance_from_parts(slot, bit_count, extra)
}

#[cfg(feature = "parallel")]
enum TapeApplied {
    BlockDone,
    OutputDone,
}

#[cfg(feature = "parallel")]
impl Rar50Decoder {
    /// Replay a decoded tape against the window in archive order, resolving
    /// the rep-distance state the workers left symbolic. Reproduces the
    /// serial decoder's stops and errors exactly (see module comment).
    fn apply_tape<E>(
        &mut self,
        tape: &mut BlockTape,
        output: &mut StreamingOutput,
        output_size: usize,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<TapeApplied, StreamDecodeError<E>> {
        let mut lit_pos = 0usize;
        let mut filter_pos = 0usize;
        for op in &tape.ops {
            if output.written() >= output_size {
                return Ok(TapeApplied::OutputDone);
            }
            let kind = op.kind();
            // nzbfast-local change (2026-09-03): MATCH accounts for about
            // 86% of real RAR 5 tape ops. Keep its predicted dispatch out of
            // the less-common-kind switch while preserving the serial
            // decoder's state-update and error order below.
            if kind == tape_kind::MATCH {
                let (distance, length) = (op.distance as usize, op.length());
                self.reps.rotate_right(1);
                self.reps[0] = distance;
                self.previous_match_length = length;
                output.copy_match(distance, length, sink)?;
                continue;
            }
            match kind {
                tape_kind::LITS => {
                    let count = op.length();
                    // The worker may have decoded past the member's end (it
                    // cannot see the running total); the serial decoder stops
                    // exactly at the limit, so clamp rather than error.
                    let take = count.min(output_size - output.written());
                    output.push_bytes(&tape.lits[lit_pos..lit_pos + take], sink)?;
                    lit_pos += count;
                    if take < count {
                        return Ok(TapeApplied::OutputDone);
                    }
                }
                tape_kind::REP_LAST => {
                    if self.previous_match_length != 0 {
                        output.copy_match(self.reps[0], self.previous_match_length, sink)?;
                    }
                }
                tape_kind::REP => {
                    let length = op.length();
                    let index = op.distance as usize;
                    let distance = self.reps[index];
                    if distance == 0 {
                        return Err(
                            Error::InvalidData("RAR 5 repeat distance is not initialized").into(),
                        );
                    }
                    self.reps[..=index].rotate_right(1);
                    self.reps[0] = distance;
                    self.previous_match_length = length;
                    output.copy_match(distance, length, sink)?;
                }
                _ => {
                    // tape_kind::FILTER; the worker emits no other kind.
                    let raw = tape.filters[filter_pos];
                    filter_pos += 1;
                    output.queue_filter(raw.resolve(output.written())?)?;
                }
            }
        }
        if output.written() >= output_size {
            return Ok(TapeApplied::OutputDone);
        }
        if let Some(resume_bit) = tape.resume_bit {
            // Worker parked at a tape cap: finish this block serially in
            // place - the rep state is live here, so this is exact. A parked
            // tape implies its worker built the tables, so this is a cache
            // read, never a build.
            let tables = tape.tables.get()?;
            let mut bits = BitReader::new_at(&tape.payload, resume_bit);
            decode_block_serial(
                tables,
                &mut bits,
                tape.payload_bits,
                &mut self.reps,
                &mut self.previous_match_length,
                output,
                output_size,
                sink,
            )?;
            if output.written() >= output_size {
                return Ok(TapeApplied::OutputDone);
            }
            return Ok(TapeApplied::BlockDone);
        }
        if let Some(error) = tape.tail_error.take() {
            return Err(error.into());
        }
        Ok(TapeApplied::BlockDone)
    }

    /// Scan blocks off the reader, fan symbol decode out to worker threads,
    /// and apply the resulting tapes in order on this thread.
    fn run_blocks_parallel<E>(
        &mut self,
        input: &mut (impl Read + Send),
        algorithm_version: u8,
        output_size: usize,
        output: &mut StreamingOutput,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        let mut next_input = || None;
        self.run_blocks_chain(
            Box::new(input),
            &mut next_input,
            algorithm_version,
            output_size,
            output,
            sink,
        )
    }

    /// The MT scan/tape pipeline over a CHAIN of block streams: a solid
    /// group is one continuous compressed stream split at member
    /// boundaries, so when a member's `is_last` block is scanned the next
    /// member's packed reader continues the same pipeline (tables, reps,
    /// and the window all carry across exactly as the serial path does).
    /// `next_input` yields the next member's reader, `None` ending the
    /// chain; single-member callers pass a closure returning `None`.
    fn run_blocks_chain<'a, E>(
        &mut self,
        input: Box<dyn Read + Send + 'a>,
        next_input: &mut (dyn FnMut() -> Option<Box<dyn Read + Send + 'a>> + Send),
        algorithm_version: u8,
        output_size: usize,
        output: &mut StreamingOutput,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        use std::collections::BTreeMap;
        use std::sync::mpsc;
        use std::sync::Arc;

        let workers = self.capped_workers(output_size).max(2);

        let (result_tx, result_rx) = mpsc::sync_channel::<BlockTape>(workers * 2);
        // Recycling is opportunistic and bounded. Neither scanner progress
        // nor early output/error shutdown depends on a buffer being returned.
        let (recycle_tx, recycle_rx) = mpsc::sync_channel::<TapeBuffers>(workers);
        let mut job_txs: Vec<mpsc::SyncSender<TapeJob>> = Vec::with_capacity(workers);
        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let (job_tx, job_rx) = mpsc::sync_channel::<TapeJob>(1);
            let result_tx = result_tx.clone();
            handles.push(std::thread::spawn(move || {
                while let Ok(job) = job_rx.recv() {
                    if result_tx.send(decode_block_tape(job)).is_err() {
                        return;
                    }
                }
            }));
            job_txs.push(job_tx);
        }
        drop(result_tx);

        let scan_tables = self
            .tables
            .clone()
            .map(|tables| Arc::new(LazyDecodeTables::prebuilt(tables)));
        let mut applied_tables: Option<Arc<LazyDecodeTables>> = None;

        let worker_exited =
            || StreamDecodeError::Decode(Error::InvalidData("RAR 5 parallel decode worker exited"));

        // The scan (block reads off the packed stream, table-length parses,
        // job dispatch) runs on its own thread, exactly as the flat chain's
        // does. Until 2 Sep 2026 the ring chain scanned INLINE on the apply
        // thread, between tapes: on a 1 GiB -m3 member on an M1 Ultra the
        // apply thread was 92% busy and the scan was 11% of it, while the
        // workers idled at ~19% each - the apply thread is the wall, and
        // every read syscall and table parse on it was wall. Moving the
        // scan off it took the leg from 1.51 s to 1.33 s, the whole of the
        // gap to the flat path, with none of the flat path's whole-member
        // buffer (research/RAR-PERF-AUDIT-2026-09-02.md).
        let (scan_outcome, apply_result, applied, output_done) = std::thread::scope(|scope| {
            let scan = scope.spawn(move || {
                let mut input = input;
                let mut tables = scan_tables;
                let mut dispatched = 0usize;
                let mut scan_done = false;
                let mut scan_error: Option<Error> = None;
                let mut rr = 0usize;
                'scan: while !scan_done {
                    let mut buffers = recycle_rx.try_recv().unwrap_or_default();
                    let header = match read_compressed_block_into(&mut input, &mut buffers.payload)
                    {
                        Ok(header) => header,
                        Err(error) => {
                            scan_error = Some(error);
                            break;
                        }
                    };
                    let mut start_bit = 0;
                    if header.has_tables {
                        // Parse the lengths here (they position the symbol
                        // start); the LUT build itself is lazy - the first
                        // worker that needs the set pays it.
                        match read_table_lengths(&buffers.payload, algorithm_version) {
                            Ok((lengths, table_bits)) => {
                                tables = Some(Arc::new(LazyDecodeTables::new(lengths)));
                                start_bit = table_bits;
                            }
                            Err(error) => {
                                scan_error = Some(error);
                                break;
                            }
                        }
                    }
                    let Some(job_tables) = tables.clone() else {
                        scan_error = Some(Error::InvalidData("RAR 5 block reuses missing tables"));
                        break;
                    };
                    if header.is_last {
                        // End of this member's block stream: a chain
                        // continues with the next member's reader, a single
                        // member is done scanning.
                        match next_input() {
                            Some(next) => input = next,
                            None => scan_done = true,
                        }
                    }
                    let mut job = Some(TapeJob {
                        seq: dispatched,
                        tables: job_tables,
                        buffers,
                        start_bit,
                        payload_bits: header.payload_bits,
                    });
                    dispatched += 1;
                    // Hand the job to any worker with queue space; when every
                    // queue is full, a blocking send on the next-in-line
                    // worker is the backpressure stall. A disconnected queue
                    // means the apply side stopped early (output done or
                    // error) - stop quietly; the apply side owns the error.
                    for probe in 0..job_txs.len() {
                        let target = (rr + probe) % job_txs.len();
                        match job_txs[target].try_send(job.take().unwrap()) {
                            Ok(()) => {
                                rr = (target + 1) % job_txs.len();
                                break;
                            }
                            Err(mpsc::TrySendError::Full(back)) => job = Some(back),
                            Err(mpsc::TrySendError::Disconnected(_)) => break 'scan,
                        }
                    }
                    if let Some(job) = job.take() {
                        match job_txs[rr].send(job) {
                            Ok(()) => rr = (rr + 1) % job_txs.len(),
                            Err(_) => break 'scan,
                        }
                    }
                }
                // Dropping the queues lets workers drain and exit; the result
                // channel closes once the last tape is delivered.
                drop(job_txs);
                (dispatched, scan_done, scan_error)
            });

            // Apply, on this thread: pull tapes as they complete, reorder,
            // apply in archive order.
            let mut reorder: BTreeMap<usize, BlockTape> = BTreeMap::new();
            let mut applied = 0usize;
            let mut output_done = false;
            let apply_result: std::result::Result<(), StreamDecodeError<E>> = 'apply: loop {
                let Ok(tape) = result_rx.recv() else {
                    // Channel closed: every dispatched tape has been delivered.
                    break Ok(());
                };
                reorder.insert(tape.seq, tape);
                while !output_done {
                    let Some(mut tape) = reorder.remove(&applied) else {
                        break;
                    };
                    applied += 1;
                    applied_tables = Some(tape.tables.clone());
                    let result = self.apply_tape(&mut tape, output, output_size, sink);
                    tape.take_buffers().recycle(&recycle_tx);
                    match result {
                        Ok(TapeApplied::BlockDone) => {}
                        Ok(TapeApplied::OutputDone) => output_done = true,
                        Err(error) => break 'apply Err(error),
                    }
                }
                if output_done {
                    break Ok(());
                }
            };
            // On an early stop (output done or apply error), dropping the
            // receiver unblocks workers stuck sending; their job queues then
            // disconnect and the scan thread stops quietly.
            drop(result_rx);
            let scan_outcome = scan.join().expect("RAR 5 ring scan thread panicked");
            (scan_outcome, apply_result, applied, output_done)
        });

        for handle in handles {
            let _ = handle.join();
        }

        // Leave the decoder's table state as the serial path would: the
        // tables of the last block actually applied (scan may have read
        // further ahead than the member needed). An applied tape's tables are
        // normally already built; an all-literal empty tape may build here.
        // If the last applied tape carried a failed build the decode errored,
        // so there is no state worth carrying.
        if let Some(lazy) = applied_tables {
            if let Ok(tables) = lazy.get() {
                self.tables = Some(std::sync::Arc::clone(tables));
            }
        }

        apply_result?;
        if output_done {
            // Reached the member size: read-ahead scan errors are work the
            // serial decoder would never have done - swallow them.
            return Ok(());
        }
        let (dispatched, scan_done, scan_error) = scan_outcome;
        if let Some(error) = scan_error {
            // The stream ran dry mid-member: the serial decoder would have
            // hit this same error at this same output position.
            return Err(error.into());
        }
        let _ = scan_done;
        if applied < dispatched {
            // Every dispatched job yields exactly one tape unless its worker
            // died; the channel closed early.
            return Err(worker_exited());
        }
        // is_last applied without filling the output; the caller turns the
        // shortfall into NeedMoreInput.
        Ok(())
    }

    /// Whether this member takes the flat-apply path: non-solid, worth the MT
    /// pipeline, and small enough to hold whole in a member-sized buffer.
    /// Solid members, members over `flat_limit`, and non-parallel builds (this
    /// method only exists under the feature) keep the streaming-ring path.
    fn use_flat_mode(
        &self,
        plan_bytes: usize,
        output_size: usize,
        solid: bool,
        flat_limit: u64,
    ) -> bool {
        if solid {
            return false;
        }
        #[cfg(test)]
        if self.test_force_flat {
            return true;
        }
        self.capped_workers(output_size) >= 2 && plan_bytes as u64 <= flat_limit
    }

    /// Flat-buffer analogue of `apply_tape`: identical op semantics, deferred
    /// errors, and literal clamp, but the target is one contiguous
    /// member-sized buffer. A parked tape (tape caps hit) is finished by
    /// re-decoding the remainder into a fresh continuation tape from the
    /// resume bit and applying that — tape decode is a pure function of
    /// (tables, payload, start_bit), so this stays free of the ring-coupled
    /// `decode_block_serial` (see 2.6). Rep state carries across the re-decode
    /// through `self`; caps bound each continuation so memory holds one tape.
    fn apply_tape_flat<E>(
        &mut self,
        tape: &mut BlockTape,
        output: &mut FlatOutput,
        output_size: usize,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<TapeApplied, StreamDecodeError<E>> {
        loop {
            let mut lit_pos = 0usize;
            let mut filter_pos = 0usize;
            // nzbfast-local change, 3 Sep 2026 - the rep shift register and
            // the last length run in LOCALS for the op walk, written back on
            // every exit; see VENDORING.md. Held in `self` they were two
            // loads and three stores of the decoder struct per MATCH, and
            // the store-to-load forwarding made them a loop-carried memory
            // dependency on the pipeline's wall thread. Every exit below
            // stores them back, so the decoder's carried state after a
            // block - which the differential suite compares against the
            // buffered decoder, error paths included - is unchanged.
            let mut reps = self.reps;
            let mut previous_match_length = self.previous_match_length;
            // nzbfast-local change, 3 Sep 2026 - and so does the write
            // cursor, with the output buffer MOVED OUT of `output` for the
            // walk; see VENDORING.md. Behind `&mut FlatOutput` every op
            // reloaded the buffer pointer, the buffer length, the position,
            // the two folded bounds and the emit watermark, and stored the
            // position back, because the walk contains calls that take the
            // same `&mut`. `output.buf` is EMPTY while the walk runs; every
            // fallback below puts it back (`sync_out`) before calling
            // anything that reads it and takes it again (`sync_in`)
            // afterwards, on the error path too, so the post-walk
            // `sync_out` always has the buffer to give back.
            let mut buf = std::mem::take(&mut output.buf);
            let mut pos = output.pos;
            let mut fast_end = output.fast_end;
            let mut limit_pos = output.limit_pos;
            let mut next_emit_check = output.next_emit_check;
            // Set once at construction; no slide or emit touches it.
            let fast_distance_max = output.fast_distance_max;
            macro_rules! sync_out {
                () => {{
                    output.buf = std::mem::take(&mut buf);
                    output.pos = pos;
                    output.next_emit_check = next_emit_check;
                }};
            }
            macro_rules! sync_in {
                () => {{
                    buf = std::mem::take(&mut output.buf);
                    pos = output.pos;
                    fast_end = output.fast_end;
                    limit_pos = output.limit_pos;
                    next_emit_check = output.next_emit_check;
                }};
            }
            // The shared short-match stride copy, on the locals: `false`
            // means the op goes to `copy_match_slow`, which owns every
            // error and its order.
            macro_rules! fast_copy {
                ($distance:expr, $length:expr) => {{
                    let length = $length;
                    if flat_stride_copy(
                        &mut buf,
                        pos,
                        $distance,
                        length,
                        fast_end,
                        fast_distance_max,
                    ) {
                        pos += length;
                        true
                    } else {
                        false
                    }
                }};
            }
            // `maybe_emit` on the locals: the emit itself needs the whole
            // `FlatOutput` (pending filters, the sink), so it syncs.
            macro_rules! maybe_emit {
                () => {{
                    if pos >= next_emit_check {
                        sync_out!();
                        let emitted = output.emit_ready(sink);
                        output.next_emit_check = output.pos + FLAT_EMIT_THRESHOLD;
                        sync_in!();
                        emitted
                    } else {
                        Ok(())
                    }
                }};
            }
            // nzbfast-local change, 3 Sep 2026 - a literal run with sixteen
            // bytes of tape BEHIND it is copied as one fixed 16-byte word
            // whatever its true length, which is what makes the dominant
            // one-to-three-byte run branchless; see VENDORING.md. Only the
            // last run of a block falls short of that and takes the ladder.
            let lits_len = tape.lits.len();
            let mut outcome: std::result::Result<Option<TapeApplied>, StreamDecodeError<E>> =
                Ok(None);
            for op in &tape.ops {
                if pos >= limit_pos {
                    outcome = Ok(Some(TapeApplied::OutputDone));
                    break;
                }
                let kind = op.kind();
                // Keep the common fully-resolved match on one predicted
                // branch; see the streaming-ring counterpart above.
                if kind == tape_kind::MATCH {
                    let (distance, length) = (op.distance as usize, op.length());
                    // `rotate_right(1)` then overwriting slot 0, spelled out:
                    // the rotated-in slot 3 value is discarded by the store
                    // that follows it.
                    reps[3] = reps[2];
                    reps[2] = reps[1];
                    reps[1] = reps[0];
                    reps[0] = distance;
                    previous_match_length = length;
                    let step = if fast_copy!(distance, length) {
                        maybe_emit!()
                    } else {
                        sync_out!();
                        let slow = output.copy_match_slow(distance, length, sink);
                        sync_in!();
                        slow
                    };
                    if let Err(error) = step {
                        outcome = Err(error);
                        break;
                    }
                    continue;
                }
                match kind {
                    tape_kind::LITS => {
                        let count = op.length();
                        // Worker may overshoot the member end; clamp like the
                        // serial decoder rather than error (trap 1).
                        // `limit_pos - pos` IS `output_size - written()`:
                        // both are `output_end - origin - pos`.
                        let take = count.min(limit_pos - pos);
                        // `fast_end` folds the buffer end and the output
                        // limit with the ladder's slack, so a run under it
                        // can neither slide nor exceed the limit - which is
                        // every check `push_bytes` would run.
                        let step = if take <= 16 && pos + 16 <= fast_end && lit_pos + 16 <= lits_len
                        {
                            // The over-copy past `pos + take` is the stride
                            // copier's argument: `fast_end` guarantees the
                            // slack (`pos + 16 <= fast_end` and `fast_end +
                            // 16 <= buf.len()`), the scribbled bytes sit at
                            // or beyond the new `pos`, every later write
                            // lands exactly at `pos` and overwrites them
                            // before `pos` moves past, matches only read
                            // below `pos`, and the emit gate never releases
                            // bytes at or above `pos`. Nothing over-READS:
                            // the third term is what guarantees the word is
                            // inside the tape's own literal vector.
                            let word: [u8; 16] = tape.lits[lit_pos..lit_pos + 16]
                                .try_into()
                                .expect("16-byte literal word");
                            buf[pos..pos + 16].copy_from_slice(&word);
                            pos += take;
                            maybe_emit!()
                        } else if take <= LITERAL_INLINE_MAX && pos + take <= fast_end {
                            flat_literal_ladder(&mut buf, pos, &tape.lits[lit_pos..lit_pos + take]);
                            pos += take;
                            maybe_emit!()
                        } else {
                            sync_out!();
                            let pushed =
                                output.push_bytes(&tape.lits[lit_pos..lit_pos + take], sink);
                            sync_in!();
                            pushed
                        };
                        if let Err(error) = step {
                            outcome = Err(error);
                            break;
                        }
                        lit_pos += count;
                        if take < count {
                            outcome = Ok(Some(TapeApplied::OutputDone));
                            break;
                        }
                    }
                    tape_kind::REP_LAST => {
                        if previous_match_length != 0 {
                            let step = if fast_copy!(reps[0], previous_match_length) {
                                maybe_emit!()
                            } else {
                                sync_out!();
                                let slow = output.copy_match_slow(reps[0], previous_match_length, sink);
                                sync_in!();
                                slow
                            };
                            if let Err(error) = step {
                                outcome = Err(error);
                                break;
                            }
                        }
                    }
                    tape_kind::REP => {
                        let length = op.length();
                        let index = op.distance as usize;
                        // Slot-indexed rather than slice-indexed: a `&mut
                        // reps[..=index]` takes the array's ADDRESS, which
                        // pins the whole shift register in memory for the
                        // MATCH path above (measured: four stores and three
                        // reloads per match survived the hoist). Only
                        // symbols 258..=261 reach here, so the index is
                        // 0..=3 by construction.
                        debug_assert!(index < 4, "rep index comes from symbol 258..=261");
                        let distance = match index {
                            0 => reps[0],
                            1 => reps[1],
                            2 => reps[2],
                            _ => reps[3],
                        };
                        if distance == 0 {
                            outcome = Err(Error::InvalidData(
                                "RAR 5 repeat distance is not initialized",
                            )
                            .into());
                            break;
                        }
                        // `reps[..=index].rotate_right(1)` then slot 0 = the
                        // hoisted distance, spelled out per index: the value
                        // rotated into slot 0 is the one being overwritten.
                        match index {
                            0 => {}
                            1 => reps[1] = reps[0],
                            2 => {
                                reps[2] = reps[1];
                                reps[1] = reps[0];
                            }
                            _ => {
                                reps[3] = reps[2];
                                reps[2] = reps[1];
                                reps[1] = reps[0];
                            }
                        }
                        reps[0] = distance;
                        previous_match_length = length;
                        let step = if fast_copy!(distance, length) {
                            maybe_emit!()
                        } else {
                            sync_out!();
                            let slow = output.copy_match_slow(distance, length, sink);
                            sync_in!();
                            slow
                        };
                        if let Err(error) = step {
                            outcome = Err(error);
                            break;
                        }
                    }
                    _ => {
                        // tape_kind::FILTER; filter starts resolve at apply
                        // time (trap 4).
                        let raw = tape.filters[filter_pos];
                        filter_pos += 1;
                        sync_out!();
                        let declared = raw
                            .resolve(output.written())
                            .map_err(StreamDecodeError::from)
                            .and_then(|pending| output.queue_filter(pending));
                        sync_in!();
                        if let Err(error) = declared {
                            outcome = Err(error);
                            break;
                        }
                    }
                }
            }
            sync_out!();
            self.reps = reps;
            self.previous_match_length = previous_match_length;
            if let Some(done) = outcome? {
                return Ok(done);
            }
            if output.output_complete(output_size) {
                return Ok(TapeApplied::OutputDone);
            }
            if let Some(resume_bit) = tape.resume_bit {
                let seq = tape.seq;
                let tables = tape.tables.clone();
                let payload_bits = tape.payload_bits;
                let job = TapeJob {
                    seq,
                    tables,
                    buffers: tape.take_buffers(),
                    start_bit: resume_bit,
                    payload_bits,
                };
                *tape = decode_block_tape(job);
                continue;
            }
            if let Some(error) = tape.tail_error.take() {
                return Err(error.into());
            }
            return Ok(TapeApplied::BlockDone);
        }
    }

    /// Flat-apply counterpart of `run_blocks_parallel`. Worker fan-out and the
    /// reorder scheme are the same skeleton (trap 8 — reuse, don't reinvent),
    /// with two flat-only differences: the apply target is `FlatOutput` (via
    /// `apply_tape_flat`), and the scan (block reads + table-LUT builds) runs
    /// on its own thread instead of interleaving with apply — profiling showed
    /// the apply thread is the pipeline's floor, and the scan was ~13% of it.
    /// Backpressure comes from the bounded channels: per-worker job queues of
    /// 1 plus a bounded result channel cap the tapes in flight, so the scan
    /// thread stalls when the pipeline is full.
    fn run_blocks_flat<E>(
        &mut self,
        input: &mut (impl Read + Send),
        algorithm_version: u8,
        output_size: usize,
        output: &mut FlatOutput,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        let mut next_input = || None;
        self.run_blocks_flat_chain(
            Box::new(input),
            &mut next_input,
            algorithm_version,
            output_size,
            output,
            sink,
        )
    }

    /// Chain-aware flat pipeline: like `run_blocks_chain`, the scan swaps
    /// to the next member's reader on `is_last` so a whole solid group
    /// decodes through the flat-apply fast path (wild copies, no ring
    /// masking) as the single stream it is. `next_input` is Send because
    /// the flat scan runs on its own thread.
    fn run_blocks_flat_chain<'a, E>(
        &mut self,
        input: Box<dyn Read + Send + 'a>,
        next_input: &mut (dyn FnMut() -> Option<Box<dyn Read + Send + 'a>> + Send),
        algorithm_version: u8,
        output_size: usize,
        output: &mut FlatOutput,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        use std::collections::BTreeMap;
        use std::sync::mpsc;
        use std::sync::Arc;

        let workers = self.capped_workers(output_size).max(2);

        let (result_tx, result_rx) = mpsc::sync_channel::<BlockTape>(workers * 2);
        // Recycling is opportunistic and bounded. Neither scanner progress
        // nor early output/error shutdown depends on a buffer being returned.
        let (recycle_tx, recycle_rx) = mpsc::sync_channel::<TapeBuffers>(workers);
        let mut job_txs: Vec<mpsc::SyncSender<TapeJob>> = Vec::with_capacity(workers);
        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let (job_tx, job_rx) = mpsc::sync_channel::<TapeJob>(1);
            let result_tx = result_tx.clone();
            handles.push(std::thread::spawn(move || {
                while let Ok(job) = job_rx.recv() {
                    if result_tx.send(decode_block_tape(job)).is_err() {
                        return;
                    }
                }
            }));
            job_txs.push(job_tx);
        }
        drop(result_tx);

        let scan_tables = self
            .tables
            .clone()
            .map(|tables| Arc::new(LazyDecodeTables::prebuilt(tables)));
        let mut applied_tables: Option<Arc<LazyDecodeTables>> = None;

        let worker_exited =
            || StreamDecodeError::Decode(Error::InvalidData("RAR 5 parallel decode worker exited"));

        let (scan_outcome, apply_result, applied, output_done) = std::thread::scope(|scope| {
            // Scan thread: read blocks, thread table sets through, dispatch
            // jobs round-robin. try_send keeps workers evenly fed; when every
            // queue is full, a blocking send on the next-in-line worker is the
            // backpressure stall. A disconnected queue means the apply side
            // stopped early (output done or error) — stop quietly; the apply
            // side owns the error story.
            let scan = scope.spawn(move || {
                let mut input = input;
                let mut tables = scan_tables;
                let mut dispatched = 0usize;
                let mut scan_done = false;
                let mut scan_error: Option<Error> = None;
                let mut rr = 0usize;
                'scan: while !scan_done {
                    let mut buffers = recycle_rx.try_recv().unwrap_or_default();
                    let header = match read_compressed_block_into(&mut input, &mut buffers.payload)
                    {
                        Ok(header) => header,
                        Err(error) => {
                            scan_error = Some(error);
                            break;
                        }
                    };
                    let mut start_bit = 0;
                    if header.has_tables {
                        // Parse only; the LUT build is lazy on the workers.
                        match read_table_lengths(&buffers.payload, algorithm_version) {
                            Ok((lengths, table_bits)) => {
                                tables = Some(Arc::new(LazyDecodeTables::new(lengths)));
                                start_bit = table_bits;
                            }
                            Err(error) => {
                                scan_error = Some(error);
                                break;
                            }
                        }
                    }
                    let Some(job_tables) = tables.clone() else {
                        scan_error = Some(Error::InvalidData("RAR 5 block reuses missing tables"));
                        break;
                    };
                    if header.is_last {
                        // Chain: the next member's reader continues the
                        // same stream; a lone member is done scanning.
                        match next_input() {
                            Some(next) => input = next,
                            None => scan_done = true,
                        }
                    }
                    let mut job = Some(TapeJob {
                        seq: dispatched,
                        tables: job_tables,
                        buffers,
                        start_bit,
                        payload_bits: header.payload_bits,
                    });
                    dispatched += 1;
                    for probe in 0..job_txs.len() {
                        let target = (rr + probe) % job_txs.len();
                        match job_txs[target].try_send(job.take().unwrap()) {
                            Ok(()) => {
                                rr = (target + 1) % job_txs.len();
                                break;
                            }
                            Err(mpsc::TrySendError::Full(back)) => job = Some(back),
                            Err(mpsc::TrySendError::Disconnected(_)) => break 'scan,
                        }
                    }
                    if let Some(job) = job.take() {
                        // Every queue is full; block on the round-robin target.
                        match job_txs[rr].send(job) {
                            Ok(()) => rr = (rr + 1) % job_txs.len(),
                            Err(_) => break 'scan,
                        }
                    }
                }
                // Dropping the queues lets workers drain and exit; the result
                // channel closes once the last tape is delivered.
                drop(job_txs);
                (dispatched, scan_done, scan_error)
            });

            // Apply, on this thread: pull tapes as they complete, reorder,
            // apply in archive order.
            let mut reorder: BTreeMap<usize, BlockTape> = BTreeMap::new();
            let mut applied = 0usize;
            let mut output_done = false;
            let apply_result: std::result::Result<(), StreamDecodeError<E>> = 'apply: loop {
                let Ok(tape) = result_rx.recv() else {
                    // Channel closed: every dispatched tape has been delivered.
                    break Ok(());
                };
                reorder.insert(tape.seq, tape);
                while !output_done {
                    let Some(mut tape) = reorder.remove(&applied) else {
                        break;
                    };
                    applied += 1;
                    applied_tables = Some(tape.tables.clone());
                    let result = self.apply_tape_flat(&mut tape, output, output_size, sink);
                    tape.take_buffers().recycle(&recycle_tx);
                    match result {
                        Ok(TapeApplied::BlockDone) => {}
                        Ok(TapeApplied::OutputDone) => output_done = true,
                        Err(error) => break 'apply Err(error),
                    }
                }
                if output_done {
                    break Ok(());
                }
            };
            // On an early stop (output done or apply error), dropping the
            // receiver unblocks workers stuck sending; their job queues then
            // disconnect and the scan thread stops quietly.
            drop(result_rx);
            let scan_outcome = scan.join().expect("RAR 5 flat scan thread panicked");
            (scan_outcome, apply_result, applied, output_done)
        });

        for handle in handles {
            let _ = handle.join();
        }

        // Leave the decoder's table state as the serial path would: the
        // tables of the last block actually applied (trap 3). See the ring
        // pipeline for why a failed build is not carried.
        if let Some(lazy) = applied_tables {
            if let Ok(tables) = lazy.get() {
                self.tables = Some(std::sync::Arc::clone(tables));
            }
        }

        apply_result?;
        if output_done {
            // Reached the member size: read-ahead scan errors are work the
            // serial decoder would never have done — swallow them (trap 2).
            return Ok(());
        }
        let (dispatched, scan_done, scan_error) = scan_outcome;
        if let Some(error) = scan_error {
            // The stream ran dry mid-member: the serial decoder would have
            // hit this same error at this same output position.
            return Err(error.into());
        }
        let _ = scan_done;
        if applied < dispatched {
            // Every dispatched job yields exactly one tape unless its worker
            // died; the channel closed early.
            return Err(worker_exited());
        }
        // is_last applied without filling the output; the caller turns the
        // shortfall into NeedMoreInput.
        Ok(())
    }
}

/// Contiguous member-sized output buffer for the flat-apply path. Non-solid
/// members that fit in memory decode straight into `buf`; literal runs are one
/// memcpy, matches are plain forward copies (the whole prefix is the window,
/// no ring masking), and finalized bytes stream to the sink incrementally so
/// CRC + disk write overlap decode on the writer thread. `buf` always holds
/// UNFILTERED bytes (the LZ window): a declared filter is applied to a scratch
/// copy of its range as the range completes, never in place (trap 5).
#[cfg(feature = "parallel")]
struct FlatOutput {
    buf: Vec<u8>,
    /// Physical write position in `buf`. With a seeded prefix this is NOT
    /// the logical output count - see `base` and `written()`.
    pos: usize,
    /// Seeded-window prefix length: `buf[..base]` is the solid window
    /// carried into this group, never emitted, reachable by matches. Zero
    /// for a group starting on an empty window (the original flat mode).
    base: usize,
    /// Bytes already emitted to the sink.
    emitted: usize,
    dictionary_size: usize,
    history_limit: usize,
    /// Declared filters awaiting their range to finish materializing, in
    /// declaration (== non-decreasing start) order.
    pending_filters: std::collections::VecDeque<PendingFilter>,
    /// Group-relative end of each chained member, in order. Empty when this
    /// buffer holds a single member; see `member_base_of`.
    member_ends: Vec<usize>,
    filter_scratch: Vec<u8>,
    /// See `StreamingOutput::delta_scratch`.
    delta_scratch: Vec<u8>,
    /// Emit is attempted once per `FLAT_EMIT_THRESHOLD` of new bytes.
    next_emit_check: usize,
    /// Logical bytes slid out of the front of `buf` so far: physical index
    /// `p` is group-logical `p + origin`. Zero until the first slide; a
    /// buffer sized to the whole output never slides.
    origin: usize,
    /// Logical end of the output (seed + output size): the bound every
    /// output-limit check compares against, since `buf.len()` is no longer
    /// that bound.
    output_end: usize,
    /// Physical bound the short-match fast path may write up to, with its
    /// 16-byte over-copy: `min(buf.len(), output_end - origin) - 16`.
    /// Recomputed on every slide.
    fast_end: usize,
    /// Largest distance the fast path accepts: the smaller of the
    /// dictionary and the window limit, so one compare stands in for the
    /// two ordered checks of the slow path (which still runs, and errors
    /// in the documented order, for anything the fast path declines).
    fast_distance_max: usize,
    /// Physical write position at which this group's declared output is
    /// complete: `output_end - origin`. The apply walk tests it once per
    /// TAPE OP, and reading it out of `written()` was three loads, an add
    /// and a subtract every time. Recomputed on every slide, beside
    /// `fast_end`. (nzbfast-local change, 3 Sep 2026; see VENDORING.md.)
    limit_pos: usize,
}

/// Emit granularity: keep the writer-thread pipe fed in ~1 MB batches while
/// decode continues, matching the streaming path's flush cadence.
#[cfg(feature = "parallel")]
const FLAT_EMIT_THRESHOLD: usize = 1 << 20;

/// Longest literal run `push_bytes` copies with the inline power-of-two
/// ladder instead of `copy_from_slice`'s `memcpy` libcall. Fifteen is the
/// widest length the four-step ladder covers exactly, and it is far past
/// the measured distribution: 99.0-99.2% of runs on the census -m3 shapes
/// are at most fifteen bytes. (nzbfast-local change, 3 Sep 2026; see
/// VENDORING.md.)
#[cfg(feature = "parallel")]
const LITERAL_INLINE_MAX: usize = 15;

/// MOST slack past the retained window in a SLIDING flat buffer: the plan
/// never reaches further than this past the window, so the memmove that
/// slides the window to the front runs at least once per this many output
/// bytes. Tests shrink it so the differential suite crosses slides
/// constantly.
///
/// This was the LEAST slack - the name is the old one - until 16 Sep 2026,
/// when `flat_slack` below made the slack a function of the member and the
/// dictionary and left this as its ceiling. The bound the old floor carried
/// (slack at least the dictionary, so at most one byte moved per byte
/// emitted) is now the rule's own lower clamp and did not move.
#[cfg(not(test))]
const FLAT_SLACK_MIN: usize = 64 << 20;
#[cfg(test)]
const FLAT_SLACK_MIN: usize = 4096;

/// Smallest slack the sliding buffer runs with at all, whatever the two
/// terms below say: a slide has to leave room for the longest single match
/// or literal run the walk can append. This is the value test builds have
/// always used for `FLAT_SLACK_MIN`, so it is the one that is proven by the
/// differential suite. (nzbfast-local change, 16 Sep 2026; see VENDORING.md.)
const FLAT_SLACK_FLOOR: usize = 4096;

/// Slack to plan past the retained window, which is a trade between two
/// costs that move in opposite directions with it:
///
/// * every page of the plan takes a first-touch zero-fill fault the first
///   time the decoder writes it, so the fault bill is linear in the WINDOW;
/// * `make_room` slides the retained window to the front once per `slack`
///   bytes of output, moving `history_limit` bytes each time, so the slide
///   bill is `output_size * history_limit / slack`.
///
/// Minimising `a * (history + slack) + b * output * history / slack` gives
/// `slack = sqrt(output * history * b / a)`, and a grid over eight member
/// sizes and seven dictionaries on an M3 Ultra fits `a / b = 2.8` - a fault
/// costs 54.3 us/MiB of plan, a slide 19.4 us/MiB moved (`research/
/// RARFAST-BENCH-2026-09-14.md` section 19, `research/rarbench-2026-09-16/`).
/// Three is that ratio rounded; the optimum is flat enough either side that
/// the exact value does not matter, which the same grid shows.
///
/// Clamped both ways, and the UPPER clamp is what makes this safe to change:
/// the result is never more than `FLAT_SLACK_MIN` past the window (so no
/// member ever plans MORE than it did before this rule, and no memory gate,
/// admission estimate or `-mm<size>` cap can be loosened by it), and never
/// less than `history_limit` (the old bound of one byte moved per byte
/// emitted) nor less than `FLAT_SLACK_FLOOR`. Under `cfg(test)` the two
/// clamps meet, so test builds plan exactly what they always did.
///
/// What it buys: a 32 to 128 MiB member with a dictionary of 8 MiB or less
/// planned 64 MiB of slack it could not use and paid the faults for it -
/// measured 2.4% to 8.5% of `rarfast t` wall across that class, and inside
/// the noise everywhere else. (nzbfast-local change, 16 Sep 2026; see
/// VENDORING.md.)
fn flat_slack(output_size: usize, history_limit: usize) -> usize {
    flat_slack_with(output_size, history_limit, FLAT_SLACK_MIN)
}

/// `flat_slack` with the ceiling named, so a test can ask what a PRODUCTION
/// build plans: `FLAT_SLACK_MIN` is a sixteen-thousandth of its shipped value
/// under `cfg(test)`, which would otherwise leave the rule untested at every
/// size it was fitted on.
fn flat_slack_with(output_size: usize, history_limit: usize, slack_min: usize) -> usize {
    // Today's slack, and the ceiling: this rule only ever plans less.
    let ceiling = history_limit.max(slack_min);
    // `u128::isqrt` is not stable on the pinned toolchain, and the product
    // reaches 2^77, so the root is taken in f64: a 53-bit mantissa is worth
    // about one part in 2^24 of it, far inside the flat region around the
    // optimum. A non-finite product would saturate to zero, which the
    // clamps below then lift to the old floor.
    let ideal = ((output_size as f64) * (history_limit as f64) / 3.0).sqrt() as usize;
    ideal.max(history_limit).max(FLAT_SLACK_FLOOR).min(ceiling)
}

/// Bytes a flat plan allocates for a member of `output_size` (plus a
/// carried `seed`) with a reachable window of `history_limit`: the whole
/// member when that is smaller, else a window of `history_limit` plus
/// slack. Until 2 Sep 2026 the flat buffer WAS the member, so every member
/// over the policy's flat cap (512 MiB, i.e. every multi-GB video) took
/// the ring path, measured 7% slower per byte on the apply thread and
/// carrying a 2x-dictionary ring; sliding makes the plan's size a
/// function of the dictionary, not the member
/// (research/RAR-PERF-AUDIT-2026-09-02.md, round 3). Not feature-gated:
/// the admission gate in rar50/extract.rs prices the plan in every build.
pub(crate) fn flat_plan_bytes(seed: usize, output_size: usize, history_limit: usize) -> usize {
    let window = history_limit.saturating_add(flat_slack(output_size, history_limit));
    seed.saturating_add(output_size.min(window))
}

/// Append a SHORT literal run at `pos` with constant-length copies. A run
/// ends at the next match and matches are 86% of tape ops, so runs are
/// overwhelmingly tiny: on the census -m3 shapes 67.8-69.4% of runs are a
/// single byte and 97.1-97.7% are three bytes or fewer, while the long
/// incompressible runs that carry most of the literal BYTES are a rounding
/// error in COUNT. `copy_from_slice` on a runtime length is a `memcpy`
/// libcall whatever that length is, and a `sample` of the 4 GiB fixture put
/// 9.6% of the apply thread - the pipeline's wall - at the return address
/// of exactly that call. Every copy below has a constant length, so it
/// lowers to inline load/store pairs; past `LITERAL_INLINE_MAX` the caller
/// keeps the libcall, which is the right shape for a long run.
///
/// Caller guarantees `bytes.len() <= LITERAL_INLINE_MAX` and that
/// `buf[pos..pos + bytes.len()]` is in bounds. (nzbfast-local change,
/// 3 Sep 2026; see VENDORING.md.)
#[cfg(feature = "parallel")]
#[inline(always)]
fn flat_literal_ladder(buf: &mut [u8], pos: usize, bytes: &[u8]) {
    let count = bytes.len();
    debug_assert!(count <= LITERAL_INLINE_MAX);
    if count == 1 {
        buf[pos] = bytes[0];
        return;
    }
    let mut src = bytes;
    let mut at = pos;
    if count & 8 != 0 {
        let (head, rest) = src.split_at(8);
        buf[at..at + 8].copy_from_slice(head);
        src = rest;
        at += 8;
    }
    if count & 4 != 0 {
        let (head, rest) = src.split_at(4);
        buf[at..at + 4].copy_from_slice(head);
        src = rest;
        at += 4;
    }
    if count & 2 != 0 {
        let (head, rest) = src.split_at(2);
        buf[at..at + 2].copy_from_slice(head);
        src = rest;
        at += 2;
    }
    if count & 1 != 0 {
        buf[at] = src[0];
    }
}

/// The common flat match: short, distance at least a stride, inside the
/// window, well inside the buffer - ONE predicate and an at-most-four
/// 16-byte stride copy. Returns whether it handled the match; `false`
/// means the caller must hand it to `FlatOutput::copy_match_slow`, which
/// owns every error and its documented order (dictionary, then
/// window-limit, then window, then output). On the apply thread of a -m3
/// member - the pipeline's wall - the guard ladder the slow path runs was
/// 55% of the thread before this predicate existed
/// (research/RAR-PERF-AUDIT-2026-09-02.md, round 4): `fast_end` folds the
/// buffer end, the output limit and the over-copy into one bound,
/// `fast_distance_max` folds the dictionary and window-limit checks, and
/// `distance <= pos` is the window check, so every guard the slow path
/// errors on is false here and the two paths cannot disagree on a valid
/// stream.
///
/// Taking the buffer and the bounds as arguments rather than reading them
/// off `&mut FlatOutput` is what lets the op walk keep them in registers
/// across a whole tape; the same call from `FlatOutput::copy_match` keeps
/// the unit tests on exactly this code. (nzbfast-local change, 3 Sep 2026;
/// see VENDORING.md.)
#[cfg(feature = "parallel")]
#[inline(always)]
fn flat_stride_copy(
    buf: &mut [u8],
    pos: usize,
    distance: usize,
    length: usize,
    fast_end: usize,
    fast_distance_max: usize,
) -> bool {
    if length <= 64
        && distance >= 16
        && distance <= fast_distance_max
        && distance <= pos
        && pos + length <= fast_end
    {
        // Decoded match lengths are at least two. The unconditional first
        // stride is also sound for the zero-length internal edge case: it
        // only scribbles at `pos`, which later output overwrites before it
        // can be emitted, and `fast_end` guarantees the 16-byte slack. The
        // fast-path ceiling fixes the stride count at four; spelling them
        // out keeps the common path free of a loop backedge. Reading each
        // word after the previous one landed keeps the overlapped-match
        // semantics exact for distance >= 16.
        let src = pos - distance;
        buf.copy_within(src..src + 16, pos);
        if length > 16 {
            buf.copy_within(src + 16..src + 32, pos + 16);
            if length > 32 {
                buf.copy_within(src + 32..src + 48, pos + 32);
                if length > 48 {
                    buf.copy_within(src + 48..src + 64, pos + 48);
                }
            }
        }
        return true;
    }
    false
}

#[cfg(feature = "parallel")]
impl FlatOutput {
    fn new(output_size: usize, dictionary_size: usize, history_limit: usize) -> Self {
        Self::new_seeded(&[], output_size, dictionary_size, history_limit)
    }

    /// Flat buffer whose prefix is a carried solid window: matches reach
    /// into it exactly as the ring path's history, output positions and
    /// emits stay logical to the group. This is what lets the SECOND and
    /// later chain groups of a solid archive keep the flat fast path - the
    /// empty-window-only gate cost them ~50% (ring 0.74s vs flat 0.49s on
    /// the 200 MB solid corpus).
    fn new_seeded(
        seed: &[u8],
        output_size: usize,
        dictionary_size: usize,
        history_limit: usize,
    ) -> Self {
        let mut buf = vec![0u8; flat_plan_bytes(seed.len(), output_size, history_limit)];
        let buf_len = buf.len();
        buf[..seed.len()].copy_from_slice(seed);
        Self {
            buf,
            pos: seed.len(),
            base: seed.len(),
            emitted: seed.len(),
            dictionary_size,
            history_limit,
            pending_filters: std::collections::VecDeque::new(),
            member_ends: Vec::new(),
            filter_scratch: Vec::new(),
            delta_scratch: Vec::new(),
            next_emit_check: seed.len() + FLAT_EMIT_THRESHOLD,
            origin: 0,
            output_end: seed.len() + output_size,
            fast_end: buf_len.min(seed.len() + output_size).saturating_sub(16),
            fast_distance_max: dictionary_size.min(history_limit),
            limit_pos: seed.len() + output_size,
        }
    }

    /// Declare the member boundaries of a chained group (group-relative
    /// cumulative ends). Only filter origins depend on them, and only a
    /// chain has more than one member, so a single-member buffer leaves
    /// them empty.
    fn with_member_ends(mut self, member_ends: Vec<usize>) -> Self {
        self.member_ends = member_ends;
        self
    }

    /// Logical bytes of THIS GROUP's output (the seeded prefix is not
    /// output). Every output-limit and member-boundary computation runs on
    /// this; `pos` stays physical.
    #[inline]
    fn written(&self) -> usize {
        self.origin + self.pos - self.base
    }

    /// Whether this group's declared output is complete - `written() >=
    /// output_size`, answered against the precomputed physical bound. The
    /// flat plan is always built with the same `output_size` the apply walk
    /// is given (both callers pass one value to `FlatOutput::new*` and to
    /// `run_blocks_flat*`), which is what makes `output_end == base +
    /// output_size` and this test equivalent; the debug assertion pins it,
    /// and the differential suite drives both a full member and three
    /// smaller prefixes. (nzbfast-local change, 3 Sep 2026; see
    /// VENDORING.md.)
    #[inline(always)]
    fn output_complete(&self, output_size: usize) -> bool {
        debug_assert_eq!(
            self.output_end,
            self.base + output_size,
            "flat plan and apply walk disagree on the output size"
        );
        self.pos >= self.limit_pos
    }

    /// Make room for `needed` bytes at `pos`, sliding the buffer when the
    /// member does not fit whole. Everything below `emitted` that is also
    /// older than `history_limit` is dropped off the front; the retained
    /// window moves to `buf[0..]` and every physical position (pos,
    /// emitted, pending filter starts, the emit watermark) shifts with it,
    /// `origin` absorbing the shift so logical positions are unchanged. A
    /// pending filter holding back more than the slack leaves nothing to
    /// slide, which is the same condition the streaming path answers with
    /// `FilteredMember`: the member falls back to the buffered decoder.
    #[cold]
    fn make_room<E>(
        &mut self,
        needed: usize,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        self.emit_ready(sink)?;
        let shift = self
            .emitted
            .min(self.pos.saturating_sub(self.history_limit));
        if shift == 0 || self.pos - shift + needed > self.buf.len() {
            return Err(StreamDecodeError::FilteredMember);
        }
        self.buf.copy_within(shift..self.pos, 0);
        self.pos -= shift;
        self.emitted -= shift;
        self.origin += shift;
        self.next_emit_check = self.next_emit_check.saturating_sub(shift);
        self.limit_pos = self.output_end.saturating_sub(self.origin);
        self.fast_end = self.buf.len().min(self.limit_pos).saturating_sub(16);
        for held in &mut self.pending_filters {
            held.start -= shift;
        }
        Ok(())
    }

    /// Append a literal run: one straight copy into `buf`, then attempt an
    /// incremental emit. The output-limit check mirrors `StreamingOutput`
    /// (the differential tests compare error values), though the caller
    /// clamps runs so it never actually trips.
    #[inline]
    fn push_bytes<E>(
        &mut self,
        bytes: &[u8],
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        // `fast_end` already folds the output limit and the buffer end
        // (see `copy_match`); a run that fits under it needs no other check.
        if self.pos + bytes.len() > self.fast_end {
            if self
                .written()
                .checked_add(bytes.len())
                .is_none_or(|end| end + self.base > self.output_end)
            {
                return Err(Error::InvalidData("RAR 5 match exceeds output limit").into());
            }
            if self.pos + bytes.len() > self.buf.len() {
                self.make_room(bytes.len(), sink)?;
            }
        }
        // The TINY run - which is nearly all of them - is a handful of
        // inline stores rather than a `memcpy` libcall; see
        // `flat_literal_ladder`. (nzbfast-local change, 3 Sep 2026; see
        // VENDORING.md.)
        let pos = self.pos;
        let count = bytes.len();
        if count <= LITERAL_INLINE_MAX {
            flat_literal_ladder(&mut self.buf, pos, bytes);
        } else {
            self.buf[pos..pos + count].copy_from_slice(bytes);
        }
        self.pos = pos + count;
        self.maybe_emit(sink)
    }

    /// Copy a back-reference forward inside `buf`, over the whole
    /// `FlatOutput`. Production's op walk drives `flat_stride_copy` and
    /// `copy_match_slow` directly on its hoisted locals; this is the
    /// unhoisted spelling of the same two steps, kept as the ORACLE the
    /// exhaustive short-match and slow-path unit tests drive. The stride
    /// copy itself is not duplicated here - both spellings call the one
    /// helper - and the walk is covered end to end by the flat/buffered
    /// differential suite. (nzbfast-local change, 3 Sep 2026; see
    /// VENDORING.md.)
    #[cfg(test)]
    #[inline(always)]
    fn copy_match<E>(
        &mut self,
        distance: usize,
        length: usize,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        if flat_stride_copy(
            &mut self.buf,
            self.pos,
            distance,
            length,
            self.fast_end,
            self.fast_distance_max,
        ) {
            self.pos += length;
            return self.maybe_emit(sink);
        }
        self.copy_match_slow(distance, length, sink)
    }

    #[inline(never)]
    fn copy_match_slow<E>(
        &mut self,
        distance: usize,
        length: usize,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        if distance > self.dictionary_size {
            return Err(Error::InvalidData("RAR 5 match distance exceeds dictionary").into());
        }
        if distance > self.history_limit {
            return Err(Error::WindowLimitExceeded {
                limit: self.history_limit as u64,
                required: distance as u64,
            }
            .into());
        }
        if distance == 0 || distance > self.pos {
            return Err(Error::InvalidData("RAR 5 match distance exceeds window").into());
        }
        if self
            .written()
            .checked_add(length)
            .is_none_or(|end| end + self.base > self.output_end)
        {
            return Err(Error::InvalidData("RAR 5 match exceeds output limit").into());
        }
        if self.pos + length > self.buf.len() {
            self.make_room(length, sink)?;
        }
        if distance == 1 {
            let byte = self.buf[self.pos - 1];
            self.buf[self.pos..self.pos + length].fill(byte);
            self.pos += length;
            return self.maybe_emit(sink);
        }

        // Short-match fast path: matches are overwhelmingly short (a few to a
        // few dozen bytes), where `copy_within`'s memmove libcall dominates
        // the copy itself. Copy in fixed 16-byte strides instead. Over-copying
        // up to 15 bytes past `pos + length` is sound in the flat buffer: the
        // scribbled bytes sit at or beyond the new `pos`, every later write
        // (literal or match) lands exactly at `pos` and overwrites them before
        // `pos` moves past, matches only read below `pos`, and the emit gate
        // never releases bytes at or above `pos`. Requires the source stride
        // to stay below `pos` (distance >= 16 keeps src+16 <= pos) and slack
        // in the buffer for the final stride.
        if length <= 64 && distance >= 16 && self.pos + length + 16 <= self.buf.len() {
            let mut src = self.pos - distance;
            let mut dst = self.pos;
            let end = self.pos + length;
            while dst < end {
                let word: [u8; 16] = self.buf[src..src + 16].try_into().unwrap();
                self.buf[dst..dst + 16].copy_from_slice(&word);
                src += 16;
                dst += 16;
            }
            self.pos = end;
            return self.maybe_emit(sink);
        }

        // Short-period overlapped repeats take the same period-doubling loop as
        // the ring path, ported EXACTLY behind its guard (trap 7): each
        // full-period run makes the doubled span periodic, so tiny copies grow
        // geometrically. Everything else keeps the tight per-`distance` loop,
        // whose cost this specialization must not touch.
        const PERIOD_DOUBLE_CEILING: usize = 4096;
        if length > distance && distance <= PERIOD_DOUBLE_CEILING {
            // Each run reads [pos-period, pos-period+run) with run <= period,
            // so source and destination never overlap within a run.
            let period_cap = self.buf.len();
            let mut remaining = length;
            let mut period = distance;
            while remaining > 0 {
                let run = remaining.min(period);
                let src = self.pos - period;
                self.buf.copy_within(src..src + run, self.pos);
                self.pos += run;
                remaining -= run;
                // Only a full-period run makes the doubled span periodic; the
                // period must stay a multiple of `distance`.
                if run == period && period * 2 <= period_cap.min(2 * PERIOD_DOUBLE_CEILING) {
                    period *= 2;
                }
            }
            return self.maybe_emit(sink);
        }

        let mut remaining = length;
        while remaining > 0 {
            // Overlapped matches repeat with period `distance`; a run of at
            // most `distance` reads an already-complete, non-overlapping span.
            let run = remaining.min(distance);
            let src = self.pos - distance;
            self.buf.copy_within(src..src + run, self.pos);
            self.pos += run;
            remaining -= run;
        }
        self.maybe_emit(sink)
    }

    /// Declare a filter over member-output range `[start, start+length)`.
    /// `buf` is 1:1 with output position (no sparse zeros in flat mode), so
    /// `start` indexes `buf` directly. Identical-range chains are kept and
    /// applied together at emit; partially-overlapping or out-of-order filters
    /// fall back to the buffered path exactly as the streaming path does
    /// (`FilteredMember`). Unlike streaming there is no hold-back limit —
    /// memory is already committed — so long filters are handled here.
    fn queue_filter<E>(
        &mut self,
        filter: PendingFilter,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        if self.pending_filters.len() >= STREAM_MAX_PENDING_FILTERS {
            return Err(StreamDecodeError::FilteredMember);
        }
        // Filter starts arrive logical (resolved against `written()`);
        // everything downstream (emit gating, scratch slicing) is physical.
        let mut filter = filter;
        // `written()` counts the whole GROUP, so pin the origin the filter
        // itself needs - the offset inside the declaring member - while the
        // start is still group-logical.
        filter.file_start = filter.start - member_base_of(&self.member_ends, filter.start);
        filter.start = filter
            .start
            .checked_add(self.base)
            .and_then(|start| start.checked_sub(self.origin))
            .ok_or(Error::InvalidData("RAR 5 filter range overflows"))?;
        if let Some(back) = self.pending_filters.back() {
            let back_end = back.start.saturating_add(back.length);
            let identical_range = filter.start == back.start && filter.length == back.length;
            if !identical_range && filter.start < back_end {
                return Err(StreamDecodeError::FilteredMember);
            }
        }
        self.pending_filters.push_back(filter);
        Ok(())
    }

    /// Attempt an emit once per `FLAT_EMIT_THRESHOLD` of newly materialized
    /// bytes, so the sink (CRC + write) stays overlapped with decode.
    #[inline]
    fn maybe_emit<E>(
        &mut self,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        if self.pos >= self.next_emit_check {
            self.emit_ready(sink)?;
            self.next_emit_check = self.pos + FLAT_EMIT_THRESHOLD;
        }
        Ok(())
    }

    /// Stream every finalized byte to the sink. Bytes below the first pending
    /// filter's start are final (a filter declared later starts at or after
    /// the position it was declared, so it can never target already-emitted
    /// bytes — the incremental-emit soundness argument, 2.5). When a filter's
    /// range is fully materialized, its scratch copy is filtered (with any
    /// identical-range chain behind it) and emitted; `buf` keeps the unfiltered
    /// window.
    fn emit_ready<E>(
        &mut self,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        loop {
            let plain_limit = self
                .pending_filters
                .front()
                .map(|held| held.start)
                .unwrap_or(usize::MAX)
                .min(self.pos);
            if self.emitted < plain_limit {
                sink(DecodedChunk::Bytes(&self.buf[self.emitted..plain_limit]))
                    .map_err(StreamDecodeError::Sink)?;
                self.emitted = plain_limit;
            }
            let Some(front) = self.pending_filters.front() else {
                return Ok(());
            };
            let end = front
                .start
                .checked_add(front.length)
                .ok_or(Error::InvalidData("RAR 5 filter range overflows"))?;
            if self.pos < end {
                // Range not fully decoded yet; held back until it is.
                return Ok(());
            }

            // Linearize the range, apply the filter (and any identical-range
            // chain behind it) to the copy, and emit it.
            self.filter_scratch.clear();
            self.filter_scratch
                .extend_from_slice(&self.buf[front.start..end]);
            loop {
                let held = self
                    .pending_filters
                    .pop_front()
                    .expect("pending filter chain underflow");
                // `held.start` indexes `buf` physically: it carries both a
                // seeded window prefix (`self.base`) and, in a chain, every
                // earlier member of the group. The FILTER wants neither -
                // it wants the offset within its own member, which is what
                // the encoder bakes in and what the buffered oracle passes,
                // and both shifts moved E8/E8E9/ARM addresses off the
                // serial walk. `queue_filter` pinned that origin at
                // declaration; slice with the physical index, translate
                // with the member-local one.
                apply_filter_to_vec(
                    &mut self.filter_scratch,
                    &held,
                    held.file_start,
                    &mut self.delta_scratch,
                )?;
                match self.pending_filters.front() {
                    Some(next) if next.start == held.start && next.length == held.length => {
                        continue;
                    }
                    _ => break,
                }
            }
            if !self.filter_scratch.is_empty() {
                sink(DecodedChunk::Bytes(&self.filter_scratch)).map_err(StreamDecodeError::Sink)?;
            }
            self.emitted = end;
        }
    }

    /// Emit the tail. At member end any filter whose range never completed is
    /// out of range — the same error the buffered path raises.
    fn finish<E>(
        &mut self,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        self.emit_ready(sink)?;
        if !self.pending_filters.is_empty() {
            return Err(Error::InvalidData("RAR 5 filter range exceeds output").into());
        }
        Ok(())
    }

    /// Retain the tail (up to `history_limit`) as unfiltered window bytes for a
    /// later solid member, mirroring the buffered path's history block. `buf`
    /// is unfiltered, so a straight tail copy is correct.
    fn into_history(self, history_limit: usize) -> Vec<u8> {
        let keep = self.pos.min(history_limit);
        self.buf[self.pos - keep..self.pos].to_vec()
    }
}

fn read_compressed_block_into(
    input: &mut impl Read,
    payload: &mut Vec<u8>,
) -> Result<CompressedBlockHeader> {
    let mut fixed = [0u8; 2];
    input
        .read_exact(&mut fixed)
        .map_err(|_| Error::NeedMoreInput)?;
    let flags = fixed[0];
    let checksum = fixed[1];
    let size_bytes_len = match (flags >> 3) & 0x03 {
        0 => 1,
        1 => 2,
        2 => 3,
        _ => return Err(Error::InvalidData("RAR 5 block size length is invalid")),
    };
    let mut size_bytes = [0u8; 3];
    input
        .read_exact(&mut size_bytes[..size_bytes_len])
        .map_err(|_| Error::NeedMoreInput)?;

    let actual = size_bytes[..size_bytes_len]
        .iter()
        .fold(checksum ^ flags, |acc, &byte| acc ^ byte);
    if actual != 0x5a {
        return Err(Error::InvalidData("RAR 5 block header checksum mismatch"));
    }

    let payload_size = size_bytes[..size_bytes_len]
        .iter()
        .enumerate()
        .fold(0usize, |acc, (index, &byte)| {
            acc | (usize::from(byte) << (index * 8))
        });
    payload.resize(payload_size, 0);
    input
        .read_exact(payload)
        .map_err(|_| Error::NeedMoreInput)?;
    let final_byte_bits = ((flags & 0x07) + 1).min(8);
    let payload_bits = if payload_size == 0 {
        0
    } else {
        (payload_size - 1) * 8 + usize::from(final_byte_bits)
    };

    Ok(CompressedBlockHeader {
        flags,
        is_last: flags & 0x40 != 0,
        has_tables: flags & 0x80 != 0,
        final_byte_bits,
        payload_size,
        payload_bits,
    })
}

impl Default for Rar50Decoder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingFilter {
    /// Where the range lives in the buffer that will be sliced for it. The
    /// flat and streaming outputs shift this into their own address space.
    start: usize,
    /// Offset of the range within its own MEMBER's output, which is what an
    /// address-translating filter mixes into every translated address (see
    /// `apply_filter_to_range`). Equal to `start` for a single-member
    /// decode; the chain outputs recompute it, because their positions
    /// count a whole solid group.
    file_start: usize,
    length: usize,
    filter_type: FilterType,
    channels: usize,
}

/// Group-relative output offset where the member containing `start` begins.
/// `member_ends` holds the group-relative end of each member in order and is
/// empty for a single-member decode, where the base is always zero.
fn member_base_of(member_ends: &[usize], start: usize) -> usize {
    let index = member_ends.partition_point(|&end| end <= start);
    if index == 0 {
        0
    } else {
        member_ends[index - 1]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterType {
    Delta,
    E8,
    E8E9,
    Arm,
}

/// A filter record as encoded in the bitstream: the start offset is relative
/// to the output position at the declaring symbol, resolved by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RawFilter {
    offset: u32,
    length: u32,
    filter_type: FilterType,
    channels: u8,
}

impl RawFilter {
    fn resolve(self, current_pos: usize) -> Result<PendingFilter> {
        let start = current_pos
            .checked_add(self.offset as usize)
            .ok_or(Error::InvalidData("RAR 5 filter start overflows"))?;
        Ok(PendingFilter {
            start,
            // Correct as-is whenever `current_pos` is a member-output
            // position (the buffered path and every single-member decode).
            // A chain output resolves against the whole group, so it
            // rewrites this in `queue_filter`.
            file_start: start,
            length: self.length as usize,
            filter_type: self.filter_type,
            channels: usize::from(self.channels),
        })
    }
}

fn parse_filter_record_fields(bits: &mut BitReader<'_>) -> Result<RawFilter> {
    let offset = read_counted_le_u32(bits)?;
    let length = read_counted_le_u32(bits)?;
    let filter_type = match bits.read_bits(3)? {
        0 => FilterType::Delta,
        1 => FilterType::E8,
        2 => FilterType::E8E9,
        3 => FilterType::Arm,
        _ => return Err(Error::InvalidData("RAR 5 filter type is unsupported")),
    };
    let channels = if filter_type == FilterType::Delta {
        bits.read_bits(5)? as u8 + 1
    } else {
        0
    };
    Ok(RawFilter {
        offset,
        length,
        filter_type,
        channels,
    })
}

fn parse_filter_record(bits: &mut BitReader<'_>, current_pos: usize) -> Result<PendingFilter> {
    parse_filter_record_fields(bits)?.resolve(current_pos)
}

fn read_counted_le_u32(bits: &mut BitReader<'_>) -> Result<u32> {
    let byte_count = bits.read_bits(2)? as usize + 1;
    let mut data = 0;
    for index in 0..byte_count {
        data |= bits.read_bits(8)? << (index * 8);
    }
    Ok(data)
}

fn write_filter(writer: &mut BitWriter, filter: EncodeFilter) -> Result<()> {
    if filter.offset > u32::MAX as usize {
        return Err(Error::InvalidData("RAR 5 filter offset is too large"));
    }
    if filter.length > u32::MAX as usize {
        return Err(Error::InvalidData("RAR 5 filter length is too large"));
    }
    write_counted_le_u32(writer, filter.offset as u32);
    write_counted_le_u32(writer, filter.length as u32);
    match filter.filter_type {
        FilterType::Delta => {
            if filter.channels == 0 || filter.channels > 32 {
                return Err(Error::InvalidData(
                    "RAR 5 DELTA filter channel count is invalid",
                ));
            }
            writer.write_bits(0, 3);
            writer.write_bits(filter.channels - 1, 5);
        }
        FilterType::E8 => writer.write_bits(1, 3),
        FilterType::E8E9 => writer.write_bits(2, 3),
        FilterType::Arm => writer.write_bits(3, 3),
    }
    Ok(())
}

fn write_counted_le_u32(writer: &mut BitWriter, value: u32) {
    let byte_count = if value <= 0xff {
        1
    } else if value <= 0xffff {
        2
    } else if value <= 0x00ff_ffff {
        3
    } else {
        4
    };
    writer.write_bits(byte_count - 1, 2);
    for index in 0..byte_count {
        writer.write_bits(((value >> (index * 8)) & 0xff) as usize, 8);
    }
}

fn apply_filters(output: &mut [u8], filters: &[PendingFilter]) -> Result<()> {
    // One delta buffer for the whole run of filters, not one per block.
    let mut scratch = Vec::new();
    for filter in filters {
        let end = filter
            .start
            .checked_add(filter.length)
            .ok_or(Error::InvalidData("RAR 5 filter range overflows"))?;
        let data = output
            .get_mut(filter.start..end)
            .ok_or(Error::InvalidData("RAR 5 filter range exceeds output"))?;
        apply_filter_to_range(data, filter, filter.start, &mut scratch)?;
    }
    Ok(())
}

/// Apply one filter to `data`, which must be exactly the filter's range.
/// `file_start` is the member-output offset of `data[0]` (address-translating
/// filters mix it into the transformed values). `scratch` is the delta
/// filter's working buffer, owned by the caller so a member full of delta
/// blocks allocates once rather than once per block; the other filters never
/// touch it.
fn apply_filter_to_range(
    data: &mut [u8],
    filter: &PendingFilter,
    file_start: usize,
    scratch: &mut Vec<u8>,
) -> Result<()> {
    match filter.filter_type {
        FilterType::Delta => {
            filters::delta_decode_into(data, filter.channels, rar50_delta_messages(), scratch)?;
            data.copy_from_slice(scratch);
        }
        FilterType::E8 => address_filters::x86(
            data,
            file_start as u32,
            Direction::Decode,
            X86Opcodes::Call,
            X86Format::Rar5,
        ),
        FilterType::E8E9 => address_filters::x86(
            data,
            file_start as u32,
            Direction::Decode,
            X86Opcodes::CallAndJump,
            X86Format::Rar5,
        ),
        FilterType::Arm => address_filters::arm(data, file_start as u32, Direction::Decode),
    }
    Ok(())
}

/// Apply one filter to an owned streaming scratch buffer. Delta decoding
/// necessarily writes to disjoint storage because it reads channel-major and
/// writes interleaved. Both streaming outputs already keep two reusable
/// vectors, so swap the decoded vector into place instead of copying the whole
/// filter range back. (nzbfast-local change, 3 Sep 2026 - see VENDORING.md.)
fn apply_filter_to_vec(
    data: &mut Vec<u8>,
    filter: &PendingFilter,
    file_start: usize,
    scratch: &mut Vec<u8>,
) -> Result<()> {
    match filter.filter_type {
        FilterType::Delta => {
            filters::delta_decode_into(data, filter.channels, rar50_delta_messages(), scratch)?;
            std::mem::swap(data, scratch);
        }
        FilterType::E8 => address_filters::x86(
            data,
            file_start as u32,
            Direction::Decode,
            X86Opcodes::Call,
            X86Format::Rar5,
        ),
        FilterType::E8E9 => address_filters::x86(
            data,
            file_start as u32,
            Direction::Decode,
            X86Opcodes::CallAndJump,
            X86Format::Rar5,
        ),
        FilterType::Arm => address_filters::arm(data, file_start as u32, Direction::Decode),
    }
    Ok(())
}

fn rar50_delta_messages() -> DeltaErrorMessages {
    DeltaErrorMessages {
        invalid_channels: "RAR 5 DELTA filter channel count is invalid",
        zero_channels: "RAR 5 DELTA filter has zero channels",
        truncated_source: "RAR 5 DELTA filter source is truncated",
    }
}

fn length_slot_extra_bits(slot: usize) -> Result<u8> {
    if slot < 8 {
        Ok(0)
    } else {
        let bit_count = (slot >> 2) - 1;
        if bit_count > 24 {
            Err(Error::InvalidData("RAR 5 length slot is too large"))
        } else {
            Ok(bit_count as u8)
        }
    }
}

fn length_bonus(distance: usize) -> usize {
    usize::from(distance > 0x100) + usize::from(distance > 0x2000) + usize::from(distance > 0x40000)
}

pub fn match_length_for_slot(slot: usize, extra_bits: u32) -> Result<usize> {
    if slot < 8 {
        return Ok(slot + 2);
    }
    let bit_count = (slot >> 2) - 1;
    if bit_count > 24 {
        return Err(Error::InvalidData("RAR 5 length slot is too large"));
    }
    let max_extra = if bit_count == 32 {
        u32::MAX
    } else {
        (1u32 << bit_count) - 1
    };
    if extra_bits > max_extra {
        return Err(Error::InvalidData("RAR 5 length extra bits exceed slot"));
    }
    Ok((((4 | (slot & 3)) << bit_count) | extra_bits as usize) + 2)
}

pub fn distance_slot_bit_count(slot: usize) -> Result<usize> {
    if slot < 4 {
        Ok(0)
    } else {
        let bit_count = (slot - 2) >> 1;
        if bit_count > 31 {
            Err(Error::InvalidData("RAR 5 distance slot is too large"))
        } else {
            Ok(bit_count)
        }
    }
}

/// The distance ladder itself: `((2 | slot & 1) << bit_count | extra) + 1`,
/// computed in `u64` and SATURATED into `usize`. Both distance decoders go
/// through here so they cannot disagree.
///
/// THE INTERMEDIATE IS WIDER THAN `usize` ON PURPOSE. A RAR 5 distance slot
/// carries up to 31 extra bits, so the largest value this ladder produces is
/// `(3 << 31) | (2^31 - 1)` plus one = 2^33 - thirty-four bits, which does
/// not fit a 32-bit `usize` and does not fit a `u32` either (hence the
/// `u32::try_from(distance)` the tape path already does on the way out).
/// Computed in `usize` it wrapped on a 32-bit target and then panicked on
/// the `+ 1`: `attempt to add with overflow`, nightly armv7-cross run
/// 33737735769, which compiles with `overflow-checks` on for exactly this
/// class. In release it would have wrapped silently to a small distance and
/// mis-decoded the match instead, which is the worse half.
///
/// Saturating rather than returning an error keeps this infallible and keeps
/// the two callers byte-identical, and it is the right answer rather than a
/// convenient one: `usize::MAX` cannot be inside any dictionary a 32-bit
/// target can allocate, so `copy_match` rejects it as "RAR 5 match distance
/// exceeds dictionary" - which is precisely what an archive needing a >4 GiB
/// window IS on a 32-bit machine. On a 64-bit target nothing saturates and
/// every answer is unchanged.
#[inline]
fn distance_from_parts(slot: usize, bit_count: u8, extra: u32) -> usize {
    usize::try_from(distance_wide(slot, bit_count, extra)).unwrap_or(usize::MAX)
}

/// The ladder before it is narrowed - the one place the expression is
/// written. `distance_slot_for_match` walks it in the encoding direction
/// and must stay on the same width, or the two halves disagree about
/// which slot a distance belongs to on a 32-bit target.
#[inline]
fn distance_wide(slot: usize, bit_count: u8, extra: u32) -> u64 {
    (((2u64 | (slot as u64 & 1)) << bit_count) | extra as u64) + 1
}

pub fn slot_to_distance(slot: usize, extra_bits: u32) -> Result<usize> {
    if slot < 4 {
        return Ok(slot + 1);
    }
    let bit_count = distance_slot_bit_count(slot)?;
    let max_extra = if bit_count == 32 {
        u32::MAX
    } else {
        (1u32 << bit_count) - 1
    };
    if extra_bits > max_extra {
        return Err(Error::InvalidData("RAR 5 distance extra bits exceed slot"));
    }
    Ok(distance_from_parts(slot, bit_count as u8, extra_bits))
}

// nzbfast-local change, 5 Sep 2026 — RAR5 encoder hot paths; see VENDORING.md.
// Encoding has a different lookup direction from decoding. Keep these
// symbol-indexed codes separate so decoder tables and caches do not grow.
struct EncoderTable {
    codes: Vec<(u16, u8)>,
}

impl EncoderTable {
    fn from_lengths(lengths: &[u8]) -> Result<Self> {
        let mut counts = [0u16; 16];
        for &length in lengths {
            if length > 15 {
                return Err(Error::InvalidData("RAR 5 Huffman length is too large"));
            }
            if length != 0 {
                counts[length as usize] += 1;
            }
        }
        validate_huffman_counts(&counts)?;
        let mut next_code = [0u16; 16];
        let mut code = 0;
        for len in 1..=15 {
            code = (code + counts[len - 1]) << 1;
            next_code[len] = code;
        }
        let mut codes = vec![(0, 0); lengths.len()];
        for (symbol, &length) in lengths.iter().enumerate() {
            if length != 0 {
                u16::try_from(symbol)
                    .map_err(|_| Error::InvalidData("RAR 5 Huffman symbol is too large"))?;
                codes[symbol] = (next_code[length as usize], length);
                next_code[length as usize] += 1;
            }
        }
        Ok(Self { codes })
    }

    fn code_for_symbol(&self, symbol: usize) -> Result<(u16, u8)> {
        self.codes
            .get(symbol)
            .copied()
            .filter(|&(_, len)| len != 0)
            .ok_or(Error::InvalidData("RAR 5 missing Huffman symbol"))
    }
}

#[derive(Debug, Clone)]
pub struct HuffmanTable {
    // nzbfast-local change, 2 Sep 2026 - re-apply the compact canonical
    // symbol vector after the next rars re-sync; see VENDORING.md.
    // Symbol ids in canonical-code order. Code and length are implicit in
    // `first_code`, `first_index`, and `counts`; keeping them beside every
    // symbol made each entry 16 bytes on 64-bit targets.
    symbols: Vec<u16>,
    first_code: [u16; 16],
    first_index: [usize; 16],
    counts: [u16; 16],
    // Primary decode LUT: top LUT_BITS of the bitstream -> (symbol << 8) | code_len.
    // Bit 31 marks literal entries; bits 24..=30 can hold distance metadata;
    // a miss is exactly HUFF_LUT_MISS.
    lut: Vec<u32>,
}

// nzbfast-local change, 3 Sep 2026 - nine bits keep the primary decode table
// in 2 KiB per role while the rare wider codes use the outlined canonical
// fallback. See VENDORING.md.
const HUFF_LUT_BITS: usize = 9;

// Symbol ids occupy bits 8..=23 and code lengths the low byte. Marking every
// literal in the otherwise-unused top bit turns the burst's per-symbol
// `wrapping_sub` + shift + branch into one bit-test branch while preserving
// zero as the generic decoder's cheap miss sentinel. Masked symbol extraction
// still lowers to one bitfield instruction. (nzbfast-local change, 3 Sep 2026;
// see VENDORING.md.)
const HUFF_LUT_LITERAL_BIT: u32 = 1 << 31;
const HUFF_LUT_LENGTH_MASK: u32 = 0xff;
const HUFF_LUT_MISS: u32 = 0;

// A distance-only LUT build caches its validated extra-bit count in bits
// 24..=28 and marks an invalid slot in bit 30. The shared symbol extractor
// masks both away. (nzbfast-local change, 3 Sep 2026; see VENDORING.md.)
#[cfg(feature = "parallel")]
const HUFF_LUT_DISTANCE_BITS_SHIFT: u32 = 24;
#[cfg(feature = "parallel")]
const HUFF_LUT_DISTANCE_BITS_MASK: u32 = 0x1f;
#[cfg(feature = "parallel")]
const HUFF_LUT_DISTANCE_INVALID_BIT: u32 = 1 << 30;

/// Literal entries set bit 31; controls and the miss sentinel leave it clear.
/// RAR control symbols begin at 256. Every other table's symbols are below
/// that boundary and carry the bit too, but the shared canonical decoder masks
/// it during symbol extraction and otherwise ignores it.
#[inline(always)]
fn lut_entry_is_literal(entry: u32) -> bool {
    entry & HUFF_LUT_LITERAL_BIT != 0
}

#[inline(always)]
fn lut_entry_symbol(entry: u32) -> usize {
    ((entry >> 8) & u32::from(u16::MAX)) as usize
}

#[cfg(feature = "parallel")]
#[inline]
fn distance_lut_metadata(slot: u16) -> u32 {
    let slot = u32::from(slot);
    let bit_count = if slot < 4 { 0 } else { (slot - 2) >> 1 };
    if bit_count > 31 {
        HUFF_LUT_DISTANCE_INVALID_BIT
    } else {
        bit_count << HUFF_LUT_DISTANCE_BITS_SHIFT
    }
}

impl HuffmanTable {
    fn from_distance_lengths(lengths: &[u8]) -> Result<Self> {
        #[cfg(feature = "parallel")]
        {
            Self::from_lengths_impl::<true>(lengths)
        }
        #[cfg(not(feature = "parallel"))]
        {
            Self::from_lengths_impl::<false>(lengths)
        }
    }

    pub fn from_lengths(lengths: &[u8]) -> Result<Self> {
        Self::from_lengths_impl::<false>(lengths)
    }

    fn from_lengths_impl<const DISTANCE_LUT: bool>(lengths: &[u8]) -> Result<Self> {
        let mut count = [0u16; 16];
        for &length in lengths {
            if length > 15 {
                return Err(Error::InvalidData("RAR 5 Huffman length is too large"));
            }
            if length != 0 {
                count[length as usize] += 1;
            }
        }
        validate_huffman_counts(&count)?;

        let mut first_code = [0u16; 16];
        let mut next_code = [0u16; 16];
        let mut code = 0u16;
        for length in 1..=15 {
            code = (code + count[length - 1]) << 1;
            first_code[length] = code;
            next_code[length] = code;
        }

        let mut first_index = [0usize; 16];
        let mut index = 0usize;
        for length in 1..=15 {
            first_index[length] = index;
            index += usize::from(count[length]);
        }

        let mut symbols = vec![0u16; index];
        let mut next_index = first_index;
        let mut lut = vec![HUFF_LUT_MISS; 1 << HUFF_LUT_BITS];
        for (symbol, &length) in lengths.iter().enumerate() {
            if length == 0 {
                continue;
            }
            let symbol = u16::try_from(symbol)
                .map_err(|_| Error::InvalidData("RAR 5 Huffman symbol is too large"))?;
            let len = usize::from(length);
            let code = next_code[len];
            next_code[len] += 1;
            symbols[next_index[len]] = symbol;
            next_index[len] += 1;
            if len <= HUFF_LUT_BITS {
                let shift = HUFF_LUT_BITS - len;
                let start = usize::from(code) << shift;
                let class = if symbol < 256 {
                    HUFF_LUT_LITERAL_BIT
                } else {
                    0
                };
                #[cfg(feature = "parallel")]
                let metadata = if DISTANCE_LUT {
                    distance_lut_metadata(symbol)
                } else {
                    0
                };
                #[cfg(not(feature = "parallel"))]
                let metadata = 0;
                let entry = (u32::from(symbol) << 8) | class | metadata | u32::from(length);
                lut[start..start + (1 << shift)].fill(entry);
            }
        }
        Ok(Self {
            symbols,
            first_code,
            first_index,
            counts: count,
            lut,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Return the primary-LUT entry, or `HUFF_LUT_MISS` when fewer than 15
    /// bits remain or this code needs the canonical long-code fallback. The
    /// entry is not consumed here: keeping literal-vs-other classification in
    /// the burst preserves its single hot-path range branch, while the cold
    /// edge can consume and hand a short-code control straight to dispatch.
    #[inline(always)]
    fn peek_lut_entry(&self, bits: &mut BitReader<'_>) -> u32 {
        let Some(peek) = bits.peek15() else {
            return HUFF_LUT_MISS;
        };
        self.lut[usize::from(peek >> (15 - HUFF_LUT_BITS))]
    }

    #[inline]
    fn decode(&self, bits: &mut BitReader<'_>) -> Result<usize> {
        if let Some(peek) = bits.peek15() {
            let entry = self.lut[usize::from(peek >> (15 - HUFF_LUT_BITS))];
            if entry != HUFF_LUT_MISS {
                bits.consume((entry & HUFF_LUT_LENGTH_MASK) as u8);
                return Ok(lut_entry_symbol(entry));
            }
            return self.decode_long(peek, bits);
        }
        self.decode_slow(bits)
    }

    /// The distance table is consulted for every fully-resolved match in the
    /// parallel tape worker and in the parallel build's buffered/serial paths.
    /// Keep its common LUT-hit path in those callers while leaving unrelated
    /// decode sites outlined. (nzbfast-local change, 3 Sep 2026; see
    /// VENDORING.md.)
    #[cfg(feature = "parallel")]
    #[inline(always)]
    fn decode_distance_hot(&self, bits: &mut BitReader<'_>) -> Result<(usize, u8)> {
        if let Some(peek) = bits.peek15() {
            let entry = self.lut[usize::from(peek >> (15 - HUFF_LUT_BITS))];
            if entry != HUFF_LUT_MISS {
                bits.consume((entry & HUFF_LUT_LENGTH_MASK) as u8);
                if entry & HUFF_LUT_DISTANCE_INVALID_BIT != 0 {
                    return Err(Error::InvalidData("RAR 5 distance slot is too large"));
                }
                let bit_count =
                    ((entry >> HUFF_LUT_DISTANCE_BITS_SHIFT) & HUFF_LUT_DISTANCE_BITS_MASK) as u8;
                return Ok((lut_entry_symbol(entry), bit_count));
            }
            let slot = self.decode_long(peek, bits)?;
            return Ok((slot, slot_distance_bits(slot)?));
        }
        let slot = self.decode_slow(bits)?;
        Ok((slot, slot_distance_bits(slot)?))
    }

    /// Codes longer than the primary LUT use a canonical walk, kept out of
    /// line so the LUT hit above stays small enough to inline at every call
    /// site (a `perf` profile on an
    /// EPYC read this function as a CALL at 17% of a small-file set's CPU;
    /// research/RAR-PERF-AUDIT-2026-09-02.md, round 7).
    #[inline(never)]
    fn decode_long(&self, peek: u16, bits: &mut BitReader<'_>) -> Result<usize> {
        {
            // Codes longer than the primary LUT.
            for len in (HUFF_LUT_BITS + 1)..=15 {
                let count = self.counts[len];
                if count != 0 {
                    let code = peek >> (15 - len);
                    let offset = code.wrapping_sub(self.first_code[len]);
                    if offset < count {
                        bits.consume(len as u8);
                        let index = self.first_index[len] + usize::from(offset);
                        return Ok(usize::from(self.symbols[index]));
                    }
                }
            }
            Err(Error::InvalidData("RAR 5 invalid Huffman code"))
        }
    }

    // Bit-by-bit canonical walk, used only near the end of input where a
    // 15-bit peek is not available but a shorter valid code may still be.
    fn decode_slow(&self, bits: &mut BitReader<'_>) -> Result<usize> {
        if self.symbols.is_empty() {
            return Err(Error::InvalidData("RAR 5 empty Huffman table"));
        }
        let mut code = 0u16;
        for len in 1..=15 {
            code = (code << 1) | bits.read_bits(1)? as u16;
            let count = self.counts[len];
            if count != 0 {
                let first = self.first_code[len];
                let offset = code.wrapping_sub(first);
                if offset < count {
                    let index = self.first_index[len] + usize::from(offset);
                    return Ok(usize::from(self.symbols[index]));
                }
            }
        }
        Err(Error::InvalidData("RAR 5 invalid Huffman code"))
    }

    #[cfg(test)]
    fn code_for_symbol(&self, symbol: usize) -> Result<(u16, u8)> {
        let Some(index) = self
            .symbols
            .iter()
            .position(|&item| usize::from(item) == symbol)
        else {
            return Err(Error::InvalidData("RAR 5 missing Huffman symbol"));
        };
        for len in 1..=15 {
            let start = self.first_index[len];
            let end = start + usize::from(self.counts[len]);
            if index < end {
                debug_assert!(index >= start);
                return Ok((self.first_code[len] + (index - start) as u16, len as u8));
            }
        }
        unreachable!("canonical symbol index belongs to one length bucket")
    }
}

/// MSB-first bit reader with a 64-bit cache.
///
/// `cache` holds the next `cache_bits` unconsumed bits, MSB-aligned; bits
/// below the valid region are garbage. `refill` loads eight bytes at a time
/// but only advances `byte_pos` by whole bytes, so any partial-byte bits it
/// ORs in below the valid region are re-ORed with identical values on the
/// next refill (the source byte has not been consumed) — the cache stays
/// consistent without masking.
struct BitReader<'a> {
    input: &'a [u8],
    byte_pos: usize,
    cache: u64,
    cache_bits: u32,
}

impl<'a> BitReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            byte_pos: 0,
            cache: 0,
            cache_bits: 0,
        }
    }

    fn new_at(input: &'a [u8], bit_pos: usize) -> Self {
        let mut reader = Self {
            input,
            byte_pos: bit_pos / 8,
            cache: 0,
            cache_bits: 0,
        };
        let skip = (bit_pos % 8) as u32;
        if skip != 0 {
            reader.refill();
            reader.cache <<= skip;
            reader.cache_bits -= skip.min(reader.cache_bits);
        }
        reader
    }

    /// Absolute position in bits from the start of the input.
    #[inline]
    fn position(&self) -> usize {
        self.byte_pos * 8 - self.cache_bits as usize
    }

    #[inline]
    fn refill(&mut self) {
        if self.byte_pos + 8 <= self.input.len() {
            let word = u64::from_be_bytes(
                self.input[self.byte_pos..self.byte_pos + 8]
                    .try_into()
                    .unwrap(),
            );
            self.cache |= word >> self.cache_bits;
            let whole = (64 - self.cache_bits) & !7;
            self.byte_pos += (whole / 8) as usize;
            self.cache_bits += whole;
        } else {
            while self.cache_bits <= 56 && self.byte_pos < self.input.len() {
                self.cache |= u64::from(self.input[self.byte_pos]) << (56 - self.cache_bits);
                self.byte_pos += 1;
                self.cache_bits += 8;
            }
        }
    }

    /// Consume up to 32 cached bits.
    ///
    /// Keep the cache-hit path in the caller: match decoding invokes this for
    /// every length and distance operand, and returning `Result<u32>` through
    /// an out-of-line call otherwise also materializes its indirect ABI result
    /// on every hit. Refill and error handling stay outlined so forcing the
    /// common path inline does not duplicate the byte-tail refill ladder at
    /// every call site. (nzbfast-local change, 3 Sep 2026; see VENDORING.md.)
    #[inline(always)]
    fn read_bits(&mut self, count: u8) -> Result<u32> {
        let count = u32::from(count);
        if count == 0 {
            return Ok(0);
        }
        if count > 32 || self.cache_bits < count {
            return self.read_bits_refilled(count);
        }
        let value = (self.cache >> (64 - count)) as u32;
        self.cache <<= count;
        self.cache_bits -= count;
        Ok(value)
    }

    #[inline(never)]
    fn read_bits_refilled(&mut self, count: u32) -> Result<u32> {
        if count > 32 {
            return Err(Error::InvalidData("RAR 5 bit read is too wide"));
        }
        self.refill();
        if self.cache_bits < count {
            return Err(Error::NeedMoreInput);
        }
        let value = (self.cache >> (64 - count)) as u32;
        self.cache <<= count;
        self.cache_bits -= count;
        Ok(value)
    }

    /// Peek the next 15 bits MSB-first, or None if fewer than 15 bits remain.
    #[inline]
    fn peek15(&mut self) -> Option<u16> {
        if self.cache_bits < 15 {
            self.refill();
            if self.cache_bits < 15 {
                return None;
            }
        }
        Some((self.cache >> 49) as u16)
    }

    #[inline]
    fn consume(&mut self, count: u8) {
        debug_assert!(u32::from(count) <= self.cache_bits);
        self.cache <<= count;
        self.cache_bits -= u32::from(count);
    }
}

// nzbfast-local change, 5 Sep 2026 - batch literal Huffman codes (Codex's
// `rar5-emit` pass); see VENDORING.md. Each canonical code is at most 15 bits:
// pairs fit 30 bits and groups of four fit 60, which the bit writer below
// takes as two spills. No staging buffer; every starting bit offset and the
// final partial byte are the writer's business.
#[inline]
fn write_literal_codes(writer: &mut BitWriter, table: &EncoderTable, data: &[u8]) -> Result<()> {
    let literals = data;
    // Most literal runs between matches are one to three bytes (round 28 of
    // research/RAR-PERF-AUDIT-2026-09-02.md counted 97% at three or fewer on
    // the census shapes); they skip the four-code setup entirely.
    #[cfg(target_pointer_width = "64")]
    let literals = if literals.len() < 4 {
        literals
    } else {
        let mut chunks = literals.chunks_exact(4);
        for chunk in &mut chunks {
            let (a, a_len) = table.code_for_symbol(usize::from(chunk[0]))?;
            let (b, b_len) = table.code_for_symbol(usize::from(chunk[1]))?;
            let (c, c_len) = table.code_for_symbol(usize::from(chunk[2]))?;
            let (d, d_len) = table.code_for_symbol(usize::from(chunk[3]))?;
            let value = (((usize::from(a) << b_len) | usize::from(b)) << c_len) | usize::from(c);
            let value = (value << d_len) | usize::from(d);
            writer.write_bits(
                value,
                usize::from(a_len) + usize::from(b_len) + usize::from(c_len) + usize::from(d_len),
            );
        }
        chunks.remainder()
    };
    let mut pairs = literals.chunks_exact(2);
    for pair in &mut pairs {
        let (first, first_len) = table.code_for_symbol(usize::from(pair[0]))?;
        let (second, second_len) = table.code_for_symbol(usize::from(pair[1]))?;
        writer.write_bits(
            (usize::from(first) << second_len) | usize::from(second),
            usize::from(first_len) + usize::from(second_len),
        );
    }
    for &byte in pairs.remainder() {
        let (code, len) = table.code_for_symbol(usize::from(byte))?;
        writer.write_bits(usize::from(code), usize::from(len));
    }
    Ok(())
}

// nzbfast-local change, 5 Sep 2026 - the bit writer accumulates in a u64 and
// spills 32 bits at a time; see VENDORING.md. Codes and operands are at most
// 32 bits, and a wider write is split: fewer than 32 bits are live between
// calls and each chunk adds at most 32. Dead high bits need not be cleared;
// word/byte spills truncate them. The live suffix always fits in u64.
// nzbfast-local change, 5 Sep 2026 — inline non-recursive chunks and retain
// dead high bits; shift wide usize values through u64 for 32-bit portability.
// Measurements and the cross-build fix are in rar5-current-2026-09-05.
struct BitWriter {
    bytes: Vec<u8>,
    /// Total bits written, spilled or not.
    bit_pos: usize,
    acc: u64,
    acc_bits: u32,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            bit_pos: 0,
            acc: 0,
            acc_bits: 0,
        }
    }

    /// Continue a stream whose first `bit_pos` bits are already in `bytes`
    /// (the table data a block starts with); a partial last byte is taken
    /// back into the accumulator so the next write lands after its bits.
    fn continuing(mut bytes: Vec<u8>, bit_pos: usize) -> Self {
        debug_assert_eq!(bytes.len(), bit_pos.div_ceil(8));
        let used = (bit_pos & 7) as u32;
        let (acc, acc_bits) = if used == 0 {
            (0, 0)
        } else {
            let last = bytes.pop().unwrap_or(0);
            (u64::from(last >> (8 - used)), used)
        };
        Self {
            bytes,
            bit_pos,
            acc,
            acc_bits,
        }
    }

    #[inline]
    fn write_bits(&mut self, value: usize, count: usize) {
        if count == 0 {
            return;
        }
        if count > 32 {
            // Through u64: `usize >> 32` is a compile-time overflow on a
            // 32-bit target (the armv7 build), and there the high half is
            // zero anyway.
            self.write_chunk(((value as u64) >> 32) as usize, count - 32);
            self.write_chunk(value & 0xffff_ffff, 32);
        } else {
            self.write_chunk(value, count);
        }
    }

    #[inline(always)]
    fn write_chunk(&mut self, value: usize, count: usize) {
        debug_assert!((1..=32).contains(&count));
        let value = (value as u64) & ((1u64 << count) - 1);
        self.acc = (self.acc << count) | value;
        self.acc_bits += count as u32;
        self.bit_pos += count;
        if self.acc_bits >= 32 {
            let spill = self.acc_bits - 32;
            let word = (self.acc >> spill) as u32;
            self.bytes.extend_from_slice(&word.to_be_bytes());
            self.acc_bits = spill;
            // Only the low acc_bits bits are live; later spills truncate stale high bits.
        }
    }

    fn finish(mut self) -> Vec<u8> {
        while self.acc_bits >= 8 {
            self.acc_bits -= 8;
            self.bytes.push((self.acc >> self.acc_bits) as u8);
        }
        if self.acc_bits != 0 {
            self.bytes
                .push(((self.acc & ((1u64 << self.acc_bits) - 1)) << (8 - self.acc_bits)) as u8);
        }
        self.bytes
    }
}

fn validate_huffman_counts(count: &[u16; 16]) -> Result<()> {
    let mut available = 1i32;
    for &len_count in count.iter().skip(1) {
        available = (available << 1) - i32::from(len_count);
        if available < 0 {
            return Err(Error::InvalidData("RAR 5 oversubscribed Huffman table"));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LevelToken {
    symbol: usize,
    extra_bits: u8,
    extra_value: u8,
}

impl LevelToken {
    const fn plain(symbol: usize) -> Self {
        Self {
            symbol,
            extra_bits: 0,
            extra_value: 0,
        }
    }

    const fn repeat_previous_short(count: usize) -> Self {
        Self {
            symbol: 16,
            extra_bits: 3,
            extra_value: (count - 3) as u8,
        }
    }

    const fn repeat_previous_long(count: usize) -> Self {
        Self {
            symbol: 17,
            extra_bits: 7,
            extra_value: (count - 11) as u8,
        }
    }

    const fn zero_run_short(count: usize) -> Self {
        Self {
            symbol: 18,
            extra_bits: 3,
            extra_value: (count - 3) as u8,
        }
    }

    const fn zero_run_long(count: usize) -> Self {
        Self {
            symbol: 19,
            extra_bits: 7,
            extra_value: (count - 11) as u8,
        }
    }
}

fn encode_table_level_tokens(lengths: &[u8]) -> Vec<LevelToken> {
    let mut tokens = Vec::new();
    let mut pos = 0usize;
    let mut previous = None;
    while pos < lengths.len() {
        let value = lengths[pos];
        let mut run = 1usize;
        while pos + run < lengths.len() && lengths[pos + run] == value {
            run += 1;
        }

        if value == 0 {
            emit_zero_level_run(&mut tokens, run);
            previous = Some(0);
            pos += run;
            continue;
        }

        if previous == Some(value) && run >= 3 {
            emit_repeat_level_run(&mut tokens, run);
            pos += run;
            continue;
        }

        tokens.push(LevelToken::plain(value as usize));
        previous = Some(value);
        pos += 1;
    }
    tokens
}

fn emit_repeat_level_run(tokens: &mut Vec<LevelToken>, mut run: usize) {
    while run != 0 {
        if run >= 11 {
            let mut chunk = run.min(138);
            if matches!(run - chunk, 1 | 2) && chunk >= 14 {
                chunk -= 3;
            }
            tokens.push(LevelToken::repeat_previous_long(chunk));
            run -= chunk;
        } else if run >= 3 {
            let chunk = run.min(10);
            tokens.push(LevelToken::repeat_previous_short(chunk));
            run -= chunk;
        } else {
            break;
        }
    }
}

fn emit_zero_level_run(tokens: &mut Vec<LevelToken>, mut run: usize) {
    while run != 0 {
        if run >= 11 {
            let mut chunk = run.min(138);
            if matches!(run - chunk, 1 | 2) && chunk >= 14 {
                chunk -= 3;
            }
            tokens.push(LevelToken::zero_run_long(chunk));
            run -= chunk;
        } else if run >= 3 {
            let chunk = run.min(10);
            tokens.push(LevelToken::zero_run_short(chunk));
            run -= chunk;
        } else {
            tokens.extend(std::iter::repeat_n(LevelToken::plain(0), run));
            break;
        }
    }
}

fn level_code_lengths_for_tokens(tokens: &[LevelToken]) -> [u8; LEVEL_TABLE_SIZE] {
    // Mark used level symbols, then normalise to a *complete* canonical code.
    // The pre-table is rebuilt by strict decoders (7-Zip's `k_BuildMode_Full`),
    // which reject an under-full table, so a uniform length assignment is only
    // valid when the used-symbol count is a power of two.
    let mut lengths = [0u8; LEVEL_TABLE_SIZE];
    for token in tokens {
        lengths[token.symbol] = 1;
    }
    huffman::assign_flat_complete_code(&mut lengths);
    lengths
}

fn write_level_lengths(writer: &mut BitWriter, lengths: &[u8; LEVEL_TABLE_SIZE]) {
    let mut pos = 0usize;
    while pos < LEVEL_TABLE_SIZE {
        let length = lengths[pos];
        if length == 0 {
            let mut count = 1usize;
            while pos + count < LEVEL_TABLE_SIZE && lengths[pos + count] == 0 {
                count += 1;
            }
            while count >= 3 {
                let chunk = count.min(17);
                writer.write_bits(15, 4);
                writer.write_bits(chunk - 2, 4);
                pos += chunk;
                count -= chunk;
            }
            for _ in 0..count {
                writer.write_bits(0, 4);
                pos += 1;
            }
        } else {
            writer.write_bits(usize::from(length), 4);
            if length == 15 {
                writer.write_bits(0, 4);
            }
            pos += 1;
        }
    }
}

#[cfg(test)]
/// Material whose regions do not all want the same tokenizer horizon:
/// phases of small-vocabulary text, fixed-width records and noise,
/// with long-range replays over them - the shape of the corpus the
/// choice was measured on, in miniature.
pub(crate) fn horizon_material(len: usize) -> Vec<u8> {
    const WORDS: [&[u8]; 8] = [
        b"alpha ",
        b"beta ",
        b"gamma delta ",
        b"epsilon ",
        b"zeta eta ",
        b"theta ",
        b"iota kappa ",
        b"lambda mu nu ",
    ];
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut out: Vec<u8> = Vec::with_capacity(len + 256 * 1024);
    while out.len() < len {
        match (out.len() / (300 * 1024)) % 3 {
            0 => {
                for _ in 0..8192 {
                    out.extend_from_slice(WORDS[(next() % 8) as usize]);
                }
            }
            1 => {
                for i in 0..4096u64 {
                    out.extend_from_slice(
                        format!("{:08x},{:012},record\n", i ^ (next() >> 40), i).as_bytes(),
                    );
                }
            }
            _ => {
                for _ in 0..4096 {
                    out.extend_from_slice(&next().to_le_bytes());
                }
            }
        }
        if out.len() > 300 * 1024 {
            let at = (next() as usize) % (out.len() - 200 * 1024);
            let replay = out[at..at + 60_000].to_vec();
            out.extend_from_slice(&replay);
        }
    }
    out.truncate(len);
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn borrowed_member_spans_match_owned_history_at_solid_seams() {
        let mut random = 73921u32;
        let data: Vec<u8> = (0..16384)
            .map(|i| {
                random ^= random << 13;
                random ^= random >> 17;
                random ^= random << 5;
                if i % 31 < 17 {
                    random as u8
                } else {
                    (i % 7) as u8
                }
            })
            .collect();
        let incoming = &data[100..4197];
        for history in [&[][..], incoming] {
            for dictionary in [0, 1, 4096, 16384, 32 << 20] {
                let tail = &history[history.len().saturating_sub(dictionary)..];
                for start in [0, 1, 4096, 8192] {
                    for candidates in [0, 16] {
                        for version in [0, 1] {
                            let options = EncodeOptions::new(candidates)
                                .with_max_match_distance(dictionary)
                                .with_lazy_matching(true);
                            let range = start..start + 4096;
                            let old_history = member_block_history(&data, tail, start, dictionary);
                            let mut old_events = Vec::new();
                            let old = encode_lz_block(
                                &data[range.clone()],
                                &old_history,
                                version,
                                &[],
                                options,
                                true,
                                Some(&mut |pos| {
                                    old_events.push(pos);
                                    true
                                }),
                            )
                            .unwrap();
                            let mut new_events = Vec::new();
                            let new = encode_member_block_borrowed(
                                &data,
                                tail,
                                range,
                                &[],
                                version,
                                options,
                                true,
                                Some(&mut |pos| {
                                    new_events.push(pos);
                                    true
                                }),
                                &mut EncoderScratch::default(),
                                None,
                                &[],
                            )
                            .unwrap();
                            assert_eq!(old, new);
                            assert_eq!(old_events, new_events);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn reverse_history_seed_preserves_candidate_order_and_future_insertions() {
        fn compare<P: MatchPosition>(a: &MatchIndex<P>, b: &MatchIndex<P>) {
            assert_eq!(a.depth(), b.depth());
            assert_eq!(a.counts.len(), b.counts.len());
            let depth = a.depth();
            for bucket in 0..a.counts.len() {
                let ac = a.counts[bucket];
                let bc = b.counts[bucket];
                let count = (ac as usize).min(depth);
                assert_eq!(count, (bc as usize).min(depth));
                let base = bucket << a.depth_bits;
                for back in 1..=count {
                    let ai = base | (ac.wrapping_sub(back as u32) as usize & (depth - 1));
                    let bi = base | (bc.wrapping_sub(back as u32) as usize & (depth - 1));
                    assert_eq!(a.slots[ai].position(), b.slots[bi].position());
                }
            }
        }
        fn check<P: MatchPosition>() {
            for budget in [1, 5, 16, 64] {
                for history_len in [0, 1, 2, 3, 4, 7, 15, 31, 64, 4097, 131073] {
                    for pattern in 0..3 {
                        let mut random = 719283u32;
                        let input: Vec<u8> = (0..history_len + 17)
                            .map(|i| {
                                random ^= random << 13;
                                random ^= random >> 17;
                                random ^= random << 5;
                                match pattern {
                                    0 => random as u8,
                                    1 => (i % 7) as u8,
                                    _ if i > history_len / 2 => 0,
                                    _ => random as u8,
                                }
                            })
                            .collect();
                        // A small table exercises both full and partial buckets,
                        // including early saturation, without large test allocations.
                        let mut forward = MatchIndex::<P>::new(1, budget);
                        let mut reverse = MatchIndex::<P>::new(1, budget);
                        insert_match_range(&input, 0..history_len, &mut forward);
                        reverse.seed_history_reverse(&input, history_len);
                        compare(&forward, &reverse);
                        let mut scalar = MatchIndex::<P>::new(1, budget);
                        let mut batched = MatchIndex::<P>::new(1, budget);
                        scalar.seed_history_reverse_scalar(&input, history_len);
                        batched.seed_history_reverse_batched(&input, history_len);
                        compare(&forward, &scalar);
                        compare(&forward, &batched);
                        for range in [history_len..history_len + 7, history_len + 7..input.len()] {
                            insert_match_range(&input, range.clone(), &mut forward);
                            insert_match_range(&input, range.clone(), &mut reverse);
                            insert_match_range(&input, range.clone(), &mut scalar);
                            insert_match_range(&input, range, &mut batched);
                            compare(&forward, &reverse);
                            compare(&forward, &scalar);
                            compare(&forward, &batched);
                        }
                        let mut forward = MatchIndex::<P>::new(1, budget);
                        let mut selected = MatchIndex::<P>::new(1, budget);
                        insert_match_range(&input, 0..history_len, &mut forward);
                        selected.seed_history(&input, history_len, None);
                        compare(&forward, &selected);
                    }
                }
            }
            // Include histories ending at the final possible prefix, where
            // the batched loader must peel a scalar tail before its u64 read.
            for history_len in (0..=16).chain([131073]) {
                for tail in 0..=7 {
                    let input: Vec<u8> = (0..history_len + tail).map(|i| (i * 17) as u8).collect();
                    let mut forward = MatchIndex::<P>::new(1, 16);
                    let mut reverse = MatchIndex::<P>::new(1, 16);
                    insert_match_range(&input, 0..history_len, &mut forward);
                    reverse.seed_history_reverse(&input, history_len);
                    compare(&forward, &reverse);
                }
            }
        }
        check::<u32>();
        check::<usize>();
    }


    /// [`encode_blocks_pooled`] must never park the thread that owns its
    /// scope while a block is still unclaimed, because that thread is a
    /// POOL thread at both of the writer's call sites (`rayon::join` in
    /// `rar50::write::volume`, `map_slice_collect` in the multi-group
    /// walk). Parking it holds a thread the `width` jobs it just spawned
    /// need in order to run at all, so N concurrent member encodes on an
    /// N-thread pool all park waiting for jobs none of them can run.
    ///
    /// FOUND IN CI, 11 Sep 2026, as a cap kill of `unit-one-process` with
    /// no failure reported: that job runs each unit binary bare, so
    /// libtest takes its thread count from the runner, and on a two-CPU
    /// runner exactly two tests run at once. nzbkit's two over-the-cap
    /// chase fixtures sit next to each other in registration order and
    /// both compress tens of megabytes, so when they aligned, both pool
    /// threads parked and the whole process wedged four tests in - 1,642
    /// of 1,646 tests never ran, for 31 minutes, at near-zero CPU, until
    /// the job's own timeout killed it. The 5 ms poll on the park is why
    /// it reads as a hang rather than a wedge.
    ///
    /// Two threads is the smallest pool that shows it and the one CI had.
    /// `recv_timeout` rather than `join` IS the assertion: a join would
    /// simply hang this suite and read as a wedge of its own. The payload
    /// must COMPRESS - `should_store_compressed_payload` has a sampled
    /// fast path that returns before the encoder on incompressible input,
    /// and the first cut of this test took it and passed over nothing -
    /// and must exceed `MAX_COMPRESSED_BLOCK_OUTPUT` so `width > 1` puts
    /// the walk on the pooled arm at all.
    ///
    /// Negative control: drop the owner's `encode_one` arm from the drain
    /// loop and this fails on the first run, at the full timeout.
    #[cfg(feature = "parallel")]
    #[test]
    fn concurrent_member_encodes_never_starve_a_pool_of_their_own_size() {
        use std::sync::{Arc, Barrier, mpsc};
        let mut seed = 0x2545F491u64 | 1;
        let data: Arc<Vec<u8>> = Arc::new(
            (0..(12usize << 20))
                .map(|i| {
                    if i % 2 == 0 {
                        seed ^= seed << 13;
                        seed ^= seed >> 7;
                        seed ^= seed << 17;
                        (seed >> 24) as u8
                    } else {
                        0
                    }
                })
                .collect(),
        );
        let pool = Arc::new(
            rayon::ThreadPoolBuilder::new()
                .num_threads(2)
                .build()
                .unwrap(),
        );
        let barrier = Arc::new(Barrier::new(2));
        let (tx, rx) = mpsc::channel();
        for _ in 0..2 {
            let (pool, barrier, tx, data) =
                (pool.clone(), barrier.clone(), tx.clone(), data.clone());
            std::thread::spawn(move || {
                barrier.wait();
                let out = pool.install(|| {
                    crate::rar50::Rar50Writer::new(
                        crate::rar50::WriterOptions::default().with_compression_level(1),
                    )
                    .compressed_entries(&[crate::rar50::CompressedEntry {
                        name: b"F.bin",
                        data: &data,
                        mtime: None,
                        attributes: 0,
                        host_os: 0,
                    }])
                    .finish()
                });
                let _ = tx.send(out.map(|v| v.len()));
            });
        }
        drop(tx);
        for i in 0..2 {
            let got = rx.recv_timeout(std::time::Duration::from_secs(90)).unwrap_or_else(|_| {
                panic!("encode {i} never finished: the two-thread pool starved")
            });
            let packed = got.unwrap();
            assert!(
                packed < data.len(),
                "the payload must compress or the writer stores it and this \
                 test never reaches the pooled block walk: {packed} from {}",
                data.len()
            );
        }
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn owned_history_cost_bounds_large_dictionary_worker_count() {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(16)
            .build()
            .unwrap();
        pool.install(|| {
            // 16 threads: a 2 GiB budget over 72 MiB per borrowed-history
            // block, or 72 MiB plus the dictionary when history is copied.
            assert_eq!(encode_block_wave_width(128 << 10), 16);
            for dictionary in [64 << 20, 128 << 20, 256 << 20, 1 << 30] {
                assert_eq!(encode_block_wave_width_for_history(dictionary, false), 16);
            }
            assert_eq!(encode_block_wave_width(4 << 20), 16);
            assert_eq!(encode_block_wave_width(8 << 20), 16);
            assert_eq!(encode_block_wave_width(32 << 20), 16);
            assert_eq!(encode_block_wave_width(64 << 20), 15);
            assert_eq!(encode_block_wave_width(128 << 20), 10);
            assert_eq!(encode_block_wave_width(256 << 20), 6);
            assert_eq!(encode_block_wave_width(1 << 30), 1);
        });
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap();
        pool.install(|| assert_eq!(encode_block_wave_width(128 << 20), 1));
    }

    #[test]
    fn batched_match_insertions_preserve_slots_counts_and_candidates() {
        fn check<P: MatchPosition>() {
            let mut seed = 71329u32;
            for len in (0..=33).chain([63, 64, 65, 127, 128, 129]) {
                let input: Vec<u8> = (0..len)
                    .map(|i| {
                        seed ^= seed << 13;
                        seed ^= seed >> 17;
                        seed ^= seed << 5;
                        if len % 2 == 0 {
                            (i % 3) as u8
                        } else {
                            seed as u8
                        }
                    })
                    .collect();
                for budget in [1, 5, 16, 64, 256] {
                    let mut expected = MatchIndex::<P>::new(len, budget);
                    let mut observed = MatchIndex::<P>::new(len, budget);
                    for step in [1, 3, 4, 7, 16, 129] {
                        for start in (0..len).step_by(step) {
                            let end = (start + step).min(len);
                            for pos in start..end {
                                expected.insert(&input, pos);
                            }
                            insert_match_range(&input, start..end, &mut observed);
                            assert_eq!(expected.counts, observed.counts);
                        }
                        assert!(expected
                            .slots
                            .iter()
                            .zip(&observed.slots)
                            .all(|(a, b)| a.position() == b.position()));
                    }
                    for pos in 0..len.saturating_sub(3) {
                        assert_eq!(
                            expected.candidates(&input, pos).collect::<Vec<_>>(),
                            observed.candidates(&input, pos).collect::<Vec<_>>()
                        );
                    }
                }
            }
        }
        check::<u32>();
        check::<usize>();
    }

    use super::*;

    #[test]
    fn bit_writer_preserves_low_live_bits_across_many_spills() {
        let mut seed = 0x517c_a931u32;
        for offset in 0..8 {
            let mut writer = BitWriter::new();
            let mut reference = Vec::new();
            let mut pos = 0usize;
            let mut emit = |writer: &mut BitWriter, value: usize, count: usize| {
                writer.write_bits(value, count);
                for shift in (0..count).rev() {
                    if pos.is_multiple_of(8) {
                        reference.push(0);
                    }
                    *reference.last_mut().unwrap() |=
                        (((value >> shift) & 1) as u8) << (7 - pos % 8);
                    pos += 1;
                }
                assert_eq!(writer.bit_pos, pos);
            };
            emit(&mut writer, usize::MAX, offset);
            for index in 0..4096 {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                let value = (seed as usize).wrapping_mul(0x9e37_79b1usize);
                let width = if index % 3 == 0 {
                    usize::BITS as usize
                } else {
                    seed as usize % (usize::BITS as usize + 1)
                };
                emit(&mut writer, value, width);
            }
            assert_eq!(writer.finish(), reference);
        }
    }
    #[test]
    #[cfg(feature = "parallel")]
    fn block_wave_without_progress_matches_reporting_path() {
        let data: Vec<u8> = (0..MAX_COMPRESSED_BLOCK_OUTPUT + 513)
            .map(|i| (i % 251) as u8)
            .collect();
        let history = vec![0x71; 97];
        let options = EncodeOptions::new(0).with_max_match_distance(128);
        for algorithm in [0, 1, 255] {
            let direct = encode_lz_member_blocks_in_waves(
                &data,
                &history,
                algorithm,
                options,
                None,
                2,
                MemberWindow::whole(),
                &EncoderScratchPool::new(),
            );
            let reporting = encode_lz_member_blocks_in_waves(
                &data,
                &history,
                algorithm,
                options,
                Some(&mut |_| true),
                2,
                MemberWindow::whole(),
                &EncoderScratchPool::new(),
            );
            match (direct, reporting) {
                (Ok(a), Ok(b)) => assert_eq!(a, b),
                (Err(a), Err(b)) => assert_eq!(format!("{a:?}"), format!("{b:?}")),
                _ => panic!("progress changed the wave result"),
            }
        }
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn flat_literal_match_pairs_preserve_ring_bytes_and_state_at_boundaries() {
        let tables = std::sync::Arc::new(LazyDecodeTables::new(TableLengths {
            main: vec![1, 1],
            distance: vec![1, 1],
            align: vec![4; ALIGN_TABLE_SIZE],
            length: vec![1, 1],
        }));
        let seed: Vec<u8> = (0..32).collect();
        for literal_len in [0, 1, 3, 16, 17] {
            for length in [2, 16, 64, 65] {
                for distance in [0, 1, 15, 16, 32, 33, 127, 129] {
                    for limit in [
                        0,
                        literal_len,
                        literal_len + length - 1,
                        literal_len + length,
                        256,
                    ] {
                        let make_tape = || BlockTape {
                            seq: 0,
                            tables: tables.clone(),
                            payload: Vec::new(),
                            payload_bits: 0,
                            lits: vec![0xa5; literal_len + 64],
                            ops: vec![
                                TapeOp::lits(literal_len as u32),
                                TapeOp::match_at(distance as u32, length as u32),
                                TapeOp::lits(64),
                            ],
                            filters: Vec::new(),
                            resume_bit: None,
                            tail_error: Some(Error::NeedMoreInput),
                        };
                        let mut ring = StreamingOutput::new(seed.clone(), 0, limit, 128, 128);
                        let mut flat = FlatOutput::new_seeded(&seed, limit, 128, 128);
                        let mut ring_decoder = Rar50Decoder::new();
                        let mut flat_decoder = Rar50Decoder::new();
                        let mut sink = |_: DecodedChunk<'_>| Ok::<_, std::convert::Infallible>(());
                        let ring_result =
                            ring_decoder.apply_tape(&mut make_tape(), &mut ring, limit, &mut sink);
                        let flat_result = flat_decoder.apply_tape_flat(
                            &mut make_tape(),
                            &mut flat,
                            limit,
                            &mut sink,
                        );
                        let classify = |result: std::result::Result<
                            TapeApplied,
                            StreamDecodeError<std::convert::Infallible>,
                        >| {
                            match result {
                                Ok(outcome) => Ok(matches!(outcome, TapeApplied::OutputDone)),
                                Err(StreamDecodeError::Decode(error)) => Err(Some(error)),
                                Err(StreamDecodeError::FilteredMember) => Err(None),
                                Err(StreamDecodeError::Sink(never)) => match never {},
                            }
                        };
                        assert_eq!(classify(flat_result), classify(ring_result));
                        assert_eq!(flat.written(), ring.written());
                        assert_eq!(&flat.buf[..flat.pos], &ring.ring[..ring.head]);
                        assert_eq!(flat_decoder.reps, ring_decoder.reps);
                        assert_eq!(flat_decoder.previous_match_length, ring_decoder.previous_match_length);
                    }
                }
            }
        }
    }

    /// Three blocks of one member (the third a few KiB), with incoming solid
    /// history: the serial walk (wave width one) and a wave holding every
    /// block must produce the same bytes, and the stream must decode.
    fn member_block_fixture() -> (Vec<u8>, Vec<u8>) {
        let mut seed = 0x2545_f491u32;
        let mut noise = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed
        };
        let history: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect();
        let data: Vec<u8> = (0..2 * MAX_COMPRESSED_BLOCK_OUTPUT + 4096)
            .map(|i| {
                let region = (i / 20_000) % 4;
                match region {
                    0 => (i * 7 % 251) as u8,
                    1 => noise() as u8,
                    2 => b"the quick brown fox jumps over the lazy dog "[i % 44],
                    _ => (i / 3 % 256) as u8,
                }
            })
            .collect();
        (history, data)
    }

    #[test]
    fn member_blocks_encode_identically_serially_and_in_a_wave() {
        let (history, data) = member_block_fixture();
        let options = EncodeOptions::new(16).with_max_match_distance(200_000);
        let serial = encode_lz_member_blocks_in_waves(
            &data,
            &history,
            0,
            options,
            None,
            1,
            MemberWindow::whole(),
            &EncoderScratchPool::new(),
        )
        .unwrap();
        for wave in [2, 3, 8] {
            let waved = encode_lz_member_blocks_in_waves(
                &data,
                &history,
                0,
                options,
                None,
                wave,
                MemberWindow::whole(),
                &EncoderScratchPool::new(),
            )
            .unwrap();
            assert_eq!(waved, serial, "wave width {wave}");
        }
        let without_history = encode_lz_member_blocks_in_waves(
            &data,
            &[],
            0,
            options,
            None,
            3,
            MemberWindow::whole(),
            &EncoderScratchPool::new(),
        )
        .unwrap();
        assert_eq!(
            Rar50Decoder::new()
                .decode_member(&without_history, 0, data.len(), false, DecodeMode::Lz)
                .unwrap(),
            data
        );
    }

    #[test]
    fn member_block_waves_report_monotone_progress_and_honour_cancellation() {
        let (history, data) = member_block_fixture();
        // The pooled workers continuously take new blocks; there is no barrier
        // between waves. They may finish before the coordinator is scheduled,
        // so a single final report is valid there. The serial walk necessarily
        // reports intermediate checkpoints between blocks.
        let options = EncodeOptions::new(16).with_max_match_distance(200_000);
        for wave in [1, 3] {
            let mut events = Vec::new();
            encode_lz_member_blocks_in_waves(
                &data,
                &history,
                0,
                options,
                Some(&mut |position| {
                    events.push(position);
                    true
                }),
                wave,
                MemberWindow::whole(),
                &EncoderScratchPool::new(),
            )
            .unwrap();
            assert!(
                events.windows(2).all(|pair| pair[0] <= pair[1]),
                "wave {wave}: progress went backwards: {events:?}"
            );
            assert_eq!(events.last(), Some(&data.len()), "wave {wave}");
            assert!(
                events.iter().all(|&position| position <= data.len()),
                "wave {wave}: progress exceeded the member length: {events:?}"
            );
            if wave == 1 {
                assert!(
                    events
                        .iter()
                        .any(|&position| position > 0 && position < data.len()),
                    "serial walk: no intermediate progress was reported"
                );
            }
            // Refusing at the first report that shows real progress cancels the
            // encode; no report may follow the refusal.
            let mut calls = 0usize;
            let mut refused_at = None;
            let result = encode_lz_member_blocks_in_waves(
                &data,
                &history,
                0,
                options,
                Some(&mut |position| {
                    calls += 1;
                    assert!(refused_at.is_none(), "reported after refusing");
                    if position > 0 {
                        refused_at = Some(calls);
                        return false;
                    }
                    true
                }),
                wave,
                MemberWindow::whole(),
                &EncoderScratchPool::new(),
            );
            assert!(
                matches!(result, Err(Error::Cancelled)),
                "wave {wave}: {result:?}"
            );
            assert!(refused_at.is_some(), "wave {wave}");
        }
    }

    #[test]
    fn batched_literal_codes_match_scalar_writes_at_all_widths_and_offsets() {
        let mut cases = Vec::new();
        for width in 1..=15 {
            cases.push(vec![width; (1usize << width).min(256)]);
        }
        // A complete, deep tree supplies codes with high bits set, including
        // 15-bit codes; uniform long-code tables alone have small code values.
        let mut deep: Vec<u8> = (1..=14).collect();
        deep.extend_from_slice(&[15, 15]);
        cases.push(deep);
        for lengths in cases {
            let table = EncoderTable::from_lengths(&lengths).unwrap();
            for offset in 0..8 {
                for count in 0..=33 {
                    let input: Vec<u8> = (0..count)
                        .map(|i| ((i * 7 + count) % lengths.len()) as u8)
                        .collect();
                    let mut batched = BitWriter::new();
                    let mut scalar = BitWriter::new();
                    batched.write_bits(0x55, offset);
                    scalar.write_bits(0x55, offset);
                    write_literal_codes(&mut batched, &table, &input).unwrap();
                    for byte in input {
                        let (code, len) = table.code_for_symbol(usize::from(byte)).unwrap();
                        scalar.write_bits(usize::from(code), usize::from(len));
                    }
                    assert_eq!(batched.bit_pos, scalar.bit_pos);
                    assert_eq!(batched.finish(), scalar.finish());
                }
            }
        }
    }

    #[test]
    fn bit_writer_continues_a_partial_byte() {
        let mut first = BitWriter::new();
        first.write_bits(0b101, 3);
        let bits = first.bit_pos;
        let mut writer = BitWriter::continuing(first.finish(), bits);
        writer.write_bits(0x1abc, 13);
        writer.write_bits(0xffff_ffff, 32);
        writer.write_bits(1, 1);
        assert_eq!(writer.bit_pos, 49);
        let mut reference = BitWriter::new();
        reference.write_bits(0b101, 3);
        reference.write_bits(0x1abc, 13);
        reference.write_bits(0xffff_ffff, 32);
        reference.write_bits(1, 1);
        let expected = reference.finish();
        assert_eq!(writer.finish(), expected);
        assert_eq!(expected, vec![0xba, 0xbc, 0xff, 0xff, 0xff, 0xff, 0x80]);
    }

    #[test]
    fn literal_runs_keep_token_storage_compact() {
        assert_eq!(
            std::mem::size_of::<EncodeToken>(),
            2 * std::mem::size_of::<usize>()
        );
        let input = vec![b'x'; 65536];
        let tokens = encode_tokens(&input, &[], EncodeOptions::new(0), DISTANCE_TABLE_SIZE_50);
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].distance, 0);
        assert_eq!(tokens[0].length, input.len());
    }

    #[test]
    fn disabled_match_search_preserves_progress_and_cancellation() {
        for size in [0, 1, 1024 * 1024 + 1, 2 * 1024 * 1024 + 3] {
            let input = vec![b'x'; size];
            let expected: Vec<_> = (1..=size).step_by(1024 * 1024).chain([size]).collect();
            for options in [
                EncodeOptions::new(0),
                EncodeOptions::new(16).with_max_match_distance(0),
            ] {
                let mut events = Vec::new();
                let tokens = encode_tokens_with_progress(
                    &input,
                    b"history",
                    options,
                    64,
                    Some(&mut |n| {
                        events.push(n);
                        true
                    }),
                )
                .unwrap();
                assert_eq!(events, expected);
                assert_eq!(tokens.len(), usize::from(size != 0));
                for stop in 1..=expected.len() {
                    let mut events = Vec::new();
                    let result = encode_tokens_with_progress(
                        &input,
                        b"history",
                        options,
                        64,
                        Some(&mut |n| {
                            events.push(n);
                            events.len() != stop
                        }),
                    );
                    assert!(matches!(result, Err(Error::Cancelled)));
                    assert_eq!(events, expected[..stop]);
                }
            }
        }
    }

    #[test]
    fn encoder_output_matches_pre_optimization_mixed_stream() {
        let mut seed = 12345u32;
        let data: Vec<u8> = (0..65536)
            .map(|i| {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                if i % 4096 < 2048 {
                    seed as u8
                } else if i % 8192 < 4096 {
                    (i % 251) as u8
                } else {
                    65
                }
            })
            .collect();
        let sixteen = encode_lz_member_with_options(&data, 0, EncodeOptions::new(16)).unwrap();
        let none = encode_lz_member_with_options(&data, 0, EncodeOptions::new(0)).unwrap();
        let filtered = Rar50Encoder::with_options(EncodeOptions::new(16))
            .encode_member_with_filters(
                &data,
                0,
                &[
                    Rar50FilterSpec::range(Rar50FilterKind::E8, 0..data.len() / 2),
                    Rar50FilterSpec::range(
                        Rar50FilterKind::Delta { channels: 4 },
                        data.len() / 2..data.len(),
                    ),
                ],
            )
            .unwrap();
        let observed = [&sixteen, &none, &filtered].map(|p| (p.len(), crc32fast::hash(p)));
        // Captured with the encoder before the September 5 creation changes:
        // (33143, 0x2269afd4), (56053, 0x213b0e1e), (33603, 0x6d15eed4). Re-pinned
        // the same day twice: for literal-run acceleration (see
        // LITERAL_SKIP_STRENGTH; the fixture's 2 KiB random regions run past 32
        // literals, so their probes thin out: 33156 and 33396), then for the
        // flat ring match index (`MatchIndex`; a 4-byte hash reaches different
        // candidates on this fixture: +9 and +68 bytes here, -2.4% to -13% on
        // the 8 MiB corpora). The zero-candidate stream is one literal run
        // either way. Re-pinned 7 Sep 2026 for the filtered stream only
        // (33464 -> 33463): its two records are now written just before the
        // token that reaches each, as an offset from there, rather than
        // both at the head of the block.
        assert_eq!(
            observed,
            [
                (33165, 0x8a06cda4),
                (56053, 0x213b0e1e),
                (33463, 0x8e690b21)
            ],
            "packed (length, crc32) of the 16-candidate, zero-candidate and filtered streams"
        );
    }

    #[test]
    fn encoder_table_matches_canonical_decoder_codes() {
        let mut seed = 0x12345678u32;
        let mut tables = vec![
            vec![],
            vec![0; 306],
            vec![1],
            vec![1, 1],
            vec![8; 256],
            vec![15; 306],
            vec![1, 1, 1],
            vec![16],
        ];
        for size in [20, 44, 64, 80, 256, 306] {
            for _ in 0..12 {
                let frequencies: Vec<_> = (0..size)
                    .map(|_| {
                        seed ^= seed << 13;
                        seed ^= seed >> 17;
                        seed ^= seed << 5;
                        (seed % 1000) as usize
                    })
                    .collect();
                tables.push(huffman::complete_lengths_for_frequencies(&frequencies, 15));
            }
        }
        let mut oversized = vec![0; 65537];
        oversized[65536] = 1;
        tables.push(oversized);
        for lengths in tables {
            match (
                EncoderTable::from_lengths(&lengths),
                HuffmanTable::from_lengths(&lengths),
            ) {
                (Ok(encode), Ok(decode)) => {
                    for symbol in 0..lengths.len() + 2 {
                        assert_eq!(
                            encode.code_for_symbol(symbol),
                            decode.code_for_symbol(symbol)
                        );
                    }
                }
                (Err(a), Err(b)) => assert_eq!(a, b),
                _ => panic!("encoder and decoder disagree on table validity"),
            }
        }
    }

    #[test]
    fn byte_bit_writer_matches_bitwise_reference_at_all_widths_and_offsets() {
        fn reference(bytes: &mut Vec<u8>, pos: &mut usize, value: usize, count: usize) {
            for shift in (0..count).rev() {
                if (*pos).is_multiple_of(8) {
                    bytes.push(0);
                }
                let last = bytes.len() - 1;
                bytes[last] |= (((value >> shift) & 1) as u8) << (7 - *pos % 8);
                *pos += 1;
            }
        }
        for offset in 0..8 {
            for width in 0..=usize::BITS as usize {
                for value in [0, 1, usize::MAX, usize::MAX / 3, 0x13579bdf] {
                    let mut writer = BitWriter::new();
                    let mut bytes = Vec::new();
                    let mut pos = 0;
                    for (v, n) in [
                        (0x55, offset),
                        (value, width),
                        (0xab, 8),
                        (value.reverse_bits(), width),
                        (3, 2),
                    ] {
                        writer.write_bits(v, n);
                        reference(&mut bytes, &mut pos, v, n);
                        assert_eq!(writer.bit_pos, pos);
                    }
                    assert_eq!(writer.finish(), bytes);
                }
            }
        }
    }

    #[test]
    fn inverse_encoder_slots_match_linear_reference() {
        for length in (0..=8192).chain([usize::MAX]) {
            assert_eq!(
                length_slot_for_match(length),
                reference_length_slot(length),
                "length {length}"
            );
        }
        let mut distances: Vec<usize> = (0..=1024).collect();
        for slot in 0..if usize::BITS == 64 { 66 } else { 60 } {
            if let Ok(base) = slot_to_distance(slot, 0) {
                distances.extend([base - 1, base, base + 1]);
                let bits = distance_slot_bit_count(slot).unwrap();
                if let Some(end) = base.checked_add((1usize << bits) - 1) {
                    distances.extend([end - 1, end]);
                    if let Some(next) = end.checked_add(1) {
                        distances.push(next);
                    }
                }
            }
        }
        #[cfg(target_pointer_width = "64")]
        distances.extend([1usize << 33, 1usize << 40, usize::MAX]);
        for size in [0, 1, 4, 5, 16, 32, 64, 66, 80] {
            for &distance in &distances {
                assert_eq!(
                    distance_slot_for_match(distance, size),
                    reference_distance_slot(distance, size),
                    "distance {distance}, table {size}"
                );
            }
        }
    }

    #[test]
    fn match_index_yields_a_buckets_newest_insertions_first_and_no_more_than_its_depth() {
        let input: Vec<u8> = b"abcd".iter().copied().cycle().take(1000).collect();
        for budget in [1, 5, 8, 64, 256] {
            let mut index = MatchIndex::<u32>::new(input.len(), budget);
            let depth = budget.max(1).next_power_of_two().clamp(4, 64);
            assert_eq!(index.depth(), depth, "budget {budget}");
            for pos in 0..40 {
                index.insert(&input, pos);
            }
            // Positions 0, 4, 8, ... share the prefix "abcd"; ten were inserted.
            let seen: Vec<usize> = index.candidates(&input, 40).collect();
            let expected: Vec<usize> = (0..10).rev().map(|i| i * 4).take(depth).collect();
            assert_eq!(seen, expected, "budget {budget}");
            // Positions with fewer than four bytes after them are not indexed.
            let mut tail = MatchIndex::<usize>::new(input.len(), 8);
            tail.insert(&input, input.len() - 4);
            tail.insert(&input, input.len() - 3);
            assert_eq!(
                tail.candidates(&input, 0).collect::<Vec<_>>(),
                vec![input.len() - 4]
            );
        }
        // A tiny input still gets the minimum table; a large one is capped.
        assert_eq!(
            MatchIndex::<u32>::new(10, 16).counts.len(),
            MATCH_INDEX_MIN_BUCKETS
        );
        assert_eq!(
            MatchIndex::<u32>::new(1 << 30, 16).counts.len(),
            MATCH_INDEX_MAX_BUCKETS
        );
    }

    #[test]
    fn prefix_match_filter_preserves_candidate_limits_and_repeat_choices() {
        let mut seed = 12345u32;
        for alphabet in [2, 17, 256] {
            let mut input: Vec<u8> = (0..1536)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    (seed % alphabet) as u8
                })
                .collect();
            input.extend_from_within(..512);
            let mut buckets = MatchIndex::<usize>::new(input.len(), 16);
            let prices = LiteralPrices::new(&input, 0);
            for pos in 0..input.len() {
                for cap in [0, 1, 4, 16] {
                    let options = EncodeOptions::new(cap).with_max_match_distance(1024);
                    let state = EncoderMatchState {
                        reps: [1, 2, 17, 1536],
                        ..Default::default()
                    };
                    assert_eq!(
                        best_match(
                            &input,
                            pos,
                            input.len(),
                            &buckets,
                            options,
                            &state,
                            64,
                            &prices
                        ),
                        reference_best_match(
                            &input,
                            pos,
                            input.len(),
                            &buckets,
                            options,
                            &state,
                            64,
                            &prices,
                        ),
                        "alphabet {alphabet}, pos {pos}, cap {cap}"
                    );
                }
                buckets.insert(&input, pos);
            }
        }
    }

    fn reference_length_slot(length: usize) -> Result<(usize, usize)> {
        if length < 2 {
            return Err(Error::InvalidData("RAR 5 match length is too short"));
        }
        for slot in 0..LENGTH_TABLE_SIZE {
            let bit_count = usize::from(length_slot_extra_bits(slot)?);
            let base = match_length_for_slot(slot, 0)?;
            let max = base
                + if bit_count == 0 {
                    0
                } else {
                    (1usize << bit_count) - 1
                };
            if length >= base && length <= max {
                return Ok((slot, length - base));
            }
        }
        Err(Error::InvalidData("RAR 5 match length is too long"))
    }

    fn reference_distance_slot(distance: usize, distance_size: usize) -> Result<(usize, usize)> {
        if distance == 0 {
            return Err(Error::InvalidData("RAR 5 match distance is zero"));
        }
        for slot in 0..distance_size {
            let bit_count = distance_slot_bit_count(slot)?;
            let base = slot_to_distance(slot, 0)?;
            let max = base
                + if bit_count == 0 {
                    0
                } else {
                    (1usize << bit_count) - 1
                };
            if distance >= base && distance <= max {
                return Ok((slot, distance - base));
            }
        }
        Err(Error::InvalidData("RAR 5 match distance is too large"))
    }

    // The differential reference for the match finder, written to take
    // the finder's own inputs one for one so the two can be read side by
    // side. Bundling them would break exactly that correspondence.
    #[allow(clippy::too_many_arguments)]
    fn reference_best_match(
        input: &[u8],
        pos: usize,
        end: usize,
        buckets: &MatchIndex<usize>,
        options: EncodeOptions,
        state: &EncoderMatchState,
        distance_size: usize,
        prices: &LiteralPrices,
    ) -> Option<MatchCandidate> {
        let max_distance = pos.min(options.max_match_distance);
        let max_length = (end - pos).min(MAX_ENCODER_MATCH_LENGTH);
        if options.max_match_candidates == 0
            || max_distance == 0
            || max_length < 4
            || pos + 3 >= input.len()
        {
            return None;
        }
        let mut best = None;
        let mut checked = 0usize;
        for distance in state.reps {
            if distance == 0 || distance > max_distance {
                continue;
            }
            let length = match_length(input, pos, distance, max_length);
            consider_match_candidate(
                &mut best,
                state,
                distance_size,
                length,
                distance,
                prices.bits(pos, length),
            );
        }
        for candidate in buckets.candidates(input, pos) {
            if candidate >= pos {
                continue;
            }
            let distance = pos - candidate;
            if distance > max_distance {
                break;
            }
            checked += 1;
            if let Some(best) = best {
                if input[candidate + best.length - 1] != input[pos + best.length - 1] {
                    if checked >= options.max_match_candidates {
                        break;
                    }
                    continue;
                }
            }
            let length = match_length(input, pos, distance, max_length);
            consider_match_candidate(
                &mut best,
                state,
                distance_size,
                length,
                distance,
                prices.bits(pos, length),
            );
            if let Some(best) = best {
                if best.length == max_length || best.length >= MATCH_NICE_LENGTH {
                    break;
                }
            }
            if checked >= options.max_match_candidates {
                break;
            }
        }
        best
    }

    /// The tape op's SHAPE is the optimisation, so it is worth an
    /// assertion rather than a comment. Before 3 Sep 2026 `TapeOp` was an
    /// enum whose widest variant carried a `RawFilter`, and the compiler
    /// assembled and re-read that aggregate with overlapping unaligned
    /// stack moves: a `perf` profile on an EPYC put 38% of the whole tape
    /// worker on the two instructions that consumed those store-forwarding
    /// stalls (research/RAR-PERF-AUDIT-2026-09-02.md, round 13). Giving
    /// the op a payload-carrying field again brings that back, quietly.
    #[cfg(feature = "parallel")]
    #[test]
    fn tape_op_is_a_flat_eight_byte_pod_and_round_trips_its_fields() {
        assert_eq!(std::mem::size_of::<TapeOp>(), 8);
        assert_eq!(std::mem::align_of::<TapeOp>(), 4);

        let lits = TapeOp::lits(TAPE_LITS_CAP as u32);
        assert_eq!(lits.kind(), tape_kind::LITS);
        assert_eq!(lits.length(), TAPE_LITS_CAP);

        // The widest match the format can express: length slot 43 with all
        // nine extra bits set, plus the distance bonus, at a distance the
        // 1 GiB window limit still allows.
        let widest_length = match_length_for_slot(LENGTH_TABLE_SIZE - 1, (1 << 9) - 1).unwrap() + 3;
        let matched = TapeOp::match_at(u32::MAX, widest_length as u32);
        assert_eq!(matched.kind(), tape_kind::MATCH);
        assert_eq!(matched.length(), widest_length);
        assert_eq!(matched.distance, u32::MAX);

        for index in 0..4u32 {
            let rep = TapeOp::rep(index, 7);
            assert_eq!(rep.kind(), tape_kind::REP);
            assert_eq!(rep.length(), 7);
            assert_eq!(rep.distance, index);
        }
        assert_eq!(TapeOp::rep_last().kind(), tape_kind::REP_LAST);
        assert_eq!(TapeOp::filter().kind(), tape_kind::FILTER);
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn lazy_decode_tables_borrows_the_cached_tables() {
        let lengths = TableLengths {
            main: vec![1, 1],
            distance: vec![1, 1],
            align: vec![4; ALIGN_TABLE_SIZE],
            length: vec![1, 1],
        };
        let tables = std::sync::Arc::new(DecodeTables::from_lengths(&lengths).unwrap());
        let lazy = LazyDecodeTables::prebuilt(std::sync::Arc::clone(&tables));
        assert_eq!(std::sync::Arc::strong_count(&tables), 2);

        for _ in 0..4 {
            let borrowed = lazy.get().unwrap();
            assert!(std::sync::Arc::ptr_eq(borrowed, &tables));
            assert_eq!(
                std::sync::Arc::strong_count(&tables),
                2,
                "a block-table lookup must not clone the nested Arc"
            );
        }
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn block_tape_returns_all_vector_capacities_for_reuse() {
        let lengths = TableLengths {
            main: vec![1, 1],
            distance: vec![1, 1],
            align: vec![4; ALIGN_TABLE_SIZE],
            length: vec![1, 1],
        };
        let tables = std::sync::Arc::new(LazyDecodeTables::prebuilt(std::sync::Arc::new(
            DecodeTables::from_lengths(&lengths).unwrap(),
        )));

        let mut payload = Vec::with_capacity(31);
        payload.extend_from_slice(&[0xaa, 0xbb]);
        let mut lits = Vec::with_capacity(23);
        lits.push(0xcc);
        let mut ops = Vec::with_capacity(17);
        ops.push(TapeOp::lits(1));
        let filters = Vec::with_capacity(11);
        let capacities = (
            payload.capacity(),
            lits.capacity(),
            ops.capacity(),
            filters.capacity(),
        );

        let mut tape = BlockTape {
            seq: 0,
            tables,
            payload,
            payload_bits: 16,
            lits,
            ops,
            filters,
            resume_bit: None,
            tail_error: None,
        };
        let buffers = tape.take_buffers();

        assert_eq!(
            (
                buffers.payload.capacity(),
                buffers.lits.capacity(),
                buffers.ops.capacity(),
                buffers.filters.capacity(),
            ),
            capacities
        );
        assert_eq!(buffers.payload, [0xaa, 0xbb]);
        assert_eq!(buffers.lits, [0xcc]);
        assert_eq!(buffers.ops.len(), 1);
        assert_eq!(tape.payload.capacity(), 0);
        assert_eq!(tape.lits.capacity(), 0);
        assert_eq!(tape.ops.capacity(), 0);
        assert_eq!(tape.filters.capacity(), 0);
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn tape_recycling_drops_oversized_capacity_bundles() {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let small = TapeBuffers {
            payload: Vec::with_capacity(1024),
            ..TapeBuffers::default()
        };
        let small_capacity = small.payload.capacity();
        small.recycle(&tx);
        assert_eq!(rx.try_recv().unwrap().payload.capacity(), small_capacity);

        let oversized = TapeBuffers {
            payload: Vec::with_capacity(TAPE_RECYCLE_BYTES_MAX + 1),
            ..TapeBuffers::default()
        };
        oversized.recycle(&tx);
        assert!(matches!(
            rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
    }

    /// The worker's slot ladder is two static tables now; they must agree
    /// with the functions the serial decoder and the encoder still use over
    /// every slot either table can produce (round 13).
    #[cfg(feature = "parallel")]
    #[test]
    fn worker_slot_tables_match_the_shared_slot_functions() {
        // The loop variable is the SLOT NUMBER, which is what both
        // tables are keyed on and what every assertion below passes to
        // the slot functions. `enumerate()` over one of the two tables
        // would name the same number after the value it happens to sit
        // beside, which is the wrong way round for a test that exists
        // to prove the two agree slot by slot.
        #[allow(clippy::needless_range_loop)]
        for slot in 0..LENGTH_TABLE_SIZE {
            assert_eq!(
                LENGTH_SLOT_EXTRA_BITS[slot],
                length_slot_extra_bits(slot).unwrap(),
                "length slot {slot}"
            );
            let extra = (1u32 << LENGTH_SLOT_EXTRA_BITS[slot]) - 1;
            assert_eq!(
                match_length_for_slot(slot, extra).unwrap(),
                if slot < 8 {
                    slot + 2
                } else {
                    (((4 | (slot & 3)) << LENGTH_SLOT_EXTRA_BITS[slot]) | extra as usize) + 2
                },
                "length slot {slot}"
            );
        }
        for slot in 0..DISTANCE_TABLE_SIZE_70 {
            match distance_slot_bit_count(slot) {
                Ok(bits) => {
                    assert_eq!(slot_distance_bits(slot).unwrap(), bits as u8, "slot {slot}");
                    let extra = if bits >= 32 {
                        u32::MAX
                    } else {
                        (1u32 << bits) - 1
                    };
                    assert_eq!(
                        slot_distance_value(slot, bits as u8, extra),
                        slot_to_distance(slot, extra).unwrap(),
                        "slot {slot}"
                    );
                }
                Err(_) => assert!(slot_distance_bits(slot).is_err(), "slot {slot}"),
            }
        }
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn fused_length_reads_match_reference_at_every_slot_and_bit_offset() {
        for slot in 0..LENGTH_TABLE_SIZE {
            let width = length_slot_extra_bits(slot).unwrap();
            for extra in 0..(1u32 << width) {
                for offset in 0..8 {
                    let mut writer = BitWriter::new();
                    writer.write_bits(0, offset);
                    writer.write_bits(extra as usize, usize::from(width));
                    let encoded = writer.finish();
                    let mut bits = BitReader::new_at(&encoded, offset);
                    assert_eq!(
                        read_slot_length(slot, &mut bits).unwrap() as usize,
                        match_length_for_slot(slot, extra).unwrap(),
                        "slot {slot}, extra {extra}, offset {offset}"
                    );
                    assert_eq!(bits.position(), offset + usize::from(width));
                }
            }
            if width != 0 {
                assert_eq!(
                    read_slot_length(slot, &mut BitReader::new(&[])),
                    Err(Error::NeedMoreInput)
                );
            }
        }
        let mut bits = BitReader::new(&[0xff; 8]);
        assert_eq!(
            read_slot_length(LENGTH_TABLE_SIZE, &mut bits),
            Err(Error::InvalidData("RAR 5 length slot is too large"))
        );
        assert_eq!(bits.position(), 0);
    }

    fn checksum(flags: u8, size_bytes: &[u8]) -> u8 {
        size_bytes
            .iter()
            .fold(0x5a ^ flags, |acc, &byte| acc ^ byte)
    }

    #[test]
    fn parses_one_byte_size_block_header() {
        let flags = 0xc7;
        let size = [3];
        let input = [flags, checksum(flags, &size), size[0], 0xaa, 0xbb, 0xcc];

        let block = parse_compressed_block(&input).unwrap();
        assert_eq!(block.header_len, 3);
        assert_eq!(block.payload, 3..6);
        assert_eq!(block.header.flags, flags);
        assert!(block.header.is_last);
        assert!(block.header.has_tables);
        assert_eq!(block.header.final_byte_bits, 8);
        assert_eq!(block.header.payload_size, 3);
        assert_eq!(block.header.payload_bits, 24);
    }

    #[test]
    fn parses_three_byte_size_block_header_with_partial_final_byte() {
        let flags = 0x94;
        let size = [0x34, 0x12, 0x00];
        let mut input = vec![flags, checksum(flags, &size), size[0], size[1], size[2]];
        input.resize(0x1234 + 5, 0);

        let block = parse_compressed_block(&input).unwrap();
        assert_eq!(block.header_len, 5);
        assert_eq!(block.payload, 5..0x1239);
        assert!(!block.header.is_last);
        assert!(block.header.has_tables);
        assert_eq!(block.header.final_byte_bits, 5);
        assert_eq!(block.header.payload_size, 0x1234);
        assert_eq!(block.header.payload_bits, (0x1234 - 1) * 8 + 5);
    }

    #[test]
    fn rejects_reserved_size_length_selector() {
        let input = [0x18, 0x42, 0x00];

        assert_eq!(
            parse_compressed_block(&input),
            Err(Error::InvalidData("RAR 5 block size length is invalid"))
        );
    }

    #[test]
    fn rejects_bad_block_header_checksum() {
        let input = [0xc7, 0x00, 0x03, 0xaa, 0xbb, 0xcc];

        assert_eq!(
            parse_compressed_block(&input),
            Err(Error::InvalidData("RAR 5 block header checksum mismatch"))
        );
    }

    #[test]
    fn rejects_truncated_block_payload() {
        let flags = 0xc7;
        let size = [3];
        let input = [flags, checksum(flags, &size), size[0], 0xaa, 0xbb];

        assert_eq!(parse_compressed_block(&input), Err(Error::NeedMoreInput));
    }

    #[test]
    fn reads_level_lengths_with_literal_fifteen() {
        let mut nibbles = vec![1, 2, 15, 0, 3, 4];
        nibbles.resize(LEVEL_TABLE_SIZE + 1, 0);

        let (lengths, bits) = read_level_lengths(&pack_nibbles(&nibbles)).unwrap();

        assert_eq!(&lengths[..6], &[1, 2, 15, 3, 4, 0]);
        assert_eq!(bits, LEVEL_TABLE_SIZE * 4 + 4);
    }

    #[test]
    fn reads_level_lengths_with_zero_run_at_current_position() {
        let mut nibbles = vec![7, 15, 3, 2];
        nibbles.resize(LEVEL_TABLE_SIZE - 3, 0);

        let (lengths, bits) = read_level_lengths(&pack_nibbles(&nibbles)).unwrap();

        assert_eq!(lengths[0], 7);
        assert_eq!(&lengths[1..6], &[0, 0, 0, 0, 0]);
        assert_eq!(lengths[6], 2);
        assert_eq!(bits, (LEVEL_TABLE_SIZE - 3) * 4);
    }

    fn pack_nibbles(nibbles: &[u8]) -> Vec<u8> {
        nibbles
            .chunks(2)
            .map(|chunk| {
                let high = chunk[0] & 0x0f;
                let low = chunk.get(1).copied().unwrap_or(0) & 0x0f;
                (high << 4) | low
            })
            .collect()
    }

    #[test]
    fn reads_rar50_second_level_table_lengths() {
        let mut writer = BitWriter::new();
        for _ in 0..LEVEL_TABLE_SIZE {
            writer.write_bits(5, 4);
        }
        for count in [138, 138, 138, 16] {
            writer.write_bits(19, 5);
            writer.write_bits(count - 11, 7);
        }
        let input = writer.finish();

        let (lengths, bits) = read_table_lengths(&input, 0).unwrap();

        assert_eq!(lengths.main.len(), MAIN_TABLE_SIZE);
        assert_eq!(lengths.distance.len(), DISTANCE_TABLE_SIZE_50);
        assert_eq!(lengths.align.len(), ALIGN_TABLE_SIZE);
        assert_eq!(lengths.length.len(), LENGTH_TABLE_SIZE);
        assert!(lengths.main.iter().all(|&length| length == 0));
        assert!(lengths.distance.iter().all(|&length| length == 0));
        assert!(lengths.align.iter().all(|&length| length == 0));
        assert!(lengths.length.iter().all(|&length| length == 0));
        assert_eq!(bits, LEVEL_TABLE_SIZE * 4 + 4 * (5 + 7));
    }

    #[test]
    fn reads_rar70_table_length_count() {
        assert_eq!(
            table_length_count(1).unwrap(),
            MAIN_TABLE_SIZE + DISTANCE_TABLE_SIZE_70 + ALIGN_TABLE_SIZE + LENGTH_TABLE_SIZE
        );
    }

    #[test]
    fn encoded_table_lengths_round_trip_with_bit_count() {
        let mut lengths = TableLengths {
            main: vec![0; MAIN_TABLE_SIZE],
            distance: vec![0; DISTANCE_TABLE_SIZE_50],
            align: vec![0; ALIGN_TABLE_SIZE],
            length: vec![0; LENGTH_TABLE_SIZE],
        };
        lengths.main[b'A' as usize] = 1;
        lengths.main[b'B' as usize] = 3;
        lengths.main[262] = 3;
        lengths.distance[1] = 1;
        lengths.align[0] = 4;
        lengths.length[0] = 1;

        let (encoded, bit_count) = encode_table_lengths_with_bit_count(&lengths, 0).unwrap();
        let (decoded, decoded_bits) = read_table_lengths(&encoded, 0).unwrap();

        assert_eq!(decoded, lengths);
        assert_eq!(decoded_bits, bit_count);
    }

    #[test]
    fn table_level_encoder_uses_rar5_run_symbols() {
        let mut lengths =
            vec![
                0u8;
                MAIN_TABLE_SIZE + DISTANCE_TABLE_SIZE_50 + ALIGN_TABLE_SIZE + LENGTH_TABLE_SIZE
            ];
        lengths[..4].fill(6);
        lengths[8..21].fill(0);

        let tokens = encode_table_level_tokens(&lengths);

        assert!(tokens.contains(&LevelToken::repeat_previous_short(3)));
        assert!(tokens.iter().any(|token| token.symbol == 19));
    }

    #[test]
    fn encoded_compressed_block_round_trips_header_fields() {
        let payload = [0xaa, 0xbb, 0xc0];
        let block = encode_compressed_block(&payload, 18, true, true).unwrap();

        let parsed = parse_compressed_block(&block).unwrap();

        assert_eq!(parsed.payload, 3..6);
        assert!(parsed.header.has_tables);
        assert!(parsed.header.is_last);
        assert_eq!(parsed.header.final_byte_bits, 2);
        assert_eq!(parsed.header.payload_bits, 18);
        assert_eq!(&block[parsed.payload], payload);
    }

    #[test]
    fn rejects_table_repeat_without_previous_length() {
        let mut writer = BitWriter::new();
        for _ in 0..LEVEL_TABLE_SIZE {
            writer.write_bits(5, 4);
        }
        writer.write_bits(16, 5);
        writer.write_bits(0, 3);

        assert_eq!(
            read_table_lengths(&writer.finish(), 0),
            Err(Error::InvalidData(
                "RAR 5 table repeats missing previous length"
            ))
        );
    }

    #[test]
    fn rejects_invalid_encoded_block_bit_counts() {
        assert_eq!(
            encode_compressed_block(&[0], 0, true, true),
            Err(Error::InvalidData("RAR 5 block has unused payload bytes"))
        );
        assert_eq!(
            encode_compressed_block(&[], 1, true, true),
            Err(Error::InvalidData("RAR 5 block bit count exceeds payload"))
        );
    }

    #[test]
    fn builds_named_decode_tables_from_lengths() {
        let lengths = TableLengths {
            main: vec![1, 1],
            distance: vec![1, 1],
            align: vec![4; ALIGN_TABLE_SIZE],
            length: vec![1, 1],
        };

        let tables = DecodeTables::from_lengths(&lengths).unwrap();

        assert!(!tables.main.is_empty());
        assert!(!tables.distance.is_empty());
        assert!(!tables.align.is_empty());
        assert!(!tables.length.is_empty());
        assert!(!tables.align_mode);
    }

    #[test]
    fn primary_lut_handoff_consumes_literals_and_controls_once() {
        let mut lengths = vec![0; MAIN_TABLE_SIZE];
        lengths[b'A' as usize] = 1;
        lengths[262] = 1;
        let table = HuffmanTable::from_lengths(&lengths).unwrap();
        let literal_entry = table.lut[0];
        assert!(lut_entry_is_literal(literal_entry));
        assert_eq!(lut_entry_symbol(literal_entry), b'A' as usize);
        assert_eq!(literal_entry & HUFF_LUT_LENGTH_MASK, 1);
        let control_entry = table.lut[1 << (HUFF_LUT_BITS - 1)];
        assert_ne!(control_entry, HUFF_LUT_MISS);
        assert!(!lut_entry_is_literal(control_entry));
        assert_eq!(lut_entry_symbol(control_entry), 262);
        assert_eq!(control_entry & HUFF_LUT_LENGTH_MASK, 1);
        // Canonical codes: A=0, match control 262=1.
        let mut bits = BitReader::new(&[0b0100_0000, 0]);
        let mut output = StreamingOutput::new(Vec::new(), 0, 2, 1024, 1024);
        let mut sink = |_chunk: DecodedChunk<'_>| Ok::<_, std::convert::Infallible>(());

        let control = output
            .literal_burst(&table, &mut bits, 2, &mut sink)
            .unwrap();
        assert_eq!(control, Some(262));
        assert_eq!(output.written(), 1);
        assert_eq!(output.ring[0], b'A');
        assert_eq!(
            bits.position(),
            2,
            "the control code is consumed at handoff"
        );

        let long_len = (HUFF_LUT_BITS + 1) as u8;
        let long = HuffmanTable::from_lengths(&[long_len, long_len]).unwrap();
        let mut long_bits = BitReader::new(&[0, 0]);
        let mut output = StreamingOutput::new(Vec::new(), 0, 1, 1024, 1024);
        assert_eq!(
            output
                .literal_burst(&long, &mut long_bits, usize::from(long_len), &mut sink)
                .unwrap(),
            None
        );
        assert_eq!(
            long_bits.position(),
            0,
            "a LUT miss remains untouched for canonical decoding"
        );
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn distance_lut_hits_carry_validated_extra_bits_without_leaking_metadata() {
        let mut distance = vec![0; DISTANCE_TABLE_SIZE_70];
        distance[0] = 1;
        distance[10] = 1;
        let tables = DecodeTables::from_lengths(&TableLengths {
            main: vec![1, 1],
            distance,
            align: vec![4; ALIGN_TABLE_SIZE],
            length: vec![1, 1],
        })
        .unwrap();
        // Canonical codes: distance slots 0 and 10 are encoded as 0 and 1.
        // Both entries also carry the generic LUT's below-256 marker.
        let encoded = [0b0100_0000, 0];
        let mut hot = BitReader::new(&encoded);
        assert_eq!(
            tables.distance.decode_distance_hot(&mut hot).unwrap(),
            (0, 0)
        );
        assert_eq!(
            tables.distance.decode_distance_hot(&mut hot).unwrap(),
            (10, 4)
        );
        assert_eq!(hot.position(), 2);

        let mut generic = BitReader::new(&encoded);
        assert_eq!(tables.distance.decode(&mut generic).unwrap(), 0);
        assert_eq!(tables.distance.decode(&mut generic).unwrap(), 10);
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn distance_lut_metadata_preserves_short_and_long_invalid_slot_errors() {
        let mut short_distance = vec![0; DISTANCE_TABLE_SIZE_70];
        short_distance[65] = 1;
        short_distance[66] = 1;
        let short = DecodeTables::from_lengths(&TableLengths {
            main: vec![1, 1],
            distance: short_distance,
            align: vec![4; ALIGN_TABLE_SIZE],
            length: vec![1, 1],
        })
        .unwrap();
        let mut max_bits = BitReader::new(&[0, 0]);
        assert_eq!(
            short.distance.decode_distance_hot(&mut max_bits).unwrap(),
            (65, 31)
        );
        let mut short_bits = BitReader::new(&[0b1000_0000, 0]);
        assert!(matches!(
            short.distance.decode_distance_hot(&mut short_bits),
            Err(Error::InvalidData("RAR 5 distance slot is too large"))
        ));
        assert_eq!(
            short_bits.position(),
            1,
            "the rejected short code is consumed"
        );

        let mut long_distance = vec![0; DISTANCE_TABLE_SIZE_70];
        long_distance[66] = (HUFF_LUT_BITS + 1) as u8;
        let long = DecodeTables::from_lengths(&TableLengths {
            main: vec![1, 1],
            distance: long_distance,
            align: vec![4; ALIGN_TABLE_SIZE],
            length: vec![1, 1],
        })
        .unwrap();
        let mut long_bits = BitReader::new(&[0, 0]);
        assert!(matches!(
            long.distance.decode_distance_hot(&mut long_bits),
            Err(Error::InvalidData("RAR 5 distance slot is too large"))
        ));
        assert_eq!(
            long_bits.position(),
            HUFF_LUT_BITS + 1,
            "the rejected long code still takes canonical fallback"
        );
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn distance_hot_decode_preserves_valid_long_codes_and_short_input_tails() {
        let mut long_distance = vec![0; DISTANCE_TABLE_SIZE_70];
        long_distance[10] = (HUFF_LUT_BITS + 1) as u8;
        long_distance[11] = (HUFF_LUT_BITS + 1) as u8;
        let long = HuffmanTable::from_distance_lengths(&long_distance).unwrap();
        let mut long_bits = BitReader::new(&[0, 0]);
        assert_eq!(long.decode_distance_hot(&mut long_bits).unwrap(), (10, 4));
        assert_eq!(long_bits.position(), HUFF_LUT_BITS + 1);

        let mut tail_distance = vec![0; DISTANCE_TABLE_SIZE_70];
        tail_distance[0] = 1;
        tail_distance[10] = 1;
        let tail = HuffmanTable::from_distance_lengths(&tail_distance).unwrap();
        let mut tail_bits = BitReader::new(&[0b1000_0000]);
        assert_eq!(tail.decode_distance_hot(&mut tail_bits).unwrap(), (10, 4));
        assert_eq!(tail_bits.position(), 1);
    }

    #[test]
    fn rejects_oversubscribed_rar50_huffman_tables() {
        assert!(matches!(
            HuffmanTable::from_lengths(&[1, 1, 1]),
            Err(Error::InvalidData("RAR 5 oversubscribed Huffman table"))
        ));
    }

    #[test]
    fn compact_huffman_symbols_preserve_canonical_codes_and_encoder_lookup() {
        // Complete tree with the symbols deliberately scattered: 0, 10,
        // 110, 1110, 1111. Symbols sharing a length stay in numeric order,
        // as required by RAR's canonical code assignment.
        let mut lengths = vec![0; MAIN_TABLE_SIZE];
        lengths[1] = 1;
        lengths[2] = 2;
        lengths[128] = 3;
        lengths[250] = 4;
        lengths[MAIN_TABLE_SIZE - 1] = 4;
        let table = HuffmanTable::from_lengths(&lengths).unwrap();

        assert_eq!(table.symbols, [1, 2, 128, 250, 305]);
        let expected = [
            (1, 0, 1),
            (2, 0b10, 2),
            (128, 0b110, 3),
            (250, 0b1110, 4),
            (305, 0b1111, 4),
        ];
        let mut writer = BitWriter::new();
        for &(symbol, code, len) in &expected {
            assert_eq!(table.code_for_symbol(symbol).unwrap(), (code, len));
            writer.write_bits(usize::from(code), usize::from(len));
        }
        assert_eq!(
            table.code_for_symbol(0),
            Err(Error::InvalidData("RAR 5 missing Huffman symbol"))
        );

        let encoded = writer.finish();
        let mut reader = BitReader::new(&encoded);
        for &(symbol, _, _) in &expected {
            assert_eq!(table.decode(&mut reader).unwrap(), symbol);
        }
    }

    #[test]
    fn compact_huffman_symbols_cover_rar7_table_boundary() {
        let mut lengths = vec![0; MAIN_TABLE_SIZE];
        lengths[MAIN_TABLE_SIZE - 1] = 1;
        lengths[0] = 1;
        let table = HuffmanTable::from_lengths(&lengths).unwrap();

        // MAIN_TABLE_SIZE is shared by RAR5 and RAR7 and contains their
        // largest symbol id. Keep that boundary representable by the compact
        // u16 storage and prove both canonical endpoints decode.
        assert_eq!(table.symbols, [0, (MAIN_TABLE_SIZE - 1) as u16]);
        assert_eq!(table.code_for_symbol(0).unwrap(), (0, 1));
        assert_eq!(table.code_for_symbol(MAIN_TABLE_SIZE - 1).unwrap(), (1, 1));
        let mut reader = BitReader::new(&[0b0100_0000]);
        assert_eq!(table.decode(&mut reader).unwrap(), 0);
        assert_eq!(table.decode(&mut reader).unwrap(), MAIN_TABLE_SIZE - 1);
    }

    #[test]
    fn compact_huffman_symbols_reject_ids_that_would_truncate() {
        let mut lengths = vec![0; usize::from(u16::MAX) + 2];
        lengths[0] = 1;
        lengths[usize::from(u16::MAX) + 1] = 1;

        assert!(matches!(
            HuffmanTable::from_lengths(&lengths),
            Err(Error::InvalidData("RAR 5 Huffman symbol is too large"))
        ));
    }

    #[test]
    fn primary_huffman_lookup_matches_bitwise_decode_across_all_prefixes() {
        let mut cases = vec![vec![8; 256]];
        for length in [1, 4, 8, 9, 10, 12, 14, 15] {
            let mut lengths = vec![0; MAIN_TABLE_SIZE];
            lengths[0] = length;
            lengths[MAIN_TABLE_SIZE - 1] = length;
            cases.push(lengths);
        }
        for lengths in cases {
            let table = HuffmanTable::from_lengths(&lengths).unwrap();
            for prefix in 0..32768u16 {
                let encoded = (prefix << 1).to_be_bytes();
                let mut fast = BitReader::new(&encoded);
                let mut bitwise = BitReader::new(&encoded);
                match (table.decode(&mut fast), table.decode_slow(&mut bitwise)) {
                    (Ok(a), Ok(b)) => {
                        assert_eq!(a, b, "prefix {prefix}");
                        assert_eq!(fast.position(), bitwise.position());
                    }
                    (Err(_), Err(_)) => {}
                    pair => panic!("lookup and bitwise decode disagree: {pair:?}"),
                }
            }
        }
    }

    #[test]
    fn codes_beyond_the_primary_huffman_lut_use_the_canonical_fallback() {
        let table = HuffmanTable::from_lengths(&[10, 10]).unwrap();
        assert_eq!(
            table.lut[0], HUFF_LUT_MISS,
            "10-bit codes must not populate the LUT"
        );

        let mut first = BitReader::new(&[0x00, 0x00]);
        assert_eq!(table.decode(&mut first).unwrap(), 0);

        // Canonical code 1 at width 10 is nine zero bits followed by one.
        let mut second = BitReader::new(&[0x00, 0x40]);
        assert_eq!(table.decode(&mut second).unwrap(), 1);
    }

    #[test]
    fn detects_rar50_align_mode_when_align_lengths_are_not_uniform_four() {
        let mut align = vec![4; ALIGN_TABLE_SIZE];
        align[0] = 0;
        align[3] = 3;
        let lengths = TableLengths {
            main: vec![1, 1],
            distance: vec![1, 1],
            align,
            length: vec![1, 1],
        };

        let tables = DecodeTables::from_lengths(&lengths).unwrap();

        assert!(tables.align_mode);
    }

    #[test]
    fn decodes_synthetic_literal_only_block() {
        let payload = literal_only_payload(b"ABBA");
        let input = encode_compressed_block(&payload, payload.len() * 8, true, true).unwrap();

        let output = decode_literal_only(&input, 0, 4).unwrap();

        assert_eq!(output, b"ABBA");
    }

    #[test]
    fn encodes_literal_only_member_that_decoder_reads() {
        let data = b"literal-only RAR5 codec stream\nwith repeated words words words";
        let input = encode_literal_only(data, 0).unwrap();

        let output = decode_literal_only(&input, 0, data.len()).unwrap();

        assert_eq!(output, data);
    }

    #[test]
    fn encodes_literal_only_rar70_table_shape_that_decoder_reads() {
        let data = b"small RAR7-compatible literal block";
        let input = encode_literal_only(data, 1).unwrap();

        let output = decode_literal_only(&input, 1, data.len()).unwrap();

        assert_eq!(output, data);
    }

    #[test]
    fn encodes_empty_literal_only_member() {
        let input = encode_literal_only(b"", 0).unwrap();

        let output = decode_literal_only(&input, 0, 0).unwrap();

        assert!(output.is_empty());
    }

    #[test]
    fn encodes_lz_member_with_same_member_matches() {
        let data = b"RAR5 match writer phrase. RAR5 match writer phrase. RAR5 match writer phrase.";
        let lz = encode_lz_member(data, 0).unwrap();
        let literal = encode_literal_only(data, 0).unwrap();

        let output = decode_lz(&lz, 0, data.len()).unwrap();

        assert_eq!(output, data);
        assert!(lz.len() < literal.len());
        assert!(
            encode_tokens(data, &[], EncodeOptions::default(), DISTANCE_TABLE_SIZE_50)
                .iter()
                .any(|token| token.distance != 0)
        );
    }

    #[test]
    fn frequency_weighted_huffman_lengths_shorten_common_symbols() {
        let mut frequencies = vec![1usize; 24];
        frequencies[3] = 1024;

        let lengths = huffman::lengths_for_frequencies(&frequencies, 15);

        assert!(lengths[3] < lengths[0]);
        assert!(lengths.iter().all(|&length| length <= 15));
    }

    #[test]
    fn lz_encoder_uses_frequency_weighted_huffman_lengths() {
        let mut data = vec![b'a'; 200];
        data.extend_from_slice(b"bcdefghijklmnopqrstuvwxyz");
        let input = encode_lz_member_with_options(&data, 0, EncodeOptions::new(0)).unwrap();
        let block = parse_compressed_block(&input).unwrap();
        let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

        let output = decode_lz(&input, 0, data.len()).unwrap();

        assert_eq!(output, data);
        assert!(lengths.main[b'a' as usize] < lengths.main[b'z' as usize]);
    }

    fn code_is_complete(lengths: &[u8]) -> bool {
        let max_len = lengths.iter().copied().max().unwrap_or(0);
        if max_len == 0 {
            return true;
        }
        let sum: u64 = lengths
            .iter()
            .filter(|&&len| len != 0)
            .map(|&len| 1u64 << (max_len - len))
            .sum();
        sum == (1u64 << max_len)
    }

    #[test]
    fn degenerate_inputs_emit_complete_huffman_tables() {
        // Highly repetitive data collapses the distance/length/align tables to a
        // single symbol. Those tables must still be transmitted as *complete*
        // prefix codes, or strict RAR 5 decoders (7-Zip / WinRAR, which build
        // with `Full_or_Empty`) reject the archive with a spurious data error.
        // See issue #19.
        let inputs: &[Vec<u8>] = &[
            vec![b'a'; 4000],
            b"ab".repeat(4000),
            (0u8..16).cycle().take(50_000).collect(),
            b"lorem ipsum dolor sit amet ".repeat(2000),
        ];
        for data in inputs {
            let input = encode_lz_member_with_options(data, 0, EncodeOptions::new(0)).unwrap();
            let block = parse_compressed_block(&input).unwrap();
            let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

            assert!(code_is_complete(&lengths.main), "main table incomplete");
            assert!(
                code_is_complete(&lengths.distance),
                "distance table incomplete"
            );
            assert!(code_is_complete(&lengths.length), "length table incomplete");
            assert!(code_is_complete(&lengths.align), "align table incomplete");

            assert_eq!(&decode_lz(&input, 0, data.len()).unwrap(), data);
        }
    }

    #[test]
    fn lazy_lz_parser_defers_short_match_for_longer_next_match() {
        // A byte-diverse prefix prices the literals like real data (about
        // eight bits each); over the bare pattern's five-symbol alphabet a
        // four-byte match costs more than the four literals it replaces and
        // the parser rightly declines it (see `LiteralPrices`).
        let mut input: Vec<u8> = (0u8..=199).collect();
        input.extend_from_slice(b"abcdXbcdYYYYYYYYYYYYabcdYYYYYYYYYYYY");
        let input = &input[..];
        let greedy = encode_tokens(
            input,
            &[],
            EncodeOptions::new(MAX_MATCH_CANDIDATES),
            DISTANCE_TABLE_SIZE_50,
        );
        let lazy = encode_tokens(
            input,
            &[],
            EncodeOptions::new(MAX_MATCH_CANDIDATES).with_lazy_matching(true),
            DISTANCE_TABLE_SIZE_50,
        );
        let packed = encode_lz_member_with_options(
            input,
            0,
            EncodeOptions::new(MAX_MATCH_CANDIDATES).with_lazy_matching(true),
        )
        .unwrap();

        assert!(greedy
            .iter()
            .any(|token| token.distance != 0 && token.length == 4));
        assert!(lazy
            .iter()
            .any(|token| token.distance != 0 && token.length > 8));
        assert_eq!(decode_lz(&packed, 0, input.len()).unwrap(), input);
    }

    #[test]
    fn cost_aware_match_selection_prefers_repeat_distance_token() {
        let pos = 64;
        let pattern = b"abcdefgh";
        let mut input: Vec<u8> = (0..96u8).map(|byte| byte.wrapping_mul(37)).collect();
        input[pos - 30..pos - 22].copy_from_slice(pattern);
        input[pos - 10..pos - 2].copy_from_slice(pattern);
        input[pos..pos + 8].copy_from_slice(pattern);
        input[pos + 8] = b'X';

        let mut buckets = MatchIndex::<usize>::new(input.len(), 256);

        let prices = LiteralPrices::new(&input, 0);
        for candidate in 0..pos {
            insert_match_position(&input, candidate, &mut buckets);
        }
        let state = EncoderMatchState {
            reps: [30, 0, 0, 0],
            previous_match_length: 8,
        };

        let best = best_match(
            &input,
            pos,
            input.len(),
            &buckets,
            EncodeOptions::default(),
            &state,
            DISTANCE_TABLE_SIZE_50,
            &prices,
        )
        .unwrap();

        assert_eq!((best.length, best.distance), (8, 30));
    }

    #[test]
    fn lazy_parser_uses_match_cost_not_only_match_length() {
        let pos = 600;
        let mut input: Vec<u8> = (0..700u16)
            .map(|value| value.wrapping_mul(73) as u8)
            .collect();
        input[pos - 512..pos - 504].copy_from_slice(b"ABCDEFGH");
        input[pos - 504] = b'Z';
        input[pos - 29..pos - 21].copy_from_slice(b"BCDEFGHI");
        input[pos - 30] = b'x';
        input[pos..pos + 9].copy_from_slice(b"ABCDEFGHI");

        let mut buckets = MatchIndex::<usize>::new(input.len(), 256);

        let prices = LiteralPrices::new(&input, 0);
        for candidate in 0..pos {
            insert_match_position(&input, candidate, &mut buckets);
        }
        let state = EncoderMatchState {
            reps: [30, 0, 0, 0],
            previous_match_length: 8,
        };
        let current = best_match(
            &input,
            pos,
            input.len(),
            &buckets,
            EncodeOptions::default(),
            &state,
            DISTANCE_TABLE_SIZE_50,
            &prices,
        )
        .unwrap();

        assert_eq!((current.length, current.distance), (8, 512));
        assert!(should_lazy_emit_literal(
            &input,
            pos,
            &buckets,
            EncodeOptions::default().with_lazy_matching(true),
            &state,
            DISTANCE_TABLE_SIZE_50,
            current,
            &prices,
        ));
    }

    #[test]
    fn lazy_parser_uses_bounded_cost_lookahead() {
        let pos = 160;
        let mut input: Vec<u8> = (0..240u16)
            .map(|value| value.wrapping_mul(91) as u8)
            .collect();
        // Under the literal price model deferring two literals must buy a
        // match that saves more than they cost: the ten-byte next match the
        // fixture used to carry no longer does, a fourteen-byte one does.
        input[pos - 30..pos - 22].copy_from_slice(b"ABCDEFGH");
        input[pos - 80..pos - 66].copy_from_slice(b"CDEFGHIJKLMNOP");
        input[pos..pos + 16].copy_from_slice(b"ABCDEFGHIJKLMNOP");

        let mut buckets = MatchIndex::<usize>::new(input.len(), 256);

        let prices = LiteralPrices::new(&input, 0);
        for candidate in 0..pos {
            insert_match_position(&input, candidate, &mut buckets);
        }
        let state = EncoderMatchState::default();
        let current = best_match(
            &input,
            pos,
            input.len(),
            &buckets,
            EncodeOptions::default(),
            &state,
            DISTANCE_TABLE_SIZE_50,
            &prices,
        )
        .unwrap();

        assert_eq!((current.length, current.distance), (8, 30));
        assert!(!should_lazy_emit_literal(
            &input,
            pos,
            &buckets,
            EncodeOptions::default()
                .with_lazy_matching(true)
                .with_lazy_lookahead(1),
            &state,
            DISTANCE_TABLE_SIZE_50,
            current,
            &prices,
        ));
        assert!(should_lazy_emit_literal(
            &input,
            pos,
            &buckets,
            EncodeOptions::default()
                .with_lazy_matching(true)
                .with_lazy_lookahead(2),
            &state,
            DISTANCE_TABLE_SIZE_50,
            current,
            &prices,
        ));
    }

    #[test]
    fn lazy_parser_charges_for_skipped_literals() {
        let pos = 160;
        let mut input: Vec<u8> = (0..240u16)
            .map(|value| value.wrapping_mul(91) as u8)
            .collect();
        input[pos - 30..pos - 22].copy_from_slice(b"ABCDEFGH");
        input[pos - 80..pos - 71].copy_from_slice(b"CDEFGHIJK");
        input[pos..pos + 12].copy_from_slice(b"ABCDEFGHIJKL");

        let mut buckets = MatchIndex::<usize>::new(input.len(), 256);

        let prices = LiteralPrices::new(&input, 0);
        for candidate in 0..pos {
            insert_match_position(&input, candidate, &mut buckets);
        }
        let state = EncoderMatchState::default();
        let current = best_match(
            &input,
            pos,
            input.len(),
            &buckets,
            EncodeOptions::default(),
            &state,
            DISTANCE_TABLE_SIZE_50,
            &prices,
        )
        .unwrap();

        let next = best_match(
            &input,
            pos + 2,
            input.len(),
            &buckets,
            EncodeOptions::default(),
            &state,
            DISTANCE_TABLE_SIZE_50,
            &prices,
        )
        .unwrap();

        assert!(next.score > current.score);
        assert!(next.score <= current.score + 16);
        assert!(!should_lazy_emit_literal(
            &input,
            pos,
            &buckets,
            EncodeOptions::default()
                .with_lazy_matching(true)
                .with_lazy_lookahead(2),
            &state,
            DISTANCE_TABLE_SIZE_50,
            current,
            &prices,
        ));
    }

    fn encode_lz_member_with_filter(data: &[u8], kind: Rar50FilterKind) -> Result<Vec<u8>> {
        Rar50Encoder::new().encode_member_with_filter(data, 0, Rar50FilterSpec::new(kind))
    }

    #[test]
    fn encodes_lz_member_with_delta_filter_record() {
        let data: Vec<u8> = (0..96).map(|index| (index * 7 + index / 3) as u8).collect();
        let input =
            encode_lz_member_with_filter(&data, Rar50FilterKind::Delta { channels: 3 }).unwrap();
        let block = parse_compressed_block(&input).unwrap();
        let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

        let output = decode_lz(&input, 0, data.len()).unwrap();

        assert_eq!(output, data);
        assert_ne!(lengths.main[256], 0);
    }

    #[test]
    fn rejects_invalid_delta_filter_channel_count() {
        assert_eq!(
            encode_lz_member_with_filter(b"abc", Rar50FilterKind::Delta { channels: 0 }),
            Err(Error::InvalidData(
                "RAR 5 DELTA filter channel count is invalid"
            ))
        );
        assert_eq!(
            encode_lz_member_with_filter(b"abc", Rar50FilterKind::Delta { channels: 33 }),
            Err(Error::InvalidData(
                "RAR 5 DELTA filter channel count is invalid"
            ))
        );
    }

    #[test]
    fn encodes_lz_member_with_e8_filter_record() {
        let mut data = b"\xe8\0\0\0\0plain text after call".to_vec();
        data.extend_from_slice(&[0xe8, 3, 0, 0, 0, b'X']);
        let input = encode_lz_member_with_filter(&data, Rar50FilterKind::E8).unwrap();
        let block = parse_compressed_block(&input).unwrap();
        let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

        let output = decode_lz(&input, 0, data.len()).unwrap();

        assert_eq!(output, data);
        assert_ne!(lengths.main[256], 0);
    }

    #[test]
    fn rar50_e8_filter_wraps_file_offset_modulo_16m() {
        let file_offset = 0x0110_0000;
        let mut encoded = vec![0xe8];
        encoded.extend_from_slice(&0x0010_0c08u32.to_le_bytes());

        let mut decoded = encoded.clone();
        address_filters::x86(
            &mut decoded,
            file_offset,
            Direction::Decode,
            X86Opcodes::Call,
            X86Format::Rar5,
        );

        assert_eq!(&decoded[1..5], &0x0000_0c07u32.to_le_bytes());
        address_filters::x86(
            &mut decoded,
            file_offset,
            Direction::Encode,
            X86Opcodes::Call,
            X86Format::Rar5,
        );
        assert_eq!(decoded, encoded);
    }

    #[test]
    fn streaming_decode_applies_filters_in_stream() {
        let data = b"\xe8\0\0\0\0plain text after call".to_vec();
        let input = encode_lz_member_with_filter(&data, Rar50FilterKind::E8).unwrap();
        let mut reader = input.as_slice();
        let mut decoder = Rar50Decoder::new();
        let mut streamed = Vec::new();

        decoder
            .decode_member_from_reader_with_dictionary_to_sink(
                &mut reader,
                0,
                data.len(),
                128 * 1024,
                false,
                0, // flat_limit 0: keep this test on the streaming path
                |chunk| {
                    match chunk {
                        DecodedChunk::Bytes(bytes) => streamed.extend_from_slice(bytes),
                        DecodedChunk::Repeated { byte, len } => {
                            streamed.resize(streamed.len() + len, byte)
                        }
                    }
                    Ok::<_, std::convert::Infallible>(())
                },
            )
            .unwrap();

        assert_eq!(streamed, data);
    }

    #[test]
    fn streaming_decode_swaps_delta_scratch_into_output() {
        let data: Vec<u8> = (0..4099)
            .map(|index| (index * 29 + index / 7) as u8)
            .collect();
        let input =
            encode_lz_member_with_filter(&data, Rar50FilterKind::Delta { channels: 5 }).unwrap();
        let mut reader = input.as_slice();
        let mut decoder = Rar50Decoder::new();
        let mut streamed = Vec::new();

        decoder
            .decode_member_from_reader_with_dictionary_to_sink(
                &mut reader,
                0,
                data.len(),
                128 * 1024,
                false,
                0, // flat_limit 0: exercise StreamingOutput's swap path
                |chunk| {
                    match chunk {
                        DecodedChunk::Bytes(bytes) => streamed.extend_from_slice(bytes),
                        DecodedChunk::Repeated { byte, len } => {
                            streamed.resize(streamed.len() + len, byte)
                        }
                    }
                    Ok::<_, std::convert::Infallible>(())
                },
            )
            .unwrap();

        assert_eq!(streamed, data);
    }

    #[test]
    fn streaming_decode_swaps_between_chained_delta_filters() {
        let data: Vec<u8> = (0..4099)
            .map(|index| (index * 41 + index / 11) as u8)
            .collect();
        let delta = Rar50FilterSpec::new(Rar50FilterKind::Delta { channels: 5 });
        let input = Rar50Encoder::new()
            .encode_member_with_filters(&data, 0, &[delta.clone(), delta])
            .unwrap();
        let mut reader = input.as_slice();
        let mut decoder = Rar50Decoder::new();
        let mut streamed = Vec::new();

        decoder
            .decode_member_from_reader_with_dictionary_to_sink(
                &mut reader,
                0,
                data.len(),
                128 * 1024,
                false,
                0,
                |chunk| {
                    match chunk {
                        DecodedChunk::Bytes(bytes) => streamed.extend_from_slice(bytes),
                        DecodedChunk::Repeated { byte, len } => {
                            streamed.resize(streamed.len() + len, byte)
                        }
                    }
                    Ok::<_, std::convert::Infallible>(())
                },
            )
            .unwrap();

        assert_eq!(streamed, data);
    }

    #[test]
    fn streaming_decode_retains_window_larger_than_initial_cap() {
        // A member decoded with a dictionary wider than the ring's up-front cap
        // must retain the full dictionary as its match window, not a truncated
        // 64 MiB slice: WinRAR builds such archives with `-md128m` and larger
        // (RAR5 or RAR7), and capping the window at the initial ring size
        // wrongly rejected their back-references with "match distance exceeds
        // window". Guards against re-capping `history_limit` below
        // `dictionary_size` on the streaming path.
        //
        // Build a >64 MiB member cheaply: encode a small compressible unit once,
        // then replay it as non-last blocks (clear the is_last flag, keeping the
        // header checksum invariant) so decode inflates to the target size
        // without a 64 MiB-scale encode.
        let pattern: Vec<u8> = (0..256u32).map(|byte| byte as u8).collect();
        let mut unit = Vec::new();
        while unit.len() < 64 * 1024 {
            unit.extend_from_slice(&pattern);
        }
        let member = encode_lz_member(&unit, 0).unwrap();
        assert_eq!(
            member[0] & 0xC0,
            0xC0,
            "expected a single has_tables + is_last block"
        );
        let mut non_last = member.clone();
        non_last[0] &= !0x40; // clear is_last
        non_last[1] ^= 0x40; // preserve the header checksum (actual stays 0x5a)

        let copies = 1088; // 1088 * 64 KiB = 68 MiB, past the 64 MiB cap
        let output_size = unit.len() * copies;
        assert!(output_size > STREAM_INITIAL_WINDOW_CAP);
        let dictionary_size = STREAM_INITIAL_WINDOW_CAP + 8 * 1024 * 1024;
        let mut stream = Vec::new();
        for _ in 0..copies - 1 {
            stream.extend_from_slice(&non_last);
        }
        stream.extend_from_slice(&member); // final block keeps is_last

        let mut decoder = Rar50Decoder::new();
        let mut decoded = Vec::with_capacity(output_size);
        let mut reader = stream.as_slice();
        decoder
            .decode_member_from_reader_with_dictionary_to_sink(
                &mut reader,
                0,
                output_size,
                dictionary_size,
                false,
                0, // flat_limit 0: keep this test on the streaming path
                |chunk| {
                    match chunk {
                        DecodedChunk::Bytes(bytes) => decoded.extend_from_slice(bytes),
                        DecodedChunk::Repeated { byte, len } => {
                            decoded.resize(decoded.len() + len, byte)
                        }
                    }
                    Ok::<_, std::convert::Infallible>(())
                },
            )
            .unwrap();

        assert_eq!(decoded.len(), output_size);
        assert!(decoded.chunks(unit.len()).all(|chunk| chunk == unit));
        // The retained window is the whole member (< dictionary), not the cap.
        assert_eq!(decoder.history.len(), output_size.min(dictionary_size));
        assert!(decoder.history.len() > STREAM_INITIAL_WINDOW_CAP);
    }

    #[test]
    fn streaming_window_limit_rejects_matches_beyond_the_cap() {
        // A back-reference legal for the archive's dictionary but reaching past
        // the caller's window limit must fail cleanly with WindowLimitExceeded
        // (the memory safety valve) rather than drive a giant ring allocation --
        // and the same stream must decode once the limit is raised above it.
        let lcg = |len: usize, mut state: u64| -> Vec<u8> {
            let mut out = Vec::with_capacity(len);
            while out.len() < len {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                out.extend_from_slice(&(state >> 24).to_le_bytes());
            }
            out.truncate(len);
            out
        };
        // R + filler + R: the trailing R repeats the leading one, so rar encodes
        // a single match at distance far = 1 MiB.
        let r = lcg(256 * 1024, 0x51ED);
        let filler = lcg(768 * 1024, 0xF00D);
        let mut payload = r.clone();
        payload.extend_from_slice(&filler);
        payload.extend_from_slice(&r);
        let far = r.len() + filler.len();
        let stream = encode_lz_member(&payload, 0).unwrap();
        let dict = 4 * 1024 * 1024; // comfortably above `far`

        // Limit below the match distance: rejected, and distinctly so.
        let mut decoder = Rar50Decoder::new();
        decoder.set_window_limit(far / 2);
        let mut rejected = Vec::new();
        let err = decoder
            .decode_member_from_reader_with_dictionary_to_sink(
                &mut stream.as_slice(),
                0,
                payload.len(),
                dict,
                false,
                0, // flat_limit 0: keep this test on the streaming path
                |chunk| {
                    match chunk {
                        DecodedChunk::Bytes(bytes) => rejected.extend_from_slice(bytes),
                        DecodedChunk::Repeated { byte, len } => {
                            rejected.resize(rejected.len() + len, byte)
                        }
                    }
                    Ok::<_, std::convert::Infallible>(())
                },
            )
            .unwrap_err();
        assert!(
            matches!(
                err,
                StreamDecodeError::Decode(Error::WindowLimitExceeded { .. })
            ),
            "expected WindowLimitExceeded, got {err:?}"
        );

        // Limit above the match distance: decodes byte-for-byte.
        let mut decoder = Rar50Decoder::new();
        decoder.set_window_limit(far + 1);
        let mut decoded = Vec::new();
        decoder
            .decode_member_from_reader_with_dictionary_to_sink(
                &mut stream.as_slice(),
                0,
                payload.len(),
                dict,
                false,
                0, // flat_limit 0: keep this test on the streaming path
                |chunk| {
                    match chunk {
                        DecodedChunk::Bytes(bytes) => decoded.extend_from_slice(bytes),
                        DecodedChunk::Repeated { byte, len } => {
                            decoded.resize(decoded.len() + len, byte)
                        }
                    }
                    Ok::<_, std::convert::Infallible>(())
                },
            )
            .unwrap();
        assert!(decoded == payload, "raised-limit decode mismatch");
    }

    #[test]
    fn streaming_decode_bails_on_overlong_filter_hold_span() {
        let filter = PendingFilter {
            start: 0,
            file_start: 0,
            length: STREAM_FILTER_HOLD_LIMIT + 1,
            filter_type: FilterType::E8,
            channels: 0,
        };
        let mut output = StreamingOutput::new(Vec::new(), 0, 1 << 20, 1 << 20, 1 << 20);
        let error = output
            .queue_filter::<std::convert::Infallible>(filter)
            .unwrap_err();
        assert!(matches!(error, StreamDecodeError::FilteredMember));
    }

    #[test]
    fn a_large_dictionary_member_sizes_its_ring_once() {
        // Growth to the ceiling used to hold the initial and the grown ring
        // resident together across a live-window copy - the RSS peak of a
        // 128 MiB-dictionary extraction. A member whose output covers the
        // window now starts at the ceiling and must never grow.
        let dict = 2 * STREAM_INITIAL_WINDOW_CAP;
        let output = StreamingOutput::new(Vec::new(), 0, 4 * dict, dict, dict);
        let ceiling =
            (dict + 2 * STREAM_FLUSH_THRESHOLD + STREAM_FILTER_HOLD_LIMIT).next_power_of_two();
        assert_eq!(output.ring.len(), ceiling);

        // A small member declaring the same dictionary keeps the lazy start.
        let small = StreamingOutput::new(Vec::new(), 0, 1 << 20, dict, dict);
        assert!(small.ring.len() < ceiling);
    }

    #[test]
    fn a_huge_declared_unpacked_size_does_not_overflow_the_growth_ceiling() {
        // `output_limit` is the header's declared unpacked size and reaches
        // here unclamped. Rounding it up to a power of two used to panic in
        // a debug build ("attempt to add with overflow") and wrap to 0 in
        // release, losing the anti-thrash ceiling. Growth is reached by
        // declaring a filter: that sets `has_filters`, clears the
        // reserve short-circuit and pushes `needed` past the initial ring.
        let dict = 128 << 10;
        let mut output = StreamingOutput::new(Vec::new(), 0, 1 << (usize::BITS - 1), dict, dict);
        let mut sink = |_: DecodedChunk<'_>| Ok::<_, std::convert::Infallible>(());
        for index in 0..1000u32 {
            output.push((index % 251) as u8, &mut sink).unwrap();
        }
        output
            .queue_filter::<std::convert::Infallible>(PendingFilter {
                start: output.written + output.pending_len(),
                file_start: 0,
                length: 16,
                filter_type: FilterType::E8,
                channels: 0,
            })
            .unwrap();
        // The declared size bounds nothing here, so the ring settles at the
        // dictionary-derived ceiling rather than at 0 or a panic.
        let ceiling =
            (dict + 2 * STREAM_FLUSH_THRESHOLD + STREAM_FILTER_HOLD_LIMIT).next_power_of_two();
        assert_eq!(output.ring.len(), ceiling);
        assert_eq!(
            StreamingOutput::growth_ceiling(usize::MAX, 2 * STREAM_FLUSH_THRESHOLD),
            usize::MAX
        );
    }

    /// Byte-at-a-time LZ reference: `out[i] = out[len - distance + i]`,
    /// overlap included - the semantics every copy path must reproduce.
    fn reference_extend(stream: &mut Vec<u8>, distance: usize, length: usize) {
        for _ in 0..length {
            let byte = stream[stream.len() - distance];
            stream.push(byte);
        }
    }

    #[test]
    fn streaming_zero_run_back_references_resolve_within_a_member() {
        // A streamed member OPENING with a multi-MiB zero run keeps the run
        // sparse: `Repeated` chunks, nothing materialized. A later match may
        // legally reach back into that run - the window is logical output,
        // not ring bytes - and used to be rejected with "match distance
        // exceeds window" once any nonzero byte had landed. Ops are hand-fed
        // because the encoder never chooses such distances on its own (its
        // match finder always has a nearer zero to point at); real WinRAR
        // streams can and do.
        let dict = 32 << 20;
        let mut output = StreamingOutput::new(Vec::new(), 0, 64 << 20, dict, dict);
        let mut expected: Vec<u8> = Vec::new();
        let mut decoded: Vec<u8> = Vec::new();
        let mut sink = |chunk: DecodedChunk<'_>| {
            match chunk {
                DecodedChunk::Bytes(bytes) => decoded.extend_from_slice(bytes),
                DecodedChunk::Repeated { byte, len } => decoded.resize(decoded.len() + len, byte),
            }
            Ok::<_, std::convert::Infallible>(())
        };

        output.push(0, &mut sink).unwrap();
        expected.push(0);
        output.copy_match(1, 6 << 20, &mut sink).unwrap();
        reference_extend(&mut expected, 1, 6 << 20);
        assert!(
            output.head < 64 * 1024,
            "the leading zero run must stay sparse, not materialize"
        );

        for index in 0..8192u32 {
            let byte = (index % 251) as u8 + 1;
            output.push(byte, &mut sink).unwrap();
            expected.push(byte);
        }

        // Wholly inside the zero run.
        output.copy_match(5 << 20, 100_000, &mut sink).unwrap();
        reference_extend(&mut expected, 5 << 20, 100_000);
        // Straddling the run into materialized bytes.
        let deep = output.window_len() + 1000;
        output.copy_match(deep, 5000, &mut sink).unwrap();
        reference_extend(&mut expected, deep, 5000);
        // Overlapped (length > distance) across the run boundary: the
        // output must repeat with period `distance`, zeroes included.
        let deep = output.window_len() + 640;
        output.copy_match(deep, 3 * deep + 100, &mut sink).unwrap();
        reference_extend(&mut expected, deep, 3 * deep + 100);
        // Past the logical window is still corruption, loudly.
        let over = output.window_len() + output.zero_prefix + 1;
        assert!(output.copy_match(over, 16, &mut sink).is_err());

        output.finish(&mut sink).unwrap();
        // `sink` holds the only mutable borrow of `decoded`; dropping it
        // is what lets the assertions below read the buffer. It has no
        // `Drop` impl - ending the BORROW is the point, not running a
        // destructor.
        #[allow(clippy::drop_non_drop)]
        drop(sink);
        assert_eq!(decoded.len(), expected.len());
        assert!(
            decoded == expected,
            "streamed bytes diverge from the LZ reference"
        );
    }

    #[test]
    fn streaming_all_zero_member_carries_its_run_to_the_next_solid_member() {
        // An all-zero streamed member materializes almost nothing, so the
        // window it hands the next solid member is a few bytes. References
        // into the zero output used to fail there with "match distance
        // exceeds window"; the sparse run now travels with the history.
        let dict = 32 << 20;
        let total = 8 << 20;
        let mut first = StreamingOutput::new(Vec::new(), 0, total, dict, dict);
        let mut first_len = 0usize;
        let mut first_nonzero = false;
        {
            let mut sink = |chunk: DecodedChunk<'_>| {
                match chunk {
                    DecodedChunk::Bytes(bytes) => {
                        first_len += bytes.len();
                        first_nonzero |= bytes.iter().any(|&byte| byte != 0);
                    }
                    DecodedChunk::Repeated { byte, len } => {
                        first_len += len;
                        first_nonzero |= byte != 0 && len != 0;
                    }
                }
                Ok::<_, std::convert::Infallible>(())
            };
            first.push(0, &mut sink).unwrap();
            first.copy_match(1, total - 1, &mut sink).unwrap();
            first.finish(&mut sink).unwrap();
        }
        assert_eq!(first_len, total);
        assert!(!first_nonzero);
        let (history, zero_prefix) = first.into_history();
        assert!(
            history.len() < 4096,
            "an all-zero member must carry a few bytes, not its output"
        );
        assert_eq!(
            history.len() + zero_prefix,
            total,
            "the sparse run must be carried, not lost"
        );

        // The whole logical stream so far seeds the reference model.
        let mut expected = vec![0u8; total];
        let start = expected.len();
        let mut second = StreamingOutput::new(history, zero_prefix, 8 << 20, dict, dict);
        let mut decoded: Vec<u8> = Vec::new();
        let mut sink = |chunk: DecodedChunk<'_>| {
            match chunk {
                DecodedChunk::Bytes(bytes) => decoded.extend_from_slice(bytes),
                DecodedChunk::Repeated { byte, len } => decoded.resize(decoded.len() + len, byte),
            }
            Ok::<_, std::convert::Infallible>(())
        };
        // Deep into the previous member's zeroes - the false rejection.
        second.copy_match(4 << 20, 4096, &mut sink).unwrap();
        reference_extend(&mut expected, 4 << 20, 4096);
        for index in 0..4096u32 {
            let byte = (index % 250) as u8 + 1;
            second.push(byte, &mut sink).unwrap();
            expected.push(byte);
        }
        second.copy_match(6 << 20, 8192, &mut sink).unwrap();
        reference_extend(&mut expected, 6 << 20, 8192);
        let deep = second.window_len() + 512;
        second.copy_match(deep, 2048, &mut sink).unwrap();
        reference_extend(&mut expected, deep, 2048);
        second.finish(&mut sink).unwrap();
        // `sink` holds the only mutable borrow of `decoded`; dropping it
        // is what lets the assertions below read the buffer. It has no
        // `Drop` impl - ending the BORROW is the point, not running a
        // destructor.
        #[allow(clippy::drop_non_drop)]
        drop(sink);
        assert!(
            decoded.as_slice() == &expected[start..],
            "solid continuation diverges from the LZ reference"
        );
    }

    #[test]
    fn solid_member_after_an_all_zero_streamed_member_decodes() {
        // The end-to-end shape extract takes: a large all-zero member goes
        // down the streaming path (its output stays sparse), then a solid
        // member decodes against that history. Byte equality here is what
        // the extract layer's CRC check would enforce.
        let first = vec![0u8; 8 << 20];
        let mut second = vec![0u8; 96 * 1024];
        let mut state = 0x5EEDu64;
        while second.len() < 160 * 1024 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            second.extend_from_slice(&(state >> 24).to_le_bytes());
        }
        let m1 = encode_lz_member(&first, 0).unwrap();
        let m2 = encode_lz_member_with_history(&second, &first, 0).unwrap();

        let dict = 32 << 20;
        let mut decoder = Rar50Decoder::new();
        let mut decoded_first = Vec::new();
        decoder
            .decode_member_from_reader_with_dictionary_to_sink(
                &mut m1.as_slice(),
                0,
                first.len(),
                dict,
                false,
                0, // flat_limit 0: keep the member on the streaming path
                |chunk| {
                    match chunk {
                        DecodedChunk::Bytes(bytes) => decoded_first.extend_from_slice(bytes),
                        DecodedChunk::Repeated { byte, len } => {
                            decoded_first.resize(decoded_first.len() + len, byte)
                        }
                    }
                    Ok::<_, std::convert::Infallible>(())
                },
            )
            .unwrap();
        assert!(decoded_first == first);
        assert!(
            decoder.history.len() < 64 * 1024,
            "an all-zero member's window must stay sparse end to end"
        );
        assert_eq!(
            decoder.history.len() + decoder.history_zero_prefix,
            first.len(),
            "the sparse run must be carried into the solid window"
        );

        let mut decoded_second = Vec::new();
        decoder
            .decode_member_from_reader_with_dictionary_to_sink(
                &mut m2.as_slice(),
                0,
                second.len(),
                dict,
                true,
                0,
                |chunk| {
                    match chunk {
                        DecodedChunk::Bytes(bytes) => decoded_second.extend_from_slice(bytes),
                        DecodedChunk::Repeated { byte, len } => {
                            decoded_second.resize(decoded_second.len() + len, byte)
                        }
                    }
                    Ok::<_, std::convert::Infallible>(())
                },
            )
            .unwrap();
        assert!(
            decoded_second == second,
            "a solid member after an all-zero member must decode"
        );
    }

    /// Streams one all-zero member through the real member path, leaving the
    /// decoder holding a few materialized bytes and a carried sparse run -
    /// the state every carried-zero-run test below starts from.
    fn decoder_after_streamed_zero_member(size: usize, dict: usize) -> Rar50Decoder {
        let member = encode_lz_member(&vec![0u8; size], 0).unwrap();
        let mut decoder = Rar50Decoder::new();
        let mut decoded = 0usize;
        decoder
            .decode_member_from_reader_with_dictionary_to_sink(
                &mut member.as_slice(),
                0,
                size,
                dict,
                false,
                0, // flat_limit 0: keep the member on the streaming path
                |chunk| {
                    decoded += match chunk {
                        DecodedChunk::Bytes(bytes) => bytes.len(),
                        DecodedChunk::Repeated { len, .. } => len,
                    };
                    Ok::<_, std::convert::Infallible>(())
                },
            )
            .unwrap();
        assert_eq!(decoded, size);
        assert!(
            decoder.history.len() < 64 * 1024,
            "the zero member's window must stay sparse"
        );
        assert_eq!(
            decoder.history.len() + decoder.history_zero_prefix,
            size,
            "the sparse run must be carried into the solid window"
        );
        decoder
    }

    #[test]
    fn buffered_solid_member_after_an_all_zero_streamed_member_decodes() {
        // The same end-to-end shape as the streaming test above, except the
        // second member is SMALL - at the extract layer anything under the
        // buffered ceiling routes through `decode_member_from_reader_with_
        // dictionary` (the Vec-output path), whose window gate ignored the
        // carried sparse run and rejected this valid chain with "match
        // distance exceeds window". The failure depended only on member B's
        // size: the >4 MiB variant streamed and extracted fine.
        let first = vec![0u8; 8 << 20];
        let mut second = vec![0u8; 96 * 1024];
        let mut state = 0x5EEDu64;
        while second.len() < 160 * 1024 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            second.extend_from_slice(&(state >> 24).to_le_bytes());
        }
        let m2 = encode_lz_member_with_history(&second, &first, 0).unwrap();

        let dict = 32 << 20;
        let mut decoder = decoder_after_streamed_zero_member(first.len(), dict);
        let decoded_second = decoder
            .decode_member_from_reader_with_dictionary(
                &mut m2.as_slice(),
                0,
                second.len(),
                dict,
                true,
                DecodeMode::Lz,
            )
            .unwrap();
        assert!(
            decoded_second == second,
            "a buffered solid member after an all-zero member must decode"
        );
    }

    #[test]
    fn buffered_copy_match_reaches_into_a_carried_zero_run() {
        // The buffered mirror of `streaming_zero_run_back_references_resolve
        // _within_a_member`: deep distances hand-fed straight into the
        // buffered decoder's `copy_match`, because the encoder never chooses
        // such distances on its own (its match finder always has a nearer
        // zero to point at); real WinRAR streams can and do. The decoder
        // state comes from a real streamed member, not from field surgery.
        let total = 8 << 20;
        let dict = 32 << 20;
        let decoder = decoder_after_streamed_zero_member(total, dict);

        // Reference model: the whole logical stream so far is zeroes.
        let mut expected = vec![0u8; total];
        let start = expected.len();
        let mut output: Vec<u8> = Vec::new();
        let limit = 16 << 20;

        for index in 0..4096u32 {
            let byte = (index % 251) as u8 + 1;
            output.push(byte);
            expected.push(byte);
        }
        let window = decoder.history_window_len();
        // Wholly inside the carried zero run.
        decoder
            .copy_match(&mut output, 5 << 20, 100_000, limit, dict)
            .unwrap();
        reference_extend(&mut expected, 5 << 20, 100_000);
        // Straddling the run into materialized bytes.
        let deep = window + output.len() + 1000;
        decoder
            .copy_match(&mut output, deep, 5000, limit, dict)
            .unwrap();
        reference_extend(&mut expected, deep, 5000);
        // Overlapped (length > distance) across the run boundary: the output
        // must repeat with period `distance`, zeroes included.
        let deep = window + output.len() + 640;
        decoder
            .copy_match(&mut output, deep, 3 * deep + 100, limit, dict)
            .unwrap();
        reference_extend(&mut expected, deep, 3 * deep + 100);
        // Past the logical window is still corruption, loudly.
        let over = window + decoder.history_zero_prefix + output.len() + 1;
        assert!(decoder
            .copy_match(&mut output.clone(), over, 16, limit, dict)
            .is_err());

        assert_eq!(output.len(), expected.len() - start);
        assert!(
            output.as_slice() == &expected[start..],
            "buffered bytes diverge from the LZ reference"
        );
    }

    #[test]
    fn carried_zero_run_survives_a_buffered_member_into_a_streamed_member() {
        // The buffered->streamed direction: a streamed all-zero member, then
        // a small buffered solid member, then a large streamed solid member.
        // The buffered member appends its output to the history it was
        // handed, and the (window, zero_prefix) pair has to stay consistent
        // through that hand-off so the third member's ring is seeded with
        // the run still logically in front of it.
        let first = vec![0u8; 8 << 20];
        let mut second = vec![0u8; 32 * 1024];
        let mut state = 0xB0BAu64;
        while second.len() < 64 * 1024 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            second.extend_from_slice(&(state >> 24).to_le_bytes());
        }
        let mut history = first.clone();
        history.extend_from_slice(&second);
        let mut third = vec![0u8; 48 * 1024];
        while third.len() < 128 * 1024 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            third.extend_from_slice(&(state >> 24).to_le_bytes());
        }
        let m2 = encode_lz_member_with_history(&second, &first, 0).unwrap();
        let m3 = encode_lz_member_with_history(&third, &history, 0).unwrap();

        let dict = 32 << 20;
        let mut decoder = decoder_after_streamed_zero_member(first.len(), dict);
        let decoded_second = decoder
            .decode_member_from_reader_with_dictionary(
                &mut m2.as_slice(),
                0,
                second.len(),
                dict,
                true,
                DecodeMode::Lz,
            )
            .unwrap();
        assert!(decoded_second == second);
        assert_eq!(
            decoder.history_window_len() + decoder.history_zero_prefix,
            first.len() + second.len(),
            "the buffered member must extend the window without dropping the run"
        );

        let mut decoded_third = Vec::new();
        decoder
            .decode_member_from_reader_with_dictionary_to_sink(
                &mut m3.as_slice(),
                0,
                third.len(),
                dict,
                true,
                0,
                |chunk| {
                    match chunk {
                        DecodedChunk::Bytes(bytes) => decoded_third.extend_from_slice(bytes),
                        DecodedChunk::Repeated { byte, len } => {
                            decoded_third.resize(decoded_third.len() + len, byte)
                        }
                    }
                    Ok::<_, std::convert::Infallible>(())
                },
            )
            .unwrap();
        assert!(
            decoded_third == third,
            "a streamed member after a buffered one must still see the run"
        );
    }

    #[test]
    fn encodes_lz_member_with_e8e9_filter_record() {
        let data = b"\xe9\0\0\0\0jump target through e9".to_vec();
        let input = encode_lz_member_with_filter(&data, Rar50FilterKind::E8E9).unwrap();
        let block = parse_compressed_block(&input).unwrap();
        let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

        let output = decode_lz(&input, 0, data.len()).unwrap();

        assert_eq!(output, data);
        assert_ne!(lengths.main[256], 0);
    }

    #[test]
    fn encodes_lz_member_with_ranged_e8e9_filter_record() {
        let mut data = b"\xe8\0\0\0\0plain prefix outside filter range".to_vec();
        let range_start = data.len();
        for _ in 0..16 {
            let operand_pos = data.len() + 1;
            data.push(0xe8);
            let relative = 0x7000u32.wrapping_sub(operand_pos as u32);
            data.extend_from_slice(&relative.to_le_bytes());
            data.extend_from_slice(b" code ");
        }
        let range = range_start..data.len();
        data.extend_from_slice(b"\xe9\0\0\0\0plain suffix outside filter range");

        let input = Rar50Encoder::new()
            .encode_member_with_filter(
                &data,
                0,
                Rar50FilterSpec::range(Rar50FilterKind::E8E9, range),
            )
            .unwrap();
        let block = parse_compressed_block(&input).unwrap();
        let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

        let output = decode_lz(&input, 0, data.len()).unwrap();

        assert_eq!(output, data);
        assert_ne!(lengths.main[256], 0);
    }

    #[test]
    fn encodes_lz_member_with_multiple_filter_records() {
        let mut data = b"\xe8\0\0\0\0plain prefix outside filters".to_vec();
        let first_start = data.len();
        data.extend_from_slice(b"\xe8\0\0\0\0first filtered cluster");
        let first_end = data.len();
        data.extend_from_slice(b"large plain middle outside filters");
        let second_start = data.len();
        data.extend_from_slice(b"\xe8\0\0\0\0second filtered cluster");
        let second_end = data.len();

        let input = Rar50Encoder::new()
            .encode_member_with_filters(
                &data,
                0,
                &[
                    Rar50FilterSpec::range(Rar50FilterKind::E8, first_start..first_end),
                    Rar50FilterSpec::range(Rar50FilterKind::E8, second_start..second_end),
                ],
            )
            .unwrap();
        let block = parse_compressed_block(&input).unwrap();
        let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();
        assert_ne!(lengths.main[256], 0, "the filter symbol is in the table");

        // Each record is written just before the token that reaches it
        // (they used to lead the block), so the proof of their starts and
        // lengths is the stream with the filters left unapplied: it is the
        // transformed input exactly, and the transform is address-keyed.
        let (transformed, records) = filtered_lz_member(
            &data,
            &[
                Rar50FilterSpec::range(Rar50FilterKind::E8, first_start..first_end),
                Rar50FilterSpec::range(Rar50FilterKind::E8, second_start..second_end),
            ],
        )
        .unwrap();
        assert_eq!(records.len(), 2);
        assert_ne!(transformed, data);
        let unapplied = Rar50Decoder::new()
            .decode_member(&input, 0, data.len(), false, DecodeMode::LzNoFilters)
            .unwrap();
        assert_eq!(unapplied, transformed);

        let output = decode_lz(&input, 0, data.len()).unwrap();

        assert_eq!(output, data);
    }

    #[test]
    fn encodes_lz_member_with_arm_filter_record() {
        let data = [0x04, 0x00, 0x00, 0xeb, b'A', b'R', b'M', b'!'];
        let input = encode_lz_member_with_filter(&data, Rar50FilterKind::Arm).unwrap();
        let block = parse_compressed_block(&input).unwrap();
        let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

        let output = decode_lz(&input, 0, data.len()).unwrap();

        assert_eq!(output, data);
        assert_ne!(lengths.main[256], 0);
    }

    #[test]
    fn arm_filter_uses_wrapping_address_arithmetic_at_u32_boundary() {
        let original = [0x04, 0x00, 0x00, 0xeb, 0x08, 0x00, 0x00, 0xeb];
        let mut filtered = original;

        address_filters::arm(&mut filtered, u32::MAX - 3, Direction::Encode);
        assert_ne!(filtered, original);
        address_filters::arm(&mut filtered, u32::MAX - 3, Direction::Decode);

        assert_eq!(filtered, original);
    }

    #[test]
    fn solid_encoder_emits_rar50_matches_against_previous_member_history() {
        let first = b"RAR5 solid shared phrase alpha beta gamma\n".repeat(16);
        let second = b"RAR5 solid shared phrase alpha beta gamma\nsecond\n".repeat(4);
        let solid = encode_lz_member_with_history(&second, &first, 0).unwrap();
        let standalone = encode_lz_member(&second, 0).unwrap();
        let mut decoder = Rar50Decoder::new();

        assert_eq!(
            decoder
                .decode_member(
                    &encode_lz_member(&first, 0).unwrap(),
                    0,
                    first.len(),
                    false,
                    DecodeMode::Lz
                )
                .unwrap(),
            first
        );
        assert_eq!(
            decoder
                .decode_member(&solid, 0, second.len(), true, DecodeMode::Lz)
                .unwrap(),
            second
        );
        assert!(solid.len() < standalone.len());
    }

    /// The uniform member the windowed-walk cells below encode: two whole
    /// blocks and a short third, repetitive enough for a parse to have
    /// matches to find and noisy enough that it is not one long run.
    fn member_window_material() -> Vec<u8> {
        let block = MAX_COMPRESSED_BLOCK_OUTPUT;
        (0..2 * block + 12_345)
            .map(|i| {
                let word = (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 59;
                if i % 97 < 90 {
                    b'a' + (i % 7) as u8 + word as u8 / 8
                } else {
                    word as u8
                }
            })
            .collect()
    }

    /// `data` encoded a block at a time, each window carrying the blocks
    /// the dictionary reaches back over plus the block to encode.
    fn member_windowed_walk(data: &[u8], dictionary: usize, options: EncodeOptions) -> Vec<u8> {
        let block = MAX_COMPRESSED_BLOCK_OUTPUT;
        let history_blocks = dictionary.div_ceil(block);
        let pool = EncoderScratchPool::new();
        let mut windowed = Vec::new();
        let mut start = 0usize;
        while start < data.len() {
            let end = (start + block).min(data.len());
            let history_start = start.saturating_sub(history_blocks * block);
            windowed.extend(
                encode_lz_member_window(
                    &data[history_start..end],
                    (start - history_start) / block,
                    0,
                    options,
                    end == data.len(),
                    &pool,
                )
                .unwrap(),
            );
            start = end;
        }
        windowed
    }

    /// One cell of the windowed-walk table: a member encoded from windows -
    /// each window the blocks before it (at least the dictionary) and the
    /// blocks to encode - is the member encoded whole, block for block,
    /// which is what the streamed compressed writer relies on.
    ///
    /// Every cell runs under BOTH parsers. The cost-based one asks the tree
    /// for a per-position CANDIDATE LIST rather than one distance, so a
    /// window's slice of the hint buffer is `stride` slots per position and
    /// an index that forgot the stride would show up here and nowhere else.
    /// (nzbfast-local change, 7 Sep 2026.)
    ///
    /// ONE TEST PER CELL rather than a loop over the table, and that is a
    /// wall-clock decision with no coverage in it: nightly's `armv7-cross`
    /// kills a test at 900 s under qemu and the loop was 605.6 s of that
    /// budget in ONE test (run 34583096699), a margin of 1.5x with nothing
    /// watching it. nextest gives each cell its own process and runs them
    /// concurrently, so the split moves work sideways: the worst cell is an
    /// estimated 149 s and the seven together cost what the one did, to
    /// within the measurement. Measured per cell on the emulated target,
    /// because the cost is NOT spread evenly over the table - the cells
    /// span 23x, from 1.27 s (sub-block dictionary, lazy) to 29.70 s
    /// (sub-block dictionary, cost-based), so neither end is anywhere near
    /// the 1/6 an even table would suggest. The cost-based parse is also
    /// CHEAPER at a one-block dictionary than at a sub-block one, because
    /// `TREE_MIN_DICTIONARY` arms the tree finder at 4 MiB and the tree is
    /// the cheaper finder for a parse that wants a candidate list. Numbers,
    /// rig and what is scaled rather than measured: the host repo's
    /// `research/ARMV7-CROSS-TEST-CEILING-2026-09-11.md`.
    /// (nzbfast-local change, 11 Sep 2026.)
    fn member_windows_match_the_whole_walk(dictionary: usize, optimal_parse: bool) {
        let uniform = member_window_material();
        let options = EncodeOptions::new(16)
            .with_max_match_distance(dictionary)
            .with_optimal_parse(optimal_parse);
        let whole = encode_lz_member_with_options(&uniform, 0, options).unwrap();
        assert_eq!(
            member_windowed_walk(&uniform, dictionary, options),
            whole,
            "dictionary {dictionary}, optimal {optimal_parse}"
        );
    }

    #[test]
    fn member_windows_match_the_whole_walk_at_a_sub_block_dictionary_lazily() {
        member_windows_match_the_whole_walk(128 << 10, false);
    }

    #[test]
    fn member_windows_match_the_whole_walk_at_a_sub_block_dictionary_optimally() {
        member_windows_match_the_whole_walk(128 << 10, true);
    }

    #[test]
    fn member_windows_match_the_whole_walk_at_a_one_block_dictionary_lazily() {
        member_windows_match_the_whole_walk(MAX_COMPRESSED_BLOCK_OUTPUT, false);
    }

    #[test]
    fn member_windows_match_the_whole_walk_at_a_one_block_dictionary_optimally() {
        member_windows_match_the_whole_walk(MAX_COMPRESSED_BLOCK_OUTPUT, true);
    }

    #[test]
    fn member_windows_match_the_whole_walk_at_a_two_block_dictionary_lazily() {
        member_windows_match_the_whole_walk(2 * MAX_COMPRESSED_BLOCK_OUTPUT, false);
    }

    #[test]
    fn member_windows_match_the_whole_walk_at_a_two_block_dictionary_optimally() {
        member_windows_match_the_whole_walk(2 * MAX_COMPRESSED_BLOCK_OUTPUT, true);
    }

    /// Under a working-memory allowance a streamed window encodes at the
    /// pool's wave shared between the windows in flight
    /// ([`member_window_wave_width`]), and that moves no byte: a window of
    /// three blocks on a four-thread pool, at a wave of two against a wave
    /// of four, is the member encoded whole. The width asserts are the
    /// control - on a pool where both widths agreed the equality would
    /// prove nothing. (nzbfast-local change, 15 Sep 2026.)
    #[cfg(feature = "parallel")]
    #[test]
    fn a_streamed_window_under_an_allowance_shares_its_wave_without_moving_a_byte() {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();
        pool.install(|| {
            let uniform = member_window_material();
            let options =
                EncodeOptions::new(16).with_max_match_distance(MAX_COMPRESSED_BLOCK_OUTPUT);
            let bounded = options.with_working_memory(Some(usize::MAX));
            assert_eq!(member_window_wave_width(options), 4);
            assert_eq!(member_window_wave_width(bounded), 2);
            let whole = encode_lz_member_with_options(&uniform, 0, options).unwrap();
            let scratch = EncoderScratchPool::new();
            for arm in [options, bounded] {
                assert_eq!(
                    encode_lz_member_window(&uniform, 0, 0, arm, true, &scratch).unwrap(),
                    whole,
                    "allowance {:?}",
                    arm.working_memory,
                );
            }
        });
    }

    /// The windowed walk also makes the same per-region horizon CHOICES as
    /// the whole-member walk, over material whose regions do not all want
    /// the same horizon. The choice is made per region from that region's
    /// own bytes and the raw member history before them, both of which a
    /// window holds exactly, so the windowed walk makes the same choices -
    /// but a selector that read anything else (an output length carried
    /// across regions, a rep model, the block index within the encode)
    /// would diverge here and nowhere else. The size assertion holds the
    /// switch-on arm to being a REAL arm: on material where the wide
    /// horizon always won, the two arms would agree however broken the
    /// plumbing was, and it is why THIS pair stays one test while the
    /// parser table above became one test per cell - the assertion is
    /// across the two arms, not inside either.
    #[test]
    fn member_windows_make_the_same_horizon_choices_as_the_whole_walk() {
        let block = MAX_COMPRESSED_BLOCK_OUTPUT;
        let mixed = horizon_material(block + 500_000);
        let mut sizes = Vec::new();
        for horizon in [false, true] {
            let options = EncodeOptions::new(16)
                .with_max_match_distance(block)
                .with_tokenizer_horizon_choice(horizon);
            let whole = encode_lz_member_with_options(&mixed, 0, options).unwrap();
            assert_eq!(
                member_windowed_walk(&mixed, block, options),
                whole,
                "horizon choice {horizon}"
            );
            sizes.push(whole.len());
        }
        assert!(
            sizes[1] < sizes[0],
            "the horizon arm of this test has to be an arm: {} bytes with the \
             choice on against {} with it off",
            sizes[1],
            sizes[0],
        );
    }

    /// [`encode_member_region`] returns whichever of its two arms encoded
    /// smaller, and with the switch off it is the wide arm byte for byte.
    ///
    /// The `assert_ne!` is the positive control: "the choice returned the
    /// wide arm" is also what a dead short arm looks like, so the test
    /// first proves the two arms differ on this region.
    #[test]
    fn the_region_horizon_choice_keeps_the_smaller_of_its_two_arms() {
        let region = 2 * TOKENIZER_SHORT_HORIZON + 300_000;
        let data = horizon_material(region);
        let options = EncodeOptions::new(16).with_max_match_distance(128 << 10);
        let mut scratch = EncoderScratch::default();
        let arm = |scratch: &mut EncoderScratch, range: Range<usize>, last: bool| {
            encode_member_block(
                &data,
                &[],
                range,
                &[],
                0,
                options,
                last,
                None,
                scratch,
                None,
                &[],
            )
            .unwrap()
        };
        let wide = arm(&mut scratch, 0..region, true);
        let mut short = Vec::new();
        let mut start = 0usize;
        while start < region {
            let end = (start + TOKENIZER_SHORT_HORIZON).min(region);
            short.extend(arm(&mut scratch, start..end, end == region));
            start = end;
        }
        assert_ne!(
            wide, short,
            "the two horizons encode this region the same way, so nothing below is a test"
        );

        let off = encode_member_region(
            &data,
            &[],
            0..region,
            &[],
            0,
            options,
            true,
            None,
            &mut scratch,
            None,
            &[],
        )
        .unwrap();
        assert_eq!(off, wide, "with the switch off the region is the wide arm");

        let on = encode_member_region(
            &data,
            &[],
            0..region,
            &[],
            0,
            options.with_tokenizer_horizon_choice(true),
            true,
            None,
            &mut scratch,
            None,
            &[],
        )
        .unwrap();
        let smaller = if short.len() < wide.len() { &short } else { &wide };
        assert_eq!(on, *smaller, "the choice kept the larger arm");
    }

    /// The switch never grows a member on any shape, and every member it
    /// writes still decodes to its input. The arm it is measured against
    /// is always one of its own candidates, so this is a property of the
    /// selector rather than of the corpus - which is why the shapes here
    /// include the ones a shorter horizon is known to LOSE on (one buffer
    /// replayed, and a member below the short horizon, where the choice
    /// is inert by construction).
    #[test]
    fn the_region_horizon_choice_never_grows_a_member() {
        let block = MAX_COMPRESSED_BLOCK_OUTPUT;
        let shapes: [(&str, Vec<u8>); 4] = [
            ("mixed phases, two regions", horizon_material(block + 500_000)),
            ("mixed phases, under a region", horizon_material(1_500_000)),
            ("under the short horizon", horizon_material(400_000)),
            (
                "one buffer replayed",
                b"the same paragraph, over and over, with nothing new in it at all.\n"
                    .repeat(40_000),
            ),
        ];
        for (name, data) in shapes {
            for dictionary in [128usize << 10, block] {
                let options = EncodeOptions::new(16).with_max_match_distance(dictionary);
                let off = encode_lz_member_with_options(&data, 0, options).unwrap();
                let on = encode_lz_member_with_options(
                    &data,
                    0,
                    options.with_tokenizer_horizon_choice(true),
                )
                .unwrap();
                assert!(
                    on.len() <= off.len(),
                    "{name} at dictionary {dictionary}: {} bytes with the choice on \
                     against {} with it off",
                    on.len(),
                    off.len(),
                );
                assert_eq!(
                    Rar50Decoder::new()
                        .decode_member(&on, 0, data.len(), false, DecodeMode::Lz)
                        .unwrap(),
                    data,
                    "{name} at dictionary {dictionary}"
                );
            }
        }
    }

    /// DIAGNOSTIC, not a test of anything: `RARS_STATS_ARCHIVE=<archive>`
    /// prints where the bits of every compressed member went - blocks,
    /// tables, literals, matches by length and distance, repeats - so two
    /// writers' archives over the same input can be compared class by
    /// class (used 6 Sep 2026 to find the 1.7% against rar at 32 MiB).
    #[test]
    #[ignore = "diagnostic: set RARS_STATS_ARCHIVE to a RAR 5 archive and run with --nocapture"]
    fn token_statistics_of_an_archive() {
        let Ok(path) = std::env::var("RARS_STATS_ARCHIVE") else {
            return;
        };
        let data = std::fs::read(&path).unwrap();
        let archive = crate::rar50::Archive::parse(&data).unwrap();
        let member_count = archive.files().filter(|f| !f.is_stored()).count();
        let mut totals = std::collections::BTreeMap::<&'static str, f64>::new();
        let mut packed_total = 0usize;
        let mut unpacked_total = 0u64;
        // Tables and repeat state carry across the members of a solid
        // stream, as the decoder carries them.
        let mut tables: Option<DecodeTables> = None;
        let mut reps = [0usize; 4];
        let mut previous_match_length = 0usize;
        for file in archive.files() {
            if file.is_stored() {
                continue;
            }
            let packed = file.packed_data(&archive).unwrap();
            let info = file.decoded_compression_info().unwrap();
            let version = info.algorithm_version;
            if !info.solid {
                tables = None;
                reps = [0; 4];
                previous_match_length = 0;
            }
            let mut input = std::io::Cursor::new(packed.as_slice());
            let mut payload_buf = Vec::new();
            // Counters: [count, bits, bytes-produced]
            let mut blocks = 0u64;
            let mut table_sets = 0u64;
            let mut repeated_table_sets = 0u64;
            let mut previous_lengths: Option<TableLengths> = None;
            let mut header_bits = 0u64;
            let mut table_bits = 0u64;
            let mut payload_bits_total = 0u64;
            let mut lit = [0u64; 3];
            let mut filt = [0u64; 3];
            let mut rep_last = [0u64; 3];
            let mut rep = [[0u64; 3]; 4];
            let mut mat = [0u64; 3];
            let mut len_hist = [0u64; 8]; // 4-7,8-15,16-31,32-63,64-127,128-255,256-1023,1024+
            let mut len_bits = [0u64; 8];
            let mut dist_hist = [0u64; 26]; // log2 distance
            let mut dist_bits = [0u64; 26];
            // Far matches (8 MiB and beyond) by length bucket: count, bytes.
            let mut far_len = [[0u64; 2]; 8];
            let mut near_len = [[0u64; 2]; 8];
            let len_bucket = |length: usize| -> usize {
                match length {
                    0..=7 => 0,
                    8..=15 => 1,
                    16..=31 => 2,
                    32..=63 => 3,
                    64..=127 => 4,
                    128..=255 => 5,
                    256..=1023 => 6,
                    _ => 7,
                }
            };
            while let Ok(header) = read_compressed_block_into(&mut input, &mut payload_buf) {
                blocks += 1;
                header_bits += 8 * (2 + 1 + header.payload_size.div_ceil(256).min(3)) as u64;
                let payload = payload_buf.as_slice();
                let mut bit_pos = 0usize;
                if header.has_tables {
                    let (lengths, bits_used) = read_table_lengths(payload, version).unwrap();
                    if previous_lengths.as_ref() == Some(&lengths) {
                        repeated_table_sets += 1;
                    }
                    previous_lengths = Some(lengths.clone());
                    tables = Some(DecodeTables::from_lengths(&lengths).unwrap());
                    table_sets += 1;
                    table_bits += bits_used as u64;
                    bit_pos = bits_used;
                }
                let tables = tables.as_ref().expect("tables");
                let mut bits = BitReader::new_at(payload, bit_pos);
                payload_bits_total += header.payload_bits as u64;
                while bits.position() < header.payload_bits {
                    let start = bits.position();
                    let symbol = match tables.main.decode(&mut bits) {
                        Ok(symbol) => symbol,
                        Err(_) => break,
                    };
                    match symbol {
                        0..=255 => {
                            lit[0] += 1;
                            lit[1] += (bits.position() - start) as u64;
                            lit[2] += 1;
                        }
                        256 => {
                            let _ = parse_filter_record(&mut bits, 0);
                            filt[0] += 1;
                            filt[1] += (bits.position() - start) as u64;
                        }
                        257 => {
                            rep_last[0] += 1;
                            rep_last[1] += (bits.position() - start) as u64;
                            rep_last[2] += previous_match_length as u64;
                        }
                        258..=261 => {
                            let index = symbol - 258;
                            let slot = tables.length.decode(&mut bits).unwrap();
                            let extra = bits
                                .read_bits(length_slot_extra_bits(slot).unwrap())
                                .unwrap();
                            let length = match_length_for_slot(slot, extra).unwrap();
                            let distance = reps[index];
                            reps[..=index].rotate_right(1);
                            reps[0] = distance;
                            previous_match_length = length;
                            rep[index][0] += 1;
                            rep[index][1] += (bits.position() - start) as u64;
                            rep[index][2] += length as u64;
                        }
                        _ => {
                            let slot = symbol - 262;
                            let extra = bits
                                .read_bits(length_slot_extra_bits(slot).unwrap())
                                .unwrap();
                            let mut length = match_length_for_slot(slot, extra).unwrap();
                            let after_length = bits.position();
                            let distance_slot = tables.distance.decode(&mut bits).unwrap();
                            let count = distance_slot_bit_count(distance_slot).unwrap();
                            let distance_extra = if count >= 4 && tables.align_mode {
                                let high = bits.read_bits((count - 4) as u8).unwrap();
                                let low = tables.align.decode(&mut bits).unwrap() as u32;
                                (high << 4) | low
                            } else {
                                bits.read_bits(count as u8).unwrap()
                            };
                            let distance = slot_to_distance(distance_slot, distance_extra).unwrap();
                            length += length_bonus(distance);
                            reps.rotate_right(1);
                            reps[0] = distance;
                            previous_match_length = length;
                            let total = (bits.position() - start) as u64;
                            mat[0] += 1;
                            mat[1] += total;
                            mat[2] += length as u64;
                            let lb = len_bucket(length);
                            len_hist[lb] += 1;
                            len_bits[lb] += (after_length - start) as u64;
                            let db = (usize::BITS - distance.max(1).leading_zeros()) as usize;
                            let db = db.min(25);
                            dist_hist[db] += 1;
                            dist_bits[db] += (bits.position() - after_length) as u64;
                            let bucket = if distance >= 8 << 20 {
                                &mut far_len[lb]
                            } else {
                                &mut near_len[lb]
                            };
                            bucket[0] += 1;
                            bucket[1] += length as u64;
                        }
                    }
                }
                if header.is_last {
                    break;
                }
            }
            let mb = |bits: u64| bits as f64 / 8.0 / 1e6;
            if member_count > 1 {
                packed_total += packed.len();
                unpacked_total += file.unpacked_size;
                for (key, value) in [
                    ("blocks", blocks as f64),
                    ("table sets", table_sets as f64),
                    ("table MB", mb(table_bits)),
                    ("header MB", mb(header_bits)),
                    ("literal tokens", lit[0] as f64),
                    ("literal MB", mb(lit[1])),
                    ("match tokens", mat[0] as f64),
                    ("match MB", mb(mat[1])),
                    ("match copied MB", mat[2] as f64 / 1e6),
                    ("rep0 tokens", rep[0][0] as f64),
                    ("rep0 copied MB", rep[0][2] as f64 / 1e6),
                    ("rep-last copied MB", rep_last[2] as f64 / 1e6),
                    (
                        "far matches",
                        far_len.iter().map(|b| b[0]).sum::<u64>() as f64,
                    ),
                    (
                        "far copied MB",
                        far_len.iter().map(|b| b[1]).sum::<u64>() as f64 / 1e6,
                    ),
                ] {
                    *totals.entry(key).or_insert(0.0) += value;
                }
                continue;
            }
            println!(
                "== {} packed {} MB, unpacked {} MB",
                String::from_utf8_lossy(&file.name),
                packed.len() as f64 / 1e6,
                file.unpacked_size as f64 / 1e6
            );
            println!("blocks {blocks}, table sets {table_sets} ({repeated_table_sets} identical to the previous), block headers {:.2} MB, tables {:.2} MB, payload {:.2} MB",
                mb(header_bits), mb(table_bits), mb(payload_bits_total));
            println!(
                "literals   {:>12} tokens {:>8.2} MB {:>6.3} bits/lit",
                lit[0],
                mb(lit[1]),
                lit[1] as f64 / lit[0].max(1) as f64
            );
            println!("filters    {:>12} tokens {:>8.2} MB", filt[0], mb(filt[1]));
            println!(
                "rep-last   {:>12} tokens {:>8.2} MB {:>10.1} MB copied",
                rep_last[0],
                mb(rep_last[1]),
                rep_last[2] as f64 / 1e6
            );
            for (index, r) in rep.iter().enumerate() {
                println!(
                    "rep{index}       {:>12} tokens {:>8.2} MB {:>10.1} MB copied, avg len {:.1}",
                    r[0],
                    mb(r[1]),
                    r[2] as f64 / 1e6,
                    r[2] as f64 / r[0].max(1) as f64
                );
            }
            println!("matches    {:>12} tokens {:>8.2} MB {:>10.1} MB copied, avg len {:.1}, {:.2} bits/match", mat[0], mb(mat[1]), mat[2] as f64 / 1e6, mat[2] as f64 / mat[0].max(1) as f64, mat[1] as f64 / mat[0].max(1) as f64);
            let names = [
                "4-7", "8-15", "16-31", "32-63", "64-127", "128-255", "256-1023", "1024+",
            ];
            for (i, name) in names.iter().enumerate() {
                println!(
                    "  len {:>9}: {:>10} matches, {:>6.2} MB of length+symbol bits",
                    name,
                    len_hist[i],
                    mb(len_bits[i])
                );
            }
            for (i, name) in names.iter().enumerate() {
                println!("  far>=8MiB len {:>9}: {:>10} matches {:>7.1} MB copied | nearer: {:>10} matches {:>7.1} MB", name, far_len[i][0], far_len[i][1] as f64 / 1e6, near_len[i][0], near_len[i][1] as f64 / 1e6);
            }
            for (i, count) in dist_hist.iter().enumerate() {
                if *count > 0 {
                    println!(
                        "  dist 2^{:>2}: {:>10} matches, {:>6.2} MB of distance bits",
                        i.saturating_sub(1),
                        count,
                        mb(dist_bits[i])
                    );
                }
            }
        }
        if member_count > 1 {
            println!(
                "== {member_count} compressed members, packed {:.2} MB, unpacked {:.2} MB",
                packed_total as f64 / 1e6,
                unpacked_total as f64 / 1e6
            );
            for (key, value) in &totals {
                println!("  {key:>20}: {value:.2}");
            }
        }
    }

    #[test]
    fn large_lz_members_are_split_into_multiple_compressed_blocks() {
        let data = vec![0u8; MAX_COMPRESSED_BLOCK_OUTPUT + 1];
        let encoded = encode_lz_member_with_options(&data, 0, EncodeOptions::new(16)).unwrap();
        let mut cursor = std::io::Cursor::new(encoded.as_slice());
        let mut payload = Vec::new();
        // Two tokenizer blocks, each cut into entropy blocks with their own
        // tables: every block but the last says it is not the last.
        let mut blocks = 0usize;
        loop {
            let block = read_compressed_block_into(&mut cursor, &mut payload).unwrap();
            blocks += 1;
            assert!(block.has_tables, "block {blocks} carries its own tables");
            if block.is_last {
                break;
            }
        }
        assert!(blocks >= 2, "{blocks} blocks");
        assert_eq!(cursor.position() as usize, encoded.len());
        let mut decoder = Rar50Decoder::new();

        assert_eq!(
            decoder
                .decode_member(&encoded, 0, data.len(), false, DecodeMode::Lz)
                .unwrap(),
            data
        );
    }

    #[test]
    fn large_filtered_lz_members_split_filter_records_by_block() {
        let mut data: Vec<_> = (0..MAX_COMPRESSED_BLOCK_OUTPUT + 512)
            .map(|index| index as u8)
            .collect();
        data[256] = 0xe8;
        data[257..261].copy_from_slice(&0x20u32.to_le_bytes());
        data[MAX_COMPRESSED_BLOCK_OUTPUT + 64] = 0xe8;
        data[MAX_COMPRESSED_BLOCK_OUTPUT + 65..MAX_COMPRESSED_BLOCK_OUTPUT + 69]
            .copy_from_slice(&0x40u32.to_le_bytes());

        let encoded = Rar50Encoder::with_options(EncodeOptions::new(0))
            .encode_member_with_filter(
                &data,
                0,
                Rar50FilterSpec::range(Rar50FilterKind::E8, 0..data.len()),
            )
            .unwrap();
        let mut cursor = std::io::Cursor::new(encoded.as_slice());
        let mut payload = Vec::new();
        let first = read_compressed_block_into(&mut cursor, &mut payload).unwrap();
        let mut blocks = 1usize;
        let mut last_is_last = first.is_last;
        while cursor.position() < encoded.len() as u64 {
            last_is_last = read_compressed_block_into(&mut cursor, &mut payload)
                .unwrap()
                .is_last;
            blocks += 1;
        }
        let mut decoder = Rar50Decoder::new();

        assert!(!first.is_last);
        assert!(last_is_last);
        // One 4 MiB tokenizer block and the tail: the records are split per
        // 262,143-byte chunk inside them, and the entropy cut is the
        // boundary search's (it used to be one compressed block per chunk).
        assert!(blocks >= 2);
        assert_eq!(
            decoder
                .decode_member(&encoded, 0, data.len(), false, DecodeMode::Lz)
                .unwrap(),
            data
        );
    }

    /// `e8 <rel32>` call records, i.e. data an E8 filter really rewrites, so
    /// the filtered stream differs from the input.
    fn e8_call_records(len: usize) -> Vec<u8> {
        let mut data = Vec::with_capacity(len + 5);
        let mut word = 0u32;
        while data.len() < len {
            data.push(0xe8);
            data.extend_from_slice(&word.wrapping_mul(2654435761).to_le_bytes());
            word = word.wrapping_add(1);
        }
        data.truncate(len);
        data
    }

    /// A solid member that follows a FILTERED member must compress against
    /// the same window the decoder has. The decoder's window holds the LZ
    /// output, i.e. the filter-encoded bytes, because a declared filter is
    /// applied to a scratch copy of its range as that range completes and
    /// never in place (trap 5: the reference extractor behaves the same way,
    /// filtering a copy of the range). The encoder used to remember
    /// the PRE-filter input instead, so any cross-member match reaching into
    /// a filter-mutated range resolved against bytes the decoder never had.
    #[test]
    fn solid_member_after_filtered_member_matches_decoder_window() {
        // The small member takes the single-block `filtered_lz_member` path;
        // the large one takes the `filtered_lz_blocks` path. Whether the
        // large one actually emits a cross-member match into a mutated range
        // is payload dependent, so it pins the branch rather than proving it.
        for len in [4000usize, MAX_FILTER_BLOCK_LENGTH + 5000] {
            let a = e8_call_records(len);
            let b = a.clone();

            let mut encoder = Rar50Encoder::with_options(EncodeOptions::new(4));
            let packed_a = encoder
                .encode_member_with_filter(&a, 0, Rar50FilterSpec::new(Rar50FilterKind::E8))
                .unwrap();
            let packed_b = encoder.encode_member(&b, 0).unwrap();

            let mut decoder = Rar50Decoder::new();
            let decoded_a = decoder
                .decode_member(&packed_a, 0, a.len(), false, DecodeMode::Lz)
                .unwrap();
            assert_eq!(decoded_a, a, "len {len}: filtered member");
            let decoded_b = decoder
                .decode_member(&packed_b, 0, b.len(), true, DecodeMode::Lz)
                .unwrap();
            assert_eq!(decoded_b, b, "len {len}: solid member after a filter");
        }
    }

    #[test]
    fn filters_are_split_before_rar_reader_filter_limit() {
        let data = vec![0u8; MAX_FILTER_BLOCK_LENGTH + 1];
        let encoded = Rar50Encoder::with_options(
            EncodeOptions::new(0).with_max_match_distance(128 * 1024),
        )
        .encode_member_with_filter(
            &data,
            0,
            Rar50FilterSpec::new(Rar50FilterKind::Delta { channels: 4 }),
        )
        .unwrap();
        let mut cursor = std::io::Cursor::new(encoded.as_slice());
        let mut payload = Vec::new();
        let mut last = read_compressed_block_into(&mut cursor, &mut payload).unwrap();
        while cursor.position() < encoded.len() as u64 {
            last = read_compressed_block_into(&mut cursor, &mut payload).unwrap();
        }
        let mut decoder = Rar50Decoder::new();

        // Two records of 262,143 and 1 byte, whatever the compressed-block
        // layout (one block since the pooled path took filtered members).
        assert!(last.is_last);
        assert_eq!(
            decoder
                .decode_member(&encoded, 0, data.len(), false, DecodeMode::Lz)
                .unwrap(),
            data
        );
    }

    #[test]
    fn solid_encoder_history_limit_follows_encode_options_dictionary() {
        let mut encoder = Rar50Encoder::with_options(
            EncodeOptions::new(0).with_max_match_distance(DEFAULT_DICTIONARY_SIZE + 1024),
        );
        encoder.remember(&vec![0x41; DEFAULT_DICTIONARY_SIZE + 512]);

        assert_eq!(encoder.history.len(), DEFAULT_DICTIONARY_SIZE + 512);

        let mut capped =
            Rar50Encoder::with_options(EncodeOptions::new(0).with_max_match_distance(1024));
        capped.remember(&vec![0x42; 4096]);

        assert_eq!(capped.history.len(), 1024);
    }

    #[test]
    fn encodes_lz_member_with_last_length_repeat_symbols() {
        // Eight distinct filler bytes between the repeats price the literals
        // like real data (a four-byte match must save bits against them -
        // see `LiteralPrices`) without a literal run long enough to start
        // the probe acceleration, which the old one-byte fillers with a
        // 200-byte diverse prefix did, skipping two of the repeats.
        let mut data = Vec::new();
        for (index, filler) in (0u8..3).zip([200u8, 208, 216]) {
            let _ = index;
            data.extend_from_slice(b"abcd");
            data.extend(filler..filler + 8);
        }
        data.extend_from_slice(b"abcd");
        let data = &data[..];
        let input = encode_lz_member(data, 0).unwrap();
        let block = parse_compressed_block(&input).unwrap();
        let (lengths, _) = read_table_lengths(&input[block.payload], 0).unwrap();

        let output = decode_lz(&input, 0, data.len()).unwrap();

        assert_eq!(output, data);
        assert_ne!(lengths.main[257], 0);
    }

    #[test]
    fn encodes_lz_member_using_rar70_distance_table_shape() {
        let data = b"RAR7-compatible repeated phrase repeated phrase repeated phrase";
        let input = encode_lz_member(data, 1).unwrap();

        let output = decode_lz(&input, 1, data.len()).unwrap();

        assert_eq!(output, data);
    }

    #[test]
    fn decode_member_from_reader_accepts_incremental_input() {
        struct OneByteReader<'a> {
            data: &'a [u8],
            pos: usize,
        }

        impl Read for OneByteReader<'_> {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                if self.pos >= self.data.len() {
                    return Ok(0);
                }
                out[0] = self.data[self.pos];
                self.pos += 1;
                Ok(1)
            }
        }

        let payload = literal_only_payload(b"ABBA");
        let input = encode_compressed_block(&payload, payload.len() * 8, true, true).unwrap();
        let mut reader = OneByteReader {
            data: &input,
            pos: 0,
        };
        let mut decoder = Rar50Decoder::new();

        let output = decoder
            .decode_member_from_reader(&mut reader, 0, 4, false, DecodeMode::LiteralOnly)
            .unwrap();

        assert_eq!(output, b"ABBA");
    }

    #[test]
    fn decodes_synthetic_new_match_block() {
        let payload = new_match_payload();
        let input = encode_compressed_block(&payload, payload.len() * 8, true, true).unwrap();

        let output = decode_lz(&input, 0, 4).unwrap();

        assert_eq!(output, b"ABAB");
    }

    #[test]
    fn decodes_synthetic_last_length_match_block() {
        let payload = repeat_payload(257);
        let input = encode_compressed_block(&payload, payload.len() * 8, true, true).unwrap();

        let output = decode_lz(&input, 0, 6).unwrap();

        assert_eq!(output, b"ABABAB");
    }

    #[test]
    fn decodes_synthetic_repeat_distance_match_block() {
        let payload = repeat_payload(258);
        let input = encode_compressed_block(&payload, payload.len() * 8, true, true).unwrap();

        let output = decode_lz(&input, 0, 6).unwrap();

        assert_eq!(output, b"ABABAB");
    }

    #[test]
    fn rejects_literal_only_block_without_tables() {
        let input = encode_compressed_block(&[0], 8, false, true).unwrap();

        assert_eq!(
            decode_literal_only(&input, 0, 1),
            Err(Error::InvalidData("RAR 5 block reuses missing tables"))
        );
    }

    #[test]
    fn decodes_length_slots() {
        assert_eq!(match_length_for_slot(0, 0).unwrap(), 2);
        assert_eq!(match_length_for_slot(7, 0).unwrap(), 9);
        assert_eq!(match_length_for_slot(8, 0).unwrap(), 10);
        assert_eq!(match_length_for_slot(8, 1).unwrap(), 11);
        assert_eq!(match_length_for_slot(11, 1).unwrap(), 17);
        assert_eq!(match_length_for_slot(12, 3).unwrap(), 21);
    }

    #[test]
    fn decodes_distance_slots() {
        assert_eq!(slot_to_distance(0, 0).unwrap(), 1);
        assert_eq!(slot_to_distance(3, 0).unwrap(), 4);
        assert_eq!(distance_slot_bit_count(4).unwrap(), 1);
        assert_eq!(slot_to_distance(4, 0).unwrap(), 5);
        assert_eq!(slot_to_distance(4, 1).unwrap(), 6);
        assert_eq!(distance_slot_bit_count(10).unwrap(), 4);
        assert_eq!(slot_to_distance(10, 15).unwrap(), 48);
    }

    /// The TOP of the distance ladder, where the value is wider than the
    /// target's `usize` on a 32-bit build.
    ///
    /// Slot 65 carries 31 extra bits, so its largest distance is
    /// `(3 << 31) | (2^31 - 1)` plus one = 2^33: thirty-four bits, which
    /// no 32-bit `usize` holds. Computing the ladder in `usize` therefore
    /// wrapped and panicked on the `+ 1` under the nightly armv7-cross
    /// job's `overflow-checks` (run 33737735769) - and in a release build
    /// would have wrapped SILENTLY to a tiny distance and mis-decoded the
    /// match. `distance_from_parts` computes in `u64` and saturates.
    ///
    /// Written to hold on BOTH widths deliberately, because this box is
    /// 64-bit and the target that broke is not: the exact answer where it
    /// is representable, `usize::MAX` where it is not, and on every slot
    /// the guarantee that matters either way - the value never wrapped
    /// DOWN below the slot's own base.
    #[test]
    fn the_widest_distance_slots_do_not_wrap_a_32_bit_usize() {
        let widest: u64 = 1u64 << 33;
        assert_eq!(
            slot_to_distance(65, (1u32 << 31) - 1).unwrap() as u64,
            widest.min(usize::MAX as u64),
            "the widest RAR 5 distance is 2^33, saturated where usize is narrower"
        );

        for slot in 0..DISTANCE_TABLE_SIZE_70 {
            let Ok(bit_count) = distance_slot_bit_count(slot) else {
                continue;
            };
            let extra = if bit_count == 0 {
                0
            } else {
                (1u32 << bit_count) - 1
            };
            let got = slot_to_distance(slot, extra).unwrap();
            let base = 1u64 << bit_count;
            assert!(
                got as u64 >= base.min(usize::MAX as u64),
                "distance slot {slot} wrapped below its own base ({got} < 2^{bit_count})"
            );
        }

        // ...and the encoding half stays on the SAME width as the decoding
        // half. `distance_slot_for_match` walks the ladder upward and must
        // evaluate the window of every slot below the one that matches, so
        // a `usize` there would overflow on the way past the top slots even
        // for a small distance. Every value the forward ladder can actually
        // represent on this target must map back to the slot and extra bits
        // it came from; the ones it cannot represent here are skipped, since
        // the forward half saturates them on purpose.
        for slot in 0..DISTANCE_TABLE_SIZE_70 {
            let Ok(bit_count) = distance_slot_bit_count(slot) else {
                continue;
            };
            let top = if bit_count == 0 {
                0
            } else {
                (1u32 << bit_count) - 1
            };
            for extra in [0, top] {
                if slot >= 4
                    && usize::try_from(distance_wide(slot, bit_count as u8, extra)).is_err()
                {
                    continue;
                }
                let d = slot_to_distance(slot, extra).unwrap();
                assert_eq!(
                    distance_slot_for_match(d, DISTANCE_TABLE_SIZE_70).unwrap(),
                    (slot, extra as usize),
                    "distance {d} did not map back to slot {slot} extra {extra}"
                );
            }
        }
    }

    #[test]
    fn bit_reader_accepts_large_rar5_distance_extras() {
        let mut bits = BitReader::new(&[0xff, 0x00, 0xaa, 0x55]);

        assert_eq!(bits.read_bits(32).unwrap(), 0xff00_aa55);
        assert_eq!(
            bits.read_bits(1),
            Err(Error::NeedMoreInput),
            "32-bit reads must not leave a partial cursor state"
        );

        // The forced-inline cache-hit arm must still reject an invalid width
        // even when a preceding peek has filled the cache far past it.
        let mut overwide = BitReader::new(&[0; 8]);
        assert_eq!(overwide.peek15(), Some(0));
        assert_eq!(overwide.position(), 0);
        assert_eq!(
            overwide.read_bits(33),
            Err(Error::InvalidData("RAR 5 bit read is too wide"))
        );
        assert_eq!(overwide.position(), 0, "an invalid read is non-consuming");
    }

    #[test]
    fn copies_lz_matches_with_overlap() {
        let decoder = Rar50Decoder::new();
        let mut output = b"AB".to_vec();

        decoder
            .copy_match(&mut output, 2, 6, 8, DEFAULT_DICTIONARY_SIZE)
            .unwrap();

        assert_eq!(output, b"ABABABAB");
    }

    #[test]
    fn rejects_invalid_match_copy() {
        let decoder = Rar50Decoder::new();
        let mut output = b"AB".to_vec();

        assert_eq!(
            decoder.copy_match(&mut output, 3, 1, 3, DEFAULT_DICTIONARY_SIZE),
            Err(Error::InvalidData("RAR 5 match distance exceeds window"))
        );
        assert_eq!(
            decoder.copy_match(&mut output, 1, 2, 3, DEFAULT_DICTIONARY_SIZE),
            Err(Error::InvalidData("RAR 5 match exceeds output limit"))
        );
    }

    #[test]
    fn rejects_match_distance_beyond_dictionary() {
        let decoder = Rar50Decoder::new();
        let mut output = b"ABCD".to_vec();

        assert_eq!(
            decoder.copy_match(&mut output, 4, 1, 5, 3),
            Err(Error::InvalidData(
                "RAR 5 match distance exceeds dictionary"
            ))
        );
    }

    #[test]
    fn solid_history_is_capped_to_dictionary_size() {
        let mut decoder = Rar50Decoder::new();
        let first_payload = literal_only_payload(b"ABBA");
        let first =
            encode_compressed_block(&first_payload, first_payload.len() * 8, true, true).unwrap();
        let second_payload = literal_only_payload(b"BAAB");
        let second =
            encode_compressed_block(&second_payload, second_payload.len() * 8, true, true).unwrap();

        assert_eq!(
            decoder
                .decode_member_with_dictionary(&first, 0, 4, 6, false, DecodeMode::LiteralOnly)
                .unwrap(),
            b"ABBA"
        );
        assert_eq!(decoder.history_window(), b"ABBA");

        assert_eq!(
            decoder
                .decode_member_with_dictionary(&second, 0, 4, 6, true, DecodeMode::LiteralOnly)
                .unwrap(),
            b"BAAB"
        );
        // The live window is offset-addressed: trimming advances the start
        // instead of shifting the buffer, so assert on the window view.
        assert_eq!(decoder.history_window(), b"BABAAB");
    }

    /// A solid checkpoint must rewind a failed member decode exactly: same
    /// window, same reps/tables, so the retry decodes identically - and a
    /// commit_member compaction afterwards must leave the window intact.
    #[test]
    fn solid_checkpoint_rewinds_member_decode() {
        let mut decoder = Rar50Decoder::new();
        let first_payload = literal_only_payload(b"ABBA");
        let first =
            encode_compressed_block(&first_payload, first_payload.len() * 8, true, true).unwrap();
        let second_payload = literal_only_payload(b"BAAB");
        let second =
            encode_compressed_block(&second_payload, second_payload.len() * 8, true, true).unwrap();

        decoder
            .decode_member_with_dictionary(&first, 0, 4, 6, false, DecodeMode::LiteralOnly)
            .unwrap();
        let cp = decoder.solid_checkpoint();
        let once = decoder
            .decode_member_with_dictionary(&second, 0, 4, 6, true, DecodeMode::LiteralOnly)
            .unwrap();
        let window_after = decoder.history_window().to_vec();

        // Rewind and decode the same member again - byte-identical outcome.
        decoder.restore_checkpoint(&cp);
        assert_eq!(decoder.history_window(), b"ABBA");
        let again = decoder
            .decode_member_with_dictionary(&second, 0, 4, 6, true, DecodeMode::LiteralOnly)
            .unwrap();
        assert_eq!(once, again);
        assert_eq!(decoder.history_window(), window_after.as_slice());

        // Compaction (when it chooses to run) must not change the window.
        // It only fires once the dead front outweighs the live window, so
        // force that shape before asserting the reclaim.
        decoder.commit_member();
        assert_eq!(decoder.history_window(), window_after.as_slice());
        decoder.history_start = decoder.history.len() - 1; // dead front > window
        let last = decoder.history_window().to_vec();
        decoder.commit_member();
        assert_eq!(decoder.history_window(), last.as_slice());
        assert_eq!(decoder.history_start, 0);
    }

    #[test]
    fn streaming_decoder_history_is_capped_without_reordering() {
        let mut decoder = Rar50Decoder::new();
        let first_payload = literal_only_payload(b"ABBA");
        let first =
            encode_compressed_block(&first_payload, first_payload.len() * 8, true, true).unwrap();
        let second_payload = literal_only_payload(b"BAAB");
        let second =
            encode_compressed_block(&second_payload, second_payload.len() * 8, true, true).unwrap();
        let mut decoded = Vec::new();

        decoder
            .decode_member_from_reader_with_dictionary_to_sink(
                &mut std::io::Cursor::new(&first),
                0,
                4,
                6,
                false,
                0, // flat_limit 0: keep this test on the streaming path
                |chunk| {
                    match chunk {
                        DecodedChunk::Bytes(bytes) => decoded.extend_from_slice(bytes),
                        DecodedChunk::Repeated { byte, len } => {
                            decoded.extend(std::iter::repeat_n(byte, len));
                        }
                    }
                    Ok::<(), std::io::Error>(())
                },
            )
            .unwrap();
        assert_eq!(decoded, b"ABBA");
        assert_eq!(decoder.history, b"ABBA");

        decoded.clear();
        decoder
            .decode_member_from_reader_with_dictionary_to_sink(
                &mut std::io::Cursor::new(&second),
                0,
                4,
                6,
                true,
                0, // flat_limit 0: solid member, streaming path regardless
                |chunk| {
                    match chunk {
                        DecodedChunk::Bytes(bytes) => decoded.extend_from_slice(bytes),
                        DecodedChunk::Repeated { byte, len } => {
                            decoded.extend(std::iter::repeat_n(byte, len));
                        }
                    }
                    Ok::<(), std::io::Error>(())
                },
            )
            .unwrap();
        assert_eq!(decoded, b"BAAB");
        assert_eq!(decoder.history, b"BABAAB");
    }

    fn literal_only_payload(data: &[u8]) -> Vec<u8> {
        let mut lengths = TableLengths {
            main: vec![0; MAIN_TABLE_SIZE],
            distance: vec![0; DISTANCE_TABLE_SIZE_50],
            align: vec![0; ALIGN_TABLE_SIZE],
            length: vec![0; LENGTH_TABLE_SIZE],
        };
        lengths.main[b'A' as usize] = 1;
        lengths.main[b'B' as usize] = 1;
        let (bytes, bit_pos) = encode_table_lengths_with_bit_count(&lengths, 0).unwrap();
        let mut writer = BitWriter::continuing(bytes, bit_pos);
        for &byte in data {
            match byte {
                b'A' => writer.write_bits(0, 1),
                b'B' => writer.write_bits(1, 1),
                _ => panic!("test helper only encodes A/B"),
            }
        }
        writer.finish()
    }

    fn new_match_payload() -> Vec<u8> {
        let mut lengths = TableLengths {
            main: vec![0; MAIN_TABLE_SIZE],
            distance: vec![0; DISTANCE_TABLE_SIZE_50],
            align: vec![0; ALIGN_TABLE_SIZE],
            length: vec![0; LENGTH_TABLE_SIZE],
        };
        lengths.main[b'A' as usize] = 2;
        lengths.main[b'B' as usize] = 2;
        lengths.main[262] = 2;
        lengths.distance[1] = 1;
        let (bytes, bit_pos) = encode_table_lengths_with_bit_count(&lengths, 0).unwrap();
        let mut writer = BitWriter::continuing(bytes, bit_pos);

        writer.write_bits(0b00, 2); // 'A'
        writer.write_bits(0b01, 2); // 'B'
        writer.write_bits(0b10, 2); // match length 2
        writer.write_bits(0, 1); // distance slot 1
        writer.finish()
    }

    /// Decode a member through the streaming sink entry point, which under
    /// `--features parallel` + cfg(test) always takes the multithreaded
    /// block pipeline. Collects the sink chunks into one buffer.
    #[cfg(feature = "parallel")]
    fn mt_sink_decode(
        encoded: &[u8],
        output_size: usize,
        decoder: &mut Rar50Decoder,
    ) -> std::result::Result<Vec<u8>, StreamDecodeError<std::convert::Infallible>> {
        let mut cursor = std::io::Cursor::new(encoded);
        let mut out = Vec::new();
        decoder.decode_member_from_reader_with_dictionary_to_sink(
            &mut cursor,
            0,
            output_size,
            DEFAULT_DICTIONARY_SIZE,
            false,
            0, // flat_limit 0: this helper exercises the streaming-MT path
            |chunk| {
                match chunk {
                    DecodedChunk::Bytes(bytes) => out.extend_from_slice(bytes),
                    DecodedChunk::Repeated { byte, len } => {
                        out.extend(std::iter::repeat_n(byte, len))
                    }
                }
                Ok(())
            },
        )?;
        Ok(out)
    }

    /// Data shapes chosen to drive distinct op mixes: literal bursts, dense
    /// short-period matches (rep chains), sparse zero runs, and transitions
    /// between them. Sizes exceed one 4 MB compressed-block output so every
    /// shape crosses block boundaries.
    #[cfg(feature = "parallel")]
    fn differential_shapes() -> Vec<(&'static str, Vec<u8>)> {
        let big = MAX_COMPRESSED_BLOCK_OUTPUT + (256 << 10);
        let mut lcg = 0x2545F491_4F6CDD1Du64;
        let mut random = Vec::with_capacity(big);
        while random.len() < big {
            lcg = lcg
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            random.extend_from_slice(&lcg.to_le_bytes());
        }
        random.truncate(big);

        let phrase = b"the quick brown fox jumps over the lazy dog 0123456789 ";
        let mut text = Vec::with_capacity(big);
        while text.len() < big {
            text.extend_from_slice(phrase);
        }
        text.truncate(big);

        let mut short_period = Vec::with_capacity(big);
        while short_period.len() < big {
            short_period.extend_from_slice(b"abcabca");
        }
        short_period.truncate(big);

        let zeroes = vec![0u8; big];

        let mut mixed = Vec::with_capacity(big);
        for chunk in 0..(big / (64 << 10)) {
            match chunk % 4 {
                0 => mixed.extend_from_slice(&random[..64 << 10]),
                1 => mixed.extend(std::iter::repeat_n(0u8, 64 << 10)),
                2 => mixed.extend_from_slice(&text[..64 << 10]),
                _ => mixed.extend(b"xyzxyzx".iter().cycle().take(64 << 10)),
            }
        }

        vec![
            ("random", random),
            ("text", text),
            ("short_period", short_period),
            ("zeroes", zeroes),
            ("mixed", mixed),
        ]
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn parallel_decode_matches_reference_across_shapes() {
        for (name, data) in differential_shapes() {
            let encoded = encode_lz_member_with_options(&data, 0, EncodeOptions::new(4)).unwrap();

            let mut mt_decoder = Rar50Decoder::new();
            let mt_out = mt_sink_decode(&encoded, data.len(), &mut mt_decoder)
                .unwrap_or_else(|_| panic!("{name}: parallel decode failed"));
            assert_eq!(mt_out, data, "{name}: parallel output mismatch");

            // Reference: the untouched buffered decoder. Output and final
            // LZ state (rep distances, last length) must agree exactly.
            let mut reference = Rar50Decoder::new();
            let ref_out = reference
                .decode_member(&encoded, 0, data.len(), false, DecodeMode::Lz)
                .unwrap();
            assert_eq!(ref_out, data, "{name}: reference output mismatch");
            assert_eq!(
                mt_decoder.reps, reference.reps,
                "{name}: rep state diverged"
            );
            assert_eq!(
                mt_decoder.previous_match_length, reference.previous_match_length,
                "{name}: previous_match_length diverged"
            );
        }
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn parallel_cap_one_streaming_decode_matches_buffered_for_match_members() {
        // `mt_workers_cap(1)` plus `flat_limit = 0` deterministically selects
        // decode_block_serial even in a parallel build. Use a dense-match
        // member under both RAR 5 algorithm table shapes so that path and the
        // buffered reference both consume real distance codes.
        let phrase = b"RAR5 serial distance metadata: abcdefghijklmnopqrstuvwxyz 0123456789\n";
        let data_len = 512 << 10;
        let mut data = Vec::with_capacity(data_len);
        while data.len() < data_len {
            data.extend_from_slice(phrase);
        }
        data.truncate(data_len);

        for algorithm_version in [0, 1] {
            let encoded =
                encode_lz_member_with_options(&data, algorithm_version, EncodeOptions::new(4))
                    .unwrap();
            let block = parse_compressed_block(&encoded).unwrap();
            let (lengths, _) =
                read_table_lengths(&encoded[block.payload], algorithm_version).unwrap();
            assert!(
                lengths.main[262..].iter().any(|&length| length != 0),
                "algorithm {algorithm_version}: fixture must contain a new match"
            );
            assert!(
                lengths.distance.iter().any(|&length| length != 0),
                "algorithm {algorithm_version}: fixture must contain a distance code"
            );

            let mut buffered = Rar50Decoder::new();
            let buffered_out = buffered
                .decode_member(
                    &encoded,
                    algorithm_version,
                    data.len(),
                    false,
                    DecodeMode::Lz,
                )
                .unwrap();
            assert_eq!(
                buffered_out, data,
                "algorithm {algorithm_version}: buffered"
            );

            let mut serial = Rar50Decoder::new();
            serial.set_mt_workers_cap(1);
            let mut cursor = std::io::Cursor::new(&encoded);
            let mut serial_out = Vec::with_capacity(data.len());
            serial
                .decode_member_from_reader_with_dictionary_to_sink(
                    &mut cursor,
                    algorithm_version,
                    data.len(),
                    DEFAULT_DICTIONARY_SIZE,
                    false,
                    0,
                    |chunk| {
                        match chunk {
                            DecodedChunk::Bytes(bytes) => serial_out.extend_from_slice(bytes),
                            DecodedChunk::Repeated { byte, len } => {
                                serial_out.extend(std::iter::repeat_n(byte, len));
                            }
                        }
                        Ok::<(), std::convert::Infallible>(())
                    },
                )
                .unwrap();

            assert_eq!(
                serial_out, buffered_out,
                "algorithm {algorithm_version}: serial sink output"
            );
            assert_eq!(
                serial.reps, buffered.reps,
                "algorithm {algorithm_version}: rep state"
            );
            assert_eq!(
                serial.previous_match_length, buffered.previous_match_length,
                "algorithm {algorithm_version}: last-length state"
            );
        }
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn parallel_decode_clamps_at_smaller_output_size() {
        // Asking for a prefix stops the apply stage mid-tape: worker-decoded
        // surplus must be discarded (literal runs clamp cleanly) or fail
        // exactly like the reference (a match crossing the limit errors).
        for (name, data) in differential_shapes() {
            let encoded = encode_lz_member_with_options(&data, 0, EncodeOptions::new(4)).unwrap();
            for prefix in [data.len() - 1234, data.len() / 2, data.len() / 3 + 7] {
                let mut reference = Rar50Decoder::new();
                let ref_result =
                    reference.decode_member(&encoded, 0, prefix, false, DecodeMode::Lz);
                let mut mt_decoder = Rar50Decoder::new();
                let mt_result = mt_sink_decode(&encoded, prefix, &mut mt_decoder);
                match ref_result {
                    Ok(ref_out) => {
                        let mt_out = mt_result.unwrap_or_else(|_| {
                            panic!("{name}/{prefix}: parallel failed where reference succeeded")
                        });
                        assert_eq!(mt_out, ref_out, "{name}/{prefix}: prefix output mismatch");
                    }
                    Err(ref_error) => match mt_result {
                        Err(StreamDecodeError::Decode(mt_error)) => {
                            assert_eq!(mt_error, ref_error, "{name}/{prefix}: error mismatch")
                        }
                        Ok(_) => {
                            panic!("{name}/{prefix}: parallel succeeded where reference errored")
                        }
                        Err(_) => panic!("{name}/{prefix}: unexpected error variant"),
                    },
                }
            }
        }
    }

    /// Two chain groups on one decoder: the second group starts with a
    /// non-empty carried window, which used to force the ring path; now it
    /// takes the SEEDED flat path. Both groups (and the ring variant, via
    /// flat_limit 0) must reproduce the serial member-by-member decode,
    /// including matches from group B reaching back into group A's bytes
    /// through the seeded prefix, and final rep/window state. Group B's
    /// SECOND member carries a mid-member E8 range, so the filter origin
    /// has to shed both shifts at once: the seeded prefix AND the earlier
    /// member of its own group.
    #[test]
    #[cfg(feature = "parallel")]
    fn seeded_flat_second_chain_group_matches_serial() {
        // Four solid members; later members repeat earlier members' data so
        // the encoder emits cross-member (and cross-GROUP) matches.
        let base: Vec<u8> = (0u32..6000)
            .map(|i| (i.wrapping_mul(2654435761) >> 11) as u8)
            .collect();
        let mut last: Vec<u8> = base
            .iter()
            .rev()
            .copied()
            .chain(base[..2000].iter().copied())
            .collect();
        let filter_start = last.len();
        last.extend_from_slice(&address_filter_payload(2048));
        let filter_range = filter_start..last.len();
        let members: Vec<Vec<u8>> = vec![
            base.clone(),
            base[..4000].to_vec(),
            base[1000..5000].to_vec(),
            last,
        ];
        let mut encoder = Rar50Encoder::with_options(EncodeOptions::new(4));
        let encoded: Vec<Vec<u8>> = members
            .iter()
            .enumerate()
            .map(|(index, data)| {
                if index == 3 {
                    encoder
                        .encode_member_with_filters(
                            data,
                            0,
                            &[Rar50FilterSpec::range(
                                Rar50FilterKind::E8,
                                filter_range.clone(),
                            )],
                        )
                        .unwrap()
                } else {
                    encoder.encode_member(data, 0).unwrap()
                }
            })
            .collect();

        // Serial oracle: one decoder, members decoded in order, solid.
        let mut serial = Rar50Decoder::new();
        let mut serial_out = Vec::new();
        for (data, packed) in members.iter().zip(&encoded) {
            serial_out.extend(
                serial
                    .decode_member(packed, 0, data.len(), true, DecodeMode::Lz)
                    .unwrap(),
            );
        }
        assert_eq!(
            serial_out,
            members.concat(),
            "oracle disagrees with encoder"
        );

        // Chain in two groups of two; the second call sees a carried window.
        for flat_limit in [u64::MAX, 0] {
            let mut chained = Rar50Decoder::new();
            let mut chain_out: Vec<u8> = Vec::new();
            for group in [[0usize, 1], [2, 3]] {
                let sizes: Vec<usize> = group.iter().map(|&i| members[i].len()).collect();
                let mut next = 0usize;
                let readers: Vec<&[u8]> = group.iter().map(|&i| encoded[i].as_slice()).collect();
                let mut next_input = || -> Option<Box<dyn std::io::Read + Send>> {
                    let reader = readers.get(next)?;
                    next += 1;
                    Some(Box::new(std::io::Cursor::new(reader.to_vec())))
                };
                if group[0] != 0 {
                    assert!(
                        chained.history_window_len() > 0,
                        "second group must start seeded"
                    );
                }
                chained
                    .decode_solid_chain_to_sink(
                        &mut next_input,
                        0,
                        &sizes,
                        DEFAULT_DICTIONARY_SIZE,
                        false,
                        flat_limit,
                        |chunk| -> std::result::Result<(), std::convert::Infallible> {
                            match chunk {
                                DecodedChunk::Bytes(bytes) => chain_out.extend_from_slice(bytes),
                                DecodedChunk::Repeated { byte, len } => {
                                    chain_out.extend(std::iter::repeat_n(byte, len))
                                }
                            }
                            Ok(())
                        },
                    )
                    .unwrap();
            }
            assert_eq!(
                chain_out, serial_out,
                "chained output diverged at flat_limit {flat_limit}"
            );
            assert_eq!(chained.reps, serial.reps, "rep state diverged");
            assert_eq!(chained.previous_match_length, serial.previous_match_length);
        }
    }

    /// Data an address-translating filter actually rewrites: `e8 <rel32>`
    /// calls for E8/E8E9 and 4-aligned words ending in 0xeb for ARM, so a
    /// wrong filter origin shows up as different bytes rather than a no-op.
    #[cfg(feature = "parallel")]
    fn address_filter_payload(len: usize) -> Vec<u8> {
        let mut data = Vec::with_capacity(len + 8);
        let mut word = 0u32;
        while data.len() < len {
            data.push(0xe8);
            data.extend_from_slice(&word.wrapping_mul(3).to_le_bytes()[..3]);
            data.push(0x00);
            data.push(0x00);
            data.push(0xeb);
            word = word.wrapping_add(1);
        }
        data.truncate(len);
        data
    }

    /// An address filter declared by a member that is NOT the first of its
    /// chain group. E8/E8E9/ARM mix the filtered range's origin into every
    /// translated address, and that origin is the offset within the MEMBER
    /// (what the encoder bakes in, what a reference extractor's per-file
    /// output count gives, what the serial walk passes). The chain outputs count the
    /// whole group, so member 2's filter used to translate against
    /// `prior members + local offset` and silently emitted shifted
    /// addresses. Both legs - flat and, via flat_limit 0, the ring - must
    /// reproduce the serial member-by-member decode.
    #[test]
    #[cfg(feature = "parallel")]
    fn chain_filter_in_non_first_member_matches_serial() {
        for kind in [
            Rar50FilterKind::E8,
            Rar50FilterKind::E8E9,
            Rar50FilterKind::Arm,
        ] {
            let lead: Vec<u8> = (0u32..4096)
                .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
                .collect();
            let filtered = address_filter_payload(4096);
            let tail: Vec<u8> = lead.iter().rev().copied().collect();
            let members = [lead, filtered, tail];
            let filtered_index = 1usize;

            let mut encoder = Rar50Encoder::new();
            let encoded: Vec<Vec<u8>> = members
                .iter()
                .enumerate()
                .map(|(index, data)| {
                    if index == filtered_index {
                        encoder
                            .encode_member_with_filter(data, 0, Rar50FilterSpec::new(kind))
                            .unwrap()
                    } else {
                        encoder.encode_member(data, 0).unwrap()
                    }
                })
                .collect();

            // Serial oracle: one decoder, members in order, solid.
            let mut serial = Rar50Decoder::new();
            let mut serial_out = Vec::new();
            for (index, (data, packed)) in members.iter().zip(&encoded).enumerate() {
                serial_out.extend(
                    serial
                        .decode_member(packed, 0, data.len(), index != 0, DecodeMode::Lz)
                        .unwrap(),
                );
            }
            assert_eq!(
                serial_out,
                members.concat(),
                "{kind:?}: oracle disagrees with encoder"
            );

            for flat_limit in [u64::MAX, 0] {
                let sizes: Vec<usize> = members.iter().map(|data| data.len()).collect();
                let mut next = 0usize;
                let readers: Vec<&[u8]> = encoded.iter().map(|packed| packed.as_slice()).collect();
                let mut next_input = || -> Option<Box<dyn std::io::Read + Send>> {
                    let reader = readers.get(next)?;
                    next += 1;
                    Some(Box::new(std::io::Cursor::new(reader.to_vec())))
                };
                let mut chained = Rar50Decoder::new();
                let mut chain_out: Vec<u8> = Vec::new();
                chained
                    .decode_solid_chain_to_sink(
                        &mut next_input,
                        0,
                        &sizes,
                        DEFAULT_DICTIONARY_SIZE,
                        true,
                        flat_limit,
                        |chunk| -> std::result::Result<(), std::convert::Infallible> {
                            match chunk {
                                DecodedChunk::Bytes(bytes) => chain_out.extend_from_slice(bytes),
                                DecodedChunk::Repeated { byte, len } => {
                                    chain_out.extend(std::iter::repeat_n(byte, len))
                                }
                            }
                            Ok(())
                        },
                    )
                    .unwrap();
                assert_eq!(
                    chain_out, serial_out,
                    "{kind:?}: chained output diverged at flat_limit {flat_limit}"
                );
            }
        }
    }

    /// Lazy table builds move `DecodeTables::from_lengths` failures from the
    /// scanner to the workers; the deferred-error contract must survive the
    /// move. A read-ahead block whose table set parses but fails to BUILD
    /// must be swallowed when the member's output completed before it (the
    /// serial decoder never builds those tables), and must surface the exact
    /// serial error when the member still needs output from it.
    #[test]
    #[cfg(feature = "parallel")]
    fn parallel_decode_defers_read_ahead_table_build_failure() {
        // Block 1: valid tables, emits "ABAB" (2 literals + a match).
        let mut lengths = TableLengths {
            main: vec![0; MAIN_TABLE_SIZE],
            distance: vec![0; DISTANCE_TABLE_SIZE_50],
            align: vec![0; ALIGN_TABLE_SIZE],
            length: vec![0; LENGTH_TABLE_SIZE],
        };
        lengths.main[b'A' as usize] = 2;
        lengths.main[b'B' as usize] = 2;
        lengths.main[257] = 2;
        lengths.main[262] = 2;
        lengths.distance[1] = 1;
        lengths.length[0] = 1;
        let (bytes, bit_pos) = encode_table_lengths_with_bit_count(&lengths, 0).unwrap();
        let mut writer = BitWriter::continuing(bytes, bit_pos);
        writer.write_bits(0b00, 2); // 'A'
        writer.write_bits(0b01, 2); // 'B'
        writer.write_bits(0b11, 2); // symbol 262: new match, length 2
        writer.write_bits(0, 1); // distance slot 1 -> distance 2
        let bits1 = writer.bit_pos;
        let payload1 = writer.finish();
        let block1 = encode_compressed_block(&payload1, bits1, true, false).unwrap();

        // Block 2: table lengths that PARSE but cannot BUILD (three length-1
        // main codes oversubscribe the tree).
        let mut bad_lengths = TableLengths {
            main: vec![0; MAIN_TABLE_SIZE],
            distance: vec![0; DISTANCE_TABLE_SIZE_50],
            align: vec![0; ALIGN_TABLE_SIZE],
            length: vec![0; LENGTH_TABLE_SIZE],
        };
        bad_lengths.main[0] = 1;
        bad_lengths.main[1] = 1;
        bad_lengths.main[2] = 1;
        assert!(
            DecodeTables::from_lengths(&bad_lengths).is_err(),
            "fixture tables must fail to build"
        );
        let (bad_bytes, bad_bits) = encode_table_lengths_with_bit_count(&bad_lengths, 0).unwrap();
        let block2 = encode_compressed_block(&bad_bytes, bad_bits, true, true).unwrap();

        let mut stream = block1;
        stream.extend_from_slice(&block2);

        // Case A: output completes inside block 1 -> every path succeeds and
        // never surfaces the read-ahead build failure.
        // Case B: output needs block 2 -> every path fails with the exact
        // error the serial decoder raises at that table build.
        for output_size in [4usize, 6] {
            let mut reference = Rar50Decoder::new();
            let ref_result =
                reference.decode_member(&stream, 0, output_size, false, DecodeMode::Lz);

            let mut mt_decoder = Rar50Decoder::new();
            let mt_result = mt_sink_decode(&stream, output_size, &mut mt_decoder);
            let mut flat_decoder = Rar50Decoder::new();
            let flat_result = flat_sink_decode(&stream, output_size, &mut flat_decoder);

            match ref_result {
                Ok(ref_out) => {
                    assert_eq!(ref_out, b"ABAB", "reference disagrees with test setup");
                    assert_eq!(
                        mt_result.expect("ring path must swallow the read-ahead build error"),
                        ref_out
                    );
                    assert_eq!(
                        flat_result.expect("flat path must swallow the read-ahead build error"),
                        ref_out
                    );
                }
                Err(ref_error) => {
                    for (name, result) in [("ring", mt_result), ("flat", flat_result)] {
                        match result {
                            Err(StreamDecodeError::Decode(error)) => assert_eq!(
                                error, ref_error,
                                "{name}: build-failure error must match serial"
                            ),
                            Ok(_) => panic!(
                                "{name}: succeeded where the serial decoder fails the table build"
                            ),
                            Err(_) => panic!("{name}: unexpected error variant"),
                        }
                    }
                }
            }
        }
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn parallel_decode_errors_on_truncated_stream() {
        let (_, data) = differential_shapes().swap_remove(1);
        let encoded = encode_lz_member_with_options(&data, 0, EncodeOptions::new(4)).unwrap();
        let truncated = &encoded[..encoded.len() / 2];
        let mut decoder = Rar50Decoder::new();
        assert!(
            mt_sink_decode(truncated, data.len(), &mut decoder).is_err(),
            "truncated stream must fail like the serial decoder"
        );
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn parallel_decode_resolves_rep_state_across_blocks() {
        // Block 1 (tables, not last): "AB" literals, a new match, then a
        // symbol-257 repeat -> "ABABAB", leaving previous_match_length=2, reps[0]=2.
        // Built inline (mirroring repeat_payload) so the exact bit count is
        // known - padding bits would otherwise decode as stray literals.
        // Block 2 (no tables, last): a bare symbol-257 repeat whose distance
        // and length only exist in state carried across the block boundary -
        // the op the workers must leave symbolic.
        let mut lengths = TableLengths {
            main: vec![0; MAIN_TABLE_SIZE],
            distance: vec![0; DISTANCE_TABLE_SIZE_50],
            align: vec![0; ALIGN_TABLE_SIZE],
            length: vec![0; LENGTH_TABLE_SIZE],
        };
        lengths.main[b'A' as usize] = 2;
        lengths.main[b'B' as usize] = 2;
        lengths.main[257] = 2;
        lengths.main[262] = 2;
        lengths.distance[1] = 1;
        lengths.length[0] = 1;
        let (bytes, bit_pos) = encode_table_lengths_with_bit_count(&lengths, 0).unwrap();
        let mut writer = BitWriter::continuing(bytes, bit_pos);
        writer.write_bits(0b00, 2); // 'A'
        writer.write_bits(0b01, 2); // 'B'
        writer.write_bits(0b11, 2); // symbol 262: new match, length 2
        writer.write_bits(0, 1); // distance slot 1 -> distance 2
        writer.write_bits(0b10, 2); // symbol 257: repeat -> "AB"
        let bits1 = writer.bit_pos;
        let payload1 = writer.finish();
        let block1 = encode_compressed_block(&payload1, bits1, true, false).unwrap();
        let mut writer = BitWriter::new();
        writer.write_bits(0b10, 2); // symbol 257: repeat last distance+length
        let payload2 = writer.finish();
        let block2 = encode_compressed_block(&payload2, 2, false, true).unwrap();
        let mut stream = block1;
        stream.extend_from_slice(&block2);

        let mut reference = Rar50Decoder::new();
        let expected = reference
            .decode_member(&stream, 0, 8, false, DecodeMode::Lz)
            .unwrap();
        assert_eq!(expected, b"ABABABAB", "reference disagrees with test setup");

        let mut mt_decoder = Rar50Decoder::new();
        let mt_out = mt_sink_decode(&stream, 8, &mut mt_decoder).expect("parallel decode failed");
        assert_eq!(mt_out, expected);
        assert_eq!(mt_decoder.reps, reference.reps);
        assert_eq!(mt_decoder.previous_match_length, reference.previous_match_length);
    }

    /// Decode a member through the flat-apply path (test-forced on regardless
    /// of size), collecting the sink chunks into one buffer. Mirror of
    /// `mt_sink_decode` for the streaming ring, but for `FlatOutput`.
    #[cfg(feature = "parallel")]
    fn flat_sink_decode(
        encoded: &[u8],
        output_size: usize,
        decoder: &mut Rar50Decoder,
    ) -> std::result::Result<Vec<u8>, StreamDecodeError<std::convert::Infallible>> {
        decoder.test_force_flat = true;
        let mut cursor = std::io::Cursor::new(encoded);
        let mut out = Vec::new();
        decoder.decode_member_from_reader_with_dictionary_to_sink(
            &mut cursor,
            0,
            output_size,
            DEFAULT_DICTIONARY_SIZE,
            false,
            u64::MAX,
            |chunk| {
                match chunk {
                    DecodedChunk::Bytes(bytes) => out.extend_from_slice(bytes),
                    DecodedChunk::Repeated { byte, len } => {
                        out.extend(std::iter::repeat_n(byte, len))
                    }
                }
                Ok(())
            },
        )?;
        Ok(out)
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn flat_short_match_fast_path_covers_every_length_bucket() {
        let prefix: Vec<u8> = (0..128u8).map(|byte| byte.wrapping_mul(37)).collect();
        for distance in [16, 17, 31, 64, 127] {
            for length in 0..=64 {
                let mut output = FlatOutput::new(prefix.len() + 80, 256, 256);
                let mut sink = |_chunk: DecodedChunk<'_>| Ok::<_, std::convert::Infallible>(());
                output.push_bytes(&prefix, &mut sink).unwrap();
                output.copy_match(distance, length, &mut sink).unwrap();

                let mut expected = prefix.clone();
                reference_extend(&mut expected, distance, length);
                assert_eq!(
                    &output.buf[..output.pos],
                    expected,
                    "distance {distance}, length {length}"
                );
            }
        }
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn flat_push_bytes_covers_every_literal_ladder_length() {
        // Every length the power-of-two ladder can see, and the first few
        // past it that keep the libcall, appended at a non-zero position so
        // each arm's offset arithmetic is exercised.
        for prefix in [0usize, 1, 7] {
            for count in 0..=20usize {
                let mut output = FlatOutput::new(prefix + count + 80, 256, 256);
                let mut sink = |_chunk: DecodedChunk<'_>| Ok::<_, std::convert::Infallible>(());
                let head: Vec<u8> = (0..prefix as u8).map(|b| b.wrapping_add(200)).collect();
                let bytes: Vec<u8> = (0..count as u8)
                    .map(|b| b.wrapping_mul(31).wrapping_add(7))
                    .collect();
                output.push_bytes(&head, &mut sink).unwrap();
                output.push_bytes(&bytes, &mut sink).unwrap();
                let mut expected = head.clone();
                expected.extend_from_slice(&bytes);
                assert_eq!(
                    &output.buf[..output.pos],
                    expected,
                    "prefix {prefix}, literal run of {count}"
                );
            }
        }
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn flat_decode_matches_reference_across_shapes() {
        // The tiny cfg(test) tape caps force the park-and-resume boundary
        // constantly, so this exercises `apply_tape_flat`'s re-decode
        // continuation path as well as the plain op-walk, across literal
        // bursts, rep chains, short-period repeats (period-doubling), and
        // sparse zeros.
        for (name, data) in differential_shapes() {
            let encoded = encode_lz_member_with_options(&data, 0, EncodeOptions::new(4)).unwrap();

            let mut flat_decoder = Rar50Decoder::new();
            let flat_out = flat_sink_decode(&encoded, data.len(), &mut flat_decoder)
                .unwrap_or_else(|_| panic!("{name}: flat decode failed"));
            assert_eq!(flat_out, data, "{name}: flat output mismatch");

            // Reference: the untouched buffered decoder. Output and final LZ
            // state (rep distances, last length) must agree exactly.
            let mut reference = Rar50Decoder::new();
            let ref_out = reference
                .decode_member(&encoded, 0, data.len(), false, DecodeMode::Lz)
                .unwrap();
            assert_eq!(ref_out, data, "{name}: reference output mismatch");
            assert_eq!(
                flat_decoder.reps, reference.reps,
                "{name}: rep state diverged"
            );
            assert_eq!(
                flat_decoder.previous_match_length, reference.previous_match_length,
                "{name}: previous_match_length diverged"
            );
        }
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn flat_decode_clamps_at_smaller_output_size() {
        // Asking for a prefix stops the apply mid-tape: literal runs clamp at
        // the (smaller) buffer size, a match crossing it errors exactly like
        // the buffered reference (error-equality, including the message).
        for (name, data) in differential_shapes() {
            let encoded = encode_lz_member_with_options(&data, 0, EncodeOptions::new(4)).unwrap();
            for prefix in [data.len() - 1234, data.len() / 2, data.len() / 3 + 7] {
                let mut reference = Rar50Decoder::new();
                let ref_result =
                    reference.decode_member(&encoded, 0, prefix, false, DecodeMode::Lz);
                let mut flat_decoder = Rar50Decoder::new();
                let flat_result = flat_sink_decode(&encoded, prefix, &mut flat_decoder);
                match ref_result {
                    Ok(ref_out) => {
                        let flat_out = flat_result.unwrap_or_else(|_| {
                            panic!("{name}/{prefix}: flat failed where reference succeeded")
                        });
                        assert_eq!(flat_out, ref_out, "{name}/{prefix}: prefix output mismatch");
                    }
                    Err(ref_error) => match flat_result {
                        Err(StreamDecodeError::Decode(flat_error)) => {
                            assert_eq!(flat_error, ref_error, "{name}/{prefix}: error mismatch")
                        }
                        Ok(_) => {
                            panic!("{name}/{prefix}: flat succeeded where reference errored")
                        }
                        Err(_) => panic!("{name}/{prefix}: unexpected error variant"),
                    },
                }
            }
        }
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn flat_decode_errors_on_truncated_stream() {
        let (_, data) = differential_shapes().swap_remove(1);
        let encoded = encode_lz_member_with_options(&data, 0, EncodeOptions::new(4)).unwrap();
        let truncated = &encoded[..encoded.len() / 2];
        let mut decoder = Rar50Decoder::new();
        assert!(
            flat_sink_decode(truncated, data.len(), &mut decoder).is_err(),
            "truncated stream must fail like the serial decoder"
        );
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn flat_decode_resolves_rep_state_across_blocks() {
        // Same two-block construction as the streaming-MT rep test: block 2's
        // bare symbol-257 repeat resolves only from rep state carried across
        // the block boundary, which the flat apply must thread through `self`.
        let mut lengths = TableLengths {
            main: vec![0; MAIN_TABLE_SIZE],
            distance: vec![0; DISTANCE_TABLE_SIZE_50],
            align: vec![0; ALIGN_TABLE_SIZE],
            length: vec![0; LENGTH_TABLE_SIZE],
        };
        lengths.main[b'A' as usize] = 2;
        lengths.main[b'B' as usize] = 2;
        lengths.main[257] = 2;
        lengths.main[262] = 2;
        lengths.distance[1] = 1;
        lengths.length[0] = 1;
        let (bytes, bit_pos) = encode_table_lengths_with_bit_count(&lengths, 0).unwrap();
        let mut writer = BitWriter::continuing(bytes, bit_pos);
        writer.write_bits(0b00, 2); // 'A'
        writer.write_bits(0b01, 2); // 'B'
        writer.write_bits(0b11, 2); // symbol 262: new match, length 2
        writer.write_bits(0, 1); // distance slot 1 -> distance 2
        writer.write_bits(0b10, 2); // symbol 257: repeat -> "AB"
        let bits1 = writer.bit_pos;
        let payload1 = writer.finish();
        let block1 = encode_compressed_block(&payload1, bits1, true, false).unwrap();
        let mut writer = BitWriter::new();
        writer.write_bits(0b10, 2); // symbol 257: repeat last distance+length
        let payload2 = writer.finish();
        let block2 = encode_compressed_block(&payload2, 2, false, true).unwrap();
        let mut stream = block1;
        stream.extend_from_slice(&block2);

        let mut reference = Rar50Decoder::new();
        let expected = reference
            .decode_member(&stream, 0, 8, false, DecodeMode::Lz)
            .unwrap();
        assert_eq!(expected, b"ABABABAB", "reference disagrees with test setup");

        let mut flat_decoder = Rar50Decoder::new();
        let flat_out = flat_sink_decode(&stream, 8, &mut flat_decoder).expect("flat decode failed");
        assert_eq!(flat_out, expected);
        assert_eq!(flat_decoder.reps, reference.reps);
        assert_eq!(flat_decoder.previous_match_length, reference.previous_match_length);
    }

    /// Flat decode with an explicit dictionary, so a member many times the
    /// window forces the sliding path (the test build's slack is 4 KiB).
    #[cfg(feature = "parallel")]
    fn flat_sink_decode_with_dictionary(
        encoded: &[u8],
        output_size: usize,
        dictionary: usize,
        decoder: &mut Rar50Decoder,
    ) -> std::result::Result<Vec<u8>, StreamDecodeError<std::convert::Infallible>> {
        decoder.test_force_flat = true;
        let mut cursor = std::io::Cursor::new(encoded);
        let mut out = Vec::new();
        decoder.decode_member_from_reader_with_dictionary_to_sink(
            &mut cursor,
            0,
            output_size,
            dictionary,
            false,
            u64::MAX,
            |chunk| {
                match chunk {
                    DecodedChunk::Bytes(bytes) => out.extend_from_slice(bytes),
                    DecodedChunk::Repeated { byte, len } => {
                        out.extend(std::iter::repeat_n(byte, len))
                    }
                }
                Ok(())
            },
        )?;
        Ok(out)
    }

    /// The flat plan's slack rule at the SHIPPED ceiling (`cfg(test)`
    /// shrinks the real constant to 4 KiB, so nothing else here exercises
    /// the sizes it was fitted on). Three claims, in order: it never plans
    /// more slack than the old `history + max(history, 64 MiB)` did; it
    /// never plans less than the dictionary; and a member small enough to
    /// have no use for 64 MiB of slack gets the square-root rule instead -
    /// which is the 2.4% to 8.5% of `rarfast t` wall that motivated it
    /// (research/RARFAST-BENCH-2026-09-14.md section 19).
    #[test]
    fn flat_slack_only_ever_plans_less_than_the_old_floor() {
        const MIB: usize = 1 << 20;
        const SHIPPED: usize = 64 << 20;
        let slack = |member: usize, dict: usize| flat_slack_with(member, dict, SHIPPED) / MIB;

        // Large members keep the old slack exactly: the rule is capped by it.
        assert_eq!(slack(1024 * MIB, 32 * MIB), 64);
        // 4096 MiB is exactly `u32::MAX + 1`, so this member does not exist
        // on a 32-bit target and the cell is compiled only where its input
        // is representable - `arithmetic_overflow` is deny-by-default and
        // const-folds it, so on armv7 this did not fail, it refused to
        // COMPILE (nightly 35078185142). The cap itself stays covered
        // everywhere by the 1024 MiB cell above and by the grid below.
        #[cfg(target_pointer_width = "64")]
        assert_eq!(slack(4096 * MIB, 64 * MIB), 64);
        // ...and a member that is only just large enough plans just under
        // it: sqrt(256 * 32 / 3) is 52, a cell the grid measured as a tie
        // with the 64 it replaces on both payload families.
        assert_eq!(slack(256 * MIB, 32 * MIB), 52);

        // Small members with a small dictionary plan the root instead.
        assert_eq!(slack(64 * MIB, 4 * MIB), 9); // sqrt(64 * 4 / 3)
        assert_eq!(slack(32 * MIB, 4 * MIB), 6);
        assert_eq!(slack(128 * MIB, 8 * MIB), 18);

        // Never below the dictionary, whatever the root says.
        assert_eq!(slack(MIB, 32 * MIB), 32);
        assert_eq!(slack(8 * MIB, 16 * MIB), 16);

        // And never above what the old rule planned, at any shape. The
        // 8192 MiB column is 64-bit-only for the same reason as the cell
        // above, and here it would have been a RUNTIME overflow panic
        // rather than a compile error: this job builds with
        // `overflow-checks = true` precisely to catch arch-width bugs, so
        // the multiply below traps instead of wrapping. The dictionary
        // column tops out at 1024 MiB and is representable on both.
        #[cfg(target_pointer_width = "64")]
        const MEMBERS_MIB: [usize; 7] = [1, 4, 17, 64, 256, 1024, 8192];
        #[cfg(not(target_pointer_width = "64"))]
        const MEMBERS_MIB: [usize; 6] = [1, 4, 17, 64, 256, 1024];
        for member in MEMBERS_MIB {
            for dict in [1usize, 4, 16, 32, 64, 128, 1024] {
                let (m, d) = (member * MIB, dict * MIB);
                assert!(
                    flat_slack_with(m, d, SHIPPED) <= d.max(SHIPPED),
                    "member {member} MiB dict {dict} MiB plans more slack than the old floor"
                );
                assert!(
                    flat_slack_with(m, d, SHIPPED) >= d,
                    "slack below the dictionary"
                );
            }
        }

        // A zero-length member is still a legal plan, not a panic.
        assert_eq!(flat_slack_with(0, 0, SHIPPED), FLAT_SLACK_FLOOR);
    }

    /// A member 24x its dictionary: matches at 32 KiB reach back within a
    /// 128 KiB window, the flat plan is 256 KiB in the test build, so the
    /// buffer slides ~20 times. Output must equal the serial decoder's and
    /// the plan must stay a function of the dictionary, not the member.
    #[test]
    #[cfg(feature = "parallel")]
    fn flat_decode_slides_a_member_larger_than_its_plan() {
        let dictionary = 128 << 10;
        let mut lcg = 0x9E3779B97F4A7C15u64;
        let mut block = Vec::with_capacity(32 << 10);
        while block.len() < 32 << 10 {
            lcg = lcg
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            block.extend_from_slice(&lcg.to_le_bytes());
        }
        let mut data = Vec::with_capacity(3 << 20);
        for i in 0..96usize {
            let mut copy = block.clone();
            // Perturb a few bytes so the encoder emits matches, not one
            // giant repeat, and every block still differs from the last.
            let len = copy.len();
            for j in 0..4 {
                copy[(i * 977 + j * 3331) % len] ^= (i as u8).wrapping_add(j as u8);
            }
            data.extend_from_slice(&copy);
        }
        assert_eq!(flat_plan_bytes(0, data.len(), dictionary), 2 * dictionary);
        let encoded = encode_lz_member_with_options(&data, 0, EncodeOptions::new(4)).unwrap();
        let mut reference = Rar50Decoder::new();
        reference.set_window_limit(dictionary);
        let expected = reference
            .decode_member_with_dictionary(
                &encoded,
                0,
                data.len(),
                dictionary,
                false,
                DecodeMode::Lz,
            )
            .unwrap();
        assert_eq!(expected, data, "reference disagrees with the encoder");
        let mut flat_decoder = Rar50Decoder::new();
        let flat_out =
            flat_sink_decode_with_dictionary(&encoded, data.len(), dictionary, &mut flat_decoder)
                .expect("sliding flat decode");
        assert_eq!(flat_out, expected);
        assert_eq!(flat_decoder.reps, reference.reps);
    }

    /// Filters across a sliding buffer: a filter that fits the slack is
    /// held, applied and emitted as the buffer slides under it (the encoder
    /// declares one per block, so this is the shape that reaches us); one
    /// holding back more than the slack leaves nothing to drop and reports
    /// `FilteredMember` (the caller takes the buffered decoder), exactly
    /// the streaming path's answer. Either way, never a wrong byte.
    #[test]
    #[cfg(feature = "parallel")]
    fn flat_decode_filters_across_slides_or_refuses() {
        let dictionary = 128 << 10;
        let mut data = vec![0u8; 1 << 20];
        data[0] = 0xe8;
        for (i, byte) in data.iter_mut().enumerate().skip(5) {
            *byte = (i % 251) as u8;
        }
        let encoded = encode_lz_member_with_filter(&data, Rar50FilterKind::E8).unwrap();
        let mut flat_decoder = Rar50Decoder::new();
        let mut reference = Rar50Decoder::new();
        let expected = reference
            .decode_member_with_dictionary(
                &encoded,
                0,
                data.len(),
                dictionary,
                false,
                DecodeMode::Lz,
            )
            .unwrap();
        match flat_sink_decode_with_dictionary(&encoded, data.len(), dictionary, &mut flat_decoder)
        {
            Err(StreamDecodeError::FilteredMember) => {}
            Ok(out) => assert_eq!(out, expected, "filtered output diverged across slides"),
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn flat_decode_applies_whole_member_filter() {
        // A whole-member E8 filter: matches read the pre-filter window in
        // `buf`, and the filter applies to a scratch copy at emit. Output must
        // equal the buffered reference (which filters at member end).
        let data = b"\xe8\0\0\0\0plain text after the call opcode".to_vec();
        let encoded = encode_lz_member_with_filter(&data, Rar50FilterKind::E8).unwrap();
        let mut reference = Rar50Decoder::new();
        let ref_out = reference
            .decode_member(&encoded, 0, data.len(), false, DecodeMode::Lz)
            .unwrap();
        let mut flat_decoder = Rar50Decoder::new();
        let flat_out =
            flat_sink_decode(&encoded, data.len(), &mut flat_decoder).expect("flat filter decode");
        assert_eq!(flat_out, ref_out);
        assert_eq!(flat_out, data);
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn flat_decode_holds_back_filter_range_until_complete() {
        // A mid-member DELTA range filter with plain text on both sides. The
        // emit gate must (a) stream the plain prefix without waiting on the
        // filter, (b) hold the filter's range until it is fully materialized
        // and emit it FILTERED (not the raw pre-filter window bytes), (c)
        // resume the plain suffix. Verified by the chunk boundaries: the
        // filtered region is delivered as its own unit at [start, end).
        let mut data = Vec::new();
        data.extend_from_slice(b"PLAIN-PREFIX-not-filtered-0000000000");
        let start = data.len();
        let region: Vec<u8> = (0..64u8)
            .map(|i| i.wrapping_mul(3).wrapping_add(7))
            .collect();
        data.extend_from_slice(&region);
        let end = data.len();
        data.extend_from_slice(b"SUFFIX-not-filtered-111111111111111");

        let encoded = Rar50Encoder::new()
            .encode_member_with_filters(
                &data,
                0,
                &[Rar50FilterSpec::range(
                    Rar50FilterKind::Delta { channels: 1 },
                    start..end,
                )],
            )
            .unwrap();

        let mut reference = Rar50Decoder::new();
        let ref_out = reference
            .decode_member(&encoded, 0, data.len(), false, DecodeMode::Lz)
            .unwrap();
        assert_eq!(ref_out, data, "reference round-trip mismatch");

        // Capture chunks in order to inspect the emit boundaries.
        let mut decoder = Rar50Decoder::new();
        decoder.test_force_flat = true;
        let mut chunks: Vec<Vec<u8>> = Vec::new();
        decoder
            .decode_member_from_reader_with_dictionary_to_sink(
                &mut std::io::Cursor::new(&encoded),
                0,
                data.len(),
                DEFAULT_DICTIONARY_SIZE,
                false,
                u64::MAX,
                |chunk| {
                    match chunk {
                        DecodedChunk::Bytes(bytes) => chunks.push(bytes.to_vec()),
                        DecodedChunk::Repeated { byte, len } => {
                            chunks.push(std::iter::repeat_n(byte, len).collect())
                        }
                    }
                    Ok::<_, std::convert::Infallible>(())
                },
            )
            .expect("flat filter decode");

        // Concatenation is the fully-filtered output.
        let flat_out: Vec<u8> = chunks.iter().flatten().copied().collect();
        assert_eq!(flat_out, data, "flat filtered output mismatch");

        // Boundaries land exactly at the filter range: the region is held back
        // and emitted as its own filtered chunk.
        let mut boundaries = Vec::new();
        let mut cursor = 0usize;
        for chunk in &chunks {
            cursor += chunk.len();
            boundaries.push(cursor);
        }
        assert!(
            boundaries.contains(&start),
            "prefix must end (be emitted) at the filter start; boundaries={boundaries:?}"
        );
        assert!(
            boundaries.contains(&end),
            "filtered region must be its own chunk ending at {end}; boundaries={boundaries:?}"
        );
        // The chunk covering [start, end) carries the FILTERED bytes (== the
        // original region, since delta round-trips), not the raw pre-filter
        // window that `buf` still holds.
        let region_chunk = chunks
            .iter()
            .find(|chunk| chunk.as_slice() == region.as_slice());
        assert!(
            region_chunk.is_some(),
            "the held-back range must be emitted filtered as a distinct chunk"
        );
    }

    fn repeat_payload(repeat_symbol: usize) -> Vec<u8> {
        let mut lengths = TableLengths {
            main: vec![0; MAIN_TABLE_SIZE],
            distance: vec![0; DISTANCE_TABLE_SIZE_50],
            align: vec![0; ALIGN_TABLE_SIZE],
            length: vec![0; LENGTH_TABLE_SIZE],
        };
        lengths.main[b'A' as usize] = 2;
        lengths.main[b'B' as usize] = 2;
        lengths.main[repeat_symbol] = 2;
        lengths.main[262] = 2;
        lengths.distance[1] = 1;
        lengths.length[0] = 1;
        let (bytes, bit_pos) = encode_table_lengths_with_bit_count(&lengths, 0).unwrap();
        let mut writer = BitWriter::continuing(bytes, bit_pos);

        writer.write_bits(0b00, 2); // 'A'
        writer.write_bits(0b01, 2); // 'B'
        writer.write_bits(0b11, 2); // match length 2
        writer.write_bits(0, 1); // distance slot 1
        writer.write_bits(0b10, 2); // repeat control symbol
        if repeat_symbol == 258 {
            writer.write_bits(0, 1); // length slot 0
        }
        writer.finish()
    }
    #[test]
    fn narrow_match_positions_preserve_full_width_token_choices() {
        let mut seed = 0x12345678u32;
        let input: Vec<u8> = (0..32769)
            .map(|i| {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                if i % 512 < 256 {
                    seed as u8
                } else {
                    (i % 251) as u8
                }
            })
            .collect();
        for history_len in [0, 1, 2, 31, 4096] {
            let history = &input[..history_len];
            for limit in [1, 64, 65536] {
                for candidates in [1, 16, 256] {
                    for lazy in [false, true] {
                        let options = EncodeOptions::new(candidates)
                            .with_max_match_distance(limit)
                            .with_lazy_matching(lazy)
                            .with_lazy_lookahead(3);
                        let mut narrow_progress = Vec::new();
                        let mut wide_progress = Vec::new();
                        let indexed_len = input.len() + history.len().min(limit);
                        let (narrow, _) = encode_tokens_indexed::<u32>(
                            &input,
                            history,
                            options,
                            DISTANCE_TABLE_SIZE_50,
                            Some(&mut |n| {
                                narrow_progress.push(n);
                                true
                            }),
                            MatchIndex::new(indexed_len, candidates),
                            Vec::new(),
                        )
                        .unwrap();
                        let (wide, _) = encode_tokens_indexed::<usize>(
                            &input,
                            history,
                            options,
                            DISTANCE_TABLE_SIZE_50,
                            Some(&mut |n| {
                                wide_progress.push(n);
                                true
                            }),
                            MatchIndex::new(indexed_len, candidates),
                            Vec::new(),
                        )
                        .unwrap();
                        let pairs = |tokens: Vec<EncodeToken>| {
                            tokens
                                .into_iter()
                                .map(|t| (t.length, t.distance))
                                .collect::<Vec<_>>()
                        };
                        assert_eq!(pairs(narrow), pairs(wide));
                        assert_eq!(narrow_progress, wide_progress);
                    }
                }
            }
        }
    }

    #[test]
    fn compact_match_index_selection_checks_span_and_overflow() {
        assert!(compact_match_index_fits(100, usize::MAX, 20));
        assert!(!compact_match_index_fits(usize::MAX, 1, 1));
        let limit = u32::MAX as usize;
        assert!(compact_match_index_fits(limit, 0, usize::MAX));
        assert!(compact_match_index_fits(limit - 10, usize::MAX, 10));
        assert!(!compact_match_index_fits(limit - 10, 11, 11));
        assert_eq!(
            <u32 as MatchPosition>::from_position(limit).position(),
            limit
        );
        #[cfg(target_pointer_width = "64")]
        {
            assert!(!compact_match_index_fits(limit + 1, 0, usize::MAX));
            let wide = limit + 1;
            assert_eq!(
                <usize as MatchPosition>::from_position(wide).position(),
                wide
            );
        }
    }

    /// Text-like bytes with real repeats, the shape the parse is for.
    fn optimal_parse_fixture(len: usize) -> Vec<u8> {
        const WORDS: [&[u8]; 8] = [
            b"the ", b"quick ", b"brown ", b"fox ", b"jumps ", b"over ", b"lazy ", b"dog ",
        ];
        let mut random = 0x1234_5678u32;
        let mut data = Vec::with_capacity(len + 64);
        while data.len() < len {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            let pick = (random >> 3) as usize % WORDS.len();
            data.extend_from_slice(WORDS[pick]);
            if random.is_multiple_of(23) {
                data.extend_from_slice(&random.to_le_bytes());
            }
            if random.is_multiple_of(101) && data.len() > 2048 {
                // A far repeat, which is where the repeat slots earn.
                let from = (random as usize) % (data.len() - 1024);
                let span = data[from..from + 300].to_vec();
                data.extend_from_slice(&span);
            }
        }
        data.truncate(len);
        data
    }

    /// The parse prices from tables it builds itself, so a length's price
    /// must be the bits the writer will actually spend on it.
    /// [`DistanceArm`] is the hot-loop form, deciding the distance's arm
    /// once and walking the length ladder; [`priced_match_cost`] is the
    /// direct one, straight off [`EncoderMatchState::encode_match`]. They
    /// are held equal here over every arm the format has, including the
    /// lengths and distances that have no encoding at all.
    #[test]
    fn distance_arm_prices_agree_with_the_direct_token_cost() {
        let slots = LengthSlots::new();
        let literal_bits = [8u8; 256];
        for distance_size in [DISTANCE_TABLE_SIZE_50, DISTANCE_TABLE_SIZE_70] {
            let mut prices = TokenPrices::constant(&literal_bits, distance_size);
            // Prices no two arms can accidentally agree under.
            for (symbol, price) in prices.main.iter_mut().enumerate() {
                *price = ((symbol % 14) as u16 + 1) << PRICE_SHIFT;
            }
            for (symbol, price) in prices.length.iter_mut().enumerate() {
                *price = ((symbol % 12) as u16 + 1) << PRICE_SHIFT;
            }
            for (symbol, price) in prices.distance.iter_mut().enumerate() {
                *price = ((symbol % 13) as u16 + 1) << PRICE_SHIFT;
            }
            for (symbol, price) in prices.align.iter_mut().enumerate() {
                *price = ((symbol % 9) as u16 + 1) << PRICE_SHIFT;
            }
            let states = [
                EncoderMatchState::default(),
                EncoderMatchState {
                    reps: [7, 300, 70_000, 1 << 20],
                    previous_match_length: 11,
                },
                EncoderMatchState {
                    reps: [1, 2, 3, 4],
                    previous_match_length: 2,
                },
                EncoderMatchState {
                    reps: [4096, 8192, 1, 0],
                    previous_match_length: 4096,
                },
            ];
            for state in states {
                for distance in [
                    1usize,
                    2,
                    4,
                    5,
                    7,
                    255,
                    256,
                    300,
                    8192,
                    70_000,
                    1 << 20,
                    3 << 21,
                    1 << 30,
                ] {
                    let arm = DistanceArm::new(&prices, &state, distance, distance_size);
                    for length in [2usize, 3, 4, 5, 11, 63, 64, 255, 4095, 4096] {
                        let direct =
                            priced_match_cost(&prices, &state, length, distance, distance_size)
                                .ok();
                        let armed = arm.and_then(|arm| arm.price(&prices, &slots, length));
                        assert_eq!(
                            direct, armed,
                            "distance {distance} length {length} state {state:?}"
                        );
                    }
                }
            }
        }
    }

    /// The parse's first entropy region has no tokens of its own to price
    /// from, so it prices with what the greedy walk always used. That
    /// fallback has to BE that model and not merely resemble it, or the
    /// parse's first quarter-megabyte optimises something else.
    #[test]
    fn constant_prices_reproduce_the_estimated_match_cost_model() {
        let mut literal_bits = [0u8; 256];
        for (byte, bits) in literal_bits.iter_mut().enumerate() {
            *bits = 1 + (byte % 15) as u8;
        }
        for distance_size in [DISTANCE_TABLE_SIZE_50, DISTANCE_TABLE_SIZE_70] {
            let prices = TokenPrices::constant(&literal_bits, distance_size);
            for (price, &bits) in prices.main.iter().zip(&literal_bits) {
                assert_eq!(*price, u16::from(bits) << PRICE_SHIFT);
            }
            let states = [
                EncoderMatchState::default(),
                EncoderMatchState {
                    reps: [9, 4096, 1 << 19, 1 << 24],
                    previous_match_length: 17,
                },
            ];
            for state in states {
                for distance in [1usize, 3, 256, 8193, 1 << 18, 1 << 24, 1 << 30] {
                    for length in [2usize, 4, 17, 100, 4096] {
                        let old = estimated_match_cost(&state, length, distance, distance_size)
                            .ok()
                            .map(|bits| (bits as u32) << PRICE_SHIFT);
                        let new =
                            priced_match_cost(&prices, &state, length, distance, distance_size)
                                .ok();
                        assert_eq!(old, new, "distance {distance} length {length}");
                    }
                }
            }
        }
    }

    /// Prices are integer arithmetic on purpose: an archive's bytes must
    /// not depend on a platform's `log2`. This holds the integer form to
    /// the real logarithm it stands in for, and to the monotonicity a
    /// price table needs of it (a rarer symbol never prices cheaper).
    #[test]
    fn log2_sixteenths_tracks_the_logarithm_it_prices_with() {
        for value in [
            1u64,
            2,
            3,
            5,
            7,
            16,
            17,
            255,
            1000,
            65_535,
            1 << 20,
            (1 << 40) + 7,
        ] {
            let exact = (value as f64).log2() * 16.0;
            let got = f64::from(log2_sixteenths(value));
            assert!(
                got <= exact + 1e-9 && got > exact - 1.0,
                "{value}: {got} against {exact}"
            );
        }
        let mut previous = 0;
        for value in 1u64..8192 {
            let now = log2_sixteenths(value);
            assert!(now >= previous, "{value} priced below {}", value - 1);
            previous = now;
        }
    }

    /// A region's frequencies become the next region's prices, so a symbol
    /// the region leaned on has to come out cheap, one it never used
    /// expensive, and a table it never used at all has to keep a workable
    /// price rather than becoming unaffordable.
    #[test]
    fn settled_prices_follow_the_region_they_were_counted_over() {
        let literals = LiteralPrices::new(&[b'a'; 4096], 0);
        let mut model = PriceModel::new(&literals, DISTANCE_TABLE_SIZE_50);
        model.observe_literals(&[b'a'; ENTROPY_BLOCK_BYTES]);
        model.observe_literals(&[b'z'; 16]);
        model.settle();
        assert!(model.prices.main[usize::from(b'a')] < model.prices.main[usize::from(b'z')]);
        assert_eq!(model.prices.main[usize::from(b'q')], PRICE_MAX);
        assert!(model.prices.main[usize::from(b'a')] >= PRICE_MIN);
        // No match token was seen at all, so the match tables keep the
        // constant model's prices instead of pricing every match at the
        // deepest code a table can hold.
        assert_eq!(model.prices.distance[3], 0);
        assert_eq!(model.prices.align[3], 4 << PRICE_SHIFT);
        // ...and the counters reset, so a region is priced by the region
        // before it and not by the whole member.
        assert_eq!(model.bytes, 0);
        assert!(model.main.iter().all(|&count| count == 0));
    }

    /// The FIRST region is short on purpose, so a member gets real code
    /// lengths four times sooner and a member shorter than one entropy
    /// region leaves the constant model at all; every region after it is
    /// a full one. A regression here is silent - it costs bytes on member
    /// sets and nothing else notices.
    #[test]
    fn the_first_price_region_is_short_and_the_rest_are_not() {
        let literals = LiteralPrices::new(&[b'a'; 4096], 0);
        let mut model = PriceModel::new(&literals, DISTANCE_TABLE_SIZE_50);
        assert_eq!(model.threshold, OPTIMAL_FIRST_REGION_BYTES);

        // One byte short of the first region settles nothing: the counters
        // still hold what was observed and the prices are still the
        // constant model's.
        model.observe_literals(&vec![b'a'; OPTIMAL_FIRST_REGION_BYTES - 1]);
        model.settle();
        assert_eq!(model.bytes, OPTIMAL_FIRST_REGION_BYTES - 1);
        assert_eq!(model.threshold, OPTIMAL_FIRST_REGION_BYTES);
        assert_eq!(
            model.main[usize::from(b'a')],
            OPTIMAL_FIRST_REGION_BYTES - 1
        );

        // Reaching it settles, and moves the bar to a full region.
        model.observe_literals(b"a");
        model.settle();
        assert_eq!(model.bytes, 0);
        assert_eq!(model.threshold, ENTROPY_BLOCK_BYTES);

        // ...which the next region has to reach before it settles again.
        model.observe_literals(&vec![b'z'; OPTIMAL_FIRST_REGION_BYTES]);
        model.settle();
        assert_eq!(model.bytes, OPTIMAL_FIRST_REGION_BYTES);
        assert_eq!(model.threshold, ENTROPY_BLOCK_BYTES);
    }

    /// The candidate list is the parse's only view of the dictionary, and
    /// its filters (the tag, and the byte one past the current best) exist
    /// to reject candidates without loading them. This re-derives the same
    /// list from the same bucket walk WITHOUT those filters, so a filter
    /// that drops a candidate it should have kept fails here.
    #[test]
    fn match_candidates_are_the_nearest_distance_for_each_length() {
        let data = optimal_parse_fixture(48 << 10);
        let options = EncodeOptions::new(64).with_max_match_distance(1 << 20);
        let mut buckets = MatchIndex::<u32>::new(data.len(), options.max_match_candidates);
        let mut runs = Vec::new();
        let mut reached = 0usize;
        for pos in 0..data.len() {
            match_candidates_at(&data, pos, data.len(), &buckets, options, TreeMatches::none(), &mut runs);
            let expected = unfiltered_candidate_list(&data, pos, data.len(), &buckets, options);
            assert_eq!(runs, expected, "position {pos}");
            let mut previous: Option<MatchRun> = None;
            for &run in &runs {
                assert!(run.length >= 4 && run.distance >= 1);
                if let Some(previous) = previous {
                    assert!(run.length > previous.length);
                    assert!(run.distance > previous.distance);
                }
                assert_eq!(
                    &data[pos..pos + run.length],
                    &data[pos - run.distance..pos - run.distance + run.length]
                );
                previous = Some(run);
            }
            reached += usize::from(!runs.is_empty());
            buckets.insert(&data, pos);
        }
        // A list that is empty everywhere would pass every assertion above.
        assert!(reached > data.len() / 4, "only {reached} positions matched");
    }

    #[test]
    fn optimal_tokenizer_consumes_an_independent_tree_hint() {
        let mut seed = 0x1937_4628_u64;
        let history: Vec<u8> = (0..4096).map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed as u8
        }).collect();
        let data = history.clone();
        let combined = [history.as_slice(), data.as_slice()].concat();
        let options = EncodeOptions::new(64)
            .with_max_match_distance(131072)
            .with_optimal_parse(true);
        // Both shapes the parse can be handed: one distance merged into the
        // ring's frontier, and a list the parse takes INSTEAD of the ring.
        for stride in [1usize, TREE_CANDIDATE_SLOTS] {
        let hints = empty_slots(data.len() * stride);
        hints[0].store(history.len() as u32, std::sync::atomic::Ordering::Relaxed);
        let parse = |tree| {
            // Deliberately do not seed history into the ring: this match must
            // arrive through the tree parameter passed by walk_tokens.
            walk_tokens(
                &combined, history.len(), combined.len(), options,
                DISTANCE_TABLE_SIZE_50, None,
                MatchIndex::<usize>::new(combined.len(), options.max_match_candidates),
                Vec::new(), tree,
            ).unwrap().0
        };
        let without = parse(TreeMatches::none());
        let with = parse(TreeMatches { base: history.len(), distances: &hints, stride });
        assert_eq!(without[0].distance, 0);
        assert_eq!(with[0].distance, history.len(), "stride {stride}");
        assert!(with[0].length >= OPTIMAL_SUFFICIENT_LENGTH);
        let (packed, _) = encode_token_block(
            &data, &with, 0, &[], 0, DISTANCE_TABLE_SIZE_50,
            &mut EncoderMatchState::default(), true,
        ).unwrap();
        let mut decoder = Rar50Decoder::new();
        decoder.decode_member_with_dictionary(
            &encode_literal_only(&history, 0).unwrap(), 0, history.len(),
            131072, false, DecodeMode::Lz,
        ).unwrap();
        assert_eq!(decoder.decode_member_with_dictionary(
            &packed, 0, data.len(), 131072, true, DecodeMode::Lz,
        ).unwrap(), data);
        }
    }

    /// The hint budget narrows a wave and moves not one byte of the
    /// archive: the wave width decides how much of the finder's answer is
    /// held at once and nothing else, which is the property the budget
    /// rests on. (nzbfast-local change, 7 Sep 2026.)
    #[test]
    fn the_hint_budget_narrows_a_wave_without_moving_its_bytes() {
        // Eight blocks at the shipped stride, and never below one.
        assert_eq!(tree_wave_width(16, TREE_CANDIDATE_SLOTS, None), 8);
        assert_eq!(tree_wave_width(4, TREE_CANDIDATE_SLOTS, None), 4);
        assert_eq!(tree_wave_width(64, tree::TREE_MAX_CANDIDATE_SLOTS, None), 4);
        assert_eq!(tree_wave_width(1, tree::TREE_MAX_CANDIDATE_SLOTS, None), 1);
        // A stride of one is the lazy parser's, and the budget does not
        // reach it at any width the pool can ask for.
        assert_eq!(tree_wave_width(20, 1, None), 20);
        // An allowance narrows and never widens: a huge one is the default,
        // a quarter-gigabyte one holds four blocks of hints. "Huge" is
        // `usize::MAX`, never a GiB-scale literal: on 32-bit `64 << 30` is
        // not flagged (the shift is under the width) and silently wraps to
        // an allowance of 0, which the armv7-cross RUN caught (left 1, right
        // 8). (nzbfast-local change, 15 Sep 2026; see VENDORING.md.)
        assert_eq!(
            tree_wave_width(16, TREE_CANDIDATE_SLOTS, Some(usize::MAX)),
            8
        );
        assert_eq!(tree_wave_width(16, TREE_CANDIDATE_SLOTS, Some(1 << 30)), 4);
        // `usize::MAX`, not `1 << 40`: the allowance is a `usize`, and on a
        // 32-bit target that shift is a deny-by-default overflow that stops
        // the whole lib test from building (armv7-cross). (nzbfast-local
        // change, 15 Sep 2026; see VENDORING.md.)
        assert_eq!(
            encode_block_wave_width_for_budget(32 << 20, false, Some(usize::MAX)),
            encode_block_wave_width_for_budget(32 << 20, false, None),
        );
        // And under an allowance the streamed member window is the wave, with
        // no floor of eight to run members beside a narrowed pool.
        let streamed = EncodeOptions::new(16).with_max_match_distance(32 << 20);
        assert!(member_window_blocks(streamed) >= 8);
        assert_eq!(
            member_window_blocks(streamed.with_working_memory(Some(1))),
            1
        );
        // But the window a large member is encoded from keeps the floor, so
        // a one-thread pool does not rebuild its tree over the whole
        // dictionary for every block it encodes.
        assert_eq!(
            member_window_segment_blocks(streamed.with_working_memory(Some(1))),
            8
        );
        assert_eq!(
            member_window_segment_blocks(streamed),
            member_window_blocks(streamed)
        );
        let block = MAX_COMPRESSED_BLOCK_OUTPUT;
        let data = optimal_parse_fixture(3 * block + 4_096);
        let options = EncodeOptions::new(16)
            .with_max_match_distance(2 * block)
            .with_optimal_parse(true);
        let pool = EncoderScratchPool::new();
        let narrow = encode_lz_member_blocks_in_waves(
            &data, &[], 0, options, None, 1, MemberWindow::whole(), &pool,
        )
        .unwrap();
        let wide = encode_lz_member_blocks_in_waves(
            &data, &[], 0, options, None, 8, MemberWindow::whole(), &pool,
        )
        .unwrap();
        assert_eq!(narrow, wide);
    }

    /// At a wide stride the finder's list REPLACES the ring walk, so what
    /// the parse prices has to be a valid frontier on its own and has to
    /// carry what the ring was carrying: every candidate a real match at
    /// its distance, lengths and distances strictly increasing, and the
    /// list reaching at least as far as the ring's at nearly every
    /// position and strictly farther at many. (nzbfast-local change,
    /// 7 Sep 2026.)
    #[test]
    fn a_wide_stride_frontier_replaces_the_ring_without_losing_reach() {
        let data = optimal_parse_fixture(96 << 10);
        let options = EncodeOptions::new(16).with_max_match_distance(4 << 20);
        let stride = TREE_CANDIDATE_SLOTS;
        let hints = empty_slots(data.len() * stride);
        let mut finder = TreeMatchFinder::new(options.max_match_distance);
        finder.advance_range(&data, 0..data.len(), Some(&hints), stride, 1);
        let tree = TreeMatches { base: 0, distances: &hints, stride };
        let mut index = MatchIndex::<u32>::new(data.len(), options.max_match_candidates);
        let mut ring = Vec::new();
        let mut listed = Vec::new();
        let mut farther = 0usize;
        let mut shorter = 0usize;
        let mut several = 0usize;
        for pos in 0..data.len() {
            match_candidates_at(&data, pos, data.len(), &index, options,
                TreeMatches::none(), &mut ring);
            match_candidates_at(&data, pos, data.len(), &index, options,
                tree, &mut listed);
            for pair in listed.windows(2) {
                assert!(pair[0].length < pair[1].length, "pos {pos}");
                assert!(pair[0].distance < pair[1].distance, "pos {pos}");
            }
            for run in &listed {
                assert!(run.distance <= pos.min(options.max_match_distance));
                assert_eq!(&data[pos..pos + run.length],
                    &data[pos - run.distance..pos - run.distance + run.length],
                    "pos {pos} is not a real match");
            }
            several += usize::from(listed.len() > 1);
            let reach = |runs: &Vec<MatchRun>| runs.last().map_or(0, |run| run.length);
            match reach(&listed).cmp(&reach(&ring)) {
                std::cmp::Ordering::Greater => farther += 1,
                std::cmp::Ordering::Less => shorter += 1,
                std::cmp::Ordering::Equal => {}
            }
            index.insert(&data, pos);
        }
        assert!(several > data.len() / 50, "only {several} positions listed several");
        assert!(farther > shorter, "tree reached farther at {farther}, shorter at {shorter}");
        // The ring is bounded to its newest slots, so the tree giving up
        // reach anywhere is a finding, not a rounding error.
        assert!(shorter * 100 < data.len(), "tree lost reach at {shorter} positions");
    }

    #[test]
    fn tree_candidate_frontiers_remain_nearest_and_valid() {
        let data = optimal_parse_fixture(96 << 10);
        let options = EncodeOptions::new(16).with_max_match_distance(4 << 20);
        let hints = empty_slots(data.len());
        let mut finder = TreeMatchFinder::new(options.max_match_distance);
        finder.advance_range(&data, 0..data.len(), Some(&hints), 1, 1);
        let tree = TreeMatches { base: 0, distances: &hints, stride: 1 };
        let mut index = MatchIndex::<u32>::new(data.len(), options.max_match_candidates);
        let mut ring = Vec::new();
        let mut combined = Vec::new();
        let mut additions = 0;
        for pos in 0..data.len() {
            match_candidates_at(&data, pos, data.len(), &index, options,
                TreeMatches::none(), &mut ring);
            match_candidates_at(&data, pos, data.len(), &index, options,
                tree, &mut combined);
            additions += usize::from(ring != combined);
            for old in &ring {
                assert!(combined.iter().any(|new|
                    new.length >= old.length && new.distance <= old.distance));
            }
            for pair in combined.windows(2) {
                assert!(pair[0].length < pair[1].length);
                assert!(pair[0].distance < pair[1].distance);
            }
            for run in &combined {
                assert!(run.distance <= pos.min(options.max_match_distance));
                assert_eq!(&data[pos..pos + run.length],
                    &data[pos - run.distance..pos - run.distance + run.length]);
            }
            index.insert(&data, pos);
        }
        assert!(additions > 0, "fixture must exercise independent tree matches");
    }

    /// [`match_candidates_at`] with its filters removed: the same walk, the
    /// same stopping points, every candidate's length measured.
    fn unfiltered_candidate_list(
        input: &[u8],
        pos: usize,
        end: usize,
        buckets: &MatchIndex<u32>,
        options: EncodeOptions,
    ) -> Vec<MatchRun> {
        let mut out = Vec::new();
        let max_distance = pos.min(options.max_match_distance);
        let max_length = (end - pos).min(MAX_ENCODER_MATCH_LENGTH);
        if options.max_match_candidates == 0
            || max_distance == 0
            || max_length < 4
            || pos + 3 >= input.len()
        {
            return out;
        }
        let prefix = &input[pos..pos + 4];
        let mut best_length = 0usize;
        let mut checked = 0usize;
        for candidate in buckets.candidates(input, pos) {
            if candidate >= pos {
                continue;
            }
            let distance = pos - candidate;
            if distance > max_distance {
                break;
            }
            checked += 1;
            if &input[candidate..candidate + 4] == prefix {
                let length = 4 + match_length(input, pos + 4, distance, max_length - 4);
                if length > best_length {
                    best_length = length;
                    out.push(MatchRun { length, distance });
                }
            }
            if best_length >= max_length || best_length >= MATCH_NICE_LENGTH {
                break;
            }
            if checked >= options.max_match_candidates {
                break;
            }
        }
        if best_length < LONG_MATCH_MIN_LENGTH {
            if let Some(candidate) = buckets.long_candidate(input, pos) {
                if candidate < pos
                    && pos - candidate <= max_distance
                    && &input[candidate..candidate + 4] == prefix
                {
                    let distance = pos - candidate;
                    let length = 4 + match_length(input, pos + 4, distance, max_length - 4);
                    if length > best_length && length >= LONG_MATCH_MIN_LENGTH.min(max_length) {
                        out.push(MatchRun { length, distance });
                    }
                }
            }
        }
        out
    }

    /// The parse is a new token stream, so what it emits has to decode to
    /// the input it was given - through history, through both algorithm
    /// versions, and over inputs long enough to cross several of its own
    /// windows - and it has to be SMALLER than the parser it sits above,
    /// which is the only reason to pay for it.
    #[test]
    fn optimal_parse_round_trips_and_undercuts_the_lazy_parser() {
        let compressible = optimal_parse_fixture(96 << 10);
        let mut random = 0x9e37_79b9u32;
        let noise: Vec<u8> = (0..4096)
            .map(|_| {
                random ^= random << 13;
                random ^= random >> 17;
                random ^= random << 5;
                random as u8
            })
            .collect();
        let fixtures: [&[u8]; 6] = [
            &[],
            b"ab",
            b"abcabcabcabcabcabc",
            &noise,
            &compressible[..1024],
            &compressible,
        ];
        let lazy_options = EncodeOptions::new(64)
            .with_lazy_matching(true)
            .with_max_match_distance(1 << 20);
        let optimal_options = lazy_options.with_optimal_parse(true);
        for data in fixtures {
            for version in [0u8, 1] {
                let optimal =
                    encode_lz_member_with_options(data, version, optimal_options).unwrap();
                assert_eq!(decode_lz(&optimal, version, data.len()).unwrap(), data);
                // ...and as a solid member, whose matches reach into the
                // history the walk was seeded with.
                let history_member =
                    encode_lz_member_with_options(&compressible, version, optimal_options).unwrap();
                let with_history = encode_lz_member_with_history_and_options(
                    data,
                    &compressible,
                    version,
                    optimal_options,
                )
                .unwrap();
                let dictionary = 1 << 20;
                let mut decoder = Rar50Decoder::new();
                assert_eq!(
                    decoder
                        .decode_member_with_dictionary(
                            &history_member,
                            version,
                            compressible.len(),
                            dictionary,
                            false,
                            DecodeMode::Lz,
                        )
                        .unwrap(),
                    compressible
                );
                decoder.commit_member();
                assert_eq!(
                    decoder
                        .decode_member_with_dictionary(
                            &with_history,
                            version,
                            data.len(),
                            dictionary,
                            true,
                            DecodeMode::Lz,
                        )
                        .unwrap(),
                    data
                );
            }
        }
        let lazy = encode_lz_member_with_options(&compressible, 0, lazy_options).unwrap();
        let optimal = encode_lz_member_with_options(&compressible, 0, optimal_options).unwrap();
        assert!(
            optimal.len() < lazy.len(),
            "optimal {} against lazy {}",
            optimal.len(),
            lazy.len()
        );
    }

    /// What the dynamic program is FOR, and the one claim a size test on
    /// one corpus cannot make: over a member priced by the model both
    /// parsers score with, the program's token sequence costs FEWER
    /// estimated bits than the greedy walk's. The repeat state is inside
    /// that claim - the four distances rotate on use and the length-repeat
    /// token costs about two bits, so a sequence that leaves the right
    /// slots in place is cheaper than one that does not, and both tokens
    /// have to actually appear or the state carried per node is decoration.
    #[test]
    fn optimal_parse_costs_fewer_estimated_bits_than_the_lazy_walk() {
        // Two spans replayed alternately, so keeping both distances in
        // repeat slots (and repeating the length) is the cheap answer.
        let mut data = Vec::new();
        let first: Vec<u8> = (0..96u8).map(|byte| byte.wrapping_mul(37)).collect();
        let second: Vec<u8> = (0..96u8)
            .map(|byte| byte.wrapping_mul(91).wrapping_add(7))
            .collect();
        let mut random = 0x51ed_2701u32;
        for _ in 0..400 {
            data.extend_from_slice(&first);
            data.extend_from_slice(&second);
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            data.extend_from_slice(&random.to_le_bytes()[..1 + (random as usize & 3)]);
        }
        data.extend_from_slice(&optimal_parse_fixture(48 << 10));
        // Short of one entropy region, so the parse never leaves the
        // constant model and this IS the model it minimised under.
        assert!(data.len() < ENTROPY_BLOCK_BYTES);
        let literals = LiteralPrices::new(&data, 0);
        let prices = TokenPrices::constant(&literals.byte_price, DISTANCE_TABLE_SIZE_50);
        let priced = |options| {
            let tokens = encode_tokens(&data, &[], options, DISTANCE_TABLE_SIZE_50);
            let mut state = EncoderMatchState::default();
            let mut bits = 0u64;
            let mut at = 0usize;
            let mut repeats = 0usize;
            let mut length_repeats = 0usize;
            for token in &tokens {
                if token.distance == 0 {
                    for &byte in &data[at..at + token.length] {
                        bits += u64::from(prices.main[usize::from(byte)]);
                    }
                } else {
                    match state
                        .encode_match(token.length, token.distance, DISTANCE_TABLE_SIZE_50)
                        .unwrap()
                    {
                        EncodedMatch::LastLengthRepeat => length_repeats += 1,
                        EncodedMatch::RepeatDistance { .. } => repeats += 1,
                        EncodedMatch::New { .. } => {}
                    }
                    bits += u64::from(
                        priced_match_cost(
                            &prices,
                            &state,
                            token.length,
                            token.distance,
                            DISTANCE_TABLE_SIZE_50,
                        )
                        .unwrap(),
                    );
                    state.remember(token.length, token.distance);
                }
                at += token.length;
            }
            assert_eq!(at, data.len(), "the tokens do not cover the input");
            (bits, repeats, length_repeats)
        };
        let lazy = EncodeOptions::new(64)
            .with_max_match_distance(1 << 20)
            .with_lazy_matching(true);
        let (lazy_bits, ..) = priced(lazy);
        let (bits, repeats, length_repeats) = priced(lazy.with_optimal_parse(true));
        assert!(
            bits < lazy_bits,
            "{bits} sixteenths of a bit against the lazy walk's {lazy_bits}"
        );
        assert!(repeats > 0, "no repeat-distance token");
        assert!(length_repeats > 0, "no length-repeat token");
    }
}
