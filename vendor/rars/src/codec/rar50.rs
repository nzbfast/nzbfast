use super::filters::{self, DeltaErrorMessages, FilterOp};
use super::{huffman, Error, Result};
use std::io::Read;
use std::ops::Range;

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
const MAX_COMPRESSED_BLOCK_OUTPUT: usize = 4 * 1024 * 1024;
const MAX_FILTER_BLOCK_LENGTH: usize = 0x3ffff;
const MATCH_HASH_BUCKETS: usize = 4096;
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
            distance: HuffmanTable::from_lengths(&lengths.distance)?,
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
    let level_table = HuffmanTable::from_lengths(&level_lengths)?;
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
    let mut decoder = Unpack50Decoder::new();
    decoder.decode_member(
        input,
        algorithm_version,
        output_size,
        false,
        DecodeMode::LiteralOnly,
    )
}

pub fn decode_lz(input: &[u8], algorithm_version: u8, output_size: usize) -> Result<Vec<u8>> {
    let mut decoder = Unpack50Decoder::new();
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

    let table = HuffmanTable::from_lengths(&lengths.main)?;
    let (table_data, table_bits) =
        encode_table_lengths_with_bit_count(&lengths, algorithm_version)?;
    let mut writer = BitWriter {
        bytes: table_data,
        bit_pos: table_bits,
    };
    for &byte in data {
        let (code, len) = table.code_for_symbol(byte as usize)?;
        writer.write_bits(usize::from(code), usize::from(len));
    }
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
}

impl EncodeOptions {
    pub const fn new(max_match_candidates: usize) -> Self {
        Self {
            max_match_candidates,
            lazy_matching: false,
            lazy_lookahead: 1,
            max_match_distance: MAX_ENCODER_MATCH_OFFSET,
        }
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
            e8e9_encode(data, file_offset as u32, false);
            Ok((FilterType::E8, 0))
        }
        Rar50FilterKind::E8E9 => {
            e8e9_encode(data, file_offset as u32, true);
            Ok((FilterType::E8E9, 0))
        }
        Rar50FilterKind::Arm => {
            arm_encode(data, file_offset as u32);
            Ok((FilterType::Arm, 0))
        }
    }
}

/// Returns the packed blocks and the LZ window as it stands after the last
/// block. That window holds the FILTERED chunks, which is what the decoder
/// keeps, so the caller can assign it straight onto the encoder history.
/// Its trim rule must stay identical to `Unpack50Encoder::remember`.
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
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<u8>> {
    if data.len() > MAX_COMPRESSED_BLOCK_OUTPUT && initial_filters.is_empty() {
        let mut out = Vec::new();
        let mut block_history =
            history[history.len().saturating_sub(options.max_match_distance)..].to_vec();
        let mut chunks = data.chunks(MAX_COMPRESSED_BLOCK_OUTPUT).peekable();
        let mut completed = 0usize;
        while let Some(chunk) = chunks.next() {
            let is_last = chunks.peek().is_none();
            let mut chunk_progress = |position: usize| {
                progress
                    .as_deref_mut()
                    .is_none_or(|report| report(completed.saturating_add(position)))
            };
            out.extend(encode_lz_block(
                chunk,
                &block_history,
                algorithm_version,
                &[],
                options,
                is_last,
                Some(&mut chunk_progress),
            )?);
            completed = completed.saturating_add(chunk.len());
            block_history.extend_from_slice(chunk);
            let keep_from = block_history
                .len()
                .saturating_sub(options.max_match_distance);
            if keep_from != 0 {
                block_history.drain(..keep_from);
            }
        }
        return Ok(out);
    }

    encode_lz_block(
        data,
        history,
        algorithm_version,
        initial_filters,
        options,
        true,
        progress,
    )
}

fn encode_lz_block(
    data: &[u8],
    history: &[u8],
    algorithm_version: u8,
    initial_filters: &[EncodeFilter],
    options: EncodeOptions,
    is_last: bool,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
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
    let mut tokens = Vec::new();
    tokens.extend(initial_filters.iter().copied().map(EncodeToken::Filter));
    tokens.extend(encode_tokens_with_progress(
        data,
        history,
        options,
        distance_size,
        progress,
    )?);
    let mut lengths = TableLengths {
        main: vec![0; MAIN_TABLE_SIZE],
        distance: vec![0; distance_size],
        align: vec![0; ALIGN_TABLE_SIZE],
        length: vec![0; LENGTH_TABLE_SIZE],
    };

    let mut main_frequencies = vec![0usize; MAIN_TABLE_SIZE];
    let mut distance_frequencies = vec![0usize; distance_size];
    let mut align_frequencies = vec![0usize; ALIGN_TABLE_SIZE];
    let mut length_frequencies = vec![0usize; LENGTH_TABLE_SIZE];
    let mut state = EncoderMatchState::default();
    for token in &tokens {
        match *token {
            EncodeToken::Filter(_) => main_frequencies[256] += 1,
            EncodeToken::Literal(byte) => main_frequencies[byte as usize] += 1,
            EncodeToken::Match { length, distance } => {
                match state.encode_match(length, distance, distance_size)? {
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
                state.remember(length, distance);
            }
        }
    }

    lengths.main = huffman::complete_lengths_for_frequencies(&main_frequencies, 15);
    lengths.distance = huffman::complete_lengths_for_frequencies(&distance_frequencies, 15);
    lengths.length = huffman::complete_lengths_for_frequencies(&length_frequencies, 15);
    lengths.align = huffman::complete_lengths_for_frequencies(&align_frequencies, 15);

    let main_table = HuffmanTable::from_lengths(&lengths.main)?;
    let distance_table = HuffmanTable::from_lengths(&lengths.distance)?;
    let align_table = HuffmanTable::from_lengths(&lengths.align)?;
    let length_table = HuffmanTable::from_lengths(&lengths.length)?;
    let (table_data, table_bits) =
        encode_table_lengths_with_bit_count(&lengths, algorithm_version)?;
    let mut writer = BitWriter {
        bytes: table_data,
        bit_pos: table_bits,
    };
    let mut state = EncoderMatchState::default();
    for token in tokens {
        match token {
            EncodeToken::Filter(filter) => {
                let (code, len) = main_table.code_for_symbol(256)?;
                writer.write_bits(usize::from(code), usize::from(len));
                write_filter(&mut writer, filter)?;
            }
            EncodeToken::Literal(byte) => {
                let (code, len) = main_table.code_for_symbol(byte as usize)?;
                writer.write_bits(usize::from(code), usize::from(len));
            }
            EncodeToken::Match { length, distance } => {
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
                        let (code, len) = length_table.code_for_symbol(length_slot)?;
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
        }
    }

    let payload_bits = writer.bit_pos;
    encode_compressed_block(&writer.finish(), payload_bits, true, is_last)
}

#[derive(Debug, Clone, Default)]
pub struct Unpack50Encoder {
    history: Vec<u8>,
    options: EncodeOptions,
}

impl Unpack50Encoder {
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
        // The window a solid successor is compressed against is what the
        // decoder keeps, and the decoder keeps the LZ output: the filtered
        // bytes, not `input`.
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
        if input.len() > MAX_FILTER_BLOCK_LENGTH {
            let (packed, history) = filtered_lz_blocks(
                input,
                filters,
                &self.history,
                algorithm_version,
                self.options,
                Some(progress),
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
            Some(progress),
        )?;
        // See `encode_member_with_filters`: remember the filtered bytes.
        self.remember(&filtered);
        Ok(packed)
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

#[derive(Debug, Clone, Copy)]
enum EncodeToken {
    Filter(EncodeFilter),
    Literal(u8),
    Match { length: usize, distance: usize },
}

#[derive(Debug, Clone, Copy)]
struct EncodeFilter {
    offset: usize,
    length: usize,
    filter_type: FilterType,
    channels: usize,
}

#[derive(Debug, Clone, Copy, Default)]
struct EncoderMatchState {
    reps: [usize; 4],
    last_length: usize,
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
        if distance == self.reps[0] && length == self.last_length && self.last_length != 0 {
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
        if distance == self.reps[0] && length == self.last_length {
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
        self.last_length = length;
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

fn encode_tokens_with_progress(
    input: &[u8],
    history: &[u8],
    options: EncodeOptions,
    distance_size: usize,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<EncodeToken>> {
    let mut tokens = Vec::new();
    let mut buckets = vec![Vec::new(); MATCH_HASH_BUCKETS];
    let history = &history[history.len().saturating_sub(options.max_match_distance)..];
    let mut combined = Vec::with_capacity(history.len() + input.len());
    combined.extend_from_slice(history);
    combined.extend_from_slice(input);
    for history_pos in 0..history.len().saturating_sub(2) {
        insert_match_position(&combined, history_pos, &mut buckets);
    }

    let mut pos = history.len();
    let end = combined.len();
    let mut state = EncoderMatchState::default();
    let mut next_report = 0usize;
    while pos < end {
        if let Some(candidate) = best_match(
            &combined,
            pos,
            end,
            &buckets,
            options,
            &state,
            distance_size,
        ) {
            if should_lazy_emit_literal(
                &combined,
                pos,
                &buckets,
                options,
                &state,
                distance_size,
                candidate,
            ) {
                tokens.push(EncodeToken::Literal(combined[pos]));
                insert_match_position(&combined, pos, &mut buckets);
                pos += 1;
                continue;
            }
            let MatchCandidate {
                length, distance, ..
            } = candidate;
            tokens.push(EncodeToken::Match { length, distance });
            state.remember(length, distance);
            for history_pos in pos..pos + length {
                insert_match_position(&combined, history_pos, &mut buckets);
            }
            pos += length;
        } else {
            tokens.push(EncodeToken::Literal(combined[pos]));
            insert_match_position(&combined, pos, &mut buckets);
            pos += 1;
        }
        let consumed = pos.saturating_sub(history.len());
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
    Ok(tokens)
}

fn should_lazy_emit_literal(
    input: &[u8],
    pos: usize,
    buckets: &[Vec<usize>],
    options: EncodeOptions,
    state: &EncoderMatchState,
    distance_size: usize,
    current: MatchCandidate,
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
            )
            .is_some_and(|next| {
                let skipped_literal_score = offset as isize * 8;
                next.score > current.score + skipped_literal_score
            })
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MatchCandidate {
    length: usize,
    distance: usize,
    score: isize,
    cost: usize,
}

fn best_match(
    input: &[u8],
    pos: usize,
    end: usize,
    buckets: &[Vec<usize>],
    options: EncodeOptions,
    state: &EncoderMatchState,
    distance_size: usize,
) -> Option<MatchCandidate> {
    let max_distance = pos.min(options.max_match_distance);
    let max_length = (end - pos).min(MAX_ENCODER_MATCH_LENGTH);
    if options.max_match_candidates == 0
        || max_distance == 0
        || max_length < 4
        || pos + 2 >= input.len()
    {
        return None;
    }
    let bucket = &buckets[match_hash(input, pos)];
    let mut best = None;
    let mut checked = 0usize;
    for distance in state.reps {
        if distance == 0 || distance > max_distance {
            continue;
        }
        let length = match_length(input, pos, distance, max_length);
        consider_match_candidate(&mut best, state, distance_size, length, distance);
    }
    for &candidate in bucket.iter().rev() {
        if candidate >= pos {
            continue;
        }
        let distance = pos - candidate;
        if distance > max_distance {
            break;
        }
        checked += 1;
        let length = match_length(input, pos, distance, max_length);
        consider_match_candidate(&mut best, state, distance_size, length, distance);
        if let Some(best) = best {
            if best.length == max_length {
                break;
            }
        }
        if checked >= options.max_match_candidates {
            break;
        }
    }
    best
}

fn match_length(input: &[u8], pos: usize, distance: usize, max_length: usize) -> usize {
    super::fast::match_length(input, pos, distance, max_length)
}

fn consider_match_candidate(
    best: &mut Option<MatchCandidate>,
    state: &EncoderMatchState,
    distance_size: usize,
    length: usize,
    distance: usize,
) {
    if length < 4 {
        return;
    }
    let Ok(cost) = estimated_match_cost(state, length, distance, distance_size) else {
        return;
    };
    let candidate = MatchCandidate {
        length,
        distance,
        score: (length as isize * 16) - cost as isize,
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
    if distance == state.reps[0] && length == state.last_length && state.last_length != 0 {
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

fn insert_match_position(input: &[u8], pos: usize, buckets: &mut [Vec<usize>]) {
    if pos + 2 < input.len() {
        buckets[match_hash(input, pos)].push(pos);
    }
}

fn match_hash(input: &[u8], pos: usize) -> usize {
    let value =
        ((input[pos] as usize) << 8) ^ ((input[pos + 1] as usize) << 4) ^ input[pos + 2] as usize;
    value & (MATCH_HASH_BUCKETS - 1)
}

fn length_slot_for_match(length: usize) -> Result<(usize, usize)> {
    if length < 2 {
        return Err(Error::InvalidData("RAR 5 match length is too short"));
    }
    for slot in 0..LENGTH_TABLE_SIZE {
        let bit_count = usize::from(length_slot_extra_bits(slot)?);
        let base = slot_to_length(slot, 0)?;
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

fn distance_slot_for_match(distance: usize, distance_size: usize) -> Result<(usize, usize)> {
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

fn literal_presence(data: &[u8]) -> [bool; 256] {
    let mut present = [false; 256];
    for &byte in data {
        present[byte as usize] = true;
    }
    present
}

#[derive(Debug, Clone)]
pub struct Unpack50Decoder {
    // Arc so the parallel block decoder can hand the current table set to
    // worker threads without cloning the LUTs; serial paths just deref.
    tables: Option<std::sync::Arc<DecodeTables>>,
    reps: [usize; 4],
    last_length: usize,
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
    #[cfg(test)]
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
    last_length: usize,
}

/// O(1) snapshot of decoder state before a solid member decodes, so a
/// failed integrity check can rewind and retry (filters off) without
/// cloning the decoder - the clone copied the whole multi-MB solid window
/// per member. Valid to restore only while no compaction has run since the
/// checkpoint; `Unpack50Decoder::commit_member` (the only compaction site)
/// must not be called between `solid_checkpoint` and `restore_checkpoint`.
pub struct SolidCheckpoint {
    tables: Option<std::sync::Arc<DecodeTables>>,
    reps: [usize; 4],
    last_length: usize,
    history_start: usize,
    history_len: usize,
    history_zero_prefix: usize,
    compactions: u64,
}

impl Unpack50Decoder {
    pub fn new() -> Self {
        Self {
            retain_history: true,
            tables: None,
            reps: [0; 4],
            last_length: 0,
            history: Vec::new(),
            history_start: 0,
            history_zero_prefix: 0,
            history_compactions: 0,
            window_limit: usize::MAX,
            mt_workers_cap: usize::MAX,
            #[cfg(test)]
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
            last_length: self.last_length,
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
        self.last_length = cp.last_length;
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
                // a tight loop, falling back to the full dispatch below at the
                // first non-literal or non-LUT symbol. This is the hot path
                // for incompressible spans, where nearly every symbol is a
                // literal with a short code.
                while output.len() < output_size && bits.position() < block_header.payload_bits {
                    let Some(peek) = bits.peek15() else {
                        break;
                    };
                    let entry = tables.main.lut[usize::from(peek >> (15 - HUFF_LUT_BITS))];
                    if entry == 0 || (entry >> 8) > 255 {
                        break;
                    }
                    bits.consume((entry & 0xff) as u8);
                    output.push((entry >> 8) as u8);
                }
                if bits.position() >= block_header.payload_bits || output.len() >= output_size {
                    break;
                }
                let symbol = tables.main.decode(&mut bits)?;
                match symbol {
                    0..=255 => output.push(symbol as u8),
                    256 if mode.uses_lz() => {
                        filters.push(read_filter(&mut bits, output.len())?);
                    }
                    257 if mode.uses_lz() => {
                        if self.last_length != 0 {
                            self.copy_match(
                                &mut output,
                                self.reps[0],
                                self.last_length,
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
                        let length = slot_to_length(length_slot, length_extra)?;
                        self.reps[..=rep_index].rotate_right(1);
                        self.reps[0] = distance;
                        self.last_length = length;
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
                        let mut length = slot_to_length(length_slot, length_extra)?;
                        let distance_slot = tables.distance.decode(&mut bits)?;
                        let distance_bit_count = distance_slot_bit_count(distance_slot)?;
                        let distance_extra = if distance_bit_count >= 4 && tables.align_mode {
                            let high = bits.read_bits((distance_bit_count - 4) as u8)?;
                            let low = tables.align.decode(&mut bits)? as u32;
                            (high << 4) | low
                        } else {
                            bits.read_bits(distance_bit_count as u8)?
                        };
                        let distance = slot_to_distance(distance_slot, distance_extra)?;
                        length += length_bonus(distance);
                        self.reps.rotate_right(1);
                        self.reps[0] = distance;
                        self.last_length = length;
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
            let history_output = if self.retain_history && mode.applies_filters() && !filters.is_empty() {
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
        if self.use_flat_mode(output_size, solid, flat_limit) {
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
            self.run_blocks_parallel(input, algorithm_version, output_size, &mut output, &mut sink)?;
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
                &mut self.last_length,
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
                .ok_or(Error::InvalidData("RAR 5 solid chain output size overflows"))?;
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
            && (total_output_size as u64).saturating_add(self.history_window_len() as u64)
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
            last_length: self.last_length,
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
        self.last_length = snapshot.last_length;
    }

    fn reset(&mut self) {
        self.tables = None;
        self.reps = [0; 4];
        self.last_length = 0;
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
    /// per block. Never read outside `apply_filter_to_range`.
    /// (nzbfast-local change, 20 Aug 2026 - see vendor/rars/VENDORING.md.)
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
    /// empty.
    fn with_member_ends(mut self, member_ends: Vec<usize>) -> Self {
        self.member_ends = member_ends;
        self
    }

    fn add_filter<E>(
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
        // filter.start >= written (read_filter adds a non-negative offset),
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
        self.pending_filters.push_back(StreamFilter { filter, ring_start });
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
        output_limit.saturating_add(headroom).next_power_of_two()
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
    /// into the ring. Stops (without consuming) at the first non-literal or
    /// non-LUT symbol, at the payload/output boundary, or when a flush is
    /// due — the caller's full dispatch handles whatever comes next. This is
    /// the hot path for incompressible spans, where nearly every symbol is
    /// a literal with an 8-10 bit code.
    fn literal_burst<E>(
        &mut self,
        table: &HuffmanTable,
        bits: &mut BitReader<'_>,
        payload_bits: usize,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        loop {
            let flush_room = self.next_flush_check.saturating_sub(self.head);
            let out_room = self.output_limit.saturating_sub(self.written);
            if flush_room == 0 && out_room != 0 {
                self.maybe_flush(sink)?;
                continue;
            }
            let mut remaining = flush_room.min(out_room);
            if remaining == 0 {
                return Ok(());
            }
            self.reserve(self.head + remaining);
            let mut zero_acc = true;
            while remaining != 0 {
                if bits.position() >= payload_bits {
                    self.all_zero &= zero_acc;
                    return Ok(());
                }
                let Some(peek) = bits.peek15() else {
                    self.all_zero &= zero_acc;
                    return Ok(());
                };
                let entry = table.lut[usize::from(peek >> (15 - HUFF_LUT_BITS))];
                if entry == 0 || (entry >> 8) > 255 {
                    self.all_zero &= zero_acc;
                    return Ok(());
                }
                bits.consume((entry & 0xff) as u8);
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
            let take = bytes
                .len()
                .min(flush_room)
                .min(self.ring.len() - offset);
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
                // declaration by `add_filter`.
                apply_filter_to_range(
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
                sink(DecodedChunk::Bytes(&self.filter_scratch))
                    .map_err(StreamDecodeError::Sink)?;
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
    last_length: &mut usize,
    output: &mut StreamingOutput,
    output_size: usize,
    sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
) -> std::result::Result<(), StreamDecodeError<E>> {
    while bits.position() < payload_bits && output.written() < output_size {
        output.literal_burst(&tables.main, bits, payload_bits, sink)?;
        if bits.position() >= payload_bits || output.written() >= output_size {
            break;
        }
        let symbol = tables.main.decode(bits)?;
        match symbol {
            0..=255 => output.push(symbol as u8, sink)?,
            256 => {
                let filter = read_filter(bits, output.written())?;
                output.add_filter(filter)?;
            }
            257 => {
                if *last_length != 0 {
                    output.copy_match(reps[0], *last_length, sink)?;
                }
            }
            258..=261 => {
                let rep_index = symbol - 258;
                let distance = reps[rep_index];
                if distance == 0 {
                    return Err(
                        Error::InvalidData("RAR 5 repeat distance is not initialized").into()
                    );
                }
                let length_slot = tables.length.decode(bits)?;
                let length_extra = bits.read_bits(length_slot_extra_bits(length_slot)?)?;
                let length = slot_to_length(length_slot, length_extra)?;
                reps[..=rep_index].rotate_right(1);
                reps[0] = distance;
                *last_length = length;
                output.copy_match(distance, length, sink)?;
            }
            262.. => {
                let length_slot = symbol - 262;
                let length_extra = bits.read_bits(length_slot_extra_bits(length_slot)?)?;
                let mut length = slot_to_length(length_slot, length_extra)?;
                let distance_slot = tables.distance.decode(bits)?;
                let distance_bit_count = distance_slot_bit_count(distance_slot)?;
                let distance_extra = if distance_bit_count >= 4 && tables.align_mode {
                    let high = bits.read_bits((distance_bit_count - 4) as u8)?;
                    let low = tables.align.decode(bits)? as u32;
                    (high << 4) | low
                } else {
                    bits.read_bits(distance_bit_count as u8)?
                };
                let distance = slot_to_distance(distance_slot, distance_extra)?;
                length += length_bonus(distance);
                reps.rotate_right(1);
                reps[0] = distance;
                *last_length = length;
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

#[cfg(feature = "parallel")]
const MT_MAX_WORKERS: usize = 4;
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

#[cfg(feature = "parallel")]
#[derive(Debug, Clone, Copy)]
enum TapeOp {
    /// Emit the next `n` bytes from the tape's literal buffer.
    Lits(u32),
    /// Fully resolved match (symbol 262..).
    Match { distance: usize, length: usize },
    /// Repeat-distance match (symbols 258..=261); distance resolved at apply.
    Rep { index: u8, length: usize },
    /// Symbol 257: reuse the last distance and length (no-op when none yet).
    RepLast,
    /// Symbol 256: filter declaration; start offset resolved at apply.
    Filter(RawFilter),
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
        built.set(Ok(tables)).expect("fresh OnceLock accepts a value");
        Self {
            lengths: None,
            built,
        }
    }

    fn get(&self) -> Result<std::sync::Arc<DecodeTables>> {
        self.built
            .get_or_init(|| {
                let lengths = self
                    .lengths
                    .as_ref()
                    .expect("unbuilt lazy tables always carry lengths");
                DecodeTables::from_lengths(lengths).map(std::sync::Arc::new)
            })
            .clone()
    }
}

#[cfg(feature = "parallel")]
struct TapeJob {
    seq: usize,
    tables: std::sync::Arc<LazyDecodeTables>,
    payload: Vec<u8>,
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
    /// Bit position where the worker parked (tape caps hit); the apply stage
    /// resumes this block with the serial decoder from here.
    resume_bit: Option<usize>,
    /// Decode error hit after the recorded ops. Raised by the apply stage
    /// only if the member still needs output when the tape runs out - the
    /// serial decoder would have stopped consuming at the output limit and
    /// never seen bits beyond it.
    tail_error: Option<Error>,
}

/// Huffman-decode one block's symbol stream into an op tape (worker side;
/// no window, no rep state, no sink).
#[cfg(feature = "parallel")]
fn decode_block_tape(job: TapeJob) -> BlockTape {
    // First use of a table set builds it here, off the scanner's critical
    // path. A build failure yields an empty tape carrying the error: the
    // ordered apply raises it only if the member still needs output when it
    // reaches this block - the serial decoder would have built (and failed)
    // these tables at exactly that point in the stream, and never at all if
    // the output completed first.
    let tables = match job.tables.get() {
        Ok(tables) => tables,
        Err(error) => {
            return BlockTape {
                seq: job.seq,
                tables: job.tables,
                payload: job.payload,
                payload_bits: job.payload_bits,
                lits: Vec::new(),
                ops: Vec::new(),
                resume_bit: None,
                tail_error: Some(error),
            }
        }
    };
    let tables = &*tables;
    let mut bits = BitReader::new_at(&job.payload, job.start_bit);
    let mut lits: Vec<u8> = Vec::new();
    let mut ops: Vec<TapeOp> = Vec::new();
    let mut lit_run: u32 = 0;
    let mut resume_bit = None;
    let mut tail_error = None;

    macro_rules! flush_lits {
        () => {
            if lit_run != 0 {
                ops.push(TapeOp::Lits(lit_run));
                lit_run = 0;
            }
        };
    }

    'blocks: while bits.position() < job.payload_bits {
        if ops.len() >= TAPE_OPS_CAP || lits.len() >= TAPE_LITS_CAP {
            flush_lits!();
            resume_bit = Some(bits.position());
            break;
        }
        // Literal burst on the LUT fast path (the mirror of
        // StreamingOutput::literal_burst, decoding into the tape buffer).
        let burst_limit = lits.len() + (64 << 10);
        while lits.len() < burst_limit {
            if bits.position() >= job.payload_bits {
                flush_lits!();
                break 'blocks;
            }
            let Some(peek) = bits.peek15() else {
                break;
            };
            let entry = tables.main.lut[usize::from(peek >> (15 - HUFF_LUT_BITS))];
            if entry == 0 || (entry >> 8) > 255 {
                break;
            }
            bits.consume((entry & 0xff) as u8);
            lits.push((entry >> 8) as u8);
            lit_run += 1;
        }
        if lits.len() >= burst_limit {
            continue;
        }
        let symbol = match tables.main.decode(&mut bits) {
            Ok(symbol) => symbol,
            Err(error) => {
                flush_lits!();
                tail_error = Some(error);
                break;
            }
        };
        let step = (|| -> Result<Option<TapeOp>> {
            Ok(match symbol {
                0..=255 => None,
                256 => Some(TapeOp::Filter(read_filter_raw(&mut bits)?)),
                257 => Some(TapeOp::RepLast),
                258..=261 => {
                    let length_slot = tables.length.decode(&mut bits)?;
                    let length_extra = bits.read_bits(length_slot_extra_bits(length_slot)?)?;
                    let length = slot_to_length(length_slot, length_extra)?;
                    Some(TapeOp::Rep {
                        index: (symbol - 258) as u8,
                        length,
                    })
                }
                262.. => {
                    let length_slot = symbol - 262;
                    let length_extra = bits.read_bits(length_slot_extra_bits(length_slot)?)?;
                    let mut length = slot_to_length(length_slot, length_extra)?;
                    let distance_slot = tables.distance.decode(&mut bits)?;
                    let distance_bit_count = distance_slot_bit_count(distance_slot)?;
                    let distance_extra = if distance_bit_count >= 4 && tables.align_mode {
                        let high = bits.read_bits((distance_bit_count - 4) as u8)?;
                        let low = tables.align.decode(&mut bits)? as u32;
                        (high << 4) | low
                    } else {
                        bits.read_bits(distance_bit_count as u8)?
                    };
                    let distance = slot_to_distance(distance_slot, distance_extra)?;
                    length += length_bonus(distance);
                    Some(TapeOp::Match { distance, length })
                }
            })
        })();
        match step {
            Ok(None) => {
                // Literal that missed the LUT (long code): decoded via the
                // canonical fallback inside decode().
                lits.push(symbol as u8);
                lit_run += 1;
            }
            Ok(Some(op)) => {
                flush_lits!();
                ops.push(op);
            }
            Err(error) => {
                flush_lits!();
                tail_error = Some(error);
                break;
            }
        }
    }
    if lit_run != 0 {
        ops.push(TapeOp::Lits(lit_run));
    }

    BlockTape {
        seq: job.seq,
        tables: job.tables,
        payload: job.payload,
        payload_bits: job.payload_bits,
        lits,
        ops,
        resume_bit,
        tail_error,
    }
}

#[cfg(feature = "parallel")]
enum TapeApplied {
    BlockDone,
    OutputDone,
}

#[cfg(feature = "parallel")]
impl Unpack50Decoder {
    /// Replay a decoded tape against the window in archive order, resolving
    /// the rep-distance state the workers left symbolic. Reproduces the
    /// serial decoder's stops and errors exactly (see module comment).
    fn apply_tape<E>(
        &mut self,
        tape: BlockTape,
        output: &mut StreamingOutput,
        output_size: usize,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<TapeApplied, StreamDecodeError<E>> {
        let mut lit_pos = 0usize;
        for op in &tape.ops {
            if output.written() >= output_size {
                return Ok(TapeApplied::OutputDone);
            }
            match *op {
                TapeOp::Lits(count) => {
                    let count = count as usize;
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
                TapeOp::RepLast => {
                    if self.last_length != 0 {
                        output.copy_match(self.reps[0], self.last_length, sink)?;
                    }
                }
                TapeOp::Rep { index, length } => {
                    let index = usize::from(index);
                    let distance = self.reps[index];
                    if distance == 0 {
                        return Err(Error::InvalidData(
                            "RAR 5 repeat distance is not initialized",
                        )
                        .into());
                    }
                    self.reps[..=index].rotate_right(1);
                    self.reps[0] = distance;
                    self.last_length = length;
                    output.copy_match(distance, length, sink)?;
                }
                TapeOp::Match { distance, length } => {
                    self.reps.rotate_right(1);
                    self.reps[0] = distance;
                    self.last_length = length;
                    output.copy_match(distance, length, sink)?;
                }
                TapeOp::Filter(raw) => {
                    output.add_filter(raw.resolve(output.written())?)?;
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
                &tables,
                &mut bits,
                tape.payload_bits,
                &mut self.reps,
                &mut self.last_length,
                output,
                output_size,
                sink,
            )?;
            if output.written() >= output_size {
                return Ok(TapeApplied::OutputDone);
            }
            return Ok(TapeApplied::BlockDone);
        }
        if let Some(error) = tape.tail_error {
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
        mut input: Box<dyn Read + Send + 'a>,
        next_input: &mut dyn FnMut() -> Option<Box<dyn Read + Send + 'a>>,
        algorithm_version: u8,
        output_size: usize,
        output: &mut StreamingOutput,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), StreamDecodeError<E>> {
        use std::collections::BTreeMap;
        use std::sync::mpsc;
        use std::sync::Arc;

        let workers = self.capped_workers(output_size).max(2);
        let max_in_flight = workers * 3;

        let (result_tx, result_rx) = mpsc::sync_channel::<BlockTape>(workers * 2);
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

        let mut scan_tables = self
            .tables
            .clone()
            .map(|tables| Arc::new(LazyDecodeTables::prebuilt(tables)));
        let mut applied_tables: Option<Arc<LazyDecodeTables>> = None;
        let mut reorder: BTreeMap<usize, BlockTape> = BTreeMap::new();
        let mut held: Option<TapeJob> = None;
        let mut dispatched = 0usize; // blocks read off the input
        let mut applied = 0usize; // next tape sequence to apply
        let mut rr = 0usize;
        let mut scan_done = false;
        let mut scan_error: Option<Error> = None;
        let mut output_done = false;

        let worker_exited =
            || StreamDecodeError::Decode(Error::InvalidData("RAR 5 parallel decode worker exited"));

        let result = 'pipeline: loop {
            // Top up workers while capacity remains: place the parked job
            // first, then read fresh blocks off the input.
            while !output_done && dispatched - applied < max_in_flight {
                let job = if let Some(job) = held.take() {
                    job
                } else if scan_done || scan_error.is_some() {
                    break;
                } else {
                    let mut payload = Vec::new();
                    match read_compressed_block_into(&mut input, &mut payload) {
                        Err(error) => {
                            scan_error = Some(error);
                            break;
                        }
                        Ok(header) => {
                        let mut start_bit = 0;
                        if header.has_tables {
                            // Parse the lengths here (they position the
                            // symbol start); the LUT build itself is lazy -
                            // the first worker that needs the set pays it.
                            match read_table_lengths(&payload, algorithm_version) {
                                Ok((lengths, table_bits)) => {
                                    scan_tables =
                                        Some(Arc::new(LazyDecodeTables::new(lengths)));
                                    start_bit = table_bits;
                                }
                                Err(error) => {
                                    scan_error = Some(error);
                                    break;
                                }
                            }
                        }
                        let Some(tables) = scan_tables.clone() else {
                            scan_error =
                                Some(Error::InvalidData("RAR 5 block reuses missing tables"));
                            break;
                        };
                            let seq = dispatched;
                            dispatched += 1;
                            if header.is_last {
                                // End of this member's block stream: a chain
                                // continues with the next member's reader,
                                // a single member is done scanning.
                                match next_input() {
                                    Some(next) => input = next,
                                    None => scan_done = true,
                                }
                            }
                            TapeJob {
                                seq,
                                tables,
                                payload,
                                start_bit,
                                payload_bits: header.payload_bits,
                            }
                        }
                    }
                };
                // Hand the job to any worker with queue space.
                let mut job = Some(job);
                for probe in 0..job_txs.len() {
                    let target = (rr + probe) % job_txs.len();
                    match job_txs[target].try_send(job.take().unwrap()) {
                        Ok(()) => {
                            rr = (target + 1) % job_txs.len();
                            break;
                        }
                        Err(mpsc::TrySendError::Full(back)) => job = Some(back),
                        Err(mpsc::TrySendError::Disconnected(_)) => {
                            break 'pipeline Err(worker_exited());
                        }
                    }
                }
                if let Some(back) = job {
                    // Every queue is full; park the job until a result drains.
                    held = Some(back);
                    break;
                }
            }

            // Apply whatever is ready, in order.
            while !output_done {
                let Some(tape) = reorder.remove(&applied) else {
                    break;
                };
                applied += 1;
                applied_tables = Some(tape.tables.clone());
                match self.apply_tape(tape, output, output_size, sink) {
                    Ok(TapeApplied::BlockDone) => {}
                    Ok(TapeApplied::OutputDone) => output_done = true,
                    Err(error) => break 'pipeline Err(error),
                }
            }
            if output_done {
                break Ok(());
            }

            let in_flight = dispatched - applied;
            if in_flight == 0 {
                if let Some(error) = scan_error.take() {
                    // The stream ran dry mid-member: the serial decoder would
                    // have hit this same error at this same output position.
                    break Err(error.into());
                }
                if scan_done {
                    // is_last applied without filling the output; the caller
                    // turns the shortfall into NeedMoreInput.
                    break Ok(());
                }
                continue;
            }
            let waiting_in_workers =
                in_flight - usize::from(held.is_some()) - reorder.len();
            if waiting_in_workers == 0 {
                // The only outstanding work is parked here (job queues were
                // full a moment ago, or tapes are already in the reorder
                // buffer) - loop back to place/apply it.
                continue;
            }
            match result_rx.recv() {
                Ok(tape) => {
                    reorder.insert(tape.seq, tape);
                }
                Err(_) => break Err(worker_exited()),
            }
        };

        drop(job_txs);
        drop(result_rx);
        for handle in handles {
            let _ = handle.join();
        }

        // Leave the decoder's table state as the serial path would: the
        // tables of the last block actually applied (scan may have read
        // further ahead than the member needed). An applied tape's tables are
        // normally already built; an all-literal empty tape may build here.
        // If the last applied tape carried a failed build the decode errored,
        // so there is no state worth carrying.
        if let Some(tables) = applied_tables.and_then(|lazy| lazy.get().ok()) {
            self.tables = Some(tables);
        }
        result
    }

    /// Whether this member takes the flat-apply path: non-solid, worth the MT
    /// pipeline, and small enough to hold whole in a member-sized buffer.
    /// Solid members, members over `flat_limit`, and non-parallel builds (this
    /// method only exists under the feature) keep the streaming-ring path.
    fn use_flat_mode(&self, output_size: usize, solid: bool, flat_limit: u64) -> bool {
        if solid {
            return false;
        }
        #[cfg(test)]
        if self.test_force_flat {
            return true;
        }
        self.capped_workers(output_size) >= 2 && output_size as u64 <= flat_limit
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
        tape: BlockTape,
        output: &mut FlatOutput,
        output_size: usize,
        sink: &mut impl FnMut(DecodedChunk<'_>) -> std::result::Result<(), E>,
    ) -> std::result::Result<TapeApplied, StreamDecodeError<E>> {
        let mut tape = tape;
        loop {
            let mut lit_pos = 0usize;
            for op in &tape.ops {
                if output.written() >= output_size {
                    return Ok(TapeApplied::OutputDone);
                }
                match *op {
                    TapeOp::Lits(count) => {
                        let count = count as usize;
                        // Worker may overshoot the member end; clamp like the
                        // serial decoder rather than error (trap 1).
                        let take = count.min(output_size - output.written());
                        output.push_bytes(&tape.lits[lit_pos..lit_pos + take], sink)?;
                        lit_pos += count;
                        if take < count {
                            return Ok(TapeApplied::OutputDone);
                        }
                    }
                    TapeOp::RepLast => {
                        if self.last_length != 0 {
                            output.copy_match(self.reps[0], self.last_length, sink)?;
                        }
                    }
                    TapeOp::Rep { index, length } => {
                        let index = usize::from(index);
                        let distance = self.reps[index];
                        if distance == 0 {
                            return Err(Error::InvalidData(
                                "RAR 5 repeat distance is not initialized",
                            )
                            .into());
                        }
                        self.reps[..=index].rotate_right(1);
                        self.reps[0] = distance;
                        self.last_length = length;
                        output.copy_match(distance, length, sink)?;
                    }
                    TapeOp::Match { distance, length } => {
                        self.reps.rotate_right(1);
                        self.reps[0] = distance;
                        self.last_length = length;
                        output.copy_match(distance, length, sink)?;
                    }
                    TapeOp::Filter(raw) => {
                        // Filter starts resolve at apply time (trap 4).
                        output.add_filter(raw.resolve(output.written())?)?;
                    }
                }
            }
            if output.written() >= output_size {
                return Ok(TapeApplied::OutputDone);
            }
            if let Some(resume_bit) = tape.resume_bit {
                let job = TapeJob {
                    seq: tape.seq,
                    tables: tape.tables.clone(),
                    payload: std::mem::take(&mut tape.payload),
                    start_bit: resume_bit,
                    payload_bits: tape.payload_bits,
                };
                tape = decode_block_tape(job);
                continue;
            }
            if let Some(error) = tape.tail_error {
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
                    let mut payload = Vec::new();
                    let header = match read_compressed_block_into(&mut input, &mut payload) {
                        Ok(header) => header,
                        Err(error) => {
                            scan_error = Some(error);
                            break;
                        }
                    };
                    let mut start_bit = 0;
                    if header.has_tables {
                        // Parse only; the LUT build is lazy on the workers.
                        match read_table_lengths(&payload, algorithm_version) {
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
                        payload,
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
                    let Some(tape) = reorder.remove(&applied) else {
                        break;
                    };
                    applied += 1;
                    applied_tables = Some(tape.tables.clone());
                    match self.apply_tape_flat(tape, output, output_size, sink) {
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
        if let Some(tables) = applied_tables.and_then(|lazy| lazy.get().ok()) {
            self.tables = Some(tables);
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
}

/// Emit granularity: keep the writer-thread pipe fed in ~1 MB batches while
/// decode continues, matching the streaming path's flush cadence.
#[cfg(feature = "parallel")]
const FLAT_EMIT_THRESHOLD: usize = 1 << 20;

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
        let mut buf = vec![0u8; seed.len() + output_size];
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
        self.pos - self.base
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
        if self
            .pos
            .checked_add(bytes.len())
            .is_none_or(|end| end > self.buf.len())
        {
            return Err(Error::InvalidData("RAR 5 match exceeds output limit").into());
        }
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
        self.maybe_emit(sink)
    }

    /// Copy a back-reference forward inside `buf`. Window is the buffer prefix
    /// itself, so there is no masking and no history head; error checks and
    /// their order match `StreamingOutput::copy_match` for differential
    /// equality (dictionary, then window-limit, then window, then output).
    #[inline]
    fn copy_match<E>(
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
            .pos
            .checked_add(length)
            .is_none_or(|end| end > self.buf.len())
        {
            return Err(Error::InvalidData("RAR 5 match exceeds output limit").into());
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
    fn add_filter<E>(
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
                // serial walk. `add_filter` pinned that origin at
                // declaration; slice with the physical index, translate
                // with the member-local one.
                apply_filter_to_range(
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
        let keep = self.buf.len().min(history_limit);
        self.buf[self.buf.len() - keep..].to_vec()
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

impl Default for Unpack50Decoder {
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
            // rewrites this in `add_filter`.
            file_start: start,
            length: self.length as usize,
            filter_type: self.filter_type,
            channels: usize::from(self.channels),
        })
    }
}

fn read_filter_raw(bits: &mut BitReader<'_>) -> Result<RawFilter> {
    let offset = read_filter_data(bits)?;
    let length = read_filter_data(bits)?;
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

fn read_filter(bits: &mut BitReader<'_>, current_pos: usize) -> Result<PendingFilter> {
    read_filter_raw(bits)?.resolve(current_pos)
}

fn read_filter_data(bits: &mut BitReader<'_>) -> Result<u32> {
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
    write_filter_data(writer, filter.offset as u32);
    write_filter_data(writer, filter.length as u32);
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

fn write_filter_data(writer: &mut BitWriter, value: u32) {
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
        FilterType::E8 => e8e9_decode(data, file_start as u32, false),
        FilterType::E8E9 => e8e9_decode(data, file_start as u32, true),
        FilterType::Arm => arm_decode(data, file_start as u32),
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

fn e8e9_decode(data: &mut [u8], file_offset: u32, include_e9: bool) {
    if data.len() <= 4 {
        return;
    }
    let cmp_mask = if include_e9 { 0xfe } else { 0xff };
    let opcode_limit = data.len() - 4;
    let mut opcode_pos = 0usize;
    while let Some(pos) = super::fast::next_x86_opcode(data, opcode_pos, opcode_limit, cmp_mask) {
        let cur_pos = pos + 1;
        let offset = file_offset.wrapping_add(cur_pos as u32) % X86_FILTER_FILE_SIZE;
        let addr = u32::from_le_bytes([
            data[cur_pos],
            data[cur_pos + 1],
            data[cur_pos + 2],
            data[cur_pos + 3],
        ]);
        let new_addr = if addr & 0x8000_0000 != 0 {
            (addr.wrapping_add(offset) & 0x8000_0000 == 0)
                .then(|| addr.wrapping_add(X86_FILTER_FILE_SIZE))
        } else {
            (addr.wrapping_sub(X86_FILTER_FILE_SIZE) & 0x8000_0000 != 0)
                .then(|| addr.wrapping_sub(offset))
        };
        if let Some(value) = new_addr {
            data[cur_pos..cur_pos + 4].copy_from_slice(&value.to_le_bytes());
        }
        opcode_pos = pos + 5;
    }
}

fn e8e9_encode(data: &mut [u8], file_offset: u32, include_e9: bool) {
    if data.len() <= 4 {
        return;
    }
    let cmp_mask = if include_e9 { 0xfe } else { 0xff };
    let opcode_limit = data.len() - 4;
    let mut opcode_pos = 0usize;
    while let Some(pos) = super::fast::next_x86_opcode(data, opcode_pos, opcode_limit, cmp_mask) {
        let cur_pos = pos + 1;
        let offset = file_offset.wrapping_add(cur_pos as u32) % X86_FILTER_FILE_SIZE;
        let addr = u32::from_le_bytes([
            data[cur_pos],
            data[cur_pos + 1],
            data[cur_pos + 2],
            data[cur_pos + 3],
        ]);
        let candidate = addr.wrapping_add(offset);
        let new_addr = if candidate < X86_FILTER_FILE_SIZE {
            Some(candidate)
        } else {
            let candidate = addr.wrapping_sub(X86_FILTER_FILE_SIZE);
            (candidate & 0x8000_0000 != 0 && candidate.wrapping_add(offset) & 0x8000_0000 == 0)
                .then_some(candidate)
        };
        if let Some(value) = new_addr {
            data[cur_pos..cur_pos + 4].copy_from_slice(&value.to_le_bytes());
        }
        opcode_pos = pos + 5;
    }
}

const X86_FILTER_FILE_SIZE: u32 = 0x0100_0000;

fn arm_decode(data: &mut [u8], file_offset: u32) {
    let mut pos = 0usize;
    while pos + 3 < data.len() {
        if data[pos + 3] == 0xeb {
            let mut offset = u32::from(data[pos])
                | (u32::from(data[pos + 1]) << 8)
                | (u32::from(data[pos + 2]) << 16);
            offset = offset.wrapping_sub(file_offset.wrapping_add(pos as u32) / 4);
            data[pos] = offset as u8;
            data[pos + 1] = (offset >> 8) as u8;
            data[pos + 2] = (offset >> 16) as u8;
        }
        pos += 4;
    }
}

fn arm_encode(data: &mut [u8], file_offset: u32) {
    let mut pos = 0usize;
    while pos + 3 < data.len() {
        if data[pos + 3] == 0xeb {
            let mut offset = u32::from(data[pos])
                | (u32::from(data[pos + 1]) << 8)
                | (u32::from(data[pos + 2]) << 16);
            offset = offset.wrapping_add(file_offset.wrapping_add(pos as u32) / 4);
            data[pos] = offset as u8;
            data[pos + 1] = (offset >> 8) as u8;
            data[pos + 2] = (offset >> 16) as u8;
        }
        pos += 4;
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

pub fn slot_to_length(slot: usize, extra_bits: u32) -> Result<usize> {
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
    Ok((((2 | (slot & 1)) << bit_count) | extra_bits as usize) + 1)
}

#[derive(Debug, Clone)]
pub struct HuffmanTable {
    symbols: Vec<HuffmanSymbol>,
    first_code: [u16; 16],
    first_index: [usize; 16],
    counts: [u16; 16],
    // Primary decode LUT: top LUT_BITS of the bitstream -> (symbol << 8) | code_len.
    // Entry 0 means "code longer than LUT_BITS or invalid" -> canonical fallback.
    lut: Vec<u32>,
}

const HUFF_LUT_BITS: usize = 12;

#[derive(Debug, Clone)]
struct HuffmanSymbol {
    code: u16,
    len: u8,
    symbol: usize,
}

impl HuffmanTable {
    pub fn from_lengths(lengths: &[u8]) -> Result<Self> {
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

        let mut symbols = Vec::new();
        for (symbol, &length) in lengths.iter().enumerate() {
            if length == 0 {
                continue;
            }
            let code = next_code[length as usize];
            next_code[length as usize] += 1;
            symbols.push(HuffmanSymbol {
                code,
                len: length,
                symbol,
            });
        }
        symbols.sort_by_key(|item| (item.len, item.code, item.symbol));
        let mut lut = vec![0u32; 1 << HUFF_LUT_BITS];
        for item in &symbols {
            let len = usize::from(item.len);
            if len <= HUFF_LUT_BITS {
                let shift = HUFF_LUT_BITS - len;
                let start = usize::from(item.code) << shift;
                let entry = ((item.symbol as u32) << 8) | u32::from(item.len);
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

    fn decode(&self, bits: &mut BitReader<'_>) -> Result<usize> {
        if let Some(peek) = bits.peek15() {
            let entry = self.lut[usize::from(peek >> (15 - HUFF_LUT_BITS))];
            if entry != 0 {
                bits.consume((entry & 0xff) as u8);
                return Ok((entry >> 8) as usize);
            }
            // Codes longer than the LUT (13..=15 bits).
            for len in (HUFF_LUT_BITS + 1)..=15 {
                let count = self.counts[len];
                if count != 0 {
                    let code = peek >> (15 - len);
                    let offset = code.wrapping_sub(self.first_code[len]);
                    if offset < count {
                        bits.consume(len as u8);
                        let index = self.first_index[len] + usize::from(offset);
                        return Ok(self.symbols[index].symbol);
                    }
                }
            }
            return Err(Error::InvalidData("RAR 5 invalid Huffman code"));
        }
        self.decode_slow(bits)
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
                    return Ok(self.symbols[index].symbol);
                }
            }
        }
        Err(Error::InvalidData("RAR 5 invalid Huffman code"))
    }

    fn code_for_symbol(&self, symbol: usize) -> Result<(u16, u8)> {
        self.symbols
            .iter()
            .find(|item| item.symbol == symbol)
            .map(|item| (item.code, item.len))
            .ok_or(Error::InvalidData("RAR 5 missing Huffman symbol"))
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
            let word =
                u64::from_be_bytes(self.input[self.byte_pos..self.byte_pos + 8].try_into().unwrap());
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

    fn read_bits(&mut self, count: u8) -> Result<u32> {
        if count > 32 {
            return Err(Error::InvalidData("RAR 5 bit read is too wide"));
        }
        if count == 0 {
            return Ok(0);
        }
        let count = u32::from(count);
        if self.cache_bits < count {
            self.refill();
            if self.cache_bits < count {
                return Err(Error::NeedMoreInput);
            }
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

struct BitWriter {
    bytes: Vec<u8>,
    bit_pos: usize,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            bit_pos: 0,
        }
    }

    fn write_bits(&mut self, value: usize, count: usize) {
        for bit in (0..count).rev() {
            if self.bit_pos.is_multiple_of(8) {
                self.bytes.push(0);
            }
            if (value >> bit) & 1 != 0 {
                let byte = self.bytes.last_mut().unwrap();
                *byte |= 1 << (7 - (self.bit_pos % 8));
            }
            self.bit_pos += 1;
        }
    }

    fn finish(self) -> Vec<u8> {
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
mod tests {
    use super::*;

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
    fn rejects_oversubscribed_rar50_huffman_tables() {
        assert!(matches!(
            HuffmanTable::from_lengths(&[1, 1, 1]),
            Err(Error::InvalidData("RAR 5 oversubscribed Huffman table"))
        ));
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
                .any(|token| matches!(token, EncodeToken::Match { .. }))
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
        let input = b"abcdXbcdYYYYYYYYYYYYabcdYYYYYYYYYYYY";
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
            .any(|token| matches!(token, EncodeToken::Match { length: 4, .. })));
        assert!(lazy
            .iter()
            .any(|token| matches!(token, EncodeToken::Match { length, .. } if *length > 8)));
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

        let mut buckets = vec![Vec::new(); MATCH_HASH_BUCKETS];
        for candidate in 0..pos {
            insert_match_position(&input, candidate, &mut buckets);
        }
        let state = EncoderMatchState {
            reps: [30, 0, 0, 0],
            last_length: 8,
        };

        let best = best_match(
            &input,
            pos,
            input.len(),
            &buckets,
            EncodeOptions::default(),
            &state,
            DISTANCE_TABLE_SIZE_50,
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

        let mut buckets = vec![Vec::new(); MATCH_HASH_BUCKETS];
        for candidate in 0..pos {
            insert_match_position(&input, candidate, &mut buckets);
        }
        let state = EncoderMatchState {
            reps: [30, 0, 0, 0],
            last_length: 8,
        };
        let current = best_match(
            &input,
            pos,
            input.len(),
            &buckets,
            EncodeOptions::default(),
            &state,
            DISTANCE_TABLE_SIZE_50,
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
        ));
    }

    #[test]
    fn lazy_parser_uses_bounded_cost_lookahead() {
        let pos = 160;
        let mut input: Vec<u8> = (0..240u16)
            .map(|value| value.wrapping_mul(91) as u8)
            .collect();
        input[pos - 30..pos - 22].copy_from_slice(b"ABCDEFGH");
        input[pos - 80..pos - 70].copy_from_slice(b"CDEFGHIJKL");
        input[pos..pos + 12].copy_from_slice(b"ABCDEFGHIJKL");

        let mut buckets = vec![Vec::new(); MATCH_HASH_BUCKETS];
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

        let mut buckets = vec![Vec::new(); MATCH_HASH_BUCKETS];
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
        ));
    }

    fn encode_lz_member_with_filter(data: &[u8], kind: Rar50FilterKind) -> Result<Vec<u8>> {
        Unpack50Encoder::new().encode_member_with_filter(data, 0, Rar50FilterSpec::new(kind))
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
        e8e9_decode(&mut decoded, file_offset, false);

        assert_eq!(&decoded[1..5], &0x0000_0c07u32.to_le_bytes());
        e8e9_encode(&mut decoded, file_offset, false);
        assert_eq!(decoded, encoded);
    }

    #[test]
    fn streaming_decode_applies_filters_in_stream() {
        let data = b"\xe8\0\0\0\0plain text after call".to_vec();
        let input = encode_lz_member_with_filter(&data, Rar50FilterKind::E8).unwrap();
        let mut reader = input.as_slice();
        let mut decoder = Unpack50Decoder::new();
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

        let mut decoder = Unpack50Decoder::new();
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
        let mut decoder = Unpack50Decoder::new();
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
            matches!(err, StreamDecodeError::Decode(Error::WindowLimitExceeded { .. })),
            "expected WindowLimitExceeded, got {err:?}"
        );

        // Limit above the match distance: decodes byte-for-byte.
        let mut decoder = Unpack50Decoder::new();
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
            .add_filter::<std::convert::Infallible>(filter)
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
        let ceiling = (dict + 2 * STREAM_FLUSH_THRESHOLD + STREAM_FILTER_HOLD_LIMIT)
            .next_power_of_two();
        assert_eq!(output.ring.len(), ceiling);

        // A small member declaring the same dictionary keeps the lazy start.
        let small = StreamingOutput::new(Vec::new(), 0, 1 << 20, dict, dict);
        assert!(small.ring.len() < ceiling);
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
                DecodedChunk::Repeated { byte, len } => {
                    decoded.resize(decoded.len() + len, byte)
                }
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
                DecodedChunk::Repeated { byte, len } => {
                    decoded.resize(decoded.len() + len, byte)
                }
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
        let mut decoder = Unpack50Decoder::new();
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
    fn decoder_after_streamed_zero_member(size: usize, dict: usize) -> Unpack50Decoder {
        let member = encode_lz_member(&vec![0u8; size], 0).unwrap();
        let mut decoder = Unpack50Decoder::new();
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

        let input = Unpack50Encoder::new()
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

        let input = Unpack50Encoder::new()
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
        let (lengths, table_bits) = read_table_lengths(&input[block.payload.clone()], 0).unwrap();
        let tables = DecodeTables::from_lengths(&lengths).unwrap();
        let mut bits = BitReader::new_at(&input[block.payload], table_bits);
        assert_eq!(tables.main.decode(&mut bits).unwrap(), 256);
        let first = read_filter(&mut bits, 0).unwrap();
        assert_eq!(tables.main.decode(&mut bits).unwrap(), 256);
        let second = read_filter(&mut bits, 0).unwrap();

        let output = decode_lz(&input, 0, data.len()).unwrap();

        assert_eq!(output, data);
        assert_eq!(first.start, first_start);
        assert_eq!(second.start, second_start);
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

        arm_encode(&mut filtered, u32::MAX - 3);
        assert_ne!(filtered, original);
        arm_decode(&mut filtered, u32::MAX - 3);

        assert_eq!(filtered, original);
    }

    #[test]
    fn solid_encoder_emits_rar50_matches_against_previous_member_history() {
        let first = b"RAR5 solid shared phrase alpha beta gamma\n".repeat(16);
        let second = b"RAR5 solid shared phrase alpha beta gamma\nsecond\n".repeat(4);
        let solid = encode_lz_member_with_history(&second, &first, 0).unwrap();
        let standalone = encode_lz_member(&second, 0).unwrap();
        let mut decoder = Unpack50Decoder::new();

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

    #[test]
    fn large_lz_members_are_split_into_multiple_compressed_blocks() {
        let data = vec![0u8; MAX_COMPRESSED_BLOCK_OUTPUT + 1];
        let encoded = encode_lz_member_with_options(&data, 0, EncodeOptions::new(16)).unwrap();
        let mut cursor = std::io::Cursor::new(encoded.as_slice());
        let mut payload = Vec::new();
        let first = read_compressed_block_into(&mut cursor, &mut payload).unwrap();
        let second = read_compressed_block_into(&mut cursor, &mut payload).unwrap();
        let mut decoder = Unpack50Decoder::new();

        assert!(!first.is_last);
        assert!(second.is_last);
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

        let encoded = Unpack50Encoder::with_options(EncodeOptions::new(0))
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
        let mut decoder = Unpack50Decoder::new();

        assert!(!first.is_last);
        assert!(last_is_last);
        assert!(blocks > 2);
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
    /// never in place (trap 5, and unrar's `UnpackWriteBuf` copying into
    /// `FilterSrcMemory` before `ApplyFilter`). The encoder used to remember
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

            let mut encoder = Unpack50Encoder::with_options(EncodeOptions::new(4));
            let packed_a = encoder
                .encode_member_with_filter(&a, 0, Rar50FilterSpec::new(Rar50FilterKind::E8))
                .unwrap();
            let packed_b = encoder.encode_member(&b, 0).unwrap();

            let mut decoder = Unpack50Decoder::new();
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
        let encoded = Unpack50Encoder::with_options(
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
        let first = read_compressed_block_into(&mut cursor, &mut payload).unwrap();
        let second = read_compressed_block_into(&mut cursor, &mut payload).unwrap();
        let mut decoder = Unpack50Decoder::new();

        assert!(!first.is_last);
        assert!(second.is_last);
        assert_eq!(
            decoder
                .decode_member(&encoded, 0, data.len(), false, DecodeMode::Lz)
                .unwrap(),
            data
        );
    }

    #[test]
    fn solid_encoder_history_limit_follows_encode_options_dictionary() {
        let mut encoder = Unpack50Encoder::with_options(
            EncodeOptions::new(0).with_max_match_distance(DEFAULT_DICTIONARY_SIZE + 1024),
        );
        encoder.remember(&vec![0x41; DEFAULT_DICTIONARY_SIZE + 512]);

        assert_eq!(encoder.history.len(), DEFAULT_DICTIONARY_SIZE + 512);

        let mut capped =
            Unpack50Encoder::with_options(EncodeOptions::new(0).with_max_match_distance(1024));
        capped.remember(&vec![0x42; 4096]);

        assert_eq!(capped.history.len(), 1024);
    }

    #[test]
    fn encodes_lz_member_with_last_length_repeat_symbols() {
        let data = b"abcdXabcdYabcdZabcd";
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
        let mut decoder = Unpack50Decoder::new();

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
        assert_eq!(slot_to_length(0, 0).unwrap(), 2);
        assert_eq!(slot_to_length(7, 0).unwrap(), 9);
        assert_eq!(slot_to_length(8, 0).unwrap(), 10);
        assert_eq!(slot_to_length(8, 1).unwrap(), 11);
        assert_eq!(slot_to_length(11, 1).unwrap(), 17);
        assert_eq!(slot_to_length(12, 3).unwrap(), 21);
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

    #[test]
    fn bit_reader_accepts_large_rar5_distance_extras() {
        let mut bits = BitReader::new(&[0xff, 0x00, 0xaa, 0x55]);

        assert_eq!(bits.read_bits(32).unwrap(), 0xff00_aa55);
        assert_eq!(
            bits.read_bits(1),
            Err(Error::NeedMoreInput),
            "32-bit reads must not leave a partial cursor state"
        );
    }

    #[test]
    fn copies_lz_matches_with_overlap() {
        let decoder = Unpack50Decoder::new();
        let mut output = b"AB".to_vec();

        decoder
            .copy_match(&mut output, 2, 6, 8, DEFAULT_DICTIONARY_SIZE)
            .unwrap();

        assert_eq!(output, b"ABABABAB");
    }

    #[test]
    fn rejects_invalid_match_copy() {
        let decoder = Unpack50Decoder::new();
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
        let decoder = Unpack50Decoder::new();
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
        let mut decoder = Unpack50Decoder::new();
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
        let mut decoder = Unpack50Decoder::new();
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
        let mut decoder = Unpack50Decoder::new();
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
        let mut writer = BitWriter { bytes, bit_pos };
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
        let mut writer = BitWriter { bytes, bit_pos };

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
        decoder: &mut Unpack50Decoder,
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
                        out.extend(std::iter::repeat(byte).take(len))
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
            lcg = lcg.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
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
                1 => mixed.extend(std::iter::repeat(0u8).take(64 << 10)),
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

            let mut mt_decoder = Unpack50Decoder::new();
            let mt_out = mt_sink_decode(&encoded, data.len(), &mut mt_decoder)
                .unwrap_or_else(|_| panic!("{name}: parallel decode failed"));
            assert_eq!(mt_out, data, "{name}: parallel output mismatch");

            // Reference: the untouched buffered decoder. Output and final
            // LZ state (rep distances, last length) must agree exactly.
            let mut reference = Unpack50Decoder::new();
            let ref_out = reference
                .decode_member(&encoded, 0, data.len(), false, DecodeMode::Lz)
                .unwrap();
            assert_eq!(ref_out, data, "{name}: reference output mismatch");
            assert_eq!(mt_decoder.reps, reference.reps, "{name}: rep state diverged");
            assert_eq!(
                mt_decoder.last_length, reference.last_length,
                "{name}: last_length diverged"
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
                let mut reference = Unpack50Decoder::new();
                let ref_result =
                    reference.decode_member(&encoded, 0, prefix, false, DecodeMode::Lz);
                let mut mt_decoder = Unpack50Decoder::new();
                let mt_result = mt_sink_decode(&encoded, prefix, &mut mt_decoder);
                match ref_result {
                    Ok(ref_out) => {
                        let mt_out = mt_result.unwrap_or_else(|_| {
                            panic!("{name}/{prefix}: parallel failed where reference succeeded")
                        });
                        assert_eq!(mt_out, ref_out, "{name}/{prefix}: prefix output mismatch");
                    }
                    Err(ref_error) => match mt_result {
                        Err(StreamDecodeError::Decode(mt_error)) => assert_eq!(
                            mt_error, ref_error,
                            "{name}/{prefix}: error mismatch"
                        ),
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
        let mut encoder = Unpack50Encoder::with_options(EncodeOptions::new(4));
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
        let mut serial = Unpack50Decoder::new();
        let mut serial_out = Vec::new();
        for (data, packed) in members.iter().zip(&encoded) {
            serial_out.extend(
                serial
                    .decode_member(packed, 0, data.len(), true, DecodeMode::Lz)
                    .unwrap(),
            );
        }
        assert_eq!(serial_out, members.concat(), "oracle disagrees with encoder");

        // Chain in two groups of two; the second call sees a carried window.
        for flat_limit in [u64::MAX, 0] {
            let mut chained = Unpack50Decoder::new();
            let mut chain_out: Vec<u8> = Vec::new();
            for group in [[0usize, 1], [2, 3]] {
                let sizes: Vec<usize> = group.iter().map(|&i| members[i].len()).collect();
                let mut next = 0usize;
                let readers: Vec<&[u8]> =
                    group.iter().map(|&i| encoded[i].as_slice()).collect();
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
                                    chain_out.extend(std::iter::repeat(byte).take(len))
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
            assert_eq!(chained.last_length, serial.last_length);
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
    /// (what the encoder bakes in, what unrar's per-file WrittenFileSize
    /// gives, what the serial walk passes). The chain outputs count the
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

            let mut encoder = Unpack50Encoder::new();
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
            let mut serial = Unpack50Decoder::new();
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
                let mut chained = Unpack50Decoder::new();
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
                                    chain_out.extend(std::iter::repeat(byte).take(len))
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
        let mut writer = BitWriter { bytes, bit_pos };
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
        let (bad_bytes, bad_bits) =
            encode_table_lengths_with_bit_count(&bad_lengths, 0).unwrap();
        let block2 = encode_compressed_block(&bad_bytes, bad_bits, true, true).unwrap();

        let mut stream = block1;
        stream.extend_from_slice(&block2);

        // Case A: output completes inside block 1 -> every path succeeds and
        // never surfaces the read-ahead build failure.
        // Case B: output needs block 2 -> every path fails with the exact
        // error the serial decoder raises at that table build.
        for output_size in [4usize, 6] {
            let mut reference = Unpack50Decoder::new();
            let ref_result =
                reference.decode_member(&stream, 0, output_size, false, DecodeMode::Lz);

            let mut mt_decoder = Unpack50Decoder::new();
            let mt_result = mt_sink_decode(&stream, output_size, &mut mt_decoder);
            let mut flat_decoder = Unpack50Decoder::new();
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
        let mut decoder = Unpack50Decoder::new();
        assert!(
            mt_sink_decode(truncated, data.len(), &mut decoder).is_err(),
            "truncated stream must fail like the serial decoder"
        );
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn parallel_decode_resolves_rep_state_across_blocks() {
        // Block 1 (tables, not last): "AB" literals, a new match, then a
        // symbol-257 repeat -> "ABABAB", leaving last_length=2, reps[0]=2.
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
        let mut writer = BitWriter { bytes, bit_pos };
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

        let mut reference = Unpack50Decoder::new();
        let expected = reference
            .decode_member(&stream, 0, 8, false, DecodeMode::Lz)
            .unwrap();
        assert_eq!(expected, b"ABABABAB", "reference disagrees with test setup");

        let mut mt_decoder = Unpack50Decoder::new();
        let mt_out = mt_sink_decode(&stream, 8, &mut mt_decoder).expect("parallel decode failed");
        assert_eq!(mt_out, expected);
        assert_eq!(mt_decoder.reps, reference.reps);
        assert_eq!(mt_decoder.last_length, reference.last_length);
    }

    /// Decode a member through the flat-apply path (test-forced on regardless
    /// of size), collecting the sink chunks into one buffer. Mirror of
    /// `mt_sink_decode` for the streaming ring, but for `FlatOutput`.
    #[cfg(feature = "parallel")]
    fn flat_sink_decode(
        encoded: &[u8],
        output_size: usize,
        decoder: &mut Unpack50Decoder,
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
                        out.extend(std::iter::repeat(byte).take(len))
                    }
                }
                Ok(())
            },
        )?;
        Ok(out)
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

            let mut flat_decoder = Unpack50Decoder::new();
            let flat_out = flat_sink_decode(&encoded, data.len(), &mut flat_decoder)
                .unwrap_or_else(|_| panic!("{name}: flat decode failed"));
            assert_eq!(flat_out, data, "{name}: flat output mismatch");

            // Reference: the untouched buffered decoder. Output and final LZ
            // state (rep distances, last length) must agree exactly.
            let mut reference = Unpack50Decoder::new();
            let ref_out = reference
                .decode_member(&encoded, 0, data.len(), false, DecodeMode::Lz)
                .unwrap();
            assert_eq!(ref_out, data, "{name}: reference output mismatch");
            assert_eq!(flat_decoder.reps, reference.reps, "{name}: rep state diverged");
            assert_eq!(
                flat_decoder.last_length, reference.last_length,
                "{name}: last_length diverged"
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
                let mut reference = Unpack50Decoder::new();
                let ref_result =
                    reference.decode_member(&encoded, 0, prefix, false, DecodeMode::Lz);
                let mut flat_decoder = Unpack50Decoder::new();
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
        let mut decoder = Unpack50Decoder::new();
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
        let mut writer = BitWriter { bytes, bit_pos };
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

        let mut reference = Unpack50Decoder::new();
        let expected = reference
            .decode_member(&stream, 0, 8, false, DecodeMode::Lz)
            .unwrap();
        assert_eq!(expected, b"ABABABAB", "reference disagrees with test setup");

        let mut flat_decoder = Unpack50Decoder::new();
        let flat_out = flat_sink_decode(&stream, 8, &mut flat_decoder).expect("flat decode failed");
        assert_eq!(flat_out, expected);
        assert_eq!(flat_decoder.reps, reference.reps);
        assert_eq!(flat_decoder.last_length, reference.last_length);
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn flat_decode_applies_whole_member_filter() {
        // A whole-member E8 filter: matches read the pre-filter window in
        // `buf`, and the filter applies to a scratch copy at emit. Output must
        // equal the buffered reference (which filters at member end).
        let data = b"\xe8\0\0\0\0plain text after the call opcode".to_vec();
        let encoded = encode_lz_member_with_filter(&data, Rar50FilterKind::E8).unwrap();
        let mut reference = Unpack50Decoder::new();
        let ref_out = reference
            .decode_member(&encoded, 0, data.len(), false, DecodeMode::Lz)
            .unwrap();
        let mut flat_decoder = Unpack50Decoder::new();
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
        let region: Vec<u8> = (0..64u8).map(|i| i.wrapping_mul(3).wrapping_add(7)).collect();
        data.extend_from_slice(&region);
        let end = data.len();
        data.extend_from_slice(b"SUFFIX-not-filtered-111111111111111");

        let encoded = Unpack50Encoder::new()
            .encode_member_with_filters(
                &data,
                0,
                &[Rar50FilterSpec::range(
                    Rar50FilterKind::Delta { channels: 1 },
                    start..end,
                )],
            )
            .unwrap();

        let mut reference = Unpack50Decoder::new();
        let ref_out = reference
            .decode_member(&encoded, 0, data.len(), false, DecodeMode::Lz)
            .unwrap();
        assert_eq!(ref_out, data, "reference round-trip mismatch");

        // Capture chunks in order to inspect the emit boundaries.
        let mut decoder = Unpack50Decoder::new();
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
                            chunks.push(std::iter::repeat(byte).take(len).collect())
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
        let mut writer = BitWriter { bytes, bit_pos };

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
}
